package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"containgo.local/containgo/internal/controlplane"
	"containgo.local/containgo/internal/domain"
)

// Client sends trusted Gateway security events to the Control Plane.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// Config contains Gateway-to-Control-Plane SPIFFE mTLS settings.
type Config struct {
	BaseURL   string
	Timeout   time.Duration
	TLSConfig *tls.Config
}

// NewClient creates a Control Plane event client.
func NewClient(config Config) (*Client, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(config.BaseURL), "/")
	if baseURL == "" {
		baseURL = "https://127.0.0.1:8090"
	}

	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse control-plane URL: %w", err)
	}

	if parsed.Scheme != "https" {
		return nil, errors.New("control-plane URL must use HTTPS")
	}

	if parsed.Host == "" {
		return nil, errors.New("control-plane URL must include a host")
	}

	if config.TLSConfig == nil {
		return nil, errors.New("Control Plane SPIFFE TLS configuration is required")
	}

	if config.Timeout <= 0 {
		config.Timeout = 3 * time.Second
	}

	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: config.Timeout,
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				ForceAttemptHTTP2:     true,
				TLSClientConfig:       config.TLSConfig.Clone(),
				TLSHandshakeTimeout:   5 * time.Second,
				ResponseHeaderTimeout: config.Timeout,
				IdleConnTimeout:       60 * time.Second,
			},
		},
	}, nil
}

// SendEvent posts one trusted security event to the Control Plane.
func (c *Client) SendEvent(
	ctx context.Context,
	event domain.SecurityEvent,
) (controlplane.IngestResult, error) {
	if ctx == nil {
		return controlplane.IngestResult{}, errors.New("context must not be nil")
	}

	if err := ctx.Err(); err != nil {
		return controlplane.IngestResult{}, fmt.Errorf("context is not usable: %w", err)
	}

	body := map[string]any{
		"request_id":         event.RequestID,
		"workload_spiffe_id": event.WorkloadID,
		"method":             event.Method,
		"path":               event.Path,
		"decision":           event.Decision,
		"status_code":        event.StatusCode,
		"reason":             event.Reason,
		"occurred_at":        event.OccurredAt,
	}

	encoded, err := json.Marshal(body)
	if err != nil {
		return controlplane.IngestResult{}, fmt.Errorf("encode security event: %w", err)
	}

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.baseURL+"/v1/events",
		bytes.NewReader(encoded),
	)
	if err != nil {
		return controlplane.IngestResult{}, fmt.Errorf("create event request: %w", err)
	}

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	response, err := c.httpClient.Do(request)
	if err != nil {
		return controlplane.IngestResult{}, fmt.Errorf("send security event: %w", err)
	}
	defer func() {
		_ = response.Body.Close()
	}()

	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return controlplane.IngestResult{}, fmt.Errorf("read control-plane response: %w", err)
	}

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return controlplane.IngestResult{}, fmt.Errorf(
			"control plane returned HTTP %d: %s",
			response.StatusCode,
			strings.TrimSpace(string(responseBody)),
		)
	}

	var result controlplane.IngestResult
	if err = json.Unmarshal(responseBody, &result); err != nil {
		return controlplane.IngestResult{}, fmt.Errorf("decode control-plane response: %w", err)
	}

	return result, nil
}

// Check verifies that the Control Plane is reachable over SPIFFE mTLS.
func (c *Client) Check(ctx context.Context) error {
	if ctx == nil {
		return errors.New("context must not be nil")
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context is not usable: %w", err)
	}

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		c.baseURL+"/healthz",
		nil,
	)
	if err != nil {
		return fmt.Errorf("create control-plane health request: %w", err)
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("call control-plane health endpoint: %w", err)
	}
	defer func() {
		_ = response.Body.Close()
	}()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf(
			"control-plane health returned HTTP %d",
			response.StatusCode,
		)
	}

	return nil
}
