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

	"containgo.local/containgo/internal/domain"
)

// EnforcementConfig configures Control Plane calls to the Gateway's internal
// quarantine-management API.
type EnforcementConfig struct {
	BaseURL   string
	Timeout   time.Duration
	TLSConfig *tls.Config
}

// DefaultEnforcementConfig returns local-development settings.
func DefaultEnforcementConfig() EnforcementConfig {
	return EnforcementConfig{
		BaseURL: "https://127.0.0.1:8443",
		Timeout: 5 * time.Second,
	}
}

// EnforcementClient updates runtime quarantine state through the API Gateway.
type EnforcementClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewEnforcementClient creates the SPIFFE mTLS Gateway enforcement client.
func NewEnforcementClient(
	config EnforcementConfig,
) (*EnforcementClient, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(config.BaseURL), "/")
	if baseURL == "" {
		baseURL = "https://127.0.0.1:8443"
	}

	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse Gateway URL: %w", err)
	}

	if parsed.Scheme != "https" {
		return nil, errors.New("Gateway enforcement URL must use HTTPS")
	}
	if parsed.Host == "" {
		return nil, errors.New("Gateway enforcement URL must include a host")
	}

	if config.TLSConfig == nil {
		return nil, errors.New("Gateway SPIFFE TLS configuration is required")
	}

	if config.Timeout <= 0 {
		config.Timeout = 5 * time.Second
	}

	return &EnforcementClient{
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

// Check verifies the authenticated internal Gateway endpoint.
func (c *EnforcementClient) Check(ctx context.Context) error {
	return c.doJSON(
		ctx,
		http.MethodGet,
		"/internal/healthz",
		nil,
	)
}

// SetQuarantined adds or removes one workload from the runtime deny set.
func (c *EnforcementClient) SetQuarantined(
	ctx context.Context,
	spiffeID string,
	quarantined bool,
) error {
	spiffeID = strings.TrimSpace(spiffeID)
	if !domain.IsKnownWorkloadID(spiffeID) {
		return fmt.Errorf("unknown workload SPIFFE ID %q", spiffeID)
	}

	return c.doJSON(
		ctx,
		http.MethodPost,
		"/internal/quarantine",
		map[string]any{
			"workload_spiffe_id": spiffeID,
			"quarantined":        quarantined,
		},
	)
}

// ReplaceQuarantined replaces the complete runtime deny set.
func (c *EnforcementClient) ReplaceQuarantined(
	ctx context.Context,
	spiffeIDs []string,
) error {
	validated := make([]string, 0, len(spiffeIDs))

	for _, spiffeID := range spiffeIDs {
		spiffeID = strings.TrimSpace(spiffeID)
		if !domain.IsKnownWorkloadID(spiffeID) {
			return fmt.Errorf("unknown workload SPIFFE ID %q", spiffeID)
		}
		validated = append(validated, spiffeID)
	}

	return c.doJSON(
		ctx,
		http.MethodPut,
		"/internal/quarantine",
		map[string]any{
			"workload_spiffe_ids": validated,
		},
	)
}

func (c *EnforcementClient) doJSON(
	ctx context.Context,
	method string,
	path string,
	value any,
) error {
	if ctx == nil {
		return errors.New("context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context is not usable: %w", err)
	}

	var body io.Reader
	if value != nil {
		encoded, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("encode Gateway request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}

	request, err := http.NewRequestWithContext(
		ctx,
		method,
		c.baseURL+path,
		body,
	)
	if err != nil {
		return fmt.Errorf("create Gateway request: %w", err)
	}

	request.Header.Set("Accept", "application/json")
	if value != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("send Gateway request: %w", err)
	}
	defer func() {
		_ = response.Body.Close()
	}()

	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read Gateway response: %w", err)
	}

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf(
			"Gateway returned HTTP %d: %s",
			response.StatusCode,
			strings.TrimSpace(string(responseBody)),
		)
	}

	return nil
}
