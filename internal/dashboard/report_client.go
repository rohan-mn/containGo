package dashboard

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

	"containgo.local/containgo/internal/reportclient"
)

const maxReportClientResponseBytes = 1 << 20

// ReportClientConfig contains the Dashboard-to-Report-Client control settings.
type ReportClientConfig struct {
	BaseURL   string
	Timeout   time.Duration
	TLSConfig *tls.Config
}

// DefaultReportClientConfig returns the local control API defaults.
func DefaultReportClientConfig() ReportClientConfig {
	return ReportClientConfig{
		BaseURL: "https://127.0.0.1:8072",
		Timeout: 5 * time.Second,
	}
}

// ReportClient controls the demonstration workload over SPIFFE mTLS.
type ReportClient struct {
	baseURL string
	http    *http.Client
}

// NewReportClient creates a SPIFFE-authenticated Report Client control client.
func NewReportClient(config ReportClientConfig) (*ReportClient, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(config.BaseURL), "/")
	if baseURL == "" {
		baseURL = DefaultReportClientConfig().BaseURL
	}

	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse Report Client URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return nil, errors.New("Report Client URL must use HTTPS")
	}
	if parsed.Host == "" {
		return nil, errors.New("Report Client URL must include a host")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("Report Client URL must not include a query or fragment")
	}
	if config.TLSConfig == nil {
		return nil, errors.New("Report Client SPIFFE TLS configuration is required")
	}
	if config.Timeout <= 0 {
		config.Timeout = DefaultReportClientConfig().Timeout
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       config.TLSConfig.Clone(),
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: config.Timeout,
		IdleConnTimeout:       60 * time.Second,
	}

	return &ReportClient{
		baseURL: baseURL,
		http: &http.Client{
			Timeout:   config.Timeout,
			Transport: transport,
		},
	}, nil
}

// Snapshot returns the current demonstration mode and request counters.
func (c *ReportClient) Snapshot(ctx context.Context) (reportclient.Snapshot, error) {
	var snapshot reportclient.Snapshot
	if err := c.doJSON(ctx, http.MethodGet, "/v1/mode", nil, &snapshot); err != nil {
		return reportclient.Snapshot{}, err
	}
	return snapshot, nil
}

// SetMode changes Report Client behavior.
func (c *ReportClient) SetMode(
	ctx context.Context,
	mode reportclient.Mode,
) (reportclient.Snapshot, error) {
	var snapshot reportclient.Snapshot
	if err := c.doJSON(
		ctx,
		http.MethodPost,
		"/v1/mode",
		map[string]string{"mode": string(mode)},
		&snapshot,
	); err != nil {
		return reportclient.Snapshot{}, err
	}
	return snapshot, nil
}

// ResetStats clears the Report Client's in-memory demonstration counters.
func (c *ReportClient) ResetStats(ctx context.Context) (reportclient.Snapshot, error) {
	var snapshot reportclient.Snapshot
	if err := c.doJSON(ctx, http.MethodPost, "/v1/reset", nil, &snapshot); err != nil {
		return reportclient.Snapshot{}, err
	}
	return snapshot, nil
}

func (c *ReportClient) doJSON(
	ctx context.Context,
	method string,
	path string,
	requestValue any,
	responseValue any,
) error {
	if ctx == nil {
		return errors.New("context must not be nil")
	}
	if c == nil || c.http == nil {
		return errors.New("Report Client control client is not configured")
	}

	var body io.Reader
	if requestValue != nil {
		encoded, err := json.Marshal(requestValue)
		if err != nil {
			return fmt.Errorf("encode Report Client request: %w", err)
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
		return fmt.Errorf("create Report Client request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	if requestValue != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("send Report Client request: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxReportClientResponseBytes))
	if err != nil {
		return fmt.Errorf("read Report Client response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message := strings.TrimSpace(string(responseBody))
		if message == "" {
			message = http.StatusText(response.StatusCode)
		}
		return fmt.Errorf("Report Client returned HTTP %d: %s", response.StatusCode, message)
	}
	if responseValue == nil || len(bytes.TrimSpace(responseBody)) == 0 {
		return nil
	}
	if err = json.Unmarshal(responseBody, responseValue); err != nil {
		return fmt.Errorf("decode Report Client response: %w", err)
	}
	return nil
}
