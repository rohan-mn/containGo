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

	"containgo.local/containgo/internal/application"
	"containgo.local/containgo/internal/domain"
)

const maxControlPlaneResponseBytes = 4 << 20

// ClientConfig contains the Dashboard-to-Control-Plane HTTP settings.
type ClientConfig struct {
	BaseURL   string
	Timeout   time.Duration
	TLSConfig *tls.Config
}

// DefaultClientConfig returns local MVP settings.
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		BaseURL: "https://127.0.0.1:8090",
		Timeout: 5 * time.Second,
	}
}

// Client reads workload state and invokes administrative Control Plane actions.
type Client struct {
	baseURL string
	http    *http.Client
}

// APIError represents an error response returned by the Control Plane.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *APIError) Error() string {
	if e == nil {
		return "control-plane request failed"
	}

	if strings.TrimSpace(e.Code) == "" {
		return fmt.Sprintf(
			"control-plane returned HTTP %d: %s",
			e.StatusCode,
			e.Message,
		)
	}

	return fmt.Sprintf(
		"control-plane returned HTTP %d (%s): %s",
		e.StatusCode,
		e.Code,
		e.Message,
	)
}

// NewClient creates a Control Plane API client.
func NewClient(config ClientConfig) (*Client, error) {
	baseURL := strings.TrimRight(
		strings.TrimSpace(config.BaseURL),
		"/",
	)
	if baseURL == "" {
		baseURL = DefaultClientConfig().BaseURL
	}

	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse control-plane URL: %w", err)
	}

	if parsed.Scheme != "https" {
		return nil, errors.New(
			"control-plane URL must use HTTPS",
		)
	}

	if parsed.Host == "" {
		return nil, errors.New(
			"control-plane URL must include a host",
		)
	}

	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New(
			"control-plane URL must not include a query or fragment",
		)
	}

	if config.TLSConfig == nil {
		return nil, errors.New(
			"Control Plane SPIFFE TLS configuration is required",
		)
	}

	if config.Timeout <= 0 {
		config.Timeout = DefaultClientConfig().Timeout
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       config.TLSConfig.Clone(),
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: config.Timeout,
		IdleConnTimeout:       60 * time.Second,
	}

	return &Client{
		baseURL: baseURL,
		http: &http.Client{
			Timeout:   config.Timeout,
			Transport: transport,
		},
	}, nil
}

// Check verifies Control Plane readiness.
func (c *Client) Check(ctx context.Context) error {
	return c.doJSON(
		ctx,
		http.MethodGet,
		"/readyz",
		nil,
		nil,
	)
}

// ListWorkloads returns every registered workload.
func (c *Client) ListWorkloads(
	ctx context.Context,
) ([]domain.Workload, error) {
	var response struct {
		Workloads []domain.Workload `json:"workloads"`
	}

	if err := c.doJSON(
		ctx,
		http.MethodGet,
		"/v1/workloads",
		nil,
		&response,
	); err != nil {
		return nil, err
	}

	return response.Workloads, nil
}

// FindWorkload returns one workload by its short registered name.
func (c *Client) FindWorkload(
	ctx context.Context,
	workloadName string,
) (domain.Workload, error) {
	var workload domain.Workload

	if err := c.doJSON(
		ctx,
		http.MethodGet,
		"/v1/workloads/"+url.PathEscape(strings.TrimSpace(workloadName)),
		nil,
		&workload,
	); err != nil {
		return domain.Workload{}, err
	}

	return workload, nil
}

// ListEvents returns a workload's newest stored security events.
func (c *Client) ListEvents(
	ctx context.Context,
	workloadName string,
	limit int,
) ([]domain.StoredEvent, error) {
	var response struct {
		Events []domain.StoredEvent `json:"events"`
	}

	path := fmt.Sprintf(
		"/v1/workloads/%s/events?limit=%d",
		url.PathEscape(strings.TrimSpace(workloadName)),
		limit,
	)

	if err := c.doJSON(
		ctx,
		http.MethodGet,
		path,
		nil,
		&response,
	); err != nil {
		return nil, err
	}

	return response.Events, nil
}

// ListIncidents returns a workload's newest quarantine incidents.
func (c *Client) ListIncidents(
	ctx context.Context,
	workloadName string,
	limit int,
) ([]domain.Incident, error) {
	var response struct {
		Incidents []domain.Incident `json:"incidents"`
	}

	path := fmt.Sprintf(
		"/v1/workloads/%s/incidents?limit=%d",
		url.PathEscape(strings.TrimSpace(workloadName)),
		limit,
	)

	if err := c.doJSON(
		ctx,
		http.MethodGet,
		path,
		nil,
		&response,
	); err != nil {
		return nil, err
	}

	return response.Incidents, nil
}

// ListAudit returns recent audit records, optionally filtered by workload.
func (c *Client) ListAudit(
	ctx context.Context,
	workloadName string,
	limit int,
) ([]domain.AuditRecord, error) {
	var response struct {
		Records []domain.AuditRecord `json:"audit_records"`
	}

	path := fmt.Sprintf("/v1/audit?limit=%d", limit)
	if strings.TrimSpace(workloadName) != "" {
		path = fmt.Sprintf(
			"/v1/workloads/%s/audit?limit=%d",
			url.PathEscape(strings.TrimSpace(workloadName)),
			limit,
		)
	}

	if err := c.doJSON(
		ctx,
		http.MethodGet,
		path,
		nil,
		&response,
	); err != nil {
		return nil, err
	}

	return response.Records, nil
}

// Release releases a quarantined workload and its open incident.
func (c *Client) Release(
	ctx context.Context,
	workloadName string,
) (application.ReleaseResult, error) {
	var result application.ReleaseResult

	if err := c.doJSON(
		ctx,
		http.MethodPost,
		"/v1/workloads/"+
			url.PathEscape(strings.TrimSpace(workloadName))+
			"/release",
		nil,
		&result,
	); err != nil {
		return application.ReleaseResult{}, err
	}

	return result, nil
}

// ResetRisk resets risk for an active workload.
func (c *Client) ResetRisk(
	ctx context.Context,
	workloadName string,
) (domain.Workload, error) {
	var workload domain.Workload

	if err := c.doJSON(
		ctx,
		http.MethodPost,
		"/v1/workloads/"+
			url.PathEscape(strings.TrimSpace(workloadName))+
			"/reset-risk",
		nil,
		&workload,
	); err != nil {
		return domain.Workload{}, err
	}

	return workload, nil
}

func (c *Client) doJSON(
	ctx context.Context,
	method string,
	path string,
	requestValue any,
	responseValue any,
) error {
	if ctx == nil {
		return errors.New("context must not be nil")
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context is not usable: %w", err)
	}

	var body io.Reader
	if requestValue != nil {
		encoded, err := json.Marshal(requestValue)
		if err != nil {
			return fmt.Errorf("encode control-plane request: %w", err)
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
		return fmt.Errorf("create control-plane request: %w", err)
	}

	request.Header.Set("Accept", "application/json")
	if requestValue != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("send control-plane request: %w", err)
	}
	defer func() {
		_ = response.Body.Close()
	}()

	responseBody, err := io.ReadAll(
		io.LimitReader(
			response.Body,
			maxControlPlaneResponseBytes,
		),
	)
	if err != nil {
		return fmt.Errorf("read control-plane response: %w", err)
	}

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var payload struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(responseBody, &payload)

		message := strings.TrimSpace(payload.Error.Message)
		if message == "" {
			message = strings.TrimSpace(string(responseBody))
		}
		if message == "" {
			message = http.StatusText(response.StatusCode)
		}

		return &APIError{
			StatusCode: response.StatusCode,
			Code:       strings.TrimSpace(payload.Error.Code),
			Message:    message,
		}
	}

	if responseValue == nil || len(bytes.TrimSpace(responseBody)) == 0 {
		return nil
	}

	if err = json.Unmarshal(responseBody, responseValue); err != nil {
		return fmt.Errorf("decode control-plane response: %w", err)
	}

	return nil
}
