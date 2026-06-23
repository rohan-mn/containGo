package workloadclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxResponseBytes = 1 << 20

// Config contains the SPIFFE mTLS settings used by a workload client to call
// the API Gateway.
type Config struct {
	BaseURL   string
	TLSConfig *tls.Config
	Timeout   time.Duration
	UserAgent string
}

// Response contains the relevant result of one Gateway request.
type Response struct {
	Method     string
	Path       string
	StatusCode int
	Body       []byte
	ReceivedAt time.Time
}

// Successful reports whether the Gateway returned a 2xx response.
func (r Response) Successful() bool {
	return r.StatusCode >= 200 && r.StatusCode < 300
}

// Client calls the API Gateway using a Workload API-backed X.509-SVID.
type Client struct {
	baseURL   string
	userAgent string
	http      *http.Client
}

// New creates a SPIFFE mTLS workload client.
func New(config Config) (*Client, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(config.BaseURL), "/")
	if baseURL == "" {
		baseURL = "https://127.0.0.1:8443"
	}

	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse Gateway URL: %w", err)
	}

	if parsedURL.Scheme != "https" {
		return nil, errors.New("Gateway URL must use HTTPS")
	}

	if parsedURL.Host == "" {
		return nil, errors.New("Gateway URL must include a host")
	}

	if config.TLSConfig == nil {
		return nil, errors.New("SPIFFE client TLS configuration is required")
	}

	if config.Timeout <= 0 {
		config.Timeout = 10 * time.Second
	}

	userAgent := strings.TrimSpace(config.UserAgent)
	if userAgent == "" {
		userAgent = "containgo-workload-client/1.0"
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: config.Timeout,
		IdleConnTimeout:       60 * time.Second,
		MaxIdleConns:          20,
		MaxIdleConnsPerHost:   10,
		TLSClientConfig:       config.TLSConfig.Clone(),
	}

	return &Client{
		baseURL:   baseURL,
		userAgent: userAgent,
		http: &http.Client{
			Timeout:   config.Timeout,
			Transport: transport,
		},
	}, nil
}

// Get performs one authenticated GET request against a protected Gateway
// route. Non-2xx responses are returned normally so callers can display deny
// and quarantine behavior.
func (c *Client) Get(
	ctx context.Context,
	path string,
) (Response, error) {
	if ctx == nil {
		return Response{}, errors.New("context must not be nil")
	}

	if err := ctx.Err(); err != nil {
		return Response{}, fmt.Errorf("context is not usable: %w", err)
	}

	path = strings.TrimSpace(path)
	if !strings.HasPrefix(path, "/api/") {
		return Response{}, errors.New("workload request path must start with /api/")
	}

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		c.baseURL+path,
		nil,
	)
	if err != nil {
		return Response{}, fmt.Errorf("create Gateway request: %w", err)
	}

	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", c.userAgent)

	response, err := c.http.Do(request)
	if err != nil {
		return Response{}, fmt.Errorf("call API Gateway: %w", err)
	}
	defer func() {
		_ = response.Body.Close()
	}()

	body, err := io.ReadAll(
		io.LimitReader(response.Body, maxResponseBytes),
	)
	if err != nil {
		return Response{}, fmt.Errorf("read Gateway response: %w", err)
	}

	return Response{
		Method:     http.MethodGet,
		Path:       path,
		StatusCode: response.StatusCode,
		Body:       body,
		ReceivedAt: time.Now().UTC(),
	}, nil
}
