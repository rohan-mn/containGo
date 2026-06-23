package apigateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// UpstreamConfig configures the internal Protected API connection.
type UpstreamConfig struct {
	BaseURL   string
	Timeout   time.Duration
	TLSConfig *tls.Config
}

// Upstream proxies authorized requests to the internal Protected API.
type Upstream struct {
	baseURL    *url.URL
	httpClient *http.Client
	proxy      *httputil.ReverseProxy
}

// NewUpstream creates the reverse proxy and its SPIFFE mTLS transport.
func NewUpstream(config UpstreamConfig) (*Upstream, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(config.BaseURL), "/")
	if baseURL == "" {
		baseURL = "https://127.0.0.1:8080"
	}

	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse protected API URL: %w", err)
	}

	if parsed.Scheme != "https" {
		return nil, errors.New("protected API upstream must use HTTPS")
	}

	if parsed.Host == "" {
		return nil, errors.New("protected API upstream URL must include a host")
	}

	if config.Timeout <= 0 {
		config.Timeout = 10 * time.Second
	}

	if config.TLSConfig == nil {
		return nil, errors.New("Protected API SPIFFE TLS configuration is required")
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       config.TLSConfig.Clone(),
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: config.Timeout,
		ExpectContinueTimeout: time.Second,
		IdleConnTimeout:       60 * time.Second,
		MaxIdleConns:          20,
		MaxIdleConnsPerHost:   10,
	}

	proxy := httputil.NewSingleHostReverseProxy(parsed)
	proxy.Director = nil
	proxy.Transport = transport
	proxy.FlushInterval = 100 * time.Millisecond
	proxy.Rewrite = func(proxyRequest *httputil.ProxyRequest) {
		proxyRequest.SetURL(parsed)
		proxyRequest.SetXForwarded()

		// Never forward caller-supplied identity hints. The Protected API
		// authenticates the Gateway from its X.509-SVID.
		for _, header := range []string{
			"X-Spiffe-Id",
			"X-SPIFFE-ID",
			"X-Forwarded-Client-Cert",
			"X-ContainGo-Identity",
		} {
			proxyRequest.Out.Header.Del(header)
		}

		proxyRequest.Out.Header.Set(
			"User-Agent",
			"ContainGo-API-Gateway/1.0",
		)
	}
	proxy.ModifyResponse = func(response *http.Response) error {
		response.Header.Set("Cache-Control", "no-store")
		return nil
	}
	proxy.ErrorHandler = func(
		writer http.ResponseWriter,
		_ *http.Request,
		proxyErr error,
	) {
		writeJSON(writer, http.StatusBadGateway, map[string]any{
			"error": map[string]string{
				"code":    "upstream_unavailable",
				"message": "protected API is unavailable",
			},
		})
		_ = proxyErr
	}

	return &Upstream{
		baseURL: parsed,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   config.Timeout,
		},
		proxy: proxy,
	}, nil
}

// ServeHTTP forwards an already authorized request.
func (u *Upstream) ServeHTTP(
	writer http.ResponseWriter,
	request *http.Request,
) {
	u.proxy.ServeHTTP(writer, request)
}

// Check verifies that the internal Protected API is healthy over SPIFFE mTLS.
func (u *Upstream) Check(ctx context.Context) error {
	if ctx == nil {
		return errors.New("context must not be nil")
	}

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		u.baseURL.String()+"/healthz",
		nil,
	)
	if err != nil {
		return fmt.Errorf("create upstream health request: %w", err)
	}

	response, err := u.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("call protected API health endpoint: %w", err)
	}
	defer func() {
		_ = response.Body.Close()
	}()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf(
			"protected API health returned HTTP %d",
			response.StatusCode,
		)
	}

	return nil
}
