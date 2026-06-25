package platform

import (
	"net"
	"net/http"
	"time"
)

type httpClientWrapper struct {
	client *http.Client
}

func newHTTPClientWrapper(files IdentityFiles, expectedPeer string, timeout time.Duration) *httpClientWrapper {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSClientConfig:       DynamicClientTLS(files, expectedPeer),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   50,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 20 * time.Second,
		}).DialContext,
	}
	return &httpClientWrapper{client: &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

func (w *httpClientWrapper) HTTPClient() *http.Client { return w.client }
