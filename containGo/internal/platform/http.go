package platform

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const MaxBodyBytes = 64 * 1024

func WriteJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func WriteError(w http.ResponseWriter, status int, message string) {
	WriteJSON(w, status, map[string]interface{}{"error": message, "status": status})
}

func DecodeJSON(r *http.Request, dst interface{}) error {
	if r.Body == nil {
		return errors.New("request body is required")
	}
	defer r.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(r.Body, MaxBodyBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	return nil
}

func ReadBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	defer r.Body.Close()
	limited := io.LimitReader(r.Body, MaxBodyBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(body) > MaxBodyBytes {
		return nil, fmt.Errorf("request body exceeds %d bytes", MaxBodyBytes)
	}
	return body, nil
}

func NewID(prefix string) string {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	}
	return prefix + "-" + hex.EncodeToString(buf)
}

func PeerSPIFFEID(r *http.Request) string {
	if r == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	return CertificateSPIFFEID(r.TLS.PeerCertificates[0])
}

func TLSMetadataFromState(state *tls.ConnectionState, sourceID string) TLSMetadata {
	metadata := TLSMetadata{Protocol: "mTLS", SourceSPIFFEID: sourceID}
	if state == nil {
		return metadata
	}
	metadata.TLSVersion = TLSVersionName(state.Version)
	metadata.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	if len(state.PeerCertificates) > 0 {
		peer := state.PeerCertificates[0]
		metadata.PeerSPIFFEID = CertificateSPIFFEID(peer)
		metadata.SerialNumber = peer.SerialNumber.Text(16)
		metadata.ValidFrom = peer.NotBefore.UTC()
		metadata.ValidUntil = peer.NotAfter.UTC()
	}
	return metadata
}

func TLSVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	default:
		return fmt.Sprintf("0x%x", version)
	}
}

type HTTPResult struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	TLS        TLSMetadata
}

func DoRequest(ctx context.Context, client *http.Client, method, url string, body []byte, headers map[string]string, sourceID string) (HTTPResult, error) {
	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(method), url, reader)
	if err != nil {
		return HTTPResult{}, err
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		return HTTPResult{}, err
	}
	defer resp.Body.Close()
	responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if readErr != nil {
		return HTTPResult{}, readErr
	}
	return HTTPResult{
		StatusCode: resp.StatusCode,
		Header:     resp.Header.Clone(),
		Body:       responseBody,
		TLS:        TLSMetadataFromState(resp.TLS, sourceID),
	}, nil
}

func ServeHealth(addr string, ready func() error) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		WriteJSON(w, http.StatusOK, map[string]string{"status": "healthy"})
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if err := ready(); err != nil {
			WriteError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		WriteJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})
	server := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.ListenAndServe() }()
	return server
}
