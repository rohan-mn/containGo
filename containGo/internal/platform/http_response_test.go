package platform

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDoRequestReadsNormalJSONResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"events":[{"id":1}]}`)
	}))
	defer server.Close()

	result, err := DoRequest(context.Background(), server.Client(), http.MethodGet, server.URL, nil, nil, "")
	if err != nil {
		t.Fatalf("DoRequest returned error: %v", err)
	}
	if got, want := string(result.Body), `{"events":[{"id":1}]}`; got != want {
		t.Fatalf("unexpected body: got %q want %q", got, want)
	}
}

func TestDoRequestRejectsOversizedResponseInsteadOfTruncating(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", 4*1024*1024+1))
	}))
	defer server.Close()

	_, err := DoRequest(context.Background(), server.Client(), http.MethodGet, server.URL, nil, nil, "")
	if err == nil {
		t.Fatal("expected an oversized-response error")
	}
	if !strings.Contains(err.Error(), "exceeds 4194304 bytes") {
		t.Fatalf("unexpected error: %v", err)
	}
}
