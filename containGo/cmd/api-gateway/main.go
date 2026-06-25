package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"containgo.local/containgo/internal/platform"
)

const (
	gatewayID      = "spiffe://containgo.local/ns/containgo/sa/api-gateway"
	protectedAPIID = "spiffe://containgo.local/ns/containgo/sa/protected-api"
	controlPlaneID = "spiffe://containgo.local/ns/containgo/sa/control-plane"
	orderClientID  = "spiffe://containgo.local/ns/containgo/sa/order-client"
	reportClientID = "spiffe://containgo.local/ns/containgo/sa/report-client"
	dashboardID    = "spiffe://containgo.local/ns/containgo/sa/dashboard"
)

type gateway struct {
	files           platform.IdentityFiles
	opaURL          string
	protectedAPIURL string
	controlPlaneURL string
	opaClient       *http.Client
	protectedClient *http.Client
	controlClient   *http.Client
}

type opaResponse struct {
	Result bool `json:"result"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	files := platform.DefaultIdentityFiles()
	g := &gateway{
		files:           files,
		opaURL:          env("OPA_URL", "http://127.0.0.1:8181/v1/data/containgo/authz/allow"),
		protectedAPIURL: strings.TrimRight(env("PROTECTED_API_URL", "https://protected-api:8443"), "/"),
		controlPlaneURL: strings.TrimRight(env("CONTROL_PLANE_URL", "https://control-plane:8443"), "/"),
		opaClient:       &http.Client{Timeout: 5 * time.Second},
		protectedClient: platform.MTLSHTTPClient(files, protectedAPIID, 20*time.Second).HTTPClient(),
		controlClient:   platform.MTLSHTTPClient(files, controlPlaneID, 20*time.Second).HTTPClient(),
	}
	if err := g.run(ctx); err != nil {
		log.Fatal(err)
	}
}

func (g *gateway) run(ctx context.Context) error {
	platform.ServeHealth(env("HEALTH_ADDR", ":8081"), func() error {
		if err := platform.ReadyIdentity(g.files); err != nil {
			return err
		}
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, strings.TrimSuffix(g.opaURL, "/v1/data/containgo/authz/allow")+"/health", nil)
		resp, err := g.opaClient.Do(req)
		if err != nil {
			return fmt.Errorf("OPA is unavailable: %w", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 500 {
			return fmt.Errorf("OPA readiness returned HTTP %d", resp.StatusCode)
		}
		return nil
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/identity", g.handleIdentity)
	mux.HandleFunc("GET /v1/policy", g.handlePolicyInfo)
	mux.HandleFunc("/api/", g.handleBusiness)

	tlsConfig := platform.DynamicServerTLS(g.files, func(peerID string) bool {
		return peerID == orderClientID || peerID == reportClientID || peerID == dashboardID
	})
	server := &http.Server{
		Handler:           requestLogger(mux),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	listener, err := tls.Listen("tcp", env("LISTEN_ADDR", ":8443"), tlsConfig)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	log.Printf("api-gateway listening on %s", env("LISTEN_ADDR", ":8443"))
	return server.Serve(listener)
}

func (g *gateway) handleIdentity(w http.ResponseWriter, _ *http.Request) {
	info, err := platform.LoadIdentityInfo(g.files, "api-gateway")
	if err != nil {
		platform.WriteError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	platform.WriteJSON(w, http.StatusOK, info)
}

func (g *gateway) handlePolicyInfo(w http.ResponseWriter, _ *http.Request) {
	platform.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"engine":  "Open Policy Agent sidecar",
		"input":   []string{"authenticated SPIFFE ID", "HTTP method", "path", "quarantine status"},
		"catalog": platform.EndpointCatalog(),
	})
}

func (g *gateway) handleBusiness(w http.ResponseWriter, r *http.Request) {
	callerID := platform.PeerSPIFFEID(r)
	if callerID != orderClientID && callerID != reportClientID {
		platform.WriteError(w, http.StatusForbidden, "business requests must originate from order-client or report-client")
		return
	}
	body, err := platform.ReadBody(r)
	if err != nil {
		platform.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	traceID := strings.TrimSpace(r.Header.Get("X-ContainGo-Trace-ID"))
	if traceID == "" {
		traceID = platform.NewID("trace")
	}
	gatewayRequestID := platform.NewID("gateway")
	workloadName := platform.WorkloadFromSPIFFEID(callerID)
	identity, err := platform.LoadIdentityInfo(g.files, "api-gateway")
	if err != nil {
		platform.WriteError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	workloadState, err := g.resolveWorkload(r.Context(), callerID, identity.SPIFFEID)
	if err != nil {
		platform.WriteError(w, http.StatusServiceUnavailable, "control-plane state lookup failed: "+err.Error())
		return
	}
	quarantined := workloadState.Status == "quarantined"
	allowed, err := g.authorize(r.Context(), callerID, workloadName, r.Method, r.URL.Path, quarantined)
	if err != nil {
		platform.WriteError(w, http.StatusServiceUnavailable, "OPA authorization failed: "+err.Error())
		return
	}

	inboundTLS := platform.TLSMetadataFromState(r.TLS, callerID)
	inboundTLS.SourceSPIFFEID = callerID
	inboundTLS.PeerSPIFFEID = gatewayID
	hops := []platform.TraceHop{
		{
			From:       workloadName,
			To:         "api-gateway",
			Stage:      "gateway.mtls.authenticated",
			Status:     "authenticated",
			OccurredAt: time.Now().UTC(),
			TLS:        inboundTLS,
			Details:    "Gateway verified the caller X.509-SVID against the SPIFFE trust bundle",
		},
		{
			From:       "api-gateway",
			To:         "opa",
			Stage:      "opa.decision.completed",
			Status:     map[bool]string{true: "allow", false: "deny"}[allowed],
			OccurredAt: time.Now().UTC(),
			TLS: platform.TLSMetadata{
				Protocol:       "localhost HTTP",
				SourceSPIFFEID: gatewayID,
				PeerSPIFFEID:   "OPA sidecar",
			},
			Details: fmt.Sprintf("OPA evaluated identity=%s method=%s path=%s quarantined=%t", callerID, r.Method, r.URL.Path, quarantined),
		},
	}

	decision := "deny"
	reason := "OPA policy denied the authenticated identity, method and path"
	statusCode := http.StatusForbidden
	responseBody := []byte(nil)
	if quarantined {
		reason = "workload is quarantined"
	}
	if allowed {
		decision = "allow"
		reason = "OPA policy allowed the authenticated identity, method and path"
		forwardResult, forwardErr := platform.DoRequest(r.Context(), g.protectedClient, r.Method, g.protectedAPIURL+r.URL.Path, body, map[string]string{
			"X-ContainGo-Trace-ID":   traceID,
			"X-ContainGo-Request-ID": gatewayRequestID,
		}, identity.SPIFFEID)
		if forwardErr != nil {
			decision = "error"
			reason = "protected API forwarding failed: " + forwardErr.Error()
			statusCode = http.StatusBadGateway
			responseBody, _ = json.Marshal(map[string]interface{}{"error": reason, "trace_id": traceID})
		} else {
			statusCode = forwardResult.StatusCode
			responseBody = forwardResult.Body
			hops = append(hops, platform.TraceHop{
				From:       "api-gateway",
				To:         "protected-api",
				Stage:      "protected-api.forwarded",
				Status:     fmt.Sprintf("HTTP %d", forwardResult.StatusCode),
				OccurredAt: time.Now().UTC(),
				TLS:        forwardResult.TLS,
				Details:    "Gateway re-originated the authorized request using its own X.509-SVID",
			})
		}
	} else {
		responseBody, _ = json.Marshal(map[string]interface{}{
			"decision":  "deny",
			"reason":    reason,
			"trace_id":  traceID,
			"workload":  workloadName,
			"spiffe_id": callerID,
		})
	}

	event := platform.DecisionEvent{
		TraceID:        traceID,
		GatewayRequest: gatewayRequestID,
		Workload:       workloadName,
		SPIFFEID:       callerID,
		Method:         r.Method,
		Path:           r.URL.Path,
		Decision:       decision,
		Reason:         reason,
		StatusCode:     statusCode,
		OccurredAt:     time.Now().UTC(),
		Hops:           hops,
		RequestBody:    truncate(string(body), 2048),
		ResponseBody:   truncate(string(responseBody), 4096),
	}
	stored, publishErr := g.publishEvent(r.Context(), event, identity.SPIFFEID)
	w.Header().Set("X-ContainGo-Trace-ID", traceID)
	w.Header().Set("X-ContainGo-Request-ID", gatewayRequestID)
	w.Header().Set("X-ContainGo-Decision", decision)
	if publishErr == nil {
		w.Header().Set("X-ContainGo-Risk-After", fmt.Sprintf("%d", stored.RiskAfter))
		w.Header().Set("X-ContainGo-Quarantined", fmt.Sprintf("%t", stored.Quarantined))
	}
	if len(responseBody) == 0 {
		responseBody, _ = json.Marshal(map[string]interface{}{"trace_id": traceID, "status": statusCode})
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	_, _ = w.Write(responseBody)
}

func (g *gateway) resolveWorkload(ctx context.Context, spiffeID, sourceID string) (platform.WorkloadState, error) {
	endpoint := g.controlPlaneURL + "/v1/workloads/resolve?spiffe_id=" + url.QueryEscape(spiffeID)
	result, err := platform.DoRequest(ctx, g.controlClient, http.MethodGet, endpoint, nil, nil, sourceID)
	if err != nil {
		return platform.WorkloadState{}, err
	}
	if result.StatusCode != http.StatusOK {
		return platform.WorkloadState{}, fmt.Errorf("HTTP %d: %s", result.StatusCode, strings.TrimSpace(string(result.Body)))
	}
	var workload platform.WorkloadState
	if err := json.Unmarshal(result.Body, &workload); err != nil {
		return platform.WorkloadState{}, err
	}
	return workload, nil
}

func (g *gateway) authorize(ctx context.Context, spiffeID, workload, method, path string, quarantined bool) (bool, error) {
	payload := map[string]interface{}{
		"input": map[string]interface{}{
			"spiffe_id":   spiffeID,
			"workload":    workload,
			"method":      strings.ToUpper(method),
			"path":        path,
			"quarantined": quarantined,
		},
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.opaURL, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.opaClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return false, err
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("OPA returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}
	var result opaResponse
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return false, err
	}
	return result.Result, nil
}

func (g *gateway) publishEvent(ctx context.Context, event platform.DecisionEvent, sourceID string) (platform.StoredEvent, error) {
	payload, _ := json.Marshal(event)
	result, err := platform.DoRequest(ctx, g.controlClient, http.MethodPost, g.controlPlaneURL+"/v1/events", payload, nil, sourceID)
	if err != nil {
		return platform.StoredEvent{}, err
	}
	if result.StatusCode != http.StatusAccepted {
		return platform.StoredEvent{}, fmt.Errorf("control-plane returned HTTP %d: %s", result.StatusCode, strings.TrimSpace(string(result.Body)))
	}
	var stored platform.StoredEvent
	if err := json.Unmarshal(result.Body, &stored); err != nil {
		return platform.StoredEvent{}, err
	}
	return stored, nil
}

func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("component=api-gateway method=%s path=%s peer=%s trace=%s duration=%s", r.Method, r.URL.Path, platform.PeerSPIFFEID(r), r.Header.Get("X-ContainGo-Trace-ID"), time.Since(started))
	})
}

func truncate(value string, maximum int) string {
	if len(value) <= maximum {
		return value
	}
	return value[:maximum] + "…"
}

func env(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
