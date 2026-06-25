package controlservice

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"containgo.local/containgo/internal/platform"
)

type Server struct {
	Store         *Store
	Files         platform.IdentityFiles
	SPIFFEID      string
	ListenAddress string
	HealthAddress string
}

func NewServer(store *Store, listenAddress, healthAddress string) *Server {
	return &Server{
		Store:         store,
		Files:         platform.DefaultIdentityFiles(),
		SPIFFEID:      "spiffe://containgo.local/ns/containgo/sa/control-plane",
		ListenAddress: listenAddress,
		HealthAddress: healthAddress,
	}
}

func (s *Server) Run(ctx context.Context) error {
	platform.ServeHealth(s.HealthAddress, func() error { return platform.ReadyIdentity(s.Files) })
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/identity", s.handleIdentity)
	mux.HandleFunc("GET /v1/workloads", s.handleWorkloads)
	mux.HandleFunc("GET /v1/workloads/resolve", s.handleResolve)
	mux.HandleFunc("GET /v1/workloads/{name}", s.handleWorkload)
	mux.HandleFunc("POST /v1/workloads/{name}/release", s.handleRelease)
	mux.HandleFunc("POST /v1/workloads/{name}/reset-risk", s.handleResetRisk)
	mux.HandleFunc("POST /v1/events", s.handleEvent)
	mux.HandleFunc("GET /v1/events", s.handleEvents)
	mux.HandleFunc("GET /v1/traces/{id}", s.handleTrace)
	mux.HandleFunc("GET /v1/incidents", s.handleIncidents)
	mux.HandleFunc("GET /v1/config", s.handleConfig)

	tlsConfig := platform.DynamicServerTLS(s.Files, func(peerID string) bool {
		return peerID == "spiffe://containgo.local/ns/containgo/sa/api-gateway" ||
			peerID == "spiffe://containgo.local/ns/containgo/sa/dashboard"
	})
	server := &http.Server{
		Handler:           loggingMiddleware(mux),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	listener, err := tls.Listen("tcp", s.ListenAddress, tlsConfig)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	log.Printf("control-plane listening on %s", s.ListenAddress)
	return server.Serve(listener)
}

func (s *Server) handleIdentity(w http.ResponseWriter, _ *http.Request) {
	info, err := platform.LoadIdentityInfo(s.Files, "control-plane")
	if err != nil {
		platform.WriteError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	platform.WriteJSON(w, http.StatusOK, info)
}

func (s *Server) handleWorkloads(w http.ResponseWriter, _ *http.Request) {
	platform.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"threshold": s.Store.Threshold(),
		"workloads": s.Store.Workloads(),
	})
}

func (s *Server) handleResolve(w http.ResponseWriter, r *http.Request) {
	workload, ok := s.Store.ResolveSPIFFEID(r.URL.Query().Get("spiffe_id"))
	if !ok {
		platform.WriteError(w, http.StatusNotFound, "workload not found")
		return
	}
	platform.WriteJSON(w, http.StatusOK, workload)
}

func (s *Server) handleWorkload(w http.ResponseWriter, r *http.Request) {
	workload, ok := s.Store.Workload(r.PathValue("name"))
	if !ok {
		platform.WriteError(w, http.StatusNotFound, "workload not found")
		return
	}
	platform.WriteJSON(w, http.StatusOK, workload)
}

func (s *Server) handleEvent(w http.ResponseWriter, r *http.Request) {
	if platform.PeerSPIFFEID(r) != "spiffe://containgo.local/ns/containgo/sa/api-gateway" {
		platform.WriteError(w, http.StatusForbidden, "only the API Gateway can publish trusted decision events")
		return
	}
	var event platform.DecisionEvent
	if err := platform.DecodeJSON(r, &event); err != nil {
		platform.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if event.TraceID == "" || event.SPIFFEID == "" || event.Workload == "" {
		platform.WriteError(w, http.StatusBadRequest, "trace_id, workload and spiffe_id are required")
		return
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Now().UTC()
	}
	peerID := platform.PeerSPIFFEID(r)
	metadata := platform.TLSMetadataFromState(r.TLS, peerID)
	metadata.SourceSPIFFEID = peerID
	metadata.PeerSPIFFEID = s.SPIFFEID
	hop := &platform.TraceHop{
		From:       "api-gateway",
		To:         "control-plane",
		Stage:      "control-plane.event.persisted",
		Status:     "received",
		OccurredAt: time.Now().UTC(),
		TLS:        metadata,
		Details:    "Trusted Gateway decision delivered over SPIFFE mTLS",
	}
	stored, err := s.Store.Process(event, hop)
	if err != nil {
		platform.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	platform.WriteJSON(w, http.StatusAccepted, stored)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	platform.WriteJSON(w, http.StatusOK, map[string]interface{}{"events": s.Store.Events(after, limit)})
}

func (s *Server) handleTrace(w http.ResponseWriter, r *http.Request) {
	events := s.Store.Trace(r.PathValue("id"))
	if len(events) == 0 {
		platform.WriteError(w, http.StatusNotFound, "trace not found")
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]interface{}{"trace_id": r.PathValue("id"), "events": events})
}

func (s *Server) handleIncidents(w http.ResponseWriter, _ *http.Request) {
	platform.WriteJSON(w, http.StatusOK, map[string]interface{}{"incidents": s.Store.Incidents()})
}

func (s *Server) handleRelease(w http.ResponseWriter, r *http.Request) {
	if !isAdministrator(platform.PeerSPIFFEID(r)) {
		platform.WriteError(w, http.StatusForbidden, "administrator identity required")
		return
	}
	workload, err := s.Store.Release(r.PathValue("name"), platform.PeerSPIFFEID(r))
	if err != nil {
		platform.WriteError(w, http.StatusConflict, err.Error())
		return
	}
	platform.WriteJSON(w, http.StatusOK, workload)
}

func (s *Server) handleResetRisk(w http.ResponseWriter, r *http.Request) {
	if !isAdministrator(platform.PeerSPIFFEID(r)) {
		platform.WriteError(w, http.StatusForbidden, "administrator identity required")
		return
	}
	workload, err := s.Store.ResetRisk(r.PathValue("name"), platform.PeerSPIFFEID(r))
	if err != nil {
		platform.WriteError(w, http.StatusConflict, err.Error())
		return
	}
	platform.WriteJSON(w, http.StatusOK, workload)
}

func (s *Server) handleConfig(w http.ResponseWriter, _ *http.Request) {
	platform.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"risk_threshold": s.Store.Threshold(),
		"rules": []map[string]interface{}{
			{"name": "unauthorized_request", "points": 25},
			{"name": "highly_sensitive_endpoint_attempt", "points": 40},
			{"name": "administrative_endpoint_attempt", "points": 35},
			{"name": "rate_anomaly", "points": 50, "window": "more than 20 requests in 5 seconds"},
		},
	})
}

func isAdministrator(id string) bool {
	return id == "spiffe://containgo.local/ns/containgo/sa/dashboard"
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("component=control-plane method=%s path=%s peer=%s duration=%s", r.Method, r.URL.Path, platform.PeerSPIFFEID(r), time.Since(started))
	})
}

func ParseAddress(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func ValidateStore(store *Store) error {
	if store == nil {
		return fmt.Errorf("store is required")
	}
	return nil
}
