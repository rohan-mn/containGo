package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"containgo.local/containgo/internal/platform"
)

const (
	gatewayID   = "spiffe://containgo.local/ns/containgo/sa/api-gateway"
	dashboardID = "spiffe://containgo.local/ns/containgo/sa/dashboard"
)

type apiServer struct {
	files   platform.IdentityFiles
	mu      sync.RWMutex
	orders  map[string]map[string]interface{}
	reports []map[string]interface{}
	config  map[string]interface{}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	server := &apiServer{
		files: platform.DefaultIdentityFiles(),
		orders: map[string]map[string]interface{}{
			"ORD-1001": {"id": "ORD-1001", "customer": "CUST-41", "amount": 1299.00, "status": "approved"},
			"ORD-1002": {"id": "ORD-1002", "customer": "CUST-72", "amount": 449.50, "status": "processing"},
		},
		reports: []map[string]interface{}{
			{"id": "RPT-DAILY", "name": "Daily settlement summary", "status": "ready"},
			{"id": "RPT-RISK", "name": "Workload risk summary", "status": "ready"},
		},
		config: map[string]interface{}{"maintenance_mode": false, "payment_limit": 5000},
	}
	if err := server.run(ctx); err != nil {
		log.Fatal(err)
	}
}

func (s *apiServer) run(ctx context.Context) error {
	platform.ServeHealth(env("HEALTH_ADDR", ":8081"), func() error { return platform.ReadyIdentity(s.files) })
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/identity", s.identity)
	mux.HandleFunc("GET /api/orders", s.business(s.listOrders))
	mux.HandleFunc("POST /api/orders", s.business(s.createOrder))
	mux.HandleFunc("PUT /api/orders/{id}", s.business(s.updateOrder))
	mux.HandleFunc("DELETE /api/orders/{id}", s.business(s.deleteOrder))
	mux.HandleFunc("GET /api/reports", s.business(s.listReports))
	mux.HandleFunc("POST /api/reports/generate", s.business(s.generateReport))
	mux.HandleFunc("GET /api/customers", s.business(s.listCustomers))
	mux.HandleFunc("GET /api/payment-details", s.business(s.paymentDetails))
	mux.HandleFunc("PUT /api/admin/config", s.business(s.updateConfig))
	mux.HandleFunc("POST /api/admin/config", s.business(s.updateConfig))

	tlsConfig := platform.DynamicServerTLS(s.files, func(peerID string) bool {
		return peerID == gatewayID || peerID == dashboardID
	})
	httpServer := &http.Server{
		Handler:           requestLogger(mux),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
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
		_ = httpServer.Shutdown(shutdownCtx)
	}()
	log.Printf("protected-api listening on %s", env("LISTEN_ADDR", ":8443"))
	return httpServer.Serve(listener)
}

func (s *apiServer) business(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if platform.PeerSPIFFEID(r) != gatewayID {
			platform.WriteError(w, http.StatusForbidden, "protected business endpoints accept only the API Gateway SPIFFE identity")
			return
		}
		next(w, r)
	}
}

func (s *apiServer) identity(w http.ResponseWriter, _ *http.Request) {
	info, err := platform.LoadIdentityInfo(s.files, "protected-api")
	if err != nil {
		platform.WriteError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	platform.WriteJSON(w, http.StatusOK, info)
}

func (s *apiServer) listOrders(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	orders := make([]map[string]interface{}, 0, len(s.orders))
	for _, order := range s.orders {
		orders = append(orders, cloneMap(order))
	}
	respond(w, r, http.StatusOK, map[string]interface{}{"orders": orders})
}

func (s *apiServer) createOrder(w http.ResponseWriter, r *http.Request) {
	var input map[string]interface{}
	if err := platform.DecodeJSON(r, &input); err != nil {
		platform.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id := fmt.Sprintf("ORD-%d", 1000+len(s.orders)+1)
	input["id"] = id
	if _, ok := input["status"]; !ok {
		input["status"] = "created"
	}
	s.orders[id] = cloneMap(input)
	respond(w, r, http.StatusCreated, map[string]interface{}{"order": input})
}

func (s *apiServer) updateOrder(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var input map[string]interface{}
	if err := platform.DecodeJSON(r, &input); err != nil {
		platform.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	order, ok := s.orders[id]
	if !ok {
		platform.WriteError(w, http.StatusNotFound, "order not found")
		return
	}
	for key, value := range input {
		order[key] = value
	}
	order["id"] = id
	respond(w, r, http.StatusOK, map[string]interface{}{"order": order})
}

func (s *apiServer) deleteOrder(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.orders[id]; !ok {
		platform.WriteError(w, http.StatusNotFound, "order not found")
		return
	}
	delete(s.orders, id)
	respond(w, r, http.StatusOK, map[string]interface{}{"deleted": id})
}

func (s *apiServer) listReports(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	respond(w, r, http.StatusOK, map[string]interface{}{"reports": s.reports})
}

func (s *apiServer) generateReport(w http.ResponseWriter, r *http.Request) {
	var input map[string]interface{}
	if err := platform.DecodeJSON(r, &input); err != nil {
		platform.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	report := map[string]interface{}{
		"id":           platform.NewID("report"),
		"name":         valueOr(input, "name", "On-demand report"),
		"status":       "generated",
		"generated_at": time.Now().UTC(),
	}
	s.mu.Lock()
	s.reports = append(s.reports, report)
	s.mu.Unlock()
	respond(w, r, http.StatusCreated, map[string]interface{}{"report": report})
}

func (s *apiServer) listCustomers(w http.ResponseWriter, r *http.Request) {
	respond(w, r, http.StatusOK, map[string]interface{}{"customers": []map[string]interface{}{
		{"id": "CUST-41", "name": "Asha Retail", "risk_band": "low"},
		{"id": "CUST-72", "name": "Northwind Labs", "risk_band": "medium"},
	}})
}

func (s *apiServer) paymentDetails(w http.ResponseWriter, r *http.Request) {
	respond(w, r, http.StatusOK, map[string]interface{}{"payment_details": []map[string]interface{}{
		{"account": "XXXX-8871", "method": "corporate-card", "tokenized": true},
	}})
}

func (s *apiServer) updateConfig(w http.ResponseWriter, r *http.Request) {
	var input map[string]interface{}
	if err := platform.DecodeJSON(r, &input); err != nil {
		platform.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	for key, value := range input {
		s.config[key] = value
	}
	config := cloneMap(s.config)
	s.mu.Unlock()
	respond(w, r, http.StatusOK, map[string]interface{}{"config": config})
}

func respond(w http.ResponseWriter, r *http.Request, status int, payload map[string]interface{}) {
	payload["trace_id"] = r.Header.Get("X-ContainGo-Trace-ID")
	payload["served_by"] = "protected-api"
	payload["authenticated_gateway"] = platform.PeerSPIFFEID(r)
	platform.WriteJSON(w, status, payload)
}

func cloneMap(input map[string]interface{}) map[string]interface{} {
	output := make(map[string]interface{}, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func valueOr(input map[string]interface{}, key string, fallback interface{}) interface{} {
	if value, ok := input[key]; ok {
		return value
	}
	return fallback
}

func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("component=protected-api method=%s path=%s peer=%s trace=%s duration=%s", r.Method, r.URL.Path, platform.PeerSPIFFEID(r), r.Header.Get("X-ContainGo-Trace-ID"), time.Since(started))
	})
}

func env(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

var _ = json.Valid
