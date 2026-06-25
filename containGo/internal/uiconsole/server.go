package uiconsole

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"containgo.local/containgo/internal/platform"
)

//go:embed web/*
var webFiles embed.FS

type Component struct {
	Name          string                 `json:"name"`
	Title         string                 `json:"title"`
	Role          string                 `json:"role"`
	SPIFFEID      string                 `json:"spiffe_id"`
	Type          string                 `json:"type"`
	URL           string                 `json:"url,omitempty"`
	Endpoints     []platform.Endpoint    `json:"endpoints,omitempty"`
	Identity      *platform.IdentityInfo `json:"identity,omitempty"`
	IdentityError string                 `json:"identity_error,omitempty"`
}

type pageData struct {
	Title     string
	Page      string
	Component string
}

type Server struct {
	files           platform.IdentityFiles
	listenAddress   string
	controlPlaneURL string
	controlPlaneID  string
	template        *template.Template
	components      map[string]Component
}

func New(listenAddress, controlPlaneURL string) (*Server, error) {
	pageBytes, err := webFiles.ReadFile("web/page.html")
	if err != nil {
		return nil, err
	}
	parsed, err := template.New("page").Parse(string(pageBytes))
	if err != nil {
		return nil, err
	}
	components := defaultComponents()
	return &Server{
		files:           platform.DefaultIdentityFiles(),
		listenAddress:   listenAddress,
		controlPlaneURL: strings.TrimRight(controlPlaneURL, "/"),
		controlPlaneID:  "spiffe://containgo.local/ns/containgo/sa/control-plane",
		template:        parsed,
		components:      components,
	}, nil
}

func (s *Server) Run(ctx context.Context) error {
	assets, err := fs.Sub(webFiles, "web")
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(assets))))
	mux.HandleFunc("GET /", s.renderHome)
	mux.HandleFunc("GET /architecture", s.renderArchitecture)
	mux.HandleFunc("GET /dashboard/{component}", s.renderComponent)
	mux.HandleFunc("GET /control-panel", s.renderControlPanel)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		platform.WriteJSON(w, http.StatusOK, map[string]string{"status": "healthy"})
	})
	mux.HandleFunc("GET /readyz", s.handleReady)
	mux.HandleFunc("GET /api/ui/topology", s.handleTopology)
	mux.HandleFunc("GET /api/ui/workloads", s.proxyControlPlane("/v1/workloads"))
	mux.HandleFunc("GET /api/ui/incidents", s.proxyControlPlane("/v1/incidents"))
	mux.HandleFunc("GET /api/ui/events", s.handleEvents)
	mux.HandleFunc("GET /api/ui/events/stream", s.handleEventStream)
	mux.HandleFunc("GET /api/ui/components/{component}", s.handleComponent)
	mux.HandleFunc("POST /api/ui/components/{component}/requests", s.handleCreateRequest)
	mux.HandleFunc("GET /api/ui/components/{component}/jobs/{id}", s.handleJob)
	mux.HandleFunc("DELETE /api/ui/components/{component}/jobs/{id}", s.handleCancelJob)
	mux.HandleFunc("POST /api/ui/workloads/{name}/release", s.handleAdminAction("release"))
	mux.HandleFunc("POST /api/ui/workloads/{name}/reset-risk", s.handleAdminAction("reset-risk"))

	server := &http.Server{
		Addr:              s.listenAddress,
		Handler:           securityHeaders(loggingMiddleware(mux)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      0,
		IdleTimeout:       90 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	log.Printf("dashboard listening on %s", s.listenAddress)
	return server.ListenAndServe()
}

func (s *Server) renderHome(w http.ResponseWriter, _ *http.Request) {
	s.render(w, pageData{Title: "ContainGo", Page: "home"})
}

func (s *Server) renderArchitecture(w http.ResponseWriter, _ *http.Request) {
	s.render(w, pageData{Title: "Interactive Architecture", Page: "architecture"})
}

func (s *Server) renderComponent(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("component")
	component, ok := s.components[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	s.render(w, pageData{Title: component.Title, Page: "component", Component: name})
}

func (s *Server) renderControlPanel(w http.ResponseWriter, _ *http.Request) {
	s.render(w, pageData{Title: "Control Panel", Page: "control-panel"})
}

func (s *Server) render(w http.ResponseWriter, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.template.Execute(w, data); err != nil {
		log.Printf("template error: %v", err)
	}
}

func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	if err := platform.ReadyIdentity(s.files); err != nil {
		platform.WriteError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	identity, err := platform.LoadIdentityInfo(s.files, "dashboard")
	if err != nil {
		platform.WriteError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	result, err := s.call(context.Background(), s.controlPlaneURL+"/v1/config", http.MethodGet, nil, s.controlPlaneID, identity.SPIFFEID)
	if err != nil || result.StatusCode != http.StatusOK {
		platform.WriteError(w, http.StatusServiceUnavailable, "control-plane is not reachable over SPIFFE mTLS")
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) handleTopology(w http.ResponseWriter, _ *http.Request) {
	components := make([]Component, 0, len(s.components))
	for _, component := range s.components {
		components = append(components, component)
	}
	platform.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"components": components,
		"edges": []map[string]string{
			{"id": "dashboard-order", "from": "dashboard", "to": "order-client", "kind": "SPIFFE mTLS control"},
			{"id": "dashboard-report", "from": "dashboard", "to": "report-client", "kind": "SPIFFE mTLS control"},
			{"id": "order-gateway", "from": "order-client", "to": "api-gateway", "kind": "SPIFFE mTLS"},
			{"id": "report-gateway", "from": "report-client", "to": "api-gateway", "kind": "SPIFFE mTLS"},
			{"id": "gateway-opa", "from": "api-gateway", "to": "opa", "kind": "localhost policy call"},
			{"id": "gateway-protected", "from": "api-gateway", "to": "protected-api", "kind": "SPIFFE mTLS"},
			{"id": "gateway-control", "from": "api-gateway", "to": "control-plane", "kind": "SPIFFE mTLS trusted event"},
			{"id": "spire-workloads", "from": "spire", "to": "all workloads", "kind": "Workload API / X.509-SVID rotation"},
		},
	})
}

func (s *Server) handleComponent(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("component")
	component, ok := s.components[name]
	if !ok {
		platform.WriteError(w, http.StatusNotFound, "component not found")
		return
	}
	if name == "dashboard" {
		identity, err := platform.LoadIdentityInfo(s.files, "dashboard")
		if err == nil {
			component.Identity = &identity
		} else {
			component.IdentityError = err.Error()
		}
	} else if component.URL != "" && component.SPIFFEID != "" {
		localIdentity, err := platform.LoadIdentityInfo(s.files, "dashboard")
		if err != nil {
			component.IdentityError = err.Error()
		} else {
			result, callErr := s.call(r.Context(), strings.TrimRight(component.URL, "/")+"/v1/identity", http.MethodGet, nil, component.SPIFFEID, localIdentity.SPIFFEID)
			if callErr != nil {
				component.IdentityError = callErr.Error()
			} else if result.StatusCode != http.StatusOK {
				component.IdentityError = fmt.Sprintf("identity endpoint returned HTTP %d", result.StatusCode)
			} else {
				var identity platform.IdentityInfo
				if err := json.Unmarshal(result.Body, &identity); err != nil {
					component.IdentityError = err.Error()
				} else {
					component.Identity = &identity
				}
			}
		}
	}
	platform.WriteJSON(w, http.StatusOK, component)
}

func (s *Server) handleCreateRequest(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("component")
	if name != "order-client" && name != "report-client" {
		platform.WriteError(w, http.StatusBadRequest, "only business clients can originate API requests")
		return
	}
	component := s.components[name]
	body, err := platform.ReadBody(r)
	if err != nil {
		platform.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	identity, err := platform.LoadIdentityInfo(s.files, "dashboard")
	if err != nil {
		platform.WriteError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	result, err := s.call(r.Context(), component.URL+"/v1/requests", http.MethodPost, body, component.SPIFFEID, identity.SPIFFEID)
	if err != nil {
		platform.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	copyResponse(w, result)
}

func (s *Server) handleJob(w http.ResponseWriter, r *http.Request) {
	s.proxyJob(w, r, http.MethodGet)
}

func (s *Server) handleCancelJob(w http.ResponseWriter, r *http.Request) {
	s.proxyJob(w, r, http.MethodDelete)
}

func (s *Server) proxyJob(w http.ResponseWriter, r *http.Request, method string) {
	name := r.PathValue("component")
	component, ok := s.components[name]
	if !ok || (name != "order-client" && name != "report-client") {
		platform.WriteError(w, http.StatusNotFound, "client not found")
		return
	}
	identity, err := platform.LoadIdentityInfo(s.files, "dashboard")
	if err != nil {
		platform.WriteError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	result, err := s.call(r.Context(), component.URL+"/v1/requests/"+url.PathEscape(r.PathValue("id")), method, nil, component.SPIFFEID, identity.SPIFFEID)
	if err != nil {
		platform.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	copyResponse(w, result)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	query := "?after=" + url.QueryEscape(r.URL.Query().Get("after")) + "&limit=" + url.QueryEscape(r.URL.Query().Get("limit"))
	s.proxyControlPlane("/v1/events"+query)(w, r)
}

func (s *Server) handleEventStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		platform.WriteError(w, http.StatusInternalServerError, "streaming is unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	ticker := time.NewTicker(800 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			identity, err := platform.LoadIdentityInfo(s.files, "dashboard")
			if err != nil {
				continue
			}
			endpoint := fmt.Sprintf("%s/v1/events?after=%d&limit=100", s.controlPlaneURL, after)
			result, err := s.call(r.Context(), endpoint, http.MethodGet, nil, s.controlPlaneID, identity.SPIFFEID)
			if err != nil || result.StatusCode != http.StatusOK {
				_, _ = fmt.Fprintf(w, "event: warning\ndata: %s\n\n", jsonString(map[string]string{"message": "Control Plane event stream unavailable"}))
				flusher.Flush()
				continue
			}
			var response struct {
				Events []platform.StoredEvent `json:"events"`
			}
			if err := json.Unmarshal(result.Body, &response); err != nil {
				continue
			}
			for _, event := range response.Events {
				if event.Sequence > after {
					after = event.Sequence
				}
				encoded, _ := json.Marshal(event)
				_, _ = fmt.Fprintf(w, "id: %d\nevent: security-event\ndata: %s\n\n", event.Sequence, encoded)
			}
			_, _ = fmt.Fprint(w, ": heartbeat\n\n")
			flusher.Flush()
		}
	}
}

func (s *Server) handleAdminAction(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		identity, err := platform.LoadIdentityInfo(s.files, "dashboard")
		if err != nil {
			platform.WriteError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		path := fmt.Sprintf("/v1/workloads/%s/%s", url.PathEscape(name), action)
		result, err := s.call(r.Context(), s.controlPlaneURL+path, http.MethodPost, []byte("{}"), s.controlPlaneID, identity.SPIFFEID)
		if err != nil {
			platform.WriteError(w, http.StatusBadGateway, err.Error())
			return
		}
		copyResponse(w, result)
	}
}

func (s *Server) proxyControlPlane(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		identity, err := platform.LoadIdentityInfo(s.files, "dashboard")
		if err != nil {
			platform.WriteError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		result, err := s.call(r.Context(), s.controlPlaneURL+path, r.Method, nil, s.controlPlaneID, identity.SPIFFEID)
		if err != nil {
			platform.WriteError(w, http.StatusBadGateway, err.Error())
			return
		}
		copyResponse(w, result)
	}
}

func (s *Server) call(ctx context.Context, endpoint, method string, body []byte, expectedPeer, sourceID string) (platform.HTTPResult, error) {
	client := platform.MTLSHTTPClient(s.files, expectedPeer, 20*time.Second).HTTPClient()
	return platform.DoRequest(ctx, client, method, endpoint, body, nil, sourceID)
}

func copyResponse(w http.ResponseWriter, result platform.HTTPResult) {
	contentType := result.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/json; charset=utf-8"
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(result.StatusCode)
	_, _ = w.Write(result.Body)
}

func jsonString(value interface{}) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func defaultComponents() map[string]Component {
	catalog := platform.EndpointCatalog()
	componentURL := func(name, fallback string) string {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return strings.TrimRight(value, "/")
		}
		return fallback
	}
	return map[string]Component{
		"dashboard":     {Name: "dashboard", Title: "Dashboard", Role: "Browser UI, authenticated workload controller and administrative console", SPIFFEID: "spiffe://containgo.local/ns/containgo/sa/dashboard", Type: "workload"},
		"order-client":  {Name: "order-client", Title: "Order Client", Role: "Originates order operations through the API Gateway using its own X.509-SVID", SPIFFEID: "spiffe://containgo.local/ns/containgo/sa/order-client", Type: "business workload", URL: componentURL("ORDER_CLIENT_URL", "https://order-client:8444"), Endpoints: catalog},
		"report-client": {Name: "report-client", Title: "Report Client", Role: "Originates report and customer operations through the API Gateway using its own X.509-SVID", SPIFFEID: "spiffe://containgo.local/ns/containgo/sa/report-client", Type: "business workload", URL: componentURL("REPORT_CLIENT_URL", "https://report-client:8444"), Endpoints: catalog},
		"api-gateway":   {Name: "api-gateway", Title: "API Gateway", Role: "Authenticates clients, invokes OPA, proxies allowed requests and emits trusted decisions", SPIFFEID: "spiffe://containgo.local/ns/containgo/sa/api-gateway", Type: "workload", URL: componentURL("API_GATEWAY_URL", "https://api-gateway:8443")},
		"protected-api": {Name: "protected-api", Title: "Protected API", Role: "Protected CRUD service that accepts business traffic only from the Gateway identity", SPIFFEID: "spiffe://containgo.local/ns/containgo/sa/protected-api", Type: "workload", URL: componentURL("PROTECTED_API_URL", "https://protected-api:8443")},
		"control-plane": {Name: "control-plane", Title: "Control Plane", Role: "Calculates risk, quarantines workloads, stores evidence and authorizes release", SPIFFEID: "spiffe://containgo.local/ns/containgo/sa/control-plane", Type: "workload", URL: componentURL("CONTROL_PLANE_URL", "https://control-plane:8443")},
		"opa":           {Name: "opa", Title: "OPA Sidecar", Role: "Evaluates identity, method, endpoint and quarantine status", Type: "sidecar"},
		"spire":         {Name: "spire", Title: "SPIRE Identity Plane", Role: "Attests processes and rotates short-lived X.509-SVIDs over the Workload API", Type: "identity infrastructure"},
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("component=dashboard method=%s path=%s duration=%s", r.Method, r.URL.Path, time.Since(started))
	})
}
