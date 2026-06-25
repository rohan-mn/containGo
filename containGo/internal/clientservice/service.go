package clientservice

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"containgo.local/containgo/internal/platform"
)

const (
	maxRequestsPerJob = 1000
	maxConcurrency    = 50
	maxRunningJobs    = 3
)

type RequestSpec struct {
	Method             string          `json:"method"`
	Path               string          `json:"path"`
	Body               json.RawMessage `json:"body,omitempty"`
	Count              int             `json:"count"`
	Concurrency        int             `json:"concurrency"`
	IntervalMS         int             `json:"interval_ms"`
	Continuous         bool            `json:"continuous"`
	MaxDurationSeconds int             `json:"max_duration_seconds,omitempty"`
}

type RequestResult struct {
	Sequence   int                  `json:"sequence"`
	TraceID    string               `json:"trace_id"`
	StatusCode int                  `json:"status_code"`
	Decision   string               `json:"decision"`
	Error      string               `json:"error,omitempty"`
	Response   string               `json:"response,omitempty"`
	TLS        platform.TLSMetadata `json:"tls"`
	StartedAt  time.Time            `json:"started_at"`
	FinishedAt time.Time            `json:"finished_at"`
}

type Job struct {
	ID           string          `json:"id"`
	Workload     string          `json:"workload"`
	Spec         RequestSpec     `json:"spec"`
	Status       string          `json:"status"`
	CreatedAt    time.Time       `json:"created_at"`
	StartedAt    time.Time       `json:"started_at,omitempty"`
	FinishedAt   time.Time       `json:"finished_at,omitempty"`
	Completed    int             `json:"completed"`
	Successful   int             `json:"successful"`
	Denied       int             `json:"denied"`
	Failed       int             `json:"failed"`
	Results      []RequestResult `json:"results"`
	LastResponse string          `json:"last_response,omitempty"`
	cancel       context.CancelFunc
	mu           sync.RWMutex
}

type JobSnapshot struct {
	ID           string          `json:"id"`
	Workload     string          `json:"workload"`
	Spec         RequestSpec     `json:"spec"`
	Status       string          `json:"status"`
	CreatedAt    time.Time       `json:"created_at"`
	StartedAt    time.Time       `json:"started_at,omitempty"`
	FinishedAt   time.Time       `json:"finished_at,omitempty"`
	Completed    int             `json:"completed"`
	Successful   int             `json:"successful"`
	Denied       int             `json:"denied"`
	Failed       int             `json:"failed"`
	Results      []RequestResult `json:"results"`
	LastResponse string          `json:"last_response,omitempty"`
}

func (j *Job) snapshot() JobSnapshot {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return JobSnapshot{
		ID: j.ID, Workload: j.Workload, Spec: j.Spec, Status: j.Status,
		CreatedAt: j.CreatedAt, StartedAt: j.StartedAt, FinishedAt: j.FinishedAt,
		Completed: j.Completed, Successful: j.Successful, Denied: j.Denied, Failed: j.Failed,
		Results: append([]RequestResult(nil), j.Results...), LastResponse: j.LastResponse,
	}
}

type Service struct {
	Name            string
	SPIFFEID        string
	GatewayURL      string
	GatewaySPIFFEID string
	ListenAddress   string
	HealthAddress   string
	Files           platform.IdentityFiles
	jobs            map[string]*Job
	jobsMu          sync.RWMutex
	runningJobs     atomic.Int32
}

func New(name, spiffeID, gatewayURL, gatewaySPIFFEID, listenAddress, healthAddress string) *Service {
	return &Service{
		Name:            name,
		SPIFFEID:        spiffeID,
		GatewayURL:      strings.TrimRight(gatewayURL, "/"),
		GatewaySPIFFEID: gatewaySPIFFEID,
		ListenAddress:   listenAddress,
		HealthAddress:   healthAddress,
		Files:           platform.DefaultIdentityFiles(),
		jobs:            make(map[string]*Job),
	}
}

func (s *Service) Run(ctx context.Context) error {
	platform.ServeHealth(s.HealthAddress, func() error {
		info, err := platform.LoadIdentityInfo(s.Files, s.Name)
		if err != nil {
			return err
		}
		if info.SPIFFEID != s.SPIFFEID {
			return fmt.Errorf("unexpected SVID %q", info.SPIFFEID)
		}
		return nil
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/identity", s.handleIdentity)
	mux.HandleFunc("GET /v1/catalog", s.handleCatalog)
	mux.HandleFunc("POST /v1/requests", s.handleCreateJob)
	mux.HandleFunc("GET /v1/requests/{id}", s.handleGetJob)
	mux.HandleFunc("DELETE /v1/requests/{id}", s.handleCancelJob)
	mux.HandleFunc("POST /v1/requests/{id}/cancel", s.handleCancelJob)
	mux.HandleFunc("GET /readyz", s.handleReady)

	server := &http.Server{
		Handler:           requestLogMiddleware(mux, s.Name),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		TLSConfig: platform.DynamicServerTLS(s.Files, func(peerID string) bool {
			return peerID == "spiffe://containgo.local/ns/containgo/sa/dashboard"
		}),
	}
	listener, err := tls.Listen("tcp", s.ListenAddress, server.TLSConfig)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	log.Printf("%s control API listening on %s", s.Name, s.ListenAddress)
	return server.Serve(listener)
}

func (s *Service) handleReady(w http.ResponseWriter, _ *http.Request) {
	if err := platform.ReadyIdentity(s.Files); err != nil {
		platform.WriteError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	platform.WriteJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Service) handleIdentity(w http.ResponseWriter, _ *http.Request) {
	info, err := platform.LoadIdentityInfo(s.Files, s.Name)
	if err != nil {
		platform.WriteError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	platform.WriteJSON(w, http.StatusOK, info)
}

func (s *Service) handleCatalog(w http.ResponseWriter, _ *http.Request) {
	platform.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"workload":  s.Name,
		"endpoints": platform.CatalogForWorkload(s.Name),
	})
}

func (s *Service) handleCreateJob(w http.ResponseWriter, r *http.Request) {
	if s.runningJobs.Load() >= maxRunningJobs {
		platform.WriteError(w, http.StatusTooManyRequests, "maximum running jobs reached")
		return
	}
	var spec RequestSpec
	if err := platform.DecodeJSON(r, &spec); err != nil {
		platform.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateSpec(&spec); err != nil {
		platform.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	var ctx context.Context
	var cancel context.CancelFunc
	if spec.Continuous {
		ctx, cancel = context.WithTimeout(context.Background(), time.Duration(spec.MaxDurationSeconds)*time.Second)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	job := &Job{
		ID:        platform.NewID("job"),
		Workload:  s.Name,
		Spec:      spec,
		Status:    "queued",
		CreatedAt: time.Now().UTC(),
		Results:   make([]RequestResult, 0, min(max(spec.Count, 1), 100)),
		cancel:    cancel,
	}
	s.jobsMu.Lock()
	s.jobs[job.ID] = job
	s.jobsMu.Unlock()
	s.runningJobs.Add(1)
	go s.executeJob(ctx, job)
	platform.WriteJSON(w, http.StatusAccepted, job.snapshot())
}

func (s *Service) handleGetJob(w http.ResponseWriter, r *http.Request) {
	job := s.getJob(r.PathValue("id"))
	if job == nil {
		platform.WriteError(w, http.StatusNotFound, "job not found")
		return
	}
	platform.WriteJSON(w, http.StatusOK, job.snapshot())
}

func (s *Service) handleCancelJob(w http.ResponseWriter, r *http.Request) {
	job := s.getJob(r.PathValue("id"))
	if job == nil {
		platform.WriteError(w, http.StatusNotFound, "job not found")
		return
	}
	job.mu.Lock()
	if job.cancel != nil {
		job.cancel()
	}
	if job.Status == "queued" || job.Status == "running" {
		job.Status = "cancelling"
	}
	job.mu.Unlock()
	platform.WriteJSON(w, http.StatusAccepted, job.snapshot())
}

func (s *Service) getJob(id string) *Job {
	s.jobsMu.RLock()
	defer s.jobsMu.RUnlock()
	return s.jobs[id]
}

func validateSpec(spec *RequestSpec) error {
	spec.Method = strings.ToUpper(strings.TrimSpace(spec.Method))
	spec.Path = strings.TrimSpace(spec.Path)
	if !platform.IsKnownEndpoint(spec.Method, spec.Path) {
		return errors.New("method and endpoint must be selected from the registered API catalog")
	}
	if spec.Continuous {
		if spec.MaxDurationSeconds == 0 {
			spec.MaxDurationSeconds = 600
		}
		if spec.MaxDurationSeconds < 1 || spec.MaxDurationSeconds > 600 {
			return errors.New("max_duration_seconds must be between 1 and 600 for continuous jobs")
		}
	} else if spec.Count == 0 {
		spec.Count = 1
	}
	if spec.Concurrency == 0 {
		spec.Concurrency = 1
	}
	if !spec.Continuous && (spec.Count < 1 || spec.Count > maxRequestsPerJob) {
		return fmt.Errorf("count must be between 1 and %d", maxRequestsPerJob)
	}
	if spec.Concurrency < 1 || spec.Concurrency > maxConcurrency {
		return fmt.Errorf("concurrency must be between 1 and %d", maxConcurrency)
	}
	if !spec.Continuous && spec.Concurrency > spec.Count {
		spec.Concurrency = spec.Count
	}
	if spec.IntervalMS < 0 || spec.IntervalMS > 60_000 {
		return errors.New("interval_ms must be between 0 and 60000")
	}
	if len(spec.Body) > platform.MaxBodyBytes {
		return fmt.Errorf("body exceeds %d bytes", platform.MaxBodyBytes)
	}
	return nil
}

func (s *Service) executeJob(ctx context.Context, job *Job) {
	defer s.runningJobs.Add(-1)
	job.mu.Lock()
	job.Status = "running"
	job.StartedAt = time.Now().UTC()
	job.mu.Unlock()

	requests := make(chan int)
	var workers sync.WaitGroup
	for worker := 0; worker < job.Spec.Concurrency; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for sequence := range requests {
				select {
				case <-ctx.Done():
					return
				default:
				}
				result := s.sendOne(ctx, sequence, job.Spec)
				job.mu.Lock()
				job.Completed++
				if result.Error != "" || result.StatusCode >= 500 {
					job.Failed++
				} else if result.StatusCode == http.StatusForbidden {
					job.Denied++
				} else if result.StatusCode >= 200 && result.StatusCode < 300 {
					job.Successful++
				}
				job.LastResponse = result.Response
				job.Results = append(job.Results, result)
				if len(job.Results) > 100 {
					job.Results = append([]RequestResult(nil), job.Results[len(job.Results)-100:]...)
				}
				job.mu.Unlock()
				if job.Spec.IntervalMS > 0 {
					select {
					case <-ctx.Done():
						return
					case <-time.After(time.Duration(job.Spec.IntervalMS) * time.Millisecond):
					}
				}
			}
		}()
	}

sendLoop:
	for sequence := 1; ; sequence++ {
		if !job.Spec.Continuous && sequence > job.Spec.Count {
			break
		}
		select {
		case <-ctx.Done():
			break sendLoop
		case requests <- sequence:
		}
	}
	close(requests)
	workers.Wait()

	job.mu.Lock()
	job.FinishedAt = time.Now().UTC()
	if ctx.Err() != nil {
		job.Status = "cancelled"
	} else {
		job.Status = "completed"
	}
	sort.Slice(job.Results, func(i, j int) bool { return job.Results[i].Sequence < job.Results[j].Sequence })
	job.mu.Unlock()
}

func (s *Service) sendOne(ctx context.Context, sequence int, spec RequestSpec) RequestResult {
	started := time.Now().UTC()
	traceID := platform.NewID("trace")
	result := RequestResult{Sequence: sequence, TraceID: traceID, StartedAt: started}
	identity, err := platform.LoadIdentityInfo(s.Files, s.Name)
	if err != nil {
		result.Error = err.Error()
		result.FinishedAt = time.Now().UTC()
		return result
	}
	client := platform.MTLSHTTPClient(s.Files, s.GatewaySPIFFEID, 20*time.Second).HTTPClient()
	httpResult, err := platform.DoRequest(ctx, client, spec.Method, s.GatewayURL+spec.Path, spec.Body, map[string]string{
		"X-ContainGo-Trace-ID": traceID,
		"X-ContainGo-Job-ID":   "job",
	}, identity.SPIFFEID)
	result.FinishedAt = time.Now().UTC()
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.StatusCode = httpResult.StatusCode
	result.Response = string(httpResult.Body)
	result.TLS = httpResult.TLS
	if httpResult.StatusCode >= 200 && httpResult.StatusCode < 300 {
		result.Decision = "allow"
	} else if httpResult.StatusCode == http.StatusForbidden {
		result.Decision = "deny"
	} else {
		result.Decision = "error"
	}
	return result
}

func requestLogMiddleware(next http.Handler, name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("component=%s method=%s path=%s peer=%s duration=%s", name, r.Method, r.URL.Path, platform.PeerSPIFFEID(r), time.Since(started))
	})
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func ListenAddress(port string) string {
	if strings.HasPrefix(port, ":") {
		return port
	}
	if _, _, err := net.SplitHostPort(port); err == nil {
		return port
	}
	return ":" + port
}
