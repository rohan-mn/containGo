package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"containgo.local/containgo/internal/domain"
)

const maxRequestBodyBytes = 1 << 20

// API exposes the SPIFFE-authenticated control-plane and administrative API.
type API struct {
	service    *Service
	identities IdentityResolver
}

// NewAPI creates the control-plane HTTP API.
func NewAPI(
	service *Service,
	identities IdentityResolver,
) (*API, error) {
	if service == nil {
		return nil, errors.New("control-plane service must not be nil")
	}

	if identities == nil {
		return nil, errors.New("identity resolver must not be nil")
	}

	return &API{
		service:    service,
		identities: identities,
	}, nil
}

// Handler returns the complete control-plane route tree.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", a.handleHealth)
	mux.HandleFunc("/readyz", a.handleReady)
	mux.HandleFunc("/v1/events", a.handleEvents)
	mux.HandleFunc("/v1/workloads", a.handleWorkloads)
	mux.HandleFunc("/v1/workloads/", a.handleWorkloadRoute)
	mux.HandleFunc("/v1/audit", a.handleAudit)
	mux.HandleFunc("/", func(writer http.ResponseWriter, _ *http.Request) {
		writeError(writer, http.StatusNotFound, "not_found", "route not found")
	})

	return recoverMiddleware(mux)
}

func (a *API) handleHealth(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if !requireMethod(writer, request, http.MethodGet) {
		return
	}

	writeJSON(writer, http.StatusOK, map[string]any{
		"service": "control-plane",
		"status":  "ok",
		"time":    time.Now().UTC(),
	})
}

func (a *API) handleReady(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if !requireMethod(writer, request, http.MethodGet) {
		return
	}

	ctx, cancel := withRequestTimeout(request, 3*time.Second)
	defer cancel()

	if err := a.service.Check(ctx); err != nil {
		writeError(
			writer,
			http.StatusServiceUnavailable,
			"not_ready",
			"control-plane dependencies are not ready",
		)
		return
	}

	writeJSON(writer, http.StatusOK, map[string]any{
		"service": "control-plane",
		"status":  "ready",
		"time":    time.Now().UTC(),
	})
}

func (a *API) handleEvents(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if !requireMethod(writer, request, http.MethodPost) {
		return
	}

	if _, ok := a.requireIdentity(
		writer,
		request,
		domain.SPIFFEIDAPIGateway,
	); !ok {
		return
	}

	var input eventInput

	if err := decodeJSON(writer, request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	occurredAt := time.Now().UTC()
	if input.OccurredAt != nil {
		occurredAt = input.OccurredAt.UTC()
	}

	event := domain.SecurityEvent{
		RequestID:  input.RequestID,
		WorkloadID: input.WorkloadSPIFFEID,
		Method:     domain.NormalizedMethod(input.Method),
		Path:       input.Path,
		Decision:   domain.SecurityDecision(strings.ToLower(strings.TrimSpace(input.Decision))),
		StatusCode: input.StatusCode,
		Reason:     input.Reason,
		OccurredAt: occurredAt,
	}

	if event.StatusCode == 0 {
		event.StatusCode = domain.DefaultStatusCode(event.Decision)
	}

	result, err := a.service.Ingest(request.Context(), event)
	if err != nil {
		if errors.Is(err, ErrDuplicateEvent) {
			writeError(writer, http.StatusConflict, "duplicate_event", err.Error())
			return
		}

		writeError(writer, http.StatusUnprocessableEntity, "event_rejected", err.Error())
		return
	}

	writeJSON(writer, http.StatusCreated, result)
}

func (a *API) handleWorkloads(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.URL.Path != "/v1/workloads" {
		writeError(writer, http.StatusNotFound, "not_found", "route not found")
		return
	}

	if !requireMethod(writer, request, http.MethodGet) {
		return
	}

	if _, ok := a.requireIdentity(
		writer,
		request,
		domain.SPIFFEIDDashboard,
		domain.SPIFFEIDDemoctl,
	); !ok {
		return
	}

	workloads, err := a.service.ListWorkloads(request.Context())
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "query_failed", err.Error())
		return
	}

	writeJSON(writer, http.StatusOK, map[string]any{
		"workloads": workloads,
	})
}

func (a *API) handleWorkloadRoute(
	writer http.ResponseWriter,
	request *http.Request,
) {
	actorSPIFFEID, ok := a.requireIdentity(
		writer,
		request,
		domain.SPIFFEIDDashboard,
		domain.SPIFFEIDDemoctl,
	)
	if !ok {
		return
	}

	remainder := strings.Trim(
		strings.TrimPrefix(request.URL.Path, "/v1/workloads/"),
		"/",
	)
	if remainder == "" {
		writeError(writer, http.StatusNotFound, "not_found", "workload is required")
		return
	}

	parts := strings.Split(remainder, "/")
	if len(parts) > 2 {
		writeError(writer, http.StatusNotFound, "not_found", "route not found")
		return
	}

	spiffeID, err := resolveWorkload(parts[0])
	if err != nil {
		writeError(writer, http.StatusNotFound, "unknown_workload", err.Error())
		return
	}

	if len(parts) == 1 {
		if !requireMethod(writer, request, http.MethodGet) {
			return
		}

		workload, findErr := a.service.FindWorkload(request.Context(), spiffeID)
		if findErr != nil {
			writeError(writer, http.StatusNotFound, "workload_not_found", findErr.Error())
			return
		}

		writeJSON(writer, http.StatusOK, workload)
		return
	}

	switch parts[1] {
	case "events":
		a.handleWorkloadEvents(writer, request, spiffeID)
	case "incidents":
		a.handleWorkloadIncidents(writer, request, spiffeID)
	case "audit":
		a.handleWorkloadAudit(writer, request, spiffeID)
	case "release":
		a.handleWorkloadRelease(writer, request, spiffeID, actorSPIFFEID)
	case "reset-risk":
		a.handleWorkloadRiskReset(writer, request, spiffeID, actorSPIFFEID)
	default:
		writeError(writer, http.StatusNotFound, "not_found", "route not found")
	}
}

func (a *API) handleWorkloadEvents(
	writer http.ResponseWriter,
	request *http.Request,
	spiffeID string,
) {
	if !requireMethod(writer, request, http.MethodGet) {
		return
	}

	limit, err := queryLimit(request, 50, 500)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_limit", err.Error())
		return
	}

	events, err := a.service.ListEvents(request.Context(), spiffeID, limit)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "query_failed", err.Error())
		return
	}

	writeJSON(writer, http.StatusOK, map[string]any{"events": events})
}

func (a *API) handleWorkloadIncidents(
	writer http.ResponseWriter,
	request *http.Request,
	spiffeID string,
) {
	if !requireMethod(writer, request, http.MethodGet) {
		return
	}

	limit, err := queryLimit(request, 20, 200)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_limit", err.Error())
		return
	}

	incidents, err := a.service.ListIncidents(request.Context(), spiffeID, limit)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "query_failed", err.Error())
		return
	}

	writeJSON(writer, http.StatusOK, map[string]any{"incidents": incidents})
}

func (a *API) handleWorkloadAudit(
	writer http.ResponseWriter,
	request *http.Request,
	spiffeID string,
) {
	if !requireMethod(writer, request, http.MethodGet) {
		return
	}

	limit, err := queryLimit(request, 50, 200)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_limit", err.Error())
		return
	}

	records, err := a.service.ListAudit(request.Context(), spiffeID, limit)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "query_failed", err.Error())
		return
	}

	writeJSON(writer, http.StatusOK, map[string]any{"audit_records": records})
}

func (a *API) handleWorkloadRelease(
	writer http.ResponseWriter,
	request *http.Request,
	spiffeID string,
	actorSPIFFEID string,
) {
	if !requireMethod(writer, request, http.MethodPost) {
		return
	}

	result, err := a.service.Release(
		request.Context(),
		spiffeID,
		actorSPIFFEID,
	)
	if err != nil {
		writeError(writer, http.StatusConflict, "release_failed", err.Error())
		return
	}

	writeJSON(writer, http.StatusOK, result)
}

func (a *API) handleWorkloadRiskReset(
	writer http.ResponseWriter,
	request *http.Request,
	spiffeID string,
	actorSPIFFEID string,
) {
	if !requireMethod(writer, request, http.MethodPost) {
		return
	}

	workload, err := a.service.ResetRisk(
		request.Context(),
		spiffeID,
		actorSPIFFEID,
	)
	if err != nil {
		writeError(writer, http.StatusConflict, "risk_reset_failed", err.Error())
		return
	}

	writeJSON(writer, http.StatusOK, workload)
}

func (a *API) handleAudit(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if !requireMethod(writer, request, http.MethodGet) {
		return
	}

	if _, ok := a.requireIdentity(
		writer,
		request,
		domain.SPIFFEIDDashboard,
		domain.SPIFFEIDDemoctl,
	); !ok {
		return
	}

	limit, err := queryLimit(request, 100, 200)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_limit", err.Error())
		return
	}

	records, err := a.service.ListAudit(request.Context(), "", limit)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "query_failed", err.Error())
		return
	}

	writeJSON(writer, http.StatusOK, map[string]any{"audit_records": records})
}

func (a *API) requireIdentity(
	writer http.ResponseWriter,
	request *http.Request,
	allowed ...string,
) (string, bool) {
	spiffeID, err := a.identities.Resolve(request)
	if err != nil {
		writeError(
			writer,
			http.StatusUnauthorized,
			"unauthenticated",
			"authenticated workload identity is required",
		)
		return "", false
	}

	for _, allowedID := range allowed {
		if spiffeID == allowedID {
			return spiffeID, true
		}
	}

	writeError(
		writer,
		http.StatusForbidden,
		"forbidden",
		"workload identity is not authorized for this Control Plane endpoint",
	)
	return "", false
}

type eventInput struct {
	RequestID        string     `json:"request_id"`
	WorkloadSPIFFEID string     `json:"workload_spiffe_id"`
	Method           string     `json:"method"`
	Path             string     `json:"path"`
	Decision         string     `json:"decision"`
	StatusCode       int        `json:"status_code"`
	Reason           string     `json:"reason"`
	OccurredAt       *time.Time `json:"occurred_at,omitempty"`
}

func decodeJSON(
	writer http.ResponseWriter,
	request *http.Request,
	destination any,
) error {
	request.Body = http.MaxBytesReader(
		writer,
		request.Body,
		maxRequestBodyBytes,
	)

	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode JSON request: %w", err)
	}

	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request body must contain one JSON object")
		}

		return fmt.Errorf("decode trailing JSON data: %w", err)
	}

	return nil
}

func resolveWorkload(value string) (string, error) {
	value = strings.TrimSpace(value)

	if domain.IsKnownWorkloadID(value) {
		return value, nil
	}

	for _, spiffeID := range domain.KnownWorkloadIDs() {
		name, found := domain.KnownWorkloadName(spiffeID)
		if found && name == value {
			return spiffeID, nil
		}
	}

	return "", fmt.Errorf("unknown workload %q", value)
}

func queryLimit(
	request *http.Request,
	fallback int,
	maximum int,
) (int, error) {
	value := strings.TrimSpace(request.URL.Query().Get("limit"))
	if value == "" {
		return fallback, nil
	}

	limit, err := strconv.Atoi(value)
	if err != nil || limit <= 0 || limit > maximum {
		return 0, fmt.Errorf("limit must be between 1 and %d", maximum)
	}

	return limit, nil
}

func requireMethod(
	writer http.ResponseWriter,
	request *http.Request,
	method string,
) bool {
	if request.Method == method {
		return true
	}

	writer.Header().Set("Allow", method)
	writeError(
		writer,
		http.StatusMethodNotAllowed,
		"method_not_allowed",
		fmt.Sprintf("only %s is supported", method),
	)
	return false
}

func writeError(
	writer http.ResponseWriter,
	status int,
	code string,
	message string,
) {
	writeJSON(writer, status, map[string]any{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}

func writeJSON(
	writer http.ResponseWriter,
	status int,
	value any,
) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer func() {
			if recover() != nil {
				writeError(
					writer,
					http.StatusInternalServerError,
					"internal_error",
					"internal server error",
				)
			}
		}()

		next.ServeHTTP(writer, request)
	})
}
