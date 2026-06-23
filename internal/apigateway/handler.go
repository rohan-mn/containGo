package apigateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"containgo.local/containgo/internal/domain"
	"containgo.local/containgo/internal/protectedapi"
)

const maxRequestBodyBytes = 1 << 20

var protectedPaths = map[string]struct{}{
	"/api/orders":          {},
	"/api/reports":         {},
	"/api/customers":       {},
	"/api/payment-details": {},
	"/api/admin/config":    {},
}

// API contains the API Gateway runtime dependencies.
type API struct {
	identities IdentityResolver
	authorizer Authorizer
	events     EventSink
	quarantine QuarantineManager
	upstream   http.Handler
	readiness  ReadinessChecker
	clock      Clock
	timeout    time.Duration
}

// NewAPI creates the API Gateway handler.
func NewAPI(
	identities IdentityResolver,
	authorizer Authorizer,
	events EventSink,
	quarantine QuarantineManager,
	upstream http.Handler,
	readiness ReadinessChecker,
	clock Clock,
	requestTimeout time.Duration,
) (*API, error) {
	if identities == nil {
		return nil, errors.New("identity resolver must not be nil")
	}
	if authorizer == nil {
		return nil, errors.New("authorizer must not be nil")
	}
	if events == nil {
		return nil, errors.New("event sink must not be nil")
	}
	if quarantine == nil {
		return nil, errors.New("quarantine manager must not be nil")
	}
	if upstream == nil {
		return nil, errors.New("upstream handler must not be nil")
	}
	if readiness == nil {
		return nil, errors.New("readiness checker must not be nil")
	}
	if clock == nil {
		return nil, errors.New("clock must not be nil")
	}
	if requestTimeout <= 0 {
		requestTimeout = 15 * time.Second
	}

	return &API{
		identities: identities,
		authorizer: authorizer,
		events:     events,
		quarantine: quarantine,
		upstream:   upstream,
		readiness:  readiness,
		clock:      clock,
		timeout:    requestTimeout,
	}, nil
}

// Handler returns all public and internal Gateway routes.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", a.handleHealth)
	mux.HandleFunc("/readyz", a.handleReady)
	mux.HandleFunc("/internal/healthz", a.handleInternalHealth)
	mux.HandleFunc("/internal/quarantine", a.handleInternalQuarantine)

	for path := range protectedPaths {
		mux.Handle(path, http.HandlerFunc(a.handleProtected))
	}

	mux.HandleFunc("/", func(
		writer http.ResponseWriter,
		_ *http.Request,
	) {
		writeError(
			writer,
			http.StatusNotFound,
			"not_found",
			"route not found",
		)
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
		"service": "api-gateway",
		"status":  "ok",
		"time":    a.clock.Now().UTC(),
	})
}

func (a *API) handleReady(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if !requireMethod(writer, request, http.MethodGet) {
		return
	}

	ctx, cancel := context.WithTimeout(
		request.Context(),
		3*time.Second,
	)
	defer cancel()

	if err := a.readiness.Check(ctx); err != nil {
		writeError(
			writer,
			http.StatusServiceUnavailable,
			"not_ready",
			"gateway dependencies are not ready",
		)
		return
	}

	writeJSON(writer, http.StatusOK, map[string]any{
		"service": "api-gateway",
		"status":  "ready",
		"time":    a.clock.Now().UTC(),
	})
}

func (a *API) handleInternalHealth(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if !requireMethod(writer, request, http.MethodGet) {
		return
	}

	if !a.requireControlPlane(writer, request) {
		return
	}

	writeJSON(writer, http.StatusOK, map[string]any{
		"service": "api-gateway-internal",
		"status":  "ok",
		"time":    a.clock.Now().UTC(),
	})
}

func (a *API) handleInternalQuarantine(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if !a.requireControlPlane(writer, request) {
		return
	}

	ctx, cancel := context.WithTimeout(
		request.Context(),
		5*time.Second,
	)
	defer cancel()

	switch request.Method {
	case http.MethodGet:
		spiffeIDs, err := a.quarantine.ListQuarantined(ctx)
		if err != nil {
			writeError(
				writer,
				http.StatusServiceUnavailable,
				"quarantine_unavailable",
				"quarantine data is unavailable",
			)
			return
		}

		writeJSON(writer, http.StatusOK, map[string]any{
			"quarantined_spiffe_ids": spiffeIDs,
		})

	case http.MethodPost:
		var input setQuarantineInput
		if err := decodeJSON(request, &input); err != nil {
			writeError(
				writer,
				http.StatusBadRequest,
				"invalid_request",
				err.Error(),
			)
			return
		}

		input.WorkloadSPIFFEID = strings.TrimSpace(
			input.WorkloadSPIFFEID,
		)
		if !domain.IsKnownWorkloadID(input.WorkloadSPIFFEID) {
			writeError(
				writer,
				http.StatusBadRequest,
				"unknown_workload",
				"unknown workload SPIFFE ID",
			)
			return
		}

		if err := a.quarantine.SetQuarantined(
			ctx,
			input.WorkloadSPIFFEID,
			input.Quarantined,
		); err != nil {
			writeError(
				writer,
				http.StatusServiceUnavailable,
				"quarantine_update_failed",
				"failed to update quarantine data",
			)
			return
		}

		writeJSON(writer, http.StatusOK, map[string]any{
			"workload_spiffe_id": input.WorkloadSPIFFEID,
			"quarantined":        input.Quarantined,
		})

	case http.MethodPut:
		var input replaceQuarantineInput
		if err := decodeJSON(request, &input); err != nil {
			writeError(
				writer,
				http.StatusBadRequest,
				"invalid_request",
				err.Error(),
			)
			return
		}

		for index, spiffeID := range input.WorkloadSPIFFEIDs {
			input.WorkloadSPIFFEIDs[index] = strings.TrimSpace(spiffeID)
			if !domain.IsKnownWorkloadID(input.WorkloadSPIFFEIDs[index]) {
				writeError(
					writer,
					http.StatusBadRequest,
					"unknown_workload",
					fmt.Sprintf(
						"unknown workload SPIFFE ID %q",
						spiffeID,
					),
				)
				return
			}
		}

		if err := a.quarantine.ReplaceQuarantined(
			ctx,
			input.WorkloadSPIFFEIDs,
		); err != nil {
			writeError(
				writer,
				http.StatusServiceUnavailable,
				"quarantine_replace_failed",
				"failed to replace quarantine data",
			)
			return
		}

		writeJSON(writer, http.StatusOK, map[string]any{
			"quarantined_spiffe_ids": input.WorkloadSPIFFEIDs,
		})

	default:
		writer.Header().Set(
			"Allow",
			strings.Join(
				[]string{
					http.MethodGet,
					http.MethodPost,
					http.MethodPut,
				},
				", ",
			),
		)
		writeError(
			writer,
			http.StatusMethodNotAllowed,
			"method_not_allowed",
			"unsupported method",
		)
	}
}

func (a *API) handleProtected(
	writer http.ResponseWriter,
	request *http.Request,
) {
	spiffeID, err := a.identities.Resolve(request)
	if err != nil {
		writeError(
			writer,
			http.StatusUnauthorized,
			"unauthenticated",
			"a verified workload identity is required",
		)
		return
	}

	ctx, cancel := context.WithTimeout(
		request.Context(),
		a.timeout,
	)
	defer cancel()

	decision, err := a.authorizer.Authorize(
		ctx,
		protectedapi.AuthorizationInput{
			SPIFFEID: spiffeID,
			Method:   request.Method,
			Path:     request.URL.Path,
		},
	)
	if err != nil {
		a.recordDeniedBestEffort(
			ctx,
			request,
			spiffeID,
			http.StatusServiceUnavailable,
			"authorization service unavailable",
		)
		writeError(
			writer,
			http.StatusServiceUnavailable,
			"authorization_unavailable",
			"authorization service is unavailable",
		)
		return
	}

	if !decision.Allowed {
		a.recordDeniedBestEffort(
			ctx,
			request,
			spiffeID,
			http.StatusForbidden,
			decision.Reason,
		)
		writeError(
			writer,
			http.StatusForbidden,
			"forbidden",
			decision.Reason,
		)
		return
	}

	event := a.securityEvent(
		request,
		spiffeID,
		domain.DecisionAllowed,
		http.StatusOK,
		decision.Reason,
	)

	ingestResult, err := a.events.SendEvent(ctx, event)
	if err != nil {
		writeError(
			writer,
			http.StatusServiceUnavailable,
			"event_pipeline_unavailable",
			"request was not forwarded because the security event could not be recorded",
		)
		return
	}

	if ingestResult.Evaluation.Quarantined {
		writeError(
			writer,
			http.StatusForbidden,
			"quarantined",
			"workload is quarantined",
		)
		return
	}

	request = request.Clone(ctx)
	request.Header.Set("X-ContainGo-Request-ID", event.RequestID)
	a.upstream.ServeHTTP(writer, request)
}

func (a *API) requireControlPlane(
	writer http.ResponseWriter,
	request *http.Request,
) bool {
	spiffeID, err := a.identities.Resolve(request)
	if err != nil {
		writeError(
			writer,
			http.StatusUnauthorized,
			"unauthenticated",
			"a verified control-plane identity is required",
		)
		return false
	}

	if spiffeID != domain.SPIFFEIDControlPlane {
		writeError(
			writer,
			http.StatusForbidden,
			"forbidden",
			"only the control plane may use this endpoint",
		)
		return false
	}

	return true
}

func (a *API) recordDeniedBestEffort(
	ctx context.Context,
	request *http.Request,
	spiffeID string,
	statusCode int,
	reason string,
) {
	event := a.securityEvent(
		request,
		spiffeID,
		domain.DecisionDenied,
		statusCode,
		reason,
	)

	if _, err := a.events.SendEvent(ctx, event); err != nil {
		log.Printf(
			"record denied security event %s: %v",
			event.RequestID,
			err,
		)
	}
}

func (a *API) securityEvent(
	request *http.Request,
	spiffeID string,
	decision domain.SecurityDecision,
	statusCode int,
	reason string,
) domain.SecurityEvent {
	return domain.SecurityEvent{
		RequestID:  newRequestID(),
		WorkloadID: spiffeID,
		Method:     domain.NormalizedMethod(request.Method),
		Path:       request.URL.Path,
		Decision:   decision,
		StatusCode: statusCode,
		Reason:     strings.TrimSpace(reason),
		OccurredAt: a.clock.Now().UTC(),
	}
}

func newRequestID() string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return fmt.Sprintf(
			"gateway-%d",
			time.Now().UTC().UnixNano(),
		)
	}

	return "gateway-" + hex.EncodeToString(value)
}

func decodeJSON(
	request *http.Request,
	destination any,
) error {
	if request.Body == nil {
		return errors.New("request body must not be empty")
	}

	decoder := json.NewDecoder(
		io.LimitReader(request.Body, maxRequestBodyBytes),
	)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode JSON body: %w", err)
	}

	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request body must contain one JSON value")
		}
		return fmt.Errorf("decode trailing JSON: %w", err)
	}

	return nil
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

func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		defer func() {
			if recovered := recover(); recovered != nil {
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
	writer.Header().Set(
		"Content-Type",
		"application/json; charset=utf-8",
	)
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

type setQuarantineInput struct {
	WorkloadSPIFFEID string `json:"workload_spiffe_id"`
	Quarantined      bool   `json:"quarantined"`
}

type replaceQuarantineInput struct {
	WorkloadSPIFFEIDs []string `json:"workload_spiffe_ids"`
}
