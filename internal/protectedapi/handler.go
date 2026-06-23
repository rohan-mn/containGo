package protectedapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// API contains the protected API dependencies.
type API struct {
	identities IdentityResolver
	authorizer Authorizer
	readiness  ReadinessChecker
}

// NewAPI creates the protected API handler.
func NewAPI(
	identities IdentityResolver,
	authorizer Authorizer,
	readiness ReadinessChecker,
) (*API, error) {
	if identities == nil {
		return nil, errors.New(
			"identity resolver must not be nil",
		)
	}

	if authorizer == nil {
		return nil, errors.New(
			"authorizer must not be nil",
		)
	}

	if readiness == nil {
		return nil, errors.New(
			"readiness checker must not be nil",
		)
	}

	return &API{
		identities: identities,
		authorizer: authorizer,
		readiness:  readiness,
	}, nil
}

// Handler returns the complete HTTP routing tree.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc(
		"/healthz",
		a.handleHealth,
	)

	mux.HandleFunc(
		"/readyz",
		a.handleReady,
	)

	mux.HandleFunc(
		"/api/orders",
		a.handleProtected(
			"orders",
			ordersPayload,
		),
	)

	mux.HandleFunc(
		"/api/reports",
		a.handleProtected(
			"reports",
			reportsPayload,
		),
	)

	mux.HandleFunc(
		"/api/customers",
		a.handleProtected(
			"customers",
			customersPayload,
		),
	)

	mux.HandleFunc(
		"/api/payment-details",
		a.handleProtected(
			"payment-details",
			paymentDetailsPayload,
		),
	)

	mux.HandleFunc(
		"/api/admin/config",
		a.handleProtected(
			"admin-config",
			adminConfigPayload,
		),
	)

	mux.HandleFunc(
		"/",
		func(
			writer http.ResponseWriter,
			_ *http.Request,
		) {
			writeError(
				writer,
				http.StatusNotFound,
				"not_found",
				"route not found",
			)
		},
	)

	return recoverMiddleware(mux)
}

func (a *API) handleHealth(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if !requireGET(
		writer,
		request,
	) {
		return
	}

	writeJSON(
		writer,
		http.StatusOK,
		map[string]any{
			"status":  "ok",
			"service": "protected-api",
			"time":    time.Now().UTC(),
		},
	)
}

func (a *API) handleReady(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if !requireGET(
		writer,
		request,
	) {
		return
	}

	ctx, cancel := context.WithTimeout(
		request.Context(),
		2*time.Second,
	)
	defer cancel()

	if err := a.readiness.Check(ctx); err != nil {
		writeError(
			writer,
			http.StatusServiceUnavailable,
			"not_ready",
			"service dependencies are not ready",
		)

		return
	}

	writeJSON(
		writer,
		http.StatusOK,
		map[string]any{
			"status":  "ready",
			"service": "protected-api",
			"time":    time.Now().UTC(),
		},
	)
}

func (a *API) handleProtected(
	resource string,
	payload func() any,
) http.HandlerFunc {
	return func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if !requireGET(
			writer,
			request,
		) {
			return
		}

		spiffeID, err := a.identities.Resolve(
			request,
		)
		if err != nil {
			if errors.Is(
				err,
				ErrUnauthenticated,
			) {
				writeError(
					writer,
					http.StatusUnauthorized,
					"unauthenticated",
					"verified workload identity is required",
				)

				return
			}

			writeError(
				writer,
				http.StatusUnauthorized,
				"unauthenticated",
				"workload identity could not be verified",
			)

			return
		}

		decision, err := a.authorizer.Authorize(
			request.Context(),
			AuthorizationInput{
				SPIFFEID: spiffeID,
				Method:   request.Method,
				Path:     request.URL.Path,
			},
		)
		if err != nil {
			writeError(
				writer,
				http.StatusServiceUnavailable,
				"authorization_unavailable",
				"authorization service is unavailable",
			)

			return
		}

		if !decision.Allowed {
			writeError(
				writer,
				http.StatusForbidden,
				"forbidden",
				decision.Reason,
			)

			return
		}

		writeJSON(
			writer,
			http.StatusOK,
			map[string]any{
				"resource":           resource,
				"workload_spiffe_id": spiffeID,
				"data":               payload(),
			},
		)
	}
}

func requireGET(
	writer http.ResponseWriter,
	request *http.Request,
) bool {
	if request.Method == http.MethodGet {
		return true
	}

	writer.Header().Set(
		"Allow",
		http.MethodGet,
	)

	writeError(
		writer,
		http.StatusMethodNotAllowed,
		"method_not_allowed",
		"only GET is supported",
	)

	return false
}

func recoverMiddleware(
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(
		func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
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

			next.ServeHTTP(
				writer,
				request,
			)
		},
	)
}

func writeError(
	writer http.ResponseWriter,
	status int,
	code string,
	message string,
) {
	writeJSON(
		writer,
		status,
		map[string]any{
			"error": map[string]string{
				"code":    code,
				"message": message,
			},
		},
	)
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
	writer.Header().Set(
		"Cache-Control",
		"no-store",
	)

	writer.WriteHeader(status)

	_ = json.NewEncoder(writer).Encode(value)
}

func ordersPayload() any {
	return map[string]any{
		"orders": []map[string]any{
			{
				"id":     "ORD-1001",
				"status": "processing",
			},
			{
				"id":     "ORD-1002",
				"status": "completed",
			},
		},
	}
}

func reportsPayload() any {
	return map[string]any{
		"reports": []map[string]any{
			{
				"id":     "RPT-2026-001",
				"name":   "daily-summary",
				"status": "ready",
			},
		},
	}
}

func customersPayload() any {
	return map[string]any{
		"customers": []map[string]any{
			{
				"id":   "CUS-1001",
				"name": "Example Customer",
			},
		},
	}
}

func paymentDetailsPayload() any {
	return map[string]any{
		"payment_details": []map[string]any{
			{
				"customer_id": "CUS-1001",
				"method":      "tokenized-card",
				"last_four":   "4242",
			},
		},
	}
}

func adminConfigPayload() any {
	return map[string]any{
		"config": map[string]any{
			"risk_threshold":     70,
			"authorization_mode": "static-phase-3",
		},
	}
}
