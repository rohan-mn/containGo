package reportclient

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"containgo.local/containgo/internal/domain"
	"containgo.local/containgo/internal/workloadidentity"
)

const maxControlBodyBytes = 64 << 10

// ControlServerConfig configures the SPIFFE-protected Report Client mode API.
type ControlServerConfig struct {
	Address   string
	TLSConfig *tls.Config
}

// ControlServer exposes the Report Client mode API. Health remains available
// without a client identity, while every mode read or change requires the
// exact democtl or Dashboard SPIFFE identity.
type ControlServer struct {
	address    string
	controller *Controller
	server     *http.Server
}

// NewControlServer creates the Report Client control server.
func NewControlServer(
	config ControlServerConfig,
	controller *Controller,
) (*ControlServer, error) {
	if controller == nil {
		return nil, errors.New("report-client controller must not be nil")
	}

	address := strings.TrimSpace(config.Address)
	if address == "" {
		address = "127.0.0.1:8072"
	}

	if _, _, err := net.SplitHostPort(address); err != nil {
		return nil, fmt.Errorf("parse Report Client control address: %w", err)
	}

	if config.TLSConfig == nil {
		return nil, errors.New("Report Client SPIFFE TLS configuration is required")
	}

	control := &ControlServer{
		address:    address,
		controller: controller,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", control.handleHealth)
	mux.HandleFunc("/v1/mode", control.handleMode)
	mux.HandleFunc("/v1/reset", control.handleReset)
	mux.HandleFunc("/", func(writer http.ResponseWriter, _ *http.Request) {
		writeError(writer, http.StatusNotFound, "not_found", "route not found")
	})

	control.server = &http.Server{
		Addr:              address,
		Handler:           recoverMiddleware(mux),
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    1 << 20,
		TLSConfig:         config.TLSConfig.Clone(),
	}

	return control, nil
}

// Address returns the configured listen address.
func (s *ControlServer) Address() string {
	return s.address
}

// Run starts the control server and gracefully stops it when ctx is cancelled.
func (s *ControlServer) Run(ctx context.Context) error {
	if ctx == nil {
		return errors.New("context must not be nil")
	}

	listener, err := net.Listen("tcp", s.address)
	if err != nil {
		return fmt.Errorf("listen on Report Client control address: %w", err)
	}

	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- s.server.ServeTLS(listener, "", "")
	}()

	select {
	case err = <-serveErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve Report Client control API: %w", err)

	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(
			context.Background(),
			5*time.Second,
		)
		defer cancel()

		shutdownErr := s.server.Shutdown(shutdownCtx)
		serveErr := <-serveErrors

		if shutdownErr != nil {
			return fmt.Errorf("shut down Report Client control API: %w", shutdownErr)
		}

		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			return fmt.Errorf("serve Report Client control API: %w", serveErr)
		}

		return nil
	}
}

func (s *ControlServer) handleHealth(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if !requireMethod(writer, request, http.MethodGet) {
		return
	}

	writeJSON(writer, http.StatusOK, map[string]any{
		"service": "report-client",
		"status":  "ok",
		"time":    time.Now().UTC(),
	})
}

func (s *ControlServer) handleMode(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if !requireDemoController(writer, request) {
		return
	}

	switch request.Method {
	case http.MethodGet:
		writeJSON(writer, http.StatusOK, s.controller.Snapshot())

	case http.MethodPost, http.MethodPut:
		var input struct {
			Mode string `json:"mode"`
		}

		if err := decodeJSON(request, &input); err != nil {
			writeError(writer, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}

		mode, err := ParseMode(input.Mode)
		if err != nil {
			writeError(writer, http.StatusBadRequest, "invalid_mode", err.Error())
			return
		}

		if err = s.controller.SetMode(mode); err != nil {
			writeError(writer, http.StatusBadRequest, "invalid_mode", err.Error())
			return
		}

		writeJSON(writer, http.StatusOK, s.controller.Snapshot())

	default:
		writer.Header().Set("Allow", "GET, POST, PUT")
		writeError(
			writer,
			http.StatusMethodNotAllowed,
			"method_not_allowed",
			"use GET, POST, or PUT",
		)
	}
}

func (s *ControlServer) handleReset(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if !requireDemoController(writer, request) {
		return
	}
	if !requireMethod(writer, request, http.MethodPost) {
		return
	}

	writeJSON(writer, http.StatusOK, s.controller.ResetStats())
}

func requireDemoController(
	writer http.ResponseWriter,
	request *http.Request,
) bool {
	if request == nil || request.TLS == nil || len(request.TLS.PeerCertificates) == 0 {
		writeError(
			writer,
			http.StatusUnauthorized,
			"unauthenticated",
			"demo controller SPIFFE identity is required",
		)
		return false
	}

	spiffeID, err := workloadidentity.PeerID(request.TLS.PeerCertificates[0])
	if err != nil {
		writeError(
			writer,
			http.StatusUnauthorized,
			"unauthenticated",
			"peer SPIFFE identity could not be verified",
		)
		return false
	}

	if spiffeID != domain.SPIFFEIDDemoctl &&
		spiffeID != domain.SPIFFEIDDashboard {
		writeError(
			writer,
			http.StatusForbidden,
			"forbidden",
			"only democtl or dashboard may control Report Client mode",
		)
		return false
	}

	return true
}

func decodeJSON(request *http.Request, destination any) error {
	if request.Body == nil {
		return errors.New("request body must not be empty")
	}

	decoder := json.NewDecoder(
		io.LimitReader(request.Body, maxControlBodyBytes),
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
