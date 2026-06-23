package apigateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ServerConfig configures the public SPIFFE mTLS API Gateway listener.
type ServerConfig struct {
	Address           string
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
	TLSConfig         *tls.Config
}

// DefaultServerConfig returns secure Gateway defaults.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Address:           "127.0.0.1:8443",
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
		ShutdownTimeout:   10 * time.Second,
	}
}

// Server runs the API Gateway with graceful shutdown.
type Server struct {
	config     ServerConfig
	httpServer *http.Server
}

// NewServer creates a mandatory TLS Gateway server. Its certificate, key,
// trust bundles, and peer authorization are supplied dynamically through the
// SPIFFE Workload API-backed TLS configuration.
func NewServer(
	config ServerConfig,
	handler http.Handler,
) (*Server, error) {
	if handler == nil {
		return nil, errors.New("HTTP handler must not be nil")
	}

	config.Address = strings.TrimSpace(config.Address)
	if config.Address == "" {
		config.Address = "127.0.0.1:8443"
	}

	if config.ShutdownTimeout <= 0 {
		config.ShutdownTimeout = 10 * time.Second
	}

	if config.TLSConfig == nil {
		return nil, errors.New("SPIFFE TLS configuration is required")
	}

	httpServer := &http.Server{
		Addr:              config.Address,
		Handler:           handler,
		ReadHeaderTimeout: config.ReadHeaderTimeout,
		ReadTimeout:       config.ReadTimeout,
		WriteTimeout:      config.WriteTimeout,
		IdleTimeout:       config.IdleTimeout,
		MaxHeaderBytes:    1 << 20,
		TLSConfig:         config.TLSConfig.Clone(),
	}

	return &Server{
		config:     config,
		httpServer: httpServer,
	}, nil
}

// Run starts the SPIFFE TLS listener and stops it when the context is
// cancelled.
func (s *Server) Run(ctx context.Context) error {
	if ctx == nil {
		return errors.New("context must not be nil")
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context is not usable: %w", err)
	}

	serveErrors := make(chan error, 1)

	go func() {
		serveErrors <- s.httpServer.ListenAndServeTLS("", "")
	}()

	select {
	case err := <-serveErrors:
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve API Gateway: %w", err)

	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(
			context.Background(),
			s.config.ShutdownTimeout,
		)
		defer cancel()

		shutdownErr := s.httpServer.Shutdown(shutdownCtx)
		serveErr := <-serveErrors

		if shutdownErr != nil {
			return fmt.Errorf("shut down API Gateway: %w", shutdownErr)
		}

		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			return fmt.Errorf("serve API Gateway: %w", serveErr)
		}

		return nil
	}
}
