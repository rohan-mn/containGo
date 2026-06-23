package controlplane

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ServerConfig contains control-plane SPIFFE TLS server settings.
type ServerConfig struct {
	Address           string
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
	TLSConfig         *tls.Config
}

// DefaultServerConfig returns safe service defaults.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Address:           "127.0.0.1:8090",
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ShutdownTimeout:   10 * time.Second,
	}
}

// Server runs the Control Plane over SPIFFE TLS.
type Server struct {
	config     ServerConfig
	httpServer *http.Server
}

// NewServer creates the Control Plane TLS server.
func NewServer(
	config ServerConfig,
	handler http.Handler,
) (*Server, error) {
	if handler == nil {
		return nil, errors.New("HTTP handler must not be nil")
	}

	config.Address = strings.TrimSpace(config.Address)
	if config.Address == "" {
		config.Address = "127.0.0.1:8090"
	}

	if config.ReadHeaderTimeout <= 0 {
		config.ReadHeaderTimeout = 5 * time.Second
	}

	if config.ReadTimeout <= 0 {
		config.ReadTimeout = 15 * time.Second
	}

	if config.WriteTimeout <= 0 {
		config.WriteTimeout = 15 * time.Second
	}

	if config.IdleTimeout <= 0 {
		config.IdleTimeout = 60 * time.Second
	}

	if config.ShutdownTimeout <= 0 {
		config.ShutdownTimeout = 10 * time.Second
	}

	if config.TLSConfig == nil {
		return nil, errors.New("SPIFFE TLS configuration is required")
	}

	return &Server{
		config: config,
		httpServer: &http.Server{
			Addr:              config.Address,
			Handler:           handler,
			ReadHeaderTimeout: config.ReadHeaderTimeout,
			ReadTimeout:       config.ReadTimeout,
			WriteTimeout:      config.WriteTimeout,
			IdleTimeout:       config.IdleTimeout,
			MaxHeaderBytes:    1 << 20,
			TLSConfig:         config.TLSConfig.Clone(),
		},
	}, nil
}

// Run starts the server and performs graceful shutdown on cancellation.
func (s *Server) Run(ctx context.Context) error {
	if err := validateContext(ctx); err != nil {
		return err
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

		return fmt.Errorf("serve control-plane API: %w", err)

	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(
			context.Background(),
			s.config.ShutdownTimeout,
		)
		defer cancel()

		shutdownErr := s.httpServer.Shutdown(shutdownCtx)
		serveErr := <-serveErrors

		if shutdownErr != nil {
			return fmt.Errorf("shut down control-plane API: %w", shutdownErr)
		}

		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			return fmt.Errorf("serve control-plane API: %w", serveErr)
		}

		return nil
	}
}

func withRequestTimeout(
	request *http.Request,
	timeout time.Duration,
) (context.Context, context.CancelFunc) {
	return context.WithTimeout(request.Context(), timeout)
}
