package protectedapi

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ServerConfig contains HTTP and SPIFFE TLS configuration.
type ServerConfig struct {
	Address           string
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
	TLSConfig         *tls.Config
}

// DefaultServerConfig returns secure HTTP timeout defaults.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Address:           ":8080",
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ShutdownTimeout:   10 * time.Second,
	}
}

// Server runs the protected API and supports graceful shutdown.
type Server struct {
	config     ServerConfig
	httpServer *http.Server
}

// NewServer creates a SPIFFE TLS HTTP server.
func NewServer(
	config ServerConfig,
	handler http.Handler,
) (*Server, error) {
	if handler == nil {
		return nil, errors.New("HTTP handler must not be nil")
	}

	config.Address = strings.TrimSpace(config.Address)
	if config.Address == "" {
		config.Address = ":8080"
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

// Run starts the server and shuts it down when the context is cancelled.
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

		return fmt.Errorf("serve protected API: %w", err)

	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(
			context.Background(),
			s.config.ShutdownTimeout,
		)
		defer cancel()

		shutdownErr := s.httpServer.Shutdown(shutdownCtx)
		serveErr := <-serveErrors

		if shutdownErr != nil {
			return fmt.Errorf("shut down protected API: %w", shutdownErr)
		}

		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			return fmt.Errorf("serve protected API: %w", serveErr)
		}

		return nil
	}
}
