package dashboard

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ServerConfig contains the local dashboard HTTP server settings.
type ServerConfig struct {
	Address           string
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
}

// DefaultServerConfig returns localhost-only MVP defaults.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Address:           "127.0.0.1:8060",
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ShutdownTimeout:   10 * time.Second,
	}
}

// Server runs the dashboard and shuts down gracefully.
type Server struct {
	config     ServerConfig
	httpServer *http.Server
}

// NewServer creates the dashboard server.
func NewServer(
	config ServerConfig,
	handler http.Handler,
) (*Server, error) {
	if handler == nil {
		return nil, errors.New("dashboard HTTP handler must not be nil")
	}

	config.Address = strings.TrimSpace(config.Address)
	if config.Address == "" {
		config.Address = DefaultServerConfig().Address
	}

	if config.ReadHeaderTimeout <= 0 {
		config.ReadHeaderTimeout = DefaultServerConfig().ReadHeaderTimeout
	}
	if config.ReadTimeout <= 0 {
		config.ReadTimeout = DefaultServerConfig().ReadTimeout
	}
	if config.WriteTimeout <= 0 {
		config.WriteTimeout = DefaultServerConfig().WriteTimeout
	}
	if config.IdleTimeout <= 0 {
		config.IdleTimeout = DefaultServerConfig().IdleTimeout
	}
	if config.ShutdownTimeout <= 0 {
		config.ShutdownTimeout = DefaultServerConfig().ShutdownTimeout
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
		},
	}, nil
}

// Run starts the dashboard and stops it when the context is cancelled.
func (s *Server) Run(ctx context.Context) error {
	if ctx == nil {
		return errors.New("context must not be nil")
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context is not usable: %w", err)
	}

	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- s.httpServer.ListenAndServe()
	}()

	select {
	case err := <-serveErrors:
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve dashboard: %w", err)

	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(
			context.Background(),
			s.config.ShutdownTimeout,
		)
		defer cancel()

		shutdownErr := s.httpServer.Shutdown(shutdownCtx)
		serveErr := <-serveErrors

		if shutdownErr != nil {
			return fmt.Errorf("shut down dashboard: %w", shutdownErr)
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			return fmt.Errorf("serve dashboard: %w", serveErr)
		}

		return nil
	}
}
