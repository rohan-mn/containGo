package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"
)

const (
	defaultEnvironment     = "development"
	defaultHTTPAddr        = ":8080"
	defaultShutdownTimeout = 10 * time.Second
	defaultRequestTimeout  = 5 * time.Second
	defaultLogLevel        = "info"
)

// AppConfig contains settings shared by every ContainGo executable.
// Application-specific configuration will embed this type in later phases.
type AppConfig struct {
	ServiceName     string
	Environment     string
	HTTPAddr        string
	ShutdownTimeout time.Duration
	RequestTimeout  time.Duration
	LogLevel        slog.Level
}

// LoadAppConfig reads common settings from the process environment.
// Empty variables use safe local-development defaults.
func LoadAppConfig(serviceName string) (AppConfig, error) {
	cfg := AppConfig{
		ServiceName:     strings.TrimSpace(serviceName),
		Environment:     envOrDefault("CONTAINGO_ENVIRONMENT", defaultEnvironment),
		HTTPAddr:        envOrDefault("CONTAINGO_HTTP_ADDR", defaultHTTPAddr),
		ShutdownTimeout: defaultShutdownTimeout,
		RequestTimeout:  defaultRequestTimeout,
		LogLevel:        slog.LevelInfo,
	}

	if value := strings.TrimSpace(os.Getenv("CONTAINGO_SHUTDOWN_TIMEOUT")); value != "" {
		duration, err := parsePositiveDuration(
			"CONTAINGO_SHUTDOWN_TIMEOUT",
			value,
		)
		if err != nil {
			return AppConfig{}, err
		}

		cfg.ShutdownTimeout = duration
	}

	if value := strings.TrimSpace(os.Getenv("CONTAINGO_REQUEST_TIMEOUT")); value != "" {
		duration, err := parsePositiveDuration(
			"CONTAINGO_REQUEST_TIMEOUT",
			value,
		)
		if err != nil {
			return AppConfig{}, err
		}

		cfg.RequestTimeout = duration
	}

	logLevel, err := parseLogLevel(
		envOrDefault("CONTAINGO_LOG_LEVEL", defaultLogLevel),
	)
	if err != nil {
		return AppConfig{}, err
	}

	cfg.LogLevel = logLevel

	if err := cfg.Validate(); err != nil {
		return AppConfig{}, fmt.Errorf(
			"validate common configuration: %w",
			err,
		)
	}

	return cfg, nil
}

// Validate checks settings that are common to every executable.
func (c AppConfig) Validate() error {
	if strings.TrimSpace(c.ServiceName) == "" {
		return errors.New("service name must not be empty")
	}

	if strings.TrimSpace(c.Environment) == "" {
		return errors.New("environment must not be empty")
	}

	if err := validateListenAddress(c.HTTPAddr); err != nil {
		return fmt.Errorf("HTTP address: %w", err)
	}

	if c.ShutdownTimeout <= 0 {
		return errors.New("shutdown timeout must be greater than zero")
	}

	if c.RequestTimeout <= 0 {
		return errors.New("request timeout must be greater than zero")
	}

	return nil
}

func envOrDefault(name, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}

	return value
}

func parsePositiveDuration(name, value string) (time.Duration, error) {
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", name, err)
	}

	if duration <= 0 {
		return 0, fmt.Errorf("%s must be greater than zero", name)
	}

	return duration, nil
}

func parseLogLevel(value string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf(
			"CONTAINGO_LOG_LEVEL must be one of debug, info, warn, or error",
		)
	}
}

func validateListenAddress(address string) error {
	address = strings.TrimSpace(address)
	if address == "" {
		return errors.New("must not be empty")
	}

	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf(
			"must use host:port form, for example :8080: %w",
			err,
		)
	}

	if port == "" {
		return errors.New("port must not be empty")
	}

	return nil
}
