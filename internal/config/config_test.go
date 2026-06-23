package config

import (
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestLoadAppConfig(t *testing.T) {
	tests := []struct {
		name        string
		serviceName string
		environment map[string]string
		want        AppConfig
		wantErr     string
	}{
		{
			name:        "uses defaults",
			serviceName: "api-gateway",
			want: AppConfig{
				ServiceName:     "api-gateway",
				Environment:     "development",
				HTTPAddr:        ":8080",
				ShutdownTimeout: 10 * time.Second,
				RequestTimeout:  5 * time.Second,
				LogLevel:        slog.LevelInfo,
			},
		},
		{
			name:        "loads explicit values",
			serviceName: "control-plane",
			environment: map[string]string{
				"CONTAINGO_ENVIRONMENT":      "test",
				"CONTAINGO_HTTP_ADDR":        "127.0.0.1:9090",
				"CONTAINGO_SHUTDOWN_TIMEOUT": "20s",
				"CONTAINGO_REQUEST_TIMEOUT":  "1500ms",
				"CONTAINGO_LOG_LEVEL":        "debug",
			},
			want: AppConfig{
				ServiceName:     "control-plane",
				Environment:     "test",
				HTTPAddr:        "127.0.0.1:9090",
				ShutdownTimeout: 20 * time.Second,
				RequestTimeout:  1500 * time.Millisecond,
				LogLevel:        slog.LevelDebug,
			},
		},
		{
			name:        "rejects missing service name",
			serviceName: "   ",
			wantErr:     "service name must not be empty",
		},
		{
			name:        "rejects invalid address",
			serviceName: "api-gateway",
			environment: map[string]string{
				"CONTAINGO_HTTP_ADDR": "8080",
			},
			wantErr: "must use host:port form",
		},
		{
			name:        "rejects invalid duration",
			serviceName: "api-gateway",
			environment: map[string]string{
				"CONTAINGO_REQUEST_TIMEOUT": "fast",
			},
			wantErr: "parse CONTAINGO_REQUEST_TIMEOUT",
		},
		{
			name:        "rejects non-positive duration",
			serviceName: "api-gateway",
			environment: map[string]string{
				"CONTAINGO_SHUTDOWN_TIMEOUT": "0s",
			},
			wantErr: "must be greater than zero",
		},
		{
			name:        "rejects unknown log level",
			serviceName: "api-gateway",
			environment: map[string]string{
				"CONTAINGO_LOG_LEVEL": "verbose",
			},
			wantErr: "must be one of debug, info, warn, or error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearConfigEnvironment(t)

			for key, value := range tt.environment {
				t.Setenv(key, value)
			}

			got, err := LoadAppConfig(tt.serviceName)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf(
						"LoadAppConfig() error = nil, want error containing %q",
						tt.wantErr,
					)
				}

				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf(
						"LoadAppConfig() error = %q, want error containing %q",
						err,
						tt.wantErr,
					)
				}

				return
			}

			if err != nil {
				t.Fatalf(
					"LoadAppConfig() unexpected error: %v",
					err,
				)
			}

			if got != tt.want {
				t.Fatalf(
					"LoadAppConfig() = %#v, want %#v",
					got,
					tt.want,
				)
			}
		})
	}
}

func TestAppConfigValidate(t *testing.T) {
	valid := AppConfig{
		ServiceName:     "protected-api",
		Environment:     "test",
		HTTPAddr:        ":8081",
		ShutdownTimeout: time.Second,
		RequestTimeout:  time.Second,
		LogLevel:        slog.LevelInfo,
	}

	tests := []struct {
		name    string
		mutate  func(*AppConfig)
		wantErr string
	}{
		{
			name: "valid configuration",
			mutate: func(_ *AppConfig) {
			},
		},
		{
			name: "empty environment",
			mutate: func(cfg *AppConfig) {
				cfg.Environment = ""
			},
			wantErr: "environment must not be empty",
		},
		{
			name: "zero request timeout",
			mutate: func(cfg *AppConfig) {
				cfg.RequestTimeout = 0
			},
			wantErr: "request timeout must be greater than zero",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid
			tt.mutate(&cfg)

			err := cfg.Validate()

			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf(
						"Validate() unexpected error: %v",
						err,
					)
				}

				return
			}

			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf(
					"Validate() error = %v, want error containing %q",
					err,
					tt.wantErr,
				)
			}
		})
	}
}

func clearConfigEnvironment(t *testing.T) {
	t.Helper()

	for _, key := range []string{
		"CONTAINGO_ENVIRONMENT",
		"CONTAINGO_HTTP_ADDR",
		"CONTAINGO_SHUTDOWN_TIMEOUT",
		"CONTAINGO_REQUEST_TIMEOUT",
		"CONTAINGO_LOG_LEVEL",
	} {
		t.Setenv(key, "")
	}
}
