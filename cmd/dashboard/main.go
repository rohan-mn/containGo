package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"containgo.local/containgo/internal/dashboard"
	"containgo.local/containgo/internal/domain"
	"containgo.local/containgo/internal/workloadidentity"
)

func main() {
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	identitySource, err := workloadidentity.New(
		ctx,
		workloadidentity.Config{
			ExpectedID: domain.SPIFFEIDDashboard,
			SocketAddress: environment(
				"SPIFFE_ENDPOINT_SOCKET",
				"",
			),
		},
	)
	if err != nil {
		log.Fatalf("create Dashboard Workload API source: %v", err)
	}
	defer func() {
		_ = identitySource.Close()
	}()
	identitySource.LogUpdates(ctx, log.Printf)

	controlPlaneTLS, err := identitySource.ClientTLSConfig(
		domain.SPIFFEIDControlPlane,
	)
	if err != nil {
		log.Fatalf("create Control Plane SPIFFE client TLS: %v", err)
	}

	clientConfig := dashboard.DefaultClientConfig()
	clientConfig.BaseURL = environment(
		"CONTAINGO_CONTROL_PLANE_URL",
		clientConfig.BaseURL,
	)
	clientConfig.Timeout = durationEnvironment(
		"CONTAINGO_DASHBOARD_API_TIMEOUT",
		clientConfig.Timeout,
	)
	clientConfig.TLSConfig = controlPlaneTLS

	controlPlaneClient, err := dashboard.NewClient(clientConfig)
	if err != nil {
		log.Fatalf("create Dashboard Control Plane client: %v", err)
	}

	reportClientTLS, err := identitySource.ClientTLSConfig(
		domain.SPIFFEIDReportClient,
	)
	if err != nil {
		log.Fatalf("create Report Client SPIFFE client TLS: %v", err)
	}

	reportConfig := dashboard.DefaultReportClientConfig()
	reportConfig.BaseURL = environment(
		"CONTAINGO_REPORT_CLIENT_CONTROL_URL",
		reportConfig.BaseURL,
	)
	reportConfig.Timeout = durationEnvironment(
		"CONTAINGO_DASHBOARD_API_TIMEOUT",
		reportConfig.Timeout,
	)
	reportConfig.TLSConfig = reportClientTLS

	reportControlClient, err := dashboard.NewReportClient(reportConfig)
	if err != nil {
		log.Fatalf("create Dashboard Report Client controller: %v", err)
	}

	app, err := dashboard.NewAppWithDemo(
		controlPlaneClient,
		reportControlClient,
		boolEnvironment("CONTAINGO_DASHBOARD_SECURE_COOKIE", false),
		environment("CONTAINGO_DEMO_API_TOKEN", ""),
	)
	if err != nil {
		log.Fatalf("create dashboard: %v", err)
	}

	handler, err := app.Handler()
	if err != nil {
		log.Fatalf("create dashboard handler: %v", err)
	}

	serverConfig := dashboard.DefaultServerConfig()
	serverConfig.Address = environment(
		"CONTAINGO_DASHBOARD_ADDRESS",
		serverConfig.Address,
	)

	server, err := dashboard.NewServer(serverConfig, handler)
	if err != nil {
		log.Fatalf("create dashboard server: %v", err)
	}

	log.Printf("ContainGo dashboard listening on http://%s", serverConfig.Address)
	log.Printf("Control Plane API: %s", clientConfig.BaseURL)
	log.Printf("Report Client control API: %s", reportConfig.BaseURL)
	log.Print("browser access remains localhost-only; service calls use SPIFFE mTLS")

	if err = server.Run(ctx); err != nil {
		log.Fatalf("dashboard stopped with error: %v", err)
	}

	log.Print("dashboard stopped cleanly")
}

func environment(name string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}

func durationEnvironment(
	name string,
	fallback time.Duration,
) time.Duration {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}

	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		log.Printf(
			"warning: invalid %s=%q; using %s",
			name,
			value,
			fallback,
		)
		return fallback
	}

	return parsed
}

func boolEnvironment(name string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}

	parsed, err := strconv.ParseBool(value)
	if err != nil {
		log.Printf(
			"warning: invalid %s=%q; using %t",
			name,
			value,
			fallback,
		)
		return fallback
	}

	return parsed
}
