package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"containgo.local/containgo/internal/domain"
	"containgo.local/containgo/internal/reportclient"
	"containgo.local/containgo/internal/workloadclient"
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
			ExpectedID: domain.SPIFFEIDReportClient,
			SocketAddress: environment(
				"SPIFFE_ENDPOINT_SOCKET",
				"",
			),
		},
	)
	if err != nil {
		log.Fatalf("create Report Client Workload API source: %v", err)
	}
	defer func() {
		_ = identitySource.Close()
	}()
	identitySource.LogUpdates(ctx, log.Printf)

	gatewayTLS, err := identitySource.ClientTLSConfig(
		domain.SPIFFEIDAPIGateway,
	)
	if err != nil {
		log.Fatalf("create API Gateway SPIFFE client TLS: %v", err)
	}

	controlServerTLS, err := identitySource.ServerTLSConfig(
		false,
		domain.SPIFFEIDDemoctl,
		domain.SPIFFEIDDashboard,
	)
	if err != nil {
		log.Fatalf("create Report Client control SPIFFE server TLS: %v", err)
	}

	initialMode, err := reportclient.ParseMode(
		environment(
			"CONTAINGO_REPORT_INITIAL_MODE",
			string(reportclient.ModeNormal),
		),
	)
	if err != nil {
		log.Fatalf("parse initial Report Client mode: %v", err)
	}

	controller, err := reportclient.NewController(initialMode)
	if err != nil {
		log.Fatalf("create Report Client controller: %v", err)
	}

	client, err := workloadclient.New(
		workloadclient.Config{
			BaseURL: environment(
				"CONTAINGO_GATEWAY_URL",
				"https://127.0.0.1:8443",
			),
			TLSConfig: gatewayTLS,
			Timeout: durationEnvironment(
				"CONTAINGO_REPORT_REQUEST_TIMEOUT",
				10*time.Second,
			),
			UserAgent: "containgo-report-client/1.0",
		},
	)
	if err != nil {
		log.Fatalf("create Report Client: %v", err)
	}

	runner, err := reportclient.NewRunner(
		client,
		controller,
		reportclient.RunnerConfig{
			NormalInterval: durationEnvironment(
				"CONTAINGO_REPORT_NORMAL_INTERVAL",
				5*time.Second,
			),
			AttackInterval: durationEnvironment(
				"CONTAINGO_REPORT_ATTACK_INTERVAL",
				3*time.Second,
			),
			RapidInterval: durationEnvironment(
				"CONTAINGO_REPORT_RAPID_INTERVAL",
				15*time.Second,
			),
			RapidBurst: integerEnvironment(
				"CONTAINGO_REPORT_RAPID_BURST",
				35,
			),
		},
	)
	if err != nil {
		log.Fatalf("create Report Client runner: %v", err)
	}

	controlServer, err := reportclient.NewControlServer(
		reportclient.ControlServerConfig{
			Address: environment(
				"CONTAINGO_REPORT_CONTROL_ADDRESS",
				"127.0.0.1:8072",
			),
			TLSConfig: controlServerTLS,
		},
		controller,
	)
	if err != nil {
		log.Fatalf("create Report Client control server: %v", err)
	}

	errCh := make(chan error, 2)
	go func() {
		errCh <- runner.Run(ctx)
	}()
	go func() {
		errCh <- controlServer.Run(ctx)
	}()

	log.Printf(
		"Report Client started in %s mode; control API at https://%s",
		initialMode,
		controlServer.Address(),
	)

	completed := 0

	select {
	case <-ctx.Done():
		// Both components observe the same cancelled context.
	case runErr := <-errCh:
		completed = 1
		if runErr != nil && !errors.Is(runErr, context.Canceled) {
			log.Printf("Report Client component stopped with error: %v", runErr)
		}
		stop()
	}

	for completed < 2 {
		select {
		case runErr := <-errCh:
			completed++
			if runErr != nil && !errors.Is(runErr, context.Canceled) {
				log.Printf("Report Client shutdown error: %v", runErr)
			}
		case <-time.After(6 * time.Second):
			log.Print("Report Client shutdown timed out")
			return
		}
	}

	log.Print("Report Client stopped cleanly")
}

func environment(name string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}

func durationEnvironment(name string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}

	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		log.Printf(
			"invalid %s=%s; using %s",
			name,
			strconv.Quote(value),
			fallback,
		)
		return fallback
	}

	return parsed
}

func integerEnvironment(name string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}

	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		log.Printf(
			"invalid %s=%s; using %d",
			name,
			strconv.Quote(value),
			fallback,
		)
		return fallback
	}

	return parsed
}
