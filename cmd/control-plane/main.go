package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"containgo.local/containgo/internal/application"
	"containgo.local/containgo/internal/controlplane"
	"containgo.local/containgo/internal/database"
	"containgo.local/containgo/internal/domain"
	gatewayclient "containgo.local/containgo/internal/gateway"
	opaclient "containgo.local/containgo/internal/opa"
	"containgo.local/containgo/internal/repository"
	"containgo.local/containgo/internal/risk"
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
			ExpectedID: domain.SPIFFEIDControlPlane,
			SocketAddress: environment(
				"SPIFFE_ENDPOINT_SOCKET",
				"",
			),
		},
	)
	must("create Control Plane Workload API source", err)
	defer func() {
		_ = identitySource.Close()
	}()
	identitySource.LogUpdates(ctx, log.Printf)

	serverTLS, err := identitySource.ServerTLSConfig(
		false,
		domain.SPIFFEIDAPIGateway,
		domain.SPIFFEIDDashboard,
		domain.SPIFFEIDDemoctl,
	)
	must("create Control Plane SPIFFE server TLS", err)

	gatewayTLS, err := identitySource.ClientTLSConfig(
		domain.SPIFFEIDAPIGateway,
	)
	must("create API Gateway SPIFFE client TLS", err)

	databasePath := environment(
		"CONTAINGO_DATABASE_PATH",
		filepath.Join("data", "containgo.db"),
	)

	db, err := database.Open(ctx, databasePath)
	if err != nil {
		log.Fatalf("open SQLite database: %v", err)
	}
	defer func() {
		_ = db.Close()
	}()

	workloads, err := repository.NewSQLiteWorkloadRepository(db)
	must("create workload repository", err)

	events, err := repository.NewSQLiteEventRepository(db)
	must("create event repository", err)

	incidents, err := repository.NewSQLiteIncidentRepository(db)
	must("create incident repository", err)

	audits, err := repository.NewSQLiteAuditRepository(db)
	must("create audit repository", err)

	clock := risk.SystemClock{}
	riskEngine, err := risk.NewEngine(clock)
	must("create risk engine", err)

	quarantineService, err := application.NewQuarantineService(
		workloads,
		incidents,
		audits,
	)
	must("create quarantine service", err)

	releaseService, err := application.NewReleaseService(
		workloads,
		incidents,
		audits,
	)
	must("create release service", err)

	enforcementMode := strings.ToLower(environment(
		"CONTAINGO_ENFORCEMENT_MODE",
		"gateway",
	))

	var enforcer controlplane.QuarantineEnforcer

	switch enforcementMode {
	case "gateway":
		gatewayConfig := gatewayclient.DefaultEnforcementConfig()
		gatewayConfig.BaseURL = environment(
			"CONTAINGO_GATEWAY_URL",
			gatewayConfig.BaseURL,
		)
		gatewayConfig.TLSConfig = gatewayTLS

		gatewayEnforcer, createErr := gatewayclient.NewEnforcementClient(
			gatewayConfig,
		)
		must("create Gateway quarantine client", createErr)
		enforcer = gatewayEnforcer

		log.Printf(
			"quarantine enforcer: API Gateway at %s",
			gatewayConfig.BaseURL,
		)

	case "opa":
		opaConfig := opaclient.DefaultConfig()
		opaConfig.BaseURL = environment(
			"CONTAINGO_OPA_URL",
			opaConfig.BaseURL,
		)

		opaClient, createErr := opaclient.NewClient(opaConfig)
		must("create OPA client", createErr)
		enforcer = opaClient

		log.Printf(
			"quarantine enforcer: direct OPA data API at %s",
			opaConfig.BaseURL,
		)

	default:
		log.Fatalf(
			"unsupported CONTAINGO_ENFORCEMENT_MODE %q; use gateway or opa",
			enforcementMode,
		)
	}

	service, err := controlplane.NewService(
		clock,
		riskEngine,
		workloads,
		events,
		incidents,
		audits,
		quarantineService,
		releaseService,
		enforcer,
	)
	must("create control-plane service", err)

	reconciliation, err := service.Reconcile(ctx)
	if err != nil {
		log.Fatalf("startup reconciliation failed: %v", err)
	}

	log.Printf(
		"startup reconciliation complete: workloads=%d quarantined=%d",
		reconciliation.WorkloadCount,
		reconciliation.QuarantinedCount,
	)

	api, err := controlplane.NewAPI(
		service,
		controlplane.TLSIdentityResolver{},
	)
	must("create control-plane API", err)

	serverConfig := controlplane.DefaultServerConfig()
	serverConfig.Address = environment(
		"CONTAINGO_CONTROL_PLANE_ADDRESS",
		serverConfig.Address,
	)
	serverConfig.TLSConfig = serverTLS

	server, err := controlplane.NewServer(
		serverConfig,
		api.Handler(),
	)
	must("create control-plane HTTPS server", err)

	log.Printf("Control Plane API listening on https://%s", serverConfig.Address)
	log.Print("event and administrative routes require exact SPIFFE identities")

	if err = server.Run(ctx); err != nil {
		log.Fatalf("control-plane stopped with error: %v", err)
	}

	log.Print("control-plane stopped cleanly")
}

func environment(name string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}

	return value
}

func must(action string, err error) {
	if err != nil {
		log.Fatal(fmt.Errorf("%s: %w", action, err))
	}
}
