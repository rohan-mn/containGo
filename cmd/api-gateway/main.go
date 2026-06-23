package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"containgo.local/containgo/internal/apigateway"
	"containgo.local/containgo/internal/domain"
	gatewayclient "containgo.local/containgo/internal/gateway"
	opaclient "containgo.local/containgo/internal/opa"
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
			ExpectedID: domain.SPIFFEIDAPIGateway,
			SocketAddress: environment(
				"SPIFFE_ENDPOINT_SOCKET",
				"",
			),
		},
	)
	must("create API Gateway Workload API source", err)
	defer func() {
		_ = identitySource.Close()
	}()
	identitySource.LogUpdates(ctx, log.Printf)

	controlPlaneTLS, err := identitySource.ClientTLSConfig(
		domain.SPIFFEIDControlPlane,
	)
	must("create Control Plane SPIFFE client TLS", err)

	protectedAPITLS, err := identitySource.ClientTLSConfig(
		domain.SPIFFEIDProtectedAPI,
	)
	must("create Protected API SPIFFE client TLS", err)

	gatewayServerTLS, err := identitySource.ServerTLSConfig(
		false,
		domain.SPIFFEIDOrderClient,
		domain.SPIFFEIDReportClient,
		domain.SPIFFEIDControlPlane,
	)
	must("create API Gateway SPIFFE server TLS", err)

	opaConfig := opaclient.DefaultConfig()
	opaConfig.BaseURL = environment(
		"CONTAINGO_OPA_URL",
		opaConfig.BaseURL,
	)

	opaClient, err := opaclient.NewClient(opaConfig)
	must("create OPA client", err)

	eventClient, err := gatewayclient.NewClient(
		gatewayclient.Config{
			BaseURL: environment(
				"CONTAINGO_CONTROL_PLANE_URL",
				"https://127.0.0.1:8090",
			),
			Timeout:   5 * time.Second,
			TLSConfig: controlPlaneTLS,
		},
	)
	must("create Control Plane event client", err)

	upstream, err := apigateway.NewUpstream(
		apigateway.UpstreamConfig{
			BaseURL: environment(
				"CONTAINGO_PROTECTED_API_URL",
				"https://127.0.0.1:8080",
			),
			Timeout:   10 * time.Second,
			TLSConfig: protectedAPITLS,
		},
	)
	must("create Protected API reverse proxy", err)

	readiness, err := apigateway.NewCompositeReadinessChecker(
		apigateway.ReadinessDependency{
			Name:    "opa",
			Checker: opaClient,
		},
		apigateway.ReadinessDependency{
			Name:    "control-plane",
			Checker: eventClient,
		},
		apigateway.ReadinessDependency{
			Name:    "protected-api",
			Checker: upstream,
		},
	)
	must("create Gateway readiness checker", err)

	api, err := apigateway.NewAPI(
		apigateway.TLSIdentityResolver{},
		opaClient,
		eventClient,
		opaClient,
		upstream,
		readiness,
		apigateway.SystemClock{},
		15*time.Second,
	)
	must("create API Gateway", err)

	serverConfig := apigateway.DefaultServerConfig()
	serverConfig.Address = environment(
		"CONTAINGO_GATEWAY_ADDRESS",
		serverConfig.Address,
	)
	serverConfig.TLSConfig = gatewayServerTLS

	server, err := apigateway.NewServer(
		serverConfig,
		api.Handler(),
	)
	must("create API Gateway server", err)

	log.Printf("API Gateway listening on https://%s", serverConfig.Address)
	log.Printf("OPA decision service: %s", opaConfig.BaseURL)
	log.Print("workload identity is sourced only from the SPIFFE Workload API")

	if err = server.Run(ctx); err != nil {
		log.Fatalf("API Gateway stopped with error: %v", err)
	}

	log.Print("API Gateway stopped cleanly")
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
		log.Fatalf("%s: %v", action, err)
	}
}
