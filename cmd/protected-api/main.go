package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"containgo.local/containgo/internal/database"
	"containgo.local/containgo/internal/domain"
	"containgo.local/containgo/internal/protectedapi"
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
			ExpectedID: domain.SPIFFEIDProtectedAPI,
			SocketAddress: environment(
				"SPIFFE_ENDPOINT_SOCKET",
				"",
			),
		},
	)
	if err != nil {
		log.Fatalf("create Protected API Workload API source: %v", err)
	}
	defer func() {
		_ = identitySource.Close()
	}()
	identitySource.LogUpdates(ctx, log.Printf)

	serverTLS, err := identitySource.ServerTLSConfig(
		false,
		domain.SPIFFEIDAPIGateway,
	)
	if err != nil {
		log.Fatalf("create Protected API SPIFFE server TLS: %v", err)
	}

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

	readiness, err := protectedapi.NewDatabaseReadinessChecker(db)
	if err != nil {
		log.Fatalf("create database readiness checker: %v", err)
	}

	api, err := protectedapi.NewAPI(
		protectedapi.TLSIdentityResolver{},
		protectedapi.GatewayAuthorizer{},
		readiness,
	)
	if err != nil {
		log.Fatalf("create Protected API: %v", err)
	}

	serverConfig := protectedapi.DefaultServerConfig()
	serverConfig.Address = environment(
		"CONTAINGO_PROTECTED_API_ADDRESS",
		"127.0.0.1:8080",
	)
	serverConfig.TLSConfig = serverTLS

	server, err := protectedapi.NewServer(
		serverConfig,
		api.Handler(),
	)
	if err != nil {
		log.Fatalf("create Protected API server: %v", err)
	}

	log.Printf("Protected API listening on https://%s", serverConfig.Address)
	log.Print("Protected API accepts only the API Gateway SPIFFE identity")

	if err = server.Run(ctx); err != nil {
		log.Fatalf("Protected API stopped with error: %v", err)
	}

	log.Print("Protected API stopped cleanly")
}

func environment(name string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}
