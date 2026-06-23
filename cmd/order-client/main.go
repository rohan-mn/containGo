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
			ExpectedID: domain.SPIFFEIDOrderClient,
			SocketAddress: environment(
				"SPIFFE_ENDPOINT_SOCKET",
				"",
			),
		},
	)
	if err != nil {
		log.Fatalf("create Order Client Workload API source: %v", err)
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

	client, err := workloadclient.New(
		workloadclient.Config{
			BaseURL: environment(
				"CONTAINGO_GATEWAY_URL",
				"https://127.0.0.1:8443",
			),
			TLSConfig: gatewayTLS,
			Timeout: durationEnvironment(
				"CONTAINGO_ORDER_REQUEST_TIMEOUT",
				10*time.Second,
			),
			UserAgent: "containgo-order-client/1.0",
		},
	)
	if err != nil {
		log.Fatalf("create Order Client: %v", err)
	}

	interval := durationEnvironment(
		"CONTAINGO_ORDER_INTERVAL",
		5*time.Second,
	)

	log.Printf("Order Client started; polling /api/orders every %s", interval)

	for {
		response, requestErr := client.Get(ctx, "/api/orders")
		if requestErr != nil {
			if errors.Is(requestErr, context.Canceled) || ctx.Err() != nil {
				break
			}
			log.Printf("order-client GET /api/orders failed: %v", requestErr)
		} else {
			log.Printf(
				"order-client GET /api/orders -> %d",
				response.StatusCode,
			)
		}

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			log.Print("Order Client stopped cleanly")
			return
		case <-timer.C:
		}
	}

	log.Print("Order Client stopped cleanly")
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
