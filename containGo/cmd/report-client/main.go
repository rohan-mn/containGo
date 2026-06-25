package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"containgo.local/containgo/internal/clientservice"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	service := clientservice.New(
		"report-client",
		env("SPIFFE_ID", "spiffe://containgo.local/ns/containgo/sa/report-client"),
		env("GATEWAY_URL", "https://api-gateway:8443"),
		env("GATEWAY_SPIFFE_ID", "spiffe://containgo.local/ns/containgo/sa/api-gateway"),
		env("CONTROL_ADDR", ":8444"),
		env("HEALTH_ADDR", ":8081"),
	)
	if err := service.Run(ctx); err != nil {
		log.Fatal(err)
	}
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
