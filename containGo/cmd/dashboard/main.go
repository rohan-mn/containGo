package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"containgo.local/containgo/internal/uiconsole"
)

func main() {
	server, err := uiconsole.New(env("LISTEN_ADDR", ":8060"), env("CONTROL_PLANE_URL", "https://control-plane:8443"))
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := server.Run(ctx); err != nil {
		log.Fatal(err)
	}
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
