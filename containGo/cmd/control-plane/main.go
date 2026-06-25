package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"containgo.local/containgo/internal/controlservice"
)

func main() {
	threshold, _ := strconv.Atoi(env("RISK_THRESHOLD", "100"))
	store, err := controlservice.NewStore(env("STATE_FILE", "/data/state.json"), threshold)
	if err != nil {
		log.Fatal(err)
	}
	server := controlservice.NewServer(store, env("LISTEN_ADDR", ":8443"), env("HEALTH_ADDR", ":8081"))
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
