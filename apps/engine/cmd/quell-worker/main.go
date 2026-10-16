package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Main entrypoint for Quell Background Worker & GitHub Webhook Receiver (Phase 3).
func main() {
	fmt.Println("🚀 Quell Async Worker & Webhook Orchestrator (Starting...)")

	redisAddr := os.Getenv("REDIS_URL")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}
	fmt.Printf("📦 Connected to Redis Queue at %s (placeholder)\n", redisAddr)

	// HTTP Server for GitHub Webhook events (git push, pull_request)
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","service":"quell-worker"}`))
	})

	mux.HandleFunc("/api/webhooks/github", func(w http.ResponseWriter, r *http.Request) {
		// Placeholder for GitHub App webhook signature verification and job dispatch
		fmt.Printf("Received webhook event: %s\n", r.Header.Get("X-GitHub-Event"))
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"status":"queued"}`))
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		fmt.Printf("🌐 Worker HTTP server listening on port %s\n", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server listen failed: %v\n", err)
		}
	}()

	<-stop
	fmt.Println("\n🛑 Gracefully shutting down worker...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server shutdown error: %v\n", err)
	}
	fmt.Println("Worker stopped cleanly.")
}
