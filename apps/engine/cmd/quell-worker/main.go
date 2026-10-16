package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	gh "github.com/google/go-github/v60/github"
	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	"github.com/quell-dev/quell/apps/engine/internal/db"
	"github.com/quell-dev/quell/apps/engine/internal/github"
	"github.com/quell-dev/quell/apps/engine/internal/triage"
	"github.com/quell-dev/quell/apps/engine/internal/worker"
)

func main() {
	fmt.Println("\033[1;36m")
	fmt.Println("  ██████╗ ██╗   ██╗███████╗██╗     ██╗     ")
	fmt.Println(" ██╔═══██╗██║   ██║██╔════╝██║     ██║     ")
	fmt.Println(" ██║   ██║██║   ██║█████╗  ██║     ██║     ")
	fmt.Println(" ██║▄▄ ██║██║   ██║██╔══╝  ██║     ██║     ")
	fmt.Println(" ╚██████╔╝╚██████╔╝███████╗███████╗███████╗")
	fmt.Println("  ╚══▀▀═╝  ╚═════╝ ╚══════╝╚══════╝╚══════╝")
	fmt.Println("    Autonomous AI Security Engine Worker   ")
	fmt.Println("\033[0m")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. Database Connection & Migration
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		databaseURL = "postgres://quell:quellpassword@localhost:5433/quell_db?sslmode=disable"
	}

	log.Printf("Connecting to PostgreSQL at %s ...", sanitizeURL(databaseURL))
	dbClient, err := db.NewClient(ctx, databaseURL)
	if err != nil {
		log.Printf("⚠️ PostgreSQL connection failed (%v). Worker running in degraded/mock mode.", err)
	} else {
		defer dbClient.Close()
		log.Printf("Applying database migrations...")
		if err := dbClient.RunMigrations(ctx); err != nil {
			log.Printf("⚠️ Migration warning: %v", err)
		} else {
			log.Printf("✓ Database schema verified with pgvector support.")
		}
	}

	// 2. Redis Asynq Setup
	redisAddr := os.Getenv("REDIS_URL")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}

	redisOpt := asynq.RedisClientOpt{Addr: redisAddr}
	asynqClient := asynq.NewClient(redisOpt)
	defer asynqClient.Close()

	concurrency := 5
	if cStr := os.Getenv("WORKER_CONCURRENCY"); cStr != "" {
		if c, err := strconv.Atoi(cStr); err == nil && c > 0 {
			concurrency = c
		}
	}

	asynqServer := asynq.NewServer(
		redisOpt,
		asynq.Config{
			Concurrency: concurrency,
			Queues: map[string]int{
				"critical": 6,
				"default":  3,
				"low":      1,
			},
		},
	)

	// 3. GitHub Client & AI Triage Agent
	ghClient, err := github.NewClient()
	if err != nil {
		log.Fatalf("GitHub client initialization error: %v", err)
	}

	triageAgent := triage.NewAgent(triage.Config{
		Model: os.Getenv("OPENAI_MODEL"),
	})

	// 4. Worker Processor & Task Router
	processor := worker.NewProcessor(dbClient, ghClient, triageAgent)
	workerMux := asynq.NewServeMux()
	processor.RegisterServerHandlers(workerMux)

	// Start Asynq worker server in background
	go func() {
		log.Printf("⚡ Task Queue Worker listening on Redis %s (Concurrency: %d)", redisAddr, concurrency)
		if err := asynqServer.Run(workerMux); err != nil {
			log.Printf("Worker server error: %v", err)
		}
	}()

	// 5. HTTP Server for GitHub Webhooks & REST API
	httpMux := http.NewServeMux()

	// Health check
	httpMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","service":"quell-engine-worker"}`))
	})

	// GitHub Webhook Receiver
	webhookSecret := os.Getenv("GITHUB_WEBHOOK_SECRET")
	httpMux.HandleFunc("/webhooks/github", func(w http.ResponseWriter, r *http.Request) {
		handleGitHubWebhook(w, r, webhookSecret, dbClient, asynqClient)
	})

	// REST API: Scans List
	httpMux.HandleFunc("/api/v1/scans", func(w http.ResponseWriter, r *http.Request) {
		handleListScans(w, r, dbClient)
	})

	// REST API: Stats Scorecard
	httpMux.HandleFunc("/api/v1/stats", func(w http.ResponseWriter, r *http.Request) {
		handleGetStats(w, r, dbClient)
	})

	// REST API: Trigger Manual Scan
	httpMux.HandleFunc("/api/v1/scan/manual", func(w http.ResponseWriter, r *http.Request) {
		handleManualScan(w, r, dbClient, asynqClient)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	httpServer := &http.Server{
		Addr:    ":" + port,
		Handler: httpMux,
	}

	go func() {
		log.Printf("🌐 HTTP Server listening on http://localhost:%s", port)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server failed: %v", err)
		}
	}()

	// Graceful Shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	log.Println("\n🛑 Shutting down Quell worker gracefully...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer shutdownCancel()

	_ = httpServer.Shutdown(shutdownCtx)
	asynqServer.Shutdown()
	log.Println("Quell worker stopped cleanly.")
}

func handleGitHubWebhook(w http.ResponseWriter, r *http.Request, secret string, dbClient *db.Client, asynqClient *asynq.Client) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var secretBytes []byte
	if secret != "" {
		secretBytes = []byte(secret)
	}

	payload, err := gh.ValidatePayload(r, secretBytes)
	if err != nil {
		log.Printf("❌ Webhook validation failed: %v", err)
		http.Error(w, "Invalid webhook signature", http.StatusUnauthorized)
		return
	}

	eventType := gh.WebHookType(r)
	log.Printf("🔔 Received GitHub Webhook: %s", eventType)

	event, err := gh.ParseWebHook(eventType, payload)
	if err != nil {
		log.Printf("⚠️ Failed to parse webhook: %v", err)
		http.Error(w, "Parse error", http.StatusBadRequest)
		return
	}

	switch ev := event.(type) {
	case *gh.PingEvent:
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"pong"}`))
		return

	case *gh.PushEvent:
		repoFullName := ev.GetRepo().GetFullName()
		repoID := ev.GetRepo().GetID()
		defaultBranch := ev.GetRepo().GetDefaultBranch()
		commitSHA := ev.GetAfter()
		installationID := ev.GetInstallation().GetID()
		owner := ev.GetRepo().GetOwner().GetLogin()

		log.Printf("⚡ Push event detected: %s (Commit: %s, Installation: %d)", repoFullName, commitSHA, installationID)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var dbOrgID uuid.UUID
		var dbRepoID uuid.UUID

		if dbClient != nil {
			org, err := dbClient.GetOrCreateOrganization(ctx, owner, "starter")
			if err == nil {
				dbOrgID = org.ID
				repo, err := dbClient.UpsertRepository(ctx, org.ID, repoID, repoFullName, defaultBranch, installationID)
				if err == nil {
					dbRepoID = repo.ID
				}
			}
		}

		// Enqueue background scan job
		scanTask, err := worker.NewScanTask(worker.ScanPayload{
			OrgID:          dbOrgID,
			RepoID:         dbRepoID,
			InstallationID: installationID,
			RepoFullName:   repoFullName,
			CommitSHA:      commitSHA,
			DefaultBranch:  defaultBranch,
		})

		if err != nil {
			http.Error(w, "Failed to create task", http.StatusInternalServerError)
			return
		}

		if _, err := asynqClient.Enqueue(scanTask); err != nil {
			log.Printf("❌ Failed to enqueue scan task: %v", err)
			http.Error(w, "Failed to queue scan", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"status":"queued","repo":"` + repoFullName + `","commit":"` + commitSHA + `"}`))
		return

	default:
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ignored"}`))
	}
}

func handleListScans(w http.ResponseWriter, r *http.Request, dbClient *db.Client) {
	if dbClient == nil {
		writeJSON(w, http.StatusOK, []interface{}{})
		return
	}

	limit := 20
	offset := 0
	if l := r.URL.Query().Get("limit"); l != "" {
		if val, err := strconv.Atoi(l); err == nil && val > 0 {
			limit = val
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if val, err := strconv.Atoi(o); err == nil && val >= 0 {
			offset = val
		}
	}

	scans, err := dbClient.ListRecentScans(r.Context(), limit, offset)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, scans)
}

func handleGetStats(w http.ResponseWriter, r *http.Request, dbClient *db.Client) {
	if dbClient == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"total_organizations":  0,
			"total_repositories":   0,
			"total_scans":          0,
			"total_vulns_found":    0,
			"total_prs_opened":     0,
			"false_positives_rate": 0,
		})
		return
	}

	stats, err := dbClient.GetStats(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, stats)
}

func handleManualScan(w http.ResponseWriter, r *http.Request, dbClient *db.Client, asynqClient *asynq.Client) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		RepoFullName   string `json:"repo_full_name"`
		LocalPath      string `json:"local_path"`
		CommitSHA      string `json:"commit_sha"`
		InstallationID int64  `json:"installation_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.RepoFullName == "" && req.LocalPath == "" {
		http.Error(w, "Either repo_full_name or local_path is required", http.StatusBadRequest)
		return
	}

	if req.RepoFullName == "" {
		req.RepoFullName = "local/sample-vuln-app"
	}
	if req.CommitSHA == "" {
		req.CommitSHA = "HEAD"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var dbOrgID uuid.UUID
	var dbRepoID uuid.UUID

	if dbClient != nil {
		org, _ := dbClient.GetOrCreateOrganization(ctx, "Manual Workspace", "growth")
		if org != nil {
			dbOrgID = org.ID
			repo, _ := dbClient.UpsertRepository(ctx, org.ID, 999999, req.RepoFullName, "main", req.InstallationID)
			if repo != nil {
				dbRepoID = repo.ID
			}
		}
	}

	task, err := worker.NewScanTask(worker.ScanPayload{
		OrgID:          dbOrgID,
		RepoID:         dbRepoID,
		InstallationID: req.InstallationID,
		RepoFullName:   req.RepoFullName,
		CommitSHA:      req.CommitSHA,
		DefaultBranch:  "main",
		IsManual:       true,
		LocalPath:      req.LocalPath,
	})

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	info, err := asynqClient.Enqueue(task)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"status":  "queued",
		"task_id": info.ID,
		"queue":   info.Queue,
		"repo":    req.RepoFullName,
	})
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func sanitizeURL(raw string) string {
	if at := strings.Index(raw, "@"); at != -1 {
		if colon := strings.Index(raw[:at], ":"); colon != -1 {
			return raw[:colon] + ":****" + raw[at:]
		}
	}
	return raw
}

