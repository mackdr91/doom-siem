/*
Author: Domonick Mack
Date: 2026-11-16
Description: Entrypoint for the Doom SIEM Go backend server with graceful shutdown.
*/

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mackdr91/doom-siem/backend/internal/api"
	"github.com/mackdr91/doom-siem/backend/internal/config"
	"github.com/mackdr91/doom-siem/backend/internal/health"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	cfg, err := config.Load()
	if err != nil {
		logger.Error("failed_to_load_config", slog.String("error", err.Error()))
		os.Exit(1)
	}

	checker := health.NewChecker(cfg)
	apiServer := api.NewServer(cfg, checker, logger)

	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.HTTPPort),
		Handler:           apiServer.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	shutdownCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Info("doom_engine_starting",
			slog.Int("http_port", cfg.HTTPPort),
			slog.String("environment", cfg.Environment),
			slog.String("version", cfg.Version),
		)
		if serveErr := httpServer.ListenAndServe(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			logger.Error("http_server_failed", slog.String("error", serveErr.Error()))
			os.Exit(1)
		}
	}()

	<-shutdownCtx.Done()
	logger.Info("doom_engine_shutting_down")

	graceCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(graceCtx); err != nil {
		logger.Error("graceful_shutdown_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	logger.Info("doom_engine_stopped")
}
