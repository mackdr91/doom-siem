/*
Author: Domonick Mack
Date: 2026-11-16
Description: HTTP API router, middleware stack, and cluster telemetry handlers for the Doom SIEM engine.
*/

package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/mackdr91/doom-siem/backend/internal/config"
	"github.com/mackdr91/doom-siem/backend/internal/health"
)

// Server encapsulates the HTTP API handlers and dependencies for Doom SIEM.
type Server struct {
	cfg     *config.Config
	checker *health.Checker
	logger  *slog.Logger
}

// NewServer constructs a new HTTP API server instance.
func NewServer(cfg *config.Config, checker *health.Checker, logger *slog.Logger) *Server {
	return &Server{
		cfg:     cfg,
		checker: checker,
		logger:  logger,
	}
}

// Handler builds the root http.Handler with CORS, recovery, and logging middleware.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	mux.HandleFunc("GET /api/v1/environment", s.handleEnvironment)

	return s.recoverMiddleware(s.loggingMiddleware(s.corsMiddleware(mux)))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	report := s.checker.CheckAll(r.Context())
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) handleEnvironment(w http.ResponseWriter, _ *http.Request) {
	payload := map[string]any{
		"project":     "Doom SIEM",
		"phase":       "Phase 1: Environment & Infrastructure Setup",
		"environment": s.cfg.Environment,
		"version":     s.cfg.Version,
		"capabilities": []string{
			"Syslog (UDP/TCP), HTTP/Webhook & File/Agent Log Shipping",
			"MITRE ATT&CK Mapping & Incident Triage Workflow",
			"AI-Assisted Log Analysis & Threat Summarization",
		},
		"PlannedModules": []string{
			"Command Center Overview",
			"Live Log Stream & Query Explorer",
			"Alerts & Incident Queue",
		},
	}
	writeJSON(w, http.StatusOK, payload)
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && (slices.Contains(s.cfg.CORSAllowedOrigins, "*") || slices.Contains(s.cfg.CORSAllowedOrigins, origin)) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		} else if len(s.cfg.CORSAllowedOrigins) > 0 {
			w.Header().Set("Access-Control-Allow-Origin", s.cfg.CORSAllowedOrigins[0])
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Doom-API-Key")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.logger.Info("http_request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Duration("duration", time.Since(start)),
		)
	})
}

func (s *Server) recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.logger.Error("panic_recovered", slog.Any("error", rec))
				writeJSON(w, http.StatusInternalServerError, map[string]string{
					"error": "internal_server_error",
				})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, statusCode int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(data)
}
