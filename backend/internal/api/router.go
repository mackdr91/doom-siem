/*
Author: Domonick Mack
Date: 2026-11-16
Description: HTTP API router, middleware stack, multi-protocol ingestion endpoints, ClickHouse query handlers, and SSE stream for Doom SIEM.
*/

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mackdr91/doom-siem/backend/internal/config"
	"github.com/mackdr91/doom-siem/backend/internal/health"
	"github.com/mackdr91/doom-siem/backend/internal/ingest"
	"github.com/mackdr91/doom-siem/backend/internal/telemetry"
)

// Server encapsulates the HTTP API handlers and dependencies for Doom SIEM.
type Server struct {
	cfg      *config.Config
	checker  *health.Checker
	repo     *telemetry.Repository
	broker   *telemetry.StreamBroker
	pipeline *ingest.Pipeline
	logger   *slog.Logger
}

// NewServer constructs a new HTTP API server instance with health, ingestion, and telemetry dependencies.
func NewServer(
	cfg *config.Config,
	checker *health.Checker,
	repo *telemetry.Repository,
	broker *telemetry.StreamBroker,
	pipeline *ingest.Pipeline,
	logger *slog.Logger,
) *Server {
	return &Server{
		cfg:      cfg,
		checker:  checker,
		repo:     repo,
		broker:   broker,
		pipeline: pipeline,
		logger:   logger,
	}
}

// Handler builds the root http.Handler with CORS, recovery, and logging middleware.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Phase 1: Health & Environment
	mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	mux.HandleFunc("GET /api/v1/environment", s.handleEnvironment)

	// Phase 2: Multi-Protocol Log Ingestion & Telemetry Pipeline
	mux.HandleFunc("POST /api/v1/ingest/webhook", s.handleIngest(telemetry.ProtocolHTTPWebhook))
	mux.HandleFunc("POST /api/v1/ingest/agent", s.handleIngest(telemetry.ProtocolAgentShipper))
	mux.HandleFunc("POST /api/v1/ingest/simulate", s.handleSimulateTraffic)
	mux.HandleFunc("GET /api/v1/events", s.handleQueryEvents)
	mux.HandleFunc("GET /api/v1/events/stats", s.handleTelemetryStats)
	mux.HandleFunc("GET /api/v1/events/stream", s.handleEventStreamSSE)

	return s.recoverMiddleware(s.loggingMiddleware(s.corsMiddleware(mux)))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	report := s.checker.CheckAll(r.Context())
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) handleEnvironment(w http.ResponseWriter, _ *http.Request) {
	payload := map[string]any{
		"project":     "Doom SIEM",
		"phase":       "Phase 2: Multi-Protocol Log Ingestion & Telemetry Pipeline",
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

func (s *Server) handleIngest(defaultProtocol string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 2*1024*1024))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "failed to read request body",
			})
			return
		}
		defer r.Body.Close()

		events, err := decodeIngestPayload(bodyBytes)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": err.Error(),
			})
			return
		}

		ingested, err := s.pipeline.IngestBatch(r.Context(), events, defaultProtocol)
		if err != nil {
			s.logger.Error("ingest_batch_failed",
				slog.String("protocol", defaultProtocol),
				slog.String("error", err.Error()),
			)
			writeJSON(w, http.StatusBadGateway, map[string]string{
				"error": err.Error(),
			})
			return
		}

		writeJSON(w, http.StatusAccepted, map[string]any{
			"status":   "accepted",
			"protocol": defaultProtocol,
			"ingested": len(ingested),
			"events":   ingested,
		})
	}
}

func (s *Server) handleSimulateTraffic(w http.ResponseWriter, r *http.Request) {
	ingested, err := s.pipeline.SimulateTraffic(r.Context(), s.cfg.SyslogUDPPort, s.cfg.SyslogTCPPort)
	if err != nil {
		s.logger.Error("simulate_traffic_failed", slog.String("error", err.Error()))
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":  "simulated",
		"message": "Dispatched UDP/TCP Syslog frames (:5514) and ingested HTTP Webhook + Agent Shipper batches",
		"count":   len(ingested),
		"events":  ingested,
	})
}

func (s *Server) handleQueryEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 100
	if rawLimit := strings.TrimSpace(q.Get("limit")); rawLimit != "" {
		if parsed, err := strconv.Atoi(rawLimit); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	filter := telemetry.EventQueryFilter{
		Severity:       q.Get("severity"),
		SourceProtocol: q.Get("protocol"),
		Host:           q.Get("host"),
		Search:         q.Get("search"),
		Limit:          limit,
	}

	events, err := s.repo.QueryEvents(r.Context(), filter)
	if err != nil {
		s.logger.Error("query_events_failed", slog.String("error", err.Error()))
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"count":  len(events),
		"events": events,
	})
}

func (s *Server) handleTelemetryStats(w http.ResponseWriter, r *http.Request) {
	streamDepth, _ := s.broker.StreamLength(r.Context())
	stats, err := s.repo.GetStats(r.Context(), streamDepth)
	if err != nil {
		s.logger.Error("telemetry_stats_failed", slog.String("error", err.Error()))
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleEventStreamSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "streaming unsupported by response writer",
		})
		return
	}

	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	_, _ = fmt.Fprintf(w, ": connected to doom-siem live stream\n\n")
	flusher.Flush()

	ch, unsubscribe := s.broker.Subscribe()
	defer unsubscribe()

	keepAliveTicker := time.NewTicker(15 * time.Second)
	defer keepAliveTicker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev, open := <-ch:
			if !open {
				return
			}
			payload, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			_, _ = fmt.Fprintf(w, "event: security_event\ndata: %s\n\n", string(payload))
			flusher.Flush()
		case <-keepAliveTicker.C:
			_, _ = fmt.Fprintf(w, ": heartbeat %s\n\n", time.Now().UTC().Format(time.RFC3339))
			flusher.Flush()
		}
	}
}

func decodeIngestPayload(raw []byte) ([]telemetry.SecurityEvent, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty request payload")
	}

	// Support JSON array of events: [...]
	if trimmed[0] == '[' {
		var list []telemetry.SecurityEvent
		if err := json.Unmarshal(trimmed, &list); err != nil {
			return nil, fmt.Errorf("invalid JSON event array: %w", err)
		}
		if len(list) == 0 {
			return nil, fmt.Errorf("events array cannot be empty")
		}
		return list, nil
	}

	// Support {"events": [...]} batch object or a single SecurityEvent JSON object
	var batch telemetry.IngestBatchRequest
	if err := json.Unmarshal(trimmed, &batch); err == nil && len(batch.Events) > 0 {
		return batch.Events, nil
	}

	var single telemetry.SecurityEvent
	if err := json.Unmarshal(trimmed, &single); err != nil {
		return nil, fmt.Errorf("invalid JSON event object: %w", err)
	}
	if strings.TrimSpace(single.Message) == "" && strings.TrimSpace(single.RawPayload) == "" {
		return nil, fmt.Errorf("event must include a non-empty 'message' or 'raw_payload'")
	}
	if strings.TrimSpace(single.Message) == "" {
		single.Message = single.RawPayload
	}

	return []telemetry.SecurityEvent{single}, nil
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
