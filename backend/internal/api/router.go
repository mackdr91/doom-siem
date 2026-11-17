/*
Author: Domonick Mack
Date: 2026-11-16
Description: HTTP API router, middleware stack, multi-protocol ingestion endpoints, MITRE ATT&CK rule/alert triage handlers, and AI threat analysis endpoints for Doom SIEM.
*/

package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mackdr91/doom-siem/backend/internal/ai"
	"github.com/mackdr91/doom-siem/backend/internal/config"
	"github.com/mackdr91/doom-siem/backend/internal/detection"
	"github.com/mackdr91/doom-siem/backend/internal/health"
	"github.com/mackdr91/doom-siem/backend/internal/ingest"
	"github.com/mackdr91/doom-siem/backend/internal/intel"
	"github.com/mackdr91/doom-siem/backend/internal/telemetry"
)

// Server encapsulates the HTTP API handlers and dependencies for Doom SIEM.
type Server struct {
	cfg             *config.Config
	checker         *health.Checker
	repo            *telemetry.Repository
	broker          *telemetry.StreamBroker
	pipeline        *ingest.Pipeline
	detectionEngine *detection.Engine
	aiAnalyzer      *ai.Analyzer
	cpeClient       *intel.CPEClient
	logger          *slog.Logger
}

// NewServer constructs a new HTTP API server instance with health, ingestion, telemetry, MITRE detection, AI analysis, and NVD CPE intelligence dependencies.
func NewServer(
	cfg *config.Config,
	checker *health.Checker,
	repo *telemetry.Repository,
	broker *telemetry.StreamBroker,
	pipeline *ingest.Pipeline,
	detectionEngine *detection.Engine,
	aiAnalyzer *ai.Analyzer,
	cpeClient *intel.CPEClient,
	logger *slog.Logger,
) *Server {
	return &Server{
		cfg:             cfg,
		checker:         checker,
		repo:            repo,
		broker:          broker,
		pipeline:        pipeline,
		detectionEngine: detectionEngine,
		aiAnalyzer:      aiAnalyzer,
		cpeClient:       cpeClient,
		logger:          logger,
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

	// Phase 3: MITRE ATT&CK Detection Engine & Alert Triage Workflow
	mux.HandleFunc("GET /api/v1/rules", s.handleListRules)
	mux.HandleFunc("POST /api/v1/rules", s.handleCreateRule)
	mux.HandleFunc("PATCH /api/v1/rules/{id}", s.handleToggleRule)
	mux.HandleFunc("GET /api/v1/alerts", s.handleListAlerts)
	mux.HandleFunc("GET /api/v1/alerts/stats", s.handleAlertStats)
	mux.HandleFunc("GET /api/v1/alerts/{id}", s.handleGetAlert)
	mux.HandleFunc("PATCH /api/v1/alerts/{id}/triage", s.handleUpdateAlertTriage)

	// Phase 4: AI-Assisted Log Analysis & Threat Summarization
	mux.HandleFunc("POST /api/v1/alerts/{id}/analyze", s.handleAnalyzeAlert)
	mux.HandleFunc("POST /api/v1/ai/analyze-log", s.handleAnalyzeAdHocLog)

	// Phase 6: Threat & Asset Intelligence (NIST NVD CPE Lookup)
	mux.HandleFunc("GET /api/v1/intel/cpes", s.handleSearchCPEs)

	return s.recoverMiddleware(s.loggingMiddleware(s.corsMiddleware(mux)))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	report := s.checker.CheckAll(r.Context())
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) handleEnvironment(w http.ResponseWriter, _ *http.Request) {
	payload := map[string]any{
		"project":     "Doom SIEM",
		"phase":       "Phase 5: Full Doom SOC Dark Ops Release",
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
		"message": "Dispatched UDP/TCP Syslog frames (:5514), ingested HTTP/Agent batches, and evaluated MITRE ATT&CK rules",
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

func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.detectionEngine.Store().ListRules(r.Context())
	if err != nil {
		s.logger.Error("list_rules_failed", slog.String("error", err.Error()))
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count": len(rules),
		"rules": rules,
	})
}

func (s *Server) handleCreateRule(w http.ResponseWriter, r *http.Request) {
	var req detection.CreateRuleRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON payload"})
		return
	}
	if strings.TrimSpace(req.RuleCode) == "" || strings.TrimSpace(req.Title) == "" || strings.TrimSpace(req.MitreTactic) == "" || strings.TrimSpace(req.MitreTechniqueID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "rule_code, title, mitre_tactic, and mitre_technique_id are required",
		})
		return
	}

	created, err := s.detectionEngine.Store().CreateRule(r.Context(), req)
	if err != nil {
		s.logger.Error("create_rule_failed", slog.String("error", err.Error()))
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	_ = s.detectionEngine.RefreshRules(r.Context())

	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleToggleRule(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing rule id"})
		return
	}

	var req detection.ToggleRuleRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON payload"})
		return
	}

	updated, err := s.detectionEngine.Store().ToggleRule(r.Context(), id, req.Enabled)
	if errors.Is(err, detection.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "detection rule not found"})
		return
	}
	if err != nil {
		s.logger.Error("toggle_rule_failed", slog.String("error", err.Error()))
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	_ = s.detectionEngine.RefreshRules(r.Context())

	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 100
	if rawLimit := strings.TrimSpace(q.Get("limit")); rawLimit != "" {
		if parsed, err := strconv.Atoi(rawLimit); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	filter := detection.AlertQueryFilter{
		Status:      q.Get("status"),
		Severity:    q.Get("severity"),
		MitreTactic: q.Get("tactic"),
		Search:      q.Get("search"),
		Limit:       limit,
	}

	alerts, err := s.detectionEngine.Store().ListAlerts(r.Context(), filter)
	if err != nil {
		s.logger.Error("list_alerts_failed", slog.String("error", err.Error()))
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"count":  len(alerts),
		"alerts": alerts,
	})
}

func (s *Server) handleAlertStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.detectionEngine.Store().GetAlertStats(r.Context())
	if err != nil {
		s.logger.Error("alert_stats_failed", slog.String("error", err.Error()))
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleGetAlert(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing alert id"})
		return
	}

	alert, err := s.detectionEngine.Store().GetAlertByID(r.Context(), id)
	if errors.Is(err, detection.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "alert not found"})
		return
	}
	if err != nil {
		s.logger.Error("get_alert_failed", slog.String("error", err.Error()))
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, alert)
}

func (s *Server) handleUpdateAlertTriage(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing alert id"})
		return
	}

	var req detection.AlertTriageUpdateRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON payload"})
		return
	}

	updated, err := s.detectionEngine.Store().UpdateAlertTriage(r.Context(), id, req)
	if errors.Is(err, detection.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "alert not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleAnalyzeAlert(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing alert id"})
		return
	}

	alert, err := s.detectionEngine.Store().GetAlertByID(r.Context(), id)
	if errors.Is(err, detection.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "alert not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	report, err := s.aiAnalyzer.AnalyzeAlert(r.Context(), *alert)
	if err != nil {
		s.logger.Error("analyze_alert_failed", slog.String("alert_id", id), slog.String("error", err.Error()))
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	updatedAlert, updateErr := s.detectionEngine.Store().UpdateAlertAISummary(r.Context(), id, report.FormattedMarkdown)
	if updateErr != nil {
		updatedAlert = alert
		updatedAlert.AISummary = report.FormattedMarkdown
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"alert":    updatedAlert,
		"analysis": report,
	})
}

func (s *Server) handleAnalyzeAdHocLog(w http.ResponseWriter, r *http.Request) {
	var req ai.AdHocLogAnalysisRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 128*1024)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON payload"})
		return
	}
	if strings.TrimSpace(req.LogLine) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "log_line is required"})
		return
	}

	report, err := s.aiAnalyzer.AnalyzeAdHocLog(r.Context(), req)
	if err != nil {
		s.logger.Error("analyze_adhoc_log_failed", slog.String("error", err.Error()))
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, report)
}

func (s *Server) handleSearchCPEs(w http.ResponseWriter, r *http.Request) {
	if s.cpeClient == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "CPE intelligence client is not initialized",
		})
		return
	}

	q := r.URL.Query()
	keyword := strings.TrimSpace(q.Get("keyword"))
	cpeMatch := strings.TrimSpace(q.Get("cpe_match"))
	if keyword == "" && cpeMatch == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "either 'keyword' or 'cpe_match' query parameter is required",
		})
		return
	}

	limit := 20
	if rawLimit := strings.TrimSpace(q.Get("limit")); rawLimit != "" {
		if parsed, err := strconv.Atoi(rawLimit); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	includeDeprecated := strings.EqualFold(strings.TrimSpace(q.Get("include_deprecated")), "true")

	result, err := s.cpeClient.SearchCPEs(r.Context(), intel.CPESearchOptions{
		Keyword:           keyword,
		CPEMatchString:    cpeMatch,
		Limit:             limit,
		IncludeDeprecated: includeDeprecated,
	})
	if err != nil {
		s.logger.Error("cpe_lookup_failed", slog.String("error", err.Error()))
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func decodeIngestPayload(raw []byte) ([]telemetry.SecurityEvent, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty request payload")
	}

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
