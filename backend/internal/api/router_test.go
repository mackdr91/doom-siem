/*
Author: Domonick Mack
Date: 2026-11-16
Description: Unit and integration tests for the Doom SIEM API router, health checker, multi-protocol ingestion, MITRE ATT&CK alert triage, and AI threat analysis.
*/

package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/mackdr91/doom-siem/backend/internal/ai"
	"github.com/mackdr91/doom-siem/backend/internal/api"
	"github.com/mackdr91/doom-siem/backend/internal/config"
	"github.com/mackdr91/doom-siem/backend/internal/detection"
	"github.com/mackdr91/doom-siem/backend/internal/health"
	"github.com/mackdr91/doom-siem/backend/internal/ingest"
	"github.com/mackdr91/doom-siem/backend/internal/telemetry"
)

func TestHealthIngestionDetectionAndAIEndpoints(t *testing.T) {
	var storedEventsMu sync.Mutex
	storedEvents := make([]telemetry.SecurityEvent, 0)

	// Spin up a stateful mock ClickHouse HTTP server supporting SELECT 1, INSERT JSONEachRow, and SELECT queries
	mockCH := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("query")

		switch {
		case query == "SELECT 1":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("1\n"))

		case strings.HasPrefix(query, "INSERT INTO"):
			bodyBytes, _ := io.ReadAll(r.Body)
			storedEventsMu.Lock()
			for _, line := range strings.Split(strings.TrimSpace(string(bodyBytes)), "\n") {
				if strings.TrimSpace(line) == "" {
					continue
				}
				var ev telemetry.SecurityEvent
				if err := json.Unmarshal([]byte(line), &ev); err == nil {
					storedEvents = append(storedEvents, ev)
				}
			}
			storedEventsMu.Unlock()
			w.WriteHeader(http.StatusOK)

		case strings.HasPrefix(query, "SELECT count()"):
			storedEventsMu.Lock()
			cnt := len(storedEvents)
			storedEventsMu.Unlock()
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(jsonNumber(cnt) + "\n"))

		case strings.Contains(query, "GROUP BY"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"key":"critical","count":2}` + "\n"))

		case strings.HasPrefix(query, "SELECT toString(event_id)"):
			storedEventsMu.Lock()
			defer storedEventsMu.Unlock()
			w.WriteHeader(http.StatusOK)
			enc := json.NewEncoder(w)
			for _, ev := range storedEvents {
				_ = enc.Encode(ev)
			}

		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer mockCH.Close()

	// Spin up a mock Redis TCP listener supporting PING, XADD, and XLEN
	redisListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock Redis TCP listener: %v", err)
	}
	defer redisListener.Close()

	go func() {
		for {
			conn, acceptErr := redisListener.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, readErr := c.Read(buf)
					if readErr != nil || n == 0 {
						return
					}
					payload := string(buf[:n])
					switch {
					case strings.Contains(payload, "XLEN"):
						_, _ = c.Write([]byte(":4\r\n"))
					case strings.Contains(payload, "XADD"):
						_, _ = c.Write([]byte("+1700000000000-0\r\n"))
					default:
						_, _ = c.Write([]byte("+PONG\r\n"))
					}
				}
			}(conn)
		}
	}()

	cfg := &config.Config{
		Environment:        "test",
		Version:            "0.4.0-test",
		HTTPPort:           8080,
		SyslogUDPPort:      0,
		SyslogTCPPort:      0,
		PostgresDSN:        "postgres://invalid:invalid@127.0.0.1:59999/doom_test?sslmode=disable&connect_timeout=1",
		ClickHouseHTTPURL:  mockCH.URL,
		ClickHouseUser:     "doom_ch",
		ClickHousePassword: "doom_ch_secret",
		ClickHouseDB:       "doom_telemetry",
		RedisAddr:          redisListener.Addr().String(),
		CORSAllowedOrigins: []string{"http://localhost:3002"},
		AIEnabled:          true,
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	checker := health.NewChecker(cfg)
	repo := telemetry.NewRepository(cfg)
	broker := telemetry.NewStreamBroker(cfg.RedisAddr)
	pipeline := ingest.NewPipeline(repo, broker, logger)

	memStore := detection.NewMemoryStore()
	detectionEngine := detection.NewEngine(memStore, logger)
	_ = detectionEngine.RefreshRules(context.Background())
	pipeline.SetDetectionEngine(detectionEngine)

	aiAnalyzer := ai.NewAnalyzer("")

	srv := api.NewServer(cfg, checker, repo, broker, pipeline, detectionEngine, aiAnalyzer, logger)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. Verify POST /api/v1/ingest/webhook triggers SQLi detection rule
	webhookBody := []byte(`{"host":"waf-edge-01","severity":"critical","source_ip":"198.51.100.42","service":"nginx-waf","message":"SQL injection blocked on /login: UNION SELECT 1,2"}`)
	ingestResp, err := http.Post(ts.URL+"/api/v1/ingest/webhook", "application/json", bytes.NewReader(webhookBody))
	if err != nil {
		t.Fatalf("POST /api/v1/ingest/webhook failed: %v", err)
	}
	defer ingestResp.Body.Close()
	if ingestResp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected HTTP 202 from webhook ingest, got %d", ingestResp.StatusCode)
	}

	// 2. Fetch triggered alert
	alertsResp, err := http.Get(ts.URL + "/api/v1/alerts")
	if err != nil {
		t.Fatalf("GET /api/v1/alerts failed: %v", err)
	}
	defer alertsResp.Body.Close()
	var alertsPayload struct {
		Count  int                       `json:"count"`
		Alerts []detection.SecurityAlert `json:"alerts"`
	}
	if err := json.NewDecoder(alertsResp.Body).Decode(&alertsPayload); err != nil {
		t.Fatalf("failed to decode alerts payload: %v", err)
	}
	if alertsPayload.Count == 0 {
		t.Fatalf("expected at least 1 triggered alert")
	}
	alertID := alertsPayload.Alerts[0].ID

	// 3. Verify POST /api/v1/alerts/{id}/analyze generates AI threat summary & persists it
	analyzeResp, err := http.Post(ts.URL+"/api/v1/alerts/"+alertID+"/analyze", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /api/v1/alerts/%s/analyze failed: %v", alertID, err)
	}
	defer analyzeResp.Body.Close()
	if analyzeResp.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200 from alert analyze, got %d", analyzeResp.StatusCode)
	}

	var analyzePayload struct {
		Alert    detection.SecurityAlert `json:"alert"`
		Analysis ai.ThreatAnalysisReport `json:"analysis"`
	}
	if err := json.NewDecoder(analyzeResp.Body).Decode(&analyzePayload); err != nil {
		t.Fatalf("failed to decode analyze payload: %v", err)
	}
	if analyzePayload.Alert.AISummary == "" {
		t.Errorf("expected alert ai_summary to be populated")
	}
	if len(analyzePayload.Analysis.RemediationPlaybook) == 0 {
		t.Errorf("expected non-empty remediation playbook")
	}

	// 4. Verify POST /api/v1/ai/analyze-log
	adhocBody := []byte(`{"log_line":"<34>Nov 16 20:10:00 bastion-gw-01 sshd[4821]: Failed password for invalid user admin from 185.220.101.42 port 51922 ssh2"}`)
	adhocResp, err := http.Post(ts.URL+"/api/v1/ai/analyze-log", "application/json", bytes.NewReader(adhocBody))
	if err != nil {
		t.Fatalf("POST /api/v1/ai/analyze-log failed: %v", err)
	}
	defer adhocResp.Body.Close()
	if adhocResp.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200 from adhoc log analysis, got %d", adhocResp.StatusCode)
	}
}

func jsonNumber(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
