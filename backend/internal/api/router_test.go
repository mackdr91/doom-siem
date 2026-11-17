/*
Author: Domonick Mack
Date: 2026-11-16
Description: Unit and integration tests for the Doom SIEM API router, health checker, and multi-protocol ingestion pipeline.
*/

package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/mackdr91/doom-siem/backend/internal/api"
	"github.com/mackdr91/doom-siem/backend/internal/config"
	"github.com/mackdr91/doom-siem/backend/internal/health"
	"github.com/mackdr91/doom-siem/backend/internal/ingest"
	"github.com/mackdr91/doom-siem/backend/internal/telemetry"
)

func TestHealthAndIngestionPipelineEndpoints(t *testing.T) {
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
		Version:            "0.2.0-test",
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
		AIEnabled:          false,
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	checker := health.NewChecker(cfg)
	repo := telemetry.NewRepository(cfg)
	broker := telemetry.NewStreamBroker(cfg.RedisAddr)
	pipeline := ingest.NewPipeline(repo, broker, logger)
	srv := api.NewServer(cfg, checker, repo, broker, pipeline, logger)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. Verify /api/v1/health
	resp, err := http.Get(ts.URL + "/api/v1/health")
	if err != nil {
		t.Fatalf("GET /api/v1/health failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", resp.StatusCode)
	}

	var report health.SystemHealthReport
	if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
		t.Fatalf("failed to decode health report: %v", err)
	}
	if report.Dependencies[1].Status != "healthy" {
		t.Errorf("expected ClickHouse status healthy, got %q", report.Dependencies[1].Status)
	}
	if report.Dependencies[2].Status != "healthy" {
		t.Errorf("expected Redis status healthy, got %q", report.Dependencies[2].Status)
	}

	// 2. Verify POST /api/v1/ingest/webhook
	webhookBody := []byte(`{"host":"waf-edge-01","severity":"critical","source_ip":"198.51.100.42","service":"nginx-waf","message":"SQL injection blocked on /login"}`)
	ingestResp, err := http.Post(ts.URL+"/api/v1/ingest/webhook", "application/json", bytes.NewReader(webhookBody))
	if err != nil {
		t.Fatalf("POST /api/v1/ingest/webhook failed: %v", err)
	}
	defer ingestResp.Body.Close()
	if ingestResp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected HTTP 202 from webhook ingest, got %d", ingestResp.StatusCode)
	}

	// 3. Verify POST /api/v1/ingest/agent
	agentBody := []byte(`{"events":[{"host":"wkstn-04","severity":"high","service":"edr-agent","message":"Suspicious powershell -enc execution"}]}`)
	agentResp, err := http.Post(ts.URL+"/api/v1/ingest/agent", "application/json", bytes.NewReader(agentBody))
	if err != nil {
		t.Fatalf("POST /api/v1/ingest/agent failed: %v", err)
	}
	defer agentResp.Body.Close()
	if agentResp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected HTTP 202 from agent ingest, got %d", agentResp.StatusCode)
	}

	// 4. Verify GET /api/v1/events
	eventsResp, err := http.Get(ts.URL + "/api/v1/events?limit=10")
	if err != nil {
		t.Fatalf("GET /api/v1/events failed: %v", err)
	}
	defer eventsResp.Body.Close()
	if eventsResp.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200 from /api/v1/events, got %d", eventsResp.StatusCode)
	}

	var eventsPayload struct {
		Count  int                       `json:"count"`
		Events []telemetry.SecurityEvent `json:"events"`
	}
	if err := json.NewDecoder(eventsResp.Body).Decode(&eventsPayload); err != nil {
		t.Fatalf("failed to decode events response: %v", err)
	}
	if eventsPayload.Count != 2 {
		t.Errorf("expected 2 stored events, got %d", eventsPayload.Count)
	}

	// 5. Verify GET /api/v1/events/stats
	statsResp, err := http.Get(ts.URL + "/api/v1/events/stats")
	if err != nil {
		t.Fatalf("GET /api/v1/events/stats failed: %v", err)
	}
	defer statsResp.Body.Close()
	if statsResp.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200 from /api/v1/events/stats, got %d", statsResp.StatusCode)
	}
}

func jsonNumber(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
