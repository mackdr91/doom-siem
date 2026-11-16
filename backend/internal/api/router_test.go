/*
Author: Domonick Mack
Date: 2026-11-16
Description: Unit and integration tests for the Doom SIEM API router and health checker.
*/

package api_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mackdr91/doom-siem/backend/internal/api"
	"github.com/mackdr91/doom-siem/backend/internal/config"
	"github.com/mackdr91/doom-siem/backend/internal/health"
)

func TestHealthAndEnvironmentEndpoints(t *testing.T) {
	// Spin up a mock ClickHouse HTTP server
	mockCH := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("query") == "SELECT 1" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("1\n"))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer mockCH.Close()

	// Spin up a mock Redis TCP listener that responds with +PONG
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
				buf := make([]byte, 64)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("+PONG\r\n"))
			}(conn)
		}
	}()

	cfg := &config.Config{
		Environment:        "test",
		Version:            "0.1.0-test",
		HTTPPort:           8080,
		SyslogUDPPort:      5514,
		SyslogTCPPort:      5514,
		PostgresDSN:        "postgres://invalid:invalid@127.0.0.1:59999/doom_test?sslmode=disable&connect_timeout=1",
		ClickHouseHTTPURL:  mockCH.URL,
		ClickHouseUser:     "doom_ch",
		ClickHousePassword: "doom_ch_secret",
		ClickHouseDB:       "doom_telemetry",
		RedisAddr:          redisListener.Addr().String(),
		CORSAllowedOrigins: []string{"http://localhost:3000"},
		AIEnabled:          false,
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	checker := health.NewChecker(cfg)
	srv := api.NewServer(cfg, checker, logger)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Verify /api/v1/health
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

	if report.Service != "doom-siem-engine" {
		t.Errorf("expected service doom-siem-engine, got %q", report.Service)
	}
	if len(report.Dependencies) != 3 {
		t.Fatalf("expected 3 dependencies, got %d", len(report.Dependencies))
	}

	// ClickHouse (index 1) and Redis (index 2) should be healthy against mocks
	if report.Dependencies[1].Status != "healthy" {
		t.Errorf("expected ClickHouse status healthy, got %q (%s)", report.Dependencies[1].Status, report.Dependencies[1].Details)
	}
	if report.Dependencies[2].Status != "healthy" {
		t.Errorf("expected Redis status healthy, got %q (%s)", report.Dependencies[2].Status, report.Dependencies[2].Details)
	}

	// Verify /api/v1/environment
	envResp, err := http.Get(ts.URL + "/api/v1/environment")
	if err != nil {
		t.Fatalf("GET /api/v1/environment failed: %v", err)
	}
	defer envResp.Body.Close()

	if envResp.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200 from /api/v1/environment, got %d", envResp.StatusCode)
	}
}
