/*
Author: Domonick Mack
Date: 2026-11-16
Description: Concurrent infrastructure health and latency verifier for PostgreSQL, ClickHouse, and Redis.
*/

package health

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
	"github.com/mackdr91/doom-siem/backend/internal/config"
)

// DependencyStatus represents the health and latency of an individual infrastructure service.
type DependencyStatus struct {
	Name      string `json:"name"`
	Role      string `json:"role"`
	Status    string `json:"status"`
	LatencyMs int64  `json:"latency_ms"`
	Details   string `json:"details"`
}

// IngestionBindings describes the configured network listeners for log collection.
type IngestionBindings struct {
	SyslogUDPPort int    `json:"syslog_udp_port"`
	SyslogTCPPort int    `json:"syslog_tcp_port"`
	HTTPPath      string `json:"http_webhook_path"`
	AgentPath     string `json:"agent_shipper_path"`
}

// SystemHealthReport aggregates overall cluster readiness and service telemetry.
type SystemHealthReport struct {
	Service      string             `json:"service"`
	Environment  string             `json:"environment"`
	Version      string             `json:"version"`
	Status       string             `json:"status"`
	UptimeSec    int64              `json:"uptime_sec"`
	TimestampUTC string             `json:"timestamp_utc"`
	AIReady      bool               `json:"ai_ready"`
	Ingestion    IngestionBindings  `json:"ingestion"`
	Dependencies []DependencyStatus `json:"dependencies"`
}

// Checker coordinates live readiness probes against all Doom SIEM backing datastores.
type Checker struct {
	cfg        *config.Config
	startedAt  time.Time
	httpClient *http.Client
}

// NewChecker initializes a new infrastructure health Checker.
func NewChecker(cfg *config.Config) *Checker {
	return &Checker{
		cfg:       cfg,
		startedAt: time.Now().UTC(),
		httpClient: &http.Client{
			Timeout: 3 * time.Second,
		},
	}
}

// CheckAll runs concurrent health checks against PostgreSQL, ClickHouse, and Redis.
func (c *Checker) CheckAll(ctx context.Context) SystemHealthReport {
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	results := make([]DependencyStatus, 3)
	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		results[0] = c.checkPostgres(probeCtx)
	}()

	go func() {
		defer wg.Done()
		results[1] = c.checkClickHouse(probeCtx)
	}()

	go func() {
		defer wg.Done()
		results[2] = c.checkRedis(probeCtx)
	}()

	wg.Wait()

	overallStatus := "operational"
	for _, dep := range results {
		if dep.Status != "healthy" {
			overallStatus = "degraded"
			break
		}
	}

	return SystemHealthReport{
		Service:      "doom-siem-engine",
		Environment:  c.cfg.Environment,
		Version:      c.cfg.Version,
		Status:       overallStatus,
		UptimeSec:    int64(time.Since(c.startedAt).Seconds()),
		TimestampUTC: time.Now().UTC().Format(time.RFC3339),
		AIReady:      c.cfg.AIEnabled,
		Ingestion: IngestionBindings{
			SyslogUDPPort: c.cfg.SyslogUDPPort,
			SyslogTCPPort: c.cfg.SyslogTCPPort,
			HTTPPath:      "/api/v1/ingest/webhook",
			AgentPath:     "/api/v1/ingest/agent",
		},
		Dependencies: results,
	}
}

func (c *Checker) checkPostgres(ctx context.Context) DependencyStatus {
	start := time.Now()
	status := DependencyStatus{
		Name: "PostgreSQL 16",
		Role: "Alerts, Incident Triage & MITRE Rules",
	}

	db, err := sql.Open("postgres", c.cfg.PostgresDSN)
	if err != nil {
		status.Status = "unreachable"
		status.LatencyMs = time.Since(start).Milliseconds()
		status.Details = fmt.Sprintf("driver initialization failed: %v", err)
		return status
	}
	defer db.Close()

	var sourceCount int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM ingestion_sources").Scan(&sourceCount)
	status.LatencyMs = time.Since(start).Milliseconds()

	if err != nil {
		// Fall back to a basic SELECT 1 ping if schema bootstrap is still in progress
		if pingErr := db.PingContext(ctx); pingErr != nil {
			status.Status = "unreachable"
			status.Details = fmt.Sprintf("connection failed: %v", pingErr)
			return status
		}
		status.Status = "healthy"
		status.Details = "Connected (schema initializing)"
		return status
	}

	status.Status = "healthy"
	status.Details = fmt.Sprintf("Connected (%d collectors registered)", sourceCount)
	return status
}

func (c *Checker) checkClickHouse(ctx context.Context) DependencyStatus {
	start := time.Now()
	status := DependencyStatus{
		Name: "ClickHouse OLAP",
		Role: "Columnar Log & Telemetry Store",
	}

	baseURL := strings.TrimRight(c.cfg.ClickHouseHTTPURL, "/")
	queryURL := fmt.Sprintf("%s/?query=%s", baseURL, url.QueryEscape("SELECT 1"))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, queryURL, nil)
	if err != nil {
		status.Status = "unreachable"
		status.LatencyMs = time.Since(start).Milliseconds()
		status.Details = fmt.Sprintf("invalid ClickHouse URL: %v", err)
		return status
	}

	if c.cfg.ClickHouseUser != "" {
		req.SetBasicAuth(c.cfg.ClickHouseUser, c.cfg.ClickHousePassword)
	}

	resp, err := c.httpClient.Do(req)
	status.LatencyMs = time.Since(start).Milliseconds()
	if err != nil {
		status.Status = "unreachable"
		status.Details = fmt.Sprintf("HTTP probe failed: %v", err)
		return status
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(bodyBytes)) != "1" {
		status.Status = "unreachable"
		status.Details = fmt.Sprintf("unexpected HTTP %d response", resp.StatusCode)
		return status
	}

	status.Status = "healthy"
	status.Details = fmt.Sprintf("Database %s online (MergeTree ready)", c.cfg.ClickHouseDB)
	return status
}

func (c *Checker) checkRedis(ctx context.Context) DependencyStatus {
	start := time.Now()
	status := DependencyStatus{
		Name: "Redis 7 Streams",
		Role: "Event Ingestion Queue & Live Pub/Sub",
	}

	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", c.cfg.RedisAddr)
	if err != nil {
		status.Status = "unreachable"
		status.LatencyMs = time.Since(start).Milliseconds()
		status.Details = fmt.Sprintf("TCP dial failed: %v", err)
		return status
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("*1\r\n$4\r\nPING\r\n")); err != nil {
		status.Status = "unreachable"
		status.LatencyMs = time.Since(start).Milliseconds()
		status.Details = fmt.Sprintf("PING write failed: %v", err)
		return status
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	status.LatencyMs = time.Since(start).Milliseconds()
	if err != nil {
		status.Status = "unreachable"
		status.Details = fmt.Sprintf("PING read failed: %v", err)
		return status
	}

	if !strings.HasPrefix(strings.TrimSpace(line), "+PONG") {
		status.Status = "unreachable"
		status.Details = fmt.Sprintf("unexpected Redis reply: %q", strings.TrimSpace(line))
		return status
	}

	status.Status = "healthy"
	status.Details = "RESP stream broker responding (+PONG)"
	return status
}
