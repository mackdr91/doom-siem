/*
Author: Domonick Mack
Date: 2026-11-16
Description: ClickHouse OLAP telemetry repository for batch event ingestion, filtered search, and real-time aggregations.
*/

package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mackdr91/doom-siem/backend/internal/config"
)

// Repository manages persistence and analytical queries against the ClickHouse security_events table.
type Repository struct {
	baseURL    string
	database   string
	username   string
	password   string
	httpClient *http.Client
}

// NewRepository constructs a ClickHouse telemetry Repository.
func NewRepository(cfg *config.Config) *Repository {
	return &Repository{
		baseURL:  strings.TrimRight(cfg.ClickHouseHTTPURL, "/"),
		database: cfg.ClickHouseDB,
		username: cfg.ClickHouseUser,
		password: cfg.ClickHousePassword,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// InsertEvents writes a batch of normalized SecurityEvent records into ClickHouse using JSONEachRow format.
func (r *Repository) InsertEvents(ctx context.Context, events []SecurityEvent) error {
	if len(events) == 0 {
		return nil
	}

	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)

	for _, ev := range events {
		if err := encoder.Encode(ev); err != nil {
			return fmt.Errorf("failed to encode event for ClickHouse: %w", err)
		}
	}

	insertSQL := fmt.Sprintf("INSERT INTO %s.security_events FORMAT JSONEachRow", sanitizeIdentifier(r.database))
	endpoint := fmt.Sprintf("%s/?query=%s", r.baseURL, url.QueryEscape(insertSQL))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, &buf)
	if err != nil {
		return fmt.Errorf("failed to create ClickHouse insert request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if r.username != "" {
		req.SetBasicAuth(r.username, r.password)
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("ClickHouse insert request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("ClickHouse insert HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(errBody)))
	}

	return nil
}

// QueryEvents executes a filtered search against ClickHouse and returns matching SecurityEvent records.
func (r *Repository) QueryEvents(ctx context.Context, filter EventQueryFilter) ([]SecurityEvent, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}

	conditions := make([]string, 0, 4)

	if sev := strings.ToLower(strings.TrimSpace(filter.Severity)); sev != "" {
		conditions = append(conditions, fmt.Sprintf("severity = '%s'", escapeSQLString(sev)))
	}
	if proto := strings.ToLower(strings.TrimSpace(filter.SourceProtocol)); proto != "" {
		conditions = append(conditions, fmt.Sprintf("source_protocol = '%s'", escapeSQLString(proto)))
	}
	if host := strings.TrimSpace(filter.Host); host != "" {
		conditions = append(conditions, fmt.Sprintf("host = '%s'", escapeSQLString(host)))
	}
	if search := strings.TrimSpace(filter.Search); search != "" {
		escaped := escapeSQLString(search)
		conditions = append(conditions, fmt.Sprintf(
			"(positionCaseInsensitive(message, '%s') > 0 OR positionCaseInsensitive(source_ip, '%s') > 0 OR positionCaseInsensitive(service, '%s') > 0 OR positionCaseInsensitive(host, '%s') > 0 OR positionCaseInsensitive(mitre_technique, '%s') > 0)",
			escaped, escaped, escaped, escaped, escaped,
		))
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	dbName := sanitizeIdentifier(r.database)
	querySQL := fmt.Sprintf(
		"SELECT toString(event_id) AS event_id, toString(timestamp) AS timestamp, source_protocol, severity, host, source_ip, destination_ip, service, mitre_tactic, mitre_technique, message, raw_payload FROM %s.security_events %s ORDER BY timestamp DESC LIMIT %d FORMAT JSONEachRow",
		dbName,
		whereClause,
		limit,
	)

	body, err := r.executeQuery(ctx, querySQL)
	if err != nil {
		return nil, err
	}

	events := make([]SecurityEvent, 0)
	lines := strings.Split(strings.TrimSpace(body), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		var ev SecurityEvent
		if decodeErr := json.Unmarshal([]byte(trimmed), &ev); decodeErr == nil {
			events = append(events, ev)
		}
	}

	return events, nil
}

// GetStats computes real-time telemetry aggregations from ClickHouse.
func (r *Repository) GetStats(ctx context.Context, streamDepth int64) (*TelemetryStats, error) {
	dbName := sanitizeIdentifier(r.database)

	totalCount, err := r.queryScalarUint64(ctx, fmt.Sprintf("SELECT count() FROM %s.security_events", dbName))
	if err != nil {
		return nil, err
	}

	bySeverity, err := r.queryBuckets(ctx, fmt.Sprintf(
		"SELECT severity AS key, toUInt64(count()) AS count FROM %s.security_events GROUP BY severity ORDER BY count DESC FORMAT JSONEachRow",
		dbName,
	))
	if err != nil {
		return nil, err
	}

	byProtocol, err := r.queryBuckets(ctx, fmt.Sprintf(
		"SELECT source_protocol AS key, toUInt64(count()) AS count FROM %s.security_events GROUP BY source_protocol ORDER BY count DESC FORMAT JSONEachRow",
		dbName,
	))
	if err != nil {
		return nil, err
	}

	topIPs, err := r.queryBuckets(ctx, fmt.Sprintf(
		"SELECT source_ip AS key, toUInt64(count()) AS count FROM %s.security_events WHERE source_ip != '' AND source_ip != '0.0.0.0' GROUP BY source_ip ORDER BY count DESC LIMIT 8 FORMAT JSONEachRow",
		dbName,
	))
	if err != nil {
		return nil, err
	}

	topHosts, err := r.queryBuckets(ctx, fmt.Sprintf(
		"SELECT host AS key, toUInt64(count()) AS count FROM %s.security_events GROUP BY host ORDER BY count DESC LIMIT 8 FORMAT JSONEachRow",
		dbName,
	))
	if err != nil {
		return nil, err
	}

	return &TelemetryStats{
		TotalEvents:      totalCount,
		StreamQueueDepth: streamDepth,
		BySeverity:       bySeverity,
		ByProtocol:       byProtocol,
		TopSourceIPs:     topIPs,
		TopHosts:         topHosts,
		LastUpdatedAtUTC: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func (r *Repository) queryScalarUint64(ctx context.Context, sqlQuery string) (uint64, error) {
	body, err := r.executeQuery(ctx, sqlQuery)
	if err != nil {
		return 0, err
	}
	val, parseErr := strconv.ParseUint(strings.TrimSpace(body), 10, 64)
	if parseErr != nil {
		return 0, nil
	}
	return val, nil
}

func (r *Repository) queryBuckets(ctx context.Context, sqlQuery string) ([]BucketCount, error) {
	body, err := r.executeQuery(ctx, sqlQuery)
	if err != nil {
		return nil, err
	}
	buckets := make([]BucketCount, 0)
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		var raw struct {
			Key   string `json:"key"`
			Count any    `json:"count"`
		}
		if err := json.Unmarshal([]byte(trimmed), &raw); err == nil {
			var parsedCount uint64
			switch v := raw.Count.(type) {
			case float64:
				parsedCount = uint64(v)
			case string:
				parsedCount, _ = strconv.ParseUint(v, 10, 64)
			}
			buckets = append(buckets, BucketCount{
				Key:   raw.Key,
				Count: parsedCount,
			})
		}
	}
	return buckets, nil
}

func (r *Repository) executeQuery(ctx context.Context, sqlQuery string) (string, error) {
	endpoint := fmt.Sprintf("%s/?query=%s", r.baseURL, url.QueryEscape(sqlQuery))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	if r.username != "" {
		req.SetBasicAuth(r.username, r.password)
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("ClickHouse query failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ClickHouse HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}

	return string(bodyBytes), nil
}

func escapeSQLString(val string) string {
	replaced := strings.ReplaceAll(val, `\`, `\\`)
	return strings.ReplaceAll(replaced, `'`, `\'`)
}

func sanitizeIdentifier(ident string) string {
	var sb strings.Builder
	for _, r := range ident {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			sb.WriteRune(r)
		}
	}
	res := sb.String()
	if res == "" {
		return "doom_telemetry"
	}
	return res
}
