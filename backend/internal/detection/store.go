/*
Author: Domonick Mack
Date: 2026-11-16
Description: PostgreSQL and in-memory persistence stores for MITRE ATT&CK detection rules and alert triage queues.
*/

package detection

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
	"github.com/mackdr91/doom-siem/backend/internal/telemetry"
)

// ErrNotFound is returned when a requested rule or alert ID does not exist.
var ErrNotFound = errors.New("record not found")

// Store defines the persistence contract for MITRE ATT&CK rules and security alerts.
type Store interface {
	Bootstrap(ctx context.Context) error
	ListRules(ctx context.Context) ([]DetectionRule, error)
	CreateRule(ctx context.Context, req CreateRuleRequest) (*DetectionRule, error)
	ToggleRule(ctx context.Context, id string, enabled bool) (*DetectionRule, error)
	CreateAlert(ctx context.Context, alert SecurityAlert) (*SecurityAlert, error)
	ListAlerts(ctx context.Context, filter AlertQueryFilter) ([]SecurityAlert, error)
	GetAlertByID(ctx context.Context, id string) (*SecurityAlert, error)
	UpdateAlertTriage(ctx context.Context, id string, req AlertTriageUpdateRequest) (*SecurityAlert, error)
	UpdateAlertAISummary(ctx context.Context, id string, summary string) (*SecurityAlert, error)
	GetAlertStats(ctx context.Context) (*AlertSummaryStats, error)
	Close() error
}

// DefaultSeedRules returns the baseline MITRE ATT&CK detection rules seeded into Doom SIEM.
func DefaultSeedRules() []CreateRuleRequest {
	enabled := true
	return []CreateRuleRequest{
		{
			RuleCode:             "DOOM-RULE-001",
			Title:                "SSH Brute Force & Invalid User Enumeration",
			Description:          "Detects repeated SSH password authentication failures and invalid account probes.",
			Severity:             telemetry.SeverityHigh,
			MitreTactic:          "Credential Access",
			MitreTechniqueID:     "T1110",
			MatchKeywords:        "failed password,invalid user,ssh brute",
			SourceProtocolFilter: "",
			Enabled:              &enabled,
		},
		{
			RuleCode:             "DOOM-RULE-002",
			Title:                "WAF SQL Injection & Web Application Exploit",
			Description:          "Detects SQL injection UNION SELECT payloads and web exploit signatures.",
			Severity:             telemetry.SeverityCritical,
			MitreTactic:          "Initial Access",
			MitreTechniqueID:     "T1190",
			MatchKeywords:        "sql injection,union select,xp_cmdshell,/etc/passwd",
			SourceProtocolFilter: "",
			Enabled:              &enabled,
		},
		{
			RuleCode:             "DOOM-RULE-003",
			Title:                "Obfuscated PowerShell & Living-off-the-Land Execution",
			Description:          "Detects base64 encoded or hidden window PowerShell execution from endpoint telemetry.",
			Severity:             telemetry.SeverityHigh,
			MitreTactic:          "Execution",
			MitreTechniqueID:     "T1059.001",
			MatchKeywords:        "powershell.exe,-enc,hidden,invoke-expression",
			SourceProtocolFilter: "",
			Enabled:              &enabled,
		},
		{
			RuleCode:             "DOOM-RULE-004",
			Title:                "SMBv2 Administrative Share Lateral Movement",
			Description:          "Detects lateral movement attempts over SMB administrative shares (ADMIN$, C$, IPC$).",
			Severity:             telemetry.SeverityHigh,
			MitreTactic:          "Lateral Movement",
			MitreTechniqueID:     "T1021.002",
			MatchKeywords:        "admin$,c$,lateral movement,psexec,smbv2",
			SourceProtocolFilter: "",
			Enabled:              &enabled,
		},
		{
			RuleCode:             "DOOM-RULE-005",
			Title:                "Container Runtime Host Escape Attempt",
			Description:          "Detects privileged hostPath mounts, core_pattern tampering, and container escape techniques.",
			Severity:             telemetry.SeverityCritical,
			MitreTactic:          "Privilege Escalation",
			MitreTechniqueID:     "T1611",
			MatchKeywords:        "container escape,core_pattern,hostpath,docker.sock",
			SourceProtocolFilter: "",
			Enabled:              &enabled,
		},
		{
			RuleCode:             "DOOM-RULE-006",
			Title:                "MFA Push Fatigue & Identity Stuffing",
			Description:          "Detects repeated MFA push rejections and anomalous identity provider authentication denials.",
			Severity:             telemetry.SeverityMedium,
			MitreTactic:          "Credential Access",
			MitreTechniqueID:     "T1110.004",
			MatchKeywords:        "mfa push,factor.denied,fatigue,impossible travel",
			SourceProtocolFilter: "",
			Enabled:              &enabled,
		},
	}
}

// PostgresStore implements Store backed by PostgreSQL 16.
type PostgresStore struct {
	db *sql.DB
}

// NewPostgresStore opens a connection pool to PostgreSQL for detection rules and alert triage.
func NewPostgresStore(dsn string) (*PostgresStore, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open postgres connection: %w", err)
	}
	db.SetMaxOpenConns(15)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	return &PostgresStore{db: db}, nil
}

// Close closes the underlying PostgreSQL connection pool.
func (s *PostgresStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// Bootstrap runs idempotent schema migrations and seeds the default MITRE ATT&CK rules.
func (s *PostgresStore) Bootstrap(ctx context.Context) error {
	migrations := []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`,
		`CREATE TABLE IF NOT EXISTS detection_rules (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			rule_code VARCHAR(64) NOT NULL UNIQUE,
			title VARCHAR(255) NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			severity VARCHAR(24) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
			mitre_tactic VARCHAR(128) NOT NULL,
			mitre_technique_id VARCHAR(32) NOT NULL,
			match_keywords TEXT NOT NULL DEFAULT '',
			source_protocol_filter VARCHAR(32) NOT NULL DEFAULT '',
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);`,
		`ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS match_keywords TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS source_protocol_filter VARCHAR(32) NOT NULL DEFAULT '';`,
		`CREATE TABLE IF NOT EXISTS security_alerts (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			rule_id UUID REFERENCES detection_rules(id) ON DELETE SET NULL,
			rule_code VARCHAR(64) NOT NULL DEFAULT '',
			title VARCHAR(255) NOT NULL,
			severity VARCHAR(24) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
			status VARCHAR(32) NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'resolved', 'false_positive')),
			mitre_tactic VARCHAR(128) NOT NULL DEFAULT '',
			mitre_technique_id VARCHAR(32) NOT NULL DEFAULT '',
			event_id VARCHAR(64) NOT NULL DEFAULT '',
			source_protocol VARCHAR(32) NOT NULL DEFAULT '',
			source_ip VARCHAR(64) NOT NULL DEFAULT '',
			target_host VARCHAR(128) NOT NULL DEFAULT '',
			service VARCHAR(64) NOT NULL DEFAULT '',
			matched_excerpt TEXT NOT NULL DEFAULT '',
			raw_event_json TEXT NOT NULL DEFAULT '',
			ai_summary TEXT,
			assignee VARCHAR(128) NOT NULL DEFAULT 'SOC-Queue',
			notes TEXT NOT NULL DEFAULT '',
			triggered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);`,
		`ALTER TABLE security_alerts ADD COLUMN IF NOT EXISTS rule_code VARCHAR(64) NOT NULL DEFAULT '';`,
		`ALTER TABLE security_alerts ADD COLUMN IF NOT EXISTS mitre_tactic VARCHAR(128) NOT NULL DEFAULT '';`,
		`ALTER TABLE security_alerts ADD COLUMN IF NOT EXISTS mitre_technique_id VARCHAR(32) NOT NULL DEFAULT '';`,
		`ALTER TABLE security_alerts ADD COLUMN IF NOT EXISTS event_id VARCHAR(64) NOT NULL DEFAULT '';`,
		`ALTER TABLE security_alerts ADD COLUMN IF NOT EXISTS source_protocol VARCHAR(32) NOT NULL DEFAULT '';`,
		`ALTER TABLE security_alerts ADD COLUMN IF NOT EXISTS service VARCHAR(64) NOT NULL DEFAULT '';`,
		`ALTER TABLE security_alerts ADD COLUMN IF NOT EXISTS matched_excerpt TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE security_alerts ADD COLUMN IF NOT EXISTS raw_event_json TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE security_alerts ADD COLUMN IF NOT EXISTS assignee VARCHAR(128) NOT NULL DEFAULT 'SOC-Queue';`,
		`ALTER TABLE security_alerts ADD COLUMN IF NOT EXISTS notes TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE security_alerts ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();`,
	}

	for _, stmt := range migrations {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("schema migration failed: %w", err)
		}
	}

	for _, seed := range DefaultSeedRules() {
		_, err := s.db.ExecContext(ctx, `
			INSERT INTO detection_rules (rule_code, title, description, severity, mitre_tactic, mitre_technique_id, match_keywords, source_protocol_filter, enabled)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (rule_code) DO UPDATE SET
				description = EXCLUDED.description,
				match_keywords = EXCLUDED.match_keywords,
				mitre_tactic = EXCLUDED.mitre_tactic,
				mitre_technique_id = EXCLUDED.mitre_technique_id
		`,
			seed.RuleCode,
			seed.Title,
			seed.Description,
			seed.Severity,
			seed.MitreTactic,
			seed.MitreTechniqueID,
			seed.MatchKeywords,
			seed.SourceProtocolFilter,
			true,
		)
		if err != nil {
			return fmt.Errorf("failed to seed rule %s: %w", seed.RuleCode, err)
		}
	}

	return nil
}

// ListRules returns all registered MITRE ATT&CK detection rules ordered by rule_code.
func (s *PostgresStore) ListRules(ctx context.Context) ([]DetectionRule, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id::text, rule_code, title, description, severity, mitre_tactic, mitre_technique_id,
		       match_keywords, source_protocol_filter, enabled, to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
		FROM detection_rules
		ORDER BY rule_code ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	rules := make([]DetectionRule, 0)
	for rows.Next() {
		var r DetectionRule
		if err := rows.Scan(
			&r.ID,
			&r.RuleCode,
			&r.Title,
			&r.Description,
			&r.Severity,
			&r.MitreTactic,
			&r.MitreTechniqueID,
			&r.MatchKeywords,
			&r.SourceProtocolFilter,
			&r.Enabled,
			&r.CreatedAt,
		); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// CreateRule inserts a new custom MITRE ATT&CK detection rule.
func (s *PostgresStore) CreateRule(ctx context.Context, req CreateRuleRequest) (*DetectionRule, error) {
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	var r DetectionRule
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO detection_rules (rule_code, title, description, severity, mitre_tactic, mitre_technique_id, match_keywords, source_protocol_filter, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id::text, rule_code, title, description, severity, mitre_tactic, mitre_technique_id, match_keywords, source_protocol_filter, enabled,
		          to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
	`,
		strings.TrimSpace(req.RuleCode),
		strings.TrimSpace(req.Title),
		strings.TrimSpace(req.Description),
		normalizeSeverity(req.Severity),
		strings.TrimSpace(req.MitreTactic),
		strings.TrimSpace(req.MitreTechniqueID),
		strings.TrimSpace(req.MatchKeywords),
		strings.TrimSpace(req.SourceProtocolFilter),
		enabled,
	).Scan(
		&r.ID,
		&r.RuleCode,
		&r.Title,
		&r.Description,
		&r.Severity,
		&r.MitreTactic,
		&r.MitreTechniqueID,
		&r.MatchKeywords,
		&r.SourceProtocolFilter,
		&r.Enabled,
		&r.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// ToggleRule enables or disables an existing detection rule by ID.
func (s *PostgresStore) ToggleRule(ctx context.Context, id string, enabled bool) (*DetectionRule, error) {
	var r DetectionRule
	err := s.db.QueryRowContext(ctx, `
		UPDATE detection_rules
		SET enabled = $2
		WHERE id::text = $1 OR rule_code = $1
		RETURNING id::text, rule_code, title, description, severity, mitre_tactic, mitre_technique_id, match_keywords, source_protocol_filter, enabled,
		          to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
	`, id, enabled).Scan(
		&r.ID,
		&r.RuleCode,
		&r.Title,
		&r.Description,
		&r.Severity,
		&r.MitreTactic,
		&r.MitreTechniqueID,
		&r.MatchKeywords,
		&r.SourceProtocolFilter,
		&r.Enabled,
		&r.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// CreateAlert persists a newly triggered SecurityAlert into PostgreSQL.
func (s *PostgresStore) CreateAlert(ctx context.Context, alert SecurityAlert) (*SecurityAlert, error) {
	var ruleIDParam any
	if strings.TrimSpace(alert.RuleID) != "" {
		ruleIDParam = alert.RuleID
	}

	if strings.TrimSpace(alert.Status) == "" {
		alert.Status = AlertStatusOpen
	}
	if strings.TrimSpace(alert.Assignee) == "" {
		alert.Assignee = "SOC-Queue"
	}

	var created SecurityAlert
	var nullableRuleID, nullableAISummary sql.NullString

	err := s.db.QueryRowContext(ctx, `
		INSERT INTO security_alerts (
			rule_id, rule_code, title, severity, status, mitre_tactic, mitre_technique_id,
			event_id, source_protocol, source_ip, target_host, service, matched_excerpt,
			raw_event_json, ai_summary, assignee, notes
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NULLIF($15, ''), $16, $17)
		RETURNING id::text, COALESCE(rule_id::text, ''), rule_code, title, severity, status,
		          mitre_tactic, mitre_technique_id, event_id, source_protocol, source_ip,
		          target_host, service, matched_excerpt, raw_event_json, COALESCE(ai_summary, ''),
		          assignee, notes,
		          to_char(triggered_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
		          to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
	`,
		ruleIDParam,
		alert.RuleCode,
		alert.Title,
		normalizeSeverity(alert.Severity),
		alert.Status,
		alert.MitreTactic,
		alert.MitreTechniqueID,
		alert.EventID,
		alert.SourceProtocol,
		alert.SourceIP,
		alert.TargetHost,
		alert.Service,
		alert.MatchedExcerpt,
		alert.RawEventJSON,
		alert.AISummary,
		alert.Assignee,
		alert.Notes,
	).Scan(
		&created.ID,
		&nullableRuleID,
		&created.RuleCode,
		&created.Title,
		&created.Severity,
		&created.Status,
		&created.MitreTactic,
		&created.MitreTechniqueID,
		&created.EventID,
		&created.SourceProtocol,
		&created.SourceIP,
		&created.TargetHost,
		&created.Service,
		&created.MatchedExcerpt,
		&created.RawEventJSON,
		&nullableAISummary,
		&created.Assignee,
		&created.Notes,
		&created.TriggeredAt,
		&created.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	created.RuleID = nullableRuleID.String
	created.AISummary = nullableAISummary.String
	return &created, nil
}

// ListAlerts queries PostgreSQL for security alerts matching the provided filter.
func (s *PostgresStore) ListAlerts(ctx context.Context, filter AlertQueryFilter) ([]SecurityAlert, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}

	clauses := make([]string, 0, 4)
	args := make([]any, 0, 5)
	argIdx := 1

	if status := strings.ToLower(strings.TrimSpace(filter.Status)); status != "" {
		clauses = append(clauses, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, status)
		argIdx++
	}
	if sev := strings.ToLower(strings.TrimSpace(filter.Severity)); sev != "" {
		clauses = append(clauses, fmt.Sprintf("severity = $%d", argIdx))
		args = append(args, sev)
		argIdx++
	}
	if tactic := strings.TrimSpace(filter.MitreTactic); tactic != "" {
		clauses = append(clauses, fmt.Sprintf("LOWER(mitre_tactic) = LOWER($%d)", argIdx))
		args = append(args, tactic)
		argIdx++
	}
	if search := strings.TrimSpace(filter.Search); search != "" {
		clauses = append(clauses, fmt.Sprintf(
			"(title ILIKE $%d OR source_ip ILIKE $%d OR target_host ILIKE $%d OR matched_excerpt ILIKE $%d OR mitre_technique_id ILIKE $%d)",
			argIdx, argIdx, argIdx, argIdx, argIdx,
		))
		args = append(args, "%"+search+"%")
		argIdx++
	}

	whereSQL := ""
	if len(clauses) > 0 {
		whereSQL = "WHERE " + strings.Join(clauses, " AND ")
	}

	args = append(args, limit)
	query := fmt.Sprintf(`
		SELECT id::text, COALESCE(rule_id::text, ''), rule_code, title, severity, status,
		       mitre_tactic, mitre_technique_id, event_id, source_protocol, source_ip,
		       target_host, service, matched_excerpt, raw_event_json, COALESCE(ai_summary, ''),
		       assignee, notes,
		       to_char(triggered_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
		       to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
		FROM security_alerts
		%s
		ORDER BY triggered_at DESC
		LIMIT $%d
	`, whereSQL, argIdx)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	alerts := make([]SecurityAlert, 0)
	for rows.Next() {
		var a SecurityAlert
		if err := rows.Scan(
			&a.ID,
			&a.RuleID,
			&a.RuleCode,
			&a.Title,
			&a.Severity,
			&a.Status,
			&a.MitreTactic,
			&a.MitreTechniqueID,
			&a.EventID,
			&a.SourceProtocol,
			&a.SourceIP,
			&a.TargetHost,
			&a.Service,
			&a.MatchedExcerpt,
			&a.RawEventJSON,
			&a.AISummary,
			&a.Assignee,
			&a.Notes,
			&a.TriggeredAt,
			&a.UpdatedAt,
		); err != nil {
			return nil, err
		}
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

// GetAlertByID retrieves a single SecurityAlert by its UUID.
func (s *PostgresStore) GetAlertByID(ctx context.Context, id string) (*SecurityAlert, error) {
	var a SecurityAlert
	err := s.db.QueryRowContext(ctx, `
		SELECT id::text, COALESCE(rule_id::text, ''), rule_code, title, severity, status,
		       mitre_tactic, mitre_technique_id, event_id, source_protocol, source_ip,
		       target_host, service, matched_excerpt, raw_event_json, COALESCE(ai_summary, ''),
		       assignee, notes,
		       to_char(triggered_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
		       to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
		FROM security_alerts
		WHERE id::text = $1
	`, id).Scan(
		&a.ID,
		&a.RuleID,
		&a.RuleCode,
		&a.Title,
		&a.Severity,
		&a.Status,
		&a.MitreTactic,
		&a.MitreTechniqueID,
		&a.EventID,
		&a.SourceProtocol,
		&a.SourceIP,
		&a.TargetHost,
		&a.Service,
		&a.MatchedExcerpt,
		&a.RawEventJSON,
		&a.AISummary,
		&a.Assignee,
		&a.Notes,
		&a.TriggeredAt,
		&a.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// UpdateAlertTriage updates the status, assignee, and notes of an alert during SOC incident triage.
func (s *PostgresStore) UpdateAlertTriage(ctx context.Context, id string, req AlertTriageUpdateRequest) (*SecurityAlert, error) {
	existing, err := s.GetAlertByID(ctx, id)
	if err != nil {
		return nil, err
	}

	status := strings.ToLower(strings.TrimSpace(req.Status))
	if status == "" {
		status = existing.Status
	}
	switch status {
	case AlertStatusOpen, AlertStatusInvestigating, AlertStatusResolved, AlertStatusFalsePositive:
	default:
		return nil, fmt.Errorf("invalid alert status %q", status)
	}

	assignee := strings.TrimSpace(req.Assignee)
	if assignee == "" {
		assignee = existing.Assignee
	}

	notes := req.Notes
	if strings.TrimSpace(notes) == "" {
		notes = existing.Notes
	}

	var updated SecurityAlert
	err = s.db.QueryRowContext(ctx, `
		UPDATE security_alerts
		SET status = $2, assignee = $3, notes = $4, updated_at = NOW()
		WHERE id::text = $1
		RETURNING id::text, COALESCE(rule_id::text, ''), rule_code, title, severity, status,
		          mitre_tactic, mitre_technique_id, event_id, source_protocol, source_ip,
		          target_host, service, matched_excerpt, raw_event_json, COALESCE(ai_summary, ''),
		          assignee, notes,
		          to_char(triggered_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
		          to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
	`, id, status, assignee, notes).Scan(
		&updated.ID,
		&updated.RuleID,
		&updated.RuleCode,
		&updated.Title,
		&updated.Severity,
		&updated.Status,
		&updated.MitreTactic,
		&updated.MitreTechniqueID,
		&updated.EventID,
		&updated.SourceProtocol,
		&updated.SourceIP,
		&updated.TargetHost,
		&updated.Service,
		&updated.MatchedExcerpt,
		&updated.RawEventJSON,
		&updated.AISummary,
		&updated.Assignee,
		&updated.Notes,
		&updated.TriggeredAt,
		&updated.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &updated, nil
}

// UpdateAlertAISummary stores an AI-generated threat analysis summary on an alert.
func (s *PostgresStore) UpdateAlertAISummary(ctx context.Context, id string, summary string) (*SecurityAlert, error) {
	var updated SecurityAlert
	err := s.db.QueryRowContext(ctx, `
		UPDATE security_alerts
		SET ai_summary = $2, updated_at = NOW()
		WHERE id::text = $1
		RETURNING id::text, COALESCE(rule_id::text, ''), rule_code, title, severity, status,
		          mitre_tactic, mitre_technique_id, event_id, source_protocol, source_ip,
		          target_host, service, matched_excerpt, raw_event_json, COALESCE(ai_summary, ''),
		          assignee, notes,
		          to_char(triggered_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
		          to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
	`, id, summary).Scan(
		&updated.ID,
		&updated.RuleID,
		&updated.RuleCode,
		&updated.Title,
		&updated.Severity,
		&updated.Status,
		&updated.MitreTactic,
		&updated.MitreTechniqueID,
		&updated.EventID,
		&updated.SourceProtocol,
		&updated.SourceIP,
		&updated.TargetHost,
		&updated.Service,
		&updated.MatchedExcerpt,
		&updated.RawEventJSON,
		&updated.AISummary,
		&updated.Assignee,
		&updated.Notes,
		&updated.TriggeredAt,
		&updated.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &updated, nil
}

// GetAlertStats aggregates alert metrics across statuses, severities, and MITRE ATT&CK tactics.
func (s *PostgresStore) GetAlertStats(ctx context.Context) (*AlertSummaryStats, error) {
	stats := &AlertSummaryStats{
		BySeverity:    make([]AlertBucket, 0),
		ByStatus:      make([]AlertBucket, 0),
		ByMitreTactic: make([]AlertBucket, 0),
	}

	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM detection_rules WHERE enabled = TRUE`).Scan(&stats.ActiveRulesCount)

	rows, err := s.db.QueryContext(ctx, `SELECT status, COUNT(*) FROM security_alerts GROUP BY status ORDER BY COUNT(*) DESC`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var b AlertBucket
		if err := rows.Scan(&b.Key, &b.Count); err == nil {
			stats.ByStatus = append(stats.ByStatus, b)
			stats.TotalAlerts += b.Count
			switch b.Key {
			case AlertStatusOpen:
				stats.OpenAlerts = b.Count
			case AlertStatusInvestigating:
				stats.InvestigatingAlerts = b.Count
			case AlertStatusResolved:
				stats.ResolvedAlerts = b.Count
			case AlertStatusFalsePositive:
				stats.FalsePositiveAlerts = b.Count
			}
		}
	}
	_ = rows.Close()

	sevRows, err := s.db.QueryContext(ctx, `SELECT severity, COUNT(*) FROM security_alerts GROUP BY severity ORDER BY COUNT(*) DESC`)
	if err == nil {
		for sevRows.Next() {
			var b AlertBucket
			if scanErr := sevRows.Scan(&b.Key, &b.Count); scanErr == nil {
				stats.BySeverity = append(stats.BySeverity, b)
				if b.Key == telemetry.SeverityCritical {
					stats.CriticalAlerts = b.Count
				}
			}
		}
		_ = sevRows.Close()
	}

	tacticRows, err := s.db.QueryContext(ctx, `SELECT mitre_tactic, COUNT(*) FROM security_alerts WHERE mitre_tactic != '' GROUP BY mitre_tactic ORDER BY COUNT(*) DESC`)
	if err == nil {
		for tacticRows.Next() {
			var b AlertBucket
			if scanErr := tacticRows.Scan(&b.Key, &b.Count); scanErr == nil {
				stats.ByMitreTactic = append(stats.ByMitreTactic, b)
			}
		}
		_ = tacticRows.Close()
	}

	return stats, nil
}

// MemoryStore is an in-memory thread-safe implementation of Store for unit testing and fallback operation.
type MemoryStore struct {
	mu     sync.RWMutex
	rules  []DetectionRule
	alerts []SecurityAlert
}

// NewMemoryStore creates an initialized MemoryStore seeded with the default MITRE ATT&CK rules.
func NewMemoryStore() *MemoryStore {
	m := &MemoryStore{
		rules:  make([]DetectionRule, 0),
		alerts: make([]SecurityAlert, 0),
	}
	_ = m.Bootstrap(context.Background())
	return m
}

// Bootstrap seeds the default MITRE ATT&CK rules into the MemoryStore.
func (m *MemoryStore) Bootstrap(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.rules) > 0 {
		return nil
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for _, seed := range DefaultSeedRules() {
		m.rules = append(m.rules, DetectionRule{
			ID:                   telemetry.GenerateUUIDv4(),
			RuleCode:             seed.RuleCode,
			Title:                seed.Title,
			Description:          seed.Description,
			Severity:             seed.Severity,
			MitreTactic:          seed.MitreTactic,
			MitreTechniqueID:     seed.MitreTechniqueID,
			MatchKeywords:        seed.MatchKeywords,
			SourceProtocolFilter: seed.SourceProtocolFilter,
			Enabled:              true,
			CreatedAt:            now,
		})
	}
	return nil
}

// ListRules returns all rules in the MemoryStore.
func (m *MemoryStore) ListRules(_ context.Context) ([]DetectionRule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]DetectionRule, len(m.rules))
	copy(out, m.rules)
	return out, nil
}

// CreateRule adds a new rule to the MemoryStore.
func (m *MemoryStore) CreateRule(_ context.Context, req CreateRuleRequest) (*DetectionRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	r := DetectionRule{
		ID:                   telemetry.GenerateUUIDv4(),
		RuleCode:             strings.TrimSpace(req.RuleCode),
		Title:                strings.TrimSpace(req.Title),
		Description:          strings.TrimSpace(req.Description),
		Severity:             normalizeSeverity(req.Severity),
		MitreTactic:          strings.TrimSpace(req.MitreTactic),
		MitreTechniqueID:     strings.TrimSpace(req.MitreTechniqueID),
		MatchKeywords:        strings.TrimSpace(req.MatchKeywords),
		SourceProtocolFilter: strings.TrimSpace(req.SourceProtocolFilter),
		Enabled:              enabled,
		CreatedAt:            time.Now().UTC().Format(time.RFC3339),
	}
	m.rules = append(m.rules, r)
	return &r, nil
}

// ToggleRule updates the enabled flag for a rule in the MemoryStore.
func (m *MemoryStore) ToggleRule(_ context.Context, id string, enabled bool) (*DetectionRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.rules {
		if m.rules[i].ID == id || m.rules[i].RuleCode == id {
			m.rules[i].Enabled = enabled
			updated := m.rules[i]
			return &updated, nil
		}
	}
	return nil, ErrNotFound
}

// CreateAlert stores a new SecurityAlert in the MemoryStore.
func (m *MemoryStore) CreateAlert(_ context.Context, alert SecurityAlert) (*SecurityAlert, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC().Format(time.RFC3339)
	alert.ID = telemetry.GenerateUUIDv4()
	if alert.Status == "" {
		alert.Status = AlertStatusOpen
	}
	if alert.Assignee == "" {
		alert.Assignee = "SOC-Queue"
	}
	alert.TriggeredAt = now
	alert.UpdatedAt = now
	m.alerts = append([]SecurityAlert{alert}, m.alerts...)
	return &alert, nil
}

// ListAlerts filters and returns alerts from the MemoryStore.
func (m *MemoryStore) ListAlerts(_ context.Context, filter AlertQueryFilter) ([]SecurityAlert, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]SecurityAlert, 0)
	for _, a := range m.alerts {
		if filter.Status != "" && !strings.EqualFold(a.Status, filter.Status) {
			continue
		}
		if filter.Severity != "" && !strings.EqualFold(a.Severity, filter.Severity) {
			continue
		}
		if filter.MitreTactic != "" && !strings.EqualFold(a.MitreTactic, filter.MitreTactic) {
			continue
		}
		out = append(out, a)
		if filter.Limit > 0 && len(out) >= filter.Limit {
			break
		}
	}
	return out, nil
}

// GetAlertByID finds an alert by ID in the MemoryStore.
func (m *MemoryStore) GetAlertByID(_ context.Context, id string) (*SecurityAlert, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, a := range m.alerts {
		if a.ID == id {
			found := a
			return &found, nil
		}
	}
	return nil, ErrNotFound
}

// UpdateAlertTriage updates an alert's triage status, assignee, and notes in the MemoryStore.
func (m *MemoryStore) UpdateAlertTriage(_ context.Context, id string, req AlertTriageUpdateRequest) (*SecurityAlert, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.alerts {
		if m.alerts[i].ID == id {
			if req.Status != "" {
				m.alerts[i].Status = strings.ToLower(strings.TrimSpace(req.Status))
			}
			if req.Assignee != "" {
				m.alerts[i].Assignee = strings.TrimSpace(req.Assignee)
			}
			if req.Notes != "" {
				m.alerts[i].Notes = req.Notes
			}
			m.alerts[i].UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			updated := m.alerts[i]
			return &updated, nil
		}
	}
	return nil, ErrNotFound
}

// UpdateAlertAISummary updates an alert's AI summary in the MemoryStore.
func (m *MemoryStore) UpdateAlertAISummary(_ context.Context, id string, summary string) (*SecurityAlert, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.alerts {
		if m.alerts[i].ID == id {
			m.alerts[i].AISummary = summary
			m.alerts[i].UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			updated := m.alerts[i]
			return &updated, nil
		}
	}
	return nil, ErrNotFound
}

// GetAlertStats computes summary metrics from the MemoryStore.
func (m *MemoryStore) GetAlertStats(_ context.Context) (*AlertSummaryStats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := &AlertSummaryStats{
		TotalAlerts:   len(m.alerts),
		BySeverity:    make([]AlertBucket, 0),
		ByStatus:      make([]AlertBucket, 0),
		ByMitreTactic: make([]AlertBucket, 0),
	}
	for _, r := range m.rules {
		if r.Enabled {
			stats.ActiveRulesCount++
		}
	}
	sevMap := map[string]int{}
	statusMap := map[string]int{}
	tacticMap := map[string]int{}

	for _, a := range m.alerts {
		sevMap[a.Severity]++
		statusMap[a.Status]++
		if a.MitreTactic != "" {
			tacticMap[a.MitreTactic]++
		}
		if a.Status == AlertStatusOpen {
			stats.OpenAlerts++
		}
		if a.Status == AlertStatusInvestigating {
			stats.InvestigatingAlerts++
		}
		if a.Status == AlertStatusResolved {
			stats.ResolvedAlerts++
		}
		if a.Status == AlertStatusFalsePositive {
			stats.FalsePositiveAlerts++
		}
		if a.Severity == telemetry.SeverityCritical {
			stats.CriticalAlerts++
		}
	}
	for k, v := range sevMap {
		stats.BySeverity = append(stats.BySeverity, AlertBucket{Key: k, Count: v})
	}
	for k, v := range statusMap {
		stats.ByStatus = append(stats.ByStatus, AlertBucket{Key: k, Count: v})
	}
	for k, v := range tacticMap {
		stats.ByMitreTactic = append(stats.ByMitreTactic, AlertBucket{Key: k, Count: v})
	}
	return stats, nil
}

// Close is a no-op for MemoryStore.
func (m *MemoryStore) Close() error {
	return nil
}

func normalizeSeverity(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case telemetry.SeverityLow, telemetry.SeverityMedium, telemetry.SeverityHigh, telemetry.SeverityCritical:
		return strings.ToLower(strings.TrimSpace(sev))
	default:
		return telemetry.SeverityMedium
	}
}
