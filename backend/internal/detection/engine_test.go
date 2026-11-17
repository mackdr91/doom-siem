/*
Author: Domonick Mack
Date: 2026-11-16
Description: Unit tests for the MITRE ATT&CK detection rule engine and alert triage workflow.
*/

package detection_test

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/mackdr91/doom-siem/backend/internal/detection"
	"github.com/mackdr91/doom-siem/backend/internal/telemetry"
)

func TestEngineEvaluateBatchAndTriageWorkflow(t *testing.T) {
	ctx := context.Background()
	store := detection.NewMemoryStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := detection.NewEngine(store, logger)

	if err := engine.RefreshRules(ctx); err != nil {
		t.Fatalf("failed to refresh rules: %v", err)
	}

	events := []telemetry.SecurityEvent{
		telemetry.NormalizeEvent(telemetry.SecurityEvent{
			SourceProtocol: telemetry.ProtocolHTTPWebhook,
			Severity:       telemetry.SeverityCritical,
			Host:           "waf-prod-01",
			SourceIP:       "45.155.205.233",
			Service:        "nginx-waf",
			Message:        "SQL Injection payload blocked: UNION SELECT username, password FROM accounts",
		}, telemetry.ProtocolHTTPWebhook),
		telemetry.NormalizeEvent(telemetry.SecurityEvent{
			SourceProtocol: telemetry.ProtocolAgentShipper,
			Severity:       telemetry.SeverityHigh,
			Host:           "win-wkstn-02",
			SourceIP:       "10.20.30.40",
			Service:        "edr-agent",
			Message:        "Obfuscated execution: powershell.exe -NoP -W Hidden -enc AAAABBBB",
		}, telemetry.ProtocolAgentShipper),
	}

	triggered, err := engine.EvaluateBatch(ctx, events)
	if err != nil {
		t.Fatalf("EvaluateBatch returned error: %v", err)
	}
	if len(triggered) < 2 {
		t.Fatalf("expected at least 2 alerts triggered, got %d", len(triggered))
	}

	// Verify alert triage workflow: open -> investigating -> resolved
	targetAlertID := triggered[0].ID
	updated, err := store.UpdateAlertTriage(ctx, targetAlertID, detection.AlertTriageUpdateRequest{
		Status:   detection.AlertStatusInvestigating,
		Assignee: "Domonick Mack",
		Notes:    "Isolating source IP at edge firewall and reviewing WAF PCAP.",
	})
	if err != nil {
		t.Fatalf("UpdateAlertTriage failed: %v", err)
	}
	if updated.Status != detection.AlertStatusInvestigating {
		t.Errorf("expected status %q, got %q", detection.AlertStatusInvestigating, updated.Status)
	}
	if updated.Assignee != "Domonick Mack" {
		t.Errorf("expected assignee Domonick Mack, got %q", updated.Assignee)
	}

	stats, err := store.GetAlertStats(ctx)
	if err != nil {
		t.Fatalf("GetAlertStats failed: %v", err)
	}
	if stats.TotalAlerts != len(triggered) {
		t.Errorf("expected TotalAlerts=%d, got %d", len(triggered), stats.TotalAlerts)
	}
	if stats.InvestigatingAlerts != 1 {
		t.Errorf("expected InvestigatingAlerts=1, got %d", stats.InvestigatingAlerts)
	}
}
