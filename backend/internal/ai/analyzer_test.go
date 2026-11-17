/*
Author: Domonick Mack
Date: 2026-11-16
Description: Unit tests for the AI threat analyzer across Gemini Interactions API v1 and local MITRE playbook synthesis.
*/

package ai_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mackdr91/doom-siem/backend/internal/ai"
	"github.com/mackdr91/doom-siem/backend/internal/detection"
)

func TestAnalyzeAlertWithGeminiInteractionsAPI(t *testing.T) {
	mockGemini := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-goog-api-key") != "test-gemini-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var reqBody map[string]any
		_ = json.NewDecoder(r.Body).Decode(&reqBody)
		if reqBody["model"] != "gemini-4-hydrogen" {
			t.Errorf("expected model gemini-4-hydrogen, got %v", reqBody["model"])
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"id": "v1_interaction_test_123",
			"model": "gemini-4-hydrogen",
			"status": "completed",
			"output_text": "Critical SQL injection vector targeting /api/v2/auth/login. Block source IP 45.155.205.233 immediately."
		}`))
	}))
	defer mockGemini.Close()

	analyzer := ai.NewAnalyzer("test-gemini-key")
	analyzer.SetEndpoint(mockGemini.URL)

	alert := detection.SecurityAlert{
		ID:               "alert-101",
		RuleCode:         "DOOM-RULE-002",
		Title:            "WAF SQL Injection & Web Application Exploit",
		Severity:         "critical",
		MitreTactic:      "Initial Access",
		MitreTechniqueID: "T1190",
		SourceIP:         "45.155.205.233",
		TargetHost:       "edge-waf-prod-02",
		Service:          "cloudflare-waf",
		SourceProtocol:   "http_webhook",
		MatchedExcerpt:   "UNION SELECT username, password_hash FROM users--",
	}

	report, err := analyzer.AnalyzeAlert(context.Background(), alert)
	if err != nil {
		t.Fatalf("AnalyzeAlert failed: %v", err)
	}
	if report.Engine != "Google Gemini Interactions API v1" {
		t.Errorf("expected engine Google Gemini Interactions API v1, got %q", report.Engine)
	}
	if !strings.Contains(report.ExecutiveSummary, "Critical SQL injection vector") {
		t.Errorf("unexpected executive summary: %q", report.ExecutiveSummary)
	}
	if report.RiskScore < 90 {
		t.Errorf("expected critical risk score >= 90, got %d", report.RiskScore)
	}
}

func TestAnalyzeAdHocLogFallbackMode(t *testing.T) {
	analyzer := ai.NewAnalyzer("")
	report, err := analyzer.AnalyzeAdHocLog(context.Background(), ai.AdHocLogAnalysisRequest{
		LogLine:  "<34>Nov 16 20:10:00 bastion-gw-01 sshd[4821]: Failed password for invalid user root from 185.220.101.42 port 51922 ssh2",
		SourceIP: "185.220.101.42",
	})
	if err != nil {
		t.Fatalf("AnalyzeAdHocLog failed: %v", err)
	}
	if len(report.RemediationPlaybook) == 0 {
		t.Errorf("expected non-empty remediation playbook")
	}
	if !strings.Contains(report.MitreContext, "T1110") {
		t.Errorf("expected MITRE T1110 context, got %q", report.MitreContext)
	}
}
