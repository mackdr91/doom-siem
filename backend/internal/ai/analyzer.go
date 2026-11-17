/*
Author: Domonick Mack
Date: 2026-11-16
Description: AI-assisted log analysis and threat summarization engine using the Gemini Interactions API v1 (gemini-4-hydrogen) with local MITRE playbook synthesis.
*/

package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mackdr91/doom-siem/backend/internal/detection"
	"github.com/mackdr91/doom-siem/backend/internal/telemetry"
)

const (
	defaultGeminiModel           = "gemini-4-hydrogen"
	defaultInteractionsEndpoint  = "https://generativelanguage.googleapis.com/v1/interactions"
)

// ThreatAnalysisReport contains structured AI threat analysis, root-cause explanation, and remediation steps.
type ThreatAnalysisReport struct {
	AlertID             string   `json:"alert_id,omitempty"`
	Engine              string   `json:"engine"`
	Model               string   `json:"model"`
	RiskScore           int      `json:"risk_score"`
	ExecutiveSummary    string   `json:"executive_summary"`
	RootCauseAnalysis   string   `json:"root_cause_analysis"`
	MitreContext        string   `json:"mitre_context"`
	Indicators          []string `json:"indicators"`
	RemediationPlaybook []string `json:"remediation_playbook"`
	FormattedMarkdown   string   `json:"formatted_markdown"`
	GeneratedAtUTC      string   `json:"generated_at_utc"`
}

// AdHocLogAnalysisRequest represents a request to analyze a raw log message or telemetry event.
type AdHocLogAnalysisRequest struct {
	LogLine        string `json:"log_line"`
	Host           string `json:"host,omitempty"`
	SourceIP       string `json:"source_ip,omitempty"`
	Service        string `json:"service,omitempty"`
	SourceProtocol string `json:"source_protocol,omitempty"`
}

// Analyzer performs AI-assisted threat analysis via the Gemini Interactions API v1 with deterministic MITRE fallback.
type Analyzer struct {
	apiKey     string
	model      string
	endpoint   string
	httpClient *http.Client
}

// NewAnalyzer creates a new AI Threat Analyzer.
func NewAnalyzer(apiKey string) *Analyzer {
	model := strings.TrimSpace(os.Getenv("GEMINI_MODEL"))
	if model == "" {
		model = defaultGeminiModel
	}
	endpoint := strings.TrimSpace(os.Getenv("GEMINI_INTERACTIONS_URL"))
	if endpoint == "" {
		endpoint = defaultInteractionsEndpoint
	}

	return &Analyzer{
		apiKey:   strings.TrimSpace(apiKey),
		model:    model,
		endpoint: endpoint,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// SetEndpoint overrides the Gemini Interactions API URL (used for testing).
func (a *Analyzer) SetEndpoint(url string) {
	a.endpoint = strings.TrimSpace(url)
}

// AnalyzeAlert generates a comprehensive threat summary and remediation playbook for a SecurityAlert.
func (a *Analyzer) AnalyzeAlert(ctx context.Context, alert detection.SecurityAlert) (*ThreatAnalysisReport, error) {
	baseline := buildDeterministicAlertReport(alert)
	if a.apiKey == "" {
		return baseline, nil
	}

	prompt := fmt.Sprintf(
		"Analyze the following SIEM security alert and provide a concise executive threat summary, root cause analysis, MITRE ATT&CK context, and 4 concrete remediation steps:\n"+
			"Rule: [%s] %s\nSeverity: %s\nMITRE Tactic: %s (%s)\nSource IP: %s\nTarget Host: %s\nService: %s\nProtocol: %s\nMatched Log Excerpt: %s\nRaw Telemetry: %s",
		alert.RuleCode,
		alert.Title,
		alert.Severity,
		alert.MitreTactic,
		alert.MitreTechniqueID,
		alert.SourceIP,
		alert.TargetHost,
		alert.Service,
		alert.SourceProtocol,
		alert.MatchedExcerpt,
		alert.RawEventJSON,
	)

	aiText, err := a.callGeminiInteractionsAPI(ctx, prompt)
	if err != nil || strings.TrimSpace(aiText) == "" {
		return baseline, nil
	}

	baseline.Engine = "Google Gemini Interactions API v1"
	baseline.Model = a.model
	baseline.ExecutiveSummary = strings.TrimSpace(aiText)
	baseline.FormattedMarkdown = fmt.Sprintf(
		"### AI Threat Assessment (`%s`)\n\n%s\n\n#### Tactical Playbook\n- %s",
		a.model,
		strings.TrimSpace(aiText),
		strings.Join(baseline.RemediationPlaybook, "\n- "),
	)
	return baseline, nil
}

// AnalyzeAdHocLog parses and analyzes an arbitrary security log message or event payload.
func (a *Analyzer) AnalyzeAdHocLog(ctx context.Context, req AdHocLogAnalysisRequest) (*ThreatAnalysisReport, error) {
	proto := req.SourceProtocol
	if proto == "" {
		proto = telemetry.ProtocolSyslogUDP
	}
	parsed := telemetry.ParseSyslogMessage(req.LogLine, req.SourceIP, proto)
	if strings.TrimSpace(req.Host) != "" {
		parsed.Host = strings.TrimSpace(req.Host)
	}
	if strings.TrimSpace(req.SourceIP) != "" {
		parsed.SourceIP = strings.TrimSpace(req.SourceIP)
	}
	if strings.TrimSpace(req.Service) != "" {
		parsed.Service = strings.TrimSpace(req.Service)
	}

	syntheticAlert := detection.SecurityAlert{
		RuleCode:         "ADHOC-AI-INSPECT",
		Title:            fmt.Sprintf("Ad-Hoc Log Analysis (%s on %s)", parsed.Service, parsed.Host),
		Severity:         parsed.Severity,
		Status:           detection.AlertStatusOpen,
		MitreTactic:      parsed.MitreTactic,
		MitreTechniqueID: parsed.MitreTechnique,
		EventID:          parsed.EventID,
		SourceProtocol:   parsed.SourceProtocol,
		SourceIP:         parsed.SourceIP,
		TargetHost:       parsed.Host,
		Service:          parsed.Service,
		MatchedExcerpt:   parsed.Message,
		RawEventJSON:     parsed.RawPayload,
	}

	return a.AnalyzeAlert(ctx, syntheticAlert)
}

func (a *Analyzer) callGeminiInteractionsAPI(ctx context.Context, inputPrompt string) (string, error) {
	reqPayload := map[string]any{
		"model": a.model,
		"system_instruction": "You are Doom AI, a senior Security Operations Center (SOC) principal threat hunter. " +
			"Produce concise, high-signal technical threat intelligence, root-cause analysis, and immediate containment commands.",
		"input": inputPrompt,
		"generation_config": map[string]any{
			"max_output_tokens": 600,
		},
	}

	bodyBytes, err := json.Marshal(reqPayload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-goog-api-key", a.apiKey)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("gemini interactions API returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBytes)))
	}

	var parsed struct {
		OutputText string `json:"output_text"`
		Steps      []struct {
			Type    string `json:"type"`
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"steps"`
	}
	if err := json.Unmarshal(respBytes, &parsed); err != nil {
		return "", err
	}

	if strings.TrimSpace(parsed.OutputText) != "" {
		return strings.TrimSpace(parsed.OutputText), nil
	}

	var sb strings.Builder
	for _, step := range parsed.Steps {
		if step.Type == "model_output" {
			for _, part := range step.Content {
				if part.Type == "text" && strings.TrimSpace(part.Text) != "" {
					if sb.Len() > 0 {
						sb.WriteString("\n")
					}
					sb.WriteString(strings.TrimSpace(part.Text))
				}
			}
		}
	}

	return sb.String(), nil
}

func buildDeterministicAlertReport(alert detection.SecurityAlert) *ThreatAnalysisReport {
	riskScore := computeRiskScore(alert.Severity, alert.MitreTactic)
	rootCause, mitreDesc, playbook := buildMitrePlaybook(alert)

	execSummary := fmt.Sprintf(
		"Detected %s-severity %s activity (%s: %s) targeting host '%s' via service '%s' from source '%s'. "+
			"Telemetry pattern matches rule %s ('%s').",
		strings.ToUpper(alert.Severity),
		alert.MitreTactic,
		alert.MitreTechniqueID,
		alert.Title,
		alert.TargetHost,
		alert.Service,
		alert.SourceIP,
		alert.RuleCode,
		alert.MatchedExcerpt,
	)

	indicators := []string{
		fmt.Sprintf("Source IP: %s", alert.SourceIP),
		fmt.Sprintf("Target Host: %s", alert.TargetHost),
		fmt.Sprintf("Service / Process: %s (%s)", alert.Service, alert.SourceProtocol),
		fmt.Sprintf("MITRE Technique: %s (%s)", alert.MitreTechniqueID, alert.MitreTactic),
	}

	markdown := fmt.Sprintf(
		"### Executive Threat Summary (Risk Score: %d/100)\n%s\n\n"+
			"### Root Cause & Vector Analysis\n%s\n\n"+
			"### MITRE ATT&CK Intelligence\n%s\n\n"+
			"### Recommended Containment & Remediation Playbook\n- %s",
		riskScore,
		execSummary,
		rootCause,
		mitreDesc,
		strings.Join(playbook, "\n- "),
	)

	return &ThreatAnalysisReport{
		AlertID:             alert.ID,
		Engine:              "Doom Tactical AI & MITRE Knowledge Graph",
		Model:               defaultGeminiModel,
		RiskScore:           riskScore,
		ExecutiveSummary:    execSummary,
		RootCauseAnalysis:   rootCause,
		MitreContext:        mitreDesc,
		Indicators:          indicators,
		RemediationPlaybook: playbook,
		FormattedMarkdown:   markdown,
		GeneratedAtUTC:      time.Now().UTC().Format(time.RFC3339),
	}
}

func computeRiskScore(severity string, tactic string) int {
	base := 45
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case telemetry.SeverityCritical:
		base = 94
	case telemetry.SeverityHigh:
		base = 82
	case telemetry.SeverityMedium:
		base = 64
	case telemetry.SeverityLow:
		base = 35
	}
	if strings.EqualFold(tactic, "Privilege Escalation") || strings.EqualFold(tactic, "Initial Access") {
		base += 4
	}
	if base > 99 {
		base = 99
	}
	return base
}

func buildMitrePlaybook(alert detection.SecurityAlert) (string, string, []string) {
	tech := strings.ToUpper(strings.TrimSpace(alert.MitreTechniqueID))
	switch {
	case strings.HasPrefix(tech, "T1190"):
		return "Adversary submitted crafted SQL injection syntax ('UNION SELECT') against a public-facing HTTP endpoint to extract backend relational credentials.",
			"MITRE ATT&CK T1190 (Exploit Public-Facing Application — Initial Access): Adversaries exploit weaknesses in internet-exposed web servers or APIs.",
			[]string{
				fmt.Sprintf("Block offending source IP %s at edge WAF / perimeter firewall immediately.", alert.SourceIP),
				fmt.Sprintf("Inspect application logs on %s for HTTP 200 responses with abnormally large byte payloads from %s.", alert.TargetHost, alert.SourceIP),
				"Verify parameterized prepared statements are enforced on all authentication and query routes.",
				"Rotate database service account credentials if any data exfiltration is suspected.",
			}
	case strings.HasPrefix(tech, "T1059"):
		return "Endpoint process tree spawned PowerShell with hidden window flags and base64-encoded command arguments, typical of fileless stage-2 loaders.",
			"MITRE ATT&CK T1059.001 (Command and Scripting Interpreter: PowerShell — Execution): Adversaries abuse PowerShell to execute arbitrary commands in memory.",
			[]string{
				fmt.Sprintf("Isolate workstation/host %s from the corporate network via EDR containment.", alert.TargetHost),
				"Decode the base64 payload (-enc) and extract secondary C2 domains or IP addresses.",
				"Capture volatile memory dump and inspect scheduled tasks / registry Run keys for persistence.",
				"Enforce PowerShell Constrained Language Mode and Script Block Logging (Event ID 4104).",
			}
	case strings.HasPrefix(tech, "T1611"):
		return "Container workload attempted to mount or modify sensitive host kernel paths (/proc/sys/kernel/core_pattern), indicating an active container escape attempt.",
			"MITRE ATT&CK T1611 (Escape to Host — Privilege Escalation): Adversaries break out of container isolation to gain root execution on the underlying node.",
			[]string{
				fmt.Sprintf("Cordon and drain Kubernetes worker node %s immediately and terminate the offending pod.", alert.TargetHost),
				"Audit PodSecurityStandards / admission controller policies to block privileged pods and hostPath volumes.",
				"Inspect node-level auditd / Falco telemetry for unauthorized binary execution on the host.",
				"Rotate node kubelet and workload service account tokens.",
			}
	case strings.HasPrefix(tech, "T1021"):
		return "Internal host initiated unauthorized SMBv2 connection attempts targeting administrative shares (ADMIN$, C$) indicative of lateral movement.",
			"MITRE ATT&CK T1021.002 (Remote Services: SMB/Windows Admin Shares — Lateral Movement): Adversaries use valid credentials to interact with remote shares and execute binaries.",
			[]string{
				fmt.Sprintf("Quarantine source host %s and block east-west SMB (TCP 445) traffic between workstation subnets.", alert.SourceIP),
				fmt.Sprintf("Audit active Kerberos tickets and NTLM sessions targeting %s.", alert.TargetHost),
				"Reset credentials for compromised domain or local administrator accounts involved.",
				"Disable administrative share auto-creation on non-server endpoints via Group Policy.",
			}
	case strings.HasPrefix(tech, "T1110"):
		return "High-frequency authentication failures or MFA push fatigue attempts observed against privileged accounts.",
			"MITRE ATT&CK T1110 (Brute Force / Credential Stuffing — Credential Access): Adversaries systematically guess passwords or bombard users with MFA prompts.",
			[]string{
				fmt.Sprintf("Rate-limit or block source IP %s on perimeter SSH / SSO gateways.", alert.SourceIP),
				fmt.Sprintf("Verify no successful authentication followed the failed attempts on %s.", alert.TargetHost),
				"Enforce FIDO2/WebAuthn phishing-resistant MFA or number-matching challenges.",
				"Lock and force credential rotation on targeted privileged accounts.",
			}
	default:
		return "Anomalous security telemetry pattern matched active SOC correlation parameters.",
			fmt.Sprintf("MITRE ATT&CK %s (%s): Activity correlated against Doom SIEM detection rules.", alert.MitreTechniqueID, alert.MitreTactic),
			[]string{
				fmt.Sprintf("Investigate recent telemetry from source IP %s targeting host %s.", alert.SourceIP, alert.TargetHost),
				"Correlate surrounding 15-minute event window in ClickHouse for precursor reconnaissance.",
				"Verify service integrity and review authentication logs on the affected asset.",
				"Update triage status and document investigation findings in the SOC incident queue.",
			}
	}
}
