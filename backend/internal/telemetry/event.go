/*
Author: Domonick Mack
Date: 2026-11-16
Description: Core telemetry event models, syslog RFC 3164/5424 parser, and event normalizer for Doom SIEM.
*/

package telemetry

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Supported ingestion protocols.
const (
	ProtocolSyslogUDP    = "syslog_udp"
	ProtocolSyslogTCP    = "syslog_tcp"
	ProtocolHTTPWebhook  = "http_webhook"
	ProtocolAgentShipper = "agent_shipper"
)

// Supported normalized event severities.
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

var ipv4Pattern = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

// SecurityEvent represents a normalized security log record stored in ClickHouse and streamed via Redis.
type SecurityEvent struct {
	EventID        string `json:"event_id"`
	Timestamp      string `json:"timestamp"`
	SourceProtocol string `json:"source_protocol"`
	Severity       string `json:"severity"`
	Host           string `json:"host"`
	SourceIP       string `json:"source_ip"`
	DestinationIP  string `json:"destination_ip"`
	Service        string `json:"service"`
	MitreTactic    string `json:"mitre_tactic"`
	MitreTechnique string `json:"mitre_technique"`
	Message        string `json:"message"`
	RawPayload     string `json:"raw_payload"`
}

// IngestBatchRequest wraps a batch of incoming events for webhook or agent ingestion.
type IngestBatchRequest struct {
	Events []SecurityEvent `json:"events"`
}

// EventQueryFilter defines filtering parameters for querying ClickHouse security events.
type EventQueryFilter struct {
	Severity       string
	SourceProtocol string
	Host           string
	Search         string
	Limit          int
}

// BucketCount represents an aggregation key-value count from ClickHouse.
type BucketCount struct {
	Key   string `json:"key"`
	Count uint64 `json:"count"`
}

// TelemetryStats summarizes the current state of the ingestion pipeline and ClickHouse event store.
type TelemetryStats struct {
	TotalEvents       uint64        `json:"total_events"`
	StreamQueueDepth  int64         `json:"stream_queue_depth"`
	BySeverity        []BucketCount `json:"by_severity"`
	ByProtocol        []BucketCount `json:"by_protocol"`
	TopSourceIPs      []BucketCount `json:"top_source_ips"`
	TopHosts          []BucketCount `json:"top_hosts"`
	LastUpdatedAtUTC  string        `json:"last_updated_at_utc"`
}

// GenerateUUIDv4 produces a standard RFC 4122 UUID v4 string using crypto/rand.
func GenerateUUIDv4() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		now := time.Now().UnixNano()
		return fmt.Sprintf("00000000-0000-4000-8000-%012x", now&0xffffffffffff)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80

	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]),
	)
}

// NormalizeEvent ensures all fields on a SecurityEvent are sanitized and populated with valid defaults.
func NormalizeEvent(ev SecurityEvent, defaultProtocol string) SecurityEvent {
	if strings.TrimSpace(ev.EventID) == "" {
		ev.EventID = GenerateUUIDv4()
	}

	if strings.TrimSpace(ev.Timestamp) == "" {
		ev.Timestamp = FormatClickHouseTimestamp(time.Now().UTC())
	} else if parsed, err := time.Parse(time.RFC3339, ev.Timestamp); err == nil {
		ev.Timestamp = FormatClickHouseTimestamp(parsed.UTC())
	}

	proto := strings.ToLower(strings.TrimSpace(ev.SourceProtocol))
	switch proto {
	case ProtocolSyslogUDP, ProtocolSyslogTCP, ProtocolHTTPWebhook, ProtocolAgentShipper:
		ev.SourceProtocol = proto
	default:
		if defaultProtocol != "" {
			ev.SourceProtocol = defaultProtocol
		} else {
			ev.SourceProtocol = ProtocolHTTPWebhook
		}
	}

	sev := strings.ToLower(strings.TrimSpace(ev.Severity))
	switch sev {
	case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		ev.Severity = sev
	default:
		ev.Severity = inferSeverityFromMessage(ev.Message)
	}

	if strings.TrimSpace(ev.Host) == "" {
		ev.Host = "unknown-host"
	}
	if strings.TrimSpace(ev.SourceIP) == "" {
		ev.SourceIP = extractFirstIPv4(ev.Message, "0.0.0.0")
	}
	if strings.TrimSpace(ev.DestinationIP) == "" {
		ev.DestinationIP = "0.0.0.0"
	}
	if strings.TrimSpace(ev.Service) == "" {
		ev.Service = "system"
	}

	tactic, technique := inferMitreFromEvent(ev)
	if strings.TrimSpace(ev.MitreTactic) == "" {
		ev.MitreTactic = tactic
	}
	if strings.TrimSpace(ev.MitreTechnique) == "" {
		ev.MitreTechnique = technique
	}

	if strings.TrimSpace(ev.RawPayload) == "" {
		ev.RawPayload = ev.Message
	}

	return ev
}

// FormatClickHouseTimestamp formats a time.Time in UTC as 'YYYY-MM-DD HH:MM:SS.mmm' for ClickHouse DateTime64(3).
func FormatClickHouseTimestamp(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04:05.000")
}

// ParseSyslogMessage parses an RFC 3164 or RFC 5424 syslog frame into a normalized SecurityEvent.
func ParseSyslogMessage(raw string, remoteAddr string, protocol string) SecurityEvent {
	trimmed := strings.TrimSpace(raw)
	ev := SecurityEvent{
		EventID:        GenerateUUIDv4(),
		Timestamp:      FormatClickHouseTimestamp(time.Now().UTC()),
		SourceProtocol: protocol,
		Severity:       SeverityLow,
		Host:           "syslog-node",
		SourceIP:       stripPort(remoteAddr),
		DestinationIP:  "0.0.0.0",
		Service:        "syslog",
		Message:        trimmed,
		RawPayload:     trimmed,
	}

	remainder := trimmed

	// Parse PRI header: <PRI>
	if strings.HasPrefix(remainder, "<") {
		endIdx := strings.Index(remainder, ">")
		if endIdx > 1 && endIdx <= 5 {
			if priVal, err := strconv.Atoi(remainder[1:endIdx]); err == nil {
				syslogSeverityCode := priVal & 0x07
				ev.Severity = mapSyslogSeverity(syslogSeverityCode)
			}
			remainder = strings.TrimSpace(remainder[endIdx+1:])
		}
	}

	// Check if RFC 5424 version token '1 ' follows PRI:
	// Format: 1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
	if strings.HasPrefix(remainder, "1 ") {
		parts := strings.SplitN(remainder, " ", 8)
		if len(parts) >= 4 {
			if parts[2] != "-" && parts[2] != "" {
				ev.Host = parts[2]
			}
			if parts[3] != "-" && parts[3] != "" {
				ev.Service = parts[3]
			}
			if len(parts) == 8 {
				ev.Message = strings.TrimSpace(parts[7])
			} else if len(parts) == 7 {
				ev.Message = strings.TrimSpace(parts[6])
			}
		}
		if extractedIP := extractFirstIPv4(ev.Message, ""); extractedIP != "" {
			ev.SourceIP = extractedIP
		}
		return NormalizeEvent(ev, protocol)
	}

	// RFC 3164 style: "Mmm dd hh:mm:ss host app[pid]: message"
	tokens := strings.Fields(remainder)
	if len(tokens) >= 5 && isMonthAbbrev(tokens[0]) {
		ev.Host = tokens[3]
		tagAndMsg := strings.Join(tokens[4:], " ")
		if colonIdx := strings.Index(tagAndMsg, ":"); colonIdx > 0 {
			rawTag := tagAndMsg[:colonIdx]
			if bracketIdx := strings.Index(rawTag, "["); bracketIdx > 0 {
				rawTag = rawTag[:bracketIdx]
			}
			ev.Service = strings.TrimSpace(rawTag)
			ev.Message = strings.TrimSpace(tagAndMsg[colonIdx+1:])
		} else {
			ev.Message = tagAndMsg
		}
	} else {
		ev.Message = remainder
	}

	if extractedIP := extractFirstIPv4(ev.Message, ""); extractedIP != "" {
		ev.SourceIP = extractedIP
	}

	return NormalizeEvent(ev, protocol)
}

func mapSyslogSeverity(code int) string {
	switch {
	case code <= 2: // Emergency (0), Alert (1), Critical (2)
		return SeverityCritical
	case code == 3: // Error (3)
		return SeverityHigh
	case code == 4: // Warning (4)
		return SeverityMedium
	default: // Notice (5), Info (6), Debug (7)
		return SeverityLow
	}
}

func inferSeverityFromMessage(msg string) string {
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "critical") || strings.Contains(lower, "ransomware") || strings.Contains(lower, "rootkit") || strings.Contains(lower, "sql injection") || strings.Contains(lower, "rce"):
		return SeverityCritical
	case strings.Contains(lower, "failed password") || strings.Contains(lower, "brute") || strings.Contains(lower, "unauthorized") || strings.Contains(lower, "exploit") || strings.Contains(lower, "powershell -enc"):
		return SeverityHigh
	case strings.Contains(lower, "warning") || strings.Contains(lower, "denied") || strings.Contains(lower, "blocked") || strings.Contains(lower, "suspicious"):
		return SeverityMedium
	default:
		return SeverityLow
	}
}

func inferMitreFromEvent(ev SecurityEvent) (string, string) {
	lower := strings.ToLower(ev.Message + " " + ev.Service)
	switch {
	case strings.Contains(lower, "failed password") || strings.Contains(lower, "brute") || strings.Contains(lower, "sshd"):
		return "Credential Access", "T1110"
	case strings.Contains(lower, "powershell") || strings.Contains(lower, "cmd.exe") || strings.Contains(lower, "/bin/sh"):
		return "Execution", "T1059"
	case strings.Contains(lower, "sql injection") || strings.Contains(lower, "union select") || strings.Contains(lower, "waf"):
		return "Initial Access", "T1190"
	case strings.Contains(lower, "smb") || strings.Contains(lower, "psexec") || strings.Contains(lower, "lateral"):
		return "Lateral Movement", "T1021"
	case strings.Contains(lower, "exfil") || strings.Contains(lower, "dns tunnel"):
		return "Exfiltration", "T1048"
	default:
		return "Discovery", "T1082"
	}
}

func isMonthAbbrev(token string) bool {
	switch token {
	case "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec":
		return true
	default:
		return false
	}
}

func stripPort(addr string) string {
	if addr == "" {
		return "127.0.0.1"
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if host == "" || host == "::1" {
		return "127.0.0.1"
	}
	return host
}

func extractFirstIPv4(text string, fallback string) string {
	match := ipv4Pattern.FindString(text)
	if match != "" {
		return match
	}
	return fallback
}
