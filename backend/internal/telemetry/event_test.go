/*
Author: Domonick Mack
Date: 2026-11-16
Description: Unit tests for RFC 3164/5424 syslog frame parsing, MITRE inference, and event normalization.
*/

package telemetry_test

import (
	"testing"

	"github.com/mackdr91/doom-siem/backend/internal/telemetry"
)

func TestParseSyslogRFC3164(t *testing.T) {
	raw := "<34>Nov 16 20:10:00 bastion-gw-01 sshd[4821]: Failed password for invalid user root from 185.220.101.42 port 51922 ssh2"
	ev := telemetry.ParseSyslogMessage(raw, "10.0.0.5:55140", telemetry.ProtocolSyslogUDP)

	if ev.SourceProtocol != telemetry.ProtocolSyslogUDP {
		t.Errorf("expected protocol %q, got %q", telemetry.ProtocolSyslogUDP, ev.SourceProtocol)
	}
	if ev.Severity != telemetry.SeverityCritical {
		t.Errorf("expected PRI <34> (crit=2) to map to critical, got %q", ev.Severity)
	}
	if ev.Host != "bastion-gw-01" {
		t.Errorf("expected host bastion-gw-01, got %q", ev.Host)
	}
	if ev.Service != "sshd" {
		t.Errorf("expected service sshd, got %q", ev.Service)
	}
	if ev.SourceIP != "185.220.101.42" {
		t.Errorf("expected extracted IP 185.220.101.42, got %q", ev.SourceIP)
	}
	if ev.MitreTechnique != "T1110" {
		t.Errorf("expected MITRE technique T1110, got %q", ev.MitreTechnique)
	}
}

func TestParseSyslogRFC5424(t *testing.T) {
	raw := "<27>1 2026-11-16T20:10:01Z dc-core-01 smbd 2190 - - Lateral movement attempt via SMBv2 administrative share from 10.24.8.99"
	ev := telemetry.ParseSyslogMessage(raw, "127.0.0.1:44123", telemetry.ProtocolSyslogTCP)

	if ev.SourceProtocol != telemetry.ProtocolSyslogTCP {
		t.Errorf("expected protocol %q, got %q", telemetry.ProtocolSyslogTCP, ev.SourceProtocol)
	}
	if ev.Severity != telemetry.SeverityHigh {
		t.Errorf("expected PRI <27> (err=3) to map to high, got %q", ev.Severity)
	}
	if ev.Host != "dc-core-01" {
		t.Errorf("expected host dc-core-01, got %q", ev.Host)
	}
	if ev.Service != "smbd" {
		t.Errorf("expected service smbd, got %q", ev.Service)
	}
	if ev.SourceIP != "10.24.8.99" {
		t.Errorf("expected extracted IP 10.24.8.99, got %q", ev.SourceIP)
	}
	if ev.Message != "Lateral movement attempt via SMBv2 administrative share from 10.24.8.99" {
		t.Errorf("unexpected RFC 5424 message: %q", ev.Message)
	}
	if ev.MitreTactic != "Lateral Movement" {
		t.Errorf("expected MITRE tactic Lateral Movement, got %q", ev.MitreTactic)
	}
}
