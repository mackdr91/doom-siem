/*
Author: Domonick Mack
Date: 2026-11-16
Description: Multi-protocol ingestion pipeline coordinator for ClickHouse persistence, Redis Streams buffering, MITRE rule evaluation, and attack simulation.
*/

package ingest

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/mackdr91/doom-siem/backend/internal/detection"
	"github.com/mackdr91/doom-siem/backend/internal/telemetry"
)

// Pipeline coordinates event normalization, ClickHouse batch writes, Redis Stream publication, and MITRE ATT&CK rule evaluation.
type Pipeline struct {
	repo            *telemetry.Repository
	broker          *telemetry.StreamBroker
	detectionEngine *detection.Engine
	logger          *slog.Logger
	acceptedCnt     atomic.Uint64
	failedCnt       atomic.Uint64
	asyncQueue      chan telemetry.SecurityEvent
}

// NewPipeline initializes the ingestion Pipeline and starts background workers for Syslog datagrams.
func NewPipeline(repo *telemetry.Repository, broker *telemetry.StreamBroker, logger *slog.Logger) *Pipeline {
	p := &Pipeline{
		repo:       repo,
		broker:     broker,
		logger:     logger,
		asyncQueue: make(chan telemetry.SecurityEvent, 2048),
	}
	go p.runAsyncWorker()
	return p
}

// SetDetectionEngine attaches the MITRE ATT&CK detection engine to evaluate every ingested batch.
func (p *Pipeline) SetDetectionEngine(engine *detection.Engine) {
	p.detectionEngine = engine
}

// EnqueueAsync queues a parsed syslog event for non-blocking background persistence and streaming.
func (p *Pipeline) EnqueueAsync(ev telemetry.SecurityEvent) {
	select {
	case p.asyncQueue <- ev:
	default:
		p.failedCnt.Add(1)
		p.logger.Warn("async_ingest_queue_full_dropping_event", slog.String("event_id", ev.EventID))
	}
}

// IngestBatch normalizes a batch of events, persists them to ClickHouse, publishes them to Redis Streams/SSE, and evaluates MITRE rules.
func (p *Pipeline) IngestBatch(ctx context.Context, rawEvents []telemetry.SecurityEvent, defaultProtocol string) ([]telemetry.SecurityEvent, error) {
	if len(rawEvents) == 0 {
		return nil, nil
	}

	normalized := make([]telemetry.SecurityEvent, 0, len(rawEvents))
	for _, ev := range rawEvents {
		normalized = append(normalized, telemetry.NormalizeEvent(ev, defaultProtocol))
	}

	if err := p.repo.InsertEvents(ctx, normalized); err != nil {
		p.failedCnt.Add(uint64(len(normalized)))
		return nil, fmt.Errorf("failed to persist batch to ClickHouse: %w", err)
	}

	if err := p.broker.Publish(ctx, normalized); err != nil {
		p.logger.Warn("redis_stream_publish_warning", slog.String("error", err.Error()))
	}

	if p.detectionEngine != nil {
		if _, err := p.detectionEngine.EvaluateBatch(ctx, normalized); err != nil {
			p.logger.Warn("detection_engine_evaluation_warning", slog.String("error", err.Error()))
		}
	}

	p.acceptedCnt.Add(uint64(len(normalized)))
	return normalized, nil
}

// SimulateTraffic injects realistic multi-protocol security telemetry across UDP Syslog, TCP Syslog, HTTP Webhook, and Agent Shipper.
func (p *Pipeline) SimulateTraffic(ctx context.Context, udpPort int, tcpPort int) ([]telemetry.SecurityEvent, error) {
	// 1. Send a live RFC 3164 Syslog UDP datagram to the active UDP listener
	udpFrame := "<34>Nov 16 20:10:00 bastion-gw-01 sshd[4821]: Failed password for invalid user admin from 185.220.101.42 port 51922 ssh2"
	if udpPort > 0 {
		if conn, err := net.DialTimeout("udp", fmt.Sprintf("127.0.0.1:%d", udpPort), time.Second); err == nil {
			_, _ = conn.Write([]byte(udpFrame))
			_ = conn.Close()
		}
	}

	// 2. Send a live RFC 5424 Syslog TCP frame to the active TCP listener
	tcpFrame := "<27>1 2026-11-16T20:10:01Z dc-core-01 smbd 2190 - - Lateral movement attempt via SMBv2 administrative share ADMIN$ from 10.24.8.99\n"
	if tcpPort > 0 {
		if conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", tcpPort), time.Second); err == nil {
			_, _ = conn.Write([]byte(tcpFrame))
			_ = conn.Close()
		}
	}

	// 3. Ingest direct HTTP Webhook & Endpoint Agent Shipper events
	batch := []telemetry.SecurityEvent{
		{
			SourceProtocol: telemetry.ProtocolHTTPWebhook,
			Severity:       telemetry.SeverityCritical,
			Host:           "edge-waf-prod-02",
			SourceIP:       "45.155.205.233",
			DestinationIP:  "172.16.10.14",
			Service:        "cloudflare-waf",
			MitreTactic:    "Initial Access",
			MitreTechnique: "T1190",
			Message:        "SQL Injection payload blocked on /api/v2/auth/login: UNION SELECT username, password_hash FROM users--",
			RawPayload:     `{"rule_id":"WAF-942100","action":"block","uri":"/api/v2/auth/login","src_ip":"45.155.205.233"}`,
		},
		{
			SourceProtocol: telemetry.ProtocolAgentShipper,
			Severity:       telemetry.SeverityHigh,
			Host:           "win-fin-wkstn-09",
			SourceIP:       "10.24.14.109",
			DestinationIP:  "198.51.100.77",
			Service:        "doom-edr-agent",
			MitreTactic:    "Execution",
			MitreTechnique: "T1059.001",
			Message:        "Suspicious obfuscated PowerShell execution detected: powershell.exe -NoP -NonI -W Hidden -enc JABjAGwAaQBlAG4AdAA=",
			RawPayload:     `{"agent_id":"agt-9921","process":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","parent":"winword.exe"}`,
		},
		{
			SourceProtocol: telemetry.ProtocolAgentShipper,
			Severity:       telemetry.SeverityCritical,
			Host:           "k8s-worker-prod-04",
			SourceIP:       "91.214.124.18",
			DestinationIP:  "10.100.4.21",
			Service:        "container-runtime",
			MitreTactic:    "Privilege Escalation",
			MitreTechnique: "T1611",
			Message:        "Critical container escape attempt: unauthorized hostPath mount of /proc/sys/kernel/core_pattern",
			RawPayload:     `{"pod":"payment-processor-7d8b","namespace":"prod-fin","syscall":"mount","uid":0}`,
		},
		{
			SourceProtocol: telemetry.ProtocolHTTPWebhook,
			Severity:       telemetry.SeverityMedium,
			Host:           "idp-sso-gateway",
			SourceIP:       "193.32.162.89",
			DestinationIP:  "172.16.4.10",
			Service:        "okta-webhook",
			MitreTactic:    "Credential Access",
			MitreTechnique: "T1110.004",
			Message:        "Multiple MFA push fatigue rejections recorded for privileged identity secops-admin@doom.local",
			RawPayload:     `{"event_type":"user.mfa.factor.denied","actor":"secops-admin@doom.local","src_ip":"193.32.162.89"}`,
		},
	}

	return p.IngestBatch(ctx, batch, telemetry.ProtocolHTTPWebhook)
}

func (p *Pipeline) runAsyncWorker() {
	ticker := time.NewTicker(400 * time.Millisecond)
	defer ticker.Stop()

	buffer := make([]telemetry.SecurityEvent, 0, 64)

	flush := func() {
		if len(buffer) == 0 {
			return
		}
		batch := make([]telemetry.SecurityEvent, len(buffer))
		copy(batch, buffer)
		buffer = buffer[:0]

		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()

		if _, err := p.IngestBatch(ctx, batch, batch[0].SourceProtocol); err != nil {
			p.logger.Error("async_batch_ingest_failed", slog.String("error", err.Error()), slog.Int("count", len(batch)))
		}
	}

	for {
		select {
		case ev := <-p.asyncQueue:
			buffer = append(buffer, ev)
			if len(buffer) >= 64 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}
