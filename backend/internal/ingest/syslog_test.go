/*
Author: Domonick Mack
Date: 2026-11-16
Description: Unit and network socket tests for the concurrent UDP and TCP Syslog collectors.
*/

package ingest_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mackdr91/doom-siem/backend/internal/config"
	"github.com/mackdr91/doom-siem/backend/internal/ingest"
	"github.com/mackdr91/doom-siem/backend/internal/telemetry"
)

func TestSyslogUDPAndTCPCollectors(t *testing.T) {
	var insertHits atomic.Int32
	mockCH := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		insertHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer mockCH.Close()

	// Find free UDP and TCP ports
	udpProbe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to probe free UDP port: %v", err)
	}
	udpPort := udpProbe.LocalAddr().(*net.UDPAddr).Port
	_ = udpProbe.Close()

	tcpProbe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to probe free TCP port: %v", err)
	}
	tcpPort := tcpProbe.Addr().(*net.TCPAddr).Port
	_ = tcpProbe.Close()

	cfg := &config.Config{
		ClickHouseHTTPURL: mockCH.URL,
		ClickHouseDB:      "doom_telemetry",
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo := telemetry.NewRepository(cfg)
	broker := telemetry.NewStreamBroker("")
	pipeline := ingest.NewPipeline(repo, broker, logger)

	subCh, unsubscribe := broker.Subscribe()
	defer unsubscribe()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	collector := ingest.NewSyslogCollector(udpPort, tcpPort, pipeline, logger)
	if err := collector.Start(ctx); err != nil {
		t.Fatalf("failed to start syslog collector: %v", err)
	}
	defer collector.Close()

	// Send UDP syslog datagram
	udpConn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", udpPort))
	if err != nil {
		t.Fatalf("failed to dial UDP syslog: %v", err)
	}
	_, _ = udpConn.Write([]byte("<34>Nov 16 20:15:00 fw-edge-01 sshd[102]: Failed password for root from 203.0.113.55 port 22"))
	_ = udpConn.Close()

	// Send TCP syslog frame
	tcpConn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tcpPort))
	if err != nil {
		t.Fatalf("failed to dial TCP syslog: %v", err)
	}
	_, _ = tcpConn.Write([]byte("<27>1 2026-11-16T20:15:01Z db-prod-01 postgres 991 - - Unauthorized role escalation attempt\n"))
	_ = tcpConn.Close()

	// Expect at least 2 events to arrive on the SSE subscriber channel within 2 seconds
	received := 0
	timeout := time.After(2 * time.Second)
	for received < 2 {
		select {
		case <-subCh:
			received++
		case <-timeout:
			t.Fatalf("timed out waiting for syslog events over SSE; received %d/2", received)
		}
	}

	if insertHits.Load() == 0 {
		t.Errorf("expected ClickHouse insert endpoint to be called at least once")
	}
}
