/*
Author: Domonick Mack
Date: 2026-11-16
Description: Concurrent UDP and TCP Syslog collector servers (RFC 3164 and RFC 5424) for Doom SIEM.
*/

package ingest

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/mackdr91/doom-siem/backend/internal/telemetry"
)

// SyslogCollector manages concurrent UDP and TCP network listeners for Syslog ingestion.
type SyslogCollector struct {
	udpPort      int
	tcpPort      int
	pipeline     *Pipeline
	logger       *slog.Logger
	udpConn      net.PacketConn
	tcpListener  net.Listener
	wg           sync.WaitGroup
}

// NewSyslogCollector creates a new SyslogCollector bound to the configured UDP and TCP ports.
func NewSyslogCollector(udpPort int, tcpPort int, pipeline *Pipeline, logger *slog.Logger) *SyslogCollector {
	return &SyslogCollector{
		udpPort:  udpPort,
		tcpPort:  tcpPort,
		pipeline: pipeline,
		logger:   logger,
	}
}

// Start binds the UDP and TCP syslog listeners and spawns background reader goroutines.
func (s *SyslogCollector) Start(ctx context.Context) error {
	if s.udpPort > 0 {
		udpAddr := fmt.Sprintf(":%d", s.udpPort)
		packetConn, err := net.ListenPacket("udp", udpAddr)
		if err != nil {
			return fmt.Errorf("failed to bind syslog UDP listener on %s: %w", udpAddr, err)
		}
		s.udpConn = packetConn
		s.wg.Add(1)
		go s.readUDPLoop(ctx)
		s.logger.Info("syslog_udp_listener_started", slog.String("addr", packetConn.LocalAddr().String()))
	}

	if s.tcpPort > 0 {
		tcpAddr := fmt.Sprintf(":%d", s.tcpPort)
		listener, err := net.Listen("tcp", tcpAddr)
		if err != nil {
			if s.udpConn != nil {
				_ = s.udpConn.Close()
			}
			return fmt.Errorf("failed to bind syslog TCP listener on %s: %w", tcpAddr, err)
		}
		s.tcpListener = listener
		s.wg.Add(1)
		go s.acceptTCPLoop(ctx)
		s.logger.Info("syslog_tcp_listener_started", slog.String("addr", listener.Addr().String()))
	}

	return nil
}

// Close gracefully stops the UDP and TCP syslog listeners and waits for active loops to exit.
func (s *SyslogCollector) Close() {
	if s.udpConn != nil {
		_ = s.udpConn.Close()
	}
	if s.tcpListener != nil {
		_ = s.tcpListener.Close()
	}
	s.wg.Wait()
}

func (s *SyslogCollector) readUDPLoop(ctx context.Context) {
	defer s.wg.Done()
	buf := make([]byte, 65535)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_ = s.udpConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, remoteAddr, err := s.udpConn.ReadFrom(buf)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			continue
		}

		raw := strings.TrimSpace(string(buf[:n]))
		if raw == "" {
			continue
		}

		addrStr := "127.0.0.1"
		if remoteAddr != nil {
			addrStr = remoteAddr.String()
		}

		ev := telemetry.ParseSyslogMessage(raw, addrStr, telemetry.ProtocolSyslogUDP)
		s.pipeline.EnqueueAsync(ev)
	}
}

func (s *SyslogCollector) acceptTCPLoop(ctx context.Context) {
	defer s.wg.Done()

	for {
		conn, err := s.tcpListener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			continue
		}

		s.wg.Add(1)
		go s.handleTCPConnection(ctx, conn)
	}
}

func (s *SyslogCollector) handleTCPConnection(ctx context.Context, conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	remoteAddr := "127.0.0.1"
	if conn.RemoteAddr() != nil {
		remoteAddr = conn.RemoteAddr().String()
	}

	scanner := bufio.NewScanner(conn)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 256*1024)

	for {
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		if !scanner.Scan() {
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		ev := telemetry.ParseSyslogMessage(line, remoteAddr, telemetry.ProtocolSyslogTCP)
		s.pipeline.EnqueueAsync(ev)
	}
}
