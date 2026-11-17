/*
Author: Domonick Mack
Date: 2026-11-16
Description: Redis 7 Streams producer and real-time Server-Sent Events (SSE) broadcaster for Doom SIEM.
*/

package telemetry

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const redisStreamKey = "doom:events"

// StreamBroker coordinates Redis Streams persistence and live SSE fan-out to connected SOC analysts.
type StreamBroker struct {
	redisAddr   string
	mu          sync.RWMutex
	subscribers map[chan SecurityEvent]struct{}
}

// NewStreamBroker constructs a new StreamBroker bound to the given Redis address.
func NewStreamBroker(redisAddr string) *StreamBroker {
	return &StreamBroker{
		redisAddr:   redisAddr,
		subscribers: make(map[chan SecurityEvent]struct{}),
	}
}

// Subscribe registers a new live event channel for SSE streaming and returns an unsubscribe callback.
func (b *StreamBroker) Subscribe() (<-chan SecurityEvent, func()) {
	ch := make(chan SecurityEvent, 64)
	b.mu.Lock()
	b.subscribers[ch] = struct{}{}
	b.mu.Unlock()

	unsubscribe := func() {
		b.mu.Lock()
		if _, exists := b.subscribers[ch]; exists {
			delete(b.subscribers, ch)
			close(ch)
		}
		b.mu.Unlock()
	}

	return ch, unsubscribe
}

// Publish appends each event to the Redis Stream (doom:events) and broadcasts it to all active SSE subscribers.
func (b *StreamBroker) Publish(ctx context.Context, events []SecurityEvent) error {
	if len(events) == 0 {
		return nil
	}

	// Broadcast to in-memory SSE subscribers immediately without blocking
	b.mu.RLock()
	for _, ev := range events {
		for ch := range b.subscribers {
			select {
			case ch <- ev:
			default:
				// Drop oldest unread message if subscriber channel is full
			}
		}
	}
	b.mu.RUnlock()

	if strings.TrimSpace(b.redisAddr) == "" {
		return nil
	}

	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", b.redisAddr)
	if err != nil {
		return fmt.Errorf("redis stream dial failed: %w", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(conn)

	for _, ev := range events {
		payloadBytes, err := json.Marshal(ev)
		if err != nil {
			continue
		}
		// XADD doom:events MAXLEN ~ 10000 * event_id <id> payload <json>
		cmd := buildRESPCommand(
			"XADD",
			redisStreamKey,
			"MAXLEN",
			"~",
			"10000",
			"*",
			"event_id",
			ev.EventID,
			"payload",
			string(payloadBytes),
		)
		if _, err := conn.Write(cmd); err != nil {
			return fmt.Errorf("redis XADD write failed: %w", err)
		}
		reply, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("redis XADD read failed: %w", err)
		}
		if strings.HasPrefix(reply, "-") {
			return fmt.Errorf("redis XADD error reply: %s", strings.TrimSpace(reply))
		}
		// If bulk string ($<len>\r\n<id>\r\n), consume the stream ID line
		if strings.HasPrefix(reply, "$") {
			_, _ = reader.ReadString('\n')
		}
	}

	return nil
}

// StreamLength queries XLEN doom:events from Redis to report the current stream buffer depth.
func (b *StreamBroker) StreamLength(ctx context.Context) (int64, error) {
	if strings.TrimSpace(b.redisAddr) == "" {
		return 0, nil
	}

	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", b.redisAddr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	cmd := buildRESPCommand("XLEN", redisStreamKey)
	if _, err := conn.Write(cmd); err != nil {
		return 0, err
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return 0, err
	}
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, ":") {
		val, parseErr := strconv.ParseInt(trimmed[1:], 10, 64)
		if parseErr == nil {
			return val, nil
		}
	}
	return 0, nil
}

func buildRESPCommand(args ...string) []byte {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("*%d\r\n", len(args)))
	for _, arg := range args {
		sb.WriteString(fmt.Sprintf("$%d\r\n%s\r\n", len(arg), arg))
	}
	return []byte(sb.String())
}
