/*
Author: Domonick Mack
Date: 2026-11-16
Description: Real-time MITRE ATT&CK rule evaluation and alert generation engine for Doom SIEM.
*/

package detection

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"

	"github.com/mackdr91/doom-siem/backend/internal/telemetry"
)

// Engine evaluates incoming telemetry events against active MITRE ATT&CK detection rules.
type Engine struct {
	store       Store
	logger      *slog.Logger
	mu          sync.RWMutex
	cachedRules []DetectionRule
}

// NewEngine initializes the MITRE ATT&CK detection Engine and loads active rules from the Store.
func NewEngine(store Store, logger *slog.Logger) *Engine {
	e := &Engine{
		store:       store,
		logger:      logger,
		cachedRules: make([]DetectionRule, 0),
	}
	return e
}

// RefreshRules reloads all detection rules from the backing Store into the in-memory evaluation cache.
func (e *Engine) RefreshRules(ctx context.Context) error {
	rules, err := e.store.ListRules(ctx)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.cachedRules = rules
	e.mu.Unlock()
	return nil
}

// EvaluateBatch checks each SecurityEvent against all enabled detection rules and persists generated alerts.
func (e *Engine) EvaluateBatch(ctx context.Context, events []telemetry.SecurityEvent) ([]SecurityAlert, error) {
	if len(events) == 0 {
		return nil, nil
	}

	e.mu.RLock()
	rules := make([]DetectionRule, len(e.cachedRules))
	copy(rules, e.cachedRules)
	e.mu.RUnlock()

	if len(rules) == 0 {
		if err := e.RefreshRules(ctx); err == nil {
			e.mu.RLock()
			rules = make([]DetectionRule, len(e.cachedRules))
			copy(rules, e.cachedRules)
			e.mu.RUnlock()
		}
	}

	triggered := make([]SecurityAlert, 0)

	for _, ev := range events {
		for _, rule := range rules {
			if !rule.Enabled {
				continue
			}
			if !matchesRule(ev, rule) {
				continue
			}

			rawBytes, _ := json.Marshal(ev)
			candidate := SecurityAlert{
				RuleID:           rule.ID,
				RuleCode:         rule.RuleCode,
				Title:            rule.Title,
				Severity:         rule.Severity,
				Status:           AlertStatusOpen,
				MitreTactic:      rule.MitreTactic,
				MitreTechniqueID: rule.MitreTechniqueID,
				EventID:          ev.EventID,
				SourceProtocol:   ev.SourceProtocol,
				SourceIP:         ev.SourceIP,
				TargetHost:       ev.Host,
				Service:          ev.Service,
				MatchedExcerpt:   ev.Message,
				RawEventJSON:     string(rawBytes),
				Assignee:         "SOC-Queue",
			}

			created, err := e.store.CreateAlert(ctx, candidate)
			if err != nil {
				e.logger.Error("failed_to_persist_security_alert",
					slog.String("rule_code", rule.RuleCode),
					slog.String("event_id", ev.EventID),
					slog.String("error", err.Error()),
				)
				continue
			}

			e.logger.Info("security_alert_triggered",
				slog.String("alert_id", created.ID),
				slog.String("rule_code", created.RuleCode),
				slog.String("severity", created.Severity),
				slog.String("mitre_technique", created.MitreTechniqueID),
				slog.String("target_host", created.TargetHost),
			)
			triggered = append(triggered, *created)
		}
	}

	return triggered, nil
}

// Store returns the underlying persistence Store.
func (e *Engine) Store() Store {
	return e.store
}

func matchesRule(ev telemetry.SecurityEvent, rule DetectionRule) bool {
	if protoFilter := strings.ToLower(strings.TrimSpace(rule.SourceProtocolFilter)); protoFilter != "" {
		if !strings.EqualFold(ev.SourceProtocol, protoFilter) {
			return false
		}
	}

	haystack := strings.ToLower(ev.Message + " " + ev.RawPayload + " " + ev.Service)
	for _, kw := range strings.Split(rule.MatchKeywords, ",") {
		trimmed := strings.ToLower(strings.TrimSpace(kw))
		if trimmed != "" && strings.Contains(haystack, trimmed) {
			return true
		}
	}

	if ruleTech := strings.TrimSpace(rule.MitreTechniqueID); ruleTech != "" {
		if strings.EqualFold(ev.MitreTechnique, ruleTech) {
			return true
		}
	}

	return false
}
