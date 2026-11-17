/*
Author: Domonick Mack
Date: 2026-11-16
Description: Alerts and Incident Triage Queue with interactive status workflows, AI Threat Analysis, and MITRE ATT&CK Detection Rules Studio.
*/

"use client";

import React, { useCallback, useEffect, useState } from "react";
import {
  Bot,
  CheckCircle2,
  Clock,
  Plus,
  RefreshCw,
  Save,
  Search,
  Shield,
  ShieldAlert,
  Sparkles,
  UserCheck,
  XCircle,
} from "lucide-react";
import { SeverityBadge } from "./CommandCenterView";
import type {
  DetectionRule,
  SecurityAlert,
  ThreatAnalysisReport,
} from "@/types/siem";

interface AlertsTriageViewProps {
  apiBaseUrl: string;
  initialSelectedAlert: SecurityAlert | null;
  onRefreshGlobalStats: () => void;
}

export function StatusBadge({ status }: { status: string }) {
  const norm = status.toLowerCase();
  if (norm === "open") {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono uppercase bg-rose-950/70 text-rose-300 border border-rose-600/60">
        <ShieldAlert className="h-3 w-3 text-rose-400" aria-hidden="true" />
        <span>OPEN</span>
      </span>
    );
  }
  if (norm === "investigating") {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono uppercase bg-amber-950/70 text-amber-300 border border-amber-500/60">
        <Clock className="h-3 w-3 text-amber-400" aria-hidden="true" />
        <span>INVESTIGATING</span>
      </span>
    );
  }
  if (norm === "resolved") {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono uppercase bg-emerald-950/70 text-emerald-300 border border-emerald-600/60">
        <CheckCircle2 className="h-3 w-3 text-emerald-400" aria-hidden="true" />
        <span>RESOLVED</span>
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono uppercase bg-zinc-900 text-zinc-400 border border-zinc-700">
      <XCircle className="h-3 w-3 text-zinc-400" aria-hidden="true" />
      <span>FALSE POSITIVE</span>
    </span>
  );
}

export default function AlertsTriageView({
  apiBaseUrl,
  initialSelectedAlert,
  onRefreshGlobalStats,
}: AlertsTriageViewProps) {
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [loading, setLoading] = useState<boolean>(false);

  // Filters
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [searchQuery, setSearchQuery] = useState<string>("");

  // Selected Alert & Triage Form State
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlert | null>(
    initialSelectedAlert
  );
  const [triageStatus, setTriageStatus] = useState<string>("open");
  const [triageAssignee, setTriageAssignee] = useState<string>("SOC-Queue");
  const [triageNotes, setTriageNotes] = useState<string>("");
  const [savingTriage, setSavingTriage] = useState<boolean>(false);
  const [triageSavedBanner, setTriageSavedBanner] = useState<string | null>(null);

  // AI Analysis State
  const [aiReport, setAiReport] = useState<ThreatAnalysisReport | null>(null);
  const [aiAnalyzing, setAiAnalyzing] = useState<boolean>(false);

  // New MITRE Rule Form State
  const [newRuleCode, setNewRuleCode] = useState<string>("DOOM-RULE-007");
  const [newRuleTitle, setNewRuleTitle] = useState<string>("");
  const [newRuleSeverity, setNewRuleSeverity] = useState<string>("high");
  const [newRuleTactic, setNewRuleTactic] = useState<string>("Exfiltration");
  const [newRuleTechnique, setNewRuleTechnique] = useState<string>("T1048");
  const [newRuleKeywords, setNewRuleKeywords] = useState<string>("");
  const [creatingRule, setCreatingRule] = useState<boolean>(false);

  const selectAlertForTriage = useCallback((alert: SecurityAlert) => {
    setSelectedAlert(alert);
    setTriageStatus(alert.status);
    setTriageAssignee(alert.assignee || "SOC-Queue");
    setTriageNotes(alert.notes || "");
    setAiReport(null);
    setTriageSavedBanner(null);
  }, []);

  const fetchAlertsAndRules = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      params.set("limit", "100");
      if (statusFilter) params.set("status", statusFilter);
      if (severityFilter) params.set("severity", severityFilter);
      if (searchQuery.trim()) params.set("search", searchQuery.trim());

      const [alertsRes, rulesRes] = await Promise.all([
        fetch(`${apiBaseUrl}/api/v1/alerts?${params.toString()}`, {
          cache: "no-store",
        }),
        fetch(`${apiBaseUrl}/api/v1/rules`, { cache: "no-store" }),
      ]);

      if (alertsRes.ok) {
        const data = await alertsRes.json();
        const list: SecurityAlert[] = data.alerts ?? [];
        setAlerts(list);
        if (list.length > 0 && !selectedAlert) {
          selectAlertForTriage(list[0]);
        } else if (selectedAlert) {
          const refreshed = list.find((a) => a.id === selectedAlert.id);
          if (refreshed) {
            setSelectedAlert(refreshed);
          }
        }
      }

      if (rulesRes.ok) {
        const rData = await rulesRes.json();
        setRules(rData.rules ?? []);
      }
    } finally {
      setLoading(false);
    }
  }, [
    apiBaseUrl,
    searchQuery,
    selectAlertForTriage,
    selectedAlert,
    severityFilter,
    statusFilter,
  ]);

  useEffect(() => {
    void fetchAlertsAndRules();
  }, [fetchAlertsAndRules]);

  useEffect(() => {
    if (initialSelectedAlert) {
      selectAlertForTriage(initialSelectedAlert);
    }
  }, [initialSelectedAlert, selectAlertForTriage]);

  const handleSaveTriage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAlert) return;
    setSavingTriage(true);
    setTriageSavedBanner(null);
    try {
      const res = await fetch(
        `${apiBaseUrl}/api/v1/alerts/${selectedAlert.id}/triage`,
        {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            status: triageStatus,
            assignee: triageAssignee,
            notes: triageNotes,
          }),
        }
      );
      if (res.ok) {
        const updated: SecurityAlert = await res.json();
        setSelectedAlert(updated);
        setTriageSavedBanner(`Triage updated to ${updated.status.toUpperCase()}`);
        await fetchAlertsAndRules();
        onRefreshGlobalStats();
      }
    } finally {
      setSavingTriage(false);
    }
  };

  const handleRunAIAnalysis = async () => {
    if (!selectedAlert) return;
    setAiAnalyzing(true);
    try {
      const res = await fetch(
        `${apiBaseUrl}/api/v1/alerts/${selectedAlert.id}/analyze`,
        {
          method: "POST",
        }
      );
      if (res.ok) {
        const data: { alert: SecurityAlert; analysis: ThreatAnalysisReport } =
          await res.json();
        setSelectedAlert(data.alert);
        setAiReport(data.analysis);
        await fetchAlertsAndRules();
      }
    } finally {
      setAiAnalyzing(false);
    }
  };

  const handleToggleRule = async (rule: DetectionRule) => {
    const res = await fetch(`${apiBaseUrl}/api/v1/rules/${rule.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: !rule.enabled }),
    });
    if (res.ok) {
      await fetchAlertsAndRules();
      onRefreshGlobalStats();
    }
  };

  const handleCreateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newRuleCode.trim() || !newRuleTitle.trim() || !newRuleKeywords.trim()) {
      return;
    }
    setCreatingRule(true);
    try {
      const res = await fetch(`${apiBaseUrl}/api/v1/rules`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          rule_code: newRuleCode.trim(),
          title: newRuleTitle.trim(),
          description: `Custom SOC rule for ${newRuleTactic} (${newRuleTechnique})`,
          severity: newRuleSeverity,
          mitre_tactic: newRuleTactic.trim(),
          mitre_technique_id: newRuleTechnique.trim(),
          match_keywords: newRuleKeywords.trim(),
          enabled: true,
        }),
      });
      if (res.ok) {
        setNewRuleTitle("");
        setNewRuleKeywords("");
        await fetchAlertsAndRules();
        onRefreshGlobalStats();
      }
    } finally {
      setCreatingRule(false);
    }
  };

  return (
    <div className="space-y-8">
      {/* Alert Filter Bar */}
      <section
        aria-label="Alert Triage Filter Bar"
        className="doom-card bg-doom-panel border border-doom-border rounded p-4 grid grid-cols-1 md:grid-cols-12 gap-3 items-end"
      >
        <div className="md:col-span-5 space-y-1">
          <label
            htmlFor="alert-search-input"
            className="block font-mono text-[11px] uppercase tracking-wider text-zinc-400"
          >
            SEARCH INCIDENT QUEUE
          </label>
          <div className="relative">
            <Search
              className="h-4 w-4 text-zinc-400 absolute left-3 top-2.5"
              aria-hidden="true"
            />
            <input
              id="alert-search-input"
              type="search"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search rule title, host, IP, or MITRE technique..."
              className="w-full pl-9 pr-3 py-2 rounded bg-doom-obsidian border border-doom-border font-mono text-xs text-white placeholder:text-zinc-500"
            />
          </div>
        </div>

        <div className="md:col-span-3 space-y-1">
          <label
            htmlFor="alert-status-select"
            className="block font-mono text-[11px] uppercase tracking-wider text-zinc-400"
          >
            TRIAGE STATUS
          </label>
          <select
            id="alert-status-select"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="w-full px-3 py-2 rounded bg-doom-obsidian border border-doom-border font-mono text-xs text-white"
          >
            <option value="">ALL STATUSES</option>
            <option value="open">OPEN</option>
            <option value="investigating">INVESTIGATING</option>
            <option value="resolved">RESOLVED</option>
            <option value="false_positive">FALSE POSITIVE</option>
          </select>
        </div>

        <div className="md:col-span-2 space-y-1">
          <label
            htmlFor="alert-severity-select"
            className="block font-mono text-[11px] uppercase tracking-wider text-zinc-400"
          >
            SEVERITY
          </label>
          <select
            id="alert-severity-select"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="w-full px-3 py-2 rounded bg-doom-obsidian border border-doom-border font-mono text-xs text-white"
          >
            <option value="">ALL SEVERITIES</option>
            <option value="critical">CRITICAL</option>
            <option value="high">HIGH</option>
            <option value="medium">MEDIUM</option>
            <option value="low">LOW</option>
          </select>
        </div>

        <div className="md:col-span-2">
          <button
            type="button"
            onClick={() => void fetchAlertsAndRules()}
            disabled={loading}
            className="w-full inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded bg-doom-elevated hover:bg-zinc-800 border border-doom-border font-mono text-xs text-white transition"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`}
              aria-hidden="true"
            />
            <span>REFRESH</span>
          </button>
        </div>
      </section>

      {/* Split-Pane Alert Queue & Incident Dossier / AI Threat Analyst */}
      <section
        aria-label="Incident Triage Workbench"
        className="grid grid-cols-1 lg:grid-cols-12 gap-5"
      >
        {/* Left Pane: Alert Queue Table */}
        <div className="lg:col-span-7 doom-card bg-doom-panel border border-doom-border rounded p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-doom-border pb-2">
            <h2
              id="alert-queue-caption"
              className="font-mono text-xs font-bold uppercase tracking-wider text-zinc-200"
            >
              PRIORITIZED ALERT TRIAGE QUEUE ({alerts.length})
            </h2>
            <span className="font-mono text-[11px] text-zinc-400">
              Click alert to open dossier
            </span>
          </div>

          <div
            tabIndex={0}
            role="region"
            aria-labelledby="alert-queue-caption"
            className="table-wrapper max-h-[580px]"
          >
            <table className="text-left font-mono text-xs">
              <caption className="visually-hidden">
                Prioritized security alerts and incident triage statuses
              </caption>
              <thead className="bg-doom-elevated text-zinc-400 border-b border-doom-border">
                <tr>
                  <th scope="col" className="py-2.5 px-3">
                    RULE / ALERT
                  </th>
                  <th scope="col" className="py-2.5 px-3">
                    SEVERITY
                  </th>
                  <th scope="col" className="py-2.5 px-3">
                    STATUS
                  </th>
                  <th scope="col" className="py-2.5 px-3">
                    MITRE
                  </th>
                  <th scope="col" className="py-2.5 px-3">
                    TARGET
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-doom-border/60">
                {alerts.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-zinc-400">
                      No alerts match the current filter.
                    </td>
                  </tr>
                ) : (
                  alerts.map((alert) => {
                    const isSelected = selectedAlert?.id === alert.id;
                    return (
                      <tr
                        key={alert.id}
                        onClick={() => selectAlertForTriage(alert)}
                        className={`cursor-pointer transition ${
                          isSelected
                            ? "bg-doom-crimson/15 border-l-2 border-l-doom-crimson"
                            : "hover:bg-doom-elevated/60"
                        }`}
                      >
                        <th scope="row" className="py-2.5 px-3 font-normal">
                          <div className="flex items-center gap-1.5">
                            <span className="text-[11px] font-bold text-rose-400">
                              {alert.rule_code}
                            </span>
                            {alert.ai_summary && (
                              <span className="px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-300 text-[10px]">
                                AI READY
                              </span>
                            )}
                          </div>
                          <div className="text-white font-semibold max-w-[230px] truncate">
                            {alert.title}
                          </div>
                        </th>
                        <td className="py-2.5 px-3">
                          <SeverityBadge severity={alert.severity} />
                        </td>
                        <td className="py-2.5 px-3">
                          <StatusBadge status={alert.status} />
                        </td>
                        <td className="py-2.5 px-3 text-amber-300">
                          {alert.mitre_technique_id}
                        </td>
                        <td className="py-2.5 px-3 text-zinc-300">
                          <div>{alert.target_host}</div>
                          <div className="text-[11px] text-zinc-500">
                            src: {alert.source_ip}
                          </div>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right Pane: Selected Alert Incident Dossier & AI Threat Analysis */}
        <div className="lg:col-span-5 space-y-4">
          {selectedAlert ? (
            <>
              <div className="doom-card bg-doom-panel border border-doom-border rounded p-5 space-y-4">
                <div className="flex items-start justify-between gap-2 border-b border-doom-border pb-3">
                  <div>
                    <div className="flex items-center gap-2 font-mono text-xs text-rose-400 font-bold">
                      <span>{selectedAlert.rule_code}</span>
                      <span>•</span>
                      <span>
                        {selectedAlert.mitre_tactic} ({selectedAlert.mitre_technique_id})
                      </span>
                    </div>
                    <h3 className="font-mono text-base font-bold text-white mt-1">
                      {selectedAlert.title}
                    </h3>
                  </div>
                  <SeverityBadge severity={selectedAlert.severity} />
                </div>

                {/* Metadata Grid */}
                <div className="grid grid-cols-2 gap-2.5 bg-doom-obsidian p-3 rounded border border-doom-border font-mono text-xs">
                  <div>
                    <span className="text-zinc-500 block text-[10px]">SOURCE IP</span>
                    <span className="text-rose-300 font-bold">
                      {selectedAlert.source_ip}
                    </span>
                  </div>
                  <div>
                    <span className="text-zinc-500 block text-[10px]">TARGET HOST</span>
                    <span className="text-white font-bold">
                      {selectedAlert.target_host}
                    </span>
                  </div>
                  <div>
                    <span className="text-zinc-500 block text-[10px]">SERVICE / PROTO</span>
                    <span className="text-emerald-300">
                      {selectedAlert.service} ({selectedAlert.source_protocol})
                    </span>
                  </div>
                  <div>
                    <span className="text-zinc-500 block text-[10px]">TRIGGERED UTC</span>
                    <span className="text-zinc-300">{selectedAlert.triggered_at}</span>
                  </div>
                </div>

                <div className="font-mono text-xs">
                  <span className="text-zinc-400 block text-[11px] mb-1">
                    MATCHED TELEMETRY EXCERPT:
                  </span>
                  <pre className="p-2.5 rounded bg-doom-obsidian border border-doom-border text-zinc-200 whitespace-pre-wrap break-all text-[11px]">
                    {selectedAlert.matched_excerpt}
                  </pre>
                </div>

                {/* Triage Workflow Form */}
                <form onSubmit={handleSaveTriage} className="space-y-3 pt-2 border-t border-doom-border">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div className="space-y-1">
                      <label
                        htmlFor="triage-status-select"
                        className="block font-mono text-[11px] uppercase text-zinc-400"
                      >
                        WORKFLOW STATUS
                      </label>
                      <select
                        id="triage-status-select"
                        value={triageStatus}
                        onChange={(e) => setTriageStatus(e.target.value)}
                        className="w-full px-3 py-2 rounded bg-doom-obsidian border border-doom-border font-mono text-xs text-white"
                      >
                        <option value="open">OPEN</option>
                        <option value="investigating">INVESTIGATING</option>
                        <option value="resolved">RESOLVED</option>
                        <option value="false_positive">FALSE POSITIVE</option>
                      </select>
                    </div>

                    <div className="space-y-1">
                      <label
                        htmlFor="triage-assignee-input"
                        className="block font-mono text-[11px] uppercase text-zinc-400"
                      >
                        ASSIGNED ANALYST
                      </label>
                      <div className="relative">
                        <UserCheck
                          className="h-3.5 w-3.5 text-zinc-400 absolute left-3 top-2.5"
                          aria-hidden="true"
                        />
                        <input
                          id="triage-assignee-input"
                          type="text"
                          value={triageAssignee}
                          onChange={(e) => setTriageAssignee(e.target.value)}
                          className="w-full pl-8 pr-3 py-2 rounded bg-doom-obsidian border border-doom-border font-mono text-xs text-white"
                        />
                      </div>
                    </div>
                  </div>

                  <div className="space-y-1">
                    <label
                      htmlFor="triage-notes-textarea"
                      className="block font-mono text-[11px] uppercase text-zinc-400"
                    >
                      ANALYST INVESTIGATION &amp; CONTAINMENT NOTES
                    </label>
                    <textarea
                      id="triage-notes-textarea"
                      rows={2}
                      value={triageNotes}
                      onChange={(e) => setTriageNotes(e.target.value)}
                      placeholder="Record containment actions, firewall blocks, or ticket references..."
                      className="w-full px-3 py-2 rounded bg-doom-obsidian border border-doom-border font-mono text-xs text-white placeholder:text-zinc-500"
                    />
                  </div>

                  {triageSavedBanner && (
                    <div
                      role="status"
                      aria-live="polite"
                      className="p-2 rounded bg-emerald-950/60 border border-emerald-600/60 font-mono text-xs text-emerald-300"
                    >
                      ✓ {triageSavedBanner}
                    </div>
                  )}

                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      type="submit"
                      disabled={savingTriage}
                      className="flex-1 inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded bg-doom-crimson hover:bg-rose-600 text-white font-mono text-xs font-semibold transition disabled:opacity-50"
                    >
                      <Save className="h-3.5 w-3.5" aria-hidden="true" />
                      <span>{savingTriage ? "SAVING..." : "SAVE TRIAGE"}</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => void handleRunAIAnalysis()}
                      disabled={aiAnalyzing}
                      className="flex-1 inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded bg-amber-500 hover:bg-amber-400 text-black font-mono text-xs font-bold transition disabled:opacity-50"
                    >
                      <Sparkles className="h-3.5 w-3.5" aria-hidden="true" />
                      <span>
                        {aiAnalyzing ? "RUNNING AI..." : "RUN AI THREAT ANALYSIS"}
                      </span>
                    </button>
                  </div>
                </form>
              </div>

              {/* AI Threat Analysis Output Card */}
              {(aiReport || selectedAlert.ai_summary) && (
                <div className="doom-card bg-doom-panel border border-amber-500/70 rounded p-5 space-y-3">
                  <div className="flex items-center justify-between border-b border-doom-border pb-2.5">
                    <div className="flex items-center gap-2 font-mono text-xs font-bold text-amber-300">
                      <Bot className="h-4 w-4 text-amber-400" aria-hidden="true" />
                      <span>
                        DOOM AI THREAT INTELLIGENCE (
                        {aiReport?.model ?? "gemini-4-hydrogen"})
                      </span>
                    </div>
                    {aiReport && (
                      <span className="px-2 py-0.5 rounded bg-rose-950 border border-rose-600 text-rose-300 font-mono text-xs font-bold">
                        RISK SCORE: {aiReport.risk_score}/100
                      </span>
                    )}
                  </div>

                  {aiReport ? (
                    <div className="space-y-3 font-mono text-xs">
                      <p className="text-zinc-200 leading-relaxed">
                        {aiReport.executive_summary}
                      </p>
                      <div className="p-3 rounded bg-doom-obsidian border border-doom-border space-y-1">
                        <strong className="text-amber-300 block">
                          ROOT CAUSE &amp; ATTACK VECTOR:
                        </strong>
                        <p className="text-zinc-300">{aiReport.root_cause_analysis}</p>
                      </div>
                      <div className="p-3 rounded bg-doom-obsidian border border-doom-border space-y-1">
                        <strong className="text-rose-300 block">
                          MITRE ATT&amp;CK CONTEXT:
                        </strong>
                        <p className="text-zinc-300">{aiReport.mitre_context}</p>
                      </div>
                      <div className="space-y-1">
                        <strong className="text-emerald-400 block">
                          CONTAINMENT &amp; REMEDIATION PLAYBOOK:
                        </strong>
                        <ol className="list-decimal list-inside space-y-1 text-zinc-200">
                          {aiReport.remediation_playbook.map((step) => (
                            <li key={step}>{step}</li>
                          ))}
                        </ol>
                      </div>
                    </div>
                  ) : (
                    <pre className="p-3 rounded bg-doom-obsidian border border-doom-border font-mono text-xs text-zinc-200 whitespace-pre-wrap leading-relaxed">
                      {selectedAlert.ai_summary}
                    </pre>
                  )}
                </div>
              )}
            </>
          ) : (
            <div className="doom-card bg-doom-panel border border-doom-border rounded p-8 text-center font-mono text-xs text-zinc-400">
              Select an alert from the queue to inspect its incident dossier and run AI threat analysis.
            </div>
          )}
        </div>
      </section>

      {/* MITRE ATT&CK Detection Rules Studio */}
      <section
        aria-labelledby="mitre-rules-heading"
        className="doom-card bg-doom-panel border border-doom-border rounded p-5 space-y-5"
      >
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-doom-border pb-3">
          <h2
            id="mitre-rules-heading"
            className="font-mono text-xs font-bold uppercase tracking-wider text-zinc-200 flex items-center gap-2"
          >
            <Shield className="h-4 w-4 text-doom-crimson" aria-hidden="true" />
            <span>MITRE ATT&amp;CK DETECTION RULES STUDIO ({rules.length} RULES)</span>
          </h2>
          <span className="font-mono text-xs text-zinc-400">
            Real-time evaluation on all ingested Syslog, Webhook &amp; Agent streams
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {rules.map((rule) => (
            <div
              key={rule.id}
              className="rounded border border-doom-border bg-doom-obsidian p-4 flex flex-col justify-between gap-3"
            >
              <div className="space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-xs font-bold text-rose-400">
                    {rule.rule_code}
                  </span>
                  <SeverityBadge severity={rule.severity} />
                </div>
                <h3 className="font-mono text-sm font-bold text-white">
                  {rule.title}
                </h3>
                <p className="text-xs text-zinc-400 leading-relaxed">
                  {rule.description}
                </p>
              </div>

              <div className="pt-3 border-t border-doom-border space-y-2 font-mono text-xs">
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-amber-300">
                    {rule.mitre_tactic} ({rule.mitre_technique_id})
                  </span>
                </div>
                <div className="text-[11px] text-zinc-500 truncate" title={rule.match_keywords}>
                  Keywords: <span className="text-zinc-300">{rule.match_keywords}</span>
                </div>
                <button
                  type="button"
                  aria-pressed={rule.enabled}
                  onClick={() => void handleToggleRule(rule)}
                  className={`w-full py-1.5 rounded border font-mono text-xs font-semibold transition ${
                    rule.enabled
                      ? "bg-emerald-950/60 border-emerald-600/60 text-emerald-300 hover:bg-emerald-900/50"
                      : "bg-zinc-900 border-zinc-700 text-zinc-400 hover:bg-zinc-800"
                  }`}
                >
                  {rule.enabled ? "RULE ENABLED (ACTIVE)" : "RULE PAUSED (CLICK TO ENABLE)"}
                </button>
              </div>
            </div>
          ))}
        </div>

        {/* Create Custom MITRE Detection Rule Form */}
        <form
          onSubmit={handleCreateRule}
          className="pt-4 border-t border-doom-border grid grid-cols-1 md:grid-cols-12 gap-3 items-end"
        >
          <div className="md:col-span-2 space-y-1">
            <label
              htmlFor="new-rule-code"
              className="block font-mono text-[11px] uppercase text-zinc-400"
            >
              RULE CODE
            </label>
            <input
              id="new-rule-code"
              type="text"
              required
              value={newRuleCode}
              onChange={(e) => setNewRuleCode(e.target.value)}
              className="w-full px-3 py-2 rounded bg-doom-obsidian border border-doom-border font-mono text-xs text-white"
            />
          </div>

          <div className="md:col-span-3 space-y-1">
            <label
              htmlFor="new-rule-title"
              className="block font-mono text-[11px] uppercase text-zinc-400"
            >
              RULE TITLE
            </label>
            <input
              id="new-rule-title"
              type="text"
              required
              value={newRuleTitle}
              onChange={(e) => setNewRuleTitle(e.target.value)}
              placeholder="e.g. DNS Tunneling Exfiltration"
              className="w-full px-3 py-2 rounded bg-doom-obsidian border border-doom-border font-mono text-xs text-white"
            />
          </div>

          <div className="md:col-span-2 space-y-1">
            <label
              htmlFor="new-rule-tactic"
              className="block font-mono text-[11px] uppercase text-zinc-400"
            >
              MITRE TACTIC / ID
            </label>
            <div className="flex gap-1">
              <input
                id="new-rule-tactic"
                type="text"
                required
                value={newRuleTactic}
                onChange={(e) => setNewRuleTactic(e.target.value)}
                className="w-2/3 px-2 py-2 rounded bg-doom-obsidian border border-doom-border font-mono text-xs text-white"
              />
              <input
                aria-label="MITRE Technique ID"
                type="text"
                required
                value={newRuleTechnique}
                onChange={(e) => setNewRuleTechnique(e.target.value)}
                className="w-1/3 px-2 py-2 rounded bg-doom-obsidian border border-doom-border font-mono text-xs text-amber-300"
              />
            </div>
          </div>

          <div className="md:col-span-1 space-y-1">
            <label
              htmlFor="new-rule-severity"
              className="block font-mono text-[11px] uppercase text-zinc-400"
            >
              SEVERITY
            </label>
            <select
              id="new-rule-severity"
              value={newRuleSeverity}
              onChange={(e) => setNewRuleSeverity(e.target.value)}
              className="w-full px-2 py-2 rounded bg-doom-obsidian border border-doom-border font-mono text-xs text-white"
            >
              <option value="critical">CRIT</option>
              <option value="high">HIGH</option>
              <option value="medium">MED</option>
              <option value="low">LOW</option>
            </select>
          </div>

          <div className="md:col-span-2 space-y-1">
            <label
              htmlFor="new-rule-keywords"
              className="block font-mono text-[11px] uppercase text-zinc-400"
            >
              MATCH KEYWORDS (CSV)
            </label>
            <input
              id="new-rule-keywords"
              type="text"
              required
              value={newRuleKeywords}
              onChange={(e) => setNewRuleKeywords(e.target.value)}
              placeholder="dns tunnel,iodine,dnscat"
              className="w-full px-3 py-2 rounded bg-doom-obsidian border border-doom-border font-mono text-xs text-white"
            />
          </div>

          <div className="md:col-span-2">
            <button
              type="submit"
              disabled={creatingRule}
              className="w-full inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded bg-doom-crimson hover:bg-rose-600 text-white font-mono text-xs font-semibold transition"
            >
              <Plus className="h-3.5 w-3.5" aria-hidden="true" />
              <span>{creatingRule ? "ADDING..." : "ADD MITRE RULE"}</span>
            </button>
          </div>
        </form>
      </section>
    </div>
  );
}
