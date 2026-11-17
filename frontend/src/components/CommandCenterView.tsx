/*
Author: Domonick Mack
Date: 2026-11-16
Description: Doom SOC Command Center Overview module with KPIs, threat velocity bars, MITRE tactic breakdown, and top attackers.
*/

"use client";

import React from "react";
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  ArrowUpRight,
  CheckCircle2,
  Cpu,
  Database,
  Flame,
  Radio,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import type {
  ActiveSocModule,
  AlertSummaryStats,
  SecurityAlert,
  SystemHealthReport,
  TelemetryStats,
} from "@/types/siem";

interface CommandCenterViewProps {
  health: SystemHealthReport | null;
  telemetryStats: TelemetryStats | null;
  alertStats: AlertSummaryStats | null;
  recentAlerts: SecurityAlert[];
  onNavigateModule: (mod: ActiveSocModule) => void;
  onSelectAlert: (alert: SecurityAlert) => void;
}

export function SeverityBadge({ severity }: { severity: string }) {
  const norm = severity.toLowerCase();
  if (norm === "critical") {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-bold uppercase bg-rose-950/80 text-rose-300 border border-rose-600/70">
        <Flame className="h-3 w-3 text-rose-400" aria-hidden="true" />
        <span>CRITICAL</span>
      </span>
    );
  }
  if (norm === "high") {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-bold uppercase bg-amber-950/80 text-amber-300 border border-amber-500/70">
        <AlertTriangle className="h-3 w-3 text-amber-400" aria-hidden="true" />
        <span>HIGH</span>
      </span>
    );
  }
  if (norm === "medium") {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-bold uppercase bg-yellow-950/70 text-yellow-200 border border-yellow-600/60">
        <AlertOctagon className="h-3 w-3 text-yellow-400" aria-hidden="true" />
        <span>MEDIUM</span>
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-bold uppercase bg-zinc-900 text-zinc-300 border border-zinc-700">
      <ShieldCheck className="h-3 w-3 text-emerald-400" aria-hidden="true" />
      <span>LOW</span>
    </span>
  );
}

export default function CommandCenterView({
  health,
  telemetryStats,
  alertStats,
  recentAlerts,
  onNavigateModule,
  onSelectAlert,
}: CommandCenterViewProps) {
  const totalEvents = telemetryStats?.total_events ?? 0;
  const openAlerts = alertStats?.open_alerts ?? 0;
  const criticalAlerts = alertStats?.critical_alerts ?? 0;
  const activeRules = alertStats?.active_rules_count ?? 6;
  const streamDepth = telemetryStats?.stream_queue_depth ?? 0;

  return (
    <div className="space-y-6">
      {/* High-Density Top KPI Strip */}
      <section aria-label="SOC Key Performance Indicators" className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <div className="doom-card bg-doom-panel border border-doom-border rounded p-4">
          <div className="flex items-center justify-between text-xs font-mono text-zinc-400">
            <span>TOTAL EVENTS INGESTED</span>
            <Activity className="h-4 w-4 text-emerald-400" aria-hidden="true" />
          </div>
          <div className="mt-2 font-mono text-2xl font-bold text-white">
            {totalEvents.toLocaleString()}
          </div>
          <div className="mt-1 font-mono text-[11px] text-zinc-400">
            ClickHouse MergeTree Store
          </div>
        </div>

        <div className="doom-card bg-doom-panel border border-doom-border rounded p-4">
          <div className="flex items-center justify-between text-xs font-mono text-zinc-400">
            <span>OPEN INCIDENT ALERTS</span>
            <ShieldAlert className="h-4 w-4 text-amber-400" aria-hidden="true" />
          </div>
          <div className="mt-2 font-mono text-2xl font-bold text-amber-300">
            {openAlerts.toLocaleString()}
          </div>
          <div className="mt-1 font-mono text-[11px] text-zinc-400">
            Total Triggered: <span className="text-zinc-200">{alertStats?.total_alerts ?? 0}</span>
          </div>
        </div>

        <div className="doom-card bg-doom-panel border border-rose-900/70 rounded p-4">
          <div className="flex items-center justify-between text-xs font-mono text-rose-300">
            <span>CRITICAL THREATS</span>
            <Flame className="h-4 w-4 text-doom-crimson" aria-hidden="true" />
          </div>
          <div className="mt-2 font-mono text-2xl font-bold text-rose-400">
            {criticalAlerts.toLocaleString()}
          </div>
          <div className="mt-1 font-mono text-[11px] text-zinc-400">
            Immediate Triage Required
          </div>
        </div>

        <div className="doom-card bg-doom-panel border border-doom-border rounded p-4">
          <div className="flex items-center justify-between text-xs font-mono text-zinc-400">
            <span>ACTIVE MITRE RULES</span>
            <Cpu className="h-4 w-4 text-doom-crimson" aria-hidden="true" />
          </div>
          <div className="mt-2 font-mono text-2xl font-bold text-white">
            {activeRules}
          </div>
          <div className="mt-1 font-mono text-[11px] text-zinc-400">
            Real-Time Correlation Active
          </div>
        </div>

        <div className="doom-card bg-doom-panel border border-doom-border rounded p-4">
          <div className="flex items-center justify-between text-xs font-mono text-zinc-400">
            <span>REDIS STREAM BUFFER</span>
            <Radio className="h-4 w-4 text-emerald-400" aria-hidden="true" />
          </div>
          <div className="mt-2 font-mono text-2xl font-bold text-emerald-300">
            {streamDepth.toLocaleString()}
          </div>
          <div className="mt-1 font-mono text-[11px] text-zinc-400">
            Stream Key: <code>doom:events</code>
          </div>
        </div>
      </section>

      {/* Middle Row: Severity Breakdown, Ingestion Protocols, and MITRE ATT&CK Tactics */}
      <section aria-label="Telemetry Distribution and MITRE Coverage" className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Severity Breakdown */}
        <div className="doom-card bg-doom-panel border border-doom-border rounded p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-doom-border pb-2.5">
            <h2 className="font-mono text-xs font-bold uppercase tracking-wider text-zinc-200">
              EVENT SEVERITY BREAKDOWN
            </h2>
            <span className="font-mono text-[11px] text-zinc-400">
              {totalEvents} Events
            </span>
          </div>
          <div className="space-y-3">
            {(telemetryStats?.by_severity?.length
              ? telemetryStats.by_severity
              : [
                  { key: "critical", count: 0 },
                  { key: "high", count: 0 },
                  { key: "medium", count: 0 },
                  { key: "low", count: 0 },
                ]
            ).map((item) => {
              const pct =
                totalEvents > 0
                  ? Math.min(100, Math.round((item.count / totalEvents) * 100))
                  : 0;
              const barColor =
                item.key === "critical"
                  ? "bg-doom-crimson"
                  : item.key === "high"
                  ? "bg-amber-500"
                  : item.key === "medium"
                  ? "bg-yellow-500"
                  : "bg-emerald-500";
              return (
                <div key={item.key} className="space-y-1">
                  <div className="flex items-center justify-between font-mono text-xs">
                    <SeverityBadge severity={item.key} />
                    <span className="text-zinc-300 font-semibold">
                      {item.count} ({pct}%)
                    </span>
                  </div>
                  <div className="h-2 w-full rounded bg-zinc-900 overflow-hidden border border-zinc-800">
                    <div
                      className={`h-full ${barColor}`}
                      style={{ width: `${Math.max(pct, item.count > 0 ? 6 : 0)}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Multi-Protocol Ingestion Telemetry */}
        <div className="doom-card bg-doom-panel border border-doom-border rounded p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-doom-border pb-2.5">
            <h2 className="font-mono text-xs font-bold uppercase tracking-wider text-zinc-200">
              INGESTION COLLECTOR THROUGHPUT
            </h2>
            <span className="font-mono text-[11px] text-emerald-400">
              4 PROTOCOLS ONLINE
            </span>
          </div>
          <div className="space-y-3">
            {(telemetryStats?.by_protocol?.length
              ? telemetryStats.by_protocol
              : [
                  { key: "syslog_udp", count: 0 },
                  { key: "syslog_tcp", count: 0 },
                  { key: "http_webhook", count: 0 },
                  { key: "agent_shipper", count: 0 },
                ]
            ).map((item) => {
              const pct =
                totalEvents > 0
                  ? Math.min(100, Math.round((item.count / totalEvents) * 100))
                  : 0;
              return (
                <div key={item.key} className="space-y-1">
                  <div className="flex items-center justify-between font-mono text-xs">
                    <span className="text-zinc-200 uppercase">{item.key}</span>
                    <span className="text-amber-300 font-semibold">
                      {item.count} frames ({pct}%)
                    </span>
                  </div>
                  <div className="h-2 w-full rounded bg-zinc-900 overflow-hidden border border-zinc-800">
                    <div
                      className="h-full bg-amber-500"
                      style={{ width: `${Math.max(pct, item.count > 0 ? 6 : 0)}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* MITRE ATT&CK Active Tactics Heatmap */}
        <div className="doom-card bg-doom-panel border border-doom-border rounded p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-doom-border pb-2.5">
            <h2 className="font-mono text-xs font-bold uppercase tracking-wider text-zinc-200">
              MITRE ATT&amp;CK TACTIC DETECTIONS
            </h2>
            <button
              type="button"
              onClick={() => onNavigateModule("alerts-triage")}
              className="inline-flex items-center gap-1 font-mono text-[11px] text-rose-400 hover:text-rose-300"
            >
              <span>OPEN QUEUE</span>
              <ArrowUpRight className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
            {(alertStats?.by_mitre_tactic?.length
              ? alertStats.by_mitre_tactic
              : [
                  { key: "Credential Access", count: 0 },
                  { key: "Initial Access", count: 0 },
                  { key: "Execution", count: 0 },
                  { key: "Lateral Movement", count: 0 },
                  { key: "Privilege Escalation", count: 0 },
                ]
            ).map((tactic) => (
              <div
                key={tactic.key}
                className="rounded border border-doom-border bg-doom-obsidian/80 p-3 flex items-center justify-between"
              >
                <span className="font-mono text-xs text-zinc-200 truncate pr-2">
                  {tactic.key}
                </span>
                <span className="px-2 py-0.5 rounded bg-doom-crimson/20 border border-doom-crimson/60 text-rose-300 font-mono text-xs font-bold">
                  {tactic.count}
                </span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Recent Priority Alerts & Top Attackers */}
      <section aria-label="Priority Alerts and Top Attackers" className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Recent Triggered Alerts Table */}
        <div className="lg:col-span-7 doom-card bg-doom-panel border border-doom-border rounded p-5 space-y-3">
          <div className="flex items-center justify-between border-b border-doom-border pb-2.5">
            <h2
              id="recent-alerts-caption"
              className="font-mono text-xs font-bold uppercase tracking-wider text-zinc-200"
            >
              LATEST CORRELATED SECURITY ALERTS
            </h2>
            <button
              type="button"
              onClick={() => onNavigateModule("alerts-triage")}
              className="font-mono text-xs text-rose-400 hover:text-rose-300 underline"
            >
              View All &amp; Run AI Triage
            </button>
          </div>

          <div
            tabIndex={0}
            role="region"
            aria-labelledby="recent-alerts-caption"
            className="table-wrapper max-h-80"
          >
            <table className="text-left font-mono text-xs">
              <caption className="visually-hidden">
                Latest correlated security alerts triggered by MITRE ATT&amp;CK rules
              </caption>
              <thead className="bg-doom-elevated text-zinc-400 border-b border-doom-border">
                <tr>
                  <th scope="col" className="py-2.5 px-3">
                    RULE / TITLE
                  </th>
                  <th scope="col" className="py-2.5 px-3">
                    SEVERITY
                  </th>
                  <th scope="col" className="py-2.5 px-3">
                    MITRE
                  </th>
                  <th scope="col" className="py-2.5 px-3">
                    SOURCE IP
                  </th>
                  <th scope="col" className="py-2.5 px-3">
                    ACTION
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-doom-border/60">
                {recentAlerts.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-6 text-center text-zinc-400">
                      No active alerts yet. Click &ldquo;SIMULATE ATTACK WAVE&rdquo; in the top bar to inject multi-protocol threat telemetry.
                    </td>
                  </tr>
                ) : (
                  recentAlerts.slice(0, 6).map((alert) => (
                    <tr
                      key={alert.id}
                      className="hover:bg-doom-elevated/60 transition"
                    >
                      <th scope="row" className="py-2.5 px-3 font-medium text-white">
                        <div className="text-[11px] text-rose-400">{alert.rule_code}</div>
                        <div className="truncate max-w-[220px]">{alert.title}</div>
                      </th>
                      <td className="py-2.5 px-3">
                        <SeverityBadge severity={alert.severity} />
                      </td>
                      <td className="py-2.5 px-3 text-amber-300">
                        {alert.mitre_technique_id}
                      </td>
                      <td className="py-2.5 px-3 text-zinc-300">
                        {alert.source_ip}
                      </td>
                      <td className="py-2.5 px-3">
                        <button
                          type="button"
                          onClick={() => {
                            onSelectAlert(alert);
                            onNavigateModule("alerts-triage");
                          }}
                          className="px-2.5 py-1 rounded bg-doom-crimson/20 hover:bg-doom-crimson text-rose-200 hover:text-white border border-doom-crimson/60 text-[11px] transition"
                        >
                          TRIAGE{" "}
                          <span className="visually-hidden">{alert.rule_code}</span>
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Top Attacker Source IPs & Targeted Hosts */}
        <div className="lg:col-span-5 doom-card bg-doom-panel border border-doom-border rounded p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-doom-border pb-2.5">
            <h2
              id="top-attackers-caption"
              className="font-mono text-xs font-bold uppercase tracking-wider text-zinc-200"
            >
              TOP ADVERSARY SOURCE IPs &amp; TARGETS
            </h2>
            <button
              type="button"
              onClick={() => onNavigateModule("live-logs")}
              className="font-mono text-xs text-amber-400 hover:text-amber-300 underline"
            >
              Explore Logs
            </button>
          </div>

          <div
            tabIndex={0}
            role="region"
            aria-labelledby="top-attackers-caption"
            className="table-wrapper max-h-80"
          >
            <table className="text-left font-mono text-xs">
              <caption className="visually-hidden">
                Top source IP addresses by security event volume
              </caption>
              <thead className="bg-doom-elevated text-zinc-400 border-b border-doom-border">
                <tr>
                  <th scope="col" className="py-2 px-3">
                    SOURCE IP
                  </th>
                  <th scope="col" className="py-2 px-3">
                    EVENTS
                  </th>
                  <th scope="col" className="py-2 px-3">
                    TARGET HOST
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-doom-border/60">
                {(telemetryStats?.top_source_ips ?? []).length === 0 ? (
                  <tr>
                    <td colSpan={3} className="py-6 text-center text-zinc-400">
                      No source IP telemetry recorded yet.
                    </td>
                  </tr>
                ) : (
                  (telemetryStats?.top_source_ips ?? []).map((ipBucket, idx) => {
                    const hostBucket = telemetryStats?.top_hosts?.[idx];
                    return (
                      <tr key={ipBucket.key} className="hover:bg-doom-elevated/50">
                        <th scope="row" className="py-2 px-3 text-rose-300 font-semibold">
                          {ipBucket.key}
                        </th>
                        <td className="py-2 px-3 text-white font-bold">
                          {ipBucket.count}
                        </td>
                        <td className="py-2 px-3 text-zinc-300">
                          {hostBucket?.key ?? "multi-host"}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* Containerized Dataplane Health Strip */}
      <section aria-labelledby="dataplane-health-heading" className="space-y-3">
        <div className="flex items-center justify-between border-b border-doom-border pb-2">
          <h2
            id="dataplane-health-heading"
            className="font-mono text-xs font-bold uppercase tracking-wider text-zinc-300 flex items-center gap-2"
          >
            <Database className="h-4 w-4 text-doom-crimson" aria-hidden="true" />
            <span>CONTAINERIZED DATAPLANE &amp; STREAMING CLUSTER HEALTH</span>
          </h2>
          <span className="font-mono text-xs text-zinc-400">
            Engine Uptime: {health?.uptime_sec ?? 0}s
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {(health?.dependencies ?? []).map((dep) => {
            const healthy = dep.status === "healthy";
            return (
              <div
                key={dep.name}
                className="doom-card bg-doom-panel border border-doom-border rounded p-4 flex items-center justify-between gap-3"
              >
                <div className="space-y-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-bold text-white">
                      {dep.name}
                    </span>
                    <span
                      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono uppercase border ${
                        healthy
                          ? "bg-emerald-950/60 border-emerald-600/60 text-emerald-300"
                          : "bg-rose-950/60 border-rose-600/60 text-rose-300"
                      }`}
                    >
                      {healthy ? (
                        <CheckCircle2 className="h-3 w-3 text-emerald-400" aria-hidden="true" />
                      ) : (
                        <XCircle className="h-3 w-3 text-rose-400" aria-hidden="true" />
                      )}
                      <span>{dep.status}</span>
                    </span>
                  </div>
                  <p className="font-mono text-xs text-zinc-400 truncate">
                    {dep.details}
                  </p>
                </div>
                <div className="font-mono text-xs font-bold text-amber-300 shrink-0">
                  {dep.latency_ms} ms
                </div>
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
}
