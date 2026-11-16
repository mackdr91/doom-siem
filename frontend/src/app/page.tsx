/*
Author: Domonick Mack
Date: 2026-11-16
Description: Phase 1 Doom SOC Dark Ops environment readiness and cluster telemetry console.
*/

"use client";

import React, { useCallback, useEffect, useState } from "react";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Cpu,
  Database,
  HardDrive,
  Layers,
  Radio,
  RefreshCw,
  Server,
  ShieldAlert,
  Terminal,
  XCircle,
} from "lucide-react";

interface DependencyStatus {
  name: string;
  role: string;
  status: string;
  latency_ms: number;
  details: string;
}

interface IngestionBindings {
  syslog_udp_port: number;
  syslog_tcp_port: number;
  http_webhook_path: string;
  agent_shipper_path: string;
}

interface SystemHealthReport {
  service: string;
  environment: string;
  version: string;
  status: string;
  uptime_sec: number;
  timestamp_utc: string;
  ai_ready: boolean;
  ingestion: IngestionBindings;
  dependencies: DependencyStatus[];
}

const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080";

export default function EnvironmentStatusPage() {
  const [report, setReport] = useState<SystemHealthReport | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [lastChecked, setLastChecked] = useState<string>("—");

  const fetchClusterHealth = useCallback(async () => {
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/health`, {
        cache: "no-store",
      });
      if (!response.ok) {
        throw new Error(`Engine returned HTTP ${response.status}`);
      }
      const data: SystemHealthReport = await response.json();
      setReport(data);
      setErrorMessage(null);
      setLastChecked(new Date().toISOString());
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Unable to reach Go engine";
      setErrorMessage(message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchClusterHealth();
    const timer = setInterval(() => {
      void fetchClusterHealth();
    }, 10000);
    return () => clearInterval(timer);
  }, [fetchClusterHealth]);

  const isOperational = report?.status === "operational" && !errorMessage;

  return (
    <div className="min-h-screen bg-doom-obsidian text-zinc-100 flex flex-col font-sans">
      {/* Top Tactical Command Bar */}
      <header className="border-b border-doom-border bg-doom-panel/90 backdrop-blur px-6 py-4">
        <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="h-9 w-9 rounded bg-doom-crimson/20 border border-doom-crimson flex items-center justify-center">
              <ShieldAlert className="h-5 w-5 text-doom-crimson" aria-hidden="true" />
            </div>
            <div>
              <div className="flex items-center gap-2.5">
                <span className="font-mono text-lg font-bold tracking-wider text-white">
                  DOOM // SIEM
                </span>
                <span className="text-[11px] font-mono uppercase tracking-widest px-2 py-0.5 rounded bg-doom-crimson/20 text-rose-300 border border-doom-crimson/50">
                  PHASE 1 ENVIRONMENT
                </span>
              </div>
              <p className="text-xs font-mono text-zinc-400">
                DARK OPS TELEMETRY, MITRE ATT&amp;CK CORRELATION &amp; AI TRIAGE ENGINE
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div
              className={`doom-badge-active flex items-center gap-2 px-3 py-1.5 rounded border font-mono text-xs ${
                isOperational
                  ? "bg-emerald-950/50 border-emerald-600/60 text-emerald-300"
                  : "bg-amber-950/60 border-amber-500/70 text-amber-300"
              }`}
              role="status"
              aria-live="polite"
            >
              {isOperational ? (
                <CheckCircle2 className="h-4 w-4 text-emerald-400" aria-hidden="true" />
              ) : (
                <AlertTriangle className="h-4 w-4 text-amber-400" aria-hidden="true" />
              )}
              <span>
                CLUSTER STATE:{" "}
                <strong>
                  {errorMessage
                    ? "ENGINE OFFLINE"
                    : (report?.status ?? "PROBING").toUpperCase()}
                </strong>
              </span>
            </div>

            <button
              type="button"
              onClick={() => void fetchClusterHealth()}
              disabled={loading}
              className="flex items-center gap-2 px-3.5 py-1.5 rounded bg-doom-crimson hover:bg-rose-600 text-white font-mono text-xs font-semibold tracking-wider transition disabled:opacity-50"
            >
              <RefreshCw
                className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`}
                aria-hidden="true"
              />
              <span>PROBE CLUSTER</span>
            </button>
          </div>
        </div>
      </header>

      {/* Main High-Density Telemetry Grid */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-6 py-8 space-y-8">
        {/* Error Banner if Backend Unreachable */}
        {errorMessage && (
          <div
            role="alert"
            className="doom-card rounded border border-rose-600 bg-rose-950/40 p-4 flex items-start gap-3 text-rose-200"
          >
            <XCircle className="h-5 w-5 text-rose-400 shrink-0 mt-0.5" aria-hidden="true" />
            <div className="font-mono text-xs space-y-1">
              <div className="font-bold uppercase tracking-wider text-rose-300">
                [CRITICAL] BACKEND TELEMETRY LINK INTERRUPTED
              </div>
              <p>
                Could not query Go Engine at <code>{API_BASE_URL}/api/v1/health</code>:{" "}
                {errorMessage}
              </p>
            </div>
          </div>
        )}

        {/* Top KPI Strip */}
        <section aria-label="Environment KPIs" className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="doom-card bg-doom-panel border border-doom-border rounded p-4">
            <div className="flex items-center justify-between text-xs font-mono text-zinc-400">
              <span>ENGINE RUNTIME</span>
              <Cpu className="h-4 w-4 text-doom-crimson" aria-hidden="true" />
            </div>
            <div className="mt-2 font-mono text-xl font-bold text-white">
              {report?.service ?? "doom-siem-engine"}
            </div>
            <div className="mt-1 font-mono text-xs text-zinc-400">
              Version: <span className="text-zinc-200">{report?.version ?? "0.1.0-phase1"}</span>
            </div>
          </div>

          <div className="doom-card bg-doom-panel border border-doom-border rounded p-4">
            <div className="flex items-center justify-between text-xs font-mono text-zinc-400">
              <span>DEPLOYMENT TIER</span>
              <Server className="h-4 w-4 text-amber-400" aria-hidden="true" />
            </div>
            <div className="mt-2 font-mono text-xl font-bold uppercase text-amber-300">
              {report?.environment ?? "development"}
            </div>
            <div className="mt-1 font-mono text-xs text-zinc-400">
              Uptime: <span className="text-zinc-200">{report?.uptime_sec ?? 0}s</span>
            </div>
          </div>

          <div className="doom-card bg-doom-panel border border-doom-border rounded p-4">
            <div className="flex items-center justify-between text-xs font-mono text-zinc-400">
              <span>SYSLOG / WEBHOOK PORTS</span>
              <Radio className="h-4 w-4 text-emerald-400" aria-hidden="true" />
            </div>
            <div className="mt-2 font-mono text-xl font-bold text-emerald-300">
              UDP/TCP :{report?.ingestion.syslog_udp_port ?? 5514}
            </div>
            <div className="mt-1 font-mono text-xs text-zinc-400">
              HTTP: <span className="text-zinc-200">{report?.ingestion.http_webhook_path ?? "/api/v1/ingest/webhook"}</span>
            </div>
          </div>

          <div className="doom-card bg-doom-panel border border-doom-border rounded p-4">
            <div className="flex items-center justify-between text-xs font-mono text-zinc-400">
              <span>LAST HEARTBEAT (UTC)</span>
              <Activity className="h-4 w-4 text-doom-crimson" aria-hidden="true" />
            </div>
            <div className="mt-2 font-mono text-sm font-bold text-white truncate">
              {report?.timestamp_utc ?? lastChecked}
            </div>
            <div className="mt-1 font-mono text-xs text-zinc-400">
              Poll Cadence: <span className="text-zinc-200">10s Auto-Refresh</span>
            </div>
          </div>
        </section>

        {/* Backing Infrastructure Matrix */}
        <section aria-labelledby="infra-heading" className="space-y-3">
          <div className="flex items-center justify-between border-b border-doom-border pb-2">
            <h2
              id="infra-heading"
              className="font-mono text-sm font-bold uppercase tracking-wider text-zinc-200 flex items-center gap-2"
            >
              <Database className="h-4 w-4 text-doom-crimson" aria-hidden="true" />
              <span>CONTAINERIZED DATAPLANE &amp; STREAMING CLUSTER</span>
            </h2>
            <span className="font-mono text-xs text-zinc-400">
              Docker Compose + Railway Ready
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {(report?.dependencies ?? [
              {
                name: "PostgreSQL 16",
                role: "Alerts, Incident Triage & MITRE Rules",
                status: loading ? "probing" : "unreachable",
                latency_ms: 0,
                details: "Awaiting engine probe...",
              },
              {
                name: "ClickHouse OLAP",
                role: "Columnar Log & Telemetry Store",
                status: loading ? "probing" : "unreachable",
                latency_ms: 0,
                details: "Awaiting engine probe...",
              },
              {
                name: "Redis 7 Streams",
                role: "Event Ingestion Queue & Live Pub/Sub",
                status: loading ? "probing" : "unreachable",
                latency_ms: 0,
                details: "Awaiting engine probe...",
              },
            ]).map((dep) => {
              const healthy = dep.status === "healthy";
              return (
                <div
                  key={dep.name}
                  className="doom-card bg-doom-panel border border-doom-border rounded p-5 flex flex-col justify-between gap-4"
                >
                  <div className="space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-base font-bold text-white">
                        {dep.name}
                      </span>
                      <span
                        className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-mono uppercase border ${
                          healthy
                            ? "bg-emerald-950/60 border-emerald-600/60 text-emerald-300"
                            : "bg-rose-950/60 border-rose-600/60 text-rose-300"
                        }`}
                      >
                        {healthy ? (
                          <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" aria-hidden="true" />
                        ) : (
                          <XCircle className="h-3.5 w-3.5 text-rose-400" aria-hidden="true" />
                        )}
                        <span>{dep.status}</span>
                      </span>
                    </div>
                    <p className="text-xs font-mono text-zinc-400">{dep.role}</p>
                  </div>

                  <div className="pt-3 border-t border-doom-border/80 flex items-center justify-between font-mono text-xs">
                    <span className="text-zinc-300 truncate max-w-[70%]" title={dep.details}>
                      {dep.details}
                    </span>
                    <span className="text-amber-300 font-semibold">
                      {dep.latency_ms} ms
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </section>

        {/* Staged SOC Modules Architecture Preview */}
        <section aria-labelledby="modules-heading" className="space-y-3">
          <div className="flex items-center justify-between border-b border-doom-border pb-2">
            <h2
              id="modules-heading"
              className="font-mono text-sm font-bold uppercase tracking-wider text-zinc-200 flex items-center gap-2"
            >
              <Layers className="h-4 w-4 text-amber-400" aria-hidden="true" />
              <span>STAGED DOOM SOC MODULES (UPCOMING PHASES)</span>
            </h2>
            <span className="font-mono text-xs text-zinc-400">
              Awaiting Phase 2 Confirmation
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="doom-card bg-doom-panel/70 border border-doom-border rounded p-4 space-y-2">
              <div className="flex items-center justify-between font-mono text-xs">
                <span className="text-doom-crimson font-bold">MODULE 01</span>
                <span className="px-2 py-0.5 rounded bg-zinc-800 text-zinc-300">
                  STAGED
                </span>
              </div>
              <h3 className="font-mono text-sm font-bold text-white">
                Command Center Overview
              </h3>
              <p className="text-xs text-zinc-400 leading-relaxed">
                High-density SOC KPIs, real-time threat velocity timelines, severity
                breakdown rings, MITRE ATT&amp;CK heatmaps, and top attacker autonomous
                system telemetry.
              </p>
            </div>

            <div className="doom-card bg-doom-panel/70 border border-doom-border rounded p-4 space-y-2">
              <div className="flex items-center justify-between font-mono text-xs">
                <span className="text-amber-400 font-bold">MODULE 02</span>
                <span className="px-2 py-0.5 rounded bg-zinc-800 text-zinc-300">
                  STAGED
                </span>
              </div>
              <h3 className="font-mono text-sm font-bold text-white">
                Live Log Stream &amp; Query Explorer
              </h3>
              <p className="text-xs text-zinc-400 leading-relaxed">
                Sub-second ClickHouse search across Syslog (UDP/TCP), HTTP Webhooks, and
                Agent shippers with live SSE streaming and deep JSON packet inspection.
              </p>
            </div>

            <div className="doom-card bg-doom-panel/70 border border-doom-border rounded p-4 space-y-2">
              <div className="flex items-center justify-between font-mono text-xs">
                <span className="text-emerald-400 font-bold">MODULE 03</span>
                <span className="px-2 py-0.5 rounded bg-zinc-800 text-zinc-300">
                  STAGED
                </span>
              </div>
              <h3 className="font-mono text-sm font-bold text-white">
                Alerts, Incident Triage &amp; AI Analyst
              </h3>
              <p className="text-xs text-zinc-400 leading-relaxed">
                Prioritized alert queue mapped to MITRE ATT&amp;CK tactics with status
                workflows and AI-assisted log anomaly explanation and remediation steps.
              </p>
            </div>
          </div>
        </section>
      </main>

      {/* Footer Status Bar */}
      <footer className="border-t border-doom-border bg-doom-panel px-6 py-3">
        <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-2 font-mono text-xs text-zinc-400">
          <div className="flex items-center gap-2">
            <Terminal className="h-3.5 w-3.5 text-doom-crimson" aria-hidden="true" />
            <span>DOOM SIEM // PHASE 1 ENVIRONMENT VERIFIED</span>
          </div>
          <div className="flex items-center gap-4">
            <span className="flex items-center gap-1">
              <HardDrive className="h-3.5 w-3.5 text-zinc-400" aria-hidden="true" />
              <span>API: {API_BASE_URL}</span>
            </span>
          </div>
        </div>
      </footer>
    </div>
  );
}
