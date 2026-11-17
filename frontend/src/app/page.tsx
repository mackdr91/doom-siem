/*
Author: Domonick Mack
Date: 2026-11-16
Description: Main Doom SOC Dark Ops dashboard application shell integrating Command Center, Live Log Stream Explorer, and Alerts & Incident Triage Queue.
*/

"use client";

import React, { useCallback, useEffect, useState } from "react";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  HardDrive,
  LayoutDashboard,
  PackageSearch,
  Radio,
  RefreshCw,
  ShieldAlert,
  Siren,
  Terminal,
  XCircle,
  Zap,
} from "lucide-react";
import CommandCenterView from "@/components/CommandCenterView";
import LiveLogExplorerView from "@/components/LiveLogExplorerView";
import AlertsTriageView from "@/components/AlertsTriageView";
import CpeLookupView from "@/components/CpeLookupView";
import type {
  ActiveSocModule,
  AlertSummaryStats,
  SecurityAlert,
  SecurityEvent,
  SystemHealthReport,
  TelemetryStats,
} from "@/types/siem";

const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080";

export default function DoomSocDashboardPage() {
  const [activeModule, setActiveModule] =
    useState<ActiveSocModule>("command-center");
  const [health, setHealth] = useState<SystemHealthReport | null>(null);
  const [telemetryStats, setTelemetryStats] = useState<TelemetryStats | null>(
    null
  );
  const [alertStats, setAlertStats] = useState<AlertSummaryStats | null>(null);
  const [recentAlerts, setRecentAlerts] = useState<SecurityAlert[]>([]);
  const [selectedAlertForTriage, setSelectedAlertForTriage] =
    useState<SecurityAlert | null>(null);

  // Live SSE streaming state
  const [liveStreamEnabled, setLiveStreamEnabled] = useState<boolean>(true);
  const [liveIncomingEvents, setLiveIncomingEvents] = useState<SecurityEvent[]>(
    []
  );
  const [sseConnected, setSseConnected] = useState<boolean>(false);

  // Action state
  const [loading, setLoading] = useState<boolean>(false);
  const [simulating, setSimulating] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const fetchSocSnapshot = useCallback(async () => {
    setLoading(true);
    try {
      const [healthRes, statsRes, alertStatsRes, alertsRes] = await Promise.all(
        [
          fetch(`${API_BASE_URL}/api/v1/health`, { cache: "no-store" }),
          fetch(`${API_BASE_URL}/api/v1/events/stats`, { cache: "no-store" }),
          fetch(`${API_BASE_URL}/api/v1/alerts/stats`, { cache: "no-store" }),
          fetch(`${API_BASE_URL}/api/v1/alerts?limit=15`, {
            cache: "no-store",
          }),
        ]
      );

      if (!healthRes.ok) {
        throw new Error(`Engine health endpoint returned HTTP ${healthRes.status}`);
      }
      setHealth(await healthRes.json());

      if (statsRes.ok) {
        setTelemetryStats(await statsRes.json());
      }
      if (alertStatsRes.ok) {
        setAlertStats(await alertStatsRes.json());
      }
      if (alertsRes.ok) {
        const aData = await alertsRes.json();
        setRecentAlerts(aData.alerts ?? []);
      }

      setErrorMessage(null);
    } catch (err) {
      setErrorMessage(
        err instanceof Error ? err.message : "Failed to reach Doom SIEM Engine"
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchSocSnapshot();
    const timer = setInterval(() => {
      void fetchSocSnapshot();
    }, 10000);
    return () => clearInterval(timer);
  }, [fetchSocSnapshot]);

  // Connect to Server-Sent Events (/api/v1/events/stream)
  useEffect(() => {
    if (!liveStreamEnabled) {
      setSseConnected(false);
      return;
    }

    const es = new EventSource(`${API_BASE_URL}/api/v1/events/stream`);
    es.onopen = () => {
      setSseConnected(true);
    };
    es.onerror = () => {
      setSseConnected(false);
    };
    es.addEventListener("security_event", (event: MessageEvent) => {
      try {
        const parsed: SecurityEvent = JSON.parse(event.data);
        setLiveIncomingEvents((prev) => [parsed, ...prev].slice(0, 50));
      } catch {
        // Ignore malformed SSE payload
      }
    });

    return () => {
      es.close();
      setSseConnected(false);
    };
  }, [liveStreamEnabled]);

  const handleSimulateAttackWave = async () => {
    setSimulating(true);
    try {
      const res = await fetch(`${API_BASE_URL}/api/v1/ingest/simulate`, {
        method: "POST",
      });
      if (res.ok) {
        await new Promise((resolve) => setTimeout(resolve, 650));
        await fetchSocSnapshot();
      }
    } finally {
      setSimulating(false);
    }
  };

  const isOperational = health?.status === "operational" && !errorMessage;

  return (
    <div className="min-h-screen bg-doom-obsidian text-zinc-100 flex flex-col font-sans">
      <a
        href="#soc-main-heading"
        className="visually-hidden focus:fixed focus:top-3 focus:left-3 focus:z-50 focus:px-4 focus:py-2 focus:rounded focus:bg-doom-crimson focus:text-white focus:font-mono focus:text-xs"
      >
        Skip to main content
      </a>

      {/* Top Tactical Command Header */}
      <header className="border-b border-doom-border bg-doom-panel/95 backdrop-blur sticky top-0 z-30">
        <div className="max-w-7xl mx-auto px-6 py-3.5 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="h-9 w-9 rounded bg-doom-crimson/20 border border-doom-crimson flex items-center justify-center">
              <ShieldAlert
                className="h-5 w-5 text-doom-crimson"
                aria-hidden="true"
              />
            </div>
            <div>
              <div className="flex items-center gap-2.5">
                <span className="font-mono text-lg font-bold tracking-wider text-white">
                  DOOM // SIEM
                </span>
                <span className="text-[11px] font-mono uppercase tracking-widest px-2 py-0.5 rounded bg-doom-crimson/20 text-rose-300 border border-doom-crimson/50">
                  DARK OPS SOC
                </span>
              </div>
              <p className="text-xs font-mono text-zinc-400">
                MULTI-PROTOCOL TELEMETRY • MITRE ATT&amp;CK CORRELATION • AI THREAT TRIAGE
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            {/* SSE Stream Indicator */}
            <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded bg-doom-obsidian border border-doom-border font-mono text-xs">
              <Radio
                className={`h-3.5 w-3.5 ${
                  sseConnected ? "text-emerald-400 animate-pulse" : "text-zinc-500"
                }`}
                aria-hidden="true"
              />
              <span className="text-zinc-300">
                SSE: <strong>{sseConnected ? "LIVE" : "STANDBY"}</strong>
              </span>
            </div>

            {/* Cluster Health Badge */}
            <div
              className={`doom-badge-active flex items-center gap-1.5 px-2.5 py-1.5 rounded border font-mono text-xs ${
                isOperational
                  ? "bg-emerald-950/50 border-emerald-600/60 text-emerald-300"
                  : "bg-amber-950/60 border-amber-500/70 text-amber-300"
              }`}
              role="status"
              aria-live="polite"
            >
              {isOperational ? (
                <CheckCircle2
                  className="h-3.5 w-3.5 text-emerald-400"
                  aria-hidden="true"
                />
              ) : (
                <AlertTriangle
                  className="h-3.5 w-3.5 text-amber-400"
                  aria-hidden="true"
                />
              )}
              <span>
                CLUSTER:{" "}
                <strong>
                  {errorMessage
                    ? "OFFLINE"
                    : (health?.status ?? "ONLINE").toUpperCase()}
                </strong>
              </span>
            </div>

            {/* Simulate Multi-Protocol Attack Wave Button */}
            <button
              type="button"
              onClick={() => void handleSimulateAttackWave()}
              disabled={simulating}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded bg-doom-crimson hover:bg-rose-600 text-white font-mono text-xs font-bold tracking-wider transition disabled:opacity-50"
            >
              <Zap className="h-3.5 w-3.5" aria-hidden="true" />
              <span>
                {simulating ? "DISPATCHING..." : "SIMULATE ATTACK WAVE"}
              </span>
            </button>

            <button
              type="button"
              onClick={() => void fetchSocSnapshot()}
              disabled={loading}
              aria-label="Refresh SOC Telemetry"
              className="p-1.5 rounded bg-doom-elevated hover:bg-zinc-800 border border-doom-border text-zinc-300 transition"
            >
              <RefreshCw
                className={`h-4 w-4 ${loading ? "animate-spin" : ""}`}
                aria-hidden="true"
              />
            </button>
          </div>
        </div>

        {/* Primary Module Navigation Bar */}
        <nav
          aria-label="Primary SOC Modules"
          className="border-t border-doom-border bg-doom-obsidian/90 px-6"
        >
          <div className="max-w-7xl mx-auto flex flex-wrap items-center gap-2 py-2">
            <button
              type="button"
              aria-current={activeModule === "command-center" ? "page" : undefined}
              onClick={() => setActiveModule("command-center")}
              className={`inline-flex items-center gap-2 px-4 py-2 rounded font-mono text-xs font-bold tracking-wider transition ${
                activeModule === "command-center"
                  ? "bg-doom-crimson text-white"
                  : "text-zinc-400 hover:text-white hover:bg-doom-panel"
              }`}
            >
              <LayoutDashboard className="h-4 w-4" aria-hidden="true" />
              <span>01 // COMMAND CENTER OVERVIEW</span>
            </button>

            <button
              type="button"
              aria-current={activeModule === "live-logs" ? "page" : undefined}
              onClick={() => setActiveModule("live-logs")}
              className={`inline-flex items-center gap-2 px-4 py-2 rounded font-mono text-xs font-bold tracking-wider transition ${
                activeModule === "live-logs"
                  ? "bg-doom-crimson text-white"
                  : "text-zinc-400 hover:text-white hover:bg-doom-panel"
              }`}
            >
              <Activity className="h-4 w-4" aria-hidden="true" />
              <span>
                02 // LIVE LOG STREAM &amp; QUERY EXPLORER (
                {telemetryStats?.total_events ?? 0})
              </span>
            </button>

            <button
              type="button"
              aria-current={activeModule === "alerts-triage" ? "page" : undefined}
              onClick={() => setActiveModule("alerts-triage")}
              className={`inline-flex items-center gap-2 px-4 py-2 rounded font-mono text-xs font-bold tracking-wider transition ${
                activeModule === "alerts-triage"
                  ? "bg-doom-crimson text-white"
                  : "text-zinc-400 hover:text-white hover:bg-doom-panel"
              }`}
            >
              <Siren className="h-4 w-4" aria-hidden="true" />
              <span>
                03 // ALERTS, INCIDENT TRIAGE &amp; AI ANALYST (
                {alertStats?.open_alerts ?? 0} OPEN)
              </span>
            </button>

            <button
              type="button"
              aria-current={activeModule === "cpe-intel" ? "page" : undefined}
              onClick={() => setActiveModule("cpe-intel")}
              className={`inline-flex items-center gap-2 px-4 py-2 rounded font-mono text-xs font-bold tracking-wider transition ${
                activeModule === "cpe-intel"
                  ? "bg-doom-crimson text-white"
                  : "text-zinc-400 hover:text-white hover:bg-doom-panel"
              }`}
            >
              <PackageSearch className="h-4 w-4" aria-hidden="true" />
              <span>04 // CPE ASSET INTEL</span>
            </button>
          </div>
        </nav>
      </header>

      {/* Main Content Landmark */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-6 py-6 space-y-6">
        <h1
          id="soc-main-heading"
          tabIndex={-1}
          className="font-mono text-sm font-bold uppercase tracking-widest text-zinc-400 border-b border-doom-border pb-2"
        >
          {activeModule === "command-center" &&
            "DOOM SOC // COMMAND CENTER & THREAT TELEMETRY OVERVIEW"}
          {activeModule === "live-logs" &&
            "DOOM SOC // CLICKHOUSE LIVE LOG STREAM & PACKET QUERY EXPLORER"}
          {activeModule === "alerts-triage" &&
            "DOOM SOC // MITRE ATT&CK INCIDENT TRIAGE & AI THREAT ANALYST"}
          {activeModule === "cpe-intel" &&
            "DOOM SOC // NIST NVD CPE 2.3 ASSET & PLATFORM INTELLIGENCE"}
        </h1>

        {errorMessage && (
          <div
            role="alert"
            className="doom-card rounded border border-rose-600 bg-rose-950/40 p-4 flex items-start gap-3 text-rose-200"
          >
            <XCircle
              className="h-5 w-5 text-rose-400 shrink-0 mt-0.5"
              aria-hidden="true"
            />
            <div className="font-mono text-xs space-y-1">
              <div className="font-bold uppercase tracking-wider text-rose-300">
                [CRITICAL] BACKEND TELEMETRY LINK INTERRUPTED
              </div>
              <p>
                Could not reach Go Engine at <code>{API_BASE_URL}</code>:{" "}
                {errorMessage}
              </p>
            </div>
          </div>
        )}

        {activeModule === "command-center" && (
          <CommandCenterView
            health={health}
            telemetryStats={telemetryStats}
            alertStats={alertStats}
            recentAlerts={recentAlerts}
            onNavigateModule={setActiveModule}
            onSelectAlert={(alert) => setSelectedAlertForTriage(alert)}
          />
        )}

        {activeModule === "live-logs" && (
          <LiveLogExplorerView
            apiBaseUrl={API_BASE_URL}
            liveStreamEnabled={liveStreamEnabled}
            onToggleLiveStream={() => setLiveStreamEnabled((prev) => !prev)}
            liveIncomingEvents={liveIncomingEvents}
            onRefreshGlobalStats={() => void fetchSocSnapshot()}
          />
        )}

        {activeModule === "alerts-triage" && (
          <AlertsTriageView
            apiBaseUrl={API_BASE_URL}
            initialSelectedAlert={selectedAlertForTriage}
            onRefreshGlobalStats={() => void fetchSocSnapshot()}
          />
        )}

        {activeModule === "cpe-intel" && (
          <CpeLookupView apiBaseUrl={API_BASE_URL} />
        )}
      </main>

      {/* Footer Status Bar */}
      <footer className="border-t border-doom-border bg-doom-panel px-6 py-3">
        <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-2 font-mono text-xs text-zinc-400">
          <div className="flex items-center gap-2">
            <Terminal
              className="h-3.5 w-3.5 text-doom-crimson"
              aria-hidden="true"
            />
            <span>
              DOOM SIEM // {health?.version ?? "v1.0.0"} • SYSLOG UDP/TCP :
              {health?.ingestion.syslog_udp_port ?? 5514} • CLICKHOUSE +
              POSTGRESQL + REDIS 7
            </span>
          </div>
          <div className="flex items-center gap-4">
            <span className="flex items-center gap-1">
              <HardDrive
                className="h-3.5 w-3.5 text-zinc-400"
                aria-hidden="true"
              />
              <span>API: {API_BASE_URL}</span>
            </span>
          </div>
        </div>
      </footer>
    </div>
  );
}
