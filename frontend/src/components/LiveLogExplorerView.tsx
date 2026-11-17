/*
Author: Domonick Mack
Date: 2026-11-16
Description: Live Log Stream and ClickHouse Query Explorer with real-time SSE, JSON packet inspection, and AI log analysis.
*/

"use client";

import React, { useCallback, useEffect, useState } from "react";
import {
  Bot,
  Code2,
  Filter,
  Pause,
  Play,
  RefreshCw,
  Search,
  Send,
  Sparkles,
  Terminal,
} from "lucide-react";
import { SeverityBadge } from "./CommandCenterView";
import type { SecurityEvent, ThreatAnalysisReport } from "@/types/siem";

interface LiveLogExplorerViewProps {
  apiBaseUrl: string;
  liveStreamEnabled: boolean;
  onToggleLiveStream: () => void;
  liveIncomingEvents: SecurityEvent[];
  onRefreshGlobalStats: () => void;
}

export default function LiveLogExplorerView({
  apiBaseUrl,
  liveStreamEnabled,
  onToggleLiveStream,
  liveIncomingEvents,
  onRefreshGlobalStats,
}: LiveLogExplorerViewProps) {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [protocolFilter, setProtocolFilter] = useState<string>("");
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);

  // Ad-hoc log injector & AI inspector state
  const [customLogLine, setCustomLogLine] = useState<string>(
    "<34>Nov 16 20:30:00 prod-db-01 sshd[8821]: Failed password for invalid user postgres from 185.220.101.77 port 49122 ssh2"
  );
  const [aiReport, setAiReport] = useState<ThreatAnalysisReport | null>(null);
  const [aiLoading, setAiLoading] = useState<boolean>(false);
  const [ingestLoading, setIngestLoading] = useState<boolean>(false);

  const queryClickHouseEvents = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      params.set("limit", "100");
      if (searchQuery.trim()) params.set("search", searchQuery.trim());
      if (severityFilter) params.set("severity", severityFilter);
      if (protocolFilter) params.set("protocol", protocolFilter);

      const res = await fetch(`${apiBaseUrl}/api/v1/events?${params.toString()}`, {
        cache: "no-store",
      });
      if (res.ok) {
        const data = await res.json();
        const fetched: SecurityEvent[] = data.events ?? [];
        setEvents(fetched);
        if (fetched.length > 0 && !selectedEvent) {
          setSelectedEvent(fetched[0]);
        }
      }
    } finally {
      setLoading(false);
    }
  }, [apiBaseUrl, protocolFilter, searchQuery, selectedEvent, severityFilter]);

  useEffect(() => {
    void queryClickHouseEvents();
  }, [queryClickHouseEvents]);

  // Prepend incoming SSE events when live stream is active and matches filters
  useEffect(() => {
    if (!liveStreamEnabled || liveIncomingEvents.length === 0) return;
    const latest = liveIncomingEvents[0];
    if (!latest) return;

    if (severityFilter && latest.severity !== severityFilter) return;
    if (protocolFilter && latest.source_protocol !== protocolFilter) return;
    if (
      searchQuery.trim() &&
      !`${latest.message} ${latest.source_ip} ${latest.host} ${latest.service}`
        .toLowerCase()
        .includes(searchQuery.trim().toLowerCase())
    ) {
      return;
    }

    setEvents((prev) => {
      if (prev.some((e) => e.event_id === latest.event_id)) return prev;
      return [latest, ...prev].slice(0, 150);
    });
  }, [liveIncomingEvents, liveStreamEnabled, protocolFilter, searchQuery, severityFilter]);

  const handleAnalyzeLogLine = async (logText: string) => {
    if (!logText.trim()) return;
    setAiLoading(true);
    try {
      const res = await fetch(`${apiBaseUrl}/api/v1/ai/analyze-log`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ log_line: logText }),
      });
      if (res.ok) {
        const report: ThreatAnalysisReport = await res.json();
        setAiReport(report);
      }
    } finally {
      setAiLoading(false);
    }
  };

  const handleIngestCustomLog = async () => {
    if (!customLogLine.trim()) return;
    setIngestLoading(true);
    try {
      const res = await fetch(`${apiBaseUrl}/api/v1/ingest/webhook`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          host: "soc-manual-injector",
          service: "manual-test",
          message: customLogLine.trim(),
          raw_payload: customLogLine.trim(),
        }),
      });
      if (res.ok) {
        await queryClickHouseEvents();
        onRefreshGlobalStats();
      }
    } finally {
      setIngestLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Query Explorer & Filter Controls */}
      <section
        aria-label="ClickHouse Telemetry Query Filter Bar"
        className="doom-card bg-doom-panel border border-doom-border rounded p-4 space-y-4"
      >
        <div className="grid grid-cols-1 md:grid-cols-12 gap-3 items-end">
          <div className="md:col-span-5 space-y-1">
            <label
              htmlFor="log-search-input"
              className="block font-mono text-[11px] uppercase tracking-wider text-zinc-400"
            >
              CLICKHOUSE SUB-SECOND FULL-TEXT SEARCH
            </label>
            <div className="relative">
              <Search
                className="h-4 w-4 text-zinc-400 absolute left-3 top-2.5"
                aria-hidden="true"
              />
              <input
                id="log-search-input"
                type="search"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter by message, IP, host, service, or MITRE ID (e.g. T1190)..."
                className="w-full pl-9 pr-3 py-2 rounded bg-doom-obsidian border border-doom-border font-mono text-xs text-white placeholder:text-zinc-500"
              />
            </div>
          </div>

          <div className="md:col-span-2 space-y-1">
            <label
              htmlFor="log-severity-select"
              className="block font-mono text-[11px] uppercase tracking-wider text-zinc-400"
            >
              SEVERITY
            </label>
            <select
              id="log-severity-select"
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

          <div className="md:col-span-2 space-y-1">
            <label
              htmlFor="log-protocol-select"
              className="block font-mono text-[11px] uppercase tracking-wider text-zinc-400"
            >
              PROTOCOL
            </label>
            <select
              id="log-protocol-select"
              value={protocolFilter}
              onChange={(e) => setProtocolFilter(e.target.value)}
              className="w-full px-3 py-2 rounded bg-doom-obsidian border border-doom-border font-mono text-xs text-white"
            >
              <option value="">ALL PROTOCOLS</option>
              <option value="syslog_udp">SYSLOG UDP (:5514)</option>
              <option value="syslog_tcp">SYSLOG TCP (:5514)</option>
              <option value="http_webhook">HTTP WEBHOOK</option>
              <option value="agent_shipper">AGENT SHIPPER</option>
            </select>
          </div>

          <div className="md:col-span-3 flex items-center gap-2">
            <button
              type="button"
              onClick={() => void queryClickHouseEvents()}
              disabled={loading}
              className="flex-1 inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded bg-doom-elevated hover:bg-zinc-800 border border-doom-border font-mono text-xs text-white transition"
            >
              <RefreshCw
                className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`}
                aria-hidden="true"
              />
              <span>QUERY</span>
            </button>

            <button
              type="button"
              aria-pressed={liveStreamEnabled}
              onClick={onToggleLiveStream}
              className={`flex-1 inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded border font-mono text-xs font-semibold transition ${
                liveStreamEnabled
                  ? "bg-emerald-950/70 border-emerald-500/70 text-emerald-300"
                  : "bg-zinc-900 border-zinc-700 text-zinc-300"
              }`}
            >
              {liveStreamEnabled ? (
                <Pause className="h-3.5 w-3.5 text-emerald-400" aria-hidden="true" />
              ) : (
                <Play className="h-3.5 w-3.5 text-zinc-400" aria-hidden="true" />
              )}
              <span>{liveStreamEnabled ? "SSE LIVE" : "SSE PAUSED"}</span>
            </button>
          </div>
        </div>

        {/* Ad-Hoc Log Injector & Instant AI Log Analyzer */}
        <div className="pt-3 border-t border-doom-border/80 grid grid-cols-1 lg:grid-cols-12 gap-3 items-end">
          <div className="lg:col-span-8 space-y-1">
            <label
              htmlFor="adhoc-log-input"
              className="block font-mono text-[11px] uppercase tracking-wider text-amber-300"
            >
              LIVE LOG INJECTOR &amp; AD-HOC AI LOG ANALYZER (RFC 3164 / 5424 / JSON)
            </label>
            <input
              id="adhoc-log-input"
              type="text"
              value={customLogLine}
              onChange={(e) => setCustomLogLine(e.target.value)}
              className="w-full px-3 py-2 rounded bg-doom-obsidian border border-doom-border font-mono text-xs text-amber-200"
            />
          </div>

          <div className="lg:col-span-4 flex items-center gap-2">
            <button
              type="button"
              onClick={() => void handleIngestCustomLog()}
              disabled={ingestLoading}
              className="flex-1 inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded bg-doom-crimson hover:bg-rose-600 text-white font-mono text-xs font-semibold transition disabled:opacity-50"
            >
              <Send className="h-3.5 w-3.5" aria-hidden="true" />
              <span>{ingestLoading ? "INGESTING..." : "INGEST EVENT"}</span>
            </button>

            <button
              type="button"
              onClick={() => void handleAnalyzeLogLine(customLogLine)}
              disabled={aiLoading}
              className="flex-1 inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded bg-amber-600 hover:bg-amber-500 text-black font-mono text-xs font-bold transition disabled:opacity-50"
            >
              <Sparkles className="h-3.5 w-3.5" aria-hidden="true" />
              <span>{aiLoading ? "ANALYZING..." : "AI INSPECT LOG"}</span>
            </button>
          </div>
        </div>
      </section>

      {/* Main Split-Pane: Event Stream Table + Deep Packet / AI Inspector */}
      <section
        aria-label="Security Event Stream and Packet Inspector"
        className="grid grid-cols-1 lg:grid-cols-12 gap-5"
      >
        {/* Left Pane: Event Table */}
        <div className="lg:col-span-7 doom-card bg-doom-panel border border-doom-border rounded p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-doom-border pb-2">
            <h2
              id="event-stream-table-caption"
              className="font-mono text-xs font-bold uppercase tracking-wider text-zinc-200 flex items-center gap-2"
            >
              <Filter className="h-3.5 w-3.5 text-doom-crimson" aria-hidden="true" />
              <span>CLICKHOUSE TELEMETRY STREAM ({events.length} RECORDS)</span>
            </h2>
            <span className="font-mono text-[11px] text-zinc-400">
              Select a row to inspect packet
            </span>
          </div>

          <div
            tabIndex={0}
            role="region"
            aria-labelledby="event-stream-table-caption"
            className="table-wrapper max-h-[540px]"
          >
            <table className="text-left font-mono text-xs">
              <caption className="visually-hidden">
                Normalized security events from ClickHouse telemetry store
              </caption>
              <thead className="bg-doom-elevated text-zinc-400 border-b border-doom-border">
                <tr>
                  <th scope="col" className="py-2.5 px-3">
                    TIMESTAMP / HOST
                  </th>
                  <th scope="col" className="py-2.5 px-3">
                    SEVERITY
                  </th>
                  <th scope="col" className="py-2.5 px-3">
                    PROTOCOL
                  </th>
                  <th scope="col" className="py-2.5 px-3">
                    MITRE
                  </th>
                  <th scope="col" className="py-2.5 px-3">
                    MESSAGE
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-doom-border/60">
                {events.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-zinc-400">
                      No matching security events found.
                    </td>
                  </tr>
                ) : (
                  events.map((ev) => {
                    const isSelected = selectedEvent?.event_id === ev.event_id;
                    return (
                      <tr
                        key={ev.event_id}
                        onClick={() => setSelectedEvent(ev)}
                        className={`cursor-pointer transition ${
                          isSelected
                            ? "bg-doom-crimson/15 border-l-2 border-l-doom-crimson"
                            : "hover:bg-doom-elevated/60"
                        }`}
                      >
                        <th scope="row" className="py-2.5 px-3 font-normal">
                          <div className="text-[11px] text-zinc-400">
                            {ev.timestamp}
                          </div>
                          <div className="text-white font-semibold">{ev.host}</div>
                        </th>
                        <td className="py-2.5 px-3">
                          <SeverityBadge severity={ev.severity} />
                        </td>
                        <td className="py-2.5 px-3 uppercase text-zinc-300 text-[11px]">
                          {ev.source_protocol}
                        </td>
                        <td className="py-2.5 px-3 text-amber-300 font-semibold">
                          {ev.mitre_technique}
                        </td>
                        <td className="py-2.5 px-3 text-zinc-200 max-w-[260px] truncate">
                          {ev.message}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right Pane: Deep Packet JSON Inspector & AI Log Analysis Output */}
        <div className="lg:col-span-5 space-y-4">
          {/* Packet JSON Inspector */}
          <div className="doom-card bg-doom-panel border border-doom-border rounded p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-doom-border pb-2">
              <h2 className="font-mono text-xs font-bold uppercase tracking-wider text-zinc-200 flex items-center gap-2">
                <Code2 className="h-4 w-4 text-amber-400" aria-hidden="true" />
                <span>DEEP PACKET &amp; NORMALIZED JSON INSPECTOR</span>
              </h2>
              {selectedEvent && (
                <button
                  type="button"
                  onClick={() => void handleAnalyzeLogLine(selectedEvent.raw_payload || selectedEvent.message)}
                  disabled={aiLoading}
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/60 font-mono text-[11px] text-amber-300"
                >
                  <Bot className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>AI EXPLAIN PACKET</span>
                </button>
              )}
            </div>

            {selectedEvent ? (
              <div className="space-y-3 font-mono text-xs">
                <div className="grid grid-cols-2 gap-2 bg-doom-obsidian p-3 rounded border border-doom-border">
                  <div>
                    <span className="text-zinc-500 block text-[10px]">EVENT UUID</span>
                    <span className="text-zinc-200 break-all">{selectedEvent.event_id}</span>
                  </div>
                  <div>
                    <span className="text-zinc-500 block text-[10px]">SOURCE IP -&gt; HOST</span>
                    <span className="text-rose-300 font-semibold">
                      {selectedEvent.source_ip} -&gt; {selectedEvent.host}
                    </span>
                  </div>
                  <div>
                    <span className="text-zinc-500 block text-[10px]">MITRE ATT&amp;CK</span>
                    <span className="text-amber-300">
                      {selectedEvent.mitre_tactic} ({selectedEvent.mitre_technique})
                    </span>
                  </div>
                  <div>
                    <span className="text-zinc-500 block text-[10px]">SERVICE / PROTOCOL</span>
                    <span className="text-emerald-300">
                      {selectedEvent.service} [{selectedEvent.source_protocol}]
                    </span>
                  </div>
                </div>

                <div>
                  <div className="text-[11px] text-zinc-400 mb-1">RAW TELEMETRY FRAME:</div>
                  <pre className="p-3 rounded bg-doom-obsidian border border-doom-border text-zinc-200 overflow-x-auto whitespace-pre-wrap break-all text-[11px]">
                    {selectedEvent.raw_payload}
                  </pre>
                </div>

                <div>
                  <div className="text-[11px] text-zinc-400 mb-1">NORMALIZED CLICKHOUSE DOCUMENT:</div>
                  <pre className="p-3 rounded bg-doom-obsidian border border-doom-border text-emerald-300 overflow-x-auto text-[11px] max-h-48">
                    {JSON.stringify(selectedEvent, null, 2)}
                  </pre>
                </div>
              </div>
            ) : (
              <div className="py-12 text-center font-mono text-xs text-zinc-400">
                Select any telemetry event from the stream to inspect its normalized document and raw frame.
              </div>
            )}
          </div>

          {/* AI Log Analysis Panel */}
          {aiReport && (
            <div className="doom-card bg-doom-panel border border-amber-500/60 rounded p-4 space-y-3">
              <div className="flex items-center justify-between border-b border-doom-border pb-2">
                <div className="flex items-center gap-2 font-mono text-xs font-bold text-amber-300">
                  <Terminal className="h-4 w-4 text-amber-400" aria-hidden="true" />
                  <span>DOOM AI LOG ANALYSIS ({aiReport.model})</span>
                </div>
                <span className="px-2 py-0.5 rounded bg-rose-950 border border-rose-600 text-rose-300 font-mono text-xs font-bold">
                  RISK: {aiReport.risk_score}/100
                </span>
              </div>

              <div className="space-y-2 font-mono text-xs">
                <p className="text-zinc-200 leading-relaxed">
                  {aiReport.executive_summary}
                </p>
                <div className="p-2.5 rounded bg-doom-obsidian border border-doom-border text-zinc-300">
                  <strong className="text-amber-300 block mb-1">ROOT CAUSE:</strong>
                  {aiReport.root_cause_analysis}
                </div>
                <div className="space-y-1">
                  <strong className="text-emerald-400 block">
                    CONTAINMENT PLAYBOOK:
                  </strong>
                  <ul className="list-disc list-inside space-y-1 text-zinc-300">
                    {aiReport.remediation_playbook.map((step) => (
                      <li key={step}>{step}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
