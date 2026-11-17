/*
Author: Domonick Mack
Date: 2026-11-17
Description: NIST NVD CPE 2.3 Asset & Platform Intelligence lookup view for Doom SIEM.
*/

"use client";

import React, { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  Copy,
  Database,
  ExternalLink,
  PackageSearch,
  RefreshCw,
  Search,
  XCircle,
} from "lucide-react";
import type { CPERecord, CPESearchResponse } from "@/types/siem";

interface CpeLookupViewProps {
  apiBaseUrl: string;
}

const PRESET_KEYWORDS = [
  "openssh",
  "nginx",
  "postgresql",
  "kubernetes",
  "log4j",
  "openssl",
];

export default function CpeLookupView({ apiBaseUrl }: CpeLookupViewProps) {
  const [keyword, setKeyword] = useState<string>("openssh");
  const [cpeMatch, setCpeMatch] = useState<string>("");
  const [includeDeprecated, setIncludeDeprecated] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [result, setResult] = useState<CPESearchResponse | null>(null);
  const [selectedCpe, setSelectedCpe] = useState<CPERecord | null>(null);
  const [copiedUri, setCopiedUri] = useState<string | null>(null);

  const executeLookup = useCallback(
    async (overrideKeyword?: string) => {
      const kw = (overrideKeyword ?? keyword).trim();
      const match = cpeMatch.trim();
      if (!kw && !match) {
        setErrorMessage("Enter a keyword or CPE 2.3 match string to search.");
        return;
      }

      setLoading(true);
      setErrorMessage(null);
      try {
        const params = new URLSearchParams();
        params.set("limit", "25");
        if (kw) params.set("keyword", kw);
        if (match) params.set("cpe_match", match);
        if (includeDeprecated) params.set("include_deprecated", "true");

        const res = await fetch(
          `${apiBaseUrl}/api/v1/intel/cpes?${params.toString()}`,
          { cache: "no-store" }
        );
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.error || `NVD CPE lookup failed (HTTP ${res.status})`);
        }
        const payload = data as CPESearchResponse;
        setResult(payload);
        setSelectedCpe(payload.cpes?.[0] ?? null);
      } catch (err) {
        setErrorMessage(
          err instanceof Error ? err.message : "Failed to query NVD CPE API"
        );
      } finally {
        setLoading(false);
      }
    },
    [apiBaseUrl, cpeMatch, includeDeprecated, keyword]
  );

  useEffect(() => {
    void executeLookup("openssh");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    void executeLookup();
  };

  const handleCopyUri = async (uri: string) => {
    try {
      await navigator.clipboard.writeText(uri);
      setCopiedUri(uri);
      setTimeout(() => setCopiedUri(null), 2000);
    } catch {
      // Clipboard API unavailable
    }
  };

  return (
    <div className="space-y-6">
      {/* Search & Quick Presets */}
      <section
        aria-label="NIST NVD CPE 2.3 Search Bar"
        className="doom-card bg-doom-panel border border-doom-border rounded p-4 space-y-4"
      >
        <form
          onSubmit={handleSubmit}
          className="grid grid-cols-1 md:grid-cols-12 gap-3 items-end"
        >
          <div className="md:col-span-5 space-y-1">
            <label
              htmlFor="cpe-keyword-input"
              className="block font-mono text-[11px] uppercase tracking-wider text-zinc-400"
            >
              PLATFORM / VENDOR / PRODUCT KEYWORD
            </label>
            <div className="relative">
              <Search
                className="h-4 w-4 text-zinc-400 absolute left-3 top-2.5"
                aria-hidden="true"
              />
              <input
                id="cpe-keyword-input"
                type="search"
                value={keyword}
                onChange={(e) => setKeyword(e.target.value)}
                placeholder="e.g. openssh, nginx, postgresql, log4j..."
                className="w-full pl-9 pr-3 py-2 rounded bg-doom-obsidian border border-doom-border font-mono text-xs text-white placeholder:text-zinc-500"
              />
            </div>
          </div>

          <div className="md:col-span-4 space-y-1">
            <label
              htmlFor="cpe-match-input"
              className="block font-mono text-[11px] uppercase tracking-wider text-zinc-400"
            >
              OPTIONAL CPE 2.3 MATCH URI
            </label>
            <input
              id="cpe-match-input"
              type="text"
              value={cpeMatch}
              onChange={(e) => setCpeMatch(e.target.value)}
              placeholder="cpe:2.3:a:openbsd:openssh:*"
              className="w-full px-3 py-2 rounded bg-doom-obsidian border border-doom-border font-mono text-xs text-amber-200 placeholder:text-zinc-500"
            />
          </div>

          <div className="md:col-span-3 flex items-center gap-2">
            <button
              type="submit"
              disabled={loading}
              className="flex-1 inline-flex items-center justify-center gap-1.5 px-3.5 py-2 rounded bg-doom-crimson hover:bg-rose-600 text-white font-mono text-xs font-bold transition disabled:opacity-50"
            >
              <RefreshCw
                className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`}
                aria-hidden="true"
              />
              <span>{loading ? "QUERYING NVD..." : "LOOKUP CPEs"}</span>
            </button>
          </div>
        </form>

        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-doom-border/80">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[11px] text-zinc-400">
              QUICK PRESETS:
            </span>
            {PRESET_KEYWORDS.map((preset) => (
              <button
                key={preset}
                type="button"
                onClick={() => {
                  setKeyword(preset);
                  setCpeMatch("");
                  void executeLookup(preset);
                }}
                className={`px-2.5 py-1 rounded font-mono text-[11px] border transition ${
                  keyword.toLowerCase() === preset
                    ? "bg-doom-crimson/20 border-doom-crimson text-rose-300"
                    : "bg-doom-obsidian border-doom-border text-zinc-300 hover:text-white"
                }`}
              >
                {preset}
              </button>
            ))}
          </div>

          <label className="inline-flex items-center gap-2 font-mono text-xs text-zinc-300 cursor-pointer">
            <input
              type="checkbox"
              checked={includeDeprecated}
              onChange={(e) => setIncludeDeprecated(e.target.checked)}
              className="rounded border-doom-border bg-doom-obsidian"
            />
            <span>Include deprecated CPEs</span>
          </label>
        </div>
      </section>

      {errorMessage && (
        <div
          role="alert"
          className="doom-card rounded border border-rose-600 bg-rose-950/40 p-4 flex items-start gap-3 text-rose-200 font-mono text-xs"
        >
          <XCircle
            className="h-5 w-5 text-rose-400 shrink-0 mt-0.5"
            aria-hidden="true"
          />
          <div>
            <strong className="block text-rose-300">
              NVD CPE LOOKUP ERROR
            </strong>
            <span>{errorMessage}</span>
          </div>
        </div>
      )}

      {/* Split-Pane Results Table & Inspector */}
      <section
        aria-label="CPE Dictionary Results and Inspector"
        className="grid grid-cols-1 lg:grid-cols-12 gap-5"
      >
        {/* Left Pane: CPE Table */}
        <div className="lg:col-span-8 doom-card bg-doom-panel border border-doom-border rounded p-4 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-doom-border pb-2">
            <h2
              id="cpe-results-caption"
              className="font-mono text-xs font-bold uppercase tracking-wider text-zinc-200 flex items-center gap-2"
            >
              <PackageSearch
                className="h-4 w-4 text-doom-crimson"
                aria-hidden="true"
              />
              <span>
                NVD CPE 2.3 DICTIONARY ({result?.cpes.length ?? 0} SHOWN /{" "}
                {result?.total_results.toLocaleString() ?? 0} TOTAL)
              </span>
            </h2>
            {result && (
              <span className="font-mono text-[11px] text-zinc-400">
                Source: {result.source} {result.cached ? "(Cached)" : "(Live)"}
              </span>
            )}
          </div>

          <div
            tabIndex={0}
            role="region"
            aria-labelledby="cpe-results-caption"
            className="table-wrapper max-h-[560px]"
          >
            <table className="text-left font-mono text-xs">
              <caption className="visually-hidden">
                Latest Common Platform Enumeration records from NIST NVD
              </caption>
              <thead className="bg-doom-elevated text-zinc-400 border-b border-doom-border">
                <tr>
                  <th scope="col" className="py-2.5 px-3">
                    TITLE / CPE 2.3 URI
                  </th>
                  <th scope="col" className="py-2.5 px-3">
                    VENDOR / PRODUCT
                  </th>
                  <th scope="col" className="py-2.5 px-3">
                    VERSION
                  </th>
                  <th scope="col" className="py-2.5 px-3">
                    STATUS
                  </th>
                  <th scope="col" className="py-2.5 px-3">
                    MODIFIED
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-doom-border/60">
                {!result || result.cpes.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-zinc-400">
                      {loading
                        ? "Querying NIST NVD CPE API v2.0..."
                        : "No matching CPE 2.3 entries found."}
                    </td>
                  </tr>
                ) : (
                  result.cpes.map((cpe) => {
                    const isSelected = selectedCpe?.cpe_name_id === cpe.cpe_name_id;
                    return (
                      <tr
                        key={cpe.cpe_name_id}
                        onClick={() => setSelectedCpe(cpe)}
                        className={`cursor-pointer transition ${
                          isSelected
                            ? "bg-doom-crimson/15 border-l-2 border-l-doom-crimson"
                            : "hover:bg-doom-elevated/60"
                        }`}
                      >
                        <th scope="row" className="py-2.5 px-3 font-normal">
                          <div className="text-white font-semibold max-w-[280px] truncate">
                            {cpe.title}
                          </div>
                          <div className="text-[11px] text-amber-300 max-w-[280px] truncate">
                            {cpe.cpe_name}
                          </div>
                        </th>
                        <td className="py-2.5 px-3 text-zinc-200">
                          <div>{cpe.vendor}</div>
                          <div className="text-[11px] text-zinc-400">
                            {cpe.product}
                          </div>
                        </td>
                        <td className="py-2.5 px-3 text-emerald-300 font-semibold">
                          {cpe.version}
                        </td>
                        <td className="py-2.5 px-3">
                          {cpe.deprecated ? (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] uppercase bg-amber-950/70 text-amber-300 border border-amber-500/60">
                              <AlertTriangle className="h-3 w-3" aria-hidden="true" />
                              <span>DEPRECATED</span>
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] uppercase bg-emerald-950/70 text-emerald-300 border border-emerald-600/60">
                              <CheckCircle2 className="h-3 w-3" aria-hidden="true" />
                              <span>ACTIVE</span>
                            </span>
                          )}
                        </td>
                        <td className="py-2.5 px-3 text-zinc-400 text-[11px]">
                          {cpe.last_modified.slice(0, 10)}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right Pane: Selected CPE Detail & References */}
        <div className="lg:col-span-4 doom-card bg-doom-panel border border-doom-border rounded p-4 space-y-4">
          <div className="flex items-center justify-between border-b border-doom-border pb-2">
            <h2 className="font-mono text-xs font-bold uppercase tracking-wider text-zinc-200 flex items-center gap-2">
              <Database className="h-4 w-4 text-amber-400" aria-hidden="true" />
              <span>CPE 2.3 ASSET DOSSIER</span>
            </h2>
          </div>

          {selectedCpe ? (
            <div className="space-y-4 font-mono text-xs">
              <div>
                <div className="text-[11px] text-zinc-400">CANONICAL TITLE</div>
                <div className="text-sm font-bold text-white mt-0.5">
                  {selectedCpe.title}
                </div>
              </div>

              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] text-zinc-400">
                    CPE 2.3 FORMATTED URI
                  </span>
                  <button
                    type="button"
                    onClick={() => void handleCopyUri(selectedCpe.cpe_name)}
                    className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-doom-elevated border border-doom-border text-[11px] text-zinc-200 hover:text-white"
                  >
                    {copiedUri === selectedCpe.cpe_name ? (
                      <>
                        <Check className="h-3 w-3 text-emerald-400" aria-hidden="true" />
                        <span>COPIED</span>
                      </>
                    ) : (
                      <>
                        <Copy className="h-3 w-3" aria-hidden="true" />
                        <span>COPY</span>
                      </>
                    )}
                  </button>
                </div>
                <pre className="p-2.5 rounded bg-doom-obsidian border border-doom-border text-amber-300 break-all whitespace-pre-wrap text-[11px]">
                  {selectedCpe.cpe_name}
                </pre>
              </div>

              <div className="grid grid-cols-2 gap-2.5 bg-doom-obsidian p-3 rounded border border-doom-border">
                <div>
                  <span className="text-zinc-500 block text-[10px]">VENDOR</span>
                  <span className="text-white font-semibold">
                    {selectedCpe.vendor}
                  </span>
                </div>
                <div>
                  <span className="text-zinc-500 block text-[10px]">PRODUCT</span>
                  <span className="text-white font-semibold">
                    {selectedCpe.product}
                  </span>
                </div>
                <div>
                  <span className="text-zinc-500 block text-[10px]">VERSION</span>
                  <span className="text-emerald-300 font-bold">
                    {selectedCpe.version}
                  </span>
                </div>
                <div>
                  <span className="text-zinc-500 block text-[10px]">NVD UUID</span>
                  <span className="text-zinc-300 break-all text-[10px]">
                    {selectedCpe.cpe_name_id}
                  </span>
                </div>
              </div>

              <div className="space-y-1.5">
                <div className="text-[11px] text-zinc-400">
                  EXTERNAL REFERENCES ({selectedCpe.refs?.length ?? 0})
                </div>
                {selectedCpe.refs && selectedCpe.refs.length > 0 ? (
                  <ul className="space-y-1.5 max-h-48 overflow-y-auto">
                    {selectedCpe.refs.map((r) => (
                      <li
                        key={r.ref}
                        className="p-2 rounded bg-doom-obsidian border border-doom-border flex items-center justify-between gap-2"
                      >
                        <a
                          href={r.ref}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-rose-300 hover:text-rose-200 underline truncate text-[11px]"
                        >
                          {r.ref}
                        </a>
                        <ExternalLink
                          className="h-3.5 w-3.5 text-zinc-400 shrink-0"
                          aria-hidden="true"
                        />
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-zinc-500 text-[11px]">
                    No external vendor references listed.
                  </p>
                )}
              </div>
            </div>
          ) : (
            <div className="py-12 text-center font-mono text-xs text-zinc-400">
              Select any CPE 2.3 row to inspect its canonical metadata and references.
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
