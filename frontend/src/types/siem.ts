/*
Author: Domonick Mack
Date: 2026-11-16
Description: TypeScript domain interfaces for Doom SIEM telemetry, alerts, MITRE ATT&CK rules, and AI threat analysis.
*/

export type ActiveSocModule = "command-center" | "live-logs" | "alerts-triage";

export interface DependencyStatus {
  name: string;
  role: string;
  status: string;
  latency_ms: number;
  details: string;
}

export interface IngestionBindings {
  syslog_udp_port: number;
  syslog_tcp_port: number;
  http_webhook_path: string;
  agent_shipper_path: string;
}

export interface SystemHealthReport {
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

export interface SecurityEvent {
  event_id: string;
  timestamp: string;
  source_protocol: string;
  severity: string;
  host: string;
  source_ip: string;
  destination_ip: string;
  service: string;
  mitre_tactic: string;
  mitre_technique: string;
  message: string;
  raw_payload: string;
}

export interface BucketCount {
  key: string;
  count: number;
}

export interface TelemetryStats {
  total_events: number;
  stream_queue_depth: number;
  by_severity: BucketCount[];
  by_protocol: BucketCount[];
  top_source_ips: BucketCount[];
  top_hosts: BucketCount[];
  last_updated_at_utc: string;
}

export interface DetectionRule {
  id: string;
  rule_code: string;
  title: string;
  description: string;
  severity: string;
  mitre_tactic: string;
  mitre_technique_id: string;
  match_keywords: string;
  source_protocol_filter: string;
  enabled: boolean;
  created_at: string;
}

export interface SecurityAlert {
  id: string;
  rule_id?: string;
  rule_code: string;
  title: string;
  severity: string;
  status: string;
  mitre_tactic: string;
  mitre_technique_id: string;
  event_id: string;
  source_protocol: string;
  source_ip: string;
  target_host: string;
  service: string;
  matched_excerpt: string;
  raw_event_json: string;
  ai_summary?: string;
  assignee: string;
  notes: string;
  triggered_at: string;
  updated_at: string;
}

export interface AlertSummaryStats {
  total_alerts: number;
  open_alerts: number;
  investigating_alerts: number;
  resolved_alerts: number;
  false_positive_alerts: number;
  critical_alerts: number;
  active_rules_count: number;
  by_severity: BucketCount[];
  by_status: BucketCount[];
  by_mitre_tactic: BucketCount[];
}

export interface ThreatAnalysisReport {
  alert_id?: string;
  engine: string;
  model: string;
  risk_score: number;
  executive_summary: string;
  root_cause_analysis: string;
  mitre_context: string;
  indicators: string[];
  remediation_playbook: string[];
  formatted_markdown: string;
  generated_at_utc: string;
}
