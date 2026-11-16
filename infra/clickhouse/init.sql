-- Author: Domonick Mack
-- Date: 2026-11-16
-- Description: Initial ClickHouse columnar telemetry schema for Doom SIEM security event ingestion and queries.

CREATE DATABASE IF NOT EXISTS doom_telemetry;

CREATE TABLE IF NOT EXISTS doom_telemetry.security_events
(
    event_id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime64(3, 'UTC') DEFAULT now64(3),
    source_protocol LowCardinality(String),
    severity LowCardinality(String),
    host String,
    source_ip String,
    destination_ip String,
    service LowCardinality(String),
    mitre_tactic LowCardinality(String),
    mitre_technique LowCardinality(String),
    message String,
    raw_payload String
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, severity, source_protocol, host)
SETTINGS index_granularity = 8192;
