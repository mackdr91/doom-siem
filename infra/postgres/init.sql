-- Author: Domonick Mack
-- Date: 2026-11-16
-- Description: Initial PostgreSQL relational schema for Doom SIEM (ingestion sources, MITRE ATT&CK rules, and alert triage).

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Ingestion collectors and registered log shipping sources
CREATE TABLE IF NOT EXISTS ingestion_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(128) NOT NULL UNIQUE,
    protocol VARCHAR(32) NOT NULL CHECK (protocol IN ('syslog_udp', 'syslog_tcp', 'http_webhook', 'agent_shipper')),
    status VARCHAR(24) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'paused', 'error')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- MITRE ATT&CK aligned detection rules
CREATE TABLE IF NOT EXISTS detection_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_code VARCHAR(64) NOT NULL UNIQUE,
    title VARCHAR(255) NOT NULL,
    severity VARCHAR(24) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    mitre_tactic VARCHAR(128) NOT NULL,
    mitre_technique_id VARCHAR(32) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Security alerts and incident triage queue
CREATE TABLE IF NOT EXISTS security_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id UUID REFERENCES detection_rules(id) ON DELETE SET NULL,
    title VARCHAR(255) NOT NULL,
    severity VARCHAR(24) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status VARCHAR(32) NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'resolved', 'false_positive')),
    source_ip VARCHAR(64),
    target_host VARCHAR(128),
    ai_summary TEXT,
    triggered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed baseline ingestion collectors for environment verification
INSERT INTO ingestion_sources (name, protocol, status)
VALUES
    ('Core Syslog UDP Receiver (:5514)', 'syslog_udp', 'active'),
    ('Core Syslog TCP Receiver (:5514)', 'syslog_tcp', 'active'),
    ('HTTP Webhook Collector (/api/v1/ingest)', 'http_webhook', 'active'),
    ('Doom File & Endpoint Agent Shipper', 'agent_shipper', 'active')
ON CONFLICT (name) DO NOTHING;
