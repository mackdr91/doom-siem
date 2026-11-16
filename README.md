<!--
Author: Domonick Mack
Date: 2026-11-16
Description: Project documentation, architecture overview, and environment setup guide for Doom SIEM.
-->

# DOOM // Next-Gen Security Information & Event Management (SIEM)

**Doom** is a high-throughput, real-time Security Information and Event Management (SIEM) platform engineered with a **"Doom SOC" Dark Ops** interface, multi-protocol log ingestion (Syslog UDP/TCP, HTTP/Webhooks, and Agent Log Shipping), MITRE ATT&CK detection & incident triage workflows, and AI-assisted threat analysis.

---

## Architecture & Tech Stack

| Layer | Technology | Role in Doom SIEM |
| :--- | :--- | :--- |
| **Ingestion & Detection Engine** | **Go 1.23+** | Concurrent UDP/TCP Syslog collectors, HTTP/Webhook log receivers, Redis stream processors, MITRE ATT&CK rule evaluation engine, and REST/SSE APIs. |
| **SOC Command Dashboard** | **Next.js 15 (TypeScript / React 19 / Tailwind CSS)** | "Doom SOC" Dark Ops UI featuring pitch-black obsidian surfaces, crimson & amber threat accents, high-density monospace telemetry panels, and real-time event streaming. |
| **Columnar Telemetry Store** | **ClickHouse** | High-speed OLAP storage for raw and normalized security logs, sub-second search queries, and time-series threat velocity aggregations. |
| **Relational State Store** | **PostgreSQL 16** | ACID storage for alert queues, incident triage workflows, MITRE ATT&CK rule configurations, ingestion API keys, and AI threat summaries. |
| **Event Streaming & Pub/Sub** | **Redis 7** | High-throughput ingestion decoupling (`Redis Streams`) and real-time live log fan-out to connected SOC analysts. |
| **Containerization & Cloud** | **Docker Compose & Railway** | Reproducible local multi-container environment and cloud-native service deployment on Railway. |

---

## Project Roadmap & Phases

- **Phase 1: Environment, Repository, Containerization & CI/CD Setup (Current)**
  - Git repository initialization & GitHub remote (`mackdr91/doom-siem`).
  - Multi-service `docker-compose.yml` (Go Engine, Next.js SOC UI, ClickHouse, PostgreSQL, Redis) with automated schema bootstrap and health verification.
  - GitHub Actions CI/CD pipeline (`.github/workflows/ci.yml`) for Go & Next.js linting, testing, and build validation.
  - Railway deployment readiness (`railway.json`).
- **Phase 2: Multi-Protocol Log Ingestion & Telemetry Pipeline**
  - Syslog (UDP/TCP RFC 3164/5424), HTTP/Webhook batch ingestion, and file/agent log shipper endpoints.
  - Redis Streams buffering and ClickHouse columnar batch writer with live SSE streaming.
- **Phase 3: MITRE ATT&CK Detection Engine & Alert Triage Workflow**
  - Real-time correlation engine mapping events to MITRE ATT&CK tactics/techniques, generating prioritized alerts and incident queues in PostgreSQL.
- **Phase 4: AI-Assisted Threat Analysis & Summarization**
  - Automated log anomaly explanation, root-cause summarization, and remediation playbooks.
- **Phase 5: "Doom SOC" Dark Ops Dashboard Modules**
  - Command Center Overview (KPIs, threat velocity chart, severity breakdown, top attackers), Live Log Stream & Query Explorer, and Alerts & Incident Triage Queue.

---

## Quick Start (Local Docker Environment)

### Prerequisites
- Docker & Docker Compose v2+
- Go 1.23+ (optional for host tooling)
- Node.js 20+ (optional for host tooling)

### 1. Configure Environment Variables
Copy the example environment file:
```bash
cp .env.example .env
```

### 2. Launch the Full Stack
```bash
docker compose up --build -d
```

### 3. Service Endpoints
- **Doom SOC Dashboard (Next.js)**: [http://localhost:3000](http://localhost:3000)
- **Doom Engine API & Health (Go)**: [http://localhost:8080/api/v1/health](http://localhost:8080/api/v1/health)
- **ClickHouse HTTP Interface**: `http://localhost:8123`
- **PostgreSQL**: `localhost:5432`
- **Redis**: `localhost:6379`
