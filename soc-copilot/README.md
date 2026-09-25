# SOC Copilot

[![tests](https://github.com/[your-github-username]/soc-copilot/actions/workflows/ci.yml/badge.svg)](https://github.com/[your-github-username]/soc-copilot/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

An AI-assisted alert triage pipeline for SOC teams. It ingests alerts from
Wazuh (and any generic JSON webhook), extracts indicators of compromise,
enriches them with VirusTotal, correlates related events into a timeline,
persists everything to Postgres, and generates a Markdown incident report
grounded in the evidence.

## Why

Tier 1 triage is repetitive. Analysts spend most of their time reading the
same alert shapes, looking up the same IPs, and writing the same reports.
SOC Copilot handles that first pass so humans can focus on investigations.

## Architecture

```
Wazuh / generic webhook
        │
        ▼
   FastAPI /ingest  ──►  parser  ──►  enrichment  ──►  Postgres  ──►  LLM report
```

## Quickstart

```bash
git clone https://github.com/[your-github-username]/soc-copilot.git
cd soc-copilot
cp .env.example .env
docker compose up --build
```

This starts four containers: `api`, `worker`, `postgres`, and `redis`. The
API enqueues alerts; the worker is what actually processes them, so both
need to be running.

Apply the database migration once the containers are up:

```bash
docker compose exec api alembic revision --autogenerate -m "create alerts and indicators tables"
docker compose exec api alembic upgrade head
```

Then, in another terminal, fire a simulated attack:

```bash
python demo/generate_alerts.py
```

Check what got stored:

```bash
curl http://localhost:8000/api/v1/alerts | python -m json.tool
```

## What's implemented

- Wazuh, Suricata, Zeek, and generic JSON parsers with a shared canonical schema
- IOC extraction (IPv4, MD5, SHA256, domains) with private-range filtering
- Async VirusTotal enrichment with fail-open error handling
- Postgres persistence for alerts and their indicators, via SQLAlchemy + Alembic
- Redis-backed job queue (RQ): the API enqueues and returns immediately, a
  separate `worker` process does enrichment, persistence, and notification,
  so an in-flight alert survives an API restart
- Slack notification for high/critical alerts, skipped entirely if no
  webhook URL is configured
- Correlation of alerts sharing a host/IP/user within a time window
- LLM-generated incident reports with a deterministic fallback
- Tests for parsers, IOC extraction, and Slack message formatting

## What's next

- RAG over runbooks (pgvector is already in the compose file)
- Persist grouped incidents, not just individual alerts
- A retry/backoff policy for failed RQ jobs (they currently land in the
  failed job registry and wait for a manual `rq requeue`)

## Stack

FastAPI · Pydantic v2 · httpx · structlog · PostgreSQL + pgvector · SQLAlchemy
(async) · Alembic · Redis · RQ · Docker Compose · pytest

## Running tests

```bash
cd backend
pip install -r requirements.txt
pytest
```

## License

MIT — see [LICENSE](LICENSE).
