# Night's Watch Threat Intelligence Agents Backend

This repository contains the FastAPI backend project designed for cross-tenant LLM threat pattern detection, leveraging SQLite for local storage and `google-adk` for building agentic intelligence workflows.

## Tech Stack
- **Core**: Python 3.10+, FastAPI, Uvicorn
- **Storage**: SQLAlchemy + SQLite
- **Intelligence**: Google ADK (`google-adk[otel-gcp]==1.30.0`)
- **Transport**: `sse-starlette`
- **Deployment**: Docker / Google Cloud Run

---

## Getting Started

### Local Installation

1. Create a Python virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

2. Install dependencies:
   ```bash
   pip install --upgrade pip
   pip install -e .
   ```

### Running the Application

Start the local development server:
```bash
uvicorn src.main:app --reload --port 8000
```

On startup, the application automatically:
1. Creates the local SQLite database (`synthetic_tenants.db`).
2. Seeds **5 synthetic tenants** (FinPay, HealthCo, ShopFast, EduPlatform, DevTools Inc).
3. Seeds **Pattern A (credit_card_in_completion)** which passes k-anonymity (5 tenants, $\ge 11$ events/tenant, across 12 distinct users).
4. Seeds **Pattern B (prompt_injection_attempt)** which fails k-anonymity (seeded in only 3 tenants).
5. Seeds **15 random noise events** per tenant for realistic volume.

---

## API Endpoints

- `GET /` - Health check and status.
- `GET /tenants` - Lists all 5 tenants with their metrics (useful for the frontend selector).
- `POST /analyze` - A stub endpoint returning a canned JSON response matching the threat pattern schema (to be wired to real ADK agents next).

---

## Deployment (Cloud Run)

To build and deploy directly to Cloud Run:
```bash
gcloud run deploy nightswatch-threat-intel-backend \
  --source . \
  --platform managed \
  --allow-unauthenticated
```
The [Dockerfile](file:///Users/jashika/Documents/GitHub/nightswatch-threat-intel-agents/Dockerfile) is optimized for Cloud Run and dynamically binds to the `$PORT` environment variable.
