import os
from datetime import datetime
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

from src.db.synthetic_tenants import init_db, seed_data, SessionLocal, Tenant, Event


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite database and seed tenants/events
    init_db()
    seed_data()
    yield

app = FastAPI(
    title="Night's Watch Threat Intelligence Backend",
    description="FastAPI backend for cross-tenant LLM threat pattern detection",
    version="1.0.0",
    lifespan=lifespan
)

# CORS configuration for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/")
def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "nightswatch-threat-intel-backend"
    }

@app.get("/tenants")
def get_tenants(db: Session = Depends(get_db)):
    """
    Returns the list of all 5 synthetic tenants for the frontend selector.
    """
    tenants = db.query(Tenant).all()
    return tenants

import uuid
import time
import asyncio
import logging
from pydantic import BaseModel
from google.genai import types
from google.adk.runners import InMemoryRunner
from src.agents.orchestrator import orchestrator

logger = logging.getLogger("uvicorn.error")

class AnalyzeRequest(BaseModel):
    tenant_ids: list[str]

@app.post("/analyze")
async def analyze(request: AnalyzeRequest):
    """
    Runs the orchestrator sequential pipeline (parallel scanners -> k-anonymity validation)
    against the specified tenant IDs, returning agent traces, findings, and publication status.
    """
    max_retries = 3
    for attempt in range(max_retries):
        try:
            run_id = f"run_{uuid.uuid4().hex[:8]}"
            runner = InMemoryRunner(agent=orchestrator, app_name="threat_intel")
            
            agent_trace = []
            started_at = time.time()
            
            # Create the session and set the initial state
            session = await runner.session_service.create_session(
                app_name="threat_intel",
                user_id="api_user",
                session_id=run_id,
                state={
                    "tenant_ids": request.tenant_ids,
                    "scanner_results_pii": [],
                    "scanner_results_inj": [],
                    "published_patterns": [],
                    "blocked_patterns": [],
                    "enriched_patterns": []
                }
            )
            
            # Run the orchestrator pipeline
            async for event in runner.run_async(
                user_id="api_user",
                session_id=run_id,
                new_message=types.Content(
                    role="user",
                    parts=[types.Part(text=f"Scan these tenants: {request.tenant_ids}")]
                )
            ):
                if event.author:
                    agent_trace.append({
                        "agent": event.author,
                        "elapsed_ms": int((time.time() - started_at) * 1000)
                    })
                    
            # Retrieve the final session state after validation completes
            final = await runner.session_service.get_session(
                app_name="threat_intel",
                user_id="api_user",
                session_id=run_id
            )
            
            return {
                "run_id": run_id,
                "agent_trace": agent_trace,
                "scanner_results": {
                    "pii_exposure": final.state.get("scanner_results_pii", []),
                    "prompt_injection": final.state.get("scanner_results_inj", [])
                },
                "published_patterns": final.state.get("published_patterns", []),
                "blocked_patterns": final.state.get("blocked_patterns", []),
                "enriched_patterns": final.state.get("enriched_patterns", [])
            }
        except Exception as e:
            err_msg = str(e)
            if "429" in err_msg or "resource_exhausted" in err_msg or "rate limit" in err_msg.lower():
                if attempt < max_retries - 1:
                    sleep_time = 3 * (attempt + 1)
                    logger.warning(f"Rate limit / 429 hit during analyze. Retrying in {sleep_time}s... Error: {e}")
                    await asyncio.sleep(sleep_time)
                    continue
            raise e

