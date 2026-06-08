import logging
from typing import Any
from google.adk import Context
from google.adk.tools import FunctionTool
from src.db.synthetic_tenants import SessionLocal, Event

logger = logging.getLogger("pii_exposure_scanner")

def adk_skill(func):
    """
    Decorator that wraps a Python function into an ADK FunctionTool.
    """
    return FunctionTool(func)

@adk_skill
def query_tenant_events(tenant_ids: list[str], marker: str) -> list[dict]:
    """
    Queries the SQLite Event table for events matching the specified marker across the given tenants.

    Args:
        tenant_ids: A list of tenant IDs to query.
        marker: The text marker to find in prompts or completions (e.g. "[REDACTED-CC]").

    Returns:
        A list of dictionaries containing tenant_id, user_id, event_id, model, and timestamp.
    """
    logger.info(f"Executing query_tenant_events for tenants {tenant_ids} with marker '{marker}'")
    
    db = SessionLocal()
    try:
        # Match marker in either prompt_redacted or completion_redacted
        results = db.query(Event).filter(
            Event.tenant_id.in_(tenant_ids),
            (Event.completion_redacted.like(f"%{marker}%") | Event.prompt_redacted.like(f"%{marker}%"))
        ).all()
        
        events_list = []
        for e in results:
            events_list.append({
                "tenant_id": e.tenant_id,
                "user_id": e.user_id,
                "event_id": e.id,
                "model": e.model,
                "timestamp": e.timestamp.isoformat()
            })
            
        logger.info(f"Query found {len(events_list)} events matching '{marker}' across tenants {tenant_ids}")
        return events_list
    except Exception as ex:
        logger.error(f"Error querying tenant events: {ex}")
        raise ex
    finally:
        db.close()

@adk_skill
def append_to_state(key: str, value: dict, tool_context: Context) -> None:
    """
    Appends a value to the session state under the given key, initializing it as an empty list if missing.
    Supports nested paths like 'scanner_results.pii_exposure'.

    Args:
        key: The state key (supports dotted path notation, e.g. 'scanner_results.pii_exposure').
        value: The dictionary value to append.
        tool_context: The ADK context object containing session state.
    """

    state = tool_context.state
    
    # Split dotted or slashed paths to handle nesting
    if "." in key:
        parts = key.split(".")
    elif "/" in key:
        parts = key.split("/")
    else:
        parts = [key]
        
    # Implicitly map 'scanner_results' with a dict containing 'pii_exposure' if passed
    if len(parts) == 1 and parts[0] == "scanner_results":
        if isinstance(value, dict) and "pii_exposure" in value:
            parts = ["scanner_results", "pii_exposure"]
            value = value["pii_exposure"]
            
    # Traversal to target nested container
    curr = state
    for part in parts[:-1]:
        if part not in curr or not isinstance(curr[part], dict):
            curr[part] = {}
        curr = curr[part]
        
    last_key = parts[-1]
    if last_key not in curr or not isinstance(curr[last_key], list):
        curr[last_key] = []
        
    curr[last_key].append(value)
    
    # Explicitly write back the root key to trigger state delta changes
    state[parts[0]] = state[parts[0]]
    logger.info(f"Appended value to state under path: {parts}")
