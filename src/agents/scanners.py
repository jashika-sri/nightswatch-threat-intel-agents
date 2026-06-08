from google.adk import Agent
from src.skills.event_skills import query_tenant_events, append_to_state

# Define the PII exposure scanner agent using google-adk
pii_exposure_scanner = Agent(
    name="pii_exposure_scanner",
    description="Scans events across tenants for PII exposure patterns (credit card data leaking into completions)",
    model="gemini-2.5-flash",
    instruction=(
        "Query events across the given tenants for the [REDACTED-CC] marker. "
        "Group findings by tenant. Compute:\n"
        "  - pattern_signature: '[REDACTED-CC]'\n"
        "  - affected_tenants: list of affected tenant IDs\n"
        "  - distinct_users: list of all unique user_ids (strings) across all matching events\n"
        "  - events_per_tenant: a dictionary mapping each affected tenant_id to its event count\n"
        "Write the finding via append_to_state with key='scanner_results_pii'."
    ),
    tools=[query_tenant_events, append_to_state]
)

# Define the Prompt Injection scanner agent using google-adk
prompt_injection_scanner = Agent(
    name="prompt_injection_scanner",
    model="gemini-2.5-flash",
    description="Scans tenant events for prompt injection attempts",

    instruction='''Query events across the given tenants for the marker "[INJECTION-ATTEMPT]".
Use query_tenant_events with marker="[INJECTION-ATTEMPT]".
Group findings by tenant. Compute:
  - tenant_count (distinct tenants with matches)
  - distinct_users_count (distinct user_ids across all matches)
  - min_events_per_tenant (minimum events count across affected tenants)
Build a finding dict with category="prompt_injection", 
signature="prompt_injection_attempt", marker_detected="[INJECTION-ATTEMPT]",
plus the counts.
Write the finding via append_to_state with key="scanner_results_inj".''',
    tools=[query_tenant_events, append_to_state]
)
