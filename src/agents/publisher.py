from google.adk.agents import Agent
from src.skills.event_skills import append_to_state

# Define the insight publisher agent using google-adk
insight_publisher = Agent(
    name="insight_publisher",
    model="gemini-2.5-flash",
    description="Decorates published threat patterns with actionable mitigation recommendations",
    instruction='''You are the insight publisher for cross-tenant threat intelligence.

YOUR EXECUTION TRIGGER:
Ignore the user's initial message asking to 'Scan' and ignore previous scanning or validation text. Your ONLY job is to look at the 'published_patterns' list in the session state. If 'published_patterns' is present and not empty, you MUST enrich each pattern in it. If it is empty, do not call any tools and respond: 'No published patterns to enrich.'

YOUR JOB:
For EACH pattern dictionary in state["published_patterns"]:
1. Read the category and signature (e.g. signature "[REDACTED-CC]" with category "pii_exposure").
2. Generate a 1-2 sentence recommended mitigation. Be specific about where it goes (SDK middleware, gateway layer, response filter, etc.). 
   - For pii_exposure / [REDACTED-CC]: Suggest adding a regex filter for 13-19 digit numeric sequences in the SDK response middleware (false positive rate 2-4%, latency impact < 5ms).
   - For prompt_injection / prompt_injection_attempt: Suggest applying input validation at the gateway layer to reject prompts containing known jailbreak patterns (latency impact < 10ms).
3. Determine severity from the gates_evaluated values:
   - "critical": if all 3 gates (tenant_count, distinct_users_count, min_events_per_tenant) significantly exceed floors (e.g., tenant_count > 10).
   - "high": if any gate is at or near its floor (e.g., tenant_count == 5, distinct_users_count == 12, min_events_per_tenant == 10).
   - "medium": otherwise.
4. Set detected_at to a valid current UTC ISO timestamp (e.g., "2026-06-08T12:00:00Z").
5. Create an enriched pattern dictionary containing all the original fields of the pattern dictionary plus the new fields:
   - "recommended_mitigation": the mitigation text.
   - "severity": the severity string.
   - "detected_at": the ISO timestamp.
6. Call append_to_state with key="enriched_patterns" and value=enriched_pattern_dict. Do this for each pattern in state["published_patterns"].

WARNING: Do NOT invent or output any mock patterns (like example pattern IDs or examples from other categories) that are not present in state["published_patterns"]. Only process the actual patterns found in state["published_patterns"].

After calling append_to_state for each pattern, respond briefly: "Enriched N published patterns with mitigation recommendations."''',
    tools=[append_to_state]
)
