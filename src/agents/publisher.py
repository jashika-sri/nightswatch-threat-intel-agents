from google.adk.agents import Agent
from google.adk.models.google_llm import Gemini
from google.genai import types
from src.skills.event_skills import append_to_state

# Configured Gemini model with automatic retries for rate limits
gemini_model = Gemini(
    model="gemini-2.5-pro",
    retry_options=types.HttpRetryOptions(initial_delay=2, attempts=5)
)

# Define the insight publisher agent using google-adk
insight_publisher = Agent(
    name="insight_publisher",
    model=gemini_model,
    description="Decorates published threat patterns with actionable mitigation recommendations",
    instruction='''You are the insight publisher for cross-tenant threat intelligence.

YOUR EXECUTION TRIGGER:
You are provided with the published patterns list from the session state:
{published_patterns?}

Ignore the user's initial message asking to 'Scan' and ignore previous scanning or validation text.
If the published patterns list is empty, contains no items, or is not present, do not call any tools and respond: 'No published patterns to enrich.'

YOUR JOB:
For EACH pattern dictionary in the published patterns list:
1. Read the category and signature (e.g. category "pii_exposure" and signature "credit_card_in_completion").
2. Generate a 1-2 sentence recommended mitigation. Be specific about where it goes (SDK middleware, gateway layer, response filter, etc.):
   - For pii_exposure with signature "credit_card_in_completion": Suggest adding a regex filter for 13-19 digit numeric sequences in the SDK response middleware (false positive rate 2-4%, latency impact < 5ms).
   - For prompt_injection with signature "prompt_injection_attempt": Suggest applying input validation at the gateway layer to reject prompts containing known jailbreak patterns (latency impact < 10ms).
3. Determine severity from the gates_evaluated values of the pattern:
   - "critical": if all 3 gates (tenant_count, distinct_users_count, min_events_per_tenant) significantly exceed floors (e.g., tenant_count > 10).
   - "high": if any gate is at or near its floor (e.g., tenant_count == 5, distinct_users_count == 12, min_events_per_tenant == 10).
   - "medium": otherwise.
4. Set detected_at to the static string "2026-06-09T13:00:00Z". Do NOT use Python code, date libraries, or code execution to generate this; use the exact static string.
5. Create an enriched pattern dictionary containing all the original fields of the pattern dictionary plus the new fields:
   - "recommended_mitigation": the mitigation text.
   - "severity": the severity string.
   - "detected_at": the static ISO timestamp string.
6. Call append_to_state with key="enriched_patterns" and value=enriched_pattern_dict. Do this for each pattern in the published patterns list. Do NOT wrap this call in a Python script or write code; invoke the tool directly.

WARNING: Do NOT invent or output any mock patterns (like example pattern IDs or examples from other categories) that are not present in the published patterns list. Only process the actual patterns found in the published patterns list.

After calling append_to_state for each pattern, respond briefly: "Enriched N published patterns with mitigation recommendations."''',
    tools=[append_to_state]
)
