from google.adk import Agent
from google.adk.models.google_llm import Gemini
from google.genai import types
from src.skills.event_skills import query_tenant_events, append_to_state

# Configured Gemini model with automatic retries for rate limits
gemini_model = Gemini(
    model="gemini-2.5-flash",
    retry_options=types.HttpRetryOptions(initial_delay=2, attempts=5)
)

# Define the PII exposure scanner agent using google-adk
pii_exposure_scanner = Agent(
    name="pii_exposure_scanner",
    description="Scans events across tenants for PII exposure patterns (credit card data leaking into completions)",
    model=gemini_model,
    instruction=(
        "You are the PII exposure scanner agent. Perform the following steps precisely:\n\n"
        "1. Retrieve the list of all tenant IDs to scan from the session state key 'tenant_ids' (i.e. state['tenant_ids']). You MUST use the exact raw string IDs from this list (e.g. 'devtools', not 'devtoolsinc'). Do NOT alter the IDs or confuse them with tenant names.\n"
        "2. Call the tool `query_tenant_events` EXACTLY ONCE with the list of all provided tenant IDs and marker='[REDACTED-CC]'. Do NOT call this tool in a loop or iterate per tenant.\n"
        "3. From the returned dictionary, get the list of events from the 'events' key.\n"
        "4. Calculate the following values from the list of events:\n"
        "   - affected_tenants: the list of unique tenant_ids present in the events\n"
        "   - distinct_users: the list of unique user_ids present in the events\n"
        "   - events_per_tenant: a dictionary mapping each affected tenant_id to the count of its events\n"
        "   - total_events: the total number of events found\n"
        "   - tenant_count: the number of unique affected tenants (length of affected_tenants)\n"
        "   - distinct_users_count: the number of unique user IDs (length of distinct_users)\n"
        "   - min_events_per_tenant: the minimum event count among the affected tenants, calculated as min(events_per_tenant.values()) if there are events, otherwise 0\n"
        "5. Construct a finding dictionary with the following schema:\n"
        "   {\n"
        "     \"category\": \"pii_exposure\",\n"
        "     \"signature\": \"credit_card_in_completion\",\n"
        "     \"marker_detected\": \"[REDACTED-CC]\",\n"
        "     \"tenant_count\": <int>,\n"
        "     \"distinct_users_count\": <int>,\n"
        "     \"min_events_per_tenant\": <int>,\n"
        "     \"affected_tenants\": <list of strings>,\n"
        "     \"distinct_users\": <list of strings>,\n"
        "     \"events_per_tenant\": <dict of string to int>,\n"
        "     \"total_events\": <int>\n"
        "   }\n"
        "6. Call the tool `append_to_state` with key='scanner_results_pii' and the constructed finding dictionary as the value.\n"
        "7. Finally, write a brief textual response explaining the findings."
    ),
    tools=[query_tenant_events, append_to_state]
)

# Define the Prompt Injection scanner agent using google-adk
prompt_injection_scanner = Agent(
    name="prompt_injection_scanner",
    model=gemini_model,
    description="Scans tenant events for prompt injection attempts",
    instruction=(
        "You are the prompt injection scanner agent. Perform the following steps precisely:\n\n"
        "1. Retrieve the list of all tenant IDs to scan from the session state key 'tenant_ids' (i.e. state['tenant_ids']). You MUST use the exact raw string IDs from this list (e.g. 'devtools', not 'devtoolsinc'). Do NOT alter the IDs or confuse them with tenant names.\n"
        "2. Call the tool `query_tenant_events` EXACTLY ONCE with the list of all provided tenant IDs and marker='[INJECTION-ATTEMPT]'. Do NOT call this tool in a loop or iterate per tenant.\n"
        "3. From the returned dictionary, get the list of events from the 'events' key.\n"
        "4. Calculate the following values from the list of events:\n"
        "   - affected_tenants: the list of unique tenant_ids present in the events\n"
        "   - distinct_users: the list of unique user_ids present in the events\n"
        "   - events_per_tenant: a dictionary mapping each affected tenant_id to the count of its events\n"
        "   - total_events: the total number of events found\n"
        "   - tenant_count: the number of unique affected tenants (length of affected_tenants)\n"
        "   - distinct_users_count: the number of unique user IDs (length of distinct_users)\n"
        "   - min_events_per_tenant: the minimum event count among the affected tenants, calculated as min(events_per_tenant.values()) if there are events, otherwise 0\n"
        "5. Construct a finding dictionary with the following schema:\n"
        "   {\n"
        "     \"category\": \"prompt_injection\",\n"
        "     \"signature\": \"prompt_injection_attempt\",\n"
        "     \"marker_detected\": \"[INJECTION-ATTEMPT]\",\n"
        "     \"tenant_count\": <int>,\n"
        "     \"distinct_users_count\": <int>,\n"
        "     \"min_events_per_tenant\": <int>,\n"
        "     \"affected_tenants\": <list of strings>,\n"
        "     \"distinct_users\": <list of strings>,\n"
        "     \"events_per_tenant\": <dict of string to int>,\n"
        "     \"total_events\": <int>\n"
        "   }\n"
        "6. Call the tool `append_to_state` with key='scanner_results_inj' and the constructed finding dictionary as the value.\n"
        "7. Finally, write a brief textual response explaining the findings."
    ),
    tools=[query_tenant_events, append_to_state]
)
