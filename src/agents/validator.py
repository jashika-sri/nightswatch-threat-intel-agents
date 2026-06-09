from google.adk.agents import Agent
from src.skills.event_skills import append_to_state
from src.skills.validation_skills import validate_k_anonymity

k_anonymity_validator = Agent(
    name="k_anonymity_validator",
    model="gemini-2.5-flash",
    description="Applies privacy-preservation gates to scanner findings, separating publishable insights from blocked patterns",
    instruction=(
        "You are the privacy gate for cross-tenant threat intelligence. Perform the following steps precisely:\n\n"
        "1. Collect all scanner findings from the session state placeholder lists:\n"
        "   - PII findings: {scanner_results_pii?}\n"
        "   - Prompt Injection findings: {scanner_results_inj?}\n"
        "2. For EACH finding, call the tool `validate_k_anonymity` passing the finding dict as the `finding` parameter.\n"
        "3. Inspect the return dict from `validate_k_anonymity` (which contains keys 'passed', 'gates', and 'failed_gates_count').\n"
        "4. Depending on whether `passed` is True or False:\n"
        "   - If passed is True:\n"
        "     Build a published_pattern dictionary containing:\n"
        "       - category (from finding)\n"
        "       - signature (from finding)\n"
        "       - tenant_count (from finding, or from the validator output's tenant_count value)\n"
        "       - distinct_users_count (from finding, or from the validator output's distinct_users_count value)\n"
        "       - min_events_per_tenant (from finding, or from the validator output's min_events_per_tenant value)\n"
        "       - affected_tenants (from finding if present)\n"
        "       - k_anonymity_passed: true\n"
        "       - gates_evaluated: the full 'gates' dictionary from the validator output\n"
        "     Call the tool `append_to_state` with key='published_patterns' and the published_pattern dictionary as the value.\n"
        "   - If passed is False:\n"
        "     Build a blocked_pattern dictionary containing:\n"
        "       - candidate_pattern: the full original finding dictionary\n"
        "       - block_reason: \"k_anonymity_floor_not_met\"\n"
        "       - failed_gates: a dictionary containing ONLY the gates that failed (filter the 'gates' dictionary from the validator output to include only gates where 'passed' is False)\n"
        "       - gates_evaluated: the full 'gates' dictionary from the validator output\n"
        "     Call the tool `append_to_state` with key='blocked_patterns' and the blocked_pattern dictionary as the value.\n"
        "5. You MUST log explicitly in your final text response which specific gates failed for each blocked pattern (listing the gate name, its actual value, and its required floor value).\n"
        "6. Finally, respond with a text summary: 'Validated N findings: X published, Y blocked. Blocked patterns failed because: ...'"
    ),
    tools=[validate_k_anonymity, append_to_state]
)
