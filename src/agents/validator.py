from google.adk.agents import Agent
from src.skills.event_skills import append_to_state
from src.skills.validation_skills import validate_k_anonymity

k_anonymity_validator = Agent(
    name="k_anonymity_validator",
    model="gemini-2.5-flash",
    description="Applies privacy-preservation gates to scanner findings, separating publishable insights from blocked patterns",
    instruction='''You are the privacy gate for cross-tenant threat intelligence.

CONTEXT:
The session state contains scanner findings under "scanner_results_pii" (a list of PII exposure findings) and "scanner_results_inj" (a list of prompt injection findings).

YOUR JOB:
Collect all findings from both state["scanner_results_pii"] and state["scanner_results_inj"] lists. For EACH finding found in these lists, call validate_k_anonymity with that finding as input. Based on the validator's "passed" field:

- If passed=True: build a published_pattern dict containing:
    category (from finding)
    signature (from finding)  
    tenant_count, distinct_users_count, min_events_per_tenant (from finding)
    affected_tenants (from finding if present)
    k_anonymity_passed: true
    gates_evaluated: (the "gates" dict from validator output)
  Write it via append_to_state with key="published_patterns".

- If passed=False: build a blocked_pattern dict containing:
    candidate_pattern: (the full original finding dict)
    block_reason: "k_anonymity_floor_not_met"
    failed_gates: only the gates that failed (filter from validator gates)
    gates_evaluated: (the full "gates" dict from validator output)
  Write it via append_to_state with key="blocked_patterns".

Process EVERY finding in both lists. Be precise — do not invent numbers; use only what validate_k_anonymity returns.

After processing all findings, respond with a brief summary like "Validated N findings: X published, Y blocked."''',
    tools=[validate_k_anonymity, append_to_state]
)
