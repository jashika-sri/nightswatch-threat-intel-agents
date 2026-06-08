from google.adk.tools import ToolContext, FunctionTool

TENANT_COUNT_FLOOR = 5
DISTINCT_USERS_FLOOR = 5
MIN_EVENTS_PER_TENANT_FLOOR = 10

def adk_skill(func):
    """
    Decorator that wraps a Python function into an ADK FunctionTool.
    """
    return FunctionTool(func)

@adk_skill
def validate_k_anonymity(
    tool_context: ToolContext,
    finding: dict
) -> dict:
    """Apply the locked 3-gate k-anonymity rule to a scanner finding.
    
    The rule (B+C combined): a pattern can be published only if
    tenant_count >= 5 AND distinct_users_count >= 5 AND 
    min_events_per_tenant >= 10. Deterministic math, no LLM reasoning.
    
    Args:
        tool_context: ADK ToolContext instance.
        finding: a dict from scanner_results.* with tenant_count, 
                 distinct_users_count, min_events_per_tenant fields
    
    Returns:
        {
          "status": "success",
          "passed": bool,
          "gates": {
            "tenant_count": {"value": int, "floor": 5, "passed": bool},
            "distinct_users_count": {"value": int, "floor": 5, "passed": bool},
            "min_events_per_tenant": {"value": int, "floor": 10, "passed": bool}
          },
          "failed_gates_count": int
        }
    """
    # Helper to get size of collection safely
    def safe_len(x):
        if isinstance(x, (list, dict, set)):
            return len(x)
        if isinstance(x, str):
            return 1 if x else 0
        return 0

    # Dynamically extract / compute metrics from the finding dict to handle different structures
    tc = finding.get("tenant_count")
    if tc is None:
        affected_tenants = finding.get("affected_tenants", [])
        events_per_tenant = finding.get("events_per_tenant", {})
        findings_nested = finding.get("findings", {})
        details_per_tenant = finding.get("details_per_tenant", {})
        
        tc = max(
            safe_len(affected_tenants),
            safe_len(events_per_tenant),
            safe_len(findings_nested),
            safe_len(details_per_tenant)
        )
        
    du = finding.get("distinct_users_count")
    if du is None:
        distinct_users = finding.get("distinct_users")
        findings_nested = finding.get("findings", {})
        details_per_tenant = finding.get("details_per_tenant", {})
        
        all_users = set()
        
        # Check distinct_users
        if isinstance(distinct_users, dict):
            for users_list in distinct_users.values():
                if isinstance(users_list, list):
                    all_users.update(users_list)
        elif isinstance(distinct_users, list):
            all_users.update(distinct_users)
            
        # Check findings_nested
        if isinstance(findings_nested, dict):
            for v in findings_nested.values():
                if isinstance(v, dict):
                    ulist = v.get("distinct_users") or v.get("users")
                    if isinstance(ulist, list):
                        all_users.update(ulist)
                        
        # Check details_per_tenant
        if isinstance(details_per_tenant, dict):
            for v in details_per_tenant.values():
                if isinstance(v, dict):
                    ulist = v.get("distinct_users") or v.get("users")
                    if isinstance(ulist, list):
                        all_users.update(ulist)
                        
        du = len(all_users) if all_users else 0
            
    mept = finding.get("min_events_per_tenant")
    if mept is None:
        events_per_tenant = finding.get("events_per_tenant", {})
        findings_nested = finding.get("findings", {})
        details_per_tenant = finding.get("details_per_tenant", {})
        
        candidates = []
        
        # Check events_per_tenant dict or numeric value
        if isinstance(events_per_tenant, dict):
            for v in events_per_tenant.values():
                if isinstance(v, (int, float)):
                    candidates.append(v)
        elif isinstance(events_per_tenant, (int, float)):
            candidates.append(events_per_tenant)
            
        # Check findings_nested dict
        if isinstance(findings_nested, dict):
            for v in findings_nested.values():
                if isinstance(v, dict):
                    cnt = v.get("event_count") or v.get("events_count")
                    if isinstance(cnt, (int, float)):
                        candidates.append(cnt)
                        
        # Check details_per_tenant dict
        if isinstance(details_per_tenant, dict):
            for v in details_per_tenant.values():
                if isinstance(v, dict):
                    cnt = v.get("event_count") or v.get("events_count")
                    if isinstance(cnt, (int, float)):
                        candidates.append(cnt)
                        
        if candidates:
            mept = min(candidates)
        else:
            mept = 0

    gates = {
        "tenant_count": {
            "value": int(tc), "floor": TENANT_COUNT_FLOOR, 
            "passed": tc >= TENANT_COUNT_FLOOR
        },
        "distinct_users_count": {
            "value": int(du), "floor": DISTINCT_USERS_FLOOR,
            "passed": du >= DISTINCT_USERS_FLOOR
        },
        "min_events_per_tenant": {
            "value": int(mept), "floor": MIN_EVENTS_PER_TENANT_FLOOR,
            "passed": mept >= MIN_EVENTS_PER_TENANT_FLOOR
        }
    }
    
    failed_count = sum(1 for g in gates.values() if not g["passed"])
    
    return {
        "status": "success",
        "passed": failed_count == 0,
        "gates": gates,
        "failed_gates_count": failed_count
    }
