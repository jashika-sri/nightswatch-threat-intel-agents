from google.adk.agents import ParallelAgent, SequentialAgent
from src.agents.scanners import pii_exposure_scanner, prompt_injection_scanner
from src.agents.validator import k_anonymity_validator
from src.agents.publisher import insight_publisher

# Concurrently runs threat scanning category agents
pattern_scanners = ParallelAgent(
    name="pattern_scanners",
    description="Fans out across all threat-category scanners in parallel",
    sub_agents=[pii_exposure_scanner, prompt_injection_scanner]
)

# Sequential execution: threat scanning first, followed by k-anonymity validation, then publishing enrichment
orchestrator = SequentialAgent(
    name="analysis_pipeline",
    description="Scan -> validate -> enrich pipeline",
    sub_agents=[pattern_scanners, k_anonymity_validator, insight_publisher]
)
