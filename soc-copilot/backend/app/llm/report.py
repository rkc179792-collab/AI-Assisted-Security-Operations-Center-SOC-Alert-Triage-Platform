from app.correlation.timeline import build_timeline
from app.llm.client import generate
from app.models.alert import NormalizedAlert


SYSTEM_PROMPT = (
    "You are a Tier 1 SOC analyst writing a concise incident report. "
    "Base every statement on the evidence provided. If evidence is missing, "
    "say so instead of guessing."
)


def _format_indicators(alerts: list[NormalizedAlert]) -> str:
    lines = []
    for alert in alerts:
        for ind in alert.indicators:
            if ind.verdict in ("malicious", "suspicious"):
                lines.append(
                    f"- {ind.kind}: {ind.value} "
                    f"({ind.verdict}, score={ind.score}, source={ind.source})"
                )
    return "\n".join(lines) or "- (none found)"


def _format_mitre(alerts: list[NormalizedAlert]) -> str:
    techniques = sorted({t for a in alerts for t in a.mitre_techniques})
    return ", ".join(techniques) if techniques else "(none mapped)"


async def generate_report(alerts: list[NormalizedAlert]) -> str:
    """Produce a Markdown incident report for a group of correlated alerts."""

    timeline = build_timeline(alerts)
    indicators = _format_indicators(alerts)
    mitre = _format_mitre(alerts)
    primary = alerts[0]

    prompt = f"""Write an incident report using the data below.

INCIDENT
- Primary rule: {primary.rule_name}
- Source tool: {primary.source.value}
- Affected host: {primary.hostname or "unknown"}
- Severity: {primary.severity.value}
- MITRE techniques: {mitre}

TIMELINE
{timeline}

INDICATORS
{indicators}

Produce Markdown with these sections:
1. Summary (2-3 sentences)
2. Severity assessment and justification
3. Timeline
4. Indicators of compromise
5. Recommended actions
"""

    body = await generate(prompt, system=SYSTEM_PROMPT)
    return body or _fallback_report(primary, timeline, indicators, mitre)


def _fallback_report(primary, timeline, indicators, mitre) -> str:
    """Emit a usable report even if the LLM is unreachable."""
    return f"""# Incident Report

**Rule:** {primary.rule_name}
**Host:** {primary.hostname or "unknown"}
**Severity:** {primary.severity.value}
**MITRE:** {mitre}

## Timeline

{timeline}

## Indicators
{indicators}

## Recommended Actions
- Review the host for signs of lateral movement
- Block confirmed malicious indicators at the perimeter
- Escalate to Tier 2 if additional alerts share the same entities
"""
