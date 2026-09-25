from datetime import datetime
from typing import Any

from app.models.alert import AlertSource, NormalizedAlert, Severity
from app.parsers.base import AlertParser


SEVERITY_MAP = [
    (12, Severity.CRITICAL),
    (9, Severity.HIGH),
    (5, Severity.MEDIUM),
    (2, Severity.LOW),
    (0, Severity.INFO),
]


def _map_severity(rule_level: int) -> Severity:
    for threshold, sev in SEVERITY_MAP:
        if rule_level >= threshold:
            return sev
    return Severity.INFO


class WazuhParser(AlertParser):
    """Parses Wazuh 4.x alert payloads."""

    def parse(self, payload: dict[str, Any]) -> NormalizedAlert:
        rule = payload.get("rule", {})
        agent = payload.get("agent", {})
        data = payload.get("data", {})

        rule_level = int(rule.get("level", 0))
        description = rule.get("description", "No description provided")
        rule_name = rule.get("id", "unknown-rule")

        techniques = self._extract_mitre(rule)

        return NormalizedAlert(
            timestamp=datetime.fromisoformat(
                payload.get("timestamp", datetime.utcnow().isoformat())
            ),
            source=AlertSource.WAZUH,
            severity=_map_severity(rule_level),
            rule_name=rule_name,
            description=description,
            src_ip=data.get("srcip") or data.get("src_ip"),
            dst_ip=data.get("dstip") or data.get("dst_ip"),
            src_user=data.get("srcuser") or data.get("dstuser"),
            hostname=agent.get("name"),
            process=payload.get("syscheck", {}).get("path") or data.get("command"),
            mitre_techniques=techniques,
            raw=payload,
        )

    @staticmethod
    def _extract_mitre(rule: dict[str, Any]) -> list[str]:
        techniques = []
        mitre = rule.get("mitre", {})
        for tech in mitre.get("technique", []):
            if isinstance(tech, dict):
                if tid := tech.get("id"):
                    techniques.append(tid)
        return techniques
