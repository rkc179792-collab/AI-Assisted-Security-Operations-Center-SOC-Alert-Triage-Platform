from datetime import datetime

from app.models.alert import AlertSource, Indicator, NormalizedAlert, Severity
from app.notifications.slack import format_message


def _alert(severity: Severity, indicators: list[Indicator] | None = None) -> NormalizedAlert:
    return NormalizedAlert(
        timestamp=datetime.utcnow(),
        source=AlertSource.WAZUH,
        severity=severity,
        rule_name="5710",
        description="sshd: brute force trying to get access",
        hostname="web-01",
        indicators=indicators or [],
    )


def test_message_includes_severity_and_host():
    message = format_message(_alert(Severity.CRITICAL))

    assert "[CRITICAL]" in message
    assert "web-01" in message


def test_message_lists_malicious_indicators_only():
    indicators = [
        Indicator(kind="ip", value="185.220.101.42", verdict="malicious"),
        Indicator(kind="ip", value="8.8.8.8", verdict="clean"),
    ]
    message = format_message(_alert(Severity.HIGH, indicators))

    assert "185.220.101.42" in message
    assert "8.8.8.8" not in message


def test_message_notes_when_no_indicators_are_malicious():
    message = format_message(_alert(Severity.HIGH))

    assert "none confirmed" in message
