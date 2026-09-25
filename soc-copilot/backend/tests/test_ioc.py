from datetime import datetime

from app.enrichment.ioc import extract_indicators
from app.models.alert import AlertSource, NormalizedAlert, Severity


def _alert(description: str) -> NormalizedAlert:
    return NormalizedAlert(
        timestamp=datetime.utcnow(),
        source=AlertSource.GENERIC,
        severity=Severity.HIGH,
        rule_name="test",
        description=description,
    )


def test_extracts_public_ip_only():
    alert = _alert("Connection from 185.220.101.42 to 10.0.0.5")
    ips = [i.value for i in extract_indicators(alert) if i.kind == "ip"]

    assert "185.220.101.42" in ips
    assert "10.0.0.5" not in ips


def test_extracts_sha256_hash():
    digest = "a" * 64
    alert = _alert(f"File dropped: {digest}")
    hashes = [i.value for i in extract_indicators(alert) if i.kind == "hash"]

    assert digest in hashes


def test_no_duplicates():
    alert = _alert("185.220.101.42 talked to 185.220.101.42")
    ips = [i.value for i in extract_indicators(alert) if i.kind == "ip"]

    assert ips.count("185.220.101.42") == 1
