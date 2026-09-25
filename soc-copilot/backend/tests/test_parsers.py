from app.models.alert import AlertSource, Severity
from app.parsers import get_parser


def test_wazuh_parser_maps_high_severity():
    payload = {
        "timestamp": "2026-09-25T10:01:00",
        "rule": {
            "id": "5710",
            "level": 10,
            "description": "sshd: brute force trying to get access",
            "mitre": {"technique": [{"id": "T1110"}]},
        },
        "agent": {"name": "web-01"},
        "data": {"srcip": "185.220.101.42"},
    }

    alert = get_parser(AlertSource.WAZUH).parse(payload)

    assert alert.severity == Severity.HIGH
    assert alert.hostname == "web-01"
    assert alert.src_ip == "185.220.101.42"
    assert "T1110" in alert.mitre_techniques


def test_suricata_parser_maps_severity_one_to_high():
    payload = {
        "timestamp": "2026-09-25T10:03:45.123456+0000",
        "event_type": "alert",
        "src_ip": "185.220.101.42",
        "dest_ip": "10.0.0.5",
        "host": "web-01",
        "alert": {
            "signature": "ET SCAN Potential SSH Scan",
            "signature_id": 2001219,
            "severity": 1,
        },
    }

    alert = get_parser(AlertSource.SURICATA).parse(payload)

    assert alert.severity == Severity.HIGH
    assert alert.src_ip == "185.220.101.42"
    assert alert.dst_ip == "10.0.0.5"
    assert alert.rule_name == "2001219"


def test_zeek_parser_flags_malware_notes_as_high():
    payload = {
        "ts": 1758790940.123,
        "note": "Malware::C2_Communication",
        "msg": "Outbound connection matched a known C2 pattern",
        "id.orig_h": "10.0.0.5",
        "id.resp_h": "45.33.32.156",
    }

    alert = get_parser(AlertSource.ZEEK).parse(payload)

    assert alert.severity == Severity.HIGH
    assert alert.src_ip == "10.0.0.5"
    assert alert.dst_ip == "45.33.32.156"


def test_zeek_parser_defaults_unknown_notes_to_medium():
    payload = {
        "ts": 1758790940.123,
        "note": "Scan::Address_Scan",
        "msg": "185.220.101.42 scanned at least 15 unique ports",
        "src": "185.220.101.42",
    }

    alert = get_parser(AlertSource.ZEEK).parse(payload)

    assert alert.severity == Severity.MEDIUM
    assert alert.src_ip == "185.220.101.42"


def test_generic_parser_handles_missing_fields():
    alert = get_parser(AlertSource.GENERIC).parse({
        "timestamp": "2026-09-25T10:01:00",
        "description": "something happened",
    })

    assert alert.severity == Severity.INFO
    assert alert.source == AlertSource.GENERIC
