"""Fire a realistic brute-force attack sequence at the local API.

Run with:  python demo/generate_alerts.py
"""
import asyncio
import random
from datetime import datetime, timezone

import httpx


API = "http://localhost:8000/api/v1/webhook"
SECRET = "change-me-wazuh"

ATTACKER_IP = "185.220.101.42"
VICTIM_HOST = "web-01"
VICTIM_USER = "admin"


def wazuh_alert(rule_id, level, description, src_ip=None, extra=None):
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rule": {
            "id": rule_id,
            "level": level,
            "description": description,
            "mitre": {
                "technique": [{"id": "T1110"}],
            },
        },
        "agent": {"name": VICTIM_HOST},
        "data": {},
    }
    if src_ip:
        payload["data"]["srcip"] = src_ip
    if extra:
        payload["data"].update(extra)
    return payload


async def main():
    sequence = [
        wazuh_alert("5710", 5, "Attempt to login using a non-existent user",
                    src_ip=ATTACKER_IP, extra={"srcuser": "root"}),
        wazuh_alert("5710", 5, "Attempt to login using a non-existent user",
                    src_ip=ATTACKER_IP, extra={"srcuser": "oracle"}),
        wazuh_alert("5710", 10, "sshd: brute force trying to get access",
                    src_ip=ATTACKER_IP),
        wazuh_alert("5715", 10, "sshd: authentication success",
                    src_ip=ATTACKER_IP, extra={"dstuser": VICTIM_USER}),
        wazuh_alert("5402", 12, "Successful sudo to ROOT executed",
                    extra={"dstuser": VICTIM_USER, "command": "cat /etc/shadow"}),
    ]

    async with httpx.AsyncClient(timeout=10.0) as client:
        for alert in sequence:
            response = await client.post(
                f"{API}/wazuh",
                json=alert,
                headers={"x-webhook-secret": SECRET},
            )
            print(f"  -> {alert['rule']['description'][:50]:<50} [{response.status_code}]")
            await asyncio.sleep(random.uniform(1.5, 3.0))

    print("\nSequence complete. Check the API logs for enrichment output.")


if __name__ == "__main__":
    asyncio.run(main())
