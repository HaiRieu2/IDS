import re
from urllib.parse import unquote
from ids.alert.alert import alert_detect_sqli
import json

def normalize_payload(payload):
    """Chuẩn hóa payload để phát hiện mẫu tấn công."""
    if not payload:
        return ""
    payload = str(payload)

    # Decode URL 3 lần
    for _ in range(3):
        decoded = unquote(payload)
        if decoded == payload:
            break
        payload = decoded

    payload = payload.lower()
    payload = re.sub(r"\s+", " ", payload)
    return payload


def detect_sqli(session, rules):
    http = session.get("http")

    print("[SQLI] http =", http)

    if not http or not http.get("is_http"):
        print("[SQLI] Not HTTP")
        return

    transactions = http.get("transactions", [])

    print("[SQLI] transactions =", transactions)

    if not transactions:
        print("[SQLI] No transaction")
        return

    transaction = transactions[-1]

    uri = (transaction.get("request") or {}).get("uri", "")
    body = (transaction.get("request") or {}).get("body", "")

    print("[SQLI] URI =", uri)
    print("[SQLI] BODY =", body)

    payload = normalize_payload(uri + " " + body)

    print("[SQLI] NORMALIZED =", payload)

    for pattern in rules.get("SQLI_PATTERNS", []):
        print("[SQLI] TEST =", pattern)

        if re.search(pattern, payload, re.IGNORECASE):
            print("[SQLI] MATCH !!!")
            network = session.get("network", {})
            src_ip = network.get("src_ip", "")
            alert_detect_sqli(src_ip, payload)
            return