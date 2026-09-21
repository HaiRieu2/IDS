import re
from urllib.parse import unquote
from alert.alert import alert_detect_sqli
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


def detect_sqli(session):
    """Quét dữ liệu SQLi từ cấu trúc session HTTP."""
    # 1. Kiểm tra session có chứa dữ liệu HTTP không
    http = session.get("http")
    if not http or not http.get("is_http"):
        return

    
    RULE_FILE = r"F:\VSCODE\IDS\config\rules.json"
    with open(RULE_FILE,"r",encoding="utf-8") as f:
        rule = json.load(f)
    SQLI_PATTERNS = rule.get("SQLI_PATTERNS",[])



   # 2. Truy cập vào mảng requests: session["http"]["transactions"]["requests"]
    transactions = http.get("transactions", [])
       # 3. Duyệt qua từng request gửi lên
    for transaction in transactions:
           # Với SQLI, quét CẢ URI lẫn Body trên TẤT CẢ các phương thức (GET, POST,...)
        uri = (transaction.get("request")).get("uri")
        body = (transaction.get("request")).get("body")
        payload = uri + body
        for pattern in SQLI_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE):
                network = session.get("network",{})
                src_ip = network.get("src_ip","")
                alert_detect_sqli(src_ip,payload)# Phát hiện SQLI
    return # Không phát hiện SQLi