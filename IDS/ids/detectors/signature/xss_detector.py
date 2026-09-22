from ids.alert.alert import alert_detect_xss
import json
import re

def normalize_payload(payload):
    """
    Chuẩn hóa payload để dễ dàng phát hiện các mẫu tấn công.
    """
    if not payload:
        return ""
    payload = str(payload)
    from urllib.parse import unquote
    #Decode URL-encoded characters
    for _ in range(3):
        payload = unquote(payload)
    #Chuyển payload về chữ thường
    payload = payload.lower()
    #Loai bo khoang trang
    payload = re.sub(r"\s+", " ", payload)
    return payload

def detect_xss(session,rules):
    """Quét và phát hiện dấu hiệu XSS dựa trên cấu trúc JSON session."""
    # 1. Kiểm tra cấu trúc session HTTP hợp lệ
    http = session.get("http")
    if not http or not http.get("is_http"):
        return
    XSS_PATTERNS = rules.get("XSS_PATTERNS",[])



    # 2. Truy cập vào mảng requests: session["http"]["transactions"]["requests"]
    transactions = http.get("transactions", [])
    # 3. Duyệt qua từng request gửi lên
    for transaction in transactions:

        uri = (transaction.get("request")).get("uri")
        body = (transaction.get("request")).get("body")
        payload = uri + body
        for pattern in XSS_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE):
                network = session.get("network",{})
                src_ip = network.get("src_ip","")
                alert_detect_xss(src_ip,payload)# Phát hiện XSS
    return # Không phát hiện XSS