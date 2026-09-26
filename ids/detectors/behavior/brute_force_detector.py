"""
Phat hien Brute Force qua HTTP login (mac dinh: POST /login tra ve 401).
"""

from ids.alert.alert import alert_detect_brute_force


def detect_brute_force(sessions, rules, window_seconds=100):
    """
    sessions: danh sach session trong cua so thoi gian gan day (tu
        behavior_engine.get_sessions()).
    rules: dict nguong, doc tu rules.json.
    window_seconds: do dai (giay) cua cua so thoi gian ma `sessions` bao
        phu. Dung de tinh toc do that su (so lan/giay) thay vi hang so
        cung "/10" nhu ban goc (khong co y nghia thoi gian ro rang).
    """

    MAX_FAILED_LOGINS = rules.get("MAX_FAILED_LOGINS", 0)
    REQUEST_RATE_THRESHOLD = rules.get("REQUEST_RATE_THRESHOLD", 0)

    login_failed_count = 0
    failed_logins = {}  # src_ip -> so lan dang nhap that bai

    for session in sessions:
        http = session.get("http", {})

        if http.get("is_http") != True:
            continue

        network = session.get("network", {})
        src_ip = network.get("src_ip", "")

        for transaction in http.get("transactions", []):
            request = transaction.get("request", {})
            response = transaction.get("response", {})

            method = request.get("method", "")
            uri = request.get("uri", "")
            status_code = response.get("status_code", 0)

            # POST /login tra ve 401 (Unauthorized) -> 1 lan dang nhap that bai
            if method == "POST" and "/login" in uri and status_code == 401:
                login_failed_count += 1
                failed_logins[src_ip] = failed_logins.get(src_ip, 0) + 1

    # --- CAC KIEM TRA NAY DAT NGOAI VONG LAP FOR (duyet xong moi ket luan) ---

    # 1. IP nao vuot nguong so lan dang nhap that bai
    for src_ip, count in failed_logins.items():
        if count > MAX_FAILED_LOGINS:
            # BUG DA SUA: ban goc goi alert_detect_brute_force(evidence) -
            # thieu tham so src_ip trong khi ham dinh nghia can 2 tham so
            # (src_ip, evidence) -> se nem TypeError ngay khi phat hien
            # brute force, lam crash worker thread.
            evidence = f"IP {src_ip} co {count} lan dang nhap that bai (nguong cho phep: {MAX_FAILED_LOGINS})"
            alert_detect_brute_force(src_ip, evidence)

    # 2. Toc do dang nhap that bai toan cuc (so lan / giay)
    #    Ban goc: login_failed_count / 10 -> "10" khong co y nghia (khong
    #    phai giay, khong phai so session), khien REQUEST_RATE_THRESHOLD
    #    trong rules.json rat kho cau hinh dung. Sua lai chia cho do dai
    #    thuc te cua cua so thoi gian (window_seconds) de ra dung don vi
    #    "request/giay".
    if window_seconds > 0:
        failed_login_rate = login_failed_count / window_seconds

        if failed_login_rate > REQUEST_RATE_THRESHOLD:
            evidence = (
                f"Toc do dang nhap that bai toan cuc = {failed_login_rate:.2f} "
                f"lan/giay (nguong: {REQUEST_RATE_THRESHOLD})"
            )
            # BUG DA SUA: thieu src_ip khi goi alert (xem giai thich o tren).
            # Vi day la thong ke TOAN CUC (nhieu IP cong lai), dung nhan
            # "MULTIPLE_IP" thay vi 1 IP cu the.
            alert_detect_brute_force("MULTIPLE_IP", evidence)

    return