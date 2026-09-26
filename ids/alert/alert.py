from datetime import datetime, timezone
from config.path import LOGS_DIR
from config.path import CONFIG_DATA
import os
import json
import time
import threading

ALERT_COUNTER_FILE = CONFIG_DATA / "alert_counter.txt"
ALERT_FILE = LOGS_DIR / "alerts.json"

# Sau khi da canh bao 1 (dedup_key, src_ip), khong canh bao lai trong bao
# nhieu giay. Tranh "alert flooding": vi cac detector chay lai tren cung
# 1 cua so session (recent_sessions) MOI LAN co session moi dong, 1 cuoc
# tan cong keo dai vai chuc giay se sinh ra hang chuc alert trung lap neu
# khong co co che nay.
ALERT_COOLDOWN_SECONDS = 60

_alert_lock = threading.Lock()
_last_alert_time = {}  # (dedup_key, src_ip) -> timestamp lan canh bao gan nhat


def _is_in_cooldown(dedup_key, src_ip):
    """
    True neu (dedup_key, src_ip) vua duoc canh bao trong ALERT_COOLDOWN_SECONDS
    giay gan day (nen bo qua lan nay). Thread-safe.
    """
    now = time.time()
    key = (dedup_key, src_ip)

    with _alert_lock:
        last_time = _last_alert_time.get(key, 0)
        if now - last_time < ALERT_COOLDOWN_SECONDS:
            return True
        _last_alert_time[key] = now
        return False


def get_alert_id():
    """
    Sinh alert_id tang dan (doc + ghi file dem).
    Dat trong _alert_lock de tranh 2 thread doc/ghi file dem cung luc
    lam trung alert_id hoac hong noi dung file (loi cu khong co lock).
    """
    with _alert_lock:
        counter = 0
        if os.path.exists(ALERT_COUNTER_FILE):
            with open(ALERT_COUNTER_FILE, "r", encoding="utf-8") as f:
                try:
                    content = f.read().strip()
                    if content:
                        counter = int(content)
                except ValueError:
                    counter = 0

        counter += 1

        with open(ALERT_COUNTER_FILE, "w", encoding="utf-8") as f:
            f.write(str(counter))

    return f"A{counter:03d}"


def save_alert_to_file(alert_data):
    with _alert_lock:
        with open(ALERT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert_data, ensure_ascii=False) + "\n")
    return


def _make_and_save_alert(src_ip, attack_type, engine, severity, evidence, dedup_key=None):
    """
    Ham dung chung cho tat ca loai alert - thay the cho ~8 ham gan nhu
    giong het nhau (chi khac attack_type) truoc day.

    dedup_key: khoa dung de chong trung lap (mac dinh = attack_type neu
    khong truyen). Cac loai DoS deu co attack_type = "DoS" nhu ban goc,
    nhung dedup_key rieng cho tung loai (SYN/UDP/ICMP/HTTP/Connection) de
    1 loai tan cong khong "nuot mat" (bo qua) alert cua loai khac tren
    cung 1 src_ip.
    """

    key = dedup_key or attack_type

    if _is_in_cooldown(key, src_ip):
        return None

    alert = {
        "alert_id": get_alert_id(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": src_ip,
        "attack_type": attack_type,
        "engine": engine,
        "severity": severity,
        "evidence": evidence,
    }

    save_alert_to_file(alert)

    return alert


# ==================================================================
# Cac ham alert cu the - GIU NGUYEN ten ham va so tham so (src_ip, evidence)
# nhu file goc de khong phai sua lai brute_force_detector.py / dos_detector.py
# ==================================================================

def alert_detect_brute_force(src_ip, evidence):
    return _make_and_save_alert(
        src_ip, "Web Attack - Brute Force", "behavior", "high", evidence,
        dedup_key="brute_force",
    )


def alert_detect_dos_connection(src_ip, evidence):
    return _make_and_save_alert(
        src_ip, "DoS", "behavior", "high", evidence,
        dedup_key="dos_connection",
    )


def alert_detect_ICMP_Flood(src_ip, evidence):
    return _make_and_save_alert(
        src_ip, "DoS", "behavior", "high", evidence,
        dedup_key="icmp_flood",
    )


def alert_detect_UDP_Flood(src_ip, evidence):
    return _make_and_save_alert(
        src_ip, "DoS", "behavior", "high", evidence,
        dedup_key="udp_flood",
    )


def alert_detect_HTTP_Flood(src_ip, evidence):
    return _make_and_save_alert(
        src_ip, "DoS", "behavior", "high", evidence,
        dedup_key="http_flood",
    )


def alert_detect_SYN_Flood(src_ip, evidence):
    return _make_and_save_alert(
        src_ip, "DoS", "behavior", "high", evidence,
        dedup_key="syn_flood",
    )


def alert_detect_xss(src_ip, payload):
    return _make_and_save_alert(
        src_ip, "XSS", "signature", "critical", payload,
        dedup_key="xss",
    )


def alert_detect_sqli(src_ip, payload):
    return _make_and_save_alert(
        src_ip, "SQLi", "signature", "critical", payload,
        dedup_key="sqli",
    )


def alert_machine_learning(attack_type):
    return _make_and_save_alert(
        "", "DoS", "machine learning", "high", attack_type,
        dedup_key=f"ml_{attack_type}",
    )