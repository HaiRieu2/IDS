"""
Nhan session da ghep xong.
Luu session moi vao recent_sessions.
Xoa session cu.
Goi detect_brute_force().
Goi detect_dos().
Tra ket qua detection.
"""

import time
import threading
from .brute_force_detector import detect_brute_force
from .dos_detector import detect_dos

# Dict luu cac session gan day: session_id -> {"time":..., "session":...}
# SUA: ban goc dung LIST va phai duyet tuyen tinh (O(n)) moi lan de tim
# xem session_id da ton tai chua. Dung dict de tra cuu/cap nhat O(1).
recent_sessions = {}

# Bao ve recent_sessions truoc truy cap dong thoi. Hien tai main.py chi
# chay 1 worker thread nen chua can thiet, nhung them san de an toan neu
# sau nay chay nhieu worker thread song song.
_lock = threading.Lock()

# Chi giu session trong TIME_WINDOW giay gan nhat
TIME_WINDOW = 120


def behavior_engine(session, rules):
    current_time = time.time()
    session_id = session.get("session_id")

    with _lock:
        # Ghi/cap nhat session - dung dict nen khong can duyet toan bo
        # danh sach nhu ban goc (vua don gian hon vua nhanh hon).
        recent_sessions[session_id] = {
            "time": current_time,
            "session": session,
        }
        
        remove_old_sessions(current_time)

        # Snapshot danh sach session hien tai de dua cho detector, tranh
        # detector doc truc tiep tu dict dung khi dict co the bi thread
        # khac sua doi.
        sessions_snapshot = get_sessions()

    # Chay detector NGOAI pham vi lock: cac ham nay co the ghi file alert
    # (I/O), khong nen giu lock trong luc do de tranh chan cac request khac.
    detect_brute_force(sessions_snapshot, rules, window_seconds=TIME_WINDOW)
    detect_dos(sessions_snapshot, rules, window_seconds=TIME_WINDOW)

    return


def remove_old_sessions(current_time):
    """
    Xoa session da qua TIME_WINDOW.
    Luu y: ham nay phai duoc goi trong luc dang giu _lock.
    """

    stale_ids = [
        session_id
        for session_id, item in recent_sessions.items()
        if current_time - item["time"] > TIME_WINDOW
    ]

    for session_id in stale_ids:
        del recent_sessions[session_id]


def get_sessions():
    """Tra ve list cac session hien tai. Goi trong luc dang giu _lock."""

    return [item["session"] for item in recent_sessions.values()]