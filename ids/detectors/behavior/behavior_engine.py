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
from contextvars import ContextVar
from contextlib import contextmanager
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
_session_store = ContextVar("ids_behavior_sessions", default=None)

# Chi giu session trong TIME_WINDOW giay gan nhat
TIME_WINDOW = 120


@contextmanager
def isolated_behavior_state():
    """Keep offline-PCAP behavior windows separate from live capture state."""
    token = _session_store.set({})
    try:
        yield
    finally:
        _session_store.reset(token)


def behavior_engine(session, rules):
    current_time = time.time()
    session_id = session.get("session_id")
    store = _session_store.get()
    if store is None:
        store = recent_sessions

    with _lock:
        # Ghi/cap nhat session - dung dict nen khong can duyet toan bo
        # danh sach nhu ban goc (vua don gian hon vua nhanh hon).
        store[session_id] = {
            "time": current_time,
            "session": session,
        }
        
        remove_old_sessions(current_time, store)

        # Snapshot danh sach session hien tai de dua cho detector, tranh
        # detector doc truc tiep tu dict dung khi dict co the bi thread
        # khac sua doi.
        sessions_snapshot = get_sessions(store)

    # Chay detector NGOAI pham vi lock: cac ham nay co the ghi file alert
    # (I/O), khong nen giu lock trong luc do de tranh chan cac request khac.
    detect_brute_force(sessions_snapshot, rules, window_seconds=TIME_WINDOW)
    detect_dos(sessions_snapshot, rules, window_seconds=TIME_WINDOW)

    return


def remove_old_sessions(current_time, store=None):
    """
    Xoa session da qua TIME_WINDOW.
    Luu y: ham nay phai duoc goi trong luc dang giu _lock.
    """

    store = store if store is not None else recent_sessions
    stale_ids = [
        session_id
        for session_id, item in store.items()
        if current_time - item["time"] > TIME_WINDOW
    ]

    for session_id in stale_ids:
        del store[session_id]


def get_sessions(store=None):
    """Tra ve list cac session hien tai. Goi trong luc dang giu _lock."""

    store = store if store is not None else recent_sessions
    return [item["session"] for item in store.values()]
