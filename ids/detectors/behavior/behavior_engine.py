"""
Nhận session đã ghép xong.
Lưu session mới vào recent_sessions.
Xóa session cũ.
Gọi detect_brute_force().
Gọi detect_dos().
Trả kết quả detection.
"""

import time
import json
from .brute_force_detector import detect_brute_force
from .dos_detector import detect_dos

# List lưu các session gần đây, mỗi session là một dict với 2 key: time và session
recent_sessions = []

# Chỉ giữ session trong 100 giây gần nhất
TIME_WINDOW = 100


def behavior_engine(session,rules):

    """
    Nhận một session đã ghép hoàn chỉnh.
    """

    current_time = time.time()
    valid_check = 0
    # Lưu session vào bộ nhớ
    for re_se in recent_sessions:
        if session.get("session_id") == (re_se.get("session")).get("session_id"):
            re_se["session"] = session
            re_se["time"] = current_time
            valid_check = 1

    if valid_check == 0:
        recent_sessions.append({
            "time": current_time,
            "session": session
        })

    # Xóa session quá cũ
    remove_old_sessions(current_time)

    # Gọi các detector
    detect_brute_force(get_sessions(),rules)
    detect_dos(get_sessions(),rules)

    return



    

def remove_old_sessions(current_time):
    """
    Xóa session đã quá TIME_WINDOW.
    """
    global recent_sessions #tác động đến biến global recent_sessions

    recent_sessions = [
        item
        for item in recent_sessions
        if current_time - item["time"] <= TIME_WINDOW
    ]

def get_sessions(): #Trả về list các session hiện tại
    """
    Lấy danh sách session hiện tại.
    """

    return [
        item["session"]
        for item in recent_sessions
    ]



