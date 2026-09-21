from datetime import datetime , timezone
from config.path import ALERT_DATA
from config.path import CONFIG_DATA
import os
import json

ALERT_COUNTER_FILE = CONFIG_DATA/"alert_counter.txt"
ALERT_FILE = ALERT_DATA/"alert.json"




def get_alert_id():
    counter = 0
    if os.path.exists(ALERT_COUNTER_FILE):
        with open(ALERT_COUNTER_FILE,"r",encoding="utf-8") as f:
            try:
                content = f.read().strip()
                if content:
                    counter=int(content)
            except ValueError:
                counter = 0
    counter += 1
    with open(ALERT_COUNTER_FILE, "w", encoding="utf-8") as f:
        f.write(str(counter))
    return f"A{counter:03d}"




def save_alert_to_file(alert_data):
    with open(ALERT_FILE,"a",encoding = "utf-8") as f:
        f.write(json.dumps(alert_data,ensure_ascii = False) + "\n")
    return
def alert_detect_brute_force(src_ip,evidence):
    a={
        "alert_id":get_alert_id(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": src_ip,
        "attack_type": "Web Attack - Brute Force",
        "engine": "behavior",
        "severity": "high",
        "evidence" : evidence
        }
    save_alert_to_file(a)
    return
def alert_detect_dos_connection(src_ip,evidence):
    a={
        "alert_id": get_alert_id(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": src_ip,
        "attack_type": "DoS",
        "engine": "behavior",
        "severity": "high",
        "evidence" : evidence
        }
    save_alert_to_file(a)
    
    return
def alert_detect_ICMP_Flood(src_ip,evidence):
    a={
        "alert_id":get_alert_id(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": src_ip,
        "attack_type": "DoS",
        "engine": "behavior",
        "severity": "high",
        "evidence" : evidence
        }
    save_alert_to_file(a)
    return
def alert_detect_UDP_Flood(src_ip,evidence):
    a={
        "alert_id":get_alert_id(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": src_ip,
        "attack_type": "DoS",
        "engine": "behavior",
        "severity": "high",
        "evidence" : evidence
        }
    save_alert_to_file(a)
    return
def alert_detect_HTTP_Flood(src_ip,evidence):
    a={
        "alert_id":get_alert_id(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": src_ip,
        "attack_type": "DoS",
        "engine": "behavior",
        "severity": "high",
        "evidence" : evidence
        }
    save_alert_to_file(a)
    return 
def alert_detect_SYN_Flood(src_ip,evidence):
    a={
        "alert_id":get_alert_id(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": src_ip,
        "attack_type": "DoS",
        "engine": "behavior",
        "severity": "high",
        "evidence" : evidence
        }
    save_alert_to_file(a)
    return

def alert_detect_xss(src_ip,payload):
    a={
        "alert_id":get_alert_id(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": src_ip,
        "attack_type": "XSS",
        "engine": "signature",
        "severity": "critical",
        "evidence" : payload
        }
    save_alert_to_file(a)
    return
def alert_detect_sqli(src_ip,payload):
   a={
       "alert_id":get_alert_id(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": src_ip,
        "attack_type": "SQLi",
        "engine": "signature",
        "severity": "critical",
        "evidence" : payload
        }
   save_alert_to_file(a)
   return