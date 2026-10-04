from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4
from flask import Flask, flash, jsonify, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename
from scapy.all import get_if_list
import json
import sys
import queue
import threading

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    from .data_reader import find_alert, read_alerts
    from .statistics import summarize
except ImportError:  # python dashboard/app.py
    from data_reader import find_alert, read_alerts
    from statistics import summarize
from ids.alert.alert import isolated_alert_output
from ids.capture.live_capture import LiveCapture
from ids.detection_pipeline import process_closed_session
from ids.detectors.behavior.behavior_engine import isolated_behavior_state

app = Flask(__name__)
app.secret_key = "ids-dashboard-local"
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024
ALLOWED_PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
OFFLINE_RESULTS_DIR = PROJECT_ROOT / "logs" / "offline_results"

RULES_PATH = PROJECT_ROOT / "config" / "rules.json"
_capture_lock = threading.Lock()
_live_capture = None
_capture_thread = None
_packet_worker = None
_capture_error = None


def _run_capture(capture):
    global _capture_error
    try:
        capture.start()
    except Exception as exc:
        _capture_error = str(exc)


def _consume_packets(capture, capture_thread):
    while capture_thread.is_alive() or not capture.packet_queue.empty():
        try:
            packet = capture.packet_queue.get(timeout=0.2)
        except queue.Empty:
            continue
        try:
            capture.process_packet(packet)
        finally:
            capture.packet_queue.task_done()

def offline_session_handler(session, rules):
    return process_closed_session(session, rules)


@app.get("/")
def dashboard():
    return render_template("dashboard.html")


@app.get("/api/alerts")
def alerts_api():
    try:
        alerts = read_alerts()
        return jsonify({"alerts": alerts, "stats": summarize(alerts)})
    except OSError as exc:
        app.logger.exception("Could not read the IDS alert log")
        return jsonify({"error": f"Không đọc được log alert: {exc}"}), 500


@app.get("/api/capture/status")
def capture_status_api():
    capture = _live_capture
    stats = capture.traffic_stats() if capture else {
        "running": False, "packets": 0, "packets_per_second": 0, "sessions": 0
    }
    stats["error"] = _capture_error
    return jsonify(stats)


@app.get("/api/capture/interfaces")
def capture_interfaces_api():
    try:
        return jsonify({"interfaces": get_if_list()})
    except Exception as exc:
        return jsonify({"interfaces": [], "error": str(exc)})


@app.post("/api/capture/start")
def capture_start_api():
    global _live_capture, _capture_thread, _packet_worker, _capture_error
    payload = request.get_json(silent=True) or {}
    interface = (payload.get("interface") or "").strip() or None
    bpf_filter = (payload.get("filter") or "tcp or udp or icmp").strip()
    with _capture_lock:
        if _capture_thread is not None and _capture_thread.is_alive():
            return jsonify({"error": "Live capture đang chạy."}), 409
        if _packet_worker is not None and _packet_worker.is_alive():
            return jsonify({"error": "Capture trước vẫn đang hoàn tất packet."}), 409
        _capture_error = None
        rules = json.loads(RULES_PATH.read_text(encoding="utf-8-sig"))
        capture = LiveCapture(
            interface=interface,
            bpf_filter=bpf_filter,
            on_session=lambda session: process_closed_session(session, rules),
            flush_on_stop=False,
        )
        _live_capture = capture
        _capture_thread = threading.Thread(target=_run_capture, args=(capture,), daemon=True)
        _capture_thread.start()
        _packet_worker = threading.Thread(
            target=_consume_packets, args=(capture, _capture_thread), daemon=True
        )
        _packet_worker.start()
    return jsonify({"ok": True, "interface": interface or "default", "filter": bpf_filter})


@app.post("/api/capture/stop")
def capture_stop_api():
    capture = _live_capture
    capture_thread = _capture_thread
    packet_worker = _packet_worker
    if capture is None or capture_thread is None:
        return jsonify({"ok": True, "running": False})
    capture.stop()
    capture_thread.join(timeout=15)
    if packet_worker is not None:
        packet_worker.join(timeout=15)
    if not capture_thread.is_alive() and not capture.packet_queue.unfinished_tasks:
        capture.flush()
    return jsonify({"ok": True, **capture.traffic_stats(), "error": _capture_error})


@app.get("/api/alerts/<alert_id>")
def alert_detail(alert_id):
    alert = find_alert(alert_id)
    if alert is None:
        return jsonify({"error": "Không tìm thấy alert"}), 404
    return jsonify(alert)


def _read_json_lines(path):
    if not path.exists():
        return []
    records = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        try:
            value = json.loads(line)
            if isinstance(value, dict):
                records.append(value)
        except json.JSONDecodeError:
            continue
    return records


@app.post("/pcap/analyze")
def analyze_pcap():
    uploaded = request.files.get("pcap")
    if uploaded is None or not uploaded.filename:
        flash("Bạn hãy chọn một file PCAP trước khi phân tích.", "error")
        return redirect(url_for("dashboard"))

    original_name = secure_filename(uploaded.filename)
    extension = Path(original_name).suffix.lower()
    if extension not in ALLOWED_PCAP_EXTENSIONS:
        flash("Định dạng chưa hỗ trợ. Hãy chọn .pcap, .pcapng hoặc .cap.", "error")
        return redirect(url_for("dashboard"))

    result_id = uuid4().hex
    OFFLINE_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    alert_path = OFFLINE_RESULTS_DIR / f"{result_id}.alerts.jsonl"
    result_path = OFFLINE_RESULTS_DIR / f"{result_id}.json"

    try:
        with TemporaryDirectory(prefix="ids-pcap-") as temp_dir:
            pcap_path = Path(temp_dir) / f"capture{extension}"
            uploaded.save(pcap_path)
            rules = json.loads(RULES_PATH.read_text(encoding="utf-8-sig"))
            capture = LiveCapture(
                on_session=lambda session: offline_session_handler(session, rules),
                enable_dedup=False,
                autosave_interval=0,
                output_file=Path(temp_dir) / "sessions.jsonl",
                output_session_counter_file=Path(temp_dir) / "session_counter.txt",
            )
            with isolated_alert_output(alert_path), isolated_behavior_state():
                sessions = capture.read_pcap(pcap_path)

        alerts = _read_json_lines(alert_path)
        result = {
            "result_id": result_id,
            "filename": original_name,
            "processed_at": datetime.now(timezone.utc).isoformat(),
            "packets": getattr(capture, "pcap_packets_read", 0),
            "sessions": len(sessions),
            "alert_count": len(alerts),
            "alerts": alerts,
        }
        result_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        return redirect(url_for("pcap_result", result_id=result_id))
    except Exception as exc:
        alert_path.unlink(missing_ok=True)
        return render_template("offline_result.html", error=str(exc), result=None), 500


@app.get("/pcap/result/<result_id>")
def pcap_result(result_id):
    if not result_id.isalnum() or len(result_id) != 32:
        return "Không tìm thấy kết quả phân tích.", 404
    result_path = OFFLINE_RESULTS_DIR / f"{result_id}.json"
    if not result_path.is_file():
        return "Không tìm thấy kết quả phân tích.", 404
    result = json.loads(result_path.read_text(encoding="utf-8"))
    return render_template("offline_result.html", result=result, error=None)


@app.errorhandler(413)
def upload_too_large(_error):
    return render_template("offline_result.html", error="File vượt quá giới hạn 500 MB.", result=None), 413


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
