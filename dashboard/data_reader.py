from pathlib import Path
import json

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ALERTS_FILE = PROJECT_ROOT / "logs" / "alerts.json"


def read_alerts():
    """Read alerts stored as JSON Lines, or a JSON array/object."""
    if not ALERTS_FILE.exists():
        return []
    raw = ALERTS_FILE.read_text(encoding="utf-8-sig").strip()
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            records = parsed
        elif isinstance(parsed, dict):
            records = parsed.get("alerts", [parsed])
        else:
            records = []
    except json.JSONDecodeError:
        records = []
        for line in raw.splitlines():
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    records.append(item)
            except json.JSONDecodeError:
                continue
    return sorted(records, key=lambda a: str(a.get("timestamp", "")), reverse=True)


def find_alert(alert_id):
    return next((a for a in read_alerts() if str(a.get("alert_id", "")) == alert_id), None)

