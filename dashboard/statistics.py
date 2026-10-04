from collections import Counter
from datetime import datetime, timezone, timedelta


def summarize(alerts):
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=24)
    recent = []
    for alert in alerts:
        try:
            stamp = datetime.fromisoformat(str(alert.get("timestamp", "")).replace("Z", "+00:00"))
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=timezone.utc)
            if stamp >= cutoff:
                recent.append(alert)
        except (ValueError, TypeError):
            continue
    return {
        "total": len(alerts),
        "today": len(recent),
        "high": sum(str(a.get("severity", "")).lower() in {"critical", "high"} for a in recent),
        "severity": dict(Counter(str(a.get("severity", "unknown")).lower() for a in recent)),
    }
