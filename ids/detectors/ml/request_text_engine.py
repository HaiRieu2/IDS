"""Run the TF-IDF/Logistic Regression model on parsed HTTP requests."""

import logging
from pathlib import Path

import joblib

from config.path import MACHINE_LEARNING_DIR
from ids.alert.alert import alert_machine_learning

logger = logging.getLogger(__name__)
MODEL_PATH = MACHINE_LEARNING_DIR / "request_text_model.joblib"
_model = None
_model_mtime_ns = None
_warned_missing_model = False


def format_request_text(method, uri, body=""):
    """Match the dataset's `method + space + URI + space + body` format."""
    method = str(method or "").strip()
    uri = str(uri or "").strip()
    body = str(body or "").strip()
    if not method or not uri:
        return ""
    return f"{method} {uri} {body}".rstrip()


def _load_model():
    global _model, _model_mtime_ns, _warned_missing_model
    try:
        model_mtime_ns = Path(MODEL_PATH).stat().st_mtime_ns
    except OSError:
        if not _warned_missing_model:
            logger.warning(
                "HTTP request model not found at %s; train it with "
                "`python -m ml.request_text_training`.",
                MODEL_PATH,
            )
            _warned_missing_model = True
        return None

    if _model is None or model_mtime_ns != _model_mtime_ns:
        _model = joblib.load(MODEL_PATH)
        _model_mtime_ns = model_mtime_ns
    return _model


def request_text_engine(session):
    """Classify every parsed request in a closed session and alert on attacks."""
    http = session.get("http") or {}
    if not http.get("is_http"):
        return []

    model = _load_model()
    if model is None:
        return []

    network = session.get("network") or {}
    src_ip = network.get("src_ip", "")
    predictions = []
    for transaction in http.get("transactions", []):
        request = transaction.get("request") or {}
        request_text = format_request_text(
            request.get("method"), request.get("uri"), request.get("body")
        )
        if not request_text:
            continue

        prediction = str(model.predict([request_text])[0])
        confidence = None
        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba([request_text])[0]
            classes = list(model.named_steps["classifier"].classes_)
            confidence = float(probabilities[classes.index(prediction)])

        predictions.append({
            "request_text": request_text,
            "label": prediction,
            "confidence": confidence,
        })
        logger.info(
            "HTTP request model predicted %s (confidence=%s) for %s",
            prediction,
            f"{confidence:.3f}" if confidence is not None else "unavailable",
            src_ip,
        )
        if prediction.casefold() != "benign":
            alert_machine_learning(src_ip, prediction, confidence=confidence)

    return predictions
