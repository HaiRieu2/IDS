"""Shared ordered detection pipeline for live and offline flow analysis."""

import logging

from ids.detectors.behavior.behavior_engine import behavior_engine
from ids.detectors.signature.signature_engine import signature_engine
from ids.detectors.ml.machine_learning_engine import ml_engine
from ids.detectors.ml.request_text_engine import request_text_engine

logger = logging.getLogger(__name__)


def process_closed_session(session, rules):
    """Run behavior, signature, then ML; isolate failures between engines."""
    engines = (
        ("behavior", lambda: behavior_engine(session, rules)),
        ("signature", lambda: signature_engine(session, rules)),
        ("HTTP request machine learning", lambda: request_text_engine(session)),
        ("machine learning", lambda: ml_engine(session)),
    )
    errors = []
    for name, run in engines:
        try:
            run()
        except Exception:
            logger.exception("%s detector failed for session %s", name, session.get("session_id"))
            errors.append(name)
    return errors
