"""Dispatcher for payload-pattern detectors."""

from ids.detectors.signature.sqli_detector import detect_sqli
from ids.detectors.signature.xss_detector import detect_xss


def signature_engine(session, rules):
    """Run the SQL injection and XSS signatures against HTTP transactions."""
    detect_sqli(session, rules)
    detect_xss(session, rules)
