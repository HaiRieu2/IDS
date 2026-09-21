import re
import json
from .sqli_detector import detect_sqli
from .xss_detector import detect_xss
def signature_engine(session):
    """
    Hàm này sẽ kiểm tra các session để phát hiện các mẫu tấn công SQL Injection và XSS.
    """
    detect_sqli(session)
    
    detect_xss(session)

    return


    