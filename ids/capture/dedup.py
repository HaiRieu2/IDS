"""
Loai bo cac goi tin TRUNG LAP HOAN TOAN (giong het tung byte) den trong 1
khoang thoi gian ngan.
"""

import hashlib
import time
from collections import OrderedDict


class PacketDeduplicator:

    # Trong khoang thoi gian nay, 2 goi giong het byte duoc coi la 1 goi
    # bi bat trung, khong phai 2 goi that su khac nhau.
    WINDOW_SECONDS = 1.0

    def __init__(self):
        self._seen = OrderedDict()  # fingerprint (md5) -> timestamp

    def is_duplicate(self, packet_bytes, timestamp=None):
        if timestamp is None:
            timestamp = time.time()

        fingerprint = hashlib.md5(packet_bytes).hexdigest()

        self._prune(timestamp)

        if fingerprint in self._seen:
            return True

        self._seen[fingerprint] = timestamp
        return False

    def _prune(self, current_time):
        stale_keys = [
            fp for fp, ts in self._seen.items()
            if (current_time - ts) > self.WINDOW_SECONDS
        ]

        for fp in stale_keys:
            del self._seen[fp]
