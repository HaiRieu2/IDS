"""
Ghep lai (reassemble) cac IP fragment cua cung 1 goi tin ban dau, truoc khi
dua cho parse_packet() xu ly.
"""

import time
from scapy.all import IP


class IPDefragmenter:

    # Qua thoi gian nay ma 1 nhom fragment van chua nhan du -> xoa,
    # tranh ro ri bo nho khi bi tan cong bang fragment co y khong gui du
    FRAGMENT_TIMEOUT = 30

    def __init__(self):
        # key -> {"parts": {offset_bytes: bytes}, "total_length": int|None,
        #         "first_ip": IP|None, "last_seen": float}
        self._groups = {}

    @staticmethod
    def _group_key(ip_layer):
        return (ip_layer.src, ip_layer.dst, ip_layer.proto, ip_layer.id)

    def process(self, packet):
        """
        Tra ve:
          - packet goc, neu khong bi phan manh (truong hop thong thuong,
            khong ton chi phi xu ly them)
          - 1 packet da duoc ghep day du, khi vua nhan fragment giup hoan
            tat 1 nhom
          - None, neu day la 1 fragment nhung nhom chua du de ghep (phai
            cho them fragment khac)
        """
        if IP not in packet:
            return packet  # Khong phai IPv4 -> khong xu ly o day

        ip_layer = packet[IP]

        is_fragment = bool(ip_layer.flags.MF) or ip_layer.frag > 0

        if not is_fragment:
            return packet

        key = self._group_key(ip_layer)
        group = self._groups.setdefault(
            key, {"parts": {}, "total_length": None, "first_ip": None}
        )

        offset_bytes = ip_layer.frag * 8
        payload_bytes = bytes(ip_layer.payload)

        group["parts"][offset_bytes] = payload_bytes
        group["last_seen"] = time.time()

        if offset_bytes == 0:
            group["first_ip"] = ip_layer

        if not ip_layer.flags.MF:
            # Day la fragment cuoi cung -> biet duoc tong do dai that su
            group["total_length"] = offset_bytes + len(payload_bytes)

        reassembled = self._try_build(group)

        if reassembled is not None:
            del self._groups[key]
            return reassembled

        return None

    @staticmethod
    def _try_build(group):
        total_length = group["total_length"]
        first_ip = group["first_ip"]

        if total_length is None or first_ip is None:
            return None  # Chua co fragment dau va/hoac fragment cuoi

        buffer = bytearray(total_length)
        covered = bytearray(total_length)

        for offset, data in group["parts"].items():
            end = offset + len(data)
            if end > total_length:
                data = data[: total_length - offset]
                end = total_length
            buffer[offset:end] = data
            for i in range(offset, end):
                covered[i] = 1

        if not all(covered):
            return None  # Con thieu 1 doan o giua -> cho them fragment

        # Dung header cua fragment dau (offset 0) + toan bo payload da ghep,
        # roi parse lai bang IP() de scapy tu dissect dung layer TCP/UDP/ICMP
        header_len = first_ip.ihl * 4
        header_bytes = bytes(first_ip)[:header_len]

        try:
            provisional = IP(header_bytes + bytes(buffer))
        except Exception:
            return None

        # Xoa danh dau fragment + xoa len/chksum de scapy tu tinh lai cho
        # dung voi kich thuoc thuc su sau khi ghep (khong con la fragment 0
        # voi len rieng cua no nua)
        provisional[IP].flags = 0
        provisional[IP].frag = 0
        provisional[IP].len = None
        provisional[IP].chksum = None

        try:
            rebuilt = IP(bytes(provisional))
        except Exception:
            return None

        return rebuilt

    def cleanup(self, current_time=None):
        """Xoa cac nhom fragment qua han chua ghep xong (chong ro ri bo nho)."""
        if current_time is None:
            current_time = time.time()

        stale_keys = [
            key
            for key, group in self._groups.items()
            if (current_time - group.get("last_seen", current_time)) > self.FRAGMENT_TIMEOUT
        ]

        for key in stale_keys:
            del self._groups[key]

        return len(stale_keys)
