import copy
import math
from datetime import datetime, timezone

from .packet_parser import extract_http
from .tcp_reassembly import TCPStreamReassembler


class SessionBuilder:

    # Gioi han so transaction giu lai moi session (chong phinh bo nho
    # voi cac ket noi keep-alive dai)
    MAX_TRANSACTIONS = 100

    def __init__(self, session_timeout=120, max_session_duration=120):

        # session_id -> session dict
        self.sessions = {}

        self._active_by_flow = {}

        self.session_counter = 0

        # Sau 120s ma session khong nhan duoc goi tin moi -> dong session
        self.session_timeout = session_timeout

        # Cat cung session o 120s
        self.max_session_duration = max_session_duration

    # =================================================
    # Session ID / flow key
    # =================================================

    def _new_session_id(self):
        self.session_counter += 1

        return f"S{self.session_counter:03d}"

    def _get_flow_key(self, packet):
        """Khoa hai chieu: sap xep 2 endpoint de forward/backward cung 1 flow."""

        endpoint1 = (packet["src_ip"], packet["src_port"])
        endpoint2 = (packet["dst_ip"], packet["dst_port"])

        endpoints = sorted([endpoint1, endpoint2])

        return (endpoints[0], endpoints[1], packet["protocol"])

    # =================================================
    # Tao session
    # =================================================

    def _create_session(self, packet, forward_key=None, prev_session_id=None):

        session_id = self._new_session_id()

        timestamp = packet["timestamp"]

        session = {
            "session_id": session_id,

            # Dung de cat session tu cung flow khi qua 120s (max_session_duration)
            "_prev_session_id": prev_session_id,
            "_next_session_id": None,

            "timestamp": {
                "start": timestamp,
                "end": timestamp,
                "duration": 0,
            },

            "network": {
                "src_ip": packet["src_ip"],
                "dst_ip": packet["dst_ip"],

                "src_port": packet["src_port"],
                "dst_port": packet["dst_port"],

                "protocol": packet["protocol"],
            },

            "flag": {
                "syn": 0,
                "syn_ack": 0,
                "ack": 0,
                "fin": 0,
                "rst": 0,
                "psh": 0,
                "urg": 0,
                "ack_count": 0,
            },

            "icmp": {
                "type": packet.get("icmp_type"),
                "code": packet.get("icmp_code"),
                "count": 0,
            },

            "packets": {
                "total": 0,

                "forward": {"count": 0, "bytes": 0},
                "backward": {"count": 0, "bytes": 0},
            },

            "flow": {
                "total_bytes": 0,
                "bytes_per_second": 0.0,
                "packets_per_second": 0.0,

                "fwd_packet_per_second": 0.0,
                "bwd_packet_per_second": 0.0,

                #forward: lay o goi dau tien
                #backward:lay o goi cuoi
                "init_win_bytes_forward": 0.0,
                "init_win_bytes_backward": 0.0,

                "packet_length": {
                    "min": 0.0,
                    "max": 0.0,
                    "mean": 0,
                    "std": 0,
                },

                "iat": {
                    "mean": 0,
                    "std": 0,
                    "min": 0.0,
                    "max": 0.0,
                },
            },

            "http": {
                "is_http": False,
                "transactions": [],
            },

            "connection": {
                "request_count": 0,
                "response_count": 0,
                "status_code": 0,
                "_state": "active",  # active | closed | timed_out
            },

            # ---- Internal (khong xuat ra get_sessions()) ----
            "_forward_key": forward_key or (packet["src_ip"], packet["src_port"]),
            "_last_seen": timestamp,
            "_fin_seen": set(),
            "_closed": False,

            # Thong ke tang dan (Welford) - thay cho viec luu toan bo
            "_len_count": 0,
            "_len_mean": 0.0,
            "_len_m2": 0.0,
            "_len_min": None,
            "_len_max": None,

            "_iat_count": 0,
            "_iat_mean": 0.0,
            "_iat_m2": 0.0,
            "_iat_min": None,
            "_iat_max": None,

            "_prev_timestamp": None,

            # Ghep lai TCP payload theo tung chieu truoc khi parse HTTP,
            # tranh mat du lieu khi 1 request/response bi cat thanh nhieu
            # goi
            "_tcp_stream": TCPStreamReassembler(),
        }

        return session

    # =================================================
    # Update tung phan
    # =================================================

    def _update_tcp(self, session, packet):

        flag = session["flag"]

        flag["syn"] += packet["syn"]
        flag["syn_ack"] += packet["syn_ack"]
        flag["ack"] += packet["ack"]
        flag["fin"] += packet["fin"]
        flag["rst"] += packet["rst"]
        flag["psh"] += packet["psh"]
        flag["urg"] += packet.get("urg", 0)

        if packet["ack"]:
            flag["ack_count"] += 1

        # Trang thai ket noi

        if packet["rst"]:
            session["_closed"] = True
            session["connection"]["_state"] = "closed"

        if packet["fin"]:

            direction = (packet["src_ip"], packet["src_port"])

            session["_fin_seen"].add(direction)

            # Hoan tat khi ca 2 chieu deu gui FIN
            if len(session["_fin_seen"]) >= 2:
                session["_closed"] = True
                session["connection"]["_state"] = "closed"

    def _update_icmp(self, session, packet):

        session["icmp"]["count"] += 1

        # Giu type/code cua goi dau tien neu chua co
        if session["icmp"]["type"] is None:
            session["icmp"]["type"] = packet.get("icmp_type")
            session["icmp"]["code"] = packet.get("icmp_code")

    @staticmethod
    def _get_direction(session, packet):

        packet_direction = (packet["src_ip"], packet["src_port"])

        if packet_direction == session["_forward_key"]:
            return "forward"

        return "backward"

    def _update_direction(self, session, direction, packet):

        session["packets"][direction]["count"] += 1
        session["packets"][direction]["bytes"] += packet["packet_length"]

    def _update_init_window(self, session, direction, packet):
        
        if packet["protocol"] != "TCP":
            return

        if direction == "forward":
            if session["flow"]["init_win_bytes_forward"] is None:
                session["flow"]["init_win_bytes_forward"] = packet.get("window", 0)
        else:
            session["flow"]["init_win_bytes_backward"] = packet.get("window", 0)

    def _feed_tcp_stream(self, session, direction, packet):
        """
        Day raw payload cua goi tin vao buffer ghep luong TCP cua session.
        Voi moi HTTP message da HOAN CHINH (co the > 1 neu keep-alive),
        parse va cap nhat vao session['http'].
        """

        payload = packet.get("payload")

        if not payload:
            return

        complete_messages = session["_tcp_stream"].feed(direction, payload)

        for message_bytes in complete_messages:
            http_result = extract_http(message_bytes)

            if http_result["is_http"]:
                self._apply_http_result(session, http_result)

    def _apply_http_result(self, session, http):

        session["http"]["is_http"] = True

        transactions = session["http"]["transactions"]

        incoming = http["transactions"][0]

        if http.get("type") == "request":

            session["connection"]["request_count"] += 1

            transactions.append(copy.deepcopy(incoming))

        elif http.get("type") == "response":

            session["connection"]["response_count"] += 1

            status_code = incoming["response"]["status_code"]

            session["connection"]["status_code"] = status_code

            # Gan response vao request gan nhat con dang cho
            for transaction in reversed(transactions):
                if transaction["response"]["status_code"] == 0:
                    transaction["response"] = copy.deepcopy(
                        incoming["response"]
                    )
                    break
            else:
                # Response khong khop request nao (vd. bat giua chung flow)
                transactions.append(copy.deepcopy(incoming))

        # Gioi han bo nho
        if len(transactions) > self.MAX_TRANSACTIONS:
            del transactions[: len(transactions) - self.MAX_TRANSACTIONS]

    # =================================================
    # Add packet
    # =================================================

    def add_packet(self, packet):

        flow_key = self._get_flow_key(packet)

        timestamp = packet["timestamp"]

        session = self._get_or_create_session(flow_key, timestamp, packet)

        # --- Timestamp / duration ---

        session["timestamp"]["end"] = timestamp
        session["_last_seen"] = timestamp

        duration = timestamp - session["timestamp"]["start"]

        session["timestamp"]["duration"] = max(0, duration)

        # --- Counters ---

        session["packets"]["total"] += 1
        session["flow"]["total_bytes"] += packet["packet_length"]

        # --- Thong ke tang dan ---

        self._accumulate_length(session, packet["packet_length"])
        self._accumulate_iat(session, timestamp)

        # --- Direction ---

        direction = self._get_direction(session, packet)

        self._update_direction(session, direction, packet)
        self._update_init_window(session, direction, packet)

        # --- Theo giao thuc ---

        if packet["protocol"] == "TCP":
            self._update_tcp(session, packet)

        elif packet["protocol"] in ("ICMP", "ICMPv6"):
            self._update_icmp(session, packet)

        # --- HTTP (ghep lai theo luong TCP truoc khi parse) ---

        if packet["protocol"] == "TCP":
            self._feed_tcp_stream(session, direction, packet)

        # --- Flow stats ---

        self._update_statistics(session)

        return session

    def _get_or_create_session(self, flow_key, timestamp, packet):

        session_id = self._active_by_flow.get(flow_key)

        session = self.sessions.get(session_id) if session_id else None

        is_idle_timeout = (
            session is not None
            and not session["_closed"]
            and (timestamp - session["_last_seen"]) > self.session_timeout
        )

        is_duration_exceeded = (
            session is not None
            and not session["_closed"]
            and (timestamp - session["timestamp"]["start"]) >= self.max_session_duration
        )

        needs_new_session = (
            session is None
            or session["_closed"]
            or is_idle_timeout
            or is_duration_exceeded
        )

        if needs_new_session:

            forward_key = None
            prev_session_id = None

            if session is not None and not session["_closed"]:

                if is_duration_exceeded:
                    session["connection"]["_state"] = "rotated"
                    forward_key = session["_forward_key"]
                    prev_session_id = session["session_id"]
                else:
                    session["connection"]["_state"] = "timed_out"

                session["_closed"] = True

            new_session = self._create_session(
                packet, forward_key=forward_key, prev_session_id=prev_session_id
            )

            if prev_session_id is not None:
                session["next_session_id"] = new_session["session_id"]

            session = new_session

            self.sessions[session["session_id"]] = session
            self._active_by_flow[flow_key] = session["session_id"]

        return session

    # =================================================
    # Thong ke (Welford)
    # =================================================

    @staticmethod
    def _welford(count, mean, m2, value):

        count += 1
        delta = value - mean
        mean += delta / count
        m2 += delta * (value - mean)

        return count, mean, m2

    def _accumulate_length(self, session, length):

        session["_len_count"], session["_len_mean"], session["_len_m2"] = (
            self._welford(
                session["_len_count"],
                session["_len_mean"],
                session["_len_m2"],
                length,
            )
        )

        if session["_len_min"] is None or length < session["_len_min"]:
            session["_len_min"] = length

        if session["_len_max"] is None or length > session["_len_max"]:
            session["_len_max"] = length

    def _accumulate_iat(self, session, timestamp):

        previous = session["_prev_timestamp"]

        session["_prev_timestamp"] = timestamp

        if previous is None:
            return

        iat = timestamp - previous

        session["_iat_count"], session["_iat_mean"], session["_iat_m2"] = (
            self._welford(
                session["_iat_count"],
                session["_iat_mean"],
                session["_iat_m2"],
                iat,
            )
        )

        if session["_iat_min"] is None or iat < session["_iat_min"]:
            session["_iat_min"] = iat

        if session["_iat_max"] is None or iat > session["_iat_max"]:
            session["_iat_max"] = iat

    def _update_statistics(self, session):

        duration = session["timestamp"]["duration"]

        total_bytes = session["flow"]["total_bytes"]
        total_packets = session["packets"]["total"]

        fwd_packets = session["packets"]["forward"]["count"]
        bwd_packets = session["packets"]["backward"]["count"]

        if duration > 0:
            session["flow"]["bytes_per_second"] = total_bytes / duration
            session["flow"]["packets_per_second"] = total_packets / duration
            session["flow"]["fwd_packet_per_second"] = fwd_packets / duration
            session["flow"]["bwd_packet_per_second"] = bwd_packets / duration
        else:
            session["flow"]["bytes_per_second"] = 0
            session["flow"]["packets_per_second"] = 0
            session["flow"]["fwd_packet_per_second"] = 0
            session["flow"]["bwd_packet_per_second"] = 0

        # Packet length

        if session["_len_count"] > 0:
            session["flow"]["packet_length"] = {
                "min": session["_len_min"],
                "max": session["_len_max"],
                "mean": session["_len_mean"],
                "std": math.sqrt(session["_len_m2"] / session["_len_count"]),
            }

        # IAT

        if session["_iat_count"] > 0:
            session["flow"]["iat"] = {
                "mean": session["_iat_mean"],
                "std": math.sqrt(session["_iat_m2"] / session["_iat_count"]),
                "min": session["_iat_min"],
                "max": session["_iat_max"],
            }

    # =================================================
    # Dong / lay / xoa session
    # =================================================

    def close_expired_sessions(self, current_time=None):

        if current_time is None:
            current_time = datetime.now(timezone.utc).timestamp()

        expired_ids = []

        for session_id, session in self.sessions.items():

            if session["_closed"]:
                continue

            if (current_time - session["_last_seen"]) > self.session_timeout:

                session["_closed"] = True
                session["connection"]["_state"] = "timed_out"

                expired_ids.append(session_id)

        return expired_ids

    def close_all_sessions(self):
        """Dong toan bo session dang mo (goi khi dung capture)."""

        closed_ids = []

        for session_id, session in self.sessions.items():

            if session["_closed"]:
                continue

            session["_closed"] = True
            session["connection"]["_state"] = "closed"

            closed_ids.append(session_id)

        return closed_ids

    def get_sessions(self, only_closed=False):

        result = []

        for session in self.sessions.values():

            if only_closed and not session["_closed"]:
                continue

            result.append(self._clean(session))

        return result

    @staticmethod
    def _clean(session):
        
        return copy.deepcopy(
            {
                key: value
                for key, value in session.items()
                if not key.startswith("_")
            }
        )

    def snapshot(self, session):
        """Ban copy doc lap, san sang json.dumps() cua mot session."""
        return self._clean(session)

    def clear_closed_sessions(self):

        closed_ids = {
            session_id
            for session_id, session in self.sessions.items()
            if session["_closed"]
        }

        for session_id in closed_ids:
            del self.sessions[session_id]

        stale_flow_keys = [
            flow_key
            for flow_key, sid in self._active_by_flow.items()
            if sid in closed_ids
        ]

        for flow_key in stale_flow_keys:
            del self._active_by_flow[flow_key]

        return len(closed_ids)
