import copy
import math
import threading
from functools import wraps
from datetime import datetime, timezone

from .packet_parser import extract_http
from .tcp_reassembly import TCPStreamReassembler


def _synchronized(method):
    @wraps(method)
    def wrapped(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    return wrapped


class SessionBuilder:
    """Group parsed packets into bidirectional flows and compute CIC features."""

    # Gioi han so transaction giu lai moi session (chong phinh bo nho
    # voi cac ket noi keep-alive dai)
    MAX_TRANSACTIONS = 1000
    CIC_ACTIVE_IDLE_TIMEOUT_US = 5_000_000

    def __init__(self, session_timeout=120, max_session_duration=120):

        # session_id -> session dict
        self.sessions = {}
        self._lock = threading.RLock()

        self._active_by_flow = {}

        # Sessions closed while a packet arrives (flow rotation or an idle
        # timeout) must still be delivered to LiveCapture's detector callback.
        # Keep clean snapshots here because clear_closed_sessions may remove
        # their mutable records during the next autosave cycle.
        self._pending_closed_sessions = []

        self.session_counter = 0

        # Sau 120s ma session khong nhan duoc goi tin moi -> dong session
        self.session_timeout = session_timeout

        # Cat cung session o 120s
        self.max_session_duration = max_session_duration

    @staticmethod
    def _empty_stats():
        """Create a running sample-statistics accumulator."""
        return {"count": 0, "total": 0.0, "mean": 0.0, "m2": 0.0,
                "min": None, "max": None}

    @staticmethod
    def _add_stat(stats, value):
        """Update count, sum, min/max, mean, and variance in one pass."""
        value = float(value)
        stats["count"] += 1
        stats["total"] += value
        delta = value - stats["mean"]
        stats["mean"] += delta / stats["count"]
        stats["m2"] += delta * (value - stats["mean"])
        if stats["min"] is None or value < stats["min"]:
            stats["min"] = value
        if stats["max"] is None or value > stats["max"]:
            stats["max"] = value

    @staticmethod
    def _stat_std(stats):
        """CICFlowMeter SummaryStatistics uses sample standard deviation."""
        if stats["count"] < 2:
            return 0.0
        return math.sqrt(max(0.0, stats["m2"]) / (stats["count"] - 1))

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
        cic_timestamp_us = packet.get(
            "cic_timestamp_us", int(round(timestamp * 1_000_000))
        )

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
                "cwr": 0,
                "ece": 0,
            },

            "icmp": {
                "type": packet.get("icmp_type"),
                "code": packet.get("icmp_code"),
                "count": 0,
            },

            "packets": {
                "total": 0,

                "forward": {"count": 0, "bytes": 0, "payload_bytes": 0},
                "backward": {"count": 0, "bytes": 0, "payload_bytes": 0},
            },

            "flow": {
                "total_bytes": 0,
                "bytes_per_second": 0.0,
                # CICFlowMeter-compatible byte features are maintained
                # separately from full IP packet bytes used by the dashboard.
                "cic_total_payload_bytes": 0,
                "cic_bytes_per_second": 0.0,
                "cic_duration_us": 0,
                "packets_per_second": 0.0,

                "fwd_packet_per_second": 0.0,
                "bwd_packet_per_second": 0.0,

                #forward: lay o goi dau tien
                #backward:lay o goi cuoi
                "init_win_bytes_forward": None,
                "init_win_bytes_backward": None,

                # Additional CICFlowMeter directional and activity features.
                "fwd_packet_length": {"min": 0, "max": 0, "mean": 0, "std": 0},
                "bwd_packet_length": {"min": 0, "max": 0, "mean": 0, "std": 0},
                "fwd_iat": {"total": 0, "mean": 0, "std": 0, "max": 0, "min": 0},
                "bwd_iat": {"total": 0, "mean": 0, "std": 0, "max": 0, "min": 0},
                "fwd_header_length": 0,
                "bwd_header_length": 0,
                "fwd_psh_flags": 0,
                "bwd_psh_flags": 0,
                "fwd_urg_flags": 0,
                "bwd_urg_flags": 0,
                "cwr_flag_count": 0,
                "ece_flag_count": 0,
                "down_up_ratio": 0,
                "average_packet_size": 0,
                "avg_fwd_segment_size": 0,
                "avg_bwd_segment_size": 0,
                "packet_length_variance": 0,
                "act_data_pkt_fwd": 0,
                "min_seg_size_forward": 0,
                "active": {"mean": 0, "std": 0, "max": 0, "min": 0},
                "idle": {"mean": 0, "std": 0, "max": 0, "min": 0},

                "packet_length": {
                    "min": 0.0,
                    "max": 0.0,
                    "mean": 0,
                    "std": 0,
                },

                "cic_packet_length": {
                    "min": 0.0,
                    "max": 0.0,
                    "mean": 0.0,
                    "std": 0.0,
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

            "_cic_len_count": 0,
            "_cic_len_mean": 0.0,
            "_cic_len_m2": 0.0,
            "_cic_len_min": None,
            "_cic_len_max": None,

            "_cic_fwd_len_stats": self._empty_stats(),
            "_cic_bwd_len_stats": self._empty_stats(),
            "_cic_fwd_iat_stats": self._empty_stats(),
            "_cic_bwd_iat_stats": self._empty_stats(),
            "_cic_active_stats": self._empty_stats(),
            "_cic_idle_stats": self._empty_stats(),
            "_cic_prev_fwd_us": None,
            "_cic_prev_bwd_us": None,
            "_cic_active_start_us": cic_timestamp_us,
            "_cic_active_end_us": cic_timestamp_us,
            "_cic_first_payload_length": 0,
            "_cic_min_forward_header_length": None,

            "_iat_count": 0,
            "_iat_mean": 0.0,
            "_iat_m2": 0.0,
            "_iat_min": None,
            "_iat_max": None,

            "_prev_timestamp": None,
            "_cic_start_us": cic_timestamp_us,
            "_cic_last_us": cic_timestamp_us,

            # Ghep lai TCP payload theo tung chieu truoc khi parse HTTP,
            # tranh mat du lieu khi 1 request/response bi cat thanh nhieu
            # goi
            "_tcp_stream": TCPStreamReassembler(),
        }

        return session

    # =================================================
    # Update tung phan
    # =================================================

    def _update_tcp(self, session, packet, direction):

        flag = session["flag"]

        flag["syn"] += packet["syn"]
        flag["syn_ack"] += packet["syn_ack"]
        flag["ack"] += packet["ack"]
        flag["fin"] += packet["fin"]
        flag["rst"] += packet["rst"]
        flag["psh"] += packet["psh"]
        flag["urg"] += packet.get("urg", 0)
        flag["cwr"] += packet.get("cwr", 0)
        flag["ece"] += packet.get("ece", 0)

        suffix = "fwd" if direction == "forward" else "bwd"
        session["flow"][f"{suffix}_psh_flags"] += packet.get("psh", 0)
        session["flow"][f"{suffix}_urg_flags"] += packet.get("urg", 0)
        session["flow"]["cwr_flag_count"] += packet.get("cwr", 0)
        session["flow"]["ece_flag_count"] += packet.get("ece", 0)

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
        session["packets"][direction]["payload_bytes"] += packet.get("payload_length", 0)

        is_forward = direction == "forward"
        stats_key = "_cic_fwd_len_stats" if is_forward else "_cic_bwd_len_stats"
        self._add_stat(session[stats_key], packet.get("payload_length", 0))

        header_length = int(packet.get("transport_header_length", 0) or 0)
        header_key = "fwd_header_length" if is_forward else "bwd_header_length"
        session["flow"][header_key] += header_length

        if is_forward:
            current_min = session["_cic_min_forward_header_length"]
            if current_min is None or header_length < current_min:
                session["_cic_min_forward_header_length"] = header_length
            # CICFlowMeter increments this for forward data packets in addPacket,
            # not for the firstPacket constructor call.
            if (session["packets"]["total"] > 1
                    and packet.get("payload_length", 0) >= 1):
                session["flow"]["act_data_pkt_fwd"] += 1

        previous_key = "_cic_prev_fwd_us" if is_forward else "_cic_prev_bwd_us"
        iat_key = "_cic_fwd_iat_stats" if is_forward else "_cic_bwd_iat_stats"
        current_us = int(packet.get(
            "cic_timestamp_us",
            round(float(packet.get("timestamp", 0)) * 1_000_000),
        ))
        previous_us = session[previous_key]
        if previous_us is not None:
            self._add_stat(session[iat_key], max(0, current_us - previous_us))
        session[previous_key] = current_us

    def _update_active_idle(self, session, timestamp_us):
        """Track CICFlowMeter active and idle spans using its 5 s boundary."""
        previous_end = session["_cic_active_end_us"]
        if timestamp_us - previous_end > self.CIC_ACTIVE_IDLE_TIMEOUT_US:
            active_duration = previous_end - session["_cic_active_start_us"]
            if active_duration > 0:
                self._add_stat(session["_cic_active_stats"], active_duration)
            self._add_stat(session["_cic_idle_stats"], timestamp_us - previous_end)
            session["_cic_active_start_us"] = timestamp_us
            session["_cic_active_end_us"] = timestamp_us
        else:
            session["_cic_active_end_us"] = timestamp_us

    def _update_init_window(self, session, direction, packet):
        
        if packet["protocol"] != "TCP":
            return

        if direction == "forward":
            if session["flow"]["init_win_bytes_forward"] is None:
                session["flow"]["init_win_bytes_forward"] = packet.get("window", 0)
        else:
            # CICFlowMeter's BasicFlow updates the backward window on each
            # backward packet (despite the feature's "initial" name).
            session["flow"]["init_win_bytes_backward"] = packet.get("window", 0)

    def _feed_tcp_stream(self, session, direction, packet):
        """
        Day raw payload cua goi tin vao buffer ghep luong TCP cua session.
        Voi moi HTTP message da HOAN CHINH (co the > 1 neu keep-alive),
        parse va cap nhat vao session['http'].
        """

        payload = packet.get("payload")

        if not payload:
            if packet.get("fin") or packet.get("rst"):
                for message_bytes in session["_tcp_stream"].flush(direction):
                    http_result = extract_http(message_bytes)
                    if http_result["is_http"]:
                        self._apply_http_result(session, http_result)
            return

        complete_messages = session["_tcp_stream"].feed(
            direction, payload, packet.get("tcp_seq")
        )

        # HTTP response khong co Content-Length duoc dong bang FIN theo chuan.
        # Giai phong phan byte close-delimited tai day de khong mat message.
        if packet.get("fin") or packet.get("rst"):
            complete_messages.extend(session["_tcp_stream"].flush(direction))

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

    @_synchronized
    def add_packet(self, packet):
        """Add one normalized packet and return its mutable flow record."""

        flow_key = self._get_flow_key(packet)

        timestamp = packet["timestamp"]
        cic_timestamp_us = packet.get(
            "cic_timestamp_us", int(round(timestamp * 1_000_000))
        )

        session = self._get_or_create_session(flow_key, timestamp, packet)

        # CICFlowMeter's BasicFlow.firstPacket adds the first packet payload
        # twice to flowLengthStats (once before direction handling, once in
        # the forward/backward branch). Its packet totals and byte totals are
        # still counted once. Preserve that training-time quirk only in the
        # CIC packet-length statistics so live vectors match CIC CSVs.
        is_first_packet = session["packets"]["total"] == 0

        # --- Timestamp / duration ---

        session["timestamp"]["end"] = timestamp
        session["_last_seen"] = timestamp

        # CICFlowMeter calculates duration and IAT from integer capture
        # timestamps in microseconds, rather than subtracting float seconds.
        session["_cic_last_us"] = cic_timestamp_us
        duration_us = max(0, cic_timestamp_us - session["_cic_start_us"])
        duration = duration_us / 1_000_000

        session["timestamp"]["duration"] = max(0, duration)

        # --- Counters ---

        session["packets"]["total"] += 1
        session["flow"]["total_bytes"] += packet["packet_length"]
        session["flow"]["cic_total_payload_bytes"] += packet.get("payload_length", 0)

        if is_first_packet:
            session["_cic_first_payload_length"] = packet.get("payload_length", 0)

        # --- Thong ke tang dan ---

        self._accumulate_length(session, packet["packet_length"])
        self._accumulate_cic_length(session, packet.get("payload_length", 0))
        if is_first_packet:
            self._accumulate_cic_length(session, packet.get("payload_length", 0))
        self._accumulate_iat(session, cic_timestamp_us)

        # --- Direction ---

        direction = self._get_direction(session, packet)

        # CICFlowMeter updates active/idle stats before addPacket(), except
        # when the current TCP packet terminates the flow (RST or second FIN).
        source = (packet["src_ip"], packet["src_port"])
        closes_tcp_flow = packet["protocol"] == "TCP" and (
            packet.get("rst", 0)
            or (packet.get("fin", 0) and source not in session["_fin_seen"]
                and bool(session["_fin_seen"]))
        )
        if not is_first_packet and not closes_tcp_flow:
            self._update_active_idle(session, cic_timestamp_us)

        self._update_direction(session, direction, packet)
        self._update_init_window(session, direction, packet)

        # --- Theo giao thuc ---

        if packet["protocol"] == "TCP":
            self._update_tcp(session, packet, direction)

        elif packet["protocol"] in ("ICMP", "ICMPv6"):
            self._update_icmp(session, packet)

        # --- HTTP (ghep lai theo luong TCP truoc khi parse) ---

        if packet["protocol"] == "TCP":
            self._feed_tcp_stream(session, direction, packet)

        # --- Flow stats ---

        self._update_statistics(session)

        return session

    def _get_or_create_session(self, flow_key, timestamp, packet):
        """Reuse an active flow or start a new one after close/timeout/rotation."""

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
            and (timestamp - session["timestamp"]["start"]) > self.max_session_duration
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
                self._pending_closed_sessions.append(self._clean(session))

            new_session = self._create_session(
                packet, forward_key=forward_key, prev_session_id=prev_session_id
            )

            if prev_session_id is not None:
                session["_next_session_id"] = new_session["session_id"]

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

    def _accumulate_cic_length(self, session, length):
        """Accumulate transport-payload lengths used by CICFlowMeter ML fields."""
        (
            session["_cic_len_count"],
            session["_cic_len_mean"],
            session["_cic_len_m2"],
        ) = self._welford(
            session["_cic_len_count"],
            session["_cic_len_mean"],
            session["_cic_len_m2"],
            length,
        )
        if session["_cic_len_min"] is None or length < session["_cic_len_min"]:
            session["_cic_len_min"] = length
        if session["_cic_len_max"] is None or length > session["_cic_len_max"]:
            session["_cic_len_max"] = length

    def _accumulate_iat(self, session, timestamp_us):

        previous = session["_prev_timestamp"]

        session["_prev_timestamp"] = timestamp_us

        if previous is None:
            return

        iat = timestamp_us - previous

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
        """Recompute rate features and publish accumulated length/IAT statistics."""

        duration = session["timestamp"]["duration"]
        duration_us = max(0, session["_cic_last_us"] - session["_cic_start_us"])
        session["flow"]["cic_duration_us"] = duration_us

        total_bytes = session["flow"]["total_bytes"]
        total_packets = session["packets"]["total"]

        fwd_packets = session["packets"]["forward"]["count"]
        bwd_packets = session["packets"]["backward"]["count"]

        if duration_us > 0:
            # CICFlowMeter's rates are per second; the denominator is the
            # flow duration in microseconds divided by 1,000,000.
            cic_duration_seconds = duration_us / 1_000_000
            session["flow"]["bytes_per_second"] = total_bytes / duration
            session["flow"]["cic_bytes_per_second"] = (
                session["flow"]["cic_total_payload_bytes"] / cic_duration_seconds
            )
            session["flow"]["packets_per_second"] = total_packets / cic_duration_seconds
            session["flow"]["fwd_packet_per_second"] = fwd_packets / cic_duration_seconds
            session["flow"]["bwd_packet_per_second"] = bwd_packets / cic_duration_seconds
        else:
            session["flow"]["bytes_per_second"] = 0
            session["flow"]["cic_bytes_per_second"] = 0
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

        if session["_cic_len_count"] > 0:
            count = session["_cic_len_count"]
            # CICFlowMeter uses sample standard deviation (n - 1).
            sample_std = (
                math.sqrt(session["_cic_len_m2"] / (count - 1))
                if count > 1 else 0.0
            )
            session["flow"]["cic_packet_length"] = {
                "min": session["_cic_len_min"],
                "max": session["_cic_len_max"],
                "mean": session["_cic_len_mean"],
                "std": sample_std,
            }

        # IAT

        if session["_iat_count"] > 0:
            iat_count = session["_iat_count"]
            session["flow"]["iat"] = {
                # These are already in CICFlowMeter microseconds.
                "mean": session["_iat_mean"],
                "std": (
                    math.sqrt(session["_iat_m2"] / (iat_count - 1))
                    if iat_count > 1 else 0.0
                ),
                "min": session["_iat_min"],
                "max": session["_iat_max"],
            }

        # Direction-specific packet-size distributions.
        for stats_key, flow_key in (
            ("_cic_fwd_len_stats", "fwd_packet_length"),
            ("_cic_bwd_len_stats", "bwd_packet_length"),
        ):
            stats = session[stats_key]
            session["flow"][flow_key] = {
                "min": stats["min"] if stats["count"] else 0,
                "max": stats["max"] if stats["count"] else 0,
                "mean": stats["mean"] if stats["count"] else 0,
                "std": self._stat_std(stats),
            }

        # Direction-specific inter-arrival times are also in microseconds.
        for stats_key, flow_key in (
            ("_cic_fwd_iat_stats", "fwd_iat"),
            ("_cic_bwd_iat_stats", "bwd_iat"),
        ):
            stats = session[stats_key]
            session["flow"][flow_key] = {
                "total": stats["total"] if stats["count"] else 0,
                "mean": stats["mean"] if stats["count"] else 0,
                "std": self._stat_std(stats),
                "max": stats["max"] if stats["count"] else 0,
                "min": stats["min"] if stats["count"] else 0,
            }

        # Additional CICFlowMeter summary features.
        cic_length_std = self._stat_std({
            "count": session["_cic_len_count"],
            "m2": session["_cic_len_m2"],
        })
        session["flow"]["packet_length_variance"] = cic_length_std ** 2
        session["flow"]["average_packet_size"] = (
            (session["flow"]["cic_total_payload_bytes"]
             + session["_cic_first_payload_length"]) / total_packets
            if total_packets else 0
        )
        session["flow"]["avg_fwd_segment_size"] = (
            session["packets"]["forward"]["payload_bytes"] / fwd_packets
            if fwd_packets else 0
        )
        session["flow"]["avg_bwd_segment_size"] = (
            session["packets"]["backward"]["payload_bytes"] / bwd_packets
            if bwd_packets else 0
        )
        session["flow"]["down_up_ratio"] = (
            bwd_packets // fwd_packets if fwd_packets else 0
        )
        session["flow"]["min_seg_size_forward"] = (
            session["_cic_min_forward_header_length"] or 0
        )

        for stats_key, flow_key in (
            ("_cic_active_stats", "active"),
            ("_cic_idle_stats", "idle"),
        ):
            stats = session[stats_key]
            session["flow"][flow_key] = {
                "mean": stats["mean"] if stats["count"] else 0,
                "std": self._stat_std(stats),
                "max": stats["max"] if stats["count"] else 0,
                "min": stats["min"] if stats["count"] else 0,
            }

    # =================================================
    # Dong / lay / xoa session
    # =================================================

    @_synchronized
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

    @_synchronized
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

    @_synchronized
    def get_sessions(self, only_closed=False):

        result = []

        for session in self.sessions.values():

            if only_closed and not session["_closed"]:
                continue

            result.append(self._clean(session))

        return result

    @_synchronized
    def count_sessions(self):
        return len(self.sessions)

    @staticmethod
    def _clean(session):
        
        return copy.deepcopy(
            {
                key: value
                for key, value in session.items()
                if not key.startswith("_")
            }
        )

    @_synchronized
    def snapshot(self, session):
        """Ban copy doc lap, san sang json.dumps() cua mot session."""
        return self._clean(session)

    @_synchronized
    def drain_pending_closed_sessions(self):
        """Return flows closed during packet ingestion, exactly once each."""
        completed = self._pending_closed_sessions
        self._pending_closed_sessions = []
        return completed

    @_synchronized
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
