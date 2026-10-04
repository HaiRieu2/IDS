from scapy.all import AsyncSniffer, PcapReader
from datetime import datetime, timezone
import json
import os
import time
import queue
import threading
from collections import deque
from .packet_parser import parse_packet
from .session_builder import SessionBuilder
from .ip_reassembly import IPDefragmenter
from .dedup import PacketDeduplicator
from config.path import LOGS_DIR
from config.path import CONFIG_DATA



class LiveCapture:  
    """Capture packets, turn them into sessions, then emit closed sessions.

    Both Scapy live traffic and offline PCAP traffic use this class. Detection
    itself is injected through ``on_session`` so the capture layer stays
    separate from detector implementation.
    """

    def __init__(
        self,
        interface=None,
        bpf_filter=None,
        session_timeout=120,
        max_session_duration=120,
        output_file= LOGS_DIR/"sessions.json",
        output_session_counter_file= CONFIG_DATA/"session_counter.txt",
        autosave_interval=30,
        on_session=None,
        enable_dedup=False,
        flush_on_stop=True,

    ):
        self.packet_queue = queue.Queue()

        self.interface = interface

        self.bpf_filter = bpf_filter

        self.session_builder = SessionBuilder(
            session_timeout=session_timeout,
            max_session_duration=max_session_duration,
        )

        # Ghep lai IP fragment truoc khi parse, tranh mat du lieu (VD Ping
        # of Death bi chia thanh nhieu fragment nho hon MTU).
        self._ip_defragmenter = IPDefragmenter()

        # Loai bo goi tin bi bat trung 
        self._deduplicator = PacketDeduplicator() if enable_dedup else None
        self.on_session = on_session
        self.flush_on_stop = flush_on_stop
        self.pcap_packets_read = 0
        self.packet_count = 0
        self._recent_packet_times = deque()
        self._traffic_lock = threading.Lock()
        self._sniffer = None
        self._stop_requested = threading.Event()

        self.output_file = output_file

        self.output_session_counter_file = output_session_counter_file

        # Load session_counter tu file
        self.session_builder.session_counter = self.load_session_counter()

        # khoang thoi gian tu dong luu
        self.autosave_interval = autosave_interval 

        self._last_autosave = time.time()

        self._running = False

        # Thoi gian xu ly goi tin cuoi cung
        self._last_packet_time = None 


    def put_packet(self,packet):
        self.packet_queue.put(packet)
        return

    # Packet callback

    def process_packet(self, packet):
        """Parse one Scapy packet, update its flow, and emit it if now closed."""

        try:

            # 1. Reject an optional duplicate and wait for complete IP fragments.
            if self._deduplicator and self._deduplicator.is_duplicate(bytes(packet)):
                return

            # Ghep IP fragment. Neu day la 1 fragment ma nhom chua du de
            # ghep -> tra ve None, cho fragment tiep theo den.
            packet = self._ip_defragmenter.process(packet)

            if packet is None:
                return

            # 2. Convert Scapy's layers into the IDS packet dictionary.
            parsed = parse_packet(packet)

            if parsed is None:
                return

            # 3. Update live counters and the bidirectional flow record.
            self._last_packet_time = parsed["timestamp"]
            now = time.monotonic()
            with self._traffic_lock:
                self.packet_count += 1
                self._recent_packet_times.append(now)
                while self._recent_packet_times and now - self._recent_packet_times[0] > 1.0:
                    self._recent_packet_times.popleft()

            session = self.session_builder.add_packet(parsed)

            # add_packet may rotate a long-lived flow or replace one that
            # exceeded the idle timeout. Emit those completed flow snapshots
            # before analyzing the newly created flow. Without this drain,
            # the old flow is marked closed internally but never reaches ML.
            for completed_session in self.session_builder.drain_pending_closed_sessions():
                self._emit_session(completed_session)

            self._log_packet(parsed)

            # 4. Save/expire periodically, then analyze a just-closed session.
            self._maybe_autosave()
            if session["_closed"]:
                snapshot = self.session_builder.snapshot(session)
                self._emit_session(snapshot)
                return snapshot

        except Exception as e:

            print(f"[ERROR] Packet processing: {e}")

    def _log_packet(self, parsed):

        if parsed["protocol"] in ("ICMP", "ICMPv6"):

            print(
                f"[PACKET] "
                f"{parsed['src_ip']} -> {parsed['dst_ip']} "
                f"{parsed['protocol']} "
                #f"type={parsed['icmp_type']} code={parsed['icmp_code']} "
                f"{parsed['packet_length']} bytes"
            )

        else:

            print(
                f"[PACKET] "
                f"{parsed['src_ip']}:{parsed['src_port']} "
                f"-> "
                f"{parsed['dst_ip']}:{parsed['dst_port']} "
                f"{parsed['protocol']} "
                f"{parsed['packet_length']} bytes"
            )

        http = parsed.get("http")

        if http and http.get("is_http"):

            if http.get("type") == "request":

                transaction = http["transactions"][0]
                
                print(
                    f"[HTTP] {transaction['request']['method']} {transaction['request']['uri']}"
                )

            elif http.get("type") == "response":

                transaction = http["transactions"][0]

                print(
                    f"[HTTP] {transaction['response']['status_code']} "
                )

    def _maybe_autosave(self):

        if self.autosave_interval <= 0:
            return

        now = time.time()

        if (now - self._last_autosave) < self.autosave_interval:
            return

        self._last_autosave = now

        # Don cac nhom IP fragment qua han chua ghep xong, tranh ro ri bo
        # nho neu bi tan cong bang fragment co y khong gui du.
        current_time = max(time.time(), self._last_packet_time or 0)
        self._ip_defragmenter.cleanup(current_time=current_time)

        expired = self.session_builder.close_expired_sessions(
            current_time=current_time
        )

        self._emit_sessions(expired)

        if expired:
            print(f"[+] Closed {len(expired)} idle session(s).")

        self.save_sessions()

        self.save_session_counter()

        self.session_builder.clear_closed_sessions()

    # Thread auto_save
    def _autosave_worker(self):
        while self._running:
            time.sleep(5)

            if not self._running:
                break

            try:
                self._maybe_autosave()
            except Exception as e:
                print(f"[ERROR] Autosave worker: {e}")

    # Start capture (live interface)

    def start(self):

        print("=" * 60)
        print("IDS Live Packet Capture")
        print("=" * 60)

        if self.interface:
            print(f"[+] Interface: {self.interface}")
        else:
            print("[+] Interface: default")

        if self.bpf_filter:
            print(f"[+] Filter: {self.bpf_filter}")

        print("[+] Starting capture...")
        print("[+] Press CTRL+C to stop.")
        print("=" * 60)

        self._running = True

        try:
            autosave_thread = threading.Thread(
                target=self._autosave_worker,
                daemon=True
            )
            autosave_thread.start()

            if not self._stop_requested.is_set():
                self._sniffer = AsyncSniffer(
                    iface=self.interface,
                    filter=self.bpf_filter,
                    prn=self.put_packet,
                    store=False
                )
                self._sniffer.start()
                self._sniffer.join()

        except KeyboardInterrupt:
            print("\n[!] Stopped by user.")

        finally:
            self.stop()
            self._running = False
            if self.flush_on_stop:
                self.flush()

    def stop(self):
        self._stop_requested.set()
        self._running = False
        sniffer = self._sniffer
        if sniffer is not None and sniffer.running:
            try:
                sniffer.stop()
            except Exception as exc:
                print(f"[!] Capture stop: {exc}")

    def traffic_stats(self):
        now = time.monotonic()
        with self._traffic_lock:
            while self._recent_packet_times and now - self._recent_packet_times[0] > 1.0:
                self._recent_packet_times.popleft()
            packets_per_second = len(self._recent_packet_times)
            packet_count = self.packet_count
        return {
            "running": self._running,
            "packets": packet_count,
            "packets_per_second": packets_per_second,
            "sessions": self.session_builder.count_sessions(),
        }

    def flush(self):
        """Dong moi session con mo va ghi ra file (goi khi ket thuc capture)."""

        closed = self.session_builder.close_all_sessions()
        self._emit_sessions(closed)

        if closed:
            print(f"[+] Closed {len(closed)} open session(s) on shutdown.")

        self.save_sessions()
        self.save_session_counter()
        self.session_builder.clear_closed_sessions()

    # =================================================
    # Đọc từ file pcap có sẵn (offline), hữu ích cho việc
    # test lại dataset/pcap mẫu thay vì phải bắt live traffic.
    # =================================================

    def read_pcap(self, pcap_path):
        """Replay a PCAP through the same parser and session builder as live."""

        print(f"[+] Reading pcap file: {pcap_path}")

        # Stream packets one by one. rdpcap() materializes the entire capture
        # in memory, which is costly for large CIC-IDS attack PCAPs; the
        # streaming reader still feeds every packet through the exact same
        # process_packet path used by live capture.
        self.pcap_packets_read = 0
        # Scapy treats strings as file paths, but treats arbitrary objects as
        # already-open file handles. pathlib.Path is not a file handle and
        # has no .read(), so normalize PathLike inputs before constructing the
        # reader (the dashboard passes a WindowsPath here).
        with PcapReader(os.fspath(pcap_path)) as packets:
            for packet in packets:
                self.pcap_packets_read += 1
                self.process_packet(packet)

        # PCAP thường kết thúc khi nhiều TCP flow vẫn còn mở. Đóng và phân tích
        # chúng để offline và live cùng đưa flow hoàn chỉnh qua một pipeline.
        self._emit_sessions(self.session_builder.close_all_sessions())

        print(f"[+] Done. {self.pcap_packets_read} packets processed.")

        return self.get_sessions()

    def _emit_session(self, session):
        if self.on_session:
            self.on_session(session)

    def _emit_sessions(self, session_ids):
        if not self.on_session:
            return
        by_id = {s["session_id"]: s for s in self.session_builder.get_sessions()}
        for session_id in session_ids:
            session = by_id.get(session_id)
            if session is not None:
                self._emit_session(session)

    # Get sessions

    def get_sessions(self, only_closed=False):

        return self.session_builder.get_sessions(only_closed=only_closed)

    # =================================================
    # Save sessions to JSON
    # =================================================

    def save_sessions(self, only_closed=True):

        sessions = self.get_sessions(only_closed=only_closed)

        output_dir = os.path.dirname(os.fspath(self.output_file))

        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        with open(self.output_file, "a", encoding="utf-8") as f:

            for session in sessions:
                f.write(json.dumps(session, ensure_ascii=False))
                f.write("\n")

        return self.output_file

    def save_session_counter(self):

        output_session_counter_dir = os.path.dirname(
            os.fspath(self.output_session_counter_file)
        )

        if output_session_counter_dir:
            os.makedirs(output_session_counter_dir, exist_ok=True)

        counter = self.session_builder.session_counter

        with open(self.output_session_counter_file, "w", encoding="utf-8") as f:
            f.write(str(counter))

        return self.output_session_counter_file

    def load_session_counter(self):

        if os.path.exists(os.fspath(self.output_session_counter_file)):
            with open(self.output_session_counter_file, "r", encoding="utf-8") as f:
                session_id = f.read().strip()
                return int(session_id) if session_id.isdigit() else 0
        return 0
