from scapy.all import sniff, rdpcap
from datetime import datetime, timezone
import json
import os
import time
import queue
import threading
from .packet_parser import parse_packet
from .session_builder import SessionBuilder
from .ip_reassembly import IPDefragmenter
from .dedup import PacketDeduplicator
from config.path import LOGS_DIR
from config.path import CONFIG_DATA



class LiveCapture:  

    def __init__(
        self,
        interface=None,
        bpf_filter=None,
        session_timeout=120,
        max_session_duration=120,
        output_file= LOGS_DIR/"sessions.json",
        output_session_counter_file= CONFIG_DATA/"session_counter.txt",
        autosave_interval=30,

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
        self._deduplicator = PacketDeduplicator()

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

        try:

            # Loai goi tin bi bat trung 
            if self._deduplicator.is_duplicate(bytes(packet)):
                return

            # Ghep IP fragment. Neu day la 1 fragment ma nhom chua du de
            # ghep -> tra ve None, cho fragment tiep theo den.
            packet = self._ip_defragmenter.process(packet)

            if packet is None:
                return

            parsed = parse_packet(packet)

            if parsed is None:
                return

            self._last_packet_time = parsed["timestamp"]

            session = self.session_builder.add_packet(parsed)

            

            self._log_packet(parsed)

            self._maybe_autosave()
            if session["_closed"]:
                return (self.session_builder.snapshot(session))

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
        self._ip_defragmenter.cleanup(current_time=self._last_packet_time)

        expired = self.session_builder.close_expired_sessions(
            current_time=self._last_packet_time
        )

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

            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self.put_packet,
                store=False
            )

        except KeyboardInterrupt:
            print("\n[!] Stopped by user.")

        finally:
            self._running = False
            self.flush()

    def stop(self):
        self._running = False

    def flush(self):
        """Dong moi session con mo va ghi ra file (goi khi ket thuc capture)."""

        closed = self.session_builder.close_all_sessions()

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

        print(f"[+] Reading pcap file: {pcap_path}")

        packets = rdpcap(pcap_path)

        for packet in packets:
            self.process_packet(packet)

        print(f"[+] Done. {len(packets)} packets processed.")

        return self.get_sessions()

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
