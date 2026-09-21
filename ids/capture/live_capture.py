from scapy.all import sniff, rdpcap
from datetime import datetime, timezone
import json
import os
import time
import queue
from .packet_parser import parse_packet
from .session_builder import SessionBuilder
from config.path import SESSION_DATA
from config.path import CONFIG_DATA
session_queue = queue.Queue()
class LiveCapture:  

    def __init__(
        self,
        interface=None,
        bpf_filter=None,
        session_timeout=120, #120 di   
        output_file= SESSION_DATA/"sessions.json",
        output_session_counter_file= CONFIG_DATA/"session_counter.txt",
        autosave_interval=30,

    ):

        self.interface = interface

        self.bpf_filter = bpf_filter

        self.session_builder = SessionBuilder(
            session_timeout=session_timeout
        )

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


    # Packet callback

    def process_packet(self, packet):

        try:

            parsed = parse_packet(packet)

            if parsed is None:
                return

            self._last_packet_time = parsed["timestamp"]

            #packet_queue.put(parsed)
            session_queue.put(self.session_builder.add_packet(parsed))  #Ket qua cua add_packet co quan trong cho 2 ham duoi khong
            
            self._log_packet(parsed)

            self._maybe_autosave()

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

                transaction = http["transactions"][1]

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

        expired = self.session_builder.close_expired_sessions(
            current_time=self._last_packet_time
        )

        if expired:
            print(f"[+] Closed {len(expired)} idle session(s).")

        self.save_sessions()

        self.save_session_counter()

        self.session_builder.clear_closed_sessions()

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

            while self._running:

                sniff(
                    iface=self.interface,
                    filter=self.bpf_filter,
                    prn=self.process_packet,#(process_packet)
                    store=False,
                    timeout=5
                )
                self._maybe_autosave()

        except KeyboardInterrupt:

            self._running = False
            raise

    def stop(self):
        self._running = False

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

        output_dir = os.path.dirname(self.output_file)

        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        with open(self.output_file, "a", encoding="utf-8") as f:

            for session in sessions:
                f.write(json.dumps(session, ensure_ascii=False))
                f.write("\n")

        return self.output_file

    def save_session_counter(self):
        
        sessions = self.get_sessions()

        output_session_counter_dir = os.path.dirname(self.output_session_counter_file)

        if output_session_counter_dir:
            os.makedirs(output_session_counter_dir, exist_ok=True)

        with open(self.output_session_counter_file, "w", encoding="utf-8") as f:

            session = sessions[-1] if sessions else None

            session_id = session["session_id"] if session else 0

            f.write(str(session_id[1:]))

        return self.output_session_counter_file

    def load_session_counter(self):

        if os.path.exists(self.output_session_counter_file):
            with open(self.output_session_counter_file, "r", encoding="utf-8") as f:
                session_id = f.read().strip()
                return int(session_id) if session_id.isdigit() else 0
        return 0
