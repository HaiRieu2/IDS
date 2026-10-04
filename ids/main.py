"""Command-line entry point for live and offline IDS capture."""

import argparse
import json
import threading

from config.path import CONFIG_DATA
from ids.capture.live_capture import LiveCapture
from ids.detection_pipeline import process_closed_session


def _consume_packet_queue(capture):
    """Drain Scapy's queue and pass each packet to the capture processor."""
    while True:
        packet = capture.packet_queue.get()
        try:
            capture.process_packet(packet)
        except Exception as exc:
            print(f"[ERROR] Packet worker: {exc}")
        finally:
            # Queue.join() waits for this signal for every dequeued packet.
            capture.packet_queue.task_done()


def _parse_args():
    """Parse capture settings shared by the CLI live and PCAP modes."""
    parser = argparse.ArgumentParser(description="IDS live and PCAP capture")
    parser.add_argument("-i", "--interface", default=None, help="Network interface")
    parser.add_argument(
        "-f", "--filter", default="tcp or udp or icmp", help="BPF capture filter"
    )
    parser.add_argument(
        "-t", "--timeout", type=int, default=120,
        help="Seconds of inactivity before a flow times out",
    )
    parser.add_argument(
        "--max-duration", type=int, default=120,
        help="Maximum flow lifetime before the flow is rotated",
    )
    parser.add_argument("--pcap", default=None, help="Analyze a PCAP instead of live capture")
    return parser.parse_args()


def main():
    """Load rules, choose an input mode, and run the shared detection pipeline."""
    args = _parse_args()
    rules_path = CONFIG_DATA / "rules.json"
    with rules_path.open("r", encoding="utf-8") as rules_file:
        rules = json.load(rules_file)

    capture = LiveCapture(
        interface=args.interface,
        bpf_filter=args.filter,
        session_timeout=args.timeout,
        max_session_duration=args.max_duration,
        on_session=lambda session: process_closed_session(session, rules),
        # main() drains the packet queue before finalizing live flows.
        flush_on_stop=False,
    )

    session_count = 0
    output_file = capture.output_file
    try:
        if args.pcap:
            capture.read_pcap(args.pcap)
            session_count = len(capture.get_sessions())
            output_file = capture.save_sessions()
        else:
            worker = threading.Thread(
                target=_consume_packet_queue, args=(capture,), daemon=True
            )
            worker.start()
            try:
                capture.start()
            finally:
                # Finish queued packets before finalizing the remaining flows.
                capture.packet_queue.join()
                session_count = len(capture.get_sessions())
                capture.flush()
                output_file = capture.output_file
    except KeyboardInterrupt:
        print("\n[+] Capture stopped by user.")
    finally:
        print(f"[+] Sessions captured: {session_count}")
        if args.pcap:
            output_file = capture.output_file
        print(f"[+] Saved: {output_file}")


if __name__ == "__main__":
    main()
