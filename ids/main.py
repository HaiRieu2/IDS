from collections import deque
import queue
import threading
import json
from capture.live_capture import LiveCapture, session_queue
from capture.session_builder import SessionBuilder
from detectors.signature.signature_engine import signature_engine
from detectors.behavior.behavior_engine import behavior_engine
def worker_xu_ly(sb):
    print('[+] Goi Ham worker_xu_ly thanh cong')
    while True:
        try:
            # Lấy packet đã parse từ hàng đợi (hàm .get() sẽ tự động chờ đến khi có dữ liệu mà ko tốn CPU)
            session = session_queue.get()
            if session is None:
                break
            # Nếu gói tin vừa rồi tạo ra hoặc cập nhật một session hợp lệ, chuyển sang cho các engine xử lý
            if session:
                behavior_engine(session)
                signature_engine(session)
                
            # Đánh dấu task trong queue đã hoàn thành
            
        except Exception as e:
            print(f"[ERROR] Worker error: {e}")
        finally:
            session_queue.task_done()
def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="IDS Live Packet Capture"
    )

    parser.add_argument(
        "-i", "--interface", default=None,
        help="Network interface"
    )

    parser.add_argument(
        "-f", "--filter", default="tcp or udp or icmp",
        help="BPF filter"
    )

    parser.add_argument(
        "-t", "--timeout", type=int, default=60,
        help="Session timeout (seconds) of inactivity before a "
             "flow is considered a new session"
    )

    parser.add_argument(
        "-o", "--output", default=r"F:\VSCODE\IDS\ids\data\sessions.json",
        help="Output JSON file"
    )

    parser.add_argument(
        "--pcap", default=None,
        help="Read packets from a .pcap file instead of live capture"
    )
    parser.add_argument(
    "--output-session-counter-file", 
    type=str, 
    default=r"F:\VSCODE\IDS\ids\config\session_counter.txt", 
    help="Đường dẫn file lưu thống kê session"
    ) 

    args = parser.parse_args()

    capture = LiveCapture(
        interface=args.interface,
        bpf_filter=args.filter,
        session_timeout=args.timeout,
        #output_file=args.output,
        #output_session_counter_file=args.output_session_counter_file,
    )

    try:

        if args.pcap:
            capture.read_pcap(args.pcap)
        else:
            threading.Thread(target=worker_xu_ly,args=(capture.session_builder,) ,daemon=True).start()
            capture.start()

    except KeyboardInterrupt:

        print("\n[+] Capture stopped.")

    finally:

        sessions = capture.get_sessions()

        print(f"[+] Sessions captured: {len(sessions)}")

        output_file = capture.save_sessions()

        print(f"[+] Saved: {output_file}")



if __name__ == "__main__":
    main()

