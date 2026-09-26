"""
DoS / DDoS Detector
1. SYN Flood            : 1 IP co tong so co SYN vuot nguong
2. Distributed SYN Flood: nhieu IP nguon khac nhau cung SYN flood
3. HTTP Flood           : 1 IP co qua nhieu HTTP request, toc do request cao,
                          hoac ket noi mo lau ma gan nhu khong gui du lieu (slow HTTP)
4. UDP Flood            : 1 IP gui qua nhieu goi UDP / tong so byte lon
5. ICMP Flood           : 1 IP gui qua nhieu goi ICMP
   Ping of Death        : 1 goi ICMP co kich thuoc bat thuong
6. Connection Flood     : 1 session ton tai qua lau, hoac qua nhieu IP
                          nguon khac nhau ket noi cung luc
"""

from ids.alert.alert import (
    alert_detect_dos_connection,
    alert_detect_SYN_Flood,
    alert_detect_HTTP_Flood,
    alert_detect_UDP_Flood,
    alert_detect_ICMP_Flood,
)


def detect_SYN_Flood(sessions, SYN_FLAG_THRESHOLD, DISTRIBUTED_IP_THRESHOLD=0):
    syn_by_ip = {}

    for session in sessions:
        network = session.get("network", {})
        flag = session.get("flag", {})

        src_ip = network.get("src_ip", "")
        syn = flag.get("syn", 0)

        if syn <= 0:
            continue

        syn_by_ip[src_ip] = syn_by_ip.get(src_ip, 0) + syn

    # 1. SYN Flood tu 1 IP don le
    attacking_ips = []
    for src_ip, syn_count in syn_by_ip.items():
        if syn_count > SYN_FLAG_THRESHOLD:
            evidence = f"So co SYN = {syn_count} (nguong: {SYN_FLAG_THRESHOLD})"
            alert_detect_SYN_Flood(src_ip, evidence)
            attacking_ips.append(src_ip)

    # 2. Distributed SYN Flood: nhieu IP nguon KHAC NHAU cung vuot nguong
    #    cung luc (truoc day file goc chi comment, chua thuc su cai dat).
    if DISTRIBUTED_IP_THRESHOLD > 0 and len(attacking_ips) > DISTRIBUTED_IP_THRESHOLD:
        evidence = (
            f"{len(attacking_ips)} IP nguon khac nhau cung SYN flood "
            f"(nguong: {DISTRIBUTED_IP_THRESHOLD})"
        )
        alert_detect_SYN_Flood("DISTRIBUTED", evidence)

    return


def detect_HTTP_Flood(
    sessions,
    HTTP_REQUEST_THRESHOLD,
    HTTP_REQUEST_RATE_THRESHOLD,
    HTTP_REQUEST_THRESHOLD_PER_IP=0,
    HTTP_CONNECTION_COUNT_THRESHOLD=0,
    SLOW_HTTP_MIN_DURATION=120,
    SLOW_HTTP_MAX_BYTES=1000,
    SLOW_HTTP_MIN_PACKETS=2,
    SLOW_HTTP_PORT=80,
    window_seconds=100,
    MIN_DURATION_FOR_RATE=1,
):
    """
    Bat 4 dang HTTP Flood khac nhau:

    (a) HTTP Flood tren 1 connection (kieu GoldenEye khi dung Keep-Alive):
        1 session co qua nhieu request + toc do cao.

    (b) HTTP Flood CONG DON tu 1 IP qua NHIEU session/connection ngan
        (kieu Hulk): Hulk mo 1 connection MOI cho gan nhu MOI request, nen
        tung session rieng le chi co 1-2 request -> khong bao gio vuot
        HTTP_REQUEST_THRESHOLD neu chi xet tung session. Phai cong don
        request_count theo src_ip tren toan bo cua so thoi gian moi thay
        duoc.

    (c) Qua nhieu connection MOI duoc mo tu 1 IP trong cua so thoi gian:
        dau hieu chung cua ca Hulk lan GoldenEye (lien tuc tao connection
        moi de nem request), khong phu thuoc vao viec co parse duoc HTTP
        hay khong.

    (d) Slow HTTP (Slowloris / Slowhttptest): connection ton tai rat lau
        nhung gui du lieu nho giot, khong bao gio du de tao thanh 1 HTTP
        message hoan chinh. QUAN TRONG: nhanh nay KHONG duoc dat dieu
        kien "is_http" nhu ban truoc - Slowloris/Slowhttptest co y khong
        bao gio gui du "\\r\\n\\r\\n" + Content-Length, nen is_http se mai
        la False; dat dieu kien slow-HTTP sau is_http se khien no khong
        bao gio duoc kiem tra dung luc can kiem tra nhat.
    """

    per_ip_requests = {}     # src_ip -> tong request_count cong don qua nhieu session
    per_ip_connections = {}  # src_ip -> so luong session/connection toi cong HTTP

    for session in sessions:
        timestamp = session.get("timestamp", {})
        network = session.get("network", {})
        packets = session.get("packets", {})
        http = session.get("http", {})
        connection = session.get("connection", {})

        if network.get("protocol", "") != "TCP":
            continue

        duration = timestamp.get("duration", 0)
        request_count = connection.get("request_count", 0)
        dst_port = network.get("dst_port", 0)
        src_ip = network.get("src_ip", "")

        forward = packets.get("forward", {})
        forward_count = forward.get("count", 0)
        forward_bytes = forward.get("bytes", 0)

        is_http_conn = bool(http.get("is_http")) or dst_port == SLOW_HTTP_PORT

        # --- (a) HTTP Flood tren 1 connection (GoldenEye) ---
        if http.get("is_http"):
            # Chi tinh request_rate khi session da du "gia" (>= MIN_DURATION_FOR_RATE
            # giay), tranh 1 session moi mo 0.01s da bi coi la "toc do cuc cao".
            request_rate = request_count / duration if duration >= MIN_DURATION_FOR_RATE else 0

            if request_count > HTTP_REQUEST_THRESHOLD and request_rate > HTTP_REQUEST_RATE_THRESHOLD:
                evidence = (
                    f"HTTP Request = {request_count}, Request Rate = {request_rate:.2f} req/s "
                    f"(tren 1 connection)"
                )
                alert_detect_HTTP_Flood(src_ip, evidence)

            per_ip_requests[src_ip] = per_ip_requests.get(src_ip, 0) + request_count

        if is_http_conn:
            per_ip_connections[src_ip] = per_ip_connections.get(src_ip, 0) + 1

        # --- (d) Slow HTTP: Slowloris / Slowhttptest ---
        if (
            duration > SLOW_HTTP_MIN_DURATION
            and dst_port == SLOW_HTTP_PORT
            and forward_bytes < SLOW_HTTP_MAX_BYTES
            and forward_count >= SLOW_HTTP_MIN_PACKETS
        ):
            evidence = (
                f"Duration = {duration:.1f}s (>{SLOW_HTTP_MIN_DURATION}), dst_port={SLOW_HTTP_PORT}, "
                f"forward_bytes={forward_bytes} (<{SLOW_HTTP_MAX_BYTES}), "
                f"forward_packets={forward_count} (>={SLOW_HTTP_MIN_PACKETS}) - nghi Slowloris/Slowhttptest"
            )
            alert_detect_HTTP_Flood(src_ip, evidence)

    # --- (b) Tong request CONG DON tu 1 IP qua nhieu session (Hulk) ---
    if HTTP_REQUEST_THRESHOLD_PER_IP > 0:
        for src_ip, total_requests in per_ip_requests.items():
            if total_requests > HTTP_REQUEST_THRESHOLD_PER_IP:
                rate = total_requests / window_seconds if window_seconds > 0 else 0
                evidence = (
                    f"Tong {total_requests} HTTP request tu cung 1 IP trong {window_seconds}s "
                    f"(~{rate:.2f} req/s), cong don qua nhieu connection rieng le "
                    f"(nguong: {HTTP_REQUEST_THRESHOLD_PER_IP})"
                )
                alert_detect_HTTP_Flood(src_ip, evidence)

    # --- (c) Qua nhieu connection MOI tu 1 IP trong cua so thoi gian ---
    if HTTP_CONNECTION_COUNT_THRESHOLD > 0:
        for src_ip, conn_count in per_ip_connections.items():
            if conn_count > HTTP_CONNECTION_COUNT_THRESHOLD:
                evidence = (
                    f"{conn_count} connection HTTP moi tu cung 1 IP trong {window_seconds}s "
                    f"(nguong: {HTTP_CONNECTION_COUNT_THRESHOLD})"
                )
                alert_detect_HTTP_Flood(src_ip, evidence)

    return


def detect_UDP_Flood(sessions, UDP_PACKET_THRESHOLD, UDP_TOTAL_BYTES_THRESHOLD):
    for session in sessions:
        packets = session.get("packets", {})
        forward = packets.get("forward", {})
        network = session.get("network", {})
        protocol = network.get("protocol", "")

        if protocol != "UDP":
            continue

        if forward.get("count", 0) > UDP_PACKET_THRESHOLD and forward.get("bytes", 0) > UDP_TOTAL_BYTES_THRESHOLD:
            evidence = (
                f"UDP Packet = {forward.get('count', 0)}, "
                f"Total bytes = {forward.get('bytes', 0)}"
            )
            alert_detect_UDP_Flood(network.get("src_ip", ""), evidence)

    return


def detect_ICMP_Flood(sessions, ICMP_COUNT_THRESHOLD, ICMP_TOTAL_BYTES_THRESHOLD):
    icmp_count_by_ip = {}
    ping_of_death = []  # list (src_ip, packet_size)

    for session in sessions:
        network = session.get("network", {})
        flow = session.get("flow", {})
        icmp = session.get("icmp", {})

        protocol = network.get("protocol", "")
        if protocol != "ICMP":
            continue

        src_ip = network.get("src_ip", "")

        icmp_count_by_ip[src_ip] = icmp_count_by_ip.get(src_ip, 0) + icmp.get("count", 0)

        # SUA: ban goc dung flow["total_bytes"] (TONG so byte CONG DON ca
        # session) de so sanh voi ICMP_TOTAL_BYTES_THRESHOLD. Nhu vay 1
        # session ICMP binh thuong nhung keo dai (nhieu goi ping nho) van
        # co the cong don vuot nguong -> bao dong nham la "Ping of Death".
        # Ping of Death la dac trung boi 1 GOI TIN DON co kich thuoc bat
        # thuong, nen phai dung kich thuoc goi LON NHAT (packet_length.max),
        # khong phai tong don.
        max_packet_len = flow.get("packet_length", {}).get("max", 0)
        if max_packet_len > ICMP_TOTAL_BYTES_THRESHOLD:
            ping_of_death.append((src_ip, max_packet_len))

    for src_ip, count in icmp_count_by_ip.items():
        if count > ICMP_COUNT_THRESHOLD:
            evidence = f"ICMP Count = {count} (nguong: {ICMP_COUNT_THRESHOLD})"
            alert_detect_ICMP_Flood(src_ip, evidence)

    for src_ip, packet_len in ping_of_death:
        evidence = (
            f"ICMP Packet Size = {packet_len} bytes "
            f"(nguong: {ICMP_TOTAL_BYTES_THRESHOLD}) - nghi Ping of Death"
        )
        alert_detect_ICMP_Flood(src_ip, evidence)

    return


def detect_dos_connection(sessions, DURATION_THRESHOLD, IP_COUNT_THRESHOLD):
    unique_ips = set()  # SUA: dung set thay vi list -> tra cuu O(1) thay vi O(n)

    for session in sessions:
        timestamp = session.get("timestamp", {})
        network = session.get("network", {})

        duration = timestamp.get("duration", 0)
        src_ip = network.get("src_ip", "")

        unique_ips.add(src_ip)

        if duration > DURATION_THRESHOLD:
            evidence = f"Duration = {duration:.1f}s (nguong: {DURATION_THRESHOLD}s)"
            alert_detect_dos_connection(src_ip, evidence)

    # SUA BUG: ban goc kiem tra "len(IP_List) > IP_COUNT_THRESHOLD" BEN
    # TRONG vong lap for, nen tu luc vuot nguong tro di, MOI session con
    # lai trong vong lap deu ban ra 1 alert rieng (co the ra hang tram
    # alert trung lap chi trong 1 lan goi ham). Phai kiem tra 1 LAN DUY
    # NHAT, sau khi da duyet xong toan bo sessions.
    if len(unique_ips) > IP_COUNT_THRESHOLD:
        evidence = f"So IP nguon khac nhau = {len(unique_ips)} (nguong: {IP_COUNT_THRESHOLD})"
        alert_detect_dos_connection("MULTIPLE_IP", evidence)

    return


def detect_dos(sessions, rules, window_seconds=100):

    SYN_FLAG_THRESHOLD = rules.get("SYN_FLAG_THRESHOLD", 0)             # vd 1000
    DISTRIBUTED_IP_THRESHOLD = rules.get("DISTRIBUTED_IP_THRESHOLD", 0)  # vd 20

    HTTP_REQUEST_THRESHOLD = rules.get("HTTP_REQUEST_THRESHOLD", 0)      # vd 1000 (tren 1 connection - GoldenEye)
    HTTP_REQUEST_RATE_THRESHOLD = rules.get("HTTP_REQUEST_RATE_THRESHOLD", 0)  # vd 10 (req/s tren 1 connection)
    HTTP_REQUEST_THRESHOLD_PER_IP = rules.get("HTTP_REQUEST_THRESHOLD_PER_IP", 0)  # vd 500 (cong don theo IP - Hulk)
    HTTP_CONNECTION_COUNT_THRESHOLD = rules.get("HTTP_CONNECTION_COUNT_THRESHOLD", 0)  # vd 100 (so connection moi/IP)
    SLOW_HTTP_MIN_DURATION = rules.get("SLOW_HTTP_MIN_DURATION", 120)    # vd 30-60 neu muon bat nhanh hon
    SLOW_HTTP_MAX_BYTES = rules.get("SLOW_HTTP_MAX_BYTES", 1000)
    SLOW_HTTP_MIN_PACKETS = rules.get("SLOW_HTTP_MIN_PACKETS", 2)
    SLOW_HTTP_PORT = rules.get("SLOW_HTTP_PORT", 80)

    UDP_PACKET_THRESHOLD = rules.get("UDP_PACKET_THRESHOLD", 0)          # vd 1000
    UDP_TOTAL_BYTES_THRESHOLD = rules.get("UDP_TOTAL_BYTES_THRESHOLD", 0)  # vd 65
    ICMP_COUNT_THRESHOLD = rules.get("ICMP_COUNT_THRESHOLD", 0)          # vd 1000
    ICMP_TOTAL_BYTES_THRESHOLD = rules.get("ICMP_TOTAL_BYTES_THRESHOLD", 0)  # vd 65535
    DURATION_THRESHOLD = rules.get("DURATION_THRESHOLD", 0)              # vd 9600
    IP_COUNT_THRESHOLD = rules.get("IP_COUNT_THRESHOLD", 0)              # vd 2000

    detect_SYN_Flood(sessions, SYN_FLAG_THRESHOLD, DISTRIBUTED_IP_THRESHOLD)
    detect_HTTP_Flood(
        sessions,
        HTTP_REQUEST_THRESHOLD,
        HTTP_REQUEST_RATE_THRESHOLD,
        HTTP_REQUEST_THRESHOLD_PER_IP=HTTP_REQUEST_THRESHOLD_PER_IP,
        HTTP_CONNECTION_COUNT_THRESHOLD=HTTP_CONNECTION_COUNT_THRESHOLD,
        SLOW_HTTP_MIN_DURATION=SLOW_HTTP_MIN_DURATION,
        SLOW_HTTP_MAX_BYTES=SLOW_HTTP_MAX_BYTES,
        SLOW_HTTP_MIN_PACKETS=SLOW_HTTP_MIN_PACKETS,
        SLOW_HTTP_PORT=SLOW_HTTP_PORT,
        window_seconds=window_seconds,
    )
    detect_UDP_Flood(sessions, UDP_PACKET_THRESHOLD, UDP_TOTAL_BYTES_THRESHOLD)
    detect_ICMP_Flood(sessions, ICMP_COUNT_THRESHOLD, ICMP_TOTAL_BYTES_THRESHOLD)
    detect_dos_connection(sessions, DURATION_THRESHOLD, IP_COUNT_THRESHOLD)

    return