
#Dos GoldenEye: 1 IP nhieu request: Flowpacket/s FlowByte/s **HTTP REQUEST COUNT
#Dos Hulk: HTTP Unbearable load king: 1 IP nhieu request: Flowpackets/s FlowByte/s Total Fwd Packet, Request Rate, **HTTP REQUEST COUNT
#Dos Slowris: Nhieu HTTP connection mo bang cach gui http request cham: 1 IP mo nhieu connection, duration > 60, fwd packet/s it
#Dos HTTPtest: slow body slow header Slow read
#TCP SYN FLood: 1 IP Nhieu SYN > 256 +
#UDP FLood: 1 IP Nhieu UDP + Flow Byte +
#ICMP FLood: 1 IP Nhieu ICMP Count + ICMP Byte +

from ids.alert.alert import (
    alert_detect_dos_connection,
    alert_detect_SYN_Flood,
    alert_detect_HTTP_Flood,
    alert_detect_UDP_Flood,
    alert_detect_ICMP_Flood,
)
WINDOW = 120

def detect_SYN_Flood(sessions, SYN_FLAG_THRESHOLD):
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
    for src_ip, syn_count in syn_by_ip.items():
        if syn_count > SYN_FLAG_THRESHOLD:
            evidence = f"So co SYN = {syn_count} (nguong: {SYN_FLAG_THRESHOLD})"
            alert_detect_SYN_Flood(src_ip, evidence)
    return

def detect_UDP_Flood(sessions,UDP_COUNT_THRESHOLD,UDP_TOTAL_BYTES_THRESHOLD):
    udp_by_ip = {}
    for session in sessions:
        network = session.get("network",{})
        if (network.get("protocol" == "UDP")):
            src_ip = network.get("src_ip","")
            if src_ip not in udp_by_ip:
                udp_by_ip[src_ip] = {
                    "counts": 0,
                    "total_bytes": 0
                }

            packets = session.get("packets",{})
            forward = packets.get("forward",{})
            forward_bytes = forward.get("bytes",0)
            udp_src_ip[src_ip]["counts"] += 1
            udp_src_ip[src_ip]["total_bytes"] += forward_bytes

    for src_ip,data in udp_by_ip.items():
        counts = data["count"]
        total_bytes = data["total_bytes"]
        if counts > UDP_COUNT_THRESHOLD or total_bytes > UDP_TOTAL_BYTES_THRESHOLD:
            evidence = f"UDP Count = {counts} and Total Bytes = {total_bytes}"
            alert_detect_UDP_Flood(src_ip,evidence)
    return

def detect_ICMP_Flood(sessions, ICMP_COUNT_THRESHOLD, ICMP_TOTAL_BYTES_THRESHOLD):
    icmp_by_ip = {}
    for session in sessions:
        network = session.get("network",{})
        if (network.get("protocol")!="ICMP"):
            continue
        src_ip = network.get("src_ip","")
        if src_ip not in icmp_by_ip:
            icmp_by_ip[src_ip] = {
            "counts": 0,
            "total_bytes": 0
        }
        packets = session.get("packets",{})
        forward = packets.get("forward",{})
        forward_bytes = forward.get("bytes",0)
        icmp = session.get("icmp",{})
        icmp_count=icmp.get("count",0)
        icmp_by_ip[src_ip]["counts"] += icmp_count
        icmp_by_ip[src_ip]["total_bytes"] += forward_bytes

    for src_ip,data in icmp_by_ip.items():
        counts=data["counts"]
        total_bytes=data["total_bytes"]
        if count > ICMP_COUNT_THRESHOLD:
            evidence = f"ICMP Count = {counts}"
            alert_detect_ICMP_Flood(src_ip,evidence)
        if total_bytes > ICMP_TOTAL_BYTES_THRESHOLD:
            evidence = f"Ping of Death, Total byte = {total_bytes}"
            alert_detect_ICMP_Flood(src_ip,evidence)
    return


def detect_HTTP_Flood(
    sessions,
    HTTP_SLOW_REQUEST_THRESHOLD,
    HTTP_SLOW_REQUEST_RATE,
    HTTP_SLOW_PACKET_THRESHOLD,
    HTTP_SLOW_DURATION_THRESHOLD,
    HTTP_SLOW_PORT,
    HTTP_FLOOD_REQUEST_THRESHOLD,
    HTTP_FLOOD_REQUEST_RATE
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

    http_flood_by_ip={}
    http_slow_by_ip={}

    for session in sessions:

        timestamp = session.get("timestamp", {})
        network = session.get("network", {})
        http = session.get("http", {})
        connection = session.get("connection", {})

        if network.get("protocol", "") != "TCP":
            continue


        dst_port = network.get("dst_port", 0)
        src_ip = network.get("src_ip", "")

        is_http_conn = bool(http.get("is_http")) or dst_port == HTTP_SLOW_PORT
        if is_http_conn == False:
            continue


        duration = timestamp.get("duration", 0)
        request_count=connection.get("request_count",0)
                    
        if duration <= 0:
            request_rate = 0
        else:
            request_rate = request_count/duration


        if src_ip not in http_slow_by_ip:
            http_slow_by_ip[src_ip]={
                "request_count": 0,
                "request_rate": 0,
                "fwd_packets": 0,
                "total_duration": 0
            }
        http_slow_by_ip[src_ip]["request_count"] += request_count
        temp = http_slow_by_ip[src_ip]["request_rate"]
        http_slow_by_ip[src_ip]["request_rate"] = ( (temp+request_rate ) / 2)
            
        packets = session.get("packets",{})
        forward = packets.get("forward",{})
        fwd_packets = forward.get("count",0)


            
        http_slow_by_ip[src_ip]["fwd_packets"] = fwd_packets
        http_slow_by_ip[src_ip]["total_duration"] += duration
        
        if src_ip not in http_flood_by_ip:
            http_flood_by_ip[src_ip]={
                "request_count": 0,
                "request_rate": 0
            }
        
        
        http_flood_by_ip[src_ip]["request_count"] += request_count
        request_count = http_flood_by_ip[src_ip]["request_count"]
        total_duration =  http_slow_by_ip[src_ip]["total_duration"]
        if total_duration > 0:
            http_flood_by_ip[src_ip]["request_rate"] = ( request_count / total_duration )
        
    for src_ip,data in http_slow_by_ip.items():
        request_count = http_slow_by_ip[src_ip]["request_count"]
        request_rate = http_slow_by_ip[src_ip]["request_rate"]
        fwd_packets = http_slow_by_ip[src_ip]["fwd_packets"]
        total_duration = http_slow_by_ip[src_ip]["total_duration"]
        if (request_count < HTTP_SLOW_REQUEST_THRESHOLD
            and request_rate < HTTP_SLOW_REQUEST_RATE
            and fwd_packets < HTTP_SLOW_PACKET_THRESHOLD
            and total_duration > HTTP_SLOW_DURATION_THRESHOLD
            ):
            evidence = f"HTTP SLOW: HTTP REQUEST COUNT = {request_count} and REQUEST RATE = {request_rate} and Fwd Packets =  {fwd_packets} and Duration = {total_duration}"
            alert_detect_HTTP_Flood(src_ip,evidence)


    for src_ip,data in http_flood_by_ip.items():
        request_count=data["request_count"]
        request_rate=data["request_rate"]
        if request_count > HTTP_FLOOD_REQUEST_THRESHOLD and request_rate > HTTP_FLOOD_REQUEST_RATE:
            
            evidence = f"HTTP_FLOOD: HTTP REQUEST Count = {request_count} AND REQUEST RATE = {request_rate}"
            alert_detect_HTTP_Flood(src_ip,evidence)
           

    return



def detect_dos(sessions, rules, window_seconds):

    SYN_FLAG_THRESHOLD = rules.get("SYN_FLAG_THRESHOLD", 0)             # vd 1000
    
    HTTP_SLOW_REQUEST_THRESHOLD = rules.get("HTTP_SLOW_REQUEST_THRESHOLD", 0)      # vd 1000 (tren 1 connection - GoldenEye)
    HTTP_SLOW_REQUEST_RATE = rules.get("HTTP_SLOW_REQUEST_RATE", 0)  # vd 10 (req/s tren 1 connection)
    HTTP_SLOW_PACKET_THRESHOLD = rules.get("HTTP_SLOW_PACKET_THRESHOLD", 0)  # vd 500 (cong don theo IP - Hulk)
    HTTP_SLOW_DURATION_THRESHOLD = rules.get("HTTP_SLOW_DURATION_THRESHOLD", 0)  # vd 100 (so connection moi/IP)
    HTTP_FLOOD_REQUEST_THRESHOLD = rules.get("HTTP_FLOOD_REQUEST_THRESHOLD", 120)    # vd 30-60 neu muon bat nhanh hon
    HTTP_FLOOD_REQUEST_RATE = rules.get("HTTP_FLOOD_REQUEST_RATE", 1000)
    HTTP_SLOW_PORT = rules.get("HTTP_SLOW_PORT", 80)

    UDP_COUNT_THRESHOLD = rules.get("UDP_COUNT_THRESHOLD", 0)          # vd 1000
    UDP_TOTAL_BYTES_THRESHOLD = rules.get("UDP_TOTAL_BYTES_THRESHOLD", 0)  # vd 65
    
    ICMP_COUNT_THRESHOLD = rules.get("ICMP_COUNT_THRESHOLD", 0)          # vd 1000
    ICMP_TOTAL_BYTES_THRESHOLD = rules.get("ICMP_TOTAL_BYTES_THRESHOLD", 0)  # vd 65535
    
    detect_SYN_Flood(sessions, SYN_FLAG_THRESHOLD)
    detect_UDP_Flood(sessions,UDP_COUNT_THRESHOLD,UDP_TOTAL_BYTES_THRESHOLD)
    detect_ICMP_Flood(sessions, ICMP_COUNT_THRESHOLD, ICMP_TOTAL_BYTES_THRESHOLD)
    detect_HTTP_Flood(
    sessions,
    HTTP_SLOW_REQUEST_THRESHOLD,
    HTTP_SLOW_REQUEST_RATE,
    HTTP_SLOW_PACKET_THRESHOLD,
    HTTP_SLOW_DURATION_THRESHOLD,
    HTTP_SLOW_PORT,
    HTTP_FLOOD_REQUEST_THRESHOLD,
    HTTP_FLOOD_REQUEST_RATE
    )
    return