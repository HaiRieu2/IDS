
# 1. SYN Flood : 1 IP + SYN_Count
## 2. Distrubuted SYN Flood : Unique + IP SYN_Count
# 3. HTTP Flood :Protocol HTTP  1 IP HTTP Request > 500 HTTP Request Rate > 10
# 4. UDP Flood : Protocol UDP 1 IP UDP Packet  Total byte
# 5. ICMP Flood : Protocol ICMP 1 IP ICMP Total Total byte
# 6. CONNECTION Flood : Duration > 72000 dst_port > 1000 cai va 10000 session
from ids.alert.alert import alert_detect_dos_connection,alert_detect_SYN_Flood,alert_detect_HTTP_Flood,alert_detect_UDP_Flood,alert_detect_ICMP_Flood
import json
def detect_SYN_Flod(sessions,SYN_FLAG_THRESHOLD):
    list_src_ip = []
    for session in sessions:
        timestamp = session.get("timestamp",{})
        network = session.get("network",{})
        flag = session.get("flag",{})
        src_ip = network.get("src_ip","")
        syn = flag.get("syn",0)
        if not any( item.get("src_ip","") == src_ip for item in list_src_ip):
            list_src_ip.append(
                {
                    "src_ip" : src_ip,
                    "SYN_Count" : syn
                }
            )
        else:
            for item in list_src_ip:
                if item.get("src_ip","") == src_ip:
                    item["SYN_Count"] = item.get("SYN_Count",0) + syn
    for item in list_src_ip:
        if item.get("SYN_Count",0) > SYN_FLAG_THRESHOLD :
           evidence = "SYN Flag = " + str( item.get("SYN_Count",0))
           alert_detect_SYN_Flood(item.get("src_ip"),evidence)
    return

def detect_HTTP_Flood(sessions,HTTP_REQUEST_THRESHOLD,HTTP_REQUEST_RATE_THRESHOLD):
    for session in sessions:
        timestamp = session.get("timestamp",{})
        network = session.get("network",{})
        packets = session.get("packets",{})
        http = session.get("http",{})
        connection = session.get("connection",{})
        duration = timestamp.get("duration",0)
        request_count = connection.get("request_count",0)
        dst_port = network.get("dst_port",0)
        forward = packets.get("forward",{})
        forward_count = forward.get("count",0)
        forward_bytes = forward.get("bytes",0)
        if duration > 0:
            request_rate = request_count / duration
        else:
            request_rate = 0
        if http.get("is_http"):
            if request_count > HTTP_REQUEST_THRESHOLD and request_rate > HTTP_REQUEST_RATE_THRESHOLD:
               evidence = " HTTP Request = " + str(request_count) + " AND Request Rate = "+str(request_rate)
               alert_detect_HTTP_Flood(network.get("src_ip"),evidence)
            if duration > 120 and dst_port == 80 and forward_bytes < 1000 and forward_count >= 2:
                evidence =" Duration > 120" + " dst_port = 80" + " forward bytes <1000"+ " forward packet >= 2"
                alert_detect_HTTP_Flood(network.get("src_ip"),evidence)
    return

def detect_UDP_Flood(sessions,UDP_PACKET_THRESHOLD,UDP_TOTAL_BYTES_THRESHOLD):
    for session in sessions:
        timestamp=session.get("timestamp",{})
        packets=session.get("packets",{})
        forward = packets.get("forward",{})
        network = session.get("network",{})
        protocol = network.get("protocol","")
        if protocol == "UDP":
            if forward.get("count",0) > UDP_PACKET_THRESHOLD and forward.get("bytes",0) > UDP_TOTAL_BYTES_THRESHOLD:
                evidence = "UDP Packet = "+ str(forward.get("count",0)) + " And Total bytes = " + str(forward.get("bytes",0))
                alert_detect_UDP_Flood(network.get("src_ip"),evidence)
    return

def detect_ICMP_Flood(sessions,ICMP_COUNT_THRESHOLD,ICMP_TOTAL_BYTES_THRESHOLD):
    list_ip_ICMP =[]
    Ping_of_death_list=[] #Return session
    for session in sessions:
        network = session.get("network",{})
        flow = session.get("flow",{})
        src_ip = network.get("src_ip","")
        protocol = network.get("protocol","")
        total_bytes = flow.get("total_bytes",0)
        if protocol != "ICMP":
            continue
        check = 0
        src_ip = network.get("src_ip","")
        for ip in list_ip_ICMP:
            if src_ip == ip.get("src_ip"):
                ip["counts"] += 1
                check = 1
                break
        if check == 0 :
            list_ip_ICMP.append(
                {
                    "src_ip": src_ip,
                    "counts": 1
                }
            )
        if total_bytes > ICMP_TOTAL_BYTES_THRESHOLD:
            Ping_of_death_list.append(session)
    for ip in list_ip_ICMP:
        if ip.get("counts",0) > ICMP_COUNT_THRESHOLD:
            evidence = "ICMP Count = " + str(ip.get("counts",0))
            alert_detect_ICMP_Flood (ip.get("src_ip",""),evidence)

    if Ping_of_death_list:
        for item in Ping_of_death_list:
            network = item.get("network",{})
            evidence = "ICMP Size: " + str( (item.get("flow",{})).get("total_bytes",0))
            alert_detect_ICMP_Flood(network.get("src_ip"),evidence)

def detect_dos_connection(sessions,DURATION_THRESHOLD,IP_COUNT_THRESHOLD):
    IP_List =[]
    for session in sessions:
        timestamp = session.get("timestamp",{})
        network = session.get("network",{})
        flow = session.get("flow",{})
        duration = timestamp.get("duration",0)
        src_ip = network.get("src_ip","")
        if src_ip not in IP_List:
            IP_List.append(src_ip)
        if duration > DURATION_THRESHOLD:
            evidence = "Duration = "+ str(duration)
            alert_detect_dos_connection(network.get("src_ip"),evidence)
        if len(IP_List) > IP_COUNT_THRESHOLD:
            evidence = "IP Count = " +str(len(IP_List))
            alert_detect_dos_connection("TOO MUCH IP",evidence)
    return
    
def detect_dos (sessions,rules):


    SYN_FLAG_THRESHOLD = rules.get("SYN_FLAG_THRESHOLD",0) #1000
    HTTP_REQUEST_THRESHOLD = rules.get("HTTP_REQUEST_THRESHOLD",0) #1000
    HTTP_REQUEST_RATE_THRESHOLD = rules.get("HTTP_REQUEST_RATE_THRESHOLD",0) #10
    UDP_PACKET_THRESHOLD = rules.get("UDP_PACKET_THRESHOLD",0) #1000
    UDP_TOTAL_BYTES_THRESHOLD = rules.get("UDP_TOTAL_BYTES_THRESHOLD",0) #65
    ICMP_COUNT_THRESHOLD = rules.get("ICMP_COUNT_THRESHOLD",0) #1000
    ICMP_TOTAL_BYTES_THRESHOLD = rules.get("ICMP_TOTAL_BYTES_THRESHOLD",0) #65535
    DURATION_THRESHOLD = rules.get("DURATION_THRESHOLD",0) #9600
    IP_COUNT_THRESHOLD = rules.get("IP_COUNT_THRESHOLD",0) #2000
    detect_SYN_Flod(sessions,SYN_FLAG_THRESHOLD)
    detect_HTTP_Flood(sessions,HTTP_REQUEST_THRESHOLD,HTTP_REQUEST_RATE_THRESHOLD)
    detect_UDP_Flood(sessions,UDP_PACKET_THRESHOLD,UDP_TOTAL_BYTES_THRESHOLD)
    detect_ICMP_Flood(sessions,ICMP_COUNT_THRESHOLD,ICMP_TOTAL_BYTES_THRESHOLD)
    detect_dos_connection(sessions,DURATION_THRESHOLD,IP_COUNT_THRESHOLD)
    return