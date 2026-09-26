def feature_extractor(session): #chỉ truyền vào session 2FIN/RST/timeout
    timestamp = session.get("timestamp",{})
    netwwork = session.get("network",{})
    flag = session.get("flag",{})
    packets = session.get("packets",{})
    forward = packets.get("forward",{})
    backward = session.get("backward",{})
    flow = session.get("flow",{})
    packet_length = flow.get("packet_length",{})
    iat = flow.get("iat",{})
    #=====================================================================
    dst_port= network.get("dst_port",0)
    flow_duration= timestamp.get("duration",0)
    total_fwd_packets= forward.get("count",0)
    total_backward_packets= backward.get("count",0)
    total_length_of_fwd_packets= forward.get("bytes",0)
    total_length_of_bwd_packets= backward.get("bytes",0)
    flow_bytes_per_second= flow.get("bytes_per_second",0)
    flow_packets_per_second= flow.get("packets_per_second",0)
    flow_iat_mean= iat.get("mean",0)
    flow_iat_std= iat.get("std",0)
    flow_iat_max= iat.get("max",0)
    flow_iat_min=iat.get("min",0)
    Fwd_Packets_per_sec=flow.get("fwd_packet_per_second",0.0)
    Bwd_Packets_per_sec=flow.get("bwd_packet_per_second",0.0)
    min_packet_length= packet_length.get("min",0)
    max_packet_length= packet_length.get("max",0)
    packet_length_mean= packet_length.get("mean",0)
    packet_length_std= packet_length.get("std",0)
    fin_flag_count= flag.get("fin",0)
    syn_flag_count= flag.get("syn",0)
    rst_flag_count= flag.get("rst",0)
    psh_flag_count= flag.get("psh",0)
    ack_flag_count= flag.get("ack",0)
    Init_Win_bytes_forward= flow.get("init_win_bytes_forward",0)
    Init_Win_bytes_backward= flow.get("init_win_bytes_backward",0)
    #====================================================================
    features = [
        dst_port,
        flow_duration,
        total_fwd_packets,
        total_backward_packets,
        total_length_of_fwd_packets,
        total_length_of_bwd_packets,
        flow_bytes_per_second,
        flow_packets_per_second,
        flow_iat_mean,
        flow_iat_std,
        flow_iat_max,
        flow_iat_min,
        fwd_packets_per_sec,
        bwd_packets_per_sec,
        min_packet_length,
        max_packet_length,
        packet_length_mean,
        packet_length_std,
        fin_flag_count,
        syn_flag_count,
        rst_flag_count,
        psh_flag_count,
        ack_flag_count,
        init_win_bytes_forward,
        init_win_bytes_backward
    ]

    return features
#Hỏi hiếu xem timeout duration có bằng 60s không