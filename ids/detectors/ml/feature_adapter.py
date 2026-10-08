"""Convert the project's session schema into the CIC feature vector."""

from ids.detectors.ml.features import CIC_FEATURES


# The values use the same units as CIC-IDS-2017: durations/IAT in microseconds,
# packet/byte rates per second, and packet lengths in bytes.

def feature_extractor(session):
    """Return all CIC fields in the exact model-training order."""
    timestamp = session.get("timestamp", {})
    network = session.get("network", {})
    flags = session.get("flag", {})
    packets = session.get("packets", {})
    forward = packets.get("forward", {})
    backward = packets.get("backward", {})
    flow = session.get("flow", {})
    packet_length = flow.get("cic_packet_length", flow.get("packet_length", {}))
    iat = flow.get("iat", {})
    fwd_packet_length = flow.get("fwd_packet_length", {})
    bwd_packet_length = flow.get("bwd_packet_length", {})
    fwd_iat = flow.get("fwd_iat", {})
    bwd_iat = flow.get("bwd_iat", {})
    active = flow.get("active", {})
    idle = flow.get("idle", {})

    values = {
        # Preserve the actual destination port. CICFlowMeter never remaps a
        # lab service port such as 8080 to 80.
        "Destination Port": int(network.get("dst_port", 0) or 0),
        "Flow Duration": flow.get(
            "cic_duration_us", timestamp.get("duration", 0) * 1_000_000
        ),
        "Total Fwd Packets": forward.get("count", 0),
        "Total Backward Packets": backward.get("count", 0),
        "Total Length of Fwd Packets": forward.get("payload_bytes", forward.get("bytes", 0)),
        "Total Length of Bwd Packets": backward.get("payload_bytes", backward.get("bytes", 0)),
        "Fwd Packet Length Max": fwd_packet_length.get("max", 0),
        "Fwd Packet Length Min": fwd_packet_length.get("min", 0),
        "Fwd Packet Length Mean": fwd_packet_length.get("mean", 0),
        "Fwd Packet Length Std": fwd_packet_length.get("std", 0),
        "Bwd Packet Length Max": bwd_packet_length.get("max", 0),
        "Bwd Packet Length Min": bwd_packet_length.get("min", 0),
        "Bwd Packet Length Mean": bwd_packet_length.get("mean", 0),
        "Bwd Packet Length Std": bwd_packet_length.get("std", 0),
        "Flow Bytes/s": flow.get("cic_bytes_per_second", flow.get("bytes_per_second", 0)),
        "Flow Packets/s": flow.get("packets_per_second", 0),
        # SessionBuilder accumulates CIC IATs directly in integer microseconds.
        "Flow IAT Mean": iat.get("mean", 0),
        "Flow IAT Std": iat.get("std", 0),
        "Flow IAT Max": iat.get("max", 0),
        "Flow IAT Min": iat.get("min", 0),
        "Fwd IAT Total": fwd_iat.get("total", 0),
        "Fwd IAT Mean": fwd_iat.get("mean", 0),
        "Fwd IAT Std": fwd_iat.get("std", 0),
        "Fwd IAT Max": fwd_iat.get("max", 0),
        "Fwd IAT Min": fwd_iat.get("min", 0),
        "Bwd IAT Total": bwd_iat.get("total", 0),
        "Bwd IAT Mean": bwd_iat.get("mean", 0),
        "Bwd IAT Std": bwd_iat.get("std", 0),
        "Bwd IAT Max": bwd_iat.get("max", 0),
        "Bwd IAT Min": bwd_iat.get("min", 0),
        "Fwd PSH Flags": flow.get("fwd_psh_flags", 0),
        "Fwd Header Length": flow.get("fwd_header_length", 0),
        "Bwd Header Length": flow.get("bwd_header_length", 0),
        "Fwd Packets/s": flow.get("fwd_packet_per_second", 0),
        "Bwd Packets/s": flow.get("bwd_packet_per_second", 0),
        "Min Packet Length": packet_length.get("min", 0),
        "Max Packet Length": packet_length.get("max", 0),
        "Packet Length Mean": packet_length.get("mean", 0),
        "Packet Length Std": packet_length.get("std", 0),
        "Packet Length Variance": flow.get("packet_length_variance", 0),
        "FIN Flag Count": flags.get("fin", 0),
        "SYN Flag Count": flags.get("syn", 0),
        "PSH Flag Count": flags.get("psh", 0),
        "ACK Flag Count": flags.get("ack", 0),
        "URG Flag Count": flags.get("urg", 0),
        "Down/Up Ratio": flow.get("down_up_ratio", 0),
        "Average Packet Size": flow.get("average_packet_size", 0),
        "Avg Fwd Segment Size": flow.get("avg_fwd_segment_size", 0),
        "Avg Bwd Segment Size": flow.get("avg_bwd_segment_size", 0),
        "Init_Win_bytes_forward": flow.get("init_win_bytes_forward", 0),
        "Init_Win_bytes_backward": flow.get("init_win_bytes_backward", 0),
        "act_data_pkt_fwd": flow.get("act_data_pkt_fwd", 0),
        "min_seg_size_forward": flow.get("min_seg_size_forward", 0),
        "Active Mean": active.get("mean", 0),
        "Active Std": active.get("std", 0),
        "Active Max": active.get("max", 0),
        "Active Min": active.get("min", 0),
        "Idle Mean": idle.get("mean", 0),
        "Idle Std": idle.get("std", 0),
        "Idle Max": idle.get("max", 0),
        "Idle Min": idle.get("min", 0),
    }
    return [values[name] for name in CIC_FEATURES]
