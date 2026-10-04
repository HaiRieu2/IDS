"""Normalize CIC-IDS flow CSVs into the model's shared feature schema."""

from pathlib import Path

import numpy as np
import pandas as pd

from ids.detectors.ml.features import CIC_FEATURES


# CICFlowMeter-V3 (CSE-CIC-IDS2018) uses abbreviated headers for many fields.
# Keys are the names used by the live IDS and CIC-IDS-2017 training files.
CIC_COLUMN_ALIASES = {
    "Destination Port": ("Destination Port", "Dst Port"),
    "Flow Duration": ("Flow Duration",),
    "Total Fwd Packets": ("Total Fwd Packets", "Tot Fwd Pkts"),
    "Total Backward Packets": ("Total Backward Packets", "Tot Bwd Pkts"),
    "Total Length of Fwd Packets": ("Total Length of Fwd Packets", "TotLen Fwd Pkts"),
    "Total Length of Bwd Packets": ("Total Length of Bwd Packets", "TotLen Bwd Pkts"),
    "Fwd Packet Length Max": ("Fwd Packet Length Max", "Fwd Pkt Len Max"),
    "Fwd Packet Length Min": ("Fwd Packet Length Min", "Fwd Pkt Len Min"),
    "Fwd Packet Length Mean": ("Fwd Packet Length Mean", "Fwd Pkt Len Mean"),
    "Fwd Packet Length Std": ("Fwd Packet Length Std", "Fwd Pkt Len Std"),
    "Bwd Packet Length Max": ("Bwd Packet Length Max", "Bwd Pkt Len Max"),
    "Bwd Packet Length Min": ("Bwd Packet Length Min", "Bwd Pkt Len Min"),
    "Bwd Packet Length Mean": ("Bwd Packet Length Mean", "Bwd Pkt Len Mean"),
    "Bwd Packet Length Std": ("Bwd Packet Length Std", "Bwd Pkt Len Std"),
    "Flow Bytes/s": ("Flow Bytes/s", "Flow Byts/s"),
    "Flow Packets/s": ("Flow Packets/s", "Flow Pkts/s"),
    "Flow IAT Mean": ("Flow IAT Mean",),
    "Flow IAT Std": ("Flow IAT Std",),
    "Flow IAT Max": ("Flow IAT Max",),
    "Flow IAT Min": ("Flow IAT Min",),
    "Fwd IAT Total": ("Fwd IAT Total", "Fwd IAT Tot"),
    "Fwd IAT Mean": ("Fwd IAT Mean",),
    "Fwd IAT Std": ("Fwd IAT Std",),
    "Fwd IAT Max": ("Fwd IAT Max",),
    "Fwd IAT Min": ("Fwd IAT Min",),
    "Bwd IAT Total": ("Bwd IAT Total", "Bwd IAT Tot"),
    "Bwd IAT Mean": ("Bwd IAT Mean",),
    "Bwd IAT Std": ("Bwd IAT Std",),
    "Bwd IAT Max": ("Bwd IAT Max",),
    "Bwd IAT Min": ("Bwd IAT Min",),
    "Fwd PSH Flags": ("Fwd PSH Flags",),
    "Bwd PSH Flags": ("Bwd PSH Flags",),
    "Fwd URG Flags": ("Fwd URG Flags",),
    "Bwd URG Flags": ("Bwd URG Flags",),
    "Fwd Header Length": ("Fwd Header Length", "Fwd Header Len"),
    "Bwd Header Length": ("Bwd Header Length", "Bwd Header Len"),
    "Fwd Packets/s": ("Fwd Packets/s", "Fwd Pkts/s"),
    "Bwd Packets/s": ("Bwd Packets/s", "Bwd Pkts/s"),
    "Min Packet Length": ("Min Packet Length", "Pkt Len Min"),
    "Max Packet Length": ("Max Packet Length", "Pkt Len Max"),
    "Packet Length Mean": ("Packet Length Mean", "Pkt Len Mean"),
    "Packet Length Std": ("Packet Length Std", "Pkt Len Std"),
    "Packet Length Variance": ("Packet Length Variance", "Pkt Len Var"),
    "FIN Flag Count": ("FIN Flag Count", "FIN Flag Cnt"),
    "SYN Flag Count": ("SYN Flag Count", "SYN Flag Cnt"),
    "RST Flag Count": ("RST Flag Count", "RST Flag Cnt"),
    "PSH Flag Count": ("PSH Flag Count", "PSH Flag Cnt"),
    "ACK Flag Count": ("ACK Flag Count", "ACK Flag Cnt"),
    "URG Flag Count": ("URG Flag Count", "URG Flag Cnt"),
    "CWE Flag Count": ("CWE Flag Count", "CWE Flag Cnt"),
    "ECE Flag Count": ("ECE Flag Count", "ECE Flag Cnt"),
    "Down/Up Ratio": ("Down/Up Ratio", "Down Up Ratio"),
    "Average Packet Size": ("Average Packet Size", "Pkt Size Avg"),
    "Avg Fwd Segment Size": ("Avg Fwd Segment Size", "Fwd Seg Size Avg"),
    "Avg Bwd Segment Size": ("Avg Bwd Segment Size", "Bwd Seg Size Avg"),
    "Init_Win_bytes_forward": ("Init_Win_bytes_forward", "Init Fwd Win Byts"),
    "Init_Win_bytes_backward": ("Init_Win_bytes_backward", "Init Bwd Win Byts"),
    "act_data_pkt_fwd": ("act_data_pkt_fwd", "Act Data Pkt Fwd", "Fwd Act Data Pkts"),
    "min_seg_size_forward": ("min_seg_size_forward", "Fwd Seg Size Min"),
    "Active Mean": ("Active Mean",),
    "Active Std": ("Active Std",),
    "Active Max": ("Active Max",),
    "Active Min": ("Active Min",),
    "Idle Mean": ("Idle Mean",),
    "Idle Std": ("Idle Std",),
    "Idle Max": ("Idle Max",),
    "Idle Min": ("Idle Min",),
}


def _canonical_label(label):
    """Map equivalent web attack labels while preserving FTP/SSH brute force."""
    original = str(label).strip()
    key = " ".join(original.casefold().replace("–", "-").replace("�", "-").split())
    compact = " ".join(key.replace("-", " ").split())

    if "heartbleed" in compact:
        return None
    if compact == "benign":
        return "BENIGN"
    if "sql injection" in compact or compact in {"sqli", "sql i"}:
        return "Sqli"
    if "xss" in compact or "cross site scripting" in compact:
        return "XSS"
    if "web" in compact and "brute force" in compact:
        return "Web Attack - Brute Force"
    # CIC-IDS-2018 writes these as "Brute Force -Web" and
    # "Brute Force -XSS"; the latter is already handled by the XSS rule.
    return original


def normalize_columns(data):
    """Rename available CIC 2017/2018 aliases into the runtime feature names."""
    data = data.copy()
    data.columns = data.columns.astype(str).str.strip()
    if "Label" not in data.columns:
        raise ValueError("Dataset không có cột Label.")

    rename = {}
    for canonical, aliases in CIC_COLUMN_ALIASES.items():
        found = next((name for name in aliases if name in data.columns), None)
        if found is not None and found != canonical:
            rename[found] = canonical
    return data.rename(columns=rename)


def data_processing(data):
    """Clean feature values and standardize attack class names."""
    data = normalize_columns(data)
    required = list(CIC_FEATURES) + ["Label"]
    missing = [name for name in required if name not in data.columns]
    if missing:
        raise ValueError("Thiếu cột CIC cần thiết: " + ", ".join(missing))

    data = data[required].copy()
    data["Label"] = data["Label"].map(_canonical_label)
    data = data[data["Label"].notna()].reset_index(drop=True)
    for column in CIC_FEATURES:
        data[column] = pd.to_numeric(data[column], errors="coerce")
    data.loc[:, CIC_FEATURES] = data.loc[:, CIC_FEATURES].replace([np.inf, -np.inf], np.nan)
    # CIC exports may use -1 as a missing/undefined measurement sentinel.
    data.loc[:, CIC_FEATURES] = data.loc[:, CIC_FEATURES].replace(-1, 0)
    data.loc[:, CIC_FEATURES] = data.loc[:, CIC_FEATURES].fillna(0)
    return data


def read_cic_csv(path, chunksize=100_000):
    """Read only label + model features, accepting CIC-IDS-2017/2018 headers."""
    path = Path(path)
    header = pd.read_csv(path, nrows=0, low_memory=False, encoding_errors="replace")
    columns = [str(name).strip() for name in header.columns]
    aliases = {alias for values in CIC_COLUMN_ALIASES.values() for alias in values}
    selected = [name for name in columns if name == "Label" or name in aliases]
    missing = [canonical for canonical, names in CIC_COLUMN_ALIASES.items()
               if not any(name in selected for name in names)]
    if "Label" not in selected or missing:
        raise ValueError(f"{path.name}: thiếu cột Label/đặc trưng: {missing}")

    chunks = []
    for chunk in pd.read_csv(
        path, usecols=lambda name: str(name).strip() in selected,
        chunksize=chunksize, low_memory=False, encoding_errors="replace",
    ):
        chunks.append(data_processing(chunk))
    if not chunks:
        raise ValueError(f"CSV không có dòng dữ liệu: {path}")
    return pd.concat(chunks, ignore_index=True)
