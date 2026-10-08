"""Read and clean CIC-IDS-2017 flow CSVs for the IDS model."""

from pathlib import Path

import numpy as np
import pandas as pd

from ids.detectors.ml.features import CIC_FEATURES


def _canonical_label(label):
    """Normalize CIC label spelling, including labels with broken separators."""
    original = str(label).strip()
    # Replace dashes and the broken-character symbol (�) with spaces, then
    # collapse repeated whitespace so label variants compare consistently.
    compact = original.casefold()
    for separator in ("-", "–", "—", "\ufffd"):
        compact = compact.replace(separator, " ")
    compact = " ".join(compact.split())

    # Heartbleed is omitted because it is not part of the model's target classes.
    if "heartbleed" in compact:
        return None
    if compact == "benign":
        return "BENIGN"
    if compact in {"dos hulk", "dos goldeneye"}:
        return "HTTP Flood"
    if compact in {"dos slowloris", "dos slowhttptest"}:
        return "HTTP slow"
    # SQLi and XSS are out of scope for this flow model; drop these rows.
    if compact in {
        "sql injection", "sqli", "sql i", "web attack sql injection",
        "web attack xss", "xss", "cross site scripting",
    }:
        return None
    if compact in {"web attack brute force", "brute force web"}:
        return "Web Attack - Brute Force"

    # Preserve other CIC-IDS-2017 labels such as FTP-Patator and SSH-Patator.
    return None


def data_processing(data):
    """Keep model columns, normalize labels, and clean numeric features."""

    data.columns = data.columns.astype(str).str.strip()
    required_columns = list(CIC_FEATURES) + ["Label"]

    data = data[required_columns].copy()
    data["Label"] = data["Label"].map(_canonical_label)
    data = data[data["Label"].notna()].reset_index(drop=True)

    # Convert features to numbers and replace invalid values with zero.
    for column in CIC_FEATURES:
        data[column] = pd.to_numeric(data[column], errors="coerce")
    data.loc[:, CIC_FEATURES] = data.loc[:, CIC_FEATURES].replace(
        [np.inf, -np.inf], np.nan
    )
    data.loc[:, CIC_FEATURES] = data.loc[:, CIC_FEATURES].replace(-1, 0)
    data.loc[:, CIC_FEATURES] = data.loc[:, CIC_FEATURES].fillna(0)
    return data


def read_cic_csv(path, chunksize=100_000):
    """Read the required CIC-IDS-2017 columns in chunks to limit memory use."""
    path = Path(path)
    header = pd.read_csv(
        path,
        nrows=0,
        low_memory=False,
        encoding_errors="replace",
    )
    
    source_columns = [str(name).strip() for name in header.columns]
    required_columns = set(CIC_FEATURES) | {"Label"}
    selected_columns = required_columns.intersection(source_columns)

    chunks = []
    for chunk in pd.read_csv(
        path,
        usecols=lambda name: str(name).strip() in required_columns,
        chunksize=chunksize,
        low_memory=False,
        encoding_errors="replace",
    ):
        chunks.append(data_processing(chunk))

    if not chunks:
        raise ValueError(f"CSV không có dòng dữ liệu: {path}")
    return pd.concat(chunks, ignore_index=True)
