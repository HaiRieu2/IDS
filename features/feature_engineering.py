"""
feature_engineering.py - Chuẩn hóa Features & Encode Labels
=============================================================

Module này thực hiện 2 việc chính:
  1. Label Encoding: chuyển tên label (text) → số (0, 1, 2, ...)
  2. Feature Scaling: chuẩn hóa giá trị features về cùng 1 thang đo

   Các features có phạm vi khác nhau:
   - Flow Duration: 0 → 120,000,000 (microseconds)
   - Total Fwd Packets: 0 → 50,000
   - Flow Bytes/s: 0 → 1,000,000,000

   StandardScaler: chuyển mỗi feature về mean=0, std=1
   Công thức: X_scaled = (X - mean) / std
"""

import numpy as np
import joblib
from sklearn.preprocessing import StandardScaler, LabelEncoder

from ml.config import SCALER_PATH, LABEL_ENCODER_PATH, CLASS_NAMES


def prepare_features(df):
    """
    Tách features (X) và labels (y) từ DataFrame, encode labels.

    Hàm này KHÔNG scale features.
    Scaling được thực hiện SAU KHI split train/test (để tránh data leakage).

    Parameters:
        df (pd.DataFrame): DataFrame đã clean (từ clean_dataset.py)

    Returns:
        X (np.ndarray): Ma trận features, shape (n_samples, n_features)
        y (np.ndarray): Vector labels (đã encode thành số), shape (n_samples,)
        feature_names (list): Danh sách tên các features

       Nếu ta fit scaler trên TOÀN BỘ data (bao gồm cả test set),
       thì scaler đã "biết" thông tin từ test set → model gián tiếp
       "nhìn thấy" test data → kết quả đánh giá bị lạc quan (cao giả).
       → Giải pháp: chỉ fit scaler trên training set.
    """
    print("\n" + "=" * 60)
    print("BƯỚC 2: FEATURE ENGINEERING")
    print("=" * 60)

    # ── TÁCH X VÀ Y ──
    # X = tất cả cột trừ "Label" (features)
    # y = chỉ cột "Label" (nhãn cần dự đoán)
    print("\n[1/2] Tách Features (X) và Labels (y)...")

    y_raw = df["Label"].values           # Array string: ["Benign", "DDoS", ...]
    X = df.drop(columns=["Label"]).values # Matrix số: [[0.5, 1.2, ...], ...]
    feature_names = df.drop(columns=["Label"]).columns.tolist()

    print(f"  → X shape: {X.shape} ({X.shape[0]:,} mẫu × {X.shape[1]} features)")
    print(f"  → y shape: {y_raw.shape}")

    # ── LABEL ENCODING ──
    # Chuyển text → số: "Benign"→0, "Brute Force"→1, "DDoS"→2, ...
    print("\n[2/2] Label Encoding (chuyển text → số)...")

    le = LabelEncoder()
    # Fit trên CLASS_NAMES (đã sort alphabet) để đảm bảo thứ tự cố định
    le.fit(CLASS_NAMES)
    y = le.transform(y_raw)

    # Hiển thị mapping
    print(f"  → Encoding mapping:")
    for class_name, class_id in zip(le.classes_, le.transform(le.classes_)):
        count = (y == class_id).sum()
        print(f"     {class_name:20s} → {class_id}  ({count:,} mẫu)")

    # Lưu LabelEncoder (để dùng khi predict)
    joblib.dump(le, LABEL_ENCODER_PATH)
    print(f"\n  💾 LabelEncoder đã lưu: {LABEL_ENCODER_PATH}")

    return X, y, feature_names


def fit_and_save_scaler(X_train):
    """
    Fit StandardScaler trên tập TRAIN và lưu lại.

    CHỈ FIT TRÊN X_TRAIN, KHÔNG FIT TRÊN X_TEST!

    Parameters:
        X_train (np.ndarray): Features của tập train

    Returns:
        StandardScaler: Scaler đã fit

    StandardScaler
       1. Tính mean và std của mỗi feature trên X_train
       2. Transform: X_scaled = (X - mean) / std
       3. Sau transform: mỗi feature có mean ≈ 0, std ≈ 1
    """
    print("\n Fitting StandardScaler trên training set...")

    scaler = StandardScaler()
    scaler.fit(X_train)

    # Lưu scaler (để dùng khi predict)
    joblib.dump(scaler, SCALER_PATH)
    print(f"  Scaler đã lưu: {SCALER_PATH}")

    return scaler


def scale_features(X, scaler=None):
    """
    Áp dụng StandardScaler lên features.

    Parameters:
        X (np.ndarray): Features cần scale
        scaler (StandardScaler, optional): Scaler đã fit.
            Nếu None, sẽ load từ file đã lưu.

    Returns:
        np.ndarray: Features đã scale
    """
    if scaler is None:
        scaler = joblib.load(SCALER_PATH)

    X_scaled = scaler.transform(X)

    return X_scaled

