"""
split_dataset.py - Chia dữ liệu Train/Test & SMOTE
=====================================================

Module này thực hiện 2 việc:
  1. Chia dữ liệu thành Train (80%) và Test (20%)
  2. Áp dụng SMOTE trên tập Train để cân bằng các lớp

💡 TẠI SAO CẦN CHIA TRAIN/TEST?
   - Train set: dùng để model HỌC
   - Test set: dùng để ĐÁNH GIÁ model (model chưa bao giờ thấy data này)
   - Nếu không chia → model "nhớ" toàn bộ data → overfitting
   - Stratified: giữ nguyên tỉ lệ mỗi lớp trong cả train và test

💡 SMOTE (Synthetic Minority Over-sampling Technique) LÀ GÌ?
   Dataset CIC-IDS 2017 rất MẤT CÂN BẰNG:
   - Benign: ~2,000,000 records (80%)
   - Web Attack: ~2,000 records (0.08%)

   Nếu train trực tiếp → model sẽ luôn đoán "Benign" (vì đúng 80%!)
   → Không phát hiện được tấn công

   SMOTE giải quyết bằng cách:
   1. Chọn 1 mẫu thuộc lớp thiểu số
   2. Tìm k mẫu gần nhất cùng lớp
   3. Tạo mẫu MỚI bằng cách nội suy giữa chúng
   → Các lớp có số lượng mẫu bằng nhau

   ⚠️ CHỈ SMOTE TRÊN TRAIN SET!
   Test set phải giữ nguyên phân phối thực tế để đánh giá chính xác.

📦 Thư viện:
   - sklearn.model_selection.train_test_split: chia data
   - imblearn.over_sampling.SMOTE: cân bằng lớp
"""

import numpy as np
from sklearn.model_selection import train_test_split
from imblearn.over_sampling import SMOTE

from ml.config import TEST_SIZE, RANDOM_STATE, CLASS_NAMES


def split_data(X, y):
    """
    Chia dữ liệu thành Train/Test (stratified).

    Parameters:
        X (np.ndarray): Features, shape (n_samples, n_features)
        y (np.ndarray): Labels, shape (n_samples,)

    Returns:
        X_train, X_test, y_train, y_test

    💡 Stratified Split:
       Đảm bảo tỉ lệ mỗi lớp trong train và test giống nhau.
       Ví dụ: nếu Benign chiếm 80% tổng → train 80% Benign, test 80% Benign
    """
    print("\n" + "=" * 60)
    print("✂️  BƯỚC 3: CHIA DỮ LIỆU TRAIN/TEST")
    print("=" * 60)

    train_pct = int((1 - TEST_SIZE) * 100)
    test_pct = int(TEST_SIZE * 100)

    print(f"\n[1/2] Stratified Split ({train_pct}/{test_pct})...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,  # Giữ tỉ lệ lớp
    )

    print(f"  → Train: {X_train.shape[0]:,} samples")
    print(f"  → Test:  {X_test.shape[0]:,} samples")

    # Hiển thị phân phối
    print(f"\n Phân phối trong Train set:")
    unique, counts = np.unique(y_train, return_counts=True)
    for class_id, count in zip(unique, counts):
        name = CLASS_NAMES[class_id] if class_id < len(CLASS_NAMES) else f"Class {class_id}"
        pct = count / len(y_train) * 100
        print(f"     {name:20s} ({class_id}): {count:>10,}  ({pct:5.2f}%)")

    return X_train, X_test, y_train, y_test


def apply_smote(X_train, y_train):
    """
    Áp dụng SMOTE để cân bằng các lớp trong tập train.

    Parameters:
        X_train (np.ndarray): Features tập train (đã scale)
        y_train (np.ndarray): Labels tập train

    Returns:
        X_resampled, y_resampled

    SMOTE synthetic samples:
       - KHÔNG đơn giản duplicate mẫu cũ
       - TẠO MỚI bằng cách nội suy giữa các mẫu gần nhau
       - Giúp model học được pattern đa dạng hơn
    """
    print(f"\n[2/2] Áp dụng SMOTE...")

    # Trước SMOTE
    unique, counts = np.unique(y_train, return_counts=True)
    print(f"\n TRƯỚC SMOTE:")
    for class_id, count in zip(unique, counts):
        name = CLASS_NAMES[class_id] if class_id < len(CLASS_NAMES) else f"Class {class_id}"
        bar = "█" * max(1, int(count / max(counts) * 30))
        print(f"     {name:20s}: {count:>10,}  {bar}")

    # Áp dụng SMOTE
    smote = SMOTE(
        random_state=RANDOM_STATE,
        n_jobs=-1,     # Dùng tất cả CPU cores
    )
    X_resampled, y_resampled = smote.fit_resample(X_train, y_train)

    # Sau SMOTE
    unique, counts = np.unique(y_resampled, return_counts=True)
    print(f"\n  SAU SMOTE:")
    for class_id, count in zip(unique, counts):
        name = CLASS_NAMES[class_id] if class_id < len(CLASS_NAMES) else f"Class {class_id}"
        bar = "█" * max(1, int(count / max(counts) * 30))
        print(f"     {name:20s}: {count:>10,}  {bar}")

    print(f"\n  → Tổng: {len(y_train):,} → {len(y_resampled):,} samples")
    print(f"  → Tất cả lớp giờ đều có {counts[0]:,} samples ✅")

    return X_resampled, y_resampled

