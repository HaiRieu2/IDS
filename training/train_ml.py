"""
train_ml.py - Huấn luyện Model Machine Learning (Random Forest)
================================================================

Module này huấn luyện Random Forest Classifier để phát hiện xâm nhập mạng.

💡 RANDOM FOREST LÀ GÌ?
   Hãy tưởng tượng bạn hỏi 200 người (200 cây quyết định) cùng 1 câu hỏi:
   "Đây là tấn công hay bình thường?"
   Mỗi người nhìn dữ liệu từ 1 góc khác nhau và đưa ra câu trả lời.
   Kết quả cuối = câu trả lời đa số (majority voting).

   Tại sao Random Forest tốt cho IDS?
   ┌─────────────────────────────────────────────────────┐
   │ ✅ Nhanh - train/predict nhanh, không cần GPU      │
   │ ✅ Mạnh - accuracy cao trên dữ liệu dạng bảng     │
   │ ✅ Robust - ít bị overfitting nhờ bagging           │
   │ ✅ Giải thích được - feature importance              │
   │ ✅ Ít tuning - hoạt động tốt với default params     │
   └─────────────────────────────────────────────────────┘

📦 Thư viện:
   - sklearn.ensemble.RandomForestClassifier: thuật toán Random Forest
   - joblib: lưu model ra file .pkl
"""

import time
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

from ml.config import ML_PARAMS, ML_MODEL_PATH, CLASS_NAMES


def train_ml_model(X_train, y_train, X_test, y_test, feature_names=None):
    """
    Huấn luyện Random Forest Classifier.

    Parameters:
        X_train (np.ndarray): Features tập train (đã scale, đã SMOTE)
        y_train (np.ndarray): Labels tập train
        X_test (np.ndarray): Features tập test (đã scale)
        y_test (np.ndarray): Labels tập test
        feature_names (list, optional): Tên các features (để hiển thị importance)

    Returns:
        model: Model đã train
        accuracy (float): Accuracy trên test set
        training_time (float): Thời gian train (giây)

    Quy trình:
        1. Tạo RandomForestClassifier với hyperparameters từ config
        2. Fit model trên X_train, y_train
        3. Predict trên X_test để đánh giá nhanh
        4. Hiển thị top 20 features quan trọng nhất
        5. Lưu model ra file .pkl
    """
    print("\n" + "=" * 60)
    print("🌲 HUẤN LUYỆN MODEL: RANDOM FOREST (Machine Learning)")
    print("=" * 60)

    # ── HIỂN THỊ HYPERPARAMETERS ──
    print(f"\n⚙️  Hyperparameters:")
    for key, value in ML_PARAMS.items():
        print(f"  {key:25s} = {value}")

    print(f"\n📐 Dataset:")
    print(f"  Train: {X_train.shape[0]:,} samples × {X_train.shape[1]} features")
    print(f"  Test:  {X_test.shape[0]:,} samples × {X_test.shape[1]} features")

    # ── TẠO MODEL ──
    # ** là "unpack dictionary" → truyền key=value từ dict vào function
    model = RandomForestClassifier(**ML_PARAMS)

    # ── TRAIN ──
    print(f"\n🏋️  Đang huấn luyện {ML_PARAMS['n_estimators']} cây quyết định...")
    print(f"   (sử dụng {ML_PARAMS.get('n_jobs', 1)} CPU cores)")

    start_time = time.time()
    model.fit(X_train, y_train)
    training_time = time.time() - start_time

    print(f"\n✅ Hoàn thành trong {training_time:.1f} giây!")

    # ── ĐÁNH GIÁ NHANH ──
    print(f"\n📊 Đánh giá nhanh trên Test set:")
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"   Accuracy: {accuracy:.4f} ({accuracy * 100:.2f}%)")

    # ── FEATURE IMPORTANCE ──
    # Random Forest cho biết mỗi feature đóng góp bao nhiêu % vào quyết định
    print(f"\n🔝 Top 20 Features quan trọng nhất:")
    importances = model.feature_importances_
    top_indices = np.argsort(importances)[::-1][:20]

    for rank, idx in enumerate(top_indices, 1):
        name = feature_names[idx] if feature_names else f"Feature [{idx}]"
        importance = importances[idx]
        bar = "█" * int(importance * 100)
        print(f"  {rank:2d}. {name:35s} {importance:.4f}  {bar}")

    # ── LƯU MODEL ──
    # joblib.dump: lưu object Python ra file
    # Sau này dùng joblib.load() để load lại
    joblib.dump(model, ML_MODEL_PATH)
    print(f"\n💾 Model đã lưu: {ML_MODEL_PATH}")
    file_size = __import__("os").path.getsize(ML_MODEL_PATH) / 1024**2
    print(f"   Kích thước: {file_size:.1f} MB")

    return model, accuracy, training_time

