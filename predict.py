"""
predict.py - Module Predict cho Backend
=========================================

Module này cung cấp class IDSPredictor để:
  1. Load model đã train (ML hoặc DL)
  2. Nhận network flow features
  3. Trả về prediction: loại traffic + confidence score

Cách sử dụng:
  from ml.predict import IDSPredictor

  # Dùng ML model (nhanh hơn)
  predictor = IDSPredictor(model_type='ml')

  # Dùng DL model (chính xác hơn)
  predictor = IDSPredictor(model_type='dl')

  # Predict
  result = predictor.predict(features_array)
  # → {'label': 'DDoS', 'confidence': 0.98, 'is_attack': True, ...}

💡 MODULE NÀY DÙNG Ở ĐÂU?
   Backend (Flask/FastAPI) sẽ gọi module này khi nhận được network flow data.
   Quy trình:
     Web/Network → Backend nhận data → IDSPredictor.predict()
     → Trả kết quả → Dashboard hiển thị → Lưu vào Database
"""

import numpy as np
import joblib
import torch

from ml.config import (
    ML_MODEL_PATH,
    DL_MODEL_PATH,
    SCALER_PATH,
    LABEL_ENCODER_PATH,
    CLASS_NAMES,
)
from ml.training.train_dl import CNNLSTM


class IDSPredictor:
    """
    Predictor cho hệ thống IDS.

    Attributes:
        model_type (str): 'ml' hoặc 'dl'
        model: Model đã train
        scaler: StandardScaler đã fit
        label_encoder: LabelEncoder đã fit

    💡 Tại sao tách thành class riêng?
       - Load model 1 lần, predict nhiều lần (nhanh hơn)
       - Dễ tích hợp vào backend
       - Quản lý resources gọn gàng
    """

    def __init__(self, model_type="ml"):
        """
        Khởi tạo predictor.

        Parameters:
            model_type (str): Loại model
                - 'ml': Random Forest (nhanh, accuracy tốt)
                - 'dl': CNN-LSTM (chính xác hơn, chậm hơn)
        """
        self.model_type = model_type

        # Load scaler và label encoder
        print(f"🔄 Loading {model_type.upper()} predictor...")
        self.scaler = joblib.load(SCALER_PATH)
        self.label_encoder = joblib.load(LABEL_ENCODER_PATH)
        print(f"  ✅ Scaler loaded")
        print(f"  ✅ LabelEncoder loaded")

        # Load model
        if model_type == "ml":
            self.model = joblib.load(ML_MODEL_PATH)
            print(f"  ✅ Random Forest model loaded")
        elif model_type == "dl":
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            checkpoint = torch.load(
                DL_MODEL_PATH, map_location=self.device, weights_only=False
            )
            self.model = CNNLSTM(
                checkpoint["input_size"],
                checkpoint["num_classes"],
                checkpoint["params"],
            ).to(self.device)
            self.model.load_state_dict(checkpoint["model_state_dict"])
            self.model.eval()
            print(f"  ✅ CNN-LSTM model loaded (device: {self.device})")
        else:
            raise ValueError(f"model_type phải là 'ml' hoặc 'dl', nhận: {model_type}")

        print(f"🛡️  Predictor sẵn sàng!")

    def predict(self, features):
        """
        Dự đoán loại network traffic.

        Parameters:
            features: Có thể là:
                - np.ndarray shape (n_features,) → 1 sample
                - np.ndarray shape (n_samples, n_features) → nhiều samples
                - dict {feature_name: value} → 1 sample
                - list of dict → nhiều samples

        Returns:
            dict hoặc list of dict:
            {
                'label': 'DDoS',           # Tên loại traffic
                'confidence': 0.98,         # Độ tin cậy (0-1)
                'is_attack': True,          # True nếu là tấn công
                'probabilities': {          # Xác suất cho từng lớp
                    'Benign': 0.01,
                    'Brute Force': 0.00,
                    'DDoS': 0.98,
                    ...
                }
            }
        """
        # ── Chuẩn hóa input ──
        if isinstance(features, dict):
            features = np.array(list(features.values()), dtype=np.float32).reshape(1, -1)
        elif isinstance(features, list) and isinstance(features[0], dict):
            features = np.array(
                [list(d.values()) for d in features], dtype=np.float32
            )

        features = np.asarray(features, dtype=np.float32)
        if features.ndim == 1:
            features = features.reshape(1, -1)

        # ── Scale features ──
        features_scaled = self.scaler.transform(features)

        # ── Predict ──
        if self.model_type == "ml":
            pred = self.model.predict(features_scaled)
            prob = self.model.predict_proba(features_scaled)
        else:
            with torch.no_grad():
                X_tensor = torch.FloatTensor(features_scaled).to(self.device)
                outputs = self.model(X_tensor)
                prob = torch.softmax(outputs, dim=1).cpu().numpy()
                pred = outputs.argmax(dim=1).cpu().numpy()

        # ── Decode labels ──
        labels = self.label_encoder.inverse_transform(pred)

        # ── Tạo kết quả ──
        results = []
        for i in range(len(pred)):
            result = {
                "label": labels[i],
                "confidence": float(np.max(prob[i])),
                "is_attack": labels[i] != "Benign",
                "class_id": int(pred[i]),
                "probabilities": {
                    name: float(prob[i][j])
                    for j, name in enumerate(CLASS_NAMES)
                },
            }
            results.append(result)

        # Trả về dict nếu chỉ 1 sample, list nếu nhiều
        return results[0] if len(results) == 1 else results

    def predict_batch(self, features_array, batch_size=1024):
        """
        Predict cho nhiều samples (hiệu quả hơn cho DL model).

        Parameters:
            features_array (np.ndarray): Shape (n_samples, n_features)
            batch_size (int): Số samples per batch

        Returns:
            list of dict: Kết quả prediction cho mỗi sample
        """
        all_results = []

        for i in range(0, len(features_array), batch_size):
            batch = features_array[i: i + batch_size]
            batch_results = self.predict(batch)
            if isinstance(batch_results, dict):
                batch_results = [batch_results]
            all_results.extend(batch_results)

        return all_results


# ═══════════════════════════════════════════════════════
# CHẠY THỬ
# ═══════════════════════════════════════════════════════
if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    print("=" * 60)
    print("🧪 TEST PREDICT MODULE")
    print("=" * 60)

    # Test ML predictor
    print("\n── Test ML Predictor ──")
    ml_predictor = IDSPredictor(model_type="ml")

    # Tạo random input (78 features)
    dummy_input = np.random.randn(78).astype(np.float32)
    result = ml_predictor.predict(dummy_input)
    print(f"\nKết quả: {result}")

    # Test DL predictor
    print("\n── Test DL Predictor ──")
    dl_predictor = IDSPredictor(model_type="dl")
    result = dl_predictor.predict(dummy_input)
    print(f"\nKết quả: {result}")

