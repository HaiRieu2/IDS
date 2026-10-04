from ids.alert.alert import alert_machine_learning
from .feature_adapter import feature_extractor
from config.path import MACHINE_LEARNING_DIR
import joblib
import numpy as np
import json
import pandas as pd
from .features import CIC_FEATURES
MODEL_PATH = MACHINE_LEARNING_DIR/("rf_model.pkl")
model = joblib.load(MODEL_PATH)
# LiveCapture/Flask invokes inference from its packet-processing thread. Using
# joblib workers for one flow at a time is slower and triggers scikit-learn's
# configuration-propagation warning on each predict/predict_proba call. A
# single worker keeps the same trained trees and predictions without that
# per-flow parallel overhead.
model.set_params(n_jobs=1)

def ml_engine(session):
    """Classify one CIC-compatible flow and alert on a non-BENIGN prediction."""
    # CICFlowMeter's CSV exporter omits flows with one or fewer packets.
    # Keep those tiny sessions available to behavior/signature engines, but do
    # not feed feature vectors to a model trained on CICFlowMeter CSV rows.
    packet_count = int(session.get("packets", {}).get("total", 0) or 0)
    if packet_count <= 1:
        print("[ML] Skip flow with <= 1 packet (not present in CICFlowMeter training rows).")
        return

    features = feature_extractor(session)
    values = np.nan_to_num(
        np.asarray([[float(value or 0) for value in features]], dtype=np.float64),
        nan=0.0, posinf=0.0, neginf=0.0,
    )
    # Pass column names as well as values so scikit-learn can verify the
    # expanded training schema and order at inference time.
    X = pd.DataFrame(values, columns=CIC_FEATURES)
    prediction = model.predict(X)
    result = str(prediction[0])
    confidence = 1.0
    attack_probability = 0.0
    try:
        probabilities = model.predict_proba(X)[0]
        classes = [str(label) for label in model.classes_]
        attack_scores = [(label, float(prob)) for label, prob in zip(classes, probabilities)
                         if label.upper() != "BENIGN"]
        if attack_scores:
            attack_label, attack_probability = max(attack_scores, key=lambda item: item[1])
            predicted_probability = dict(zip(classes, probabilities)).get(result, 1.0)
            confidence = float(predicted_probability)
            with open(MACHINE_LEARNING_DIR.parent / "config" / "rules.json", encoding="utf-8") as f:
                threshold = float(json.load(f).get("ML_ALERT_THRESHOLD", 0.30))
            # Recall-oriented backstop: surface a plausible attack even when
            # the model's winning class is BENIGN. This trades precision for recall.
            if result.upper() == "BENIGN" and attack_probability >= threshold:
                result = attack_label
                confidence = attack_probability
    except (AttributeError, ValueError, OSError, json.JSONDecodeError):
        pass

    print(f"[ML] Prediction result: {result} (confidence={confidence:.3f})")
    if result.upper() != "BENIGN":
        network = session.get("network",{})
        src_ip = network.get("src_ip", "")
        alert_machine_learning(src_ip, result, confidence=confidence)
    return


