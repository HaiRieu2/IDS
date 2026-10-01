from ids.alert.alert import alert_machine_learning
from .feature_adapter import feature_extractor
from config.path import MACHINE_LEARNING_DIR
import joblib
import numpy as np
MODEL_PATH = MACHINE_LEARNING_DIR/("rf_model.pkl")
model = joblib.load(MODEL_PATH)
def ml_engine(session):
    feature = feature_extractor(session)
    X = np.array([features])
    prediction = model.predict(X)
    result = prediction[0]
    print("[ML] Prediction result:", result)
    if result != "BENIGN":
        network = session.get("network",{})
        src_ip = network.get("src_ip",{})
        alert_machine_learning(src_ip,result)
    return


