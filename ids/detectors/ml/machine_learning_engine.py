from ids.alert.alert import alert_machine_learning
from feature_adapter import feature_extractor
MODEL_PATH = MACHINE_LEARNING_DIR/("rf_model.pkl")
model = joblib.load(MODEL_PATH)
def ml_engine(session):
    feature = feature_extractor(session)
    X = np.array([features])
    prediction = model.predict(X)
    result = prediction[0]
    alert_machine_learning(result)
    return


