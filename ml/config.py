import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
IDS_DIR = os.path.dirname(BASE_DIR)                       # .../IDS/ids
REPO_ROOT = os.path.dirname(IDS_DIR)                       # .../IDS

DATA_DIR = os.path.join(REPO_ROOT, "data", "raw", "MachineLearningCVE")

CIC_FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
]

MODELS_DIR = os.path.join(BASE_DIR, "models", "saved")
os.makedirs(MODELS_DIR, exist_ok=True)

LABEL_ENCODER_PATH = os.path.join(MODELS_DIR, "label_encoder.pkl")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.pkl")
ML_MODEL_PATH = os.path.join(MODELS_DIR, "model.pkl")
DL_MODEL_PATH = os.path.join(MODELS_DIR, "model.pth")

LABEL_COL = "Label"

LEAK_COLUMNS = [
    "Flow ID", "Source IP", "Src IP", "Source Port", "Src Port",
    "Destination IP", "Dst IP", "Destination Port", "Dst Port",
    "Timestamp", "SimillarHTTP",
]

RANDOM_STATE = 42
TEST_SIZE = 0.2