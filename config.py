"""
config.py - Cấu hình trung tâm cho toàn bộ ML/DL Pipeline
===========================================================

File này chứa TẤT CẢ các cấu hình cần thiết:
  - Đường dẫn đến dataset, models, reports
  - Danh sách file CSV của CIC-IDS 2017
  - Mapping label (gom nhóm các loại tấn công)
  - Hyperparameters cho ML model (Random Forest)
  - Hyperparameters cho DL model (CNN-LSTM)
  - Các hằng số khác

💡 TẠI SAO CẦN FILE CONFIG RIÊNG?
   → Tập trung tất cả cấu hình vào 1 nơi, dễ thay đổi
   → Không cần sửa code trong các module khác khi muốn điều chỉnh
   → Tránh hardcode đường dẫn, số liệu rải rác khắp nơi
"""

import os

# ╔══════════════════════════════════════════════════════════════╗
# ║                     ĐƯỜNG DẪN (PATHS)                       ║
# ╚══════════════════════════════════════════════════════════════╝

# __file__ là đường dẫn đến file config.py này
# os.path.dirname() lấy thư mục cha
# Ví dụ: nếu file này ở F:/VSCODE/IDS/ml/config.py
#   → BASE_DIR = F:/VSCODE/IDS/ml
#   → REPO_ROOT = F:/VSCODE/IDS

BASE_DIR = os.path.dirname(os.path.abspath(__file__))   # .../IDS/ml
REPO_ROOT = os.path.dirname(BASE_DIR)                   # .../IDS

# Thư mục chứa dữ liệu thô (raw CSV files từ CIC-IDS 2017)
DATA_DIR = os.path.join(REPO_ROOT, "data", "raw", "MachineLearningCVE")

# Thư mục lưu dữ liệu đã xử lý (cleaned, processed)
PROCESSED_DIR = os.path.join(REPO_ROOT, "data", "processed")
os.makedirs(PROCESSED_DIR, exist_ok=True)

# Thư mục lưu models đã train
MODELS_DIR = os.path.join(BASE_DIR, "models", "saved")
os.makedirs(MODELS_DIR, exist_ok=True)

# Thư mục lưu biểu đồ, báo cáo
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


# ╔══════════════════════════════════════════════════════════════╗
# ║                  DANH SÁCH FILE DATASET                      ║
# ╚══════════════════════════════════════════════════════════════╝
#
# Dataset CIC-IDS 2017 gồm 8 file CSV, mỗi file tương ứng 1 ngày
# thu thập dữ liệu mạng tại Canadian Institute for Cybersecurity.
#
# Mỗi ngày có các loại tấn công khác nhau:
#   - Monday:    Chỉ có Benign (lưu lượng bình thường)
#   - Tuesday:   Brute Force (FTP-Patator, SSH-Patator)
#   - Wednesday: DoS (Hulk, GoldenEye, Slowloris, Slowhttptest) + Heartbleed
#   - Thursday:  Web Attacks (XSS, SQL Injection) + Infiltration
#   - Friday:    Botnet, DDoS, PortScan

CIC_FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
]


# ╔══════════════════════════════════════════════════════════════╗
# ║                   LABEL MAPPING (GOM NHÓM)                  ║
# ╚══════════════════════════════════════════════════════════════╝
#
# Dataset CIC-IDS 2017 có ~15 loại label chi tiết.
# Ta gom nhóm chúng thành 6 lớp chính để model dễ học hơn:
#
#   ┌─────────────────────────────────────────────────────────┐
#   │  Label gốc trong dataset    →    Nhóm của chúng ta     │
#   ├─────────────────────────────────────────────────────────┤
#   │  BENIGN                     →    Benign                 │
#   │  FTP-Patator, SSH-Patator   →    Brute Force            │
#   │  DoS Hulk, DoS GoldenEye,  →    DoS                    │
#   │  DoS slowloris, DoS Slow..  │                           │
#   │  DDoS                       →    DDoS                   │
#   │  Web Attack – Brute Force,  →    Web Attack             │
#   │  Web Attack – XSS,          │    (bao gồm SQLi + XSS)  │
#   │  Web Attack – Sql Injection │                           │
#   │  PortScan                   →    PortScan               │
#   └─────────────────────────────────────────────────────────┘
#
# 💡 Heartbleed (11 mẫu), Infiltration (36 mẫu), Bot (~1966 mẫu)
#    → Loại bỏ vì quá ít mẫu hoặc ngoài phạm vi đề tài

LABEL_MAP = {
    # Lưu lượng bình thường
    "BENIGN": "Benign",

    # Brute Force: tấn công dò mật khẩu
    "FTP-Patator": "Brute Force",
    "SSH-Patator": "Brute Force",

    # DoS (Denial of Service): tấn công từ chối dịch vụ (1 nguồn)
    "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS",
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",

    # DDoS (Distributed DoS): tấn công từ chối dịch vụ phân tán (nhiều nguồn)
    "DDoS": "DDoS",

    # Web Attack: tấn công ứng dụng web (SQLi, XSS)
    # Lưu ý: ký tự giữa "Web Attack" và tên là en-dash (–), không phải hyphen (-)
    "Web Attack \u2013 Brute Force": "Web Attack",
    "Web Attack \u2013 XSS": "Web Attack",
    "Web Attack \u2013 Sql Injection": "Web Attack",
    # Backup: một số bản dataset dùng hyphen thường
    "Web Attack - Brute Force": "Web Attack",
    "Web Attack - XSS": "Web Attack",
    "Web Attack - Sql Injection": "Web Attack",

    # PortScan: quét cổng để tìm lỗ hổng
    "PortScan": "PortScan",
}

# Labels sẽ bị loại bỏ (quá ít mẫu hoặc ngoài phạm vi đề tài)
DROP_LABELS = ["Heartbleed", "Infiltration", "Bot"]

# Tên các lớp theo thứ tự alphabet (dùng cho LabelEncoder)
CLASS_NAMES = ["Benign", "Brute Force", "DDoS", "DoS", "PortScan", "Web Attack"]
NUM_CLASSES = len(CLASS_NAMES)  # = 6


# ╔══════════════════════════════════════════════════════════════╗
# ║               CỘT KHÔNG CẦN THIẾT (DROP)                    ║
# ╚══════════════════════════════════════════════════════════════╝
#
# Một số cột trong dataset KHÔNG phải là features hữu ích cho ML:
#   - Flow ID: mã định danh flow, không mang thông tin gì
#   - Source IP, Destination IP: địa chỉ IP cụ thể, model sẽ "nhớ" IP
#     thay vì học pattern → overfitting
#   - Timestamp: thời gian cụ thể, không liên quan đến loại tấn công
#   - SimillarHTTP: cột thường trống hoặc không numeric

DROP_COLUMNS = [
    "Flow ID",
    "Source IP",
    "Src IP",
    "Destination IP",
    "Dst IP",
    "Timestamp",
    "SimillarHTTP",
]


# ╔══════════════════════════════════════════════════════════════╗
# ║                    ĐƯỜNG DẪN LƯU MODEL                      ║
# ╚══════════════════════════════════════════════════════════════╝

# Machine Learning model (Random Forest) - lưu bằng joblib
ML_MODEL_PATH = os.path.join(MODELS_DIR, "random_forest.pkl")

# Deep Learning model (CNN-LSTM) - lưu bằng torch.save
DL_MODEL_PATH = os.path.join(MODELS_DIR, "cnn_lstm.pth")

# StandardScaler - để chuẩn hóa features khi predict
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.pkl")

# LabelEncoder - để chuyển số → tên label khi predict
LABEL_ENCODER_PATH = os.path.join(MODELS_DIR, "label_encoder.pkl")

# Dữ liệu đã clean (Parquet format - nhanh hơn CSV)
CLEANED_DATA_PATH = os.path.join(PROCESSED_DIR, "cleaned_data.parquet")


# ╔══════════════════════════════════════════════════════════════╗
# ║             HYPERPARAMETERS - MACHINE LEARNING               ║
# ╚══════════════════════════════════════════════════════════════╝
#
# Random Forest: thuật toán "rừng ngẫu nhiên"
#   → Tạo nhiều cây quyết định (decision trees), mỗi cây vote
#   → Kết quả cuối = vote đa số
#
# 💡 Tại sao dùng Random Forest?
#   1. Hoạt động tốt với dữ liệu dạng bảng (tabular data)
#   2. Nhanh, không cần GPU
#   3. Ít cần tuning hyperparameters
#   4. Dễ giải thích (feature importance)
#   5. Ít bị overfitting nhờ cơ chế bagging

ML_PARAMS = {
    "n_estimators": 200,          # Số lượng cây quyết định
    "max_depth": 30,              # Độ sâu tối đa của mỗi cây
    "min_samples_split": 5,       # Số mẫu tối thiểu để split 1 node
    "min_samples_leaf": 2,        # Số mẫu tối thiểu ở mỗi lá
    "class_weight": "balanced",   # Tự cân bằng trọng số theo tỉ lệ lớp
    "random_state": 42,           # Seed cho reproducibility
    "n_jobs": -1,                 # Dùng tất cả CPU cores (song song)
    "verbose": 1,                 # Hiển thị tiến trình
}


# ╔══════════════════════════════════════════════════════════════╗
# ║              HYPERPARAMETERS - DEEP LEARNING                 ║
# ╚══════════════════════════════════════════════════════════════╝
#
# CNN-LSTM Hybrid: kết hợp CNN + LSTM
#   - CNN (Convolutional Neural Network): trích xuất đặc trưng cục bộ
#     từ các features liền kề
#   - LSTM (Long Short-Term Memory): học các mối quan hệ tuần tự
#     giữa các features
#   - Bidirectional: LSTM đọc dữ liệu từ 2 chiều (trái→phải, phải→trái)
#   - Attention: cho model tập trung vào phần quan trọng nhất

DL_PARAMS = {
    "epochs": 50,                 # Số lần duyệt qua toàn bộ dataset
    "batch_size": 1024,           # Số mẫu xử lý cùng lúc
    "learning_rate": 0.001,       # Tốc độ học (bước nhảy khi update weights)
    "weight_decay": 1e-5,         # L2 regularization (chống overfitting)
    "patience": 10,               # Early stopping: dừng sau 10 epochs không cải thiện
    "lr_patience": 5,             # Giảm LR sau 5 epochs không cải thiện
    "dropout": 0.3,               # Xác suất "tắt" neuron (chống overfitting)
    "hidden_size": 128,           # Kích thước hidden state của LSTM
    "num_layers": 2,              # Số tầng LSTM xếp chồng
    "conv_channels": [64, 128],   # Số filter cho mỗi tầng Conv1d
}


# ╔══════════════════════════════════════════════════════════════╗
# ║                       CÁC HẰNG SỐ KHÁC                      ║
# ╚══════════════════════════════════════════════════════════════╝

TEST_SIZE = 0.2       # Tỉ lệ test set: 20% dữ liệu dùng để đánh giá
RANDOM_STATE = 42     # Seed chung cho toàn bộ pipeline (reproducibility)

