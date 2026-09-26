import pandas as pd
import numpy as np
import glob
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

def main():
    features_clean = [
        "Destination Port",
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets",
        "Flow Bytes/s",
        "Flow Packets/s",
        "Flow IAT Mean",
        "Flow IAT Std",
        "Flow IAT Max",
        "Flow IAT Min",
        "Fwd Packets/s",
        "Bwd Packets/s",
        "Min Packet Length",
        "Max Packet Length",
        "Packet Length Mean",
        "Packet Length Std",
        "FIN Flag Count",
        "SYN Flag Count",
        "RST Flag Count",
        "PSH Flag Count",
        "ACK Flag Count",
        "Init_Win_bytes_forward",
        "Init_Win_bytes_backward",
    ]
    
    # 1. Lấy danh sách đường dẫn tất cả các file CSV
    #file_paths = glob.glob(r"F:/temp/MachineLearningCVE/*.csv")
    file_paths = glob.glob(r"F:/VSCODE/IDS/data/raw/MachineLearningCVE/*.csv")
    print(f"Số file tìm thấy: {len(file_paths)}")
    
    df_list = []
    for file in file_paths:
        print(f"Đang xử lý file: {file}")
        df_temp = pd.read_csv(
           file,
           low_memory=False
        )
        df_list.append(df_temp)
        
    # Gộp file vào làm 1 data
    data = pd.concat(
        df_list,
        ignore_index=True
    )
    
    # QUAN TRỌNG: Xóa khoảng trắng thừa trong tên cột của CIC-IDS-2017
    data.columns = data.columns.str.strip()

    print("\nTong so dong:", len(data))
    print("So cot:", len(data.columns))
    
    # Kiểm tra đúng tên feature trích chưa
    missing_features = [
        feature for feature in features_clean
        if feature not in data.columns
    ]

    if missing_features:
        print("\nLOI: Khong tim thay cac feature:")
        for feature in missing_features:
            print("-", feature)
        raise ValueError("Dataset khong co day du feature can thiet.")

    X = data[features_clean].copy()
    y = data["Label"].copy()
    
    # Chuyển toàn bộ feature sang kiểu số
    for col in features_clean:
        X[col] = pd.to_numeric(X[col], errors="coerce")
    
    # Thay thế -1 thành 0
    X.replace(-1, 0, inplace=True)
    
    # QUAN TRỌNG: Xử lý giá trị vô cực (inf) và NaN đặc trưng của CIC-IDS-2017
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.dropna(inplace=True)
    #X.fillna(0, inplace=True)
    X = X.astype(np.float32)
    
    print("Đã làm sạch dữ liệu thành công.")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    print("\n==============================")
    print("DATASET")
    print("==============================")
    print("X_train:", X_train.shape)
    print("X_test :", X_test.shape)
    print("y_train:", y_train.shape)
    print("y_test :", y_test.shape)

    # Xây dựng Random Forest
    model = RandomForestClassifier(
        n_estimators=100,
        max_samples=0.8,
        random_state=42,
        n_jobs=6,
    )

    # Xây dựng model (ĐÃ THÊM LỆNH FIT ĐỂ HUẤN LUYỆN)
    print("\nDang train Random Forest...")
    model.fit(X_train, y_train)
    print("Train xong!")

    # Dự đoán
    y_pred = model.predict(X_test)
    print("===============Y_PRED=================")
    print(y_pred)
    print(type(y_pred))

    # Đánh giá model
    accuracy = accuracy_score(y_test, y_pred)

    print("\n==============================")
    print("KET QUA")
    print("==============================")
    print(f"Accuracy: {accuracy:.4f}")

    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            y_pred,
            zero_division=0
        )
    )

    print("\nConfusion Matrix:")
    print(
        confusion_matrix(
            y_test,
            y_pred
        )
    )

    # Feature Importance
    importance = pd.DataFrame({
        "Feature": features_clean,
        "Importance": model.feature_importances_
    })

    importance = importance.sort_values(
        by="Importance",
        ascending=False
    )

    print("\n==============================")
    print("FEATURE IMPORTANCE")
    print("==============================")
    print(importance.to_string(index=False))

    joblib.dump(model, r"C:\Users\GIGABYTE\Desktop\IDS\ml\rf_model.pkl")

    print("Model saved!")
if __name__ == "__main__":
    main()
