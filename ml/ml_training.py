import pandas as pd
import numpy as np
import glob
import joblib
from pathlib import Path
from data_processing import data_processing
from imblearn.over_sampling import SMOTE
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

def ml_training():
    current_dir = Path(__file__).resolve().parent
    data_dir = current_dir.parent/"data"
    #Goi ham xu li du lieu
    file_paths = list(data_dir.glob("*.csv"))
    print(f"Số file tìm thấy: {len(file_paths)}")
    df_list=[]
    for file in file_paths:
        print(f"Dang xu ly file: {file}")
        df_temp = pd.read_csv(
            file,
            low_memory = False
        )
        df_list.append(df_temp)
    
    data = pd.concat(
        df_list,
        ignore_index = True
    )

    data = data_processing(data)


    #Goi ham xu ly xong

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
    
   
    print("Đã làm sạch dữ liệu thành công.")

    #Bat dau train mo hinh

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=43,
        stratify=y,
    )

    # target_counts = {
    # 'Sqli': 1000,                  # Đưa lớp Sqli lên 1000 mẫu
    # 'XSS': 2500,                   # Đưa lớp XSS lên 2000 mẫu
    # 'Web Attack - Brute Force': 3200 # Đưa Brute Force lên 3000 mẫu
    # Các lớp đa số giữ nguyên không cần khai báo
    # }
    # smote = SMOTE(sampling_strategy=target_counts,random_state=42)
    # X_train_resampled, y_train_resampled = smote.fit_resample(X_train, y_train)

    # Sau đó dùng X_train_resampled và y_train_resampled để train model
    print("\n==============================")
    print("DATASET")
    print("==============================")
    print("X_train:", X_train.shape)
    print("X_test :", X_test.shape)
    print("y_train:", y_train.shape)
    print("y_test :", y_test.shape)

    # Xây dựng Random Forest

    model = RandomForestClassifier(
        n_estimators=160,
        criterion='gini', 
        max_depth=None, 
        min_samples_split=3, 
        min_samples_leaf=1, 
        min_weight_fraction_leaf=0.0, 
        max_features='sqrt', 
        max_leaf_nodes=None, 
        min_impurity_decrease=0.0, 
        bootstrap=True, 
        oob_score=False, 
        n_jobs=-1, 
        random_state=42, 
        verbose=0, 
        warm_start=False, 
        class_weight='balanced', 
        ccp_alpha=0.0, 
        max_samples=None, 
        monotonic_cst=None
    )

    # Xây dựng model (ĐÃ THÊM LỆNH FIT ĐỂ HUẤN LUYỆN)

    print("\nDang train Random Forest...")
    # model.fit(X_train_resampled, y_train_resampled)
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


    joblib.dump(model, r"./rf_model.pkl")
    print("Model saved!")
    return

def main():

    ml_training()
if __name__ == "__main__":
    main()


