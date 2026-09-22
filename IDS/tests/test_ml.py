import pandas as pd
import numpy as np
import glob

import matplotlib.pyplot as plt
from sklearn.tree import plot_tree
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
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    ]
    # 1. Lấy danh sách đường dẫn tất cả các file CSV
    file_paths = glob.glob(r"F:/VSCODE/IDS/data/raw/MachineLearningCVE/*.csv")
    print(f"Số file tìm thấy: {len(file_paths)}")
    df_list = []
    for file in file_paths:
        print(f"Đang xử lý file: {file}")

        # 2. Đọc file CSV
        df_temp = pd.read_csv(
           file,
           low_memory = False
        )
        df_list.append(df_temp)
    #Gộp file vào làm 1 data
    data = pd.concat(
        df_list,
        ignore_index=True
    )
    print("\nTong so dong:", len(data))
    print("So cot:", len(data.columns))
    #Kiểm tra đúng tên feature trích chưa
    missing_features = [
    feature
    for feature in features_clean
    if feature not in data.columns
    ]

    if missing_features:
        print("\nLOI: Khong tim thay cac feature:")
        for feature in missing_features:
            print("-", feature)

        raise ValueError("Dataset khong co day du feature can thiet.")

    X = data[features_clean].copy()
    y = data["Label"].copy()
    ##Chuyển toàn bộ feature sang kiểu số
    X = X.apply(pd.to_numeric, errors="coerce")

    X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=21,
    stratify=y
    )

    print("\n==============================")
    print("DATASET")
    print("==============================")
    print("X_train:", X_train.shape)
    print("X_test :", X_test.shape)
    print("y_train:", y_train.shape)
    print("y_test :", y_test.shape)

    #Xây dựng Random Forest
    model = RandomForestClassifier(
    n_estimators=100,
    criterion='gini',
    max_depth=None,
    min_samples_split=2,
    min_samples_leaf=1,
    min_weight_fraction_leaf=0.0,
    max_features='sqrt',
    max_leaf_nodes=None,
    min_impurity_decrease=0.0,
    bootstrap=True,
    oob_score=False,
    n_jobs=-1,
    random_state=21,
    verbose=0,
    warm_start=False,
    class_weight="balanced",
    ccp_alpha=0.0,
    max_samples=None,
    monotonic_cst=None
    )

    #Xây dựng model
    print("\nDang train Random Forest...")
    model.fit(X_train, y_train)
    print("Train xong!")

    #Dự đoán
    y_pred = model.predict(X_test)

    #Vẽ cây:
    # 1. Chọn cây đầu tiên
    chosen_tree = model.estimators_[0]

    # 2. Khởi tạo hình ảnh
    plt.figure(figsize=(40, 20))
    # 3. Vẽ cây
    plot_tree(
        chosen_tree,
        feature_names=features_clean,
        class_names=[str(c) for c in model.classes_],
        filled=True,
        rounded=True,
        max_depth=7,
    )

    # 4. LƯU THÀNH FILE ÂNH PNG (Lưu vào cùng thư mục chạy code)
    plt.savefig("decision_tree_vector.svg", format="svg", bbox_inches="tight")
    print("Đã lưu file 'decision_tree_vector.svg'. Bạn kéo file này thả vào Chrome hoặc Edge để zoom xem nhé!")

    
    
    #Đánh giá model
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

    #Feature Important
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




if __name__ == "__main__":
    main()