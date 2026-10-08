"""Train the IDS Random Forest using CIC-IDS-2017 CSV files only."""

from pathlib import Path
import glob

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data" / "cicids2017"
MODEL_PATH = PROJECT_ROOT / "ml" / "rf_model.pkl"

from ids.detectors.ml.features import CIC_FEATURES
from ml.data_processing import read_cic_csv

features_clean = list(CIC_FEATURES)


def main():
    file_paths = sorted(glob.glob(str(DATA_DIR / "*.csv")))
    print(f"Số file CIC-IDS-2017 tìm thấy: {len(file_paths)}")
    if not file_paths:
        raise FileNotFoundError(f"Không tìm thấy CSV trong {DATA_DIR}")

    df_list = []
    for file in file_paths:
        print(f"Đang xử lý file: {file}")
        df_temp = read_cic_csv(file)
        df_list.append(df_temp)

    data = pd.concat(df_list, ignore_index=True)
    data.columns = data.columns.astype(str).str.strip()

    duplicate_count = int(data.duplicated().sum())
    data = data.drop_duplicates().reset_index(drop=True)
    print(f"Số dòng trùng đã loại: {duplicate_count}")

    print("\nTổng số dòng:", len(data))
    print("Số cột:", len(data.columns))

    
    X = data[features_clean].copy().astype(np.float32)
    y = data["Label"].copy()


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

    model = RandomForestClassifier(
        n_estimators=160,
        criterion="gini",
        class_weight="balanced",
        min_samples_split=4,
        min_samples_leaf=2,
        max_samples=0.8,
        bootstrap=True,
        random_state=21,
        n_jobs=-1,
    )

    print("\nĐang train Random Forest...")
    model.fit(X_train, y_train)
    print("Train xong!")

    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    print("\n==============================")
    print("KẾT QUẢ")
    print("==============================")
    print(f"Accuracy: {accuracy:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, zero_division=0))
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred, labels=model.classes_))

    importance = pd.DataFrame(
        {"Feature": features_clean, "Importance": model.feature_importances_}
    ).sort_values(by="Importance", ascending=False)

    print("\n==============================")
    print("FEATURE IMPORTANCE")
    print("==============================")
    print(importance.to_string(index=False))

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"\nModel saved: {MODEL_PATH}")


if __name__ == "__main__":
    main()
