"""Huấn luyện Logistic Regression để phân loại nội dung HTTP request."""

import argparse
from contextlib import redirect_stdout
from pathlib import Path
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline


# Các đường dẫn mặc định được tính từ thư mục gốc F:\IDS.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET = PROJECT_ROOT / "data" / "xss_sqli" / "xss_sqli_http_requests.csv"
DEFAULT_MODEL = PROJECT_ROOT / "ml" / "request_text_model.joblib"
DEFAULT_LOG = PROJECT_ROOT / "reports" / "request_text_training.log"

REQUIRED_COLUMNS = {"request_text", "label"}
REQUIRED_LABELS = {"BENIGN", "XSS", "SQLi"}


def build_model():
    """Tạo pipeline: text -> TF-IDF -> Logistic Regression đa lớp."""

    # Word n-gram giữ từ đơn và cặp từ, ví dụ: "script", "alert".
    word_tfidf = TfidfVectorizer(
        analyzer="word",
        ngram_range=(1, 2),
        min_df=2,
        max_features=100_000,
        sublinear_tf=True,
        dtype=np.float32,
    )

    # Character n-gram giữ các chuỗi ký tự ngắn, hữu ích với payload và dấu câu.
    char_tfidf = TfidfVectorizer(
        analyzer="char",
        ngram_range=(2, 5),
        min_df=2,
        max_features=250_000,
        sublinear_tf=True,
        dtype=np.float32,
    )

    # Ghép hai nhóm TF-IDF thành một vector đầu vào duy nhất.
    text_features = FeatureUnion([
        ("word", word_tfidf),
        ("char", char_tfidf),
    ])

    # Dữ liệu có 3 nhãn nên Logistic Regression phân loại đa lớp.
    classifier = LogisticRegression(
        C=4.0,
        class_weight="balanced",
        max_iter=1_000,
        random_state=42,
        solver="lbfgs",
    )

    # Pipeline đảm bảo lúc predict, request được biến đổi giống lúc train.
    return Pipeline([
        ("tfidf", text_features),
        ("classifier", classifier),
    ])


def load_dataset(csv_path):
    """Đọc CSV, bỏ dòng trống và kiểm tra đúng 3 nhãn của model."""

    csv_path = Path(csv_path)
    data = pd.read_csv(csv_path, encoding="utf-8-sig")
    data.columns = data.columns.astype(str).str.strip()

    # Dataset chỉ cần request_text và label.
    missing_columns = REQUIRED_COLUMNS - set(data.columns)
    if missing_columns:
        raise ValueError("Dataset thiếu cột: " + ", ".join(sorted(missing_columns)))
    data = data[["request_text", "label"]].copy()

    # Chuẩn hóa dữ liệu rỗng và khoảng trắng.
    data["request_text"] = data["request_text"].fillna("").astype(str).str.strip()
    data["label"] = data["label"].fillna("").astype(str).str.strip()
    data = data[(data["request_text"] != "") & (data["label"] != "")].copy()

    # Chuẩn hóa cách viết nhãn, ví dụ sqli -> SQLi.
    label_map = {label.casefold(): label for label in REQUIRED_LABELS}
    data["label"] = data["label"].map(
        lambda label: label_map.get(label.casefold(), label)
    )


    return data.reset_index(drop=True)


def train_request_model(csv_path=DEFAULT_DATASET, model_path=DEFAULT_MODEL):
    """Đánh giá trên holdout, sau đó train model cuối và lưu ra file."""

    print(f"Đang đọc dataset: {csv_path}", flush=True)
    data = load_dataset(csv_path)
    print(f"Đã đọc {len(data):,} request.", flush=True)
    print("Số mẫu mỗi nhãn:")
    print(data["label"].value_counts().sort_index().to_string())

    # Chia 80% để train và 20% để đánh giá; stratify giữ tỷ lệ nhãn gần nhau.
    x_train, x_test, y_train, y_test = train_test_split(
        data["request_text"],
        data["label"],
        test_size=0.20,
        random_state=42,
        stratify=data["label"],
    )

    # Train trên 80%; giữ nguyên model này để lưu và dùng trong IDS.
    model = build_model()
    print("\nĐang train model trên 80% dữ liệu...", flush=True)
    model.fit(x_train, y_train)
    predictions = model.predict(x_test)

    print("\nKết quả trên 20% dữ liệu holdout:")
    print(classification_report(
        y_test,
        predictions,
        labels=["BENIGN", "SQLi", "XSS"],
        zero_division=0,
    ))
    print("Confusion matrix (thứ tự nhãn: BENIGN, SQLi, XSS):")
    print(confusion_matrix(
        y_test,
        predictions,
        labels=["BENIGN", "SQLi", "XSS"],
    ))

    model_path = Path(model_path)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_path)

    print(f"Đã lưu model: {model_path}")
    print("Các lớp model nhận diện:", list(model.named_steps["classifier"].classes_))
    return model


class Tee:
    """Ghi nội dung print đồng thời ra terminal và file log."""

    def __init__(self, *streams):
        self.streams = streams

    def write(self, text):
        for stream in self.streams:
            stream.write(text)
            stream.flush()
        return len(text)

    def flush(self):
        for stream in self.streams:
            stream.flush()


def main():
    # Cho phép đổi dataset, model đầu ra hoặc log khi chạy từ terminal.
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG)
    args = parser.parse_args()

    # Tạo thư mục log nếu chưa có và ghi tiến trình ra cả hai nơi.
    args.log.parent.mkdir(parents=True, exist_ok=True)
    with args.log.open("w", encoding="utf-8", newline="\n") as log_file:
        with redirect_stdout(Tee(sys.stdout, log_file)):
            train_request_model(args.dataset, args.output)
            print(f"Log đã lưu: {args.log}", flush=True)


if __name__ == "__main__":
    main()
