"""Train the HTTP request text classifier used by the IDS runtime."""

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

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET = PROJECT_ROOT / "data" / "xss_sqli" / "xss_sqli_http_requests.csv"
DEFAULT_MODEL = PROJECT_ROOT / "ml" / "request_text_model.joblib"
DEFAULT_LOG = PROJECT_ROOT / "reports" / "request_text_training.log"
REQUIRED_COLUMNS = {"request_text", "label"}
REQUIRED_LABELS = {"BENIGN", "XSS", "SQLi"}


def build_model():
    """Combine word and character TF-IDF with a balanced multinomial classifier."""
    features = FeatureUnion(
        [
            (
                "word",
                TfidfVectorizer(
                    analyzer="word",
                    ngram_range=(1, 2),
                    min_df=2,
                    max_features=100_000,
                    sublinear_tf=True,
                    dtype=np.float32,
                ),
            ),
            (
                "char",
                TfidfVectorizer(
                    analyzer="char",
                    ngram_range=(2, 5),
                    min_df=2,
                    max_features=250_000,
                    sublinear_tf=True,
                    dtype=np.float32,
                ),
            ),
        ]
    )
    return Pipeline(
        [
            ("tfidf", features),
            (
                "classifier",
                LogisticRegression(
                    C=4.0,
                    class_weight="balanced",
                    max_iter=1_000,
                    random_state=42,
                ),
            ),
        ]
    )


def load_dataset(csv_path):
    """Load the two-column request-text dataset and validate its labels."""
    csv_path = Path(csv_path)
    data = pd.read_csv(csv_path, encoding="utf-8-sig")
    data.columns = data.columns.astype(str).str.strip()
    missing = REQUIRED_COLUMNS - set(data.columns)
    if missing:
        raise ValueError("Dataset thiếu cột: " + ", ".join(sorted(missing)))

    data = data[["request_text", "label"]].copy()
    data["request_text"] = data["request_text"].fillna("").astype(str).str.strip()
    data["label"] = data["label"].fillna("").astype(str).str.strip()
    data = data[(data["request_text"] != "") & (data["label"] != "")]

    label_map = {label.casefold(): label for label in REQUIRED_LABELS}
    data["label"] = data["label"].map(lambda value: label_map.get(value.casefold(), value))
    unknown = sorted(set(data["label"]) - REQUIRED_LABELS)
    if unknown:
        raise ValueError("Dataset có nhãn ngoài phạm vi XSS/SQLi/BENIGN: " + ", ".join(unknown))

    counts = data["label"].value_counts()
    missing_labels = REQUIRED_LABELS - set(counts.index)
    if missing_labels:
        raise ValueError("Dataset thiếu nhãn: " + ", ".join(sorted(missing_labels)))
    if (counts < 2).any():
        raise ValueError("Mỗi nhãn cần ít nhất hai request để chia tập đánh giá.")
    return data.reset_index(drop=True)


def train_request_model(csv_path=DEFAULT_DATASET, model_path=DEFAULT_MODEL):
    """Evaluate a stratified holdout, then train and save the final pipeline."""
    print(f"Reading dataset: {csv_path}", flush=True)
    data = load_dataset(csv_path)
    print(f"Loaded {len(data):,} rows. Preparing stratified 80/20 split.", flush=True)
    x_train, x_test, y_train, y_test = train_test_split(
        data["request_text"],
        data["label"],
        test_size=0.20,
        random_state=42,
        stratify=data["label"],
    )

    evaluation_model = build_model()
    print("Training holdout model (80% of rows)...", flush=True)
    evaluation_model.fit(x_train, y_train)
    predictions = evaluation_model.predict(x_test)
    print(f"Rows loaded: {len(data):,}")
    print("Label counts:")
    print(data["label"].value_counts().sort_index().to_string())
    print("\nStratified random holdout report (20%):")
    print(classification_report(y_test, predictions, labels=sorted(REQUIRED_LABELS), zero_division=0))
    print("Confusion matrix (BENIGN, SQLi, XSS):")
    print(confusion_matrix(y_test, predictions, labels=["BENIGN", "SQLi", "XSS"]))

    # Train the deployable pipeline on all supplied rows after holdout scoring.
    final_model = build_model()
    print("Training final model on all rows...", flush=True)
    final_model.fit(data["request_text"], data["label"])
    model_path = Path(model_path)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_model_path = model_path.with_suffix(model_path.suffix + ".tmp")
    print(f"Saving model atomically to {model_path}...", flush=True)
    joblib.dump(final_model, temporary_model_path)
    temporary_model_path.replace(model_path)
    print(f"\nSaved request-text model: {model_path}")
    print("Model classes:", list(final_model.named_steps["classifier"].classes_))
    return final_model


class _Tee:
    """Write training progress to both the console and a UTF-8 log file."""

    def __init__(self, *streams):
        self.streams = streams

    def write(self, value):
        for stream in self.streams:
            stream.write(value)
            stream.flush()
        return len(value)

    def flush(self):
        for stream in self.streams:
            stream.flush()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG)
    args = parser.parse_args()
    args.log.parent.mkdir(parents=True, exist_ok=True)
    with args.log.open("w", encoding="utf-8", newline="\n") as log_file:
        with redirect_stdout(_Tee(sys.stdout, log_file)):
            train_request_model(args.dataset, args.output)
            print(f"Training log saved: {args.log}", flush=True)


if __name__ == "__main__":
    main()
