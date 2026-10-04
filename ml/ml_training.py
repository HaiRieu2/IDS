"""Train the IDS Random Forest from CIC-IDS-2017/2018 flow CSVs."""

from pathlib import Path
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if hasattr(sys.stdout, "reconfigure"):
    # Vietnamese progress/error messages should work in Windows legacy consoles.
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from ids.detectors.ml.features import CIC_FEATURES

try:
    from .data_processing import read_cic_csv
except ImportError:  # Support direct execution as well as `python -m ml.ml_training`.
    from data_processing import read_cic_csv

REQUIRED_CLASSES = {"BENIGN", "XSS", "Sqli", "Web Attack - Brute Force"}


def load_dataset(data_dir):
    """Load supported CIC flow files and print how many usable rows each adds."""
    files = sorted(Path(data_dir).rglob("*.csv"))
    if not files:
        raise FileNotFoundError(f"Không tìm thấy CIC CSV trong {data_dir}")

    datasets = []
    for path in files:
        print(f"Đang đọc: {path}")
        frame = read_cic_csv(path)
        frame["_source"] = path.name
        print("  Số flow sau chuẩn hóa:", len(frame))
        print(frame["Label"].value_counts().to_string())
        datasets.append(frame)
    return pd.concat(datasets, ignore_index=True)


def validate_dataset(data):
    """Check the required CIC columns and attack families before training."""
    missing_features = [name for name in CIC_FEATURES + ("Label",) if name not in data.columns]
    if missing_features:
        raise ValueError("Thiếu cột CIC cần thiết: " + ", ".join(missing_features))

    counts = data["Label"].value_counts()
    missing_classes = sorted(REQUIRED_CLASSES - set(counts.index))
    if missing_classes:
        raise ValueError("Dataset thiếu lớp bắt buộc: " + ", ".join(missing_classes))
    if not any("dos" in str(label).casefold() for label in counts.index):
        raise ValueError("Dataset không có lớp DoS; không thể huấn luyện đủ phạm vi đề tài.")
    too_small = counts[counts < 2]
    if not too_small.empty:
        raise ValueError("Mỗi lớp cần ít nhất 2 flow: " + str(too_small.to_dict()))


def build_model(n_estimators=160):
    """Build a class-balanced Random Forest with recall-friendly leaves."""
    return RandomForestClassifier(
        n_estimators=n_estimators,
        criterion="entropy",
        max_features="sqrt",
        min_samples_leaf=1,
        class_weight="balanced_subsample",
        # Flow CSVs can contain millions of rows. Each tree sees a bootstrap
        # sample of 40%, which keeps training practical while giving rare
        # classes chances to appear across the forest.
        max_samples=0.4,
        n_jobs=-1,
        random_state=42,
    )


def _fit_model(model, features, labels):
    """Fit the standard class-balanced Random Forest without extra weights."""
    model.fit(features, labels)
    return model


def _runtime_predictions(model, features, threshold):
    """Apply the same low-confidence BENIGN backstop as the live IDS."""
    # Use object dtype so promoting a short label like BENIGN to the longer
    # "Web Attack - Brute Force" label does not truncate it to a fixed-width
    # NumPy unicode string.
    predictions = np.asarray(model.predict(features), dtype=object)
    probabilities = model.predict_proba(features)
    classes = [str(label) for label in model.classes_]
    attack_indexes = [i for i, label in enumerate(classes) if label.upper() != "BENIGN"]
    if not attack_indexes:
        return predictions

    attack_probabilities = probabilities[:, attack_indexes]
    best_indexes = attack_probabilities.argmax(axis=1)
    best_classes = [classes[attack_indexes[i]] for i in best_indexes]
    best_scores = attack_probabilities.max(axis=1)
    benign_rows = np.fromiter(
        (str(label).upper() == "BENIGN" for label in predictions),
        dtype=bool,
        count=len(predictions),
    )
    promote = benign_rows & (best_scores >= threshold)
    predictions[promote] = np.asarray(best_classes, dtype=object)[promote]
    return predictions


def _report(model, x_test, y_test, heading):
    # Evaluation predicts one batch on the main thread; parallel tree workers
    # add overhead and can trigger scikit-learn/joblib configuration warnings.
    model.set_params(n_jobs=1)
    raw_predictions = model.predict(x_test)
    print(f"\n{heading}")
    print("Raw argmax classification report:")
    print(classification_report(y_test, raw_predictions, zero_division=0))
    labels = list(model.classes_)
    print("Confusion matrix labels:", labels)
    print(confusion_matrix(y_test, raw_predictions, labels=labels))

    threshold = 0.30
    try:
        from config.path import CONFIG_DATA
        import json
        rules = json.loads((CONFIG_DATA / "rules.json").read_text(encoding="utf-8-sig"))
        threshold = float(rules.get("ML_ALERT_THRESHOLD", threshold))
    except (OSError, ValueError, TypeError):
        pass
    runtime_predictions = _runtime_predictions(model, x_test, threshold)
    print(f"\nLive IDS prediction report (BENIGN backstop threshold={threshold:.2f}):")
    print(classification_report(y_test, runtime_predictions, zero_division=0))
    truth_is_attack = np.asarray(y_test.astype(str) != "BENIGN")
    predicted_is_attack = np.asarray(runtime_predictions != "BENIGN")
    attack_total = int(truth_is_attack.sum())
    attack_detected = int((truth_is_attack & predicted_is_attack).sum())
    benign_total = int((~truth_is_attack).sum())
    benign_false_alarms = int((~truth_is_attack & predicted_is_attack).sum())
    print(
        "Binary attack detection: "
        f"recall={attack_detected / attack_total:.4f} ({attack_detected}/{attack_total}), "
        f"benign false-positive rate={benign_false_alarms / benign_total:.4f} "
        f"({benign_false_alarms}/{benign_total})"
        if attack_total and benign_total else "Binary attack detection: insufficient class support."
    )


def _cross_dataset_report(data):
    """Measure transfer from CIC-IDS-2017 to the independent 2018 web day."""
    if "_source" not in data.columns:
        return
    is_2018 = data["_source"].str.contains("2018", case=False, regex=False)
    train = data[~is_2018]
    test = data[is_2018]
    if train.empty or test.empty:
        print("\nBỏ qua đánh giá chéo nguồn: cần có cả CSV 2017 và 2018.")
        return

    # The report is intentionally cross-dataset: 2018 flows are never used to
    # fit this temporary model. It helps reveal source/version mismatch.
    model = build_model(n_estimators=80)
    _fit_model(model, train[list(CIC_FEATURES)].astype("float32"),
               train["Label"].astype(str))
    known = test["Label"].isin(model.classes_)
    if known.any():
        _report(model, test.loc[known, list(CIC_FEATURES)].astype("float32"),
                test.loc[known, "Label"].astype(str),
                "Cross-source stress test: train only on CIC-IDS-2017, evaluate CIC-IDS-2018 "
                "(the final IDS model is trained on all configured sources)")
    unknown = sorted(set(test.loc[~known, "Label"].astype(str)))
    if unknown:
        print("Nhãn chỉ có ở tập 2018, không đánh giá được bằng model 2017:", unknown)


def train_and_evaluate(data, model_path):
    """Evaluate, then fit the final model on every approved training flow."""
    validate_dataset(data)
    features = data[list(CIC_FEATURES)].astype("float32")
    labels = data["Label"].astype(str)

    # This stratified score is a development check. The independent 2018 report
    # below is more useful for spotting capture-day/domain shift.
    x_train, x_test, y_train, y_test = train_test_split(
        features, labels, test_size=0.25, random_state=43, stratify=labels
    )

    evaluation_model = build_model(n_estimators=80)
    _fit_model(evaluation_model, x_train, y_train)
    _report(evaluation_model, x_test, y_test, "Stratified holdout evaluation")

    _cross_dataset_report(data)

    # Refit using all labeled records only after producing evaluation reports.
    final_model = build_model()
    _fit_model(final_model, features, labels)
    model_path = Path(model_path)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(final_model, model_path)
    print(f"\nFinal model (fit on all {len(data):,} flows) saved: {model_path}")
    print("Final classes:", list(final_model.classes_))
    return final_model


def ml_training():
    data = load_dataset(PROJECT_ROOT / "data")
    return train_and_evaluate(data, PROJECT_ROOT / "ml" / "rf_model.pkl")


def main():
    ml_training()


if __name__ == "__main__":
    main()
