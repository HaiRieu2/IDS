"""
metrics.py - Tính toán các chỉ số đánh giá Model
==================================================

Module này cung cấp các hàm tính metrics để đánh giá hiệu suất model.

CÁC METRICS QUAN TRỌNG CHO IDS:

┌─────────────┬──────────────────────────────────────────────────────┐
│ Metric      │ Ý nghĩa                                            │
├─────────────┼──────────────────────────────────────────────────────┤
│ Accuracy    │ % dự đoán đúng tổng thể                            │
│             │ = (TP + TN) / (TP + TN + FP + FN)                  │
│             │ ⚠️ Có thể gây hiểu lầm khi data mất cân bằng!     │
├─────────────┼──────────────────────────────────────────────────────┤
│ Precision   │ Trong các dự đoán "tấn công", bao nhiêu % đúng?   │
│             │ = TP / (TP + FP)                                    │
│             │ Precision cao → ít false alarm                      │
├─────────────┼──────────────────────────────────────────────────────┤
│ Recall      │ Trong các tấn công THẬT, bao nhiêu % được phát     │
│ (Detection  │ hiện?                                               │
│  Rate)      │ = TP / (TP + FN)                                    │
│             │ Recall cao → ít bỏ sót tấn công                    │
├─────────────┼──────────────────────────────────────────────────────┤
│ F1-Score    │ Trung bình hài hòa của Precision và Recall         │
│             │ = 2 × (P × R) / (P + R)                            │
│             │ F1 cao → cân bằng giữa precision và recall         │
├─────────────┼──────────────────────────────────────────────────────┤
│ ROC-AUC     │ Khả năng phân biệt giữa các lớp                   │
│             │ 1.0 = hoàn hảo, 0.5 = random                      │
├─────────────┼──────────────────────────────────────────────────────┤
│ Confusion   │ Ma trận nhầm lẫn: cho thấy model nhầm lẫn giữa    │
│ Matrix      │ các lớp nào với nhau                                │
└─────────────┴──────────────────────────────────────────────────────┘

   - Macro: tính riêng cho mỗi lớp rồi lấy trung bình
   - Weighted: trung bình có trọng số theo số lượng mẫu mỗi lớp
"""

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_auc_score,
)

from ml.config import CLASS_NAMES


def compute_all_metrics(y_true, y_pred, y_prob=None):
    """
    Tính toán TẤT CẢ metrics đánh giá.

    Parameters:
        y_true (np.ndarray): Labels thật (ground truth)
        y_pred (np.ndarray): Labels dự đoán
        y_prob (np.ndarray, optional): Xác suất dự đoán cho mỗi lớp
            Shape (n_samples, n_classes). Cần cho ROC-AUC.

    Returns:
        dict: Dictionary chứa tất cả metrics
    """
    results = {}

    # ── Accuracy ──
    results["accuracy"] = accuracy_score(y_true, y_pred)

    # ── Precision, Recall, F1 (Macro) ──
    # Macro: mỗi lớp có trọng số bằng nhau
    results["precision_macro"] = precision_score(
        y_true, y_pred, average="macro", zero_division=0
    )
    results["recall_macro"] = recall_score(
        y_true, y_pred, average="macro", zero_division=0
    )
    results["f1_macro"] = f1_score(
        y_true, y_pred, average="macro", zero_division=0
    )

    # ── Precision, Recall, F1 (Weighted) ──
    # Weighted: trọng số theo số lượng mẫu
    results["precision_weighted"] = precision_score(
        y_true, y_pred, average="weighted", zero_division=0
    )
    results["recall_weighted"] = recall_score(
        y_true, y_pred, average="weighted", zero_division=0
    )
    results["f1_weighted"] = f1_score(
        y_true, y_pred, average="weighted", zero_division=0
    )

    # ── Confusion Matrix ──
    results["confusion_matrix"] = confusion_matrix(y_true, y_pred)

    # ── Classification Report ──
    # Báo cáo chi tiết precision, recall, f1 cho TỪNG lớp
    results["classification_report"] = classification_report(
        y_true, y_pred, target_names=CLASS_NAMES, zero_division=0
    )

    # ── ROC-AUC ──
    # Cần y_prob (xác suất) chứ không chỉ y_pred (nhãn)
    if y_prob is not None:
        try:
            results["roc_auc"] = roc_auc_score(
                y_true, y_prob, multi_class="ovr", average="macro"
            )
        except Exception as e:
            print(f"Không tính được ROC-AUC: {e}")
            results["roc_auc"] = None
    else:
        results["roc_auc"] = None

    return results


def print_metrics(results, model_name="Model"):
    """
    In kết quả đánh giá ra console một cách đẹp mắt.

    Parameters:
        results (dict): Output từ compute_all_metrics()
        model_name (str): Tên model (để hiển thị)
    """
    print(f"\n{'═' * 60}")
    print(f"KẾT QUẢ ĐÁNH GIÁ: {model_name}")
    print(f"{'═' * 60}")

    # Tổng quan
    print(f"\n  TỔNG QUAN:")
    acc = results["accuracy"]
    print(f"     Accuracy:             {acc:.4f}  ({acc * 100:.2f}%)")

    # Macro metrics
    print(f"\n  MACRO METRICS (mỗi lớp cùng trọng số):")
    print(f"     Precision (macro):    {results['precision_macro']:.4f}")
    print(f"     Recall (macro):       {results['recall_macro']:.4f}")
    print(f"     F1-Score (macro):     {results['f1_macro']:.4f}")

    # Weighted metrics
    print(f"\n  WEIGHTED METRICS (trọng số theo số mẫu):")
    print(f"     Precision (weighted): {results['precision_weighted']:.4f}")
    print(f"     Recall (weighted):    {results['recall_weighted']:.4f}")
    print(f"     F1-Score (weighted):  {results['f1_weighted']:.4f}")

    # ROC-AUC
    if results.get("roc_auc"):
        print(f"\n  ROC-AUC:              {results['roc_auc']:.4f}")

    # Classification Report (chi tiết cho từng lớp)
    print(f"\n  CLASSIFICATION REPORT (chi tiết từng lớp):")
    print(f"  {'─' * 55}")
    for line in results["classification_report"].split("\n"):
        if line.strip():
            print(f"  {line}")

    # Confusion Matrix
    print(f"\n  CONFUSION MATRIX:")
    print(f"  {'─' * 55}")
    cm = results["confusion_matrix"]
    # Header
    header = "          " + "  ".join(f"{name[:6]:>8s}" for name in CLASS_NAMES)
    print(f"  {header}")
    print(f"  {'─' * 55}")
    for i, row in enumerate(cm):
        name = CLASS_NAMES[i] if i < len(CLASS_NAMES) else f"Class {i}"
        row_str = "  ".join(f"{val:>8d}" for val in row)
        print(f"  {name:>8s}  {row_str}")

