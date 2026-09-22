"""
evaluate.py - Đánh giá Models & Tạo Visualizations
=====================================================

Module này đánh giá cả 2 models (ML & DL) và tạo các biểu đồ:
  1. Confusion Matrix (heatmap)
  2. ROC Curves cho từng lớp
  3. Feature Importance (Random Forest)
  4. Training History (Loss & Accuracy curves cho DL)
  5. Model Comparison (bar chart so sánh ML vs DL)
"""

import os
import numpy as np
import joblib
import torch

# Dùng backend 'Agg' để không cần GUI (chạy trên server/headless)
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.metrics import confusion_matrix, roc_curve, auc
from sklearn.preprocessing import label_binarize

from ml.config import (
    ML_MODEL_PATH,
    DL_MODEL_PATH,
    REPORTS_DIR,
    CLASS_NAMES,
    NUM_CLASSES,
)
from ml.evaluation.metrics import compute_all_metrics, print_metrics
from ml.training.train_dl import CNNLSTM


# ╔══════════════════════════════════════════════════════════════╗
# ║                   VISUALIZATION FUNCTIONS                    ║
# ╚══════════════════════════════════════════════════════════════╝


def plot_confusion_matrix(y_true, y_pred, class_names, title, save_path):
    """
    Vẽ Confusion Matrix dạng heatmap.

       - Hàng = label THẬT
       - Cột = label DỰ ĐOÁN
       - Đường chéo chính = dự đoán ĐÚNG
       - Ngoài đường chéo = dự đoán SAI
       - Màu đậm = số lượng nhiều

       Ví dụ: ô (DoS, DDoS) = 50
       → 50 mẫu DoS thật bị model đoán nhầm thành DDoS
    """
    cm = confusion_matrix(y_true, y_pred)

    plt.figure(figsize=(10, 8))
    sns.heatmap(
        cm,
        annot=True,              # Hiển thị số trong ô
        fmt="d",                 # Định dạng số nguyên
        cmap="Blues",            # Bảng màu xanh
        xticklabels=class_names,
        yticklabels=class_names,
        linewidths=0.5,          # Đường kẻ giữa các ô
        linecolor="gray",
    )
    plt.title(title, fontsize=14, fontweight="bold", pad=15)
    plt.xlabel("Predicted Label (Dự đoán)", fontsize=12)
    plt.ylabel("True Label (Thật)", fontsize=12)
    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {os.path.basename(save_path)}")


def plot_roc_curves(y_true, y_prob, class_names, title, save_path):
    """
    Vẽ ROC Curves cho từng lớp.

    ROC Curve
       - Trục X: False Positive Rate (FPR) - tỉ lệ báo động sai
       - Trục Y: True Positive Rate (TPR) - tỉ lệ phát hiện đúng
       - Đường lý tưởng: sát góc trên bên trái (FPR=0, TPR=1)
       - Đường xấu: đường chéo 45° (random guess)
       - AUC (Area Under Curve): diện tích dưới đường cong
         → AUC = 1.0: hoàn hảo, AUC = 0.5: random
    """
    # Binarize labels: [0,1,2,3,4,5] → one-hot encoding
    y_bin = label_binarize(y_true, classes=range(len(class_names)))

    plt.figure(figsize=(10, 8))
    colors = plt.cm.Set1(np.linspace(0, 1, len(class_names)))

    for i, (name, color) in enumerate(zip(class_names, colors)):
        fpr, tpr, _ = roc_curve(y_bin[:, i], y_prob[:, i])
        roc_auc = auc(fpr, tpr)
        plt.plot(fpr, tpr, color=color, lw=2,
                 label=f"{name} (AUC = {roc_auc:.3f})")

    # Đường random (baseline)
    plt.plot([0, 1], [0, 1], "k--", lw=1, label="Random (AUC = 0.500)")

    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel("False Positive Rate (Tỉ lệ báo sai)", fontsize=12)
    plt.ylabel("True Positive Rate (Tỉ lệ phát hiện)", fontsize=12)
    plt.title(title, fontsize=14, fontweight="bold")
    plt.legend(loc="lower right", fontsize=10)
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {os.path.basename(save_path)}")


def plot_training_history(history, save_path):
    """
    Vẽ Training/Validation Loss và Accuracy curves.
    """
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

    epochs = range(1, len(history["train_loss"]) + 1)

    # ── Loss Plot ──
    ax1.plot(epochs, history["train_loss"], "b-o", markersize=3, label="Train Loss")
    ax1.plot(epochs, history["val_loss"], "r-o", markersize=3, label="Val Loss")
    ax1.set_xlabel("Epoch", fontsize=11)
    ax1.set_ylabel("Loss", fontsize=11)
    ax1.set_title("Training & Validation Loss", fontweight="bold")
    ax1.legend(fontsize=10)
    ax1.grid(True, alpha=0.3)

    # ── Accuracy Plot ──
    ax2.plot(epochs, history["train_acc"], "b-o", markersize=3, label="Train Acc")
    ax2.plot(epochs, history["val_acc"], "r-o", markersize=3, label="Val Acc")
    ax2.set_xlabel("Epoch", fontsize=11)
    ax2.set_ylabel("Accuracy", fontsize=11)
    ax2.set_title("Training & Validation Accuracy", fontweight="bold")
    ax2.legend(fontsize=10)
    ax2.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {os.path.basename(save_path)}")


def plot_feature_importance(model, feature_names, save_path, top_n=20):
    """
    Vẽ Feature Importance (top N features) cho Random Forest.

       Mỗi feature đóng góp bao nhiêu % vào quyết định của model.
       Feature importance cao → feature đó rất quan trọng để phân biệt
       các loại tấn công.
    """
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1][:top_n]

    plt.figure(figsize=(12, 7))
    names = [feature_names[i] if feature_names else f"Feature {i}" for i in indices]

    # Vẽ barh (horizontal bar chart)
    colors = plt.cm.viridis(np.linspace(0.3, 0.9, top_n))
    bars = plt.barh(range(top_n), importances[indices][::-1], color=colors[::-1])

    plt.yticks(range(top_n), names[::-1], fontsize=9)
    plt.xlabel("Importance Score", fontsize=11)
    plt.title(f"Top {top_n} Feature Importance (Random Forest)", fontweight="bold")
    plt.grid(True, alpha=0.3, axis="x")
    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  🔝 Saved: {os.path.basename(save_path)}")


def plot_model_comparison(ml_results, dl_results, save_path):
    """
    Vẽ biểu đồ so sánh ML vs DL trên các metrics chính.
    """
    metrics_keys = ["accuracy", "precision_macro", "recall_macro", "f1_macro"]
    labels = ["Accuracy", "Precision\n(Macro)", "Recall\n(Macro)", "F1-Score\n(Macro)"]

    ml_vals = [ml_results[m] for m in metrics_keys]
    dl_vals = [dl_results[m] for m in metrics_keys]

    x = np.arange(len(labels))
    width = 0.35

    fig, ax = plt.subplots(figsize=(10, 6))
    bars1 = ax.bar(x - width / 2, ml_vals, width,
                   label="Random Forest (ML)", color="steelblue", edgecolor="white")
    bars2 = ax.bar(x + width / 2, dl_vals, width,
                   label="CNN-LSTM (DL)", color="coral", edgecolor="white")

    ax.set_ylabel("Score", fontsize=12)
    ax.set_title("Model Comparison: Random Forest vs CNN-LSTM",
                 fontsize=14, fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=10)
    ax.legend(fontsize=11)
    ax.set_ylim(0, 1.15)
    ax.grid(True, alpha=0.3, axis="y")

    # Thêm giá trị lên đầu mỗi bar
    for bar in bars1:
        height = bar.get_height()
        ax.annotate(f"{height:.3f}",
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3), textcoords="offset points",
                    ha="center", fontsize=9, fontweight="bold")
    for bar in bars2:
        height = bar.get_height()
        ax.annotate(f"{height:.3f}",
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3), textcoords="offset points",
                    ha="center", fontsize=9, fontweight="bold")

    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {os.path.basename(save_path)}")


# ╔══════════════════════════════════════════════════════════════╗
# ║                   EVALUATE FUNCTIONS                         ║
# ╚══════════════════════════════════════════════════════════════╝


def evaluate_ml(X_test, y_test, feature_names=None):
    """
    Đánh giá Random Forest model.

    Parameters:
        X_test: Features test set (đã scale)
        y_test: Labels test set
        feature_names: Tên các features

    Returns:
        dict: Tất cả metrics
    """
    print("\n" + "=" * 60)
    print("ĐÁNH GIÁ: RANDOM FOREST (ML)")
    print("=" * 60)

    # Load model
    model = joblib.load(ML_MODEL_PATH)
    print(f"  Loaded model: {ML_MODEL_PATH}")

    # Predict
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)

    # Compute metrics
    results = compute_all_metrics(y_test, y_pred, y_prob)
    print_metrics(results, "Random Forest")

    # Generate plots
    os.makedirs(REPORTS_DIR, exist_ok=True)
    print(f"\n  Tạo biểu đồ...")

    plot_confusion_matrix(
        y_test, y_pred, CLASS_NAMES,
        "Confusion Matrix - Random Forest",
        os.path.join(REPORTS_DIR, "ml_confusion_matrix.png"),
    )

    plot_roc_curves(
        y_test, y_prob, CLASS_NAMES,
        "ROC Curves - Random Forest",
        os.path.join(REPORTS_DIR, "ml_roc_curves.png"),
    )

    if feature_names:
        plot_feature_importance(
            model, feature_names,
            os.path.join(REPORTS_DIR, "ml_feature_importance.png"),
        )

    return results


def evaluate_dl(X_test, y_test):
    """
    Đánh giá CNN-LSTM model.

    Parameters:
        X_test: Features test set (đã scale)
        y_test: Labels test set

    Returns:
        dict: Tất cả metrics
    """
    print("\n" + "=" * 60)
    print("ĐÁNH GIÁ: CNN-LSTM (Deep Learning)")
    print("=" * 60)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    # Load model checkpoint
    checkpoint = torch.load(DL_MODEL_PATH, map_location=device, weights_only=False)
    model = CNNLSTM(
        checkpoint["input_size"],
        checkpoint["num_classes"],
        checkpoint["params"],
    ).to(device)
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()  # Tắt Dropout, BatchNorm dùng running stats

    print(f"  Loaded model: {DL_MODEL_PATH}")
    print(f"  Device: {device}")

    # Predict theo batches (để không hết RAM)
    X_test_t = torch.FloatTensor(X_test).to(device)
    all_preds = []
    all_probs = []
    batch_size = 1024

    with torch.no_grad():
        for i in range(0, len(X_test_t), batch_size):
            batch = X_test_t[i: i + batch_size]
            outputs = model(batch)
            probs = torch.softmax(outputs, dim=1)  # Chuyển logits → xác suất
            preds = outputs.argmax(dim=1)           # Lấy lớp có xác suất cao nhất
            all_preds.append(preds.cpu().numpy())
            all_probs.append(probs.cpu().numpy())

    y_pred = np.concatenate(all_preds)
    y_prob = np.concatenate(all_probs)

    # Compute metrics
    results = compute_all_metrics(y_test, y_pred, y_prob)
    print_metrics(results, "CNN-LSTM")

    # Generate plots
    os.makedirs(REPORTS_DIR, exist_ok=True)
    print(f"\n  Tạo biểu đồ...")

    plot_confusion_matrix(
        y_test, y_pred, CLASS_NAMES,
        "Confusion Matrix - CNN-LSTM",
        os.path.join(REPORTS_DIR, "dl_confusion_matrix.png"),
    )

    plot_roc_curves(
        y_test, y_prob, CLASS_NAMES,
        "ROC Curves - CNN-LSTM",
        os.path.join(REPORTS_DIR, "dl_roc_curves.png"),
    )

    # Training history
    if "history" in checkpoint:
        plot_training_history(
            checkpoint["history"],
            os.path.join(REPORTS_DIR, "dl_training_history.png"),
        )

    return results

