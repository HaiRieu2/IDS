"""
run_pipeline.py - Script chạy toàn bộ ML/DL Pipeline
======================================================

Đây là script CHÍNH để chạy toàn bộ quy trình từ A đến Z:
  Load Data → Clean → Feature Engineering → Split → SMOTE
  → Train ML → Train DL → Evaluate → Compare

Cách sử dụng:
  # Chạy TẤT CẢ (từ đầu đến cuối)
  python -m ml.run_pipeline --mode all

  # Chỉ clean data (nếu đã clean rồi thì bỏ qua bước này)
  python -m ml.run_pipeline --mode clean

  # Chỉ train Machine Learning (Random Forest)
  python -m ml.run_pipeline --mode train-ml

  # Chỉ train Deep Learning (CNN-LSTM)
  python -m ml.run_pipeline --mode train-dl

  # Chỉ đánh giá (cần đã train models trước)
  python -m ml.run_pipeline --mode evaluate

💡 LƯU Ý:
   - Lần đầu tiên: chạy mode='all' để thực hiện đầy đủ
   - Lần sau: nếu chỉ muốn thử hyperparameters khác → chạy mode='train-ml' hoặc 'train-dl'
   - Dữ liệu clean được lưu ra Parquet → không cần clean lại mỗi lần
"""

import os
import sys
import time
import argparse

# ===== THÊM THƯ MỤC GỐC VÀO PATH =====
# Để Python tìm được package 'ml' khi chạy script
# __file__ = F:/VSCODE/IDS/ml/run_pipeline.py
# parent = F:/VSCODE/IDS → thêm vào sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.dataset.load_dataset import load_all_csv
from ml.dataset.clean_dataset import clean_data, save_cleaned_data, load_cleaned_data
from ml.features.feature_engineering import prepare_features, fit_and_save_scaler, scale_features
from ml.dataset.split_dataset import split_data, apply_smote
from ml.training.train_ml import train_ml_model
from ml.training.train_dl import train_dl_model
from ml.evaluation.evaluate import evaluate_ml, evaluate_dl, plot_model_comparison
from ml.config import REPORTS_DIR, CLEANED_DATA_PATH


def print_banner():
    """In banner đẹp khi bắt đầu."""
    print()
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║                                                              ║")
    print("║   🛡️  HỆ THỐNG PHÁT HIỆN XÂM NHẬP (IDS)                    ║")
    print("║   Machine Learning & Deep Learning Pipeline                  ║")
    print("║                                                              ║")
    print("║   Dataset: CIC-IDS 2017                                      ║")
    print("║   ML Model: Random Forest                                    ║")
    print("║   DL Model: CNN-LSTM Hybrid                                  ║")
    print("║                                                              ║")
    print("╚══════════════════════════════════════════════════════════════╝")


def run_pipeline(mode="all"):
    """
    Chạy pipeline theo mode.

    Parameters:
        mode (str): Bước cần chạy
            - 'all': chạy tất cả từ đầu đến cuối
            - 'clean': chỉ load + clean data
            - 'train-ml': load cleaned data + feature eng + split + train ML
            - 'train-dl': load cleaned data + feature eng + split + train DL
            - 'evaluate': load cleaned data + feature eng + split + evaluate both
    """
    print_banner()
    print(f"\n🚀 Mode: {mode}")
    total_start = time.time()

    # ═══════════════════════════════════════════════════════
    # BƯỚC 1 & 2: LOAD + CLEAN DATA
    # ═══════════════════════════════════════════════════════
    if mode in ("all", "clean"):
        # Load tất cả CSV files
        df = load_all_csv()

        # Clean data
        df = clean_data(df)

        # Lưu ra Parquet (để không cần clean lại)
        save_cleaned_data(df)

        if mode == "clean":
            print(f"\n✅ Clean data hoàn tất!")
            return

    # ═══════════════════════════════════════════════════════
    # LOAD CLEANED DATA (nếu không phải mode 'all')
    # ═══════════════════════════════════════════════════════
    if mode in ("train-ml", "train-dl", "evaluate"):
        df = load_cleaned_data()

    # ═══════════════════════════════════════════════════════
    # BƯỚC 3: FEATURE ENGINEERING (Encode labels)
    # ═══════════════════════════════════════════════════════
    X, y, feature_names = prepare_features(df)

    # ═══════════════════════════════════════════════════════
    # BƯỚC 4: SPLIT TRAIN/TEST
    # ═══════════════════════════════════════════════════════
    X_train, X_test, y_train, y_test = split_data(X, y)

    # ═══════════════════════════════════════════════════════
    # BƯỚC 5: SCALE FEATURES (fit trên train, transform cả 2)
    # ═══════════════════════════════════════════════════════
    print("\n  📏 Scaling features...")
    scaler = fit_and_save_scaler(X_train)
    X_train_scaled = scale_features(X_train, scaler)
    X_test_scaled = scale_features(X_test, scaler)
    print(f"  ✅ Scaling hoàn tất!")

    # ═══════════════════════════════════════════════════════
    # BƯỚC 6: SMOTE (cân bằng lớp trên tập train)
    # ═══════════════════════════════════════════════════════
    X_train_resampled, y_train_resampled = apply_smote(X_train_scaled, y_train)

    # ═══════════════════════════════════════════════════════
    # BƯỚC 7: TRAIN MODELS
    # ═══════════════════════════════════════════════════════
    if mode in ("all", "train-ml"):
        ml_model, ml_acc, ml_time = train_ml_model(
            X_train_resampled, y_train_resampled,
            X_test_scaled, y_test,
            feature_names,
        )

    if mode in ("all", "train-dl"):
        dl_model, dl_history, dl_time = train_dl_model(
            X_train_resampled, y_train_resampled,
            X_test_scaled, y_test,
        )

    # ═══════════════════════════════════════════════════════
    # BƯỚC 8: EVALUATE MODELS
    # ═══════════════════════════════════════════════════════
    if mode in ("all", "evaluate"):
        ml_results = evaluate_ml(X_test_scaled, y_test, feature_names)
        dl_results = evaluate_dl(X_test_scaled, y_test)

        # So sánh ML vs DL
        os.makedirs(REPORTS_DIR, exist_ok=True)
        plot_model_comparison(
            ml_results, dl_results,
            os.path.join(REPORTS_DIR, "model_comparison.png"),
        )

        # ── TỔNG KẾT ──
        print("\n" + "═" * 60)
        print("📊 TỔNG KẾT SO SÁNH")
        print("═" * 60)
        print(f"{'Metric':<25s} {'Random Forest':>15s} {'CNN-LSTM':>15s}")
        print("─" * 55)
        for metric in ["accuracy", "precision_macro", "recall_macro", "f1_macro"]:
            ml_val = ml_results[metric]
            dl_val = dl_results[metric]
            winner = "  ⭐" if ml_val > dl_val else ""
            winner2 = "  ⭐" if dl_val > ml_val else ""
            metric_name = metric.replace("_", " ").title()
            print(f"  {metric_name:<23s} {ml_val:>13.4f}{winner} {dl_val:>13.4f}{winner2}")

        if ml_results.get("roc_auc") and dl_results.get("roc_auc"):
            print(f"  {'ROC-AUC':<23s} {ml_results['roc_auc']:>13.4f} {dl_results['roc_auc']:>13.4f}")

    # ═══════════════════════════════════════════════════════
    # KẾT THÚC
    # ═══════════════════════════════════════════════════════
    total_time = time.time() - total_start
    print(f"\n{'═' * 60}")
    print(f"✅ PIPELINE HOÀN THÀNH!")
    print(f"⏱️  Tổng thời gian: {total_time:.1f}s ({total_time / 60:.1f} phút)")
    print(f"📁 Reports lưu tại: {REPORTS_DIR}")
    print(f"{'═' * 60}")


# ═══════════════════════════════════════════════════════
# CHẠY TỪ COMMAND LINE
# ═══════════════════════════════════════════════════════
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="🛡️ IDS - Machine Learning & Deep Learning Pipeline",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--mode",
        type=str,
        default="all",
        choices=["all", "clean", "train-ml", "train-dl", "evaluate"],
        help=(
            "Chọn bước chạy:\n"
            "  all       - Chạy TẤT CẢ từ đầu đến cuối\n"
            "  clean     - Chỉ load & clean data\n"
            "  train-ml  - Chỉ train Random Forest\n"
            "  train-dl  - Chỉ train CNN-LSTM\n"
            "  evaluate  - Chỉ đánh giá models"
        ),
    )
    args = parser.parse_args()
    run_pipeline(args.mode)

