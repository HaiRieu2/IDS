"""
  1. Bản ghi trùng lặp (duplicates)
  2. Giá trị vô cùng (Infinity) và thiếu (NaN)
  3. Labels quá chi tiết (cần gom nhóm)
  4. Cột không cần thiết (IP, Timestamp...)
  5. Kiểu dữ liệu tốn bộ nhớ (float64 → float32)

Thư viện:
   - numpy: tính toán số học, xử lý array
   - pandas: xử lý dữ liệu dạng bảng
"""

import os
import numpy as np
import pandas as pd

from ml.config import (
    LABEL_MAP,
    DROP_LABELS,
    DROP_COLUMNS,
    CLEANED_DATA_PATH,
    PROCESSED_DIR,
)


def clean_data(df):
    """
    Làm sạch DataFrame thô từ CIC-IDS 2017.

    Parameters:
        df (pd.DataFrame): DataFrame thô từ load_all_csv()

    Returns:
        pd.DataFrame: DataFrame đã được làm sạch

        1. Xóa cột không cần thiết
        2. Xóa bản ghi trùng lặp
        3. Gom nhóm labels
        4. Xử lý Infinity và NaN
        5. Đảm bảo tất cả features là numeric
        6. Tối ưu bộ nhớ (downcast)
    """
    print("\n" + "=" * 60)
    print("🧹 BƯỚC 1: LÀM SẠCH DỮ LIỆU")
    print("=" * 60)

    original_rows = len(df)

    # ────────────────────────────────────────────────────────────
    # BƯỚC 1: XÓA CỘT KHÔNG CẦN THIẾT
    # Flow ID, Source IP, Dest IP, Timestamp → không phải features hữu ích
    # Source_file → cột phụ do ta thêm vào khi load

    print("\n[1/6] Xóa các cột không cần thiết...")
    cols_to_drop = [c for c in DROP_COLUMNS if c in df.columns]
    if "source_file" in df.columns:
        cols_to_drop.append("source_file")
    df = df.drop(columns=cols_to_drop, errors="ignore")
    print(f"  → Đã xóa {len(cols_to_drop)} cột: {cols_to_drop}")
    print(f"  → Còn lại: {df.shape[1]} cột")

    # ────────────────────────────────────────────────────────────
    # BƯỚC 2/6: XÓA BẢN GHI TRÙNG LẶP
    # Dataset CIC-IDS 2017 có nhiều rows hoàn toàn giống nhau
    # Giữ lại chỉ 1 bản, xóa các bản trùng

    print("\n[2/6] Xóa bản ghi trùng lặp...")
    before = len(df)
    df = df.drop_duplicates()
    removed = before - len(df)
    print(f"  → Xóa {removed:,} duplicates ({before:,} → {len(df):,})")

    # ────────────────────────────────────────────────────────────
    # BƯỚC 3/6: GOM NHÓM LABELS
    # Chuyển ~15 label chi tiết → 6 nhóm chính
    # Ví dụ: "DoS Hulk", "DoS GoldenEye" → "DoS"

    print("\n[3/6] Gom nhóm labels...")

    # Strip whitespace ở label (CIC-IDS 2017 đôi khi có khoảng trắng thừa)
    df["Label"] = df["Label"].astype(str).str.strip()

    # Hiển thị labels gốc
    print("  → Labels gốc trong dataset:")
    for label, count in df["Label"].value_counts().items():
        print(f"     {label:40s} → {count:>10,}")

    # Loại bỏ labels quá ít mẫu (Heartbleed, Infiltration, Bot)
    mask_drop = df["Label"].isin(DROP_LABELS)
    dropped_count = mask_drop.sum()
    if dropped_count > 0:
        print(f"\n  → Loại bỏ {dropped_count:,} records thuộc: {DROP_LABELS}")
        df = df[~mask_drop]

    # Áp dụng label mapping
    df["Label"] = df["Label"].map(LABEL_MAP)

    # Xóa rows có label không nằm trong LABEL_MAP (NaN sau map)
    unmapped = df["Label"].isna().sum()
    if unmapped > 0:
        print(f"  → Loại bỏ {unmapped:,} records với label không xác định")
        df = df.dropna(subset=["Label"])

    # Hiển thị phân phối sau gom nhóm
    print(f"\n  → Phân phối sau khi gom nhóm:")
    for label, count in df["Label"].value_counts().items():
        pct = count / len(df) * 100
        print(f"     {label:20s} {count:>10,}  ({pct:5.2f}%)")

    # ────────────────────────────────────────────────────────────
    # BƯỚC 4/6: XỬ LÝ INFINITY VÀ NaN
    # ────────────────────────────────────────────────────────────
    # CICFlowMeter (tool tạo dataset) đôi khi tạo ra:
    #   - Infinity: khi chia cho 0 (ví dụ: bytes/flow_duration khi duration=0)
    #   - NaN: khi thiếu dữ liệu
    # ML/DL models KHÔNG THỂ xử lý Inf và NaN → cần loại bỏ

    print("\n[4/6] ♾️  Xử lý giá trị Infinity và NaN...")

    # Chọn các cột số (không tính cột Label)
    numeric_cols = df.select_dtypes(include=[np.number]).columns

    # Thay Inf bằng NaN (để xử lý đồng nhất)
    inf_count = np.isinf(df[numeric_cols].values).sum()
    df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)

    # Đếm NaN
    nan_count = df[numeric_cols].isna().sum().sum()
    print(f"  → Tìm thấy {inf_count:,} Infinity + {nan_count - inf_count:,} NaN = {nan_count:,} tổng")

    # Xóa rows chứa NaN
    before = len(df)
    df = df.dropna()
    print(f"  → Xóa {before - len(df):,} rows chứa NaN/Inf")

    # ────────────────────────────────────────────────────────────
    # BƯỚC 5/6: ĐẢM BẢO TẤT CẢ FEATURES LÀ NUMERIC
    # ────────────────────────────────────────────────────────────
    # Đôi khi 1 cột bị mixed types (vừa số vừa chữ)
    # pd.to_numeric(..., errors='coerce') chuyển các giá trị không phải số → NaN

    print("\n[5/6] 🔢 Đảm bảo tất cả features là numeric...")

    label_col = df["Label"].copy()
    feature_df = df.drop(columns=["Label"])

    # Chuyển tất cả sang numeric
    feature_df = feature_df.apply(pd.to_numeric, errors="coerce")

    # Xóa rows mới bị NaN do coercion
    valid_mask = feature_df.notna().all(axis=1)
    invalid_count = (~valid_mask).sum()
    if invalid_count > 0:
        print(f"  → Loại bỏ {invalid_count:,} rows có giá trị không phải số")
        feature_df = feature_df[valid_mask]
        label_col = label_col[valid_mask]

    df = pd.concat([feature_df, label_col], axis=1)
    print(f"  → Tất cả {feature_df.shape[1]} features đều là numeric ✅")

    # ────────────────────────────────────────────────────────────
    # BƯỚC 6/6: TỐI ƯU BỘ NHỚ (DOWNCAST)
    # ────────────────────────────────────────────────────────────
    # float64 → float32: giảm 50% RAM mà không ảnh hưởng kết quả
    # int64 → int32/int16/int8: tùy giá trị

    print("\n[6/6] 💾 Tối ưu bộ nhớ (downcast kiểu dữ liệu)...")
    mem_before = df.memory_usage(deep=True).sum() / 1024**2

    for col in df.select_dtypes(include=["float64"]).columns:
        df[col] = df[col].astype(np.float32)

    for col in df.select_dtypes(include=["int64"]).columns:
        df[col] = pd.to_numeric(df[col], downcast="integer")

    mem_after = df.memory_usage(deep=True).sum() / 1024**2
    print(f"  → Bộ nhớ: {mem_before:.1f} MB → {mem_after:.1f} MB (giảm {(1 - mem_after/mem_before)*100:.0f}%)")

    # ────────────────────────────────────────────────────────────
    # TỔNG KẾT
    # ────────────────────────────────────────────────────────────
    print(f"\n{'═' * 50}")
    print(f"✅ LÀM SẠCH HOÀN TẤT!")
    print(f"{'═' * 50}")
    print(f"  Records: {original_rows:,} → {len(df):,} (giữ {len(df)/original_rows*100:.1f}%)")
    print(f"  Features: {df.shape[1] - 1} cột")
    print(f"  Bộ nhớ: {mem_after:.1f} MB")

    return df


def save_cleaned_data(df):
    """
    Lưu dữ liệu đã clean ra file Parquet.

    💡 TẠI SAO DÙNG PARQUET THAY VÌ CSV?
       - Parquet nén tốt hơn → file nhỏ hơn CSV 5-10 lần
       - Đọc nhanh hơn CSV 10-100 lần
       - Giữ nguyên kiểu dữ liệu (CSV luôn đọc lại thành string rồi convert)
       - Chuẩn công nghiệp cho Big Data

    Parameters:
        df (pd.DataFrame): DataFrame đã clean
    """
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    df.to_parquet(CLEANED_DATA_PATH, index=False, engine="pyarrow")
    file_size = os.path.getsize(CLEANED_DATA_PATH) / 1024**2
    print(f"\n💾 Đã lưu cleaned data: {CLEANED_DATA_PATH}")
    print(f"   Kích thước file: {file_size:.1f} MB")


def load_cleaned_data():
    """
    Load dữ liệu đã clean từ file Parquet.

    Returns:
        pd.DataFrame: DataFrame đã clean

    💡 Dùng hàm này khi muốn bỏ qua bước clean
       (đã clean rồi, chỉ cần load lại)
    """
    if not os.path.exists(CLEANED_DATA_PATH):
        raise FileNotFoundError(
            f"Chưa có cleaned data tại: {CLEANED_DATA_PATH}\n"
            f"Hãy chạy pipeline với mode='clean' trước!"
        )
    print(f"📂 Loading cleaned data từ: {CLEANED_DATA_PATH}")
    df = pd.read_parquet(CLEANED_DATA_PATH)
    print(f"   → {len(df):,} records, {df.shape[1]} cột")
    return df


# ===== CHẠY THỬ =====
if __name__ == "__main__":
    from ml.dataset.load_dataset import load_all_csv

    df = load_all_csv()
    df = clean_data(df)
    save_cleaned_data(df)

