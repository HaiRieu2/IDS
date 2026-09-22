"""
Module này đọc tất cả file CSV từ dataset và ghép
thành một DataFrame duy nhất.

   Mỗi file chứa 1 ngày, nhưng model cần học TẤT CẢ loại tấn công
   Ghép lại để có 1 dataset đầy đủ cho training

Thư viện sử dụng:
   - pandas: thư viện xử lý dữ liệu dạng bảng (DataFrame)
   - os: làm việc với đường dẫn file
"""

import os
import pandas as pd

# Import cấu hình từ config.py
from ml.config import DATA_DIR, CIC_FILES


def load_single_csv(filepath):
    """
    Đọc 1 file CSV.

    Parameters:
        filepath (str): Đường dẫn đến file CSV

    Returns:
        pd.DataFrame: Dữ liệu từ file CSV

    low_memory=False: đọc toàn bộ file vào RAM trước khi xử lý.
       Chậm hơn nhưng tránh lỗi mixed types (1 cột vừa có số vừa có chữ).
    """
    df = pd.read_csv(filepath, low_memory=False, encoding="utf-8")
    return df


def load_all_csv():
    """
    Đọc TẤT CẢ file CSV trong danh sách CIC_FILES và ghép thành 1 DataFrame.

    Returns:
        pd.DataFrame: DataFrame chứa toàn bộ dữ liệu

        1. Duyệt qua từng file trong CIC_FILES
        2. Đọc file → thêm cột 'source_file' để biết record đến từ file nào
        3. Ghép tất cả bằng pd.concat()
        4. Chuẩn hóa tên cột (strip whitespace)
        5. In thống kê cơ bản
    """
    print("\n" + "=" * 60)
    print("TẢI DỮ LIỆU CIC-IDS")
    print("=" * 60)
    print(f"Thư mục: {DATA_DIR}")
    print(f"Số file: {len(CIC_FILES)}\n")

    dataframes = []  # Danh sách chứa các DataFrame

    for i, filename in enumerate(CIC_FILES, 1):
        filepath = os.path.join(DATA_DIR, filename)

        # Kiểm tra file có tồn tại không
        if not os.path.exists(filepath):
            print(f"  ⚠️  [{i}/{len(CIC_FILES)}] KHÔNG TÌM THẤY: {filename}")
            continue

        # Đọc file
        print(f"  📄 [{i}/{len(CIC_FILES)}] Đang đọc: {filename}...", end=" ", flush=True)
        df = load_single_csv(filepath)

        # Thêm cột source_file để truy vết nguồn gốc
        df["source_file"] = filename

        print(f"✅ ({len(df):,} records)")
        dataframes.append(df)

    # Kiểm tra có đọc được file nào không
    if not dataframes:
        raise FileNotFoundError(
            f"Không tìm thấy file CSV nào trong: {DATA_DIR}\n"
            f"Hãy kiểm tra lại đường dẫn và danh sách file trong config.py"
        )

    # Ghép tất cả DataFrame thành 1
    # ignore_index=True: đánh số index lại từ 0
    print(f"\n Đang ghép {len(dataframes)} files...", end=" ", flush=True)
    combined = pd.concat(dataframes, ignore_index=True)
    print("✅")

    # ===== CHUẨN HÓA TÊN CỘT =====
    # CIC-IDS 2017 có bug: tên cột thường có dấu cách thừa ở đầu
    # Ví dụ: " Label" thay vì "Label", " Flow Duration" thay vì "Flow Duration"
    # .str.strip() xóa khoảng trắng ở đầu và cuối
    combined.columns = combined.columns.str.strip()

    # ===== IN THỐNG KÊ =====
    print(f"\n{'─' * 50}")
    print(f"THỐNG KÊ TỔNG QUAN:")
    print(f"{'─' * 50}")
    print(f"  Tổng records:  {len(combined):,}")
    print(f"  Tổng cột:      {combined.shape[1]}")
    print(f"  Bộ nhớ:        {combined.memory_usage(deep=True).sum() / 1024**2:.1f} MB")

    print(f"\n📋 PHÂN PHỐI LABEL (loại traffic):")
    print(f"{'─' * 50}")
    label_counts = combined["Label"].value_counts()
    for label, count in label_counts.items():
        pct = count / len(combined) * 100
        bar = "█" * int(pct / 2)  # Thanh biểu đồ đơn giản
        print(f"  {label:35s} {count:>10,}  ({pct:5.2f}%)  {bar}")

    return combined


# ===== CHẠY THỬ =====
# Nếu chạy file này trực tiếp (python load_dataset.py), sẽ thực thi phần dưới
if __name__ == "__main__":
    df = load_all_csv()
    print(f"\nDone! Shape: {df.shape}")

