import pandas as pd
import numpy as np
import glob
def data_processing(data):
    #=================================================
    #Xu li data

    #1. Xoa cac bang tin trung lap
    print("So ban tin trung lap: " + str(data.duplicated().sum()))
    data = data.drop_duplicates(ignore_index=True)
    print("Da xoa!")
    print("So ban tin trung lap con lai: "+str(data.duplicated().sum()))
    
    #2.Xoa khoang trang thua
    data.columns = data.columns.str.strip()
    print("Da Xoa Khoang Trang!")

    #3. Xoa nhung label khong dung den
    
    # Lọc lại giữ lại những dòng KHÁC 'Heartbleed'
    data = data[data['Label'] != 'Heartbleed'].reset_index(drop=True)

    #4. Doi ten label :Web Attack � Brute Force, Web Attack � XSS,Web Attack � Sql Injection
   
    doi_ten_label = {
        'Web Attack � Brute Force': 'Web Attack - Brute Force',
        'Web Attack � XSS': 'XSS',
        'Web Attack � Sql Injection': 'Sqli'
    }

    data['Label'] = data['Label'].replace(doi_ten_label)
    print(data["Label"].value_counts())

    #5. Xu li Inf va NaN va cho trong ""

    data = data.replace([np.inf, -np.inf, -1], 0)

    data = data.replace(r'^\s*$', np.nan, regex=True)

    data = data.fillna(0)

    #6. Dam bao feature la numeric

    if 'Label' in data.columns:
        label_col = data['Label']
        feature_cols = data.drop(columns=['Label'])
    else:
        feature_cols = data.copy()

    # 2. Ép tất cả các cột feature sang kiểu số (numeric)
    # errors='coerce': Nếu ô nào chứa chữ hoặc ký tự không đổi được thành số sẽ tự động biến thành NaN
    for col in feature_cols.columns:
        feature_cols[col] = pd.to_numeric(feature_cols[col], errors='coerce')

    # 3. Điền số 0 cho tất cả các giá trị NaN vừa phát sinh (hoặc các giá trị trống sẵn có)
    feature_cols = feature_cols.fillna(0)

    # 4. Gộp lại cột Label (nếu có ban đầu)
    if 'Label' in data.columns:
        data = pd.concat([feature_cols, label_col], axis=1)
    else:
        data = feature_cols

    print("Đã ép kiểu toàn bộ features thành công!")
    #print(data.dtypes) # Kiểm tra lại kiểu dữ liệu của các cột

    return data
def main():
    data_processing()
if __name__ == "__main__":
    main()


