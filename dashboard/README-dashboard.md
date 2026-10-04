# Dashboard IDS

## Chạy trên Windows
Mở PowerShell tại thư mục `dashboard`:

```powershell
cd "F:\IDS\dashboard"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r ..\requirements.txt
python app.py
```

Mở http://127.0.0.1:5000.

## Phân tích PCAP ngoại tuyến
Trên dashboard, chọn hoặc kéo thả `.pcap`, `.pcapng` hoặc `.cap`, sau đó bấm **Phân tích offline**. Flask lưu tệp tạm thời, dùng `LiveCapture.read_pcap()` đọc tuần tự từng packet, đưa các session đã đóng qua behavior, signature, model TF-IDF/Logistic Regression theo từng HTTP request và Random Forest theo flow, rồi chuyển sang trang kết quả riêng `/pcap/result/<id>`.

Alert của PCAP được lưu riêng trong `logs/offline_results/`; nó không ghi vào `logs/alerts.json` của live capture. Kết quả phân tích được giữ ở đó để có thể mở lại trang kết quả. Tệp PCAP gốc sẽ bị xóa sau khi xử lý. Giới hạn upload là 500 MB.

Hai model và các dependency trong `requirements.txt` cần có sẵn: `ml/rf_model.pkl` cho feature flow, `ml/request_text_model.joblib` cho nội dung HTTP. Train model request từ thư mục project bằng `python -m ml.request_text_training`; log được lưu ở `reports/request_text_training.log`. Dashboard cũng điều khiển live capture tại thẻ Live traffic capture. Chọn card mạng, bắt đầu/dừng capture; packet/s lấy trực tiếp từ packet đã xử lý. Live và PCAP dùng chung pipeline behavior → signature → request ML → flow ML. Session được phân tích khi đóng hoặc khi PCAP kết thúc.

