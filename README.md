# IDS: CIC-IDS-2017 flow analysis

Tài liệu giải thích kiến trúc và chức năng từng hàm: [Hướng dẫn đọc code và bảo vệ đồ án](docs/ARCHITECTURE_AND_DEFENSE_GUIDE.md).

Hệ thống có hai đầu vào dùng chung một pipeline phân tích: capture trực tiếp và PCAP offline. TCP flow được ghép hai chiều, payload TCP được sắp xếp theo sequence number để xử lý gói đến sai thứ tự/retransmission, HTTP request/response được ghép theo Content-Length/chunked/FIN. Khi session đóng, pipeline chạy behavior → signature → TF-IDF/Logistic Regression theo từng HTTP request → Random Forest theo đặc trưng flow. Alert của live ghi vào `logs/alerts.json`; kết quả PCAP được cô lập theo lần phân tích.

## Chạy hệ thống trên Windows

Cài dependency một lần:

```powershell
python -m pip install -r requirements.txt
```

Chạy dashboard trong terminal thứ nhất:

```powershell
python -m dashboard.app
```

Mở `http://127.0.0.1:5000`. Trong thẻ **Live traffic capture**, nhập tên card mạng nếu cần, giữ filter mặc định hoặc đổi BPF filter, rồi chọn **Bắt đầu capture**. Capture cần Npcap và quyền truy cập card mạng. **Dừng capture** đóng các flow còn lại và hoàn tất pipeline.

Chạy web victim trong terminal thứ hai:

```powershell
python -m web.app
```

Victim lắng nghe ở `http://127.0.0.1:8080`; dashboard dùng cổng 5000. Có thể đổi victim host/port bằng `IDS_WEB_HOST` và `IDS_WEB_PORT`. Web giữ các điểm yếu SQL injection và stored XSS để phục vụ bài lab; chỉ chạy trên mạng lab cô lập.

Tải `.pcap`, `.pcapng` hoặc `.cap` trong dashboard để phân tích offline. Các flow chưa có FIN/RST sẽ được finalize ở cuối tệp. Các detector behavior, signature, ML theo request và ML theo flow đều chạy; alert PCAP không ghi vào log live.

## Huấn luyện ML

Trainer chỉ đọc các CSV CIC-IDS-2017 trong `data/cicids2017`. Runtime và trainer dùng chung schema `CIC_FEATURES` gồm 61 feature; sáu feature cờ đã được loại khỏi vector.

Chạy:

```powershell
python -m ml.rf_training
```

Trainer chuẩn hóa DoS Hulk và DoS GoldenEye thành `HTTP Flood`, DoS slowloris và DoS Slowhttptest thành `HTTP slow`; các nhãn BENIGN/XSS/SQLi/Web Brute Force cũng được chuẩn hóa, còn FTP/SSH brute-force được giữ riêng. Trước khi chia tập hoặc train, flow XSS và SQLi bị loại khỏi Random Forest; hai loại này do signature và request-text Logistic Regression xử lý. Random Forest dùng criterion `gini` cùng class weights cân bằng. Trainer chỉ in stratified holdout metrics, sau đó fit model cuối trên toàn bộ flow còn lại và lưu `ml/rf_model.pkl`; không chạy cross-dataset test. Khởi động lại dashboard/capture sau khi thay model để tiến trình nạp model mới.

Runtime và trainer dùng chung vector 61 feature, đã bỏ sáu feature cờ. Cần chạy lại trainer để tạo artifact Random Forest theo schema này trước khi dùng nhánh flow ML. Trường byte/packet-length ML đã dùng payload TCP/UDP như CICFlowMeter; byte IP cho Dashboard vẫn tách riêng. Đây vẫn là phép tính tương thích gần đúng cho đến khi so sánh từng flow trên cùng PCAP với đúng phiên bản CICFlowMeter. Ngưỡng `ML_ALERT_THRESHOLD` hiện là 0.20 để tăng cảnh báo khi model còn nghiêng về BENIGN; đánh đổi là false positive có thể tăng. Không mô hình nào bảo đảm bỏ sót bằng 0; xem recall từng lớp trên tập độc lập và đánh giá lại bằng PCAP live/ngoài huấn luyện trước khi dùng ngoài lab.

### Phân loại nội dung HTTP request

Model HTTP là model riêng với model CICFlowMeter. Dataset mặc định là `data/xss_sqli/xss_sqli_http_requests.csv`, gồm `request_text` và `label` (`BENIGN`, `SQLi`, `XSS`). Huấn luyện và ghi pipeline TF-IDF + Logistic Regression vào `ml/request_text_model.joblib`:

```powershell
python -m ml.request_text_training
```

Tiến trình train được in trực tiếp ra terminal và lưu vào `reports/request_text_training.log`.

Pipeline kết hợp word n-gram và character n-gram để giữ cả từ khóa và dấu câu trong request, sau đó phân lớp bằng Logistic Regression. Khi session đóng, IDS predict từng HTTP request theo định dạng `method + " " + uri + " " + body`, giống dataset; header HTTP và HTTP version không được đưa vào model. IDS tạo alert XSS/SQLi khi xác suất cao nhất giữa hai lớp tấn công đạt `REQUEST_TEXT_ALERT_THRESHOLD` (mặc định 0.8 trong `config/rules.json`). Model CICFlowMeter tiếp tục phân loại flow riêng. Model request được serialize bằng joblib và có phần mở rộng `.joblib`. Chạy lại lệnh train để cập nhật model; runtime tự nạp lại file model mới.

Báo cáo trong lúc train dùng stratified random holdout. Dataset tổng hợp có thể chứa các họ mẫu gần nhau giữa train/test, nên không xem điểm này là kết quả tổng quát hóa trên traffic thật. Đánh giá thêm bằng request thật đã gán nhãn độc lập.
