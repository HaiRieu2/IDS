"""
train_dl.py - Huấn luyện Model Deep Learning (CNN-LSTM Hybrid)
================================================================

Module này huấn luyện mô hình CNN-LSTM kết hợp sử dụng PyTorch
để phát hiện xâm nhập mạng.

╔══════════════════════════════════════════════════════════════╗
║                  KIẾN TRÚC CNN-LSTM                         ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  Input (78 features)                                         ║
║      ↓                                                       ║
║  Reshape → (batch, 1, 78)     ← xem features như 1 "chuỗi"  ║
║      ↓                                                       ║
║  ┌─ Conv1d(1→64, k=3) ─┐                                    ║
║  │  BatchNorm1d(64)     │     ← CNN trích xuất đặc trưng     ║
║  │  ReLU + Dropout(0.3) │       cục bộ từ features liền kề   ║
║  └──────────────────────┘                                    ║
║      ↓                                                       ║
║  ┌─ Conv1d(64→128, k=3) ┐                                   ║
║  │  BatchNorm1d(128)     │    ← CNN sâu hơn, patterns phức   ║
║  │  ReLU + Dropout(0.3)  │      tạp hơn                      ║
║  └───────────────────────┘                                   ║
║      ↓                                                       ║
║  Permute → (batch, 78, 128)   ← đổi chiều cho LSTM          ║
║      ↓                                                       ║
║  ┌─ BiLSTM(128→128×2) ──┐                                   ║
║  │  2 layers, bidir      │    ← LSTM học mối quan hệ tuần    ║
║  │  Dropout(0.3)         │      tự giữa các features         ║
║  └───────────────────────┘                                   ║
║      ↓                                                       ║
║  Attention Layer              ← Tập trung vào phần quan      ║
║      ↓                         trọng nhất                    ║
║  FC(256→128) + ReLU + Drop    ← Fully Connected layers       ║
║      ↓                                                       ║
║  FC(128→6)                    ← Output: 6 lớp                ║
║      ↓                                                       ║
║  Softmax → [Benign, Brute Force, DDoS, DoS, PortScan, Web]  ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

💡 TẠI SAO KẾT HỢP CNN + LSTM?
   - CNN: giỏi trích xuất patterns cục bộ (nhóm features gần nhau)
   - LSTM: giỏi học mối quan hệ xa (giữa các features ở vị trí khác nhau)
   - Kết hợp: khai thác cả hai → accuracy cao hơn dùng riêng lẻ

💡 ATTENTION LÀ GÌ?
   Giống như con người đọc 1 đoạn văn dài:
   → Không phải mọi từ đều quan trọng
   → Attention giúp model "tập trung" vào các features quan trọng nhất
   → Tự động học weights cho mỗi feature

📦 Thư viện:
   - torch: framework deep learning (PyTorch)
   - torch.nn: các layer neural network
   - torch.optim: các optimizer (Adam, SGD, ...)
"""

import time
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

from ml.config import DL_PARAMS, DL_MODEL_PATH, NUM_CLASSES


# ╔══════════════════════════════════════════════════════════════╗
# ║                    ATTENTION LAYER                           ║
# ╚══════════════════════════════════════════════════════════════╝

class AttentionLayer(nn.Module):
    """
    Attention mechanism cho LSTM output.

    Input:  (batch, seq_len, hidden_size)
    Output: (batch, hidden_size)

    Cách hoạt động:
        1. Tính "điểm attention" cho mỗi time step
        2. Softmax → chuyển thành xác suất (tổng = 1)
        3. Weighted sum → tổng có trọng số
        → Time step nào quan trọng hơn sẽ có weight lớn hơn
    """

    def __init__(self, hidden_size):
        super().__init__()
        # Linear layer: hidden_size → 1 (tính attention score)
        self.attention_weights = nn.Linear(hidden_size, 1)

    def forward(self, lstm_output):
        # lstm_output shape: (batch, seq_len, hidden_size)

        # Tính attention scores
        scores = self.attention_weights(lstm_output)  # → (batch, seq_len, 1)

        # Softmax: chuyển scores → xác suất (tổng = 1 theo dim seq_len)
        weights = torch.softmax(scores, dim=1)  # → (batch, seq_len, 1)

        # Weighted sum: nhân weights × lstm_output rồi cộng lại
        context = torch.sum(weights * lstm_output, dim=1)  # → (batch, hidden_size)

        return context


# ╔══════════════════════════════════════════════════════════════╗
# ║                  CNN-LSTM HYBRID MODEL                       ║
# ╚══════════════════════════════════════════════════════════════╝

class CNNLSTM(nn.Module):
    """
    CNN-LSTM Hybrid Model cho Network Intrusion Detection.

    Parameters:
        input_size (int): Số features đầu vào (78 cho CIC-IDS 2017)
        num_classes (int): Số lớp đầu ra (6: Benign + 5 loại tấn công)
        params (dict): Hyperparameters từ config.py

    💡 nn.Module: lớp cơ sở cho tất cả neural network trong PyTorch.
       Mọi model đều phải kế thừa (inherit) từ nn.Module.
    """

    def __init__(self, input_size, num_classes, params=None):
        super().__init__()

        if params is None:
            params = DL_PARAMS

        hidden_size = params["hidden_size"]       # 128
        num_layers = params["num_layers"]          # 2
        dropout = params["dropout"]                # 0.3
        conv_channels = params["conv_channels"]    # [64, 128]

        # ── CNN LAYERS ──
        # Conv1d: convolution 1 chiều
        #   - in_channels: số kênh đầu vào (1 = xem features như 1 "chuỗi")
        #   - out_channels: số filter (mỗi filter học 1 pattern khác nhau)
        #   - kernel_size: kích thước cửa sổ trượt (3 = nhìn 3 features liên tiếp)
        #   - padding: thêm 0 ở 2 đầu để output cùng kích thước input

        self.conv1 = nn.Sequential(
            nn.Conv1d(1, conv_channels[0], kernel_size=3, padding=1),
            nn.BatchNorm1d(conv_channels[0]),   # Chuẩn hóa output → train ổn định hơn
            nn.ReLU(),                           # Hàm kích hoạt: f(x) = max(0, x)
            nn.Dropout(dropout),                 # Tắt ngẫu nhiên 30% neuron → chống overfitting
        )

        self.conv2 = nn.Sequential(
            nn.Conv1d(conv_channels[0], conv_channels[1], kernel_size=3, padding=1),
            nn.BatchNorm1d(conv_channels[1]),
            nn.ReLU(),
            nn.Dropout(dropout),
        )

        # ── LSTM LAYER ──
        # LSTM: Long Short-Term Memory
        #   - input_size: kích thước đầu vào mỗi time step (= conv_channels[1])
        #   - hidden_size: kích thước hidden state
        #   - num_layers: số tầng LSTM xếp chồng (sâu hơn → học phức tạp hơn)
        #   - batch_first: input shape = (batch, seq_len, features)
        #   - bidirectional: đọc từ 2 chiều → output_size = hidden_size × 2

        self.lstm = nn.LSTM(
            input_size=conv_channels[1],
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            bidirectional=True,
            dropout=dropout if num_layers > 1 else 0,
        )

        # ── ATTENTION LAYER ──
        # hidden_size × 2 vì bidirectional LSTM
        self.attention = AttentionLayer(hidden_size * 2)

        # ── FULLY CONNECTED (CLASSIFIER) ──
        # Nhận output từ Attention → phân loại thành num_classes lớp
        self.classifier = nn.Sequential(
            nn.Linear(hidden_size * 2, hidden_size),  # 256 → 128
            nn.ReLU(),
            nn.Dropout(0.5),                           # Dropout mạnh hơn ở FC layer
            nn.Linear(hidden_size, num_classes),        # 128 → 6
        )

    def forward(self, x):
        """
        Forward pass: dữ liệu đi qua model từ đầu đến cuối.

        Input:  x shape (batch_size, num_features)  ← mỗi sample là 1 vector
        Output: shape (batch_size, num_classes)      ← xác suất cho mỗi lớp
        """
        # ── BƯỚC 1: RESHAPE cho CNN ──
        # (batch, features) → (batch, 1, features)
        # Conv1d cần 3 chiều: (batch, channels, length)
        x = x.unsqueeze(1)

        # ── BƯỚC 2: CNN ──
        # Trích xuất đặc trưng cục bộ
        x = self.conv1(x)     # (batch, 1, feat) → (batch, 64, feat)
        x = self.conv2(x)     # (batch, 64, feat) → (batch, 128, feat)

        # ── BƯỚC 3: RESHAPE cho LSTM ──
        # (batch, channels, length) → (batch, length, channels)
        # LSTM cần: (batch, seq_len, input_size)
        x = x.permute(0, 2, 1)

        # ── BƯỚC 4: LSTM ──
        # Học mối quan hệ tuần tự giữa các features
        x, _ = self.lstm(x)   # → (batch, seq_len, hidden×2)

        # ── BƯỚC 5: ATTENTION ──
        # Tập trung vào phần quan trọng nhất
        x = self.attention(x)  # → (batch, hidden×2)

        # ── BƯỚC 6: CLASSIFY ──
        # Fully connected layers → output
        x = self.classifier(x)  # → (batch, num_classes)

        return x


# ╔══════════════════════════════════════════════════════════════╗
# ║                    TRAINING FUNCTION                         ║
# ╚══════════════════════════════════════════════════════════════╝

def train_dl_model(X_train, y_train, X_test, y_test):
    """
    Huấn luyện CNN-LSTM model.

    Parameters:
        X_train (np.ndarray): Features tập train (đã scale, đã SMOTE)
        y_train (np.ndarray): Labels tập train
        X_test (np.ndarray): Features tập test (đã scale)
        y_test (np.ndarray): Labels tập test

    Returns:
        model: Model đã train (best checkpoint)
        history (dict): Lịch sử training (loss, accuracy mỗi epoch)
        training_time (float): Tổng thời gian train (giây)

    💡 Training Loop:
       Mỗi epoch:
         1. TRAIN: model học từ training data
         2. VALIDATE: đánh giá trên test data (không update weights)
         3. Ghi lại loss/accuracy
         4. Kiểm tra early stopping
         5. Lưu best model
    """
    print("\n" + "=" * 60)
    print("🧠 HUẤN LUYỆN MODEL: CNN-LSTM (Deep Learning)")
    print("=" * 60)

    params = DL_PARAMS

    # ── CHỌN DEVICE ──
    # GPU (CUDA) nhanh hơn CPU 10-100 lần cho deep learning
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"\n🖥️  Device: {device}")
    if device.type == "cuda":
        print(f"   GPU: {torch.cuda.get_device_name(0)}")
        print(f"   VRAM: {torch.cuda.get_device_properties(0).total_mem / 1024**3:.1f} GB")
    else:
        print("   ⚠️ Đang dùng CPU - training sẽ chậm hơn GPU")

    # ── CHUYỂN DỮ LIỆU SANG TENSOR ──
    # PyTorch dùng Tensor (tương tự numpy array nhưng chạy được trên GPU)
    print("\n📦 Chuẩn bị dữ liệu...")
    X_train_t = torch.FloatTensor(X_train)
    y_train_t = torch.LongTensor(y_train)
    X_test_t = torch.FloatTensor(X_test)
    y_test_t = torch.LongTensor(y_test)

    # ── TẠO DATALOADER ──
    # DataLoader: tự động chia data thành batches, shuffle mỗi epoch
    train_dataset = TensorDataset(X_train_t, y_train_t)
    test_dataset = TensorDataset(X_test_t, y_test_t)

    train_loader = DataLoader(
        train_dataset,
        batch_size=params["batch_size"],  # 1024 samples/batch
        shuffle=True,                      # Xáo trộn mỗi epoch
        num_workers=0,                     # Không dùng multiprocessing (Windows compatible)
        pin_memory=True if device.type == "cuda" else False,
    )
    test_loader = DataLoader(
        test_dataset,
        batch_size=params["batch_size"],
        shuffle=False,  # Test set không cần shuffle
        num_workers=0,
        pin_memory=True if device.type == "cuda" else False,
    )

    # ── TẠO MODEL ──
    input_size = X_train.shape[1]  # Số features
    model = CNNLSTM(input_size, NUM_CLASSES, params).to(device)

    # Hiển thị kiến trúc model
    print(f"\n📐 Kiến trúc Model:")
    print(model)
    total_params = sum(p.numel() for p in model.parameters())
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"\n   Tổng parameters: {total_params:,}")
    print(f"   Trainable params: {trainable_params:,}")

    # ── CLASS WEIGHTS ──
    # Nếu data vẫn mất cân bằng sau SMOTE, class weights giúp
    # penalize nhiều hơn khi model đoán sai lớp thiểu số
    class_counts = np.bincount(y_train, minlength=NUM_CLASSES)
    if class_counts.min() > 0:
        class_weights = 1.0 / class_counts.astype(np.float32)
        class_weights = class_weights / class_weights.sum() * NUM_CLASSES
    else:
        class_weights = np.ones(NUM_CLASSES)
    weights_tensor = torch.FloatTensor(class_weights).to(device)

    # ── LOSS FUNCTION ──
    # CrossEntropyLoss: loss phổ biến nhất cho multi-class classification
    # Kết hợp LogSoftmax + NLLLoss
    criterion = nn.CrossEntropyLoss(weight=weights_tensor)

    # ── OPTIMIZER ──
    # Adam: optimizer phổ biến nhất, tự điều chỉnh learning rate cho mỗi parameter
    optimizer = torch.optim.Adam(
        model.parameters(),
        lr=params["learning_rate"],     # 0.001
        weight_decay=params["weight_decay"],  # L2 regularization
    )

    # ── LEARNING RATE SCHEDULER ──
    # Giảm learning rate khi val_loss ngừng giảm
    # factor=0.5: giảm LR còn 1/2
    # patience=5: chờ 5 epochs không cải thiện trước khi giảm
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode="min", patience=params["lr_patience"], factor=0.5
    )

    # ── TRAINING LOOP ──
    best_val_loss = float("inf")
    patience_counter = 0
    history = {
        "train_loss": [],
        "val_loss": [],
        "train_acc": [],
        "val_acc": [],
    }

    print(f"\n⚙️  Hyperparameters:")
    print(f"   Epochs: {params['epochs']} | Batch: {params['batch_size']} | LR: {params['learning_rate']}")
    print(f"   Early Stopping patience: {params['patience']}")

    print(f"\n{'Epoch':>5} │ {'Train Loss':>10} │ {'Val Loss':>10} │ {'Train Acc':>9} │ {'Val Acc':>9} │ {'LR':>10}")
    print("─" * 72)

    start_time = time.time()

    for epoch in range(params["epochs"]):

        # ════════════════════════════════════
        #            TRAIN PHASE
        # ════════════════════════════════════
        model.train()  # Bật training mode (Dropout hoạt động)
        train_loss = 0.0
        train_correct = 0
        train_total = 0

        for X_batch, y_batch in train_loader:
            # Chuyển batch lên device (GPU/CPU)
            X_batch = X_batch.to(device)
            y_batch = y_batch.to(device)

            # Forward pass: dữ liệu đi qua model
            optimizer.zero_grad()  # Reset gradients (quan trọng!)
            outputs = model(X_batch)
            loss = criterion(outputs, y_batch)

            # Backward pass: tính gradients
            loss.backward()

            # Gradient clipping: ngăn gradients quá lớn (exploding gradients)
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)

            # Update weights
            optimizer.step()

            # Thống kê
            train_loss += loss.item() * X_batch.size(0)
            _, predicted = outputs.max(1)
            train_total += y_batch.size(0)
            train_correct += predicted.eq(y_batch).sum().item()

        train_loss /= train_total
        train_acc = train_correct / train_total

        # ════════════════════════════════════
        #          VALIDATION PHASE
        # ════════════════════════════════════
        model.eval()  # Tắt training mode (Dropout không hoạt động)
        val_loss = 0.0
        val_correct = 0
        val_total = 0

        with torch.no_grad():  # Không tính gradients → nhanh hơn, ít RAM hơn
            for X_batch, y_batch in test_loader:
                X_batch = X_batch.to(device)
                y_batch = y_batch.to(device)

                outputs = model(X_batch)
                loss = criterion(outputs, y_batch)

                val_loss += loss.item() * X_batch.size(0)
                _, predicted = outputs.max(1)
                val_total += y_batch.size(0)
                val_correct += predicted.eq(y_batch).sum().item()

        val_loss /= val_total
        val_acc = val_correct / val_total

        # ════════════════════════════════════
        #           GHI LỊCH SỬ
        # ════════════════════════════════════
        history["train_loss"].append(train_loss)
        history["val_loss"].append(val_loss)
        history["train_acc"].append(train_acc)
        history["val_acc"].append(val_acc)

        current_lr = optimizer.param_groups[0]["lr"]
        print(
            f"{epoch + 1:5d} │ {train_loss:10.4f} │ {val_loss:10.4f} │ "
            f"{train_acc:8.4f}  │ {val_acc:8.4f}  │ {current_lr:.2e}"
        )

        # Update learning rate scheduler
        scheduler.step(val_loss)

        # ════════════════════════════════════
        #          EARLY STOPPING
        # ════════════════════════════════════
        # Nếu val_loss giảm → lưu best model, reset counter
        # Nếu val_loss không giảm → tăng counter
        # Khi counter == patience → DỪNG (model bắt đầu overfitting)

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            patience_counter = 0

            # Lưu best model checkpoint
            torch.save(
                {
                    "model_state_dict": model.state_dict(),
                    "optimizer_state_dict": optimizer.state_dict(),
                    "epoch": epoch,
                    "val_loss": val_loss,
                    "val_acc": val_acc,
                    "input_size": input_size,
                    "num_classes": NUM_CLASSES,
                    "params": params,
                    "history": history,
                },
                DL_MODEL_PATH,
            )
        else:
            patience_counter += 1
            if patience_counter >= params["patience"]:
                print(f"\n⏹️  Early Stopping tại epoch {epoch + 1}!")
                print(f"   Val loss không cải thiện trong {params['patience']} epochs liên tiếp.")
                break

    # ── KẾT QUẢ ──
    training_time = time.time() - start_time
    best_val_acc = max(history["val_acc"])

    print(f"\n{'═' * 50}")
    print(f"✅ TRAINING HOÀN TẤT!")
    print(f"{'═' * 50}")
    print(f"  ⏱️  Thời gian: {training_time:.1f}s ({training_time / 60:.1f} phút)")
    print(f"  📊 Best Val Loss: {best_val_loss:.4f}")
    print(f"  📊 Best Val Accuracy: {best_val_acc:.4f} ({best_val_acc * 100:.2f}%)")
    print(f"  💾 Model lưu tại: {DL_MODEL_PATH}")

    # Load best model (vì model cuối cùng có thể không phải best)
    checkpoint = torch.load(DL_MODEL_PATH, map_location=device, weights_only=False)
    model.load_state_dict(checkpoint["model_state_dict"])

    # Cập nhật history đầy đủ vào checkpoint
    checkpoint["history"] = history
    torch.save(checkpoint, DL_MODEL_PATH)

    return model, history, training_time

