# AI Training Utilities

Module này chứa các công cụ Python để retrain model phát hiện bất thường từ dữ liệu log của hệ thống (Dataset Logs).

## Yêu cầu
- Python 3.9 trở lên
- Các thư viện trong `requirements.txt`

## Cài đặt

```bash
pip install -r requirements.txt
```

## Hướng dẫn Training

1. **Export Dataset**:
   Trên ứng dụng, vào Dashboard -> Dataset Inspector -> Click "Export Dataset".
   Bạn sẽ nhận được file `.jsonl` chứa lịch sử hành vi và nhãn (nếu có).

2. **Chạy script training**:

```bash
# Windows
python train.py --input "C:\Users\username\Downloads\dataset.jsonl" --out "new-model.onnx"

# Linux/Mac
python3 train.py --input ~/Downloads/dataset.jsonl --out new-model.onnx
```

**Các tham số:**
- `--input`: Đường dẫn đến file dataset đầu vào (Bắt buộc).
- `--out`: Đường dẫn lưu file model ONNX đầu ra (Bắt buộc).
- `--features`: Số lượng feature đầu vào (Mặc định: 15).

## Deploy Model Mới
Sau khi có file `.onnx`, bạn có thể cập nhật model cho ứng dụng bằng cách thay thế file model hiện tại (thường là `core.sys` hoặc cấu hình trong settings).
