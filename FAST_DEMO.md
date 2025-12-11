# ⚡ One-Shield: 1-Minute Fast Demo

Dành cho Senior Demo: Clone, Build & Attack trong 60 giây.

## 1. Setup (Clean Slate)
```powershell
git clone https://github.com/oneone404/One-Shield.git OneShield-Demo
cd OneShield-Demo
git checkout stable/v1.0
npm install
```

## 2. Launch (Terminal 1)
```powershell
npm run tauri dev
```
*Chờ App lên. Check Status: "Active" & "System Secure".*

## 3. Attack Simulation (Terminal 2)
Giả lập cuộc tấn công "Process Storm" ngay lập tức.
```powershell
.\manual_tests\test_process_storm.bat
```

## 4. Verify (Trên Dashboard)
- **Incident**: 1 Alert (Suspicious/Malicious)
- **Timeline**: Xuất hiện các thẻ `HIGHCHURNRATE`, `PROCESSSPIKE`.
- **Explain**: Bấm vào incident xem lý do "Why detected?".

## 5. Cleanup
Sử dụng script restore để trả về trạng thái sạch:
```powershell
.\manual_tests\restore_model.bat
```

> **Note**: Branch `stable/v1.0` là bản release ổn định nhất. Không dùng branch `main` nếu đang dev dở dang.
