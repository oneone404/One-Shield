# AI Security – Anomaly Detection System

<div align="center">

![Version](https://img.shields.io/badge/version-0.6.1-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)
![Tauri](https://img.shields.io/badge/Tauri-2.0-orange.svg)
![React](https://img.shields.io/badge/React-18-61dafb.svg)
![Rust](https://img.shields.io/badge/Rust-1.70+-brown.svg)

**Ứng dụng desktop giám sát hệ thống & phát hiện bất thường theo kiến trúc EDR, tăng cường bằng AI/ML**

</div>

---

## 📖 Tổng Quan

**AI Security** là một ứng dụng desktop xây dựng trên **Tauri 2.0**, kết hợp **Rust (backend)** và **React (frontend)**. Ứng dụng giám sát hệ thống theo thời gian thực, trích xuất đặc trưng hành vi, so sánh baseline và **phát hiện bất thường theo pipeline EDR chuẩn**. AI (ONNX Runtime) đóng vai trò **chấm điểm & gợi ý**, trong khi quyết định cuối cùng được kiểm soát bởi **Threat Classification → Policy Engine → Action Guard**.

### ✨ Tính Năng Chính

* 🖥️ **Giám sát hệ thống real-time**: CPU, RAM, GPU, Disk, Network, Processes
* 🤖 **AI-powered Anomaly Detection**: ONNX model với 15 features
* 🛡️ **Action Guard**: Phê duyệt/auto-block hành động nguy hiểm
* 📊 **Dashboard trực quan**: Glassmorphism + performance charts
* 🌓 **Dark / Light Theme**
* 🔔 **Event-driven Notifications**: latency ~10ms
* 📈 **Baseline Learning**: Tự học hành vi bình thường
* 🎮 **GPU Monitoring**: NVIDIA GPU (temp, power, VRAM, fan)
* 🔒 **Confidence Guard**: Giảm false positives bằng kiểm tra độ tin cậy
* 📝 **Security Telemetry**: Audit trail, analytics, training data collection

---

## 🏗️ Kiến Trúc Dự Án

```
PS/
├── assets/
│   ├── core-service/               # ONNX Runtime files
│   ├── data/                       # Models & training data
│   └── scripts/                    # Python AI scripts
│
├── core-service/                   # Backend Rust (Tauri)
│   ├── src/
│   │   ├── main.rs                 # Entry point
│   │   ├── api/
│   │   │   ├── mod.rs
│   │   │   ├── commands.rs         # Tauri commands (~870 LOC)
│   │   │   └── v1/                 # API versioning
│   │   │       └── mod.rs
│   │   │
│   │   └── logic/
│   │       ├── collector.rs        # Process data collector
│   │       ├── baseline.rs         # Baseline learning engine
│   │       ├── guard.rs            # Model integrity & protection
│   │       ├── ai_bridge.rs        # ONNX inference bridge
│   │       ├── action_guard.rs     # Action approval/execution
│   │       ├── events.rs           # Event emitter
│   │       │
│   │       ├── threat/             # Threat Classification (v0.6)
│   │       │   ├── mod.rs
│   │       │   ├── types.rs        # ThreatClass, AnomalyScore, BaselineDiff
│   │       │   ├── context.rs      # ThreatContext (builder pattern)
│   │       │   ├── rules.rs        # Thresholds & constants
│   │       │   └── classifier.rs   # classify() + Confidence Guard
│   │       │
│   │       ├── policy/             # Policy Decision (v0.6)
│   │       │   ├── mod.rs
│   │       │   ├── types.rs        # Decision, Severity, ActionType
│   │       │   ├── config.rs       # PolicyConfig (strict / aggressive)
│   │       │   ├── engine.rs       # decide() logic
│   │       │   └── rules.rs        # Extensible rules (CryptoMining, Ransomware)
│   │       │
│   │       ├── features/           # Feature extraction
│   │       │   ├── cpu.rs
│   │       │   ├── memory.rs
│   │       │   ├── network.rs
│   │       │   ├── disk.rs
│   │       │   ├── process.rs
│   │       │   ├── gpu.rs
│   │       │   └── vector.rs
│   │       │
│   │       └── model/              # AI/ML modules
│   │           ├── inference.rs
│   │           ├── buffer.rs
│   │           └── threshold.rs
│   │
│   ├── capabilities/               # Tauri permissions
│   └── Cargo.toml
│
└── web-app/                        # Frontend React
    ├── src/
    │   ├── main.jsx
    │   ├── App.jsx
    │   ├── components/
    │   ├── pages/
    │   ├── hooks/
    │   ├── services/
    │   └── styles/
    └── package.json
```

---

## 🎯 EDR-style Pipeline (v0.6)

```
[ Collect ] → [ Feature ] → [ Baseline ] → [ AI Score ]
                                         │
                                         ▼
                               [ Threat Classification ]
                               Benign / Suspicious / Malicious
                                         │
                                         ▼
                               [ Policy Decision Engine ]
                               SilentLog / Notify /
                               RequireApproval / AutoBlock
                                         │
                                         ▼
                               [ Action Guard ] → UI / Execute
```

### Separation of Concerns

| Module         | Responsibility                                |
| -------------- | --------------------------------------------- |
| `threat/`      | Chuyển **AI score + context** → `ThreatClass` |
| `policy/`      | Chuyển `ThreatClass` → `Decision`             |
| `action_guard` | Thực thi hành động an toàn                    |
| `telemetry/`   | Audit trail & analytics                       |

---

## 🚀 Quick Start

### Prerequisites

* Rust **1.70+**
* Node.js **18+**
* pnpm (recommended) hoặc npm

### Installation

```bash
# Clone repository
git clone <repo-url>
cd PS

# Frontend
cd web-app
pnpm install

# Run development
cd ../core-service
cargo tauri dev
```

### Build Production

```bash
cargo tauri build
```

---

## 📊 Feature Vector (15)

```
[cpu_percent, memory_percent, network_sent_rate, network_recv_rate,
 cpu_spike_rate, memory_spike_rate, disk_read_rate, disk_write_rate,
 unique_processes, network_ratio, cpu_memory_product, spike_correlation,
 new_process_rate, combined_io, process_churn_rate]
```

---

## 🔒 Confidence Guard (v0.6)

Giảm **false positives** bằng cách yêu cầu **điều kiện kép**:

* **Malicious** chỉ khi: `score ≥ 0.8` **AND** `confidence ≥ 0.7`
* Score cao nhưng confidence thấp → **downgrade** xuống `Suspicious`

```rust
if score >= 0.8 && confidence >= 0.7 {
    ThreatClass::Malicious
} else if score >= 0.8 {
    ThreatClass::Suspicious
}
```

---

## 🛡️ Action Guard Flow

```
AI Score → ThreatClass → Policy Decision
        → Pending Action → Event Emit
        → UI Approval → Execute / Cancel
```

---

## 📝 Changelog

### v0.6.2 (Current)

* ✅ **Feature Versioning (P1.1)**: Centralized `layout.rs` & versioned `FeatureVector`
* ✅ **Safe Baseline (P1.2)**: `logic/baseline` refactored with version check
* ✅ **Dataset Logging (P1.3)**: Real-time AI training data collector with rotation & versioning
* ✅ **AI Dashboard (P2.1)**: Real-time UI for Engine/Baseline/Dataset status
* ✅ **Auto-Recovery**: Reset baseline on layout mismatch
* ✅ **Stability**: 120+ tests passed (Features + Baseline + Telemetry + Dataset)

### v0.6.1

* ✅ **Security Telemetry** module
  - SecurityEvent struct (14 event types)
  - Append-only JSONL recorder
  - Export: CSV, JSON, training data
  - Analytics: approval rate, override rate
* ✅ Telemetry API commands
* ✅ SecurityLogs UI component
* ✅ 55 unit tests

* ✅ **Security Telemetry** module
  - SecurityEvent struct (14 event types)
  - Append-only JSONL recorder
  - Export: CSV, JSON, training data
  - Analytics: approval rate, override rate
* ✅ Telemetry API commands
* ✅ SecurityLogs UI component
* ✅ 55 unit tests

### v0.6.0

* ✅ Modular `threat/` & `policy/`
* ✅ Confidence Guard
* ✅ Extensible security rules
* ✅ Clean EDR-style separation

### v0.5.x

* Event-driven notifications
* GPU monitoring (NVIDIA)
* Usage charts & performance tuning

---

## 📄 License

MIT License

---

<div align="center">
<b>Built with ❤️ using Tauri, Rust & React</b>
</div>
