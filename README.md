# 🛡️ One-Shield - AI-Powered Endpoint Detection & Response (EDR)

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.2.0-blue" alt="Version">
  <img src="https://img.shields.io/badge/Platform-Windows-lightgrey" alt="Platform">
  <img src="https://img.shields.io/badge/AI-ONNX%20Runtime-green" alt="AI">
  <img src="https://img.shields.io/badge/UI-React%20%2B%20Tauri-purple" alt="UI">
  <img src="https://img.shields.io/badge/Enterprise-Ready-orange" alt="Enterprise">
  <img src="https://img.shields.io/badge/Tests-131%20Passed-brightgreen" alt="Tests">
</p>

**One-Shield** là một giải pháp bảo mật Endpoint thông minh, kết hợp Machine Learning với Behavioral Analysis để phát hiện và phản ứng với các mối đe dọa trong thời gian thực.

> 🎯 **Mục tiêu**: Xây dựng EDR Agent từ số 0, có khả năng tự học hành vi hệ thống và phát hiện bất thường mà không cần signature database.

---

## � Mục Lục

- [Tính Năng v1.0](#-tính-năng-v10)
- [Kiến Trúc Hệ Thống](#-kiến-trúc-hệ-thống)
- [Cấu Trúc Thư Mục](#-cấu-trúc-thư-mục)
- [Chi Tiết Từng Module](#-chi-tiết-từng-module)
- [Cài Đặt & Chạy](#-cài-đặt--chạy)
- [Test & Demo](#-test--demo)
- [Roadmap](#-roadmap---kế-hoạch-phát-triển) | [Chi tiết kỹ thuật](./ROADMAP_DETAIL.md)

---

## ✅ Tính Năng v2.0

### 🔍 Detection Engine (Phát hiện)
| Tính năng | Mô tả | Trạng thái |
|-----------|-------|------------|
| **Real-time Monitoring** | Thu thập 15 chỉ số hệ thống mỗi 2 giây | ✅ Hoàn thành |
| **Baseline Learning** | Tự học "thói quen bình thường" của máy tính | ✅ Hoàn thành |
| **Anomaly Detection** | Phát hiện hành vi lệch so với baseline | ✅ Hoàn thành |
| **Heuristic Rules** | Luật cứng phát hiện tấn công (Process Storm, Network Spike) | ✅ Hoàn thành |
| **AI Inference (ONNX)** | Sử dụng model ONNX pre-trained để chấm điểm | ✅ Hoàn thành |
| **Fallback Mode** | Tự động chuyển sang Heuristic nếu AI lỗi | ✅ Hoàn thành |

### 📊 Dashboard & UI
| Tính năng | Mô tả | Trạng thái |
|-----------|-------|------------|
| **Glassmorphism UI** | Giao diện hiện đại, premium với hiệu ứng kính mờ | ✅ Hoàn thành |
| **AI Engine Status** | Hiển thị trạng thái Model, Baseline, Dataset | ✅ Hoàn thành |
| **Security Incidents Panel** | Danh sách các sự cố bảo mật real-time | ✅ Hoàn thành |
| **Incident Timeline** | Chi tiết timeline của từng sự cố | ✅ Hoàn thành |
| **Explainability (Why Detected?)** | Giải thích tại sao hệ thống phát hiện anomaly | ✅ Hoàn thành |
| **System Stats Cards** | CPU, RAM, Network, GPU metrics | ✅ Hoàn thành |
| **Performance Chart** | Biểu đồ 60s realtime | ✅ Hoàn thành |

### 🛡️ Safety & Resilience
| Tính năng | Mô tả | Trạng thái |
|-----------|-------|------------|
| **Kill-Switch AI** | Có thể tắt AI inference khi cần | ✅ Hoàn thành |
| **Kill-Switch Auto-Block** | Vô hiệu hóa tự động chặn | ✅ Hoàn thành |
| **Model Failover** | Không crash khi model bị hỏng/thiếu | ✅ Hoàn thành |
| **Panic-Free Code** | Xử lý graceful mọi lỗi runtime | ✅ Hoàn thành |
| **Baseline Persistence** | Lưu baseline ra đĩa, không mất khi restart | ✅ Hoàn thành |

### 📦 Data & Training
| Tính năng | Mô tả | Trạng thái |
|-----------|-------|------------|
| **Dataset Logging** | Ghi mọi sample vào file .jsonl | ✅ Hoàn thành |
| **Feature Versioning** | Quản lý version của feature layout | ✅ Hoàn thành |
| **Export Dataset** | Xuất dataset để train offline | ✅ Hoàn thành |
| **Anti-Poisoning (Basic)** | Không học mẫu có score > 0.5 | ✅ Hoàn thành |

### 🛡️ Anti-Poisoning v1.1 (NEW!)
| Tính năng | Mô tả | Trạng thái |
|-----------|-------|------------|
| **Quarantine Queue** | Hàng đợi xét duyệt sample trước khi học | ✅ Hoàn thành |
| **Delayed Learning** | Sample phải clean 6h liên tục mới được học | ✅ Hoàn thành |
| **Multi-Feature Voting** | 6 nhóm features phải sạch mới học | ✅ Hoàn thành |
| **Drift Monitoring** | Phát hiện baseline shift bất thường | ✅ Hoàn thành |
| **Baseline Snapshots** | Lưu checkpoints để rollback | ✅ Hoàn thành |
| **Audit Log** | Ghi lại mọi thay đổi baseline | ✅ Hoàn thành |

### 🔍 Process Intelligence v1.0 (NEW!)
| Tính năng | Mô tả | Trạng thái |
|-----------|-------|------------|
| **Signature Verification** | Kiểm tra chữ ký Authenticode | ✅ Hoàn thành |
| **Process Tree Analysis** | Phân tích parent-child relationships | ✅ Hoàn thành |
| **LOLBin Detection** | Database 20+ LOLBins với MITRE ATT&CK mapping | ✅ Hoàn thành |
| **Suspicious Spawn Detection** | Phát hiện spawn patterns đáng ngờ | ✅ Hoàn thành |
| **Process Reputation** | Điểm tin cậy dựa trên lịch sử behavior | ✅ Hoàn thành |
| **Trusted Publisher Whitelist** | Whitelist Microsoft, Google, Adobe... | ✅ Hoàn thành |

### 🎯 Behavioral Signatures v1.0 (NEW!)
| Tính năng | Mô tả | Trạng thái |
|-----------|-------|------------|
| **C2 Beaconing Detection** | Phát hiện kết nối định kỳ (low jitter) | ✅ Hoàn thành |
| **Registry Persistence Monitor** | Theo dõi Run keys, Services, Tasks | ✅ Hoàn thành |
| **Never-Learn Blacklist** | Block mimikatz, Tor, known C2 | ✅ Hoàn thành |
| **Behavioral Rules Engine** | 6 built-in rules + custom rules | ✅ Hoàn thành |
| **MITRE ATT&CK Mapping** | All rules mapped to MITRE techniques | ✅ Hoàn thành |

### 🌐 External Intelligence v1.0 (NEW!)
| Tính năng | Mô tả | Trạng thái |
|-----------|-------|------------|
| **VirusTotal Integration** | Check file hash với rate limiting & cache | ✅ Hoàn thành |
| **Threat Feed Sync** | URLhaus, Emerging Threats, Feodo Tracker | ✅ Hoàn thành |
| **MITRE ATT&CK Database** | 30+ techniques với mapping tự động | ✅ Hoàn thành |
| **IOC Matching** | IP, Domain, Hash, URL matching | ✅ Hoàn thành |

### ⚡ Response & Automation v1.0 (NEW!)
| Tính năng | Mô tả | Trạng thái |
|-----------|-------|------------|
| **Process Actions** | Suspend, Resume, Kill processes | ✅ Hoàn thành |
| **Network Isolation** | Block/Unblock via Windows Firewall | ✅ Hoàn thành |
| **File Quarantine** | Secure quarantine với SHA256, restore | ✅ Hoàn thành |
| **Webhook Alerts** | Slack, Discord, Teams, Telegram | ✅ Hoàn thành |
| **Auto-Response Config** | Configurable automated responses | ✅ Hoàn thành |

### 🏢 Enterprise Features v2.0 (NEW!)
| Tính năng | Mô tả | Trạng thái |
|-----------|-------|------------|
| **RBAC** | User roles (Admin, Analyst, Viewer) | ✅ Hoàn thành |
| **Session Management** | Token-based auth, auto-expiry | ✅ Hoàn thành |
| **Agent Management** | Central registration, heartbeat | ✅ Hoàn thành |
| **Policy Sync** | Remote policy distribution | ✅ Hoàn thành |
| **Executive Reports** | Security score, threat overview | ✅ Hoàn thành |
| **REST API** | 20+ endpoints với auth | ✅ Hoàn thành |

### 🔬 Advanced Detection v2.2 (NEW!)
| Tính năng | Mô tả | Trạng thái |
|-----------|-------|------------|
| **AMSI Script Scanning** | 70+ malicious patterns (Mimikatz, Empire, etc.) | ✅ Hoàn thành |
| **DLL Injection Detection** | 60+ patterns, MITRE ATT&CK mapping | ✅ Hoàn thành |
| **Memory Shellcode Scanning** | 18 patterns (MSF, Cobalt Strike, etc.) | ✅ Hoàn thành |
| **Suspicious Spawn Detection** | Office→CMD, Browser→Script patterns | ✅ Hoàn thành |
| **Encoded Command Detection** | Base64, -EncodedCommand detection | ✅ Hoàn thành |

---

## 🏗️ Kiến Trúc Hệ Thống

```
┌─────────────────────────────────────────────────────────────────┐
│                        ONE-SHIELD v2.0                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐ │
│  │  COLLECTOR  │───▶│  ANALYSIS   │───▶│  INCIDENT MANAGER   │ │
│  │  (2s loop)  │    │    LOOP     │    │  (Alert & Explain)  │ │
│  └─────────────┘    └──────┬──────┘    └─────────────────────┘ │
│         │                  │                      │             │
│         ▼                  ▼                      ▼             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐ │
│  │   SYSINFO   │    │  BASELINE   │    │     DASHBOARD       │ │
│  │  (metrics)  │    │  + AI/ONNX  │    │  (React + Tauri)    │ │
│  └─────────────┘    └─────────────┘    └─────────────────────┘ │
│                            │                                    │
│                            ▼                                    │
│                     ┌─────────────┐                             │
│                     │   DATASET   │                             │
│                     │  (.jsonl)   │                             │
│                     └─────────────┘                             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Data Flow (Luồng dữ liệu)
1. **Collector** thu thập metrics hệ thống mỗi 2 giây
2. **Analysis Loop** xử lý dữ liệu qua Baseline + AI
3. Nếu phát hiện anomaly → Tạo **Incident** + gửi lên Dashboard
4. Mọi sample đều được ghi vào **Dataset** để train sau

---

## 📁 Cấu Trúc Thư Mục

```
PS/
├── 📂 core-service/           # Backend Rust (Tauri)
│   ├── 📂 src/
│   │   ├── 📂 api/            # API endpoints cho Frontend
│   │   │   ├── commands.rs    # Tauri commands (IPC)
│   │   │   ├── engine_status.rs # AI Engine status structs
│   │   │   └── mod.rs
│   │   │
│   │   ├── 📂 logic/          # ⭐ CORE LOGIC (Não bộ)
│   │   │   ├── 📂 baseline/   # Baseline Learning System
│   │   │   │   ├── mod.rs     # Analysis engine, compare logic
│   │   │   │   ├── types.rs   # VersionedBaseline, AnomalyTag
│   │   │   │   └── storage.rs # Persistence (save/load JSON)
│   │   │   │
│   │   │   ├── 📂 dataset/    # Dataset Collection (P1.3)
│   │   │   │   ├── mod.rs     # Global logger, stats
│   │   │   │   ├── record.rs  # DatasetRecord struct
│   │   │   │   ├── writer.rs  # JSONL file writer
│   │   │   │   └── export.rs  # Export utilities
│   │   │   │
│   │   │   ├── 📂 features/   # Feature Extraction (P1.1)
│   │   │   │   ├── layout.rs  # ⭐ FEATURE_LAYOUT (15 features)
│   │   │   │   ├── vector.rs  # FeatureVector struct
│   │   │   │   ├── cpu.rs     # CPU feature extractor
│   │   │   │   ├── memory.rs  # Memory feature extractor
│   │   │   │   ├── network.rs # Network feature extractor
│   │   │   │   ├── disk.rs    # Disk I/O feature extractor
│   │   │   │   ├── process.rs # Process feature extractor
│   │   │   │   └── mod.rs
│   │   │   │
│   │   │   ├── 📂 model/      # AI Model Management
│   │   │   │   ├── inference.rs # ONNX Runtime integration
│   │   │   │   ├── threshold.rs # Dynamic thresholds
│   │   │   │   ├── buffer.rs  # Prediction buffer
│   │   │   │   └── mod.rs
│   │   │   │
│   │   │   ├── 📂 incident/   # Incident Management (P3.1)
│   │   │   │   ├── manager.rs # IncidentManager (in-memory)
│   │   │   │   ├── types.rs   # Incident, DatasetRecordSummary
│   │   │   │   └── mod.rs
│   │   │   │
│   │   │   ├── 📂 explain/    # Explainability Engine (P3.2)
│   │   │   │   ├── engine.rs  # Feature contribution analysis
│   │   │   │   └── mod.rs
│   │   │   │
│   │   │   ├── 📂 telemetry/  # Security Logging
│   │   │   │   └── mod.rs
│   │   │   │
│   │   │   ├── 📂 policy/     # Policy Engine (Action Decision)
│   │   │   │   └── mod.rs
│   │   │   │
│   │   │   ├── collector.rs   # ⭐ System Metrics Collector
│   │   │   ├── analysis_loop.rs # ⭐ Main Analysis Thread
│   │   │   ├── ai_bridge.rs   # AI Model bridge (prediction)
│   │   │   ├── action_guard.rs # Action Guard (Block/Alert)
│   │   │   ├── threat.rs      # ThreatClass enum
│   │   │   ├── config.rs      # SafetyConfig (Kill-switches)
│   │   │   ├── events.rs      # Tauri event emitter
│   │   │   └── mod.rs
│   │   │
│   │   └── main.rs            # ⭐ Entry point, Tauri setup
│   │
│   ├── Cargo.toml             # Rust dependencies
│   └── tauri.conf.json        # Tauri configuration
│
├── 📂 web-app/                # Frontend React
│   ├── 📂 src/
│   │   ├── 📂 components/     # UI Components
│   │   │   ├── TitleBar.jsx   # Custom window title bar
│   │   │   ├── Header.jsx     # Dashboard header
│   │   │   ├── Sidebar.jsx    # Navigation sidebar
│   │   │   ├── AiEngineStatus.jsx # AI status panel
│   │   │   ├── IncidentPanel.jsx  # Security incidents
│   │   │   ├── ApprovalModal.jsx  # Action approval modal
│   │   │   ├── UsageChart.jsx # Performance chart
│   │   │   ├── 📂 cards/      # Stat cards (CPU, RAM, GPU...)
│   │   │   │   ├── CpuCard.jsx
│   │   │   │   ├── MemoryCard.jsx
│   │   │   │   ├── NetworkCard.jsx
│   │   │   │   ├── ProcessesCard.jsx
│   │   │   │   ├── GpuCard.jsx
│   │   │   │   ├── AiStatusCard.jsx
│   │   │   │   └── index.js
│   │   │   └── index.js
│   │   │
│   │   ├── � pages/
│   │   │   └── Dashboard.jsx  # Main dashboard page
│   │   │
│   │   ├── 📂 services/
│   │   │   └── tauriApi.js    # Tauri IPC wrapper
│   │   │
│   │   ├── 📂 hooks/
│   │   │   └── useActionGuard.js # Action Guard hook
│   │   │
│   │   ├── 📂 styles/         # CSS Styles
│   │   │   ├── 📂 components/ # Component-specific CSS
│   │   │   │   ├── titlebar.css
│   │   │   │   ├── header.css
│   │   │   │   ├── sidebar.css
│   │   │   │   ├── ai-engine-status.css
│   │   │   │   ├── incident-panel.css
│   │   │   │   ├── buttons.css
│   │   │   │   ├── modal.css
│   │   │   │   └── dashboard.css
│   │   │   ├── � pages/
│   │   │   │   └── dashboard.css
│   │   │   ├── index.css      # Global styles + Design tokens
│   │   │   └── layout.css     # Layout utilities
│   │   │
│   │   ├── App.jsx            # Root component
│   │   ├── App.css
│   │   └── main.jsx           # React entry
│   │
│   ├── index.html
│   ├── package.json
│   └── vite.config.js
│
├── 📂 ai-trainer/             # Python AI Training
│   ├── train.py               # Model training script
│   ├── convert_to_onnx.py     # Convert to ONNX format
│   └── requirements.txt
│
├── 📂 models/                 # AI Model Files
│   ├── core.sys               # Encrypted Global Model (ONNX)
│   └── profile.sys            # Encrypted Profile Model
│
├── 📂 manual_tests/           # Test Scripts
│   ├── test_process_storm.bat # Process Storm attack simulation
│   ├── test_model_failover.bat # AI failover test
│   └── restore_model.bat      # Restore after tests
│
├── 📄 README.md               # This file
├── 📄 CHANGELOG-v1.0.md       # Version changelog
├── 📄 DEMO_SCRIPT.md          # 5-minute demo script
├── 📄 FAST_DEMO.md            # 1-minute quick demo
└── 📄 package.json            # Root package.json
```

---

## 📦 Chi Tiết Từng Module

### 🔵 Core Service (Rust Backend)

#### `logic/collector.rs`
**Mục đích**: Thu thập metrics hệ thống real-time.
- Sử dụng `sysinfo` crate để lấy CPU, RAM, Disk, Network, Process list.
- Interval: 2 giây.
- Output: `SummaryVector` với 15 features.

#### `logic/analysis_loop.rs`
**Mục đích**: Xử lý trung tâm, kết nối Collector → Baseline → Incident.
- Chạy trong thread riêng.
- Lấy pending summaries từ Collector.
- Gọi `baseline::analyze_summary()` để phân tích.
- Gọi `incident::process_event()` nếu phát hiện anomaly.
- Gọi `dataset::log()` để lưu mọi sample.

#### `logic/baseline/mod.rs`
**Mục đích**: Baseline Learning + Anomaly Detection.
- **Learning Mode**: Thu thập samples để tính mean/variance.
- **Stable Mode**: So sánh current features với baseline.
- **Heuristic Fallback**: Hard rules khi baseline chưa sẵn sàng.
- Chống nhiễm độc: Không học mẫu có score ≥ 0.5.

#### `logic/features/layout.rs`
**Mục đích**: Định nghĩa Feature Schema (Single Source of Truth).
```rust
pub const FEATURE_LAYOUT: &[&str] = &[
    "cpu_percent",           // 0
    "cpu_spike_rate",        // 1
    "memory_percent",        // 2
    "memory_spike_rate",     // 3
    "network_sent_rate",     // 4
    "network_recv_rate",     // 5
    "network_ratio",         // 6
    "disk_read_rate",        // 7
    "disk_write_rate",       // 8
    "combined_io",           // 9
    "unique_processes",      // 10
    "new_process_rate",      // 11
    "process_churn_rate",    // 12
    "cpu_memory_product",    // 13
    "spike_correlation",     // 14
];
```

#### `logic/incident/manager.rs`
**Mục đích**: Quản lý Incident lifecycle.
- Tạo Incident mới khi phát hiện anomaly.
- Gom nhóm events trong 60s window.
- Gọi Explainability Engine để giải thích.

#### `logic/explain/engine.rs`
**Mục đích**: Trả lời câu hỏi "Tại sao phát hiện?".
- Tính contribution của từng feature.
- Map sang human-readable description.
- Output: Top 5 features đóng góp nhiều nhất.

#### `logic/config.rs`
**Mục đích**: Kill-switches cho safety.
- `AI_ENABLED`: Bật/tắt AI inference.
- `EXPLAIN_ENABLED`: Bật/tắt explainability.
- `AUTO_BLOCK_ENABLED`: Bật/tắt auto-blocking (v1.0 = false).

### 🟣 Web App (React Frontend)

#### `components/AiEngineStatus.jsx`
**Mục đích**: Panel hiển thị trạng thái AI Engine.
- Model status (Active/Fallback).
- Baseline mode (Learning/Stable).
- Dataset statistics (Records count, breakdown).

#### `components/IncidentPanel.jsx`
**Mục đích**: Danh sách Security Incidents.
- Real-time polling (5s).
- Timeline view với severity badges.
- Explainability section ("Why was this detected?").

#### `services/tauriApi.js`
**Mục đích**: Wrapper cho Tauri IPC.
- `getSystemStatus()`, `getAiStatus()`.
- `startCollector()`, `stopCollector()`.
- `getIncidents()`, `getIncidentDetail()`.

---

## 🔧 Cài Đặt & Chạy

### Yêu cầu
- **Node.js** >= 18
- **Rust** >= 1.70
- **Windows 10/11**

### Development
```bash
# Clone repository
git clone https://github.com/oneone404/One-Shield.git
cd One-Shield

# Install dependencies
npm install

# Run in development mode
npm run tauri dev
```

### Production Build
```bash
npm run tauri build
```
Output: `core-service/target/release/one-shield.exe`

---

## 🧪 Test & Demo

### Quick Demo (1 phút)
Xem file [FAST_DEMO.md](./FAST_DEMO.md).

### Manual Tests

**Test 1: Process Storm Attack**
```powershell
.\manual_tests\test_process_storm.bat
```
Expected: Dashboard hiện Incident với tags `PROCESSSPIKE`, `HIGHCHURNRATE`.

**Test 2: Model Failover**
```powershell
.\manual_tests\test_model_failover.bat
# Restart app
# Observe: AI Engine shows "Fallback Mode"
```

**Restore**
```powershell
.\manual_tests\restore_model.bat
```

---

## 🚀 Roadmap - Kế Hoạch Phát Triển

> ⚠️ **Vấn đề cần giải quyết**: Hệ thống v1.0 có thể bị "nhiễm độc" (Baseline Poisoning) nếu malware hoạt động ẩn trong thời gian dài với cường độ thấp. Các phase dưới đây được thiết kế để giải quyết vấn đề này.

---

### 📅 Phase 1: Anti-Poisoning & Baseline Hardening (v1.1)
> *Mục tiêu: Chống nhiễm độc baseline từ APT/Stealth malware*

| Tính năng | Mô tả | Effort |
|-----------|-------|--------|
| **Delayed Baseline Learning** | Sample phải "clean" liên tục trong X giờ mới được học | 🔴 High |
| **Quarantine Queue** | Hàng đợi xét duyệt sample trước khi học vào baseline | 🔴 High |
| **Learning Rate Limiter** | Giới hạn baseline drift/shift bất thường | 🟡 Medium |
| **Multi-Feature Voting** | Tất cả 6 nhóm features phải sạch mới học | 🟡 Medium |
| **Baseline Snapshot & Rollback** | Lưu checkpoint, rollback nếu phát hiện poisoning | � Medium |

---

### 📅 Phase 2: Process Intelligence (v1.2)
> *Mục tiêu: Deep analysis cho process behaviors*

| Tính năng | Mô tả | Effort |
|-----------|-------|--------|
| **Signed App Whitelist** | Chỉ trust app có chữ ký số hợp lệ (Microsoft, etc.) | 🔴 High |
| **Process Tree Analysis** | Phân tích Parent-Child relationship | 🔴 High |
| **Suspicious Spawn Detection** | Phát hiện cmd.exe spawn từ Office, notepad, etc. | 🔴 High |
| **Process Reputation Score** | Điểm tin cậy dựa trên lịch sử behavior | 🟡 Medium |

---

### 📅 Phase 3: Behavioral Signatures (v1.3)
> *Mục tiêu: Hardcoded rules cho các hành vi KHÔNG BAO GIỜ chấp nhận*

| Tính năng | Mô tả | Effort |
|-----------|-------|--------|
| **Keylogger Pattern Detection** | Phát hiện keyboard hook bất thường | 🔴 High |
| **Registry Persistence Monitor** | Cảnh báo ghi vào Run keys, Services | 🔴 High |
| **Network Beaconing Detection** | Phát hiện kết nối định kỳ (C2 communication) | 🔴 High |
| **DLL Injection Detection** | Phát hiện inject vào process khác | 🟡 Medium |
| **Never-Learn Blacklist** | Một số pattern KHÔNG BAO GIỜ được học | 🟡 Medium |

---

### 📅 Phase 4: External Intelligence (v1.4)
> *Mục tiêu: Kết nối threat intelligence bên ngoài*

| Tính năng | Mô tả | Effort |
|-----------|-------|--------|
| **VirusTotal Integration** | Check hash file với VT database | 🔴 High |
| **Cloud Threat Feed** | Sync known-bad indicators từ cloud | 🟡 Medium |
| **Community Baseline Sharing** | Chia sẻ baseline profile giữa các máy | 🟢 Low |
| **MITRE ATT&CK Mapping** | Map incidents với MITRE framework | 🟢 Low |

---

### 📅 Phase 5: Response & Automation (v1.5)
> *Mục tiêu: Tự động phản ứng với threats*

| Tính năng | Mô tả | Effort |
|-----------|-------|--------|
| **Auto-Block Execution** | Tự động kill/suspend process nguy hiểm | � High |
| **Network Quarantine** | Block network cho process suspicious | 🔴 High |
| **SQLite Incident Database** | Lưu incidents persistent | 🟡 Medium |
| **Alert Integration (Webhook)** | Gửi alert qua Slack/Discord/Email | �🟡 Medium |
| **Forensic Export** | Xuất timeline đầy đủ để phân tích | 🟢 Low |

---

### 📅 Phase 6: Enterprise Features (v2.0)
> *Mục tiêu: Scale cho doanh nghiệp*

| Tính năng | Mô tả | Effort |
|-----------|-------|--------|
| **Central Management Console** | Quản lý nhiều endpoint | ✅ Done |
| **Cloud Sync** | Đồng bộ model/baseline lên cloud | 🔴 High |
| **Role-Based Access Control** | Phân quyền admin/viewer | ✅ Done |
| **Compliance Reporting** | Báo cáo tuân thủ ISO/SOC2 | � Low |

---

## 🚀 Roadmap v3.0 - Next Generation

> Tất cả 6 phases của v1.0-v2.0 đã hoàn thành! Dưới đây là kế hoạch cho v3.0.

---

### 📅 Phase 7: UI Integration (v2.1) ✅ COMPLETE
> *Mục tiêu: Tích hợp Enterprise Features vào UI*

| Tính năng | Mô tả | Trạng thái |
|-----------|-------|------------|
| **Tauri Commands** | 24 enterprise APIs qua IPC | ✅ Done |
| **Executive Dashboard** | Security Score, Metrics, Recommendations | ✅ Done |
| **Settings Page** | Quarantine & Webhook configuration | ✅ Done |
| **Quarantine UI** | List, restore, delete quarantined files | ✅ Done |
| **Webhook Configuration** | Add, test, remove webhook alerts | ✅ Done |

---

### 📅 Phase 8: Advanced Detection (v2.2) ✅ COMPLETE
> *Mục tiêu: Nâng cao khả năng phát hiện*

| Tính năng | Mô tả | Status |
|-----------|-------|--------|
| **AMSI Script Scanning** | Heuristic patterns for malicious scripts | ✅ Done |
| **DLL Injection Detection** | Detect RemoteThread, APC, Hollowing | ✅ Done |
| **Memory Scanning** | Scan for shellcode patterns (MSF, CS) | ✅ Done |
| **Keylogger API Hooking** | Detect GetAsyncKeyState abuse | � v2.3 |
| **ETW Tracing** | Event Tracing for Windows | � v2.3 |

---

### 📅 Phase 9: Cloud & Sync (v2.3)
> *Mục tiêu: Cloud-based management*

| Tính năng | Mô tả | Effort |
|-----------|-------|--------|
| **Cloud Backend** | Central server (PostgreSQL + API) | 🔴 High |
| **Agent-Server Protocol** | Secure communication | 🔴 High |
| **Baseline Sync** | Share baselines across endpoints | 🟡 Medium |
| **Model Updates** | Push model updates from cloud | 🟡 Medium |
| **Multi-Tenant** | Support multiple organizations | 🔴 High |

---

### 📅 Phase 10: Compliance & Reporting (v3.0)
> *Mục tiêu: Enterprise compliance*

| Tính năng | Mô tả | Effort |
|-----------|-------|--------|
| **ISO 27001 Reports** | Compliance reporting | 🟡 Medium |
| **SOC2 Audit Trail** | Complete audit logging | 🟡 Medium |
| **GDPR Data Handling** | Data privacy controls | � Medium |
| **Custom Report Builder** | Build custom reports | �🟢 Low |
| **Scheduled Reports** | Auto-generate & email | 🟢 Low |

---

### 📊 V2.1 Completion Summary

| Phase | Version | Status | LOC |
|-------|---------|--------|-----|
| Phase 1: Anti-Poisoning | v1.1 | ✅ Complete | ~1,200 |
| Phase 2: Process Intelligence | v1.2 | ✅ Complete | ~2,000 |
| Phase 3: Behavioral Signatures | v1.3 | ✅ Complete | ~2,100 |
| Phase 4: External Intelligence | v1.4 | ✅ Complete | ~1,450 |
| Phase 5: Response & Automation | v1.5 | ✅ Complete | ~1,785 |
| Phase 6: Enterprise Features | v2.0 | ✅ Complete | ~2,500 |
| Phase 7: UI Integration | v2.1 | ✅ Complete | ~1,500 |
| **Total** | **v2.1** | **✅ 100%** | **~12,535** |

---

## � License

MIT License - See [LICENSE](./LICENSE) file.

---

## 👨‍💻 Author

**oneone404** - [GitHub](https://github.com/oneone404)

---

<p align="center">
  <b>One-Shield v2.1.0</b> - Enterprise-Grade EDR Built with ❤️ and AI
</p>
