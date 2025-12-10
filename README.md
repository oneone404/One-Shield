# AI Security - Anomaly Detection System

<div align="center">

![Version](https://img.shields.io/badge/version-0.5.1-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)
![Tauri](https://img.shields.io/badge/Tauri-2.0-orange.svg)
![React](https://img.shields.io/badge/React-18-61dafb.svg)
![Rust](https://img.shields.io/badge/Rust-1.70+-brown.svg)

**Ứng dụng giám sát hệ thống và phát hiện bất thường sử dụng AI/ML**

</div>

---

## 📖 Tổng Quan

**AI Security** là một ứng dụng desktop được xây dựng trên nền tảng **Tauri 2.0**, kết hợp sức mạnh của **Rust** (backend) và **React** (frontend). Ứng dụng giám sát hoạt động hệ thống theo thời gian thực, phân tích hành vi và phát hiện các hoạt động bất thường sử dụng mô hình AI (ONNX Runtime).

### ✨ Tính Năng Chính

- 🖥️ **Giám sát hệ thống real-time**: CPU, RAM, GPU, Disk, Network, Processes
- 🤖 **AI-powered Anomaly Detection**: ONNX model với 15 features
- 🛡️ **Action Guard**: Hệ thống phê duyệt hành động nguy hiểm
- 📊 **Dashboard trực quan**: Glassmorphism design với performance chart
- 🌓 **Dark/Light Theme**: Hỗ trợ chế độ sáng/tối
- 🔔 **Event-driven Notifications**: Real-time alerts (~10ms latency)
- 📈 **Baseline Learning**: Tự động học hành vi bình thường
- 🎮 **GPU Monitoring**: NVIDIA GPU metrics (temp, power, VRAM, fan)

---

## 🏗️ Kiến Trúc Dự Án

```
PS/
├── assets/                         # Tài nguyên tĩnh
│   ├── core-service/               # ONNX Runtime files
│   ├── data/                       # Models & training data
│   └── scripts/                    # Python AI scripts
│
├── core-service/                   # Backend Rust (Tauri)
│   ├── src/
│   │   ├── main.rs                 # Entry point
│   │   ├── api/
│   │   │   ├── mod.rs              # API module
│   │   │   ├── commands.rs         # Tauri commands (~870 lines)
│   │   │   └── v1/                 # API versioning
│   │   │       └── mod.rs          # v1 re-exports
│   │   └── logic/
│   │       ├── collector.rs        # Process data collector
│   │       ├── baseline.rs         # Baseline learning engine
│   │       ├── guard.rs            # Model protection
│   │       ├── ai_bridge.rs        # ONNX inference bridge
│   │       ├── action_guard.rs     # Action approval system
│   │       ├── events.rs           # Event emitter (NEW)
│   │       ├── features/           # Feature extraction
│   │       │   ├── cpu.rs
│   │       │   ├── memory.rs
│   │       │   ├── network.rs
│   │       │   ├── disk.rs
│   │       │   ├── process.rs
│   │       │   ├── gpu.rs
│   │       │   └── vector.rs
│   │       └── model/              # AI/ML modules
│   │           ├── inference.rs    # ONNX prediction
│   │           ├── buffer.rs       # Sequence buffer
│   │           └── threshold.rs    # Dynamic thresholds
│   ├── capabilities/               # Tauri permissions
│   └── Cargo.toml
│
└── web-app/                        # Frontend React
    ├── src/
    │   ├── main.jsx                # Entry point
    │   ├── App.jsx                 # Root component
    │   ├── components/             # UI Components
    │   │   ├── index.js            # Exports
    │   │   ├── Header.jsx
    │   │   ├── Sidebar.jsx
    │   │   ├── TitleBar.jsx
    │   │   ├── ApprovalModal.jsx
    │   │   ├── CpuCard.jsx
    │   │   ├── MemoryCard.jsx
    │   │   ├── ProcessesCard.jsx
    │   │   ├── NetworkCard.jsx
    │   │   ├── GpuCard.jsx
    │   │   ├── AiStatusCard.jsx
    │   │   └── UsageChart.jsx
    │   ├── pages/
    │   │   └── Dashboard.jsx
    │   ├── hooks/
    │   │   └── useActionGuard.js   # Event-driven hook
    │   ├── services/
    │   │   └── tauriApi.js         # API client
    │   └── styles/
    │       ├── index.css           # Variables & base
    │       ├── components/         # Component styles
    │       └── pages/              # Page styles
    └── package.json
```

---

## 🚀 Quick Start

### Prerequisites

- **Rust** 1.70+
- **Node.js** 18+
- **pnpm** (recommended) or npm

### Installation

```bash
# Clone repository
git clone <repo-url>
cd PS

# Install frontend dependencies
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

## 🔧 Technical Stack

### Backend (Rust)
- **Tauri 2.0** - Desktop framework
- **ONNX Runtime** - AI inference
- **sysinfo** - System metrics
- **parking_lot** - Fast synchronization

### Frontend (React)
- **React 18** - UI framework
- **Vite** - Build tool
- **Lucide Icons** - Icon library
- **CSS Variables** - Theming

---

## 📊 Features Detail

### 15-Feature Vector
```
[cpu_percent, memory_percent, network_sent_rate, network_recv_rate,
 cpu_spike_rate, memory_spike_rate, disk_read_rate, disk_write_rate,
 unique_processes, network_ratio, cpu_memory_product, spike_correlation,
 new_process_rate, combined_io, process_churn_rate]
```

### Event-driven Architecture (v0.5.1)
- **Rust emits events** khi có pending action mới
- **Frontend listens** qua `@tauri-apps/api/event`
- **Fallback polling** 5s (reduced from 1s)
- **CPU savings** ~80%

### GPU Monitoring
- NVIDIA GPU via `nvidia-smi`
- Metrics: Usage, VRAM, Temperature, Power, Fan Speed
- Auto-fallback when GPU unavailable

---

## 🛡️ Action Guard Flow

```
AI Detect Anomaly (score > 0.95)
        ↓
Create Pending Action
        ↓
Emit Event → UI receives instantly
        ↓
User Approve/Deny
        ↓
Execute Action (Kill/Suspend/Block)
```

---

## 📝 Changelog

### v0.5.1 (Current)
- ✅ Event-driven notifications
- ✅ Modular component architecture
- ✅ Cleaned up CSS structure
- ✅ API versioning ready
- ✅ Usage chart with 60s history
- ✅ GPU fan speed monitoring

### v0.5.0
- ✅ GPU monitoring (NVIDIA)
- ✅ AI Status card
- ✅ Modular features architecture
- ✅ Performance optimizations

### v0.4.0
- ✅ ONNX native inference
- ✅ Action Guard system
- ✅ 15-feature vector

---

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

---

<div align="center">
<b>Built with ❤️ using Tauri, Rust & React</b>
</div>
