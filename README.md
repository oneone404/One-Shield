# One-Shield: AI-Powered Endpoint Security (EDR)

> **Next-Gen Security Agent built with Rust & AI.**
> *Detects what traditional AVs miss through Behavioral Analysis.*

## 📖 The Story
Traditional antiviruses rely on signatures. If a malware changes one byte, it bypasses detection.
**One-Shield** is different. It doesn't care about signatures. It cares about **Behavior**.

- Is a process consuming 100% CPU suddenly? (Crypto-mining?)
- Is it uploading massive data to an unknown IP? (Exfiltration?)
- Is it encrypting disk files rapidly? (Ransomware?)

By baselining normal system behavior and using AI to detect deviations, One-Shield identifies threats in real-time.

## 🌟 Key Features (v1.0)
- **🔍 AI Anomaly Detection**: Hybrid Statistical + ML engine.
- **🛡️ Explainability**: "Why was this flagged?" - detailed feature contribution analysis.
- **⏱️ Incident Timeline**: Correlates fragmented events into contextual security incidents.
- **🧠 Self-Learning**: Collects data, trains offline, updates model online.
- **🚀 Performance**: Built with Rust for <1% CPU overhead.

## 🛠️ Architecture
- **Core**: Rust (Tauri Backend)
- **Frontend**: React + Tailwind (Glassmorphism)
- **AI Engine**: ONNX Runtime (Random Forest)
- **Trainer**: Python (Scikit-learn)

## 🚀 Getting Started

### Prerequisites
- Node.js & NPM
- Rust (Cargo)
- Python 3.9+ (for training)

### Installation
1. Data Collection:
```bash
npm install
npm run tauri dev
```
2. Train Model (Optional):
```bash
cd ai-trainer
pip install -r requirements.txt
python train.py
```

## 📄 License
MIT License.
