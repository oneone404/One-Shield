# AI Security Assistant - Version 1.0.0 (Release Candidate)

## 🌟 Highlights
- **End-to-End AI Security Pipeline**: From data collection to Threat Detection & Explanation.
- **Hybrid AI Engine**: Combines Statistical Baseline (Z-Score) with ONNX-based Random Forest model.
- **SOC Dashboard**: Real-time Incident Timeline and Explanation (Why detected?).
- **Safety First**: Kill-switch configuration and safe-fail architecture.

## 🚀 Key Features

### Core Service
- **Intelligent Collector**: Captures CPU, RAM, Network, Disk I/O per-process.
- **Incident Manager**: Correlates events into incidents (60s window).
- **Explainability Engine**: Heuristic analysis of feature deviations.
- **Action Guard**: Alert-only mode (v1.0) with auto-block capabilities (ready for v1.1).

### AI & Data
- **Feature Vector**: 15-dimensional vector (Spikes, Rates, Ratios).
- **Dataset Management**: Automatic JSONL logging and Export for training.
- **Training Loop**: Integrated Python trainer script (Scikit-learn -> ONNX).

### UI / Experience
- **Glassmorphism Design**: Modern, transparent aesthetic.
- **Visualizations**: Real-time charts, Severity Badges, Feature Contribution bars.
- **Multi-language**: Structure ready (English/Vietnamese).

## 🔒 Security & Stability
- **Audit**: Panics removed from critical paths.
- **Config**: Global Safety Config (AI, Explain, Auto-Block).
- **Privacy**: Local-first processing (No cloud upload).

---
*Built with Rust (Tauri), React, and Python.*
