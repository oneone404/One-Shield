---
description: Standard development workflow for AI Security pipeline (EDR-style)
---

# 🧠 AI Security Development Workflow

## Core Principle
```
AI chỉ chấm điểm → Rust quyết định → UI phản ứng
```

---

## 🧩 PIPELINE FLOW

```
[Collect] → [Feature] → [Baseline] → [Anomaly Score] → [Threat Class] → [Policy Decision] → [Action/Alert]
```

Each step = 1 clear module

---

## 📋 STEP 0 – Task Type

Before coding, identify task type:

| Task Type | Example | Files |
|-----------|---------|-------|
| Feature | thêm metric mới | logic/collector.rs, logic/features/ |
| AI | chỉnh threshold/model | logic/ai_bridge.rs, logic/model/ |
| Security | policy/action | logic/threat.rs, logic/policy.rs |
| UI | hiển thị threat | web-app/src/components/ |
| Infra | perf/logging | everywhere |

❗ **RULE: Không trộn task AI + UI trong 1 PR**

---

## 📋 STEP 1 – Collector/Feature (Rust)

📁 `logic/collector.rs`, `logic/features/`

```rust
fn collect_gpu_usage() -> f32;
```

✅ Rules:
- Không AI logic
- Không policy
- Chỉ thu thập & normalize

📌 Output: `FeatureVector { cpu, ram, net_out, gpu, ... }`

---

## 📋 STEP 2 – Baseline Handling

📁 `logic/baseline.rs`

Question: "Cái này lạ hay bình thường so với thói quen?"

```rust
fn compare_with_baseline(fv: &FeatureVector) -> BaselineDiff;
```

📌 Output: `BaselineDiff { deviation_score, duration }`

---

## 📋 STEP 3 – AI Inference (KHÔNG DECIDE)

📁 `logic/ai_bridge.rs`, `logic/model/`

```rust
AnomalyScore {
  score: f32,
  confidence: f32,
}
```

❌ AI không:
- kill process
- block network
- quyết định malicious

---

## 📋 STEP 4 – Threat Classification (CORE)

📁 `logic/threat.rs` (tách file riêng)

```rust
enum ThreatClass {
    Benign,
    Suspicious,
    Malicious,
}

fn classify(
  anomaly: AnomalyScore,
  baseline: BaselineDiff,
  context: Context,
) -> ThreatClass
```

📌 Rules:
- Deterministic
- Explainable

---

## 📋 STEP 5 – Policy Decision Engine

📁 `logic/policy.rs`

```rust
enum Decision {
    SilentLog,
    Notify,
    RequireApproval,
    AutoBlock,
}

fn decide(threat: ThreatClass, severity: Severity) -> Decision
```

📌 **ĐÂY là nơi làm Security**

---

## 📋 STEP 6 – Action Guard/Execution

📁 `logic/action_guard.rs`

| Decision | Action |
|----------|--------|
| SilentLog | log only |
| Notify | UI alert |
| RequireApproval | ApprovalModal |
| AutoBlock | kill/block |

✅ DEV không bypass step này

---

## 📋 STEP 7 – API Layer (Tauri)

📁 `api/commands.rs`

```rust
#[tauri::command]
fn get_threat_events() -> Vec<ThreatEvent>
```

✅ API chỉ expose event + decision, không expose raw AI

---

## 📋 STEP 8 – UI React

```javascript
switch (event.threat) {
  case "benign": // không popup
  case "suspicious": // modal
  case "malicious": // warning + disabled button
}
```

📌 **UI không quyết định security**

---

## 🌿 BRANCHING & COMMIT

### Branch convention
```
feat/collector-gpu
feat/threat-classification
fix/baseline-overflow
perf/onnx-buffer
```

### Commit message
```
feat(threat): add suspicious classification for net burst
fix(ai): clamp anomaly score overflow
perf(collector): reduce polling overhead
```

---

## 🧪 TEST PRIORITY

1. Unit test: threat classification
2. Policy decision test
3. Integration test: fake anomaly → decision

```rust
// tests/threat_test.rs
assert_eq!(
  classify(score=0.9, context),
  ThreatClass::Malicious
);
```

---

## 🔍 DEBUG FLOW

Debug theo thứ tự:
1. Feature vector đúng chưa?
2. Baseline lệch vì data hay logic?
3. AI score có spike?
4. Threat classify có rule sai?
5. Policy mapping đúng không?

❌ Không debug từ UI ngược xuống AI

---

## ⛔ RULES BẤT DI BẤT DỊCH

- ❌ Không để AI quyết định kill
- ❌ Không logic security trong UI
- ❌ Không bypass Action Guard
- ❌ Không poll vô hạn không throttle
- ✅ Rust là "judge cuối cùng"

---

## ✅ DEV CHECKLIST

- [ ] Feature thuần → collector
- [ ] Intelligence → AI
- [ ] Decision → threat + policy
- [ ] Action → guard
- [ ] UI chỉ phản ứng
