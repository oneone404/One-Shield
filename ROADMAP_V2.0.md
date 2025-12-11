# 🗺️ One-Shield Roadmap - Chi Tiết Kỹ Thuật

> Tài liệu này mô tả chi tiết kế hoạch phát triển One-Shield từ v1.1 đến v2.0, bao gồm giải pháp cho vấn đề **Baseline Poisoning** và các tính năng nâng cao.

---

## 📋 Mục Lục

- [Vấn Đề Cần Giải Quyết](#-vấn-đề-cần-giải-quyết)
- [Phase 1: Anti-Poisoning (v1.1)](#-phase-1-anti-poisoning--baseline-hardening-v11)
- [Phase 2: Process Intelligence (v1.2)](#-phase-2-process-intelligence-v12)
- [Phase 3: Behavioral Signatures (v1.3)](#-phase-3-behavioral-signatures-v13)
- [Phase 4: External Intelligence (v1.4)](#-phase-4-external-intelligence-v14)
- [Phase 5: Response & Automation (v1.5)](#-phase-5-response--automation-v15)
- [Phase 6: Enterprise Features (v2.0)](#-phase-6-enterprise-features-v20)

---

## ⚠️ Vấn Đề Cần Giải Quyết

### Baseline Poisoning Attack

**Kịch bản tấn công:**
```
Tuần 1: Malware hoạt động ở mức 2% CPU, 50KB/s network
         → Hệ thống học: "Đây là hành vi bình thường"

Tuần 2: Malware tăng lên 5% CPU, 200KB/s network
         → Hệ thống: "Chỉ hơi bất thường" (vì baseline đã shift)

Tuần 3: Malware exfiltrate data với 500KB/s
         → Hệ thống: "Medium anomaly" thay vì "Critical"
```

**Nguyên nhân trong v1.0:**
```rust
// baseline/mod.rs - Dòng 268-271
if final_score < BASELINE_UPDATE_THRESHOLD {  // 0.5
    update_global_baseline(features);  // ← Học ngay lập tức!
}
```

**Hậu quả:**
- APT có thể "huấn luyện" hệ thống chấp nhận hành vi độc hại
- Baseline drift dần dần làm giảm độ nhạy phát hiện
- Không có cơ chế rollback khi phát hiện poisoning

---

## 📅 Phase 1: Anti-Poisoning & Baseline Hardening (v1.1)

> **Mục tiêu:** Ngăn chặn malware "nhiễm độc" baseline bằng cách kiểm soát chặt điều kiện học.

### 1.1 Delayed Baseline Learning

**Mô tả:** Sample phải "clean" liên tục trong X giờ mới được học vào baseline.

**Thiết kế kỹ thuật:**
```rust
// Cấu trúc dữ liệu mới
struct PendingSample {
    features: FeatureVector,
    first_seen: DateTime<Utc>,
    clean_streak: u32,        // Số lần liên tiếp được đánh giá sạch
    required_streak: u32,     // Mặc định: 180 (= 6 giờ với interval 2 phút)
}

// Logic học
fn should_learn(sample: &PendingSample) -> bool {
    let delay_hours = 6;
    let now = Utc::now();
    let age = now - sample.first_seen;

    age >= Duration::hours(delay_hours)
        && sample.clean_streak >= sample.required_streak
}
```

**File cần sửa:**
- `core-service/src/logic/baseline/mod.rs`
- `core-service/src/logic/baseline/types.rs` (thêm PendingSample)

---

### 1.2 Quarantine Queue

**Mô tả:** Tất cả sample mới đi vào hàng đợi "quarantine" trước khi được xét duyệt học.

**Thiết kế kỹ thuật:**
```rust
// Quarantine Manager
struct QuarantineQueue {
    pending: VecDeque<PendingSample>,
    max_size: usize,          // Giới hạn memory, mặc định 10,000 samples
    auto_approve_hours: u32,  // Tự động approve sau X giờ sạch
}

impl QuarantineQueue {
    fn add(&mut self, sample: PendingSample) {
        if self.pending.len() >= self.max_size {
            self.pending.pop_front(); // FIFO eviction
        }
        self.pending.push_back(sample);
    }

    fn process(&mut self) -> Vec<FeatureVector> {
        // Trả về samples đủ điều kiện học
        let approved: Vec<_> = self.pending
            .iter()
            .filter(|s| should_learn(s))
            .map(|s| s.features.clone())
            .collect();

        // Xóa samples đã approve
        self.pending.retain(|s| !should_learn(s));
        approved
    }
}
```

**File cần tạo:**
- `core-service/src/logic/baseline/quarantine.rs`

---

### 1.3 Learning Rate Limiter

**Mô tả:** Giới hạn tốc độ baseline drift để phát hiện poisoning sớm.

**Thiết kế kỹ thuật:**
```rust
struct DriftMonitor {
    baseline_snapshots: Vec<BaselineSnapshot>,
    max_drift_per_hour: f32,    // Mặc định: 5% thay đổi
    alert_threshold: f32,       // Mặc định: 10% thay đổi
}

struct BaselineSnapshot {
    timestamp: DateTime<Utc>,
    mean: [f32; 15],
    variance: [f32; 15],
}

impl DriftMonitor {
    fn check_drift(&self, current: &VersionedBaseline) -> DriftResult {
        let last = self.baseline_snapshots.last()?;

        // Tính % thay đổi trung bình của mean values
        let drift = (0..15)
            .map(|i| ((current.mean[i] - last.mean[i]) / last.mean[i].max(0.001)).abs())
            .sum::<f32>() / 15.0;

        if drift > self.alert_threshold {
            DriftResult::Alert("Baseline drift bất thường!")
        } else if drift > self.max_drift_per_hour {
            DriftResult::PauseLearning
        } else {
            DriftResult::Normal
        }
    }
}
```

**File cần tạo:**
- `core-service/src/logic/baseline/drift.rs`

---

### 1.4 Multi-Feature Voting

**Mô tả:** Tất cả 6 nhóm features phải sạch mới được học.

**Thiết kế kỹ thuật:**
```rust
// 6 nhóm features
enum FeatureGroup {
    Cpu,        // features 0-1
    Memory,     // features 2-3
    Network,    // features 4-6
    Disk,       // features 7-9
    Process,    // features 10-12
    Correlation,// features 13-14
}

fn all_groups_clean(features: &FeatureVector, baseline: &VersionedBaseline) -> bool {
    let groups = [
        is_group_clean(features, baseline, &[0, 1]),      // CPU
        is_group_clean(features, baseline, &[2, 3]),      // Memory
        is_group_clean(features, baseline, &[4, 5, 6]),   // Network
        is_group_clean(features, baseline, &[7, 8, 9]),   // Disk
        is_group_clean(features, baseline, &[10, 11, 12]),// Process
        is_group_clean(features, baseline, &[13, 14]),    // Correlation
    ];

    groups.iter().all(|&clean| clean)
}

fn is_group_clean(features: &FeatureVector, baseline: &VersionedBaseline, indices: &[usize]) -> bool {
    indices.iter().all(|&i| {
        let deviation = (features.values[i] - baseline.mean[i]).abs();
        let threshold = baseline.variance[i].sqrt() * 1.5;
        deviation <= threshold
    })
}
```

**File cần sửa:**
- `core-service/src/logic/baseline/mod.rs` (hàm `update_global_baseline`)

---

### 1.5 Baseline Snapshot & Rollback

**Mô tả:** Lưu checkpoint định kỳ, rollback nếu phát hiện poisoning.

**Thiết kế kỹ thuật:**
```rust
struct BaselineHistory {
    snapshots: Vec<(DateTime<Utc>, VersionedBaseline)>,
    max_snapshots: usize,  // Mặc định: 24 (= 24 giờ nếu snapshot mỗi giờ)
}

impl BaselineHistory {
    fn save_snapshot(&mut self, baseline: &VersionedBaseline) {
        let now = Utc::now();
        self.snapshots.push((now, baseline.clone()));

        if self.snapshots.len() > self.max_snapshots {
            self.snapshots.remove(0);
        }

        // Persist to disk
        self.save_to_disk();
    }

    fn rollback(&mut self, hours_ago: u32) -> Option<VersionedBaseline> {
        let target_time = Utc::now() - Duration::hours(hours_ago as i64);

        self.snapshots
            .iter()
            .rev()
            .find(|(time, _)| *time <= target_time)
            .map(|(_, baseline)| baseline.clone())
    }
}
```

**File cần tạo:**
- `core-service/src/logic/baseline/history.rs`

**File cần sửa:**
- `core-service/src/logic/baseline/storage.rs`

---

## 📅 Phase 2: Process Intelligence (v1.2)

> **Mục tiêu:** Phân tích sâu hành vi process để phát hiện suspicious activity.

### 2.1 Signed App Whitelist

**Mô tả:** Chỉ trust các app có chữ ký số hợp lệ từ các publisher đáng tin cậy.

**Thiết kế kỹ thuật:**
```rust
use windows::Win32::Security::WinVerifyTrust;

struct SignatureValidator {
    trusted_publishers: HashSet<String>,  // "Microsoft Corporation", etc.
}

impl SignatureValidator {
    fn verify(&self, exe_path: &Path) -> SignatureResult {
        // Gọi Windows API để verify signature
        match wintrust::verify_signature(exe_path) {
            Ok(signer) => {
                if self.trusted_publishers.contains(&signer) {
                    SignatureResult::Trusted(signer)
                } else {
                    SignatureResult::SignedButUntrusted(signer)
                }
            }
            Err(_) => SignatureResult::Unsigned
        }
    }
}

enum SignatureResult {
    Trusted(String),           // App được trust
    SignedButUntrusted(String),// Có chữ ký nhưng không trong whitelist
    Unsigned,                  // Không có chữ ký
    Invalid,                   // Chữ ký không hợp lệ
}
```

**Dependencies mới:**
```toml
# Cargo.toml
[dependencies]
wintrust = "0.3"
```

**File cần tạo:**
- `core-service/src/logic/features/signature.rs`

---

### 2.2 Process Tree Analysis

**Mô tả:** Phân tích Parent-Child relationship để phát hiện spawn bất thường.

**Thiết kế kỹ thuật:**
```rust
struct ProcessTree {
    nodes: HashMap<u32, ProcessNode>,  // pid -> node
}

struct ProcessNode {
    pid: u32,
    name: String,
    exe_path: PathBuf,
    parent_pid: Option<u32>,
    children: Vec<u32>,
    spawn_time: DateTime<Utc>,
    signature: SignatureResult,
}

// Rules phát hiện spawn bất thường
const SUSPICIOUS_SPAWN_RULES: &[(&str, &[&str])] = &[
    // (Parent, [Suspicious Children])
    ("WINWORD.EXE", &["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"]),
    ("EXCEL.EXE", &["cmd.exe", "powershell.exe", "mshta.exe"]),
    ("OUTLOOK.EXE", &["cmd.exe", "powershell.exe"]),
    ("notepad.exe", &["cmd.exe", "powershell.exe"]),
    ("explorer.exe", &["mshta.exe", "wscript.exe"]),
];

impl ProcessTree {
    fn check_suspicious_spawn(&self, child_pid: u32) -> Option<SuspiciousSpawn> {
        let child = self.nodes.get(&child_pid)?;
        let parent_pid = child.parent_pid?;
        let parent = self.nodes.get(&parent_pid)?;

        for (parent_pattern, suspicious_children) in SUSPICIOUS_SPAWN_RULES {
            if parent.name.eq_ignore_ascii_case(parent_pattern) {
                for sus_child in *suspicious_children {
                    if child.name.eq_ignore_ascii_case(sus_child) {
                        return Some(SuspiciousSpawn {
                            parent: parent.clone(),
                            child: child.clone(),
                            reason: format!("{} spawned {}", parent.name, child.name),
                        });
                    }
                }
            }
        }
        None
    }
}
```

**File cần tạo:**
- `core-service/src/logic/features/process_tree.rs`

---

### 2.3 Suspicious Spawn Detection

**Mô tả:** Real-time monitoring cho LOLBins (Living Off the Land Binaries).

**LOLBins cần monitor:**
```rust
const LOLBINS: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "msiexec.exe",
    "wmic.exe",
];
```

---

### 2.4 Process Reputation Score

**Mô tả:** Điểm tin cậy dựa trên lịch sử behavior của mỗi process.

**Thiết kế kỹ thuật:**
```rust
struct ProcessReputation {
    scores: HashMap<String, ReputationEntry>,  // exe_hash -> score
}

struct ReputationEntry {
    exe_hash: String,
    exe_name: String,
    first_seen: DateTime<Utc>,
    times_seen: u64,
    anomaly_count: u64,
    reputation_score: f32,  // 0.0 (untrusted) - 1.0 (fully trusted)
}

impl ProcessReputation {
    fn calculate_score(&self, entry: &ReputationEntry) -> f32 {
        let age_days = (Utc::now() - entry.first_seen).num_days() as f32;
        let anomaly_rate = entry.anomaly_count as f32 / entry.times_seen.max(1) as f32;

        // Công thức: Tuổi càng cao + anomaly rate càng thấp = score càng cao
        let age_factor = (age_days / 30.0).min(1.0);  // Max sau 30 ngày
        let clean_factor = 1.0 - anomaly_rate;

        (age_factor * 0.4 + clean_factor * 0.6).clamp(0.0, 1.0)
    }
}
```

**File cần tạo:**
- `core-service/src/logic/features/reputation.rs`

---

## 📅 Phase 3: Behavioral Signatures (v1.3)

> **Mục tiêu:** Hardcoded rules cho các hành vi KHÔNG BAO GIỜ chấp nhận, bất kể ML score.

### 3.1 Keylogger Pattern Detection

**Indicators:**
```rust
struct KeyloggerDetector {
    // Patterns cần detect
    patterns: Vec<KeyloggerPattern>,
}

enum KeyloggerPattern {
    // 1. Hook keyboard API liên tục
    KeyboardHookFrequency { threshold_per_minute: u32 },

    // 2. Ghi file với tên suspicious
    SuspiciousLogFile { patterns: Vec<Regex> },

    // 3. Clipboard monitoring
    ClipboardAccess { threshold_per_minute: u32 },
}

const SUSPICIOUS_LOG_PATTERNS: &[&str] = &[
    r"(?i)keylog",
    r"(?i)keystroke",
    r"(?i)typed",
    r"(?i)password.*log",
];
```

---

### 3.2 Registry Persistence Monitor

**Locations cần monitor:**
```rust
const PERSISTENCE_KEYS: &[&str] = &[
    // Run keys
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",

    // Services
    r"SYSTEM\CurrentControlSet\Services",

    // Scheduled Tasks
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks",

    // Startup folder
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",

    // Image hijack
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
];
```

**Event cần bắt:**
- REG_NOTIFY_CHANGE_NAME
- REG_NOTIFY_CHANGE_LAST_SET

---

### 3.3 Network Beaconing Detection

**Mô tả:** Phát hiện kết nối định kỳ đến cùng một endpoint (C2 communication).

**Thiết kế kỹ thuật:**
```rust
struct BeaconingDetector {
    connections: HashMap<String, Vec<DateTime<Utc>>>,  // endpoint -> timestamps
    min_samples: usize,        // Cần ít nhất N samples
    jitter_threshold: f32,     // % variance cho phép
}

impl BeaconingDetector {
    fn detect_beacon(&self, endpoint: &str) -> Option<BeaconAlert> {
        let timestamps = self.connections.get(endpoint)?;

        if timestamps.len() < self.min_samples {
            return None;
        }

        // Tính intervals giữa các connections
        let intervals: Vec<f32> = timestamps
            .windows(2)
            .map(|w| (w[1] - w[0]).num_seconds() as f32)
            .collect();

        let mean_interval = intervals.iter().sum::<f32>() / intervals.len() as f32;
        let variance = intervals.iter()
            .map(|i| (i - mean_interval).powi(2))
            .sum::<f32>() / intervals.len() as f32;

        let jitter = variance.sqrt() / mean_interval;

        // Beaconing thường có jitter thấp (intervals đều)
        if jitter < self.jitter_threshold {
            Some(BeaconAlert {
                endpoint: endpoint.to_string(),
                interval_seconds: mean_interval,
                jitter_percent: jitter * 100.0,
                sample_count: timestamps.len(),
            })
        } else {
            None
        }
    }
}
```

---

### 3.4 DLL Injection Detection

**Techniques cần detect:**
```rust
enum InjectionTechnique {
    // Classic injection
    CreateRemoteThread,

    // APC injection
    QueueUserAPC,

    // Thread hijacking
    SetThreadContext,

    // Process hollowing
    NtUnmapViewOfSection,

    // Atom bombing
    GlobalAddAtom,
}

// Monitor các API calls
const INJECTION_APIS: &[&str] = &[
    "NtCreateThreadEx",
    "RtlCreateUserThread",
    "CreateRemoteThread",
    "CreateRemoteThreadEx",
    "QueueUserAPC",
    "NtQueueApcThread",
    "SetThreadContext",
    "NtSetContextThread",
    "NtUnmapViewOfSection",
    "VirtualAllocEx",
    "WriteProcessMemory",
];
```

---

### 3.5 Never-Learn Blacklist

**Mô tả:** Một số patterns KHÔNG BAO GIỜ được học vào baseline.

```rust
struct NeverLearnBlacklist {
    rules: Vec<NeverLearnRule>,
}

enum NeverLearnRule {
    // Process-based
    ProcessName(Vec<String>),       // ["mimikatz.exe", "lazagne.exe"]
    ProcessHash(HashSet<String>),   // Known malware hashes

    // Behavior-based
    NetworkToTor,                   // Connections to .onion
    NetworkToKnownC2,               // Known C2 IPs
    RegistryPersistence,            // Any persistence write

    // Signature-based
    UnsignedAndNetwork,             // Unsigned + network activity
    UnsignedAndDiskWrite,           // Unsigned + disk write
}

impl NeverLearnBlacklist {
    fn should_never_learn(&self, context: &SampleContext) -> bool {
        self.rules.iter().any(|rule| rule.matches(context))
    }
}
```

---

## 📅 Phase 4: External Intelligence (v1.4)

> **Mục tiêu:** Kết nối với nguồn threat intelligence bên ngoài.

### 4.1 VirusTotal Integration

**API Integration:**
```rust
struct VirusTotalClient {
    api_key: String,
    cache: LruCache<String, VTResult>,
    rate_limiter: RateLimiter,  // 4 requests/minute (free tier)
}

impl VirusTotalClient {
    async fn check_hash(&self, sha256: &str) -> Result<VTResult, VTError> {
        // Check cache first
        if let Some(cached) = self.cache.get(sha256) {
            return Ok(cached.clone());
        }

        self.rate_limiter.wait().await;

        let url = format!("https://www.virustotal.com/api/v3/files/{}", sha256);
        let resp = reqwest::get(&url)
            .header("x-apikey", &self.api_key)
            .await?
            .json::<VTResponse>()
            .await?;

        let result = VTResult {
            sha256: sha256.to_string(),
            detections: resp.data.attributes.last_analysis_stats.malicious,
            total_engines: resp.data.attributes.last_analysis_stats.total,
            first_seen: resp.data.attributes.first_submission_date,
        };

        self.cache.put(sha256.to_string(), result.clone());
        Ok(result)
    }
}
```

---

### 4.2 Cloud Threat Feed

**Sync known-bad indicators:**
```rust
struct ThreatFeed {
    malicious_ips: HashSet<IpAddr>,
    malicious_domains: HashSet<String>,
    malicious_hashes: HashSet<String>,
    last_updated: DateTime<Utc>,
}

impl ThreatFeed {
    async fn sync(&mut self) -> Result<(), FeedError> {
        // Fetch from multiple sources
        let sources = vec![
            "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            "https://urlhaus.abuse.ch/downloads/text/",
        ];

        for source in sources {
            let content = reqwest::get(source).await?.text().await?;
            self.parse_and_add(&content);
        }

        self.last_updated = Utc::now();
        Ok(())
    }
}
```

---

### 4.3 MITRE ATT&CK Mapping

**Map incidents với MITRE framework:**
```rust
struct MitreMapper {
    techniques: HashMap<String, MitreTechnique>,
}

struct MitreTechnique {
    id: String,           // "T1055"
    name: String,         // "Process Injection"
    tactic: String,       // "Defense Evasion"
    description: String,
}

// Mapping từ AnomalyTag sang MITRE
const TAG_TO_MITRE: &[(&str, &str)] = &[
    ("PROCESS_SPIKE", "T1059"),      // Command and Scripting Interpreter
    ("NETWORK_SPIKE", "T1071"),      // Application Layer Protocol
    ("REGISTRY_PERSIST", "T1547"),   // Boot or Logon Autostart
    ("DLL_INJECTION", "T1055"),      // Process Injection
    ("KEYLOGGER", "T1056"),          // Input Capture
    ("BEACONING", "T1071"),          // Application Layer Protocol
];
```

---

## 📅 Phase 5: Response & Automation (v1.5)

> **Mục tiêu:** Tự động phản ứng với threats.

### 5.1 Auto-Block Execution

**Thiết kế:**
```rust
struct AutoBlocker {
    enabled: bool,
    block_threshold: f32,     // Score >= này sẽ block
    block_actions: Vec<BlockAction>,
}

enum BlockAction {
    SuspendProcess(u32),      // Tạm dừng process
    KillProcess(u32),         // Kill process
    QuarantineFile(PathBuf),  // Di chuyển file vào quarantine
    BlockNetwork(u32),        // Block network cho PID
}
```

---

### 5.2 Network Quarantine

**Windows Firewall integration:**
```rust
async fn block_network_for_process(pid: u32) -> Result<(), NetworkError> {
    let exe_path = get_exe_path_from_pid(pid)?;

    // Tạo firewall rule
    let rule_name = format!("OneShield_Block_{}", pid);
    let cmd = format!(
        "netsh advfirewall firewall add rule name=\"{}\" dir=out program=\"{}\" action=block",
        rule_name, exe_path.display()
    );

    Command::new("cmd").args(&["/C", &cmd]).output().await?;
    Ok(())
}
```

---

### 5.3 SQLite Incident Database

**Schema:**
```sql
CREATE TABLE incidents (
    id TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,  -- 'open', 'acknowledged', 'resolved'
    title TEXT NOT NULL,
    description TEXT,
    mitre_techniques TEXT,  -- JSON array
    affected_processes TEXT,  -- JSON array
    response_actions TEXT  -- JSON array
);

CREATE TABLE incident_events (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    features BLOB,  -- Binary features
    tags TEXT,  -- JSON array
    FOREIGN KEY (incident_id) REFERENCES incidents(id)
);

CREATE INDEX idx_incidents_created ON incidents(created_at);
CREATE INDEX idx_events_incident ON incident_events(incident_id);
```

---

### 5.4 Alert Integration (Webhook)

**Support multiple platforms:**
```rust
struct AlertManager {
    webhooks: Vec<WebhookConfig>,
}

struct WebhookConfig {
    name: String,
    url: String,
    platform: WebhookPlatform,
    min_severity: Severity,
}

enum WebhookPlatform {
    Slack,
    Discord,
    Teams,
    Generic,
}

impl AlertManager {
    async fn send_alert(&self, incident: &Incident) -> Result<(), AlertError> {
        for webhook in &self.webhooks {
            if incident.severity >= webhook.min_severity {
                let payload = match webhook.platform {
                    WebhookPlatform::Slack => self.format_slack(incident),
                    WebhookPlatform::Discord => self.format_discord(incident),
                    _ => self.format_generic(incident),
                };

                reqwest::post(&webhook.url)
                    .json(&payload)
                    .await?;
            }
        }
        Ok(())
    }
}
```

---

## 📅 Phase 6: Enterprise Features (v2.0)

> **Mục tiêu:** Scale cho doanh nghiệp với quản lý tập trung.

### 6.1 Central Management Console

**Architecture:**
```
┌─────────────────────────────────────────────────┐
│            Central Management Server            │
│  ┌─────────┐  ┌─────────┐  ┌─────────────────┐ │
│  │  API    │  │  Auth   │  │  Policy Engine  │ │
│  │ Gateway │  │ Service │  │                 │ │
│  └────┬────┘  └────┬────┘  └────────┬────────┘ │
│       │            │                │          │
│  ┌────▼────────────▼────────────────▼────────┐ │
│  │              PostgreSQL DB                 │ │
│  └────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────┘
         │                    │
    ┌────▼────┐          ┌────▼────┐
    │Endpoint │          │Endpoint │
    │Agent #1 │          │Agent #2 │
    └─────────┘          └─────────┘
```

---

### 6.2 Role-Based Access Control

**Roles:**
```rust
enum UserRole {
    Admin,          // Full access
    Analyst,        // View + Acknowledge incidents
    Viewer,         // View only
    ApiClient,      // API access only
}

struct Permission {
    resource: Resource,
    actions: Vec<Action>,
}

enum Resource {
    Incidents,
    Policies,
    Endpoints,
    Settings,
    Users,
}

enum Action {
    Read,
    Write,
    Delete,
    Execute,
}
```

---

## 📊 Timeline Ước Tính

| Phase | Version | Thời gian | Độ phức tạp |
|-------|---------|-----------|-------------|
| Phase 1 | v1.1 | 2-3 tuần | 🔴 High |
| Phase 2 | v1.2 | 2-3 tuần | 🔴 High |
| Phase 3 | v1.3 | 3-4 tuần | 🔴 High |
| Phase 4 | v1.4 | 2 tuần | 🟡 Medium |
| Phase 5 | v1.5 | 2-3 tuần | 🟡 Medium |
| Phase 6 | v2.0 | 4-6 tuần | 🔴 High |

**Tổng cộng:** ~15-21 tuần (4-5 tháng)

---

## 🎯 Priority Matrix

| Tính năng | Impact | Effort | Priority |
|-----------|--------|--------|----------|
| Delayed Learning | ⬆️ High | 🟡 Medium | 🔴 #1 |
| Quarantine Queue | ⬆️ High | 🟡 Medium | 🔴 #2 |
| Process Tree Analysis | ⬆️ High | 🔴 High | 🔴 #3 |
| Signed Whitelist | ⬆️ High | 🟡 Medium | 🔴 #4 |
| Network Beaconing | ⬆️ High | 🔴 High | 🟡 #5 |
| VirusTotal Integration | 🟡 Medium | 🟢 Low | 🟡 #6 |
| SQLite Database | 🟡 Medium | 🟢 Low | 🟢 #7 |

---

## 📝 Ghi Chú

- Phase 1 **BẮT BUỘC** phải hoàn thành trước khi deploy production
- Phase 2-3 cần cho môi trường có APT threat cao
- Phase 4-6 là nice-to-have cho enterprise

---

*Cập nhật lần cuối: 2025-12-11*
