# 🗺️ One-Shield Roadmap v2.5

> Chi tiết kế hoạch phát triển từ v2.3 đến v3.0, bao gồm giải pháp kỹ thuật cho từng tính năng.

**Cập nhật**: 2025-12-12
**Version hiện tại**: v2.5.0 (Phase 10 Complete - Cloud Backend)

---

## 📋 Mục Lục

- [Tổng Quan Tiến Độ](#-tổng-quan-tiến-độ)
- [Phase 9: Advanced Detection v2.3](#-phase-9-advanced-detection-v23)
- [Phase 10: Cloud & Sync v2.5](#-phase-10-cloud--sync-v25)
- [Phase 11: Enterprise Scale v3.0](#-phase-11-enterprise-scale-v30)
- [Priority Matrix](#-priority-matrix)
- [Timeline Ước Tính](#-timeline-ước-tính)

---

## 📊 Tổng Quan Tiến Độ

### ✅ Đã Hoàn Thành (v1.0 - v2.2)

| Phase | Version | Tính năng chính | LOC |
|-------|---------|-----------------|-----|
| 1 | v1.1 | Anti-Poisoning, Baseline Hardening | ~1,200 |
| 2 | v1.2 | Process Intelligence, Signature Verification | ~2,000 |
| 3 | v1.3 | Behavioral Signatures, LOLBin Detection | ~2,100 |
| 4 | v1.4 | VirusTotal, Threat Feeds, MITRE ATT&CK | ~1,450 |
| 5 | v1.5 | Auto-Response, Quarantine, Webhooks | ~1,785 |
| 6 | v2.0 | Enterprise RBAC, Policy Sync, Reports | ~2,500 |
| 7 | v2.1 | UI Integration, Executive Dashboard | ~1,500 |
| 8 | v2.2 | AMSI, DLL Injection, Memory Shellcode | ~2,700 |
| 9 | v2.3 | Keylogger Detection, IAT Analysis | ~1,500 |
| 10 | v2.5 | Cloud Backend, Agent-Server Sync | ~2,500 |
| **Total** | **v2.5** | **10 Phases Complete** | **~19,235** |

### 🔜 Cần Làm (v3.0)

| Phase | Version | Tính năng chính | Effort |
|-------|---------|-----------------|--------|
| 11 | v3.0 | Multi-Tenant, Compliance Reports, Dashboard | 🔴 High |

---

## 🔬 Phase 9: Advanced Detection v2.3

> **Mục tiêu**: Nâng cao detection với kernel-level events và API monitoring.

### 9.1 Keylogger API Hooking Detection

**Mục đích**: Phát hiện phần mềm ghi lại keystroke.

**Indicators cần detect**:

```rust
// Các API thường bị abuse bởi keyloggers
const KEYLOGGER_APIS: &[&str] = &[
    "GetAsyncKeyState",      // Polling keyboard state
    "GetKeyState",           // Check key status
    "GetKeyboardState",      // Get all 256 key states
    "SetWindowsHookExW",     // WH_KEYBOARD_LL hook
    "GetClipboardData",      // Clipboard monitoring
    "OpenClipboard",
    "GetForegroundWindow",   // Track active window
    "GetWindowTextW",        // Get window title (for logging)
];

// Behavioral patterns
struct KeyloggerPattern {
    api_calls_per_minute: u32,     // > 100 = suspicious
    clipboard_access_rate: u32,    // > 10/min = suspicious
    window_tracking_rate: u32,     // > 30/min = suspicious
    log_file_writes: bool,         // Writing to suspicious files
}
```

**Giải pháp kỹ thuật**:

```rust
// File: core-service/src/logic/advanced_detection/keylogger.rs

use std::collections::HashMap;
use parking_lot::RwLock;
use once_cell::sync::Lazy;

/// API call frequency tracker
static API_TRACKER: Lazy<RwLock<HashMap<u32, ApiCallStats>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

#[derive(Debug, Clone)]
pub struct ApiCallStats {
    pid: u32,
    process_name: String,
    get_async_key_state: u32,
    get_keyboard_state: u32,
    clipboard_access: u32,
    window_tracking: u32,
    last_reset: i64,
}

#[derive(Debug, Clone)]
pub struct KeyloggerAlert {
    pid: u32,
    process_name: String,
    confidence: u8,
    indicators: Vec<String>,
    mitre_id: String,  // T1056.001 - Keylogging
}

impl ApiCallStats {
    pub fn check_keylogger(&self) -> Option<KeyloggerAlert> {
        let mut indicators = Vec::new();
        let mut score = 0;

        // High frequency GetAsyncKeyState (polling)
        if self.get_async_key_state > 100 {
            indicators.push(format!(
                "GetAsyncKeyState called {} times/min",
                self.get_async_key_state
            ));
            score += 30;
        }

        // Clipboard monitoring
        if self.clipboard_access > 10 {
            indicators.push(format!(
                "Clipboard accessed {} times/min",
                self.clipboard_access
            ));
            score += 25;
        }

        // Window tracking (for logging which app has focus)
        if self.window_tracking > 30 {
            indicators.push(format!(
                "Window tracking {} times/min",
                self.window_tracking
            ));
            score += 20;
        }

        // GetKeyboardState (dump all keys)
        if self.get_keyboard_state > 50 {
            indicators.push(format!(
                "GetKeyboardState called {} times/min",
                self.get_keyboard_state
            ));
            score += 25;
        }

        if score >= 50 {
            Some(KeyloggerAlert {
                pid: self.pid,
                process_name: self.process_name.clone(),
                confidence: score.min(100) as u8,
                indicators,
                mitre_id: "T1056.001".to_string(),
            })
        } else {
            None
        }
    }
}
```

**Cách implement** (2 options):

| Option | Mô tả | Pros | Cons |
|--------|-------|------|------|
| **A. ETW Provider** | Dùng Microsoft-Windows-Kernel-Audit-API-Calls | Native Windows, không cần driver | Chỉ Windows 10+, cần Admin |
| **B. Import Table Scan** | Scan IAT của suspicious processes | Không cần quyền đặc biệt | Chỉ phát hiện static imports |

**Đề xuất**: Bắt đầu với **Option B** (Import Table Scan), sau đó upgrade lên ETW.

---

### 9.2 ETW Tracing (Event Tracing for Windows)

**Mục đích**: Monitor kernel-level events real-time.

**Events cần bắt**:

```rust
// ETW Providers cần subscribe
const ETW_PROVIDERS: &[(&str, &str)] = &[
    // Process events
    ("Microsoft-Windows-Kernel-Process", "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"),

    // Network events
    ("Microsoft-Windows-Kernel-Network", "{7DD42A49-5329-4832-8DFD-43D979153A88}"),

    // File events
    ("Microsoft-Windows-Kernel-File", "{EDD08927-9CC4-4E65-B970-C2560FB5C289}"),

    // Registry events
    ("Microsoft-Windows-Kernel-Registry", "{70EB4F03-C1DE-4F73-A051-33D13D5413BD}"),

    // DNS queries
    ("Microsoft-Windows-DNS-Client", "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}"),

    // PowerShell (Script Block Logging)
    ("Microsoft-Windows-PowerShell", "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}"),
];
```

**Giải pháp kỹ thuật**:

```rust
// File: core-service/src/logic/advanced_detection/etw.rs

use windows::Win32::System::Diagnostics::Etw::*;
use std::sync::mpsc;

/// ETW Event types we care about
#[derive(Debug, Clone)]
pub enum EtwEvent {
    ProcessCreate {
        pid: u32,
        parent_pid: u32,
        image_path: String,
        cmdline: String,
        timestamp: i64,
    },
    ProcessTerminate {
        pid: u32,
        timestamp: i64,
    },
    NetworkConnect {
        pid: u32,
        local_addr: String,
        remote_addr: String,
        remote_port: u16,
        timestamp: i64,
    },
    FileCreate {
        pid: u32,
        path: String,
        timestamp: i64,
    },
    RegistrySetValue {
        pid: u32,
        key_path: String,
        value_name: String,
        timestamp: i64,
    },
    DnsQuery {
        pid: u32,
        query_name: String,
        query_type: u16,
        timestamp: i64,
    },
    PowerShellScript {
        pid: u32,
        script_block: String,
        timestamp: i64,
    },
}

/// ETW Session Manager
pub struct EtwSession {
    session_handle: u64,
    event_tx: mpsc::Sender<EtwEvent>,
}

impl EtwSession {
    pub fn start() -> Result<(Self, mpsc::Receiver<EtwEvent>), EtwError> {
        let (tx, rx) = mpsc::channel();

        // Create ETW trace session
        let session_name = "OneShield-EDR-Trace";

        // ... Windows API calls to start trace ...

        Ok((Self {
            session_handle: 0,
            event_tx: tx
        }, rx))
    }

    pub fn stop(&self) -> Result<(), EtwError> {
        // Stop trace session
        Ok(())
    }
}
```

**Dependencies cần thêm**:

```toml
# Cargo.toml
[target.'cfg(windows)'.dependencies]
windows = { version = "0.58", features = [
    "Win32_System_Diagnostics_Etw",
    "Win32_Foundation",
    "Win32_Security",
]}
```

**Ưu điểm ETW**:
- ✅ Real-time process creation monitoring
- ✅ Network connections without netstat
- ✅ Registry changes real-time
- ✅ DNS queries (detect C2 domains)
- ✅ PowerShell Script Block Logging

**Nhược điểm**:
- ❌ Chỉ Windows
- ❌ Cần Administrator rights
- ❌ Complex implementation

---

### 9.3 Native AMSI Integration

**Mục đích**: Dùng Windows AMSI API thật thay vì heuristic patterns.

**Giải pháp kỹ thuật**:

```rust
// File: core-service/src/logic/advanced_detection/amsi_native.rs

use windows::Win32::System::Antimalware::*;
use windows::core::PCWSTR;

pub struct NativeAmsiScanner {
    context: HAMSICONTEXT,
    session: HAMSISESSION,
}

impl NativeAmsiScanner {
    pub fn new(app_name: &str) -> Result<Self, AmsiError> {
        let app_name_wide: Vec<u16> = app_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut context = HAMSICONTEXT::default();

        unsafe {
            AmsiInitialize(
                PCWSTR(app_name_wide.as_ptr()),
                &mut context
            )?;
        }

        let mut session = HAMSISESSION::default();
        unsafe {
            AmsiOpenSession(context, &mut session)?;
        }

        Ok(Self { context, session })
    }

    pub fn scan(&self, content: &str, content_name: &str) -> AmsiResult {
        let content_wide: Vec<u16> = content
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let name_wide: Vec<u16> = content_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut result = AMSI_RESULT::default();

        unsafe {
            AmsiScanString(
                self.context,
                PCWSTR(content_wide.as_ptr()),
                PCWSTR(name_wide.as_ptr()),
                self.session,
                &mut result
            )?;
        }

        match result {
            AMSI_RESULT_CLEAN => AmsiResult::Clean,
            AMSI_RESULT_NOT_DETECTED => AmsiResult::NotDetected,
            AMSI_RESULT_BLOCKED_BY_ADMIN_START..=AMSI_RESULT_BLOCKED_BY_ADMIN_END
                => AmsiResult::BlockedByAdmin,
            AMSI_RESULT_DETECTED => AmsiResult::Malware,
            _ => AmsiResult::Unknown,
        }
    }
}

impl Drop for NativeAmsiScanner {
    fn drop(&mut self) {
        unsafe {
            AmsiCloseSession(self.context, self.session);
            AmsiUninitialize(self.context);
        }
    }
}
```

**Khi nào dùng**:
- Heuristic patterns: Phát hiện 70+ known patterns
- Native AMSI: Leverage AV engine đã cài (Windows Defender, etc.)

**Đề xuất**: Chạy **cả hai** - heuristic + native AMSI cho coverage tốt nhất.

---

### 9.4 Import Address Table (IAT) Analysis

**Mục đích**: Phân tích DLL imports để detect suspicious API usage.

```rust
// File: core-service/src/logic/advanced_detection/iat_analysis.rs

use std::collections::HashSet;

/// Suspicious API combinations
const INJECTION_COMBO: &[&str] = &[
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
];

const CREDENTIAL_THEFT_COMBO: &[&str] = &[
    "LsaOpenPolicy",
    "LsaQueryInformationPolicy",
    "LsaRetrievePrivateData",
];

const EVASION_COMBO: &[&str] = &[
    "NtUnmapViewOfSection",
    "NtAllocateVirtualMemory",
    "NtWriteVirtualMemory",
];

pub struct IatAnalyzer;

impl IatAnalyzer {
    pub fn analyze_exe(path: &Path) -> Result<IatAnalysisResult, IatError> {
        let pe_data = std::fs::read(path)?;
        let pe = goblin::pe::PE::parse(&pe_data)?;

        let mut imports: HashSet<String> = HashSet::new();

        for import in pe.imports {
            imports.insert(import.name.to_string());
        }

        let mut alerts = Vec::new();

        // Check for injection combo
        if INJECTION_COMBO.iter().all(|api| imports.contains(*api)) {
            alerts.push(IatAlert {
                category: "Process Injection",
                mitre_id: "T1055",
                apis_found: INJECTION_COMBO.to_vec(),
                severity: 90,
            });
        }

        // Check for credential theft
        if CREDENTIAL_THEFT_COMBO.iter().all(|api| imports.contains(*api)) {
            alerts.push(IatAlert {
                category: "Credential Theft",
                mitre_id: "T1003",
                apis_found: CREDENTIAL_THEFT_COMBO.to_vec(),
                severity: 95,
            });
        }

        Ok(IatAnalysisResult {
            path: path.to_path_buf(),
            total_imports: imports.len(),
            alerts,
        })
    }
}
```

**Dependencies**:
```toml
[dependencies]
goblin = "0.8"  # PE parsing
```

---

## ☁️ Phase 10: Cloud & Sync v2.5 ✅ COMPLETE

> **Mục tiêu**: Central management với cloud backend.
>
> **Status**: ✅ Hoàn thành - 2025-12-12
>
> **Thành quả**:
> - ✅ Cloud Server (Axum + PostgreSQL) - `cloud-server/`
> - ✅ Agent Registration & Heartbeat (30s intervals)
> - ✅ JWT Authentication + Agent Token Auth
> - ✅ Database Schema (Organizations, Endpoints, Incidents, Policies)
> - ✅ Docker Compose Setup (PostgreSQL + Adminer)

### 10.1 Cloud Backend Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    ONE-SHIELD CLOUD                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌───────────┐  ┌───────────┐  ┌─────────────────────────┐ │
│  │  API      │  │  Auth     │  │  Event Processing       │ │
│  │  Gateway  │  │  Service  │  │  (Kafka/Redis Streams)  │ │
│  │  (Axum)   │  │  (JWT)    │  │                         │ │
│  └─────┬─────┘  └─────┬─────┘  └────────────┬────────────┘ │
│        │              │                      │              │
│        └──────────────┼──────────────────────┘              │
│                       │                                     │
│                ┌──────▼──────┐                             │
│                │ PostgreSQL  │                             │
│                │   + Redis   │                             │
│                └─────────────┘                             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
         ▲              ▲              ▲
         │              │              │
    ┌────┴────┐    ┌────┴────┐    ┌────┴────┐
    │Endpoint │    │Endpoint │    │Endpoint │
    │Agent #1 │    │Agent #2 │    │Agent #3 │
    └─────────┘    └─────────┘    └─────────┘
```

### 10.2 Database Schema (PostgreSQL)

```sql
-- Organizations (Multi-tenant)
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    license_key VARCHAR(255) UNIQUE,
    max_agents INT DEFAULT 10,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Endpoints (Agents)
CREATE TABLE endpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id),
    hostname VARCHAR(255) NOT NULL,
    os_version VARCHAR(100),
    agent_version VARCHAR(50),
    last_heartbeat TIMESTAMPTZ,
    status VARCHAR(20) DEFAULT 'online',
    baseline_hash VARCHAR(64),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Incidents (Synced from agents)
CREATE TABLE incidents (
    id UUID PRIMARY KEY,
    endpoint_id UUID REFERENCES endpoints(id),
    severity VARCHAR(20) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    mitre_techniques JSONB,
    status VARCHAR(20) DEFAULT 'open',
    created_at TIMESTAMPTZ NOT NULL,
    resolved_at TIMESTAMPTZ
);

-- Policies
CREATE TABLE policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id),
    name VARCHAR(255) NOT NULL,
    config JSONB NOT NULL,
    version INT DEFAULT 1,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Audit Log
CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    org_id UUID REFERENCES organizations(id),
    user_id UUID,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id UUID,
    details JSONB,
    ip_address INET,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_endpoints_org ON endpoints(org_id);
CREATE INDEX idx_endpoints_heartbeat ON endpoints(last_heartbeat);
CREATE INDEX idx_incidents_endpoint ON incidents(endpoint_id);
CREATE INDEX idx_incidents_created ON incidents(created_at);
CREATE INDEX idx_audit_org ON audit_log(org_id, created_at);
```

### 10.3 API Gateway (Axum)

```rust
// cloud-server/src/main.rs

use axum::{
    Router,
    routing::{get, post},
    middleware,
};
use tower_http::cors::CorsLayer;

#[tokio::main]
async fn main() {
    let app = Router::new()
        // Agent endpoints
        .route("/api/v1/agent/register", post(agent::register))
        .route("/api/v1/agent/heartbeat", post(agent::heartbeat))
        .route("/api/v1/agent/sync/baseline", post(agent::sync_baseline))
        .route("/api/v1/agent/sync/incidents", post(agent::sync_incidents))
        .route("/api/v1/agent/policy", get(agent::get_policy))

        // Management endpoints
        .route("/api/v1/endpoints", get(endpoints::list))
        .route("/api/v1/endpoints/:id", get(endpoints::get))
        .route("/api/v1/incidents", get(incidents::list))
        .route("/api/v1/policies", get(policies::list).post(policies::create))
        .route("/api/v1/reports/executive", get(reports::executive))

        // Auth
        .route("/api/v1/auth/login", post(auth::login))
        .route("/api/v1/auth/refresh", post(auth::refresh))

        // Middleware
        .layer(middleware::from_fn(auth::require_auth))
        .layer(CorsLayer::permissive());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

### 10.4 Agent-Server Protocol

```rust
// Agent → Server communication
#[derive(Serialize, Deserialize)]
pub struct AgentHeartbeat {
    agent_id: Uuid,
    timestamp: i64,
    status: AgentStatus,
    metrics: AgentMetrics,
}

#[derive(Serialize, Deserialize)]
pub struct AgentMetrics {
    cpu_usage: f32,
    memory_usage: f32,
    incident_count: u32,
    baseline_version: u32,
    model_version: String,
}

// Server → Agent responses
#[derive(Serialize, Deserialize)]
pub struct HeartbeatResponse {
    server_time: i64,
    policy_version: u32,
    has_model_update: bool,
    commands: Vec<AgentCommand>,
}

#[derive(Serialize, Deserialize)]
pub enum AgentCommand {
    UpdatePolicy { policy: PolicyConfig },
    UpdateModel { url: String, checksum: String },
    CollectForensics { target_path: String },
    IsolateNetwork,
    RestoreNetwork,
}
```

### 10.5 Baseline Sync

```rust
// Sync baseline từ agent lên cloud
#[derive(Serialize, Deserialize)]
pub struct BaselineSyncRequest {
    agent_id: Uuid,
    baseline_hash: String,
    baseline_version: u32,
    mean_values: [f32; 15],
    variance_values: [f32; 15],
    sample_count: u64,
}

// Cloud aggregates baselines từ nhiều agents
impl CloudBaselineAggregator {
    pub async fn aggregate(&self, org_id: Uuid) -> OrgBaseline {
        let agents = self.db.get_agents_by_org(org_id).await?;

        // Weighted average based on sample count
        let mut aggregated = [0.0f32; 15];
        let mut total_samples = 0u64;

        for agent in agents {
            if let Some(baseline) = agent.baseline {
                for i in 0..15 {
                    aggregated[i] += baseline.mean_values[i] * baseline.sample_count as f32;
                }
                total_samples += baseline.sample_count;
            }
        }

        for i in 0..15 {
            aggregated[i] /= total_samples as f32;
        }

        OrgBaseline {
            org_id,
            mean_values: aggregated,
            agent_count: agents.len(),
            total_samples,
        }
    }
}
```

---

## 🏢 Phase 11: Enterprise Scale v3.0

> **Mục tiêu**: Multi-tenant, compliance, và scaling.

### 11.1 Multi-Tenant Architecture

```rust
// Tenant isolation
pub struct TenantContext {
    org_id: Uuid,
    user_id: Uuid,
    role: UserRole,
    permissions: Vec<Permission>,
}

// All database queries include org_id
impl IncidentRepository {
    pub async fn list(&self, ctx: &TenantContext, filter: IncidentFilter) -> Vec<Incident> {
        sqlx::query_as!(
            Incident,
            r#"
            SELECT * FROM incidents
            WHERE endpoint_id IN (
                SELECT id FROM endpoints WHERE org_id = $1
            )
            AND severity = COALESCE($2, severity)
            ORDER BY created_at DESC
            LIMIT $3
            "#,
            ctx.org_id,
            filter.severity,
            filter.limit
        )
        .fetch_all(&self.pool)
        .await?
    }
}
```

### 11.2 Compliance Reporting

```rust
// ISO 27001 Report Generator
pub struct Iso27001Report {
    period: DateRange,
    org_id: Uuid,
    sections: Vec<ComplianceSection>,
}

#[derive(Serialize)]
pub struct ComplianceSection {
    control_id: String,      // "A.12.4.1"
    control_name: String,    // "Event Logging"
    status: ComplianceStatus,
    evidence: Vec<Evidence>,
    findings: Vec<Finding>,
}

impl Iso27001ReportGenerator {
    pub async fn generate(&self, org_id: Uuid, period: DateRange) -> Iso27001Report {
        let sections = vec![
            self.generate_a12_4_1(org_id, period).await?, // Event Logging
            self.generate_a12_4_3(org_id, period).await?, // Admin Logs
            self.generate_a16_1_2(org_id, period).await?, // Incident Reporting
            self.generate_a16_1_4(org_id, period).await?, // Assessment of Events
            self.generate_a16_1_5(org_id, period).await?, // Response to Incidents
        ];

        Iso27001Report { period, org_id, sections }
    }

    async fn generate_a12_4_1(&self, org_id: Uuid, period: DateRange) -> ComplianceSection {
        // A.12.4.1 - Event Logging
        let log_count = self.db.count_security_events(org_id, period).await?;
        let missing_logs = self.db.find_agents_without_logs(org_id, period).await?;

        ComplianceSection {
            control_id: "A.12.4.1".to_string(),
            control_name: "Event Logging".to_string(),
            status: if missing_logs.is_empty() {
                ComplianceStatus::Compliant
            } else {
                ComplianceStatus::NonCompliant
            },
            evidence: vec![
                Evidence::new("total_events", log_count.to_string()),
                Evidence::new("active_agents", self.db.count_active_agents(org_id).await?.to_string()),
            ],
            findings: missing_logs.into_iter().map(|a| Finding {
                severity: FindingSeverity::Medium,
                description: format!("Agent {} has no logs in reporting period", a.hostname),
            }).collect(),
        }
    }
}
```

### 11.3 SOC2 Audit Trail

```rust
// Comprehensive audit logging
pub struct AuditLogger {
    pool: PgPool,
}

impl AuditLogger {
    pub async fn log(&self, event: AuditEvent) -> Result<(), AuditError> {
        sqlx::query!(
            r#"
            INSERT INTO audit_log
            (org_id, user_id, action, resource_type, resource_id, details, ip_address)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
            event.org_id,
            event.user_id,
            event.action,
            event.resource_type,
            event.resource_id,
            event.details,
            event.ip_address
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

// Audit all sensitive actions
#[derive(Serialize)]
pub enum AuditAction {
    // Auth
    Login,
    Logout,
    PasswordChange,
    MfaEnabled,
    MfaDisabled,

    // User management
    UserCreated,
    UserDeleted,
    RoleChanged,

    // Policy
    PolicyCreated,
    PolicyUpdated,
    PolicyDeleted,
    PolicyApplied,

    // Incident
    IncidentAcknowledged,
    IncidentResolved,
    IncidentEscalated,

    // Agent
    AgentRegistered,
    AgentDeregistered,
    AgentIsolated,
    AgentRestored,
}
```

---

## 🎯 Priority Matrix

| # | Feature | Impact | Effort | Priority | Phase |
|---|---------|--------|--------|----------|-------|
| 1 | Keylogger Detection | ⬆️ High | 🟡 Medium | 🔴 P1 | v2.3 |
| 2 | IAT Analysis | ⬆️ High | 🟢 Low | 🔴 P1 | v2.3 |
| 3 | ETW Tracing | ⬆️ High | 🔴 High | 🟡 P2 | v2.3 |
| 4 | Native AMSI | 🟡 Medium | 🟡 Medium | 🟡 P2 | v2.3 |
| 5 | Cloud Backend | ⬆️ High | 🔴 High | 🟡 P2 | v2.5 |
| 6 | Agent Protocol | ⬆️ High | 🔴 High | 🟡 P2 | v2.5 |
| 7 | Baseline Sync | 🟡 Medium | 🟡 Medium | 🟢 P3 | v2.5 |
| 8 | Multi-Tenant | 🟡 Medium | 🔴 High | 🟢 P3 | v3.0 |
| 9 | ISO 27001 Reports | 🟢 Low | 🟡 Medium | 🟢 P3 | v3.0 |
| 10 | SOC2 Audit | 🟢 Low | 🟡 Medium | 🟢 P3 | v3.0 |

---

## 📅 Timeline Ước Tính

| Phase | Tasks | Thời gian | Target |
|-------|-------|-----------|--------|
| **v2.3** | Keylogger + IAT | 1-2 tuần | Jan 2025 |
| **v2.4** | ETW + Native AMSI | 2-3 tuần | Feb 2025 |
| **v2.5** | Cloud Backend + Sync | 3-4 tuần | Mar 2025 |
| **v3.0** | Enterprise Features | 4-6 tuần | May 2025 |

**Total estimated**: 10-15 tuần (2.5-4 tháng)

---

## 📝 Quick Start - Bắt đầu v2.3

### Step 1: Keylogger Detection (Day 1-3)
```bash
# Tạo file mới
touch core-service/src/logic/advanced_detection/keylogger.rs

# Implement ApiCallStats và KeyloggerAlert
# Integrate vào analysis_loop.rs
```

### Step 2: IAT Analysis (Day 4-5)
```bash
# Add dependency
cargo add goblin

# Tạo file
touch core-service/src/logic/advanced_detection/iat_analysis.rs

# Integrate với file scanning
```

### Step 3: Testing & Polish (Day 6-7)
```bash
# Thêm tests
cargo test advanced_detection

# Build release
cargo build --release
```

---

## 🔗 References

- [MITRE ATT&CK - Input Capture](https://attack.mitre.org/techniques/T1056/)
- [ETW Documentation](https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-portal)
- [AMSI API](https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)
- [PE Format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)

---

*Document Version: 1.0*
*Last Updated: 2025-12-12*
