//! Collector Engine - Thu thập Raw Events (ENHANCED VERSION)
//!
//! Thu thập thông tin hệ thống CHI TIẾT cho từng process.
//! Sử dụng sysinfo crate để đọc CPU, RAM, Network, Disk I/O per-process.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use std::collections::HashMap;
use parking_lot::RwLock;
use sysinfo::{System, Networks};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ============================================================================
// CONSTANTS
// ============================================================================

/// Interval thu thập (10 giây)
const COLLECT_INTERVAL_SECS: u64 = 10;

/// Số Raw Events cần để tạo 1 Summary Vector
const EVENTS_PER_SUMMARY: usize = 150;

/// Kích thước buffer tối đa
const MAX_BUFFER_SIZE: usize = 500;

/// Ngưỡng CPU spike (%)
const CPU_SPIKE_THRESHOLD: f32 = 50.0;

/// Ngưỡng Memory spike (MB)
const MEMORY_SPIKE_THRESHOLD: f64 = 500.0;

// ============================================================================
// STATE MANAGEMENT
// ============================================================================

static IS_RUNNING: AtomicBool = AtomicBool::new(false);
static TOTAL_EVENTS: AtomicU64 = AtomicU64::new(0);
static TOTAL_SUMMARIES: AtomicU64 = AtomicU64::new(0);

/// Buffer chứa Process Events (chi tiết từng process)
static PROCESS_EVENTS_BUFFER: RwLock<Vec<ProcessEvent>> = RwLock::new(Vec::new());

/// Summary Vectors đã tạo
static SUMMARY_QUEUE: RwLock<Vec<SummaryVector>> = RwLock::new(Vec::new());

/// System info instance
static SYSTEM: RwLock<Option<System>> = RwLock::new(None);

/// Networks instance
static NETWORKS: RwLock<Option<Networks>> = RwLock::new(None);

/// Process history (để tính delta/spikes)
static PROCESS_HISTORY: RwLock<Option<HashMap<u32, ProcessHistory>>> = RwLock::new(None);

// ============================================================================
// DATA STRUCTURES - ENHANCED
// ============================================================================

/// Process Event - Sự kiện chi tiết từng process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,

    // Process info
    pub pid: u32,
    pub name: String,
    pub status: String,

    // Resource usage
    pub cpu_percent: f32,
    pub memory_mb: f64,
    pub memory_percent: f32,

    // I/O metrics
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
    pub disk_read_rate: f64,  // bytes/sec (delta)
    pub disk_write_rate: f64, // bytes/sec (delta)

    // Network (từ system total, chia đều cho active processes)
    pub network_sent_bytes: u64,
    pub network_recv_bytes: u64,

    // Process lifecycle
    pub run_time_secs: u64,
    pub start_time: Option<u64>,

    // Spike detection flags
    pub is_cpu_spike: bool,
    pub is_memory_spike: bool,
    pub is_new_process: bool,
}

/// Process History - Lưu trạng thái trước để tính delta
#[derive(Debug, Clone, Default)]
struct ProcessHistory {
    pub last_cpu: f32,
    pub last_memory: f64,
    pub last_disk_read: u64,
    pub last_disk_write: u64,
    pub last_seen: DateTime<Utc>,
    pub first_seen: DateTime<Utc>,
    pub spike_count: u32,
}

/// Summary Vector - ENHANCED với 15 features
///
/// Features:
/// 0.  avg_cpu - CPU trung bình (%)
/// 1.  max_cpu - CPU cao nhất (%)
/// 2.  avg_memory - Memory trung bình (MB)
/// 3.  max_memory - Memory cao nhất (MB)
/// 4.  total_network_sent - Tổng bytes gửi (log)
/// 5.  total_network_recv - Tổng bytes nhận (log)
/// 6.  total_disk_read - Tổng bytes đọc (log)
/// 7.  total_disk_write - Tổng bytes ghi (log)
/// 8.  unique_processes - Số process unique
/// 9.  network_ratio - Tỷ lệ sent/recv
/// 10. cpu_spike_rate - Tỷ lệ CPU spikes / tổng events
/// 11. memory_spike_rate - Tỷ lệ Memory spikes / tổng events
/// 12. new_process_rate - Tỷ lệ processes mới
/// 13. avg_disk_io_rate - Tỷ lệ I/O trung bình
/// 14. process_churn_rate - Tỷ lệ thay đổi processes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SummaryVector {
    pub id: String,
    pub features: [f32; 15],  // ENHANCED: 15 features thay vì 10
    pub created_at: DateTime<Utc>,
    pub raw_events_count: u32,
    pub processed: bool,
    pub ml_score: Option<f32>,
    pub tag_score: Option<f32>,
    pub final_score: Option<f32>,
    pub tags: Vec<String>,

    // Metadata cho analysis
    pub unique_pids: Vec<u32>,
    pub top_cpu_processes: Vec<(String, f32)>,
    pub top_memory_processes: Vec<(String, f64)>,
    pub spike_events: u32,
}

impl SummaryVector {
    /// Check if this summary is flagged as anomaly
    pub fn is_anomaly(&self) -> bool {
        self.final_score.map(|f| f >= 0.6).unwrap_or(false)
    }

    /// Get timestamp for training export
    pub fn timestamp(&self) -> &DateTime<Utc> {
        &self.created_at
    }
}

/// System Metrics - Thông tin tổng quan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub cpu_usage: f32,
    pub memory_used_mb: f64,
    pub memory_total_mb: f64,
    pub memory_percent: f32,
    pub network_sent_rate: u64,
    pub network_recv_rate: u64,
    pub process_count: usize,
    pub events_collected: u64,
    pub summaries_created: u64,
    pub active_spikes: u32,
}

/// Process Info cho Frontend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cpu_percent: f32,
    pub memory_mb: f64,
    pub status: String,
    pub is_spike: bool,
}

// ============================================================================
// ERROR HANDLING
// ============================================================================

#[derive(Debug)]
pub struct CollectorError(pub String);

impl std::fmt::Display for CollectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CollectorError: {}", self.0)
    }
}

impl std::error::Error for CollectorError {}

// ============================================================================
// INITIALIZATION
// ============================================================================

fn init_system() {
    let mut sys_guard = SYSTEM.write();
    if sys_guard.is_none() {
        let mut sys = System::new_all();
        sys.refresh_all();
        *sys_guard = Some(sys);
    }

    let mut net_guard = NETWORKS.write();
    if net_guard.is_none() {
        *net_guard = Some(Networks::new_with_refreshed_list());
    }
}

// ============================================================================
// COLLECTOR CONTROL
// ============================================================================

pub async fn start() -> Result<bool, CollectorError> {
    if IS_RUNNING.load(Ordering::SeqCst) {
        return Err(CollectorError("Collector đang chạy".to_string()));
    }

    init_system();
    IS_RUNNING.store(true, Ordering::SeqCst);

    tokio::spawn(async move {
        collector_loop().await;
    });

    log::info!("Enhanced Collector started (interval: {}s, features: 15)", COLLECT_INTERVAL_SECS);
    Ok(true)
}

pub async fn stop() -> Result<bool, CollectorError> {
    if !IS_RUNNING.load(Ordering::SeqCst) {
        return Err(CollectorError("Collector không đang chạy".to_string()));
    }

    IS_RUNNING.store(false, Ordering::SeqCst);
    log::info!("Collector stopped");
    Ok(true)
}

pub fn is_running() -> bool {
    IS_RUNNING.load(Ordering::SeqCst)
}

// ============================================================================
// MAIN COLLECTOR LOOP
// ============================================================================

async fn collector_loop() {
    log::info!("Collector loop started");

    while IS_RUNNING.load(Ordering::SeqCst) {
        if let Err(e) = collect_process_events() {
            log::error!("Error collecting events: {}", e);
        }

        check_and_create_summary();

        tokio::time::sleep(Duration::from_secs(COLLECT_INTERVAL_SECS)).await;
    }

    log::info!("Collector loop stopped");
}

/// Thu thập Process Events chi tiết
fn collect_process_events() -> Result<(), CollectorError> {
    let mut sys_guard = SYSTEM.write();
    let sys = sys_guard.as_mut().ok_or(CollectorError("System not initialized".to_string()))?;

    sys.refresh_all();

    // Refresh Networks
    let mut net_guard = NETWORKS.write();
    if let Some(networks) = net_guard.as_mut() {
        networks.refresh();
    }

    // Network totals
    let (net_sent, net_recv) = net_guard.as_ref()
        .map(|n| {
            let mut sent = 0u64;
            let mut recv = 0u64;
            for (_name, data) in n.iter() {
                sent += data.transmitted();
                recv += data.received();
            }
            (sent, recv)
        })
        .unwrap_or((0, 0));

    let timestamp = Utc::now();
    let mut buffer = PROCESS_EVENTS_BUFFER.write();

    // Initialize history if needed
    let mut history_guard = PROCESS_HISTORY.write();
    if history_guard.is_none() {
        *history_guard = Some(HashMap::new());
    }
    let history = history_guard.as_mut().unwrap();

    let process_count = sys.processes().len();
    let net_per_process = if process_count > 0 {
        (net_sent / process_count as u64, net_recv / process_count as u64)
    } else {
        (0, 0)
    };

    let total_memory = sys.total_memory() as f64;

    // Thu thập từng process
    for (pid, process) in sys.processes() {
        let pid_u32 = pid.as_u32();
        let proc_name = process.name().to_string();

        let cpu = process.cpu_usage();
        let memory_bytes = process.memory();
        let memory_mb = memory_bytes as f64 / 1024.0 / 1024.0;
        let memory_percent = if total_memory > 0.0 {
            (memory_bytes as f64 / total_memory * 100.0) as f32
        } else {
            0.0
        };

        let disk_usage = process.disk_usage();
        let disk_read = disk_usage.read_bytes;
        let disk_write = disk_usage.written_bytes;

        // Get/update history
        let hist = history.entry(pid_u32).or_insert_with(|| ProcessHistory {
            first_seen: timestamp,
            last_seen: timestamp,
            ..Default::default()
        });

        // Calculate deltas và rates
        let time_delta = (timestamp - hist.last_seen).num_seconds().max(1) as f64;
        let disk_read_rate = (disk_read.saturating_sub(hist.last_disk_read)) as f64 / time_delta;
        let disk_write_rate = (disk_write.saturating_sub(hist.last_disk_write)) as f64 / time_delta;

        // Spike detection
        let is_cpu_spike = cpu > CPU_SPIKE_THRESHOLD;
        let is_memory_spike = memory_mb > MEMORY_SPIKE_THRESHOLD;
        let is_new_process = (timestamp - hist.first_seen).num_seconds() < 30;

        if is_cpu_spike || is_memory_spike {
            hist.spike_count += 1;
        }

        // Update history
        hist.last_cpu = cpu;
        hist.last_memory = memory_mb;
        hist.last_disk_read = disk_read;
        hist.last_disk_write = disk_write;
        hist.last_seen = timestamp;

        let run_time = process.run_time();
        let start_time = process.start_time();

        let event = ProcessEvent {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp,
            pid: pid_u32,
            name: proc_name,
            status: format!("{:?}", process.status()),
            cpu_percent: cpu,
            memory_mb,
            memory_percent,
            disk_read_bytes: disk_read,
            disk_write_bytes: disk_write,
            disk_read_rate,
            disk_write_rate,
            network_sent_bytes: net_per_process.0,
            network_recv_bytes: net_per_process.1,
            run_time_secs: run_time,
            start_time: Some(start_time),
            is_cpu_spike,
            is_memory_spike,
            is_new_process,
        };

        buffer.push(event);
        TOTAL_EVENTS.fetch_add(1, Ordering::SeqCst);
    }

    // Cleanup old history entries
    let cutoff = timestamp - chrono::Duration::minutes(10);
    history.retain(|_, h| h.last_seen > cutoff);

    // Limit buffer size
    if buffer.len() > MAX_BUFFER_SIZE {
        let excess = buffer.len() - MAX_BUFFER_SIZE;
        buffer.drain(0..excess);
    }

    log::debug!("Collected {} process events, buffer: {}", sys.processes().len(), buffer.len());
    Ok(())
}

/// Tạo Summary Vector với 15 Enhanced Features
fn check_and_create_summary() {
    let mut buffer = PROCESS_EVENTS_BUFFER.write();

    if buffer.len() >= EVENTS_PER_SUMMARY {
        let events: Vec<ProcessEvent> = buffer.drain(0..EVENTS_PER_SUMMARY).collect();
        let summary = create_enhanced_summary_vector(&events);

        let mut queue = SUMMARY_QUEUE.write();
        queue.push(summary.clone());

        TOTAL_SUMMARIES.fetch_add(1, Ordering::SeqCst);

        log::info!("Created Enhanced Summary Vector: {} (15 features, {} events, {} spikes)",
            summary.id, events.len(), summary.spike_events);
    }
}

/// Tạo Enhanced Summary Vector với Feature Crosses
fn create_enhanced_summary_vector(events: &[ProcessEvent]) -> SummaryVector {
    if events.is_empty() {
        return SummaryVector {
            id: uuid::Uuid::new_v4().to_string(),
            features: [0.0; 15],
            created_at: Utc::now(),
            raw_events_count: 0,
            processed: false,
            ml_score: None,
            tag_score: None,
            final_score: None,
            tags: vec![],
            unique_pids: vec![],
            top_cpu_processes: vec![],
            top_memory_processes: vec![],
            spike_events: 0,
        };
    }

    // Basic stats
    let mut total_cpu = 0.0f64;
    let mut max_cpu = 0.0f32;
    let mut total_memory = 0.0f64;
    let mut max_memory = 0.0f64;
    let mut total_net_sent = 0u64;
    let mut total_net_recv = 0u64;
    let mut total_disk_read = 0u64;
    let mut total_disk_write = 0u64;
    let mut total_disk_io_rate = 0.0f64;

    // Spike counts
    let mut cpu_spike_count = 0u32;
    let mut memory_spike_count = 0u32;
    let mut new_process_count = 0u32;

    // Process tracking
    let mut unique_pids = std::collections::HashSet::new();
    let mut process_cpu: HashMap<String, f32> = HashMap::new();
    let mut process_memory: HashMap<String, f64> = HashMap::new();

    // First pass: collect stats
    for event in events {
        total_cpu += event.cpu_percent as f64;
        if event.cpu_percent > max_cpu {
            max_cpu = event.cpu_percent;
        }

        total_memory += event.memory_mb;
        if event.memory_mb > max_memory {
            max_memory = event.memory_mb;
        }

        total_net_sent = total_net_sent.max(event.network_sent_bytes);
        total_net_recv = total_net_recv.max(event.network_recv_bytes);
        total_disk_read += event.disk_read_bytes;
        total_disk_write += event.disk_write_bytes;
        total_disk_io_rate += event.disk_read_rate + event.disk_write_rate;

        if event.is_cpu_spike {
            cpu_spike_count += 1;
        }
        if event.is_memory_spike {
            memory_spike_count += 1;
        }
        if event.is_new_process {
            new_process_count += 1;
        }

        unique_pids.insert(event.pid);

        // Track per-process usage
        *process_cpu.entry(event.name.clone()).or_insert(0.0) += event.cpu_percent;
        *process_memory.entry(event.name.clone()).or_insert(0.0) += event.memory_mb;
    }

    let n = events.len() as f64;
    let n_u32 = events.len() as u32;

    // Calculate features
    let avg_cpu = (total_cpu / n) as f32;
    let avg_memory = (total_memory / n) as f32;

    let network_ratio = if total_net_sent + total_net_recv > 0 {
        total_net_sent as f32 / (total_net_sent + total_net_recv) as f32
    } else {
        0.5
    };

    // Feature Crosses (NEW)
    let cpu_spike_rate = cpu_spike_count as f32 / n as f32;
    let memory_spike_rate = memory_spike_count as f32 / n as f32;
    let new_process_rate = new_process_count as f32 / n as f32;
    let avg_disk_io_rate = (total_disk_io_rate / n) as f32;

    // Process churn rate (unique processes / total events)
    let process_churn_rate = unique_pids.len() as f32 / n as f32;

    // Normalize large values (log scale)
    let norm_net_sent = ((total_net_sent as f64) + 1.0).ln() as f32;
    let norm_net_recv = ((total_net_recv as f64) + 1.0).ln() as f32;
    let norm_disk_read = ((total_disk_read as f64) + 1.0).ln() as f32;
    let norm_disk_write = ((total_disk_write as f64) + 1.0).ln() as f32;
    let norm_disk_io_rate = (avg_disk_io_rate + 1.0).ln();

    // 15 Features array
    let features = [
        avg_cpu,                           // 0. avg_cpu
        max_cpu,                           // 1. max_cpu
        avg_memory,                        // 2. avg_memory
        max_memory as f32,                 // 3. max_memory
        norm_net_sent,                     // 4. total_network_sent (log)
        norm_net_recv,                     // 5. total_network_recv (log)
        norm_disk_read,                    // 6. total_disk_read (log)
        norm_disk_write,                   // 7. total_disk_write (log)
        unique_pids.len() as f32,          // 8. unique_processes
        network_ratio,                     // 9. network_ratio
        cpu_spike_rate,                    // 10. cpu_spike_rate (NEW)
        memory_spike_rate,                 // 11. memory_spike_rate (NEW)
        new_process_rate,                  // 12. new_process_rate (NEW)
        norm_disk_io_rate,                 // 13. avg_disk_io_rate (NEW)
        process_churn_rate,                // 14. process_churn_rate (NEW)
    ];

    // Top processes
    let mut top_cpu: Vec<_> = process_cpu.into_iter().collect();
    top_cpu.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    let top_cpu_processes: Vec<(String, f32)> = top_cpu.into_iter().take(5).collect();

    let mut top_mem: Vec<_> = process_memory.into_iter().collect();
    top_mem.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    let top_memory_processes: Vec<(String, f64)> = top_mem.into_iter().take(5).collect();

    SummaryVector {
        id: uuid::Uuid::new_v4().to_string(),
        features,
        created_at: Utc::now(),
        raw_events_count: n_u32,
        processed: false,
        ml_score: None,
        tag_score: None,
        final_score: None,
        tags: vec![],
        unique_pids: unique_pids.into_iter().collect(),
        top_cpu_processes,
        top_memory_processes,
        spike_events: cpu_spike_count + memory_spike_count,
    }
}

// ============================================================================
// PUBLIC API
// ============================================================================

pub fn get_system_metrics() -> SystemMetrics {
    init_system();

    let mut sys_guard = SYSTEM.write();
    let sys = sys_guard.as_mut();

    let (cpu_usage, memory_used, memory_total, process_count) = if let Some(s) = sys {
        s.refresh_all();

        let cpus = s.cpus();
        let cpu = if !cpus.is_empty() {
            cpus.iter().map(|c| c.cpu_usage()).sum::<f32>() / cpus.len() as f32
        } else {
            0.0
        };

        let mem_used = s.used_memory() as f64 / 1024.0 / 1024.0;
        let mem_total = s.total_memory() as f64 / 1024.0 / 1024.0;
        let procs = s.processes().len();

        (cpu, mem_used, mem_total, procs)
    } else {
        (0.0, 0.0, 0.0, 0)
    };

    let mut net_guard = NETWORKS.write();
    let (net_sent, net_recv) = if let Some(networks) = net_guard.as_mut() {
        networks.refresh();
        let mut sent = 0u64;
        let mut recv = 0u64;
        for (_name, data) in networks.iter() {
            sent += data.transmitted();
            recv += data.received();
        }
        (sent, recv)
    } else {
        (0, 0)
    };

    // Count active spikes
    let buffer = PROCESS_EVENTS_BUFFER.read();
    let active_spikes = buffer.iter()
        .filter(|e| e.is_cpu_spike || e.is_memory_spike)
        .count() as u32;

    SystemMetrics {
        cpu_usage,
        memory_used_mb: memory_used,
        memory_total_mb: memory_total,
        memory_percent: if memory_total > 0.0 { (memory_used / memory_total * 100.0) as f32 } else { 0.0 },
        network_sent_rate: net_sent,
        network_recv_rate: net_recv,
        process_count,
        events_collected: TOTAL_EVENTS.load(Ordering::SeqCst),
        summaries_created: TOTAL_SUMMARIES.load(Ordering::SeqCst),
        active_spikes,
    }
}

pub fn get_running_processes(limit: usize) -> Vec<ProcessInfo> {
    init_system();

    let mut sys_guard = SYSTEM.write();
    let sys = match sys_guard.as_mut() {
        Some(s) => s,
        None => return vec![],
    };

    sys.refresh_processes();

    let history_guard = PROCESS_HISTORY.read();

    let mut processes: Vec<ProcessInfo> = sys.processes()
        .iter()
        .map(|(pid, proc)| {
            let pid_u32 = pid.as_u32();
            let is_spike = history_guard.as_ref()
                .and_then(|h| h.get(&pid_u32))
                .map(|hist| hist.spike_count > 0)
                .unwrap_or(false);

            ProcessInfo {
                pid: pid_u32,
                name: proc.name().to_string(),
                cpu_percent: proc.cpu_usage(),
                memory_mb: proc.memory() as f64 / 1024.0 / 1024.0,
                status: format!("{:?}", proc.status()),
                is_spike,
            }
        })
        .collect();

    processes.sort_by(|a, b| b.cpu_percent.partial_cmp(&a.cpu_percent).unwrap_or(std::cmp::Ordering::Equal));
    processes.truncate(limit);

    processes
}

pub fn get_recent_events(limit: usize) -> Vec<ProcessEvent> {
    let buffer = PROCESS_EVENTS_BUFFER.read();
    let start = if buffer.len() > limit { buffer.len() - limit } else { 0 };
    buffer[start..].to_vec()
}

pub fn get_pending_summaries() -> Vec<SummaryVector> {
    let queue = SUMMARY_QUEUE.read();
    queue.iter().filter(|s| !s.processed).cloned().collect()
}

/// Get ALL summaries (for training data export)
pub fn get_all_summaries() -> Vec<SummaryVector> {
    let queue = SUMMARY_QUEUE.read();
    queue.clone()
}

pub fn mark_summary_processed(id: &str, ml_score: f32, tag_score: f32, final_score: f32, tags: Vec<String>) {
    let mut queue = SUMMARY_QUEUE.write();
    if let Some(summary) = queue.iter_mut().find(|s| s.id == id) {
        summary.processed = true;
        summary.ml_score = Some(ml_score);
        summary.tag_score = Some(tag_score);
        summary.final_score = Some(final_score);
        summary.tags = tags;
    }
}

pub fn get_total_events() -> u64 {
    TOTAL_EVENTS.load(Ordering::SeqCst)
}

pub fn get_total_summaries() -> u64 {
    TOTAL_SUMMARIES.load(Ordering::SeqCst)
}

pub fn reset() {
    IS_RUNNING.store(false, Ordering::SeqCst);
    TOTAL_EVENTS.store(0, Ordering::SeqCst);
    TOTAL_SUMMARIES.store(0, Ordering::SeqCst);
    PROCESS_EVENTS_BUFFER.write().clear();
    SUMMARY_QUEUE.write().clear();
    *PROCESS_HISTORY.write() = None;
}

// ============================================================================
// LEGACY COMPATIBILITY (for commands.rs)
// ============================================================================

/// Legacy RawEvent (backwards compatible)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub process_id: u32,
    pub process_name: String,
    pub cpu_percent: f32,
    pub memory_mb: f64,
    pub network_sent_bytes: u64,
    pub network_recv_bytes: u64,
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
}

impl From<ProcessEvent> for RawEvent {
    fn from(e: ProcessEvent) -> Self {
        RawEvent {
            id: e.id,
            timestamp: e.timestamp,
            process_id: e.pid,
            process_name: e.name,
            cpu_percent: e.cpu_percent,
            memory_mb: e.memory_mb,
            network_sent_bytes: e.network_sent_bytes,
            network_recv_bytes: e.network_recv_bytes,
            disk_read_bytes: e.disk_read_bytes,
            disk_write_bytes: e.disk_write_bytes,
        }
    }
}
