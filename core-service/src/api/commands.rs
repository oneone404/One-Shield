//! Tauri Commands - API cho Frontend (PHASE IV - ONNX Native)
//!
//! Hỗ trợ 15 Features, Severity Scoring, ProcessEvent chi tiết, Action Guard, và ONNX Inference.

use serde::{Deserialize, Serialize};
use crate::logic::{collector, baseline, guard, action_guard, ai_bridge};

// ============================================================================
// DATA STRUCTURES - ENHANCED
// ============================================================================

/// Trạng thái hệ thống
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStatus {
    pub is_monitoring: bool,
    pub cpu_usage: f32,
    pub memory_usage: f32,
    pub memory_used_mb: f64,
    pub memory_total_mb: f64,
    pub network_sent_rate: u64,
    pub network_recv_rate: u64,
    pub process_count: usize,
    pub events_collected: u64,
    pub summaries_created: u64,
    pub anomalies_detected: u32,
    pub active_spikes: u32,
    pub last_scan_time: Option<String>,
}

/// Process Event (Enhanced)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEventInfo {
    pub id: String,
    pub timestamp: String,
    pub pid: u32,
    pub name: String,
    pub cpu_percent: f32,
    pub memory_mb: f64,
    pub disk_read_rate: f64,
    pub disk_write_rate: f64,
    pub is_cpu_spike: bool,
    pub is_memory_spike: bool,
    pub is_new_process: bool,
}

/// Sự kiện thô (Raw Event) cho Frontend - Legacy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawEvent {
    pub id: String,
    pub timestamp: String,
    pub process_name: String,
    pub process_id: u32,
    pub cpu_percent: f32,
    pub memory_mb: f64,
    pub network_sent: u64,
    pub network_recv: u64,
    pub disk_read: u64,
    pub disk_write: u64,
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

/// Summary Log (15 features) - ENHANCED
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SummaryLog {
    pub id: String,
    pub timestamp: String,
    pub features: Vec<f32>,  // 15 features
    pub ml_score: Option<f32>,
    pub tag_score: Option<f32>,
    pub final_score: Option<f32>,
    pub tags: Vec<String>,
    pub is_anomaly: bool,
    pub processed: bool,
    pub spike_events: u32,
    pub severity_level: String,
}

/// Baseline Profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineProfile {
    pub app_name: String,
    pub avg_cpu: f32,
    pub avg_memory: f32,
    pub avg_network: f32,
    pub typical_hours: Vec<u8>,
    pub last_updated: String,
}

/// Kết quả dự đoán từ AI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredictionResult {
    pub ml_score: f32,
    pub tag_score: f32,
    pub final_score: f32,
    pub is_anomaly: bool,
    pub confidence: f32,
    pub tags: Vec<String>,
    pub severity_level: String,
}

/// Tag Detail với Severity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagInfo {
    pub tag: String,
    pub severity: f32,
    pub description: String,
}

// ============================================================================
// SYSTEM COMMANDS (LIVE DATA)
// ============================================================================

/// Lấy trạng thái tổng quan của hệ thống (LIVE)
#[tauri::command]
pub async fn get_system_status() -> Result<SystemStatus, String> {
    let metrics = collector::get_system_metrics();
    let is_monitoring = collector::is_running();
    let anomaly_count = baseline::get_anomaly_count();

    Ok(SystemStatus {
        is_monitoring,
        cpu_usage: metrics.cpu_usage,
        memory_usage: metrics.memory_percent,
        memory_used_mb: metrics.memory_used_mb,
        memory_total_mb: metrics.memory_total_mb,
        network_sent_rate: metrics.network_sent_rate,
        network_recv_rate: metrics.network_recv_rate,
        process_count: metrics.process_count,
        events_collected: metrics.events_collected,
        summaries_created: metrics.summaries_created,
        anomalies_detected: anomaly_count,
        active_spikes: metrics.active_spikes,
        last_scan_time: Some(chrono::Utc::now().to_rfc3339()),
    })
}

/// Lấy CPU usage hiện tại (LIVE)
#[tauri::command]
pub async fn get_cpu_usage() -> Result<f32, String> {
    let metrics = collector::get_system_metrics();
    Ok(metrics.cpu_usage)
}

/// Lấy Memory usage hiện tại (LIVE)
#[tauri::command]
pub async fn get_memory_usage() -> Result<f32, String> {
    let metrics = collector::get_system_metrics();
    Ok(metrics.memory_percent)
}

/// Lấy danh sách processes đang chạy (LIVE)
#[tauri::command]
pub async fn get_running_processes(limit: Option<usize>) -> Result<Vec<ProcessInfo>, String> {
    let limit = limit.unwrap_or(50);
    let processes = collector::get_running_processes(limit);

    Ok(processes.into_iter().map(|p| ProcessInfo {
        pid: p.pid,
        name: p.name,
        cpu_percent: p.cpu_percent,
        memory_mb: p.memory_mb,
        status: p.status,
        is_spike: p.is_spike,
    }).collect())
}

// ============================================================================
// COLLECTOR COMMANDS
// ============================================================================

/// Bắt đầu thu thập events
#[tauri::command]
pub async fn start_collector() -> Result<bool, String> {
    collector::start().await.map_err(|e| e.to_string())
}

/// Dừng thu thập events
#[tauri::command]
pub async fn stop_collector() -> Result<bool, String> {
    collector::stop().await.map_err(|e| e.to_string())
}

/// Lấy danh sách raw events gần đây (LIVE)
#[tauri::command]
pub async fn get_raw_events(limit: Option<u32>) -> Result<Vec<RawEvent>, String> {
    let limit = limit.unwrap_or(100) as usize;
    let events = collector::get_recent_events(limit);

    Ok(events.into_iter().map(|e| RawEvent {
        id: e.id,
        timestamp: e.timestamp.to_rfc3339(),
        process_name: e.name,
        process_id: e.pid,
        cpu_percent: e.cpu_percent,
        memory_mb: e.memory_mb,
        network_sent: e.network_sent_bytes,
        network_recv: e.network_recv_bytes,
        disk_read: e.disk_read_bytes,
        disk_write: e.disk_write_bytes,
    }).collect())
}

/// Lấy Process Events chi tiết (ENHANCED)
#[tauri::command]
pub async fn get_process_events(limit: Option<u32>) -> Result<Vec<ProcessEventInfo>, String> {
    let limit = limit.unwrap_or(100) as usize;
    let events = collector::get_recent_events(limit);

    Ok(events.into_iter().map(|e| ProcessEventInfo {
        id: e.id,
        timestamp: e.timestamp.to_rfc3339(),
        pid: e.pid,
        name: e.name,
        cpu_percent: e.cpu_percent,
        memory_mb: e.memory_mb,
        disk_read_rate: e.disk_read_rate,
        disk_write_rate: e.disk_write_rate,
        is_cpu_spike: e.is_cpu_spike,
        is_memory_spike: e.is_memory_spike,
        is_new_process: e.is_new_process,
    }).collect())
}

// ============================================================================
// SUMMARY COMMANDS (15 FEATURES)
// ============================================================================

/// Lấy danh sách summary logs (ENHANCED - 15 features)
#[tauri::command]
pub async fn get_summary_logs(limit: Option<u32>, _offset: Option<u32>) -> Result<Vec<SummaryLog>, String> {
    let summaries = collector::get_pending_summaries();
    let limit = limit.unwrap_or(50) as usize;

    Ok(summaries.into_iter().take(limit).map(|s| {
        let severity = if s.final_score.unwrap_or(0.0) >= 0.8 {
            "Critical"
        } else if s.final_score.unwrap_or(0.0) >= 0.6 {
            "High"
        } else if s.final_score.unwrap_or(0.0) >= 0.4 {
            "Medium"
        } else {
            "Low"
        };

        SummaryLog {
            id: s.id,
            timestamp: s.created_at.to_rfc3339(),
            features: s.features.to_vec(),
            ml_score: s.ml_score,
            tag_score: s.tag_score,
            final_score: s.final_score,
            tags: s.tags,
            is_anomaly: s.final_score.map(|f| f >= 0.6).unwrap_or(false),
            processed: s.processed,
            spike_events: s.spike_events,
            severity_level: severity.to_string(),
        }
    }).collect())
}

// ============================================================================
// BASELINE COMMANDS
// ============================================================================

/// Lấy baseline profile của một app
#[tauri::command]
pub async fn get_baseline_profile(app_name: String) -> Result<Option<BaselineProfile>, String> {
    baseline::get_profile(&app_name).await.map_err(|e| e.to_string())
}

/// Cập nhật baseline profile
#[tauri::command]
pub async fn update_baseline(app_name: String) -> Result<bool, String> {
    baseline::update(&app_name).await.map_err(|e| e.to_string())
}

/// Lấy anomaly tags từ Tag Engine
#[tauri::command]
pub async fn get_anomaly_tags(summary_id: String) -> Result<Vec<String>, String> {
    baseline::get_tags(&summary_id).await.map_err(|e| e.to_string())
}

/// Lấy Severity Matrix
#[tauri::command]
pub async fn get_severity_matrix() -> Result<serde_json::Value, String> {
    Ok(baseline::get_severity_matrix())
}

/// Lấy Global Baseline hiện tại
#[tauri::command]
pub async fn get_global_baseline() -> Result<serde_json::Value, String> {
    if let Some(baseline) = baseline::get_global_baseline() {
        Ok(serde_json::json!({
            "avg_cpu": baseline.avg_cpu,
            "avg_memory": baseline.avg_memory,
            "avg_cpu_spike_rate": baseline.avg_cpu_spike_rate,
            "avg_memory_spike_rate": baseline.avg_memory_spike_rate,
            "avg_churn_rate": baseline.avg_churn_rate,
            "sample_count": baseline.sample_count,
            "typical_hours": baseline.typical_hours,
            "last_updated": baseline.last_updated.to_rfc3339(),
        }))
    } else {
        Ok(serde_json::json!(null))
    }
}

// ============================================================================
// GUARD COMMANDS (Model Protection)
// ============================================================================

/// Tải và giải mã model vào RAM
#[tauri::command]
pub async fn load_model() -> Result<bool, String> {
    guard::load_model().await.map_err(|e| e.to_string())
}

/// Xác minh checksum của model
#[tauri::command]
pub async fn verify_model_checksum() -> Result<bool, String> {
    guard::verify_checksum().await.map_err(|e| e.to_string())
}

// ============================================================================
// AI COMMANDS - ENHANCED
// ============================================================================

/// Chạy dự đoán trên summary log (15 features)
#[tauri::command]
pub async fn run_prediction(features: Vec<f32>) -> Result<PredictionResult, String> {
    // Validate features count
    if features.len() != 15 {
        return Err(format!("Expected 15 features, got {}", features.len()));
    }

    // Convert to fixed array
    let mut features_arr = [0.0f32; 15];
    features_arr.copy_from_slice(&features);

    // For now, use simple heuristic ML score (until Python model is integrated)
    let ml_score = calculate_simple_ml_score(&features_arr);

    // Run full analysis
    let result = baseline::analyze_summary_15(
        &uuid::Uuid::new_v4().to_string(),
        &features_arr,
        ml_score,
    );

    Ok(PredictionResult {
        ml_score: result.ml_score,
        tag_score: result.tag_score,
        final_score: result.final_score,
        is_anomaly: result.is_anomaly,
        confidence: result.confidence,
        tags: result.tags,
        severity_level: result.severity_level,
    })
}

/// Simple ML score calculation (placeholder until Python model)
fn calculate_simple_ml_score(features: &[f32; 15]) -> f32 {
    // Weighted sum of normalized features
    let weights = [
        0.15, 0.10, 0.10, 0.05, // CPU, Memory
        0.05, 0.05, 0.05, 0.05, // Network, Disk
        0.05, 0.05,              // Processes, Network ratio
        0.10, 0.10, 0.05, 0.03, 0.02, // Feature crosses
    ];

    let thresholds = [
        50.0, 80.0, 500.0, 1000.0,
        15.0, 15.0, 10.0, 10.0,
        100.0, 0.9,
        0.2, 0.2, 0.3, 10.0, 1.0,
    ];

    let mut score = 0.0f32;
    for (i, &feature) in features.iter().enumerate() {
        if feature > thresholds[i] {
            let excess = (feature - thresholds[i]) / thresholds[i];
            score += weights[i] * excess.min(1.0);
        }
    }

    score.min(1.0)
}

/// Lấy ML score của summary log cụ thể
#[tauri::command]
pub async fn get_ml_score(summary_id: String) -> Result<f32, String> {
    let summaries = collector::get_pending_summaries();
    if let Some(summary) = summaries.iter().find(|s| s.id == summary_id) {
        Ok(summary.ml_score.unwrap_or(0.0))
    } else {
        Ok(0.0)
    }
}

// ============================================================================
// ANALYSIS COMMANDS
// ============================================================================

/// Lấy lịch sử phân tích
#[tauri::command]
pub async fn get_analysis_history(limit: Option<usize>) -> Result<Vec<serde_json::Value>, String> {
    let limit = limit.unwrap_or(50);
    let history = baseline::get_analysis_history(limit);

    Ok(history.into_iter().map(|r| serde_json::json!({
        "summary_id": r.summary_id,
        "ml_score": r.ml_score,
        "tag_score": r.tag_score,
        "final_score": r.final_score,
        "is_anomaly": r.is_anomaly,
        "tags": r.tags,
        "severity_level": r.severity_level,
        "confidence": r.confidence,
        "analyzed_at": r.analyzed_at.to_rfc3339(),
    })).collect())
}

// ============================================================================
// LOG COMMANDS
// ============================================================================

/// Export logs ra file
#[tauri::command]
pub async fn export_logs(path: String, format: String) -> Result<bool, String> {
    let summaries = collector::get_pending_summaries();

    let content = match format.as_str() {
        "json" => serde_json::to_string_pretty(&summaries)
            .map_err(|e| e.to_string())?,
        "csv" => {
            let mut csv = String::from("id,timestamp,spike_events,processed,ml_score,tag_score,final_score,tags\n");
            for s in &summaries {
                csv.push_str(&format!(
                    "{},{},{},{},{:?},{:?},{:?},{}\n",
                    s.id, s.created_at, s.spike_events, s.processed,
                    s.ml_score, s.tag_score, s.final_score, s.tags.join(";")
                ));
            }
            csv
        },
        _ => return Err("Format không hỗ trợ (json, csv)".to_string()),
    };

    std::fs::write(&path, content).map_err(|e| e.to_string())?;
    log::info!("Exported {} summaries to {}", summaries.len(), path);

    Ok(true)
}

/// Lấy thống kê tổng quan
#[tauri::command]
pub async fn get_statistics() -> Result<serde_json::Value, String> {
    let metrics = collector::get_system_metrics();
    let summaries = collector::get_pending_summaries();
    let anomaly_count = baseline::get_anomaly_count();

    let high_severity_count = summaries.iter()
        .filter(|s| s.final_score.map(|f| f >= 0.6).unwrap_or(false))
        .count();

    Ok(serde_json::json!({
        "total_events": metrics.events_collected,
        "total_summaries": metrics.summaries_created,
        "pending_summaries": summaries.len(),
        "anomalies_detected": anomaly_count,
        "high_severity_count": high_severity_count,
        "active_spikes": metrics.active_spikes,
        "is_monitoring": collector::is_running(),
        "features_count": 15,
    }))
}

/// Reset hệ thống (cho testing)
#[tauri::command]
pub async fn reset_system() -> Result<bool, String> {
    collector::reset();
    baseline::reset_baseline();
    action_guard::reset();
    log::info!("System reset completed");
    Ok(true)
}

// ============================================================================
// TRAINING DATA COMMANDS
// ============================================================================

/// Export training data (Summary Vectors) ra file JSON
#[tauri::command]
pub async fn export_training_data(path: String) -> Result<serde_json::Value, String> {
    let summaries = collector::get_all_summaries();

    // Convert to training format
    let training_data: Vec<serde_json::Value> = summaries.iter()
        .filter(|s| !s.is_anomaly()) // Chỉ lấy data bình thường
        .map(|s| {
            serde_json::json!({
                "features": s.features.to_vec(),
                "timestamp": s.timestamp().to_rfc3339(),
                "id": s.id,
            })
        })
        .collect();

    let export = serde_json::json!({
        "version": "1.0",
        "exported_at": chrono::Utc::now().to_rfc3339(),
        "total_samples": training_data.len(),
        "feature_count": 15,
        "data": training_data,
    });

    // Write to file
    let json_str = serde_json::to_string_pretty(&export)
        .map_err(|e| format!("JSON error: {}", e))?;

    std::fs::write(&path, json_str)
        .map_err(|e| format!("File write error: {}", e))?;

    log::info!("Exported {} training samples to {}", training_data.len(), path);

    Ok(serde_json::json!({
        "success": true,
        "path": path,
        "samples": training_data.len(),
    }))
}

/// Lấy số lượng training data hiện có
#[tauri::command]
pub async fn get_training_data_count() -> Result<serde_json::Value, String> {
    let summaries = collector::get_all_summaries();
    let normal_count = summaries.iter().filter(|s| !s.is_anomaly()).count();
    let anomaly_count = summaries.iter().filter(|s| s.is_anomaly()).count();

    Ok(serde_json::json!({
        "total": summaries.len(),
        "normal": normal_count,
        "anomaly": anomaly_count,
        "ready_for_training": normal_count >= 100, // Cần ít nhất 100 samples
        "recommended_samples": 500,
    }))
}

// ============================================================================
// ACTION GUARD COMMANDS (PHASE III)
// ============================================================================

/// Lấy trạng thái Action Guard
#[tauri::command]
pub async fn get_action_guard_status() -> Result<serde_json::Value, String> {
    Ok(action_guard::get_status())
}

/// Lấy danh sách pending actions
#[tauri::command]
pub async fn get_pending_actions() -> Result<Vec<serde_json::Value>, String> {
    let pending = action_guard::get_pending_actions();
    Ok(pending.into_iter().map(|a| serde_json::json!({
        "id": a.id,
        "action_type": format!("{:?}", a.action_type),
        "target_pid": a.target_pid,
        "target_name": a.target_name,
        "final_score": a.final_score,
        "reason": a.reason,
        "created_at": a.created_at.to_rfc3339(),
        "expires_at": a.expires_at.to_rfc3339(),
    })).collect())
}

/// Approve một pending action
#[tauri::command]
pub async fn approve_action(action_id: String) -> Result<serde_json::Value, String> {
    match action_guard::approve_action(&action_id) {
        Ok(result) => Ok(serde_json::json!({
            "success": result.success,
            "action_type": format!("{:?}", result.action_type),
            "target_pid": result.target_pid,
            "message": result.message,
            "executed_at": result.executed_at.to_rfc3339(),
        })),
        Err(e) => Err(e.to_string()),
    }
}

/// Cancel một pending action
#[tauri::command]
pub async fn cancel_action(action_id: String) -> Result<bool, String> {
    action_guard::cancel_action(&action_id).map_err(|e| e.to_string())?;
    Ok(true)
}

/// Lấy lịch sử actions
#[tauri::command]
pub async fn get_action_history(limit: Option<usize>) -> Result<Vec<serde_json::Value>, String> {
    let limit = limit.unwrap_or(50);
    let history = action_guard::get_action_history(limit);

    Ok(history.into_iter().map(|a| serde_json::json!({
        "id": a.id,
        "action_type": format!("{:?}", a.action_type),
        "target_pid": a.target_pid,
        "target_name": a.target_name,
        "final_score": a.final_score,
        "tags": a.tags,
        "status": format!("{:?}", a.status),
        "result": a.result,
        "executed_at": a.executed_at.to_rfc3339(),
        "auto_executed": a.auto_executed,
    })).collect())
}

/// Kill một process (manual action)
#[tauri::command]
pub async fn kill_process(pid: u32) -> Result<serde_json::Value, String> {
    match action_guard::kill_process(pid) {
        Ok(result) => Ok(serde_json::json!({
            "success": result.success,
            "message": result.message,
        })),
        Err(e) => Err(e.to_string()),
    }
}

/// Suspend một process
#[tauri::command]
pub async fn suspend_process(pid: u32) -> Result<serde_json::Value, String> {
    match action_guard::suspend_process(pid) {
        Ok(result) => Ok(serde_json::json!({
            "success": result.success,
            "message": result.message,
        })),
        Err(e) => Err(e.to_string()),
    }
}

/// Thêm process vào whitelist
#[tauri::command]
pub async fn add_to_whitelist(process_name: String) -> Result<bool, String> {
    action_guard::add_to_whitelist(&process_name);
    Ok(true)
}

/// Xóa process khỏi whitelist
#[tauri::command]
pub async fn remove_from_whitelist(process_name: String) -> Result<bool, String> {
    action_guard::remove_from_whitelist(&process_name);
    Ok(true)
}

/// Lấy danh sách whitelist
#[tauri::command]
pub async fn get_whitelist() -> Result<Vec<String>, String> {
    Ok(action_guard::get_whitelist())
}

// ============================================================================
// ONNX AI COMMANDS (PHASE IV)
// ============================================================================

/// Load ONNX model
#[tauri::command]
pub async fn load_onnx_model(model_path: String) -> Result<bool, String> {
    ai_bridge::load_onnx_model(&model_path).map_err(|e| e.to_string())?;
    Ok(true)
}

/// Initialize AI Bridge (auto-load model)
#[tauri::command]
pub async fn init_ai_bridge() -> Result<bool, String> {
    ai_bridge::init().map_err(|e| e.to_string())?;
    Ok(ai_bridge::is_model_loaded())
}

/// Check if ONNX model is loaded
#[tauri::command]
pub async fn is_model_loaded() -> Result<bool, String> {
    Ok(ai_bridge::is_model_loaded())
}

/// Get model metadata
#[tauri::command]
pub async fn get_model_metadata() -> Result<serde_json::Value, String> {
    match ai_bridge::get_metadata() {
        Some(metadata) => Ok(serde_json::json!({
            "model_path": metadata.model_path,
            "model_type": metadata.model_type,
            "sequence_length": metadata.sequence_length,
            "features": metadata.features,
            "threshold": metadata.threshold,
            "loaded_at": metadata.loaded_at.to_rfc3339(),
        })),
        None => Ok(serde_json::json!(null)),
    }
}

/// Run ONNX prediction on sequence
#[tauri::command]
pub async fn run_onnx_prediction(sequence: Vec<Vec<f32>>) -> Result<serde_json::Value, String> {
    // Convert to fixed arrays
    let sequence_arr: Result<Vec<[f32; 15]>, _> = sequence.iter()
        .map(|v| {
            if v.len() != 15 {
                return Err(format!("Expected 15 features, got {}", v.len()));
            }
            let mut arr = [0.0f32; 15];
            arr.copy_from_slice(v);
            Ok(arr)
        })
        .collect();

    let sequence_arr = sequence_arr?;

    let result = ai_bridge::predict(&sequence_arr);

    Ok(serde_json::json!({
        "score": result.score,
        "is_anomaly": result.is_anomaly,
        "confidence": result.confidence,
        "raw_mse": result.raw_mse,
        "threshold": result.threshold,
        "inference_time_us": result.inference_time_us,
        "method": result.method,
    }))
}

/// Push features to buffer and get prediction if ready
#[tauri::command]
pub async fn push_and_predict(features: Vec<f32>) -> Result<Option<serde_json::Value>, String> {
    if features.len() != 15 {
        return Err(format!("Expected 15 features, got {}", features.len()));
    }

    let mut features_arr = [0.0f32; 15];
    features_arr.copy_from_slice(&features);

    match ai_bridge::push_and_predict(features_arr) {
        Some(result) => Ok(Some(serde_json::json!({
            "score": result.score,
            "is_anomaly": result.is_anomaly,
            "confidence": result.confidence,
            "raw_mse": result.raw_mse,
            "threshold": result.threshold,
            "inference_time_us": result.inference_time_us,
            "method": result.method,
        }))),
        None => Ok(None),
    }
}

/// Clear AI prediction buffer
#[tauri::command]
pub async fn clear_prediction_buffer() -> Result<bool, String> {
    ai_bridge::clear_buffer();
    Ok(true)
}

/// Get buffer status
#[tauri::command]
pub async fn get_buffer_status() -> Result<serde_json::Value, String> {
    let has_data = ai_bridge::has_enough_data();
    let metadata = ai_bridge::get_metadata();

    Ok(serde_json::json!({
        "has_enough_data": has_data,
        "model_loaded": ai_bridge::is_model_loaded(),
        "sequence_length": metadata.map(|m| m.sequence_length).unwrap_or(5),
    }))
}
