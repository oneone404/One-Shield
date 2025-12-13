//! AI Security Core - Main Entry Point (PHASE X - Cloud Backend)

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod api;
mod logic;
pub mod constants;

use api::commands;
use api::enterprise;
use api::advanced_detection;
use api::cloud_sync;

// --- Window Control Commands (Manual Implementation) ---
#[tauri::command]
async fn window_minimize(window: tauri::Window) {
    let _ = window.minimize();
}

#[tauri::command]
async fn window_toggle_maximize(window: tauri::Window) {
    if let Ok(is_max) = window.is_maximized() {
        if is_max {
            let _ = window.unmaximize();
        } else {
            let _ = window.maximize();
        }
    }
}

#[tauri::command]
async fn window_close(window: tauri::Window) {
    let _ = window.close();
}

#[tauri::command]
async fn window_start_drag(window: tauri::Window) {
    let _ = window.start_dragging();
}

#[tauri::command]
async fn show_main_window(window: tauri::Window) {
    let _ = window.show();
    let _ = window.set_focus();
}
// -----------------------------------------------------

fn main() {
    #[cfg(debug_assertions)]
    {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
            .init();
    }

    log::info!("Starting AI Security App v2.2.0 (Phase VIII - Advanced Detection)...");

    logic::baseline::init();

    if let Err(e) = logic::ai_bridge::init() {
        log::warn!("AI Bridge init: {}", e);
    } else if logic::ai_bridge::is_model_loaded() {
        log::info!("ONNX model loaded successfully");
    } else {
        log::info!("ONNX model not found - using fallback heuristics");
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            // Initialize event system with AppHandle
            logic::events::init(app.handle().clone());
            log::info!("Event system initialized");

            // Initialize telemetry (security logging)
            if let Err(e) = logic::telemetry::init(None) {
                log::warn!("Telemetry init failed: {} - events will not be recorded", e);
            } else {
                log::info!("Telemetry system initialized");
            }

            // Start Analysis Engine Loop (Bridges Collector -> Incident)
            logic::analysis_loop::start();

            // Start Cloud Sync Loop (Phase 10)
            logic::cloud_sync::init();
            let sync_config = logic::cloud_sync::SyncConfig::default();
            log::info!("🌐 Cloud Sync: Starting background sync...");
            log::info!("   Server: {}", sync_config.server_url);
            log::info!("   Heartbeat: {}s", sync_config.heartbeat_interval_secs);

            // Spawn cloud sync in background task
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("Failed to create tokio runtime for cloud sync");

                rt.block_on(async {
                    logic::cloud_sync::start_sync_loop(sync_config).await;
                });
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // Window Controls (Manual)
            window_minimize,
            window_toggle_maximize,
            window_close,
            window_start_drag,
            show_main_window,

            // System Commands
            commands::get_system_status,
            commands::get_cpu_usage,
            commands::get_memory_usage,
            commands::get_running_processes,

            // Collector Commands
            commands::start_collector,
            commands::stop_collector,
            commands::get_raw_events,
            commands::get_process_events,

            // Summary Commands
            commands::get_summary_logs,

            // Baseline Commands
            commands::get_baseline_profile,
            commands::update_baseline,
            commands::get_anomaly_tags,
            commands::get_severity_matrix,
            commands::get_global_baseline,

            // Guard Commands
            commands::load_model,
            commands::verify_model_checksum,

            // AI Commands (Legacy)
            commands::run_prediction,
            commands::get_ml_score,

            // Analysis Commands
            commands::get_analysis_history,

            // Log Commands
            commands::export_logs,
            commands::get_statistics,
            commands::reset_system,

            // Action Guard Commands (Phase III)
            commands::get_action_guard_status,
            commands::get_pending_actions,
            commands::approve_action,
            commands::cancel_action,
            commands::get_action_history,
            commands::kill_process,
            commands::suspend_process,
            commands::add_to_whitelist,
            commands::remove_from_whitelist,
            commands::get_whitelist,

            // ONNX AI Commands (Phase IV)
            commands::load_onnx_model,
            commands::init_ai_bridge,
            commands::is_model_loaded,
            commands::get_model_metadata,
            commands::run_onnx_prediction,
            commands::push_and_predict,
            commands::clear_prediction_buffer,
            commands::get_buffer_status,

            // GPU Commands (v0.5.0)
            commands::get_gpu_info,
            commands::get_gpu_metrics,

            // AI Status Commands (v0.5.0)
            commands::get_ai_status,

            // Training Data Commands
            commands::export_training_data,
            commands::get_training_data_count,

            // Telemetry Commands (v0.6.1)
            commands::get_telemetry_stats,
            commands::get_security_analytics,
            commands::get_security_log_files,
            commands::get_recent_security_events,

            // Engine Status (P2.1)
            commands::get_engine_status,
            commands::export_dataset,
            commands::submit_user_feedback,
            commands::get_incidents,
            commands::get_incident_detail,

            // Enterprise Commands (Phase 7)
            enterprise::enterprise_login,
            enterprise::enterprise_logout,
            enterprise::validate_session,
            enterprise::get_current_user,
            enterprise::get_users,
            enterprise::create_user,
            enterprise::get_rbac_stats,
            enterprise::get_policies,
            enterprise::get_policy,
            enterprise::sync_policies,
            enterprise::get_policy_sync_status,
            enterprise::get_quarantined_files,
            enterprise::quarantine_file,
            enterprise::restore_quarantined_file,
            enterprise::delete_quarantined_file,
            enterprise::get_quarantine_stats,
            enterprise::get_webhooks,
            enterprise::add_webhook,
            enterprise::remove_webhook,
            enterprise::test_webhook,
            enterprise::get_executive_report,
            enterprise::get_incident_summary,
            enterprise::get_endpoint_stats,
            enterprise::user_logout,

            // Advanced Detection Commands (Phase 8)
            advanced_detection::init_advanced_detection,
            advanced_detection::is_advanced_detection_ready,
            advanced_detection::scan_script,
            advanced_detection::is_script_malicious,
            advanced_detection::get_amsi_stats,
            advanced_detection::analyze_process_injection,
            advanced_detection::get_injection_alerts,
            advanced_detection::get_injection_stats,
            advanced_detection::scan_memory,
            advanced_detection::scan_file_shellcode,
            advanced_detection::get_memory_stats,
            advanced_detection::get_threat_alerts,
            advanced_detection::get_advanced_detection_stats,

            // Keylogger Detection Commands (Phase 9)
            advanced_detection::get_keylogger_alerts,
            advanced_detection::get_keylogger_stats,
            advanced_detection::check_process_keylogger,

            // IAT Analysis Commands (Phase 9)
            advanced_detection::analyze_file_imports,
            advanced_detection::analyze_api_imports,
            advanced_detection::get_iat_stats,
            advanced_detection::clear_iat_cache,

            // Cloud Sync Commands (Phase 10)
            cloud_sync::get_cloud_sync_status,
            cloud_sync::is_cloud_connected,
            cloud_sync::get_cloud_sync_config,
            cloud_sync::update_cloud_sync_config,
            cloud_sync::queue_incident_for_sync,
            cloud_sync::get_pending_incidents_count,

            // Personal Auth Commands (Phase 13)
            cloud_sync::get_agent_mode,
            cloud_sync::personal_enroll,
            cloud_sync::has_user_jwt,
            cloud_sync::get_user_jwt,
        ])
        .run(tauri::generate_context!())
        .expect("Lỗi khi khởi chạy ứng dụng Tauri");
}
