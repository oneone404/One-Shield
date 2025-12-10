//! AI Security Core - Main Entry Point (PHASE IV - ONNX Native)

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod api;
mod logic;

use api::commands;

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

    log::info!("Starting AI Security App v0.5.0 (Phase V - Modular Architecture)...");

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
        ])
        .run(tauri::generate_context!())
        .expect("Lỗi khi khởi chạy ứng dụng Tauri");
}
