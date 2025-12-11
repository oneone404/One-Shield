/**
 * Tauri API Service - LIVE DATA
 *
 * Bridge giữa React frontend và Rust backend.
 */

// Check if running in Tauri
const isTauri = () => {
    return typeof window !== 'undefined' && window.__TAURI_INTERNALS__;
}

// Dynamic import Tauri API
export let invoke = async (cmd, args = {}) => {
    if (isTauri()) {
        const { invoke: tauriInvoke } = await import('@tauri-apps/api/core');
        return tauriInvoke(cmd, args);
    }
    // Mock mode for development without Tauri
    console.log(`[Mock] Invoke: ${cmd}`, args);
    return getMockResponse(cmd, args);
}

// Mock responses for development (simulate live data)
function getMockResponse(cmd, args) {
    const now = new Date().toISOString();

    const mocks = {
        get_system_status: {
            is_monitoring: Math.random() > 0.5,
            cpu_usage: 20 + Math.random() * 40,
            cpu_name: 'AMD Ryzen 9 5900X 12-Core Processor',
            memory_usage: 40 + Math.random() * 30,
            memory_used_mb: 4000 + Math.random() * 4000,
            memory_total_mb: 16384,
            network_sent_rate: Math.floor(Math.random() * 10000000),
            network_recv_rate: Math.floor(Math.random() * 50000000),
            process_count: 80 + Math.floor(Math.random() * 50),
            events_collected: Math.floor(Math.random() * 10000),
            summaries_created: Math.floor(Math.random() * 100),
            anomalies_detected: Math.floor(Math.random() * 5),
            last_scan_time: now,
        },
        get_cpu_usage: 20 + Math.random() * 40,
        get_memory_usage: 40 + Math.random() * 30,
        get_running_processes: generateMockProcesses(args?.limit || 20),
        start_collector: true,
        stop_collector: true,
        get_raw_events: generateMockEvents(args?.limit || 50),
        get_baseline_profile: null,
        update_baseline: true,
        get_anomaly_tags: [],
        load_model: true,
        verify_model_checksum: true,
        run_prediction: {
            ml_score: Math.random(),
            is_anomaly: Math.random() > 0.8,
            confidence: Math.random(),
            tags: [],
        },
        get_ml_score: Math.random(),
        get_summary_logs: generateMockSummaries(args?.limit || 20),
        export_logs: true,
        get_statistics: {
            total_events: Math.floor(Math.random() * 10000),
            total_summaries: Math.floor(Math.random() * 100),
            pending_summaries: Math.floor(Math.random() * 10),
            anomalies_detected: Math.floor(Math.random() * 5),
            is_monitoring: true,
            uptime_seconds: Math.floor(Math.random() * 3600),
        },
        // GPU (v0.5.0)
        get_gpu_info: {
            available: true,
            name: 'NVIDIA GeForce RTX 3080',
            driver_version: '546.33',
            cuda_version: '12.3',
            memory_total_mb: 10240,
        },
        get_gpu_metrics: {
            available: true,
            gpu_usage: 15 + Math.random() * 40,
            memory_usage: 20 + Math.random() * 30,
            memory_used_mb: 2048 + Math.random() * 3000,
            memory_total_mb: 10240,
            temperature: 45 + Math.random() * 25,
            power_draw: 80 + Math.random() * 150,
            fan_speed: 30 + Math.random() * 40,
        },
        // AI Status (v0.5.0)
        get_ai_status: {
            model: {
                loaded: true,
                type: 'lstm',
                path: 'models/model.onnx',
                sequence_length: 5,
                features: 15,
                threshold: 0.7,
            },
            buffer: {
                current_size: Math.floor(Math.random() * 10),
                required_size: 5,
                fill_percent: Math.random() * 100,
                is_ready: Math.random() > 0.3,
            },
            inference: {
                method: 'onnx',
                ready: true,
            }
        },
    };

    return Promise.resolve(mocks[cmd] ?? null);
}

// Generate mock processes
function generateMockProcesses(count) {
    const processNames = [
        'chrome.exe', 'firefox.exe', 'code.exe', 'node.exe', 'explorer.exe',
        'svchost.exe', 'System', 'csrss.exe', 'dwm.exe', 'taskhostw.exe',
        'SearchHost.exe', 'RuntimeBroker.exe', 'Discord.exe', 'Slack.exe'
    ];

    return Array.from({ length: Math.min(count, processNames.length) }, (_, i) => ({
        pid: 1000 + i * 123,
        name: processNames[i],
        cpu_percent: Math.random() * 30,
        memory_mb: 50 + Math.random() * 500,
        status: 'Run',
    }));
}

// Generate mock events
function generateMockEvents(count) {
    const processNames = ['chrome.exe', 'code.exe', 'node.exe', 'explorer.exe'];

    return Array.from({ length: count }, (_, i) => ({
        id: `evt-${Date.now()}-${i}`,
        timestamp: new Date(Date.now() - i * 10000).toISOString(),
        process_name: processNames[Math.floor(Math.random() * processNames.length)],
        process_id: 1000 + Math.floor(Math.random() * 5000),
        cpu_percent: Math.random() * 50,
        memory_mb: 50 + Math.random() * 500,
        network_sent: Math.floor(Math.random() * 1000000),
        network_recv: Math.floor(Math.random() * 5000000),
        disk_read: Math.floor(Math.random() * 100000),
        disk_write: Math.floor(Math.random() * 100000),
    }));
}

// Generate mock summaries
function generateMockSummaries(count) {
    return Array.from({ length: count }, (_, i) => ({
        id: `sum-${Date.now()}-${i}`,
        timestamp: new Date(Date.now() - i * 60000).toISOString(),
        features: Array.from({ length: 10 }, () => Math.random() * 100),
        ml_score: Math.random() > 0.8 ? 0.7 + Math.random() * 0.3 : Math.random() * 0.5,
        tags: Math.random() > 0.7 ? ['HIGH_CPU', 'UNUSUAL_NETWORK'] : [],
        is_anomaly: Math.random() > 0.8,
        processed: true,
    }));
}

// ============================================================================
// SYSTEM API
// ============================================================================

export async function getSystemStatus() {
    return invoke('get_system_status');
}

export async function getCpuUsage() {
    return invoke('get_cpu_usage');
}

export async function getMemoryUsage() {
    return invoke('get_memory_usage');
}

export async function getRunningProcesses(limit = 50) {
    return invoke('get_running_processes', { limit });
}

// ============================================================================
// COLLECTOR API
// ============================================================================

export async function startCollector() {
    return invoke('start_collector');
}

export async function stopCollector() {
    return invoke('stop_collector');
}

export async function getRawEvents(limit = 100) {
    return invoke('get_raw_events', { limit });
}

// ============================================================================
// SUMMARY API
// ============================================================================

export async function getSummaryLogs(limit = 50, offset = 0) {
    return invoke('get_summary_logs', { limit, offset });
}

// ============================================================================
// BASELINE API
// ============================================================================

export async function getBaselineProfile(appName) {
    return invoke('get_baseline_profile', { appName });
}

export async function updateBaseline(appName) {
    return invoke('update_baseline', { appName });
}

export async function getAnomalyTags(summaryId) {
    return invoke('get_anomaly_tags', { summaryId });
}

// ============================================================================
// GUARD API (Model Protection)
// ============================================================================

export async function loadModel() {
    return invoke('load_model');
}

export async function verifyModelChecksum() {
    return invoke('verify_model_checksum');
}

// ============================================================================
// AI API
// ============================================================================

export async function runPrediction(features) {
    return invoke('run_prediction', { features });
}

export async function getMlScore(summaryId) {
    return invoke('get_ml_score', { summaryId });
}

// ============================================================================
// LOG API
// ============================================================================

export async function exportLogs(path, format = 'json') {
    return invoke('export_logs', { path, format });
}

export async function getStatistics() {
    return invoke('get_statistics');
}

export async function resetSystem() {
    return invoke('reset_system');
}

// ============================================================================
// ACTION GUARD API (Phase III - Proactive Defense)
// ============================================================================

export async function getActionGuardStatus() {
    return invoke('get_action_guard_status');
}

export async function getPendingActions() {
    return invoke('get_pending_actions');
}

export async function approveAction(actionId) {
    return invoke('approve_action', { actionId });
}

export async function cancelAction(actionId) {
    return invoke('cancel_action', { actionId });
}

export async function getActionHistory(limit = 50) {
    return invoke('get_action_history', { limit });
}

export async function killProcess(pid) {
    return invoke('kill_process', { pid });
}

export async function suspendProcess(pid) {
    return invoke('suspend_process', { pid });
}

export async function addToWhitelist(processName) {
    return invoke('add_to_whitelist', { processName });
}

export async function removeFromWhitelist(processName) {
    return invoke('remove_from_whitelist', { processName });
}

export async function getWhitelist() {
    return invoke('get_whitelist');
}

// ============================================================================
// ONNX AI API (Phase IV - Native Inference)
// ============================================================================

export async function loadOnnxModel(modelPath) {
    return invoke('load_onnx_model', { modelPath });
}

export async function initAiBridge() {
    return invoke('init_ai_bridge');
}

export async function isModelLoaded() {
    return invoke('is_model_loaded');
}

export async function getModelMetadata() {
    return invoke('get_model_metadata');
}

export async function runOnnxPrediction(sequence) {
    return invoke('run_onnx_prediction', { sequence });
}

export async function pushAndPredict(features) {
    return invoke('push_and_predict', { features });
}

export async function clearPredictionBuffer() {
    return invoke('clear_prediction_buffer');
}

export async function getBufferStatus() {
    return invoke('get_buffer_status');
}

// ============================================================================
// GPU API (v0.5.0)
// ============================================================================

export async function getGpuInfo() {
    return invoke('get_gpu_info');
}

export async function getGpuMetrics() {
    return invoke('get_gpu_metrics');
}

// ============================================================================
// AI STATUS API (v0.5.0)
// ============================================================================

export async function getAiStatus() {
    return invoke('get_ai_status');
}

// ============================================================================
// ENTERPRISE API (Phase 7)
// ============================================================================

// Authentication
export async function enterpriseLogin(username, password) {
    return invoke('enterprise_login', { username, password });
}

export async function enterpriseLogout(token) {
    return invoke('enterprise_logout', { token });
}

export async function validateSession(token) {
    return invoke('validate_session', { token });
}

export async function getCurrentUser(token) {
    return invoke('get_current_user', { token });
}

// User Management
export async function getUsers() {
    return invoke('get_users');
}

export async function createUser(username, email, password, role) {
    return invoke('create_user', { username, email, password, role });
}

export async function getRbacStats() {
    return invoke('get_rbac_stats');
}

// Policy Management
export async function getPolicies() {
    return invoke('get_policies');
}

export async function getPolicy(policyId) {
    return invoke('get_policy', { policyId });
}

export async function syncPolicies() {
    return invoke('sync_policies');
}

export async function getPolicySyncStatus() {
    return invoke('get_policy_sync_status');
}

// File Quarantine
export async function getQuarantinedFiles() {
    return invoke('get_quarantined_files');
}

export async function quarantineFile(filePath, reason) {
    return invoke('quarantine_file', { filePath, reason });
}

export async function restoreQuarantinedFile(entryId) {
    return invoke('restore_quarantined_file', { entryId });
}

export async function deleteQuarantinedFile(entryId) {
    return invoke('delete_quarantined_file', { entryId });
}

export async function getQuarantineStats() {
    return invoke('get_quarantine_stats');
}

// Webhooks
export async function getWebhooks() {
    return invoke('get_webhooks');
}

export async function addWebhook(name, url, platform) {
    return invoke('add_webhook', { name, url, platform });
}

export async function removeWebhook(name) {
    return invoke('remove_webhook', { name });
}

export async function testWebhook(name) {
    return invoke('test_webhook', { name });
}

// Reporting
export async function getExecutiveReport() {
    return invoke('get_executive_report');
}

export async function getIncidentSummary(period = 'daily') {
    return invoke('get_incident_summary', { period });
}

export async function getEndpointStats() {
    return invoke('get_endpoint_stats');
}

// ============================================================================
// UTILITY
// ============================================================================

export function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

export function formatDuration(seconds) {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    return `${h}h ${m}m ${s}s`;
}

// ============================================================================
// ADVANCED DETECTION API (Phase 8)
// ============================================================================

// Initialize advanced detection modules
export async function initAdvancedDetection() {
    return invoke('init_advanced_detection');
}

// Check if advanced detection is ready
export async function isAdvancedDetectionReady() {
    return invoke('is_advanced_detection_ready');
}

// AMSI - Script Scanning
export async function scanScript(content, contentType = 'powershell') {
    return invoke('scan_script', { content, contentType });
}

export async function isScriptMalicious(content, contentType = 'powershell') {
    return invoke('is_script_malicious', { content, contentType });
}

export async function getAmsiStats() {
    return invoke('get_amsi_stats');
}

// Injection Detection
export async function analyzeProcessInjection(pid, name, cmdline, parentPid = null, parentName = null) {
    return invoke('analyze_process_injection', { pid, name, cmdline, parentPid, parentName });
}

export async function getInjectionAlerts(limit = 50) {
    return invoke('get_injection_alerts', { limit });
}

export async function getInjectionStats() {
    return invoke('get_injection_stats');
}

// Memory Scanning
export async function scanMemory(data, sourceName) {
    return invoke('scan_memory', { data: Array.from(data), sourceName });
}

export async function scanFileShellcode(path) {
    return invoke('scan_file_shellcode', { path });
}

export async function getMemoryStats() {
    return invoke('get_memory_stats');
}

// Unified Threat Alerts
export async function getThreatAlerts(limit = 50) {
    return invoke('get_threat_alerts', { limit });
}

export async function getAdvancedDetectionStats() {
    return invoke('get_advanced_detection_stats');
}

export default {
    // System
    getSystemStatus,
    getCpuUsage,
    getMemoryUsage,
    getRunningProcesses,
    // Collector
    startCollector,
    stopCollector,
    getRawEvents,
    getSummaryLogs,
    // Baseline
    getBaselineProfile,
    updateBaseline,
    getAnomalyTags,
    // Guard
    loadModel,
    verifyModelChecksum,
    // AI Legacy
    runPrediction,
    getMlScore,
    // Logs
    exportLogs,
    getStatistics,
    resetSystem,
    // Action Guard (Phase III)
    getActionGuardStatus,
    getPendingActions,
    approveAction,
    cancelAction,
    getActionHistory,
    killProcess,
    suspendProcess,
    addToWhitelist,
    removeFromWhitelist,
    getWhitelist,
    // ONNX AI (Phase IV)
    loadOnnxModel,
    initAiBridge,
    isModelLoaded,
    getModelMetadata,
    runOnnxPrediction,
    pushAndPredict,
    clearPredictionBuffer,
    getBufferStatus,
    // GPU (v0.5.0)
    getGpuInfo,
    getGpuMetrics,
    // AI Status (v0.5.0)
    getAiStatus,
    // Enterprise (Phase 7)
    enterpriseLogin,
    enterpriseLogout,
    validateSession,
    getCurrentUser,
    getUsers,
    createUser,
    getRbacStats,
    getPolicies,
    getPolicy,
    syncPolicies,
    getPolicySyncStatus,
    getQuarantinedFiles,
    quarantineFile,
    restoreQuarantinedFile,
    deleteQuarantinedFile,
    getQuarantineStats,
    getWebhooks,
    addWebhook,
    removeWebhook,
    testWebhook,
    getExecutiveReport,
    getIncidentSummary,
    getEndpointStats,
    // Advanced Detection (Phase 8)
    initAdvancedDetection,
    isAdvancedDetectionReady,
    scanScript,
    isScriptMalicious,
    getAmsiStats,
    analyzeProcessInjection,
    getInjectionAlerts,
    getInjectionStats,
    scanMemory,
    scanFileShellcode,
    getMemoryStats,
    getThreatAlerts,
    getAdvancedDetectionStats,
    // Utility
    formatBytes,
    formatDuration,
};

