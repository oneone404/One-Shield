import { invoke } from '@tauri-apps/api/core';

export async function getEngineStatus() {
    return await invoke("get_engine_status");
}
