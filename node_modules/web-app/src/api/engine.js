import api from '../services/tauriApi';

export async function getEngineStatus() {
    return await api.invoke("get_engine_status");
}
