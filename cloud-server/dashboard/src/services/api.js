/**
 * One-Shield Cloud API Service
 * Connects to cloud-server backend
 */

// Read from environment variable, fallback to production URL
const API_BASE_URL = import.meta.env.VITE_API_URL || 'https://api.accone.vn';

// Store token in memory (and localStorage for persistence)
let authToken = localStorage.getItem('token') || null;

/**
 * Set authentication token
 */
export function setToken(token) {
    authToken = token;
    if (token) {
        localStorage.setItem('token', token);
    } else {
        localStorage.removeItem('token');
    }
}

/**
 * Get current token
 */
export function getToken() {
    return authToken;
}

/**
 * Check if user is authenticated
 */
export function isAuthenticated() {
    return !!authToken;
}

/**
 * Clear authentication
 */
export function logout() {
    setToken(null);
}

/**
 * Make authenticated API request
 */
async function apiRequest(endpoint, options = {}) {
    const url = `${API_BASE_URL}${endpoint}`;

    const headers = {
        'Content-Type': 'application/json',
        ...options.headers,
    };

    if (authToken && !options.noAuth) {
        headers['Authorization'] = `Bearer ${authToken}`;
    }

    try {
        const response = await fetch(url, {
            ...options,
            headers,
        });

        // Handle auth errors
        if (response.status === 401) {
            logout();
            window.location.href = '/login';
            throw new Error('Unauthorized');
        }

        // Get response text first
        const text = await response.text();

        // Try to parse as JSON
        let data;
        try {
            data = text ? JSON.parse(text) : {};
        } catch {
            // If not JSON, treat the text as error message
            if (!response.ok) {
                throw new Error(text || 'Request failed');
            }
            data = { message: text };
        }

        if (!response.ok) {
            throw new Error(data.error || data.message || 'Request failed');
        }

        return data;
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

// ============================================
// Health & Status
// ============================================

export async function getHealth() {
    return apiRequest('/health', { noAuth: true });
}

// ============================================
// Authentication
// ============================================

export async function login(email, password) {
    const data = await apiRequest('/api/v1/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
        noAuth: true,
    });
    setToken(data.token);
    return data;
}

/**
 * Register new organization
 * @param {Object} data - Registration data
 * @param {string} data.organization_name - Organization name
 * @param {string} data.email - Admin email
 * @param {string} data.password - Admin password
 * @param {string} [data.name] - Admin name (optional)
 */
export async function register(data) {
    const response = await apiRequest('/api/v1/auth/register', {
        method: 'POST',
        body: JSON.stringify({
            organization_name: data.organization_name,
            email: data.email,
            password: data.password,
            name: data.name || null,
        }),
        noAuth: true,
    });
    return response;
}

// ============================================
// Endpoints (Agents)
// ============================================

export async function getEndpoints() {
    return apiRequest('/api/v1/endpoints');
}

export async function getEndpoint(id) {
    return apiRequest(`/api/v1/endpoints/${id}`);
}

export async function deleteEndpoint(id) {
    return apiRequest(`/api/v1/endpoints/${id}`, {
        method: 'DELETE',
    });
}

// ============================================
// Incidents
// ============================================

export async function getIncidents(limit = 50, offset = 0) {
    return apiRequest(`/api/v1/incidents?limit=${limit}&offset=${offset}`);
}

export async function getIncident(id) {
    return apiRequest(`/api/v1/incidents/${id}`);
}

export async function updateIncidentStatus(id, status) {
    return apiRequest(`/api/v1/incidents/${id}/status`, {
        method: 'PUT',
        body: JSON.stringify({ status }),
    });
}

// ============================================
// Policies
// ============================================

export async function getPolicies() {
    return apiRequest('/api/v1/policies');
}

export async function getPolicy(id) {
    return apiRequest(`/api/v1/policies/${id}`);
}

export async function createPolicy(policy) {
    return apiRequest('/api/v1/policies', {
        method: 'POST',
        body: JSON.stringify(policy),
    });
}

export async function updatePolicy(id, policy) {
    return apiRequest(`/api/v1/policies/${id}`, {
        method: 'PUT',
        body: JSON.stringify(policy),
    });
}

// ============================================
// Reports
// ============================================

export async function getExecutiveReport() {
    return apiRequest('/api/v1/reports/executive');
}

export async function getComplianceReport() {
    return apiRequest('/api/v1/reports/compliance');
}

// ============================================
// Organization
// ============================================

export async function getOrganization() {
    return apiRequest('/api/v1/organization');
}

export async function getOrganizationUsers() {
    return apiRequest('/api/v1/organization/users');
}

// Default export
export default {
    // Auth
    login,
    register,
    logout,
    isAuthenticated,
    getToken,
    setToken,

    // Health
    getHealth,

    // Endpoints
    getEndpoints,
    getEndpoint,
    deleteEndpoint,

    // Incidents
    getIncidents,
    getIncident,
    updateIncidentStatus,

    // Policies
    getPolicies,
    getPolicy,
    createPolicy,
    updatePolicy,

    // Reports
    getExecutiveReport,
    getComplianceReport,

    // Organization
    getOrganization,
    getOrganizationUsers,
};

// Generic API helper object for dynamic endpoints
export const api = {
    get: (endpoint) => apiRequest(`/api/v1${endpoint}`),
    post: (endpoint, data) => apiRequest(`/api/v1${endpoint}`, {
        method: 'POST',
        body: JSON.stringify(data),
    }),
    put: (endpoint, data) => apiRequest(`/api/v1${endpoint}`, {
        method: 'PUT',
        body: JSON.stringify(data),
    }),
    delete: (endpoint) => apiRequest(`/api/v1${endpoint}`, {
        method: 'DELETE',
    }),
};
