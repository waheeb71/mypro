/**
 * API Service Layer
 * Single source of truth for all backend communication.
 * Uses Axios with JWT Bearer token interceptor.
 */
import axios from 'axios';

const BASE_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

const api = axios.create({
  baseURL: BASE_URL,
  headers: { 'Content-Type': 'application/json' },
});

// Attach JWT token to every request
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('ngfw_token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// Handle 401 globally → redirect to login
api.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('ngfw_token');
      window.location.href = '/login';
    }
    return Promise.reject(err);
  }
);

export default api;

/* ── Auth ──────────────────────────────────────────── */
export const authApi = {
  login: (data)   => api.post('/api/v1/auth/login', data),
  refresh: ()     => api.post('/api/v1/auth/refresh'),
  me: ()          => api.get('/api/v1/auth/me'),
};

/* ── System ────────────────────────────────────────── */
export const systemApi = {
  status: ()      => api.get('/api/v1/status'),
  health: ()      => api.get('/health'),
  config: (file = 'base.yaml') => api.get(`/api/v1/config?file=${file}`),
  modules: ()     => api.get('/api/v1/config/modules'),
  updateConfig: (data, file = 'base.yaml') => api.put(`/api/v1/config?file=${file}`, data),
  toggleModule: (name, enabled) =>
    api.put(`/api/v1/modules/${name}/toggle`, { enabled }),
  checkUpdate: () => api.get('/api/v1/system/update/check'),
  applyUpdate: (data) => api.post('/api/v1/system/update/apply', data),
};

/* ── Users & RBAC ──────────────────────────────────── */
export const usersApi = {
  list: ()        => api.get('/api/v1/users/'),
  create: (data)  => api.post('/api/v1/users/', data),
  delete: (name)  => api.delete(`/api/v1/users/${name}`),
  rules: (name)   => api.get(`/api/v1/users/${name}/rules`),
  addRule: (name, data)      => api.post(`/api/v1/users/${name}/rules`, data),
  deleteRule: (name, id)     => api.delete(`/api/v1/users/${name}/rules/${id}`),
};

/* ── Firewall ──────────────────────────────────────── */
export const firewallApi = {
  rules: ()        => api.get('/api/v1/rules'),
  createRule: (d)  => api.post('/api/v1/rules', d),
  updateRule: (id, d) => api.put(`/api/v1/rules/${id}`, d),
  deleteRule: (id) => api.delete(`/api/v1/rules/${id}`),
  blockIp: (ip, duration) =>
    api.post(`/api/v1/block/${ip}`, null, { params: { duration } }),
  unblockIp: (ip)  => api.delete(`/api/v1/block/${ip}`),
};

/* ── WAF ───────────────────────────────────────────── */
export const wafApi = {
  status: ()       => api.get('/api/v1/waf/status'),
  gnnStatus: ()    => api.get('/api/v1/waf/gnn/status'),
  gnnLogs: ()      => api.get('/api/v1/waf/gnn/logs'),
  flushLogs: ()    => api.post('/api/v1/waf/gnn/logs/flush'),
  startTraining: (data) => api.post('/api/v1/waf/gnn/train', data),
  trainingStatus: ()    => api.get('/api/v1/waf/gnn/train/status'),
  activateModel: (data) => api.put('/api/v1/waf/gnn/activate', data),
  toggleGnn: (enabled)  => api.put('/api/v1/waf/gnn/toggle', { enabled }),
};

/* ── IDS/IPS ───────────────────────────────────────── */
export const idsApi = {
  status: ()       => api.get('/api/v1/ids_ips/status'),
  alerts: ()       => api.get('/api/v1/ids_ips/alerts'),
  rules: ()        => api.get('/api/v1/ids_ips/rules'),
};

/* ── DNS Security ──────────────────────────────────── */
export const dnsApi = {
  status: ()       => api.get('/api/v1/dns_security/status'),
  blocklist: ()    => api.get('/api/v1/dns_security/blocklist'),
};

/* ── VPN ───────────────────────────────────────────── */
export const vpnApi = {
  status: ()       => api.get('/api/v1/vpn/status'),
  peers: ()        => api.get('/api/v1/vpn/peers'),
};

/* ── HTTP Inspection ───────────────────────────────── */
export const httpApi = {
  status: ()       => api.get('/api/v1/http_inspection/status'),
  patterns: ()     => api.get('/api/v1/http_inspection/patterns'),
};
