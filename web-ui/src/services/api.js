/**
 * API Service Layer
 * Single source of truth for all backend communication.
 * Uses Axios with JWT Bearer token interceptor.
 */
import axios from 'axios';

const BASE_URL = import.meta.env.VITE_API_URL || 'http://192.168.109.137:8000';

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
  resetConfig:  (file = 'base.yaml') => api.post(`/api/v1/config/reset?file=${file}`),
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
  rules:       ()         => api.get('/api/v1/rules'),
  createRule:  (d)        => api.post('/api/v1/rules', d),
  updateRule:  (id, d)    => api.put(`/api/v1/rules/${id}`, d),
  deleteRule:  (id)       => api.delete(`/api/v1/rules/${id}`),
  // IP Blocklist
  blockedIps:  ()         => api.get('/api/v1/block/ips'),
  blockIp:     (ip, reason, duration_seconds) =>
    api.post(`/api/v1/block/${encodeURIComponent(ip)}`, { reason: reason || 'Manual block', duration_seconds: duration_seconds || null }),
  unblockIp:   (ip)       => api.delete(`/api/v1/block/${encodeURIComponent(ip)}`),
  unblockAll:  ()         => api.delete('/api/v1/block/all'),
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
  
  // WAAP Controls
  toggleWaapFeature: (feature, enabled) => api.put(`/api/v1/waf/waap/toggle/${feature}`, { enabled }),
  updateRateLimit: (data) => api.put('/api/v1/waf/waap/rate_limiter/config', data),
  
  // Shadow Autopilot
  startShadowMode: (hours) => api.post('/api/v1/waf/waap/shadow_mode/start', { hours }),
  shadowModeStatus: () => api.get('/api/v1/waf/waap/shadow_mode/status'),
  exportShadowSchema: () => api.get('/api/v1/waf/waap/shadow_mode/export'),
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
  config: ()       => api.get('/api/v1/vpn/config'),
  updateConfig: (d)=> api.put('/api/v1/vpn/config', d),
  start: ()        => api.post('/api/v1/vpn/start'),
  stop: ()         => api.post('/api/v1/vpn/stop'),
  peers: ()        => api.get('/api/v1/vpn/peers'),
  addPeer: (d)     => api.post('/api/v1/vpn/peers', d),
  removePeer: (k)  => api.delete(`/api/v1/vpn/peers/${encodeURIComponent(k)}`),
  generateKeys: () => api.post('/api/v1/vpn/keys/generate')
};

/* ── HTTP Inspection ───────────────────────────────── */
export const httpApi = {
  status: ()       => api.get('/api/v1/http_inspection/status'),
  config: ()       => api.get('/api/v1/http_inspection/config'),
  updateConfig: (d) => api.put('/api/v1/http_inspection/config', d),
  patterns: ()     => api.get('/api/v1/http_inspection/patterns'),
  addPattern: (d)  => api.post('/api/v1/http_inspection/patterns', d),
  deletePattern: (id) => api.delete(`/api/v1/http_inspection/patterns/${id}`),
};

/* ── Web Filter ────────────────────────────────────── */
export const webFilterApi = {
  status: ()       => api.get('/api/v1/web_filter/status'),
};

/* ── Email Security ────────────────────────────────── */
export const emailApi = {
  status:           () => api.get('/api/v1/email_security/status'),
  config:           () => api.get('/api/v1/email_security/config'),
  updateConfig:     (d) => api.put('/api/v1/email_security/config', d),
  whitelist:        () => api.get('/api/v1/email_security/whitelist'),
  addWhitelist:     (d) => api.post('/api/v1/email_security/whitelist', d),
  removeWhitelist:  (type, value) => api.delete(`/api/v1/email_security/whitelist/${type}/${encodeURIComponent(value)}`),
};

/* ── Malware AV ────────────────────────────────────── */
export const malwareApi = {
  status: () => api.get('/api/v1/malware_av/status'),
  config: () => api.get('/api/v1/malware_av/config'),
  updateConfig: (d) => api.put('/api/v1/malware_av/config', d),
};

/* ── UBA (User Behavior) ───────────────────────────── */
export const ubaApi = {
  status: ()           => api.get('/api/v1/uba/status'),
  config: ()           => api.get('/api/v1/uba/config'),
  updateConfig: (d)    => api.put('/api/v1/uba/config', d),
  users: (params)      => api.get('/api/v1/uba/users', { params }),
  userProfile: (name)  => api.get(`/api/v1/uba/users/${name}`),
  userEvents: (name, p) => api.get(`/api/v1/uba/users/${name}/events`, { params: p }),
  events: (params)     => api.get('/api/v1/uba/events', { params }),
  alerts: ()           => api.get('/api/v1/uba/alerts'),
  resetUser: (name)    => api.delete(`/api/v1/uba/users/${name}/reset`),
};

/* ── Predictive AI ─────────────────────────────────── */
export const aiApi = {
  config: ()           => api.get('/api/v1/ai/config'),
  updateConfig: (d)    => api.put('/api/v1/ai/config', d),
  models: ()           => api.get('/api/v1/ai/models'),
  uploadModel: (id, f) => {
    const fd = new FormData();
    fd.append('file', f);
    return api.post(`/api/v1/ai/models/upload/${id}`, fd, { headers: { 'Content-Type': 'multipart/form-data' } });
  },
};

/* ── SSL Inspection ────────────────────────────────── */
export const sslApi = {
  status: ()           => api.get('/api/v1/ssl_inspection/status'),
  policies: ()         => api.get('/api/v1/ssl-inspection/policies'),
  createPolicy: (d)    => api.post('/api/v1/ssl-inspection/policies', d),
  updatePolicy: (id, d) => api.put(`/api/v1/ssl-inspection/policies/${id}`, d),
  deletePolicy: (id)   => api.delete(`/api/v1/ssl-inspection/policies/${id}`),
  certificates: ()     => api.get('/api/v1/ssl-inspection/certificates'),
  uploadCert: (d)      => api.post('/api/v1/ssl-inspection/certificates/upload', d),
};

/* ── DLP (Data Loss) ───────────────────────────────── */
export const dlpApi = {
  status: ()           => api.get('/api/v1/dlp/status'),
  config: ()           => api.get('/api/v1/dlp/config'),
  updateConfig: (d)    => api.put('/api/v1/dlp/config', d),
  rules: ()            => api.get('/api/v1/dlp/rules'),
  createRule: (d)      => api.post('/api/v1/dlp/rules', d),
  deleteRule: (id)     => api.delete(`/api/v1/dlp/rules/${id}`),
};

/* ── QoS (Quality of Service) ──────────────────────── */
export const qosApi = {
  status: ()           => api.get('/api/v1/qos/status'),
  config: ()           => api.get('/api/v1/qos/config'),
  updateConfig: (d)    => api.put('/api/v1/qos/config', d),
  stats: ()            => api.get('/api/v1/qos/stats'),
};

/* ── Proxy ─────────────────────────────────────────── */
export const proxyApi = {
  status: ()           => api.get('/api/v1/proxy/status'),
  config: ()           => api.get('/api/v1/proxy/config'),
  updateConfig: (d)    => api.put('/api/v1/proxy/config', d),
};
