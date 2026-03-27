/**
 * useEmail.js — Centralized React-Query hooks for the Email Security module.
 */
import { useQueryClient, useQuery, useMutation } from '@tanstack/react-query';
import { emailApi } from '../../../services/api';

const DEFAULT_STATS = {
  total_inspected: 0, total_blocked: 0, total_quarantined: 0, total_allowed: 0,
  phishing_detected: 0, spam_detected: 0, avg_risk_score: 0, decision_breakdown: {}, top_blocked_senders: []
};

const DEFAULT_CFG = {
  enabled: true, mode: 'monitor', monitored_ports: [25, 587, 465, 143, 993, 110, 995],
  preprocessing: {}, phishing: {}, url_scanner: {}, attachment_guard: {}, sender_reputation: {}, spam_filter: {}, thresholds: {}
};

export function useEmail() {
  const qc = useQueryClient();

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['email_config'] });
    qc.invalidateQueries({ queryKey: ['email_status'] });
    qc.invalidateQueries({ queryKey: ['email_stats'] });
  };

  const { data: status } = useQuery({
    queryKey: ['email_status'],
    queryFn: () => emailApi.status().then(r => r.data),
    refetchInterval: 15000,
  });

  const { data: config = DEFAULT_CFG } = useQuery({
    queryKey: ['email_config'],
    queryFn: () => emailApi.config().then(r => r.data),
    placeholderData: DEFAULT_CFG,
  });

  const { data: stats = DEFAULT_STATS } = useQuery({
    queryKey: ['email_stats'],
    queryFn: () => emailApi.stats().then(r => r.data),
    placeholderData: DEFAULT_STATS,
    refetchInterval: 20000,
  });

  const { data: whitelist = { emails: [], domains: [], ips: [] } } = useQuery({
    queryKey: ['email_whitelist'],
    queryFn: () => emailApi.whitelist().then(r => r.data),
  });

  const updateConfig = useMutation({ mutationFn: d => emailApi.updateConfig(d), onSuccess: invalidate });
  const addToWhitelist = useMutation({ mutationFn: d => emailApi.addToWhitelist(d), onSuccess: () => qc.invalidateQueries({ queryKey: ['email_whitelist'] }) });
  const removeFromWhitelist = useMutation({ mutationFn: ({ type, val }) => emailApi.removeFromWhitelist(type, val), onSuccess: () => qc.invalidateQueries({ queryKey: ['email_whitelist'] }) });

  return { status, config, stats, whitelist, updateConfig, addToWhitelist, removeFromWhitelist };
}
