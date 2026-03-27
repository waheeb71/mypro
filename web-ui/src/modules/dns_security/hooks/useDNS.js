/**
 * useDNS.js — Centralized React-Query hooks for the DNS Security module.
 * All data fetching and mutations live here; components stay clean.
 */
import { useQueryClient, useQuery, useMutation } from '@tanstack/react-query';
import { dnsApi } from '../../../services/api';

export const DEFAULT_CFG = {
  is_active: true,
  enable_dga_detection: true,
  enable_tunneling_detection: true,
  enable_threat_intel: true,
  enable_rate_limiting: true,
  enable_tld_blocking: true,
  dga_entropy_threshold: 3.8,
  tunneling_query_threshold: 50,
  rate_limit_per_minute: 100,
  suspicious_tlds: '.tk,.ml,.ga,.cf,.gq,.xyz,.top,.win,.bid,.onion',
};

export const DEFAULT_STATS = { total_rules: 0, active_rules: 0, blocked_count: 0, top_blocked: [] };

export function useDNS() {
  const qc = useQueryClient();

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['dns-config'] });
    qc.invalidateQueries({ queryKey: ['dns-stats'] });
    qc.invalidateQueries({ queryKey: ['dns-rules'] });
  };

  const { data: config = DEFAULT_CFG } = useQuery({
    queryKey: ['dns-config'],
    queryFn: () => dnsApi.getConfig().then(r => r.data),
    retry: false,
    placeholderData: DEFAULT_CFG,
  });

  const { data: stats = DEFAULT_STATS } = useQuery({
    queryKey: ['dns-stats'],
    queryFn: () => dnsApi.stats().then(r => r.data),
    retry: false,
    placeholderData: DEFAULT_STATS,
    refetchInterval: 15000,
  });

  const { data: rules = [] } = useQuery({
    queryKey: ['dns-rules'],
    queryFn: () => dnsApi.rules().then(r => r.data),
    retry: false,
    placeholderData: [],
  });

  const updateConfig = useMutation({ mutationFn: d => dnsApi.updateConfig(d), onSuccess: invalidate });
  const createRule   = useMutation({ mutationFn: d => dnsApi.createRule(d),   onSuccess: invalidate });
  const updateRule   = useMutation({ mutationFn: ({ id, d }) => dnsApi.updateRule(id, d), onSuccess: invalidate });
  const deleteRule   = useMutation({ mutationFn: id => dnsApi.deleteRule(id), onSuccess: invalidate });

  return { config, stats, rules, updateConfig, createRule, updateRule, deleteRule };
}
