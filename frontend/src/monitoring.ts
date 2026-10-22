export type HostEvent = {
  id: number; identity: string; observed_at: string; received_at: number; source: string;
  category: string; severity: string; summary: string; evidence?: Record<string, unknown>;
};
export type SourceHealth = {
  status: string; checked_at?: number; last_success?: number; error?: string;
  scope?: string; identity?: string; items?: number; raw?: string; note?: string;
  cursor?: { record: number; observed_at: string };
};
export type Collection = {
  connection: string; last_heartbeat: number | null; last_ingestion: number | null;
  database_bytes: number; message: string;
  health: { sources?: Record<string, SourceHealth>; queue_bytes?: number; queue_limit_bytes?: number;
    spool_bytes?: number; spool_limit_bytes?: number; min_free_disk_bytes?: number;
    failures?: number; dropped_data?: number; gaps?: number; delivery_error?: string;
    last_delivery?: number; updated_at?: number };
};
export type Policy = { retention_days: number; max_database_mb: number; min_free_disk_mb: number;
  failed_logon_threshold: number; failed_logon_window_seconds: number };
export type Explanation = { why: string; legitimate: string[]; steps: string[]; references: string[];
  facts: string; interpretation: string; entity: string; prerequisites: string; threshold: number; window_seconds: number };
export type Alert = { id: number; rule: string; severity: string; title: string; first_seen: string;
  last_seen: string; state: string; explanation: Explanation; evidence?: HostEvent[]; more_evidence?: boolean };
export type Suppressions = { suppressions: { rule: string; until: number; reason: string }[];
  rules: { id: string; title: string; prerequisites: string }[] };
export const instant = (value: string | number | null | undefined) => value == null ? 'Not recorded' :
  new Date(typeof value === 'number' ? value * 1000 : value).toLocaleString();
export const bytes = (n?: number) => n == null ? 'Unknown' : `${(n / 1024 / 1024).toFixed(2)} MB`;
