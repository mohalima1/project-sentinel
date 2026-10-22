import { useEffect, useRef, useState, type FormEvent } from 'react';
import { api, type AccountSession } from './api';
import { bytes, instant, type Alert, type Collection, type HostEvent, type Policy, type Suppressions } from './monitoring';

export async function mutate<T>(path: string, method: string, body?: unknown) {
  const current = await api<AccountSession>('/api/auth/session');
  return api<T>(path, { method, headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': current.csrf_token },
    body: body === undefined ? undefined : JSON.stringify(body) });
}

export function Evidence({ event }: { event: HostEvent }) {
  const [full, setFull] = useState<HostEvent | null>(event.evidence ? event : null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  async function load() {
    if (full || busy) return;
    setBusy(true);
    try { setFull(await api<HostEvent>(`/api/events/${event.id}`)); setError(''); }
    catch (failure) { setError((failure as Error).message); }
    finally { setBusy(false); }
  }
  return <details className="evidence" onToggle={e => { if (e.currentTarget.open) void load(); }}>
    <summary>Original evidence · event {event.id}</summary>
    <p className="muted">Observed {instant(event.observed_at)} · Received {instant(event.received_at)} · UTC {event.observed_at}</p>
    {error && <p className="error" role="alert">{error} <button onClick={() => void load()}>Retry evidence</button></p>}
    {!full && !error && <p role="status">{busy ? 'Loading evidence…' : 'Open to load evidence.'}</p>}
    {full && <pre tabIndex={0}>{JSON.stringify(full.evidence, null, 2)}</pre>}
  </details>;
}

export function EventExplorer({ changes, refreshKey, reportError }: {
  changes: boolean; refreshKey: number; reportError: (error: unknown) => void;
}) {
  const [filters, setFilters] = useState('');
  const [before, setBefore] = useState<number | null>(null);
  const [data, setData] = useState<{ events: HostEvent[]; next_cursor: number | null } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const sequence = useRef(0);
  useEffect(() => {
    const request = ++sequence.current;
    setBusy(true);
    const params = new URLSearchParams(filters);
    if (changes) params.set('changes_only', 'true');
    if (before) params.set('before', String(before));
    void api<{ events: HostEvent[]; next_cursor: number | null }>(`/api/events?${params}`).then(result => {
      if (request === sequence.current) { setData(result); setError(''); }
    }).catch(failure => {
      if (request === sequence.current) { setError((failure as Error).message); reportError(failure); }
    }).finally(() => { if (request === sequence.current) setBusy(false); });
    return () => { sequence.current++; };
  }, [changes, before, filters, refreshKey, reportError]);
  function search(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const params = new URLSearchParams();
    new FormData(e.currentTarget).forEach((v, k) => {
      if (String(v)) params.set(k, k === 'since' || k === 'until' ? new Date(String(v)).toISOString() : String(v));
    });
    setBefore(null); setData(null); setFilters(params.toString());
  }
  return <section aria-label={changes ? 'Change timeline' : 'Event search'}>
    <p className="muted">{changes ? 'Inventory differences and Windows service, task, administrator, log-clearing and Defender events. Snapshot times bound when a change occurred.' :
      'Windows host evidence, initial baselines and collection gaps. Dashboard sign-ins are in Settings & audit.'}</p>
    <form className="filters" onSubmit={search}>
      <label>Search evidence<input name="q" maxLength={200} placeholder="Account, executable or task" /></label>
      <label>Source<select name="source" aria-label="Source"><option value="">All sources</option>{[
        'System', 'Security', 'Microsoft-Windows-Windows Defender/Operational',
        'Microsoft-Windows-TaskScheduler/Operational', 'Microsoft-Windows-Sysmon/Operational',
        'services', 'tasks', 'startup', 'administrators', 'software',
      ].map(s => <option key={s}>{s}</option>)}</select></label>
      <label>Severity<select name="severity" aria-label="Severity"><option value="">All severities</option>{['info', 'low', 'medium', 'high', 'critical'].map(s => <option key={s}>{s}</option>)}</select></label>
      {!changes && <label>Category<select name="category" aria-label="Category"><option value="">All categories</option>{[
        'windows_event', 'inventory_baseline', 'inventory_change', 'collection_gap',
      ].map(s => <option key={s}>{s}</option>)}</select></label>}
      <label>From (local time)<input name="since" type="datetime-local" /></label>
      <label>Until (local time)<input name="until" type="datetime-local" /></label>
      <button type="submit" disabled={busy}>Apply filters</button>
    </form>
    {busy && <p role="status">Loading {changes ? 'changes' : 'events'}…</p>}
    {error && <p role="alert" className="error">{error} {data && 'Showing previously loaded results; filters may differ.'}</p>}
    {data && data.events.length === 0 && <p className="empty">{changes ?
      'No changes match these filters. Initial inventory is a baseline, not a new change. Check Collection health to verify coverage.' :
      'No events match these filters. Check Collection health and clear restrictive filters.'}</p>}
    <ol className="timeline">{data?.events.map(event => <li key={event.id}>
      <div className="section-heading"><strong>{event.summary}</strong><span className={`badge severity-${event.severity}`}>{event.severity}</span></div>
      <p className="muted">{instant(event.observed_at)} · {event.source} · {event.category.replaceAll('_', ' ')}</p>
      {event.category === 'inventory_baseline' && <p>Initial baseline: existing items, not newly created items.</p>}
      <Evidence event={event} />
    </li>)}</ol>
    <div className="pagination"><button disabled={!before || busy} onClick={() => { setBefore(null); setData(null); }}>Newest results</button>
      <button disabled={!data?.next_cursor || busy} onClick={() => { setBefore(data!.next_cursor); setData(null); }}>Older results</button></div>
  </section>;
}

function AlertDetail({ alert, reportError, onChange }: { alert: Alert; reportError: (e: unknown) => void; onChange: () => void }) {
  const [full, setFull] = useState<Alert | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  async function load() {
    try { setFull(await api<Alert>(`/api/alerts/${alert.id}`)); setError(''); }
    catch (failure) { setError((failure as Error).message); reportError(failure); }
  }
  async function state(value: string) {
    setBusy(true);
    try { await mutate(`/api/alerts/${alert.id}`, 'PATCH', { state: value }); setError(''); onChange(); }
    catch (failure) { setError((failure as Error).message); reportError(failure); }
    finally { setBusy(false); }
  }
  const why = alert.explanation;
  return <li className="alert-item">
    <div className="section-heading"><h2>{alert.title}</h2><span className={`badge severity-${alert.severity}`}>{alert.severity}</span></div>
    <p>{instant(alert.first_seen)}{alert.first_seen !== alert.last_seen && ` – ${instant(alert.last_seen)}`}</p>
    <p className="muted">Relevant account or object: {why.entity}</p>
    <label className="state-control">Investigation state<select aria-label={`Investigation state for alert ${alert.id}`} value={alert.state} disabled={busy} onChange={e => void state(e.target.value)}>
      {['new', 'investigating', 'resolved', 'false_positive'].map(s => <option key={s} value={s}>{s.replaceAll('_', ' ')}</option>)}
    </select></label>
    {error && <p role="alert" className="error">{error}</p>}
    <p><strong>Why it may matter:</strong> {why.why}</p>
    <p>{why.interpretation}</p>
    <details onToggle={e => { if (e.currentTarget.open && !full) void load(); }}>
      <summary>Investigation guidance and evidence</summary>
      <h3>Observed facts</h3><p>{why.facts}</p>
      {alert.rule === 'failed_windows_signins' && <p>Threshold: {why.threshold} failures within {why.window_seconds} seconds for the same account, domain and source address.</p>}
      <h3>Common legitimate explanations</h3><ul>{why.legitimate.map(s => <li key={s}>{s}</li>)}</ul>
      <h3>What to check next</h3><ol>{why.steps.map(s => <li key={s}>{s}</li>)}</ol>
      <h3>Coverage prerequisites</h3><p>{why.prerequisites}</p>
      <h3>Authoritative references</h3><ul>{why.references.map(url => <li key={url}><a href={url} target="_blank" rel="noreferrer">{new URL(url).pathname.split('/').at(-1)}</a></li>)}</ul>
      <h3>Triggering evidence</h3>
      {!full && <button onClick={() => void load()}>Load evidence</button>}
      {full?.evidence?.map(event => <div key={event.id}><p><strong>{event.summary}</strong></p><Evidence event={event} /></div>)}
      {full?.more_evidence && <p>Showing the first 100 linked events. Search Events for the same account and time window to continue.</p>}
    </details>
  </li>;
}

export function Alerts({ refreshKey, reportError }: { refreshKey: number; reportError: (e: unknown) => void }) {
  const [data, setData] = useState<{ alerts: Alert[]; next_cursor: number | null } | null>(null);
  const [state, setState] = useState('');
  const [before, setBefore] = useState<number | null>(null);
  const [version, setVersion] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => {
    let active = true; setBusy(true);
    const params = new URLSearchParams(); if (state) params.set('state', state); if (before) params.set('before', String(before));
    void api<{ alerts: Alert[]; next_cursor: number | null }>(`/api/alerts?${params}`).then(result => {
      if (active) { setData(result); setError(''); }
    }).catch(e => { if (active) { setError((e as Error).message); reportError(e); } }).finally(() => { if (active) setBusy(false); });
    return () => { active = false; };
  }, [state, before, refreshKey, version, reportError]);
  return <section>
    <p className="muted">Observed evidence and explanations for review. An alert does not confirm compromise; an empty list does not establish safety.</p>
    <label className="state-control">Filter investigation state<select value={state} onChange={e => { setState(e.target.value); setBefore(null); setData(null); }}>
      <option value="">All states</option>{['new', 'investigating', 'resolved', 'false_positive'].map(s => <option key={s} value={s}>{s.replaceAll('_', ' ')}</option>)}</select></label>
    {busy && <p role="status">Loading alerts…</p>}
    {error && <p className="error" role="alert">{error} {data && 'Showing previously loaded alerts.'}</p>}
    {data?.alerts.length === 0 && <p className="empty">No alerts match this state. Check Collection health for missing sources or audit settings.</p>}
    <ul className="alert-list">{data?.alerts.map(alert => <AlertDetail key={alert.id} alert={alert} reportError={reportError} onChange={() => setVersion(v => v + 1)} />)}</ul>
    <div className="pagination"><button disabled={!before || busy} onClick={() => setBefore(null)}>Newest alerts</button>
      <button disabled={!data?.next_cursor || busy} onClick={() => setBefore(data!.next_cursor)}>Older alerts</button></div>
  </section>;
}

export function CollectionHealth({ collection, policy }: { collection: Collection; policy: Policy }) {
  const health = collection.health;
  return <>
    <section className="coverage"><h2>Collector: {collection.connection.replaceAll('_', ' ')}</h2><p>{collection.message}</p>
      {collection.connection === 'never_connected' && <p>Start the separate collector or reopen Start-Sentinel.cmd. A responding backend does not mean collection is working.</p>}
      {collection.connection === 'stale' && <p>No heartbeat within two minutes. Check the collector process, its private health.json, storage and delivery errors.</p>}
      {health.delivery_error && <p>{health.delivery_error}</p>}
    </section>
    <dl className="health-summary">
      <div><dt>Last heartbeat</dt><dd>{instant(collection.last_heartbeat)}</dd></div>
      <div><dt>Last evidence ingestion</dt><dd>{instant(collection.last_ingestion)}</dd></div>
      <div><dt>Collector last acknowledged delivery</dt><dd>{instant(health.last_delivery)}</dd></div>
      <div><dt>Queue usage / limit</dt><dd>{bytes(health.queue_bytes)} / {bytes(health.queue_limit_bytes)}</dd></div>
      <div><dt>Collector database / limit</dt><dd>{bytes(health.spool_bytes)} / {bytes(health.spool_limit_bytes)}</dd></div>
      <div><dt>Failures / deliberately dropped data</dt><dd>{health.failures ?? 'Unknown'} / {health.dropped_data ?? 'Unknown'}</dd></div>
      <div><dt>Detected collection boundaries and gaps</dt><dd>{health.gaps ?? 'Unknown'} · Inspect Events → collection gap</dd></div>
      <div><dt>Backend database / configured limit</dt><dd>{bytes(collection.database_bytes)} / {policy.max_database_mb} MB</dd></div>
      <div><dt>Evidence and alert retention</dt><dd>{policy.retention_days} days</dd></div>
      <div><dt>Minimum free disk space</dt><dd>{policy.min_free_disk_mb} MB backend · {bytes(health.min_free_disk_bytes)} collector</dd></div>
    </dl>
    <section className="source-list"><h2>Source availability and permissions</h2>
      {!health.sources && <p>No source report received. Coverage is unknown.</p>}
      {Object.entries(health.sources ?? {}).map(([name, source]) => <article key={name}>
        <div className="section-heading"><h3>{name}</h3><span className={`badge ${source.status === 'available' ? '' : 'warning'}`}>{source.status}</span></div>
        <p>Last retained collection: {instant(source.last_success)} · Last checked: {instant(source.checked_at)}</p>
        {source.error && <p className="source-error">{source.error}</p>}
        {source.items != null && <p>{source.items} items in the last complete snapshot.</p>}
        {source.cursor && <p>Retained log cursor: record {source.cursor.record} · {instant(source.cursor.observed_at)}</p>}
        {source.scope && <p className="muted">{source.scope} Collector identity: {source.identity}</p>}
        {name === 'audit_policy' && <p>Rule prerequisites require Windows auditing. If this query is denied or settings cannot be read, coverage is unknown. Sentinel does not change audit policy.</p>}
        {source.raw && <details><summary>Original audit policy query</summary><pre tabIndex={0}>{source.raw}</pre></details>}
      </article>)}
    </section>
  </>;
}

export function MonitoringSettings({ policy, reportError, onSave }: { policy: Policy; reportError: (e: unknown) => void; onSave: () => void }) {
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');
  const [rules, setRules] = useState<Suppressions | null>(null);
  const [version, setVersion] = useState(0);
  useEffect(() => { let active = true;
    void api<Suppressions>('/api/suppressions').then(r => { if (active) setRules(r); }).catch(e => { if (active) { setError((e as Error).message); reportError(e); } });
    return () => { active = false; };
  }, [version, reportError]);
  async function save(e: FormEvent<HTMLFormElement>) {
    e.preventDefault(); setBusy(true); setNotice('');
    const values = Object.fromEntries([...new FormData(e.currentTarget)].map(([k, v]) => [k, Number(v)]));
    try { await mutate('/api/settings', 'PUT', values); setNotice('Settings saved. Retention was applied; expired evidence cannot be restored.'); setError(''); onSave(); }
    catch (failure) { setError((failure as Error).message); reportError(failure); }
    finally { setBusy(false); }
  }
  async function suppress(e: FormEvent<HTMLFormElement>, rule: string) {
    e.preventDefault(); const form = new FormData(e.currentTarget); setBusy(true); setNotice('');
    try { await mutate(`/api/suppressions/${rule}`, 'PUT', { seconds: Number(form.get('seconds')), reason: form.get('reason') }); setVersion(v => v + 1); setNotice('Suppression saved. Original events continue to be retained.'); setError(''); onSave(); }
    catch (failure) { setError((failure as Error).message); reportError(failure); }
    finally { setBusy(false); }
  }
  async function remove(rule: string) {
    setBusy(true);
    try { await mutate(`/api/suppressions/${rule}`, 'DELETE'); setVersion(v => v + 1); setError(''); onSave(); }
    catch (failure) { setError((failure as Error).message); reportError(failure); }
    finally { setBusy(false); }
  }
  return <>
    {error && <p role="alert" className="error">{error}</p>}{notice && <p role="status" className="notice">{notice}</p>}
    <h2>Retention, storage and sign-in rule</h2><p className="muted">Settings affect future ingestion. Saving applies retention immediately. Queue limits are configured in the separate collector; a full queue pauses collection.</p>
    <form className="filters" onSubmit={save}>
      <label>Evidence retention (days)<input type="number" name="retention_days" defaultValue={policy.retention_days} min={1} max={365} required /></label>
      <label>Database limit (MB)<input type="number" name="max_database_mb" defaultValue={policy.max_database_mb} min={16} max={8192} required /></label>
      <label>Minimum free disk (MB)<input type="number" name="min_free_disk_mb" defaultValue={policy.min_free_disk_mb} min={16} max={8192} required /></label>
      <label>Failed Windows sign-ins threshold<input type="number" name="failed_logon_threshold" defaultValue={policy.failed_logon_threshold} min={2} max={100} required /></label>
      <label>Sign-in window (seconds)<input type="number" name="failed_logon_window_seconds" defaultValue={policy.failed_logon_window_seconds} min={30} max={3600} required /></label>
      <button disabled={busy} type="submit">Save settings</button>
    </form>
    <h2>Detection suppression</h2><p>Suppress a rule during known maintenance. This stops new alerts for that rule on this computer, while collection and existing alerts remain available.</p>
    {rules?.rules.map(rule => {
      const active = rules.suppressions.find(s => s.rule === rule.id);
      return <details className="rule-setting" key={rule.id}><summary>{rule.title}{active ? ` · Suppressed until ${instant(active.until)}` : ''}</summary>
        <p>{rule.prerequisites}</p>
        {active ? <><p>Reason: {active.reason}</p><button disabled={busy} onClick={() => void remove(rule.id)}>End suppression</button></> :
          <form className="filters" onSubmit={e => void suppress(e, rule.id)}><label>Reason<input name="reason" minLength={3} maxLength={300} required /></label>
            <label>Duration<select name="seconds"><option value="1800">30 minutes</option><option value="3600">1 hour</option><option value="86400">24 hours</option></select></label>
            <button disabled={busy}>Suppress rule</button></form>}
      </details>;
    })}
  </>;
}
