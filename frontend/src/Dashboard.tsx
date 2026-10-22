import { useCallback, useEffect, useState } from 'react';
import { api, ApiError, type AccountSession, type AuditEvent, type Status } from './api';
import { Alerts, CollectionHealth, EventExplorer, MonitoringSettings } from './MonitorViews';
import { bytes, instant, type Alert, type Collection, type Policy } from './monitoring';

const actions: Record<string, string> = {
  account_created: 'Administrator created', signed_in: 'Signed in',
  signed_out: 'Signed out', sign_in_failed: 'Sign-in failed',
  settings_changed: 'Monitoring settings changed',
};
const date = (seconds: number) => new Date(seconds * 1000).toLocaleString();

export function Dashboard({ session, onLogout }: {
  session: AccountSession; onLogout: (notice: string) => void;
}) {
  const [data, setData] = useState<{ status: Status; events: AuditEvent[]; collection: Collection; policy: Policy; alerts: Alert[] } | null>(null);
  const [tab, setTab] = useState('overview');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [signingOut, setSigningOut] = useState(false);
  const [updated, setUpdated] = useState(0);
  const [clock, setClock] = useState(Date.now());

  const reportError = useCallback((failure: unknown) => {
    if (failure instanceof ApiError && failure.status === 401) onLogout('Your session ended. Open the launcher again to continue.');
  }, [onLogout]);

  const refresh = useCallback(async () => {
    setBusy(true);
    try {
      const [status, audit, collection, policy, alerts] = await Promise.all([
        api<Status>('/api/status'), api<{ events: AuditEvent[] }>('/api/audit'),
        api<Collection>('/api/collection'), api<Policy>('/api/settings'), api<{ alerts: Alert[] }>('/api/alerts?limit=5'),
      ]);
      setData({ status, events: audit.events, collection, policy, alerts: alerts.alerts });
      setUpdated(Date.now());
      setError('');
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) {
        onLogout('Your session ended. Sign in again to continue.');
      } else { setError((failure as Error).message); }
    } finally { setBusy(false); }
  }, [onLogout]);

  useEffect(() => {
    void refresh();
    const poll = window.setInterval(() => { void refresh(); }, 30000);
    const tick = window.setInterval(() => setClock(Date.now()), 10000);
    return () => { clearInterval(poll); clearInterval(tick); };
  }, [refresh]);

  async function logout() {
    setSigningOut(true);
    try {
      const current = await api<AccountSession>('/api/auth/session');
      await api('/api/auth/logout', { method: 'POST',
        headers: { 'X-CSRF-Token': current.csrf_token } });
      onLogout('You have signed out.');
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) {
        onLogout('Your session ended.');
      } else { setError((failure as Error).message); }
    } finally { setSigningOut(false); }
  }

  const stale = updated > 0 && clock - updated > 60000;
  const tabs: Record<string, string> = { overview: 'Overview', changes: 'Changes', events: 'Events', alerts: 'Alerts', health: 'Collection health', settings: 'Settings & audit' };
  const sources = Object.values(data?.collection.health.sources ?? {});
  const incomplete = sources.some(source => source.status !== 'available');
  return <>
    <header className="topbar"><div className="brand">S<span>Project Sentinel</span></div>
      <div className="account"><span>{session.username === '@local' ? 'This computer' : session.username}</span>
        <button onClick={() => void logout()} disabled={signingOut}>
          {signingOut ? 'Signing out…' : 'Sign out'}</button></div>
    </header>
    <div className="workspace">
      <nav aria-label="Workspace">{Object.entries(tabs).map(([key, label]) => <button key={key} aria-current={tab === key ? 'page' : undefined}
        onClick={() => setTab(key)}>{label}</button>)}
        <span className="environment">Local · v{data?.status.version ?? '0.1.0'}</span>
      </nav>
      <main id="main">
        <div className="page-heading"><div>
          <h1>{tab === 'changes' ? 'What changed?' : tabs[tab]}</h1>
          <p className="muted">{tab === 'overview' ? 'Host observations, explained alerts and collection coverage.' :
            'Private Windows monitoring · Evidence stays on this computer.'}</p></div>
          <button disabled={busy} onClick={() => void refresh()}>{busy ? 'Refreshing…' : 'Refresh'}</button>
        </div>
        {error && <div className="error" role="alert">{error} {data && 'Showing previously loaded data.'}</div>}
        {stale && <p className="notice" role="status">Data is stale. Last updated {new Date(updated).toLocaleTimeString()}.</p>}
        {!data && <p role="status">{busy ? 'Loading dashboard…' : 'No dashboard data available. Use Refresh to retry.'}</p>}
        {data && <>
          {tab === 'overview' && <>
            <section className="coverage" aria-labelledby="coverage-title">
              <span className="badge warning">{data.collection.connection === 'never_connected' ? 'Telemetry unavailable' : `Collector ${data.collection.connection}`}</span>
              <h2 id="coverage-title">{data.collection.connection === 'never_connected' ? 'No host security assessment yet' :
                data.collection.connection === 'stale' ? 'Collector heartbeat is stale' : incomplete ? 'Monitoring coverage needs review' : 'Host observations available'}</h2>
              <p>{data.status.telemetry.reason}</p>
              <p>{sources.filter(source => source.status === 'available').length} of {sources.length} reported sources available. Last evidence ingestion: {instant(data.collection.last_ingestion)}.</p>
              <p>Missing telemetry and an empty alert list do not mean your computer is secure.</p>
              <button onClick={() => setTab('health')}>Review collection health</button>
            </section>
            <section className="readiness" aria-labelledby="readiness-title">
              <div><h2 id="readiness-title">Backend & storage</h2>
                <p className="muted">These checks describe Sentinel itself.</p></div>
              <dl>
                <div><dt>FastAPI backend</dt><dd><span className="badge">Responding</span></dd></div>
                <div><dt>SQLite database</dt><dd>{data.status.database.status}</dd></div>
                <div><dt>Schema revision</dt><dd className="mono">{data.status.database.revision}</dd></div>
                <div><dt>Administrator accounts</dt><dd>{data.status.database.users}</dd></div>
                <div><dt>Active sessions</dt><dd>{data.status.database.active_sessions}</dd></div>
                <div><dt>Host-changing controls</dt><dd>Disabled</dd></div>
                <div><dt>Evidence retention</dt><dd>{data.policy.retention_days} days</dd></div>
                <div><dt>Local evidence database</dt><dd>{bytes(data.collection.database_bytes)}</dd></div>
              </dl>
            </section>
            <section className="activity" aria-labelledby="alerts-title"><div className="section-heading"><h2 id="alerts-title">Recent alerts</h2>
              <button onClick={() => setTab('alerts')}>Review alerts</button></div>
              {data.alerts.length === 0 ? <p>No alerts recorded. Review source coverage before drawing conclusions.</p> :
                <ul className="event-list">{data.alerts.map(alert => <li key={alert.id}><div><strong>{alert.title}</strong><span>{alert.state.replaceAll('_', ' ')} · {alert.severity}</span></div>
                  <time>{instant(alert.last_seen)}</time></li>)}</ul>}
            </section>
          </>}
          {(tab === 'changes' || tab === 'events') && <EventExplorer key={tab} changes={tab === 'changes'} refreshKey={updated} reportError={reportError} />}
          {tab === 'alerts' && <Alerts refreshKey={updated} reportError={reportError} />}
          {tab === 'health' && <CollectionHealth collection={data.collection} policy={data.policy} />}
          {tab === 'settings' && <MonitoringSettings policy={data.policy} reportError={reportError} onSave={() => void refresh()} />}
          {(tab === 'overview' || tab === 'settings') &&
          <section className="activity" aria-labelledby="activity-title">
            <div className="section-heading"><h2 id="activity-title">{tab === 'settings' ? 'Sentinel audit activity' : 'Recent account activity'}</h2>
              {tab === 'overview' && <button onClick={() => setTab('settings')}>View audit log</button>}</div>
            <p className="muted">Dashboard sign-ins and investigation/settings activity. Windows sign-ins are collected separately in Events.</p>
            {data.events.length === 0 ? <p className="muted">No account activity has been recorded.</p> :
              <ul className="event-list">{data.events.slice(0, tab === 'settings' ? 50 : 5).map(event =>
                <li key={event.id}><div><strong>{actions[event.action] ?? event.action}</strong>
                  <span className="muted">{event.username}</span></div>
                  <time dateTime={new Date(event.created_at * 1000).toISOString()}>{date(event.created_at)}</time></li>
              )}</ul>}
          </section>}
          <footer>Last updated {new Date(updated).toLocaleTimeString()} · Refreshes every 30 seconds
            <span>Session expires {date(session.expires_at)}</span></footer>
        </>}
      </main>
    </div>
  </>;
}
