import { useCallback, useEffect, useState } from 'react';
import { api, ApiError, type AccountSession } from './api';
import { Dashboard } from './Dashboard';
import { Login } from './Login';

// Capture once before React effects run; immediately remove the secret from history.
const localToken = new URLSearchParams(window.location.hash.slice(1)).get('local');
if (localToken) window.history.replaceState(null, '', window.location.pathname + window.location.search);
let localExchange: Promise<AccountSession> | undefined;

export function App() {
  const [session, setSession] = useState<AccountSession | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const signedOut = useCallback((message: string) => { setSession(null); setNotice(message); }, []);

  async function restore() {
    setLoading(true);
    setError('');
    try {
      if (localToken) {
        localExchange ??= api<AccountSession>('/api/auth/local', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: localToken }),
        }).catch((failure: unknown) => { localExchange = undefined; throw failure; });
        setSession(await localExchange);
      } else { setSession(await api<AccountSession>('/api/auth/session')); }
    }
    catch (failure) {
      if (localToken && failure instanceof ApiError && failure.status === 401) {
        setNotice(failure.message);
      } else if (!(failure instanceof ApiError && failure.status === 401)) {
        setError((failure as Error).message);
      }
    } finally { setLoading(false); }
  }
  useEffect(() => { void restore(); }, []);

  if (loading) return <main className="startup" role="status">Opening Project Sentinel…</main>;
  if (error) return <main className="startup"><h1>Sentinel is unavailable</h1>
    <p role="alert">{error}</p><button onClick={() => void restore()}>Retry</button></main>;
  return <><a className="skip" href="#main">Skip to main content</a>
    {session ? <Dashboard session={session} onLogout={signedOut} /> :
      <Login onLogin={setSession} notice={notice} />}</>;
}
