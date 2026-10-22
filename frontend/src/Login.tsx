import { useState } from 'react';
import type { FormEvent } from 'react';
import { api, type AccountSession } from './api';

export function Login({ onLogin, notice }: {
  onLogin: (session: AccountSession) => void; notice: string;
}) {
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setBusy(true);
    setError('');
    try {
      const { csrf_token } = await api<{ csrf_token: string }>('/api/auth/csrf');
      const session = await api<AccountSession>('/api/auth/login', {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf_token },
        body: JSON.stringify({ username: form.get('username'), password: form.get('password') }),
      });
      onLogin(session);
    } catch (failure) {
      setError((failure as Error).message);
    } finally { setBusy(false); }
  }

  return <main id="main" className="login-layout">
    <div className="login-intro">
      <h1>Your security workspace,<br />on your computer.</h1>
      <p>Open Sentinel from your computer to check application health and review activity.</p>
      <div className="scope-note"><strong>Private Windows monitoring</strong>
        <p>Review real host changes, supporting evidence and collection coverage.
          Collection health and alerts do not establish whether your computer is secure.</p>
      </div>
    </div>
    <section className="login-panel" aria-labelledby="login-title">
      <h2 id="login-title">Open Sentinel locally</h2>
      <p>Double-click <strong>Start-Sentinel.cmd</strong> in your project folder.
        Your dashboard opens automatically. No registration or password needed.</p>
      <p className="muted">If you signed out or your access link expired, stop Sentinel
        with Ctrl+C in its terminal, then open the launcher again.</p>
      {notice && <p role="status" className="notice">{notice}</p>}
      <details><summary>Use an existing password account</summary>
      <form onSubmit={submit} aria-busy={busy}>
        <label htmlFor="username">Username</label>
        <input id="username" name="username" autoComplete="username" required maxLength={64}
          autoCapitalize="none" spellCheck={false} />
        <label htmlFor="password">Password</label>
        <input id="password" name="password" type="password" autoComplete="current-password"
          required maxLength={128} />
        {error && <p className="error" role="alert">{error}</p>}
        <button className="primary" disabled={busy} type="submit">
          {busy ? 'Signing in…' : 'Sign in'}</button>
      </form>
      </details>
    </section>
  </main>;
}
