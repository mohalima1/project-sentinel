export type AccountSession = { username: string; csrf_token: string; expires_at: number };
export type Status = {
  version: string; server_time: number; uptime_seconds: number;
  database: { status: string; revision: string; users: number; active_sessions: number };
  telemetry: { status: string; reason: string };
  host_controls_enabled: boolean;
};
export type AuditEvent = { id: number; username: string; action: string; created_at: number };

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

export async function api<T>(path: string, options?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, { ...options, credentials: 'same-origin', cache: 'no-store',
      signal: AbortSignal.timeout(10000) });
  } catch {
    throw new ApiError(0, 'Backend unavailable. Check that Sentinel is running and try again.');
  }
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new ApiError(response.status,
      typeof body.detail === 'string' ? body.detail : 'Request failed. Check your input and retry.');
  }
  return response.status === 204 ? undefined as T : response.json();
}
