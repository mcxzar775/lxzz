export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

function readCookie(name: string): string | undefined {
  const prefix = `${encodeURIComponent(name)}=`
  return document.cookie
    .split('; ')
    .find((item) => item.startsWith(prefix))
    ?.slice(prefix.length)
}

export async function apiRequest<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers)
  const method = (init.method ?? 'GET').toUpperCase()
  if (init.body !== undefined && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    const csrf = readCookie('vpngate_csrf')
    if (csrf) {
      headers.set('X-CSRF-Token', decodeURIComponent(csrf))
    }
  }
  const response = await fetch(path, {
    ...init,
    method,
    headers,
    credentials: 'include',
  })
  if (response.status === 204) {
    return undefined as T
  }
  let payload: unknown
  try {
    payload = await response.json()
  } catch {
    payload = undefined
  }
  if (!response.ok) {
    const detail =
      typeof payload === 'object' && payload !== null && 'detail' in payload
        ? String(payload.detail)
        : '请求失败，请稍后重试'
    throw new ApiError(response.status, detail)
  }
  return payload as T
}

