import type { AlertResponse, Device, LoginResponse, NetworkInterface, ScanResult, Stats, TopologyData, WifiInfo } from './types'

const API_BASE = '/api'

let accessToken = ''
let refreshPromise: Promise<string | null> | null = null

export function setAccessToken(token: string): void {
  accessToken = token
}

/** Token is held in memory, but also persisted by App; fall back to storage
 * after a page reload so the api client stays authenticated without a round
 * trip through React state. */
function getStoredToken(): string {
  if (accessToken) return accessToken
  accessToken = localStorage.getItem('nw_access_token') || ''
  return accessToken
}

/** Swap the expired access token for a fresh one using the 7-day refresh
 * token. Returns the new token, or null when the refresh itself fails. */
async function refreshAccessToken(): Promise<string | null> {
  const refresh = localStorage.getItem('nw_refresh_token')
  if (!refresh) return null
  const res = await fetch(`${API_BASE}/auth/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token: refresh }),
  })
  if (!res.ok) return null
  const data = (await res.json()) as { access_token: string; refresh_token?: string }
  accessToken = data.access_token
  localStorage.setItem('nw_access_token', data.access_token)
  if (data.refresh_token) localStorage.setItem('nw_refresh_token', data.refresh_token)
  return accessToken
}

function authHeaders(token: string): Record<string, string> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (token) headers.Authorization = `Bearer ${token}`
  return headers
}

async function http<T>(path: string, init: RequestInit = {}): Promise<T> {
  const doFetch = (token: string) =>
    fetch(`${API_BASE}${path}`, {
      ...init,
      headers: { ...authHeaders(token), ...(init.headers as Record<string, string> | undefined) },
    })

  const token = getStoredToken()
  let res = await doFetch(token)

  if (res.status === 401 && token) {
    // Access token expired — silently refresh (deduplicated across parallel
    // calls), then retry the request once. On failure the caller sees the 401.
    refreshPromise ??= refreshAccessToken().finally(() => { refreshPromise = null })
    const fresh = await refreshPromise
    if (fresh) res = await doFetch(fresh)
  }

  if (!res.ok) throw new Error(`API ${res.status} on ${path}`)
  return (await res.json()) as T
}

export const login = async (username: string, password: string): Promise<LoginResponse> => {
  const data = await http<LoginResponse>('/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) })
  setAccessToken(data.access_token)
  return data
}

export const logout = async (): Promise<void> => {
  try {
    await http('/auth/logout', { method: 'POST' })
  } finally {
    setAccessToken('')
  }
}

export const getStats = () => http<Stats>('/stats')

export const getWifi = () => http<WifiInfo>('/wifi')

export const getDevices = () => http<{ devices: Device[] }>('/devices')

export const resetDevices = () => http<{ status: string }>('/devices', { method: 'DELETE' })

export const scanNetwork = () => http<ScanResult>('/scan', { method: 'POST' })

export const getAlerts = () => http<AlertResponse>('/alerts')

export const resolveAlert = (alertId: number) => http<{ status: string }>(`/alerts/${alertId}`, { method: 'DELETE' })

export const clearAlerts = () => http<{ status: string }>('/alerts', { method: 'DELETE' })

/** `minutes` selects the historical window the backend returns in `history`. */
export const getBandwidth = (minutes?: number) =>
  http<BandwidthResponse>(minutes ? `/bandwidth?minutes=${Math.round(minutes)}` : '/bandwidth')

export const getTopology = () => http<TopologyData>('/topology')

export const getInterfaces = () => http<{ interfaces: NetworkInterface[] }>('/bandwidth/interfaces')

export type LiveEvent = { type: string; payload: unknown }

type LiveHandler = (event: LiveEvent) => void;

// One shared socket for the whole app (App's scan listener + DevicesPage's
// devices listener previously opened a socket each). Fewer sockets means
// fewer aborted proxy connections in dev.
const liveHandlers = new Set<LiveHandler>()
let liveSocket: WebSocket | null = null
let liveRetry: ReturnType<typeof setTimeout> | null = null
let liveIdleClose: ReturnType<typeof setTimeout> | null = null

// Grace period before closing an unreferenced socket. React StrictMode mounts
// every effect twice (connect → cleanup → reconnect) and HMR swaps remount
// components the same way; without this grace each of those cycles aborts a
// socket mid-handshake, which is exactly what Vite logs as
// "ws proxy socket error: write ECONNABORTED". Reuse within the window means
// steady-state dev usage opens one socket and never aborts it.
const LIVE_IDLE_CLOSE_MS = 1500
const LIVE_RETRY_MS = 3000

function openLiveSocket(): void {
  if (liveSocket || liveRetry) return
  const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
  const socket = new WebSocket(`${proto}://${window.location.host}/ws`)
  liveSocket = socket
  socket.onmessage = (e) => {
    let event: LiveEvent
    try {
      event = JSON.parse(e.data) as LiveEvent
    } catch {
      // ignore malformed frames
      return
    }
    liveHandlers.forEach((handler) => {
      try {
        handler(event)
      } catch {
        // one bad subscriber must not break fan-out to the rest
      }
    })
  }
  socket.onclose = () => {
    liveSocket = null
    // Nobody left to serve (all unsubscribed during an outage) — stay down.
    if (liveHandlers.size === 0) return
    if (liveRetry) return
    liveRetry = setTimeout(() => {
      liveRetry = null
      openLiveSocket()
    }, LIVE_RETRY_MS)
  }
  // Browsers fire error alongside close; drive everything through onclose so
  // there is exactly one reconnect path.
  socket.onerror = () => {
    try {
      socket.close()
    } catch {
      // already gone — onclose handles the retry
    }
  }
}

function closeLiveSocketIfIdle(): void {
  if (liveHandlers.size > 0) return
  if (liveRetry) {
    clearTimeout(liveRetry)
    liveRetry = null
  }
  const socket = liveSocket
  liveSocket = null
  liveIdleClose = null
  if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
    try {
      // Clean close handshake — unlike an abort, this does not surface as a
      // proxy socket error on either side.
      socket.close(1000, 'idle')
    } catch {
      // already gone
    }
  }
}

/**
 * Subscribe to real-time push events from the backend WebSocket.
 * Returns an unsubscribe function. Automatically reconnects.
 *
 * All subscribers share a single underlying socket (reference-counted); the
 * last unsubscribe only closes it after a short grace period so StrictMode
 * remounts and HMR swaps reuse the live connection.
 */
export function subscribeLive(onEvent: LiveHandler): () => void {
  liveHandlers.add(onEvent)
  if (liveIdleClose) {
    clearTimeout(liveIdleClose)
    liveIdleClose = null
  }
  if (liveRetry) {
    clearTimeout(liveRetry)
    liveRetry = null
  }
  openLiveSocket()
  return () => {
    liveHandlers.delete(onEvent)
    if (liveHandlers.size === 0 && !liveIdleClose) {
      liveIdleClose = setTimeout(closeLiveSocketIfIdle, LIVE_IDLE_CLOSE_MS)
    }
  }
}

export interface BandwidthInterface {
  interface: string
  mbps_in: number
  mbps_out: number
  speed_mbps: number
  utilization: number
  total_in: number
  total_out: number
  packets_in: number
  packets_out: number
  errors_in: number
  errors_out: number
  drops_in: number
  drops_out: number
}

export interface LanTraffic {
  available: boolean
  source: 'snmp'
  reason?: string
  gateway?: string
  interface?: string
  interface_index?: string
  mbps_in?: number
  mbps_out?: number
  speed_mbps?: number
  utilization?: number
  warming_up?: boolean
  updated_at?: string
}

/** One point of the historical series. The backend stores a bucket per
 * `traffic_history_bucket_sec` (10 s) and averages long ranges down, so
 * `bucket_sec` is the real width of the point's window. */
export interface BandwidthHistoryPoint {
  recorded_at: string
  mbps_in?: number
  mbps_out?: number
  bytes_in: number
  bytes_out: number
  bucket_sec?: number
}

export interface BandwidthResponse {
  current: Record<string, BandwidthInterface>
  history: BandwidthHistoryPoint[]
  history_minutes?: number
  protocols?: Record<string, number>
  lan?: LanTraffic | null
}