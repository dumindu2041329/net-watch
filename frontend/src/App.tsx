import { lazy, Suspense, useState, useEffect, useCallback } from 'react'
import type { ComponentType } from 'react'
import type { PageId, AlertResponse, ScanResult, LoginResponse } from './types'
import { getAlerts, logout, scanNetwork, subscribeLive } from './api'
import TopBar from './components/TopBar'
import Sidebar from './components/Sidebar'
import LoginPage from './pages/LoginPage'
import type { AlertFilter } from './pages/AlertsPage'

const DashboardPage = lazy(() => import('./pages/DashboardPage'))
const DevicesPage = lazy(() => import('./pages/DevicesPage'))
const TopologyPage = lazy(() => import('./pages/TopologyPage'))
const TrafficPage = lazy(() => import('./pages/TrafficPage'))
const PerformancePage = lazy(() => import('./pages/PerformancePage'))
const AlertsPage = lazy(() => import('./pages/AlertsPage'))
const AboutPage = lazy(() => import('./pages/AboutPage'))

const pageComponents: Record<PageId, ComponentType> = {
  dashboard: DashboardPage,
  devices: DevicesPage,
  topology: TopologyPage,
  traffic: TrafficPage,
  performance: PerformancePage,
  alerts: AlertsPage,
  about: AboutPage,
}

function PageLoader() {
  return (
    <div className="flex items-center justify-center py-24">
      <div className="animate-blink font-mono-noc text-sm tracking-[2px] text-accent">LOADING…</div>
    </div>
  )
}

export default function App() {
  // Auth state
  const [accessToken, setAccessToken] = useState<string | null>(() => localStorage.getItem('nw_access_token'))

  const [activePage, setActivePage] = useState<PageId>('dashboard')
  const [alertFilter, setAlertFilter] = useState<AlertFilter>('all')
  const [alertStats, setAlertStats] = useState({ critical: 0, warning: 0 })
  const [scanning, setScanning] = useState(false)
  const [scanVersion, setScanVersion] = useState(0)
  const [toast, setToast] = useState<string | null>(null)

  const handleLogout = useCallback(async () => {
    try {
      await logout()
    } catch {
      // Ignore logout errors
    } finally {
      // Clear all stored auth data
      localStorage.removeItem('nw_access_token')
      localStorage.removeItem('nw_refresh_token')
      localStorage.removeItem('nw_user')
      setAccessToken(null)
    }
  }, [])

  useEffect(() => {
    if (!accessToken) return
    const fetchStats = async () => {
      const d: AlertResponse | null = await getAlerts()
      if (d) setAlertStats({ critical: d.critical || 0, warning: (d.warning || 0) + (d.new_devices || 0) })
    }
    fetchStats()
    const id = setInterval(fetchStats, 5000)
    return () => clearInterval(id)
  }, [accessToken])

  // Automatic scans (scheduler + network watcher) also publish `scan` events.
  // Surface a network change instantly even when the user never pressed SCAN.
  useEffect(() => {
    if (!accessToken) return
    const unsub = subscribeLive((e) => {
      if (e.type !== 'scan') return
      const p = e.payload as ScanResult | null
      if (p && p.network_changed) {
        setScanVersion(v => v + 1)
        const cleared = p.cleared_devices || 0
        setToast(
          cleared > 0
            ? `Network changed — cleared ${cleared} old device${cleared !== 1 ? 's' : ''}. Found ${p.devices_found} on the new network.`
            : `Network changed — showing the new network (${p.devices_found} devices).`
        )
        setTimeout(() => setToast(null), 5000)
      }
    })
    return unsub
  }, [accessToken])

  const handleScan = useCallback(async () => {
    if (scanning || !accessToken) return
    setScanning(true)

    const result: ScanResult | null = await scanNetwork()
    if (result) {
      setScanVersion(v => v + 1)
      const base = `Found ${result.devices_found} device${result.devices_found !== 1 ? 's' : ''} (${result.new_devices} new) in ${result.scan_duration_ms}ms`
      const msg = result.network_changed && (result.cleared_devices || 0) > 0
        ? `Network changed — cleared ${result.cleared_devices} old device${result.cleared_devices !== 1 ? 's' : ''}. ${base}`
        : result.network_changed
          ? `Network changed — old devices cleared. ${base}`
          : base
      setToast(msg)
      setTimeout(() => setToast(null), 5000)
    }
    setTimeout(() => setScanning(false), 3000)
  }, [scanning, accessToken])

  const handleOpenAlerts = useCallback((filter: 'crit' | 'warn') => {
    setAlertFilter(filter)
    setActivePage('alerts')
  }, [])

  const handleLogin = useCallback((loginResponse: LoginResponse) => {
    // Store securely in localStorage (note: in production use HttpOnly cookies if possible)
    localStorage.setItem('nw_access_token', loginResponse.access_token)
    localStorage.setItem('nw_refresh_token', loginResponse.refresh_token)
    localStorage.setItem('nw_user', JSON.stringify(loginResponse.user))
    setAccessToken(loginResponse.access_token)
  }, [])

  if (!accessToken) {
    return <LoginPage onLogin={handleLogin} />
  }

  const PageComponent = pageComponents[activePage]

  return (
    <>
      <TopBar stats={alertStats} onLogout={handleLogout} onOpenAlerts={handleOpenAlerts} />
      <div className="relative z-[1]">
        <Sidebar
          activePage={activePage}
          onNavigate={setActivePage}
          onScan={handleScan}
          alertCount={alertStats.critical + alertStats.warning}
          scanning={scanning}
        />
        <main className="ml-[220px] p-6">
          <Suspense fallback={<PageLoader />}>
            {activePage === 'dashboard' ? (
              <DashboardPage scanVersion={scanVersion} token={accessToken} />
            ) : activePage === 'devices' ? (
              <DevicesPage scanVersion={scanVersion} token={accessToken} />
            ) : activePage === 'topology' ? (
              <TopologyPage scanVersion={scanVersion} token={accessToken} />
            ) : activePage === 'alerts' ? (
              <AlertsPage key={alertFilter} initialFilter={alertFilter} />
            ) : (
              <PageComponent />
            )}
          </Suspense>
        </main>
      </div>
      {toast && (
        <div className="fixed bottom-6 right-6 z-[100] bg-panel border border-accent/30 rounded-lg px-5 py-3 shadow-[0_0_20px_rgba(0,212,255,0.15)] animate-fade-in">
          <div className="flex items-center gap-3">
            <span className="text-accent text-lg">&#10003;</span>
            <span className="text-text-noc text-sm font-mono-noc">{toast}</span>
          </div>
        </div>
      )}
    </>
  )
}
