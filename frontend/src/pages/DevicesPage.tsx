import { useState, useEffect } from 'react'
import type { Device } from '../types'
import { getDevices, subscribeLive } from '../api'
import StatusBadge from '../components/StatusBadge'
import PingBar from '../components/PingBar'

export default function DevicesPage({ scanVersion, token }: { scanVersion?: number; token?: string }) {
  const [devices, setDevices] = useState<Device[]>([])
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)

  useEffect(() => {
    const fetchDevices = () => {
      getDevices().then(d => setDevices(d.devices || [])).catch(() => {})
    }
    fetchDevices()
    const id = setInterval(fetchDevices, 5000)
    return () => clearInterval(id)
  }, [token])

  // Live push: the backend publishes the full inventory after every ping
  // cycle and every scan, so a network change renders in ~1 s instead of
  // waiting for the next 5 s poll.
  useEffect(() => {
    const unsub = subscribeLive((e) => {
      if (e.type !== 'devices') return
      const payload = e.payload as { devices?: Device[] } | null
      if (payload && Array.isArray(payload.devices)) {
        setDevices(payload.devices)
        setPage(1)
      }
    })
    return unsub
  }, [])

  useEffect(() => {
    if (scanVersion && scanVersion > 0) {
      getDevices().then(d => setDevices(d.devices || [])).catch(() => {})
    }
  }, [scanVersion])

  // IP search is prefix-based: a full IP matches that device, and a partial
  // IP lists every device in the range (e.g. "192.168.8.1" also shows
  // "192.168.8.101"). Name/MAC keep partial substring matching.
  const q = search.trim().toLowerCase()
  const filtered = devices.filter(d =>
    d.device_name.toLowerCase().includes(q) ||
    d.ip.startsWith(q) ||
    d.mac.toLowerCase().includes(q)
  )

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize))
  const safePage = Math.min(page, totalPages)
  const pageItems = filtered.slice((safePage - 1) * pageSize, safePage * pageSize)

  const pageNumbers: (number | '…')[] = []
  if (totalPages <= 7) {
    for (let i = 1; i <= totalPages; i++) pageNumbers.push(i)
  } else {
    pageNumbers.push(1)
    if (safePage > 3) pageNumbers.push('…')
    for (let i = Math.max(2, safePage - 1); i <= Math.min(totalPages - 1, safePage + 1); i++) pageNumbers.push(i)
    if (safePage < totalPages - 2) pageNumbers.push('…')
    pageNumbers.push(totalPages)
  }

  return (
    <>
      <div className="font-display font-extrabold text-2xl text-text-noc tracking-[2px] mb-5 flex items-center gap-3">
        {'\u25C8'} <span className="text-accent">Device</span> Inventory
      </div>

      <div className="bg-panel border border-border-noc rounded-[10px] overflow-hidden mb-4">
        <div className="flex items-center justify-between px-[18px] py-3.5 border-b border-border-noc bg-panel2">
          <div className="flex items-center gap-3">
            <div className="font-display font-bold text-sm tracking-[1px] text-accent">All Discovered Hosts</div>
          </div>
          <input
            className="bg-bg-noc border border-border-noc text-text-noc px-3 py-1.5 rounded text-[13px] font-body w-[220px] focus:outline-none focus:border-accent"
            placeholder="Search device name or IP..."
            value={search}
            onChange={e => {
              setSearch(e.target.value)
              setPage(1)
            }}
          />
        </div>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[1200px] border-collapse">
            <thead>
              <tr>
                {['#', 'DEVICE NAME', 'IP ADDRESS', 'MAC ADDRESS', 'VENDOR', 'TYPE', 'OS', 'STATUS', 'OPEN PORTS', 'LATENCY', 'UPTIME', 'FIRST CONNECTED'].map(h => (
                  <th key={h} className="text-[10px] tracking-[2px] text-muted text-left px-3 py-2 border-b border-border-noc font-mono-noc">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {pageItems.map((d, i) => (
                <tr key={d.ip} className={d.is_gateway ? 'bg-accent/10 shadow-[inset_3px_0_0_var(--color-accent)]' : 'hover:bg-accent/[0.03]'}>
                  <td className="px-3 py-2.5 border-b border-border-noc/40 text-[13px] text-muted font-mono-noc text-[11px]">{String((safePage - 1) * pageSize + i + 1).padStart(2, '0')}</td>
                  <td className="px-3 py-2.5 border-b border-border-noc/40 text-[13px] font-semibold">
                    {d.device_name}
                    {d.is_gateway && (
                      <span className="ml-2 inline-block px-1.5 py-0.5 bg-accent/20 border border-accent/40 rounded text-[9px] font-mono-noc tracking-[1px] text-accent">GATEWAY</span>
                    )}
                  </td>
                  <td className="px-3 py-2.5 border-b border-border-noc/40 font-mono-noc text-xs text-muted">{d.ip}</td>
                  <td className="px-3 py-2.5 border-b border-border-noc/40 font-mono-noc text-xs text-muted">{d.mac}</td>
                  <td className="px-3 py-2.5 border-b border-border-noc/40 text-xs text-muted">{d.vendor || '—'}</td>
                  <td className="px-3 py-2.5 border-b border-border-noc/40 text-muted text-xs">{d.type}</td>
                  <td className="px-3 py-2.5 border-b border-border-noc/40 text-xs">{d.os}</td>
                  <td className="px-3 py-2.5 border-b border-border-noc/40"><StatusBadge status={d.status} /></td>
                  <td className="px-3 py-2.5 border-b border-border-noc/40">
                    {d.open_ports ? (
                      <div className="flex flex-wrap gap-1">
                        {d.open_ports.split(',').map(p => (
                          <span key={p} className="inline-block px-1.5 py-0.5 bg-accent/10 border border-accent/20 rounded text-[10px] font-mono-noc text-accent">{p}</span>
                        ))}
                      </div>
                    ) : (
                      <span className="text-muted text-[11px]">—</span>
                    )}
                  </td>
                  <td className="px-3 py-2.5 border-b border-border-noc/40"><PingBar ping={d.ping_ms} /></td>
                  <td className="px-3 py-2.5 border-b border-border-noc/40 font-mono-noc text-xs text-accent2">{d.uptime_pct}%</td>
                  <td className="px-3 py-2.5 border-b border-border-noc/40 font-mono-noc text-[11px] text-muted">{d.first_seen ? new Date(d.first_seen + (d.first_seen.includes('Z') || d.first_seen.includes('+') ? '' : 'Z')).toLocaleString('en-LK', { timeZone: 'Asia/Colombo', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true }) : '—'}</td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr><td colSpan={12} className="text-center text-muted p-[30px] text-[13px]">
                  {devices.length === 0 ? 'No devices discovered yet. The scanner runs every 30s — wireless clients appear here automatically.' : (
                    <span>
                      No devices match your search.{' '}
                      <button
                        onClick={() => { setSearch(''); setPage(1) }}
                        className="underline text-accent hover:text-accent2 transition-colors"
                      >
                        Clear search
                      </button>{' '}
                      (tip: after switching networks, an old IP filter hides the new devices)
                    </span>
                  )}
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
        <div className="flex items-center justify-between px-[18px] py-3 border-t border-border-noc bg-panel2">
          <div className="text-[11px] font-mono-noc text-muted tracking-[1px]">
            {filtered.length === 0
              ? '0 DEVICES'
              : `SHOWING ${(safePage - 1) * pageSize + 1}–${Math.min(safePage * pageSize, filtered.length)} OF ${filtered.length} DEVICES`}
          </div>
          <div className="flex items-center gap-1.5">
            <select
              value={pageSize}
              onChange={e => {
                setPageSize(Number(e.target.value))
                setPage(1)
              }}
              className="bg-bg-noc border border-border-noc text-text-noc px-2 py-1 rounded text-[11px] font-mono-noc focus:outline-none focus:border-accent"
              title="Devices per page"
            >
              {[5, 10, 25, 50].map(n => <option key={n} value={n}>{n} / PAGE</option>)}
            </select>
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={safePage === 1}
              className="px-2.5 py-1 border border-border-noc rounded text-[11px] font-mono-noc text-muted disabled:opacity-30 disabled:cursor-not-allowed hover:border-accent/50 hover:text-accent transition-all"
            >‹</button>
            {pageNumbers.map((n, idx) =>
              n === '…' ? (
                <span key={`e${idx}`} className="px-1 text-[11px] font-mono-noc text-muted">…</span>
              ) : (
                <button
                  key={n}
                  onClick={() => setPage(n)}
                  className={`px-2.5 py-1 border rounded text-[11px] font-mono-noc transition-all ${n === safePage ? 'bg-accent/20 border-accent/60 text-accent' : 'border-border-noc text-muted hover:border-accent/50 hover:text-accent'}`}
                >{n}</button>
              )
            )}
            <button
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              disabled={safePage === totalPages}
              className="px-2.5 py-1 border border-border-noc rounded text-[11px] font-mono-noc text-muted disabled:opacity-30 disabled:cursor-not-allowed hover:border-accent/50 hover:text-accent transition-all"
            >›</button>
          </div>
        </div>
      </div>
    </>
  )
}
