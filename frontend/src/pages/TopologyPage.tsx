import { useState, useEffect, useRef, useMemo, useCallback } from 'react'
import type { TopologyData, TopologyNode } from '../types'
import { getTopology, subscribeLive } from '../api'

const VIEW_W = 1200
const CORE_TYPES = new Set(['router', 'firewall', 'switch', 'ap'])
const NODE_SIZE = 44

const STATUS_COLOR: Record<string, string> = { up: '#00ff88', warn: '#ffcc00', down: '#ff3355' }

const TYPE_NAMES: Record<string, string> = {
  router: 'Router', firewall: 'Firewall', switch: 'Switch', ap: 'Access Point',
  server: 'Server', nas: 'NAS', pc: 'Computer', laptop: 'Laptop', printer: 'Printer',
  camera: 'Camera', voip: 'VoIP Phone', phone: 'Phone', tablet: 'Tablet', mobile: 'Mobile', device: 'Device',
}

/** Gateway-centric layout: the default gateway (router or hotspot phone) is the
 * hub at the top, other infra devices form a second row, everything else —
 * including this monitoring PC — hangs off the hub in rows below. This keeps
 * standard Wi-Fi (router hub) and phone-hotspot/tethered uplinks (phone hub)
 * on one rule instead of electing the hub from IP string order. */
function defaultLayout(nodes: TopologyNode[], gatewayIp?: string): Record<string, { x: number; y: number }> {
  const pos: Record<string, { x: number; y: number }> = {}
  const topY = 120
  const isHub = (n: TopologyNode) => !!n.is_gateway || (!!gatewayIp && n.ip === gatewayIp)
  const hub = nodes.find(isHub)
  const otherCore = nodes.filter(n => !isHub(n) && CORE_TYPES.has(n.type))
  const leaves = nodes.filter(n => !isHub(n) && !CORE_TYPES.has(n.type))

  const layoutRow = (row: TopologyNode[], y: number) => {
    if (row.length === 0) return
    const span = row.length > 1 ? Math.min(260, (VIEW_W - 240) / (row.length - 1)) : 0
    // Widest leaf rows need tighter spacing than the narrow core row.
    const tight = row.length > 4 ? Math.min(200, (VIEW_W - 160) / (row.length - 1)) : span
    row.forEach((n, i) => {
      pos[n.id] = { x: VIEW_W / 2 + (i - (row.length - 1) / 2) * tight, y }
    })
  }

  if (hub) {
    pos[hub.id] = { x: VIEW_W / 2, y: topY }
    const secondY = topY + 190
    layoutRow(otherCore, secondY)
    const leavesStartY = secondY + (otherCore.length ? 190 : 0) + (otherCore.length ? 0 : 0)
    const startY = otherCore.length ? leavesStartY : topY + 190
    const cols = Math.max(1, Math.min(6, leaves.length))
    const colSpan = Math.min(200, (VIEW_W - 160) / (cols > 1 ? cols - 1 : 1))
    const rowGap = 180
    leaves.forEach((n, i) => {
      const r = Math.floor(i / cols)
      const c = i % cols
      const inRow = Math.min(cols, leaves.length - r * cols)
      pos[n.id] = { x: VIEW_W / 2 + (c - (inRow - 1) / 2) * colSpan, y: startY + r * rowGap }
    })
    return pos
  }

  const core = nodes.filter(n => CORE_TYPES.has(n.type))
  const rest0 = nodes.filter(n => !CORE_TYPES.has(n.type))

  core.forEach((n, i) => {
    const span = core.length > 1 ? Math.min(260, (VIEW_W - 240) / (core.length - 1)) : 0
    pos[n.id] = { x: VIEW_W / 2 + (i - (core.length - 1) / 2) * span, y: topY }
  })

  if (core.length === 0 && rest0.length) pos[rest0[0].id] = { x: VIEW_W / 2, y: topY }
  const rest = core.length === 0 ? rest0.slice(1) : rest0

  const cols = Math.max(1, Math.min(6, rest.length))
  const colSpan = Math.min(200, (VIEW_W - 160) / (cols > 1 ? cols - 1 : 1))
  const rowGap = 180
  const startY = topY + 190
  rest.forEach((n, i) => {
    const r = Math.floor(i / cols)
    const c = i % cols
    const inRow = Math.min(cols, rest.length - r * cols)
    pos[n.id] = { x: VIEW_W / 2 + (c - (inRow - 1) / 2) * colSpan, y: startY + r * rowGap }
  })
  return pos
}

/** Packet Tracer style device glyph, drawn in a 44x44 box. */
function Glyph({ type, color }: { type: string; color: string }) {
  const body = <rect x="3" y="3" width="38" height="38" rx="8" fill="rgba(9,23,38,0.96)" stroke={color} strokeWidth="1.6" />
  const c = color
  switch (type) {
    case 'router':
      return (
        <>
          {body}
          <circle cx="22" cy="22" r="8" fill="none" stroke={c} strokeWidth="2" />
          <path d="M22 12v-6M22 38v-6M12 22H6M38 22h-6" stroke={c} strokeWidth="2" strokeLinecap="round" />
          <path d="M19 6.5h6L22 2.5zM19 41.5h6l-3 4zM6.5 19v6l-4-3zM41.5 19v6l-4-3z" fill={c} />
        </>
      )
    case 'switch':
      return (
        <>
          {body}
          <rect x="10" y="9" width="24" height="20" rx="3" fill="rgba(0,212,255,0.07)" stroke={c} strokeWidth="1.6" />
          {[15, 21, 27, 33].map(x => <circle key={x} cx={x} cy="25" r="2.2" fill={c} />)}
        </>
      )
    case 'firewall':
      return (
        <>
          {body}
          <rect x="10" y="10" width="24" height="24" rx="3" fill="none" stroke={c} strokeWidth="1.6" />
          <path d="M10 19h24M10 28h24M19 10v9M28 19v9" stroke={c} strokeWidth="1.4" />
        </>
      )
    case 'ap':
      return (
        <>
          {body}
          <path d="M10 12c3.5-4 20.5-4 24 0M14.5 16c2-2.4 13-2.4 15 0" fill="none" stroke={c} strokeWidth="2" strokeLinecap="round" />
          <circle cx="22" cy="21" r="2.2" fill={c} />
          <rect x="8" y="25" width="28" height="12" rx="4" fill="none" stroke={c} strokeWidth="1.6" />
          <path d="M17 31h10" stroke={c} strokeWidth="1.6" strokeLinecap="round" />
        </>
      )
    case 'server':
      return (
        <>
          {body}
          <rect x="10" y="8" width="24" height="28" rx="3" fill="none" stroke={c} strokeWidth="1.6" />
          <path d="M10 18h24M10 28h24" stroke={c} strokeWidth="1.4" />
          {[13, 23, 33].map(y => <circle key={y} cx="15" cy={y} r="1.8" fill={c} />)}
        </>
      )
    case 'nas':
      return (
        <>
          {body}
          <rect x="8" y="8" width="28" height="28" rx="4" fill="none" stroke={c} strokeWidth="1.6" />
          <ellipse cx="15" cy="15" rx="5" ry="3.2" fill={c} opacity="0.85" />
          <ellipse cx="15" cy="27" rx="5" ry="3.2" fill={c} opacity="0.85" />
          <path d="M24 13h9M24 25h9" stroke={c} strokeWidth="1.4" />
        </>
      )
    case 'pc':
      return (
        <>
          {body}
          <rect x="9" y="7" width="26" height="19" rx="2.5" fill="rgba(0,212,255,0.08)" stroke={c} strokeWidth="1.6" />
          <path d="M18 30h8M22 26v4" stroke={c} strokeWidth="1.8" strokeLinecap="round" />
          <path d="M12 34h20" stroke={c} strokeWidth="1.8" strokeLinecap="round" />
        </>
      )
    case 'laptop':
      return (
        <>
          {body}
          <path d="M11 27V13a4 4 0 0 1 4-4h14a4 4 0 0 1 4 4v14" fill="none" stroke={c} strokeWidth="1.6" />
          <rect x="6" y="26" width="32" height="6" rx="2" fill="rgba(0,212,255,0.12)" stroke={c} strokeWidth="1.6" />
          <path d="M7 34h30" stroke={c} strokeWidth="1.6" strokeLinecap="round" />
        </>
      )
    case 'printer':
      return (
        <>
          {body}
          <rect x="17" y="7" width="10" height="9" rx="1.5" fill="rgba(0,212,255,0.1)" stroke={c} strokeWidth="1.4" />
          <rect x="9" y="15" width="26" height="19" rx="3" fill="none" stroke={c} strokeWidth="1.6" />
          <path d="M13 24h18M13 29h18" stroke={c} strokeWidth="1.4" />
          <circle cx="32" cy="30" r="1.6" fill={c} />
        </>
      )
    case 'camera':
      return (
        <>
          {body}
          <path d="M15 12l2-4h10l2 4" fill="rgba(0,212,255,0.12)" stroke={c} strokeWidth="1.4" />
          <rect x="8" y="11" width="28" height="20" rx="3" fill="none" stroke={c} strokeWidth="1.6" />
          <circle cx="22" cy="21" r="6" fill="none" stroke={c} strokeWidth="1.6" />
          <circle cx="22" cy="21" r="2.2" fill={c} />
          <circle cx="31" cy="17" r="1.4" fill={c} />
        </>
      )
    case 'voip':
      return (
        <>
          {body}
          <path d="M14 13c0 5 16 5 16 0" fill="none" stroke={c} strokeWidth="2.4" strokeLinecap="round" />
          <circle cx="11" cy="13" r="4.5" fill="none" stroke={c} strokeWidth="1.6" />
          <circle cx="33" cy="13" r="4.5" fill="none" stroke={c} strokeWidth="1.6" />
          <path d="M11 17v7M33 17v7" stroke={c} strokeWidth="1.6" />
        </>
      )
    case 'phone':
    case 'mobile':
      return (
        <>
          {body}
          <rect x="14" y="7" width="16" height="30" rx="4" fill="none" stroke={c} strokeWidth="1.6" />
          <path d="M18 11h8" stroke={c} strokeWidth="1.6" strokeLinecap="round" />
          <circle cx="22" cy="31" r="1.8" fill={c} />
        </>
      )
    case 'tablet':
      return (
        <>
          {body}
          <rect x="10" y="9" width="24" height="26" rx="3" fill="none" stroke={c} strokeWidth="1.6" />
          <path d="M15 12h14" stroke={c} strokeWidth="1.2" opacity="0.6" />
          <circle cx="22" cy="30" r="1.5" fill={c} />
        </>
      )
    default:
      return (
        <>
          {body}
          <path d="M22 5l13 7v14l-13 7-13-7V12z" fill="none" stroke={c} strokeWidth="1.6" />
          <circle cx="22" cy="19" r="2.4" fill={c} />
        </>
      )
  }
}

/** Merge freshly laid-out defaults with positions the user has dragged. */
function mergePositions(prev: Record<string, { x: number; y: number }>, nodes: TopologyNode[], gatewayIp?: string): Record<string, { x: number; y: number }> {
  const defaults = defaultLayout(nodes, gatewayIp)
  const next: Record<string, { x: number; y: number }> = {}
  for (const n of nodes) next[n.id] = prev[n.id] ?? defaults[n.id]
  return next
}

export default function TopologyPage({ scanVersion, token }: { scanVersion?: number; token?: string }) {
  const [topo, setTopo] = useState<TopologyData>({ nodes: [], edges: [] })
  const [positions, setPositions] = useState<Record<string, { x: number; y: number }>>({})
  const [selected, setSelected] = useState<TopologyNode | null>(null)
  const [draggingId, setDraggingId] = useState<string | null>(null)
  const svgRef = useRef<SVGSVGElement>(null)
  const dragRef = useRef<{ id: string; dx: number; dy: number; startX: number; startY: number; moved: boolean } | null>(null)

  const fetchTopology = useCallback(() => {
    getTopology()
      .then(data => {
        setTopo(data)
        setPositions(prev => mergePositions(prev, data.nodes, data.gateway_ip))
        // Drop a selection pointing at a host from the previous network —
        // after a network change its id no longer exists in the inventory.
        setSelected(sel => (sel && data.nodes.some(n => n.id === sel.id) ? sel : null))
      })
      .catch(() => {})
  }, [])

  // Poll so routine discoveries (new device on the same network) render
  // without a manual refresh — same 5 s rhythm as the Devices page.
  useEffect(() => {
    fetchTopology()
    const id = setInterval(fetchTopology, 5000)
    return () => clearInterval(id)
  }, [fetchTopology, token])

  // Live push: every completed discovery publishes a `scan` event (the
  // network watcher also triggers one seconds after a physical switch), so
  // the map rebuilds ~1 s after a network change instead of waiting for the
  // next poll. Manual scans bump `scanVersion` in App and refetch below.
  useEffect(() => {
    const unsub = subscribeLive((e) => {
      if (e.type !== 'scan') return
      fetchTopology()
    })
    return unsub
  }, [fetchTopology])

  useEffect(() => {
    if (scanVersion && scanVersion > 0) fetchTopology()
  }, [scanVersion, fetchTopology])

  // Responsive canvas height: always large enough to fit every node.
  const viewH = useMemo(() => {
    const maxY = Object.values(positions).reduce((m, p) => Math.max(m, p.y), 0)
    return Math.max(360, maxY + 150)
  }, [positions])

  const toSvgPoint = useCallback((clientX: number, clientY: number) => {
    const svg = svgRef.current
    if (!svg) return { x: clientX, y: clientY }
    const ctm = svg.getScreenCTM()
    if (!ctm) return { x: clientX, y: clientY }
    const pt = svg.createSVGPoint()
    pt.x = clientX; pt.y = clientY
    const p = pt.matrixTransform(ctm.inverse())
    return { x: p.x, y: p.y }
  }, [])

  const handlePointerDown = (e: React.PointerEvent, node: TopologyNode) => {
    const p = toSvgPoint(e.clientX, e.clientY)
    dragRef.current = { id: node.id, dx: p.x - positions[node.id].x, dy: p.y - positions[node.id].y, startX: p.x, startY: p.y, moved: false }
    e.currentTarget.setPointerCapture(e.pointerId)
    setDraggingId(node.id)
  }

  const handlePointerMove = (e: React.PointerEvent) => {
    const d = dragRef.current
    if (!d) return
    const p = toSvgPoint(e.clientX, e.clientY)
    if (!d.moved && (Math.abs(p.x - d.startX) > 4 || Math.abs(p.y - d.startY) > 4)) d.moved = true
    const nx = Math.min(Math.max(48, p.x - d.dx), VIEW_W - 48)
    const ny = Math.min(Math.max(48, p.y - d.dy), viewH - 48)
    setPositions(prev => ({ ...prev, [d.id]: { x: nx, y: ny } }))
  }

  const handlePointerUp = (e: React.PointerEvent, node: TopologyNode) => {
    const d = dragRef.current
    dragRef.current = null
    setDraggingId(null)
    if (e.currentTarget.hasPointerCapture(e.pointerId)) e.currentTarget.releasePointerCapture(e.pointerId)
    if (d && !d.moved) setSelected(node)
  }

  const cancelDrag = () => {
    dragRef.current = null
    setDraggingId(null)
  }

  const presentTypes = useMemo(() => {
    const s = new Set<string>()
    topo.nodes.forEach(n => s.add(n.type))
    return Array.from(s)
  }, [topo])

  const statusColor = (s: string) => s === 'up' ? 'bg-accent2/12 text-accent2 border-accent2/30' : s === 'warn' ? 'bg-warn/12 text-warn border-warn/30' : 'bg-danger/12 text-danger border-danger/30'

  const hub = topo.nodes.find(n => n.is_gateway || (!!topo.gateway_ip && n.ip === topo.gateway_ip))
  const hubLabel = hub ? hub.label : null

  return (
    <>
      <div className="font-display font-extrabold text-2xl text-text-noc tracking-[2px] mb-5 flex items-center gap-3">
        {'\u25C9'} <span className="text-accent">Network</span> Topology
      </div>

      {topo.nodes.length > 0 && (
        <div className="mb-4 rounded-[10px] border border-border-noc bg-panel px-[18px] py-3 text-[12.5px] leading-relaxed text-muted">
          {topo.hotspot ? (
            <span><b className="text-accent">Hotspot uplink{hubLabel ? ` · ${hubLabel}` : ''}.</b> The phone is the central access point — this computer and every other device connect directly to the phone{topo.gateway_ip ? ` (${topo.gateway_ip})` : ''}, exactly like devices connect to the router on standard Wi-Fi.</span>
          ) : hub ? (
            <span><b className="text-accent">Infrastructure uplink{hubLabel ? ` · ${hubLabel}` : ''}.</b> All devices connect directly to the hub{topo.gateway_ip ? ` (${topo.gateway_ip})` : ''}.</span>
          ) : (
            <span>Hub not detected yet — showing discovered devices without a centre node.</span>
          )}
        </div>
      )}

      <div className="bg-panel border border-border-noc rounded-[10px] overflow-hidden mb-4">
        <div className="flex items-center justify-between px-[18px] py-3.5 border-b border-border-noc bg-panel2">
          <div className="font-display font-bold text-sm tracking-[1px] text-accent">Live Network Map</div>
          <div className="text-[11px] text-muted font-mono-noc hidden sm:block">DRAG NODES TO REPOSITION · CLICK TO INSPECT</div>
        </div>
        <div className="relative bg-[#060d17]">
          <svg
            ref={svgRef}
            viewBox={`0 0 ${VIEW_W} ${viewH}`}
            preserveAspectRatio="xMidYMid meet"
            className="w-full h-auto max-h-[72vh] block select-none"
            onPointerMove={handlePointerMove}
            onPointerUp={() => dragRef.current && cancelDrag()}
            onPointerLeave={() => dragRef.current && cancelDrag()}
          >
            <defs>
              <pattern id="topo-grid" width="30" height="30" patternUnits="userSpaceOnUse">
                <circle cx="1.5" cy="1.5" r="1.3" fill="rgba(120,170,215,0.14)" />
              </pattern>
            </defs>
            <rect width={VIEW_W} height={viewH} fill="url(#topo-grid)" />

            {topo.edges.map(([a, b], i) => {
              const pa = positions[a]; const pb = positions[b]
              if (!pa || !pb) return null
              const active = selected !== null && (selected.id === a || selected.id === b)
              return (
                <line
                  key={i}
                  x1={pa.x} y1={pa.y} x2={pb.x} y2={pb.y}
                  stroke={active ? 'rgba(0,212,255,0.75)' : 'rgba(0,212,255,0.22)'}
                  strokeWidth={active ? 2 : 1.4}
                  strokeDasharray={active ? undefined : '1 0'}
                />
              )
            })}

            {topo.nodes.map(n => {
              const p = positions[n.id]
              if (!p) return null
              const color = STATUS_COLOR[n.status] || '#00d4ff'
              const isDragging = draggingId === n.id
              const isSel = selected?.id === n.id
              const isHub = !!n.is_gateway || (!!topo.gateway_ip && n.ip === topo.gateway_ip)
              return (
                <g
                  key={n.id}
                  transform={`translate(${p.x - NODE_SIZE / 2} ${p.y - NODE_SIZE / 2})`}
                  style={{ cursor: isDragging ? 'grabbing' : 'grab' }}
                  onPointerDown={e => handlePointerDown(e, n)}
                  onPointerMove={e => { e.stopPropagation(); handlePointerMove(e) }}
                  onPointerUp={e => { e.stopPropagation(); handlePointerUp(e, n) }}
                  onPointerCancel={cancelDrag}
                >
                  {isSel && (
                    <rect x="-6" y="-6" width="56" height="62" rx="10" fill="none" stroke="rgba(0,212,255,0.6)" strokeWidth="1.6" strokeDasharray="5 4" />
                  )}
                  {isHub && !isSel && (
                    <rect x="-4" y="-4" width="52" height="52" rx="10" fill="none" stroke="rgba(0,212,255,0.35)" strokeWidth="1.2" />
                  )}
                  <g style={{ filter: isDragging ? 'drop-shadow(0 0 6px rgba(0,212,255,0.6))' : undefined }}>
                    <Glyph type={n.type} color={color} />
                  </g>
                  <text x="22" y="50" textAnchor="middle" fontSize="12" fontFamily="'Share Tech Mono',monospace" fontWeight="600" fill={isSel ? '#00d4ff' : '#d7e8f8'} style={{ pointerEvents: 'none' }}>{n.label}</text>
                  {n.label !== n.ip && (
                    <text x="22" y="63" textAnchor="middle" fontSize="9.5" fontFamily="'Share Tech Mono',monospace" fill="rgba(150,190,225,0.55)" style={{ pointerEvents: 'none' }}>{n.ip}</text>
                  )}
                  {(isHub || n.is_self) && (
                    <text x="22" y="-8" textAnchor="middle" fontSize="9" fontFamily="'Share Tech Mono',monospace" fontWeight="700" fill="rgba(0,212,255,0.85)" style={{ pointerEvents: 'none' }}>
                      {isHub ? (topo.hotspot ? 'HOTSPOT · HUB' : 'HUB') : 'THIS PC'}
                    </text>
                  )}
                </g>
              )
            })}

            {topo.nodes.length === 0 && (
              <text x={VIEW_W / 2} y="90" textAnchor="middle" fontSize="14" fontFamily="'Share Tech Mono',monospace" fill="rgba(150,190,225,0.5)">
                No devices discovered yet — the network map appears here once hosts are found.
              </text>
            )}
          </svg>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-panel border border-border-noc rounded-[10px] overflow-hidden">
          <div className="px-[18px] py-3.5 border-b border-border-noc bg-panel2"><div className="font-display font-bold text-sm tracking-[1px] text-accent">Legend</div></div>
          <div className="p-4 flex flex-col gap-3">
            <div className="flex flex-wrap gap-4">
              {[{ color: 'bg-accent2', label: 'Online Host' }, { color: 'bg-danger', label: 'Offline Host' }, { color: 'bg-warn', label: 'Warning' }].map(item => (
                <div key={item.label} className="flex items-center gap-2 text-[13px]">
                  <span className={`w-3 h-3 rounded-full ${item.color} inline-block`} />{item.label}
                </div>
              ))}
            </div>
            {presentTypes.length > 0 && (
              <div className="flex flex-wrap gap-x-4 gap-y-2 border-t border-border-noc/50 pt-3">
                {presentTypes.map(t => (
                  <div key={t} className="flex items-center gap-2 text-[12px] text-muted">
                    <svg viewBox="0 0 44 44" width="24" height="24" className="shrink-0"><Glyph type={t} color="#00d4ff" /></svg>
                    {TYPE_NAMES[t] || t}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="bg-panel border border-border-noc rounded-[10px] overflow-hidden">
          <div className="px-[18px] py-3.5 border-b border-border-noc bg-panel2">
            <div className="font-display font-bold text-sm tracking-[1px] text-accent">{selected ? selected.label : 'Select a Node'}</div>
          </div>
          <div className={`p-4 text-[13px] ${selected ? 'text-text-noc' : 'text-muted'}`}>
            {selected ? (
              <div className="grid gap-2">
                <div className="flex items-center gap-2">
                  <svg viewBox="0 0 44 44" width="30" height="30"><Glyph type={selected.type} color={STATUS_COLOR[selected.status] || '#00d4ff'} /></svg>
                  <div>
                    <div className="font-semibold">{selected.label}</div>
                    <div className="text-[11px] text-muted font-mono-noc">{TYPE_NAMES[selected.type] || selected.type}</div>
                  </div>
                </div>
                <div>IP: <b className="text-accent font-mono-noc">{selected.ip}</b></div>
                <div className="flex flex-wrap items-center gap-2">
                  {(selected.is_gateway || (!!topo.gateway_ip && selected.ip === topo.gateway_ip)) && (
                    <span className="inline-flex items-center gap-[5px] px-2.5 py-[3px] rounded-[12px] text-[11px] font-semibold border bg-accent/12 text-accent border-accent/30">{topo.hotspot ? 'HOTSPOT HUB' : 'NETWORK HUB'}</span>
                  )}
                  {selected.is_self && (
                    <span className="inline-flex items-center gap-[5px] px-2.5 py-[3px] rounded-[12px] text-[11px] font-semibold border bg-accent2/12 text-accent2 border-accent2/30">THIS PC</span>
                  )}
                </div>
                <div>Status: <span className={`inline-flex items-center gap-[5px] px-2.5 py-[3px] rounded-[12px] text-[11px] font-semibold border ${statusColor(selected.status)}`}>{selected.status.toUpperCase()}</span></div>
              </div>
            ) : 'Click on any device node to view details. Drag nodes to rearrange the map.'}
          </div>
        </div>
      </div>
    </>
  )
}
