"""Application services shared by API routers and the background scheduler."""

import asyncio
import logging
import time
from datetime import datetime, timedelta

from . import models, store
from .config import get_settings
from .events import get_broker
from .monitor import BandwidthSampler, ProtocolMonitor
from .scanner import (
    arp_probe,
    classify_device,
    enrich_entries,
    get_default_gateway,
    get_network_cidr,
    l2_sweep,
    oui_vendor,
    ping_host,
    usable_unicast_mac,
)
from .snmp import LanTrafficSampler
from .store import Alert, Device
from .traffic_history import traffic_history

logger = logging.getLogger(__name__)

settings = get_settings()

# History window served when a client does not ask for one (the Traffic page
# always sends its own range; this keeps the WebSocket payload small).
DEFAULT_HISTORY_MINUTES = 5

bandwidth_sampler = BandwidthSampler()
protocol_monitor = ProtocolMonitor(settings.sniffing_enabled)
lan_traffic = LanTrafficSampler()

_gateway_cache: dict[str, float] = {"ip": "", "ts": 0.0}
_GATEWAY_CACHE_TTL = 30.0

# Serializes full discovery scans: the scheduled scan, a manual POST /api/scan
# and the ping-cycle network watcher below can all fire at once. Waiting
# holders would stack behind a 15-20 s scan, so trigger paths check
# `locked()` first and skip instead of queueing.
_scan_lock = asyncio.Lock()


def current_gateway() -> str:
    """Default gateway (the hotspot host) with a short TTL cache."""
    now = time.monotonic()
    if now - _gateway_cache["ts"] > _GATEWAY_CACHE_TTL:
        _gateway_cache["ip"] = get_default_gateway()
        _gateway_cache["ts"] = now
    return _gateway_cache["ip"]


def utcnow() -> datetime:
    return models.utcnow()


def iso_now() -> str:
    return utcnow().isoformat(timespec="seconds")


async def publish(event_type: str, payload: dict) -> None:
    broker = get_broker()
    if broker is not None:
        await broker.publish({"type": event_type, "payload": payload})


# ---------------- payload builders ----------------

def display_name(device: Device) -> str:
    """Device name for the DEVICE NAME column.

    Use the real reverse-DNS hostname when the device returns one; otherwise
    show the IP address (routers, phones and IoT devices often have no PTR
    record, and a bare IP is clearer than a made-up label).
    """
    hostname = (device.hostname or "").strip()
    if hostname and hostname != device.ip_address:
        return hostname
    return device.ip_address or "Unknown device"


def device_payload(device: Device) -> dict:
    return {
        "id": device.id,
        "device_name": display_name(device),
        "hostname": device.hostname or device.ip_address,
        "ip": device.ip_address,
        "mac": device.mac_address or "",
        "type": device.device_type or "Device",
        "os": device.os_guess or "",
        "status": device.status or "unknown",
        "ping_ms": round(device.ping_ms or 0.0, 1),
        "uptime_pct": round(device.uptime_pct or 0.0, 1),
        "open_ports": device.open_ports or "",
        "last_seen": device.last_seen.isoformat(timespec="seconds") if device.last_seen else None,
        "first_seen": device.first_seen.isoformat(timespec="seconds") if device.first_seen else None,
        "vendor": device.vendor or "",
        "is_gateway": bool(device.ip_address and device.ip_address == current_gateway()),
    }


def devices_payload() -> dict:
    items = [device_payload(d) for d in sorted(store.devices(), key=lambda d: d.ip_address)]
    return {"count": len(items), "devices": items}


def alert_payload(alert: Alert) -> dict:
    return {
        "id": alert.id,
        "level": alert.level,
        "message": alert.message,
        "device_ip": alert.device_ip or None,
        "created_at": alert.created_at.isoformat(timespec="seconds") if alert.created_at else None,
    }


def alerts_payload() -> dict:
    active = [a for a in store.alerts() if not a.resolved]
    active.sort(key=lambda a: a.created_at or datetime.min, reverse=True)
    items = [alert_payload(a) for a in active[:100]]
    return {
        "count": len(items),
        "alerts": items,
        "critical": sum(1 for a in items if a["level"] == "crit"),
        "warning": sum(1 for a in items if a["level"] == "warn"),
        "new": sum(1 for a in items if a["level"] == "new"),
        "new_devices": sum(1 for a in items if a["level"] == "new"),
        "info": sum(1 for a in items if a["level"] == "info"),
    }


def stats_payload() -> dict:
    devices = store.devices()
    new_count = sum(1 for a in store.alerts() if a.level == "new" and not a.resolved)
    online = sum(1 for d in devices if d.status == "up")
    offline = sum(1 for d in devices if d.status == "down")
    warning = sum(1 for d in devices if d.status == "warn")
    live = [d for d in devices if d.status in ("up", "warn")]
    avg = round(sum(d.ping_ms or 0 for d in live) / len(live), 1) if live else 0.0
    return {
        "total_devices": len(devices),
        "online": online,
        "offline": offline,
        "warning": warning,
        "avg_latency": avg,
        "new_devices": new_count,
    }


def bandwidth_payload(minutes: int = DEFAULT_HISTORY_MINUTES, fetch_history: bool = False) -> dict:
    """Current rates plus the historical series for the last ``minutes``.

    ``fetch_history`` is only set by the HTTP endpoint: it may read shards from
    Supabase Storage that are not in memory yet. The 2 s WebSocket push leaves
    it off so a background publish can never block on object storage.
    """
    current: dict[str, dict] = {}
    for s in bandwidth_sampler.last_snapshot():
        current[s["interface"]] = {
            "interface": s["interface"],
            "mbps_in": round(s["mbps_in"], 2),
            "mbps_out": round(s["mbps_out"], 2),
            "speed_mbps": s["speed_mbps"],
            "utilization": round(min(s["utilization"], 99.0), 1),
            "total_in": s["total_in"],
            "total_out": s["total_out"],
            "packets_in": s["packets_in"],
            "packets_out": s["packets_out"],
            "errors_in": s["errors_in"],
            "errors_out": s["errors_out"],
            "drops_in": s["drops_in"],
            "drops_out": s["drops_out"],
        }
    return {
        "current": current,
        "history": traffic_history.series(minutes, fetch_missing=fetch_history),
        "history_minutes": max(1, int(minutes)),
        "protocols": protocol_monitor.stats(),
        "lan": lan_traffic.last_snapshot(),
    }


def interfaces_payload() -> dict:
    return {"interfaces": bandwidth_sampler.interface_details()}


def top_talkers_payload() -> dict:
    # Ranking individual consumers needs per-device traffic, which a host's own
    # interface counters cannot provide; the endpoint stays for API compatibility.
    return {"talkers": []}


_CORE_TYPES = {"Router", "Firewall", "Switch", "Access Point"}
# Device-type normalization used by the topology payload. Each value maps to a
# distinct icon rendered by the frontend topology map (Packet Tracer style).
_TYPE_MAP = {
    "Gateway": "router",
    "Router": "router",
    "Firewall": "firewall",
    "Switch": "switch",
    "Network device": "switch",
    "Access Point": "ap",
    "Server": "server",
    "NAS": "nas",
    "Printer": "printer",
    "Camera": "camera",
    "VoIP": "voip",
    "Phone": "phone",
    "Tablet": "tablet",
    "Mobile/Tablet": "mobile",
    "Computer": "pc",
    "PC": "pc",
    "Laptop": "laptop",
}


def topology_payload() -> dict:
    devices = sorted(store.devices(), key=lambda d: d.ip_address)
    if not devices:
        return {"nodes": [], "edges": []}

    core = [d for d in devices if d.device_type in _CORE_TYPES or d.ip_address.endswith(".1") or d.ip_address.endswith(".254")]
    leaves = [d for d in devices if d not in core]

    nodes: list[dict] = []
    edges: list[list[str]] = []
    core_positions = [(450, 60), (450, 160), (450, 260)]
    for i, d in enumerate(core):
        x, y = core_positions[i % len(core_positions)]
        nodes.append(_topology_node(d, x, y))

    leaf_cols = [200, 310, 420, 530, 640, 750]
    for i, d in enumerate(leaves):
        x = leaf_cols[i % len(leaf_cols)]
        y = 340 + (i // len(leaf_cols)) * 130
        nodes.append(_topology_node(d, x, y))

    if core:
        for i in range(len(core) - 1):
            edges.append([f"d{core[i].id}", f"d{core[i + 1].id}"])
        parent = f"d{core[0].id}"
    elif leaves:
        parent = f"d{leaves[0].id}"
    else:
        parent = None
    if parent:
        for d in leaves:
            edges.append([parent, f"d{d.id}"])
    return {"nodes": nodes, "edges": edges}


def _topology_node(device: Device, x: int, y: int) -> dict:
    status = device.status if device.status in ("up", "warn", "down") else "down"
    return {
        "id": f"d{device.id}",
        "label": device.hostname or device.ip_address,
        "ip": device.ip_address,
        "type": _TYPE_MAP.get(device.device_type, "device"),
        "x": x,
        "y": y,
        "status": status,
    }


# ---------------- background jobs ----------------

def _norm_mac(value: str | None) -> str:
    """Lowercased unicast MAC, or "" when the value is missing or unusable."""
    mac = (value or "").strip().lower()
    return mac if usable_unicast_mac(mac) else ""


def _find_device(entry: dict) -> Device | None:
    """The stored device a discovery entry belongs to, or None when it is new.

    Identity is the MAC address, not the IP: a DHCP lease change moves a device
    to a new IP and it must stay one row instead of showing up twice. Rows that
    share a MAC are folded into one (an IP was reused by a device whose old row
    still carried that MAC). The IP is only a fallback for entries that have no
    usable MAC, and only while the row stored for that IP has no MAC yet — a row
    holding a different MAC belongs to a device that lost that IP, so the entry
    is a new device and the stale row is left for the prune in `run_scan`.
    """
    devices = store.devices()
    mac = _norm_mac(entry.get("mac"))
    if mac:
        matches = [d for d in devices if _norm_mac(d.mac_address) == mac]
        if matches:
            # Keep the row already on this IP — its name/type/ports describe the
            # device as it is now — otherwise the oldest, preserving first_seen.
            matches.sort(key=lambda d: (d.ip_address != entry["ip"], d.first_seen or datetime.max))
            keep = matches[0]
            for duplicate in matches[1:]:
                if duplicate.first_seen and (
                    keep.first_seen is None or duplicate.first_seen < keep.first_seen
                ):
                    keep.first_seen = duplicate.first_seen
                devices.remove(duplicate)
            return keep
        current = next((d for d in devices if d.ip_address == entry["ip"]), None)
        return current if current is not None and not _norm_mac(current.mac_address) else None
    return next((d for d in devices if d.ip_address == entry["ip"]), None)


def _upsert_device(entry: dict):
    device = _find_device(entry)
    is_new = device is None
    mac = _norm_mac(entry.get("mac"))
    status = entry.get("status") or "unknown"
    if device is None:
        device = Device(
            id=store.next_device_id(),
            ip_address=entry["ip"],
            mac_address=mac,
            # Never store the raw IP as the hostname: an empty value lets a
            # later scan fill in the real reverse-DNS name.
            hostname=entry.get("hostname") or "",
            device_type=entry.get("device_type") or "",
            os_guess=entry.get("os") or "",
            vendor=entry.get("vendor") or "",
            open_ports=entry.get("open_ports") or "",
            status=status,
            first_seen=utcnow(),
            last_seen=utcnow(),
        )
        store.devices().append(device)
    else:
        # The device may have moved to another IP (DHCP): track it in place.
        device.ip_address = entry["ip"]
        if not device.mac_address and mac:
            device.mac_address = mac
        # Fill in a real hostname when DNS resolves it, replacing an earlier
        # empty value or an IP that was stored as a stand-in name.
        if entry.get("hostname") and (not device.hostname or device.hostname == entry["ip"]):
            device.hostname = entry["hostname"]
        if not device.vendor and entry.get("vendor"):
            device.vendor = entry["vendor"]
        # Refresh ports only when the scan actually probed the host; a sleeping
        # host has no "open_ports" key, so its last known ports are kept.
        if "open_ports" in entry:
            device.open_ports = entry["open_ports"] or ""
        # Refresh type/OS from the latest discovery, but never downgrade a
        # specific guess (e.g. "Mobile/Tablet" from a TTL probe) to the generic
        # "Device" bucket: a scan where the host ignored ICMP yields no type
        # evidence and used to flap the classification back to "Device".
        incoming_type = (entry.get("device_type") or "").strip()
        if incoming_type and not (incoming_type == "Device" and device.device_type and device.device_type != "Device"):
            device.device_type = incoming_type
        if entry.get("os"):
            device.os_guess = entry["os"]
        if status == "up" and device.status in ("unknown", "down"):
            device.status = "up"
            device.fail_count = 0
        device.last_seen = utcnow()
    return device, is_new


def _norm_bssid(value: str | None) -> str:
    """Upper-case colon-separated BSSID, or "" when missing."""
    return (value or "").strip().upper().replace("-", ":")


def _is_hotspot_bssid(bssid: str) -> bool:
    """True for locally-administered (randomized) AP MACs — phone hotspots."""
    try:
        return bool(int(bssid[:2], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def _current_wifi_identity() -> dict:
    """Best-effort SSID/BSSID of the active uplink (never raises)."""
    try:
        from .wifi import wifi_payload

        info = wifi_payload() or {}
    except Exception:
        return {"ssid": "", "bssid": ""}
    if not info.get("connected"):
        return {"ssid": "", "bssid": ""}
    return {"ssid": (info.get("ssid") or "").strip(), "bssid": _norm_bssid(info.get("bssid"))}


def _network_fingerprint(cidr: str, gateway: str, wifi: dict) -> dict:
    """Identity of the LAN the scan just ran on."""
    return {
        "cidr": (cidr or "").strip(),
        "gateway": (gateway or "").strip(),
        "ssid": (wifi.get("ssid") or "").strip(),
        "bssid": _norm_bssid(wifi.get("bssid")),
    }


def _network_changed(old: dict | None, new: dict) -> bool:
    """True when `new` is positively a different LAN than `old`.

    A missing piece of evidence is never a change: an empty gateway/SSID only
    means detection failed (or the link is down), not that the network moved.
    The BSSID alone never triggers — roaming between APs of one SSID keeps the
    same LAN — except when both BSSIDs are hotspot-style randomized MACs with
    an equal SSID, i.e. two different phones sharing one hotspot name.
    """
    if not old:
        return False
    if new.get("cidr") and old.get("cidr") and new["cidr"] != old["cidr"]:
        return True
    if new.get("gateway") and old.get("gateway") and new["gateway"] != old["gateway"]:
        return True
    new_ssid = (new.get("ssid") or "").strip()
    old_ssid = (old.get("ssid") or "").strip()
    if new_ssid and old_ssid and new_ssid != old_ssid:
        return True
    new_bssid = _norm_bssid(new.get("bssid"))
    old_bssid = _norm_bssid(old.get("bssid"))
    if new_bssid and old_bssid and new_bssid != old_bssid:
        same_ssid = bool(new_ssid and old_ssid and new_ssid == old_ssid)
        if same_ssid and _is_hotspot_bssid(new_bssid) and _is_hotspot_bssid(old_bssid):
            return True
        if not new_ssid and not old_ssid:
            # No SSID to anchor on (non-WiFi uplinks report none): a different
            # AP MAC together with an otherwise identical fingerprint is still
            # the same LAN, so only hotspot-style BSSIDs count here as well.
            return _is_hotspot_bssid(new_bssid) and _is_hotspot_bssid(old_bssid)
    return False


def _merge_network(old: dict | None, new: dict) -> dict:
    """Fold `new` into `old`, keeping good values a thin scan left blank."""
    merged = dict(old) if old else {}
    for key, value in new.items():
        if value:
            merged[key] = value
        elif key not in merged:
            merged[key] = value
    return merged


async def run_scan() -> dict:
    """Full discovery cycle. Returns ScanResult-shaped payload."""
    async with _scan_lock:
        return await _run_scan_locked()


async def _detect_network_change_and_rescan() -> bool:
    """Trigger a full scan the moment the uplink moves (ping-cycle watcher).

    The scheduled discovery only runs every 30 s, so without this a physical
    network switch would leave the Devices page showing a half-cleared list
    (often just the gateway, the first host to answer on the fresh LAN)
    until the next cycle. The ping job runs every 5 s, so a cheap fingerprint
    check here cuts the reaction to seconds. Returns True when a rescan was
    started — the caller should skip its own work and let the scan publish.
    """
    if _scan_lock.locked():
        return False
    try:
        cidr, gateway, wifi_identity = await asyncio.gather(
            asyncio.to_thread(get_network_cidr),
            asyncio.to_thread(get_default_gateway),
            asyncio.to_thread(_current_wifi_identity),
        )
    except Exception:
        return False
    fingerprint = _network_fingerprint(cidr, gateway, wifi_identity)
    previous = store.get_network()
    uplink_present = bool(fingerprint.get("gateway") or fingerprint.get("ssid"))
    if previous and uplink_present and _network_changed(previous, fingerprint):
        logger.info("Network watcher detected change %s -> %s — rescanning now", previous, fingerprint)
        await run_scan()
        return True
    return False


def _skeleton_entry(ip: str, mac: str, gateway: str) -> dict:
    """Fast L2-only entry: IP/MAC/vendor/type with no network round-trips.

    Published immediately so the Devices page shows MAC addresses and vendors
    seconds after a network change; reverse DNS, TTL/OS and port scans fill in
    with the enrichment publish. L2 presence (an ARP reply or a sweep hit) is
    evidence of life, so the row starts "up" — the same rule the enricher
    applies to MAC-bearing hosts.
    """
    norm = _norm_mac(mac)
    vendor = oui_vendor(norm) if norm else ""
    return {
        "ip": ip,
        "mac": norm,
        "hostname": "",
        "vendor": vendor,
        "device_type": classify_device(ip, gateway or "", norm, "", None, vendor),
        "os": "",
        "status": "up",
    }


def _upsert_found(entries: list[dict]) -> int:
    """Upsert discovery entries plus new-device alerts. Returns new count.

    Entries carrying a MAC go first: the MAC is a device's identity, so it
    must claim or re-key its row before an IP-only entry falls back to
    whatever row is currently sitting on that IP. Must run inside
    ``store.transaction()``.
    """
    new_devices = 0
    for entry in sorted(entries, key=lambda e: not _norm_mac(e.get("mac"))):
        device, is_new = _upsert_device(entry)
        if is_new:
            new_devices += 1
            store.add_alert(
                level="new",
                message=f"{display_name(device)} ({device.ip_address}) — New device joined network",
                device_ip=device.ip_address,
            )
    return new_devices


def _prune_missing(found_ips: set, network_changed: bool) -> None:
    """Drop rows the discovery did not see. Must run inside ``store.transaction()``."""
    devices = store.devices()
    if network_changed:
        # The old LAN is gone: anything the new discovery did not see
        # belongs to it, grace window or not. The Devices page must not
        # keep showing the previous network's hosts.
        if found_ips:
            devices[:] = [d for d in devices if d.ip_address in found_ips]
        else:
            devices.clear()
        if found_ips:
            store.alerts()[:] = [
                a for a in store.alerts() if not a.device_ip or a.device_ip in found_ips
            ]
    elif found_ips:
        # Keep only real, currently connected devices: drop anything that
        # was not seen in this discovery AND has been quiet past the grace
        # window. Wireless clients (phones, IoT behind home broadband
        # routers) sleep often and vanish from ARP/ping briefly, so a
        # single missed scan is not proof of disconnection.
        grace_cutoff = utcnow() - timedelta(seconds=settings.stale_device_grace_sec)
        stale = [
            d
            for d in devices
            if d.ip_address not in found_ips and (d.last_seen or utcnow()) < grace_cutoff
        ]
        if stale:
            stale_ips = {d.ip_address for d in stale}
            stale_ids = {d.id for d in stale}
            devices[:] = [d for d in devices if d.id not in stale_ids]
            store.alerts()[:] = [a for a in store.alerts() if a.device_ip not in stale_ips]


async def _publish_inventory() -> None:
    """Push the current devices/alerts/stats to every live client."""
    await publish("devices", devices_payload())
    await publish("alerts", alerts_payload())
    await publish("stats", stats_payload())


async def _run_scan_locked() -> dict:
    """Full discovery cycle. Returns ScanResult-shaped payload."""
    start = time.perf_counter()
    cidr, gateway, wifi_identity = await asyncio.gather(
        asyncio.to_thread(get_network_cidr),
        asyncio.to_thread(get_default_gateway),
        asyncio.to_thread(_current_wifi_identity),
    )
    fingerprint = _network_fingerprint(cidr, gateway, wifi_identity)
    # Refresh the gateway cache with the fresh lookup so is_gateway flags and
    # SNMP polling use the new uplink immediately after a network change.
    if gateway:
        _gateway_cache["ip"] = gateway
        _gateway_cache["ts"] = time.monotonic()
    # Positive uplink evidence: without a gateway or an SSID the host may
    # simply be disconnected, which must not wipe the last known inventory.
    uplink_present = bool(fingerprint.get("gateway") or fingerprint.get("ssid"))
    network_changed = False
    cleared_devices = 0
    with store.transaction():
        previous = store.get_network()
        if previous is None:
            store.set_network(fingerprint)
        elif _network_changed(previous, fingerprint) and uplink_present:
            network_changed = True
            removed = store.clear_inventory()
            cleared_devices = removed["devices"]
            # Re-anchor BEFORE upserting so the rows added below belong to the
            # new LAN even if the process crashes mid-scan; the saves below
            # then remove the old rows from Supabase Storage too.
            store.set_network(fingerprint)
            logger.info(
                "Network changed from %s to %s — cleared %d old device(s) and %d alert(s)",
                previous,
                fingerprint,
                removed["devices"],
                removed["alerts"],
            )
            if removed["devices"] or removed["alerts"]:
                store.add_alert(
                    level="info",
                    message=(
                        f"Network changed ({previous.get('ssid') or previous.get('cidr') or 'unknown'} → "
                        f"{fingerprint.get('ssid') or fingerprint.get('cidr') or 'unknown'}) — "
                        f"cleared {removed['devices']} old device(s)"
                    ),
                )
        else:
            store.set_network(_merge_network(previous, fingerprint))
    # Phase 1 (fast, seconds): L2 sweep needs no DNS/ping/ports, so MAC
    # addresses and vendors are known as soon as ARP/ICMP answer. Upsert and
    # publish them now instead of holding them behind the slow enrichment —
    # otherwise the Devices page shows bare IPs for 10-20 s after every
    # network change while hostnames and port scans grind through.
    by_ip, l2_cache, l2_gateway = await asyncio.to_thread(l2_sweep, cidr)
    scan_gateway = l2_gateway or gateway
    skeletons = [
        _skeleton_entry(ip, entry.get("mac") or l2_cache.get(ip, ""), scan_gateway)
        for ip, entry in by_ip.items()
    ]
    found_ips = {s["ip"] for s in skeletons}
    with store.transaction():
        new_devices = _upsert_found(skeletons)
        _prune_missing(found_ips, network_changed)
    await _publish_inventory()
    await asyncio.to_thread(store.save)
    # Phase 2 (slow): reverse DNS, TTL/OS fingerprint and port scan fill in
    # the rows the skeleton just created (matched by MAC, so no duplicate
    # new-device alerts). If enrichment ever fails, the skeleton published
    # above already shows correct IPs, MACs and vendors.
    try:
        enriched = await asyncio.to_thread(enrich_entries, skeletons, scan_gateway, l2_cache)
    except Exception:
        logger.exception("Enrichment failed — keeping the L2 skeleton")
        enriched = []
    if enriched:
        with store.transaction():
            new_devices += _upsert_found(enriched)
        await _publish_inventory()
        await asyncio.to_thread(store.save)
    duration = int((time.perf_counter() - start) * 1000)
    result = {
        "status": "complete",
        "network_cidr": cidr,
        "devices_found": len(skeletons),
        "new_devices": new_devices,
        "scan_duration_ms": duration,
        "timestamp": iso_now(),
        "network_changed": network_changed,
        "cleared_devices": cleared_devices,
    }
    await publish("scan", result)
    return result


async def run_ping_cycle() -> None:
    """Ping every known device, update status/uptime, raise latency & offline alerts.

    When ICMP fails, a live ARP request is sent: many real devices (phones,
    printers, IoT) silently drop ping probes while remaining connected at
    Layer 2. An ARP reply counts as fresh evidence of connectivity, so the
    device is kept "up" (with the last known latency) instead of being
    flapped to "down". A device that answers neither ICMP nor ARP is marked
    offline on the very next cycle.
    """
    # A discovery scan is already rebuilding the inventory — pinging the old
    # rows now would only flap them down and spam unreachable alerts that the
    # scan is about to clear anyway.
    if _scan_lock.locked():
        return
    # Physical network switch: rescan immediately (5 s reaction) instead of
    # waiting for the 30 s scheduled scan, so the Devices page never sits on
    # a half-found list with only the gateway.
    if await _detect_network_change_and_rescan():
        return
    devices = store.devices()
    if not devices:
        return

    sem = asyncio.Semaphore(settings.max_concurrent_pings)

    async def check(device: Device):
        async with sem:
            # Unicast the probe straight to the known MAC when we have one —
            # avoids Scapy's broadcast fallback for unresolved neighbors.
            return device, await asyncio.to_thread(ping_host, device.ip_address, 1000, device.mac_address or "")

    results = await asyncio.gather(*(check(d) for d in devices))
    now = utcnow()

    # Live ARP probe for every host that ignored ICMP. Unlike the system ARP
    # cache (whose entries linger minutes after a client leaves), a reply to a
    # broadcast ARP request is proof the host answers right now — a phone with
    # WiFi switched off no longer stays "up" on a stale cache entry.
    need_probe = [_d for _d, reply in results if reply is None]
    probe_ok: dict[str, bool] = {}

    async def arp_probe_check(device: Device) -> tuple[str, bool]:
        async with sem:
            return device.ip_address, await asyncio.to_thread(arp_probe, device.ip_address)

    if need_probe:
        probed = await asyncio.gather(*(arp_probe_check(d) for d in need_probe))
        probe_ok = dict(probed)

    with store.transaction():
        for device, reply in results:
            live = device
            if reply is None and probe_ok.get(live.ip_address):
                # L2-reachable right now (ping-blocked device): keep alive
                # without inventing a fake latency value.
                live.total_checks += 1
                live.total_ups += 1
                live.fail_count = 0
                if live.status == "down":
                    live.status = "up"
                    store.add_alert(
                        level="info",
                        message=f"{display_name(live)} ({live.ip_address}) — Device recovered",
                        device_ip=live.ip_address,
                    )
                live.last_seen = now
                continue
            live.total_checks += 1
            if reply is None:
                live.fail_count += 1
                live.ping_ms = 0.0
                if live.status != "down":
                    live.status = "down"
                    store.add_alert(
                        level="crit",
                        message=f"{display_name(live)} ({live.ip_address}) — Host unreachable",
                        device_ip=live.ip_address,
                    )
            else:
                ms, ttl = reply
                live.fail_count = 0
                live.ping_ms = ms
                live.total_ups += 1
                if live.status == "down":
                    live.status = "up"
                    store.add_alert(
                        level="info",
                        message=f"{display_name(live)} ({live.ip_address}) — Device recovered",
                        device_ip=live.ip_address,
                    )
                if ms >= settings.latency_crit_ms:
                    if live.status != "warn":
                        live.status = "warn"
                        store.add_alert(
                            level="crit",
                            message=f"{display_name(live)} ({live.ip_address}) — High latency: {ms:.0f}ms (threshold: {settings.latency_crit_ms}ms)",
                            device_ip=live.ip_address,
                        )
                elif ms >= settings.latency_warn_ms:
                    if live.status != "warn":
                        live.status = "warn"
                        store.add_alert(
                            level="warn",
                            message=f"{display_name(live)} ({live.ip_address}) — Latency spike: {ms:.0f}ms detected (threshold: {settings.latency_warn_ms}ms)",
                            device_ip=live.ip_address,
                        )
                elif live.status == "warn":
                    live.status = "up"
                # Only real evidence of life moves last_seen forward: an
                # unreachable host must keep the time of its last reply so the
                # stale-device prune in run_scan can eventually drop it.
                live.last_seen = now
            live.uptime_pct = round(100.0 * live.total_ups / max(1, live.total_checks), 1)
    await asyncio.to_thread(store.save)

    await publish("devices", devices_payload())
    await publish("alerts", alerts_payload())
    await publish("stats", stats_payload())


async def run_bandwidth_cycle() -> None:
    snapshots = await asyncio.to_thread(bandwidth_sampler.snapshot)
    if not snapshots:
        return
    # Fold these rates into the traffic history bucket. A closed bucket means the
    # hour shard changed, so it is uploaded once per bucket — never per sample.
    if traffic_history.record(snapshots):
        await asyncio.to_thread(traffic_history.flush)
    await publish("bandwidth", bandwidth_payload())


async def run_lan_traffic_cycle() -> None:
    """Poll the gateway's SNMP counters for whole-LAN traffic.

    Runs off the request path (blocking UDP in a worker thread). When the
    router does not answer, the sampler enters a cooldown and the dashboard
    falls back to this host's per-interface counters.
    """
    await asyncio.to_thread(lan_traffic.sample, settings.snmp_host or current_gateway())
    await publish("bandwidth", bandwidth_payload())


async def cleanup_old_logs() -> None:
    alert_cutoff = utcnow() - timedelta(days=30)
    with store.transaction():
        alerts = store.alerts()
        alerts[:] = [a for a in alerts if not (a.resolved and (a.created_at or utcnow()) < alert_cutoff)]
    await asyncio.to_thread(store.save)
    # Drop the historical traffic shards past the retention window (Storage has
    # no retention policy of its own, unlike the TimescaleDB hypertable it replaced).
    removed = await asyncio.to_thread(traffic_history.purge)
    if removed:
        logger.info("Purged %d expired traffic-history shard(s)", removed)