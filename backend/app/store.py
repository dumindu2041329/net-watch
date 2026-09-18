"""Devices and alerts persisted as a JSON document in Supabase Storage.

Supabase Storage is object storage, not a database: the document cannot be
queried server-side. The single backend process therefore keeps both
collections in memory and rewrites the whole document after a change. All
writes are serialized with a process-wide lock (last-writer-wins if a second
instance is ever run against the same bucket).

Bucket layout::

    netwatch/state.json
        {"updated_at": ..., "device_seq": N, "alert_seq": M,
         "devices": [...], "alerts": [...]}

    netwatch/bandwidth/2026-09-15T10.json
        {"hour": ..., "bucket_sec": 10, "samples": [...]}   # see app/traffic_history.py

Both collections share one object so that a save is a single atomic upload and
a failed save can never leave devices and alerts out of sync.

Safety rule: a failed *read* is never treated as "there is no data". In that
case writes are disabled until a later read succeeds, so an incomplete
in-memory state can never overwrite what is already stored.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from .config import get_settings

logger = logging.getLogger(__name__)

settings = get_settings()

_STATE_PATH = "state.json"
_RETRY_AFTER_SEC = 30.0

_lock = threading.RLock()
_loaded = False
_load_failed = False
_retry_at = 0.0
_devices: list["Device"] = []
_alerts: list["Alert"] = []
_network: dict | None = None
_seq = {"device": 0, "alert": 0}
_last_saved = ""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


@dataclass
class Device:
    ip_address: str
    id: int = 0
    hostname: str = ""
    mac_address: str = ""
    device_type: str = ""
    os_guess: str = ""
    vendor: str = ""
    status: str = "unknown"
    ping_ms: float = 0.0
    uptime_pct: float = 0.0
    open_ports: str = ""
    fail_count: int = 0
    total_checks: int = 0
    total_ups: int = 0
    last_seen: datetime | None = None
    first_seen: datetime | None = None


@dataclass
class Alert:
    level: str
    message: str
    id: int = 0
    device_ip: str = ""
    created_at: datetime | None = None
    resolved: int = 0


# ---------------- serialization ----------------

def _iso(value: datetime | None) -> str | None:
    return value.isoformat(timespec="seconds") if value else None


def _parse(value: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(value) if value else None
    except ValueError:
        return None


def _device_to_dict(device: Device) -> dict:
    data = asdict(device)
    data["last_seen"] = _iso(device.last_seen)
    data["first_seen"] = _iso(device.first_seen)
    return data


def _device_from_dict(data: dict) -> Device:
    return Device(
        ip_address=data.get("ip_address", ""),
        id=int(data.get("id", 0)),
        hostname=data.get("hostname", ""),
        mac_address=data.get("mac_address", ""),
        device_type=data.get("device_type", ""),
        os_guess=data.get("os_guess", ""),
        vendor=data.get("vendor", ""),
        status=data.get("status", "unknown"),
        ping_ms=float(data.get("ping_ms", 0.0)),
        uptime_pct=float(data.get("uptime_pct", 0.0)),
        open_ports=data.get("open_ports", ""),
        fail_count=int(data.get("fail_count", 0)),
        total_checks=int(data.get("total_checks", 0)),
        total_ups=int(data.get("total_ups", 0)),
        last_seen=_parse(data.get("last_seen")),
        first_seen=_parse(data.get("first_seen")),
    )


def _alert_to_dict(alert: Alert) -> dict:
    data = asdict(alert)
    data["created_at"] = _iso(alert.created_at)
    return data


def _alert_from_dict(data: dict) -> Alert:
    return Alert(
        level=data.get("level", "info"),
        message=data.get("message", ""),
        id=int(data.get("id", 0)),
        device_ip=data.get("device_ip", ""),
        created_at=_parse(data.get("created_at")),
        resolved=int(data.get("resolved", 0)),
    )


def _state_body() -> dict:
    """Document contents excluding ``updated_at`` (used for change detection)."""
    return {
        "device_seq": _seq["device"],
        "alert_seq": _seq["alert"],
        "network": dict(_network) if _network else None,
        "devices": [_device_to_dict(d) for d in _devices],
        "alerts": [_alert_to_dict(a) for a in _alerts],
    }


# ---------------- Supabase Storage REST ----------------

def _configured() -> bool:
    """True only when a real Supabase Storage credential is present."""
    key = settings.supabase_service_key.strip()
    if not settings.supabase_url.strip() or not key:
        return False
    # Reject leftover <PLACEHOLDER> values. Legacy keys are JWTs, new secret
    # keys start with sb_secret_; anything else cannot authenticate.
    return key.startswith("eyJ") or key.startswith("sb_secret_")


def _headers() -> dict:
    key = settings.supabase_service_key
    headers = {"apikey": key, "Content-Type": "application/json"}
    # Legacy keys (anon / service_role) are JWTs and are also sent as a Bearer
    # token. The newer sb_secret_... keys are not JWTs and must only ever be
    # sent on the `apikey` header, so the Bearer header is omitted for them.
    if key.startswith("eyJ"):
        headers["Authorization"] = f"Bearer {key}"
    return headers


def _object_url(path: str) -> str:
    base = settings.supabase_url.rstrip("/")
    return f"{base}/storage/v1/object/{settings.supabase_storage_bucket}/{path}"


def _read_document(path: str) -> dict | None:
    """Return the document, ``{}`` when it does not exist yet, ``None`` on failure."""
    if not _configured():
        return {}
    request = urllib.request.Request(_object_url(path), headers=_headers(), method="GET")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
            return payload if isinstance(payload, dict) else {}
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", errors="ignore").lower()
        except Exception:  # noqa: BLE001 - body is best-effort diagnostics only
            pass
        # Supabase answers 400 for both "the object does not exist yet"
        # (NoSuchKey) and "the bucket/key is wrong" (NoSuchBucket). Only the
        # first means there is no data yet; the rest must fail closed so an
        # empty in-memory state can never overwrite stored data.
        unreachable = "nosuchbucket" in body or "bucket not found" in body or exc.code in (401, 403)
        if not unreachable and (
            exc.code == 404 or "nosuchkey" in body or "not_found" in body or "object not found" in body
        ):
            return {}
        logger.error("Supabase Storage read failed for %s: %s", path, exc)
    except (urllib.error.URLError, ValueError) as exc:
        logger.error("Supabase Storage read failed for %s: %s", path, exc)
    return None


def _write_document(path: str, payload: str) -> bool:
    if not _configured():
        return False
    request = urllib.request.Request(
        _object_url(path),
        data=payload.encode("utf-8"),
        headers={**_headers(), "x-upsert": "true"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            response.read()
        return True
    except (urllib.error.URLError, urllib.error.HTTPError) as exc:
        logger.error("Supabase Storage write failed for %s: %s", path, exc)
        return False


# ---------------- generic object access ----------------

def storage_configured() -> bool:
    """True when a usable Supabase Storage credential is configured."""
    return _configured()


def read_json(path: str) -> dict | None:
    """Read a JSON object: ``{}`` when it does not exist yet, ``None`` on failure."""
    return _read_document(path)


def write_json(path: str, payload: str) -> bool:
    """Create or replace one object with ``payload`` (already serialized)."""
    return _write_document(path, payload)


def list_paths(prefix: str = "") -> list[str] | None:
    """Object names stored under ``prefix``, or ``None`` when listing failed.

    Names come back relative to the prefix (``2026-09-15T10.json`` for prefix
    ``bandwidth/``); callers that need the full path must re-attach the prefix.
    """
    if not _configured():
        return None
    url = f"{settings.supabase_url.rstrip('/')}/storage/v1/object/list/{settings.supabase_storage_bucket}"
    body = json.dumps(
        {"prefix": prefix, "limit": 1000, "offset": 0, "sortBy": {"column": "name", "order": "asc"}}
    )
    request = urllib.request.Request(url, data=body.encode("utf-8"), headers=_headers(), method="POST")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError) as exc:
        logger.error("Supabase Storage list failed for %r: %s", prefix, exc)
        return None
    if not isinstance(payload, list):
        return None
    return [entry["name"] for entry in payload if isinstance(entry, dict) and entry.get("name")]


def delete_paths(paths: list[str]) -> bool:
    """Delete objects in one bulk request. True when all of them are gone."""
    if not _configured():
        return False
    targets = [path for path in paths if path]
    if not targets:
        return True
    url = f"{settings.supabase_url.rstrip('/')}/storage/v1/object/{settings.supabase_storage_bucket}"
    request = urllib.request.Request(
        url,
        data=json.dumps({"prefixes": targets}).encode("utf-8"),
        headers=_headers(),
        method="DELETE",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            response.read()
        return True
    except (urllib.error.URLError, urllib.error.HTTPError) as exc:
        logger.error("Supabase Storage delete failed for %s: %s", targets, exc)
        return False


# ---------------- public API ----------------

@contextmanager
def transaction():
    """Hold the store lock while mutating ``devices()`` / ``alerts()`` in place.

    Mutating either list (or a ``Device`` / ``Alert`` field that ``save()``
    reads) outside this block races with ``save()``, which snapshots the state
    on a worker thread. Do not ``await`` inside the block: ``save()`` needs the
    same lock, so awaiting here would block the loop against that worker.
    """
    with _lock:
        yield


def load(force: bool = False) -> None:
    """Load the document into memory.

    Retries are rate limited so a storage outage cannot turn into a request
    storm; once a read succeeds the in-memory state is trusted again.
    """
    global _loaded, _load_failed, _retry_at, _devices, _alerts, _network, _last_saved
    with _lock:
        if _loaded and not force:
            return
        if _load_failed and not force and time.monotonic() < _retry_at:
            return
        document = _read_document(_STATE_PATH)
        if document is None:
            _load_failed = True
            _retry_at = time.monotonic() + _RETRY_AFTER_SEC
            logger.error(
                "Supabase Storage read failed — keeping the last known state and "
                "refusing to save until a read succeeds"
            )
            return
        _devices = [_device_from_dict(item) for item in document.get("devices", [])]
        _alerts = [_alert_from_dict(item) for item in document.get("alerts", [])]
        raw_network = document.get("network")
        _network = dict(raw_network) if isinstance(raw_network, dict) else None
        _seq["device"] = max(int(document.get("device_seq", 0)), max((d.id for d in _devices), default=0))
        _seq["alert"] = max(int(document.get("alert_seq", 0)), max((a.id for a in _alerts), default=0))
        _last_saved = json.dumps(_state_body(), sort_keys=True)
        _loaded = True
        _load_failed = False
    if not _configured():
        logger.warning("Supabase Storage is not configured — devices/alerts are kept in memory only")


def devices() -> list[Device]:
    load()
    return _devices


def alerts() -> list[Alert]:
    load()
    return _alerts


def get_network() -> dict | None:
    """The network the stored inventory belongs to, or None on first run.

    Shape: ``{"cidr": ..., "gateway": ..., "ssid": ..., "bssid": ...}``.
    A copy is returned so callers cannot mutate the stored value without
    going through :func:`set_network` (which keeps ``save()`` change
    detection accurate). Old documents written before this field existed
    report None, which callers treat as "unknown — adopt, don't wipe".
    """
    load()
    with _lock:
        return dict(_network) if _network else None


def set_network(info: dict | None) -> None:
    """Remember which network the in-memory inventory belongs to.

    Does not persist by itself — the caller saves (``save()`` picks the new
    value up through ``_state_body``) so a network change and the inventory
    wipe stay one atomic Storage upload.
    """
    with _lock:
        global _network
        _network = dict(info) if info else None


def clear_inventory() -> dict:
    """Drop every stored device and alert (old network is gone).

    Must be called inside :func:`transaction`. Returns the removal counts so
    callers can log and report them. Persistence is left to the caller —
    ``save()`` rewrites ``state.json`` in Supabase Storage, which is what
    removes the old-network rows from Storage as well as from memory.
    """
    with _lock:
        removed_devices = len(_devices)
        removed_alerts = len(_alerts)
        _devices.clear()
        _alerts.clear()
        return {"devices": removed_devices, "alerts": removed_alerts}


def next_device_id() -> int:
    with _lock:
        _seq["device"] += 1
        return _seq["device"]


def next_alert_id() -> int:
    with _lock:
        _seq["alert"] += 1
        return _seq["alert"]


def add_alert(level: str, message: str, device_ip: str = "") -> Alert:
    with _lock:
        alert = Alert(level=level, message=message, id=next_alert_id(), device_ip=device_ip, created_at=_utcnow())
        alerts().append(alert)
        return alert


def save() -> bool:
    """Persist the state. Returns True when stored (or already up to date)."""
    global _last_saved
    with _lock:
        if not _configured():
            return False  # in-memory mode: there is nowhere to persist to
        if _load_failed:
            logger.error(
                "Refusing to save: the last Storage read failed, so the in-memory "
                "state may be incomplete and would overwrite stored data"
            )
            return False
        serialized = json.dumps(_state_body(), sort_keys=True)
        if serialized == _last_saved:
            return True  # nothing changed since the last write
        document = {"updated_at": _iso(_utcnow()), **_state_body()}
        if not _write_document(_STATE_PATH, json.dumps(document)):
            return False
        _last_saved = serialized
        return True
