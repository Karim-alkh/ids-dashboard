"""
Real-time Network IDS -- Flask-SocketIO backend.

This is a corrected rewrite of the original detection engine. Three
structural problems were causing both false positives and false
negatives; all three are fixed here. See README.md for the full list.

  1. FLAG.  The KDD-style connection 'flag' (SF/S0/REJ/RSTO/...) is now
     derived from real TCP handshake/teardown state tracked across the
     whole connection (ConnState), instead of a bitwise-AND lookup on a
     single packet's raw flags byte. The old logic classified an ordinary
     PSH+ACK data packet as 'RSTO', so routine traffic satisfied
     neptune/portsweep/ipsweep's flag requirement by accident.

  2. CROSS-FLOW FEATURES.  'count', 'srv_count', every '*error_rate' and
     every 'dst_host_*' feature are now computed by HostConnectionTracker,
     which looks across ALL flows to/from a host -- matching the real
     NSL-KDD definitions (a 2-second time window for the 'traffic'
     features, a 100-connection window per destination host for the
     'host' features). Previously these were computed from a single
     flow's own packet list, so a single 5-tuple connection only ever
     saw itself: dst_host_count was structurally stuck at 1, meaning
     satan, smurf and portsweep could never fire, and *_serror/rerror
     rates were always 0 because they checked a `.flag` attribute that
     was never actually set on individual packets.

  3. MATCHING.  Attack matching is now a scored match (fraction of
     zero_fields/ranges satisfied, gated by protocol/service/flag) with a
     configurable confidence threshold, instead of requiring every single
     condition to match exactly. Live traffic has natural jitter; an
     all-or-nothing AND across 15-20 fields will almost never fire even
     for a real attack.

Known limitations (see README.md): the content-based features
(num_failed_logins, root_shell, etc.) are keyword/regex heuristics on
payload bytes, not a full protocol/session reconstruction -- treat them
as indicative, not authoritative.
"""
# --------------------------------------------------------------------------
# Eventlet must be patched before importing networking/threading libraries.
# Flask-SocketIO uses Eventlet as its asynchronous backend for real-time
# communication. While Eventlet is in maintenance mode, it remains suitable
# for this project's synchronous architecture.
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# Eventlet patching
# MUST happen before any other imports.
# --------------------------------------------------------------------------

import eventlet

eventlet.monkey_patch()

# --------------------------------------------------------------------------
# Standard library imports
# --------------------------------------------------------------------------

import json
import uuid
import logging
import math
import os
import re
import time
import traceback
import socket
import sqlite3

from collections import Counter, defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple

# --------------------------------------------------------------------------
# Third-party imports
# --------------------------------------------------------------------------

import eventlet.queue as queue
import pyshark
import subprocess
import shutil
import tempfile
import psutil

from flask import Flask, render_template, jsonify, request, send_file
from flask_socketio import SocketIO, emit
# --------------------------------------------------------------------------
# Logging configuration
# --------------------------------------------------------------------------

LOG_FORMAT = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"

logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
)

logger = logging.getLogger("ids-dashboard")

# --------------------------------------------------------------------------
# Flask application
# --------------------------------------------------------------------------

app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv(
    "FLASK_SECRET_KEY",
    "development-secret-change-me",
)

socketio = SocketIO(
    app,
    cors_allowed_origins=os.getenv('CORS_ORIGINS', '*').split(','),
    async_mode="eventlet"
)

# --------------------------------------------------------------------------
# Runtime data structures
# --------------------------------------------------------------------------

dashboard_event_queue = queue.Queue(maxsize=2000)

RECENT_FLOWS_LIMIT = 50
ALERT_HISTORY_LIMIT = 100
CHART_HISTORY_SECONDS = 60

recent_flows: Deque[Dict[str, Any]] = deque(maxlen=RECENT_FLOWS_LIMIT)
recent_alerts: Deque[Dict[str, Any]] = deque(maxlen=ALERT_HISTORY_LIMIT)
alert_event_queue = queue.Queue(maxsize=1000)

# Persistence queue for alerts (written asynchronously)
alert_persist_queue = queue.Queue(maxsize=2000)

# Optional GeoIP reader (lazy-initialized) - provide path in config.json under 'geoip_db_path'
GEOIP_READER = None

chart_data_packets_per_sec = deque(maxlen=CHART_HISTORY_SECONDS)
chart_data_attacks_per_sec = deque(maxlen=CHART_HISTORY_SECONDS)

# Persistence config defaults (will be set after loading config)
ALERTS_PERSIST_PATH = None
ALERTS_ROTATE_MB = 10
# SQLite DB path for structured alerts persistence (preferred)
ALERTS_DB_PATH = None

# --------------------------------------------------------------------------
# Load configuration
# --------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.json"

try:
    with CONFIG_PATH.open("r", encoding="utf-8") as config_file:
        config = json.load(config_file)
except FileNotFoundError:
    logger.critical("Configuration file not found: %s", CONFIG_PATH)
    raise
except json.JSONDecodeError as exc:
    logger.critical("Invalid JSON in config file: %s", exc)
    raise

# psutil.cpu_percent(interval=None) reports the delta since the LAST call --
# the very first call has no baseline and returns a meaningless 0.0. Warm it
# up once here so the first real reading later is accurate.
psutil.cpu_percent(interval=None)
_process_handle = psutil.Process(os.getpid())

# --------------------------------------------------------------------------
# Persistence config (after config loaded)
# --------------------------------------------------------------------------
ALERTS_PERSIST_PATH = config.get('alerts_persist_path') if isinstance(config, dict) else None
ALERTS_ROTATE_MB = int(config.get('alerts_rotate_mb', 10) if isinstance(config, dict) else 10)
ALERTS_DB_PATH = config.get('alerts_db_path') if isinstance(config, dict) else None

# --------------------------------------------------------------------------
# Validate configuration
# --------------------------------------------------------------------------

REQUIRED_CONFIG_KEYS = {
    "interface",
    "thresholds",
}

# Optional IOC list path (newline list of IPs, CIDRs, or domains)
IOC_LIST_PATH = config.get('ioc_list_path') if isinstance(config, dict) else None
# sensible defaults for capture/export
CAPTURE_PACKET_LIMIT = int(config.get('capture_packet_limit', 200) if isinstance(config, dict) else 200)
CAPTURE_TIMEOUT_SECONDS = int(config.get('capture_timeout_seconds', 10) if isinstance(config, dict) else 10)

# In-memory IOC caches
ioc_ip_set = set()
ioc_cidrs = []
ioc_domains = set()
ioc_mtime = None
ioc_watcher_started = False

missing_keys = REQUIRED_CONFIG_KEYS - config.keys()

if missing_keys:
    raise RuntimeError(
        f"Missing required configuration keys: {', '.join(sorted(missing_keys))}"
    )

# --------------------------------------------------------------------------
# Constants / lookup tables
# --------------------------------------------------------------------------

SERROR_FLAGS = {'S0', 'S1', 'S2', 'S3'}
REJ_FLAG = 'REJ'

LOGIN_PORTS = {21, 22, 23, 3389}

FAILED_LOGIN_PATTERNS = (
    b"login incorrect", b"access denied", b"550 ", b"authentication failed",
    b"permission denied", b"login failed", b"530 ", b"incorrect password",
)
SUCCESS_LOGIN_PATTERNS: Dict[int, "re.Pattern"] = {
    21: re.compile(rb"230[ -]", re.IGNORECASE),
    22: re.compile(rb"welcome|last login", re.IGNORECASE),
    23: re.compile(rb"welcome|login successful", re.IGNORECASE),
    3389: re.compile(rb"session established", re.IGNORECASE),
}
SHELL_COMMAND_PATTERNS = (b'/bin/sh', b'/bin/bash', b'cmd.exe', b'root@', b'sudo ', b'# ')
FILE_OP_KEYWORDS = (b'retr ', b'stor ', b'get ', b'put ', b'download', b'upload')
GUEST_KEYWORDS = (b'anonymous', b'guest')

# NSL-KDD 'service' feature: mapped mostly by well-known port number.
# A handful of services are protocol-sensitive (e.g. DNS is 'domain' over
# TCP but 'domain_u' over UDP) -- those are special-cased in get_service().
PORT_SERVICE_MAP = {
    7: 'echo', 9: 'discard', 11: 'systat', 13: 'daytime', 19: 'chargen', 20: 'ftp_data',
    21: 'ftp', 22: 'ssh', 23: 'telnet', 24: 'mtp', 25: 'smtp', 37: 'time', 42: 'name',
    43: 'whois', 49: 'login', 53: 'domain', 67: 'csnet_ns', 68: 'csnet_ns', 69: 'tftp_u',
    70: 'gopher', 79: 'finger', 80: 'http', 87: 'link', 95: 'supdup', 101: 'hostname',
    102: 'iso_tsap', 105: 'csnet_ns', 106: 'pop_2', 109: 'pop_2', 110: 'pop_3',
    111: 'sunrpc', 119: 'nntp', 123: 'ntp_u', 137: 'netbios_ns', 138: 'netbios_dgm',
    139: 'netbios_ssn', 143: 'imap4', 150: 'sql_net', 152: 'bftp', 161: 'pm_dump',
    162: 'pm_dump', 170: 'print-srv', 177: 'X11', 179: 'bgp', 389: 'ldap', 443: 'http_443',
    445: 'private', 512: 'exec', 513: 'login', 514: 'shell', 515: 'printer', 520: 'rje',
    522: 'supdup', 525: 'tim_i', 526: 'tempo', 530: 'courier', 532: 'netnews',
    540: 'uucp', 543: 'klogin', 544: 'kshell', 546: 'eco_i', 547: 'eco_i', 554: 'rtsp',
    561: 'efc', 600: 'ipcserver', 631: 'printer', 993: 'imap4', 995: 'pop_3',
    1080: 'socks', 1433: 'sql_net', 1434: 'sql_net', 1521: 'sql_net', 1701: 'mtp',
    1720: 'h323', 1723: 'pptp', 2049: 'nfs', 2784: 'http_2784', 3306: 'sql_net',
    3389: 'vmnet', 5000: 'other', 5432: 'postgres', 6000: 'X11', 6379: 'redis',
    6667: 'IRC', 7000: 'afs', 8001: 'http_8001', 8080: 'http', 8081: 'http',
    8888: 'http', 8889: 'http', 9999: 'Z39_50', 27017: 'mongodb', 27018: 'other',
    31337: 'red_i',
}
# port -> udp-specific service name, where NSL-KDD distinguishes it from TCP
UDP_SERVICE_OVERRIDES = {53: 'domain_u'}

ICMP_TYPE_SERVICE_MAP = {
    0: 'ecr_i', 8: 'ecr_i',    # echo reply / echo request
    13: 'tim_i', 14: 'tim_i',  # timestamp request / reply
    3: 'urp_i',                # destination unreachable
}


# Lightweight caches for DNS and GeoIP to avoid repeated lookups
from functools import lru_cache

@lru_cache(maxsize=2000)
def cached_rdns(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

@lru_cache(maxsize=2000)
def cached_geo(ip: str) -> Optional[Dict[str, Any]]:
    try:
        geoip_db = config.get('geoip_db_path') if isinstance(config, dict) else None
        if not geoip_db:
            return None
        try:
            from app_geoip_helper import enrich_ip
        except Exception:
            return None
        info = enrich_ip(ip, geoip_db)
        return info.get('geo')
    except Exception:
        return None


def check_ioc(ip: Optional[str], rdns: Optional[str] = None) -> List[str]:
    """Check an IP and optional reverse DNS against loaded IOC lists.

    Returns a list of matching IOC descriptions (strings) or empty list.
    This is intentionally fast (in-memory lookups and CIDR checks).
    """
    matches = []
    if not ip:
        return matches
    try:
        if ip in ioc_ip_set:
            matches.append(f"ip:{ip}")
        # check CIDRs
        try:
            import ipaddress
            ipa = ipaddress.ip_address(ip)
            for net in ioc_cidrs:
                if ipa in net:
                    matches.append(f"cidr:{net}")
        except Exception:
            pass
        # check rdns against domains (if provided)
        if rdns:
            for d in ioc_domains:
                if rdns.endswith(d):
                    matches.append(f"domain:{d}")
    except Exception:
        pass
    return matches


def enrich_alert(alert: Dict[str, Any]) -> None:
    """Enrich an alert dict in-place with cached reverse DNS and optional cached GeoIP.

    This function is safe to call from a background worker and uses small
    in-memory LRU caches to avoid repeated network/database lookups.
    """
    if not isinstance(alert, dict):
        return

    src = alert.get('src_ip')
    dst = alert.get('dst_ip')

    try:
        alert['src_rdns'] = cached_rdns(src) if src else None
    except Exception:
        alert['src_rdns'] = None
    try:
        alert['dst_rdns'] = cached_rdns(dst) if dst else None
    except Exception:
        alert['dst_rdns'] = None

    try:
        src_geo = cached_geo(src) if src else None
        if src_geo:
            alert['src_geo'] = src_geo
    except Exception:
        pass
    try:
        dst_geo = cached_geo(dst) if dst else None
        if dst_geo:
            alert['dst_geo'] = dst_geo
    except Exception:
        pass

    # human-friendly summary
    try:
        parts = []
        if isinstance(alert.get('src_geo'), dict):
            sc = alert['src_geo'].get('city')
            sct = alert['src_geo'].get('country')
            if sc or sct:
                parts.append(f"src:{sc or ''}{', ' if sc and sct else ''}{sct or ''}".strip(', '))
        if isinstance(alert.get('dst_geo'), dict):
            dc = alert['dst_geo'].get('city')
            dct = alert['dst_geo'].get('country')
            if dc or dct:
                parts.append(f"dst:{dc or ''}{', ' if dc and dct else ''}{dct or ''}".strip(', '))
        if parts:
            alert['enrichment_summary'] = ' | '.join(parts)
    except Exception:
        pass


def get_service(src_port: Optional[int], dst_port: Optional[int], protocol_type: str = 'TCP') -> str:
    if protocol_type == 'UDP':
        if src_port in UDP_SERVICE_OVERRIDES:
            return UDP_SERVICE_OVERRIDES[src_port]
        if dst_port in UDP_SERVICE_OVERRIDES:
            return UDP_SERVICE_OVERRIDES[dst_port]
    if src_port in PORT_SERVICE_MAP:
        return PORT_SERVICE_MAP[src_port]
    if dst_port in PORT_SERVICE_MAP:
        return PORT_SERVICE_MAP[dst_port]
    return 'other'


def get_icmp_service(icmp_type: Optional[int]) -> str:
    return ICMP_TYPE_SERVICE_MAP.get(icmp_type, 'other')


def to_number(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def get_layer_payload_bytes(layer) -> bytes:
    """pyshark exposes a TCP/UDP segment's data as a colon-separated hex
    string in the `payload` (or `segment_data`) field, e.g. '47:45:54:20',
    NOT as literal text. It must be hex-decoded, not utf-8 encoded -- this
    was silently broken in the original code, which meant none of the
    payload-keyword heuristics (failed logins, shell access, guest login,
    file access) could ever match anything."""
    raw = (getattr(layer, 'payload', None) or getattr(layer, 'segment_data', None)
           or getattr(layer, 'data', None))
    if raw is None:
        return b''
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    try:
        return bytes.fromhex(str(raw).replace(':', ''))
    except ValueError:
        return b''


def get_packet_payload(packet) -> bytes:
    for proto_name in ('tcp', 'udp'):
        layer = getattr(packet, proto_name, None)
        if layer is not None:
            payload = get_layer_payload_bytes(layer)
            if payload:
                return payload
    # ICMP payload isn't a top-level layer -- it's a nested sub-layer
    # (packet.icmp.data), whose own .data field holds the hex string.
    # Missing this meant src_bytes/dst_bytes were permanently stuck at 0
    # for every ICMP flow, which silently broke smurf's signature (it
    # requires src_bytes in [508,1032] specifically to distinguish a heavy
    # amplification payload from an ordinary ping). Verified directly
    # against a captured ICMP packet before relying on this.
    for proto_name in ('icmp', 'icmpv6'):
        icmp_layer = getattr(packet, proto_name, None)
        if icmp_layer is not None:
            data_sublayer = getattr(icmp_layer, 'data', None)
            if data_sublayer is not None:
                payload = get_layer_payload_bytes(data_sublayer)
                if payload:
                    return payload
    return b''


def compute_entropy(values: Iterable[Any]) -> float:
    values = list(values)
    if not values:
        return 0.0
    counts = Counter(values)
    total = sum(counts.values())
    probs = (c / total for c in counts.values())
    return -sum(p * math.log2(p) for p in probs if p > 0)


# --------------------------------------------------------------------------
# TCP connection state -> KDD/Zeek-style 'flag'
# --------------------------------------------------------------------------

class ConnState:
    """
    Tracks one connection's TCP handshake/teardown lifecycle to derive a
    KDD/Zeek-style connection state: SF, S0, S1, S2, S3, REJ, RSTO, RSTR,
    RSTOS0, SH, OTH. This is the origin of the NSL-KDD 'flag' feature --
    it describes the outcome of the WHOLE connection, not any one packet.
    """

    __slots__ = ('syn_seen', 'synack_seen', 'established', 'fin_orig',
                 'fin_resp', 'rst_orig', 'rst_resp', 'any_data')

    def __init__(self):
        self.syn_seen = False
        self.synack_seen = False
        self.established = False
        self.fin_orig = False
        self.fin_resp = False
        self.rst_orig = False
        self.rst_resp = False
        self.any_data = False

    def observe(self, is_orig: bool, syn: bool, ack: bool, fin: bool, rst: bool, has_payload: bool) -> None:
        if rst:
            if is_orig:
                self.rst_orig = True
            else:
                self.rst_resp = True
            return
        if syn and not ack:
            if is_orig:
                self.syn_seen = True
        elif syn and ack:
            if not is_orig:
                self.synack_seen = True
        elif ack and self.synack_seen and is_orig and not self.established:
            self.established = True
        if fin:
            if is_orig:
                self.fin_orig = True
            else:
                self.fin_resp = True
        if has_payload:
            self.any_data = True
            if self.synack_seen:
                self.established = True

    @property
    def flag(self) -> str:
        if self.rst_orig:
            return 'RSTO' if (self.established or self.synack_seen) else 'RSTOS0'
        if self.rst_resp:
            return 'RSTR' if (self.established or self.synack_seen) else 'REJ'
        if self.syn_seen and not self.synack_seen:
            return 'SH' if self.fin_orig else 'S0'
        if self.established or self.any_data:
            if self.fin_orig and self.fin_resp:
                return 'SF'
            if self.fin_orig:
                return 'S2'
            if self.fin_resp:
                return 'S3'
            return 'S1'
        if self.synack_seen:
            return 'S1'
        return 'OTH'


# --------------------------------------------------------------------------
# Cross-flow aggregation (count / srv_count / *error_rate / dst_host_*)
# --------------------------------------------------------------------------

class ConnRecord:
    __slots__ = ('flow_id', 'timestamp', 'src_ip', 'src_port', 'dst_ip',
                 'dst_port', 'service', 'protocol_type', 'flag')

    def __init__(self, flow_id, timestamp, src_ip, src_port, dst_ip, dst_port,
                 service, protocol_type, flag):
        self.flow_id = flow_id
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.service = service
        self.protocol_type = protocol_type
        self.flag = flag


def _frac(records, predicate, total: int) -> float:
    if not total:
        return 0.0
    return sum(1 for r in records if predicate(r)) / total


class HostConnectionTracker:
    """
    A single FlowFeatures object only knows about its own 5-tuple, but
    several NSL-KDD features are explicitly defined over OTHER recent
    connections:

      - 'traffic' features (count, srv_count, *error_rate, same/diff_srv_rate)
        use a 2-second time window across ALL connections.
      - 'host' features (dst_host_*) use a window of the last 100
        connections to the SAME destination host.

    This class holds both windows and recomputes them as flows are
    observed. It also tracks simple per-source fan-out (distinct
    destination ports / distinct destination hosts in a short window) to
    power deterministic portsweep/ipsweep heuristics -- those two attack
    types are defined by cross-connection breadth rather than any single
    connection's content, which is exactly what the scored KDD-style
    matcher is weakest at.

    Scale note: this project scans the whole recent-record set per lookup
    (O(active flows)), which is simple, obviously correct, and fine for a
    demo/portfolio-scale deployment. A production NIDS would index records
    by destination host up front; left as a documented follow-up.
    """

    TIME_WINDOW_SECONDS = 2.0
    HOST_WINDOW_SIZE = 100
    STALE_RECORD_SECONDS = 600  # garbage-collect flows untouched this long

    def __init__(self, portsweep_port_threshold: int = 5,
                 ipsweep_host_threshold: int = 5,
                 recon_window_seconds: float = 10.0):
        self._records: Dict[str, ConnRecord] = {}
        self._host_order: Dict[str, Deque[str]] = defaultdict(lambda: deque(maxlen=self.HOST_WINDOW_SIZE))
        self._dst_ports_seen: Dict[Tuple[str, str], Deque[Tuple[float, int]]] = defaultdict(deque)
        self._dst_hosts_seen: Dict[str, Deque[Tuple[float, str]]] = defaultdict(deque)
        self.portsweep_port_threshold = portsweep_port_threshold
        self.ipsweep_host_threshold = ipsweep_host_threshold
        self.recon_window_seconds = recon_window_seconds
        self._touches_since_cleanup = 0

    def update(self, flow_id: str, timestamp: float, src_ip: str, src_port: int,
               dst_ip: str, dst_port: int, service: str, protocol_type: str,
               flag: str) -> None:
        rec = self._records.get(flow_id)
        if rec is None:
            rec = ConnRecord(flow_id, timestamp, src_ip, src_port, dst_ip,
                              dst_port, service, protocol_type, flag)
            self._records[flow_id] = rec
            self._host_order[dst_ip].append(flow_id)
        else:
            rec.timestamp = timestamp
            rec.flag = flag
            rec.service = service

        port_hist = self._dst_ports_seen[(src_ip, dst_ip)]
        port_hist.append((timestamp, dst_port))
        self._prune_pairs(port_hist, timestamp, self.recon_window_seconds)

        host_hist = self._dst_hosts_seen[src_ip]
        host_hist.append((timestamp, dst_ip))
        self._prune_pairs(host_hist, timestamp, self.recon_window_seconds)

        self._touches_since_cleanup += 1
        if self._touches_since_cleanup >= 2000:
            self._cleanup(timestamp)
            self._touches_since_cleanup = 0

    @staticmethod
    def _prune_pairs(dq: "Deque[Tuple[float, Any]]", now: float, window: float) -> None:
        while dq and now - dq[0][0] > window:
            dq.popleft()

    def _cleanup(self, now: float) -> None:
        stale = [fid for fid, rec in self._records.items()
                 if now - rec.timestamp > self.STALE_RECORD_SECONDS]
        for fid in stale:
            del self._records[fid]

    def time_based_features(self, dst_ip: str, service: str, now: float) -> Dict[str, float]:
        same_host = [r for r in self._records.values()
                     if r.dst_ip == dst_ip and now - r.timestamp <= self.TIME_WINDOW_SECONDS]
        same_srv = [r for r in self._records.values()
                    if r.service == service and now - r.timestamp <= self.TIME_WINDOW_SECONDS]
        count = len(same_host)
        srv_count = len(same_srv)
        return {
            'count': count,
            'srv_count': srv_count,
            'serror_rate': _frac(same_host, lambda r: r.flag in SERROR_FLAGS, count),
            'rerror_rate': _frac(same_host, lambda r: r.flag == REJ_FLAG, count),
            'same_srv_rate': _frac(same_host, lambda r: r.service == service, count),
            'diff_srv_rate': _frac(same_host, lambda r: r.service != service, count),
            'srv_serror_rate': _frac(same_srv, lambda r: r.flag in SERROR_FLAGS, srv_count),
            'srv_rerror_rate': _frac(same_srv, lambda r: r.flag == REJ_FLAG, srv_count),
            'srv_diff_host_rate': _frac(same_srv, lambda r: r.dst_ip != dst_ip, srv_count),
        }

    def host_based_features(self, src_ip: str, src_port: int, dst_ip: str, service: str) -> Dict[str, float]:
        ids = self._host_order.get(dst_ip, deque())
        window = [self._records[fid] for fid in ids if fid in self._records]
        dst_host_count = len(window)
        same_srv = [r for r in window if r.service == service]
        dst_host_srv_count = len(same_srv)
        return {
            'dst_host_count': dst_host_count,
            'dst_host_srv_count': dst_host_srv_count,
            'dst_host_same_srv_rate': _frac(window, lambda r: r.service == service, dst_host_count),
            'dst_host_diff_srv_rate': _frac(window, lambda r: r.service != service, dst_host_count),
            'dst_host_same_src_port_rate': _frac(window, lambda r: r.src_port == src_port, dst_host_count),
            # Approximation: among connections that share this dst host+service,
            # the fraction that came from a DIFFERENT source than the current
            # one. This is a source-diversity proxy for the original feature.
            'dst_host_srv_diff_host_rate': _frac(same_srv, lambda r: r.src_ip != src_ip, dst_host_srv_count),
            'dst_host_serror_rate': _frac(window, lambda r: r.flag in SERROR_FLAGS, dst_host_count),
            'dst_host_srv_serror_rate': _frac(same_srv, lambda r: r.flag in SERROR_FLAGS, dst_host_srv_count),
            'dst_host_rerror_rate': _frac(window, lambda r: r.flag == REJ_FLAG, dst_host_count),
            'dst_host_srv_rerror_rate': _frac(same_srv, lambda r: r.flag == REJ_FLAG, dst_host_srv_count),
        }

    def check_portsweep(self, src_ip: str, dst_ip: str) -> Tuple[bool, int]:
        ports = self._dst_ports_seen.get((src_ip, dst_ip))
        if not ports:
            return False, 0
        distinct = {p for _, p in ports}
        return len(distinct) >= self.portsweep_port_threshold, len(distinct)

    def check_ipsweep(self, src_ip: str) -> Tuple[bool, int]:
        hosts = self._dst_hosts_seen.get(src_ip)
        if not hosts:
            return False, 0
        distinct = {h for _, h in hosts}
        return len(distinct) >= self.ipsweep_host_threshold, len(distinct)


# --------------------------------------------------------------------------
# Per-flow feature extraction
# --------------------------------------------------------------------------

class FlowFeatures:
    def __init__(self, flow_id: str, src_ip: str, dst_ip: str, src_port: int,
                 dst_port: int, protocol_type: str, cfg: dict):
        self.flow_id = flow_id
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol_type = protocol_type
        self.service = get_service(src_port, dst_port, protocol_type)

        self.config = cfg
        self.monitored_ip = cfg.get('monitored_ip', dst_ip)

        self.start_time: Optional[float] = None
        self.last_time: Optional[float] = None
        self.duration = 0.0

        self.src_bytes = 0
        self.dst_bytes = 0
        self.packet_count = 0
        self.fwd_packets = 0
        self.bwd_packets = 0
        self.wrong_fragment = 0
        self.urgent = 0
        self.land = int(src_ip == dst_ip and src_port == dst_port)

        self.conn_state = ConnState() if protocol_type == 'TCP' else None
        self.flag = 'SF' if protocol_type == 'UDP' else 'OTH'

        # Content / heuristic features -- best-effort payload keyword
        # matching. There's no full protocol/session reconstruction, so
        # treat these as indicative, not authoritative.
        self.hot = 0
        self.num_failed_logins = 0
        self.logged_in = False
        self.num_compromised = 0
        self.root_shell = 0
        self.su_attempted = 0
        self.num_root = 0
        self.num_file_creations = 0
        self.num_shells = 0
        self.num_access_files = 0
        self.num_outbound_cmds = 0
        self.is_host_login = False
        self.is_guest_login = 0

        self.outcome = 'normal'
        self.confidence = 0.0
        self.level = 0

    def observe(self, packet, timestamp: float, direction: str) -> None:
        is_orig = (direction == 'fwd')
        if self.start_time is None:
            self.start_time = timestamp
        self.last_time = timestamp
        self.duration = max(0.0, self.last_time - self.start_time)
        self.packet_count += 1

        payload = get_packet_payload(packet)
        payload_len = len(payload)

        ip_layer = getattr(packet, 'ip', None)
        if ip_layer is not None:
            self._observe_fragmentation(ip_layer)

        tcp_layer = getattr(packet, 'tcp', None)
        udp_layer = getattr(packet, 'udp', None)
        icmp_layer = getattr(packet, 'icmp', None)

        if tcp_layer is not None:
            self._observe_tcp(tcp_layer, is_orig, payload_len > 0)
        elif udp_layer is not None:
            self.flag = 'SF'
        elif icmp_layer is not None:
            self._observe_icmp(icmp_layer)

        if is_orig:
            self.src_bytes += payload_len
            self.fwd_packets += 1
        else:
            self.dst_bytes += payload_len
            self.bwd_packets += 1

        self._observe_content(payload)

    def _observe_fragmentation(self, ip_layer) -> None:
        try:
            frag_offset = int(getattr(ip_layer, 'frag_offset', 0) or 0)
        except (TypeError, ValueError):
            frag_offset = 0
        try:
            ip_flags = int(str(getattr(ip_layer, 'flags', '0x00')), 16)
        except (TypeError, ValueError):
            ip_flags = 0
        more_fragments = bool(ip_flags & 0x1)
        if more_fragments or frag_offset > 0:
            self.wrong_fragment += 1

    def _observe_tcp(self, tcp_layer, is_orig: bool, has_payload: bool) -> None:
        try:
            raw_flags = int(str(tcp_layer.flags), 16)
        except (TypeError, ValueError):
            raw_flags = 0
        syn = bool(raw_flags & 0x02)
        ack = bool(raw_flags & 0x10)
        fin = bool(raw_flags & 0x01)
        rst = bool(raw_flags & 0x04)
        urg = bool(raw_flags & 0x20)

        if urg:
            self.urgent += 1
        else:
            urg_ptr = getattr(tcp_layer, 'urgent_pointer', None)
            try:
                if urg_ptr is not None and int(urg_ptr) > 0:
                    self.urgent += 1
            except (TypeError, ValueError):
                pass

        if self.conn_state is None:
            self.conn_state = ConnState()
        self.conn_state.observe(is_orig, syn, ack, fin, rst, has_payload)
        self.flag = self.conn_state.flag

    def _observe_icmp(self, icmp_layer) -> None:
        try:
            icmp_type = int(getattr(icmp_layer, 'type', -1))
        except (TypeError, ValueError):
            icmp_type = -1
        self.service = get_icmp_service(icmp_type)
        self.flag = 'REJ' if icmp_type == 3 else 'SF'

    def _observe_content(self, payload: bytes) -> None:
        if not payload:
            return
        payload_lower = payload.lower()

        if any(pat in payload_lower for pat in FAILED_LOGIN_PATTERNS):
            self.num_failed_logins += 1

        if not self.logged_in:
            if self.dst_port in LOGIN_PORTS and self.src_bytes > 0 and self.dst_bytes > 0:
                self.logged_in = True
            pattern = SUCCESS_LOGIN_PATTERNS.get(self.dst_port)
            if pattern and pattern.search(payload):
                self.logged_in = True

        if self.logged_in:
            if any(k in payload_lower for k in GUEST_KEYWORDS):
                self.is_guest_login = 1
            service_l = (self.service or '').lower()
            if service_l in ('ftp', 'tftp_u') or any(k in payload_lower for k in FILE_OP_KEYWORDS):
                self.num_access_files += 1
            if service_l in ('ssh', 'telnet', 'shell', 'login') and any(
                    cmd in payload_lower for cmd in SHELL_COMMAND_PATTERNS):
                self.num_compromised = 1
                self.num_shells += 1
                if b'root@' in payload_lower or b'sudo ' in payload_lower:
                    self.root_shell = 1
                    self.su_attempted = 1

        self.hot = int(self.num_failed_logins > 3 or self.num_access_files > 5 or self.root_shell == 1)

    def snapshot(self, tracker: HostConnectionTracker, now: float) -> Dict[str, Any]:
        """Combine this flow's own features with the tracker's cross-flow
        features into one flat dict, used both for classification and for
        the dashboard payload -- a single source of truth for both."""
        time_feats = tracker.time_based_features(self.dst_ip, self.service, now)
        host_feats = tracker.host_based_features(self.src_ip, self.src_port, self.dst_ip, self.service)

        features: Dict[str, Any] = {
            'duration': round(self.duration, 3),
            'protocol_type': self.protocol_type,
            'service': self.service or 'other',
            'flag': self.flag,
            'src_bytes': self.src_bytes,
            'dst_bytes': self.dst_bytes,
            'land': self.land,
            'wrong_fragment': self.wrong_fragment,
            'urgent': self.urgent,
            'hot': self.hot,
            'num_failed_logins': self.num_failed_logins,
            'logged_in': int(self.logged_in),
            'num_compromised': self.num_compromised,
            'root_shell': self.root_shell,
            'su_attempted': self.su_attempted,
            'num_root': self.num_root,
            'num_file_creations': self.num_file_creations,
            'num_shells': self.num_shells,
            'num_access_files': self.num_access_files,
            'num_outbound_cmds': self.num_outbound_cmds,
            'is_host_login': int(self.is_host_login),
            'is_guest_login': self.is_guest_login,
        }
        features.update(time_feats)
        features.update(host_feats)
        for key in ('serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
                    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
                    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
                    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
                    'dst_host_serror_rate', 'dst_host_srv_serror_rate',
                    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'):
            features[key] = round(float(features.get(key, 0.0)), 3)
        return features


# --------------------------------------------------------------------------
# Signature scoring
# --------------------------------------------------------------------------

def _as_list(value) -> List[str]:
    return value if isinstance(value, list) else [value]


def score_attack(features: Dict[str, Any], attack_cfg: Dict[str, Any]) -> Tuple[bool, float]:
    """Hard-gate on protocol/service/flag/zero_fields, then score the
    fraction of range conditions satisfied.

    zero_fields are a HARD gate, not part of the fractional score. They
    represent near-invariant properties of an attack category (a real
    SYN flood genuinely has zero response bytes, zero login activity,
    etc.) -- unlike ranges, they have essentially no natural jitter, so
    violating even one is strong evidence the flow doesn't belong to
    this category. Averaging them in with 30+ range conditions let a
    single ordinary HTTP request/response (nonzero dst_bytes, nonzero
    duration) still score ~0.90 against 'ipsweep' -- which requires
    dst_bytes==0 -- because two failed zero_fields barely dented a
    39-condition average. Confirmed empirically before this fix."""
    protocol_types = attack_cfg.get('protocol_types')
    if protocol_types:
        allowed = {p.upper() for p in _as_list(protocol_types)}
        if str(features.get('protocol_type', '')).upper() not in allowed:
            return False, 0.0

    services = attack_cfg.get('services')
    if services:
        allowed = {s.lower() for s in _as_list(services)}
        if str(features.get('service', '')).lower() not in allowed:
            return False, 0.0

    flags = attack_cfg.get('flags')
    if flags:
        allowed = {f.upper() for f in _as_list(flags)}
        if str(features.get('flag', '')).upper() not in allowed:
            return False, 0.0

    zero_fields = attack_cfg.get('zero_fields', []) or []
    for field_name in zero_fields:
        if to_number(features.get(field_name, 0)) != 0:
            return False, 0.0

    ranges = attack_cfg.get('ranges', {}) or {}
    if not ranges:
        return True, 1.0

    hits = 0
    for field_name, bounds in ranges.items():
        lo, hi = bounds[0], bounds[1]
        val = to_number(features.get(field_name, 0))
        if lo <= val <= hi:
            hits += 1

    return True, hits / len(ranges)


# Flags that describe a connection still IN PROGRESS (handshake not yet
# finished either way). Every ordinary new TCP connection passes through
# S0 for the first few milliseconds of its life -- if we score against
# signatures the instant a packet arrives, an ordinary browser tab
# opening a connection looks identical to a neptune SYN, for that one
# instant. We give a connection a brief grace period to resolve itself
# (complete the handshake, get rejected, etc.) unless there's already
# cross-flow corroboration (several other half-open connections to the
# same host right now, which IS what a real SYN flood looks like from
# the very first packet).
TRANSIENT_FLAGS = {'S0', 'S1', 'S2', 'S3', 'SH'}


def classify(features: Dict[str, Any], thresholds: Dict[str, Any],
             match_threshold: float, half_open_grace_seconds: float = 0.5,
             half_open_min_count: int = 3) -> Tuple[str, float]:
    """Picks the highest-scoring attack that clears both its hard gates
    and the confidence threshold, instead of the first exact match found
    in dict order."""
    if features.get('flag') in TRANSIENT_FLAGS:
        settled_long_enough = features.get('duration', 0.0) >= half_open_grace_seconds
        corroborated = features.get('count', 0) >= half_open_min_count
        if not settled_long_enough and not corroborated:
            return 'normal', 0.0

    best_name, best_score = 'normal', 0.0
    for name, cfg in thresholds.items():
        gates_ok, score = score_attack(features, cfg)
        if gates_ok and score >= match_threshold and score > best_score:
            best_name, best_score = name, score
    return best_name, best_score


# --------------------------------------------------------------------------
# Packet capture / orchestration
# --------------------------------------------------------------------------

class PacketAnalyzer:
    def __init__(self, config_path: str = CONFIG_PATH):
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
        
        self.config = config
        self.thresholds = self.config.get('thresholds', {})
        detection_cfg = self.config.get('detection', {})
        self.match_threshold = detection_cfg.get('match_threshold', 0.85)
        self.half_open_grace_seconds = detection_cfg.get('half_open_grace_seconds', 0.5)
        self.half_open_min_count = detection_cfg.get('half_open_min_count', 3)
        self.interface = self.config.get('interface', 'Wi-Fi')

        self.tracker = HostConnectionTracker(
            portsweep_port_threshold=self.config.get('portsweep_port_threshold', 5),
            ipsweep_host_threshold=self.config.get('ipsweep_host_threshold', 5),
        )
        self.threat_intel = self.config.get('threat_intel', {})
        self.rule_active_window = detection_cfg.get('rule_active_window_seconds', 15.0)
        self.flows: Dict[str, FlowFeatures] = {}
        self.running = True
        self._processing_times: Deque[float] = deque(maxlen=200)

        # capture tuning: optional BPF filter and sampling rate to reduce load
        self.bpf_filter = self.config.get('capture_bpf') or None
        # sampling_rate: process 1 in N packets (integer >=1)
        try:
            sr = int(self.config.get('sampling_rate', 1))
            self.sampling_rate = max(1, sr)
        except Exception:
            self.sampling_rate = 1
        self._capture_counter = 0

    @property
    def avg_detection_latency_ms(self) -> float:
        if not self._processing_times:
            return 0.0
        return round(sum(self._processing_times) / len(self._processing_times) * 1000, 2)

    @staticmethod
    def determine_protocol(packet) -> str:
        if hasattr(packet, 'tcp'):
            return 'TCP'
        if hasattr(packet, 'udp'):
            return 'UDP'
        if hasattr(packet, 'icmp') or hasattr(packet, 'icmpv6'):
            return 'ICMP'
        return 'OTHER'

    @staticmethod
    def extract_ports(packet, protocol_type: str) -> Tuple[int, int]:
        try:
            if protocol_type == 'TCP' and hasattr(packet, 'tcp'):
                return int(packet.tcp.srcport), int(packet.tcp.dstport)
            if protocol_type == 'UDP' and hasattr(packet, 'udp'):
                return int(packet.udp.srcport), int(packet.udp.dstport)
        except (AttributeError, ValueError):
            pass
        return 0, 0

    @staticmethod
    def get_flow_id(src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol_type: str) -> str:
        # Canonical, direction-independent id so both directions of the
        # same connection map to one FlowFeatures instance.
        a, b = (src_ip, src_port), (dst_ip, dst_port)
        lo, hi = (a, b) if a <= b else (b, a)
        return f"{protocol_type}:{lo[0]}:{lo[1]}-{hi[0]}:{hi[1]}"

    def process_packet(self, packet) -> None:
        _start_perf = time.perf_counter()
        try:
            ip_layer = getattr(packet, 'ip', None) or getattr(packet, 'ipv6', None)
            if ip_layer is None:
                return
            src_ip, dst_ip = getattr(ip_layer, 'src', None), getattr(ip_layer, 'dst', None)
            if src_ip is None or dst_ip is None:
                return
            protocol_type = self.determine_protocol(packet)
            src_port, dst_port = self.extract_ports(packet, protocol_type)
            timestamp = float(packet.sniff_time.timestamp())

            flow_id = self.get_flow_id(src_ip, src_port, dst_ip, dst_port, protocol_type)
            flow = self.flows.get(flow_id)
            if flow is None:
                flow = FlowFeatures(flow_id, src_ip, dst_ip, src_port, dst_port,
                                     protocol_type, self.config)
                self.flows[flow_id] = flow

            direction = 'fwd' if (src_ip == flow.src_ip and src_port == flow.src_port) else 'bwd'
            flow.observe(packet, timestamp, direction)

            # Update host-level tracking before classification so the current
            # connection is reflected in cross-flow features and recon heuristics.
            self.tracker.update(flow_id, timestamp, flow.src_ip, flow.src_port,
                                 flow.dst_ip, flow.dst_port, flow.service,
                                 flow.protocol_type, flow.flag)

            features = flow.snapshot(self.tracker, timestamp)
            outcome, score = classify(features, self.thresholds, self.match_threshold,
                                       self.half_open_grace_seconds, self.half_open_min_count)

            recon_outcome = self._check_recon_heuristics(src_ip, dst_ip)
            if recon_outcome:
                outcome, score = recon_outcome, max(score, 0.99)

            flow.outcome = outcome
            flow.confidence = score
            flow.level = 0 if outcome == 'normal' else 1

            packet_data = self._build_dashboard_payload(flow, features, outcome, score, timestamp)
            try:
                dashboard_event_queue.put_nowait(packet_data)
            except queue.Full:
                # Keep the queue size bounded under heavy load by dropping the oldest
                try:
                    dashboard_event_queue.get_nowait()
                except queue.Empty:
                    pass
                try:
                    dashboard_event_queue.put_nowait(packet_data)
                except queue.Full:
                    pass
 
            if outcome != 'normal':
                alert_data = self._build_alert_payload(packet_data)
                try:
                    # enqueue alert quickly; enrichment will run asynchronously to avoid blocking capture
                    alert_event_queue.put_nowait(alert_data)
                except Exception:
                    logger.debug('Failed to enqueue alert: %s', traceback.format_exc())
                except queue.Full:
                    try:
                        alert_event_queue.get_nowait()
                    except queue.Empty:
                        pass
                    try:
                        alert_event_queue.put_nowait(alert_data)
                    except queue.Full:
                        pass
 
            global total_packets_processed, total_attacks_detected
            total_packets_processed += 1
            chart_data_packets_per_sec.append(1)
            if outcome != 'normal':
                total_attacks_detected += 1
                chart_data_attacks_per_sec.append(1)
            else:
                chart_data_attacks_per_sec.append(0)

        except Exception:
            logger.exception("Error processing packet")
        finally:
            self._processing_times.append(time.perf_counter() - _start_perf)

    def _check_recon_heuristics(self, src_ip: str, dst_ip: str) -> Optional[str]:
        """Deterministic, cross-flow recon detectors. portsweep/ipsweep are
        defined by breadth across many connections, not by any single
        connection's content -- a plain distinct-count rule is more
        reliable here than trying to force them through the KDD-style
        scored matcher."""
        is_portsweep, _ = self.tracker.check_portsweep(src_ip, dst_ip)
        if is_portsweep:
            return 'portsweep'
        is_ipsweep, _ = self.tracker.check_ipsweep(src_ip)
        if is_ipsweep:
            return 'ipsweep'
        return None

    @staticmethod
    def _build_dashboard_payload(flow: FlowFeatures, features: Dict[str, Any],
                                  outcome: str, score: float, timestamp: float) -> Dict[str, Any]:
        data = dict(features)
        data.update({
            'flow_id': flow.flow_id,
            'src_ip': flow.src_ip,
            'dst_ip': flow.dst_ip,
            'src_port': flow.src_port,
            'dst_port': flow.dst_port,
            'outcome': outcome,
            'confidence': round(score, 3),
            'level': flow.level,
            'timestamp': datetime.fromtimestamp(timestamp).isoformat(),
        })
        return data

    def _build_alert_payload(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        outcome = flow_data.get('outcome')
        # Was: severity = 'high' if outcome in {'neptune','portsweep','ipsweep'} else 'medium' --
        # a hardcoded 3-attack guess that ignored config.json's actual per-attack severity
        # (and got several wrong: portsweep/ipsweep are 'medium' there, while guess_passwd
        # and processtable -- rated 'high' -- fell through to the 'medium' default).
        severity = self.threat_intel.get(outcome, {}).get('severity', 'medium')
        return {
            'flow_id': flow_data.get('flow_id'),
            'src_ip': flow_data.get('src_ip'),
            'dst_ip': flow_data.get('dst_ip'),
            'protocol_type': flow_data.get('protocol_type'),
            'outcome': outcome,
            'confidence': flow_data.get('confidence'),
            'timestamp': flow_data.get('timestamp'),
            'severity': severity,
            'message': f"Suspicious activity detected: {outcome}",
            'acknowledged': False,
        }

    def capture_packets(self) -> None:
        """Opens the capture ONCE and sniffs continuously until stopped.

        PyShark internally relies on asyncio. Because Flask-SocketIO is using
        Eventlet green threads, there may be no asyncio event loop available.
        This creates one for the capture worker before starting tshark.
        """

        import asyncio

        try:
            asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        logger.info(f"Starting capture on interface: {self.interface}")

        capture = None

        try:
            # Apply optional BPF filter to reduce capture volume at source (low CPU and memory impact)
            if self.bpf_filter:
                logger.info(f"Applying BPF filter for capture: {self.bpf_filter}")
                capture = pyshark.LiveCapture(interface=self.interface, bpf_filter=self.bpf_filter)
            else:
                capture = pyshark.LiveCapture(interface=self.interface)

            for packet in capture.sniff_continuously():

                if not self.running:
                    break

                try:
                    # simple packet sampling to reduce processing load (process 1 in N packets)
                    self._capture_counter += 1
                    if self.sampling_rate > 1 and (self._capture_counter % self.sampling_rate) != 0:
                        # yield to eventlet and skip heavy work
                        socketio.sleep(0)
                        continue

                    self.process_packet(packet)

                except Exception:
                    logger.debug(traceback.format_exc())

                # Allow Flask-SocketIO/Eventlet to handle other tasks
                socketio.sleep(0)

        except Exception:
            logger.exception("Capture error")

        finally:
            if capture is not None:
                try:
                    capture.close()
                except Exception:
                    pass


# --------------------------------------------------------------------------
# Flask / SocketIO wiring
# --------------------------------------------------------------------------

ids_running = False
packet_analyzer_instance: Optional[PacketAnalyzer] = None
dashboard_emitter_started = False
capture_start_time: Optional[float] = None
# Cumulative counters for the current capture session -- these did not
# exist anywhere before, which is why "Total Packets"/"Detected Attacks"
# on the dashboard always showed 0 regardless of actual traffic.
total_packets_processed = 0
total_attacks_detected = 0


@app.route('/')
def dashboard():
    return render_template('index.html', page='dashboard')


@app.route('/alerts')
def alerts():
    return render_template('alerts.html', page='alerts')


@app.route('/flows')
def flows():
    return render_template('flows.html', page='flows')


@app.route('/export')
def export_page():
    return render_template('export.html', page='export')


@app.route('/settings')
def settings():
    return render_template('settings.html', page='settings', config=config)


@socketio.on('connect')
def on_connect():
    global dashboard_emitter_started
    logger.info('Client connected')
    if not dashboard_emitter_started:
        dashboard_emitter_started = True
        socketio.start_background_task(emit_flow_data_from_queue)
        logger.info('Started dashboard emitter task')
    # This is a multi-page app -- every navigation is a full page reload,
    # which creates a brand new socket connection with no memory of
    # whether capture was already running. Without this, the Start/Stop
    # buttons always reset to the HTML's hardcoded default (Start enabled,
    # Stop disabled) after navigating away and back, even mid-capture.
    emit('status_update', {
        'status': 'IDS Started' if ids_running else 'IDS Stopped',
        'color': 'success' if ids_running else 'info',
        'running': ids_running,
    })


@socketio.on('disconnect')
def on_disconnect():
    logger.info('Client disconnected')


def ids_capture_loop():
    global ids_running, packet_analyzer_instance
    if packet_analyzer_instance is None:
        packet_analyzer_instance = PacketAnalyzer(CONFIG_PATH)
    global capture_start_time
    capture_start_time = time.time()
    packet_analyzer_instance.running = True
    try:
        packet_analyzer_instance.capture_packets()
    except Exception:
        logger.error(f"IDS capture loop error: {traceback.format_exc()}")
    finally:
        ids_running = False
        packet_analyzer_instance = None
        capture_start_time = None


@socketio.on('start_ids')
def start_ids():
    global ids_running, total_packets_processed, total_attacks_detected
    if not ids_running:
        ids_running = True
        total_packets_processed = 0
        total_attacks_detected = 0
        socketio.start_background_task(ids_capture_loop)
        emit('status_update', {'status': 'IDS Started', 'color': 'success', 'running': True})
        logger.info("IDS start requested.")
    else:
        emit('status_update', {'status': 'IDS is already running', 'color': 'warning', 'running': True})


@socketio.on('ack_alert')
def ack_alert(data):
    """Mark an alert acknowledged by flow_id and broadcast the update."""
    flow_id = data.get('flow_id') if isinstance(data, dict) else None
    if not flow_id:
        return
    updated = None
    for a in list(recent_alerts):
        if a.get('flow_id') == flow_id:
            a['acknowledged'] = True
            # record when acknowledged for persistence
            a['acknowledged_timestamp'] = datetime.utcnow().isoformat() + 'Z'
            updated = a
            break
    if updated is not None:
        try:
            socketio.emit('alert_update', {'alerts': [updated]})
        except Exception:
            logger.error(f"Emit error on ack_alert: {traceback.format_exc()}")
        # enqueue a persist update (non-blocking)
        try:
            persist_item = {'action': 'update', 'alert': updated}
            alert_persist_queue.put_nowait(persist_item)
        except queue.Full:
            logger.warning('Alert persist queue full; dropping persist update')


@socketio.on('investigate_alert')
def investigate_alert(data):
    """Mark an alert investigated with optional note and broadcast the update."""
    if not isinstance(data, dict):
        return
    flow_id = data.get('flow_id')
    note = data.get('note')
    false_positive = bool(data.get('false_positive'))
    if not flow_id:
        return
    updated = None
    for a in list(recent_alerts):
        if a.get('flow_id') == flow_id:
            a['acknowledged'] = True
            a['investigated'] = True
            a.setdefault('investigator_notes', [])
            entry = {
                'note': note or ('False positive' if false_positive else 'Investigated'),
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'false_positive': false_positive,
                'investigator': data.get('investigator') if isinstance(data, dict) else None,
            }
            a['investigator_notes'].append(entry)
            # record investigator at top-level for quick access
            inv = data.get('investigator') if isinstance(data, dict) else None
            if inv:
                a['investigator'] = inv
            updated = a
            break
    if updated is not None:
        try:
            socketio.emit('alert_update', {'alerts': [updated]})
        except Exception:
            logger.error(f"Emit error on investigate_alert: {traceback.format_exc()}")
        try:
            persist_item = {'action': 'update', 'alert': updated}
            alert_persist_queue.put_nowait(persist_item)
        except queue.Full:
            logger.warning('Alert persist queue full; dropping persist update')


@socketio.on('stop_ids')
def stop_ids():
    global ids_running, packet_analyzer_instance
    if ids_running:
        ids_running = False
        if packet_analyzer_instance is not None:
            packet_analyzer_instance.running = False
        emit('status_update', {'status': 'IDS Stopping...', 'color': 'warning', 'running': False})
        logger.info("IDS stop requested.")
    else:
        emit('status_update', {'status': 'IDS is not running', 'color': 'info', 'running': False})


def get_system_health() -> Dict[str, Any]:
    """Real metrics, not placeholders: process CPU/RAM via psutil, queue
    depth from the actual event queue, packets/sec from the same rolling
    window the traffic chart uses, and uptime from when capture actually
    started. (The previous version of these handlers sent hardcoded 0s
    for cpu_percent/memory_used_mb despite psutil already being imported
    and used elsewhere in this file for /api/interfaces.)"""
    mem_info = _process_handle.memory_info()
    vm = psutil.virtual_memory()
    uptime_seconds = (time.time() - capture_start_time) if (ids_running and capture_start_time) else 0
    hours, rem = divmod(int(uptime_seconds), 3600)
    minutes, seconds = divmod(rem, 60)
    latency_ms = packet_analyzer_instance.avg_detection_latency_ms if packet_analyzer_instance else 0.0
    return {
        'cpu_percent': psutil.cpu_percent(interval=None),
        'memory_used_mb': round(mem_info.rss / (1024 * 1024), 1),
        'memory_total_mb': round(vm.total / (1024 * 1024), 1),
        'queue_length': dashboard_event_queue.qsize(),
        'active_flows': len(recent_flows),
        'active_alerts': len(recent_alerts),
        'total_packets': total_packets_processed,
        'total_attacks': total_attacks_detected,
        'packets_per_sec': sum(chart_data_packets_per_sec) if chart_data_packets_per_sec else 0,
        'attacks_per_sec': sum(chart_data_attacks_per_sec) if chart_data_attacks_per_sec else 0,
        'capture_status': 'RUNNING' if ids_running else 'STOPPED',
        'running': ids_running,
        'detection_latency_ms': latency_ms,
        'uptime': f"{hours:02d}:{minutes:02d}:{seconds:02d}",
    }


@socketio.on('request_initial_data')
def request_initial_data(data=None):
    # data can include {'page': 'flows'} to request full flow list (only used by flows page)
    page = None
    if isinstance(data, dict):
        page = data.get('page')
    if page == 'flows':
        try:
            emit('flow_update', {'flows': list(recent_flows)[-500:]})
        except Exception:
            logger.debug('Failed sending flow list')
    # always send alerts and health summary
    emit('alert_update', {'alerts': list(recent_alerts)[-100:]})
    emit('system_health', get_system_health())


@socketio.on('request_health')
def request_health():
    emit('system_health', get_system_health())


def emit_system_health_loop():
    """Runs continuously in the background so health metrics keep
    updating even between explicit 'request_health' pings from clients."""
    while True:
        try:
            socketio.emit('system_health', get_system_health())
        except Exception:
            logger.error(f"Health emit error: {traceback.format_exc()}")
        socketio.sleep(3.0)


def emit_flow_data_from_queue():
    while True:
        flow_batch = []
        alert_batch = []
        start_time = time.time()
        while time.time() - start_time < 0.05:
            flow_data = None
            alert_data = None
            try:
                flow_data = dashboard_event_queue.get_nowait()
                recent_flows.append(flow_data)
                flow_batch.append(flow_data)
            except queue.Empty:
                pass
            try:
                alert_data = alert_event_queue.get_nowait()
                alert_batch.append(alert_data)
            except queue.Empty:
                pass
            if flow_data is None and alert_data is None:
                socketio.sleep(0.01)
        if flow_batch:
            try:
                # update per-second counters and broadcast summary stats instead of flow lists
                stats = {
                    'packets_per_sec': sum(chart_data_packets_per_sec) if chart_data_packets_per_sec else 0,
                    'attacks_per_sec': sum(chart_data_attacks_per_sec) if chart_data_attacks_per_sec else 0,
                    'queue_length': dashboard_event_queue.qsize(),
                    'active_flows': len(recent_flows),
                    'capture_status': 'RUNNING' if ids_running else 'STOPPED',
                }
                socketio.emit('stats_update', stats)
            except Exception:
                logger.error(f"Emit error: {traceback.format_exc()}")
        if alert_batch:
            # perform enrichment and emission asynchronously so the emitter loop stays responsive
            try:
                socketio.start_background_task(enrich_and_emit_alerts, list(alert_batch))
            except Exception:
                logger.error(f"Failed to start enrichment task: {traceback.format_exc()}")


def enrich_and_emit_alerts(alerts: List[Dict[str, Any]]) -> None:
    """Background worker: enrich alerts using cached lookups, append to recent_alerts and emit updates."""
    enriched = []
    for a in alerts:
        try:
            enrich_alert(a)
        except Exception:
            logger.debug('Error enriching alert: %s', traceback.format_exc())
        # perform IOC check (fast in-memory) if available
        try:
            a_iocs = []
            if a.get('src_ip'):
                a_iocs.extend(check_ioc(a.get('src_ip'), a.get('src_rdns')) or [])
            if a.get('dst_ip'):
                a_iocs.extend(check_ioc(a.get('dst_ip'), a.get('dst_rdns')) or [])
            if a_iocs:
                a['ioc_matches'] = a_iocs
            else:
                a['ioc_matches'] = []
        except Exception:
            a['ioc_matches'] = []
        # mark acknowledged default if missing
        if 'acknowledged' not in a:
            a['acknowledged'] = False
        recent_alerts.appendleft(a)
        # ensure recent_alerts capped
        while len(recent_alerts) > ALERT_HISTORY_LIMIT:
            try:
                recent_alerts.pop()
            except Exception:
                break
        # enqueue persistence of the new alert (non-blocking)
        try:
            persist_item = {'action': 'new', 'alert': a}
            alert_persist_queue.put_nowait(persist_item)
        except queue.Full:
            logger.warning('Alert persist queue full; dropping persist')
        enriched.append(a)
    if enriched:
        try:
            socketio.emit('alert_update', {'alerts': enriched})
        except Exception:
            logger.error(f"Emit error in enrich_and_emit_alerts: {traceback.format_exc()}")


def load_ioc_list():
    """Load IOC entries from IOC_LIST_PATH into in-memory structures."""
    global ioc_ip_set, ioc_cidrs, ioc_domains, ioc_mtime
    if not IOC_LIST_PATH:
        return
    try:
        p = Path(IOC_LIST_PATH)
        if not p.exists():
            logger.info('IOC list not found: %s', IOC_LIST_PATH)
            return
        mtime = p.stat().st_mtime
        if ioc_mtime and mtime == ioc_mtime:
            return
        lines = [l.strip() for l in p.read_text(encoding='utf-8').splitlines() if l.strip() and not l.strip().startswith('#')]
        ipset = set()
        cidrs = []
        domains = set()
        for l in lines:
            # try CIDR
            if '/' in l:
                try:
                    import ipaddress
                    net = ipaddress.ip_network(l, strict=False)
                    cidrs.append(net)
                    continue
                except Exception:
                    pass
            # try IP
            try:
                import ipaddress
                ip = ipaddress.ip_address(l)
                ipset.add(str(ip))
                continue
            except Exception:
                pass
            # fallback domain
            domains.add(l.lower())
        ioc_ip_set = ipset
        ioc_cidrs = cidrs
        ioc_domains = domains
        ioc_mtime = mtime
        logger.info('Loaded %d IOC IPs, %d CIDRs, %d domains', len(ioc_ip_set), len(ioc_cidrs), len(ioc_domains))
    except Exception:
        logger.exception('Failed loading IOC list')


def ioc_watcher_loop():
    global ioc_watcher_started
    if ioc_watcher_started:
        return
    ioc_watcher_started = True
    while True:
        try:
            load_ioc_list()
        except Exception:
            logger.debug('IOC watcher error: %s', traceback.format_exc())
        socketio.sleep(60)


# --------------------------------------------------------------------------
# Small helper endpoints for UI: interfaces, settings update, and on-demand PCAP export
# --------------------------------------------------------------------------

@app.route('/api/interfaces')
def api_interfaces():
    """Return a list of available network interfaces (best-effort).
    Tries psutil.net_if_addrs() if available; otherwise returns configured interface.
    """
    out = []
    try:
        for name, addrs in psutil.net_if_addrs().items():
            out.append(name)
    except Exception:
        # fallback to the interface in config
        iface = config.get('interface') if isinstance(config, dict) else None
        if iface:
            out = [iface]
    return jsonify({'interfaces': out})


@app.route('/settings/update', methods=['POST'])
def settings_update():
    """Update capture and detection settings. Accepts JSON body and writes to config.json.
    Applies a best-effort runtime update (updates global config and live PacketAnalyzer if running).
    """
    if not request.is_json:
        return jsonify({'error': 'expected application/json'}), 400
    body = request.get_json()
    if not isinstance(body, dict):
        return jsonify({'error': 'invalid payload'}), 400
    # allowed keys to update at top-level and nested detection
    allowed_top = {'interface', 'capture_bpf', 'sampling_rate', 'capture_packet_limit', 'capture_timeout_seconds', 'ioc_list'}
    allowed_detection = {'match_threshold', 'half_open_grace_seconds', 'half_open_min_count'}
    updated = False
    try:
        # read existing config
        p = CONFIG_PATH
        cfg = {}
        with p.open('r', encoding='utf-8') as fh:
            cfg = json.load(fh)
        # top-level updates
        for k in allowed_top:
            if k in body:
                val = body.get(k)
                if k == 'ioc_list':
                    # write IOC list to IOC_LIST_PATH
                    ioc_path = cfg.get('ioc_list_path') or './data/ioc.txt'
                    try:
                        Path(ioc_path).parent.mkdir(parents=True, exist_ok=True)
                        Path(ioc_path).write_text('\n'.join([l.strip() for l in str(val).splitlines() if l.strip()]), encoding='utf-8')
                        logger.info('Wrote IOC list to %s', ioc_path)
                        updated = True
                    except Exception:
                        logger.exception('Failed writing IOC list')
                else:
                    cfg[k] = val
                    updated = True
        # detection updates
        det = cfg.get('detection', {})
        for k in allowed_detection:
            if k in body:
                det[k] = body.get(k)
                updated = True
        cfg['detection'] = det
        if updated:
            # write back atomically
            tmp = CONFIG_PATH.with_suffix('.tmp')
            with tmp.open('w', encoding='utf-8') as fh:
                json.dump(cfg, fh, indent=2)
            tmp.replace(CONFIG_PATH)
            # update in-memory config reference
            global config, IOC_LIST_PATH, CAPTURE_PACKET_LIMIT, CAPTURE_TIMEOUT_SECONDS
            config = cfg
            IOC_LIST_PATH = config.get('ioc_list_path') if isinstance(config, dict) else IOC_LIST_PATH
            CAPTURE_PACKET_LIMIT = int(config.get('capture_packet_limit', CAPTURE_PACKET_LIMIT))
            CAPTURE_TIMEOUT_SECONDS = int(config.get('capture_timeout_seconds', CAPTURE_TIMEOUT_SECONDS))
            # update running PacketAnalyzer if present
            try:
                if 'packet_analyzer_instance' in globals() and packet_analyzer_instance is not None:
                    packet_analyzer_instance.config = config
                    packet_analyzer_instance.bpf_filter = config.get('capture_bpf') or None
                    try:
                        sr = int(config.get('sampling_rate', 1))
                        packet_analyzer_instance.sampling_rate = max(1, sr)
                    except Exception:
                        pass
                    packet_analyzer_instance.match_threshold = config.get('detection', {}).get('match_threshold', packet_analyzer_instance.match_threshold)
                    packet_analyzer_instance.half_open_grace_seconds = config.get('detection', {}).get('half_open_grace_seconds', packet_analyzer_instance.half_open_grace_seconds)
                    packet_analyzer_instance.half_open_min_count = config.get('detection', {}).get('half_open_min_count', packet_analyzer_instance.half_open_min_count)
            except Exception:
                logger.debug('Failed to apply settings to running analyzer: %s', traceback.format_exc())
    except Exception:
        logger.exception('Failed updating settings')
        return jsonify({'error': 'update failed'}), 500
    # reload IOC list immediately if changed
    try:
        load_ioc_list()
    except Exception:
        logger.debug('Failed reloading IOC list after settings update')
    return jsonify({'ok': True})


@app.route('/export/alert_pcap')
def export_alert_pcap():
    """On-demand PCAP export for a given flow_id or alert id. This runs tshark with
    a small capture filter and returns a PCAP file. Query params: flow_id, count, timeout
    """
    flow_id = request.args.get('flow_id')
    if not flow_id:
        return jsonify({'error': 'flow_id required'}), 400
    # find alert or flow
    alert_obj = None
    try:
        # check DB first
        if ALERTS_DB_PATH:
            conn = sqlite3.connect(str(Path(ALERTS_DB_PATH)))
            cur = conn.cursor()
            cur.execute('SELECT alert_json FROM alerts WHERE flow_id = ? OR id = ? LIMIT 1', (flow_id, flow_id))
            row = cur.fetchone()
            conn.close()
            if row:
                try:
                    alert_obj = json.loads(row[0])
                except Exception:
                    alert_obj = None
        # fallback to recent_alerts
        if alert_obj is None:
            for a in recent_alerts:
                if a.get('flow_id') == flow_id or a.get('id') == flow_id:
                    alert_obj = a
                    break
        # fallback to recent_flows
        if alert_obj is None:
            for f in recent_flows:
                if f.get('flow_id') == flow_id:
                    alert_obj = f
                    break
        if alert_obj is None:
            return jsonify({'error': 'flow not found'}), 404
        src = alert_obj.get('src_ip')
        dst = alert_obj.get('dst_ip')
        src_port = alert_obj.get('src_port')
        dst_port = alert_obj.get('dst_port')
        proto = (alert_obj.get('protocol_type') or '').upper()
        # build a BPF filter matching the 5-tuple as closely as possible
        parts = []
        if src:
            parts.append(f"host {src}")
        if dst:
            parts.append(f"host {dst}")
        if proto in ('TCP','UDP') and (src_port or dst_port):
            # prefer dst port
            if dst_port:
                parts.append(f"port {dst_port}")
            elif src_port:
                parts.append(f"port {src_port}")
        bpf = ' and '.join(parts) if parts else (config.get('capture_bpf') or '')
        count = int(request.args.get('count', CAPTURE_PACKET_LIMIT))
        timeout = int(request.args.get('timeout', CAPTURE_TIMEOUT_SECONDS))
        iface = config.get('interface') if isinstance(config, dict) else None
        # find tshark
        tshark = shutil.which('tshark') or shutil.which('dumpcap')
        if not tshark:
            return jsonify({'error': 'tshark/dumpcap not found on host'}), 500
        # temp file path
        tmpdir = Path('./data/pcaps')
        tmpdir.mkdir(parents=True, exist_ok=True)
        out_path = tmpdir / f"{flow_id.replace(':','_')}.pcap"
        # build command - use -f for BPF, -c for count, -a duration for timeout
        cmd = [tshark, '-i', iface, '-w', str(out_path)]
        if bpf:
            cmd.extend(['-f', bpf])
        if count:
            cmd.extend(['-c', str(count)])
        if timeout:
            # tshark uses -a duration:<seconds> with dumpcap/tshark
            cmd.extend(['-a', f'duration:{int(timeout)}'])
        logger.info('Running capture for export: %s', ' '.join(cmd))
        try:
            # run command and wait up to timeout+5s
            subprocess.run(cmd, check=False, timeout=timeout + 5)
        except subprocess.TimeoutExpired:
            logger.warning('PCAP capture timed out')
        except Exception:
            logger.exception('PCAP capture failed')
        if not out_path.exists() or out_path.stat().st_size == 0:
            return jsonify({'error': 'no pcap captured'}), 500
        return send_file(str(out_path), as_attachment=True, download_name=out_path.name)
    except Exception:
        logger.exception('Failed creating pcap for flow')
        return jsonify({'error': 'export failed'}), 500


def init_alerts_db(path: str) -> None:
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(p))
        cur = conn.cursor()
        cur.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                flow_id TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                outcome TEXT,
                severity TEXT,
                confidence REAL,
                timestamp TEXT,
                persisted_timestamp TEXT,
                acknowledged INTEGER DEFAULT 0,
                acknowledged_timestamp TEXT,
                investigated INTEGER DEFAULT 0,
                investigator_notes TEXT,
                investigator TEXT,
                alert_json TEXT
            )
        ''')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_alerts_flow_id ON alerts(flow_id)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_alerts_persisted ON alerts(persisted_timestamp)')
        conn.commit()
        # ensure investigator column exists for older DBs
        try:
            cur.execute("PRAGMA table_info(alerts)")
            cols = [r[1] for r in cur.fetchall()]
            if 'investigator' not in cols:
                cur.execute("ALTER TABLE alerts ADD COLUMN investigator TEXT")
                conn.commit()
        except Exception:
            logger.debug('Failed ensuring investigator column exists: %s', traceback.format_exc())
        conn.close()
        logger.info('Initialized alerts DB at %s', path)
    except Exception:
        logger.exception('Failed to initialize alerts DB')


def alert_persist_writer():
    """Background worker that writes alert records to a SQLite database.
    Batch-inserts/updates to avoid excessive I/O and keep capture responsive.
    """
    if not ALERTS_DB_PATH:
        # fallback: if DB not configured but JSONL path is provided, keep file writer
        if ALERTS_PERSIST_PATH:
            logger.info('Alert DB not configured, would fall back to JSONL writer (not implemented)')
        return

    try:
        p = Path(ALERTS_DB_PATH)
        init_alerts_db(str(p))
    except Exception:
        logger.exception('Failed preparing alerts DB')
        return

    logger.info('Starting alert DB writer -> %s', ALERTS_DB_PATH)
    while True:
        batch = []
        try:
            for _ in range(200):
                try:
                    it = alert_persist_queue.get_nowait()
                    batch.append(it)
                except queue.Empty:
                    break
        except Exception:
            logger.debug('Error draining alert_persist_queue: %s', traceback.format_exc())

        if not batch:
            socketio.sleep(1)
            continue

        try:
            conn = sqlite3.connect(str(p))
            cur = conn.cursor()
            for item in batch:
                try:
                    action = item.get('action')
                    alert = item.get('alert') or {}
                    # ensure an id
                    aid = alert.get('id') or str(uuid.uuid4())
                    flow_id = alert.get('flow_id')
                    src_ip = alert.get('src_ip')
                    dst_ip = alert.get('dst_ip')
                    outcome = alert.get('outcome')
                    severity = alert.get('severity')
                    confidence = float(alert.get('confidence') or 0.0)
                    ts = alert.get('timestamp')
                    persisted = datetime.utcnow().isoformat() + 'Z'
                    acknowledged = 1 if alert.get('acknowledged') else 0
                    acknowledged_ts = alert.get('acknowledged_timestamp')
                    investigated = 1 if alert.get('investigated') else 0
                    notes = json.dumps(alert.get('investigator_notes') or [])
                    alert_json = json.dumps(alert, ensure_ascii=False)

                    investigator_val = alert.get('investigator') if isinstance(alert, dict) else None
                    if action == 'new':
                        cur.execute('''INSERT OR REPLACE INTO alerts (id, flow_id, src_ip, dst_ip, outcome, severity, confidence, timestamp, persisted_timestamp, acknowledged, acknowledged_timestamp, investigated, investigator_notes, investigator, alert_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                                    (aid, flow_id, src_ip, dst_ip, outcome, severity, confidence, ts, persisted, acknowledged, acknowledged_ts, investigated, notes, investigator_val, alert_json))
                    else:
                        # update existing by flow_id or id
                        cur.execute('SELECT id FROM alerts WHERE flow_id = ? OR id = ?', (flow_id, aid))
                        row = cur.fetchone()
                        if row:
                            cur.execute('''UPDATE alerts SET src_ip=?, dst_ip=?, outcome=?, severity=?, confidence=?, timestamp=?, persisted_timestamp=?, acknowledged=?, acknowledged_timestamp=?, investigated=?, investigator_notes=?, investigator=?, alert_json=? WHERE id = ?''',
                                        (src_ip, dst_ip, outcome, severity, confidence, ts, persisted, acknowledged, acknowledged_ts, investigated, notes, investigator_val, alert_json, row[0]))
                        else:
                            cur.execute('''INSERT OR REPLACE INTO alerts (id, flow_id, src_ip, dst_ip, outcome, severity, confidence, timestamp, persisted_timestamp, acknowledged, acknowledged_timestamp, investigated, investigator_notes, investigator, alert_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                                        (aid, flow_id, src_ip, dst_ip, outcome, severity, confidence, ts, persisted, acknowledged, acknowledged_ts, investigated, notes, investigator_val, alert_json))
                except Exception:
                    logger.debug('Failed persisting alert item: %s', traceback.format_exc())
            conn.commit()
            conn.close()
        except Exception:
            logger.exception('Failed writing alerts to DB')


@app.route('/alerts/history')
def alerts_history():
    """Return recent persisted alerts as JSON list from SQLite DB."""
    if not ALERTS_DB_PATH:
        return jsonify({'error': 'alerts DB not configured'}), 404
    limit = int(request.args.get('limit', 500))
    p = Path(ALERTS_DB_PATH)
    if not p.exists():
        return jsonify([])
    try:
        conn = sqlite3.connect(str(p))
        cur = conn.cursor()
        cur.execute('SELECT alert_json FROM alerts ORDER BY persisted_timestamp DESC LIMIT ?', (limit,))
        rows = cur.fetchall()
        conn.close()
        out = []
        for (aj,) in rows:
            try:
                out.append(json.loads(aj))
            except Exception:
                try:
                    out.append({'_raw': aj})
                except Exception:
                    out.append({'_raw': str(aj)})
        return jsonify(out)
    except Exception:
        logger.exception('Failed reading alerts history from DB')
        return jsonify({'error': 'read failed'}), 500


@app.route('/export/flows.csv')
def export_flows_csv():
    """Return recent flows as a CSV file (limited to recent 500).
    This is a simple export for forensic review.
    """
    try:
        import csv
        from io import StringIO
        rows = list(recent_flows)[-500:]
        if not rows:
            sio = StringIO()
            sio.write('')
            return (sio.getvalue(), 200, {'Content-Type': 'text/csv'})
        # choose a set of columns that are safe and useful
        columns = ['flow_id', 'timestamp', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol_type', 'outcome', 'confidence', 'src_bytes', 'dst_bytes', 'duration']
        sio = StringIO()
        writer = csv.DictWriter(sio, fieldnames=columns)
        writer.writeheader()
        for r in rows:
            out = {k: r.get(k, '') for k in columns}
            writer.writerow(out)
        return (sio.getvalue(), 200, {
            'Content-Type': 'text/csv',
            'Content-Disposition': 'attachment; filename="flows.csv"'
        })
    except Exception:
        logger.exception('Failed to export flows')
        return ("", 500)


if __name__ == '__main__':
    socketio.start_background_task(emit_system_health_loop)
    # start IOC watcher if configured
    if IOC_LIST_PATH:
        try:
            socketio.start_background_task(ioc_watcher_loop)
        except Exception:
            logger.debug('Failed to start IOC watcher: %s', traceback.format_exc())

    # start alerts persistence writer if configured (prefer SQLite DB)
    if ALERTS_DB_PATH:
        try:
            socketio.start_background_task(alert_persist_writer)
        except Exception:
            logger.debug('Failed to start alerts persistence writer: %s', traceback.format_exc())
    elif ALERTS_PERSIST_PATH:
        try:
            # legacy JSONL writer not implemented in this branch; keep fallback note
            logger.info('ALERTS_DB_PATH not configured, JSONL writer fallback disabled')
        except Exception:
            logger.debug('Failed to start alerts persistence writer fallback: %s', traceback.format_exc())

    logger.info("Starting Flask-SocketIO server...")
    socketio.run(
        app,
        debug=False,
        port=5000,
        use_reloader=False
    )