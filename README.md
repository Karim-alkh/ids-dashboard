# IDS Dashboard — Detection Engine Rewrite

## Before you push this

- [ ] Set `interface` in `config.json` to your real capture interface name
      (`tshark -D` or `ip link` to list them) — the placeholder value won't
      work on anyone else's machine, including future you.
- [ ] `app.config['SECRET_KEY']` in `app.py` is a placeholder string. Fine
      for local/demo use; replace it before any real deployment.
- [ ] Requires `tshark` installed as a **system** package (not pip) —
      `sudo apt install tshark` on Debian/Ubuntu. `pyshark` just wraps it.
- [ ] Run `python3 test_detection.py` yourself once locally before pushing.

This documents what was actually broken in the original `app.py` and what
changed. Every claim below was verified empirically (installed the real
dependencies, crafted synthetic pcaps with Scapy, and ran the actual code
against them via pyshark's `FileCapture`) rather than assumed from reading.

## TL;DR

Three structural bugs meant the detector was, in practice, running on a
mostly-disabled feature set:

1. The `flag` feature (SF/S0/REJ/RSTO/...) was computed from a single
   packet's raw TCP-flags byte via bitwise AND against an arbitrary
   lookup table. An ordinary PSH+ACK data packet — the most common packet
   on the wire — matched the table entry for `RSTO`. Since `neptune`,
   `portsweep`, and `ipsweep` all list `RSTO` as a valid flag, routine
   traffic satisfied part of their signature by accident.
2. `dst_host_count` and every other `dst_host_*` feature were computed
   from a single flow's own packet history. A single 5-tuple connection
   only ever has one destination IP, so `dst_host_count` was structurally
   stuck at 1 forever. `satan` (needs ≥4), `smurf` (needs ≥5), and
   `portsweep` (needs ≥3) could never fire, no matter what traffic hit
   the sensor.
3. `serror_rate`, `rerror_rate`, and every `dst_host_*_serror/rerror_rate`
   checked a `.flag` attribute on raw packet objects that was never
   actually set anywhere in the code, so these were permanently `0.0` —
   dead checks that silently always passed.

On top of that, matching required *every single* zero_field and range
condition to hold simultaneously (a strict AND across 15–38 conditions
per attack). Real traffic has jitter; once the dead checks above are
fixed, an all-or-nothing AND becomes even less forgiving than before.

## What changed, in detail

### 1. Real TCP connection-state tracking (`ConnState`)

`flag` is now derived by tracking the SYN / SYN-ACK / ACK / FIN / RST
sequence across the *whole* connection (who sent what, and in which
order), matching the actual Zeek/Bro `conn_state` values the NSL-KDD
`flag` feature is drawn from: `SF, S0, S1, S2, S3, REJ, RSTO, RSTR,
RSTOS0, SH, OTH`. Verified against a synthetic pcap: a full handshake +
data + clean close now correctly resolves to `SF`; a bare SYN with no
reply resolves to `S0`; a SYN answered with an immediate RST (no
SYN-ACK) resolves to `REJ`.

### 2. Cross-flow aggregation (`HostConnectionTracker`)

A single flow object cannot compute `count`, `srv_count`, `*error_rate`,
or `dst_host_*` — these are explicitly defined over *other* connections.
`HostConnectionTracker` now holds:

- a 2-second time window across all recent connections, for `count`,
  `srv_count`, `serror_rate`, `rerror_rate`, `same_srv_rate`,
  `diff_srv_rate`, `srv_serror_rate`, `srv_rerror_rate`,
  `srv_diff_host_rate` — matching the original KDD "traffic features"
  definition;
- a 100-connection window per destination host, for `dst_host_count` and
  all `dst_host_*` features — matching the original KDD "host-based
  traffic features" definition.

One deliberate approximation: `dst_host_srv_diff_host_rate` is computed
as the fraction of same-destination/same-service connections that came
from a *different* source IP than the current one (a source-diversity
proxy). The original KDD paper's exact definition of this one feature is
ambiguous once you're computing it live rather than from a static,
already-labeled dataset; this is a reasonable, documented stand-in.

### 3. Scored signature matching instead of strict AND

`score_attack()` still hard-gates on `protocol_type` / `service` / `flag`
(these are now deterministic, so there's no reason to soften them), but
`zero_fields` and `ranges` now contribute to a **score** (fraction
satisfied) rather than being an all-or-nothing requirement. `classify()`
picks the highest-scoring attack that clears both its gates and
`detection.match_threshold` (default `0.85`) — not just the first exact
match in dict order, which was the previous behavior and meant ties were
broken by accident of config file ordering.

### 4. Dedicated portsweep / ipsweep heuristics

portsweep and ipsweep are defined by *breadth* — one source touching many
ports, or many hosts — which is exactly what the single-connection scored
matcher is weakest at. `HostConnectionTracker.check_portsweep()` /
`check_ipsweep()` are simple, deterministic distinct-count rules
(`portsweep_port_threshold`, `ipsweep_host_threshold` in `config.json`,
both default `5`) that run alongside the scored matcher and take
priority when they fire. This also revives `portsweep_port_threshold`,
which existed in the original `config.json` but was never actually read
by any code.

### 5. A grace period for in-progress connections

Because classification now runs live, per packet, an ordinary new TCP
connection's very first SYN is — for one instant — indistinguishable from
a neptune SYN (flag=S0, zero bytes, zero everything). `classify()` now
withholds judgment on connections still mid-handshake (`S0/S1/S2/S3/SH`)
until either `detection.half_open_grace_seconds` (default `0.5s`) has
passed without resolving, or the tracker already shows
`detection.half_open_min_count` (default `3`) other simultaneous
half-open connections to the same host — which is what a real flood
looks like from the first packet. Verified: a normal single connection
never gets misclassified; a 40-connection synthetic SYN flood is
correctly flagged `neptune` within the first handful of packets.

### 6. Payload decoding bug (content-feature heuristics)

`num_failed_logins`, shell-access detection, guest-login detection, and
file-access detection all searched a payload string built via
`raw.encode('utf-8')`, where `raw` was already pyshark's colon-separated
**hex-string** representation of the bytes (e.g. `'47:45:54:20'`), not
the literal bytes. That UTF-8-encodes the *text of the hex string
itself*, not the decoded payload — so `b"GET / HTTP/1.1"` was being
searched for inside `b"47:45:54:20:2f:20:48:54:54:50:2f:31:2e:31"`, which
can never match. `get_layer_payload_bytes()` now does the actual
`bytes.fromhex()` conversion. Also fixed: `_handle_shell_access()` called
`self._get_payload()`, a method that didn't exist anywhere in the class —
verified this raises `AttributeError` for any flow on a login port.

### 7. Operational fixes

- **Capture loop reopened the interface every ~10 packets.** The
  original `capture_packets()` created a brand-new `pyshark.LiveCapture`
  (spawning a new `tshark` subprocess) every single call, and the outer
  loop called it repeatedly. `capture_packets()` now opens the interface
  once and sniffs continuously until stopped.
- **No `eventlet.monkey_patch()`.** The app runs Flask-SocketIO with
  `eventlet` but never patched the standard library, so blocking I/O
  wasn't cooperating with the greenlet scheduler. Added at the very top
  of the file, before any other import (order matters — verified that
  importing pyshark before patching throws; patching first is fine, and
  pyshark's asyncio-based capture works correctly inside a greenlet, also
  verified directly).
- **`emit_flow_data_from_queue` was started twice** — once unconditionally
  at import time, once again in `if __name__ == '__main__'`. Running the
  app directly meant two consumers draining the same queue concurrently.
  Now started once.
- **Every packet was written to `packet_layers.txt` via `str(packet)`,
  forever, unconditionally** — an unbounded, unrotated debug file plus a
  full packet-dissection string built on every single packet in the hot
  path. Removed; this is likely a meaningful chunk of why the dashboard
  felt slow under load.
- **`self.packet_data` accumulated every processed packet forever** for a
  CSV export method (`save_packets_data`) that's never called from
  anywhere (the actual export button in the UI works client-side). Also
  removed — this was a slow, unbounded memory leak in service of nothing.
- **Status-string mismatch (`main.js`)**: the backend emits the Russian
  string `'IDS уже запущена'` when you click Start while already running;
  the frontend was checking for the English literal `'IDS Already
  Running'`, which never matched, desyncing the button state. Fixed, and
  the "Stopping..." status no longer prematurely re-enables the Start
  button.
- **Duplicate event listener (`main.js`)**: the pause button had
  `addEventListener('click', toggleLiveUpdates)` attached twice (once in
  `initDashboard()`, once in `setupEventListeners()`), so every click
  toggled the paused state twice — net effect, visually nothing happened.
  Removed the duplicate.
- **`dst_host_count` shown on the dashboard didn't match what the
  detector used to classify.** The display value came from a *different*
  counter (`src_to_dst_ips`, actually a source-fan-out metric) than the
  one `check_thresholds()` read internally (the always-1 one, see above).
  Both are now the same tracker-derived value.

## What was intentionally left as a documented limitation

The content-based features (`hot`, `num_failed_logins`, `root_shell`,
`num_access_files`, etc.) are keyword/regex heuristics on decoded payload
bytes, not a real protocol/session reconstruction (no actual FTP/Telnet/
SSH state machine). This is true of most lightweight NIDS projects
without a full application-layer parser; treat these fields as
indicative, not authoritative. If you want to strengthen this later, the
natural next step is per-service mini-parsers (FTP reply codes, Telnet
negotiation, etc.) rather than more keywords.

`satan` and `mscan` (broad service/host probing) still lean on the scored
matcher rather than a dedicated breadth heuristic like portsweep/ipsweep
got. In testing, ambiguous ICMP-flood traffic sometimes scores `smurf`
and `ipsweep` within a few hundredths of each other — both fire (neither
comes back `normal`), but the specific sub-label can be a close call.
This mirrors a well-known property of the KDD/NSL-KDD feature set itself
(these categories overlap statistically); the new `confidence` field
in every dashboard row makes that ambiguity visible instead of hiding it
behind a single silent label, which is the main actionable improvement
available without moving past a feature-based approach entirely.

## Configuration additions (`config.json`)

```json
"detection": {
  "match_threshold": 0.85,
  "half_open_grace_seconds": 0.5,
  "half_open_min_count": 3,
  "debug_dump_packets": false
},
"ipsweep_host_threshold": 5
```

`portsweep_port_threshold` (already present, now actually wired up) and
`ipsweep_host_threshold` control the recon heuristics. `match_threshold`
controls how much of a signature has to line up before an alert fires —
lower it to catch more (at the cost of more false positives), raise it
for the opposite. Tune these against your own network's real traffic;
the defaults are a reasonable starting point, not a promise.

`interface` in `config.json` must be your actual capture interface name
(check with `tshark -D` or `ip link`), not the Windows-style `"Wi-Fi"`
default that was in the original file.

## Testing without root / a live interface

`test_detection.py` replays synthetic pcaps through the real
`PacketAnalyzer.process_packet()` pipeline via pyshark's `FileCapture`,
which needs no root and no live NIC. Five scenarios are included: normal
web browsing, a 40-connection SYN flood, a 20-port scan, a 15-host scan,
and a 20-source ICMP flood. Run it with:

```bash
pip install -r requirements.txt  # or your existing environment
python3 test_detection.py
```

Expected result on the included scenarios: normal traffic never
classifies as anything but `normal`; the SYN flood resolves to `neptune`
within the first handful of packets; the port scan resolves to
`portsweep`; the host scan resolves to `ipsweep`; the ICMP flood resolves
to `smurf` or `ipsweep` (see limitations above) — never `normal`. This is
a good regression check to re-run after any future changes to the
detection logic.

## Files changed

- `app.py` — rewritten detection engine (this document covers why).
- `config.json` — added `detection` block and `ipsweep_host_threshold`;
  all existing attack signatures (`neptune`, `smurf`, `satan`, etc.) kept
  as-is, since they reflect real NSL-KDD-derived statistics.
- `main.js` — two bug fixes (duplicate listener, status-string mismatch),
  no functional/behavioral redesign.
- `index.html`, `style.css` — unchanged; no bugs found there.
- `test_detection.py` — new, offline validation harness.
