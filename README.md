# ⬡ NetProbe — Network Analysis Utility

**v1.1.0** — A portable, single-file desktop network analysis tool built with Python + Tkinter.
No compiled dependencies required. Ships as a standalone `.exe` on Windows.

---

## Screenshot

![NetProbe](NetProbe_preview.png)

---

## Tools

NetProbe covers the full OSI stack through a collapsible sidebar grouped by function.

### NETWORK
| Tool | Description |
|------|-------------|
| **Ping** | Continuous ICMP ping with live RTT graph, jitter, packet loss, and configurable loss alerts |
| **Traceroute** | Single-run hop-by-hop trace with RTT × 3, ASN, and GeoIP per hop |
| **MTR** | Continuous traceroute — rolling loss%, avg/best/worst/stdev per hop, ASN, GeoIP |
| **Bandwidth** | Built-in TCP throughput test (no iperf3 required). Optional iperf3 integration for UDP and cross-platform testing |

### DISCOVERY
| Tool | Description |
|------|-------------|
| **Port Scan** | Threaded TCP and UDP scanner. Accepts single hosts, hostnames, or CIDR ranges (`10.0.0.0/24`). Banner grabbing on open ports |
| **DNS** | A / AAAA / MX / NS / TXT / CNAME / SOA / PTR lookup. DNS-over-HTTPS comparison against Google and Cloudflare |
| **L2 / ARP** | ARP scan and ping sweep. MAC address resolution, vendor lookup, hostname resolution |
| **Netstat** | Live connection table filterable by protocol, state, port, and process name. Auto-refresh with psutil process info |

### SECURITY
| Tool | Description |
|------|-------------|
| **SSL/TLS** | Certificate inspection — subject, issuer, SANs, cipher suite, TLS version, expiry countdown. Flags expired and self-signed certs |
| **HTTP Probe** | HEAD/GET with time-to-first-byte, total time, redirect chain capture, and response headers table |
| **WHOIS** | Raw port-43 WHOIS with automatic IANA / registrar referral following. Colorized output |

### TOOLS
| Tool | Description |
|------|-------------|
| **Pkt Capture** | Live packet sniffer with protocol decode (requires Scapy + Npcap/libpcap) |
| **Ext Monitor** | Continuous ping dashboard for multiple targets simultaneously. Per-target latency and loss thresholds, sparkline trend graphs |
| **Wake-on-LAN** | Magic packet sender. Saved targets list, configurable broadcast address and port. ARP panel integration via right-click |

---

## Quick Start

### From source

```bash
git clone <repo>
cd NetworkApp

# Optional but recommended
pip install scapy dnspython psutil cryptography

# Run
python main.py
```

> **Windows:** Run as Administrator for ICMP ping, traceroute, and packet capture.
> **Linux:** `sudo python main.py` for raw socket access.

### Pre-built executable (Windows)

Download `NetProbe.exe` from the releases page and run it directly — no Python installation required.

> Npcap must be installed separately for packet capture and raw ARP scanning.
> All other features work without it. Download from [npcap.com](https://npcap.com).

---

## Dependencies

| Package | Purpose | Without it |
|---------|---------|------------|
| `scapy` | Packet capture, raw ARP scan | Falls back to raw sockets (L3+) and `arp -a` |
| `dnspython` | Full DNS record types | Basic A/PTR via `socket.getaddrinfo` |
| `psutil` | Netstat process names, interface list | PID shown without process name |
| `cryptography` | Richer SSL cert parsing | Falls back to stdlib `ssl` module |
| Npcap / libpcap | Kernel packet capture driver | Packet Capture panel unavailable |

---

## Building from Source

The included `NetProbe.spec` produces a single self-contained executable:

```bash
pip install pyinstaller
python -m PyInstaller NetProbe.spec --clean
# Output: dist/NetProbe.exe  (~27 MB)
```

The spec bundles iperf3, the Cygwin DLLs, Scapy, dnspython, psutil, and cryptography automatically.

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+1` – `Ctrl+9` | Jump to tool 1–9 |
| `Ctrl+B` | Toggle sidebar (expand / icon-only) |
| `Ctrl+E` | Export results (TXT / CSV / JSON) |
| `Ctrl+W` | Exit |
| Right-click table row | Copy row · Copy all · Navigate to related tool |
| Click column header | Sort by column |

---

## Architecture

```
NetworkApp/
├── main.py                  # Entry point
├── requirements.txt
├── NetProbe.spec            # PyInstaller build spec
├── iperf3.exe               # Bundled iperf3 binary (Windows)
├── core/
│   ├── __init__.py          # Public API exports
│   └── engine.py            # All network operations (threaded, callback-based)
│       ├── PingMonitor          Continuous ICMP ping
│       ├── MTRMonitor           Continuous MTR
│       ├── traceroute()         Single traceroute
│       ├── port_scan()          Threaded TCP scanner (CIDR-aware via panel)
│       ├── udp_port_scan()      UDP scanner
│       ├── dns_lookup()         Multi-record DNS
│       ├── doh_lookup()         DNS-over-HTTPS (Google + Cloudflare)
│       ├── arp_scan()           Scapy ARP / system fallback
│       ├── ping_sweep()         Concurrent ping sweep
│       ├── geoip_lookup()       ip-api.com (cached, no key required)
│       ├── asn_lookup()         Team Cymru DNS ASN lookup
│       ├── ssl_inspect()        TLS certificate inspection
│       ├── http_probe()         HTTP timing + redirect chain
│       ├── whois_lookup()       Raw port-43 WHOIS
│       ├── wake_on_lan()        Magic packet sender
│       ├── netstat_snapshot()   Connection table (psutil / netstat fallback)
│       ├── BandwidthServer/Client  TCP throughput
│       ├── IPerf3Client         iperf3 wrapper
│       ├── PacketCapture        Scapy / raw socket sniffer
│       └── ExternalMonitor      Multi-target ping+MTR manager
└── ui/
    ├── app.py               # Main window, sidebar navigation, menus, export
    ├── theme.py             # Color palette, fonts, widget style constants
    ├── widgets.py           # Reusable components (cards, trees, graphs, status bar)
    └── panels.py            # 14 tool panel classes
```

---

## Export

Results from any active tool can be exported via `Ctrl+E` or **File → Export Results** in three formats:

| Format | Use case |
|--------|----------|
| **TXT** | Human-readable report, paste into a ticket or email |
| **CSV** | Import into Excel, Sheets, or a SIEM |
| **JSON** | Structured data for scripting or further processing |

---

## Notes

- **GeoIP** — Uses the free [ip-api.com](http://ip-api.com) endpoint (no API key). Results are cached per session to avoid hammering the rate limit.
- **ASN lookup** — Uses Team Cymru's DNS-based ASN service. No external API key needed.
- **Bandwidth test** — The built-in server/client works without iperf3. iperf3 is used automatically when detected and unlocks UDP testing and cross-platform compatibility.
- **CIDR scanning** — The port scanner accepts ranges like `10.17.10.0/24`. Subnets larger than 1,024 hosts prompt for confirmation. Results include a HOST column so you can see which host each open port belongs to.
- **Cross-tool navigation** — Right-clicking a host in ARP, Netstat, or Port Scan results offers direct navigation to Ping, Port Scan, WHOIS, or Wake-on-LAN with the host pre-filled.
- **Session persistence** — Recent targets and Wake-on-LAN saved entries are written to `netprobe_session.json` on exit and restored on next launch.
