# ⬡ NetProbe — Network Analysis Utility

A portable desktop network analysis tool built with Python + Tkinter.
No compiled dependencies. Runs on Linux and Windows.

---

## Features by OSI Layer

| Layer | Tool | Tab |
|-------|------|-----|
| L2 | ARP scan, MAC discovery, neighbor discovery | L2 / ARP |
| L3 | ICMP Ping, Traceroute, MTR (continuous) | PING / TRACEROUTE / MTR |
| L4 | TCP port scanner, banner grabbing, TCP bandwidth test | PORT SCAN / BANDWIDTH |
| L5 | Session/connection monitoring | PACKET CAPTURE |
| L6 | TLS/encoding visibility, raw packet decode | PACKET CAPTURE |
| L7 | DNS A/AAAA/MX/NS/TXT/CNAME/SOA lookup | DNS |
| Multi | Continuous external ping/MTR dashboard | EXT MONITOR |

---

## Quick Start

```bash
# Clone / copy the netprobe/ directory
cd netprobe

# Install optional (but recommended) dependencies
pip install scapy dnspython psutil

# Run
python main.py

# Linux: ICMP + packet capture require root
sudo python main.py
```

**Windows:** Run as Administrator for raw socket access (ICMP ping, packet capture).

---

## Fallback Mode

NetProbe degrades gracefully without optional packages:

| Missing | Fallback |
|---------|----------|
| `scapy` | Raw socket capture; ARP uses system `arp -a` |
| `dnspython` | Basic A/PTR lookup via `socket.getaddrinfo` |
| `psutil` | Interface detection via hostname resolution |
| No root | Subprocess `ping`/`traceroute` system commands |

---

## Packaging to Single Executable

### Linux/Windows — PyInstaller

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name NetProbe main.py
# Output: dist/NetProbe (Linux) or dist/NetProbe.exe (Windows)
```

### With all deps bundled

```bash
pip install scapy dnspython psutil pyinstaller
pyinstaller --onefile --windowed \
  --collect-all scapy \
  --name NetProbe main.py
```

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| Ctrl+1   | Ping tab |
| Ctrl+2   | Traceroute tab |
| Ctrl+3   | MTR tab |
| Ctrl+4   | Bandwidth tab |
| Ctrl+5   | Port Scan tab |
| Ctrl+6   | DNS tab |
| Ctrl+7   | L2/ARP tab |
| Ctrl+8   | Packet Capture tab |
| Ctrl+9   | External Monitor tab |

---

## Architecture

```
netprobe/
├── main.py              # Entry point
├── requirements.txt
├── core/
│   ├── __init__.py
│   └── engine.py        # All network ops (threaded, callback-based)
│       ├── PingMonitor         # Continuous ICMP ping
│       ├── MTRMonitor          # Continuous MTR (traceroute + ping)
│       ├── traceroute()        # Single traceroute run
│       ├── port_scan()         # Threaded TCP port scanner
│       ├── dns_lookup()        # Multi-record DNS with dnspython
│       ├── arp_scan()          # Scapy ARP or system fallback
│       ├── ping_sweep()        # Fast concurrent ping sweep
│       ├── BandwidthServer     # TCP throughput server
│       ├── BandwidthClient     # TCP throughput client
│       ├── PacketCapture       # Scapy or raw socket sniffer
│       └── ExternalMonitor     # Multi-target ping+MTR manager
└── ui/
    ├── __init__.py
    ├── app.py           # Main window, notebook, menus
    ├── theme.py         # Color palette, fonts, widget defaults
    ├── widgets.py       # Reusable components (cards, trees, graphs)
    └── panels.py        # 9 tab panel classes
```

---

## Notes

- **Bandwidth test**: Built-in TCP throughput (no iperf3 needed). Run server on one host, client on another.
- **External Monitor**: Runs continuous ping + optional MTR to multiple targets simultaneously. Uses ASCII sparklines for trend visualization.
- **Packet Capture**: Requires `scapy` for full L2-L6 visibility. Falls back to raw sockets (L3+) without it.
- **MTR**: Pure Python implementation using raw ICMP. Falls back to system `mtr` command if available.
