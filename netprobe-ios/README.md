# NetProbe iOS

SwiftUI client for the NetProbe Server backend.
Connects via HTTPS/WSS — works locally or through a Cloudflare Tunnel from anywhere.

---

## Requirements

| | |
|---|---|
| Xcode | 15.0 or later |
| iOS deployment target | 17.0+ |
| Swift | 5.9+ |
| Backend | NetProbe Server (see `../netprobe-server/`) |

No third-party dependencies — pure SwiftUI + URLSession.

---

## Xcode Project Setup

### 1. Create the Xcode project

1. Open Xcode → **File → New → Project**
2. Choose **iOS → App**
3. Set:
   - **Product Name:** `NetProbe`
   - **Interface:** SwiftUI
   - **Language:** Swift
   - **Minimum Deployments:** iOS 17.0
4. Save the project somewhere on your Mac

### 2. Add the source files

1. In Xcode's Project Navigator, right-click the `NetProbe` group → **Add Files to "NetProbe"**
2. Select all files from `Sources/NetProbe/` (select the four subfolders: `App`, `Core`, `Theme`, `Views`)
3. Make sure **"Copy items if needed"** is checked and the target is checked

Alternatively, drag the `Sources/NetProbe/` folder directly onto the Xcode project navigator.

### 3. Delete the generated files

Xcode creates `ContentView.swift` and `[AppName]App.swift` by default. Delete them — the ones from this repo replace them.

### 4. Add the `@Observable` environment object

In your `NetProbeApp.swift` (already in this repo), the app environment provides `AppSettings`. Xcode may flag `@Environment(AppSettings.self)` — ensure the `@Observable` macro is available by confirming your deployment target is iOS 17+.

### 5. App Transport Security (for HTTP targets)

If you need to probe plain `http://` URLs, add this to `Info.plist`:

```xml
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
</dict>
```

For HTTPS-only setups (Cloudflare Tunnel always uses HTTPS) this is not needed.

### 6. Build and run

- Select a simulator or connected device (iOS 17+)
- ⌘R to build and run
- On first launch, the Settings sheet opens automatically
- Enter your server URL (e.g. `https://netprobe.yourdomain.com`) and API key
- Tap **Test Connection** to verify

---

## Source Structure

```
Sources/NetProbe/
│
├── App/
│   ├── NetProbeApp.swift       @main entry point
│   └── ContentView.swift       NavigationSplitView + sidebar (11 tools)
│
├── Core/
│   ├── AppSettings.swift       Server URL + API key (UserDefaults, @Observable)
│   ├── Models.swift            All Codable structs matching server JSON
│   ├── WSClient.swift          WebSocket streaming via AsyncStream
│   └── NetProbeClient.swift    REST API client (async/await, URLSession)
│
├── Theme/
│   └── Theme.swift             Color palette, modifiers, reusable components
│
└── Views/
    ├── SettingsView.swift       Server config + connection test
    ├── PingView.swift           Live RTT stream, jitter, loss%, sparkline
    ├── TracerouteView.swift     Hop-by-hop trace with RTT × 3 and loss%
    ├── MTRView.swift            Continuous MTR table (avg/best/worst/stdev)
    ├── PortScanView.swift       TCP/UDP port scan, CIDR-aware, open ports only
    ├── DNSView.swift            Multi-record lookup + Google vs Cloudflare DoH
    ├── SSLView.swift            Cert details, expiry countdown, SANs
    ├── HTTPProbeView.swift      TTFB, redirect chain, response headers
    ├── WHOISView.swift          Raw WHOIS with copy + text selection
    ├── NetstatView.swift        Server connection table, filterable
    ├── WakeOnLANView.swift      Magic packet sender with saved targets
    └── ARPScanView.swift        ARP scan stream with swipe-to-copy
```

---

## Tools

| Tool | Protocol | Endpoint |
|---|---|---|
| Ping | WebSocket | `wss://.../ws/ping?host=&interval=` |
| Traceroute | WebSocket | `wss://.../ws/traceroute?host=&max_hops=` |
| MTR | WebSocket | `wss://.../ws/mtr?host=&interval=&max_hops=` |
| Port Scan | WebSocket | `wss://.../ws/portscan?host=&ports=&proto=` |
| ARP Scan | WebSocket | `wss://.../ws/arp?network=` |
| DNS | REST GET | `/api/dns?host=&types=` |
| DoH Compare | REST GET | `/api/doh?domain=&type=` |
| SSL/TLS | REST GET | `/api/ssl?host=&port=` |
| HTTP Probe | REST GET | `/api/http?url=&method=` |
| WHOIS | REST GET | `/api/whois?target=` |
| Netstat | REST GET | `/api/netstat` |
| Wake-on-LAN | REST POST | `/api/wol` body: `{mac, broadcast, port}` |

---

## WebSocket Message Protocol

All streaming endpoints use the same envelope:

```json
// Server → client
{ "type": "result",  "data": { ... } }   // one result item
{ "type": "hop",     "data": { ... } }   // traceroute hop
{ "type": "update",  "data": [ ... ] }   // MTR snapshot (array)
{ "type": "done"                       } // stream finished
{ "type": "error",   "data": "msg"    }  // error, stream closed

// Client → server (to stop a continuous stream)
{ "cmd": "stop" }
```

The `WSClient.swift` implementation handles decoding this into typed `WSMessage` enum cases and delivers them via `AsyncStream`.

---

## Authentication

The API key is sent as a `?key=` query parameter on every request (both REST and WebSocket). If the server is configured with `NETPROBE_API_KEY=`, all requests without a valid key return HTTP 403 (REST) or WebSocket close code 4003.

If you also use **Cloudflare Access** with a Service Token, add these headers to `URLRequest` in `NetProbeClient.swift`:

```swift
req.setValue(cfClientId,     forHTTPHeaderField: "CF-Access-Client-Id")
req.setValue(cfClientSecret, forHTTPHeaderField: "CF-Access-Client-Secret")
```

---

## Notes

- **WebSocket keep-alive:** Cloudflare terminates idle connections after 100 seconds. The server sends WS ping frames every 30 seconds (`ws_ping_interval=30` in uvicorn). iOS `URLSessionWebSocketTask` automatically responds to server ping frames, keeping the connection alive.
- **Netstat shows the server's connections** — not the iPhone's. This is by design since iOS doesn't expose raw socket tables to apps.
- **ARP/packet capture** require the server to run with `NET_RAW` capability. Ensure the Docker container is started with `--cap-add NET_RAW`.
- **iPad:** `NavigationSplitView` shows the sidebar and tool panel side by side. **iPhone:** shows sidebar as a navigation layer (tap a tool → navigates to it).
