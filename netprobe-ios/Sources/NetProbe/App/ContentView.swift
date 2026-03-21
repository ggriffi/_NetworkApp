import SwiftUI

// MARK: - Tool definition

enum Tool: String, CaseIterable, Identifiable {
    // NETWORK
    case ping        = "Ping"
    case traceroute  = "Traceroute"
    case mtr         = "MTR"
    // DISCOVERY
    case portScan    = "Port Scan"
    case dns         = "DNS"
    case arp         = "ARP Scan"
    case netstat     = "Netstat"
    // SECURITY
    case ssl         = "SSL / TLS"
    case httpProbe   = "HTTP Probe"
    case whois       = "WHOIS"
    // TOOLS
    case wol         = "Wake-on-LAN"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .ping:       return "dot.radiowaves.left.and.right"
        case .traceroute: return "arrow.triangle.swap"
        case .mtr:        return "chart.xyaxis.line"
        case .portScan:   return "lock.open.laptopcomputer"
        case .dns:        return "globe"
        case .arp:        return "network"
        case .netstat:    return "list.bullet.rectangle"
        case .ssl:        return "lock.shield"
        case .httpProbe:  return "safari"
        case .whois:      return "person.text.rectangle"
        case .wol:        return "power"
        }
    }

    var group: String {
        switch self {
        case .ping, .traceroute, .mtr:            return "NETWORK"
        case .portScan, .dns, .arp, .netstat:     return "DISCOVERY"
        case .ssl, .httpProbe, .whois:            return "SECURITY"
        case .wol:                                return "TOOLS"
        }
    }

    @ViewBuilder
    var view: some View {
        switch self {
        case .ping:       PingView()
        case .traceroute: TracerouteView()
        case .mtr:        MTRView()
        case .portScan:   PortScanView()
        case .dns:        DNSView()
        case .arp:        ARPScanView()
        case .netstat:    NetstatView()
        case .ssl:        SSLView()
        case .httpProbe:  HTTPProbeView()
        case .whois:      WHOISView()
        case .wol:        WakeOnLANView()
        }
    }
}

// MARK: - ContentView

struct ContentView: View {

    @State private var selectedTool: Tool? = .ping
    @State private var showSettings = false
    @Environment(AppSettings.self) private var settings

    // Grouped tool list for the sidebar
    private let groups: [(String, [Tool])] = {
        let all = Tool.allCases
        let groupNames = ["NETWORK", "DISCOVERY", "SECURITY", "TOOLS"]
        return groupNames.compactMap { g in
            let tools = all.filter { $0.group == g }
            return tools.isEmpty ? nil : (g, tools)
        }
    }()

    var body: some View {
        NavigationSplitView {
            sidebar
        } detail: {
            if let tool = selectedTool {
                tool.view
                    .navigationBarTitleDisplayMode(.inline)
                    .toolbar {
                        ToolbarItem(placement: .principal) {
                            Text(tool.rawValue)
                                .font(.system(.headline, design: .monospaced).weight(.semibold))
                                .foregroundStyle(Color.npCyan)
                        }
                        ToolbarItem(placement: .navigationBarTrailing) {
                            Button { showSettings = true } label: {
                                Image(systemName: "gearshape")
                                    .foregroundStyle(Color.npFgDim)
                            }
                        }
                    }
            } else {
                welcomeView
            }
        }
        .navigationSplitViewStyle(.balanced)
        .sheet(isPresented: $showSettings) { SettingsView() }
        .onAppear {
            if !settings.isConfigured { showSettings = true }
        }
    }

    // MARK: - Sidebar

    private var sidebar: some View {
        List(selection: $selectedTool) {
            ForEach(groups, id: \.0) { groupName, tools in
                Section {
                    ForEach(tools) { tool in
                        Label(tool.rawValue, systemImage: tool.icon)
                            .tag(tool)
                            .foregroundStyle(
                                selectedTool == tool ? Color.npCyan : Color.npFgMid
                            )
                    }
                } header: {
                    Text(groupName)
                        .font(.system(.caption2, design: .monospaced).weight(.semibold))
                        .foregroundStyle(Color.npFgDim)
                }
            }
        }
        .listStyle(.sidebar)
        .scrollContentBackground(.hidden)
        .background(Color.npPanel)
        .navigationTitle("NetProbe")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button { showSettings = true } label: {
                    Image(systemName: "gearshape")
                        .foregroundStyle(Color.npFgDim)
                }
            }
        }
    }

    // MARK: - Welcome / not configured

    private var welcomeView: some View {
        VStack(spacing: 20) {
            Image(systemName: "antenna.radiowaves.left.and.right")
                .font(.system(size: 60))
                .foregroundStyle(Color.npCyan)
            Text("NetProbe")
                .font(.system(.title, design: .monospaced).weight(.bold))
                .foregroundStyle(Color.npFgBright)
            Text(settings.isConfigured
                    ? "Select a tool from the sidebar."
                    : "Configure your server in Settings to get started.")
                .font(.subheadline)
                .foregroundStyle(Color.npFgDim)
                .multilineTextAlignment(.center)
            if !settings.isConfigured {
                Button("Open Settings") { showSettings = true }
                    .buttonStyle(.borderedProminent)
                    .tint(Color.npCyan)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.npBackground)
    }
}
