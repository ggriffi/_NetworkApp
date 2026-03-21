import SwiftUI

@Observable
final class TracerouteViewModel {
    var host   = ""
    var hops:  [HopResult] = []
    var status = StatusBadge.State.idle
    var errorMsg = ""

    private var task: Task<Void, Never>?

    func start() {
        guard let url = AppSettings.shared.wsURL("/ws/traceroute",
              params: ["host": host, "max_hops": "30"]) else { return }
        hops.removeAll()
        status = .running
        errorMsg = ""

        task = Task {
            for await msg in WSClient.stream(url: url) {
                if Task.isCancelled { break }
                await MainActor.run {
                    switch msg {
                    case .result(let data):
                        if let h = data.decode(HopResult.self) { hops.append(h) }
                    case .done:    status = .done
                    case .error(let e): errorMsg = e; status = .error
                    case .arrayUpdate: break
                    }
                }
            }
        }
    }

    func stop() { task?.cancel(); task = nil; status = .done }
}

struct TracerouteView: View {
    @State private var vm = TracerouteViewModel()

    var body: some View {
        ZStack {
            Color.npBackground.ignoresSafeArea()
            VStack(spacing: 12) {
                HostBar(placeholder: "hostname or IP", text: $vm.host,
                        isRunning: vm.status == .running,
                        onStart: vm.start, onStop: vm.stop)

                HStack {
                    StatusBadge(state: vm.status)
                    Spacer()
                    Text("\(vm.hops.count) hops")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(Color.npFgDim)
                }
                .padding(.horizontal)

                if vm.hops.isEmpty {
                    EmptyState(icon: "arrow.triangle.swap", message: "Enter a host and tap Start")
                } else {
                    List(vm.hops) { hop in
                        HopRow(hop: hop)
                            .listRowBackground(Color.npCard)
                            .listRowSeparatorTint(Color.npBorder)
                    }
                    .listStyle(.plain)
                    .scrollContentBackground(.hidden)
                }

                if !vm.errorMsg.isEmpty {
                    Text(vm.errorMsg).font(.caption).foregroundStyle(Color.npRed).padding(.horizontal)
                }
            }
        }
    }
}

struct HopRow: View {
    let hop: HopResult
    var body: some View {
        HStack(alignment: .center, spacing: 8) {
            Text("\(hop.hop)")
                .font(.system(.caption, design: .monospaced).weight(.bold))
                .foregroundStyle(Color.npCyan)
                .frame(width: 22, alignment: .trailing)

            VStack(alignment: .leading, spacing: 2) {
                Text(hop.ip == "*" ? "* * *" : hop.ip)
                    .font(.system(.subheadline, design: .monospaced))
                    .foregroundStyle(hop.ip == "*" ? Color.npFgDim : Color.npFgBright)
                if hop.hostname != hop.ip && !hop.hostname.isEmpty {
                    Text(hop.hostname)
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(Color.npFgDim)
                }
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 2) {
                Text(hop.rttText)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(hop.avgRtt?.rttColor ?? .npFgDim)
                if hop.lossPct > 0 {
                    Text(String(format: "%.0f%% loss", hop.lossPct))
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(Color.npOrange)
                }
            }
        }
        .padding(.vertical, 4)
    }
}
