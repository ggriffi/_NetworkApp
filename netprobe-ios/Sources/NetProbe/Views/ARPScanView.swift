import SwiftUI

@Observable
final class ARPScanViewModel {
    var network  = ""
    var entries: [ARPEntry] = []
    var status   = StatusBadge.State.idle
    var errorMsg = ""

    private var task: Task<Void, Never>?

    func start() {
        guard let url = AppSettings.shared.wsURL("/ws/arp",
              params: ["network": network]) else { return }
        entries.removeAll()
        status = .running
        errorMsg = ""

        task = Task {
            for await msg in WSClient.stream(url: url) {
                if Task.isCancelled { break }
                await MainActor.run {
                    switch msg {
                    case .result(let data):
                        if let e = data.decode(ARPEntry.self) { entries.append(e) }
                    case .done:    status = .done
                    case .error(let e): errorMsg = e; status = .error
                    default: break
                    }
                }
            }
        }
    }

    func stop() { task?.cancel(); task = nil; status = .done }
}

struct ARPScanView: View {
    @State private var vm = ARPScanViewModel()

    var body: some View {
        ZStack {
            Color.npBackground.ignoresSafeArea()
            VStack(spacing: 12) {
                HostBar(placeholder: "192.168.1.0/24", text: $vm.network,
                        isRunning: vm.status == .running,
                        onStart: vm.start, onStop: vm.stop)

                HStack {
                    StatusBadge(state: vm.status)
                    Spacer()
                    Text("\(vm.entries.count) hosts")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(Color.npFgDim)
                }
                .padding(.horizontal)

                if vm.entries.isEmpty {
                    EmptyState(icon: "network",
                               message: "Enter a subnet (e.g. 192.168.1.0/24)\nand tap Start")
                } else {
                    List(vm.entries) { e in
                        HStack(spacing: 8) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(e.ip)
                                    .font(.system(.subheadline, design: .monospaced).weight(.semibold))
                                    .foregroundStyle(Color.npCyan)
                                if !e.hostname.isEmpty && e.hostname != e.ip {
                                    Text(e.hostname)
                                        .font(.system(.caption2, design: .monospaced))
                                        .foregroundStyle(Color.npFgDim)
                                }
                            }
                            Spacer()
                            VStack(alignment: .trailing, spacing: 2) {
                                Text(e.mac)
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundStyle(Color.npFgMid)
                                if !e.vendor.isEmpty {
                                    Text(e.vendor)
                                        .font(.system(.caption2, design: .monospaced))
                                        .foregroundStyle(Color.npFgDim)
                                }
                            }
                        }
                        .listRowBackground(Color.npCard)
                        .listRowSeparatorTint(Color.npBorder)
                        .swipeActions(edge: .trailing) {
                            Button("Copy IP") { UIPasteboard.general.string = e.ip }
                                .tint(Color.npCyan)
                            Button("Copy MAC") { UIPasteboard.general.string = e.mac }
                                .tint(Color.npYellow)
                        }
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
