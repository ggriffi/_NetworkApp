import SwiftUI

@Observable
final class MTRViewModel {
    var host   = ""
    var rows:  [MTRRow] = []
    var status = StatusBadge.State.idle
    var errorMsg = ""

    private var task: Task<Void, Never>?

    func start() {
        guard let url = AppSettings.shared.wsURL("/ws/mtr",
              params: ["host": host, "interval": "1.0", "max_hops": "30"]) else { return }
        rows.removeAll()
        status = .running
        errorMsg = ""

        task = Task {
            for await msg in WSClient.stream(url: url) {
                if Task.isCancelled { break }
                await MainActor.run {
                    switch msg {
                    case .arrayUpdate(let data):
                        if let updated = try? JSONDecoder.netProbe.decode([MTRRow].self, from: data) {
                            rows = updated
                        }
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

struct MTRView: View {
    @State private var vm = MTRViewModel()

    var body: some View {
        ZStack {
            Color.npBackground.ignoresSafeArea()
            VStack(spacing: 12) {
                HostBar(placeholder: "hostname or IP", text: $vm.host,
                        isRunning: vm.status == .running,
                        onStart: vm.start, onStop: vm.stop)

                // Column headers
                if !vm.rows.isEmpty {
                    HStack(spacing: 4) {
                        Text("HOP").frame(width: 32)
                        Text("HOST").frame(maxWidth: .infinity, alignment: .leading)
                        Text("LOSS").frame(width: 48)
                        Text("AVG").frame(width: 56)
                        Text("BEST").frame(width: 48)
                        Text("WRST").frame(width: 48)
                    }
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(Color.npFgDim)
                    .padding(.horizontal)
                }

                if vm.rows.isEmpty {
                    EmptyState(icon: "chart.xyaxis.line", message: "Enter a host and tap Start")
                } else {
                    List(vm.rows) { row in
                        MTRRowView(row: row)
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

struct MTRRowView: View {
    let row: MTRRow
    var body: some View {
        HStack(spacing: 4) {
            Text("\(row.hop)")
                .font(.system(.caption, design: .monospaced).weight(.bold))
                .foregroundStyle(Color.npCyan)
                .frame(width: 32, alignment: .trailing)

            VStack(alignment: .leading, spacing: 1) {
                Text(row.ip == "*" ? "* * *" : row.ip)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(Color.npFgBright)
                if row.hostname != row.ip {
                    Text(row.hostname)
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(Color.npFgDim)
                        .lineLimit(1)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            Text(String(format: "%.0f%%", row.lossPct))
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(row.lossPct > 10 ? Color.npRed : Color.npFgDim)
                .frame(width: 48, alignment: .trailing)

            Text(String(format: "%.1f", row.avgMs))
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(row.avgMs.rttColor)
                .frame(width: 56, alignment: .trailing)

            Text(String(format: "%.1f", row.bestMs == 999999 ? 0 : row.bestMs))
                .font(.system(.caption2, design: .monospaced))
                .foregroundStyle(Color.npFgDim)
                .frame(width: 48, alignment: .trailing)

            Text(String(format: "%.1f", row.worstMs))
                .font(.system(.caption2, design: .monospaced))
                .foregroundStyle(Color.npFgDim)
                .frame(width: 48, alignment: .trailing)
        }
        .padding(.vertical, 3)
    }
}
