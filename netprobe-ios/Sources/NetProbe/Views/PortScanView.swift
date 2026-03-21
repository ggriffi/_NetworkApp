import SwiftUI

@Observable
final class PortScanViewModel {
    var host     = ""
    var ports    = "1-1024"
    var proto    = "tcp"
    var results: [PortResult] = []
    var status   = StatusBadge.State.idle
    var errorMsg = ""

    var openCount: Int { results.filter(\.isOpen).count }

    private var task: Task<Void, Never>?

    func start() {
        guard let url = AppSettings.shared.wsURL("/ws/portscan", params: [
            "host": host, "ports": ports, "proto": proto, "threads": "100"
        ]) else { return }
        results.removeAll()
        status = .running
        errorMsg = ""

        task = Task {
            for await msg in WSClient.stream(url: url) {
                if Task.isCancelled { break }
                await MainActor.run {
                    switch msg {
                    case .result(let data):
                        if let r = data.decode(PortResult.self), r.isOpen { results.append(r) }
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

struct PortScanView: View {
    @State private var vm = PortScanViewModel()

    var body: some View {
        ZStack {
            Color.npBackground.ignoresSafeArea()
            VStack(spacing: 12) {
                // Host
                HostBar(placeholder: "IP, hostname, or 10.0.0.0/24", text: $vm.host,
                        isRunning: vm.status == .running,
                        onStart: vm.start, onStop: vm.stop)

                // Options row
                HStack(spacing: 10) {
                    // Port spec
                    HStack(spacing: 6) {
                        Image(systemName: "number").foregroundStyle(Color.npFgDim).font(.caption)
                        TextField("ports: 1-1024", text: $vm.ports)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(Color.npFgBright)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .keyboardType(.numbersAndPunctuation)
                    }
                    .padding(.horizontal, 10)
                    .padding(.vertical, 7)
                    .cardStyle()

                    // Protocol picker
                    Picker("", selection: $vm.proto) {
                        Text("TCP").tag("tcp")
                        Text("UDP").tag("udp")
                    }
                    .pickerStyle(.segmented)
                    .frame(width: 100)
                }
                .padding(.horizontal)

                // Stats
                HStack {
                    StatusBadge(state: vm.status)
                    Spacer()
                    Text("\(vm.openCount) open")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(vm.openCount > 0 ? Color.npGreen : Color.npFgDim)
                }
                .padding(.horizontal)

                if vm.results.isEmpty {
                    EmptyState(icon: "lock.open.laptopcomputer",
                               message: "Only open ports are shown.\nEnter a target and tap Start.")
                } else {
                    List(vm.results) { r in
                        HStack {
                            Text("\(r.port)")
                                .font(.system(.body, design: .monospaced).weight(.bold))
                                .foregroundStyle(Color.npGreen)
                                .frame(width: 50, alignment: .leading)
                            Text(r.service.isEmpty ? vm.proto.uppercased() : r.service)
                                .font(.system(.subheadline, design: .monospaced))
                                .foregroundStyle(Color.npFgMid)
                            Spacer()
                            if !r.host.isEmpty {
                                Text(r.host)
                                    .font(.system(.caption2, design: .monospaced))
                                    .foregroundStyle(Color.npFgDim)
                            }
                            Text(String(format: "%.0f ms", r.rttMs))
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundStyle(Color.npFgDim)
                        }
                        .listRowBackground(Color.npCard)
                        .swipeActions {
                            Button("Copy") { UIPasteboard.general.string = "\(r.host):\(r.port)" }
                                .tint(Color.npCyan)
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
