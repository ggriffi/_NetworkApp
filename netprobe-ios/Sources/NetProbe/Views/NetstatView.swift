import SwiftUI

@Observable
final class NetstatViewModel {
    var entries:    [NetstatEntry] = []
    var isLoading = false
    var errorMsg  = ""

    // Filters
    var filterProto   = "All"
    var filterState   = "All"
    var filterText    = ""

    var filteredEntries: [NetstatEntry] {
        entries.filter { e in
            (filterProto == "All" || e.proto.uppercased() == filterProto) &&
            (filterState == "All" || e.state.uppercased() == filterState) &&
            (filterText.isEmpty ||
                e.localAddr.contains(filterText)  ||
                e.remoteAddr.contains(filterText) ||
                "\(e.localPort)".contains(filterText) ||
                "\(e.remotePort)".contains(filterText) ||
                e.process.localizedCaseInsensitiveContains(filterText))
        }
    }

    let protoOptions = ["All", "TCP", "UDP", "TCP6", "UDP6"]
    let stateOptions = ["All", "LISTEN", "ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT", "SYN_SENT"]

    func load() {
        isLoading = true
        errorMsg  = ""

        Task {
            do {
                let r = try await NetProbeClient.shared.netstat()
                await MainActor.run { entries = r; isLoading = false }
            } catch {
                await MainActor.run { errorMsg = error.localizedDescription; isLoading = false }
            }
        }
    }
}

struct NetstatView: View {
    @State private var vm = NetstatViewModel()
    @State private var refreshTimer: Timer?

    var body: some View {
        ZStack {
            Color.npBackground.ignoresSafeArea()
            VStack(spacing: 10) {
                // Filter bar
                HStack(spacing: 8) {
                    Image(systemName: "magnifyingglass").foregroundStyle(Color.npFgDim).font(.caption)
                    TextField("filter by IP, port, or process", text: $vm.filterText)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(Color.npFgBright)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                    if !vm.filterText.isEmpty {
                        Button { vm.filterText = "" } label: {
                            Image(systemName: "xmark.circle.fill").foregroundStyle(Color.npFgDim)
                        }.buttonStyle(.plain)
                    }
                }
                .padding(.horizontal, 12).padding(.vertical, 8).cardStyle().padding(.horizontal)

                // Picker row
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        ForEach(vm.protoOptions, id: \.self) { p in
                            FilterChip(label: p, selected: vm.filterProto == p) { vm.filterProto = p }
                        }
                        Divider().frame(height: 20)
                        ForEach(vm.stateOptions, id: \.self) { s in
                            FilterChip(label: s, selected: vm.filterState == s) { vm.filterState = s }
                        }
                    }
                    .padding(.horizontal)
                }

                // Toolbar
                HStack {
                    Text("\(vm.filteredEntries.count) connections")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(Color.npFgDim)
                    Spacer()
                    if vm.isLoading { ProgressView().scaleEffect(0.7) }
                    Button(action: vm.load) {
                        Image(systemName: "arrow.clockwise")
                            .foregroundStyle(Color.npCyan)
                    }
                }
                .padding(.horizontal)

                if vm.entries.isEmpty && !vm.isLoading {
                    EmptyState(icon: "list.bullet.rectangle",
                               message: "Tap refresh to load connections")
                } else {
                    List(vm.filteredEntries) { e in
                        HStack(spacing: 6) {
                            Text(e.proto)
                                .font(.system(.caption2, design: .monospaced).weight(.bold))
                                .foregroundStyle(protoColor(e.proto))
                                .frame(width: 36, alignment: .leading)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(e.localEndpoint)
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundStyle(Color.npFgBright)
                                if !e.remoteAddr.isEmpty {
                                    Text(e.remoteEndpoint)
                                        .font(.system(.caption2, design: .monospaced))
                                        .foregroundStyle(Color.npFgDim)
                                }
                            }
                            Spacer()
                            VStack(alignment: .trailing, spacing: 2) {
                                Text(e.state)
                                    .font(.system(.caption2, design: .monospaced))
                                    .foregroundStyle(stateColor(e.state))
                                if !e.process.isEmpty {
                                    Text(e.process)
                                        .font(.system(.caption2, design: .monospaced))
                                        .foregroundStyle(Color.npFgDim)
                                }
                            }
                        }
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
        .onAppear { vm.load() }
    }

    private func protoColor(_ proto: String) -> Color {
        switch proto.uppercased() {
        case "TCP", "TCP6": return .npCyan
        case "UDP", "UDP6": return .npYellow
        default:            return .npFgDim
        }
    }

    private func stateColor(_ state: String) -> Color {
        switch state.uppercased() {
        case "LISTEN":      return .npGreen
        case "ESTABLISHED": return .npCyan
        case "TIME_WAIT":   return .npYellow
        case "CLOSE_WAIT":  return .npOrange
        default:            return .npFgDim
        }
    }
}

struct FilterChip: View {
    let label: String
    let selected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(label)
                .font(.system(.caption2, design: .monospaced).weight(selected ? .bold : .regular))
                .foregroundStyle(selected ? Color.npBackground : Color.npFgDim)
                .padding(.horizontal, 10)
                .padding(.vertical, 5)
                .background(selected ? Color.npCyan : Color.npCard)
                .clipShape(Capsule())
        }
        .buttonStyle(.plain)
    }
}
