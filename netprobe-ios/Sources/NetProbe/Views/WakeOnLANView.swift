import SwiftUI

struct SavedWoLTarget: Codable, Identifiable {
    var id     = UUID()
    var label  : String
    var mac    : String
    var broadcast: String
    var port   : Int
}

@Observable
final class WakeOnLANViewModel {
    var mac       = ""
    var broadcast = "255.255.255.255"
    var port      = "9"
    var label     = ""
    var lastResult = ""
    var isSending = false
    var errorMsg  = ""

    var savedTargets: [SavedWoLTarget] = []

    init() { loadSaved() }

    func send() {
        guard !mac.isEmpty else { errorMsg = "Enter a MAC address."; return }
        isSending  = true
        lastResult = ""
        errorMsg   = ""

        Task {
            do {
                let r = try await NetProbeClient.shared.wol(
                    mac: mac,
                    broadcast: broadcast,
                    port: Int(port) ?? 9
                )
                await MainActor.run {
                    lastResult = r.success ? "Magic packet sent to \(r.mac)" : "Failed to send."
                    isSending  = false
                }
            } catch {
                await MainActor.run {
                    errorMsg  = error.localizedDescription
                    isSending = false
                }
            }
        }
    }

    func save() {
        guard !mac.isEmpty else { return }
        let t = SavedWoLTarget(
            label: label.isEmpty ? mac : label,
            mac: mac,
            broadcast: broadcast,
            port: Int(port) ?? 9
        )
        savedTargets.insert(t, at: 0)
        persistSaved()
    }

    func delete(at offsets: IndexSet) {
        savedTargets.remove(atOffsets: offsets)
        persistSaved()
    }

    func load(target: SavedWoLTarget) {
        mac       = target.mac
        broadcast = target.broadcast
        port      = "\(target.port)"
        label     = target.label
    }

    private func persistSaved() {
        if let data = try? JSONEncoder().encode(savedTargets) {
            UserDefaults.standard.set(data, forKey: "wolTargets")
        }
    }

    private func loadSaved() {
        if let data = UserDefaults.standard.data(forKey: "wolTargets"),
           let targets = try? JSONDecoder().decode([SavedWoLTarget].self, from: data) {
            savedTargets = targets
        }
    }
}

struct WakeOnLANView: View {
    @State private var vm = WakeOnLANViewModel()

    var body: some View {
        ZStack {
            Color.npBackground.ignoresSafeArea()
            VStack(spacing: 12) {
                // MAC input
                HStack(spacing: 8) {
                    Image(systemName: "power").foregroundStyle(Color.npFgDim)
                    TextField("MAC  AA:BB:CC:DD:EE:FF", text: $vm.mac)
                        .font(.system(.body, design: .monospaced))
                        .foregroundStyle(Color.npFgBright)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .keyboardType(.asciiCapable)
                    Spacer()
                    if vm.isSending { ProgressView().scaleEffect(0.8) }
                    else {
                        Button(action: vm.send) {
                            Label("Send", systemImage: "bolt.fill")
                                .font(.system(.subheadline).weight(.semibold))
                                .foregroundStyle(Color.npCyan)
                        }
                    }
                }
                .padding(.horizontal, 14).padding(.vertical, 10).cardStyle().padding(.horizontal)

                // Options
                HStack(spacing: 10) {
                    HStack(spacing: 6) {
                        Image(systemName: "network").foregroundStyle(Color.npFgDim).font(.caption)
                        TextField("Broadcast", text: $vm.broadcast)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(Color.npFgMid)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .keyboardType(.numbersAndPunctuation)
                    }
                    .padding(.horizontal, 10).padding(.vertical, 7).cardStyle()

                    HStack(spacing: 6) {
                        Text("Port").font(.system(.caption, design: .monospaced)).foregroundStyle(Color.npFgDim)
                        TextField("9", text: $vm.port)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(Color.npCyan)
                            .keyboardType(.numberPad)
                            .frame(width: 40)
                    }
                    .padding(.horizontal, 10).padding(.vertical, 7).cardStyle()
                }
                .padding(.horizontal)

                // Label + Save
                HStack(spacing: 8) {
                    TextField("Label (optional)", text: $vm.label)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(Color.npFgMid)
                        .padding(.horizontal, 10).padding(.vertical, 7).cardStyle()
                    Button("Save", action: vm.save)
                        .font(.system(.subheadline).weight(.semibold))
                        .foregroundStyle(Color.npYellow)
                }
                .padding(.horizontal)

                // Result / error
                if !vm.lastResult.isEmpty {
                    Text(vm.lastResult)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(Color.npGreen)
                        .padding(.horizontal)
                }
                if !vm.errorMsg.isEmpty {
                    Text(vm.errorMsg).font(.caption).foregroundStyle(Color.npRed).padding(.horizontal)
                }

                // Saved targets
                if !vm.savedTargets.isEmpty {
                    SectionHeader(title: "Saved Targets")
                    List {
                        ForEach(vm.savedTargets) { t in
                            Button(action: { vm.load(target: t) }) {
                                HStack {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(t.label)
                                            .font(.system(.subheadline, design: .monospaced))
                                            .foregroundStyle(Color.npFgBright)
                                        Text(t.mac)
                                            .font(.system(.caption2, design: .monospaced))
                                            .foregroundStyle(Color.npFgDim)
                                    }
                                    Spacer()
                                    Button(action: {
                                        vm.load(target: t)
                                        vm.send()
                                    }) {
                                        Image(systemName: "bolt.fill")
                                            .foregroundStyle(Color.npCyan)
                                    }
                                }
                            }
                            .listRowBackground(Color.npCard)
                            .listRowSeparatorTint(Color.npBorder)
                        }
                        .onDelete(perform: vm.delete)
                    }
                    .listStyle(.plain)
                    .scrollContentBackground(.hidden)
                }
            }
        }
    }
}
