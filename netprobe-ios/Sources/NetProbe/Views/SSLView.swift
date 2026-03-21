import SwiftUI

@Observable
final class SSLViewModel {
    var host      = ""
    var port      = "443"
    var result:   SSLInfo?
    var isLoading = false
    var errorMsg  = ""

    func inspect() {
        isLoading = true
        result    = nil
        errorMsg  = ""
        let p = Int(port) ?? 443

        Task {
            do {
                let r = try await NetProbeClient.shared.ssl(host: host, port: p)
                await MainActor.run { result = r; isLoading = false }
            } catch {
                await MainActor.run { errorMsg = error.localizedDescription; isLoading = false }
            }
        }
    }
}

struct SSLView: View {
    @State private var vm = SSLViewModel()

    var body: some View {
        ZStack {
            Color.npBackground.ignoresSafeArea()
            VStack(spacing: 12) {
                // Input
                HStack(spacing: 8) {
                    Image(systemName: "lock.shield").foregroundStyle(Color.npFgDim)
                    TextField("hostname", text: $vm.host)
                        .font(.system(.body, design: .monospaced))
                        .foregroundStyle(Color.npFgBright)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .keyboardType(.URL)
                    Text(":")
                        .foregroundStyle(Color.npFgDim)
                    TextField("443", text: $vm.port)
                        .font(.system(.body, design: .monospaced))
                        .foregroundStyle(Color.npCyan)
                        .frame(width: 50)
                        .keyboardType(.numberPad)
                    Spacer()
                    if vm.isLoading {
                        ProgressView().scaleEffect(0.8)
                    } else {
                        Button("Inspect", action: vm.inspect).foregroundStyle(Color.npCyan)
                    }
                }
                .padding(.horizontal, 14).padding(.vertical, 10).cardStyle().padding(.horizontal)

                if let r = vm.result {
                    SSLResultView(info: r)
                } else if !vm.errorMsg.isEmpty {
                    Text(vm.errorMsg).font(.caption).foregroundStyle(Color.npRed).padding(.horizontal)
                } else {
                    EmptyState(icon: "lock.shield", message: "Enter a hostname and tap Inspect")
                }
            }
        }
    }
}

struct SSLResultView: View {
    let info: SSLInfo

    private var expiryColor: Color {
        if info.expired             { return .npRed    }
        if info.daysRemaining < 14  { return .npOrange }
        if info.daysRemaining < 30  { return .npYellow }
        return .npGreen
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                // Expiry chip row
                HStack(spacing: 8) {
                    StatChip(label: "DAYS LEFT",
                             value: "\(info.daysRemaining)",
                             color: expiryColor)
                    StatChip(label: "VERIFIED",
                             value: info.verified ? "YES" : "NO",
                             color: info.verified ? .npGreen : .npOrange)
                    StatChip(label: "TLS",
                             value: info.version,
                             color: .npCyan)
                }
                .padding(.horizontal)

                // Certificate fields
                VStack(spacing: 0) {
                    SSLField(label: "Subject",  value: info.subjectCn.isEmpty ? info.subject : info.subjectCn)
                    SSLField(label: "Issuer",   value: info.issuer)
                    SSLField(label: "Cipher",   value: info.cipher)
                    SSLField(label: "Valid from", value: info.notBefore)
                    SSLField(label: "Valid to",  value: info.notAfter)
                }
                .cardStyle()
                .padding(.horizontal)

                // SANs
                if !info.san.isEmpty {
                    SectionHeader(title: "Subject Alternative Names")
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(info.san, id: \.self) { san in
                            HStack {
                                Text(san)
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundStyle(Color.npFgMid)
                                Spacer()
                                CopyButton(text: san)
                            }
                            .padding(.horizontal, 12)
                            .padding(.vertical, 4)
                        }
                    }
                    .cardStyle()
                    .padding(.horizontal)
                }

                if !info.error.isEmpty {
                    Text(info.error).font(.caption).foregroundStyle(Color.npRed).padding(.horizontal)
                }
            }
            .padding(.bottom)
        }
    }
}

struct SSLField: View {
    let label: String
    let value: String
    var body: some View {
        HStack(alignment: .top) {
            Text(label)
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(Color.npFgDim)
                .frame(width: 90, alignment: .leading)
            Text(value.isEmpty ? "—" : value)
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(Color.npFgBright)
                .frame(maxWidth: .infinity, alignment: .leading)
            CopyButton(text: value)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        Divider().background(Color.npBorder)
    }
}
