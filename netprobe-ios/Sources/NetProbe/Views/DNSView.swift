import SwiftUI

@Observable
final class DNSViewModel {
    var host      = ""
    var results: [DNSResult] = []
    var dohResult: DoHResult?
    var isLoading = false
    var errorMsg  = ""

    func lookup() {
        isLoading = true
        results.removeAll()
        dohResult = nil
        errorMsg  = ""

        Task {
            do {
                let r = try await NetProbeClient.shared.dns(host: host)
                await MainActor.run { results = r; isLoading = false }
            } catch {
                await MainActor.run { errorMsg = error.localizedDescription; isLoading = false }
            }
        }
    }

    func dohCompare() {
        isLoading = true
        dohResult = nil
        errorMsg  = ""

        Task {
            do {
                let r = try await NetProbeClient.shared.doh(domain: host)
                await MainActor.run { dohResult = r; isLoading = false }
            } catch {
                await MainActor.run { errorMsg = error.localizedDescription; isLoading = false }
            }
        }
    }
}

struct DNSView: View {
    @State private var vm = DNSViewModel()

    var body: some View {
        ZStack {
            Color.npBackground.ignoresSafeArea()
            VStack(spacing: 12) {
                // Input bar (manual submit only)
                HStack(spacing: 8) {
                    Image(systemName: "globe").foregroundStyle(Color.npFgDim)
                    TextField("domain or IP", text: $vm.host)
                        .font(.system(.body, design: .monospaced))
                        .foregroundStyle(Color.npFgBright)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .keyboardType(.URL)
                        .submitLabel(.go)
                        .onSubmit { vm.lookup() }
                    Spacer()
                    if vm.isLoading {
                        ProgressView().scaleEffect(0.8)
                    } else {
                        Button("Lookup", action: vm.lookup).foregroundStyle(Color.npCyan)
                        Button("DoH", action: vm.dohCompare)
                            .font(.system(.subheadline, design: .monospaced))
                            .foregroundStyle(Color.npYellow)
                    }
                }
                .padding(.horizontal, 14).padding(.vertical, 10).cardStyle().padding(.horizontal)

                if let doh = vm.dohResult {
                    DoHCompareView(result: doh)
                } else if vm.results.isEmpty {
                    EmptyState(icon: "globe", message: "Enter a domain and tap Lookup")
                } else {
                    List(vm.results) { r in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Text(r.recordType)
                                    .font(.system(.caption, design: .monospaced).weight(.bold))
                                    .foregroundStyle(Color.npCyan)
                                    .frame(width: 48, alignment: .leading)
                                Spacer()
                                Text(String(format: "%.0f ms", r.rttMs))
                                    .font(.system(.caption2, design: .monospaced))
                                    .foregroundStyle(Color.npFgDim)
                            }
                            ForEach(r.answers, id: \.self) { ans in
                                HStack {
                                    Text(ans)
                                        .font(.system(.caption, design: .monospaced))
                                        .foregroundStyle(Color.npFgBright)
                                    Spacer()
                                    CopyButton(text: ans)
                                }
                            }
                            if !r.error.isEmpty {
                                Text(r.error).font(.caption2).foregroundStyle(Color.npRed)
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
    }
}

struct DoHCompareView: View {
    let result: DoHResult
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionHeader(title: "DNS-over-HTTPS Comparison")
            HStack(alignment: .top, spacing: 12) {
                DoHColumn(title: "Google", answers: result.google, color: .npCyan)
                DoHColumn(title: "Cloudflare", answers: result.cloudflare, color: .npOrange)
            }
            .padding(.horizontal)
        }
    }
}

struct DoHColumn: View {
    let title: String
    let answers: [String]
    let color: Color
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.system(.caption, design: .monospaced).weight(.semibold))
                .foregroundStyle(color)
            ForEach(answers, id: \.self) { ans in
                Text(ans)
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(Color.npFgMid)
            }
            if answers.isEmpty {
                Text("—").font(.caption2).foregroundStyle(Color.npFgDim)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
        .cardStyle()
    }
}
