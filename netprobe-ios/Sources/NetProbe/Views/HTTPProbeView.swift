import SwiftUI

@Observable
final class HTTPProbeViewModel {
    var url       = "https://"
    var method    = "GET"
    var result:   HTTPResult?
    var isLoading = false
    var errorMsg  = ""

    func probe() {
        isLoading = true
        result    = nil
        errorMsg  = ""

        Task {
            do {
                let r = try await NetProbeClient.shared.httpProbe(url: url, method: method)
                await MainActor.run { result = r; isLoading = false }
            } catch {
                await MainActor.run { errorMsg = error.localizedDescription; isLoading = false }
            }
        }
    }
}

struct HTTPProbeView: View {
    @State private var vm = HTTPProbeViewModel()

    private var statusColor: Color {
        guard let r = vm.result else { return .npFgDim }
        if r.statusCode < 300 { return .npGreen  }
        if r.statusCode < 400 { return .npYellow }
        return .npRed
    }

    var body: some View {
        ZStack {
            Color.npBackground.ignoresSafeArea()
            VStack(spacing: 12) {
                // Input
                HStack(spacing: 8) {
                    Image(systemName: "safari").foregroundStyle(Color.npFgDim)
                    TextField("https://example.com", text: $vm.url)
                        .font(.system(.body, design: .monospaced))
                        .foregroundStyle(Color.npFgBright)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .keyboardType(.URL)
                        .submitLabel(.go)
                        .onSubmit { vm.probe() }
                    Picker("", selection: $vm.method) {
                        Text("GET").tag("GET")
                        Text("HEAD").tag("HEAD")
                    }
                    .pickerStyle(.segmented)
                    .frame(width: 90)
                    Spacer()
                    if vm.isLoading { ProgressView().scaleEffect(0.8) }
                    else { Button("Probe", action: vm.probe).foregroundStyle(Color.npCyan) }
                }
                .padding(.horizontal, 14).padding(.vertical, 10).cardStyle().padding(.horizontal)

                if let r = vm.result {
                    // Stat chips
                    HStack(spacing: 8) {
                        StatChip(label: "STATUS",
                                 value: "\(r.statusCode)",
                                 color: statusColor)
                        StatChip(label: "TTFB",
                                 value: String(format: "%.0f ms", r.ttfbMs),
                                 color: r.ttfbMs.rttColor)
                        StatChip(label: "TOTAL",
                                 value: String(format: "%.0f ms", r.totalMs))
                        if r.contentLength > 0 {
                            StatChip(label: "SIZE",
                                     value: formatBytes(r.contentLength))
                        }
                    }
                    .padding(.horizontal)

                    ScrollView {
                        VStack(alignment: .leading, spacing: 16) {
                            // Final URL
                            if r.finalUrl != r.url && !r.finalUrl.isEmpty {
                                VStack(alignment: .leading, spacing: 4) {
                                    SectionHeader(title: "Final URL")
                                    HStack {
                                        Text(r.finalUrl)
                                            .font(.system(.caption, design: .monospaced))
                                            .foregroundStyle(Color.npFgMid)
                                        Spacer()
                                        CopyButton(text: r.finalUrl)
                                    }
                                    .padding(12).cardStyle()
                                }
                                .padding(.horizontal)
                            }

                            // Redirect chain
                            if !r.redirectChain.isEmpty {
                                SectionHeader(title: "Redirect Chain")
                                VStack(alignment: .leading, spacing: 4) {
                                    ForEach(Array(r.redirectChain.enumerated()), id: \.offset) { i, url in
                                        HStack(alignment: .top, spacing: 6) {
                                            Text("\(i + 1)")
                                                .font(.system(.caption2, design: .monospaced))
                                                .foregroundStyle(Color.npCyan)
                                            Text(url)
                                                .font(.system(.caption2, design: .monospaced))
                                                .foregroundStyle(Color.npFgMid)
                                        }
                                        .padding(.horizontal, 12).padding(.vertical, 3)
                                    }
                                }
                                .cardStyle().padding(.horizontal)
                            }

                            // Response headers
                            if !r.headers.isEmpty {
                                SectionHeader(title: "Response Headers")
                                VStack(spacing: 0) {
                                    ForEach(r.headers.sorted(by: { $0.key < $1.key }), id: \.key) { k, v in
                                        HStack(alignment: .top) {
                                            Text(k)
                                                .font(.system(.caption2, design: .monospaced))
                                                .foregroundStyle(Color.npCyan)
                                                .frame(width: 140, alignment: .leading)
                                            Text(v)
                                                .font(.system(.caption2, design: .monospaced))
                                                .foregroundStyle(Color.npFgMid)
                                                .frame(maxWidth: .infinity, alignment: .leading)
                                        }
                                        .padding(.horizontal, 12).padding(.vertical, 5)
                                        Divider().background(Color.npBorder)
                                    }
                                }
                                .cardStyle().padding(.horizontal)
                            }
                        }
                        .padding(.bottom)
                    }
                } else if !vm.errorMsg.isEmpty {
                    Text(vm.errorMsg).font(.caption).foregroundStyle(Color.npRed).padding(.horizontal)
                } else {
                    EmptyState(icon: "safari", message: "Enter a URL and tap Probe")
                }
            }
        }
    }

    private func formatBytes(_ bytes: Int) -> String {
        if bytes > 1_000_000 { return String(format: "%.1f MB", Double(bytes) / 1_000_000) }
        if bytes > 1_000     { return String(format: "%.0f KB", Double(bytes) / 1_000) }
        return "\(bytes) B"
    }
}
