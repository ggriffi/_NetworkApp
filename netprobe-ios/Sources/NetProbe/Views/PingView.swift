import SwiftUI

// MARK: - ViewModel

@Observable
final class PingViewModel {

    var host      = ""
    var results: [PingResult] = []
    var status    = StatusBadge.State.idle
    var errorMsg  = ""

    var sent:     Int    { results.count }
    var received: Int    { results.filter { !$0.isTimeout }.count }
    var lossPct:  Double { sent == 0 ? 0 : Double(sent - received) / Double(sent) * 100 }
    var avgRtt:   Double? {
        let valid = results.compactMap { $0.isTimeout ? nil : $0.rttMs }
        return valid.isEmpty ? nil : valid.reduce(0, +) / Double(valid.count)
    }
    var minRtt: Double? { results.compactMap { $0.isTimeout ? nil : $0.rttMs }.min() }
    var maxRtt: Double? { results.compactMap { $0.isTimeout ? nil : $0.rttMs }.max() }
    var jitter:  Double? {
        let valid = results.suffix(20).compactMap { $0.isTimeout ? nil : $0.rttMs }
        guard valid.count > 1, let avg = avgRtt else { return nil }
        let variance = valid.map { ($0 - avg) * ($0 - avg) }.reduce(0, +) / Double(valid.count)
        return sqrt(variance)
    }

    // Sparkline — last 60 RTTs
    var sparkline: [Double] { results.suffix(60).map { $0.isTimeout ? -1 : $0.rttMs } }

    private var task: Task<Void, Never>?

    func start() {
        guard let url = AppSettings.shared.wsURL("/ws/ping",
              params: ["host": host, "interval": "1.0"]) else {
            errorMsg = "Server not configured."
            return
        }
        results.removeAll()
        status = .running
        errorMsg = ""

        task = Task {
            for await msg in WSClient.stream(url: url) {
                if Task.isCancelled { break }
                await MainActor.run {
                    switch msg {
                    case .result(let data):
                        if let r = data.decode(PingResult.self) { results.append(r) }
                    case .done:
                        status = .done
                    case .error(let e):
                        errorMsg = e; status = .error
                    case .arrayUpdate:
                        break
                    }
                }
            }
        }
    }

    func stop() {
        task?.cancel()
        task = nil
        status = .done
    }
}

// MARK: - View

struct PingView: View {

    @State private var vm = PingViewModel()

    var body: some View {
        ZStack {
            Color.npBackground.ignoresSafeArea()

            VStack(spacing: 12) {
                // ── Host bar ─────────────────────────────────────────────────
                HostBar(
                    placeholder: "hostname or IP",
                    text: $vm.host,
                    isRunning: vm.status == .running,
                    onStart: vm.start,
                    onStop: vm.stop
                )

                // ── Stats row ─────────────────────────────────────────────────
                HStack(spacing: 8) {
                    StatChip(label: "SENT",    value: "\(vm.sent)")
                    StatChip(label: "RECV",    value: "\(vm.received)")
                    StatChip(label: "LOSS",
                             value: String(format: "%.0f%%", vm.lossPct),
                             color: vm.lossPct > 10 ? .npRed : .npGreen)
                    StatChip(label: "AVG",
                             value: vm.avgRtt.map { String(format: "%.1f ms", $0) } ?? "—",
                             color: vm.avgRtt?.rttColor ?? .npFgDim)
                    StatChip(label: "JITTER",
                             value: vm.jitter.map { String(format: "%.1f ms", $0) } ?? "—")
                }
                .padding(.horizontal)

                // ── Sparkline ─────────────────────────────────────────────────
                if !vm.sparkline.isEmpty {
                    SparklineView(values: vm.sparkline)
                        .frame(height: 44)
                        .padding(.horizontal)
                }

                // ── Result list ───────────────────────────────────────────────
                if vm.results.isEmpty {
                    EmptyState(icon: "dot.radiowaves.left.and.right",
                               message: "Enter a host and tap Start")
                } else {
                    List(vm.results.reversed()) { r in
                        HStack {
                            Text("#\(r.seq)")
                                .font(.system(.caption, design: .monospaced))
                                .foregroundStyle(Color.npFgDim)
                                .frame(width: 40, alignment: .leading)
                            Text(r.rttText)
                                .font(.system(.body, design: .monospaced).weight(.semibold))
                                .foregroundStyle(r.isTimeout ? Color.npRed : r.rttMs.rttColor)
                            Spacer()
                            Text(r.ip)
                                .font(.system(.caption, design: .monospaced))
                                .foregroundStyle(Color.npFgDim)
                            Text("TTL \(r.ttl)")
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundStyle(Color.npFgDim)
                        }
                        .listRowBackground(Color.npCard)
                    }
                    .listStyle(.plain)
                    .scrollContentBackground(.hidden)
                }

                if !vm.errorMsg.isEmpty {
                    Text(vm.errorMsg)
                        .font(.caption)
                        .foregroundStyle(Color.npRed)
                        .padding(.horizontal)
                }
            }
        }
    }
}

// MARK: - Sparkline

struct SparklineView: View {
    let values: [Double]  // -1 = timeout

    var body: some View {
        GeometryReader { geo in
            let max = values.filter { $0 >= 0 }.max() ?? 1
            let w   = geo.size.width / CGFloat(max(values.count, 1))
            let h   = geo.size.height

            ZStack(alignment: .bottom) {
                // Grid line at 50%
                Rectangle()
                    .fill(Color.npBorder)
                    .frame(height: 0.5)
                    .offset(y: -h * 0.5)

                HStack(alignment: .bottom, spacing: 1) {
                    ForEach(Array(values.enumerated()), id: \.offset) { _, v in
                        if v < 0 {
                            Rectangle()
                                .fill(Color.npRed.opacity(0.6))
                                .frame(width: w - 1, height: 3)
                        } else {
                            let barH = max == 0 ? 4 : max(4, CGFloat(v / max) * h)
                            Rectangle()
                                .fill(v.rttColor.opacity(0.85))
                                .frame(width: w - 1, height: barH)
                        }
                    }
                }
            }
        }
        .background(Color.npCard)
        .clipShape(RoundedRectangle(cornerRadius: 6))
    }
}
