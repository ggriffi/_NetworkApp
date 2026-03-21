import SwiftUI

@Observable
final class WHOISViewModel {
    var target    = ""
    var raw       = ""
    var isLoading = false
    var errorMsg  = ""

    func lookup() {
        isLoading = true
        raw       = ""
        errorMsg  = ""

        Task {
            do {
                let r = try await NetProbeClient.shared.whois(target: target)
                await MainActor.run { raw = r.raw; isLoading = false }
            } catch {
                await MainActor.run { errorMsg = error.localizedDescription; isLoading = false }
            }
        }
    }
}

struct WHOISView: View {
    @State private var vm = WHOISViewModel()

    var body: some View {
        ZStack {
            Color.npBackground.ignoresSafeArea()
            VStack(spacing: 12) {
                HStack(spacing: 8) {
                    Image(systemName: "person.text.rectangle").foregroundStyle(Color.npFgDim)
                    TextField("domain or IP", text: $vm.target)
                        .font(.system(.body, design: .monospaced))
                        .foregroundStyle(Color.npFgBright)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .keyboardType(.URL)
                        .submitLabel(.go)
                        .onSubmit { vm.lookup() }
                    Spacer()
                    if vm.isLoading { ProgressView().scaleEffect(0.8) }
                    else { Button("Lookup", action: vm.lookup).foregroundStyle(Color.npCyan) }
                }
                .padding(.horizontal, 14).padding(.vertical, 10).cardStyle().padding(.horizontal)

                if vm.raw.isEmpty && vm.errorMsg.isEmpty {
                    EmptyState(icon: "person.text.rectangle",
                               message: "Enter a domain or IP and tap Lookup")
                } else if !vm.errorMsg.isEmpty {
                    Text(vm.errorMsg).font(.caption).foregroundStyle(Color.npRed).padding(.horizontal)
                } else {
                    ScrollView {
                        Text(vm.raw)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(Color.npFgMid)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(12)
                            .textSelection(.enabled)
                    }
                    .background(Color.npCard)
                    .clipShape(RoundedRectangle(cornerRadius: 10))
                    .padding(.horizontal)
                    .overlay(alignment: .topTrailing) {
                        CopyButton(text: vm.raw)
                            .padding(16)
                    }
                }
            }
        }
    }
}
