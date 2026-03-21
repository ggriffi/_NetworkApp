import SwiftUI

struct SettingsView: View {

    @Environment(AppSettings.self) private var settings
    @Environment(\.dismiss) private var dismiss

    @State private var urlDraft  = ""
    @State private var keyDraft  = ""
    @State private var testState: TestState = .idle
    @State private var testDetail = ""

    enum TestState { case idle, testing, ok, fail }

    var body: some View {
        NavigationStack {
            Form {
                // ── Connection ──────────────────────────────────────────────
                Section {
                    LabeledContent("Server URL") {
                        TextField("https://netprobe.yourdomain.com", text: $urlDraft)
                            .multilineTextAlignment(.trailing)
                            .font(.system(.body, design: .monospaced))
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .keyboardType(.URL)
                    }
                    LabeledContent("API Key") {
                        SecureField("your-secret-key", text: $keyDraft)
                            .multilineTextAlignment(.trailing)
                            .font(.system(.body, design: .monospaced))
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                    }
                } header: {
                    Text("Server")
                } footer: {
                    Text("The server URL should match your Cloudflare Tunnel hostname (e.g. https://netprobe.yourdomain.com). Leave API Key blank if auth is disabled.")
                }

                // ── Test connection ──────────────────────────────────────────
                Section {
                    Button(action: testConnection) {
                        HStack {
                            Label("Test Connection", systemImage: "wifi")
                            Spacer()
                            switch testState {
                            case .idle:    EmptyView()
                            case .testing: ProgressView().scaleEffect(0.8)
                            case .ok:      Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                            case .fail:    Image(systemName: "xmark.circle.fill").foregroundStyle(.red)
                            }
                        }
                    }
                    .disabled(urlDraft.isEmpty || testState == .testing)
                    if !testDetail.isEmpty {
                        Text(testDetail)
                            .font(.caption)
                            .foregroundStyle(testState == .ok ? Color.green : Color.red)
                    }
                }

                // ── About ────────────────────────────────────────────────────
                Section("About") {
                    LabeledContent("Version", value: "1.1.0")
                    LabeledContent("Minimum iOS", value: "17.0")
                    Link("Server Docs", destination: URL(string: urlDraft.isEmpty ? "https://github.com" : urlDraft + "/docs")!)
                }
            }
            .scrollContentBackground(.hidden)
            .background(Color.npBackground)
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { save() }
                        .fontWeight(.semibold)
                        .foregroundStyle(Color.npCyan)
                }
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                        .foregroundStyle(Color.npFgDim)
                }
            }
        }
        .onAppear {
            urlDraft = settings.serverURL
            keyDraft = settings.apiKey
        }
    }

    // MARK: - Actions

    private func save() {
        settings.serverURL = urlDraft
        settings.apiKey    = keyDraft
        dismiss()
    }

    private func testConnection() {
        testState  = .testing
        testDetail = ""

        // Temporarily apply draft values for the test
        let savedURL = settings.serverURL
        let savedKey = settings.apiKey
        settings.serverURL = urlDraft
        settings.apiKey    = keyDraft

        Task {
            do {
                let h = try await NetProbeClient.shared.health()
                testState  = .ok
                testDetail = "Connected — NetProbe Server v\(h.version)"
            } catch {
                testState  = .fail
                testDetail = error.localizedDescription
            }
            // Restore original values (user hasn't saved yet)
            settings.serverURL = savedURL
            settings.apiKey    = savedKey
        }
    }
}
