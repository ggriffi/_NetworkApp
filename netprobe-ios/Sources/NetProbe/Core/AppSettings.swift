import Foundation
import Combine

// MARK: - AppSettings

/// Single source of truth for server connection config.
/// Persisted in UserDefaults via @AppStorage — survives app restarts.
@Observable
final class AppSettings {

    static let shared = AppSettings()

    // ── persisted ────────────────────────────────────────────────────────────

    var serverURL: String {
        get { _serverURL }
        set { _serverURL = newValue.trimmingCharacters(in: .whitespacesAndNewlines) }
    }

    var apiKey: String {
        get { _apiKey }
        set { _apiKey = newValue.trimmingCharacters(in: .whitespacesAndNewlines) }
    }

    // ── private backing with UserDefaults ────────────────────────────────────

    private var _serverURL: String {
        get { UserDefaults.standard.string(forKey: "serverURL") ?? "" }
        set { UserDefaults.standard.set(newValue, forKey: "serverURL") }
    }

    private var _apiKey: String {
        get { UserDefaults.standard.string(forKey: "apiKey") ?? "" }
        set { UserDefaults.standard.set(newValue, forKey: "apiKey") }
    }

    // ── computed ─────────────────────────────────────────────────────────────

    /// Base URL validated and trimmed (trailing slash stripped).
    var baseURL: String {
        var url = serverURL
        while url.hasSuffix("/") { url.removeLast() }
        return url
    }

    var isConfigured: Bool {
        !baseURL.isEmpty
    }

    /// Build a REST URL for the given path, appending the API key if set.
    func restURL(_ path: String, params: [String: String] = [:]) -> URL? {
        guard !baseURL.isEmpty else { return nil }
        var components = URLComponents(string: baseURL + path)
        var items = params.map { URLQueryItem(name: $0.key, value: $0.value) }
        if !apiKey.isEmpty { items.append(URLQueryItem(name: "key", value: apiKey)) }
        components?.queryItems = items.isEmpty ? nil : items
        return components?.url
    }

    /// Build a WebSocket URL for the given path with params + API key.
    func wsURL(_ path: String, params: [String: String] = [:]) -> URL? {
        guard !baseURL.isEmpty else { return nil }
        // Replace http(s) with ws(s)
        let wsBase = baseURL
            .replacingOccurrences(of: "https://", with: "wss://")
            .replacingOccurrences(of: "http://",  with: "ws://")
        var components = URLComponents(string: wsBase + path)
        var items = params.map { URLQueryItem(name: $0.key, value: $0.value) }
        if !apiKey.isEmpty { items.append(URLQueryItem(name: "key", value: apiKey)) }
        components?.queryItems = items.isEmpty ? nil : items
        return components?.url
    }

    private init() {}
}
