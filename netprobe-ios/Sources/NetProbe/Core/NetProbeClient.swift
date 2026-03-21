import Foundation

// MARK: - API errors

enum APIError: LocalizedError {
    case notConfigured
    case invalidURL
    case httpError(Int, String)
    case decodingError(Error)
    case networkError(Error)

    var errorDescription: String? {
        switch self {
        case .notConfigured:        return "Server URL is not configured. Open Settings."
        case .invalidURL:           return "Invalid URL."
        case .httpError(let c, let m): return "HTTP \(c): \(m)"
        case .decodingError(let e): return "Decode error: \(e.localizedDescription)"
        case .networkError(let e):  return e.localizedDescription
        }
    }
}

// MARK: - NetProbeClient

/// Async/await REST client for NetProbe Server.
/// All methods throw APIError on failure.
final class NetProbeClient {

    static let shared = NetProbeClient()
    private let session = URLSession(configuration: .default)
    private var settings: AppSettings { .shared }

    private init() {}

    // MARK: - Health

    func health() async throws -> HealthResponse {
        try await get("/health", params: [:])
    }

    // MARK: - Ping (blocking, one-shot)

    func ping(host: String, count: Int = 4) async throws -> [String: Any] {
        try await getRaw("/api/ping", params: ["host": host, "count": "\(count)"])
    }

    // MARK: - DNS

    func dns(host: String, types: String = "A,AAAA,MX,NS,TXT,CNAME,SOA") async throws -> [DNSResult] {
        try await getArray("/api/dns", params: ["host": host, "types": types])
    }

    func doh(domain: String, type: String = "A") async throws -> DoHResult {
        try await get("/api/doh", params: ["domain": domain, "type": type])
    }

    // MARK: - SSL

    func ssl(host: String, port: Int = 443) async throws -> SSLInfo {
        try await get("/api/ssl", params: ["host": host, "port": "\(port)"])
    }

    // MARK: - HTTP Probe

    func httpProbe(url: String, method: String = "GET", followRedirects: Bool = true) async throws -> HTTPResult {
        try await get("/api/http", params: [
            "url": url,
            "method": method,
            "follow_redirects": followRedirects ? "true" : "false",
        ])
    }

    // MARK: - WHOIS

    func whois(target: String) async throws -> WHOISResult {
        try await get("/api/whois", params: ["target": target])
    }

    // MARK: - GeoIP

    func geoip(ip: String) async throws -> GeoIPResult {
        try await get("/api/geoip", params: ["ip": ip])
    }

    // MARK: - ASN

    func asn(ip: String) async throws -> [String: Any] {
        try await getRaw("/api/asn", params: ["ip": ip])
    }

    // MARK: - Netstat

    func netstat(
        proto: String? = nil,
        state: String? = nil,
        port: Int? = nil,
        process: String? = nil
    ) async throws -> [NetstatEntry] {
        var p: [String: String] = [:]
        if let proto   { p["proto"]   = proto }
        if let state   { p["state"]   = state }
        if let port    { p["port"]    = "\(port)" }
        if let process { p["process"] = process }
        return try await getArray("/api/netstat", params: p)
    }

    // MARK: - Interfaces

    func interfaces() async throws -> [[String: Any]] {
        guard let url = settings.restURL("/api/interfaces") else { throw APIError.notConfigured }
        let data = try await fetch(url: url)
        guard let arr = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
            throw APIError.decodingError(NSError(domain: "decode", code: 0))
        }
        return arr
    }

    // MARK: - Ping sweep

    func sweep(network: String) async throws -> SweepResult {
        try await get("/api/sweep", params: ["network": network])
    }

    // MARK: - Wake-on-LAN

    func wol(mac: String, broadcast: String = "255.255.255.255", port: Int = 9) async throws -> WoLResponse {
        guard let url = settings.restURL("/api/wol") else { throw APIError.notConfigured }
        let body: [String: Any] = ["mac": mac, "broadcast": broadcast, "port": port]
        let data = try await post(url: url, body: body)
        return try decode(WoLResponse.self, from: data)
    }

    // MARK: - Private helpers

    private func get<T: Decodable>(_ path: String, params: [String: String]) async throws -> T {
        guard let url = settings.restURL(path, params: params) else { throw APIError.notConfigured }
        let data = try await fetch(url: url)
        return try decode(T.self, from: data)
    }

    private func getArray<T: Decodable>(_ path: String, params: [String: String]) async throws -> [T] {
        guard let url = settings.restURL(path, params: params) else { throw APIError.notConfigured }
        let data = try await fetch(url: url)
        return try decode([T].self, from: data)
    }

    private func getRaw(_ path: String, params: [String: String]) async throws -> [String: Any] {
        guard let url = settings.restURL(path, params: params) else { throw APIError.notConfigured }
        let data = try await fetch(url: url)
        guard let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw APIError.decodingError(NSError(domain: "decode", code: 0))
        }
        return dict
    }

    private func fetch(url: URL) async throws -> Data {
        do {
            let (data, response) = try await session.data(from: url)
            if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
                let msg = String(data: data, encoding: .utf8) ?? "Unknown error"
                throw APIError.httpError(http.statusCode, msg)
            }
            return data
        } catch let err as APIError {
            throw err
        } catch {
            throw APIError.networkError(error)
        }
    }

    private func post(url: URL, body: [String: Any]) async throws -> Data {
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try? JSONSerialization.data(withJSONObject: body)
        do {
            let (data, response) = try await session.data(for: req)
            if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
                let msg = String(data: data, encoding: .utf8) ?? "Unknown error"
                throw APIError.httpError(http.statusCode, msg)
            }
            return data
        } catch let err as APIError {
            throw err
        } catch {
            throw APIError.networkError(error)
        }
    }

    private func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        do {
            return try JSONDecoder.netProbe.decode(type, from: data)
        } catch {
            throw APIError.decodingError(error)
        }
    }
}
