import Foundation

// MARK: - JSON decoder shared config

extension JSONDecoder {
    static let netProbe: JSONDecoder = {
        let d = JSONDecoder()
        d.keyDecodingStrategy = .convertFromSnakeCase
        return d
    }()
}

// MARK: - WebSocket envelope

struct WSEnvelope: Decodable {
    let type: String        // "result" | "hop" | "update" | "done" | "error"
    let data: WSPayload?

    enum WSPayload: Decodable {
        case dict([String: AnyCodable])
        case array([AnyCodable])

        init(from decoder: Decoder) throws {
            let c = try decoder.singleValueContainer()
            if let arr = try? c.decode([AnyCodable].self) {
                self = .array(arr)
            } else {
                self = .dict((try? c.decode([String: AnyCodable].self)) ?? [:])
            }
        }
    }
}

// MARK: - AnyCodable helper (handles mixed JSON)

struct AnyCodable: Codable {
    let value: Any

    init(_ value: Any) { self.value = value }

    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if let v = try? c.decode(Bool.self)             { value = v; return }
        if let v = try? c.decode(Int.self)              { value = v; return }
        if let v = try? c.decode(Double.self)           { value = v; return }
        if let v = try? c.decode(String.self)           { value = v; return }
        if let v = try? c.decode([AnyCodable].self)     { value = v.map(\.value); return }
        if let v = try? c.decode([String: AnyCodable].self) {
            value = v.mapValues(\.value); return
        }
        value = NSNull()
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch value {
        case let v as Bool:   try c.encode(v)
        case let v as Int:    try c.encode(v)
        case let v as Double: try c.encode(v)
        case let v as String: try c.encode(v)
        default:              try c.encodeNil()
        }
    }
}

// MARK: - Ping

struct PingResult: Codable, Identifiable {
    var id = UUID()
    let host: String
    let ip: String
    let seq: Int
    let rttMs: Double     // -1 = timeout
    let ttl: Int
    let timestamp: Double

    var isTimeout: Bool { rttMs < 0 }
    var rttText: String { isTimeout ? "—" : String(format: "%.1f ms", rttMs) }

    enum CodingKeys: String, CodingKey {
        case host, ip, seq, ttl, timestamp
        case rttMs = "rtt_ms"
    }
}

// MARK: - Traceroute / MTR

struct HopResult: Codable, Identifiable {
    var id = UUID()
    let hop: Int
    let ip: String
    let hostname: String
    let rtts: [Double]
    let lossPct: Double

    var rttText: String {
        rtts.map { $0 < 0 ? "*" : String(format: "%.1f", $0) }.joined(separator: " / ")
    }
    var avgRtt: Double? {
        let valid = rtts.filter { $0 >= 0 }
        return valid.isEmpty ? nil : valid.reduce(0, +) / Double(valid.count)
    }

    enum CodingKeys: String, CodingKey {
        case hop, ip, hostname, rtts
        case lossPct = "loss_pct"
    }
}

struct MTRRow: Codable, Identifiable {
    var id = UUID()
    let hop: Int
    let ip: String
    let hostname: String
    let sent: Int
    let lossPct: Double
    let lastMs: Double
    let avgMs: Double
    let bestMs: Double
    let worstMs: Double
    let stdevMs: Double

    enum CodingKeys: String, CodingKey {
        case hop, ip, hostname, sent
        case lossPct = "loss_pct"
        case lastMs  = "last_ms"
        case avgMs   = "avg_ms"
        case bestMs  = "best_ms"
        case worstMs = "worst_ms"
        case stdevMs = "stdev_ms"
    }
}

// MARK: - Port Scan

struct PortResult: Codable, Identifiable {
    var id = UUID()
    let host: String
    let port: Int
    let state: String    // "open" | "closed" | "filtered" | "open|filtered"
    let service: String
    let banner: String
    let rttMs: Double

    var isOpen: Bool { state == "open" || state == "open|filtered" }

    enum CodingKeys: String, CodingKey {
        case host, port, state, service, banner
        case rttMs = "rtt_ms"
    }
}

// MARK: - DNS

struct DNSResult: Codable, Identifiable {
    var id = UUID()
    let query: String
    let recordType: String
    let answers: [String]
    let nameserver: String
    let rttMs: Double
    let error: String

    enum CodingKeys: String, CodingKey {
        case query, answers, nameserver, error
        case recordType = "record_type"
        case rttMs      = "rtt_ms"
    }
}

struct DoHResult: Codable {
    let google: [String]
    let cloudflare: [String]
    let error: String?
}

// MARK: - SSL

struct SSLInfo: Codable {
    let host: String
    let port: Int
    let subjectCn: String
    let subject: String
    let issuer: String
    let version: String
    let cipher: String
    let notBefore: String
    let notAfter: String
    let san: [String]
    let daysRemaining: Int
    let expired: Bool
    let verified: Bool
    let error: String

    enum CodingKeys: String, CodingKey {
        case host, port, subject, issuer, version, cipher, san, expired, verified, error
        case subjectCn     = "subject_cn"
        case notBefore     = "not_before"
        case notAfter      = "not_after"
        case daysRemaining = "days_remaining"
    }
}

// MARK: - HTTP Probe

struct HTTPResult: Codable {
    let url: String
    let finalUrl: String
    let statusCode: Int
    let ttfbMs: Double
    let totalMs: Double
    let redirectChain: [String]
    let headers: [String: String]
    let contentLength: Int
    let server: String
    let error: String

    enum CodingKeys: String, CodingKey {
        case url, headers, error, server
        case finalUrl      = "final_url"
        case statusCode    = "status_code"
        case ttfbMs        = "ttfb_ms"
        case totalMs       = "total_ms"
        case redirectChain = "redirect_chain"
        case contentLength = "content_length"
    }
}

// MARK: - WHOIS

struct WHOISResult: Codable {
    let target: String
    let raw: String
}

// MARK: - GeoIP

struct GeoIPResult: Codable {
    let ip: String
    let country: String
    let countryCode: String
    let city: String
    let region: String
    let org: String
    let lat: Double
    let lon: Double
    let error: String

    enum CodingKeys: String, CodingKey {
        case ip, country, city, region, org, lat, lon, error
        case countryCode = "country_code"
    }
}

// MARK: - Netstat

struct NetstatEntry: Codable, Identifiable {
    var id = UUID()
    let proto: String
    let localAddr: String
    let localPort: Int
    let remoteAddr: String
    let remotePort: Int
    let state: String
    let pid: Int
    let process: String

    var localEndpoint:  String { localPort  > 0 ? "\(localAddr):\(localPort)"  : localAddr  }
    var remoteEndpoint: String { remotePort > 0 ? "\(remoteAddr):\(remotePort)" : remoteAddr }

    enum CodingKeys: String, CodingKey {
        case proto, state, pid, process
        case localAddr  = "local_addr"
        case localPort  = "local_port"
        case remoteAddr = "remote_addr"
        case remotePort = "remote_port"
    }
}

// MARK: - ARP

struct ARPEntry: Codable, Identifiable {
    var id = UUID()
    let ip: String
    let mac: String
    let hostname: String
    let vendor: String
    let interface: String
}

// MARK: - Wake-on-LAN

struct WoLResponse: Codable {
    let success: Bool
    let mac: String
    let broadcast: String
    let port: Int
}

// MARK: - Ping sweep

struct SweepResult: Codable {
    let network: String
    let live: [String]
    let count: Int
}

// MARK: - Health

struct HealthResponse: Codable {
    let status: String
    let version: String
}
