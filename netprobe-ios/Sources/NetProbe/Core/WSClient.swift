import Foundation

// MARK: - WSMessage

/// A decoded message from the server WebSocket stream.
enum WSMessage {
    case result(Data)       // raw JSON Data of the "data" field
    case arrayUpdate(Data)  // when "data" is an array (MTR snapshot)
    case done
    case error(String)
}

// MARK: - WSClient

/// Generic WebSocket streaming client.
///
/// Usage:
/// ```swift
/// let stream = WSClient.stream(url: url)
/// for await message in stream {
///     switch message {
///     case .result(let data): ...
///     case .done: break
///     }
/// }
/// ```
///
/// Cancel the Task that iterates the stream to disconnect.
final class WSClient {

    private init() {}

    // MARK: - Public streaming API

    static func stream(url: URL) -> AsyncStream<WSMessage> {
        AsyncStream(bufferingPolicy: .bufferingNewest(256)) { continuation in
            let session  = URLSession(configuration: .default)
            let task     = session.webSocketTask(with: url)

            // Kick off receive loop
            func receive() {
                task.receive { result in
                    switch result {
                    case .failure(let err):
                        continuation.yield(.error(err.localizedDescription))
                        continuation.finish()

                    case .success(let msg):
                        switch msg {
                        case .string(let text):
                            process(text: text, continuation: continuation)
                        case .data(let data):
                            if let text = String(data: data, encoding: .utf8) {
                                process(text: text, continuation: continuation)
                            }
                        @unknown default:
                            break
                        }

                        // Only continue if stream is still open
                        if !Task.isCancelled {
                            receive()
                        }
                    }
                }
            }

            task.resume()
            receive()

            // Tear down when the Task owning this stream is cancelled
            continuation.onTermination = { _ in
                task.cancel(with: .goingAway, reason: nil)
            }
        }
    }

    // MARK: - Send a command (fire and forget)

    static func send(task: URLSessionWebSocketTask, dict: [String: String]) {
        guard let data = try? JSONSerialization.data(withJSONObject: dict),
              let text = String(data: data, encoding: .utf8) else { return }
        task.send(.string(text)) { _ in }
    }

    // MARK: - Private

    private static func process(
        text: String,
        continuation: AsyncStream<WSMessage>.Continuation
    ) {
        guard let raw = text.data(using: .utf8),
              let top = try? JSONSerialization.jsonObject(with: raw) as? [String: Any],
              let type = top["type"] as? String
        else { return }

        switch type {
        case "done":
            continuation.yield(.done)
            continuation.finish()

        case "error":
            let msg = (top["data"] as? String) ?? "Unknown server error"
            continuation.yield(.error(msg))
            continuation.finish()

        default:
            // Re-encode the "data" field for type-safe decoding in callers
            guard let dataPayload = top["data"] else { return }
            if let encoded = try? JSONSerialization.data(withJSONObject: dataPayload) {
                if dataPayload is [Any] {
                    continuation.yield(.arrayUpdate(encoded))
                } else {
                    continuation.yield(.result(encoded))
                }
            }
        }
    }
}

// MARK: - Convenience decode helper used by ViewModels

extension Data {
    func decode<T: Decodable>(_ type: T.Type) -> T? {
        try? JSONDecoder.netProbe.decode(type, from: self)
    }
}
