import SwiftUI

// MARK: - Palette

extension Color {
    static let npBackground  = Color(red: 0.08, green: 0.08, blue: 0.10)
    static let npPanel       = Color(red: 0.12, green: 0.12, blue: 0.16)
    static let npCard        = Color(red: 0.15, green: 0.15, blue: 0.20)
    static let npBorder      = Color(white: 0.22)

    static let npCyan        = Color(red: 0.00, green: 0.85, blue: 1.00)
    static let npGreen       = Color(red: 0.18, green: 0.85, blue: 0.40)
    static let npYellow      = Color(red: 1.00, green: 0.85, blue: 0.00)
    static let npOrange      = Color(red: 1.00, green: 0.50, blue: 0.10)
    static let npRed         = Color(red: 1.00, green: 0.27, blue: 0.27)

    static let npFgBright    = Color.white
    static let npFgDim       = Color(white: 0.55)
    static let npFgMid       = Color(white: 0.75)
}

// MARK: - RTT colour helper

extension Double {
    /// Colour-code a millisecond RTT value the same way the desktop app does.
    var rttColor: Color {
        guard self >= 0 else { return .npFgDim }
        if self < 50  { return .npGreen }
        if self < 150 { return .npYellow }
        if self < 300 { return .npOrange }
        return .npRed
    }
}

// MARK: - Reusable modifiers

struct CardStyle: ViewModifier {
    func body(content: Content) -> some View {
        content
            .background(Color.npCard)
            .clipShape(RoundedRectangle(cornerRadius: 10))
            .overlay(
                RoundedRectangle(cornerRadius: 10)
                    .stroke(Color.npBorder, lineWidth: 0.5)
            )
    }
}

extension View {
    func cardStyle() -> some View { modifier(CardStyle()) }

    func npLabel() -> some View {
        self.font(.system(.caption, design: .monospaced))
            .foregroundStyle(Color.npFgDim)
            .textCase(.uppercase)
    }
}

// MARK: - Stat chip

struct StatChip: View {
    let label: String
    let value: String
    var color: Color = .npCyan

    var body: some View {
        VStack(spacing: 2) {
            Text(value)
                .font(.system(.callout, design: .monospaced).weight(.semibold))
                .foregroundStyle(color)
            Text(label)
                .npLabel()
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .cardStyle()
    }
}

// MARK: - Section header

struct SectionHeader: View {
    let title: String
    var body: some View {
        Text(title)
            .npLabel()
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal)
            .padding(.top, 8)
    }
}

// MARK: - Status badge

struct StatusBadge: View {
    enum State { case idle, running, done, error }
    let state: State

    private var label: String {
        switch state {
        case .idle:    return "IDLE"
        case .running: return "RUNNING"
        case .done:    return "DONE"
        case .error:   return "ERROR"
        }
    }
    private var color: Color {
        switch state {
        case .idle:    return .npFgDim
        case .running: return .npCyan
        case .done:    return .npGreen
        case .error:   return .npRed
        }
    }

    var body: some View {
        HStack(spacing: 4) {
            Circle()
                .fill(color)
                .frame(width: 6, height: 6)
                .opacity(state == .running ? 1 : 0.8)
            Text(label)
                .font(.system(.caption2, design: .monospaced).weight(.semibold))
                .foregroundStyle(color)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(color.opacity(0.12))
        .clipShape(Capsule())
    }
}

// MARK: - Host input bar

struct HostBar: View {
    let placeholder: String
    @Binding var text: String
    let isRunning: Bool
    let onStart: () -> Void
    let onStop: () -> Void

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "network")
                .foregroundStyle(Color.npFgDim)
            TextField(placeholder, text: $text)
                .font(.system(.body, design: .monospaced))
                .foregroundStyle(Color.npFgBright)
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
                .keyboardType(.URL)
                .submitLabel(.go)
                .onSubmit { isRunning ? onStop() : onStart() }
            Spacer()
            Button(action: isRunning ? onStop : onStart) {
                Label(isRunning ? "Stop" : "Start",
                      systemImage: isRunning ? "stop.fill" : "play.fill")
                    .font(.system(.subheadline, design: .rounded).weight(.semibold))
                    .foregroundStyle(isRunning ? Color.npRed : Color.npCyan)
            }
            .buttonStyle(.plain)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .cardStyle()
        .padding(.horizontal)
    }
}

// MARK: - Empty state

struct EmptyState: View {
    let icon: String
    let message: String

    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: icon)
                .font(.system(size: 40))
                .foregroundStyle(Color.npFgDim)
            Text(message)
                .font(.subheadline)
                .foregroundStyle(Color.npFgDim)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - Copy button

struct CopyButton: View {
    let text: String
    @State private var copied = false

    var body: some View {
        Button {
            UIPasteboard.general.string = text
            copied = true
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
        } label: {
            Image(systemName: copied ? "checkmark" : "doc.on.doc")
                .font(.caption)
                .foregroundStyle(copied ? Color.npGreen : Color.npFgDim)
        }
        .buttonStyle(.plain)
    }
}
