import Foundation

/// Only these bounded fields are passed to the local diagnostic writer.
struct GuardDiagnosticPhase: Codable, Sendable {
    let decision, backend_reason: String
    let backend_healthy, backend_native: Bool?
    let enabled, guard_enabled: Bool
    let sampled_at: Double
    let backend_heartbeat_status, guard_heartbeat_status: String
    let guard_heartbeat_code: String?
    let backend_heartbeat_age_seconds, guard_heartbeat_age_seconds: Double?
    let policy_matches: Bool?
}
struct GuardDiagnosticRound: Codable, Sendable {
    let observation_id: String
    let before, after: GuardDiagnosticPhase
}
private struct GuardDiagnosticEnvelope: Decodable {
    let guard_diagnostics: GuardDiagnosticRound?
}
enum GuardDiagnosticLogger {
    static func input(from response: Data) -> Data? {
        guard let envelope = try? JSONDecoder().decode(GuardDiagnosticEnvelope.self, from: response),
              let round = envelope.guard_diagnostics else { return nil }
        return try? JSONEncoder().encode(round)
    }
    static func submit(from response: Data) {
        guard let data = input(from: response) else { return }
        DiagnosticLogRunner.submit(data, command: "guard-diagnostic")
    }
}
