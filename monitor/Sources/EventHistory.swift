import Foundation

struct EventHistoryRequest: Encodable, Sendable {
    let filter, query: String
    let offset: Int
}

struct EventHistoryResponse: Decodable, Sendable {
    let status: String
    let events: [Event]
    let total, nextOffset: Int
    let hasMore: Bool
    let invalidRecords: Int
}

enum EventHistoryRead: Sendable {
    case success(EventHistoryResponse)
    case failure
}

enum EventHistoryRunner {
    static func read(_ request: EventHistoryRequest) -> EventHistoryRead {
        do {
            let input = try JSONEncoder().encode(request)
            // Search text goes through stdin, not process arguments or a log.
            let data = try SwitcherCommandRunner.run(["event-history"], input: input)
            let response = try JSONDecoder().decode(EventHistoryResponse.self, from: data)
            guard response.status == "ok" else { return .failure }
            return .success(response)
        } catch {
            return .failure
        }
    }
}

enum DiagnosticExportRunner {
    static func write(to path: String) -> Bool {
        do {
            let data = try SwitcherCommandRunner.run(["diagnostic-export", "--export", path])
            let response = try JSONSerialization.jsonObject(with: data) as? [String: Any]
            return response?["status"] as? String == "ok"
        } catch { return false }
    }
}
