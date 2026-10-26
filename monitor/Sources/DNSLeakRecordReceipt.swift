import Foundation

/// A narrow response from dns-leak-record.  Replacing only this row preserves
/// the timestamps and evidence of unrelated environment checks.
struct DNSLeakRecordReceipt: Decodable {
    var dns_row: EnvironmentCheckRow?
    var source_notices: [EnvironmentSourceNotice]?
    var context_id: String?
    var sampled_at: Double?
}

struct DNSLeakRecordInput: Encodable {
    let probe: LeakProbeResult
    let expected_context: String
}

struct WebRTCRiskRecordInput: Encodable {
    let probe: LeakProbeResult
    let expected_context: String
}
