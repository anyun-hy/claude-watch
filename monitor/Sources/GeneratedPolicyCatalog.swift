// Generated from crates/watch-core/src/policy.rs.
// Do not edit. Run: python3 tools/generate-ai-policy-swift.py --write
// The Rust catalog owns keys, selectable actions, and fallback policy.
struct GeneratedPolicyCriterion {
    let id: String
    let fallback: String
}
struct GeneratedPolicyFamily {
    let id: String
    let keyPrefix: String
    let criteria: [GeneratedPolicyCriterion]
    let actions: [String]
    let defaultAction: String
}
enum GeneratedPolicyCatalog {
    static let families: [GeneratedPolicyFamily] = [
        .init(
            id: "claude", keyPrefix: "claude",
            criteria: [
                .init(id: "ip", fallback: "close"),
                .init(id: "cn", fallback: "close"),
                .init(id: "dns", fallback: "close"),
                .init(id: "webrtc", fallback: "close"),
                .init(id: "session", fallback: "close"),
            ],
            actions: ["force", "close", "warn"],
            defaultAction: "close"
        ),
        .init(
            id: "openai", keyPrefix: "gpt",
            criteria: [
                .init(id: "ip", fallback: "close"),
                .init(id: "cn", fallback: "close"),
                .init(id: "dns", fallback: "close"),
                .init(id: "webrtc", fallback: "close"),
                .init(id: "session", fallback: "close"),
            ],
            actions: ["force", "close", "warn"],
            defaultAction: "close"
        ),
    ]
}
