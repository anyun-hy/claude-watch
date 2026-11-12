import Foundation

@main
struct ServiceStatusDecodeTests {
    static func main() throws {
        func require(_ ok: Bool, _ message: String) { if !ok { fatalError(message) } }
        func row(_ changes: [String: Any]) throws -> BackgroundServiceRow {
            var value: [String: Any] = ["id":"guard", "title":"fixture", "state":"pending", "detail":"fixture", "source":"fixture",
                "desired":true, "backend_alive":true, "sampling_state":"stale", "protection_ready":false, "execution_verified":false]
            for (key, field) in changes { value[key] = field }
            return try JSONDecoder().decode(BackgroundServiceRow.self, from: JSONSerialization.data(withJSONObject:value))
        }
        let pending = try row([:])
        require(!pending.healthy && pending.statusLabel == "运行中 · 保护待核验", "a live backend with stale evidence cannot satisfy protection readiness")
        require(pending.evidenceSummary?.contains("后台活性：已确认") == true && pending.evidenceSummary?.contains("采样：已过期") == true,
                "liveness and evidence validity remain separate")
        let ready = try row(["state":"running", "sampling_state":"complete", "protection_ready":true, "execution_verified":true])
        require(ready.healthy && ready.statusLabel == "保护就绪", "explicit current protection evidence is ready")
        let inactive = try row(["state":"inactive", "backend_alive":false, "protection_ready":true])
        require(!inactive.healthy && inactive.statusLabel == "已停用", "a contradictory ready flag cannot make an inactive service healthy")
        let disabledAlive = try row(["state":"inactive", "backend_alive":true, "desired":false])
        require(disabledAlive.statusLabel == "已停用" && disabledAlive.evidenceSummary?.contains("保护：停用") == true,
                "a live sampler does not override a disabled protection setting")
        let original = try row(["id":"original", "state":"scheduled", "execution_verified":true,
                                "health_basis":"root_execution_receipt", "last_success_at":1000])
        require(original.healthy && original.statusLabel == "独立运行" && original.last_success_at == 1000,
                "a read-only original-service success receipt is independently healthy")
        let registered = try row(["id":"original", "state":"scheduled", "health_basis":"registered_only"])
        require(!registered.healthy && registered.statusLabel == "已加载（执行待确认）", "registration alone is not an execution receipt")
        let updater = try row(["id":"updater", "state":"running", "execution_verified":true])
        require(updater.statusLabel == "运行中", "an unrelated service is not labeled disconnect protection ready")
        print("ServiceStatusDecodeTests: 8 fixture assertions passed")
        guard (2...3).contains(CommandLine.arguments.count) else { fatalError("service-status JSON path required") }
        let expected = CommandLine.arguments.count == 3 ? CommandLine.arguments[2] : nil
        let bytes = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
        let receipt = try JSONDecoder().decode(BackgroundServiceReceipt.self, from: bytes)
        if let session = receipt.session_guard {
            guard ["safe", "active", "idle", "disabled", "unknown", "pending", "pending_verification", "risk", "locked", "missing"].contains(session.state) else {
                fatalError("unknown session state")
            }
            if ["risk", "locked"].contains(session.state) {
                guard session.reason?.code.isEmpty == false, session.reason?.detail.isEmpty == false else {
                    fatalError("risk/locked receipt must explain its reason")
                }
            }
            if let baseline = session.baseline, baseline.ip?.isEmpty != false {
                fatalError("baseline must contain an IP when present")
            }
        } else {
            require(receipt.backend_alive != nil && receipt.protection_ready != nil,
                    "a service-only receipt must provide explicit liveness and protection evidence")
        }
        if receipt.backend_alive != nil && receipt.protection_ready != nil {
            if receipt.services.first(where: { $0.id == "guard" })?.state == "inactive" {
                require(receipt.evidenceSummary.contains("保护：停用"), "real Rust disabled guard is not described as awaiting readiness")
            }
            if receipt.backend_alive == true && receipt.backend_sampling_state == "stale" && receipt.protection_ready == false {
                let guardRow = receipt.services.first { $0.id == "guard" }!
                require(!guardRow.healthy && guardRow.statusLabel == "运行中 · 保护待核验", "real Rust stale sampling wire stays unready")
                require(receipt.evidenceSummary.contains("后台活性：已确认") && receipt.evidenceSummary.contains("监控采样：已过期"),
                        "real Rust liveness and sampling fields remain distinct")
            }
            if let original = receipt.services.first(where: { $0.id == "original" }), original.execution_verified == true {
                require(original.healthy && original.statusLabel == "独立运行" && original.last_success_at != nil,
                        "real Rust original-service receipt is independently healthy")
            }
        }
        if expected == "live-stale-unready" {
            require(receipt.backend_alive == true && receipt.backend_sampling_state == "stale" && receipt.protection_ready == false,
                    "Rust stale-unready case must retain all three distinct truth values")
            require(receipt.services.first { $0.id == "guard" }?.healthy == false, "Rust stale guard cannot pass the ready gate")
        } else if expected == "original-fresh" {
            let original = receipt.services.first { $0.id == "original" }
            require(original?.health_basis == "root_execution_receipt" && original?.healthy == true && original?.statusLabel == "独立运行",
                    "Rust root-owned success receipt must reach the independent original-service presentation")
        }
        print("ServiceStatusDecodeTests: production service-status decoded")
    }
}
