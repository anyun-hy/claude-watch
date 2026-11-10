import Foundation

@main
struct TargetDiscoveryTests {
    static func main() throws {
        func require(_ condition: Bool, _ message: String) { if !condition { fatalError(message) } }
        struct Catalog: Decodable { let revision: String; let complete: Bool }
        struct Wire: Decodable { let discovery: Catalog; let monitor: MonitorSnapshot }
        let decoder = JSONDecoder()
        let data = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
        let wire = try decoder.decode(Wire.self, from: data)
        require(wire.discovery.complete && wire.monitor.targetDiscovery?.complete == true, "accepted discovery status lost")
        require(wire.discovery.revision == wire.monitor.targetDiscovery?.revision, "sampler revision differs from accepted catalog")
        require(wire.monitor.processes.count == 3, "three supported desktop identities missing")
        for row in wire.monitor.processes {
            require(row.matchReason == "verified_bundle" && row.discoveryExplanation == "应用包身份", "dynamic installation classification lost")
            require(row.protection?.state != "protected", "discovery became network protection")
            require(!row.protectionExplanation(state: nil, executorBootId: nil, now: wire.monitor.capturedAt, live: true).hasPrefix("已保护"), "catalog is not a permit")
        }
        let pending = try decoder.decode(MonitorSnapshot.self, from: Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[2])))
        require(pending.targetDiscovery?.complete == false && !pending.targetDiscovery!.issues.isEmpty, "partial discovery hidden")
        require(pending.processes.count == 1, "known running identity disappeared with unreadable installation")
        let row = pending.processes[0]
        require(row.matchReason == "installation_pending" && row.discoveryExplanation == "已发现，安装证据待确认", "installation pending explanation lost")
        require(row.protection?.state != "protected", "unreadable installation appears protected")
        let staging = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[3]))) as! [String: Any]
        let info = staging["entry_info"] as! [String: Any]
        let request = staging["request"] as! [String: Any]
        let path = info["CWTargetBundlePath"] as! String
        require(path.contains(" & ") && path.contains("'Renamed'"), "staging fixture must exercise custom path escaping")
        let arguments = ControlledEntryLaunchBinding.arguments(target: "claude-desktop", bundlePath: path)
        require(arguments == ["launch", "--target", "claude-desktop", "--apply", "--target-bundle", path], "production wrapper dropped or split selected source")
        require(info["CWTargetExecutable"] as? String == request["target_executable"] as? String, "staged and prepared executables differ")
        require(staging["i03_ready"] as? Bool == false, "fixture cannot establish I03")
        require(ControlledEntryLaunchBinding.arguments(target: "claude-desktop", bundlePath: "") == ["launch", "--target", "claude-desktop", "--apply"], "legacy wrapper compatibility lost")
        var object = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        var monitor = object["monitor"] as! [String: Any]
        monitor.removeValue(forKey: "targetDiscovery")
        require(try decoder.decode(MonitorSnapshot.self, from: JSONSerialization.data(withJSONObject: monitor)).targetDiscovery == nil, "legacy missing status implies success")
        monitor["targetDiscovery"] = NSNull()
        require(try decoder.decode(MonitorSnapshot.self, from: JSONSerialization.data(withJSONObject: monitor)).targetDiscovery == nil, "null status implies success")
        monitor["targetDiscovery"] = ["revision": "corrupt", "complete": "yes", "issues": []] as [String: Any]
        do { _ = try decoder.decode(MonitorSnapshot.self, from: JSONSerialization.data(withJSONObject: monitor)); fatalError("corrupt discovery status silently accepted") }
        catch is DecodingError { }
        object.removeAll()
        print("TargetDiscoveryTests: production Rust catalog/monitor/staging decoded; custom source binding, pending installation, conservative compatibility and no discovery-as-protection passed")
    }
}
