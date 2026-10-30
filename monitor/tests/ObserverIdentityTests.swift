import Foundation

@main
struct ObserverIdentityTests {
    static func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
        guard condition() else {
            FileHandle.standardError.write(Data("FAIL: \(message)\n".utf8))
            exit(1)
        }
    }

    static func child() throws -> Process {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sleep")
        process.arguments = ["30"]
        try process.run()
        return process
    }

    static func stop(_ process: Process) {
        if process.isRunning { process.terminate(); process.waitUntilExit() }
    }

    static func main() throws {
        let live = try child()
        defer { stop(live) }
        let pid = live.processIdentifier

        observerIdentityMisses[pid] = 1
        let recovered = try inventory()
        let recoveredRows = recovered["processes"] as! [[String: Any]]
        let recoveredMissing = recovered["unavailable"] as! [[String: Any]]
        expect(recoveredRows.contains { ($0["pid"] as? NSNumber)?.int32Value == pid }, "transient inventory failure is rechecked")
        expect(!recoveredMissing.contains { ($0["pid"] as? NSNumber)?.int32Value == pid }, "recovered identity is not left unavailable")

        observerIdentityMisses[pid] = 2
        let unreadable = try inventory()
        let unreadableRows = unreadable["unavailable"] as! [[String: Any]]
        expect(unreadableRows.contains { ($0["pid"] as? NSNumber)?.int32Value == pid && $0["code"] as? String == "identity_unavailable" }, "unreadable live process stays unavailable")
        expect(!(unreadable["exited"] as! [Int32]).contains(pid), "unreadable live process is not treated as exited")
        observerIdentityMisses.removeValue(forKey: pid)

        let ending = try child()
        defer { stop(ending) }
        let endingPID = ending.processIdentifier
        observerIdentityMisses[endingPID] = 1
        observerAfterInventoryScan = { stop(ending) }
        let exitedInventory = try inventory()
        observerAfterInventoryScan = nil
        expect((exitedInventory["exited"] as! [Int32]).contains(endingPID), "confirmed exit during inventory is not reported as a read failure")

        guard let identity = currentIdentity(pid) else { fatalError("test child identity unavailable") }
        let request = Request(schema: 1, round_id: UUID().uuidString, targets: [identity])
        observerBeforeSocketRecheck = { target in
            if target == pid { observerIdentityMisses[pid] = 1 }
        }
        let unknown = try sockets(request)
        observerBeforeSocketRecheck = nil
        let unknownRow = (unknown["socket_samples"] as! [[String: Any]])[0]
        expect(unknownRow["code"] as? String == "identity_unavailable", "live target with unreadable identity remains unknown")
        expect(live.isRunning, "identity failure does not terminate the target")

        let wrong = Identity(pid: identity.pid, parent: identity.parent, uid: identity.uid,
                             executable: identity.executable, start_seconds: identity.start_seconds + 1,
                             start_microseconds: identity.start_microseconds, start_stamp: identity.start_stamp)
        let reused = try sockets(Request(schema: 1, round_id: UUID().uuidString, targets: [wrong]))
        expect((reused["socket_samples"] as! [[String: Any]])[0]["code"] as? String == "identity_changed", "mismatched process identity remains unconfirmed")

        observerBeforeSocketRecheck = { target in if target == pid { stop(live) } }
        let exitedSockets = try sockets(request)
        observerBeforeSocketRecheck = nil
        let exitedRow = (exitedSockets["socket_samples"] as! [[String: Any]])[0]
        expect(exitedRow["code"] as? String == "process_exited", "confirmed exit during socket scan is not misreported as identity change")
        expect(exitedRow["sockets"] == nil, "no stale sockets survive an exited target")
        print("ObserverIdentityTests: temporary owned processes only")
    }
}
