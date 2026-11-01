import AppKit
import Darwin
import Foundation

// The guard's explicitly selected IP-risk path may force only verified identities.
enum MonitoredProduct: Equatable, Sendable { case claude, openAI }

@main
struct WatchProcessHelper {
    static func desktopInventory() throws -> [AIProcessIdentity] {
        var inventory = try AIProcessInventory.read()
        for i in inventory.indices {
            if inventory[i].rootProduct == .claude && !inventory[i].executable.contains(".app/Contents/") {
                inventory[i].rootProduct = nil
            }
        }
        return inventory
    }
    static func plan(_ inventory: [AIProcessIdentity]) -> AIProcessClosePlan {
        AIProcessClosePolicy.plan(.claude, inventory: inventory, uid: getuid(),
                                  protected: AIProcessInventory.protectedIDs(in: inventory, backendPID: nil))
    }
    static func encode(_ p: AIProcessIdentity) -> [String: Any] {
        ["pid": p.pid, "parent": p.parent, "uid": p.uid, "executable": p.executable,
         "start_seconds": p.startSeconds, "start_microseconds": p.startMicroseconds,
         "desktop_main": p.desktopMain]
    }
    static func regionalStatus(_ references: [String]) throws -> [String: Any] {
        guard references.count <= 32, references.allSatisfy({
            $0.range(of: "^[a-z]{2,3}_[A-Z]{2}$", options: .regularExpression) != nil
        }) else { throw NSError(domain: "invalid_locale_reference", code: 1) }
        let sample = Date(timeIntervalSince1970: 1792713600)
        let styles: [(String, DateFormatter.Style)] = [("short", .short), ("medium", .medium), ("long", .long)]
        func formats(_ locale: Locale?) -> [String: String] {
            var value: [String: String] = [:]
            for (name, style) in styles {
                let formatter = DateFormatter()
                if let locale { formatter.locale = locale }
                formatter.dateStyle = style; formatter.timeStyle = .none
                value[name] = formatter.dateFormat ?? ""
            }
            return value
        }
        let actual = DateFormatter(); actual.dateStyle = .short; actual.timeStyle = .none
        var referencePatterns: [String: [String: String]] = [:], samples: [String: String] = [:]
        for identifier in Set(references) {
            referencePatterns[identifier] = formats(Locale(identifier: identifier))
            let formatter = DateFormatter(); formatter.locale = Locale(identifier: identifier)
            formatter.dateStyle = .short; formatter.timeStyle = .none
            samples[identifier] = formatter.string(from: sample)
        }
        let preferences = UserDefaults.standard.persistentDomain(forName: UserDefaults.globalDomain) ?? [:]
        return ["status": "ok", "regional": ["state": "available",
            "configured_locale": preferences["AppleLocale"] as? String ?? "",
            "effective_locale": Locale.current.identifier, "patterns": formats(nil),
            "short_sample": actual.string(from: sample), "reference_patterns": referencePatterns,
            "reference_samples": samples, "has_custom_formats": preferences["AppleICUDateFormatStrings"] != nil]]
    }
    static func main() {
        do {
            guard getuid() != 0 else { throw NSError(domain: "user_required", code: 1) }
            let args = Array(CommandLine.arguments.dropFirst())
            guard !args.isEmpty, args.count == 1 || args[0] == "regional-status" else {
                throw NSError(domain: "invalid_arguments", code: 1)
            }
            var result: [String: Any]
            switch args[0] {
            case "regional-status": result = try regionalStatus(Array(args.dropFirst()))
            case "inventory":
                result = ["status": "ok", "processes": try AIProcessInventory.read().map(encode)]
            case "desktop-status":
                result = ["status": "ok", "processes": plan(try desktopInventory()).targets.map(encode)]
            case "close-desktop", "guard-close-desktop":
                let allowForce = args[0] == "guard-close-desktop"
                let selected = plan(try desktopInventory())
                let outcome = AIProcessClosePolicy.execute(selected, lookup: AIProcessInventory.identity,
                    quitApplication: { NSRunningApplication(processIdentifier: $0)?.terminate() ?? false },
                    terminate: { Darwin.kill($0, SIGTERM) == 0 })
                var remaining = selected.targets
                var forced = (requested: 0, skipped: 0, failed: 0)
                if allowForce {
                    func originalStillRunning() -> Bool {
                        selected.targets.contains { target in
                            guard let live = AIProcessInventory.identity(target.pid) else { return false }
                            return target.sameProcess(as: live)
                        }
                    }
                    let graceDeadline = ProcessInfo.processInfo.systemUptime + 2
                    while originalStillRunning() && ProcessInfo.processInfo.systemUptime < graceDeadline {
                        Thread.sleep(forTimeInterval: 0.1)
                    }
                    if originalStillRunning() {
                        forced = AIProcessClosePolicy.forceRemaining(selected, lookup: AIProcessInventory.identity,
                            force: { Darwin.kill($0, SIGKILL) == 0 })
                    }
                    let forceDeadline = ProcessInfo.processInfo.systemUptime + 5
                    while originalStillRunning() && ProcessInfo.processInfo.systemUptime < forceDeadline {
                        Thread.sleep(forTimeInterval: 0.1)
                    }
                    // Re-scan the full tree for processes started during exit;
                    // only the original verified plan was eligible for force.
                    remaining = plan(try desktopInventory()).targets
                } else {
                    let until = ProcessInfo.processInfo.systemUptime + 15
                    repeat {
                        remaining = plan(try desktopInventory()).targets
                        if remaining.isEmpty { break }
                        Thread.sleep(forTimeInterval: 0.2)
                    } while ProcessInfo.processInfo.systemUptime < until
                }
                result = ["status": remaining.isEmpty ? "ok" : "error",
                          "code": remaining.isEmpty ? "" : "claude_still_running",
                          "message": remaining.isEmpty ? "Claude Desktop 已退出" : "Claude 未完全退出，禁止替换数据",
                          "requested": outcome.requested, "remaining": remaining.count,
                          "force_requested": forced.requested, "force_skipped": forced.skipped, "force_failed": forced.failed]
            default: throw NSError(domain: "invalid_action", code: 1)
            }
            let data = try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
            print(String(decoding: data, as: UTF8.self))
        } catch {
            print(#"{"status":"error","code":"process_identity_unavailable","message":"无法确认进程身份，未执行后续数据操作"}"#)
            exit(4)
        }
    }
}
