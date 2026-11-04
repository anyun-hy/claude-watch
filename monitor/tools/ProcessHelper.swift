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
    static func inventory(for product: MonitoredProduct) throws -> [AIProcessIdentity] {
        switch product {
        // A bare binary named like Claude is not a Claude install; only the
        // app bundle's own tree is eligible.
        case .claude: return try desktopInventory()
        // ChatGPT / Codex also runs as an independent CLI, which carries no
        // bundle, so the full inventory is the eligible set.
        case .openAI: return try AIProcessInventory.read()
        }
    }
    static func plan(_ product: MonitoredProduct, inventory: [AIProcessIdentity]) -> AIProcessClosePlan {
        AIProcessClosePolicy.plan(product, inventory: inventory, uid: getuid(),
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
    /// Closes one product's verified process tree and reports what is left.
    /// `allowForce` mirrors the policy decision made upstream: the engine only
    /// issues `guard-close-desktop` for a family whose policy declares force,
    /// so the helper carries no per-product rule of its own.
    static func close(_ product: MonitoredProduct, allowForce: Bool) throws -> [String: Any] {
        let label = product == .claude ? "Claude" : "ChatGPT / Codex"
        let selected = plan(product, inventory: try inventory(for: product))
        let outcome = AIProcessClosePolicy.execute(selected, lookup: AIProcessInventory.identity,
            quitApplication: { expected in
                AIProcessClosePolicy.applyToMatchingIdentity(expected, lookup: AIProcessInventory.identity) {
                    NSRunningApplication(processIdentifier: $0)?.terminate() ?? false
                }
            },
            terminate: { expected in
                AIProcessClosePolicy.applyToMatchingIdentity(expected, lookup: AIProcessInventory.identity) {
                    Darwin.kill($0, SIGTERM) == 0
                }
            })
        var forced = (requested: 0, skipped: 0, failed: 0)
        if allowForce {
            func originalNotConfirmedGone() -> Bool {
                selected.targets.contains { target in
                    switch AIProcessInventory.presence(target.pid) {
                    case .live(let actual): return target.sameProcess(as: actual)
                    case .gone: return false
                    case .unavailable: return true
                    }
                }
            }
            let graceDeadline = ProcessInfo.processInfo.systemUptime + 2
            while originalNotConfirmedGone() && ProcessInfo.processInfo.systemUptime < graceDeadline {
                Thread.sleep(forTimeInterval: 0.1)
            }
            if originalNotConfirmedGone() {
                // Never extend force authority to a new/restarted process.
                forced = AIProcessClosePolicy.forceRemaining(selected, lookup: AIProcessInventory.identity,
                    force: { expected in
                        AIProcessClosePolicy.applyToMatchingIdentity(expected, lookup: AIProcessInventory.identity) {
                            Darwin.kill($0, SIGKILL) == 0
                        }
                    })
            }
        }
        // A root disappearing must not erase an original, now-orphaned child.
        // New roots are reported, not force-signalled by this invocation.
        let until = ProcessInfo.processInfo.systemUptime + (allowForce ? 5 : 15)
        var evidence: AIProcessExitEvidence
        repeat {
            evidence = AIProcessClosePolicy.exitEvidence(selected, inventory: try inventory(for: product),
                                                         lookup: AIProcessInventory.presence)
            if evidence.complete { break }
            if ProcessInfo.processInfo.systemUptime >= until { break }
            Thread.sleep(forTimeInterval: 0.2)
        } while true
        let code = evidence.complete ? "" : (evidence.unconfirmed > 0
            ? "process_identity_unavailable" : "target_still_running")
        return ["schema": 1, "product": product == .claude ? "claude" : "openai",
                "status": evidence.complete ? "ok" : "error", "code": code,
                "message": evidence.complete ? "\(label) 已退出" : "\(label) 未确认完全退出",
                "planned": selected.targets.count, "requested": outcome.requested, "skipped": outcome.skipped, "failed": outcome.failed,
                "remaining": evidence.remaining.count, "identity_unconfirmed": evidence.unconfirmed,
                "force_requested": forced.requested, "force_skipped": forced.skipped, "force_failed": forced.failed]
    }

    /// The helper command names the supervised product the same way the
    /// policy table does: one Claude family, one ChatGPT / Codex family.
    static func product(_ name: String) -> MonitoredProduct? {
        switch name {
        case "claude": return .claude
        case "openai": return .openAI
        default: return nil
        }
    }
    static func main() {
        do {
            guard getuid() != 0 else { throw NSError(domain: "user_required", code: 1) }
            let args = Array(CommandLine.arguments.dropFirst())
            guard !args.isEmpty, args.count == 1 || args.count == 2 || args[0] == "regional-status" else {
                throw NSError(domain: "invalid_arguments", code: 1)
            }
            var result: [String: Any]
            switch args[0] {
            case "regional-status": result = try regionalStatus(Array(args.dropFirst()))
            case "inventory":
                result = ["status": "ok", "processes": try AIProcessInventory.read().map(encode)]
            // One exit routine for every supervised family: the product is a
            // command argument, and `guard-close-desktop` is only issued when
            // the family's policy declares force, so which trees may be forced
            // follows the policy table, never a helper-side product check.
            case "close-desktop", "guard-close-desktop":
                guard args.count == 2, let product = product(args[1]) else {
                    throw NSError(domain: "invalid_arguments", code: 1)
                }
                result = try close(product, allowForce: args[0] == "guard-close-desktop")
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
