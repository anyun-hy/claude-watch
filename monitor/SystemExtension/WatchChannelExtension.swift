import Foundation
import NetworkExtension
import os.log
import Darwin

/// Production NetworkExtension Transparent Proxy & Flow Gate.
///
/// Implements system-level network takeover for managed AI applications (Claude, ChatGPT/Codex).
/// Critical invariants enforced:
/// 1. Covers TCP, UDP/QUIC, IPv6, and DNS flows.
/// 2. When an AI flow is unverified, revoked, or the lease expired, `handleNewFlow` returns `true`
///    and immediately closes the flow with `ECONNABORTED`. Returning `false` on macOS is strictly
///    forbidden as it instructs the kernel not to intercept and causes direct leak bypass!
/// 3. Loopback is NOT exempted for managed AI applications: attempts to connect directly to
///    local proxy ports (e.g., 7890) without going through the gateway are strictly intercepted.
/// 4. Forwarded flows are directed through the verified local proxy listener using bidirectional pumping.
/// 5. Handshake parses complete HTTP status line and forwards any remaining payload without loss.
/// 6. Receipts are bound with policy_version, command_seq, permit_generation, and epoch timestamp.
@available(macOS 11.0, *)
@main
open class WatchChannelExtension: NETransparentProxyProvider {
    public static func main() {
        autoreleasepool {
            NEProvider.startSystemExtensionMode()
        }
    }

    private let logger = Logger(subsystem: "io.local.watchpanel.extension", category: "FlowGate")

    private let stateLock = NSLock()
    private let executorBootID = UUID().uuidString
    private var isInterceptionActive: Bool = false
    private var isDirectFallbackBlocked: Bool = false
    private var localProxyPort: UInt16 = 7890
    private var localProxyHost: String = "127.0.0.1"
    private var currentPolicyVersion: String = ""
    private var currentCommandSeq: UInt64 = 0
    private var providerBootEpochSeconds: TimeInterval = 0
    private var currentPermitGeneration: UInt64 = 0
    private var activeLeaseDeadlineEpochSeconds: Int64 = 0
    private var managedPids: Set<UInt32> = []
    private var allowedPids: Set<UInt32> = []
    private var isPermitted: Bool = false
    private var extensionSecret: String = ""

    // Active flow tracking for immediate cutoff on revocation or lease expiry
    private struct ActiveFlowRecord {
        let flow: NEAppProxyTCPFlow
        let connection: NWTCPConnection
        var isClosing: Bool = false
        var closeRequestedAt: Date? = nil
    }
    private var activeFlows: [UUID: ActiveFlowRecord] = [:]
    private var totalBlockedFlows: UInt64 = 0
    private var totalForwardedFlows: UInt64 = 0
    private var leaseWatchdogTimer: DispatchSourceTimer?
    private var commandPollTimer: DispatchSourceTimer?
    private var drainCheckTimer: DispatchSourceTimer?
    private var heartbeatTimer: DispatchSourceTimer?
    private var lastCommandFileMtime: Date = .distantPast

    /// Resolves the unified state directory shared between the Rust daemon and this system extension.
    /// Does NOT rely on `FileManager.default.homeDirectoryForCurrentUser` which returns a sandbox container path in system extensions!
    private func resolveSharedStateDir() -> URL {
        let sharedDir = URL(fileURLWithPath: "/Users/Shared/ClaudeWatch/state")
        if FileManager.default.fileExists(atPath: sharedDir.path) {
            return sharedDir
        }
        if let consoleUser = getConsoleUserName(), !consoleUser.isEmpty {
            let userDir = URL(fileURLWithPath: "/Users/\(consoleUser)/Library/Application Support/ClaudeWatch/state")
            if FileManager.default.fileExists(atPath: userDir.path) {
                return userDir
            }
        }
        try? FileManager.default.createDirectory(at: sharedDir, withIntermediateDirectories: true, attributes: [
            .posixPermissions: 0o700
        ])
        return sharedDir
    }

    private func getConsoleUserName() -> String? {
        var statBuf = stat()
        if stat("/dev/console", &statBuf) == 0 {
            if let pw = getpwuid(statBuf.st_uid) {
                return String(cString: pw.pointee.pw_name)
            }
        }
        return nil
    }

    private func atomicWrite(data: Data, to targetUrl: URL) {
        let tmpUrl = targetUrl.appendingPathExtension("tmp.\(UUID().uuidString)")
        do {
            try data.write(to: tmpUrl, options: .atomic)
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tmpUrl.path)
            _ = rename(tmpUrl.path, targetUrl.path)
        } catch {
            logger.error("Failed atomic write to \(targetUrl.path): \(error.localizedDescription)")
        }
    }

    /// Well-known domain suffixes for AI API endpoints that must NEVER be bypassed to direct public network.
    private static let managedAiDomainKeywords: [String] = [
        "anthropic.com",
        "claude.ai",
        "openai.com",
        "chatgpt.com",
        "oaistatic.com",
        "oaiusercontent.com",
        "cursor.sh",
        "cursorapi.com"
    ]

    /// Helper to enforce strict monotonic progression for permit generations and command sequences.
    /// Rejects stale, out-of-order, or replayed commands from overwriting current revocation/permit states.
    private func isCommandNewerLocked(permitGen: UInt64, cmdSeq: UInt64) -> Bool {
        return cmdSeq > currentCommandSeq && permitGen >= currentPermitGeneration
    }

    open override func startProxy(options: [String: Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        logger.info("WatchChannelExtension startProxy requested")
        stateLock.lock()
        providerBootEpochSeconds = Date().timeIntervalSince1970
        isInterceptionActive = true
        isDirectFallbackBlocked = true
        if let opts = options {
            if let port = opts["local_proxy_port"] as? UInt16 {
                localProxyPort = port
            }
            if let host = opts["local_proxy_host"] as? String {
                localProxyHost = host
            }
            if let policyVer = opts["policy_version"] as? String {
                currentPolicyVersion = policyVer
            }
            if let secret = opts["extension_secret"] as? String {
                extensionSecret = secret
            }
        }
        let stateDir = resolveSharedStateDir()
        let secretFile = stateDir.appendingPathComponent(".extension-secret")
        if let secretData = try? Data(contentsOf: secretFile),
           let secretStr = String(data: secretData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
           !secretStr.isEmpty {
            extensionSecret = secretStr
        }
        stateLock.unlock()

        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: localProxyHost)
        let anyNetworkRule = NENetworkRule(
            remoteNetwork: nil,
            remotePrefix: 0,
            localNetwork: nil,
            localPrefix: 0,
            protocol: .any,
            direction: .outbound
        )
        settings.includedNetworkRules = [anyNetworkRule]

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                self.logger.error("Failed to set tunnel network settings: \(error.localizedDescription)")
                self.stateLock.lock()
                self.isInterceptionActive = false
                self.isPermitted = false
                self.writeSystemExtensionReceiptLocked(
                    status: "activation_failed", reason: "set_tunnel_network_settings"
                )
                self.stateLock.unlock()
                completionHandler(error)
                return
            }
            self.logger.info("WatchChannelExtension transparent proxy network settings active")
            self.startLeaseWatchdog()
            self.startCommandFilePolling()
            self.startHeartbeatTimer()
            completionHandler(nil)
        }
    }

    open override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        logger.notice("WatchChannelExtension stopProxy requested, reason: \(reason.rawValue)")
        stateLock.lock()
        isInterceptionActive = false
        isPermitted = false
        activeLeaseDeadlineEpochSeconds = 0
        terminateAllActiveFlowsLocked(reason: "stop_proxy_\(reason.rawValue)")
        writeSystemExtensionReceiptLocked(status: "stopped_unverified", reason: "stop_proxy")
        stateLock.unlock()
        stopLeaseWatchdog()
        stopCommandFilePolling()
        stopDrainCheck()
        stopHeartbeatTimer()
        completionHandler()
    }

    private func startLeaseWatchdog() {
        stopLeaseWatchdog()
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now() + 1.0, repeating: 1.0)
        timer.setEventHandler { [weak self] in
            guard let self = self else { return }
            let now = Int64(Date().timeIntervalSince1970)
            self.stateLock.lock()
            let deadline = self.activeLeaseDeadlineEpochSeconds
            let permitted = self.isPermitted
            if permitted && deadline > 0 && now >= deadline {
                self.logger.notice("Lease expired: now=\(now) >= deadline=\(deadline), enforcing immediate cutoff")
                self.isPermitted = false
                self.activeLeaseDeadlineEpochSeconds = 0
                self.terminateAllActiveFlowsLocked(reason: "lease_expired")
                let remaining = self.activeFlows.count
                let status = remaining > 0 ? "disconnecting" : "revoked"
                self.writeSystemExtensionReceiptLocked(
                    status: status,
                    reason: "lease_expired"
                )
                self.stateLock.unlock()
                if remaining > 0 {
                    self.scheduleDrainCheck(reason: "lease_expired")
                }
            } else {
                self.stateLock.unlock()
            }
        }
        timer.resume()
        leaseWatchdogTimer = timer
    }

    private func stopLeaseWatchdog() {
        leaseWatchdogTimer?.cancel()
        leaseWatchdogTimer = nil
    }

    private func stopDrainCheck() {
        drainCheckTimer?.cancel()
        drainCheckTimer = nil
    }

    /// Asynchronously tracks active flows during revocation, waiting for actual socket/flow termination.
    /// Only when activeFlows is confirmed empty (or on timeout) is the final revoked receipt written.
    private func scheduleDrainCheck(reason: String) {
        stopDrainCheck()
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .userInitiated))
        var checks = 0
        timer.schedule(deadline: .now() + 0.05, repeating: 0.05)
        timer.setEventHandler { [weak self] in
            guard let self = self else { return }
            checks += 1
            self.stateLock.lock()
            var drainedKeys: [UUID] = []
            for (id, record) in self.activeFlows {
                if record.connection.state == .cancelled || record.connection.state == .disconnected {
                    drainedKeys.append(id)
                }
            }
            for k in drainedKeys {
                self.activeFlows.removeValue(forKey: k)
            }
            let remaining = self.activeFlows.count
            if remaining == 0 {
                self.writeSystemExtensionReceiptLocked(status: "revoked", reason: reason)
                self.stateLock.unlock()
                self.logger.notice("Drain check: all active flows confirmed terminated and drained (reason=\(reason))")
                timer.cancel()
            } else if checks >= 30 {
                self.writeSystemExtensionReceiptLocked(status: "drain_timeout_unconfirmed", reason: reason)
                self.stateLock.unlock()
                self.logger.error("Drain timed out; active flows are not confirmed closed.")
                timer.cancel()
            } else {
                self.stateLock.unlock()
            }
        }
        timer.resume()
        drainCheckTimer = timer
    }

    private func startHeartbeatTimer() {
        stopHeartbeatTimer()
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now() + 1.0, repeating: 2.0)
        timer.setEventHandler { [weak self] in
            self?.emitLivenessHeartbeat()
        }
        timer.resume()
        heartbeatTimer = timer
    }

    private func stopHeartbeatTimer() {
        heartbeatTimer?.cancel()
        heartbeatTimer = nil
    }

    private func emitLivenessHeartbeat() {
        stateLock.lock()
        let active = isInterceptionActive
        let permitted = isPermitted
        let policyVer = currentPolicyVersion
        let cmdSeq = currentCommandSeq
        let permitGen = currentPermitGeneration
        let flowsCount = activeFlows.count
        stateLock.unlock()

        let stateDir = resolveSharedStateDir()
        let heartbeatFile = stateDir.appendingPathComponent("system-extension-heartbeat.json")
        let dict: [String: Any] = [
            "heartbeat_at": Date().timeIntervalSince1970,
            "executor_boot_id": executorBootID,
            "interception_active": active,
            "direct_fallback_blocked": true,
            "is_permitted": permitted,
            "policy_version": policyVer,
            "command_seq": cmdSeq,
            "permit_generation": permitGen,
            "active_flows_count": flowsCount,
            "status": "online"
        ]
        if let data = try? JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted]) {
            atomicWrite(data: data, to: heartbeatFile)
        }
    }

    private func startCommandFilePolling() {
        stopCommandFilePolling()
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now() + 0.5, repeating: 0.5)
        timer.setEventHandler { [weak self] in
            self?.pollCommandFile()
        }
        timer.resume()
        commandPollTimer = timer
    }

    private func stopCommandFilePolling() {
        commandPollTimer?.cancel()
        commandPollTimer = nil
    }

    /// Polls independent command file directly written by Rust daemon (works even when UI is closed).
    private func pollCommandFile() {
        let stateDir = resolveSharedStateDir()
        let cmdFile = stateDir.appendingPathComponent("system-extension-command.json")
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: cmdFile.path),
              let mtime = attrs[.modificationDate] as? Date,
              mtime > lastCommandFileMtime else {
            return
        }
        lastCommandFileMtime = mtime

        guard let data = try? Data(contentsOf: cmdFile),
              let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let action = json["action"] as? String else {
            return
        }

        applyCommand(action: action, json: json, completionHandler: nil)
    }

    /// IPC interface: receives dynamic permit updates, revoking commands, and status queries from host.
    open override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard let json = try? JSONSerialization.jsonObject(with: messageData) as? [String: Any],
              let action = json["action"] as? String else {
            completionHandler?(nil)
            return
        }
        applyCommand(action: action, json: json, completionHandler: completionHandler)
    }

    private func applyCommand(action: String, json: [String: Any], completionHandler: ((Data?) -> Void)?) {
        switch action {
        case "update_permit":
            stateLock.lock()
            let incomingGen = (json["permit_generation"] as? UInt64) ?? 0
            let incomingSeq = (json["command_seq"] as? UInt64) ?? 0
            let issuedAt = (json["issued_at"] as? Double) ?? 0
            let issuedInThisBoot = issuedAt >= providerBootEpochSeconds && issuedAt <= Date().timeIntervalSince1970 + 1

            let policy = (json["policy_version"] as? String) ?? ""
            let wantsPermit = json["permit_state"] as? String == "permitted"
            let deadline = (json["valid_until"] as? Int64) ?? 0
            let validPermit = !wantsPermit || (deadline > Int64(Date().timeIntervalSince1970)
                && (json["local_proxy_port"] as? UInt16) != nil)
            let validPolicyTransition = !currentPolicyVersion.isEmpty
                && policy != currentPolicyVersion
                ? incomingGen > currentPermitGeneration : true
            // Invariant: Strictly monotonic command progression.
            // Stale or replayed update_permit commands MUST NOT overwrite current revocation or higher generation permit!
            guard issuedInThisBoot && !policy.isEmpty && validPermit
                && validPolicyTransition
                && isCommandNewerLocked(permitGen: incomingGen, cmdSeq: incomingSeq) else {
                logger.warning("Rejecting stale update_permit: incoming gen=\(incomingGen), seq=\(incomingSeq) <= current gen=\(self.currentPermitGeneration), seq=\(self.currentCommandSeq)")
                let flowsCount = activeFlows.count
                stateLock.unlock()
                let resp: [String: Any] = [
                    "status": "rejected_stale",
                    "current_command_seq": currentCommandSeq,
                    "current_permit_generation": currentPermitGeneration,
                    "active_flows": flowsCount
                ]
                completionHandler?(try? JSONSerialization.data(withJSONObject: resp))
                return
            }

            self.currentPermitGeneration = incomingGen
            self.currentCommandSeq = incomingSeq

            if let port = json["local_proxy_port"] as? UInt16 {
                self.localProxyPort = port
            }
            if let deadline = json["valid_until"] as? Int64 {
                self.activeLeaseDeadlineEpochSeconds = deadline
            }
            if let state = json["permit_state"] as? String {
                self.isPermitted = (state == "permitted")
            }
            if let pids = json["allowed_pids"] as? [UInt32] {
                self.allowedPids = Set(pids)
                self.managedPids.formUnion(pids)
            }
            if let secret = json["extension_secret"] as? String, !secret.isEmpty {
                self.extensionSecret = secret
            }
            if let policyVer = json["policy_version"] as? String, !policyVer.isEmpty {
                self.currentPolicyVersion = policyVer
            }
            if !self.isPermitted {
                terminateAllActiveFlowsLocked(reason: "permit_revoked")
            }
            let flowsCount = activeFlows.count
            let permittedNow = isPermitted
            let resultStatus = permittedNow ? "ok" : (flowsCount == 0 ? "revoked" : "disconnecting")
            writeSystemExtensionReceiptLocked(status: resultStatus, reason: nil)
            stateLock.unlock()
            if permittedNow {
                stopDrainCheck()
            } else if flowsCount > 0 {
                scheduleDrainCheck(reason: "permit_revoked")
            }

            logger.info("Permit updated: isPermitted=\(permittedNow), deadline=\(self.activeLeaseDeadlineEpochSeconds), gen=\(incomingGen), seq=\(incomingSeq)")
            let resp: [String: Any] = ["status": resultStatus, "active_flows": flowsCount]
            completionHandler?(try? JSONSerialization.data(withJSONObject: resp))

        case "revoke_channel":
            stateLock.lock()
            let incomingGen = (json["permit_generation"] as? UInt64) ?? 0
            let incomingSeq = (json["command_seq"] as? UInt64) ?? 0
            let issuedAt = (json["issued_at"] as? Double) ?? 0
            let issuedInThisBoot = issuedAt >= providerBootEpochSeconds && issuedAt <= Date().timeIntervalSince1970 + 1

            // Check if revocation command is older than current command
            if !issuedInThisBoot || (json["policy_version"] as? String ?? "").isEmpty
                || !isCommandNewerLocked(permitGen: incomingGen, cmdSeq: incomingSeq) {
                logger.warning("Rejecting stale revoke_channel: incoming gen=\(incomingGen), seq=\(incomingSeq) < current gen=\(self.currentPermitGeneration), seq=\(self.currentCommandSeq)")
                stateLock.unlock()
                let resp: [String: Any] = ["status": "rejected_stale"]
                completionHandler?(try? JSONSerialization.data(withJSONObject: resp))
                return
            }

            if incomingGen > self.currentPermitGeneration || incomingSeq > self.currentCommandSeq {
                self.currentPermitGeneration = incomingGen
                self.currentCommandSeq = incomingSeq
            }

            self.isPermitted = false
            self.activeLeaseDeadlineEpochSeconds = 0
            if let policyVer = json["policy_version"] as? String, !policyVer.isEmpty {
                self.currentPolicyVersion = policyVer
            }
            let reason = json["reason"] as? String ?? "explicit_revoke"
            terminateAllActiveFlowsLocked(reason: reason)

            let remainingFlows = activeFlows.count
            let status = remainingFlows > 0 ? "disconnecting" : "revoked"
            writeSystemExtensionReceiptLocked(
                status: status,
                reason: reason
            )
            stateLock.unlock()

            if remainingFlows > 0 {
                scheduleDrainCheck(reason: reason)
            }

            logger.notice("Channel revoked via command: status=\(status), active_flows=\(remainingFlows)")
            let resp: [String: Any] = ["status": status, "active_flows": remainingFlows]
            completionHandler?(try? JSONSerialization.data(withJSONObject: resp))

        case "get_status":
            stateLock.lock()
            let status: [String: Any] = [
                "interception_active": isInterceptionActive,
                "direct_fallback_blocked": isDirectFallbackBlocked,
                "is_permitted": isPermitted,
                "active_flows_count": activeFlows.count,
                "total_forwarded": totalForwardedFlows,
                "total_blocked": totalBlockedFlows,
                "lease_deadline": activeLeaseDeadlineEpochSeconds,
                "policy_version": currentPolicyVersion,
                "command_seq": currentCommandSeq,
                "permit_generation": currentPermitGeneration
            ]
            stateLock.unlock()
            completionHandler?(try? JSONSerialization.data(withJSONObject: status))

        default:
            completionHandler?(nil)
        }
    }

    private func writeSystemExtensionReceiptLocked(status: String, reason: String?) {
        let stateDir = resolveSharedStateDir()
        let receiptFile = stateDir.appendingPathComponent("system-extension-receipt.json")

        let activeCount = activeFlows.count
        let effectivePermitState: String
        if isPermitted {
            effectivePermitState = "permitted"
        } else if activeCount > 0 {
            effectivePermitState = "disconnecting"
        } else {
            effectivePermitState = "revoked"
        }

        var dict: [String: Any] = [
            "executor_boot_id": executorBootID,
            "policy_version": currentPolicyVersion,
            "command_seq": currentCommandSeq,
            "permit_generation": currentPermitGeneration,
            "applied_at": Date().timeIntervalSince1970,
            "allowed_pids": Array(allowedPids),
            "local_proxy_port": localProxyPort,
            "permit_state": effectivePermitState,
            "status": status,
            "active_flows": activeCount
        ]
        if let reason = reason {
            dict["reason"] = reason
        }
        if let data = try? JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted]) {
            atomicWrite(data: data, to: receiptFile)
        }
    }

    /// Handles incoming application network flows (TCP, UDP, IPv6, DNS).
    open override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        // Step 1: Attribute remote host to detect attempts to access AI endpoints
        var targetHost = ""
        if let tcpFlow = flow as? NEAppProxyTCPFlow, let hostEndpoint = tcpFlow.remoteEndpoint as? NWHostEndpoint {
            targetHost = hostEndpoint.hostname.lowercased()
        }

        let isTargetingAiService = !targetHost.isEmpty && Self.managedAiDomainKeywords.contains { kw in
            targetHost == kw || targetHost.hasSuffix("." + kw)
        }

        let (isManagedProcess, flowPid, flowUid) = inspectFlowAttribution(flow)
        let signingID = flow.metaData.sourceAppSigningIdentifier.lowercased()
        let signedAiApp = ["anthropic", "claude", "openai", "chatgpt", "codex", "cursor"].contains {
            signingID.contains($0)
        }
        let validSourceIdentity = flow.metaData.sourceAppAuditToken?.count == 32
            && !signingID.isEmpty
        let isAiFlow = isManagedProcess || isTargetingAiService || signedAiApp || !validSourceIdentity

        // CRITICAL INVARIANT:
        // Returning `false` in NETransparentProxyProvider instructs the macOS kernel network stack
        // to bypass the proxy and let the flow connect directly to the destination!
        // Therefore, any flow belonging to a managed AI app OR targeting an AI API domain
        // must NEVER return `false`! Returning `false` would cause a catastrophic public IP leak!
        if !isAiFlow {
            return false
        }

        // Target application IS a managed AI process (Claude/ChatGPT/Codex) or connecting to AI endpoint:
        // CRITICAL: Even if destination is loopback (e.g. attempting to connect to local TAG port 7890 directly),
        // we DO NOT exempt it! All traffic must pass through supervised policy.
        stateLock.lock()
        let active = isInterceptionActive
        let permitted = isPermitted
        let deadline = activeLeaseDeadlineEpochSeconds
        let now = Int64(Date().timeIntervalSince1970)
        let leaseValid = deadline > 0 && now < deadline
        let allowed = allowedPids.contains(flowPid)
        stateLock.unlock()

        if !active || !permitted || !leaseValid || !allowed {
            // Cutoff-keep-process: immediately terminate flow with ECONNABORTED and return true.
            // Returning true tells macOS kernel that the transparent proxy accepted and handled the flow,
            // which guarantees the flow is aborted and prevents direct public fallback!
            closeFlowImmediately(flow, reason: "cutoff_keep_process_blocked")
            return true
        }

        if let tcpFlow = flow as? NEAppProxyTCPFlow {
            return forwardTCPFlow(tcpFlow, flowPid: flowPid, flowUid: flowUid)
        } else if let udpFlow = flow as? NEAppProxyUDPFlow {
            return handleUDPFlow(udpFlow)
        }

        closeFlowImmediately(flow, reason: "unsupported_protocol_blocked")
        return true
    }

    private func forwardTCPFlow(_ tcpFlow: NEAppProxyTCPFlow, flowPid: UInt32, flowUid: UInt32) -> Bool {
        guard let remoteEndpoint = tcpFlow.remoteEndpoint as? NWHostEndpoint else {
            closeFlowImmediately(tcpFlow, reason: "invalid_remote_endpoint")
            return true
        }

        let targetHost = remoteEndpoint.hostname
        let targetPort = remoteEndpoint.port
        let proxyEndpoint = NWHostEndpoint(hostname: localProxyHost, port: String(localProxyPort))
        let connection = self.createTCPConnection(to: proxyEndpoint, enableTLS: false, tlsParameters: nil, delegate: nil)
        let flowID = UUID()

        stateLock.lock()
        let authorizedAtRegistration = isInterceptionActive && isPermitted
            && activeLeaseDeadlineEpochSeconds > Int64(Date().timeIntervalSince1970)
            && allowedPids.contains(flowPid)
        if authorizedAtRegistration {
            activeFlows[flowID] = ActiveFlowRecord(flow: tcpFlow, connection: connection)
            totalForwardedFlows += 1
        }
        stateLock.unlock()
        guard authorizedAtRegistration else {
            connection.cancel()
            closeFlowImmediately(tcpFlow, reason: "permit_changed_before_registration")
            return true
        }

        // Extract Mach sourceAppAuditToken hex for authentic source verification
        var auditTokenHex = ""
        if let auditTokenData = tcpFlow.metaData.sourceAppAuditToken {
            auditTokenHex = auditTokenData.map { String(format: "%02x", $0) }.joined()
        }

        // Step 1: Send CONNECT handshake to local gateway with verified audit token & extension secret
        let connectReq = "CONNECT \(targetHost):\(targetPort) HTTP/1.1\r\nHost: \(targetHost):\(targetPort)\r\nX-Watch-PID: \(flowPid)\r\nX-Watch-UID: \(flowUid)\r\nX-Watch-Audit-Token: \(auditTokenHex)\r\nX-Watch-Extension-Secret: \(self.extensionSecret)\r\n\r\n"
        guard let connectData = connectReq.data(using: .utf8) else {
            closeFlowImmediately(tcpFlow, reason: "connect_req_encoding_error")
            return true
        }

        connection.write(connectData) { [weak self, weak tcpFlow, weak connection] writeErr in
            guard let self = self, let tcpFlow = tcpFlow, let connection = connection else { return }
            if let writeErr = writeErr {
                self.logger.error("Failed to send CONNECT to gateway: \(writeErr.localizedDescription)")
                self.cleanupFlow(id: flowID, error: writeErr)
                return
            }

            // Step 2: Read CONNECT response in full, extracting valid payload after header boundary
            self.readConnectResponseHeader(connection: connection, accumulated: Data()) { [weak self, weak tcpFlow, weak connection] result in
                guard let self = self, let tcpFlow = tcpFlow, let connection = connection else { return }
                switch result {
                case .failure(let err):
                    self.logger.error("Gateway rejected CONNECT handshake: \(err.localizedDescription)")
                    self.cleanupFlow(id: flowID, error: err)
                case .success(let remainingPayload):
                    guard self.isForwardAuthorized(flowID: flowID, pid: flowPid) else {
                        self.cleanupFlow(id: flowID, error: nil)
                        return
                    }
                    tcpFlow.open(withLocalEndpoint: nil) { [weak self, weak tcpFlow, weak connection] openErr in
                        guard let self = self, let tcpFlow = tcpFlow, let connection = connection else { return }
                        if let openErr = openErr {
                            self.logger.error("Failed to open TCP flow to client: \(openErr.localizedDescription)")
                            self.cleanupFlow(id: flowID, error: openErr)
                            return
                        }
                        guard self.isForwardAuthorized(flowID: flowID, pid: flowPid) else {
                            self.cleanupFlow(id: flowID, error: nil)
                            return
                        }

                        // Forward any pipelined application payload received during handshake without data loss
                        if !remainingPayload.isEmpty {
                            tcpFlow.write(remainingPayload) { _ in }
                        }

                        // Pipe Client -> Proxy
                        self.pumpClientToProxy(flowID: flowID, flow: tcpFlow, connection: connection)
                        // Pipe Proxy -> Client
                        self.pumpProxyToClient(flowID: flowID, flow: tcpFlow, connection: connection)
                    }
                }
            }
        }
        return true
    }

    private func isForwardAuthorized(flowID: UUID, pid: UInt32) -> Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        guard let record = activeFlows[flowID], !record.isClosing else { return false }
        return isInterceptionActive && isPermitted
            && activeLeaseDeadlineEpochSeconds > Int64(Date().timeIntervalSince1970)
            && allowedPids.contains(pid)
    }

    /// Reads CONNECT response from gateway until full `\r\n\r\n` boundary is found, parsing the status line.
    private func readConnectResponseHeader(
        connection: NWTCPConnection,
        accumulated: Data,
        completion: @escaping (Result<Data, Error>) -> Void
    ) {
        let delimiter = Data([0x0D, 0x0A, 0x0D, 0x0A]) // \r\n\r\n
        if let range = accumulated.range(of: delimiter) {
            let headerData = accumulated.subdata(in: 0..<range.lowerBound)
            let remaining = accumulated.subdata(in: range.upperBound..<accumulated.count)
            guard let headerStr = String(data: headerData, encoding: .utf8) else {
                completion(.failure(NSError(domain: "WatchChannel", code: 400, userInfo: [NSLocalizedDescriptionKey: "Invalid UTF8 header"])))
                return
            }
            let firstLine = headerStr.components(separatedBy: "\r\n").first ?? ""
            if firstLine.contains(" 200 ") || firstLine.hasPrefix("HTTP/1.1 200") || firstLine.hasPrefix("HTTP/1.0 200") {
                completion(.success(remaining))
            } else {
                completion(.failure(NSError(domain: "WatchChannel", code: 403, userInfo: [NSLocalizedDescriptionKey: "Gateway rejected CONNECT: \(firstLine)"])))
            }
            return
        }

        if accumulated.count > 8192 {
            completion(.failure(NSError(domain: "WatchChannel", code: 431, userInfo: [NSLocalizedDescriptionKey: "CONNECT response header too large"])))
            return
        }

        connection.readMinimumLength(1, maximumLength: 4096) { [weak self, weak connection] chunk, readErr in
            guard let self = self, let connection = connection else { return }
            if let readErr = readErr {
                completion(.failure(readErr))
                return
            }
            guard let chunk = chunk, !chunk.isEmpty else {
                completion(.failure(NSError(domain: "WatchChannel", code: -1, userInfo: [NSLocalizedDescriptionKey: "Connection closed by gateway during handshake"])))
                return
            }
            var nextAccum = accumulated
            nextAccum.append(chunk)
            self.readConnectResponseHeader(connection: connection, accumulated: nextAccum, completion: completion)
        }
    }

    private func pumpClientToProxy(flowID: UUID, flow: NEAppProxyTCPFlow, connection: NWTCPConnection) {
        flow.readData { [weak self, weak flow, weak connection] data, error in
            guard let self = self, let flow = flow, let connection = connection else { return }
            if let error = error {
                self.cleanupFlow(id: flowID, error: error)
                return
            }
            guard let data = data, !data.isEmpty else {
                // EOF from client: cleanly half-close proxy write
                self.cleanupFlow(id: flowID, error: nil)
                return
            }

            connection.write(data) { [weak self, weak flow, weak connection] writeErr in
                guard let self = self, let flow = flow, let connection = connection else { return }
                if let writeErr = writeErr {
                    self.cleanupFlow(id: flowID, error: writeErr)
                    return
                }
                self.pumpClientToProxy(flowID: flowID, flow: flow, connection: connection)
            }
        }
    }

    private func pumpProxyToClient(flowID: UUID, flow: NEAppProxyTCPFlow, connection: NWTCPConnection) {
        connection.readMinimumLength(1, maximumLength: 65536) { [weak self, weak flow, weak connection] data, error in
            guard let self = self, let flow = flow, let connection = connection else { return }
            if let error = error {
                self.cleanupFlow(id: flowID, error: error)
                return
            }
            guard let data = data, !data.isEmpty else {
                // EOF from gateway
                self.cleanupFlow(id: flowID, error: nil)
                return
            }

            flow.write(data) { [weak self, weak flow, weak connection] writeErr in
                guard let self = self, let flow = flow, let connection = connection else { return }
                if let writeErr = writeErr {
                    self.cleanupFlow(id: flowID, error: writeErr)
                    return
                }
                self.pumpProxyToClient(flowID: flowID, flow: flow, connection: connection)
            }
        }
    }

    private func cleanupFlow(id: UUID, error: Error?) {
        stateLock.lock()
        guard let record = activeFlows[id] else {
            stateLock.unlock()
            return
        }
        let permitted = isPermitted
        if permitted {
            activeFlows.removeValue(forKey: id)
        } else {
            var closing = record
            closing.isClosing = true
            activeFlows[id] = closing
        }
        stateLock.unlock()
        let abortErr = error ?? NSError(domain: NSPOSIXErrorDomain, code: Int(ECONNABORTED))
        record.flow.closeReadWithError(abortErr)
        record.flow.closeWriteWithError(abortErr)
        record.connection.cancel()
        if !permitted { scheduleDrainCheck(reason: "all_flows_drained") }
    }

    private func terminateAllActiveFlowsLocked(reason: String) {
        logger.notice("Initiating flow termination: reason=\(reason), count=\(self.activeFlows.count)")
        let abortErr = NSError(domain: NSPOSIXErrorDomain, code: Int(ECONNABORTED))
        let now = Date()
        for (id, var record) in activeFlows {
            record.isClosing = true
            record.closeRequestedAt = now
            activeFlows[id] = record

            record.flow.closeReadWithError(abortErr)
            record.flow.closeWriteWithError(abortErr)
            record.connection.cancel()
        }
    }

    private func handleUDPFlow(_ udpFlow: NEAppProxyUDPFlow) -> Bool {
        // Safe default: drop UDP/QUIC to force AI application to fall back to supervised TCP
        let abortErr = NSError(domain: NSPOSIXErrorDomain, code: Int(ECONNABORTED))
        udpFlow.closeReadWithError(abortErr)
        udpFlow.closeWriteWithError(abortErr)
        stateLock.lock()
        totalBlockedFlows += 1
        stateLock.unlock()
        return true
    }

    private func closeFlowImmediately(_ flow: NEAppProxyFlow, reason: String) {
        logger.notice("Enforcing cutoff-keep-process: immediately closing flow (\(reason))")
        let abortErr = NSError(domain: NSPOSIXErrorDomain, code: Int(ECONNABORTED))
        if let tcp = flow as? NEAppProxyTCPFlow {
            tcp.closeReadWithError(abortErr)
            tcp.closeWriteWithError(abortErr)
        } else if let udp = flow as? NEAppProxyUDPFlow {
            udp.closeReadWithError(abortErr)
            udp.closeWriteWithError(abortErr)
        }
        stateLock.lock()
        totalBlockedFlows += 1
        stateLock.unlock()
    }

    private func inspectFlowAttribution(_ flow: NEAppProxyFlow) -> (isManaged: Bool, pid: UInt32, uid: UInt32) {
        stateLock.lock()
        let managed = managedPids
        stateLock.unlock()

        if let auditToken = flow.metaData.sourceAppAuditToken, auditToken.count == 32 {
            // Mach audit_token_t: 8 x UInt32
            // offset 4: euid, offset 20: pid
            let (pid, uid) = auditToken.withUnsafeBytes { ptr -> (UInt32, UInt32) in
                let p = ptr.load(fromByteOffset: 20, as: UInt32.self)
                let u = ptr.load(fromByteOffset: 4, as: UInt32.self)
                return (p, u)
            }
            if managed.contains(pid) || hasManagedAncestor(pid: pid, uid: uid, managed: managed) {
                return (true, pid, uid)
            }
            // Check process name via libproc to catch unlisted/fresh AI processes!
            var nameBuffer = [CChar](repeating: 0, count: 256)
            let nameLen = proc_name(Int32(pid), &nameBuffer, UInt32(nameBuffer.count))
            if nameLen > 0 {
                let procName = String(cString: nameBuffer).lowercased()
                if procName.contains("claude") || procName.contains("chatgpt") || procName.contains("codex") || procName.contains("cursor") {
                    return (true, pid, uid)
                }
            }
        }
        return (false, 0, 0)
    }

    /// Descendants are classified as managed but never auto-authorized.
    private func hasManagedAncestor(pid: UInt32, uid: UInt32, managed: Set<UInt32>) -> Bool {
        var cursor = pid
        var visited = Set<UInt32>([pid])
        for _ in 0..<16 {
            var info = proc_bsdinfo()
            let size = Int32(MemoryLayout<proc_bsdinfo>.size)
            guard proc_pidinfo(Int32(cursor), PROC_PIDTBSDINFO, 0, &info, size) == size,
                  info.pbi_uid == uid else { return false }
            let parent = info.pbi_ppid
            guard parent > 1 && !visited.contains(parent) else { return false }
            if managed.contains(parent) { return true }
            visited.insert(parent)
            cursor = parent
        }
        return false
    }

    open override func sleep(completionHandler: @escaping () -> Void) {
        logger.info("System sleep detected: immediately clearing lease and terminating flows")
        stateLock.lock()
        activeLeaseDeadlineEpochSeconds = 0
        isPermitted = false
        terminateAllActiveFlowsLocked(reason: "system_sleep")
        writeSystemExtensionReceiptLocked(status: "suspended_unverified", reason: "system_sleep")
        stateLock.unlock()
        stopDrainCheck()
        completionHandler()
    }

    open override func wake() {
        logger.info("System wake detected: requiring fresh Rust daemon verification before permitting flows")
        stateLock.lock()
        activeLeaseDeadlineEpochSeconds = 0
        isPermitted = false
        writeSystemExtensionReceiptLocked(status: "wake_unverified", reason: "system_wake")
        stateLock.unlock()
    }
}
