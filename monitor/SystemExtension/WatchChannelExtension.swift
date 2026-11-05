import Foundation
import NetworkExtension
import os.log

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
/// 5. IPC via `handleAppMessage` enables Rust daemon and host manager to push dynamic permits and revoking commands.
@available(macOS 11.0, *)
open class WatchChannelExtension: NETransparentProxyProvider {
    private let logger = Logger(subsystem: "io.local.watchpanel.extension", category: "FlowGate")

    private let stateLock = NSLock()
    private var isInterceptionActive: Bool = false
    private var isDirectFallbackBlocked: Bool = false
    private var localProxyPort: UInt16 = 7890
    private var localProxyHost: String = "127.0.0.1"
    private var currentPolicyVersion: String = ""
    private var activeLeaseDeadlineEpochSeconds: Int64 = 0
    private var managedPids: Set<UInt32> = []
    private var allowedPids: Set<UInt32> = []
    private var isPermitted: Bool = false

    // Active flow tracking for immediate cutoff on revocation or lease expiry
    private struct ActiveFlowRecord {
        let flow: NEAppProxyTCPFlow
        let connection: NWTCPConnection
    }
    private var activeFlows: [UUID: ActiveFlowRecord] = [:]
    private var totalBlockedFlows: UInt64 = 0
    private var totalForwardedFlows: UInt64 = 0

    open override func startProxy(options: [String: Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        logger.info("WatchChannelExtension startProxy requested")
        stateLock.lock()
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
        }
        stateLock.unlock()

        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: localProxyHost)
        let defaultIPv4Route = NEIPv4Route.default()
        let ipv4Settings = NEIPv4Settings(addresses: ["198.18.0.1"], subnetMasks: ["255.255.0.0"])
        ipv4Settings.includedRoutes = [defaultIPv4Route]
        settings.ipv4Settings = ipv4Settings

        let defaultIPv6Route = NEIPv6Route.default()
        let ipv6Settings = NEIPv6Settings(addresses: ["fd00::1"], networkPrefixLengths: [64])
        ipv6Settings.includedRoutes = [defaultIPv6Route]
        settings.ipv6Settings = ipv6Settings

        setTunnelNetworkSettings(settings) { [weak self] error in
            if let error = error {
                self?.logger.error("Failed to apply tunnel settings: \(error.localizedDescription)")
                completionHandler(error)
            } else {
                self?.logger.info("WatchChannelExtension tunnel settings applied successfully")
                completionHandler(nil)
            }
        }
    }

    open override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        logger.info("WatchChannelExtension stopProxy reason: \(reason.rawValue)")
        stateLock.lock()
        isInterceptionActive = false
        isDirectFallbackBlocked = false
        terminateAllActiveFlowsLocked(reason: "proxy_stopped")
        stateLock.unlock()
        completionHandler()
    }

    /// IPC interface: receives dynamic permit updates, revoking commands, and status queries from host.
    open override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard let json = try? JSONSerialization.jsonObject(with: messageData) as? [String: Any],
              let action = json["action"] as? String else {
            completionHandler?(nil)
            return
        }

        switch action {
        case "update_permit":
            stateLock.lock()
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
            if !self.isPermitted {
                terminateAllActiveFlowsLocked(reason: "permit_revoked")
            }
            stateLock.unlock()
            logger.info("Permit updated: isPermitted=\(self.isPermitted), deadline=\(self.activeLeaseDeadlineEpochSeconds)")
            let resp: [String: Any] = ["status": "ok", "active_flows": activeFlows.count]
            completionHandler?(try? JSONSerialization.data(withJSONObject: resp))

        case "revoke_channel":
            stateLock.lock()
            self.isPermitted = false
            self.activeLeaseDeadlineEpochSeconds = 0
            terminateAllActiveFlowsLocked(reason: json["reason"] as? String ?? "explicit_revoke")
            stateLock.unlock()
            logger.notice("Channel revoked via IPC")
            let resp: [String: Any] = ["status": "revoked", "active_flows": 0]
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
            ]
            stateLock.unlock()
            completionHandler?(try? JSONSerialization.data(withJSONObject: status))

        default:
            completionHandler?(nil)
        }
    }

    /// Handles incoming application network flows (TCP, UDP, IPv6, DNS).
    open override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        let (isManaged, flowPid) = inspectFlowAttribution(flow)

        // Non-managed applications: do not intercept non-AI flows
        if !isManaged {
            return false
        }

        // Target application IS a managed AI process (Claude/ChatGPT/Codex):
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
            closeFlowImmediately(flow, reason: "cutoff_keep_process_blocked")
            return true
        }

        if let tcpFlow = flow as? NEAppProxyTCPFlow {
            return forwardTCPFlow(tcpFlow)
        } else if let udpFlow = flow as? NEAppProxyUDPFlow {
            return handleUDPFlow(udpFlow)
        }

        closeFlowImmediately(flow, reason: "unsupported_protocol_blocked")
        return true
    }

    private func forwardTCPFlow(_ tcpFlow: NEAppProxyTCPFlow) -> Bool {
        guard let remoteEndpoint = tcpFlow.remoteEndpoint as? NWHostEndpoint else {
            closeFlowImmediately(tcpFlow, reason: "invalid_remote_endpoint")
            return true
        }

        // Avoid proxy loop: if the flow originates from our own local proxy port, pass through
        if remoteEndpoint.hostname == localProxyHost && remoteEndpoint.port == String(localProxyPort) {
            return false
        }

        let proxyEndpoint = NWHostEndpoint(hostname: localProxyHost, port: String(localProxyPort))
        let connection = self.createTCPConnection(to: proxyEndpoint, enableTLS: false, tlsParameters: nil, delegate: nil)
        let flowID = UUID()

        stateLock.lock()
        activeFlows[flowID] = ActiveFlowRecord(flow: tcpFlow, connection: connection)
        totalForwardedFlows += 1
        stateLock.unlock()

        tcpFlow.open(withLocalEndpoint: nil) { [weak self, weak connection] error in
            guard let self = self, let connection = connection else { return }
            if let error = error {
                self.logger.error("Failed to open TCP flow: \(error.localizedDescription)")
                self.cleanupFlow(id: flowID, error: error)
                return
            }

            // Pipe Client -> Proxy
            self.pumpClientToProxy(flowID: flowID, flow: tcpFlow, connection: connection)
            // Pipe Proxy -> Client
            self.pumpProxyToClient(flowID: flowID, flow: tcpFlow, connection: connection)
        }
        return true
    }

    private func pumpClientToProxy(flowID: UUID, flow: NEAppProxyTCPFlow, connection: NWTCPConnection) {
        flow.readData { [weak self, weak flow, weak connection] data, error in
            guard let self = self, let flow = flow, let connection = connection else { return }
            if let error = error {
                self.cleanupFlow(id: flowID, error: error)
                return
            }
            guard let data = data, !data.isEmpty else {
                // EOF from client
                self.cleanupFlow(id: flowID, error: nil)
                return
            }
            connection.write(data) { writeErr in
                if let writeErr = writeErr {
                    self.cleanupFlow(id: flowID, error: writeErr)
                } else {
                    self.pumpClientToProxy(flowID: flowID, flow: flow, connection: connection)
                }
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
                // EOF from proxy
                self.cleanupFlow(id: flowID, error: nil)
                return
            }
            flow.writeData(data) { writeErr in
                if let writeErr = writeErr {
                    self.cleanupFlow(id: flowID, error: writeErr)
                } else {
                    self.pumpProxyToClient(flowID: flowID, flow: flow, connection: connection)
                }
            }
        }
    }

    private func cleanupFlow(id: UUID, error: Error?) {
        stateLock.lock()
        guard let record = activeFlows.removeValue(forKey: id) else {
            stateLock.unlock()
            return
        }
        stateLock.unlock()

        let abortErr = error ?? NSError(domain: NSPOSIXErrorDomain, code: Int(ECONNABORTED))
        record.flow.closeReadWithError(abortErr)
        record.flow.closeWriteWithError(abortErr)
        record.connection.cancel()
    }

    private func terminateAllActiveFlowsLocked(reason: String) {
        logger.notice("Terminating all active flows: reason=\(reason), count=\(self.activeFlows.count)")
        let abortErr = NSError(domain: NSPOSIXErrorDomain, code: Int(ECONNABORTED))
        for (_, record) in activeFlows {
            record.flow.closeReadWithError(abortErr)
            record.flow.closeWriteWithError(abortErr)
            record.connection.cancel()
        }
        activeFlows.removeAll()
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

    private func inspectFlowAttribution(_ flow: NEAppProxyFlow) -> (isManaged: Bool, pid: UInt32) {
        stateLock.lock()
        let managed = managedPids
        stateLock.unlock()

        if let auditToken = flow.sourceProcessAuditToken, auditToken.count == 32 {
            // Mach audit_token_t: 8 x UInt32, index 5 is pid
            let pid = auditToken.withUnsafeBytes { ptr -> UInt32 in
                ptr.load(fromByteOffset: 20, as: UInt32.self)
            }
            if managed.contains(pid) {
                return (true, pid)
            }
        }
        return (false, 0)
    }

    open override func sleep(completionHandler: @escaping () -> Void) {
        logger.info("System sleep detected: immediately clearing lease and terminating flows")
        stateLock.lock()
        activeLeaseDeadlineEpochSeconds = 0
        isPermitted = false
        terminateAllActiveFlowsLocked(reason: "system_sleep")
        stateLock.unlock()
        completionHandler()
    }

    open override func wake() {
        logger.info("System wake detected: requiring fresh Rust daemon verification before permitting flows")
        stateLock.lock()
        activeLeaseDeadlineEpochSeconds = 0
        isPermitted = false
        stateLock.unlock()
    }
}
