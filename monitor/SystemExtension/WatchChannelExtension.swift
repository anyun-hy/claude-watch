import Foundation
import NetworkExtension
import os.log
import Darwin
import Security

@available(macOS 11.0, *)
@main
@objc(WatchChannelExtension)
open class WatchChannelExtension: NETransparentProxyProvider {
    public static func main() {
        NEProvider.startSystemExtensionMode()
        dispatchMain()
    }
    private let logger = Logger(subsystem: "io.local.watchpanel.extension", category: "FlowGate")
    private let stateLock = NSLock()
    private let controlQueue = DispatchQueue(label: "watch.extension.control", qos: .userInitiated)
    private let extensionBoot = UUID().uuidString
    private var providerStartedAt: Double = 0
    private var executorBoot = ""
    private var stateDirectory: ExtensionStateDirectory?
    private var controlUID: uid_t = 0
    private var gatewaySocket = ""
    private var isInterceptionActive = false
    private var observationHealthy = true
    private var managedProcesses: [ChannelProcessIdentity] = []
    private var ownership = ChannelOwnershipRegistry()
    private var totalBlockedFlows: UInt64 = 0
    private var totalForwardedFlows: UInt64 = 0
    private var controlTimer: DispatchSourceTimer?
    private var commandEvents: DispatchSourceFileSystemObject?
    private var heartbeatTimer: DispatchSourceTimer?
    private var lastCommandData: Data?
    private struct Permit {
        var policy: [String: Any]
        var seq: UInt64
        var generation: UInt64
        var issuedAt: Double
        var appliedAt: Double
        var deadline: Double
        var monotonicDeadline: Double
        var pids: Set<UInt32>
        var processes: [ChannelProcessIdentity]
        var sessionID: String?
        var commandBinding: String
        var requestedState: String
        var permitted: Bool
        var status: String
        var reason: String?
        var closingSince: Double?
        var isLive: Bool {
            channelPermitIsLive(permitted: permitted, issuedAt: issuedAt, deadline: deadline,
                monotonicDeadline: monotonicDeadline, now: Date().timeIntervalSince1970,
                uptime: ProcessInfo.processInfo.systemUptime)
        }
    }
    private struct ActiveFlowRecord {
        let flow: NEAppProxyTCPFlow
        let connection: GatewayConnection
        let family: String
        let identity: ChannelProcessIdentity
    }
    private var families: [String: Permit] = [:]
    private var activeFlows: [UUID: ActiveFlowRecord] = [:]

    open override func startProxy(options: [String: Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        providerStartedAt = Date().timeIntervalSince1970
        do {
            guard let config = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration,
                  let home = config["control_home"] as? String,
                  let uid = (config["control_uid"] as? NSNumber)?.uint32Value else {
                throw ExtensionStateDirectory.error("Missing control directory configuration")
            }
            stateDirectory = try ExtensionStateDirectory(home: home, uid: uid)
            controlUID = uid
        } catch { completionHandler(error); return }
        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.includedNetworkRules = [NENetworkRule(remoteNetwork: nil, remotePrefix: 0,
            localNetwork: nil, localPrefix: 0, protocol: .any, direction: .outbound)]
        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self = self else { return }
            if let error = error { completionHandler(error); return }
            self.stateLock.lock()
            self.isInterceptionActive = true
            self.stateLock.unlock()
            self.startControlTimers()
            completionHandler(nil)
        }
    }
    private func startControlTimers() {
        if let directory = stateDirectory {
            let events = DispatchSource.makeFileSystemObjectSource(fileDescriptor: directory.fd, eventMask: [.write, .rename, .delete], queue: controlQueue)
            events.setEventHandler { [weak self] in self?.controlTick() }
            events.resume()
            commandEvents = events
        }
        let control = DispatchSource.makeTimerSource(queue: controlQueue)
        control.schedule(deadline: .now(), repeating: 0.25)
        control.setEventHandler { [weak self] in self?.controlTick() }
        control.resume()
        controlTimer = control
        let heartbeat = DispatchSource.makeTimerSource(queue: controlQueue)
        heartbeat.schedule(deadline: .now(), repeating: 2.0)
        heartbeat.setEventHandler { [weak self] in self?.emitHeartbeat() }
        heartbeat.resume()
        heartbeatTimer = heartbeat
    }
    private func controlTick() {
        do {
            guard let directory = stateDirectory else { throw ExtensionStateDirectory.error("Control directory missing") }
            let path = try directory.gatewayLocation()
            let data = try GatewayConnection.controlSnapshot(path: path, uid: controlUID, home: directory.home)
            if data != lastCommandData {
                try applyCommands(ChannelCommandEnvelope.decode(data))
                lastCommandData = data
            }
        } catch {
            if lastCommandData != nil {
                lastCommandData = nil
                stateLock.lock(); revokeAllLocked(reason: "invalid_control_command"); stateLock.unlock()
                logger.error("Command rejected: \(error.localizedDescription)")
            }
        }
        stateLock.lock()
        let now = Date().timeIntervalSince1970
        var changed = false
        for family in Array(families.keys) {
            guard var permit = families[family] else { continue }
            if permit.permitted && (now >= permit.deadline || now + 0.05 < permit.issuedAt
                || ProcessInfo.processInfo.systemUptime >= permit.monotonicDeadline) {
                permit.permitted = false
                permit.reason = "lease_expired"
                permit.closingSince = now
                families[family] = permit
                terminateFlowsLocked(family: family)
                changed = true
            }
            if let since = families[family]?.closingSince {
                let remaining = activeFlows.values.filter { $0.family == family }.count
                let status = channelDrainStatus(remaining: remaining, started: since, now: now)
                if status == "revoked" {
                    families[family]?.status = "revoked"
                    families[family]?.closingSince = nil
                    families[family]?.appliedAt = now
                    changed = true
                } else if status == "failed" && families[family]?.status != "failed" {
                    // A timeout is a failure, never evidence that sockets closed.
                    families[family]?.status = "failed"
                    families[family]?.reason = "drain_timeout"
                    families[family]?.appliedAt = now
                    changed = true
                }
            }
        }
        if changed { writeReceiptsLocked() }
        stateLock.unlock()
    }
    private func applyCommands(_ envelope: ChannelCommandEnvelope) throws {
        stateLock.lock(); defer { stateLock.unlock() }
        let changedBoot = executorBoot != envelope.executor_boot_id
        // Validate the entire envelope before applying any of it.
        if !changedBoot {
            for command in envelope.commands {
                if let previous = families[command.family] {
                    if command.permit_generation == previous.generation && command.command_seq == previous.seq {
                        guard NSDictionary(dictionary: command.policy_version.dictionary).isEqual(to: previous.policy),
                              command.issued_at == previous.issuedAt, command.valid_until == previous.deadline,
                              command.permit_state == previous.requestedState, Set(command.allowed_pids) == previous.pids,
                              command.session_id == previous.sessionID, command.allowed_processes == previous.processes,
                              command.command_binding == previous.commandBinding else {
                            throw ExtensionStateDirectory.error("Conflicting command sequence")
                        }
                    } else {
                        guard channelCommandAdvances(generation: command.permit_generation, sequence: command.command_seq,
                            previousGeneration: previous.generation, previousSequence: previous.seq),
                            NSDictionary(dictionary: command.policy_version.dictionary).isEqual(to: previous.policy)
                                || command.permit_generation > previous.generation,
                            command.session_id == previous.sessionID || command.permit_generation > previous.generation else {
                            throw ExtensionStateDirectory.error("Stale command or policy generation")
                        }
                    }
                }
            }
        }
        if changedBoot {
            terminateFlowsLocked(family: nil)
            families.removeAll()
            executorBoot = envelope.executor_boot_id
        }
        gatewaySocket = envelope.gateway_socket
        let now = Date().timeIntervalSince1970
        for command in envelope.commands {
            let family = command.family
            let policy = command.policy_version.dictionary
            let previous = families[family]
            if let previous = previous, previous.seq == command.command_seq && previous.generation == command.permit_generation { continue }
            let allowed = command.canGrant(providerStartedAt: providerStartedAt, now: now)
            var permit = Permit(policy: policy, seq: command.command_seq, generation: command.permit_generation,
                issuedAt: command.issued_at, appliedAt: now, deadline: command.valid_until,
                monotonicDeadline: ProcessInfo.processInfo.systemUptime + max(0, min(10, command.valid_until - now)),
                pids: Set(command.allowed_pids), processes: command.allowed_processes, sessionID: command.session_id,
                commandBinding: command.command_binding,
                requestedState: command.permit_state, permitted: allowed,
                status: allowed ? "ok" : "disconnecting", reason: command.reason, closingSince: allowed ? nil : now)
            for process in command.allowed_processes { ownership.remember(process) }
            let previousPolicy = previous.flatMap { p -> ChannelPolicy? in
                guard let policy = p.policy["policy_digest"] as? String,
                      let guardPolicy = p.policy["guard_policy_digest"] as? String else { return nil }
                return ChannelPolicy(policy_digest: policy, guard_policy_digest: guardPolicy)
            }
            let update = ChannelFlowUpdate(command: command, allowed: allowed, changedBoot: changedBoot,
                previousGeneration: previous?.generation, previousPolicy: previousPolicy,
                previousSession: previous?.sessionID, wasClosing: previous?.closingSince != nil)
            terminateFlowsLocked(family: family, keeping: update.keeps)
            let remaining = activeFlows.values.contains { $0.family == family }
            if !allowed && !remaining { permit.status = "revoked"; permit.closingSince = nil }
            let unclosed = activeFlows.values.contains { $0.family == family && !update.keeps($0.identity) }
            if allowed && unclosed {
                permit.permitted = false; permit.status = "failed"; permit.reason = "previous_flows_not_closed"
                permit.closingSince = previous?.closingSince ?? now
            }
            families[family] = permit
        }
        // An omitted previously-managed family is denied, never orphaned open.
        let present = Set(envelope.commands.map { $0.family })
        for family in families.keys.filter({ !present.contains($0) }) {
            families[family]?.permitted = false
            families[family]?.closingSince = now
            families[family]?.reason = "family_command_removed"
            terminateFlowsLocked(family: family)
        }
        managedProcesses = families.values.flatMap { $0.processes }
        ownership.prune(current: { ChannelCodeIdentity.process(pid: $0)?.identity }, exited: { pid in
            var info = proc_bsdinfo()
            return proc_pidinfo(Int32(pid), PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size)) <= 0 && errno == ESRCH
        })
        writeReceiptsLocked()
    }
    private func writeReceiptsLocked() {
        let receipts: [[String: Any]] = families.map { family, permit in
            let count = activeFlows.values.filter { $0.family == family }.count
            var value: [String: Any] = [
                "family": family, "executor_boot_id": executorBoot, "extension_boot_id": extensionBoot,
                "command_binding": permit.commandBinding,
                "policy_version": permit.policy, "command_seq": permit.seq, "permit_generation": permit.generation,
                "applied_at": permit.appliedAt, "allowed_pids": Array(permit.pids), "local_proxy_port": 0,
                "permit_state": permit.permitted ? "permitted" : (count > 0 ? "disconnecting" : "revoked"),
                "status": permit.status, "active_flows": count, "new_connections_blocked": !permit.permitted
            ]
            if let reason = permit.reason { value["reason"] = reason }
            return value
        }
        do { try stateDirectory?.writeObservation(receipts, name: "system-extension-receipt.json"); observationHealthy = true }
        catch {
            observationHealthy = false
            for key in Array(families.keys) { families[key]?.permitted = false }
            terminateFlowsLocked(family: nil)
            logger.error("Receipt publish failed: \(error.localizedDescription)")
        }
    }
    private func emitHeartbeat() {
        stateLock.lock(); defer { stateLock.unlock() }
        do {
            try stateDirectory?.writeObservation([
                "executor_boot_id": executorBoot, "extension_boot_id": extensionBoot,
                "heartbeat_at": Date().timeIntervalSince1970,
                "interception_active": isInterceptionActive && observationHealthy
            ], name: "system-extension-heartbeat.json")
        } catch { logger.error("Heartbeat publish failed: \(error.localizedDescription)") }
    }
    open override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        // Commands have one authority: Rust. UI messages cannot grant or revoke permits.
        completionHandler?(try? JSONSerialization.data(withJSONObject: ["status": "read_only", "extension_boot_id": extensionBoot]))
    }
    open override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        controlTimer?.cancel(); heartbeatTimer?.cancel(); commandEvents?.cancel()
        stateLock.lock()
        isInterceptionActive = false
        revokeAllLocked(reason: "stop_proxy")
        stateLock.unlock()
        emitHeartbeat()
        completionHandler()
    }
    private func revokeAllLocked(reason: String) {
        let now = Date().timeIntervalSince1970
        for key in Array(families.keys) {
            families[key]?.permitted = false
            families[key]?.closingSince = now
            families[key]?.reason = reason
        }
        terminateFlowsLocked(family: nil)
        for key in Array(families.keys) {
            families[key]?.status = activeFlows.values.contains { $0.family == key } ? "disconnecting" : "revoked"
            families[key]?.appliedAt = now
        }
        writeReceiptsLocked()
    }
    open override func sleep(completionHandler: @escaping () -> Void) {
        stateLock.lock(); revokeAllLocked(reason: "system_sleep"); stateLock.unlock()
        completionHandler()
    }
    open override func wake() { controlQueue.async { [weak self] in self?.controlTick(); self?.emitHeartbeat() } }

    open override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        let (classification, source) = inspectFlowAttribution(flow)
        if channelMayBypass(ownership: classification) { return false }
        guard classification == .managed, let source else {
            closeFlowImmediately(flow, reason: "source_ownership_unconfirmed"); return true
        }
        stateLock.lock()
        let family = families.first { $0.value.processes.contains(where: { $0.matches(source.identity) }) }?.key
        let permit = family.flatMap { families[$0] }
        let allowed = isInterceptionActive && observationHealthy && permit?.isLive == true
        let socket = gatewaySocket
        stateLock.unlock()
        guard allowed, let family = family else {
            closeFlowImmediately(flow, reason: "cutoff_keep_process_blocked"); return true
        }
        guard let tcp = flow as? NEAppProxyTCPFlow else {
            closeFlowImmediately(flow, reason: "udp_or_unsupported_blocked"); return true
        }
        return forwardTCPFlow(tcp, source: source, family: family, socketPath: socket)
    }
    private func forwardTCPFlow(_ tcpFlow: NEAppProxyTCPFlow, source: ChannelCodeIdentity.Process, family: String, socketPath: String) -> Bool {
        let flowPid = source.identity.pid, flowUid = source.identity.uid
        guard let remoteEndpoint = tcpFlow.remoteEndpoint as? NWHostEndpoint else {
            closeFlowImmediately(tcpFlow, reason: "invalid_remote_endpoint")
            return true
        }

        let targetHost = remoteEndpoint.hostname
        let targetPort = remoteEndpoint.port
        guard let current = ChannelCodeIdentity.process(pid: flowPid, token: source.token),
              source.identity.matches(current.identity) else {
            closeFlowImmediately(tcpFlow, reason: "source_process_unavailable")
            return true
        }
        let connection: GatewayConnection
        do { connection = try GatewayConnection(path: socketPath, expectedUID: controlUID) }
        catch { closeFlowImmediately(tcpFlow, reason: "gateway_unavailable"); return true }
        let flowID = UUID()
        stateLock.lock()
        guard isInterceptionActive, observationHealthy,
              let permit = families[family], permit.isLive,
              permit.processes.contains(where: { $0.matches(source.identity) }) else {
            stateLock.unlock()
            connection.cancel()
            closeFlowImmediately(tcpFlow, reason: "permit_changed_before_connect")
            return true
        }
        activeFlows[flowID] = ActiveFlowRecord(flow: tcpFlow, connection: connection, family: family, identity: source.identity)
        totalForwardedFlows += 1
        stateLock.unlock()

        // Extract Mach sourceAppAuditToken hex for authentic source verification
        var auditTokenHex = ""
        if let auditTokenData = tcpFlow.metaData.sourceAppAuditToken {
            auditTokenHex = auditTokenData.map { String(format: "%02x", $0) }.joined()
        }

        // Step 1: Send CONNECT handshake to local gateway with verified audit token
        let authority = targetHost.contains(":") && !targetHost.hasPrefix("[") ? "[\(targetHost)]:\(targetPort)" : "\(targetHost):\(targetPort)"
        let connectReq = "CONNECT \(authority) HTTP/1.1\r\nHost: \(authority)\r\nX-Watch-PID: \(flowPid)\r\nX-Watch-UID: \(flowUid)\r\nX-Watch-Audit-Token: \(auditTokenHex)\r\nX-Watch-Start-Seconds: \(source.identity.start_seconds)\r\nX-Watch-Start-Micros: \(source.identity.start_microseconds)\r\n\r\n"
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
                    // Step 3: Gateway tunnel established! Open client flow and start bidirectional data pump
                    tcpFlow.open(withLocalEndpoint: nil) { [weak self, weak tcpFlow, weak connection] openErr in
                        guard let self = self, let tcpFlow = tcpFlow, let connection = connection else { return }
                        if let openErr = openErr {
                            self.logger.error("Failed to open TCP flow to client: \(openErr.localizedDescription)")
                            self.cleanupFlow(id: flowID, error: openErr)
                            return
                        }

                        guard self.isForwardAuthorized(flowID: flowID, pid: flowPid) else {
                            // Revocation may have removed the record before
                            // this open callback arrived; close the flow itself.
                            self.closeFlowImmediately(tcpFlow, reason: "permit_changed_during_open")
                            self.cleanupFlow(id: flowID, error: nil)
                            return
                        }

                        let beginPumps = {
                            guard self.isForwardAuthorized(flowID: flowID, pid: flowPid) else {
                                self.closeFlowImmediately(tcpFlow, reason: "permit_changed_before_pump")
                                self.cleanupFlow(id: flowID, error: nil)
                                return
                            }
                            self.pumpClientToProxy(flowID: flowID, flow: tcpFlow, connection: connection)
                            self.pumpProxyToClient(flowID: flowID, flow: tcpFlow, connection: connection)
                        }
                        if remainingPayload.isEmpty { beginPumps() }
                        else {
                            tcpFlow.write(remainingPayload) { error in
                                if let error = error { self.cleanupFlow(id: flowID, error: error) }
                                else { beginPumps() }
                            }
                        }
                    }
                }
            }
        }
        return true
    }

    private func isForwardAuthorized(flowID: UUID, pid: UInt32) -> Bool {
        stateLock.lock(); defer { stateLock.unlock() }
        guard isInterceptionActive, observationHealthy,
              let record = activeFlows[flowID], record.connection.state == .connected,
              let permit = families[record.family] else { return false }
        return permit.isLive && record.identity.pid == pid && permit.processes.contains(where: { $0.matches(record.identity) })
    }

    /// Reads CONNECT response from gateway until full `\r\n\r\n` boundary is found, parsing the status line.
    private func readConnectResponseHeader(
        connection: GatewayConnection,
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

    private func pumpClientToProxy(flowID: UUID, flow: NEAppProxyTCPFlow, connection: GatewayConnection) {
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

    private func pumpProxyToClient(flowID: UUID, flow: NEAppProxyTCPFlow, connection: GatewayConnection) {
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
        stateLock.lock(); defer { stateLock.unlock() }
        guard let record = activeFlows[id] else { return }
        let abort = error ?? NSError(domain: NSPOSIXErrorDomain, code: Int(ECONNABORTED))
        record.flow.closeReadWithError(abort)
        record.flow.closeWriteWithError(abort)
        if record.connection.cancel() {
            activeFlows.removeValue(forKey: id)
            if families[record.family]?.permitted == false && !activeFlows.values.contains(where: { $0.family == record.family }) {
                families[record.family]?.status = "revoked"
                families[record.family]?.closingSince = nil
                families[record.family]?.appliedAt = Date().timeIntervalSince1970
            }
        } else {
            families[record.family]?.status = "failed"
            families[record.family]?.reason = "flow_close_failed"
        }
        writeReceiptsLocked()
    }
    private func terminateFlowsLocked(family: String?, keeping: (ChannelProcessIdentity) -> Bool = { _ in false }) {
        let abort = NSError(domain: NSPOSIXErrorDomain, code: Int(ECONNABORTED))
        for (id, record) in Array(activeFlows) where (family == nil || record.family == family) && !keeping(record.identity) {
            record.flow.closeReadWithError(abort)
            record.flow.closeWriteWithError(abort)
            if record.connection.cancel() { activeFlows.removeValue(forKey: id) }
        }
    }
    private func closeFlowImmediately(_ flow: NEAppProxyFlow, reason: String) {
        let abort = NSError(domain: NSPOSIXErrorDomain, code: Int(ECONNABORTED))
        if let tcp = flow as? NEAppProxyTCPFlow { tcp.closeReadWithError(abort); tcp.closeWriteWithError(abort) }
        if let udp = flow as? NEAppProxyUDPFlow { udp.closeReadWithError(abort); udp.closeWriteWithError(abort) }
        stateLock.lock(); totalBlockedFlows += 1; stateLock.unlock()
    }
    private func inspectFlowAttribution(_ flow: NEAppProxyFlow) -> (ChannelOwnership, ChannelCodeIdentity.Process?) {
        let signedTarget = channelIsManagedSigningID(flow.metaData.sourceAppSigningIdentifier)
        guard let words = ChannelCodeIdentity.words(flow.metaData.sourceAppAuditToken),
              let source = ChannelCodeIdentity.process(pid: words[5], token: flow.metaData.sourceAppAuditToken) else {
            stateLock.lock()
            let token = ChannelCodeIdentity.words(flow.metaData.sourceAppAuditToken)
            let knownTarget = token.map { words in
                ownership.contains(token: words) || managedProcesses.contains { $0.audit_token == words }
            } ?? false
            stateLock.unlock()
            return (channelOwnership(targetEvidence: signedTarget || knownTarget, identityConfirmed: false), nil)
        }
        stateLock.lock()
        let managed = managedProcesses
        let retained = ownership
        let home = stateDirectory?.home
        stateLock.unlock()
        // Resolve aliases before this flow's decision, including the first
        // flow after installation/update; do not wait for the next inventory.
        let aliases = channelResolvedCLIAliases(home: home)
        var current = source
        var visited: Set<UInt32> = []
        var isManaged = signedTarget
        for _ in 0..<64 {
            guard visited.insert(current.identity.pid).inserted else { break }
            if retained.contains(current.identity) || managed.contains(where: { $0.sameLifetime(current.identity) })
                || channelIsManagedExecutable(current.executable, home: home, aliases: aliases) {
                isManaged = true; break
            }
            if let code = ChannelCodeIdentity.code(current.token),
               let identifier = ChannelCodeIdentity.signingInfo(code)?[kSecCodeInfoIdentifier as String] as? String,
               channelIsManagedSigningID(identifier) { isManaged = true; break }
            if (["node", "nodejs", "bun"].contains(URL(fileURLWithPath: current.executable).lastPathComponent)
                || channelIsManagedAppServerPath(current.executable, home: home)),
               let invocation = ChannelCodeIdentity.invocation(current),
               channelIsManagedInvocation(executable: current.executable, arguments: invocation.arguments, cwd: invocation.cwd, home: home) {
                isManaged = true; break
            }
            if current.parent <= 1 { break }
            guard let parent = ChannelCodeIdentity.process(pid: current.parent) else { break }
            current = parent
        }
        if isManaged {
            stateLock.lock(); ownership.remember(source.identity); stateLock.unlock()
        }
        // Unknown software is outside this product's AI scope. Only positive
        // target evidence creates ownership; it never creates a permission.
        return (channelOwnership(targetEvidence: isManaged, identityConfirmed: true), source)
    }

}
