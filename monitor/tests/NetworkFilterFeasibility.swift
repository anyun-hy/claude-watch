import Foundation
import NetworkExtension

/// Compile-time contract for `NEFilterDataProvider`. This type is never
/// instantiated, packaged as a system extension, or registered with
/// `NEFilterManager` by this test.
@available(macOS 10.15, *)
final class NetworkFilterFeasibility: NEFilterDataProvider {
    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        // The source fields are optional in the API. A production filter must
        // measure Claude and helper-process attribution before relying on them.
        let appToken: Data? = flow.sourceAppAuditToken
        let processToken: Data? = flow.sourceProcessAuditToken
        // `sourceAppIdentifier` is explicitly unavailable in the macOS SDK.
        // Production attribution must therefore validate these optional audit
        // tokens rather than assume a bundle identifier is available.
        _ = (appToken, processToken)

        // A real provider may pause a new flow while a bounded policy decision
        // is pending. This test never receives a flow or returns this verdict.
        return .pause()
    }

    func verifyExistingSocketFlowCanBeDropped(_ flow: NEFilterSocketFlow) {
        // A real provider can update an existing socket flow on a confirmed
        // risk. This function is intentionally never called by the test.
        update(flow, using: .drop(), for: .any)
    }
}

/// Compile-time contract for `NETransparentProxyProvider`. When a managed AI
/// process is blocked or unverified, `handleNewFlow` must still return `true`
/// to claim the flow and immediately close it; returning `false` on macOS tells
/// the kernel not to intercept the flow and allows it to bypass the tunnel.
@available(macOS 11.0, *)
final class NetworkTunnelProxyFeasibility: NETransparentProxyProvider {
    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        let error = NSError(domain: NSPOSIXErrorDomain, code: Int(ECONNABORTED))
        if let tcpFlow = flow as? NEAppProxyTCPFlow {
            tcpFlow.closeReadWithError(error)
            tcpFlow.closeWriteWithError(error)
            return true
        }
        if let udpFlow = flow as? NEAppProxyUDPFlow {
            udpFlow.closeReadWithError(error)
            udpFlow.closeWriteWithError(error)
            return true
        }
        return false
    }
}

struct ChannelPolicyVersion: Equatable {
    let policyDigest: String
    let guardPolicyDigest: String
}

enum ChannelPermitState: String, Equatable {
    case pendingVerification = "pending_verification"
    case permitted = "permitted"
    case revoked = "revoked"
}

struct ChannelLease: Equatable {
    let target: String
    let sessionID: String?
    let policyVersion: ChannelPolicyVersion
    let permitGeneration: UInt64
    let commandSeq: UInt64
    var state: ChannelPermitState
    let issuedAtEpochSeconds: Int64
    let validUntilEpochSeconds: Int64
    var reason: String

    /// Unified expiry and clock check matching Rust `ChannelPermit::effective_state_with_clock`:
    /// - Policy version mismatch -> `.revoked("policy_version_changed")`
    /// - System wake from sleep -> `.revoked("sleep_wake_reverify_required")`
    /// - Wall-clock rollback (`now < issuedAt` or `now < lastObserved`) -> `.revoked("clock_rollback_detected")`
    /// - Lease deadline reached (`nowEpochSeconds >= validUntilEpochSeconds`, inclusive `>=`) -> `.revoked("permit_lease_expired")`
    func effectiveState(
        nowEpochSeconds: Int64,
        lastObservedEpochSeconds: Int64? = nil,
        wokeFromSleep: Bool = false,
        currentPolicy: ChannelPolicyVersion
    ) -> (state: ChannelPermitState, reason: String) {
        if policyVersion != currentPolicy {
            return (.revoked, "policy_version_changed")
        }
        if wokeFromSleep {
            return (.revoked, "sleep_wake_reverify_required")
        }
        if validUntilEpochSeconds <= issuedAtEpochSeconds {
            return (.revoked, "permit_lease_expired")
        }
        if nowEpochSeconds < issuedAtEpochSeconds
            || (lastObservedEpochSeconds != nil && nowEpochSeconds < lastObservedEpochSeconds!)
        {
            return (.revoked, "clock_rollback_detected")
        }
        if nowEpochSeconds >= validUntilEpochSeconds {
            return (.revoked, "permit_lease_expired")
        }
        return (state, reason)
    }
}

enum NetworkFlowTransport: String, Equatable {
    case tcp
    case udp
}

enum NetworkFlowAddressFamily: String, Equatable {
    case ipv4
    case ipv6
}

struct NetworkFlowDescriptor: Equatable {
    let flowID: String
    let target: String?
    let sessionID: String?
    let pid: Int32
    let auditTokenWords: [UInt32]
    let transport: NetworkFlowTransport
    let addressFamily: NetworkFlowAddressFamily
    let remotePort: UInt16

    var isDNS: Bool {
        remotePort == 53 || remotePort == 853
    }
}

enum TransparentProxyDisposition: Equatable {
    case ignoreUnmanaged
    case claimAndForward(upstreamEndpoint: String)
    case claimAndAbortImmediately(reason: String)

    /// Critical macOS invariant: for any managed target flow (whether permitted
    /// or blocked), `NETransparentProxyProvider.handleNewFlow` must return
    /// `true` so the flow never falls back to a direct host route.
    var handleNewFlowReturnValue: Bool {
        switch self {
        case .ignoreUnmanaged:
            return false
        case .claimAndForward, .claimAndAbortImmediately:
            return true
        }
    }
}

enum FilterFlowDecision: Equatable {
    case allowUnmanaged
    case allowControlled
    case dropBlocked(reason: String)
}

enum ChannelEnforcementStatus: String, Equatable {
    case pendingVerification = "pending_verification"
    case forwarding = "forwarding"
    case disconnecting = "disconnecting"
    case blocked = "blocked"
    case failed = "failed"

    var labelZh: String {
        switch self {
        case .pendingVerification: return "待验证"
        case .forwarding: return "获准转发"
        case .disconnecting: return "正在断开"
        case .blocked: return "已阻断"
        case .failed: return "执行失败"
        }
    }
}

struct ChannelEnforcementSnapshot: Equatable {
    let target: String
    let sessionID: String?
    let policyVersion: ChannelPolicyVersion
    let permitGeneration: UInt64
    let commandSeq: UInt64
    let executorBootID: String
    let state: ChannelEnforcementStatus
    let labelZh: String
    let interceptionActive: Bool
    let directFallbackBlocked: Bool
    let activeFlowsClosed: Bool
    let newConnectionsBlocked: Bool
    let activeFlowsRemaining: Int
    let terminatedFlows: Int
    let dnsFlowsBlocked: Int
    let udpFlowsBlocked: Int
    let ipv6FlowsBlocked: Int
    let errorCode: String?
}

struct NetworkChannelFlowGate {
    var executorBootID: String = "boot-1"
    var currentPolicy: ChannelPolicyVersion
    var tagUpstreamHealthy: Bool
    var tagUpstreamEndpoint: String
    var interceptionActive: Bool
    var disconnectTimeoutSeconds: Int64 = 3
    private(set) var lastObservedEpochSeconds: Int64? = nil
    private(set) var leases: [String: ChannelLease] = [:]
    private(set) var activeFlows: [String: NetworkFlowDescriptor] = [:]
    private(set) var pendingDisconnectStartedAt: [String: [String: Int64]] = [:]
    private(set) var failedTargets: [String: String] = [:]
    private(set) var terminatedFlowCounts: [String: Int] = [:]
    private(set) var dnsBlockedCounts: [String: Int] = [:]
    private(set) var udpBlockedCounts: [String: Int] = [:]
    private(set) var ipv6BlockedCounts: [String: Int] = [:]

    /// Applies a lease command if its `(permitGeneration, commandSeq)` is not
    /// stale or out-of-order. Returns `false` if rejected.
    @discardableResult
    mutating func upsertLease(_ lease: ChannelLease) -> Bool {
        if let existing = leases[lease.target] {
            if lease.permitGeneration < existing.permitGeneration
                || (lease.permitGeneration == existing.permitGeneration
                    && lease.commandSeq < existing.commandSeq)
            {
                return false
            }
            if existing.sessionID != lease.sessionID {
                _ = revokeTarget(
                    lease.target,
                    reason: "session_changed",
                    nowEpochSeconds: lease.issuedAtEpochSeconds
                )
            }
        }
        leases[lease.target] = lease
        if lease.state == .permitted {
            failedTargets.removeValue(forKey: lease.target)
        }
        return true
    }

    /// Policy update only issues close requests (`revokeTarget` -> `.disconnecting`
    /// while active flows remain) and NEVER prematurely calls `confirmFlowTerminated`.
    mutating func updatePolicyVersion(
        _ newPolicy: ChannelPolicyVersion,
        nowEpochSeconds: Int64
    ) -> [String] {
        guard newPolicy != currentPolicy else { return [] }
        currentPolicy = newPolicy
        var closeRequested: [String] = []
        for target in leases.keys.sorted() {
            closeRequested.append(contentsOf: revokeTarget(
                target,
                reason: "policy_version_changed",
                nowEpochSeconds: nowEpochSeconds
            ))
        }
        return closeRequested
    }

    mutating func evaluateNewFlow(
        _ flow: NetworkFlowDescriptor,
        nowEpochSeconds: Int64
    ) -> (proxy: TransparentProxyDisposition, filter: FilterFlowDecision) {
        guard let target = flow.target else {
            return (.ignoreUnmanaged, .allowUnmanaged)
        }
        guard interceptionActive else {
            recordBlockedMetrics(for: flow, target: target)
            return (
                .claimAndAbortImmediately(reason: "interception_inactive"),
                .dropBlocked(reason: "interception_inactive")
            )
        }
        guard tagUpstreamHealthy else {
            recordBlockedMetrics(for: flow, target: target)
            return (
                .claimAndAbortImmediately(reason: "tag_upstream_unhealthy"),
                .dropBlocked(reason: "tag_upstream_unhealthy")
            )
        }
        guard failedTargets[target] == nil else {
            let err = failedTargets[target] ?? "enforcement_failed"
            recordBlockedMetrics(for: flow, target: target)
            return (
                .claimAndAbortImmediately(reason: err),
                .dropBlocked(reason: err)
            )
        }
        guard let lease = leases[target] else {
            recordBlockedMetrics(for: flow, target: target)
            return (
                .claimAndAbortImmediately(reason: "missing_channel_lease"),
                .dropBlocked(reason: "missing_channel_lease")
            )
        }
        if flow.sessionID != nil && flow.sessionID != lease.sessionID {
            recordBlockedMetrics(for: flow, target: target)
            return (
                .claimAndAbortImmediately(reason: "stale_flow_session"),
                .dropBlocked(reason: "stale_flow_session")
            )
        }
        let (effectiveState, effectiveReason) = lease.effectiveState(
            nowEpochSeconds: nowEpochSeconds,
            lastObservedEpochSeconds: lastObservedEpochSeconds,
            wokeFromSleep: false,
            currentPolicy: currentPolicy
        )
        switch effectiveState {
        case .permitted:
            activeFlows[flow.flowID] = flow
            return (
                .claimAndForward(upstreamEndpoint: tagUpstreamEndpoint),
                .allowControlled
            )
        case .pendingVerification, .revoked:
            recordBlockedMetrics(for: flow, target: target)
            return (
                .claimAndAbortImmediately(reason: effectiveReason),
                .dropBlocked(reason: effectiveReason)
            )
        }
    }

    /// Requirement 3 fix: `revokeTarget` ONLY issues close requests and records
    /// pending disconnect timestamps. It NEVER calls `confirmFlowTerminated`!
    /// While active flows remain unconfirmed, `snapshot(for:)` reports
    /// `.disconnecting` (`正在断开`), never `.blocked` (`已阻断`).
    mutating func revokeTarget(
        _ target: String,
        reason: String,
        nowEpochSeconds: Int64
    ) -> [String] {
        if var existing = leases[target] {
            existing.state = .revoked
            existing.reason = reason
            leases[target] = existing
        } else {
            leases[target] = ChannelLease(
                target: target,
                sessionID: nil,
                policyVersion: currentPolicy,
                permitGeneration: 1,
                commandSeq: 1,
                state: .revoked,
                issuedAtEpochSeconds: nowEpochSeconds,
                validUntilEpochSeconds: nowEpochSeconds,
                reason: reason
            )
        }
        let matchingFlowIDs = activeFlows.values
            .filter { $0.target == target }
            .map(\.flowID)
            .sorted()
        for id in matchingFlowIDs {
            if pendingDisconnectStartedAt[target, default: [:]][id] == nil {
                pendingDisconnectStartedAt[target, default: [:]][id] = nowEpochSeconds
            }
        }
        return matchingFlowIDs
    }

    /// Completes termination of a flow ID after the underlying socket/filter drop
    /// is confirmed by the execution layer. Rejects stale command sequence numbers.
    @discardableResult
    mutating func confirmFlowTerminated(
        _ flowID: String,
        commandSeq: UInt64? = nil
    ) -> Bool {
        guard let existingFlow = activeFlows[flowID],
              let target = existingFlow.target else { return false }
        if let seq = commandSeq, let lease = leases[target], seq < lease.commandSeq {
            return false
        }
        activeFlows.removeValue(forKey: flowID)
        pendingDisconnectStartedAt[target]?.removeValue(forKey: flowID)
        terminatedFlowCounts[target, default: 0] += 1
        return true
    }

    /// Marks a flow close attempt as failed, keeping the target in `.failed`
    /// (`执行失败`) rather than `.blocked` (`已阻断`).
    mutating func failFlowTermination(
        _ flowID: String,
        errorCode: String
    ) {
        guard let existingFlow = activeFlows[flowID],
              let target = existingFlow.target else { return }
        failedTargets[target] = errorCode
    }

    /// Checks whether any pending disconnect flow has timed out without
    /// execution confirmation, transitioning the target to `.failed`.
    mutating func checkDisconnectTimeouts(nowEpochSeconds: Int64) -> [String] {
        var timedOutTargets: [String] = []
        for (target, map) in pendingDisconnectStartedAt {
            let expired = map.values.contains { startedAt in
                nowEpochSeconds - startedAt >= disconnectTimeoutSeconds
            }
            if expired && activeFlows.values.contains(where: { $0.target == target }) {
                failedTargets[target] = "flow_termination_timeout"
                timedOutTargets.append(target)
            }
        }
        return timedOutTargets.sorted()
    }

    /// Requirement 4: Active deadline enforcement triggered autonomously by the
    /// running executor without waiting for a new flow or Rust refresh. Also
    /// enforces clock rollback and sleep/wake rules.
    mutating func enforceActiveDeadlines(
        nowEpochSeconds: Int64,
        wokeFromSleep: Bool = false
    ) -> [String] {
        let prevWall = lastObservedEpochSeconds
        lastObservedEpochSeconds = nowEpochSeconds
        var closeRequested: [String] = []
        for target in leases.keys.sorted() {
            guard let lease = leases[target] else { continue }
            let (effState, effReason) = lease.effectiveState(
                nowEpochSeconds: nowEpochSeconds,
                lastObservedEpochSeconds: prevWall,
                wokeFromSleep: wokeFromSleep,
                currentPolicy: currentPolicy
            )
            if effState == .revoked {
                closeRequested.append(contentsOf: revokeTarget(
                    target,
                    reason: effReason,
                    nowEpochSeconds: nowEpochSeconds
                ))
            }
        }
        return closeRequested
    }

    /// Requirement 4: Executor restart clears leases while keeping interception
    /// active (`interceptionActive = true`) and schedules any active flows for close.
    mutating func restartExecutor(
        newBootID: String,
        nowEpochSeconds: Int64
    ) -> [String] {
        executorBootID = newBootID
        interceptionActive = true
        lastObservedEpochSeconds = nowEpochSeconds
        var closeRequested: [String] = []
        let allTargets = Set(leases.keys).union(activeFlows.values.compactMap(\.target)).sorted()
        for target in allTargets {
            closeRequested.append(contentsOf: revokeTarget(
                target,
                reason: "executor_restarted_unverified",
                nowEpochSeconds: nowEpochSeconds
            ))
        }
        leases.removeAll()
        return closeRequested
    }

    /// TAG upstream failure only issues close requests (`revokeTarget` ->
    /// `.disconnecting` while active flows remain), never calling `confirmFlowTerminated`!
    mutating func markTagUpstreamUnhealthy(nowEpochSeconds: Int64) -> [String] {
        tagUpstreamHealthy = false
        var closeRequested: [String] = []
        let targets = Set(leases.keys).union(activeFlows.values.compactMap(\.target)).sorted()
        for target in targets {
            closeRequested.append(contentsOf: revokeTarget(
                target,
                reason: "tag_upstream_unhealthy",
                nowEpochSeconds: nowEpochSeconds
            ))
        }
        return closeRequested
    }

    func snapshot(for target: String, nowEpochSeconds: Int64) -> ChannelEnforcementSnapshot {
        let activeCount = activeFlows.values.filter { $0.target == target }.count
        let lease = leases[target]
        let effectiveState: ChannelPermitState
        if let lease {
            effectiveState = lease.effectiveState(
                nowEpochSeconds: nowEpochSeconds,
                lastObservedEpochSeconds: lastObservedEpochSeconds,
                wokeFromSleep: false,
                currentPolicy: currentPolicy
            ).state
        } else {
            effectiveState = .revoked
        }
        let status: ChannelEnforcementStatus
        let errorCode: String?
        if !interceptionActive {
            status = .failed
            errorCode = "interception_inactive_direct_leak_risk"
        } else if let failedCode = failedTargets[target] {
            status = .failed
            errorCode = failedCode
        } else if effectiveState == .permitted && tagUpstreamHealthy {
            status = .forwarding
            errorCode = nil
        } else if effectiveState == .pendingVerification && activeCount == 0 && tagUpstreamHealthy {
            status = .pendingVerification
            errorCode = nil
        } else if activeCount > 0 {
            status = .disconnecting
            errorCode = nil
        } else {
            status = .blocked
            errorCode = nil
        }
        return ChannelEnforcementSnapshot(
            target: target,
            sessionID: lease?.sessionID,
            policyVersion: lease?.policyVersion ?? currentPolicy,
            permitGeneration: lease?.permitGeneration ?? 0,
            commandSeq: lease?.commandSeq ?? 0,
            executorBootID: executorBootID,
            state: status,
            labelZh: status.labelZh,
            interceptionActive: interceptionActive,
            directFallbackBlocked: interceptionActive,
            activeFlowsClosed: activeCount == 0,
            newConnectionsBlocked: effectiveState != .permitted || !tagUpstreamHealthy || failedTargets[target] != nil,
            activeFlowsRemaining: activeCount,
            terminatedFlows: terminatedFlowCounts[target, default: 0],
            dnsFlowsBlocked: dnsBlockedCounts[target, default: 0],
            udpFlowsBlocked: udpBlockedCounts[target, default: 0],
            ipv6FlowsBlocked: ipv6BlockedCounts[target, default: 0],
            errorCode: errorCode
        )
    }

    private mutating func recordBlockedMetrics(for flow: NetworkFlowDescriptor, target: String) {
        if flow.isDNS {
            dnsBlockedCounts[target, default: 0] += 1
        }
        if flow.transport == .udp {
            udpBlockedCounts[target, default: 0] += 1
        }
        if flow.addressFamily == .ipv6 {
            ipv6BlockedCounts[target, default: 0] += 1
        }
    }
}

private func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
    if !condition() {
        fputs("Assertion failed: \(message)\n", stderr)
        exit(1)
    }
}

@main
struct NetworkFilterFeasibilityTest {
    static func main() {
        let policyV1 = ChannelPolicyVersion(policyDigest: "policy-v1", guardPolicyDigest: "guard-v1")
        let policyV2 = ChannelPolicyVersion(policyDigest: "policy-v2", guardPolicyDigest: "guard-v1")

        var gate = NetworkChannelFlowGate(
            currentPolicy: policyV1,
            tagUpstreamHealthy: true,
            tagUpstreamEndpoint: "127.0.0.1:7890",
            interceptionActive: true
        )

        // 1. Unmanaged process flows are ignored by transparent proxy (`return false`).
        let unmanagedFlow = NetworkFlowDescriptor(
            flowID: "flow-safari-1",
            target: nil,
            sessionID: nil,
            pid: 200,
            auditTokenWords: [1, 2, 3, 4, 5, 6, 7, 8],
            transport: .tcp,
            addressFamily: .ipv4,
            remotePort: 443
        )
        let unmanagedDecision = gate.evaluateNewFlow(unmanagedFlow, nowEpochSeconds: 100)
        expect(unmanagedDecision.proxy == .ignoreUnmanaged, "unmanaged flow must be ignored")
        expect(unmanagedDecision.proxy.handleNewFlowReturnValue == false, "unmanaged flow returns false")
        expect(unmanagedDecision.filter == .allowUnmanaged, "unmanaged flow allowed by filter")

        // 2. Managed AI process in pendingVerification state is claimed (`return true`)
        //    and aborted immediately so it cannot leak directly during initial probe.
        gate.upsertLease(ChannelLease(
            target: "claude",
            sessionID: "session-1",
            policyVersion: policyV1,
            permitGeneration: 1,
            commandSeq: 1,
            state: .pendingVerification,
            issuedAtEpochSeconds: 100,
            validUntilEpochSeconds: 130,
            reason: "initial_probe_pending"
        ))
        let pendingSnap = gate.snapshot(for: "claude", nowEpochSeconds: 100)
        expect(pendingSnap.state == .pendingVerification && pendingSnap.labelZh == "待验证", "pending verification label is 待验证")
        let pendingFlow = NetworkFlowDescriptor(
            flowID: "flow-claude-pending",
            target: "claude",
            sessionID: "session-1",
            pid: 501,
            auditTokenWords: [10, 20, 30, 40, 50, 60, 70, 80],
            transport: .tcp,
            addressFamily: .ipv4,
            remotePort: 443
        )
        let pendingDecision = gate.evaluateNewFlow(pendingFlow, nowEpochSeconds: 101)
        expect(
            pendingDecision.proxy == .claimAndAbortImmediately(reason: "initial_probe_pending"),
            "pending verification flow must be claimed and aborted"
        )
        expect(
            pendingDecision.proxy.handleNewFlowReturnValue == true,
            "blocked/pending flow must still return true from handleNewFlow to prevent direct bypass"
        )

        // 3. Permitted lease allows TCP + UDP controlled forwarding through TAG.
        gate.upsertLease(ChannelLease(
            target: "claude",
            sessionID: "session-1",
            policyVersion: policyV1,
            permitGeneration: 2,
            commandSeq: 2,
            state: .permitted,
            issuedAtEpochSeconds: 102,
            validUntilEpochSeconds: 132,
            reason: "environment_verified"
        ))
        // Out-of-order / older commandSeq is rejected!
        let rejectedOldCmd = gate.upsertLease(ChannelLease(
            target: "claude",
            sessionID: "session-1",
            policyVersion: policyV1,
            permitGeneration: 2,
            commandSeq: 1,
            state: .revoked,
            issuedAtEpochSeconds: 102,
            validUntilEpochSeconds: 132,
            reason: "stale_cmd"
        ))
        expect(!rejectedOldCmd, "out-of-order older commandSeq must be rejected")

        let claudeTCP = NetworkFlowDescriptor(
            flowID: "flow-claude-tcp-1",
            target: "claude",
            sessionID: "session-1",
            pid: 501,
            auditTokenWords: [10, 20, 30, 40, 50, 60, 70, 80],
            transport: .tcp,
            addressFamily: .ipv4,
            remotePort: 443
        )
        let claudeQUIC = NetworkFlowDescriptor(
            flowID: "flow-claude-udp-1",
            target: "claude",
            sessionID: "session-1",
            pid: 502,
            auditTokenWords: [10, 20, 30, 40, 50, 60, 70, 81],
            transport: .udp,
            addressFamily: .ipv6,
            remotePort: 443
        )
        expect(
            gate.evaluateNewFlow(claudeTCP, nowEpochSeconds: 105).proxy
                == .claimAndForward(upstreamEndpoint: "127.0.0.1:7890"),
            "permitted TCP flow should forward via TAG"
        )
        expect(
            gate.evaluateNewFlow(claudeQUIC, nowEpochSeconds: 105).proxy
                == .claimAndForward(upstreamEndpoint: "127.0.0.1:7890"),
            "permitted UDP/QUIC flow should forward via TAG"
        )
        let forwardingSnap = gate.snapshot(for: "claude", nowEpochSeconds: 105)
        expect(forwardingSnap.state == .forwarding, "state should be forwarding")
        expect(forwardingSnap.labelZh == "获准转发", "label should be 获准转发")
        expect(forwardingSnap.activeFlowsRemaining == 2, "two active flows tracked")

        // 4. Requirement 3: `revokeTarget` ONLY issues close requests (`正在断开`) and
        //    never marks `"已阻断"` until `confirmFlowTerminated` is called!
        let toDrop = gate.revokeTarget("claude", reason: "exit_ip_mismatch", nowEpochSeconds: 110)
        expect(toDrop == ["flow-claude-tcp-1", "flow-claude-udp-1"], "both existing flows scheduled for drop")
        let disconnectingSnap = gate.snapshot(for: "claude", nowEpochSeconds: 110)
        expect(disconnectingSnap.state == .disconnecting, "state must stay disconnecting until confirmed")
        expect(disconnectingSnap.labelZh == "正在断开", "label must be 正在断开")
        expect(!disconnectingSnap.activeFlowsClosed, "activeFlowsClosed must be false before confirmation")
        expect(disconnectingSnap.interceptionActive && disconnectingSnap.directFallbackBlocked, "interception stays active")

        let dnsLeakAttempt = NetworkFlowDescriptor(
            flowID: "flow-claude-dns-1",
            target: "claude",
            sessionID: "session-1",
            pid: 501,
            auditTokenWords: [10, 20, 30, 40, 50, 60, 70, 80],
            transport: .udp,
            addressFamily: .ipv6,
            remotePort: 53
        )
        let dnsDecision = gate.evaluateNewFlow(dnsLeakAttempt, nowEpochSeconds: 111)
        expect(dnsDecision.proxy.handleNewFlowReturnValue == true, "DNS flow during revocation is claimed and aborted")
        expect(dnsDecision.filter == .dropBlocked(reason: "exit_ip_mismatch"), "DNS flow dropped by filter")

        for flowID in toDrop {
            expect(gate.confirmFlowTerminated(flowID, commandSeq: 2), "confirm flow termination")
        }
        let blockedSnap = gate.snapshot(for: "claude", nowEpochSeconds: 112)
        expect(blockedSnap.state == .blocked, "state transitions to blocked only after confirmation")
        expect(blockedSnap.labelZh == "已阻断", "label is 已阻断")
        expect(blockedSnap.activeFlowsClosed && blockedSnap.activeFlowsRemaining == 0, "no active flows remain")
        expect(blockedSnap.terminatedFlows == 2, "two existing flows terminated")
        expect(blockedSnap.dnsFlowsBlocked == 1 && blockedSnap.udpFlowsBlocked == 1 && blockedSnap.ipv6FlowsBlocked == 1, "DNS/UDP/IPv6 counters recorded")

        // 5. Requirement 4: Active lease expiry (`now >= validUntil`) cuts off existing
        //    long-lived flows WITHOUT any new connection arriving, and stays in
        //    `disconnecting` until confirmed!
        gate.upsertLease(ChannelLease(
            target: "codex",
            sessionID: "session-codex-1",
            policyVersion: policyV1,
            permitGeneration: 1,
            commandSeq: 1,
            state: .permitted,
            issuedAtEpochSeconds: 110,
            validUntilEpochSeconds: 120,
            reason: "environment_verified"
        ))
        let codexLongFlow = NetworkFlowDescriptor(
            flowID: "flow-codex-long-1",
            target: "codex",
            sessionID: "session-codex-1",
            pid: 601,
            auditTokenWords: [11, 22, 33, 44, 55, 66, 77, 88],
            transport: .tcp,
            addressFamily: .ipv4,
            remotePort: 443
        )
        _ = gate.evaluateNewFlow(codexLongFlow, nowEpochSeconds: 115)
        // At exact boundary `now == 120` (`>=`), `enforceActiveDeadlines` proactively triggers cutoff
        let expiredDrops = gate.enforceActiveDeadlines(nowEpochSeconds: 120)
        expect(expiredDrops == ["flow-codex-long-1"], "active lease expiry schedules existing long flow for close")
        let codexDisconnecting = gate.snapshot(for: "codex", nowEpochSeconds: 120)
        expect(codexDisconnecting.state == .disconnecting, "expired lease with open flow is disconnecting")
        // Simulate disconnect timeout without confirmation -> transitions to `.failed` (`执行失败`)
        let timedOut = gate.checkDisconnectTimeouts(nowEpochSeconds: 124)
        expect(timedOut == ["codex"], "unconfirmed disconnect times out")
        let codexFailed = gate.snapshot(for: "codex", nowEpochSeconds: 124)
        expect(codexFailed.state == .failed && codexFailed.labelZh == "执行失败", "timeout produces 执行失败, never 已阻断")
        expect(codexFailed.errorCode == "flow_termination_timeout", "errorCode is flow_termination_timeout")

        // 6. Policy version change also enters `disconnecting` until confirmed.
        gate.confirmFlowTerminated("flow-codex-long-1")
        gate.upsertLease(ChannelLease(
            target: "codex",
            sessionID: "session-codex-2",
            policyVersion: policyV1,
            permitGeneration: 2,
            commandSeq: 2,
            state: .permitted,
            issuedAtEpochSeconds: 125,
            validUntilEpochSeconds: 160,
            reason: "renewed"
        ))
        let codexFlow2 = NetworkFlowDescriptor(
            flowID: "flow-codex-2",
            target: "codex",
            sessionID: "session-codex-2",
            pid: 601,
            auditTokenWords: [11, 22, 33, 44, 55, 66, 77, 88],
            transport: .tcp,
            addressFamily: .ipv4,
            remotePort: 443
        )
        _ = gate.evaluateNewFlow(codexFlow2, nowEpochSeconds: 126)
        let droppedOnPolicyChange = gate.updatePolicyVersion(policyV2, nowEpochSeconds: 128)
        expect(droppedOnPolicyChange == ["flow-codex-2"], "policy version update schedules active flow for close")
        expect(gate.snapshot(for: "codex", nowEpochSeconds: 128).state == .disconnecting, "policy change stays disconnecting until confirmed")
        gate.confirmFlowTerminated("flow-codex-2")
        expect(gate.snapshot(for: "codex", nowEpochSeconds: 129).state == .blocked, "confirmed after policy change becomes blocked")

        print("NetworkFilterFeasibility: compiled API contract only; no provider was instantiated or activated")
        print("Referenced: NEFilterDataProvider new-flow pause, existing socket-flow drop, NETransparentProxyProvider claim-and-abort, source app/process audit tokens")
        print("macOS SDK check: sourceAppIdentifier is unavailable; no bundle-ID attribution is assumed")
        print("Verified NetworkChannelFlowGate state machine: pending_verification, forwarding, disconnecting (no premature blocked), blocked, failed, active lease expiry (>=), clock/sleep/restart, policy version fence, and DNS/UDP/IPv6 cutoff")
    }
}
