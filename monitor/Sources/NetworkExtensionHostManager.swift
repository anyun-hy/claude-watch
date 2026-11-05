import Foundation
import NetworkExtension
import SystemExtensions
import Combine
import Security

/// Lifecycle and activation state of the system network extension.
public struct NetworkExtensionActivationState: Equatable, Sendable {
    public let isSystemExtensionActive: Bool
    public let isTunnelActive: Bool
    public let detail: String
    public let lastErrorCode: String?

    public static let initial = NetworkExtensionActivationState(
        isSystemExtensionActive: false,
        isTunnelActive: false,
        detail: "网络扩展未激活",
        lastErrorCode: nil
    )
}

/// Host-side manager for NetworkExtension transparent proxy lifecycle and activation.
///
/// Apple NetworkExtension Architecture Alignment:
/// - NETransparentProxyManager inherits from NEVPNManager.
/// - In the Apple macOS SDK, NETransparentProxyManager uses NETunnelProviderProtocol as its
///   underlying protocolConfiguration and NETunnelProviderSession as its active connection type.
///   This is the official, documented Apple design (not a misconfiguration or packet-tunnel mix-up).
/// - The extension bundle conforms to `com.apple.networkextension.app-proxy` with provider class
///   `WatchChannelExtension` inheriting from `NETransparentProxyProvider`.
@available(macOS 11.0, *)
public final class NetworkExtensionHostManager: NSObject, OSSystemExtensionRequestDelegate, ObservableObject {
    public static let shared = NetworkExtensionHostManager()

    public static let extensionBundleIdentifier = "io.local.watchpanel.network-extension"

    @Published public private(set) var activationState: NetworkExtensionActivationState = .initial

    private var targetProviderManager: NETransparentProxyManager?
    private var isSettingUpConfiguration: Bool = false

    public override init() {
        super.init()
        startAndActivateIfNeeded()
    }

    /// Do not request installation with ad-hoc signing or absent host entitlement.
    private func canInstallSystemExtension() -> Bool {
        guard let task = SecTaskCreateFromSelf(nil) else { return false }
        return SecTaskCopyValueForEntitlement(
            task, "com.apple.developer.system-extension.install" as CFString, nil
        ) as? Bool == true
    }

    public func startAndActivateIfNeeded() {
        guard canInstallSystemExtension() else {
            let unavailable = NetworkExtensionActivationState(
                isSystemExtensionActive: false,
                isTunnelActive: false,
                detail: "应用未具备系统扩展安装权限，请使用已授权的开发者签名",
                lastErrorCode: "missing_system_extension_entitlement"
            )
            activationState = unavailable
            persistActivationStatus(state: unavailable)
            return
        }
        refreshStatus { [weak self] ready in
            guard let self = self else { return }
            if !ready { self.requestActivation() }
        }
    }

    /// Checks the current system extension and transparent proxy tunnel status.
    public func refreshStatus(completion: ((Bool) -> Void)? = nil) {
        NETransparentProxyManager.loadAllFromPreferences { [weak self] managers, error in
            guard let self = self else {
                completion?(false)
                return
            }
            if let error = error {
                DispatchQueue.main.async {
                    let failState = NetworkExtensionActivationState(
                        isSystemExtensionActive: false,
                        isTunnelActive: false,
                        detail: "读取透明代理配置失败: \(error.localizedDescription)",
                        lastErrorCode: "preferences_load_failed"
                    )
                    self.activationState = failState
                    self.persistActivationStatus(state: failState)
                }
                completion?(false)
                return
            }

            let manager = managers?.first { mgr in
                (mgr.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == Self.extensionBundleIdentifier
            }
            self.targetProviderManager = manager

            let isEnabled = manager?.isEnabled ?? false
            let isConnected = isEnabled && manager?.connection.status == .connected

            // If configured and enabled but tunnel is disconnected, attempt to connect
            if isEnabled && !isConnected, let session = manager?.connection as? NETunnelProviderSession {
                if session.status == .disconnected || session.status == .invalid {
                    do {
                        try session.startTunnel(options: nil)
                    } catch {
                        self.recordExtensionFailure(reason: "start_tunnel_failed: \(error.localizedDescription)")
                    }
                }
            }

            DispatchQueue.main.async {
                let newState = NetworkExtensionActivationState(
                    // Preferences enabled does not prove the provider is running.
                    isSystemExtensionActive: isConnected,
                    isTunnelActive: isConnected,
                    detail: isConnected ? "透明代理已连接（待执行回执确认保护）" : (isEnabled ? "配置存在，尚未确认网络接管" : "网络扩展未启用"),
                    lastErrorCode: nil
                )
                self.activationState = newState
                self.persistActivationStatus(state: newState)
            }
            completion?(isEnabled && isConnected)
        }
    }

    /// Sets up and enables transparent proxy configuration via NETransparentProxyManager.
    public func setupAndEnableTransparentProxyConfiguration(completion: ((Bool) -> Void)? = nil) {
        guard !isSettingUpConfiguration else {
            completion?(false)
            return
        }
        isSettingUpConfiguration = true

        NETransparentProxyManager.loadAllFromPreferences { [weak self] managers, error in
            guard let self = self else {
                completion?(false)
                return
            }
            let manager = managers?.first { mgr in
                (mgr.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == Self.extensionBundleIdentifier
            } ?? NETransparentProxyManager()

            let proto = (manager.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
            proto.providerBundleIdentifier = Self.extensionBundleIdentifier
            proto.serverAddress = "127.0.0.1"

            manager.protocolConfiguration = proto
            manager.localizedDescription = "Claude Watch Transparent Proxy"
            manager.isEnabled = true

            manager.saveToPreferences { [weak self] saveErr in
                guard let self = self else {
                    completion?(false)
                    return
                }
                self.isSettingUpConfiguration = false
                if let saveErr = saveErr {
                    NSLog("[NetworkExtensionHostManager] Failed to save transparent proxy preferences: %@", saveErr.localizedDescription)
                    self.recordExtensionFailure(reason: "save_preferences_failed: \(saveErr.localizedDescription)")
                    completion?(false)
                    return
                }

                // Reload to acquire system-assigned session
                NETransparentProxyManager.loadAllFromPreferences { reloadedManagers, _ in
                    let readyMgr = reloadedManagers?.first {
                        ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == Self.extensionBundleIdentifier
                    }
                    self.targetProviderManager = readyMgr
                    if let session = readyMgr?.connection as? NETunnelProviderSession, readyMgr?.isEnabled == true {
                        do {
                            try session.startTunnel(options: nil)
                        } catch {
                            NSLog("[NetworkExtensionHostManager] Failed to start transparent proxy tunnel: %@", error.localizedDescription)
                        }
                    }
                    self.refreshStatus()
                    completion?(readyMgr != nil && readyMgr?.isEnabled == true)
                }
            }
        }
    }

    /// Requests system extension installation and activation via `OSSystemExtensionRequest`.
    public func requestActivation() {
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: Self.extensionBundleIdentifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    /// Requests deactivation of the system extension.
    public func requestDeactivation() {
        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: Self.extensionBundleIdentifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    // MARK: - OSSystemExtensionRequestDelegate

    public func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        return .replace
    }

    public func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        DispatchQueue.main.async {
            self.activationState = NetworkExtensionActivationState(
                isSystemExtensionActive: false,
                isTunnelActive: false,
                detail: "等待主公在系统偏好设置中允许扩展",
                lastErrorCode: "needs_user_approval"
            )
        }
    }

    public func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        let active = result == .completed
        DispatchQueue.main.async {
            self.activationState = NetworkExtensionActivationState(
                isSystemExtensionActive: active,
                isTunnelActive: false,
                detail: active ? "系统扩展安装成功，正在启动透明代理" : "系统扩展安装待重启",
                lastErrorCode: nil
            )
            // Immediately configure and start tunnel once extension activation succeeds
            if active {
                self.setupAndEnableTransparentProxyConfiguration { _ in
                    self.refreshStatus()
                }
            }
        }
    }

    public func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        let nsErr = error as NSError
        DispatchQueue.main.async {
            self.activationState = NetworkExtensionActivationState(
                isSystemExtensionActive: false,
                isTunnelActive: false,
                detail: "系统扩展激活失败: \(error.localizedDescription)",
                lastErrorCode: "activation_failed_\(nsErr.code)"
            )
        }
    }

    // MARK: - Extension IPC Communication

    /// Sends an IPC message to the running NetworkExtension provider via `NETunnelProviderSession.sendProviderMessage`.
    public func sendProviderMessage(_ message: [String: Any], completion: @escaping (Result<[String: Any], Error>) -> Void) {
        guard let manager = targetProviderManager,
              let session = manager.connection as? NETunnelProviderSession,
              manager.connection.status == .connected else {
            completion(.failure(NSError(domain: "NetworkExtensionHostManager", code: -1, userInfo: [NSLocalizedDescriptionKey: "Tunnel session is not connected"])))
            return
        }
        guard let data = try? JSONSerialization.data(withJSONObject: message) else {
            completion(.failure(NSError(domain: "NetworkExtensionHostManager", code: -2, userInfo: [NSLocalizedDescriptionKey: "Failed to serialize message"])))
            return
        }
        do {
            try session.sendProviderMessage(data) { responseData in
                guard let responseData = responseData,
                      let json = (try? JSONSerialization.jsonObject(with: responseData)) as? [String: Any] else {
                    completion(.success([:]))
                    return
                }
                completion(.success(json))
            }
        } catch {
            completion(.failure(error))
        }
    }

    /// Pushes a permit update to the extension.
    public func pushPermit(
        validUntil: Int64,
        permitState: String,
        allowedPids: [UInt32],
        localProxyPort: UInt16,
        policyVersion: String = "",
        commandSeq: UInt64 = 0,
        permitGeneration: UInt64 = 0,
        completion: @escaping (Bool) -> Void
    ) {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let secretFile = home.appendingPathComponent("Library/Application Support/ClaudeWatch/state/.extension-secret")
        let secret = (try? String(contentsOf: secretFile, encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

        var msg: [String: Any] = [
            "action": "update_permit",
            "valid_until": validUntil,
            "permit_state": permitState,
            "allowed_pids": allowedPids,
            "local_proxy_port": localProxyPort,
            "policy_version": policyVersion,
            "command_seq": commandSeq,
            "permit_generation": permitGeneration
        ]
        if !secret.isEmpty {
            msg["extension_secret"] = secret
        }
        sendProviderMessage(msg) { result in
            switch result {
            case .success(let resp):
                completion(resp["status"] as? String == "ok")
            case .failure:
                completion(false)
            }
        }
    }

    /// Revokes channel access in the extension.
    public func revokeChannel(
        reason: String,
        policyVersion: String = "",
        commandSeq: UInt64 = 0,
        permitGeneration: UInt64 = 0,
        completion: @escaping (Bool) -> Void
    ) {
        let msg: [String: Any] = [
            "action": "revoke_channel",
            "reason": reason,
            "policy_version": policyVersion,
            "command_seq": commandSeq,
            "permit_generation": permitGeneration
        ]
        sendProviderMessage(msg) { result in
            switch result {
            case .success(let resp):
                let status = resp["status"] as? String
                // Both "revoked" (immediate) and "disconnecting" (async drain in progress) indicate
                // that the extension has accepted and is enforcing revocation without bypass.
                completion(status == "revoked" || status == "disconnecting")
            case .failure:
                completion(false)
            }
        }
    }

    /// Synchronizes channel supervision permits and revocation with the network extension.
    func syncWithChannelPermits(snapshot: ChannelMonitorSnapshot) {
        for (family, state) in snapshot.families {
            guard family == "claude" else { continue }
            let policyVersion = state.applied_policy_version?.policy_digest ?? state.saved_policy_version.policy_digest
            let commandSeq = state.command_seq
            let permitGeneration = state.permit_generation

            if state.isPermitted {
                guard let port = state.local_proxy_port, port > 0 else {
                    NSLog("[NetworkExtensionHostManager] Gateway port not yet assigned for family %@", family)
                    continue
                }
                guard let deadline = state.valid_until, deadline > state.updated_at else {
                    NSLog("[NetworkExtensionHostManager] Authoritative lease deadline missing or expired for family %@", family)
                    continue
                }
                let validUntil = Int64(deadline)
                let allowed = state.active_member_pids
                self.pushPermit(
                    validUntil: validUntil,
                    permitState: "permitted",
                    allowedPids: allowed,
                    localProxyPort: port,
                    policyVersion: policyVersion,
                    commandSeq: commandSeq,
                    permitGeneration: permitGeneration
                ) { [weak self] success in
                    if !success {
                        NSLog("[NetworkExtensionHostManager] Failed to push permit to extension for family %@", family)
                        self?.recordExtensionFailure(reason: "push_permit_rejected_by_extension")
                    }
                }
            } else {
                self.revokeChannel(
                    reason: state.reason_code,
                    policyVersion: policyVersion,
                    commandSeq: commandSeq,
                    permitGeneration: permitGeneration
                ) { [weak self] success in
                    if !success {
                        NSLog("[NetworkExtensionHostManager] Failed to revoke channel in extension for family %@", family)
                        self?.recordExtensionFailure(reason: "revoke_channel_rejected_by_extension")
                    }
                }
            }
        }
    }

    /// Records an execution failure back to the shared status file to immediately inform Rust supervisor.
    public func recordExtensionFailure(reason: String) {
        DispatchQueue.main.async {
            let failedState = NetworkExtensionActivationState(
                isSystemExtensionActive: false,
                isTunnelActive: false,
                detail: "扩展执行失败: \(reason)",
                lastErrorCode: reason
            )
            self.activationState = failedState
            self.persistActivationStatus(state: failedState)
        }
    }

    private func persistActivationStatus(state: NetworkExtensionActivationState) {
        let fileManager = FileManager.default
        let home = fileManager.homeDirectoryForCurrentUser
        let statusFile = home
            .appendingPathComponent("Library/Application Support/ClaudeWatch/state/system-extension-status.json")
        let dir = statusFile.deletingLastPathComponent()
        try? fileManager.createDirectory(at: dir, withIntermediateDirectories: true)
        let dict: [String: Any] = [
            "is_system_extension_active": state.isSystemExtensionActive,
            "is_tunnel_active": state.isTunnelActive,
            "detail": state.detail,
            "last_error_code": state.lastErrorCode as Any,
            "updated_at": Date().timeIntervalSince1970
        ]
        if let data = try? JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted]) {
            try? data.write(to: statusFile, options: .atomic)
        }
    }
}
