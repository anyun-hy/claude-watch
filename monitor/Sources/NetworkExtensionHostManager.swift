import Foundation
import Darwin
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
    private var statusObserver: NSObjectProtocol?

    public override init() {
        super.init()
        statusObserver = NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] _ in
            self?.refreshStatus()
        }
        startAndActivateIfNeeded()
    }
    deinit { if let observer = statusObserver { NotificationCenter.default.removeObserver(observer) } }

    /// Check the signed host's entitlement before requesting OS activation.
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
            if !ready {
                // First obtain the OS activation result, then configure/start
                // the provider in the successful activation callback.
                self.requestActivation()
            }
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
            let configured = (manager?.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
            let matchesControlUser = configured?["control_home"] as? String == NSHomeDirectory()
                && (configured?["control_uid"] as? NSNumber)?.uint32Value == getuid()

            // If configured and enabled but tunnel is disconnected, attempt to connect
            if isEnabled && matchesControlUser && !isConnected, let session = manager?.connection as? NETunnelProviderSession {
                if session.status == .disconnected || session.status == .invalid {
                    do { try session.startTunnel(options: nil) }
                    catch {
                        self.recordExtensionFailure(reason: "start_tunnel_failed: \(error.localizedDescription)")
                        completion?(false)
                        return
                    }
                }
            }

            DispatchQueue.main.async {
                let newState = NetworkExtensionActivationState(
                    isSystemExtensionActive: isConnected && matchesControlUser,
                    isTunnelActive: isConnected && matchesControlUser,
                    detail: isConnected && matchesControlUser ? "透明代理已连接（待执行回执确认保护）" : (isEnabled ? "扩展已配置，尚未确认通道生效" : "网络扩展未启用"),
                    lastErrorCode: nil
                )
                self.activationState = newState
                self.persistActivationStatus(state: newState)
            }
            completion?(isEnabled && isConnected && matchesControlUser)
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
            if let error = error {
                self.isSettingUpConfiguration = false
                self.recordExtensionFailure(reason: "preferences_load_failed: \(error.localizedDescription)")
                completion?(false)
                return
            }
            let manager = managers?.first { mgr in
                (mgr.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == Self.extensionBundleIdentifier
            } ?? NETransparentProxyManager()

            let proto = (manager.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
            let prior = proto.providerConfiguration
            let controlChanged = prior?["control_home"] as? String != NSHomeDirectory()
                || (prior?["control_uid"] as? NSNumber)?.uint32Value != getuid()
            if controlChanged { manager.connection.stopVPNTunnel() }
            proto.providerBundleIdentifier = Self.extensionBundleIdentifier
            proto.serverAddress = "127.0.0.1"
            proto.providerConfiguration = ["control_home": NSHomeDirectory(), "control_uid": NSNumber(value: getuid())]

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
                NETransparentProxyManager.loadAllFromPreferences { reloadedManagers, reloadError in
                    if let reloadError = reloadError {
                        self.recordExtensionFailure(reason: "preferences_reload_failed: \(reloadError.localizedDescription)")
                        completion?(false)
                        return
                    }
                    let readyMgr = reloadedManagers?.first {
                        ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == Self.extensionBundleIdentifier
                    }
                    self.targetProviderManager = readyMgr
                    guard let session = readyMgr?.connection as? NETunnelProviderSession, readyMgr?.isEnabled == true else {
                        self.recordExtensionFailure(reason: "configured_tunnel_missing")
                        completion?(false)
                        return
                    }
                    do {
                        try session.startTunnel(options: nil)
                    } catch {
                        NSLog("[NetworkExtensionHostManager] Failed to start transparent proxy tunnel: %@", error.localizedDescription)
                        self.recordExtensionFailure(reason: "start_tunnel_failed: \(error.localizedDescription)")
                        completion?(false)
                        return
                    }
                    self.refreshStatus()
                    completion?(true)
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
                detail: "等待在系统设置中允许扩展",
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
            // A reboot-pending result has not activated the provider yet.
            guard active else { return }
            self.setupAndEnableTransparentProxyConfiguration { success in
                if success { self.refreshStatus() }
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

    /// UI lifecycle status only. Rust authorizes traffic from root executor observations.
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
