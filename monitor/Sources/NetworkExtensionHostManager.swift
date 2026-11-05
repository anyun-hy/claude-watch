import Foundation
import NetworkExtension
import SystemExtensions
import Combine

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
@available(macOS 11.0, *)
public final class NetworkExtensionHostManager: NSObject, OSSystemExtensionRequestDelegate, ObservableObject {
    public static let shared = NetworkExtensionHostManager()

    public static let extensionBundleIdentifier = "io.local.watchpanel.network-extension"

    @Published public private(set) var activationState: NetworkExtensionActivationState = .initial

    private var targetProviderManager: NETunnelProviderManager?

    public override init() {
        super.init()
        refreshStatus()
    }

    /// Checks the current system extension and tunnel status.
    public func refreshStatus() {
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            guard let self = self else { return }
            if let error = error {
                DispatchQueue.main.async {
                    self.activationState = NetworkExtensionActivationState(
                        isSystemExtensionActive: false,
                        isTunnelActive: false,
                        detail: "读取配置失败: \(error.localizedDescription)",
                        lastErrorCode: "preferences_load_failed"
                    )
                }
                return
            }

            let manager = managers?.first { mgr in
                (mgr.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == Self.extensionBundleIdentifier
            }
            self.targetProviderManager = manager

            let isEnabled = manager?.isEnabled ?? false
            let isConnected = manager?.connection.status == .connected

            DispatchQueue.main.async {
                self.activationState = NetworkExtensionActivationState(
                    isSystemExtensionActive: isEnabled,
                    isTunnelActive: isConnected,
                    detail: isConnected ? "网络接管正常运行" : (isEnabled ? "扩展已启用但隧道未连接" : "网络扩展未启用"),
                    lastErrorCode: nil
                )
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
                detail: active ? "系统扩展安装成功，等待启动隧道" : "系统扩展安装待重启",
                lastErrorCode: nil
            )
            self.refreshStatus()
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
}

