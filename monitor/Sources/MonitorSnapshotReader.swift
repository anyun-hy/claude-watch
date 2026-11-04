import Foundation

enum ReadOutcome: Sendable {
    case success(MonitorSnapshot)
    case failure(String)
}

enum SnapshotRunner {
    static func run(full: Bool) -> ReadOutcome {
        guard let variant = BundledBackendVariant.current() else {
            return .failure("构建包未声明后台类型，请重新构建界面。")
        }
        switch variant {
        case .rustCandidate:
            guard let engine = Bundle.main.url(forResource: "watch-engine", withExtension: nil) else {
                return .failure("找不到 Rust 数据读取组件，请重新构建。")
            }
            let result = SnapshotProcessTransport.run(
                executable: engine, arguments: ["snapshot"] + (full ? ["--full"] : []))
            switch result {
            case .launchFailed:
                return .failure("数据读取组件未能启动。")
            case .executionFailed:
                return .failure("本次读取未完成，将在下次刷新时重试。")
            case .outputTooLarge:
                return .failure("本次快照超出安全大小限制，未采纳该结果。")
            case .timedOut:
                return .failure("本次读取超时，已停止并丢弃该结果，将在下次刷新时重试。")
            case .success(let data):
                do { return .success(try JSONDecoder().decode(MonitorSnapshot.self, from: data)) }
                catch { return .failure("检测数据暂时无法解析，将在下次刷新时重试。") }
            }
        }
    }
}
