import Foundation

enum ReadOutcome: Sendable {
    case success(MonitorSnapshot)
    case failure(String)
}

enum SnapshotRunner {
    static func run(full: Bool) -> ReadOutcome {
        let task = Process()
        let output = Pipe()
        let errors = Pipe()
        guard let variant = BundledBackendVariant.current() else {
            return .failure("构建包未声明后台类型，请重新构建界面。")
        }
        switch variant {
        case .rustCandidate:
            guard let engine = Bundle.main.url(forResource: "watch-engine", withExtension: nil) else {
                return .failure("找不到 Rust 数据读取组件，请重新构建。")
            }
            task.executableURL = engine
            task.arguments = ["snapshot"] + (full ? ["--full"] : [])
        }
        task.standardOutput = output
        task.standardError = errors
        do {
            try task.run()
        } catch {
            return .failure("数据读取组件未能启动。")
        }
        let timeout = DispatchWorkItem { if task.isRunning { task.terminate() } }
        DispatchQueue.global().asyncAfter(deadline: .now() + 20, execute: timeout)
        let data = output.fileHandleForReading.readDataToEndOfFile()
        _ = errors.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit()
        timeout.cancel()
        guard task.terminationStatus == 0 else {
            return .failure("本次读取未完成，将在下次刷新时重试。")
        }
        do { return .success(try JSONDecoder().decode(MonitorSnapshot.self, from: data)) }
        catch { return .failure("检测数据暂时无法解析，将在下次刷新时重试。") }
    }
}
