import Foundation

/// Runs the bundled read-only snapshot command. Stderr is deliberately
/// discarded: draining two pipes sequentially deadlocks if the child fills
/// stderr before it starts writing to stdout.
enum SnapshotProcessResult {
    case success(Data)
    case launchFailed
    case executionFailed
    case outputTooLarge
}

enum SnapshotProcessTransport {
    static let maximumOutputBytes = 16 * 1024 * 1024

    static func run(executable: URL, arguments: [String], timeoutSeconds: TimeInterval = 20) -> SnapshotProcessResult {
        let task = Process()
        let output = Pipe()
        task.executableURL = executable
        task.arguments = arguments
        task.standardOutput = output
        // Stderr is not exposed to the UI and can contain private data.
        // Do not allocate a second pipe which nobody drains concurrently.
        task.standardError = FileHandle.nullDevice
        do {
            try task.run()
        } catch {
            return .launchFailed
        }
        let timeout = DispatchWorkItem { if task.isRunning { task.terminate() } }
        DispatchQueue.global().asyncAfter(deadline: .now() + timeoutSeconds, execute: timeout)
        var data = Data()
        var oversized = false
        var readFailed = false
        while true {
            do {
                guard let chunk = try output.fileHandleForReading.read(upToCount: 65_536), !chunk.isEmpty else { break }
                if !oversized {
                    if chunk.count > Self.maximumOutputBytes - data.count {
                        oversized = true
                        data.removeAll(keepingCapacity: false)
                    } else {
                        data.append(chunk)
                    }
                }
            } catch {
                readFailed = true
                if task.isRunning { task.terminate() }
                break
            }
        }
        task.waitUntilExit()
        timeout.cancel()
        if oversized { return .outputTooLarge }
        if readFailed || task.terminationStatus != 0 { return .executionFailed }
        return .success(data)
    }
}
