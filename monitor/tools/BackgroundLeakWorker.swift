import AppKit
import CryptoKit
import Darwin
import Foundation

/// Windowless WebKit collection for an active protected session. The helper
/// reads only the fixed runtime files beside itself and emits one bounded
/// `LeakProbeResult` JSON document on stdout. It owns no policy, state file,
/// network configuration, or process-control capability.
enum BackgroundLeakWorker {
    static let maximumOutputBytes = 1_048_576

    static func kind(arguments: [String]) -> LeakKind? {
        guard arguments.count == 2 else { return nil }
        switch arguments[1] {
        case "--dns": return .dns
        case "--webrtc": return .webrtc
        default: return nil
        }
    }

    static func resources(executable: URL) -> URL? {
        let manager = FileManager.default
        guard executable.isFileURL,
              manager.fileExists(atPath: executable.path),
              (try? manager.destinationOfSymbolicLink(atPath: executable.path)) == nil else {
            return nil
        }
        let directory = executable.deletingLastPathComponent()
        for name in ["BuildInfo.plist", "watch-engine", "netcoffee_probe.html", "netcoffee_probe.js", "netcoffee_probe.css", "ipleak_probe.html", "ipleak_probe.js"] {
            let path = directory.appendingPathComponent(name, isDirectory: false)
            var isDirectory: ObjCBool = false
            guard manager.fileExists(atPath: path.path, isDirectory: &isDirectory),
                  !isDirectory.boolValue,
                  (try? manager.destinationOfSymbolicLink(atPath: path.path)) == nil else {
                return nil
            }
        }
        return directory
    }

    private static func digest(_ file: URL) -> String? {
        let manager = FileManager.default
        guard let attributes = try? manager.attributesOfItem(atPath: file.path),
              attributes[.type] as? FileAttributeType == .typeRegular,
              let size = attributes[.size] as? NSNumber,
              size.intValue >= 0, size.intValue <= 128 * 1024 * 1024,
              let handle = try? FileHandle(forReadingFrom: file) else { return nil }
        defer { try? handle.close() }
        var hasher = SHA256()
        while let bytes = try? handle.read(upToCount: 64 * 1024), !bytes.isEmpty {
            hasher.update(data: bytes)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    static func verifiedResources(executable: URL) -> URL? {
        guard let directory = resources(executable: executable),
              BundledBackendVariant.read(from: directory) == .rustCandidate,
              BundledBackendVariant.backgroundEvidenceSchema(from: directory) == 2,
              let manifest = NSDictionary(contentsOf: directory.appendingPathComponent("BuildInfo.plist", isDirectory: false)),
              let hashes = manifest["RuntimeHashes"] as? [String: String] else { return nil }
        for name in ["watch-leak-worker", "watch-engine", "netcoffee_probe.html", "netcoffee_probe.js", "netcoffee_probe.css", "ipleak_probe.html", "ipleak_probe.js"] {
            let file = directory.appendingPathComponent(name, isDirectory: false)
            guard let expected = hashes[name], expected.count == 64,
                  expected.allSatisfy({ $0.isASCII && $0.isHexDigit }),
                  digest(file) == expected.lowercased() else { return nil }
        }
        return directory
    }

    static func write(_ result: LeakProbeResult) {
        let encoder = JSONEncoder()
        guard let bytes = try? encoder.encode(result), bytes.count <= maximumOutputBytes else { return }
        FileHandle.standardOutput.write(bytes)
        FileHandle.standardOutput.write(Data([0x0a]))
    }
}

#if BACKGROUND_LEAK_WORKER
@main
struct BackgroundLeakWorkerMain {
    @MainActor static func main() {
        guard let kind = BackgroundLeakWorker.kind(arguments: CommandLine.arguments) else {
            BackgroundLeakWorker.write(.failure(.dns, code: "invalid_arguments", message: "后台检测仅接受 --dns 或 --webrtc。"))
            exit(2)
        }
        let executable = URL(fileURLWithPath: CommandLine.arguments.first ?? "").standardizedFileURL
        guard let directory = BackgroundLeakWorker.verifiedResources(executable: executable) else {
            BackgroundLeakWorker.write(.failure(kind, code: "component_missing", message: "后台检测组件或固定资源不可用。"))
            return
        }
        let app = NSApplication.shared
        app.setActivationPolicy(.prohibited)
        let workerStarted = ProcessInfo.processInfo.systemUptime
        let runner = NetCoffeeLeakRunner(resourceDirectory: directory, backendVariant: .rustCandidate)
        let dnsRunner = IPLeakDNSRetryRunner(resourceDirectory: directory)
        // Fixed labels only; the supervisor validates and persists these on an
        // incomplete run. Never include probe data or arbitrary WebKit errors.
        let diagnostic: (String, Bool) -> Void = { event, attached in
            let record: [String: Any] = ["cw_trace": event, "attached": attached,
                                         "elapsed_ms": Int((ProcessInfo.processInfo.systemUptime - workerStarted) * 1000)]
            if let bytes = try? JSONSerialization.data(withJSONObject: record, options: [.sortedKeys]) {
                FileHandle.standardError.write(bytes); FileHandle.standardError.write(Data([0x0a]))
            }
        }
        runner.onDiagnostic = diagnostic
        dnsRunner.onDiagnostic = diagnostic
        #if BACKGROUND_LEAK_WORKER_TEST
        runner.onPhase = { phase, elapsed in
            let record: [String: Any] = ["phase": phase, "elapsed_ms": elapsed]
            if let bytes = try? JSONSerialization.data(withJSONObject: record, options: [.sortedKeys]) {
                FileHandle.standardError.write(bytes)
                FileHandle.standardError.write(Data([0x0a]))
            }
        }
        #endif
        // WebKit needs an attached view to advance navigation callbacks. This
        // host is never ordered front or activated; it only owns the hidden
        // view for the lifetime of this one bounded collection.
        let host = NSWindow(contentRect: NSRect(x: -10_000, y: -10_000, width: 1, height: 1),
                            styleMask: .borderless, backing: .buffered, defer: false)
        host.isReleasedWhenClosed = false
        var completed = false
        var termination: DispatchSourceSignal?
        func finish(_ result: LeakProbeResult) {
            guard !completed else { return }
            completed = true
            termination?.cancel()
            BackgroundLeakWorker.write(result)
            NSApp.terminate(nil)
        }
        signal(SIGTERM, SIG_IGN)
        let signalSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        signalSource.setEventHandler {
            _ = runner.cancel()
            dnsRunner.cancel()
            finish(.failure(kind, code: "cancelled", message: "保护后台已取消本轮检测。"))
        }
        termination = signalSource; signalSource.resume()
        DispatchQueue.main.async {
            if kind == .dns {
                dnsRunner.start(rounds: 5, id: UUID(), progress: { label in
                    #if BACKGROUND_LEAK_WORKER_TEST
                    let phase = label.contains("归属") ? "geoip" : label.contains("HTTP") ? "http" : "dns"
                    let event = label.contains("失败") ? "failure" : label.contains("完成") ? "complete" : "start"
                    let record: [String: Any] = ["phase": phase, "event": event, "elapsed_ms": Int((ProcessInfo.processInfo.systemUptime - workerStarted) * 1000)]
                    if let bytes = try? JSONSerialization.data(withJSONObject: record, options: [.sortedKeys]) {
                        FileHandle.standardError.write(bytes); FileHandle.standardError.write(Data([0x0a]))
                    }
                    #endif
                }) { result in finish(result) }
            } else {
                runner.start(kind: kind, id: UUID(), progress: { label in
                #if BACKGROUND_LEAK_WORKER_TEST
                let stage = label.contains("trace") ? "trace" : label.contains("geoip") ? "geoip" : label.contains("DNS") ? "dns" : "other"
                FileHandle.standardError.write(Data("background fixture stage: \(stage)\n".utf8))
                #endif
                }) { result in finish(result) }
                host.contentView = runner.browserView
                host.orderFront(nil)
                diagnostic(runner.browserView?.window == nil ? "host_detached" : "host_attached", runner.browserView?.window != nil)
            }
        }
        app.run()
        _ = (runner, dnsRunner)
    }
}
#endif
