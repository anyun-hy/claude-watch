import AppKit
import CryptoKit
import Darwin
import Foundation

/// WebKit collection for an active protected session. The resident mode keeps
/// loaded views and answers bounded, ID-bound requests over private pipes.
/// The helper reads only its fixed runtime files and owns no policy, state
/// file, network configuration, or process-control capability.
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
private struct WorkerRequest: Decodable {
    let schema: Int
    let id: String
    let kind: String
}

@MainActor
private final class BackgroundLeakService {
    private let serving: Bool
    private let runner: NetCoffeeLeakRunner
    private let dnsRunner: IPLeakDNSRetryRunner
    private var requestID: String?
    private var kind: LeakKind = .dns
    private var started = ProcessInfo.processInfo.systemUptime

    init(directory: URL, serving: Bool) {
        self.serving = serving
        runner = NetCoffeeLeakRunner(resourceDirectory: directory, backendVariant: .rustCandidate)
        dnsRunner = IPLeakDNSRetryRunner(resourceDirectory: directory)
        let diagnostic: (String, Bool) -> Void = { [weak self] event, attached in
            guard let self, let id = self.requestID else { return }
            self.write(["cw_trace": event, "request_id": id, "attached": attached,
                        "elapsed_ms": Int((ProcessInfo.processInfo.systemUptime - self.started) * 1000)], stderr: true)
        }
        runner.onDiagnostic = diagnostic
        dnsRunner.onDiagnostic = diagnostic
    }
    private func write(_ value: [String: Any], stderr: Bool = false) {
        guard let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]),
              data.count <= BackgroundLeakWorker.maximumOutputBytes else { return }
        let output = stderr ? FileHandle.standardError : FileHandle.standardOutput
        output.write(data); output.write(Data([10]))
    }
    func receive(_ request: WorkerRequest) {
        guard requestID == nil, request.schema == 1, let id = UUID(uuidString: request.id),
              ["dns", "webrtc"].contains(request.kind), request.id.count == 36 else { invalid(); return }
        requestID = request.id
        kind = request.kind == "dns" ? .dns : .webrtc
        started = ProcessInfo.processInfo.systemUptime
        if kind == .dns {
            dnsRunner.start(rounds: 5, id: id) { [weak self] result in self?.finish(result) }
        } else {
            runner.start(kind: kind, id: id) { [weak self] result in self?.finish(result) }
        }
    }
    private func finish(_ value: LeakProbeResult) {
        guard let id = requestID else { return }
        var result = value
        if value.kind != kind.rawValue || (try? JSONEncoder().encode(value).count).map({ $0 > 900_000 }) != false {
            result = .failure(kind, code: "invalid_result", message: "后台检测返回结果无效或超限。")
            _ = runner.invalidate(); dnsRunner.invalidate()
        }
        requestID = nil
        if serving, let data = try? JSONEncoder().encode(result),
           let object = try? JSONSerialization.jsonObject(with: data) {
            write(["schema": 1, "id": id, "kind": kind.rawValue, "result": object])
        } else {
            BackgroundLeakWorker.write(result)
            shutdown()
        }
    }
    func ready() { write(["schema": 1, "ready": true]) }
    func invalid() {
        write(["schema": 1, "error": "invalid_request"])
        shutdown()
    }
    func shutdown() {
        requestID = nil
        _ = runner.invalidate(); dnsRunner.invalidate()
        NSApp.terminate(nil)
    }
}

@main
struct BackgroundLeakWorkerMain {
    @MainActor static func main() {
        let arguments = CommandLine.arguments
        let serving = arguments.count == 2 && arguments[1] == "--serve"
        let oneShotKind = BackgroundLeakWorker.kind(arguments: arguments)
        guard serving || oneShotKind != nil else {
            BackgroundLeakWorker.write(.failure(.dns, code: "invalid_arguments", message: "后台检测仅接受固定采集入口。"))
            exit(2)
        }
        let executable = URL(fileURLWithPath: arguments.first ?? "").standardizedFileURL
        guard let directory = BackgroundLeakWorker.verifiedResources(executable: executable) else {
            BackgroundLeakWorker.write(.failure(oneShotKind ?? .dns, code: "component_missing", message: "后台检测组件或固定资源不可用。"))
            return
        }
        let app = NSApplication.shared
        app.setActivationPolicy(.prohibited)
        let service = BackgroundLeakService(directory: directory, serving: serving)
        signal(SIGTERM, SIG_IGN)
        let termination = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        termination.setEventHandler { service.shutdown() }
        termination.resume()
        if serving {
            service.ready()
            // One bounded line per request. No caller-provided paths, scripts,
            // endpoints, settings or process-control commands are accepted.
            DispatchQueue.global(qos: .utility).async {
                var pending = Data()
                var bytes = [UInt8](repeating: 0, count: 512)
                while true {
                    let count = Darwin.read(STDIN_FILENO, &bytes, bytes.count)
                    if count < 0 && errno == EINTR { continue }
                    if count <= 0 { break }
                    pending.append(contentsOf: bytes.prefix(count))
                    if pending.count > 2048 { DispatchQueue.main.async { service.invalid() }; return }
                    while let end = pending.firstIndex(of: 10) {
                        let line = Data(pending[..<end]); pending.removeSubrange(...end)
                        guard line.count <= 1024,
                              let object = try? JSONSerialization.jsonObject(with: line) as? [String: Any], object.count == 3,
                              let request = try? JSONDecoder().decode(WorkerRequest.self, from: line) else {
                            DispatchQueue.main.async { service.invalid() }; return
                        }
                        DispatchQueue.main.async { service.receive(request) }
                    }
                }
                DispatchQueue.main.async { service.shutdown() }
            }
        } else if let kind = oneShotKind {
            DispatchQueue.main.async { service.receive(WorkerRequest(schema: 1, id: UUID().uuidString, kind: kind.rawValue)) }
        }
        app.run()
        _ = (service, termination)
    }
}
#endif
