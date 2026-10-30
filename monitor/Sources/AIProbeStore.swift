import Foundation
import Combine

enum AIService: String, CaseIterable, Sendable {
    case claude, gpt
    var title: String { self == .claude ? "Claude AI 检测" : "GPT / Codex 检测" }
    var product: MonitoredProduct { self == .claude ? .claude : .openAI }
}
struct AIEndpointResult: Codable, Identifiable, Sendable {
    let url, status: String
    let httpStatus: Int?
    let elapsedMs: Double?
    let message: String
    var id: String { url }
}
struct AIProbeResult: Codable, Sendable {
    let service, status: String
    let startedAt, finishedAt: Double
    let exitIP, referenceIP, exitSource: String
    let countryCode, country, region, city, organization, ipTimezone: String
    let endpoints: [AIEndpointResult]
    let errors: [LeakProbeError]
    let details: [String]
    static func failure(_ service: AIService, code: String, message: String) -> AIProbeResult {
        let epoch = Date().timeIntervalSince1970
        return .init(service: service.rawValue, status: code == "timeout" ? "timeout" : "error",
            startedAt: epoch, finishedAt: epoch, exitIP: "", referenceIP: "", exitSource: "",
            countryCode: "", country: "", region: "", city: "", organization: "", ipTimezone: "",
            endpoints: [], errors: [.init(stage: "collector", code: code, message: message)], details: [])
    }
}
struct AIProbeState {
    var running = false
    var result: AIProbeResult?
    var verdict = LeakVerdict(state: .idle, title: "未检测", detail: "点击开始后检测当前代理诊断路径。")
}
enum AIProbePolicy {
    static func evaluate(_ result: AIProbeResult, service: AIService, now: Double) -> LeakVerdict {
        func incomplete(_ message: String) -> LeakVerdict { .init(state: .incomplete, title: "检测未完成", detail: message) }
        guard result.service == service.rawValue, result.startedAt.isFinite, result.finishedAt.isFinite,
              result.startedAt <= result.finishedAt, result.finishedAt - result.startedAt <= 90,
              result.finishedAt <= now + 5, result.endpoints.count <= 8, result.errors.count <= 16 else {
            return incomplete("诊断结果无效，不能用于当前判断。")
        }
        guard now - result.finishedAt <= 300 else { return .init(state: .incomplete, title: "结果已过期", detail: "这次诊断已超过 5 分钟，请重新检测。") }
        let limited = result.endpoints.filter { $0.status == "responded" && ($0.httpStatus == 403 || $0.httpStatus == 429 || ($0.httpStatus ?? 0) >= 500) }
        if !limited.isEmpty {
            return .init(state: .difference, title: "入口返回限制或异常", detail: "已收到 HTTP 响应，请查看入口状态；这不能直接判断账号是否可用或被封禁。")
        }
        guard result.status == "complete", result.errors.isEmpty,
              !result.endpoints.isEmpty, result.endpoints.allSatisfy({ $0.status == "responded" && (100...599).contains($0.httpStatus ?? 0) }),
              LeakIPAddress(result.exitIP)?.isPublic == true, LeakIPAddress(result.referenceIP)?.isPublic == true else {
            return incomplete(result.errors.first?.message ?? "出口或服务响应信息不完整，已保留有效观测。")
        }
        return .init(state: .unconfigured, title: "已取得网络响应", detail: "已取得对应域名的代理诊断结果；不代表 AI 桌面应用的实际出口或已登录账号的可用性。")
    }
}

private final class AIProbeRunner: @unchecked Sendable {
    private let lock = NSLock()
    private var process: Process?
    private var cancelled = false
    func cancel() {
        lock.lock(); cancelled = true; let task = process; lock.unlock()
        if task?.isRunning == true { task?.terminate() }
    }
    func run(_ service: AIService) -> AIProbeResult {
        let candidate = Bundle.main.url(forResource: "BuildInfo", withExtension: "plist")
            .flatMap { NSDictionary(contentsOf: $0)?["BackendVariant"] as? String } == "rust-candidate"
        let executable: URL
        let arguments: [String]
        if candidate {
            guard let engine = Bundle.main.url(forResource: "watch-engine", withExtension: nil),
                  FileManager.default.isExecutableFile(atPath: engine.path) else {
                return .failure(service, code: "component_missing", message: "Rust AI 网络诊断组件不可用。")
            }
            executable = engine; arguments = ["ai-probe", "--service", service.rawValue]
        } else {
            guard let script = Bundle.main.url(forResource: "ai_probe", withExtension: "py"),
                  let python = ["/opt/homebrew/bin/python3", "/usr/local/bin/python3", "/usr/bin/python3"].first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
                return .failure(service, code: "component_missing", message: "AI 网络诊断组件或 Python 3 不可用。")
            }
            executable = URL(fileURLWithPath: python); arguments = [script.path, "--service", service.rawValue]
        }
        let task = Process(), output = Pipe()
        task.executableURL = executable; task.arguments = arguments
        task.standardOutput = output; task.standardError = FileHandle.nullDevice
        lock.lock()
        if cancelled { lock.unlock(); return .failure(service, code: "cancelled", message: "检测已取消。") }
        process = task
        do { try task.run() } catch {
            process = nil; lock.unlock()
            return .failure(service, code: "launch_failed", message: "诊断组件无法启动。")
        }
        lock.unlock()
        let timeout = DispatchWorkItem { [weak self] in self?.cancel() }
        DispatchQueue.global().asyncAfter(deadline: .now() + 35, execute: timeout)
        let data = output.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit(); timeout.cancel()
        lock.lock(); process = nil; let interrupted = cancelled; lock.unlock()
        guard !interrupted else { return .failure(service, code: "timeout", message: "诊断未在时限内完成。") }
        guard task.terminationStatus == 0, data.count <= 65_536,
              let result = try? JSONDecoder().decode(AIProbeResult.self, from: data) else {
            return .failure(service, code: "invalid_result", message: "诊断结果不完整或格式无效。")
        }
        return result
    }
}
enum AIProbeFixtureScenario: String, CaseIterable {
    case ready = "AI 网络响应", limited = "AI 入口限制", timeout = "AI 诊断超时", empty = "AI 暂无结果"
}

@MainActor
final class AIProbeStore: ObservableObject {
    @Published private(set) var claude = AIProbeState()
    @Published private(set) var gpt = AIProbeState()
    @Published var now = Date() { didSet { refresh(.claude); refresh(.gpt) } }
    let isFixture: Bool
    var onResult: ((AIProbeResult) -> Void)?
    var contextProvider: (() -> String?)?
    var fixtureScenario: AIProbeFixtureScenario = .ready
    private var runners: [AIService: AIProbeRunner] = [:]
    private var runs: [AIService: UUID] = [:]
    private struct Context { let required: Bool; let value: String? }
    private var contexts: [AIService: Context] = [:]
    init(isFixture: Bool = false) {
        #if UI_REVIEW
        self.isFixture = true
        #else
        self.isFixture = isFixture
        #endif
    }
    func state(_ service: AIService) -> AIProbeState { service == .claude ? claude : gpt }
    private func set(_ state: AIProbeState, _ service: AIService) { if service == .claude { claude = state } else { gpt = state } }
    func start(_ service: AIService) {
        guard !state(service).running else { return }
        let id = UUID(); runs[service] = id
        contexts[service] = .init(required: contextProvider != nil, value: contextProvider?())
        set(.init(running: true, result: nil, verdict: .init(state: .running, title: "正在诊断", detail: "正在请求对应服务的公开网络诊断入口。")), service)
        if isFixture {
            Task { [weak self] in
                try? await Task.sleep(nanoseconds: 500_000_000)
                guard let self else { return }
                self.complete(service, id: id, result: Self.fixture(service, scenario: self.fixtureScenario))
            }
        } else {
            let runner = AIProbeRunner(); runners[service] = runner
            Task { [weak self] in
                let result = await Task.detached(priority: .utility) { runner.run(service) }.value
                self?.complete(service, id: id, result: result)
            }
        }
    }
    func cancel(_ service: AIService) {
        guard state(service).running else { return }
        runs[service] = nil; runners[service]?.cancel(); runners[service] = nil
        set(.init(running: false, result: nil, verdict: .cancelled), service)
    }
    private func complete(_ service: AIService, id: UUID, result: AIProbeResult) {
        guard runs[service] == id else { return }
        runs[service] = nil; runners[service] = nil; now = Date()
        set(.init(running: false, result: result, verdict: .idle), service)
        onResult?(result)
        refresh(service)
    }
    private func refresh(_ service: AIService) {
        var value = state(service)
        guard !value.running, let result = value.result else { return }
        if let context = contexts[service], context.required,
           context.value == nil || contextProvider?() == nil || contextProvider?() != context.value {
            value.verdict = .init(state: .incomplete, title: "上下文待核对", detail: "代理采样未就绪或检测期间发生变化，请在环境稳定后重新检测。")
        } else { value.verdict = AIProbePolicy.evaluate(result, service: service, now: now.timeIntervalSince1970) }
        set(value, service)
    }
    func loadFixture(_ scenario: AIProbeFixtureScenario) {
        guard isFixture else { return }
        fixtureScenario = scenario; now = Date()
        for service in AIService.allCases {
            cancel(service); contexts[service] = nil
            set(.init(result: Self.fixture(service, scenario: scenario)), service); refresh(service)
        }
    }
    static func fixture(_ service: AIService, scenario: AIProbeFixtureScenario) -> AIProbeResult {
        let epoch = Date().timeIntervalSince1970
        let mainURL = service == .claude ? "https://claude.ai/cdn-cgi/trace" : "https://chatgpt.com/cdn-cgi/trace"
        let secondaryURL = service == .claude ? "https://www.anthropic.com/cdn-cgi/trace" : "https://api.openai.com/v1/models"
        let empty = scenario == .empty || scenario == .timeout
        let hasExit = !empty && scenario != .limited
        return .init(service: service.rawValue, status: scenario == .ready ? "complete" : scenario == .timeout ? "timeout" : "partial",
            startedAt: epoch - 2, finishedAt: epoch, exitIP: hasExit ? "8.8.8.8" : "", referenceIP: empty ? "" : "1.1.1.1",
            exitSource: hasExit ? mainURL : "", countryCode: hasExit ? "US" : "", country: hasExit ? "美国（模拟）" : "", region: hasExit ? "California" : "", city: hasExit ? "Mountain View" : "",
            organization: hasExit ? "模拟网络服务商" : "", ipTimezone: hasExit ? "America/Los_Angeles" : "",
            endpoints: empty ? [] : [
                .init(url: mainURL, status: "responded", httpStatus: scenario == .limited ? 403 : 200, elapsedMs: 120, message: "隔离模拟响应"),
                .init(url: secondaryURL, status: "responded", httpStatus: service == .gpt ? 401 : 200, elapsedMs: 80, message: service == .gpt ? "模拟认证响应，无凭据请求" : "隔离模拟响应")
            ],
            errors: scenario == .ready || scenario == .limited ? [] : [.init(stage: "probe", code: scenario == .timeout ? "timeout" : "no_result", message: "模拟未完成结果")],
            details: ["此页面为隔离模拟数据，没有访问 AI 服务器、调用检测服务或启动 AI 应用。"])
    }
}
