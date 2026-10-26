import AppKit
import ApplicationServices
import Foundation

struct ClaudeLoginAccount: Codable, Equatable {
    let displayName: String?
    let email: String?
    let menuLabel: String?
}
struct ClaudeLoginProbeResult: Codable, Equatable {
    let state: String
    let observedAt: Double
    let source: String
    let detail: String
    let account: ClaudeLoginAccount?
    let appVersion: String?
    let processId: Int?
}
// Structural metadata and the account control only; no AXValue or chat text.
struct ClaudeAXNode: Equatable {
    let role: String
    var title: String?
    var description: String?
    let url: String?
    let parent: Int?
}
enum ClaudeLoginProbe {
    static let bundleID = "com.anthropic.claudefordesktop"
    static let source = "Claude 当前界面（辅助功能）"
    private static let sidebarNames = Set(["sidebar", "侧边栏", "側邊欄", "サイドバー"])
    private static let loginButtons = Set(["log in", "sign in", "continue with google", "continue with email", "登录", "登入"])
    private static let genericMenus = Set(["account", "account menu", "profile", "profile menu", "user menu", "guest", "guest free", "anonymous", "账号", "账户", "账号菜单", "访客"])
    private static let noDescend = Set(["AXStaticText", "AXTextArea", "AXTextField", "AXSecureTextField", "AXImage", "AXButton", "AXPopUpButton", "AXMenuButton", "AXMenuBar", "AXMenu", "AXMenuItem"])

    private static func label(_ node: ClaudeAXNode) -> String {
        [node.title, node.description].compactMap { $0?.trimmingCharacters(in: .whitespacesAndNewlines) }
            .first { !$0.isEmpty } ?? ""
    }
    private static func official(_ node: ClaudeAXNode) -> Bool {
        guard node.role == "AXWebArea", let text = node.url, let url = URL(string: text) else { return false }
        return url.scheme == "https" && url.host?.lowercased() == "claude.ai" && (url.port == nil || url.port == 443) && url.user == nil && url.password == nil
    }
    private static func isLoginPage(_ node: ClaudeAXNode) -> Bool {
        guard official(node), let url = URL(string: node.url ?? "") else { return false }
        return url.path == "/login" || url.path.hasPrefix("/login/") || url.path == "/signup" || url.path.hasPrefix("/signup/")
    }
    private static func ancestors(_ index: Int, _ nodes: [ClaudeAXNode]) -> [Int] {
        guard nodes.indices.contains(index) else { return [] }
        var result: [Int] = [], next = nodes[index].parent
        while let parent = next, nodes.indices.contains(parent), !result.contains(parent), result.count < 64 {
            result.append(parent); next = nodes[parent].parent
        }
        return result
    }
    private static func webAncestor(_ index: Int, _ nodes: [ClaudeAXNode]) -> Int? {
        ancestors(index, nodes).first { nodes[$0].role == "AXWebArea" }
    }
    private static func accountIndices(_ nodes: [ClaudeAXNode]) -> [Int] {
        let downloads = nodes.indices.filter { index in
            let node = nodes[index]
            guard node.role == "AXLink", let url = URL(string: node.url ?? ""),
                  url.scheme == "https", url.host?.lowercased() == "claude.ai", (url.port == nil || url.port == 443), url.path == "/downloads",
                  let web = webAncestor(index, nodes), official(nodes[web]) else { return false }
            return ancestors(index, nodes).contains { sidebarNames.contains(label(nodes[$0]).lowercased()) && webAncestor($0, nodes) == web }
        }
        return nodes.indices.filter { index in
            let node = nodes[index]
            guard ["AXPopUpButton", "AXMenuButton"].contains(node.role), node.parent != nil,
                  let web = webAncestor(index, nodes), official(nodes[web]), !isLoginPage(nodes[web]) else { return false }
            return downloads.contains { download in
                guard webAncestor(download, nodes) == web else { return false }
                // Chromium can wrap the downloads link in an extra AXGroup.
                // Accept only the small footer group, never the whole sidebar.
                let menuParents = ancestors(index, nodes).prefix(2)
                return ancestors(download, nodes).prefix(2).contains { footer in
                    menuParents.contains(footer) && nodes[footer].role == "AXGroup" &&
                    !sidebarNames.contains(label(nodes[footer]).lowercased()) &&
                    webAncestor(footer, nodes) == web && ancestors(footer, nodes).contains {
                        sidebarNames.contains(label(nodes[$0]).lowercased()) && webAncestor($0, nodes) == web
                    }
                }
            }
        }
    }
    static func classify(running: Bool, trusted: Bool, nodes: [ClaudeAXNode], appVersion: String? = nil,
                         pid: Int? = nil, now: Double = Date().timeIntervalSince1970,
                         complete: Bool = true) -> ClaudeLoginProbeResult {
        func result(_ state: String, _ detail: String, _ account: ClaudeLoginAccount? = nil) -> ClaudeLoginProbeResult {
            .init(state: state, observedAt: now, source: source, detail: detail, account: account, appVersion: appVersion, processId: pid)
        }
        guard running else { return result("app_closed", "Claude 未运行；没有把本地资料槽当成登录状态。") }
        guard trusted else { return result("access_required", "需要允许 Claude Watch 读取 Claude 的账号界面，才能识别当前登录。") }
        guard complete else { return result("unknown", "Claude 界面读取未完整完成或超时；没有据此判断退出登录。") }
        guard nodes.allSatisfy({ $0.parent == nil || nodes.indices.contains($0.parent!) }) else {
            return result("unknown", "Claude 界面结构无效，未推断账号状态。")
        }
        let menus = accountIndices(nodes)
        let labels = Set(menus.map { label(nodes[$0]) }.filter { !$0.isEmpty && $0.count <= 160 })
        let loginWebs = Set(nodes.indices.filter { isLoginPage(nodes[$0]) })
        let hasLoginForm = nodes.indices.contains { index in
            guard nodes[index].role == "AXButton", let web = webAncestor(index, nodes), loginWebs.contains(web) else { return false }
            return loginButtons.contains(label(nodes[index]).lowercased())
        }
        if labels.count == 1, menus.count == 1, !hasLoginForm, let text = labels.first,
           !loginButtons.contains(text.lowercased()), !genericMenus.contains(text.lowercased()) {
            return result("logged_in", "由 Claude 当前账号菜单识别，与 A/B 本地资料槽无关。",
                          .init(displayName: nil, email: nil, menuLabel: text))
        }
        if labels.count > 1 || menus.count > 1 || (!labels.isEmpty && hasLoginForm) {
            return result("unknown", "Claude 界面出现多个或冲突的账号状态，未选择其中一个冒充当前登录。")
        }
        if hasLoginForm { return result("logged_out", "Claude 当前显示官方登录页面及登录操作。") }
        return result("unknown", "尚未读取到完整的 Claude 账号菜单或登录页；请保持主窗口已加载。")
    }
    static func probe(prompt: Bool = false) -> ClaudeLoginProbeResult {
        // Source compatibility only: observations never request system permissions.
        let runningApps = NSRunningApplication.runningApplications(withBundleIdentifier: bundleID).filter { !$0.isTerminated }
        let candidates = runningApps.filter {
            !$0.isTerminated && $0.bundleURL?.standardizedFileURL.path == "/Applications/Claude.app" &&
            $0.executableURL?.standardizedFileURL.path == "/Applications/Claude.app/Contents/MacOS/Claude"
        }
        guard candidates.count == 1, let app = candidates.first else {
            if runningApps.isEmpty { return classify(running: false, trusted: false, nodes: []) }
            return .init(state: "unknown", observedAt: Date().timeIntervalSince1970, source: source,
                         detail: "多个 Claude 主进程，无法确认当前账号窗口。", account: nil, appVersion: nil, processId: nil)
        }
        let pid = app.processIdentifier
        let version = Bundle(url: app.bundleURL!)?.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
        guard AXIsProcessTrusted() else { return classify(running: true, trusted: false, nodes: [], appVersion: version, pid: Int(pid)) }
        let snapshot = readNodes(AXUIElementCreateApplication(pid))
        #if LOGIN_PROBE_DIAGNOSTICS
        let roles = Dictionary(grouping: snapshot.nodes, by: { $0.role }).mapValues { $0.count }
        let structure = snapshot.nodes.enumerated().compactMap { index, node -> [String: Any]? in
            guard node.url != nil || node.description != nil || ["AXWebArea", "AXPopUpButton", "AXMenuButton"].contains(node.role) else { return nil }
            return ["index": index, "role": node.role, "url": node.url ?? "", "structuralLabel": node.description ?? "", "parent": node.parent ?? -1]
        }
        if let data = try? JSONSerialization.data(withJSONObject: ["nodes": snapshot.nodes.count, "complete": snapshot.complete, "roles": roles, "structure": structure]),
           let text = String(data: data, encoding: .utf8) { fputs(text + "\n", stderr) }
        #endif
        guard !app.isTerminated, NSRunningApplication(processIdentifier: pid)?.launchDate == app.launchDate else {
            return .init(state: "unknown", observedAt: Date().timeIntervalSince1970, source: source,
                         detail: "读取期间 Claude 进程发生变化，已丢弃旧账号结果。", account: nil, appVersion: version, processId: Int(pid))
        }
        return classify(running: true, trusted: true, nodes: snapshot.nodes, appVersion: version, pid: Int(pid), complete: snapshot.complete)
    }
    private struct Snapshot { var nodes: [ClaudeAXNode]; var complete: Bool }
    private static func readNodes(_ root: AXUIElement) -> Snapshot {
        let deadline = ProcessInfo.processInfo.systemUptime + 3
        var nodes: [ClaudeAXNode] = [], elements: [AXUIElement] = []
        var queue: [(AXUIElement, Int?, Int)] = [(root, nil, 0)], cursor = 0, complete = true
        var seen: [CFHashCode: [AXUIElement]] = [:]
        func value(_ element: AXUIElement, _ key: String) -> CFTypeRef? {
            if ProcessInfo.processInfo.systemUptime >= deadline { complete = false; return nil }
            AXUIElementSetMessagingTimeout(element, 0.12)
            var result: CFTypeRef?
            let status = AXUIElementCopyAttributeValue(element, key as CFString, &result)
            if status == .cannotComplete || status == .invalidUIElement { complete = false }
            return status == .success ? result : nil
        }
        func text(_ element: AXUIElement, _ key: String) -> String? { value(element, key) as? String }
        func publicURL(_ element: AXUIElement) -> String? {
            guard let raw = value(element, kAXURLAttribute) else { return nil }
            let url = (raw as? URL) ?? (raw as? String).flatMap(URL.init(string:))
            guard let url, url.scheme == "https", url.host?.lowercased() == "claude.ai", (url.port == nil || url.port == 443), url.user == nil, url.password == nil else { return nil }
            // Strip query, fragment, and private conversation identifiers.
            let path = ["/", "/new", "/login", "/signup", "/downloads"].contains(url.path) ? url.path :
                (url.path.hasPrefix("/login/") ? "/login/" : url.path.hasPrefix("/signup/") ? "/signup/" : "/page")
            return "https://claude.ai" + path
        }
        while cursor < queue.count {
            guard nodes.count < 2048, ProcessInfo.processInfo.systemUptime < deadline else { complete = false; break }
            let (element, parent, depth) = queue[cursor]; cursor += 1
            if depth > 32 { complete = false; continue }
            let hash = CFHash(element)
            if seen[hash]?.contains(where: { CFEqual($0, element) }) == true { continue }
            seen[hash, default: []].append(element)
            guard let role = text(element, kAXRoleAttribute) else { continue }
            let url = ["AXWebArea", "AXLink"].contains(role) ? publicURL(element) : nil
            var description: String?
            if ["AXGroup", "AXSplitGroup", "AXLandmarkComplementary"].contains(role) {
                if let name = text(element, kAXDescriptionAttribute), sidebarNames.contains(name.lowercased()) { description = name }
                if description == nil, let name = text(element, kAXTitleAttribute), sidebarNames.contains(name.lowercased()) { description = name }
            }
            let index = nodes.count
            nodes.append(.init(role: role, title: nil, description: description, url: url, parent: parent)); elements.append(element)
            if noDescend.contains(role) { continue }
            var count: CFIndex = 0
            AXUIElementSetMessagingTimeout(element, 0.12)
            let status = AXUIElementGetAttributeValueCount(element, kAXChildrenAttribute as CFString, &count)
            if status == .cannotComplete || status == .invalidUIElement { complete = false }
            guard status == .success, count > 0 else { continue }
            if count > 256 { complete = false }
            var children: CFArray?
            if AXUIElementCopyAttributeValues(element, kAXChildrenAttribute as CFString, 0, min(count, 256), &children) == .success,
               let list = children as? [AXUIElement] {
                for child in list { queue.append((child, index, depth + 1)) }
            } else { complete = false }
        }
        // Names are read only from verified account controls and login actions.
        let menuIndices = accountIndices(nodes)
        for index in nodes.indices {
            let isLoginButton = nodes[index].role == "AXButton" && webAncestor(index, nodes).map { isLoginPage(nodes[$0]) } == true
            if menuIndices.contains(index) || isLoginButton {
                nodes[index].title = text(elements[index], kAXTitleAttribute).map { String($0.prefix(160)) }
                nodes[index].description = text(elements[index], kAXDescriptionAttribute).map { String($0.prefix(160)) }
            }
        }
        return Snapshot(nodes: nodes, complete: complete)
    }
}
