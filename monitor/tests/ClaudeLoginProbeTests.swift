import Foundation

@main
struct ClaudeLoginProbeTests {
    static func main() {
        var passed = 0
        func expect(_ value: @autoclosure () -> Bool, _ message: String) { guard value() else { fputs("FAIL: \(message)\n", stderr); exit(1) }; passed += 1 }
        let web = ClaudeAXNode(role: "AXWebArea", title: nil, description: nil, url: "https://claude.ai/", parent: nil)
        let sidebar = ClaudeAXNode(role: "AXGroup", title: "Sidebar", description: nil, url: nil, parent: 0)
        let footer = ClaudeAXNode(role: "AXGroup", title: nil, description: nil, url: nil, parent: 1)
        let account = ClaudeAXNode(role: "AXPopUpButton", title: "Ada · Pro", description: nil, url: nil, parent: 2)
        let downloads = ClaudeAXNode(role: "AXLink", title: "Downloads", description: nil, url: "https://claude.ai/downloads", parent: 2)
        let logged = ClaudeLoginProbe.classify(running: true, trusted: true, nodes: [web, sidebar, footer, downloads, account], now: 1)
        expect(logged.state == "logged_in" && logged.account?.menuLabel == "Ada · Pro", "sidebar account menu identifies loaded login")
        expect(ClaudeLoginProbe.classify(running: false, trusted: false, nodes: []).state == "app_closed", "closed app")
        expect(ClaudeLoginProbe.classify(running: true, trusted: false, nodes: [web]).state == "access_required", "no AX permission")
        let login = ClaudeAXNode(role: "AXButton", title: "Log in", description: nil, url: nil, parent: 0)
        let auth = ClaudeAXNode(role: "AXWebArea", title: nil, description: "Sign in", url: "https://claude.ai/login", parent: nil)
        expect(ClaudeLoginProbe.classify(running: true, trusted: true, nodes: [auth, login]).state == "logged_out", "official login form only")
        let fake = ClaudeAXNode(role: "AXPopUpButton", title: "Model menu", description: nil, url: nil, parent: nil)
        expect(ClaudeLoginProbe.classify(running: true, trusted: true, nodes: [web, fake]).state == "unknown", "unrelated popup is not account")
        expect(ClaudeLoginProbe.classify(running: true, trusted: true, nodes: [web, sidebar, footer, downloads, account, account]).state == "unknown", "multiple account menus conflict")
        expect(ClaudeLoginProbe.classify(running: true, trusted: true, nodes: []).state == "unknown", "empty tree is not logout")
        let evil = ClaudeAXNode(role: "AXWebArea", title: nil, description: nil, url: "https://claude.ai.evil.example/", parent: nil)
        expect(ClaudeLoginProbe.classify(running: true, trusted: true, nodes: [evil, sidebar, footer, downloads, account]).state == "unknown", "host must be exact claude.ai")
        var deep: [ClaudeAXNode] = [ClaudeAXNode(role: "AXWebArea", title: nil, description: nil, url: "https://claude.ai/", parent: nil)]
        for index in 0..<10 { deep.append(.init(role: "AXGroup", title: index == 8 ? "Sidebar" : nil, description: nil, url: nil, parent: index)) }
        deep.append(.init(role: "AXLink", title: "Downloads", description: nil, url: "https://claude.ai/downloads", parent: 10))
        deep.append(.init(role: "AXPopUpButton", title: "Ada · Pro", description: nil, url: nil, parent: 10))
        expect(ClaudeLoginProbe.classify(running: true, trusted: true, nodes: deep).state == "logged_in", "deep sidebar profile paired with downloads link")
        let modelInSidebar = ClaudeAXNode(role: "AXPopUpButton", title: "Sonnet", description: nil, url: nil, parent: 1)
        let downloadsElsewhere = ClaudeAXNode(role: "AXLink", title: "Downloads", description: nil, url: "https://claude.ai/downloads", parent: nil)
        expect(ClaudeLoginProbe.classify(running: true, trusted: true, nodes: [web, sidebar, modelInSidebar, downloadsElsewhere]).state == "unknown", "model menu and unrelated downloads link are not account evidence")
        let truncated = ClaudeLoginProbe.classify(running: true, trusted: true, nodes: Array(deep.prefix(2)))
        expect(truncated.state == "unknown", "truncated accessibility tree is never logout")
        expect(ClaudeLoginProbe.classify(running: true, trusted: true, nodes: [web, sidebar, footer, downloads, account], complete: false).state == "unknown", "incomplete tree cannot confirm login")
        let chatSidebar = ClaudeAXNode(role: "AXStaticText", title: "sidebar", description: "chat text", url: nil, parent: 0)
        expect(ClaudeLoginProbe.classify(running: true, trusted: true, nodes: [web, chatSidebar, account]).state == "unknown", "chat text cannot create sidebar evidence")
        let otherWeb = ClaudeAXNode(role: "AXWebArea", title: nil, description: nil, url: "https://claude.ai/", parent: nil)
        let foreignSidebar = ClaudeAXNode(role: "AXGroup", title: "Sidebar", description: nil, url: nil, parent: 1)
        let foreignDownloads = ClaudeAXNode(role: "AXLink", title: "Downloads", description: nil, url: "https://claude.ai/downloads", parent: 0)
        let foreignAccount = ClaudeAXNode(role: "AXPopUpButton", title: "Ada · Pro", description: nil, url: nil, parent: 2)
        expect(ClaudeLoginProbe.classify(running: true, trusted: true, nodes: [web, otherWeb, foreignSidebar, foreignDownloads, foreignAccount]).state == "unknown", "cross WebArea structure cannot be combined")
        print("ClaudeLoginProbeTests: \(passed) assertions passed; no real AX")
    }
}
