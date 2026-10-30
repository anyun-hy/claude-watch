import Foundation

@main
struct GraphContinuityTests {
    static func main() {
        var checks = 0
        func expect(_ value: @autoclosure () -> Bool, _ message: String) {
            checks += 1
            if !value() { fputs("FAIL: \(message)\n", stderr); exit(1) }
        }
        func process(_ product: MonitoredProduct, pid: Int = 42, start: String = "source-start") -> WatchedProcess {
            .init(id: "p-\(pid)-\(start)", pid: pid, started: start,
                  kind: product == .claude ? "desktop-helper" : "openai-desktop-helper", authorized: true,
                  runtimeRole: "chromium_network", roleEvidence: "runtime_component")
        }
        func flow(_ product: MonitoredProduct, pid: Int = 42, id: String = "f", host: String? = nil,
                  association: String = "correlated", node: String = "JP", policy: String = "match") -> Flow {
            .init(id: id, pid: pid, host: host ?? (product == .claude ? "claude.ai" : "chatgpt.com"),
                  peer: "198.18.0.89:443", local: "198.18.0.1:55000", transport: "UDP",
                  association: association, policy: policy, reason: "fixture", chains: ["GLOBAL", node],
                  routePath: "Tun", interfaceName: "utun4", destinationIP: "160.79.104.10",
                  destinationPort: 443, destinationIPState: "public")
        }
        func snapshot(_ product: MonitoredProduct, time: Double, flows: [Flow],
                      processes: [WatchedProcess]? = nil, node: String = "JP", collector: String = "ok",
                      proxyTime: Double? = nil, sourceStart: String = "source-start", listenerStart: String = "tag-start",
                      withReceipt: Bool = true, filtered: Int = 0, receiptSkew: Double = 0,
                      health: String = "running", proxyError: String? = nil) -> MonitorSnapshot {
            let processes = processes ?? [process(product, start: sourceStart)]
            let at = proxyTime ?? time
            var proxy = ProxySnapshot(observedAt: at, entryState: "verified", entryReason: "fixture", entrySource: "fixture",
                endpoint: "127.0.0.1:7890", listenerPID: 99, listenerPath: "/fixture/tag", apiState: "available", apiReason: "",
                mode: "global", coversProxy: true, expectedGroup: "GLOBAL", expectedNode: node, selectedNode: node,
                globalNode: node, pinned: true, selectionChanged: false, flows: flows, listenerStarted: listenerStart)
            if withReceipt {
                proxy.connectionObservation = ConnectionObservation(schema: 1, roundID: "round-\(at)", observedAt: at + receiptSkew,
                    collectorState: collector, targetCount: processes.count, parsedCount: flows.count, acceptedCount: flows.count,
                    correlatedCount: flows.filter { $0.association == "correlated" }.count,
                    unconfirmedCount: flows.filter { $0.association == "unconfirmed" }.count,
                    dropped: [:], detail: "fixture \(collector)", uiFilteredCount: filtered, uiDropped: filtered == 0 ? [:] : ["pid_missing": filtered])
            }
            return MonitorSnapshot(capturedAt: time, health: .init(state: health, mode: "ACTIVE", pid: 7, heartbeatAge: 0,
                started: "agent-start", detail: "fixture health", alerts: "on"), installed: true, autoStart: true,
                keepAlive: true, hasBaseline: true, stderrBytes: 0, processes: processes, events: [], proxy: proxy,
                proxyError: proxyError, logPath: "/fixture/log", backendVersion: "fixture", monitoredApps: ["claude", "codex", "chatgpt"])
        }
        for product in MonitoredProduct.allCases {
            var timeline = GraphContinuityStore(), selection = NetworkGraphSelection()
            func apply(_ value: MonitorSnapshot, error: String? = nil, automatic: Bool = true,
                       ip: String? = "222.10.87.169", ipTime: Double? = nil, blocked: Bool = false) -> GraphDisplayState {
                selection.reconcile(proxy: value.proxy, processes: value.processes,
                    fresh: error == nil && value.proxy?.connectionObservationIsComplete == true)
                timeline.observe(snapshot: value, selection: selection, now: value.capturedAt, error: error, automatic: automatic,
                    claudeEgressIP: ip, egressObservedAt: ipTime ?? value.capturedAt, safetyBlocked: blocked)
                return timeline.display(product: product, snapshot: value, selection: selection, now: value.capturedAt,
                    error: error, automatic: automatic, claudeEgressIP: ip, egressObservedAt: ipTime ?? value.capturedAt, safetyBlocked: blocked)
            }
            let live = apply(snapshot(product, time: 1000, flows: [flow(product)]))
            expect(live.phase == .live && live.canAnimate && live.platformFlowCount == 1, "\(product) current associated route animates")
            let idle = apply(snapshot(product, time: 1010, flows: [], collector: "empty"))
            expect(idle.phase == .noSample && idle.platformFlowCount == 0, "\(product) valid empty stays zero")
            expect(idle.isHistorical && !idle.canAnimate && idle.sampledAt == 1000, "\(product) idle retains original time only")
            expect(idle.projection.gatewayTitle == "TUN 通道" && idle.projection.groupTitle == "GLOBAL" && idle.projection.nodeTitle == "JP", "\(product) idle never switches to configuration reference")
            expect(idle.projection.nodeState == .pending, "\(product) history does not stay green")
            let failure = apply(snapshot(product, time: 1020, flows: []), error: "read failed")
            expect(failure.phase == .failed && !failure.countsAvailable && failure.platformFlowCount == nil, "\(product) failure is not zero")
            expect(failure.sampledAt == 1000 && failure.isHistorical && !failure.canAnimate, "\(product) failed read never renews history")
            let partial = apply(snapshot(product, time: 1021, flows: [], collector: "partial"))
            expect(partial.phase == .partial && !partial.countsAvailable && partial.sampledAt == 1000, "\(product) partial does not erase or validate history")
            let resumed = apply(snapshot(product, time: 1030, flows: [flow(product, id: "new-id")]))
            expect(resumed.phase == .live && resumed.canAnimate && resumed.sample?.flowID == "new-id", "\(product) only fresh reacquired flow resumes animation")
            let late = apply(snapshot(product, time: 1031, flows: [flow(product, id: "late", node: "old")], node: "old", proxyTime: 1025))
            expect(late.phase == .partial && late.sample?.flowID == "new-id", "\(product) late old network never retires newest route")
            let swapped = apply(snapshot(product, time: 1040, flows: [], node: "JP2", collector: "empty"))
            expect(swapped.phase == .contextChanged && swapped.sample == nil && swapped.archivedSample?.proxy.currentNode == "JP", "\(product) changed node archives route immediately")
            let unavailable = apply(snapshot(product, time: 1041, flows: [], node: "", collector: "failed"))
            expect(unavailable.phase == .failed && unavailable.sample == nil && unavailable.archivedSample != nil, "\(product) missing new context never revives old route")
            let newNetwork = apply(snapshot(product, time: 1050, flows: [flow(product, id: "new-network", node: "JP2")], node: "JP2"))
            expect(newNetwork.phase == .live && newNetwork.projection.nodeTitle == "JP2", "\(product) new context requires fresh observed route")
            let pidChange = apply(snapshot(product, time: 1051, flows: [], node: "JP2", collector: "empty", sourceStart: "reused-pid"))
            expect(pidChange.phase == .contextChanged && pidChange.sample == nil, "\(product) PID reuse cannot borrow old path")
            _ = apply(snapshot(product, time: 1060, flows: [flow(product, id: "after-pid")], node: "JP2", sourceStart: "reused-pid"))
            let stopped = apply(snapshot(product, time: 1070, flows: [], processes: [], node: "JP2", collector: "no_targets"))
            expect(stopped.phase == .stopped && stopped.sample == nil && stopped.archivedSample != nil, "\(product) confirmed exit archives history")
            _ = apply(snapshot(product, time: 1080, flows: [flow(product, id: "current")], node: "JP2"))
            let paused = apply(snapshot(product, time: 1081, flows: [], node: "JP2", collector: "empty"), automatic: false)
            expect(paused.phase == .paused && !paused.canAnimate && !paused.countsAvailable, "\(product) UI pause is not current traffic or zero")
            let stale = apply(snapshot(product, time: 1120, flows: [], node: "JP2", collector: "empty", proxyTime: 1080))
            expect(stale.phase == .expired && stale.isHistorical && !stale.canAnimate, "\(product) expired data retains clearly historical route")
            let absentReceipt = apply(snapshot(product, time: 1121, flows: [], node: "JP2", withReceipt: false))
            expect(absentReceipt.phase == .partial && !absentReceipt.countsAvailable, "\(product) legacy empty lacks completeness proof")
            let filtered = apply(snapshot(product, time: 1122, flows: [], node: "JP2", filtered: 1))
            expect(filtered.phase == .partial && !filtered.countsAvailable, "\(product) identity filtering cannot look like empty")
            let wrongRound = apply(snapshot(product, time: 1123, flows: [], node: "JP2", receiptSkew: 6))
            expect(wrongRound.phase == .partial, "\(product) observation from another round rejected")
            _ = apply(snapshot(product, time: 1130, flows: [flow(product, id: "matched")], node: "JP2"))
            let unmatched = apply(snapshot(product, time: 1131, flows: [flow(product, association: "unconfirmed")], node: "JP2"))
            expect(unmatched.phase == .unassociated && !unmatched.canAnimate && unmatched.sample?.flowID == "matched", "\(product) failed association cannot become a live path")
            let ipChanged = apply(snapshot(product, time: 1140, flows: [], node: "JP2", collector: "empty"), ip: "222.10.87.170")
            if product == .claude {
                expect(ipChanged.phase == .contextChanged && ipChanged.sample == nil, "confirmed Claude egress change archives its old path")
                let oldRound = apply(snapshot(product, time: 1141, flows: [flow(product, id: "old-ip")], node: "JP2", proxyTime: 1139), ip: "222.10.87.170")
                expect(!oldRound.canAnimate && oldRound.sample == nil, "older connection round cannot certify new egress context")
            } else {
                expect(ipChanged.phase == .noSample && ipChanged.isHistorical, "OpenAI does not borrow Claude egress policy")
            }
            _ = apply(snapshot(product, time: 1150, flows: [flow(product, id: "latest")], node: "JP2"), ip: "222.10.87.170")
            let locked = apply(snapshot(product, time: 1151, flows: [flow(product, id: "still-visible")], node: "JP2"), ip: "222.10.87.170", blocked: true)
            expect(product == .claude ? !locked.canAnimate && locked.sample == nil : locked.canAnimate, "only Claude graph reflects its own session stop")
        }
        var referenceTimeline = GraphContinuityStore(), referenceSelection = NetworkGraphSelection()
        var dnsFlow = flow(.openAI, id: "reference-flow")
        dnsFlow.destinationIP = nil; dnsFlow.destinationIPState = nil
        let referenceSnapshot = snapshot(.openAI, time: 1500, flows: [dnsFlow])
        let reference = ServerReference(host: "chatgpt.com", basis: "dns_reference", address: "104.18.32.7", addresses: ["104.18.32.7"],
            countryCode: "US", country: "美国", region: "California", city: "", status: "ready", message: "fixture", queriedAt: 1495,
            expiresAt: 1510, dnsSource: "fixture DNS", geoSource: "fixture GeoIP")
        referenceSelection.reconcile(proxy: referenceSnapshot.proxy, processes: referenceSnapshot.processes, fresh: true)
        referenceTimeline.observe(snapshot: referenceSnapshot, selection: referenceSelection, now: 1500, error: nil, automatic: true,
            references: ["chatgpt.com|dns": reference])
        let quietReference = snapshot(.openAI, time: 1600, flows: [], collector: "empty")
        referenceSelection.reconcile(proxy: quietReference.proxy, processes: quietReference.processes, fresh: true)
        let late = ServerReference(host: "chatgpt.com", basis: "dns_reference", address: "8.8.8.8", addresses: ["8.8.8.8"],
            countryCode: "US", country: "美国", region: "", city: "", status: "ready", message: "late", queriedAt: 1595,
            expiresAt: 1700, dnsSource: "late DNS", geoSource: "late GeoIP")
        referenceTimeline.observe(snapshot: quietReference, selection: referenceSelection, now: 1600, error: nil, automatic: true,
            references: ["chatgpt.com|dns": late])
        let history = referenceTimeline.display(product: .openAI, snapshot: quietReference, selection: referenceSelection,
            now: 1600, error: nil, automatic: true)
        expect(history.sample?.reference?.address == "104.18.32.7", "late metadata never replaces an ended route's saved reference")
        expect(history.sample?.referenceCapturedAt == 1500 && history.sampledAt == 1500, "history keeps both original path/reference capture clocks")
        let savedTarget = ServerTargetPresentation(product: .openAI, flow: history.sample?.flow, reference: history.sample?.reference,
            now: history.sample?.referenceCapturedAt ?? 0, historical: true)
        expect(savedTarget.addressLine.contains("104.18.32.7") && savedTarget.detail.contains("上次保存"), "old reference remains explicitly historical after its live TTL")
        let absentReference = ServerTargetPresentation(product: .openAI, flow: dnsFlow, reference: nil, now: 1500, historical: true)
        expect(!absentReference.addressLine.contains("待查询"), "history does not imply a future lookup that will not run")
        for product in MonitoredProduct.allCases {
            let ambiguous = WatchedProcess(id: "ambiguous", pid: 42, started: "source-start",
                kind: product == .claude ? "child" : "codex-child", authorized: nil)
            let p = snapshot(product, time: 1700, flows: [flow(product)], processes: [ambiguous])
            let graph = ConnectionGraphProjection(proxy: p.proxy, processes: p.processes, selectedFlowID: "f", fresh: true, showConfigurationReference: false)
            expect(!graph.supportsPathAnimation && graph.sourceEdgeState == .pending, "ambiguous source role stays unconfirmed for both products")
        }
        let cli = WatchedProcess(id: "cli", pid: 71, started: "cli-start", kind: "codex-cli", authorized: true)
        let desktop = WatchedProcess(id: "desktop", pid: 72, started: "desktop-start", kind: "openai-child", authorized: true)
        let cliFlow = flow(.openAI, pid: 71, id: "cli-flow", host: "api.openai.com")
        let desktopFlow = flow(.openAI, pid: 72, id: "desktop-flow")
        func dualDisplay(_ cliFlow: Flow, collector: String = "ok", automatic: Bool = true,
                         selectedID: String = "desktop-flow") -> GraphDisplayState {
            let snap = snapshot(.openAI, time: 2000, flows: [cliFlow, desktopFlow], processes: [cli, desktop], collector: collector)
            var selection = NetworkGraphSelection()
            selection.select(flowID: selectedID, product: .openAI)
            selection.reconcile(proxy: snap.proxy, processes: snap.processes, fresh: true)
            var timeline = GraphContinuityStore()
            timeline.observe(snapshot: snap, selection: selection, now: 2000, error: nil, automatic: automatic)
            return timeline.display(product: .openAI, snapshot: snap, selection: selection, now: 2000,
                                    error: nil, automatic: automatic)
        }
        let dual = dualDisplay(cliFlow)
        expect(dual.phase == .live && dual.projection.sourceKind == "desktop", "desktop remains the selected shared route")
        expect(dual.sourceProjection(.desktop)?.sourcePID == 72, "desktop edge is bound to its own flow")
        expect(dual.sourceProjection(.cli)?.sourcePID == 71 && dual.sourceProjection(.cli)?.sourceEdgeState == .confirmed,
               "CLI also has an independently confirmed edge on the same route")
        let selectedCLI = dualDisplay(cliFlow, selectedID: "cli-flow")
        expect(selectedCLI.projection.sourceKind == "code" && selectedCLI.sourceProjection(.desktop)?.sourcePID == 72,
               "desktop keeps its own confirmed edge when CLI is selected")
        let frontend = WatchedProcess(id: "frontend", pid: 79345, started: "front-start", kind: "codex-cli", authorized: true)
        let managed = WatchedProcess(id: "managed-server", pid: 38392, started: "server-start", kind: "codex-cli", authorized: true)
        let managedFlow = flow(.openAI, pid: 38392, id: "managed-flow", host: "ab.chatgpt.com")
        let managedSnapshot = snapshot(.openAI, time: 2050, flows: [desktopFlow, managedFlow], processes: [frontend, managed, desktop])
        var managedSelection = NetworkGraphSelection()
        managedSelection.select(flowID: "desktop-flow", product: .openAI)
        managedSelection.reconcile(proxy: managedSnapshot.proxy, processes: managedSnapshot.processes, fresh: true)
        var managedTimeline = GraphContinuityStore()
        managedTimeline.observe(snapshot: managedSnapshot, selection: managedSelection, now: 2050, error: nil, automatic: true)
        let managedDisplay = managedTimeline.display(product: .openAI, snapshot: managedSnapshot, selection: managedSelection, now: 2050, error: nil, automatic: true)
        expect(managedDisplay.sourceProjection(.cli)?.sourcePID == 38392 && managedDisplay.sourceProjection(.cli)?.sourceEdgeState == .confirmed && managedDisplay.sourceProjection(.desktop)?.sourcePID == 72,
               "independent managed server's own flow can join desktop on the same observed route")
        let desktopOnly = dualDisplay(flow(.openAI, pid: 71, id: "cli-flow", association: "unconfirmed"))
        expect(desktopOnly.sourceProjection(.desktop)?.sourcePID == 72 && desktopOnly.sourceProjection(.cli) == nil,
               "missing CLI evidence leaves desktop evidence intact and CLI as a reference")
        let cliOnlySnapshot = snapshot(.openAI, time: 2000, flows: [cliFlow], processes: [cli, desktop])
        var cliOnlySelection = NetworkGraphSelection()
        cliOnlySelection.select(flowID: "cli-flow", product: .openAI)
        cliOnlySelection.reconcile(proxy: cliOnlySnapshot.proxy, processes: cliOnlySnapshot.processes, fresh: true)
        var cliOnlyTimeline = GraphContinuityStore()
        cliOnlyTimeline.observe(snapshot: cliOnlySnapshot, selection: cliOnlySelection, now: 2000, error: nil, automatic: true)
        let cliOnly = cliOnlyTimeline.display(product: .openAI, snapshot: cliOnlySnapshot, selection: cliOnlySelection, now: 2000, error: nil, automatic: true)
        expect(cliOnly.sourceProjection(.cli)?.sourcePID == 71 && cliOnly.sourceProjection(.desktop) == nil,
               "missing desktop evidence leaves CLI evidence intact and desktop as a reference")
        var exitedTimeline = GraphContinuityStore()
        var exitedSelection = NetworkGraphSelection()
        let beforeExit = snapshot(.openAI, time: 2100, flows: [cliFlow, desktopFlow], processes: [cli, desktop])
        exitedSelection.select(flowID: "cli-flow", product: .openAI)
        exitedSelection.reconcile(proxy: beforeExit.proxy, processes: beforeExit.processes, fresh: true)
        exitedTimeline.observe(snapshot: beforeExit, selection: exitedSelection, now: 2100, error: nil, automatic: true)
        let afterExit = snapshot(.openAI, time: 2101, flows: [desktopFlow], processes: [cli, desktop])
        exitedSelection.reconcile(proxy: afterExit.proxy, processes: afterExit.processes, fresh: true)
        exitedTimeline.observe(snapshot: afterExit, selection: exitedSelection, now: 2101, error: nil, automatic: true)
        let afterExitDisplay = exitedTimeline.display(product: .openAI, snapshot: afterExit, selection: exitedSelection, now: 2101, error: nil, automatic: true)
        expect(afterExitDisplay.phase == .live && afterExitDisplay.sourceProjection(.desktop)?.sourcePID == 72 && afterExitDisplay.sourceProjection(.cli) == nil,
               "complete round preserves a surviving route without reviving exited PID flow")
        let otherRoute = flow(.openAI, pid: 71, id: "cli-flow", host: "api.openai.com", node: "OTHER")
        expect(dualDisplay(otherRoute).sourceProjection(.cli) == nil, "another node never borrows the selected route")
        let unknown = flow(.openAI, pid: 71, id: "cli-flow", host: "api.openai.com", association: "unconfirmed")
        expect(dualDisplay(unknown).sourceProjection(.cli) == nil, "unconfirmed CLI evidence never draws a green edge")
        let wrongPolicy = flow(.openAI, pid: 71, id: "cli-flow", host: "api.openai.com", policy: "mismatch")
        expect(dualDisplay(wrongPolicy).sourceProjection(.cli) == nil, "a differing policy cannot borrow a green selected route")
        expect(dualDisplay(cliFlow, collector: "partial").sourceProjection(.cli) == nil, "incomplete round never adds a live edge")
        expect(dualDisplay(cliFlow, automatic: false).sourceProjection(.cli) == nil, "paused observation never adds a live edge")
        print("GraphContinuityTests: \(checks) assertions passed")
    }
}
