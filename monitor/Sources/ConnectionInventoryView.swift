import SwiftUI

struct ConnectionInventoryView: View {
    @ObservedObject var store: MonitorStore
    let p: Palette
    @State private var expanded: Set<ConnectionPurpose> = []
    private var product: MonitoredProduct { store.networkSelection.product }
    private var display: GraphDisplayState { store.graphDisplay(for: product) }
    private var groups: [ConnectionServiceGroup] {
        guard display.countsAvailable else { return [] }
        return ConnectionInventory.groups(product: product,
            processes: display.currentProcesses, flows: display.currentFlows,
            proxyEndpoint: display.currentProxy?.endpoint ?? "127.0.0.1:7890")
    }
    var body: some View {
        Surface(p) {
            VStack(alignment: .leading, spacing: 16) {
                SectionHeading(title: "连接用途", caption: display.countsAvailable
                    ? "仅统计本轮完整采样；历史路径不参与分类或计数。"
                    : "本轮统计不可确认（—）；原因见上方连接状态。", p: p)
                ForEach(ConnectionPurpose.allCases) { purpose in
                    let items = groups.filter { $0.purpose == purpose }
                    DisclosureGroup(isExpanded: Binding(get: { expanded.contains(purpose) }, set: {
                        if $0 { expanded.insert(purpose) } else { expanded.remove(purpose) }
                    })) {
                        if display.countsAvailable {
                            VStack(spacing: 0) {
                                if items.isEmpty {
                                    Text("本轮暂无").font(.caption).foregroundStyle(p.secondary)
                                        .frame(maxWidth: .infinity, alignment: .leading).padding(.top, 8)
                                } else {
                                    ForEach(items) { group in ConnectionServiceRow(group: group, store: store, p: p) }
                                }
                            }.padding(.top, 8)
                        } else {
                            Text("—").font(.caption).foregroundStyle(p.secondary).padding(.top, 8)
                        }
                    } label: {
                        HStack(spacing: 10) {
                            InspectorIcon(name: purpose.symbol, color: tint(purpose)).frame(width: 18)
                            Text(purpose.title).font(.body.weight(.medium)).foregroundStyle(p.text)
                            Spacer()
                            Text(display.countsAvailable
                                 ? "\(items.count) 项 · \(items.reduce(0) { $0 + $1.flows.count }) 条连接"
                                 : "—")
                                .font(.caption).foregroundStyle(p.secondary).monospacedDigit()
                        }.padding(.vertical, 6)
                    }.disclosureGroupStyle(FullWidthDisclosureStyle(p: p))
                }
            }
        }
    }
    private func tint(_ purpose: ConnectionPurpose) -> Color {
        switch purpose {
        case .platform: return p.blue
        case .mcp: return InspectorStyle(p: p).location
        case .local: return p.secondary
        case .component: return InspectorStyle(p: p).transport
        case .unidentified: return p.secondary
        }
    }
}

private struct ConnectionServiceRow: View {
    let group: ConnectionServiceGroup
    @ObservedObject var store: MonitorStore
    let p: Palette
    @State private var expanded = false
    @State private var rawExpanded = false
    private var tint: Color {
        if group.purpose == .local { return p.secondary }
        if group.flows.contains(where: { $0.policy == "mismatch" }) { return p.amber }
        return group.purpose == .platform && group.status == "样本匹配" ? p.mint : p.secondary
    }
    var body: some View {
        DisclosureGroup(isExpanded: $expanded) {
            VStack(alignment: .leading, spacing: 10) {
                Text(group.note).font(.callout).foregroundStyle(p.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                ForEach(group.routes, id: \.self) { route in
                    Label(route, systemImage: "point.3.connected.trianglepath.dotted")
                        .font(.callout).foregroundStyle(p.blue).textSelection(.enabled)
                }
                if group.routes.isEmpty && group.purpose != .local {
                    Text("代理链尚未关联；不会据此认定直连或安全。").font(.caption).foregroundStyle(p.secondary)
                }
                ForEach(group.endpoints, id: \.self) { endpoint in
                    Text(endpoint).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                }
                if group.purpose == .platform {
                    Button("在连接图查看此服务") { store.selectNetworkFlow(group.representative, product: store.networkSelection.product) }
                        .buttonStyle(.link).font(.callout)
                }
                DisclosureGroup(isExpanded: $rawExpanded) {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(group.flows) { flow in
                            VStack(alignment: .leading, spacing: 4) {
                                Text(verbatim: "PID \(flow.pid) · \(flow.transport) · \(flow.local) → \(flow.peer)")
                                Text(flow.reason)
                            }.font(.system(.caption, design: .monospaced)).foregroundStyle(p.secondary)
                                .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                        }
                    }.padding(.top, 8)
                } label: { Text("原始 socket 记录（\(group.flows.count)）").font(.caption).foregroundStyle(p.secondary) }
                    .disclosureGroupStyle(FullWidthDisclosureStyle(p: p))
            }.padding(.top, 10).padding(.bottom, 6)
        } label: {
            HStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 5) {
                    Text(group.name).font(.body.weight(.medium)).foregroundStyle(p.text)
                    Text("\(group.flows.count) 条连接" + (group.routes.count > 1 ? " · \(group.routes.count) 条代理链" : ""))
                        .font(.caption).foregroundStyle(p.secondary).monospacedDigit()
                }
                Spacer(minLength: 10)
                Text(group.status).font(.caption.weight(.medium)).foregroundStyle(tint)
            }.padding(.vertical, 12)
        }.disclosureGroupStyle(FullWidthDisclosureStyle(p: p))
            .overlay(alignment: .bottom) { Rectangle().fill(p.border.opacity(0.5)).frame(height: 0.5) }
    }
}
