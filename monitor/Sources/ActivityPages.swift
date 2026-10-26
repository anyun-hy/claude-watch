import AppKit
import SwiftUI

struct ProcessActivityPage: View {
    @ObservedObject var store: MonitorStore
    let p: Palette
    var body: some View {
        Surface(p) {
            VStack(alignment: .leading, spacing: 16) {
                SectionHeading(title: "应用与组件", caption: "按名称聚合 Chromium 组件与 MCP 工具；PID 变化不会增加新的组件条目。", p: p)
                if let snapshot = store.snapshot {
                    let groups = Dictionary(grouping: snapshot.processes, by: \.componentKey)
                    if groups.isEmpty {
                        EmptyState(symbol: "desktopcomputer", title: "当前未检测到 AI 应用进程", detail: "后台会继续观察进程活动。", p: p)
                    } else {
                        ForEach(groups.keys.sorted(), id: \.self) { key in
                            if let records = groups[key] { ProcessComponentRow(records: records, live: store.live, p: p) }
                        }
                    }
                } else {
                    Text(store.error ?? "等待首次进程采样。").font(.callout).foregroundStyle(p.secondary)
                }
            }
        }
    }
}

private struct ProcessComponentRow: View {
    let records: [WatchedProcess]
    let live: Bool
    let p: Palette
    @State private var rawExpanded = false
    private var first: WatchedProcess { records[0] }
    private var symbol: String {
        if first.runtimeRole == "mcp" { return "puzzlepiece.extension" }
        if first.runtimeRole == "chromium_network" { return "network" }
        if first.runtimeRole == "chromium_gpu" { return "cpu" }
        if first.sourceRole == .cli { return "terminal" }
        return "macwindow"
    }
    var body: some View {
        DisclosureGroup(isExpanded: $rawExpanded) {
            VStack(alignment: .leading, spacing: 8) {
                Text("原始进程信息，仅用于故障排查；应用与组件身份不依赖 PID 数字显示。")
                    .font(.caption).foregroundStyle(p.secondary)
                ForEach(records) { process in
                    Text("PID \(process.pid) · \(process.started) · 会话登记：\(process.authorized == true ? "已登记" : "未登记或未采样")")
                        .font(WatchTypography.mono).foregroundStyle(p.secondary).textSelection(.enabled)
                }
            }.padding(.top, 10).padding(.bottom, 12)
        } label: {
            HStack(spacing: 12) {
                InspectorIcon(name: symbol, color: first.runtimeRole == "mcp" ? InspectorStyle(p: p).location : p.blue)
                    .frame(width: 22)
                VStack(alignment: .leading, spacing: 5) {
                    Text(first.componentName).font(.body.weight(.medium)).foregroundStyle(p.text)
                    Text(first.productDisplay + " · " + (first.runtimeRole == "mcp" ? "工具组件" : first.sourceRole == .child ? "应用关联组件" : first.sourceDisplay))
                        .font(.caption).foregroundStyle(p.secondary)
                }
                Spacer(minLength: 12)
                Text("\(records.count) 个进程 · " + (live ? "运行中" : "上次采样"))
                    .font(.caption).foregroundStyle(p.secondary).monospacedDigit()
            }.padding(.vertical, 12)
        }.disclosureGroupStyle(FullWidthDisclosureStyle(p: p))
            .overlay(alignment: .bottom) { Rectangle().fill(p.border.opacity(0.6)).frame(height: 0.5) }
    }
}

struct EventTimelinePage: View {
    @ObservedObject var store: MonitorStore
    let p: Palette
    @State private var query = ""
    @State private var filter = "全部"

    private let filters = ["全部", "需关注", "网络", "进程"]

    private var filteredEvents: [Event] {
        (store.snapshot?.events ?? []).filter { event in
            matchesFilter(event) && matchesQuery(event)
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            controls
            Surface(p) {
                HStack(alignment: .firstTextBaseline) {
                    SectionHeading(title: "事件记录", caption: "来自已有监控日志；最新记录在前。", p: p)
                    Spacer()
                    if store.snapshot != nil { Text("\(filteredEvents.count) 条")
                        .font(WatchTypography.caption).foregroundStyle(p.secondary) }
                }

                if let snapshot = store.snapshot {
                    if snapshot.events.isEmpty {
                        EmptyState(symbol: "text.alignleft", title: "尚无事件记录",
                                   detail: "当前快照已读取，但日志中没有可显示的事件。", p: p)
                    } else if filteredEvents.isEmpty {
                        EmptyState(symbol: "line.3.horizontal.decrease.circle", title: "没有符合条件的记录",
                                   detail: query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                                   ? "调整筛选条件，或等待新的监控事件。"
                                   : "没有记录匹配“\(query)”。可清除搜索或调整筛选条件。", p: p)
                    } else {
                        LazyVStack(spacing: 0) {
                            ForEach(filteredEvents) { event in
                                EventTimelineRow(event: event, p: p)
                            }
                        }.padding(.top, 12)
                    }
                } else if let error = store.error {
                    InlineNotice(title: "暂时无法读取事件记录", detail: error,
                                 symbol: "exclamationmark.triangle", tint: p.amber, p: p)
                        .padding(.top, 18)
                } else {
                    EmptyState(symbol: "clock.arrow.circlepath", title: "正在读取事件记录",
                               detail: "等待首次监控快照。", p: p)
                }
            }
        }
    }

    private var controls: some View {
        HStack(spacing: 12) {
            Picker("类型", selection: $filter) {
                ForEach(filters, id: \.self) { Text($0).tag($0) }
            }
            .pickerStyle(.segmented).labelsHidden().frame(width: 278)

            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass").font(.system(size: 12)).foregroundStyle(p.secondary)
                TextField("搜索记录、IP 或 PID", text: $query)
                    .textFieldStyle(.plain).font(WatchTypography.caption)
                if !query.isEmpty {
                    Button { query = "" } label: {
                        Image(systemName: "xmark.circle.fill").foregroundStyle(p.secondary)
                    }.buttonStyle(.plain).accessibilityLabel("清除搜索")
                }
            }
            .padding(.horizontal, 10).frame(height: 32).frame(maxWidth: 360)
            .background(p.surface, in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(p.border, lineWidth: 1))

            Spacer(minLength: 8)
            Button("打开日志") { openLog() }
                .buttonStyle(.bordered).controlSize(.small).disabled(store.snapshot?.logPath.isEmpty != false)
        }
    }

    private func matchesFilter(_ event: Event) -> Bool {
        switch filter {
        case "需关注": return ["warning", "error", "notice"].contains(event.severity)
        case "网络": return event.category == "network"
        case "进程": return event.category == "process"
        default: return true
        }
    }

    private func matchesQuery(_ event: Event) -> Bool {
        let term = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !term.isEmpty else { return true }
        return (event.title + " " + event.detail + " " + event.timestamp).localizedCaseInsensitiveContains(term)
    }

    private func openLog() {
        guard let path = store.snapshot?.logPath, !path.isEmpty else { return }
        NSWorkspace.shared.open(URL(fileURLWithPath: path))
    }
}

struct EventTimelineRow: View {
    let event: Event
    let p: Palette
    var compact = false
    @State private var expanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Image(systemName: statusSymbol).font(.system(size: 12, weight: .semibold)).foregroundStyle(statusColor)
                    .frame(width: 16)
                Text(event.title.isEmpty ? "未命名事件" : event.title)
                    .font(WatchTypography.bodyStrong).foregroundStyle(p.text).lineLimit(compact ? 1 : 2)
                Spacer(minLength: 8)
                Text(timestamp).font(WatchTypography.small.monospaced()).foregroundStyle(p.secondary)
                    .lineLimit(1).textSelection(.enabled)
            }

            HStack(spacing: 8) {
                Badge(text: statusLabel, color: statusColor)
                if !event.category.isEmpty { Text(categoryLabel).font(WatchTypography.small).foregroundStyle(p.secondary) }
            }.padding(.leading, 26)

            if compact {
                Text(detailText).font(WatchTypography.caption).foregroundStyle(p.secondary).lineSpacing(3)
                    .lineLimit(2).textSelection(.enabled).padding(.leading, 26)
            } else {
                DisclosureGroup(isExpanded: $expanded) {
                    Text(detailText).font(WatchTypography.caption).foregroundStyle(p.secondary).lineSpacing(3)
                        .textSelection(.enabled).padding(.top, 5)
                } label: {
                    Text(expanded ? "收起原始记录" : detailText)
                        .font(WatchTypography.caption).foregroundStyle(expanded ? p.blue : p.secondary)
                        .lineLimit(2).multilineTextAlignment(.leading)
                }
                .padding(.leading, 26).padding(.top, 1).help("展开或收起完整记录")
            }
        }
        .padding(.vertical, compact ? 10 : 13)
        .overlay(alignment: .bottom) { Rectangle().fill(p.border.opacity(0.62)).frame(height: 1) }
    }

    private var detailText: String { event.detail.isEmpty ? "未提供原始记录内容。" : event.detail }
    private var timestamp: String { event.epoch.map { timeText($0, date: !compact) } ?? (event.timestamp.isEmpty ? "时间待确认" : event.timestamp) }

    private var statusLabel: String {
        switch event.severity {
        case "error": return "错误"
        case "warning": return "需关注"
        case "notice": return "提示"
        case "info": return "信息"
        default: return event.severity.isEmpty ? "状态待确认" : event.severity
        }
    }

    private var statusColor: Color {
        switch event.severity {
        case "error": return p.red
        case "warning": return p.amber
        case "notice": return p.blue
        default: return p.secondary
        }
    }

    private var statusSymbol: String {
        switch event.severity {
        case "error": return "xmark.octagon.fill"
        case "warning": return "exclamationmark.triangle.fill"
        case "notice": return "info.circle.fill"
        default: return "info.circle"
        }
    }

    private var categoryLabel: String {
        switch event.category {
        case "network": return "网络"
        case "process": return "进程"
        default: return event.category
        }
    }
}
