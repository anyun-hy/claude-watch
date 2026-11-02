import AppKit
import SwiftUI

struct MonitorEntryView: View {
    @ObservedObject var store: MonitorStore
    @ObservedObject var initialization: FirstRunInitialization
    var body: some View {
        Group {
            if initialization.entered { MonitorView(store: store) }
            else { FirstRunView(store: store, initialization: initialization) }
        }
        .task { await initialization.start() }
    }
}

struct FirstRunView: View {
    @ObservedObject var store: MonitorStore
    @ObservedObject var initialization: FirstRunInitialization
    @ObservedObject private var switcher: SwitcherStore
    @ObservedObject private var leakChecks: LeakCheckStore
    @AppStorage("darkAppearance") private var dark = false
    @State private var showingApproval: InitializationApproval?
    @State private var showingReport = false
    @State private var lastPresentedApproval: String?
    private let clock = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    init(store: MonitorStore, initialization: FirstRunInitialization) {
        self.store = store; self.initialization = initialization; self.switcher = store.switcher
        self.leakChecks = store.leakChecks
    }
    private var p: Palette { Palette(dark: dark) }
    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    header
                    Surface(p, padding: 0) {
                        VStack(spacing: 0) {
                            ForEach(Array(initialization.rows.enumerated()), id: \.element.id) { index, row in
                                checkRow(row, number: index + 1)
                                if index < initialization.rows.count - 1 { Divider().padding(.leading, 68) }
                            }
                        }
                    }
                    if let policy = switcher.currentPolicyEvaluation {
                        Surface(p) {
                            VStack(alignment: .leading, spacing: 12) {
                                Text("最近一次环境检测的必检项目").font(WatchTypography.section)
                                Text("以下为该次采样结果；当前保护是否就绪以第 8 项联合复核为准。")
                                    .font(WatchTypography.caption).foregroundStyle(p.secondary)
                                ForEach(policy.rows.filter(\.required)) { row in
                                    HStack(alignment: .top, spacing: 12) {
                                        Image(systemName: row.state == "ok" ? "checkmark.circle.fill" : "exclamationmark.circle")
                                            .foregroundStyle(row.state == "ok" ? p.mint : p.amber)
                                        VStack(alignment: .leading, spacing: 4) {
                                            Text(row.name).font(WatchTypography.bodyStrong)
                                            Text(row.detail).font(WatchTypography.caption).foregroundStyle(p.secondary)
                                                .fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
                                        }
                                        Spacer(minLength: 8)
                                        Text(row.statusLabel).font(WatchTypography.caption)
                                            .foregroundStyle(row.state == "ok" ? p.mint : p.amber)
                                    }.accessibilityElement(children: .combine)
                                }
                            }
                        }
                    }
                    Text("授权与检测由此窗口依次完成。首次启用后，Watch 自有守护会按已保存设置在重新打开软件或重启电脑后恢复。")
                        .font(WatchTypography.caption).foregroundStyle(p.secondary)
                }.frame(maxWidth: 880).frame(maxWidth: .infinity)
                    .padding(32)
            }
            footer
        }
        .foregroundStyle(p.text).background(p.background)
        .preferredColorScheme(dark ? .dark : .light)
        .frame(minWidth: 900, minHeight: 660)
        .navigationTitle("Claude Watch · 首次初始化")
        .onChange(of: initialization.approval?.id) {
            if initialization.approval == nil { showingApproval = nil; lastPresentedApproval = nil }
            else { presentApprovalIfNeeded() }
        }
        .onAppear { presentApprovalIfNeeded() }
        .onReceive(clock) { now in
            initialization.refreshReadiness(at: now)
            Task { await initialization.pollAccessibility(at: now) }
        }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            Task { await initialization.recheckAuthorization() }
        }
        .sheet(item: $showingApproval) { request in authorization(request) }
        .sheet(isPresented: $showingReport) { report }
    }
    private var header: some View {
        HStack(alignment: .top, spacing: 16) {
            Image(systemName: initialization.allPassed ? "checkmark.shield.fill" : "checklist")
                .font(.system(size: 30, weight: .medium))
                .foregroundStyle(initialization.allPassed ? p.mint : p.blue)
                .frame(width: 56, height: 56).background(p.surface, in: RoundedRectangle(cornerRadius: 12))
            VStack(alignment: .leading, spacing: 8) {
                Text("首次初始化检查").font(WatchTypography.pageTitle)
                Text("全部项目通过后，才能进入 Claude Watch。需要权限时会说明操作并弹出授权窗口。")
                    .font(WatchTypography.body).foregroundStyle(p.secondary)
                Text("全部通过后，等待期间会自动刷新 DNS、WebRTC 和环境状态。")
                    .font(WatchTypography.caption).foregroundStyle(p.secondary)
                HStack(spacing: 12) {
                    Text("\(initialization.passedCount) / \(initialization.rows.count) 项已通过")
                        .font(WatchTypography.bodyStrong).foregroundStyle(p.mint)
                    if initialization.running { ProgressView().controlSize(.small) }
                }
            }
        }
    }
    private func checkRow(_ row: InitializationRow, number: Int) -> some View {
        HStack(alignment: .top, spacing: 16) {
            Group {
                if row.status == .running { ProgressView().controlSize(.small) }
                else {
                    Image(systemName: row.status == .passed ? "checkmark.circle.fill" : row.status == .authorization ? "lock.circle" : row.status == .failed ? "exclamationmark.circle.fill" : "circle")
                        .font(.system(size: 24, weight: .regular))
                }
            }.frame(width: 28, height: 28).foregroundStyle(tint(row.status))
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text("\(number). \(row.step.title)").font(WatchTypography.section)
                    Spacer(minLength: 8)
                    Text(row.status == .authorization && initialization.approval?.action != .accessibility ? "等待确认" : row.status.title)
                        .font(WatchTypography.caption).foregroundStyle(tint(row.status))
                }
                if !row.detail.isEmpty {
                    Text(row.detail).font(WatchTypography.body).foregroundStyle(p.secondary)
                        .fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
                }
                if row.status == .running, row.step == .dns {
                    Text("DNS 需要多轮查询，请等待本轮完成。")
                        .font(WatchTypography.caption).foregroundStyle(p.secondary)
                }
                if row.status == .running, row.step == .dns || row.step == .webrtc,
                   let browser = leakChecks.browserViews[row.step == .dns ? .dns : .webrtc] {
                    CoffeeCollectorView(browser: browser, onDetach: row.step == .dns ? { store.leakChecks.reattachDNSBrowser($0) } : nil).frame(height: 72)
                        .clipShape(RoundedRectangle(cornerRadius: 10))
                }
                if row.status == .authorization, let request = initialization.approval {
                    HStack(spacing: 12) {
                        Button(request.action == .accessibility ? "查看并授权…" : "查看并确认…") { showingApproval = request }.frame(minHeight: 36)
                        if request.action == .accessibility {
                            Button("我已授权，重新核对") { Task { await initialization.recheckAuthorization() } }
                                .frame(minHeight: 36)
                        }
                    }.disabled(initialization.running)
                }
            }
        }.padding(20).accessibilityElement(children: .contain)
    }
    private var footer: some View {
        HStack(spacing: 12) {
            Button("退出") { NSApp.terminate(nil) }.frame(minHeight: 44).disabled(initialization.running)
            Button("检查记录…") { showingReport = true }.frame(minHeight: 44)
            Spacer()
            Button("重新检查") { Task { await initialization.retry() } }
                .frame(minHeight: 44).disabled(initialization.running)
            TimelineView(.periodic(from: .now, by: 1)) { context in
                Button("进入 Claude Watch") { Task { await initialization.enter() } }
                    .buttonStyle(.borderedProminent).tint(p.mint).frame(minHeight: 44)
                    .disabled(!initialization.canEnter(at: context.date.timeIntervalSince1970))
            }
        }.padding(.horizontal, 32).padding(.vertical, 12).background(p.surface)
            .overlay(alignment: .top) { Divider() }
    }
    private func authorization(_ request: InitializationApproval) -> some View {
        VStack(alignment: .leading, spacing: 20) {
            Label(request.title, systemImage: "lock.shield").font(WatchTypography.title)
            Text(request.detail).font(WatchTypography.body).fixedSize(horizontal: false, vertical: true)
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    ForEach(Array(request.changes.enumerated()), id: \.offset) { _, change in
                        Label(change, systemImage: "arrow.right").font(WatchTypography.body)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }.frame(maxHeight: 260)
            Text("TAG 配置与独立原版保镖保持不变。")
                .font(WatchTypography.caption).foregroundStyle(p.secondary)
            HStack {
                Button(request.action == .accessibility ? "暂不授权" : "暂不应用") {
                    if request.action == .accessibility { initialization.stopAccessibilityPolling() }
                    showingApproval = nil
                }.frame(minHeight: 44)
                Spacer()
                Button(request.action == .accessibility ? "打开系统授权" : "确认并应用") {
                    showingApproval = nil
                    Task { await initialization.authorize(request) }
                }.buttonStyle(.borderedProminent).tint(p.mint).frame(minHeight: 44)
            }
        }.padding(24).frame(width: 600).foregroundStyle(p.text).background(p.surface)
            .interactiveDismissDisabled(initialization.running)
    }
    private var report: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("初始化检查记录").font(WatchTypography.title)
            Text("第 2 步逐轮记录自动保存到本机日志；首次失败与重试分别保留。可复制下方记录，不包含 IP、节点、账号或凭据。")
                .font(WatchTypography.caption).foregroundStyle(p.secondary)
            ScrollView {
                Text(initialization.diagnosticReport).font(WatchTypography.mono).textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }.frame(height: 280)
            HStack {
                Button("关闭") { showingReport = false }.frame(minHeight: 44)
                Spacer()
                Button("复制记录") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(initialization.diagnosticReport, forType: .string)
                }.frame(minHeight: 44)
                Button("保存记录…") {
                    let panel = NSSavePanel()
                    panel.nameFieldStringValue = "ClaudeWatch-initialization.txt"
                    if panel.runModal() == .OK, let url = panel.url {
                        do { try initialization.diagnosticReport.write(to: url, atomically: true, encoding: .utf8) }
                        catch { NSAlert(error: error).runModal() }
                    }
                }.frame(minHeight: 44)
            }
        }.padding(24).frame(width: 680).foregroundStyle(p.text).background(p.surface)
    }
    private func tint(_ status: InitializationStatus) -> Color {
        switch status {
        case .passed: return p.mint
        case .failed: return p.red
        case .authorization: return p.amber
        case .running: return p.blue
        case .pending: return p.secondary
        }
    }
    private func presentApprovalIfNeeded() {
        guard let request = initialization.approval, request.id != lastPresentedApproval else { return }
        lastPresentedApproval = request.id
        showingApproval = request
    }
}
