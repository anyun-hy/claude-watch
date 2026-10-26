import SwiftUI

struct NetCoffeeScorePage: View {
    @ObservedObject var store: NetCoffeeStore
    let p: Palette
    private var style: InspectorStyle { .init(p: p) }
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            InspectorHeading(title: "IP 评分", subtitle: "Net.Coffee · 原始评分与网络情报", symbol: "gauge.with.dots.needle.50percent", color: style.service, p: p) { EmptyView() }
            InspectorPanel(p: p) {
                VStack(alignment: .leading, spacing: 12) {
                    HStack(spacing: 12) {
                        Image(systemName: "globe").foregroundStyle(style.network)
                        TextField("输入公网 IPv4 / IPv6", text: $store.query).textFieldStyle(.roundedBorder).font(.system(.body, design: .monospaced)).onSubmit { store.start() }
                            .accessibilityLabel("评分查询 IP")
                        Button(store.isQuerying ? "取消" : "查询评分") {
                            if store.isQuerying { store.cancelQuery() } else { store.start() }
                        }.buttonStyle(.borderedProminent).tint(style.action).controlSize(.large)
                    }
                    Text("留空时查询 7890 的 HTTP 诊断出口；AI 检测页按各自诊断出口查询。").font(.caption).foregroundStyle(p.secondary)
                    if let message = store.message { Label(message, systemImage: "info.circle").foregroundStyle(p.amber).font(.callout) }
                }.padding(20)
            }
            if store.isFixture { Label("隔离预览 · 录制的真实 API 返回，采样时间见下方；不进行网络查询", systemImage: "play.rectangle").font(.caption).foregroundStyle(style.location) }
            CoffeeReportView(receipt: store.report(store.selectedIP), running: store.isQuerying, compact: false, p: p)
            Label("评分和风险属性来自第三方，不代表 AI 账号状态，也不能单独证明无泄漏。", systemImage: "info.circle").font(.caption).foregroundStyle(p.secondary)
        }.foregroundStyle(p.text).frame(maxWidth: 1120, alignment: .leading).padding(.top,24)
    }
}

struct CoffeeReportView: View {
    let receipt: CoffeeReceipt?
    let running: Bool
    var compact = false
    let p: Palette
    @State private var rawExpanded = false
    private var style: InspectorStyle { .init(p:p) }
    private let attributes: [(String,String)] = [("isResidential","住宅网络"),("is_datacenter","数据中心"),("is_vpn","VPN"),("is_proxy","代理"),("is_tor","Tor"),("is_abuser","滥用记录"),("is_mobile","移动网络"),("is_crawler","爬虫")]
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            InspectorPanel(p:p) {
                VStack(alignment:.leading,spacing:16) {
                    HStack {
                        Label("Net.Coffee 网络资料",systemImage:"chart.bar.xaxis").font(.headline).foregroundStyle(style.service)
                        Spacer()
                        if running { ProgressView().controlSize(.small); Text("查询中").font(.caption).foregroundStyle(p.secondary) }
                        else if let r = receipt { Text("HTTP \(r.httpStatus.map(String.init) ?? "—")").font(.caption.monospaced()).foregroundStyle(p.secondary) }
                    }
                    if let r = receipt {
                        if running { Text("正在获取本轮数据，下方为上次结果。").font(.caption).foregroundStyle(p.amber) }
                        if r.status != "complete" { Label(r.error ?? "未取得完整结果",systemImage:"exclamationmark.triangle").font(.callout).foregroundStyle(p.amber) }
                        scoreAndIdentity(r)
                        Divider()
                        Text("来源 Net.Coffee · \(Date(timeIntervalSince1970:r.queriedAt).formatted(date:.abbreviated,time:.standard))\(Date().timeIntervalSince1970-r.queriedAt > 300 ? " · 历史样本" : "")")
                            .font(.caption).foregroundStyle(p.secondary)
                        Text(r.sourceURL).font(.caption).foregroundStyle(p.secondary).textSelection(.enabled).fixedSize(horizontal:false,vertical:true)
                    } else {
                        Text(running ? "等待原站返回评分和 IP 资料" : "尚未查询 IP 资料").font(.body.weight(.medium))
                        Text("超时、空结果或缺少评分时均显示未取得。").font(.callout).foregroundStyle(p.secondary)
                    }
                }.padding(20)
            }
            if !compact, let r = receipt, let data = r.data {
                InspectorPanel(p:p) {
                    VStack(alignment:.leading,spacing:16) {
                        Label("网络属性",systemImage:"line.3.horizontal.decrease.circle").font(.headline).foregroundStyle(style.proxy)
                        LazyVGrid(columns:[GridItem(.adaptive(minimum:220),alignment:.leading)],alignment:.leading,spacing:16) {
                            ForEach(attributes,id:\.0) { key,title in
                                HStack { Text(title).foregroundStyle(p.secondary); Spacer(); Text(data[key]?.flag.map { $0 ? "是" : "否" } ?? "未提供").fontWeight(.medium) }
                            }
                        }
                        Divider()
                        DetailRow(title:"运营组织",value:r.field("company_name"),p:p)
                        DetailRow(title:"组织类型",value:r.field("company_type"),p:p)
                        DetailRow(title:"数据中心",value:r.field("datacenter_name"),p:p)
                        DetailRow(title:"反向 DNS",value:r.field("rdns"),p:p,monospaced:true)
                        DetailRow(title:"CIDR",value:r.field("cidr"),p:p,monospaced:true)
                        DetailRow(title:"RPKI",value:r.field("rpki_status"),p:p)
                    }.padding(20)
                }
                if let ai = data["ai_verdict"] {
                    InspectorPanel(p:p) { VStack(alignment:.leading,spacing:12) {
                        Label("原站分析",systemImage:"text.magnifyingglass").font(.headline).foregroundStyle(style.location)
                        Text(ai["label"]?.text ?? "未提供分析标签").font(.body.weight(.semibold))
                        if let text = ai["reasoning"]?.text { Text(text).font(.callout).fixedSize(horizontal:false,vertical:true).textSelection(.enabled) }
                        Text("置信信息：\(ai["confidence"]?.text ?? "未提供") · 原站字段，非本软件推断").font(.caption).foregroundStyle(p.secondary)
                    }.padding(20) }
                }
                ForEach([("geo_sources","多源地理数据","map"),("intelligence","威胁情报","shield.lefthalf.filled"),("range","地址范围","square.stack.3d.up"),("public_service","公共服务识别","server.rack"),("vpn_trace","VPN 线索","point.topleft.down.curvedto.point.bottomright.up"),("related_domains","关联域名","link"),("location_history","位置历史","clock.arrow.circlepath"),("asn_history","ASN 历史","clock"),("company_history","组织历史","building.2"),("dc_neighbors","同段数据中心","externaldrive")],id:\.0) { key,title,icon in
                    if let value = data[key] {
                        DisclosureGroup { Text(value.pretty).font(.system(.caption,design:.monospaced)).textSelection(.enabled).frame(maxWidth:.infinity,alignment:.leading).padding(.top,12) } label: {
                            Label(title,systemImage:icon).font(.callout.weight(.medium)).foregroundStyle(style.network)
                        }.disclosureGroupStyle(FullWidthDisclosureStyle(p:p))
                    }
                }
                DisclosureGroup(isExpanded:$rawExpanded) {
                    VStack(alignment:.leading,spacing:12) {
                        Text("\(r.transport ?? "") · 原始响应 SHA-256 \(r.sha256 ?? "未提供")").font(.caption).foregroundStyle(p.secondary).textSelection(.enabled)
                        Text(r.raw).font(.system(.caption,design:.monospaced)).textSelection(.enabled).frame(maxWidth:.infinity,alignment:.leading)
                    }.padding(.top,12)
                } label: { Label("全部原始字段",systemImage:"doc.text.magnifyingglass").font(.callout.weight(.medium)).foregroundStyle(p.secondary) }
                .disclosureGroupStyle(FullWidthDisclosureStyle(p:p))
            }
        }
    }
    private func scoreAndIdentity(_ r: CoffeeReceipt) -> some View {
        HStack(alignment:.center,spacing:24) {
            VStack(alignment:.leading,spacing:4) {
                HStack(alignment:.firstTextBaseline,spacing:4) {
                    Text(r.score.map(String.init) ?? "—").font(.system(size:44,weight:.semibold,design:.rounded)).monospacedDigit()
                    Text("/ 100").font(.callout).foregroundStyle(p.secondary)
                }
                Text("原站信任分").font(.caption).foregroundStyle(p.secondary)
            }.frame(minWidth:116,alignment:.leading)
            Rectangle().fill(p.border).frame(width:1,height:64)
            VStack(alignment:.leading,spacing:8) {
                Text(r.query).font(.system(.title3,design:.monospaced).weight(.semibold)).textSelection(.enabled)
                CountryLine(code:r.data?["countryCode"]?.text,country:r.data?["country"]?.text,region:r.data?["region"]?.text,city:r.data?["city"]?.text,p:p)
                Text("AS\(r.field("asn")) · \(r.field("asOrganization"))").font(.callout).foregroundStyle(p.secondary).fixedSize(horizontal:false,vertical:true)
            }.frame(maxWidth:.infinity,alignment:.leading)
        }
    }
}

struct CoffeeAIReport: View {
    let ip: String
    @ObservedObject var store: NetCoffeeStore
    let p: Palette
    let open: () -> Void
    var body: some View {
        VStack(alignment:.leading,spacing:12) {
            HStack {
                Text("诊断出口 IP 资料").font(.headline)
                Spacer()
                Button("查看完整资料") { store.query=ip; store.selectedForPage(ip); open() }.disabled(LeakIPAddress(ip)?.isPublic != true)
                Button(store.running.contains("risk:"+ip) ? "查询中" : "查询评分") { store.fetchAI(ip) }.disabled(LeakIPAddress(ip)?.isPublic != true || store.running.contains("risk:"+ip))
            }
            CoffeeReportView(receipt:store.riskReports[ip],running:store.running.contains("risk:"+ip),compact:true,p:p)
            Text("此处使用原站 AI 检测的 iprisk 接口；完整资料页使用 ip/lookup，两者保留各自返回与时间。 ").font(.caption).foregroundStyle(p.secondary)
        }
    }
}
