import SwiftUI

/// A small semantic palette for the four diagnostic pages. Icon colors describe
/// content; verdict colors retain their independent success/warning meaning.
struct InspectorStyle {
    let p: Palette
    var action: Color { p.color(0xE5B591, 0x945A35) }
    var service: Color { action }
    var network: Color { p.blue }
    var proxy: Color { p.mint }
    var location: Color { p.color(0xC9B8ED, 0x75519B) }
    var transport: Color { p.color(0x8BD5D7, 0x197A80) }
    var border: Color { p.border.opacity(p.dark ? 0.55 : 0.65) }
    func pageIcon(_ page: Page) -> Color {
        switch page {
        case .ipScore: return service
        case .claudeAI: return service
        case .gptAI: return proxy
        case .dns: return network
        case .webrtc: return location
        default: return p.secondary
        }
    }
    func verdictColor(_ state: LeakVerdictState) -> Color {
        switch state {
        case .matched: return p.mint
        case .difference, .incomplete: return p.amber
        case .running, .unconfigured: return p.blue
        case .idle, .cancelled: return p.secondary
        }
    }
    func verdictSymbol(_ state: LeakVerdictState) -> String {
        switch state {
        case .matched: return "checkmark.circle"
        case .difference: return "exclamationmark.triangle"
        case .incomplete: return "clock.badge.exclamationmark"
        case .running: return "arrow.triangle.2.circlepath"
        case .cancelled: return "xmark.circle"
        case .unconfigured: return "info.circle"
        case .idle: return "circle.dotted"
        }
    }
}

struct InspectorIcon: View {
    let name: String
    let color: Color
    var size: CGFloat = 15
    var body: some View {
        Image(systemName: name).font(.system(size: size, weight: .regular))
            .symbolRenderingMode(.hierarchical).foregroundStyle(color).accessibilityHidden(true)
    }
}

struct InspectorHeading<Actions: View>: View {
    let title, subtitle, symbol: String
    let color: Color
    let p: Palette
    var brand: ServiceBrand? = nil
    @ViewBuilder let actions: Actions
    var body: some View {
        HStack(spacing: 14) {
            Group {
                if let brand { BrandLogo(brand:brand,size:26) }
                else { InspectorIcon(name:symbol,color:color,size:20)
                    .frame(width:40,height:40).background(color.opacity(p.dark ? 0.14 : 0.08),in:RoundedRectangle(cornerRadius:11)) }
            }.frame(width:40,height:40)
            VStack(alignment: .leading, spacing: 6) {
                Text(title).font(.largeTitle.weight(.semibold))
                Text(subtitle).font(.subheadline).foregroundStyle(p.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 12)
            actions
        }
    }
}

struct InspectorStatus: View {
    let verdict: LeakVerdict
    let running: Bool
    var finishedAt: Double? = nil
    let p: Palette
    var body: some View {
        let style = InspectorStyle(p: p)
        let color = style.verdictColor(verdict.state)
        HStack(alignment: .top, spacing: 12) {
            if running { ProgressView().controlSize(.small).frame(width: 20, height: 20) }
            else { InspectorIcon(name: style.verdictSymbol(verdict.state), color: color).frame(width: 20, height: 20) }
            VStack(alignment: .leading, spacing: 5) {
                Text(verdict.title).font(.headline).foregroundStyle(color)
                Text(verdict.detail).font(.callout).foregroundStyle(p.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 10)
            if let epoch = finishedAt, epoch.isFinite, epoch > 0 {
                Label(timeText(epoch), systemImage: "clock").font(.caption)
                    .foregroundStyle(p.secondary).monospacedDigit()
            }
        }.padding(16).frame(maxWidth: .infinity, alignment: .leading)
            .background(color.opacity(p.dark ? 0.09 : 0.045), in: RoundedRectangle(cornerRadius: 10))
    }
}

struct InspectorPanel<Content: View>: View {
    let p: Palette
    @ViewBuilder let content: Content
    var body: some View {
        content.background(p.surface, in: RoundedRectangle(cornerRadius: 14))
            .overlay(RoundedRectangle(cornerRadius: 14).strokeBorder(InspectorStyle(p: p).border, lineWidth: 0.7))
    }
}
