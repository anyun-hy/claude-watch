import SwiftUI

enum WatchTypography {
    static let pageTitle = Font.system(size: 22, weight: .semibold)
    static let title = Font.system(size: 17, weight: .semibold)
    static let section = Font.system(size: 14, weight: .semibold)
    static let body = Font.system(size: 13)
    static let bodyStrong = Font.system(size: 13, weight: .medium)
    static let caption = Font.system(size: 12)
    static let small = Font.system(size: 11)
    static let mono = Font.system(size: 12, design: .monospaced)
}

struct Palette {
    let dark: Bool
    // The two schemes share a deliberately quiet blue-gray base.
    // State colors remain more saturated so paths and evidence stay scannable.
    var background: Color { color(0x26323F, 0xF6F8FB) }
    var sidebar: Color { color(0x2B3744, 0xFFFFFF) }
    var surface: Color { color(0x334150, 0xFFFFFF) }
    var elevated: Color { color(0x3A4959, 0xF1F4F8) }
    var graphBackground: Color { color(0x2A3745, 0xFAFBFE) }
    var border: Color { color(0x58687A, 0xD9E0E8) }
    var text: Color { color(0xE7EDF3, 0x27313B) }
    var secondary: Color { color(0xC0CAD5, 0x59636D) }
    var mint: Color { color(0x7BE0C3, 0x08795E) }
    var blue: Color { color(0xA8C8FF, 0x375FB0) }
    var amber: Color { color(0xF2CA86, 0x8C5908) }
    var red: Color { color(0xF5ABB4, 0xB33445) }
    func color(_ night: UInt32, _ day: UInt32) -> Color {
        let value = dark ? night : day
        return Color(red: Double((value >> 16) & 255) / 255,
                     green: Double((value >> 8) & 255) / 255, blue: Double(value & 255) / 255)
    }
}

struct Surface<Content: View>: View {
    let p: Palette
    let padding: CGFloat
    let content: Content
    init(_ p: Palette, padding: CGFloat = 16, @ViewBuilder content: () -> Content) {
        self.p = p; self.padding = padding; self.content = content()
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 0) { content }
            .padding(padding).frame(maxWidth: .infinity, alignment: .leading)
            .background(p.surface, in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(p.border.opacity(0.85), lineWidth: 1))
    }
}

struct Badge: View {
    let text: String
    let color: Color
    var body: some View {
        HStack(spacing: 5) {
            Circle().fill(color).frame(width: 5, height: 5)
            Text(text).font(.system(size: 11, weight: .medium)).lineLimit(1)
        }.padding(.horizontal, 8).padding(.vertical, 4)
            .foregroundStyle(color).background(color.opacity(0.1), in: Capsule())
            .accessibilityElement(children: .combine)
    }
}

struct SectionHeading: View {
    let title: String
    var caption: String? = nil
    let p: Palette
    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title).font(WatchTypography.section).foregroundStyle(p.text)
            if let caption {
                Text(caption).font(WatchTypography.caption).foregroundStyle(p.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

/// A single native button owns the entire header. Detail controls remain outside
/// its hit target, so selecting text or inspecting a connection never collapses it.
struct FullWidthDisclosureStyle: DisclosureGroupStyle {
    let p: Palette

    func makeBody(configuration: Configuration) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Button {
                configuration.isExpanded.toggle()
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: configuration.isExpanded ? "chevron.down" : "chevron.right")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundStyle(p.secondary)
                        .frame(width: 10)
                        .accessibilityHidden(true)
                    configuration.label.frame(maxWidth: .infinity, alignment: .leading)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityValue(configuration.isExpanded ? "已展开" : "已收起")
            if configuration.isExpanded {
                configuration.content.padding(.leading, 18)
            }
        }
    }
}

struct DetailRow: View {
    let title: String
    let value: String
    let p: Palette
    var tint: Color? = nil
    var monospaced = false
    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 14) {
            Text(title).font(WatchTypography.caption).foregroundStyle(p.secondary)
                .frame(width: 112, alignment: .leading)
            Text(value.isEmpty ? "待确认" : value)
                .font(monospaced ? WatchTypography.mono : WatchTypography.body)
                .foregroundStyle(tint ?? p.text).textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .fixedSize(horizontal: false, vertical: true)
        }.padding(.vertical, 6)
    }
}

struct InlineNotice: View {
    let title: String
    let detail: String
    let symbol: String
    let tint: Color
    let p: Palette
    var iconSize: CGFloat = 15
    var iconWidth: CGFloat = 20
    var iconWeight: Font.Weight = .regular
    var iconTint: Color? = nil
    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: symbol).font(.system(size: iconSize, weight: iconWeight)).foregroundStyle(iconTint ?? tint)
                .frame(width: iconWidth).padding(.top, 2)
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(WatchTypography.bodyStrong).foregroundStyle(p.text)
                if !detail.isEmpty {
                    Text(detail).font(WatchTypography.caption).foregroundStyle(p.secondary)
                        .lineSpacing(3).fixedSize(horizontal: false, vertical: true)
                }
            }.frame(maxWidth: .infinity, alignment: .leading)
        }.padding(12).background(tint.opacity(0.06), in: RoundedRectangle(cornerRadius: 9))
    }
}

struct EmptyState: View {
    let symbol, title, detail: String
    let p: Palette
    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: symbol).font(.system(size: 23, weight: .regular)).foregroundStyle(p.secondary)
                .frame(width: 44, height: 44).background(p.elevated, in: RoundedRectangle(cornerRadius: 12))
            Text(title).font(.system(size: 15, weight: .medium)).foregroundStyle(p.text)
            Text(detail).font(WatchTypography.body).lineSpacing(3).multilineTextAlignment(.center)
                .foregroundStyle(p.secondary).frame(maxWidth: 480)
        }.frame(maxWidth: .infinity).padding(.vertical, 24)
    }
}
