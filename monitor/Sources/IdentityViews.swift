import AppKit
import SwiftUI

private enum IdentityAssets {
    static let images = NSCache<NSString,NSImage>()
    static func image(_ relative: String) -> NSImage? {
        if let cached = images.object(forKey:relative as NSString) { return cached }
        guard let root = Bundle.main.resourceURL, let image = NSImage(contentsOf:root.appendingPathComponent("Identity/"+relative)) else { return nil }
        images.setObject(image,forKey:relative as NSString); return image
    }
}

struct BrandLogo: View {
    let brand: ServiceBrand
    var size: CGFloat = 20
    var body: some View {
        Group {
            if let image = IdentityAssets.image("brands/"+brand.rawValue+".png") {
                Image(nsImage:image).resizable().interpolation(.high).scaledToFit()
            } else { Image(systemName:"square.dashed").resizable().scaledToFit().foregroundStyle(.secondary) }
        }.frame(width:size,height:size)
            .padding(size >= 22 ? 4 : 2)
            .background(Color.white.opacity(0.96),in:RoundedRectangle(cornerRadius:size >= 22 ? 7 : 4))
            .overlay(RoundedRectangle(cornerRadius:size >= 22 ? 7 : 4).strokeBorder(Color.black.opacity(0.06),lineWidth:0.5))
            .accessibilityLabel(brand.title+" 标识")
    }
}
struct CountryFlag: View {
    let code: String?
    var width: CGFloat = 18
    var body: some View {
        if let code = CountryIdentity.code(code), let image = IdentityAssets.image("flags/"+code.lowercased()+".png") {
            Image(nsImage:image).resizable().interpolation(.high).scaledToFit()
                .frame(width:width,height:width*0.75)
                .clipShape(RoundedRectangle(cornerRadius:2))
                .overlay(RoundedRectangle(cornerRadius:2).strokeBorder(Color.gray.opacity(0.22),lineWidth:0.5))
                .accessibilityHidden(true)
        }
    }
}
struct CountryLine: View {
    var code: String? = nil
    var country: String? = nil
    var region: String? = nil
    var city: String? = nil
    var organization: String? = nil
    let p: Palette
    var body: some View {
        HStack(alignment:.center,spacing:8) {
            CountryFlag(code:CountryIdentity.code(code,country:country))
            Text(CountryIdentity.place([country,region,city,organization]))
                .font(.callout).foregroundStyle(p.secondary).textSelection(.enabled)
                .fixedSize(horizontal:false,vertical:true)
        }.accessibilityElement(children:.combine)
    }
}
