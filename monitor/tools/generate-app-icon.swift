import AppKit

// Original vector artwork for Claude Watch. No downloaded or vendor logo assets.
let output = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
let iconset = output.appendingPathComponent("AppIcon.iconset", isDirectory: true)
try FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)

func color(_ hex: UInt32, alpha: CGFloat = 1) -> NSColor {
    NSColor(srgbRed: CGFloat((hex >> 16) & 255) / 255,
            green: CGFloat((hex >> 8) & 255) / 255,
            blue: CGFloat(hex & 255) / 255, alpha: alpha)
}

func drawIcon(size: Int) throws -> Data {
    let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size,
                                  bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
                                  isPlanar: false, colorSpaceName: .deviceRGB,
                                  bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: bitmap)
    let context = NSGraphicsContext.current!.cgContext
    context.setAllowsAntialiasing(true)
    context.setShouldAntialias(true)
    context.scaleBy(x: CGFloat(size) / 1024, y: CGFloat(size) / 1024)

    let tile = NSBezierPath(roundedRect: NSRect(x: 72, y: 72, width: 880, height: 880),
                            xRadius: 200, yRadius: 200)
    context.saveGState()
    context.setShadow(offset: CGSize(width: 0, height: -10), blur: 26,
                      color: color(0x102631, alpha: 0.22).cgColor)
    color(0x1B3343).setFill()
    tile.fill()
    context.restoreGState()
    NSGradient(starting: color(0x334E63), ending: color(0x152B38))!
        .draw(in: tile, angle: -90)

    let edge = NSBezierPath(roundedRect: NSRect(x: 75, y: 75, width: 874, height: 874),
                           xRadius: 198, yRadius: 198)
    color(0xD3E7EB, alpha: 0.16).setStroke()
    edge.lineWidth = 3
    edge.stroke()

    let shield = NSBezierPath()
    shield.move(to: NSPoint(x: 512, y: 795))
    shield.curve(to: NSPoint(x: 300, y: 716), controlPoint1: NSPoint(x: 443, y: 757), controlPoint2: NSPoint(x: 372, y: 733))
    shield.line(to: NSPoint(x: 300, y: 548))
    shield.curve(to: NSPoint(x: 512, y: 252), controlPoint1: NSPoint(x: 300, y: 408), controlPoint2: NSPoint(x: 390, y: 314))
    shield.curve(to: NSPoint(x: 724, y: 548), controlPoint1: NSPoint(x: 634, y: 314), controlPoint2: NSPoint(x: 724, y: 408))
    shield.line(to: NSPoint(x: 724, y: 716))
    shield.curve(to: NSPoint(x: 512, y: 795), controlPoint1: NSPoint(x: 652, y: 733), controlPoint2: NSPoint(x: 581, y: 757))
    shield.close()
    context.saveGState()
    context.setShadow(offset: CGSize(width: 0, height: -10), blur: 22,
                      color: color(0x071C26, alpha: 0.24).cgColor)
    color(0x8FE5C9).setFill()
    shield.fill()
    context.restoreGState()
    NSGradient(starting: color(0xE3FFF5), ending: color(0x64CEAF))!
        .draw(in: shield, angle: -90)
    color(0xF3FFFA, alpha: 0.70).setStroke()
    shield.lineWidth = 4
    shield.stroke()

    let route = NSBezierPath()
    route.move(to: NSPoint(x: 384, y: 558))
    route.line(to: NSPoint(x: 442, y: 558))
    route.curve(to: NSPoint(x: 548, y: 478), controlPoint1: NSPoint(x: 480, y: 558), controlPoint2: NSPoint(x: 510, y: 478))
    route.line(to: NSPoint(x: 640, y: 478))
    route.lineCapStyle = .round
    route.lineJoinStyle = .round
    route.lineWidth = 25
    color(0x24495A).setStroke()
    route.stroke()
    for point in [NSPoint(x: 384, y: 558), NSPoint(x: 640, y: 478)] {
        color(0x24495A).setFill()
        NSBezierPath(ovalIn: NSRect(x: point.x - 25, y: point.y - 25, width: 50, height: 50)).fill()
        color(0xD8FBEF).setFill()
        NSBezierPath(ovalIn: NSRect(x: point.x - 9, y: point.y - 9, width: 18, height: 18)).fill()
    }
    NSGraphicsContext.restoreGraphicsState()
    guard let data = bitmap.representation(using: .png, properties: [:]) else {
        throw NSError(domain: "ClaudeWatchIcon", code: 1)
    }
    return data
}

let sizes: [(String, Int)] = [
    ("icon_16x16.png", 16), ("icon_16x16@2x.png", 32),
    ("icon_32x32.png", 32), ("icon_32x32@2x.png", 64),
    ("icon_128x128.png", 128), ("icon_128x128@2x.png", 256),
    ("icon_256x256.png", 256), ("icon_256x256@2x.png", 512),
    ("icon_512x512.png", 512), ("icon_512x512@2x.png", 1024)
]
for (name, size) in sizes {
    let data = try drawIcon(size: size)
    try data.write(to: iconset.appendingPathComponent(name))
    if size == 1024 { try data.write(to: output.appendingPathComponent("AppIcon.png")) }
}
let task = Process()
task.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
task.arguments = ["-c", "icns", iconset.path, "-o", output.appendingPathComponent("AppIcon.icns").path]
try task.run()
task.waitUntilExit()
guard task.terminationStatus == 0 else { exit(task.terminationStatus) }
print("Generated AppIcon.icns and 16–1024 px icon set")
