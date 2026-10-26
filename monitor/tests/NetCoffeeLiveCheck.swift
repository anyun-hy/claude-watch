import AppKit
import WebKit
@main struct NetCoffeeLiveCheck {
    @MainActor static func main() {
        let app=NSApplication.shared; app.setActivationPolicy(.accessory)
        let host = NSWindow(contentRect:NSRect(x:120,y:120,width:640,height:120),styleMask:[.titled],backing:.buffered,defer:false)
        host.title = "Claude Watch · 隔离网络检测"
        let runner=NetCoffeeLeakRunner(); var receipts:[LeakProbeResult]=[]
        let destination=CommandLine.arguments[1]
        func finish() {
            do { let e=JSONEncoder(); e.outputFormatting=[.prettyPrinted,.sortedKeys]; try e.encode(receipts).write(to:URL(fileURLWithPath:destination)); print("Own diagnostic harness finished: \(receipts.map{$0.kind+":"+$0.status}.joined(separator:", "))") } catch { print(error); exit(1) }; exit(0)
        }
        runner.start(kind:.dns,id:UUID(),progress:{ print($0); fflush(stdout) }) { dns in
            print("DNS finished: \(dns.status)"); fflush(stdout); receipts.append(dns)
            runner.start(kind:.webrtc,id:UUID(),progress:{print($0);fflush(stdout)}) { rtc in receipts.append(rtc); host.orderOut(nil); finish() }
            host.contentView = runner.browserView; host.orderFront(nil)
        }
        host.contentView = runner.browserView; host.orderFront(nil)
        app.run(); _=runner
    }
}
