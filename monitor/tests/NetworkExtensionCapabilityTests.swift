import Foundation

@main
struct NetworkExtensionCapabilityTests {
    static func main() {
        let required = ["app-proxy-provider-systemextension"]
        let cases: [(Any?, Any?, Bool)] = [
            (true, required, true),
            (true, required + ["packet-tunnel-provider-systemextension"], true),
            (false, required, false),
            (nil, required, false),
            ("true", required, false),
            (true, nil, false),
            (true, [], false),
            (true, ["packet-tunnel-provider-systemextension"], false),
            (true, "app-proxy-provider-systemextension", false),
            (true, [1, "app-proxy-provider-systemextension"] as [Any], false),
        ]
        for (installation, providers, expected) in cases {
            precondition(NetworkExtensionCapabilities.allowsActivation(installation: installation, providers: providers) == expected,
                "Installation and the specific proxy capability must both be present and correctly typed")
        }
        print("PASS: host signing capability combinations (no manager initialization or OS calls)")
    }
}
