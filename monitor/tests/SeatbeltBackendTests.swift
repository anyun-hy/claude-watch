import Foundation

@main
struct SeatbeltBackendTests {
    static func require(_ condition: Bool, _ message: String) {
        precondition(condition, message)
    }

    static func main() throws {
        let decoder = JSONDecoder()
        var facts: [String: Any] = [
            "backend": "seatbelt", "configured_entries": ["controlled-fixture"],
            "protected_pids": [4101], "unprotected_pids": [], "uncovered_boundaries": [],
            "server_identity_verified": false, "gateway_endpoint_protection_verified": true,
            "gateway_endpoint_protection_method": "launchd_socket_reservation"
        ]
        func scope() throws -> BackendCoverageScopeModel {
            try decoder.decode(BackendCoverageScopeModel.self,
                               from: JSONSerialization.data(withJSONObject: facts))
        }
        require(try scope().allDiscoveredProtected, "current Seatbelt proof remains usable")
        for backend in ["network_extension", "network-extension", "ne", "legacy_ne", "future_backend"] {
            facts["backend"] = backend
            let decoded = try scope()
            require(decoded.backend == backend, "legacy facts remain readable for diagnosis")
            require(!decoded.allDiscoveredProtected, "retired or unknown backend cannot claim current coverage")
        }
        facts["backend"] = "seatbelt"
        facts["gateway_endpoint_protection_verified"] = false
        require(try !scope().allDiscoveredProtected, "missing endpoint evidence cannot claim protection")
        facts["gateway_endpoint_protection_verified"] = true
        facts["unprotected_pids"] = [4102]
        require(try !scope().allDiscoveredProtected, "ordinary discovery does not imply protected coverage")
        facts["unprotected_pids"] = []
        facts.removeValue(forKey: "configured_entries")
        require(try !scope().allDiscoveredProtected, "incomplete legacy facts cannot claim protection")
        print("SeatbeltBackendTests: current coverage retained; retired, unknown and incomplete evidence rejected")
    }
}
