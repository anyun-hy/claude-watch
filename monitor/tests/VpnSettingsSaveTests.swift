import Foundation

@main
struct VpnSettingsSaveTests {
    @MainActor
    static func main() async throws {
        var checks = 0
        func expect(_ value: @autoclosure () -> Bool, _ message: String) {
            checks += 1
            guard value() else {
                FileHandle.standardError.write(Data(("FAIL: " + message + "\n").utf8))
                exit(1)
            }
        }

        let initialExpectation = VpnExpectationModel(
            configured: true, proxy_mode: "tag", proxy_url: "http://127.0.0.1:18991",
            proxy_group: "A", running_mode: "rule", expected_node: "N1"
        )
        var persisted: [String: Any] = [
            "schema": 2, "network_backend": "seatbelt", "enabled": true,
            "proxy_mode": "tag", "proxy_url": "http://127.0.0.1:18991",
            "proxy_group": "A", "country": "JP",
            "vpn_expectation": try JSONSerialization.jsonObject(with: JSONEncoder().encode(initialExpectation))
        ]
        var failNext = false
        var writes = 0
        let store = SwitcherStore(isFixture: true)
        // Exercise real Store actions and response handling with an isolated
        // transport. This fixture does not claim Rust persistence or UI clicks.
        store.configurationCommandFixture = { args, input in
            writes += 1
            if failNext {
                failNext = false
                return try JSONSerialization.data(withJSONObject: ["status": "error", "message": "fixture save rejected"])
            }
            let submitted = try JSONSerialization.jsonObject(with: input) as! [String: Any]
            if args.starts(with: ["config", "vpn-expectation-save"]) {
                persisted["vpn_expectation"] = submitted
                for key in ["proxy_mode", "proxy_url", "proxy_group"] { persisted[key] = submitted[key] }
            } else {
                persisted = submitted
            }
            return try JSONSerialization.data(withJSONObject: [
                "status": "ok", "config": persisted, "policy_sync_state": "pending_apply"
            ])
        }
        store.settings = persisted
        await store.save()
        expect(!store.failure && store.vpnExpectationDraft.configured, "initial saved baseline is decoded")

        store.updateVpnExpectationDraft(proxyGroup: "B")
        store.flag(Setting.enabled).wrappedValue = false
        await store.save()
        expect(!store.failure && !store.hasUnsavedSettings, "combined save acknowledges both drafts")
        expect(persisted["proxy_group"] as? String == "B", "VPN editor group survives general save")
        expect((persisted["vpn_expectation"] as? [String: Any])?["proxy_group"] as? String == "B", "shared authorities agree in submitted config")
        expect(persisted["enabled"] as? Bool == false, "ordinary change is included in general save")

        store.text(Setting.country).wrappedValue = "US"
        store.updateVpnExpectationDraft(expectedNode: "N2")
        await store.confirmAndSaveVpnExpectation()
        expect(!store.failure, "VPN-only save succeeds")
        expect(persisted["country"] as? String == "JP", "VPN-only action does not save ordinary draft")
        expect(store.settings["country"] as? String == "US" && store.hasUnsavedSettings, "VPN-only acknowledgement retains ordinary unsaved draft")
        expect(store.vpnExpectationDraft.expected_node == "N2", "VPN draft reflects the acknowledged expectation")
        store.discardChanges()
        expect(store.settings["country"] as? String == "JP" && !store.hasUnsavedSettings, "discard restores only the remaining ordinary draft")
        expect(store.vpnExpectationDraft.expected_node == "N2", "discard does not undo separately saved VPN expectation")

        store.updateVpnExpectationDraft(expectedNode: "N3")
        store.flag(Setting.enabled).wrappedValue = true
        let previousSyncState = store.policySyncPendingApply
        failNext = true
        await store.save()
        expect(store.failure && store.hasUnsavedSettings, "general save failure preserves dirty state")
        expect(store.vpnExpectationDraft.expected_node == "N3" && store.settings["enabled"] as? Bool == true, "general failure preserves both drafts")
        expect((persisted["vpn_expectation"] as? [String: Any])?["expected_node"] as? String == "N2", "failure does not update persisted expectation")
        failNext = true
        await store.confirmAndSaveVpnExpectation()
        expect(store.failure && store.hasUnsavedSettings, "VPN save failure preserves ordinary and VPN drafts")
        expect(store.policySyncPendingApply == previousSyncState, "failed save cannot clear the previous saved policy's pending state")
        await store.save()
        expect(!store.failure && !store.hasUnsavedSettings, "subsequent success acknowledges retained drafts")

        store.text(TextSetting(key: "proxy_group")).wrappedValue = "C"
        expect(store.vpnExpectationDraft.proxy_group == "C", "ordinary shared-field editor updates the same VPN draft")
        await store.confirmAndSaveVpnExpectation()
        expect(persisted["proxy_group"] as? String == "C", "VPN save preserves latest ordinary shared-field edit")
        store.updateVpnExpectationDraft(proxyGroup: "D")
        await store.save()
        expect(persisted["proxy_group"] as? String == "D", "latest VPN editor change is not overwritten by stale ordinary state")

        store.settings["proxy_group"] = "top-level-conflict"
        store.vpnExpectationDraft.proxy_group = "vpn-conflict"
        let writesBeforeConflict = writes
        await store.save()
        expect(store.failure && writes == writesBeforeConflict, "conflicting programmatic drafts fail before sending a write")
        expect(store.settings["proxy_group"] as? String == "top-level-conflict" && store.vpnExpectationDraft.proxy_group == "vpn-conflict", "conflict does not destroy either edit")

        store.discardChanges()
        store.configurationCommandFixture = { _, _ in
            try JSONSerialization.data(withJSONObject: ["status": "ok", "config": persisted, "policy_sync_state": "apply_failed"])
        }
        await store.save()
        expect(store.policySyncState == .applyFailed && !store.policySyncPendingApply,
               "executor application failure remains distinct from pending apply")
        expect(store.policySyncState?.labelZh.contains("失败") == true,
               "settings view receives the actual execution failure wording")

        let sparse = try JSONDecoder().decode(VpnExpectationModel.self, from: Data(#"{"configured":true,"running_mode":"rule","expected_node":"N4"}"#.utf8))
        expect(sparse.configured && sparse.expected_chain.isEmpty && sparse.expected_node == "N4", "Rust-omitted optional fields do not reset saved expectation")
        print("VpnSettingsSaveTests: \(checks) checks passed; isolated transport, no real configuration writes")
    }
}
