import Foundation

/// A typed handle for one configuration key.
///
/// A key is declared once here and referenced by handle everywhere else, so a
/// call site cannot misspell a name and a rename cannot leave a stale literal
/// behind. Reading is a table lookup, never a chain of comparisons on an id.
struct FlagSetting: Hashable {
    let key: String
}

struct TextSetting: Hashable {
    let key: String
}

/// A three-state action. The fallback is the value assumed when the key is
/// absent, and it belongs to the service the key belongs to.
struct ChoiceSetting: Hashable {
    let key: String
    let fallback: String
}

enum Setting {
    static let enabled = FlagSetting(key: "enabled")
    static let guardEnabled = FlagSetting(key: "guard_enabled")
    static let timezoneWatchdog = FlagSetting(key: "timezone_watchdog")
    static let autoUpdate = FlagSetting(key: "auto_update")
    static let returnToOverview = FlagSetting(key: "return_to_overview_after_launch")
    static let requireIPv6Off = FlagSetting(key: "require_ipv6_off")
    static let requireEnglish = FlagSetting(key: "require_english")
    static let requireDNS = FlagSetting(key: "require_dns")
    static let requireStun = FlagSetting(key: "require_stun")
    static let requirePinnedRules = FlagSetting(key: "require_pinned_rules")
    static let updateURL = TextSetting(key: "update_url")
    static let updatePublicKey = TextSetting(key: "update_public_key")
    static let country = TextSetting(key: "country")
    static let locale = TextSetting(key: "locale")
}

/// How one background service is presented and which setting its switch owns.
///
/// The services differ, and the difference is declared here: a lookup by id
/// replaces comparisons against `service.id` scattered through the view.
enum BackgroundServiceCatalog {
    struct Descriptor {
        let symbol: String
        /// The setting this service's switch writes. `nil` marks a service
        /// that is only reported on and has no switch of its own.
        let toggle: FlagSetting?
        let enableTitle: String
        let disableTitle: String
        let syncTitle: String
        /// Shown instead of a switch when the service has none.
        let note: String?
        /// A service whose switch only makes sense once the watch itself is
        /// enabled.
        let requiresEnabled: Bool
        /// A service that cannot be switched on before its release source is
        /// configured.
        let requiresSource: Bool
    }
    static let byID: [String: Descriptor] = [
        "guard": .init(
            symbol: "shield.lefthalf.filled", toggle: Setting.guardEnabled,
            enableTitle: "启用保护", disableTitle: "预览停用保护", syncTitle: "预览同步后台状态",
            note: nil, requiresEnabled: true, requiresSource: false),
        "watchdog": .init(
            symbol: "clock.badge.checkmark", toggle: Setting.timezoneWatchdog,
            enableTitle: "预览启用", disableTitle: "预览停用", syncTitle: "预览同步后台状态",
            note: nil, requiresEnabled: false, requiresSource: false),
        "updater": .init(
            symbol: "arrow.down.circle", toggle: Setting.autoUpdate,
            enableTitle: "预览启用", disableTitle: "预览停用", syncTitle: "预览同步后台状态",
            note: nil, requiresEnabled: false, requiresSource: true),
        "original": .init(
            symbol: "link", toggle: nil,
            enableTitle: "", disableTitle: "", syncTitle: "",
            note: "原版独立管理，与 Claude Watch 保持并行", requiresEnabled: false, requiresSource: false),
    ]
    /// Unknown ids keep the generic shield and get no switch rather than
    /// falling back to a guessed key.
    static func descriptor(_ id: String) -> Descriptor {
        byID[id] ?? .init(symbol: "shield.lefthalf.filled", toggle: nil,
                          enableTitle: "", disableTitle: "", syncTitle: "",
                          note: nil, requiresEnabled: false, requiresSource: false)
    }
}
