import Foundation

/// Coalesces reads while keeping automatic synchronization visually silent.
struct MonitorRefreshGate {
    private(set) var reading = false
    private(set) var manualVisible = false
    private var manualQueued = false

    mutating func request(manual: Bool) -> Bool {
        if reading {
            if manual {
                manualQueued = true
                manualVisible = true
            }
            return false
        }
        reading = true
        manualVisible = manual
        return true
    }

    /// Returns true when one explicit refresh must run after the current read.
    mutating func complete() -> Bool {
        reading = false
        if manualQueued {
            manualQueued = false
            return true
        }
        manualVisible = false
        return false
    }
}
