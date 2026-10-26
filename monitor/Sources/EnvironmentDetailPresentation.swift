// Presentation policy shared by pointer, keyboard and native-popover dismissal.
struct EnvironmentDetailPresentation {
    private(set) var isPresented = false
    private(set) var isPinned = false
    private(set) var isOverCard = false
    private(set) var isOverDetails = false
    private var dismissedDuringHover = false

    var shouldPreview: Bool { isOverCard && !dismissedDuringHover && !isPresented }
    var shouldClose: Bool { isPresented && !isPinned && !isOverCard && !isOverDetails }

    mutating func hoverCard(_ inside: Bool) {
        isOverCard = inside
        if !inside { dismissedDuringHover = false }
    }
    mutating func hoverDetails(_ inside: Bool) { isOverDetails = inside }
    mutating func previewIfNeeded() {
        if shouldPreview { isPresented = true }
    }
    mutating func closeIfNeeded() {
        if shouldClose { dismiss() }
    }
    mutating func activate() {
        if isPinned { dismiss() }
        else { isPresented = true; isPinned = true; dismissedDuringHover = false }
    }
    mutating func togglePin() { isPinned.toggle() }
    mutating func dismiss() {
        isPresented = false
        isPinned = false
        isOverDetails = false
        dismissedDuringHover = isOverCard
    }
}
