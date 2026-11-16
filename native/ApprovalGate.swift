// Only an explicit action on this immutable card creates an eligible attempt.
// A method switch, failure or terminal decision invalidates earlier callbacks.
struct ApprovalGate {
    private(set) var generation = 0
    private(set) var pending: Int?
    private(set) var terminal = false

    mutating func begin() -> Int? {
        guard !terminal else { return nil }
        generation += 1
        pending = generation
        return generation
    }
    func accepts(_ attempt: Int) -> Bool {
        !terminal && pending == attempt && generation == attempt
    }
    mutating func invalidate() {
        generation += 1
        pending = nil
    }
    mutating func finish() {
        invalidate()
        terminal = true
    }
}
