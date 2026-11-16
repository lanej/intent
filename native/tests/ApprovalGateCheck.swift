@main enum ApprovalGateCheck {
    static func main() {
        var gate = ApprovalGate()
        precondition(!gate.accepts(0), "a callback cannot approve before a card action")
        let first = gate.begin()!
        precondition(gate.accepts(first))
        let password = gate.begin()!
        precondition(!gate.accepts(first), "method switch must reject the obsolete callback")
        precondition(gate.accepts(password))
        gate.invalidate()
        precondition(!gate.accepts(password), "failed or cancelled attempt cannot later approve")
        let retry = gate.begin()!
        gate.finish()
        precondition(!gate.accepts(retry) && gate.begin() == nil, "deny and close are terminal")
        print("Approval gate checks passed")
    }
}
