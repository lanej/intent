import AppKit
import Foundation
import LocalAuthentication
import Security

struct Request: Decodable { let version: Int; let request_id: String; let review: Review }

// One process, one immutable request. Both an explicit action on the card and
// successful OS authentication for that same attempt precede request-bound approval.
final class ApprovalController: NSObject, NSApplicationDelegate, NSWindowDelegate {
    let request: Request
    let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 560, height: 640), styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
    var context: LAContext?
    var gate = ApprovalGate()
    var card: ApprovalCardView!

    init(request: Request) { self.request = request; super.init() }
    func applicationDidFinishLaunching(_ notification: Notification) {
        card = ApprovalCardView(review: request.review, target: self, approveAction: #selector(approve), passwordAction: #selector(usePassword), denyAction: #selector(deny))
        card.status.stringValue = "Review the request. Approve starts macOS authentication."
        window.title = "Intent · Approval"
        window.minSize = NSSize(width: 520, height: 580)
        window.isReleasedWhenClosed = false; window.delegate = self
        window.contentView = card
        window.initialFirstResponder = card.deny
        window.center(); window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        // Opening the card never starts authentication or makes approval eligible.
    }
    func freshContext() -> LAContext {
        context?.invalidate()
        let fresh = LAContext()
        fresh.touchIDAuthenticationAllowableReuseDuration = 0
        context = fresh
        return fresh
    }
    var reason: String { "Approve the reviewed request \(request.request_id.prefix(8))." }
    @objc func approve() {
        guard let attempt = gate.begin() else { return }
        let fresh = freshContext()
        var error: NSError?
        guard fresh.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            gate.invalidate()
            card.approve.isEnabled = true
            card.password.isEnabled = true
            card.status.stringValue = "Mac authentication is unavailable. Use Password or select Deny."
            return
        }
        card.approve.isEnabled = false
        card.password.isEnabled = true
        card.status.stringValue = "Confirm this request in the macOS authentication dialog."
        // Preserve the standard policy and system-owned dialog used by the prior
        // helper. A fresh, unpaired context avoids the failing embedded Watch flow.
        fresh.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, error in
            DispatchQueue.main.async { self.completed(attempt, success: success, error: error) }
        }
    }
    @objc func usePassword() {
        guard let attempt = gate.begin() else { return }
        let fresh = freshContext()
        // The ephemeral ACL requires the Mac password. No keychain item is read
        // or stored, and the application never receives the password.
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .devicePasscode, &error) else {
            gate.invalidate()
            card.approve.isEnabled = true
            card.password.isEnabled = true
            card.status.stringValue = "Mac password authentication is unavailable. Select Deny."
            return
        }
        card.approve.isEnabled = true
        card.password.isEnabled = false
        card.status.stringValue = "Enter your Mac password in the macOS authentication prompt."
        fresh.evaluateAccessControl(access, operation: .useItem, localizedReason: reason) { success, error in
            DispatchQueue.main.async { self.completed(attempt, success: success, error: error) }
        }
    }
    func completed(_ attempt: Int, success: Bool, error: Error?) {
        // Success alone cannot approve before a card action or after a switch.
        guard gate.accepts(attempt) else { return }
        if success { finish("approved") }
        let code = (error as? LAError)?.code
        if code == .userCancel { finish("cancelled") }
        gate.invalidate()
        card.approve.isEnabled = true
        card.password.isEnabled = true
        card.status.stringValue = "Authentication did not approve this request. Try again or select Deny."
    }
    @objc func deny() { finish("denied") }
    func windowShouldClose(_ sender: NSWindow) -> Bool { finish("denied") }
    func finish(_ decision: String) -> Never {
        gate.finish(); context?.invalidate()
        let response: [String: Any] = ["version": 1, "request_id": request.request_id, "decision": decision]
        guard let output = try? JSONSerialization.data(withJSONObject: response) else { exit(2) }
        FileHandle.standardOutput.write(output); FileHandle.standardOutput.write(Data("\n".utf8))
        exit(0)
    }
}

@main enum IntentHelper {
    static func main() {
        let data = FileHandle.standardInput.readDataToEndOfFile()
        guard data.count <= 1048576, let request = try? JSONDecoder().decode(Request.self, from: data),
              request.version == 1, request.request_id.count == 32, !request.review.title.isEmpty else { exit(2) }
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        let controller = ApprovalController(request: request)
        app.delegate = controller
        withExtendedLifetime(controller) { app.run() }
        exit(1)
    }
}
