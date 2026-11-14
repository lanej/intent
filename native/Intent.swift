import AppKit
import LocalAuthentication
import Foundation

struct Review: Decodable { let title: String; let summary: String; let details: String }
struct Request: Decodable { let version: Int; let request_id: String; let review: Review }
// One process handles one immutable request. Only the authentication callback
// may return an explicit, request-bound approval to its parent.
let data = FileHandle.standardInput.readDataToEndOfFile()
guard data.count <= 1048576, let request = try? JSONDecoder().decode(Request.self, from: data),
      request.version == 1, request.request_id.count == 32,
      !request.review.title.isEmpty else { exit(2) }
func review(_ request: Request) -> Never {
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    app.activate(ignoringOtherApps: true)
    func finish(_ decision: String) -> Never {
        let response: [String: Any] = ["version": 1, "request_id": request.request_id, "decision": decision]
        guard let output = try? JSONSerialization.data(withJSONObject: response) else { exit(2) }
        FileHandle.standardOutput.write(output)
        FileHandle.standardOutput.write(Data("\n".utf8))
        exit(0)
    }
    let alert = NSAlert()
    alert.messageText = request.review.title
    alert.informativeText = "Review the complete request below before authenticating."
    let text = NSTextView(frame: NSRect(x: 0, y: 0, width: 560, height: 240))
    text.string = request.review.summary + "\n\n" + request.review.details
    text.isEditable = false
    text.isSelectable = true
    text.isVerticallyResizable = true
    text.isHorizontallyResizable = false
    text.maxSize = NSSize(width: 560, height: CGFloat.greatestFiniteMagnitude)
    text.textContainer?.containerSize = NSSize(width: 560, height: CGFloat.greatestFiniteMagnitude)
    text.textContainer?.widthTracksTextView = true
    text.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
    let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 560, height: 240))
    scroll.hasVerticalScroller = true
    scroll.documentView = text
    alert.accessoryView = scroll
    alert.addButton(withTitle: "Authenticate")
    alert.addButton(withTitle: "Deny")
    guard alert.runModal() == .alertFirstButtonReturn else { finish("denied") }
    let context = LAContext()
    context.touchIDAuthenticationAllowableReuseDuration = 0
    var error: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else { finish("unavailable") }
    context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Approve the reviewed request \(request.request_id.prefix(8)).") { success, error in
        DispatchQueue.main.async {
            if success { finish("approved") }
            let code = (error as? LAError)?.code
            switch code {
            case .userCancel: finish("cancelled")
            case .authenticationFailed: finish("denied")
            default: finish("unavailable")
            }
        }
    }
    app.run()
    exit(1)
}

review(request)
