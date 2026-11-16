import AppKit
import Foundation

// Separate renderer check: this executable has no approval response or
// authentication evaluation path and is never part of the shipped bundle.
final class CaptureTarget: NSObject { @objc func action() {} }
@main enum CardCapture {
    static func main() throws {
        let args = CommandLine.arguments
        let review = try JSONDecoder().decode(Review.self, from: Data(contentsOf: URL(fileURLWithPath: args[1])))
        let app = NSApplication.shared; app.setActivationPolicy(.accessory)
        let target = CaptureTarget()
        let view = ApprovalCardView(review: review, target: target, approveAction: #selector(CaptureTarget.action), passwordAction: #selector(CaptureTarget.action), denyAction: #selector(CaptureTarget.action))
        let bounded = args.contains("--bounded")
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: bounded ? 520 : 560, height: bounded ? 580 : 720), styleMask: [.titled, .resizable], backing: .buffered, defer: false)
        window.appearance = NSAppearance(named: args.contains("--dark") ? .darkAqua : .aqua)
        window.contentView = view
        view.status.stringValue = "Review the request. Approve starts macOS authentication."
        if args.contains("--details") { view.toggleDetails() }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) {
            view.layoutSubtreeIfNeeded()
            for button in [view.approve, view.password, view.deny] {
                precondition(view.bounds.contains(button.convert(button.bounds, to: view)), "fixed footer clipped")
            }
            precondition(view.scroll.documentView!.bounds.height >= 280, "request content collapsed")
            guard let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { exit(2) }
            window.appearance?.performAsCurrentDrawingAppearance { view.cacheDisplay(in: view.bounds, to: bitmap) }
            guard let png = bitmap.representation(using: .png, properties: [:]) else { exit(2) }
            do { try png.write(to: URL(fileURLWithPath: args[2])) } catch { exit(2) }
            print("Captured \(bitmap.pixelsWide)x\(bitmap.pixelsHigh); footer visible; document \(view.scroll.documentView!.bounds.height)pt")
            withExtendedLifetime([target, window]) { exit(0) }
        }
        app.run()
    }
}
