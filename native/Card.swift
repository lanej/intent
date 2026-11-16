import AppKit
import Foundation

struct Review: Decodable {
    let title: String
    let summary: String
    let details: String
    let agent: AgentIdentity?
    let card: Card?
}
struct AgentIdentity: Decodable { let type: String; let id: String }
struct Fact: Decodable { let label: String; let value: String; let caller_supplied: Bool }
struct Credential: Decodable { let name: String; let variable: String }
struct Card: Decodable {
    let application: String
    let subtitle: String
    let access: [Fact]?
    let credentials: [Credential]?
    let facts: [Fact]?
    let notice_title: String?
    let notice: String?
}

final class DisclosureButton: NSButton {
    override func draw(_ dirtyRect: NSRect) {
        let text = (title.hasPrefix("Hide") ? "⌄  " : "›  ") + title
        (text as NSString).draw(in: bounds.insetBy(dx: 3, dy: 3), withAttributes: [.font: NSFont.systemFont(ofSize: 12), .foregroundColor: NSColor.secondaryLabelColor])
        if window?.firstResponder === self {
            NSColor.keyboardFocusIndicatorColor.setStroke()
            NSBezierPath(rect: bounds.insetBy(dx: 1, dy: 1)).stroke()
        }
    }
}
final class FlippedDocument: NSView { override var isFlipped: Bool { true } }
final class Surface: NSView {
    override func draw(_ dirtyRect: NSRect) {
        let dark = effectiveAppearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
        (dark ? NSColor(srgbRed: 0.16, green: 0.17, blue: 0.17, alpha: 1) : NSColor(srgbRed: 0.95, green: 0.96, blue: 0.95, alpha: 1)).setFill()
        NSBezierPath(roundedRect: bounds, xRadius: 10, yRadius: 10).fill()
    }
}

// AppKit retains hit testing, keyboard actions and accessibility. Drawing keeps
// the compact icon-and-label actions legible in both appearances and captures.
final class CardButton: NSButton {
    var glyph = ""
    var primary = false
    override func draw(_ dirtyRect: NSRect) {
        let dark = effectiveAppearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
        let fill = primary ? (dark ? NSColor.systemMint : NSColor(srgbRed: 0.11, green: 0.21, blue: 0.20, alpha: 1)) : NSColor.controlBackgroundColor
        let textColor: NSColor = !isEnabled ? .disabledControlTextColor : (primary ? (dark ? .black : .white) : .labelColor)
        (isHighlighted ? NSColor.selectedControlColor : fill).setFill()
        let shape = NSBezierPath(roundedRect: bounds.insetBy(dx: 1, dy: 1), xRadius: 7, yRadius: 7)
        shape.fill()
        NSColor.separatorColor.setStroke(); shape.stroke()
        let attributes: [NSAttributedString.Key: Any] = [.font: NSFont.systemFont(ofSize: 13, weight: .medium), .foregroundColor: textColor]
        let size = (title as NSString).size(withAttributes: attributes)
        (title as NSString).draw(at: NSPoint(x: (bounds.width - size.width) / 2, y: isFlipped ? bounds.height - 12 - size.height : 12), withAttributes: attributes)
        if let image = NSImage(systemSymbolName: glyph, accessibilityDescription: nil) {
            let configured = image.withSymbolConfiguration(NSImage.SymbolConfiguration(paletteColors: [textColor])) ?? image
            configured.draw(in: NSRect(x: (bounds.width - 26) / 2, y: isFlipped ? 13 : bounds.height - 39, width: 26, height: 26))
        }
        if window?.firstResponder === self {
            NSColor.keyboardFocusIndicatorColor.setStroke(); shape.lineWidth = 2; shape.stroke()
        }
    }
}

// Immutable request content and a fixed footer. Expanding the full source text
// rebuilds only the scroll document, keeping the action controls fixed and available.
final class ApprovalCardView: NSView {
    override func draw(_ dirtyRect: NSRect) {
        NSColor.windowBackgroundColor.setFill()
        bounds.fill()
    }
    let review: Review
    let body = NSStackView()
    let status = NSTextField(wrappingLabelWithString: "")
    let approve = CardButton(title: "Approve", target: nil, action: nil)
    let password = CardButton(title: "Use Password", target: nil, action: nil)
    let deny = CardButton(title: "Deny", target: nil, action: nil)
    let scroll = NSScrollView()
    var expanded = false

    init(review: Review, target: AnyObject, approveAction: Selector, passwordAction: Selector, denyAction: Selector) {
        self.review = review
        super.init(frame: .zero)
        let root = stack([], spacing: 12)
        pin(root, in: self, inset: 24)
        scroll.drawsBackground = false
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        scroll.scrollerStyle = .legacy
        scroll.contentView.clipsToBounds = true
        fullWidth(scroll, in: root)
        scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 280).isActive = true
        let document = FlippedDocument()
        document.translatesAutoresizingMaskIntoConstraints = false
        scroll.documentView = document
        document.widthAnchor.constraint(equalTo: scroll.contentView.widthAnchor).isActive = true
        body.orientation = .vertical; body.alignment = .leading; body.spacing = 16
        pin(body, in: document, inset: 1)
        let separator = NSBox(); separator.boxType = .separator
        fullWidth(separator, in: root)
        status.font = .systemFont(ofSize: 11)
        status.textColor = .secondaryLabelColor
        status.setAccessibilityLabel("Authentication status")
        fullWidth(status, in: root)
        let actions = stack([], spacing: 8, horizontal: true)
        actions.distribution = .fillEqually
        for button in [approve, password, deny] {
            button.target = target
            button.font = .systemFont(ofSize: 13, weight: .medium)
            button.heightAnchor.constraint(equalToConstant: 76).isActive = true
            actions.addArrangedSubview(button)
        }
        approve.action = approveAction; approve.primary = true; approve.glyph = "checkmark.shield"
        password.action = passwordAction; password.glyph = "lock"
        // Return does not trigger authentication before the person reviews it.
        deny.action = denyAction; deny.glyph = "xmark"; deny.keyEquivalent = "\u{1b}"
        fullWidth(actions, in: root)
        renderBody()
    }
    required init?(coder: NSCoder) { fatalError("init(coder:) is not supported") }

    func label(_ value: String, size: CGFloat = 13, weight: NSFont.Weight = .regular, secondary: Bool = false, mono: Bool = false) -> NSTextField {
        let field = NSTextField(wrappingLabelWithString: value)
        field.font = mono ? .monospacedSystemFont(ofSize: size, weight: weight) : .systemFont(ofSize: size, weight: weight)
        field.textColor = secondary ? .secondaryLabelColor : .labelColor
        field.isSelectable = true
        field.setContentCompressionResistancePriority(.required, for: .vertical)
        field.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        return field
    }
    func stack(_ views: [NSView], spacing: CGFloat = 12, horizontal: Bool = false) -> NSStackView {
        let view = NSStackView(views: views)
        view.orientation = horizontal ? .horizontal : .vertical
        view.alignment = horizontal ? .centerY : .leading
        view.spacing = spacing; view.translatesAutoresizingMaskIntoConstraints = false
        return view
    }
    func pin(_ child: NSView, in parent: NSView, inset: CGFloat = 0) {
        child.translatesAutoresizingMaskIntoConstraints = false; parent.addSubview(child)
        NSLayoutConstraint.activate([
            child.leadingAnchor.constraint(equalTo: parent.leadingAnchor, constant: inset),
            child.trailingAnchor.constraint(equalTo: parent.trailingAnchor, constant: -inset),
            child.topAnchor.constraint(equalTo: parent.topAnchor, constant: inset),
            child.bottomAnchor.constraint(equalTo: parent.bottomAnchor, constant: -inset)
        ])
    }
    func fullWidth(_ child: NSView, in parent: NSStackView) {
        parent.addArrangedSubview(child)
        child.widthAnchor.constraint(equalTo: parent.widthAnchor).isActive = true
    }
    func artwork(_ name: String, fallback: String, size: CGFloat) -> NSImageView {
        // Only built-in names resolve to bundle resources; request paths and URLs
        // cannot reach NSImage(contentsOf:).
        let files = ["Keylease": "keylease.png", "codex": "codex.icns", "1Password": "1password.icns"]
        let image = files[name].flatMap { Bundle.main.url(forResource: $0, withExtension: nil).flatMap(NSImage.init(contentsOf:)) }
            ?? NSImage(systemSymbolName: fallback, accessibilityDescription: nil) ?? NSImage()
        let view = NSImageView(image: image)
        view.imageScaling = .scaleProportionallyUpOrDown
        if image.isTemplate { view.contentTintColor = .systemMint }
        view.translatesAutoresizingMaskIntoConstraints = false
        view.widthAnchor.constraint(equalToConstant: size).isActive = true
        view.heightAnchor.constraint(equalToConstant: size).isActive = true
        view.setAccessibilityElement(false)
        return view
    }
    func panel(_ content: NSView) -> NSView { let view = Surface(); pin(content, in: view, inset: 14); return view }
    func fact(_ item: Fact) -> NSView {
        let heading = stack([label(item.label, size: 10, weight: .semibold, secondary: true)], spacing: 6, horizontal: true)
        if item.caller_supplied { heading.addArrangedSubview(label("Caller supplied", size: 10, secondary: true)) }
        let content = stack([heading], spacing: 5)
        fullWidth(label(item.value, size: 12, mono: true), in: content)
        return content
    }
    func renderBody() {
        for view in body.arrangedSubviews { body.removeArrangedSubview(view); view.removeFromSuperview() }
        let application = review.card?.application ?? "Intent"
        let brand = stack([label(application, weight: .semibold), label("via Intent", size: 11, secondary: true)], spacing: 2)
        let identity = stack([artwork(application, fallback: "checkmark.shield", size: 32), brand], spacing: 9, horizontal: true)
        identity.alignment = .top; identity.widthAnchor.constraint(equalToConstant: 116).isActive = true
        let heading = stack([label(review.title, weight: .semibold)], spacing: 2)
        fullWidth(label(review.card?.subtitle ?? review.summary, size: 11, secondary: true), in: heading)
        let header = stack([identity, heading], spacing: 18, horizontal: true); header.alignment = .top
        fullWidth(header, in: body)
        if let agent = review.agent {
            let family = stack([label("Agent · caller supplied", size: 10, secondary: true),
                                stack([artwork(agent.type, fallback: "terminal", size: 18), label(agent.type == "codex" ? "Codex" : agent.type, weight: .medium)], spacing: 6, horizontal: true)], spacing: 4)
            family.widthAnchor.constraint(equalToConstant: 150).isActive = true
            let instance = stack([label("Agent ID", size: 10, secondary: true)], spacing: 4)
            fullWidth(label(agent.id, size: 11, mono: true), in: instance)
            let requester = stack([family, instance], spacing: 16, horizontal: true); requester.alignment = .top
            fullWidth(requester, in: body)
        } else { fullWidth(label("Agent identity not supplied", size: 11, secondary: true), in: body) }
        if let card = review.card {
            if let notice = card.notice, !notice.isEmpty {
                let warning = stack([label("⚠ " + (card.notice_title ?? "Notice"), size: 12, weight: .semibold), label(notice, size: 12)], spacing: 4)
                fullWidth(panel(warning), in: body)
            }
            let access = stack([], spacing: 14, horizontal: true); access.alignment = .top; access.distribution = .fillEqually
            for item in card.access ?? [] {
                let column = stack([label(item.label, size: 10, secondary: true)], spacing: 5)
                if item.label == "Provider" {
                    let provider = stack([artwork(item.value, fallback: "lock.shield", size: 22), label(item.value, weight: .medium)], spacing: 6, horizontal: true)
                    fullWidth(provider, in: column)
                } else { fullWidth(label(item.value, weight: .medium), in: column) }
                if item.caller_supplied { fullWidth(label("Caller supplied", size: 10, secondary: true), in: column) }
                access.addArrangedSubview(column)
            }
            if !access.arrangedSubviews.isEmpty { fullWidth(access, in: body) }
            if let credentials = card.credentials, !credentials.isEmpty {
                let list = stack([label("Credentials", size: 12, weight: .semibold, secondary: true)], spacing: 12)
                for credential in credentials {
                    let text = stack([label(credential.name, weight: .medium)], spacing: 3)
                    fullWidth(label(credential.variable, size: 11, secondary: true, mono: true), in: text)
                    fullWidth(stack([artwork("", fallback: "key.horizontal", size: 16), text], spacing: 10, horizontal: true), in: list)
                }
                fullWidth(list, in: body)
            }
            for item in card.facts ?? [] { fullWidth(panel(fact(item)), in: body) }
        }
        if review.card == nil && !review.details.isEmpty {
            fullWidth(panel(label(review.details, size: 12, mono: true)), in: body)
        } else if review.card != nil {
            let disclosure = DisclosureButton(title: expanded ? "Hide complete request" : "Complete request", target: self, action: #selector(toggleDetails))
            disclosure.bezelStyle = .inline
            disclosure.widthAnchor.constraint(greaterThanOrEqualToConstant: 190).isActive = true
            disclosure.heightAnchor.constraint(greaterThanOrEqualToConstant: 24).isActive = true
            disclosure.setAccessibilityLabel(expanded ? "Hide complete request" : "Show complete request")
            body.addArrangedSubview(disclosure)
            if expanded {
                fullWidth(panel(label(review.summary + "\n\n" + review.details, size: 12, mono: true)), in: body)
            }
        }
    }
    @objc func toggleDetails() { expanded.toggle(); renderBody() }
}
