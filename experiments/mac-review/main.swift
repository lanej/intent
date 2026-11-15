import AppKit
import Foundation

// Prototype inputs deliberately remain separate from Intent's public Review API.
struct Brand: Decodable {
    let name: String
    let accent: String
    let accentDark: String?
    let actionAccent: String?
    let symbol: String
    let icon: String?
}
struct Fact: Decodable {
    let label: String
    let value: String
    let callerSupplied: Bool
}
struct Credential: Decodable {
    let name: String
    let variable: String
}
struct Consequence: Decodable {
    let title: String
    let description: String
}
struct Provider: Decodable {
    let name: String
    let detail: String
    let icon: String?
    let symbol: String?
}
struct Access: Decodable {
    let duration: String
    let expires: String
    let profile: String
    let provider: Provider
}
struct Agent: Decodable {
    let type: String
    let id: String
    let name: String?
    let icon: String?
    let symbol: String?
}
struct Card: Decodable {
    var brand: Brand
    let agent: Agent?
    let title: String
    let summary: String
    let access: Access
    let facts: [Fact]
    let credentials: [Credential]
    let consequence: Consequence?
    let details: [Fact]
}

// Device capabilities belong to the local authenticator, never the request.
// This isolated prototype simulates those capabilities through local settings.
enum SimulatedMethods: Int, CaseIterable {
    case both, touchID, watch, passwordOnly
    var title: String {
        switch self {
        case .both: return "Touch ID + Apple Watch"
        case .touchID: return "Touch ID only"
        case .watch: return "Apple Watch only"
        case .passwordOnly: return "Password only"
        }
    }
    var touchAvailable: Bool { self == .both || self == .touchID }
    var watchAvailable: Bool { self == .both || self == .watch }
}

func color(_ hex: String) -> NSColor {
    let number = UInt32(hex, radix: 16) ?? 0x269D79
    return NSColor(srgbRed: CGFloat((number >> 16) & 255) / 255,
                   green: CGFloat((number >> 8) & 255) / 255,
                   blue: CGFloat(number & 255) / 255, alpha: 1)
}

// Explicit AppKit drawing keeps the prototype's controls visible in PDF/PNG
// exports even when a locked graphical session cannot composite glass controls.
// NSButton/NSPopUpButton still own hit testing, menus, actions and accessibility.
final class PreviewButton: NSButton {
    var primaryFill: NSColor?
    var primaryText: NSColor?
    var actionSymbol: String?
    override func draw(_ dirtyRect: NSRect) {
        let primary = keyEquivalent == "\r"
        if bezelStyle != .inline {
            (isHighlighted ? NSColor.selectedControlColor : (primary ? (primaryFill ?? NSColor.controlAccentColor) : NSColor.controlBackgroundColor)).setFill()
            NSBezierPath(roundedRect: bounds.insetBy(dx: 1, dy: 1), xRadius: 7, yRadius: 7).fill()
            NSColor.separatorColor.setStroke()
            NSBezierPath(roundedRect: bounds.insetBy(dx: 1, dy: 1), xRadius: 7, yRadius: 7).stroke()
        }
        let text = (bezelStyle == .inline && title.contains("details") ? (title.hasPrefix("Hide") ? "⌄  " : "›  ") : "") + title
        let attributes: [NSAttributedString.Key: Any] = [
            .font: font ?? NSFont.systemFont(ofSize: 13),
            .foregroundColor: !isEnabled ? NSColor.disabledControlTextColor : (primary ? (primaryText ?? NSColor.white) : NSColor.labelColor)
        ]
        let size = (text as NSString).size(withAttributes: attributes)
        let textY = actionSymbol == nil ? (bounds.height - size.height) / 2 : (isFlipped ? bounds.height - 15 - size.height : 15)
        (text as NSString).draw(at: NSPoint(x: (bounds.width - size.width) / 2, y: textY), withAttributes: attributes)
        if let actionSymbol, let icon = NSImage(systemSymbolName: actionSymbol, accessibilityDescription: nil) {
            let tint = attributes[.foregroundColor] as? NSColor ?? .labelColor
            let configured = icon.withSymbolConfiguration(NSImage.SymbolConfiguration(paletteColors: [tint])) ?? icon
            configured.draw(in: NSRect(x: (bounds.width - 26) / 2, y: isFlipped ? 15 : bounds.height - 41, width: 26, height: 26))
        }
        if window?.firstResponder === self {
            NSColor.keyboardFocusIndicatorColor.setStroke()
            let ring = NSBezierPath(roundedRect: bounds.insetBy(dx: 2, dy: 2), xRadius: 7, yRadius: 7)
            ring.lineWidth = 2
            ring.stroke()
        }
    }
}
final class PreviewPopup: NSPopUpButton {
    override func draw(_ dirtyRect: NSRect) {
        NSColor.controlBackgroundColor.setFill()
        let rect = NSBezierPath(roundedRect: bounds.insetBy(dx: 1, dy: 1), xRadius: 5, yRadius: 5)
        rect.fill()
        NSColor.separatorColor.setStroke()
        rect.stroke()
        let attributes: [NSAttributedString.Key: Any] = [.font: NSFont.systemFont(ofSize: 11), .foregroundColor: NSColor.labelColor]
        ((titleOfSelectedItem ?? "") as NSString).draw(at: NSPoint(x: 8, y: 4), withAttributes: attributes)
        ("⌄" as NSString).draw(at: NSPoint(x: bounds.width - 16, y: 4), withAttributes: attributes)
        if window?.firstResponder === self {
            NSColor.keyboardFocusIndicatorColor.setStroke()
            rect.lineWidth = 2
            rect.stroke()
        }
    }
}
final class PreviewCheckbox: NSButton {
    override func draw(_ dirtyRect: NSRect) {
        let attributes: [NSAttributedString.Key: Any] = [.font: NSFont.systemFont(ofSize: 11), .foregroundColor: NSColor.labelColor]
        let mark = state == .on ? "☑" : "☐"
        ("\(mark) \(title)" as NSString).draw(at: NSPoint(x: 0, y: 3), withAttributes: attributes)
        if window?.firstResponder === self {
            NSColor.keyboardFocusIndicatorColor.setStroke()
            NSBezierPath(rect: bounds.insetBy(dx: 1, dy: 1)).stroke()
        }
    }
}
final class FlippedDocument: NSView { override var isFlipped: Bool { true } }
final class Surface: NSView {
    let fill: NSColor
    init(fill: NSColor) { self.fill = fill; super.init(frame: .zero); clipsToBounds = true }
    required init?(coder: NSCoder) { fatalError("init(coder:) is not supported") }
    override func draw(_ dirtyRect: NSRect) {
        fill.setFill()
        NSBezierPath(roundedRect: bounds, xRadius: 10, yRadius: 10).fill()
    }
}

final class Preview: NSObject, NSApplicationDelegate {
    let root: URL
    let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 560, height: 640),
                          styleMask: [.titled, .closable, .miniaturizable, .resizable],
                          backing: .buffered, defer: false)
    let settings = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 430, height: 275),
                            styleMask: [.titled, .closable], backing: .buffered, defer: false)
    let cases = PreviewPopup()
    let appearance = PreviewPopup()
    let branding = PreviewPopup()
    let methods = PreviewPopup()
    var simulatedMethods: SimulatedMethods { SimulatedMethods(rawValue: methods.indexOfSelectedItem) ?? .passwordOnly }
    let larger = PreviewCheckbox(title: "Larger text", target: nil, action: nil)
    let status = NSTextField(labelWithString: "")
    var resultMessage = ""
    var expanded = false
    var card: Card!
    var scale: CGFloat { larger.state == .on ? 1.2 : 1 }
    var accent: NSColor { color(appearance.indexOfSelectedItem == 1 ? (card.brand.accentDark ?? card.brand.accent) : card.brand.accent) }

    init(root: URL) {
        self.root = root
        super.init()
        cases.addItems(withTitles: ["Credential access", "Long request", "Plaintext file"])
        appearance.addItems(withTitles: ["Light", "Dark"])
        branding.addItems(withTitles: ["Keylease", "Example app"])
        methods.addItems(withTitles: SimulatedMethods.allCases.map { $0.title })
        for popup in [cases, appearance, branding, methods] {
            popup.target = self
            popup.action = #selector(change)
        }
        larger.setButtonType(.switch)
        larger.target = self
        larger.action = #selector(change)
        window.title = "Intent · Approval preview"
        window.minSize = NSSize(width: 520, height: 580)
        window.isReleasedWhenClosed = false
        window.center()
        settings.title = "Preview options"
        settings.isReleasedWhenClosed = false
        settings.center()
        cases.setAccessibilityLabel("Sample request")
        appearance.setAccessibilityLabel("Appearance")
        branding.setAccessibilityLabel("Application branding")
        methods.setAccessibilityLabel("Simulated authentication methods")
        let options = stack([], spacing: 14)
        for (title, popup) in [("Sample", cases), ("Application", branding), ("Appearance", appearance), ("Methods", methods)] {
            let heading = label(title)
            heading.widthAnchor.constraint(equalToConstant: 100).isActive = true
            fullWidth(stack([heading, popup], spacing: 12, horizontal: true), in: options)
        }
        options.addArrangedSubview(larger)
        let surface = NSView()
        settings.contentView = surface
        pin(options, in: surface, inset: 24)
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        let menu = NSMenu()
        let item = NSMenuItem()
        menu.addItem(item)
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: "Preview options…", action: #selector(showOptions), keyEquivalent: ",").target = self
        appMenu.addItem(withTitle: "Quit Preview", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        item.submenu = appMenu
        NSApp.mainMenu = menu
        reload()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        if let index = CommandLine.arguments.firstIndex(of: "--capture"), CommandLine.arguments.count > index + 1 {
            let output = URL(fileURLWithPath: CommandLine.arguments[index + 1], isDirectory: true)
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { self.captureVariants(output) }
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    func label(_ value: String, size: CGFloat = 13, weight: NSFont.Weight = .regular,
               secondary: Bool = false, mono: Bool = false) -> NSTextField {
        let field = NSTextField(wrappingLabelWithString: value)
        field.font = mono ? .monospacedSystemFont(ofSize: size * scale, weight: weight)
                          : .systemFont(ofSize: size * scale, weight: weight)
        field.textColor = secondary ? .secondaryLabelColor : .labelColor
        field.isSelectable = true
        field.setContentCompressionResistancePriority(.required, for: .vertical)
        return field
    }

    func stack(_ views: [NSView], spacing: CGFloat = 12, horizontal: Bool = false) -> NSStackView {
        let view = NSStackView(views: views)
        view.orientation = horizontal ? .horizontal : .vertical
        view.alignment = horizontal ? .centerY : .leading
        view.spacing = spacing
        view.translatesAutoresizingMaskIntoConstraints = false
        return view
    }

    func pin(_ child: NSView, in parent: NSView, inset: CGFloat = 0) {
        child.translatesAutoresizingMaskIntoConstraints = false
        parent.addSubview(child)
        NSLayoutConstraint.activate([
            child.leadingAnchor.constraint(equalTo: parent.leadingAnchor, constant: inset),
            child.trailingAnchor.constraint(equalTo: parent.trailingAnchor, constant: -inset),
            child.topAnchor.constraint(equalTo: parent.topAnchor, constant: inset),
            child.bottomAnchor.constraint(equalTo: parent.bottomAnchor, constant: -inset)
        ])
    }

    func symbol(_ name: String, tint: NSColor, size: CGFloat = 18) -> NSImageView {
        let view = NSImageView(image: NSImage(systemSymbolName: name, accessibilityDescription: nil) ?? NSImage())
        view.contentTintColor = tint
        view.imageScaling = .scaleProportionallyUpOrDown
        view.translatesAutoresizingMaskIntoConstraints = false
        view.widthAnchor.constraint(equalToConstant: size).isActive = true
        view.heightAnchor.constraint(equalToConstant: size).isActive = true
        view.setAccessibilityElement(false)
        return view
    }

    // Supplied artwork is bundled with this local preview. It cannot fetch URLs
    // or read an arbitrary file outside assets, including through a symlink.
    func artwork(_ reference: String?, fallback: String, size: CGFloat) -> NSImageView {
        var image: NSImage?
        if let reference {
            let assets = root.appendingPathComponent("assets", isDirectory: true).resolvingSymlinksInPath().standardizedFileURL
            let file = root.appendingPathComponent(reference).resolvingSymlinksInPath().standardizedFileURL
            if file.path.hasPrefix(assets.path + "/"), ["png", "icns"].contains(file.pathExtension.lowercased()) {
                image = NSImage(contentsOf: file)
            }
        }
        if image == nil { image = NSImage(systemSymbolName: fallback, accessibilityDescription: nil) }
        let view = NSImageView(image: image ?? NSImage())
        view.imageScaling = .scaleProportionallyUpOrDown
        if image?.isTemplate == true { view.contentTintColor = accent }
        view.translatesAutoresizingMaskIntoConstraints = false
        view.widthAnchor.constraint(equalToConstant: size).isActive = true
        view.heightAnchor.constraint(equalToConstant: size).isActive = true
        view.setAccessibilityElement(false)
        return view
    }

    func panel(_ content: NSView, tint: NSColor? = nil) -> NSView {
        let box = Surface(fill: tint?.withAlphaComponent(0.08) ?? (appearance.indexOfSelectedItem == 1 ? color("282C2C") : color("F3F5F4")))
        pin(content, in: box, inset: 14)
        return box
    }

    func fullWidth(_ child: NSView, in parent: NSStackView) {
        parent.addArrangedSubview(child)
        child.widthAnchor.constraint(equalTo: parent.widthAnchor).isActive = true
    }

    func fact(_ item: Fact) -> NSView {
        let heading = label(item.label.uppercased(), size: 10, weight: .semibold, secondary: true)
        let title: NSView
        if item.callerSupplied {
            let claim = label("Caller supplied", size: 10, secondary: true)
            title = stack([heading, claim], spacing: 8, horizontal: true)
        } else { title = heading }
        return stack([title, label(item.value, size: item.label == "Profile SHA-256" ? 11 : 13, mono: item.label == "Profile SHA-256" || item.label == "Session identifier")], spacing: 5)
    }

    @objc func change() {
        resultMessage = ""
        reload()
    }

    func reload() {
        do {
            let names = ["credentials", "long-request", "plaintext"]
            let data = try Data(contentsOf: root.appendingPathComponent("fixtures/\(names[cases.indexOfSelectedItem]).json"))
            card = try JSONDecoder().decode(Card.self, from: data)
            if branding.indexOfSelectedItem == 1 {
                let brand = try Data(contentsOf: root.appendingPathComponent("fixtures/example-brand.json"))
                card.brand = try JSONDecoder().decode(Brand.self, from: brand)
            }
        } catch {
            fputs("Preview fixture: \(error)\n", stderr)
            exit(1)
        }
        window.appearance = NSAppearance(named: appearance.indexOfSelectedItem == 1 ? .darkAqua : .aqua)
        window.appearance?.performAsCurrentDrawingAppearance { render() }
    }

    func render() {
        let content = Surface(fill: NSColor.windowBackgroundColor)
        window.contentView = content
        let rootStack = stack([], spacing: 12)
        pin(rootStack, in: content, inset: 24)
        fullWidth(label("Preview only · no approvals are issued", size: 10, secondary: true), in: rootStack)
        let scroll = NSScrollView()
        scroll.drawsBackground = false
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        scroll.scrollerStyle = .legacy
        scroll.clipsToBounds = true
        scroll.contentView.clipsToBounds = true
        fullWidth(scroll, in: rootStack)
        scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 280).isActive = true
        let document = FlippedDocument()
        document.translatesAutoresizingMaskIntoConstraints = false
        scroll.documentView = document
        document.widthAnchor.constraint(equalTo: scroll.contentView.widthAnchor).isActive = true
        let body = stack([], spacing: 16)
        pin(body, in: document, inset: 1)

        let icon = NSImageView()
        if let path = card.brand.icon { icon.image = NSImage(contentsOf: root.appendingPathComponent(path)) }
        else { icon.image = NSImage(systemSymbolName: card.brand.symbol, accessibilityDescription: nil) }
        icon.contentTintColor = accent
        icon.imageScaling = .scaleProportionallyUpOrDown
        icon.translatesAutoresizingMaskIntoConstraints = false
        icon.widthAnchor.constraint(equalToConstant: 32).isActive = true
        icon.heightAnchor.constraint(equalToConstant: 32).isActive = true
        icon.setAccessibilityElement(false)
        let headerTitleSize: CGFloat = 13
        let headerSubtitleSize: CGFloat = 11
        let brand = stack([label(card.brand.name, size: headerTitleSize, weight: .semibold),
                           label("via Intent", size: headerSubtitleSize, secondary: true)], spacing: 2)
        let identity = stack([icon, brand], spacing: 9, horizontal: true)
        identity.alignment = .top
        identity.widthAnchor.constraint(equalToConstant: 116).isActive = true
        let heading = stack([label(card.title, size: headerTitleSize, weight: .semibold),
                             label(card.summary, size: headerSubtitleSize, secondary: true)], spacing: 2)
        for view in heading.arrangedSubviews {
            view.widthAnchor.constraint(equalTo: heading.widthAnchor).isActive = true
        }
        let header = stack([identity, heading], spacing: 18, horizontal: true)
        header.alignment = .top
        heading.setContentHuggingPriority(.defaultLow, for: .horizontal)
        fullWidth(header, in: body)

        if let agent = card.agent {
            let knownIcon = agent.type == "codex" ? "assets/codex.icns" : nil
            let name = agent.name ?? (agent.type == "codex" ? "Codex" : agent.type)
            let family = stack([label("Agent · caller supplied", size: 10, secondary: true),
                                stack([artwork(agent.icon ?? knownIcon, fallback: agent.symbol ?? "terminal", size: 18),
                                       label(name, size: 13, weight: .medium)], spacing: 6, horizontal: true)], spacing: 4)
            family.widthAnchor.constraint(equalToConstant: 150).isActive = true
            let instance = stack([label("Agent ID", size: 10, secondary: true),
                                  label(agent.id, size: 11, mono: true)], spacing: 4)
            for view in instance.arrangedSubviews {
                view.widthAnchor.constraint(equalTo: instance.widthAnchor).isActive = true
            }
            instance.setContentHuggingPriority(.defaultLow, for: .horizontal)
            let requester = stack([family, instance], spacing: 16, horizontal: true)
            requester.alignment = .top
            fullWidth(requester, in: body)
        } else {
            fullWidth(label("Agent identity not supplied", size: 11, secondary: true), in: body)
        }

        if let consequence = card.consequence {
            fullWidth(panel(stack([symbol("exclamationmark.triangle", tint: .systemOrange, size: 16),
                                   stack([label(consequence.title, size: 12, weight: .semibold),
                                          label(consequence.description, size: 12)], spacing: 4)], spacing: 9, horizontal: true), tint: .systemOrange), in: body)
        }

        let duration = stack([label("Access duration", size: 10, secondary: true),
                              stack([symbol("clock", tint: accent, size: 14),
                                     label(card.access.duration, size: 13, weight: .semibold)], spacing: 6, horizontal: true),
                              label("Until " + card.access.expires, size: 11, secondary: true)], spacing: 4)
        let profile = stack([label("Credential profile", size: 10, secondary: true),
                             stack([symbol("rectangle.stack", tint: .secondaryLabelColor, size: 14),
                                    label(card.access.profile, size: 13, weight: .medium)], spacing: 6, horizontal: true)], spacing: 4)
        let provider = stack([label("Provider", size: 10, secondary: true),
                              stack([artwork(card.access.provider.icon, fallback: card.access.provider.symbol ?? "lock.shield", size: 22),
                                     stack([label(card.access.provider.name, size: 13, weight: .medium),
                                            label(card.access.provider.detail, size: 11, secondary: true)], spacing: 2)], spacing: 6, horizontal: true)], spacing: 4)
        let access = stack([duration, profile, provider], spacing: 14, horizontal: true)
        access.alignment = .top
        access.distribution = .fillEqually
        fullWidth(access, in: body)

        let credentials = stack([label("Credentials", size: 12, weight: .semibold, secondary: true)], spacing: 12)
        for credential in card.credentials {
            let row = stack([symbol("key.horizontal", tint: accent, size: 16),
                             stack([label(credential.name, size: 13, weight: .medium),
                                    label(credential.variable, size: 11, secondary: true, mono: true)], spacing: 3)], spacing: 10, horizontal: true)
            fullWidth(row, in: credentials)
        }
        fullWidth(credentials, in: body)

        for item in card.facts {
            let heading = stack([label(item.label, size: 12, weight: .semibold),
                                 label(item.callerSupplied ? "Caller supplied" : "", size: 10, secondary: true)], spacing: 8, horizontal: true)
            let requested = stack([heading], spacing: 7)
            fullWidth(panel(label(item.value, size: 12, mono: true)), in: requested)
            fullWidth(requested, in: body)
        }
        fullWidth(label("Any command in this session can read these credentials.", size: 11, secondary: true), in: body)

        let disclosure = PreviewButton(title: expanded ? "Hide connection details" : "Connection details", target: self, action: #selector(toggleDetails))
        disclosure.bezelStyle = .inline
        disclosure.image = NSImage(systemSymbolName: expanded ? "chevron.down" : "chevron.right", accessibilityDescription: nil)
        disclosure.imagePosition = .imageLeading
        disclosure.setAccessibilityLabel(expanded ? "Hide connection details" : "Show connection details")
        body.addArrangedSubview(disclosure)
        if expanded {
            let details = stack([], spacing: 12)
            for item in card.details { fullWidth(fact(item), in: details) }
            fullWidth(panel(details), in: body)
        }

        let scrollHint = label("", size: 11, secondary: true)
        scrollHint.isHidden = true
        fullWidth(scrollHint, in: rootStack)
        let separator = NSBox()
        separator.boxType = .separator
        fullWidth(separator, in: rootStack)
        let actions = stack([], spacing: 8, horizontal: true)
        actions.distribution = .fillEqually
        func waitingMethod(_ title: String, _ glyph: String) -> NSView {
            let content = stack([symbol(glyph, tint: accent, size: 26),
                                 label(title, size: 13, weight: .medium)], spacing: 6)
            content.alignment = .centerX
            let view = NSView()
            view.addSubview(content)
            NSLayoutConstraint.activate([
                view.heightAnchor.constraint(equalToConstant: 76),
                content.centerXAnchor.constraint(equalTo: view.centerXAnchor),
                content.centerYAnchor.constraint(equalTo: view.centerYAnchor),
                content.widthAnchor.constraint(lessThanOrEqualTo: view.widthAnchor)
            ])
            view.setAccessibilityElement(true)
            view.setAccessibilityLabel("\(title), waiting for authentication")
            return view
        }
        if resultMessage.isEmpty && simulatedMethods.touchAvailable {
            actions.addArrangedSubview(waitingMethod("Touch ID", "touchid"))
        }
        if resultMessage.isEmpty && simulatedMethods.watchAvailable {
            actions.addArrangedSubview(waitingMethod("Apple Watch", "applewatch"))
        }
        status.font = .systemFont(ofSize: 11)
        status.textColor = .secondaryLabelColor
        status.setAccessibilityLabel("Preview result")
        status.isHidden = resultMessage.isEmpty
        fullWidth(status, in: rootStack)
        let deny = PreviewButton(title: "Deny", target: self, action: #selector(denyPreview))
        deny.bezelStyle = .rounded
        deny.keyEquivalent = "\u{1b}"
        deny.isEnabled = resultMessage.isEmpty
        deny.font = .systemFont(ofSize: 13 * scale, weight: .medium)
        deny.actionSymbol = "xmark"
        deny.heightAnchor.constraint(equalToConstant: 76).isActive = true
        deny.widthAnchor.constraint(greaterThanOrEqualToConstant: 72).isActive = true
        let next = PreviewButton(title: "Use Password", target: self, action: #selector(passwordPreview))
        next.bezelStyle = .rounded
        next.keyEquivalent = "\r"
        next.isEnabled = resultMessage.isEmpty
        next.primaryFill = appearance.indexOfSelectedItem == 1 ? accent : color(card.brand.actionAccent ?? card.brand.accent)
        next.primaryText = appearance.indexOfSelectedItem == 1 ? color("0B171D") : .white
        next.font = .systemFont(ofSize: 13 * scale, weight: .medium)
        next.actionSymbol = "lock"
        next.heightAnchor.constraint(equalToConstant: 76).isActive = true
        next.widthAnchor.constraint(greaterThanOrEqualToConstant: 110).isActive = true
        actions.addArrangedSubview(next)
        actions.addArrangedSubview(deny)
        fullWidth(actions, in: rootStack)
        window.initialFirstResponder = deny
        window.contentView?.layoutSubtreeIfNeeded()
        status.stringValue = resultMessage
        status.isHidden = status.stringValue.isEmpty
        scrollHint.stringValue = document.frame.height > scroll.contentView.bounds.height ? "Scroll to review the full request." : ""
        scrollHint.isHidden = scrollHint.stringValue.isEmpty
    }

    @objc func showOptions() { settings.makeKeyAndOrderFront(nil) }

    @objc func toggleDetails() { expanded.toggle(); reload() }
    @objc func denyPreview() { resultMessage = "Preview: denied. No approval was issued."; reload() }
    @objc func passwordPreview() {
        let sheet = NSAlert()
        sheet.messageText = "Mac password · preview"
        sheet.informativeText = "Your Mac password belongs in the macOS authentication prompt. This preview does not open that prompt, collect a password, or issue an approval."
        sheet.addButton(withTitle: "Back to review")
        sheet.beginSheetModal(for: window) { _ in
            self.resultMessage = ""
            self.reload()
        }
    }

    func captureVariants(_ directory: URL) {
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            for (name, sample, dark, large, details, brand, method) in [
                ("keylease-light", 0, false, false, false, 0, 0),
                ("keylease-dark", 0, true, false, false, 0, 0),
                ("plaintext-light", 2, false, false, false, 0, 0),
                ("details-dark", 0, true, false, true, 0, 0),
                ("long-large", 1, false, true, true, 0, 0),
                ("application-brand", 0, false, false, false, 1, 0),
                ("bounded-large", 1, false, true, true, 0, 0),
                ("touch-id-only", 0, false, false, false, 0, 1),
                ("watch-only", 0, false, false, false, 0, 2),
                ("password-only", 0, false, false, false, 0, 3)
            ] {
                cases.selectItem(at: sample)
                appearance.selectItem(at: dark ? 1 : 0)
                branding.selectItem(at: brand)
                methods.selectItem(at: method)
                larger.state = large ? .on : .off
                expanded = details
                // Fit the full document for review artifacts; the interactive
                // window retains its bounded viewport and native scrolling.
                window.setContentSize(NSSize(width: name == "bounded-large" ? 520 : 560, height: name == "bounded-large" ? 580 : (large ? 1080 : (details ? 880 : (sample == 2 ? 730 : 640)))))
                reload()
                guard let view = window.contentView,
                      let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { throw PreviewError.capture }
                window.appearance?.performAsCurrentDrawingAppearance {
                    view.cacheDisplay(in: view.bounds, to: bitmap)
                }
                guard let png = bitmap.representation(using: .png, properties: [:]) else { throw PreviewError.capture }
                try png.write(to: directory.appendingPathComponent(name + ".png"))
            }
            print("Captured ten native AppKit variants in \(directory.path)")
            NSApp.terminate(nil)
        } catch {
            fputs("Preview capture: \(error)\n", stderr)
            exit(1)
        }
    }
}

enum PreviewError: Error { case capture }
let arguments = CommandLine.arguments
let root = URL(fileURLWithPath: arguments.count > 1 ? arguments[1] : FileManager.default.currentDirectoryPath, isDirectory: true)
let preview = Preview(root: root)
let app = NSApplication.shared
app.setActivationPolicy(.regular)
app.delegate = preview
app.run()
