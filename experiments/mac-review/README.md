# Structured Mac approval preview

A standalone AppKit prototype for reviewing structured approval content with application branding. It is intentionally separate from Intent's public SDK, production helper and SSH transport. No credential is read, no command runs, and no approval or authentication is issued. Every screen carries a preview label.

## Run on a Mac

Requires macOS 13 or later and Xcode Command Line Tools. From the repository root:

```sh
python3 experiments/mac-review/preview.py
```

The script compiles `main.swift` into the ignored `bin/mac-review-preview` and opens a standalone review window. Select a normal credential request, a long request or a plaintext-file request. Change Keylease/example branding, light/dark appearance or larger text without changing the layout. Expand technical details to inspect the session and profile metadata. All data is synthetic.

Deny changes only the preview status. Continue opens a simulated authentication explanation with a Back to review button. It never invokes macOS authentication. Escape is assigned to Deny, Return to Continue and Command-Q exits. The window uses native scrolling and selectable request text. Keyboard navigation, focus, selection and the sheet still require verification in an unlocked graphical session; they have not been live-tested.

## Information architecture

| Structured input | Human presentation |
| --- | --- |
| Application name, icon or SF Symbol, light/dark accents | Application identity; Intent remains visible as the presenter. Branding does not establish trust. |
| Action title and summary | The decision in plain language, above the facts. |
| Labeled facts and caller-supplied flags | Requested command, duration and profile, with explicit provenance. A requested command is a claim, not a command restriction. |
| Credential names and environment mappings | What becomes accessible, without any credential values. The session-wide extraction consequence remains visible. |
| Consequence | A prominent warning for plaintext-file output, including destination, readability and expiry behavior. |
| Supporting facts | Expandable technical details for the session identifier, session label and profile digest. |

The fixtures in `fixtures/` are design inputs, not a proposed stable wire format. Alternate application branding is supplied by `example-brand.json`; typography, hierarchy, decision wording and layout remain owned by Intent. Colors distinguish identity and consequential effects, rather than encoding trust. The Keylease icon is copied from `lanej/keylease`'s `assets/icon/png/keylease-128.png`; its mint/teal accents follow that project's `assets/icon/design.json`. Harbor is a fictitious application used to demonstrate customization.

## Render evidence

```sh
python3 experiments/mac-review/preview.py --capture /tmp/intent-review-captures
```

This renders seven AppKit content-view PNGs and exits. These are native view exports, not desktop screenshots; they exclude window chrome. Six captures fit the document to inspect long content; `bounded-large.png` instead uses the minimum 620×650 content viewport to show overflow and the fixed footer. The interactive window instead has a bounded viewport with scrolling and persistent footer controls. The prototype draws its controls explicitly through AppKit because PDF export of modern composited controls omitted them while the Mac was locked; native `NSButton`/`NSPopUpButton` still own actions, menus and accessibility. These exports do not establish live keyboard, VoiceOver or authentication behavior.

| Variant | Artifact |
| --- | --- |
| Keylease, light | [View](screenshots/keylease-light.png) |
| Keylease, dark | [View](screenshots/keylease-dark.png) |
| Plaintext-file consequence | [View](screenshots/plaintext-light.png) |
| Technical details expanded | [View](screenshots/details-dark.png) |
| Long request with larger text | [View](screenshots/long-large.png) |
| Alternate application branding | [View](screenshots/application-brand.png) |
| Minimum viewport with long request and larger text | [View](screenshots/bounded-large.png) |

The seven exports were inspected for hierarchy, contrast, wrapping and clipping. The Swift build and repository `make check` passed; native interaction remains unverified because the Mac was locked and live testing was deferred. The images establish appearance, not acceptance of the design. Review this prototype before deciding the production SDK schema or integration.
