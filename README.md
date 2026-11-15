# Intent

Explicit human approval for Go applications and commands over SSH. Review a request on your Mac, then authenticate using the methods macOS makes available, including Touch ID, Apple Watch, or password. Callers receive a decision, never biometric data or your password.

Intent collects approval. Your application owns what the approval permits and must proceed only after a confirmed `Approved` result. A remote caller's reason is an unverified claim; Intent neither verifies nor executes the described action.

## Install

Download the archive for your platform from [Releases](https://github.com/lanej/intent/releases), verify it against `SHA256SUMS`, and put `intent` on your PATH. CLI archives support macOS and Linux on arm64 and amd64. macOS native approval requires macOS 13 or later. Windows native approval and SSH setup are unsupported.

Alternatively, with Go 1.26.11 or newer:

```sh
go install github.com/lanej/intent/cmd/intent@v0.1.0
```

Mac consumers need no separate app bundle, Swift compiler, CGo, or runtime download. Signed helper bundles are embedded in the Go module and executable. They are ad-hoc signed, not notarized. You must be logged into the Mac's graphical session to authenticate; available methods depend on hardware and system settings.

## Approve remotely

Install the CLI on the Mac and on the remote host's noninteractive SSH PATH. Configure ports, identities, and jump hosts through your ordinary SSH config, then run from the Mac:

```sh
intent ssh user@host
```

Inside that remote shell:

```sh
intent request --reason 'Deploy revision abc123 to production' && ./deploy abc123
```

The legacy production launcher exposes a private one-time approval socket as `INTENT_APPROVAL_SOCKET` and uses SSH multiplexing. It forwards no credential endpoints and leaves your authentication agent alone. The [stable remote socket proof](experiments/stable-socket/README.md) explores dedicated connections without multiplexing; production integration is pending. [Dotfiles](https://github.com/lanej/dotfiles) installs Intent and Keylease independently. Its `make intent-ssh` target currently rejects activation, while `make intent-ssh-remove` retires the old managed hook.

`intent request` writes JSON with `request_id` and `decision`. Exit codes are approved **0**, denied **2**, cancelled **3**, timed out **4**, unavailable **5**, and busy **6**. Operational or caller-context errors use **1**. `--timeout 30s` shortens the maximum two-minute request lifetime. An expired caller can return a context error before receiving a timeout decision; neither permits proceeding.

## Agent identity

Agent applications supply a type and opaque instance/session ID as caller context. This identifies the requesting agent for human review; it does not authenticate that agent or authorize its action. The agent ID is distinct from the fresh approval request ID and the SSH transport session.

The CLI resolves identity in this order:

1. `--agent-type TYPE --agent-id ID` replaces the whole identity.
2. `INTENT_AGENT_TYPE` and `INTENT_AGENT_ID` supply an explicit environment pair for any agent family.
3. `CODEX_THREAD_ID`, or `CODEX_SESSION_ID` when the thread variable is absent or empty, infers type `codex`.
4. Without any of these, identity remains unspecified.

Partial explicit pairs and invalid values are errors; fields are never combined across sources. Environment inference is a caller claim, not proof of process identity. For example:

```sh
intent request --reason 'Publish build abc123' --agent-type codex --agent-id thread-123
INTENT_AGENT_TYPE=custom-agent INTENT_AGENT_ID=session-456 intent request --reason 'Publish build abc123'
```

SSH does not automatically forward agent environment variables. An agent running remotely can inherit its own context; an invocation sent from another host should supply the flags explicitly.

The Go library never infers agent identity from environment variables. Set `Request.Agent` for a remote request or `Review.Agent` for a local native review. Both fields are optional for non-agent callers. `AgentIdentity` requires both `Type` (1–64 UTF-8 bytes) and `ID` (1–256 bytes), without whitespace, control or formatting characters. Preserve the identity while the call is pending.

Agent-bearing SSH requests require updated clients and Mac approval brokers. Older strict brokers reject the new field; the client never drops identity or retries to obtain approval. Requests without identity keep their existing wire shape. The existing native renderer displays type and ID as labeled caller-supplied summary fields; the experimental card renders them as structured fields.

## Go libraries

Remote applications import the standard-library-only root package:

```go
client, err := intent.ClientFromEnv()
if err != nil {
    return err
}
result, err := client.Approve(ctx, intent.Request{
    Reason: "Publish build abc123",
    Agent: &intent.AgentIdentity{Type: "codex", ID: "thread-123"},
})
if err != nil {
    return err
}
if result.Decision != intent.Approved {
    return fmt.Errorf("publication not approved: %s", result.Decision)
}
return publish(ctx, "abc123")
```

`ClientFromEnv` snapshots an explicit `INTENT_APPROVAL_SOCKET` first; otherwise it discovers an owned receipt for sshd's `SSH_CONNECTION`. It waits under the caller's context for up to ten seconds for setup. Use `intent.NewClient(socketPath)` for custom forwarding. Clients are safe for concurrent use; every request has a new connection and approval request ID. Reasons must be nonempty UTF-8, at most 4096 bytes, without control or formatting characters except tabs and newlines.

Local Mac applications import `github.com/lanej/intent/native` and call it directly:

```go
result, err := native.Review(ctx, intent.Review{
    Title:   "Authorize deployment",
    Summary: "Target: production\nRevision: abc123",
    Details: changeSummary,
    Agent:   &intent.AgentIdentity{Type: "codex", ID: "thread-123"},
})
if err != nil {
    return err
}
if result.Decision != intent.Approved {
    return fmt.Errorf("deployment not approved: %s", result.Decision)
}
return deploy(ctx, "abc123")
```

The SDK manages a private helper process and its lifecycle without requiring an installed `intent` CLI or AppKit setup in your process. Titles are limited to 256 bytes, summaries to 64 KiB, and scrollable details to 256 KiB; all must be UTF-8 without control or formatting characters except tabs and newlines. Label caller-supplied claims in your review. Non-macOS native calls return `Unavailable`.

## Lifetime and trust

Every approval requires explicit review and fresh OS authentication. Approvals are not cached or leased. One request can be pending per SSH broker; overlaps receive `Busy`. Cancellation, expiry, and transport loss cancel pending UI and prevent late success. Requests are never automatically retried after submission. `intent.ErrOutcomeUnknown` means no trustworthy decision was received; do not infer approval or automatically repeat the request.

The legacy hook uses its SSH master's local connection metadata. Proxy transports may hide the destination; the review then reports it unavailable. Remote root and same-user processes can access the forwarded endpoint, and Intent cannot establish which remote process made a request. Same-user processes on the Mac are also outside its isolation boundary. Intent provides no signed receipts or privileged enforcement.

Helper bytes and signatures live in an owner-only content-addressed cache at `~/Library/Caches/dev.joshlane.intent`. The SDK checks ownership, permissions, and content before execution, and fails closed on unexpected or altered entries. Remove that cache while no reviews are running to recover from corruption; it is recreated from embedded assets. Review content, credentials, and decisions are never stored there.

The automatic broker stops with its SSH master without sustaining idle connections. New setup conservatively removes stale owned receipts and matching private endpoints only when no socket listener exists. Uncertain failures and unexpected files are preserved. Final disconnected metadata can remain until the next setup; it contains no credentials or decisions. Hook diagnostics are under `~/.intent-ssh/*.log`.

## Develop and verify

`make build` builds only Go. `make check` runs formatting, vet, race tests, and embedded-asset consistency checks; `make lint` uses the version in `.golangci-version`. Maintainers rebuild both signed Mac helper bundles using `make native` on macOS with Xcode Command Line Tools, then commit the assets and manifest before tagging. Consumers never run this generation step. `python3 scripts/release.py` builds the four CLI archives and checksums.

`INTENT_SSH_INTEGRATION=1 go test -v ./internal/approvalssh -run TestOpenSSHIntegration` exercises a disposable real loopback sshd with synthetic approval callbacks, including decisions, cancellation, multiplexing, reconnect, idle expiry, and stale cleanup. It changes no user SSH configuration.

A [stable remote socket design and executable proof](experiments/stable-socket/README.md) explores a separate non-multiplexed transport. It is not installed or enabled by the production CLI.

A [structured Mac approval preview](experiments/mac-review/README.md) explores application branding and human presentation of structured requests. It is a standalone, inert prototype. Agent metadata is supported separately by the SDK and request CLI; the visual prototype is not installed or enabled by production commands.

Human authentication and rendered interaction remain unverified. To exercise them explicitly on your Mac, run `INTENT_NATIVE_ACCEPTANCE=1 go test -v ./native -run TestHumanAcceptance`: authenticate the first request and deny the second. Repeat for each available method; only the method actually exercised is verified.

## Migrate from Keylease

Use `intent request` instead of `keylease approval request`, `intent ssh` instead of `keylease ssh`, `github.com/lanej/intent` instead of `github.com/lanej/keylease/approval`, and `INTENT_APPROVAL_SOCKET` instead of `KEYLEASE_APPROVAL_SOCKET`. No compatibility aliases are provided. Install Intent on both SSH endpoints. Dotfiles automatic SSH activation awaits production stable-socket integration; `make intent-ssh-remove` retires its old managed configuration. Existing sessions are not terminated. Keylease credential review uses this SDK directly and retains its credential policy.

## License

MIT. Extracted from the author's Keylease approval implementation into a clean public history.

## Go quality

`make check` runs the tracked strict Go profile: formatting, the preserved legacy lint gate, exhaustive enums and sum types, checked errors, security analysis, uncached race tests, and reachable-vulnerability analysis. There is no grandfathered lint baseline. `make lint` runs the lint portion and `make fmt` applies the profile's formatting. Checks select the Go patch version in `go.mod` because the pinned profile linter requires that toolchain; builds may use a compatible newer Go release.

`source-code.toml` records the tracked beta profile and Codex guidance. Use `source-code setup --dry-run` to preview policy changes and `source-code validate --strict` to verify installed packages and pins. CI runs the full strict gate on Linux and macOS. `make quality-windows` cross-checks Windows lint and reachable vulnerabilities; native Windows CI retains its build and race tests. A passing profile does not establish human native authentication.
