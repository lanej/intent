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

The launcher owns a dedicated SSH connection and exposes a private one-time approval socket as `INTENT_APPROVAL_SOCKET`. It forwards no credential endpoints and leaves your SSH authentication agent alone. With [dotfiles](https://github.com/lanej/dotfiles), `make intent-ssh` enables the same mechanism for ordinary `ssh` sessions and direct commands; `make intent-ssh-remove` disables the managed setup. Automatic setup requires OpenSSH 10.3+ on the Mac.

`intent request` writes JSON with `request_id` and `decision`. Exit codes are approved **0**, denied **2**, cancelled **3**, timed out **4**, unavailable **5**, and busy **6**. Operational or caller-context errors use **1**. `--timeout 30s` shortens the maximum two-minute request lifetime. An expired caller can return a context error before receiving a timeout decision; neither permits proceeding.

## Go libraries

Remote applications import the standard-library-only root package:

```go
client, err := intent.ClientFromEnv()
if err != nil {
    return err
}
result, err := client.Approve(ctx, intent.Request{Reason: "Publish build abc123"})
if err != nil {
    return err
}
if result.Decision != intent.Approved {
    return fmt.Errorf("publication not approved: %s", result.Decision)
}
return publish(ctx, "abc123")
```

`ClientFromEnv` snapshots an explicit `INTENT_APPROVAL_SOCKET` first; otherwise it discovers an owned receipt for sshd's `SSH_CONNECTION`. It waits under the caller's context for up to ten seconds for setup. Use `intent.NewClient(socketPath)` for custom forwarding. Clients are safe for concurrent use; every request has a new connection and identity. Reasons must be nonempty UTF-8, at most 4096 bytes, without control or formatting characters except tabs and newlines.

Local Mac applications import `github.com/lanej/intent/native` and call it directly:

```go
result, err := native.Review(ctx, intent.Review{
    Title:   "Authorize deployment",
    Summary: "Target: production\nRevision: abc123",
    Details: changeSummary,
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

The automatic hook uses the existing SSH master's local connection metadata. Proxy transports may hide the destination; the review then reports it unavailable. Remote root and same-user processes can access the forwarded endpoint, and Intent cannot establish which remote process made a request. Same-user processes on the Mac are also outside its isolation boundary. Intent provides no signed receipts or privileged enforcement.

Helper bytes and signatures live in an owner-only content-addressed cache at `~/Library/Caches/dev.joshlane.intent`. The SDK checks ownership, permissions, and content before execution, and fails closed on unexpected or altered entries. Remove that cache while no reviews are running to recover from corruption; it is recreated from embedded assets. Review content, credentials, and decisions are never stored there.

The automatic broker stops with its SSH master without sustaining idle connections. New setup conservatively removes stale owned receipts and matching private endpoints only when no socket listener exists. Uncertain failures and unexpected files are preserved. Final disconnected metadata can remain until the next setup; it contains no credentials or decisions. Hook diagnostics are under `~/.intent-ssh/*.log`.

## Develop and verify

`make build` builds only Go. `make check` runs formatting, vet, race tests, and embedded-asset consistency checks; `make lint` uses the version in `.golangci-version`. Maintainers rebuild both signed Mac helper bundles using `make native` on macOS with Xcode Command Line Tools, then commit the assets and manifest before tagging. Consumers never run this generation step. `python3 scripts/release.py` builds the four CLI archives and checksums.

`INTENT_SSH_INTEGRATION=1 go test -v ./internal/approvalssh -run TestOpenSSHIntegration` exercises a disposable real loopback sshd with synthetic approval callbacks, including decisions, cancellation, multiplexing, reconnect, idle expiry, and stale cleanup. It changes no user SSH configuration.

A [stable remote socket design and executable proof](experiments/stable-socket/README.md) explores a separate non-multiplexed transport. It is not installed or enabled by the production CLI.

Human authentication and rendered interaction remain unverified. To exercise them explicitly on your Mac, run `INTENT_NATIVE_ACCEPTANCE=1 go test -v ./native -run TestHumanAcceptance`: authenticate the first request and deny the second. Repeat for each available method; only the method actually exercised is verified.

## Migrate from Keylease

Use `intent request` instead of `keylease approval request`, `intent ssh` instead of `keylease ssh`, `github.com/lanej/intent` instead of `github.com/lanej/keylease/approval`, and `INTENT_APPROVAL_SOCKET` instead of `KEYLEASE_APPROVAL_SOCKET`. No compatibility aliases are provided. Install Intent on both SSH endpoints, then run dotfiles `make intent-ssh` to replace its owned legacy configuration and reconnect. Existing sessions are not terminated. Keylease credential review uses this SDK directly and retains its credential policy.

## License

MIT. Extracted from the author's Keylease approval implementation into a clean public history.

## Go quality

`make check` runs the tracked strict Go profile: formatting, the preserved legacy lint gate, exhaustive enums and sum types, checked errors, security analysis, uncached race tests, and reachable-vulnerability analysis. There is no grandfathered lint baseline. `make lint` runs the lint portion and `make fmt` applies the profile's formatting. Checks select the Go patch version in `go.mod` because the pinned profile linter requires that toolchain; builds may use a compatible newer Go release.

`source-code.toml` records the tracked beta profile and Codex guidance. Use `source-code setup --dry-run` to preview policy changes and `source-code validate --strict` to verify installed packages and pins. CI runs the full strict gate on Linux and macOS. `make quality-windows` cross-checks Windows lint and reachable vulnerabilities; native Windows CI retains its build and race tests. A passing profile does not establish human native authentication.
