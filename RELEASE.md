Intent provides a Go client, a macOS native approval SDK, and an SSH approval CLI. The SDK embeds its native helper; applications require no installed Intent executable or Swift toolchain. CLI archives include everything needed for their platform.

macOS helper bundles are ad-hoc signed, not notarized. Native authentication interaction remains unverified; automated checks exercise the helper protocol, cache, and SSH transport using synthetic decisions.

Migrating from Keylease requires updating CLI commands, Go imports, environment variables, and dotfiles SSH setup together. See the README for installation and the cooperative approval contract.
