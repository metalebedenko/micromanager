# micromanager

[По-русски](README.md)

An experimental tool that lets an AI agent work with files and commands on a computer. The owner controls which files the agent can access and can approve or decline changes. It supports Windows, Linux and macOS.

## Before using a release

The downloadable [0.0.3 binaries](https://github.com/metalebedenko/micromanager/releases/tag/v0.0.3) predate the dependency updates in this source revision. The installers verify the published SHA-256 checksum before extracting an archive. To use the updated dependencies, build from the current source. Keep local credentials, peer identities and private configuration out of public issues and logs.

The desktop interface shows approval requests. The [architecture](ARCHITECTURE.md) describes how access limits, local settings and remote sessions fit together. The [Russian guide](README.md) covers the commands and supported release platforms.

Recognised credential formats are masked in the file audit log and automatic Telegram reports. Telegram approval rejects requests containing recognisable credentials. Use local approval for these actions. On Unix, new and reopened audit logs are restricted to the file owner. Free-form command text can still contain private information. Share only a short, redacted excerpt in a public issue.

[MIT licence](LICENSE-MIT) · [Apache 2.0 licence](LICENSE-APACHE)
