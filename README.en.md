# micromanager

[По-русски](README.md)

An experimental tool that lets an AI agent work with files and commands on a computer. The owner controls which files the agent can access and can approve or decline changes. It supports Windows, Linux and macOS.

## Download

[Download micromanager v0.0.4](https://github.com/metalebedenko/micromanager/releases/tag/v0.0.4) for macOS on Apple silicon (arm64) or Intel (x86_64), Windows x86_64, or Linux x86_64. The prebuilt downloads do not require Rust.

Version 0.0.4 includes the dependency updates and improvements to audit logs and local credential storage. The installers verify the archive’s SHA-256 checksum before extraction. Keep credentials and private configuration out of public issues.

The desktop interface shows approval requests. The [architecture](ARCHITECTURE.md) describes how access limits, local settings and remote sessions fit together. The [Russian guide](README.md) covers the commands and supported release platforms.

Recognised credential formats are masked in the file audit log and automatic Telegram reports. Telegram approval rejects requests containing recognisable credentials. Use local approval for these actions. On Unix, new and reopened audit logs are restricted to the file owner. Free-form command text can still contain private information. Share only a short, redacted excerpt in a public issue.

[MIT licence](LICENSE-MIT) · [Apache 2.0 licence](LICENSE-APACHE)
