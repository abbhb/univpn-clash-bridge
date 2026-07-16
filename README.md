# UniVPN Clash Bridge

A small native macOS utility for running Clash Verge Rev TUN together with a
packet-tunnel VPN that publishes private DNS servers.

It keeps normal proxy egress on Clash's automatically detected interface while
routing configured private domains and their DNS queries through a dedicated
Mihomo `direct` outbound bound to the VPN's current `utunN` interface.

## Features

- First-run configuration for VPN DNS/probe IPs and private domain suffixes.
- Detects the VPN interface from the macOS route to the configured DNS servers.
- Rejects Clash's own `198.18.0.1` TUN interface.
- Updates Clash Verge Rev's global extension script and DNS settings.
- Validates the final configuration before hot-reloading Mihomo.
- Bundled privileged DNS Guard removes only matching root-domain DNS takeover.
- Atomic rollback and permission-restricted backups.
- No telemetry, update checker, or app-managed outbound internet requests.

## Requirements

- macOS 15 or later on Apple Silicon.
- Clash Verge Rev installed in `/Applications`.
- Mihomo with custom `direct` outbound support.

## First Run

Configure these values locally in the app:

1. The DNS server IPs exposed by your VPN. They are also used as route probes.
2. The private domain suffixes that should resolve and connect through the VPN.
3. The Clash Verge Rev application-support directory.
4. Whether to install DNS root-domain protection.

Installing DNS protection requires the standard macOS administrator prompt.

## Local Data

No user configuration or backup is bundled into a build or sent anywhere.
Application data is stored under:

```text
~/Library/Application Support/UniVPN Clash Bridge/
```

This contains `config.json`, private backups, and temporary installer files.
Configuration and backup files use restrictive local permissions.

The optional root DNS Guard installs its system files under standard macOS
`/Library` locations and runs as a LaunchDaemon because modifying the System
Configuration dynamic store requires root privileges.

## Build

```sh
chmod +x package_app.sh scripts/privacy-audit.sh scripts/release-audit.sh
./scripts/privacy-audit.sh
./package_app.sh
./scripts/release-audit.sh
```

The release build is ad-hoc signed. It is not notarized, so downloaded builds
may require using Finder's **Open** command the first time.

## Safety Model

Before every update, the app backs up the three Clash files it owns. It then
updates a marked JavaScript block, rewrites only configured DNS policies and
domain rules, runs `verge-mihomo -t`, and finally reloads through the local Unix
socket. Any validation or reload failure restores the original files.

This independent project is not affiliated with Clash Verge Rev or UniVPN.
Product names and marks belong to their respective owners.

## License

MIT
