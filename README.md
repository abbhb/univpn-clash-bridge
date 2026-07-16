# UniVPN Clash Bridge

A small native macOS utility for running Clash Verge Rev TUN together with a
packet-tunnel VPN that publishes private DNS servers.

It maintains a dedicated Mihomo `direct` outbound bound to the VPN's current
`utunN` interface while leaving normal proxy egress on Clash's own interface.
Private-domain rules and DNS policies can remain fully managed by Clash.

## Features

- First-run configuration for VPN DNS/probe IPs and optional private domain suffixes.
- Detects the VPN interface from the macOS route to the configured DNS servers.
- Rejects Clash's own `198.18.0.1` TUN interface.
- Updates the dedicated direct outbound without touching existing rules or DNS in interface-only mode.
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
2. Optional private domain suffixes for the app to manage. Leave this empty when
   Clash already owns the domain rules and DNS policies.
3. The Clash Verge Rev application-support directory.
4. Whether to install DNS root-domain protection.

Installing DNS protection requires the standard macOS administrator prompt.

When the domain list is empty, existing Clash rules that need the VPN should
select `UNIVPN-DIRECT`. The app then updates only that outbound's
`interface-name` as the VPN's `utunN` changes.

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

Before every update, the app backs up only the Clash files it will change. It
updates a marked JavaScript block and the dedicated direct outbound. DNS policies
and domain rules are touched only when optional managed domains are configured.
It then runs `verge-mihomo -t` and reloads through the local Unix socket. Any
validation or reload failure restores the original files.

This independent project is not affiliated with Clash Verge Rev or UniVPN.
Product names and marks belong to their respective owners.

## License

MIT
