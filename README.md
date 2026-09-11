# UniVPN Clash Bridge

A small native macOS utility for running Clash Verge Rev TUN together with a
packet-tunnel VPN that publishes private DNS servers.

It maintains a dedicated Mihomo `direct` outbound bound to the VPN's current
`utunN` interface while leaving normal proxy egress on Clash's own interface.
DNS selection and application-traffic routing are configured independently.

## Features

- First-run configuration for VPN DNS/probe IPs and optional VPN route domains.
- Detects the VPN interface from the macOS route to the configured DNS servers.
- Rejects Clash's own `198.18.0.1` TUN interface.
- Restores a clean `DIRECT` mode when the VPN is disconnected or only Clash TUN is detected.
- Removes VPN DNS servers from Clash's general resolver pool even when no domains are configured.
- Reads a top-level `internalDomains` array from the Clash script for internal DNS policy only.
- Forces only the domains entered in the app (`vpnRouteDomains`) through `UNIVPN-DIRECT`.
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
2. Optional domain suffixes whose application traffic must use the VPN-bound
   `UNIVPN-DIRECT` outbound. An empty list means the bridge forces no business
   traffic through the VPN.
3. The Clash Verge Rev application-support directory.
4. Whether to install DNS root-domain protection.

Installing DNS protection requires the standard macOS administrator prompt.

The app always removes the configured VPN DNS IPs from Clash's general
`nameserver` list, so those IPs are no longer used as general resolvers. A
top-level, JSON-style `internalDomains` string array in `Script.js` controls
only which domains use those internal DNS servers through `UNIVPN-DIRECT`; it
never forces their application connections through the VPN. The app's
`vpnRouteDomains` list controls only application routing and does not create DNS
policies. If `internalDomains` is absent, DNS cleanup still succeeds.

Clicking **Detect and Update** is intentionally reversible. With a real VPN
`utunN`, the bridge block, custom outbound, and `#UNIVPN-DIRECT` DNS bindings
are installed. Without a real VPN route, the bridge block is removed, the
dedicated outbound becomes an ordinary unbound `direct` outbound, managed DNS
bindings become explicit `#DIRECT`, and only bridge-owned VPN route rules are
removed. Keeping the harmless unbound outbound prevents unrelated custom rules
from becoming dangling references. Connecting the VPN and clicking again
switches back. On a public network without the company LAN or VPN, private DNS
servers are naturally unreachable even in DIRECT mode.

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
updates a marked JavaScript block and the dedicated direct outbound. VPN DNS
servers are removed from the general resolver pool. Script `internalDomains`
DNS policies and app `vpnRouteDomains` traffic rules are managed separately,
including cleanup when either list becomes empty.
Managed DNS policy comments keep DIRECT-mode entries identifiable so removed
`internalDomains` do not leave stale policies behind.
Managed application-route comments provide the same ownership boundary for
`vpnRouteDomains`; rules outside those markers are preserved even if they also
reference `UNIVPN-DIRECT`.
When upgrading from the old combined-domain behavior, the bridge restores any
overwritten route from Clash Verge's last generated check configuration at its
original priority; it aborts and rolls back if that recovery cannot be proven safe.
It then runs `verge-mihomo -t` and reloads through the local Unix socket. Any
validation or reload failure restores the original files.

This independent project is not affiliated with Clash Verge Rev or UniVPN.
Product names and marks belong to their respective owners.

## License

MIT
