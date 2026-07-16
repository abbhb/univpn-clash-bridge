# Privacy

UniVPN Clash Bridge has no analytics, telemetry, crash uploader, update checker,
or app-managed outbound internet request. It communicates with Mihomo only over
its local Unix socket and invokes local macOS command-line tools.

The following data remains on the local Mac:

- configured VPN DNS/probe IPs;
- configured private domain suffixes;
- the selected Clash Verge Rev directory;
- backups of modified Clash configuration files;
- local DNS Guard logs.

The public source tree and release package do not contain user configuration,
Clash profiles, subscription URLs, access tokens, logs, or backups.
