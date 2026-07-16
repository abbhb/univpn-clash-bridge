import Foundation

public struct DNSGuardManager {
    private let fileManager = FileManager.default
    private let helperPath = "/Library/PrivilegedHelperTools/io.github.abbhb.univpn-clash-bridge.dns-guard"
    private let configurationPath = "/Library/Application Support/UniVPN Clash Bridge/dns-guard.json"
    private let launchDaemonPath = "/Library/LaunchDaemons/io.github.abbhb.univpn-clash-bridge.dns-guard.plist"
    private let logPath = "/Library/Logs/UniVPN Clash Bridge/dns-guard.log"

    public init() {}

    public func status() -> DNSGuardStatus {
        guard fileManager.fileExists(atPath: launchDaemonPath) else { return .notInstalled }
        guard let result = try? Shell.run(
            "/bin/launchctl",
            ["print", "system/\(BridgeConstants.dnsGuardLabel)"]
        ) else {
            return .stopped
        }
        return result.exitCode == 0 && result.standardOutput.contains("state = running") ? .running : .stopped
    }

    public func installOrUpdate(configuration: AppConfiguration) throws {
        let normalized = try configuration.normalized()
        guard let bundledHelper = Bundle.main.url(forResource: "univpn-dns-guard", withExtension: nil) else {
            throw BridgeError.dnsGuardFailed("应用包中缺少 DNS Guard")
        }

        let appData = try AppDataPaths.current()
        let stagedConfiguration = appData.installerStaging.appendingPathComponent("dns-guard.json")
        let stagedPlist = appData.installerStaging.appendingPathComponent("dns-guard.plist")

        let guardConfiguration = GuardConfigurationFile(
            enabled: true,
            serviceID: "",
            serverAddresses: normalized.dnsServers,
            rootMatchOnly: true
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        try encoder.encode(guardConfiguration).write(to: stagedConfiguration, options: .atomic)
        try Data(launchDaemonPlist.utf8).write(to: stagedPlist, options: .atomic)
        try? fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: stagedConfiguration.path)

        let helperDirectory = (helperPath as NSString).deletingLastPathComponent
        let configurationDirectory = (configurationPath as NSString).deletingLastPathComponent
        let logDirectory = (logPath as NSString).deletingLastPathComponent
        let commands = [
            "(/bin/launchctl bootout system/\(BridgeConstants.dnsGuardLabel) >/dev/null 2>&1 || true)",
            "/bin/mkdir -p \(shellQuote(helperDirectory)) \(shellQuote(configurationDirectory)) \(shellQuote(logDirectory))",
            "/bin/chmod 700 \(shellQuote(configurationDirectory)) \(shellQuote(logDirectory))",
            "/usr/bin/install -m 755 \(shellQuote(bundledHelper.path)) \(shellQuote(helperPath))",
            "/usr/bin/install -m 600 \(shellQuote(stagedConfiguration.path)) \(shellQuote(configurationPath))",
            "/usr/bin/install -m 644 \(shellQuote(stagedPlist.path)) \(shellQuote(launchDaemonPath))",
            "/usr/bin/touch \(shellQuote(logPath))",
            "/bin/chmod 600 \(shellQuote(logPath))",
            "/bin/launchctl bootstrap system \(shellQuote(launchDaemonPath))",
            "/bin/launchctl enable system/\(BridgeConstants.dnsGuardLabel)",
            "/bin/launchctl kickstart -k system/\(BridgeConstants.dnsGuardLabel)",
        ]
        try runPrivilegedShell(commands.joined(separator: " && "))

        guard status() == .running else {
            throw BridgeError.dnsGuardFailed("守护进程安装后未进入运行状态")
        }
    }

    public func uninstall() throws {
        let commands = [
            "(/bin/launchctl bootout system/\(BridgeConstants.dnsGuardLabel) >/dev/null 2>&1 || true)",
            "/bin/rm -f \(shellQuote(launchDaemonPath)) \(shellQuote(helperPath)) \(shellQuote(configurationPath))",
        ]
        try runPrivilegedShell(commands.joined(separator: " && "))
    }

    private var launchDaemonPlist: String {
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>\(BridgeConstants.dnsGuardLabel)</string>
            <key>ProgramArguments</key>
            <array>
                <string>\(helperPath)</string>
                <string>--watch</string>
                <string>--config</string>
                <string>\(configurationPath)</string>
            </array>
            <key>RunAtLoad</key>
            <true/>
            <key>KeepAlive</key>
            <true/>
            <key>Umask</key>
            <integer>63</integer>
            <key>StandardOutPath</key>
            <string>\(logPath)</string>
            <key>StandardErrorPath</key>
            <string>\(logPath)</string>
        </dict>
        </plist>
        """
    }

    private func runPrivilegedShell(_ command: String) throws {
        let escaped = command
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        let script = "do shell script \"\(escaped)\" with administrator privileges"
        let result = try Shell.run("/usr/bin/osascript", ["-e", script])
        guard result.exitCode == 0 else {
            let message = result.standardError.trimmingCharacters(in: .whitespacesAndNewlines)
            throw BridgeError.dnsGuardFailed(message.isEmpty ? "管理员授权被取消" : message)
        }
    }

    private func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}

private struct GuardConfigurationFile: Codable {
    let enabled: Bool
    let serviceID: String
    let serverAddresses: [String]
    let rootMatchOnly: Bool
}
