import Foundation
import Network

public struct AppConfiguration: Codable, Sendable, Equatable {
    public var schemaVersion: Int
    public var dnsServers: [String]
    public var internalDomains: [String]
    public var clashConfigDirectory: String
    public var dnsGuardEnabled: Bool

    public init(
        schemaVersion: Int = 1,
        dnsServers: [String],
        internalDomains: [String],
        clashConfigDirectory: String,
        dnsGuardEnabled: Bool = true
    ) {
        self.schemaVersion = schemaVersion
        self.dnsServers = dnsServers
        self.internalDomains = internalDomains
        self.clashConfigDirectory = clashConfigDirectory
        self.dnsGuardEnabled = dnsGuardEnabled
    }

    public static func suggestedClashConfigDirectory(fileManager: FileManager = .default) -> String {
        fileManager.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/io.github.clash-verge-rev.clash-verge-rev")
            .path
    }

    public func normalized(fileManager: FileManager = .default) throws -> AppConfiguration {
        let normalizedDNS = try unique(dnsServers.map(normalizeScalar)).map { address in
            guard IPv4Address(address) != nil || IPv6Address(address) != nil else {
                throw BridgeError.invalidConfiguration("“\(address)”不是有效的 DNS IP 地址")
            }
            return address
        }
        guard !normalizedDNS.isEmpty else {
            throw BridgeError.invalidConfiguration("至少需要一个 VPN DNS / 探测 IP")
        }

        let normalizedDomains = try unique(internalDomains.map(normalizeDomain))
        guard !normalizedDomains.isEmpty else {
            throw BridgeError.invalidConfiguration("至少需要一个内网域名后缀")
        }

        let expandedPath = NSString(string: normalizeScalar(clashConfigDirectory)).expandingTildeInPath
        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: expandedPath, isDirectory: &isDirectory), isDirectory.boolValue else {
            throw BridgeError.invalidConfiguration("Clash Verge 配置目录不存在")
        }

        return AppConfiguration(
            schemaVersion: 1,
            dnsServers: normalizedDNS,
            internalDomains: normalizedDomains,
            clashConfigDirectory: URL(fileURLWithPath: expandedPath).standardizedFileURL.path,
            dnsGuardEnabled: dnsGuardEnabled
        )
    }

    private func normalizeScalar(_ value: String) -> String {
        value.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func normalizeDomain(_ value: String) throws -> String {
        var domain = normalizeScalar(value).lowercased()
        for prefix in ["+.", "*."] where domain.hasPrefix(prefix) {
            domain.removeFirst(prefix.count)
        }
        while domain.hasPrefix(".") { domain.removeFirst() }
        while domain.hasSuffix(".") { domain.removeLast() }

        let labels = domain.split(separator: ".", omittingEmptySubsequences: false)
        guard !labels.isEmpty, domain.count <= 253 else {
            throw BridgeError.invalidConfiguration("“\(value)”不是有效的域名后缀")
        }
        for label in labels {
            guard !label.isEmpty,
                  label.count <= 63,
                  label.first?.isLetter == true || label.first?.isNumber == true,
                  label.last?.isLetter == true || label.last?.isNumber == true,
                  label.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "-" })
            else {
                throw BridgeError.invalidConfiguration("“\(value)”不是有效的域名后缀")
            }
        }
        return domain
    }

    private func unique(_ values: [String]) -> [String] {
        var seen = Set<String>()
        return values.filter { !$0.isEmpty && seen.insert($0).inserted }
    }
}

public struct AppDataPaths: Sendable {
    public let root: URL
    public let configuration: URL
    public let backups: URL
    public let installerStaging: URL

    public static func current(fileManager: FileManager = .default) throws -> AppDataPaths {
        let root = fileManager.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support")
            .appendingPathComponent(BridgeConstants.appSupportDirectoryName)
        let paths = AppDataPaths(
            root: root,
            configuration: root.appendingPathComponent("config.json"),
            backups: root.appendingPathComponent("Backups"),
            installerStaging: root.appendingPathComponent("Installer")
        )
        try paths.ensureDirectories(fileManager: fileManager)
        return paths
    }

    private func ensureDirectories(fileManager: FileManager) throws {
        for directory in [root, backups, installerStaging] {
            try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
            try? fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        }
    }
}

public struct ConfigurationStore {
    private let fileManager: FileManager

    public init(fileManager: FileManager = .default) {
        self.fileManager = fileManager
    }

    public func load() throws -> AppConfiguration? {
        let paths = try AppDataPaths.current(fileManager: fileManager)
        guard fileManager.fileExists(atPath: paths.configuration.path) else { return nil }
        let data = try Data(contentsOf: paths.configuration)
        return try JSONDecoder().decode(AppConfiguration.self, from: data).normalized(fileManager: fileManager)
    }

    @discardableResult
    public func save(_ configuration: AppConfiguration) throws -> AppConfiguration {
        let normalized = try configuration.normalized(fileManager: fileManager)
        let paths = try AppDataPaths.current(fileManager: fileManager)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        try encoder.encode(normalized).write(to: paths.configuration, options: .atomic)
        try? fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: paths.configuration.path)
        return normalized
    }

    @discardableResult
    public func migrateLegacyBackups(for configuration: AppConfiguration) throws -> Int {
        let paths = try AppDataPaths.current(fileManager: fileManager)
        let legacyRoot = URL(fileURLWithPath: configuration.clashConfigDirectory)
            .appendingPathComponent("UniVPNClashBridge")
        let legacyBackups = legacyRoot.appendingPathComponent("Backups")
        guard fileManager.fileExists(atPath: legacyBackups.path) else { return 0 }

        let children = try fileManager.contentsOfDirectory(
            at: legacyBackups,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        )
        var moved = 0
        for source in children {
            var destination = paths.backups.appendingPathComponent("Legacy-\(source.lastPathComponent)")
            if fileManager.fileExists(atPath: destination.path) {
                destination = paths.backups.appendingPathComponent("Legacy-\(UUID().uuidString)-\(source.lastPathComponent)")
            }
            try fileManager.moveItem(at: source, to: destination)
            try restrictBackupPermissions(at: destination)
            moved += 1
        }

        try fileManager.removeItem(at: legacyRoot)
        return moved
    }

    private func restrictBackupPermissions(at url: URL) throws {
        let values = try url.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
        guard values.isSymbolicLink != true else { return }
        let isDirectory = values.isDirectory == true
        try? fileManager.setAttributes(
            [.posixPermissions: isDirectory ? 0o700 : 0o600],
            ofItemAtPath: url.path
        )
        guard isDirectory else { return }

        for child in try fileManager.contentsOfDirectory(at: url, includingPropertiesForKeys: nil) {
            try restrictBackupPermissions(at: child)
        }
    }
}
