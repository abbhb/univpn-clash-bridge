import Foundation

public struct BridgePaths: Sendable {
    public let clashHome: URL
    public let globalScript: URL
    public let dnsConfig: URL
    public let runtimeConfig: URL
    public let mihomoCore: URL
    public let mihomoSocket: URL

    public static func current(
        configuration: AppConfiguration,
        fileManager: FileManager = .default
    ) throws -> BridgePaths {
        let home = URL(fileURLWithPath: configuration.clashConfigDirectory).standardizedFileURL
        guard fileManager.fileExists(atPath: home.path) else {
            throw BridgeError.clashHomeMissing(home.path)
        }

        let coreCandidates = [
            "/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo",
            "/Applications/Clash Verge Rev.app/Contents/MacOS/verge-mihomo",
        ]
        guard let corePath = coreCandidates.first(where: fileManager.fileExists(atPath:)) else {
            throw BridgeError.requiredFileMissing("Clash Verge 的 verge-mihomo")
        }

        let paths = BridgePaths(
            clashHome: home,
            globalScript: home.appendingPathComponent("profiles/Script.js"),
            dnsConfig: home.appendingPathComponent("dns_config.yaml"),
            runtimeConfig: home.appendingPathComponent("clash-verge.yaml"),
            mihomoCore: URL(fileURLWithPath: corePath),
            mihomoSocket: URL(fileURLWithPath: "/tmp/verge/verge-mihomo.sock")
        )

        var requiredFiles = [paths.globalScript, paths.runtimeConfig]
        if !configuration.internalDomains.isEmpty {
            requiredFiles.append(paths.dnsConfig)
        }
        for file in requiredFiles {
            guard fileManager.fileExists(atPath: file.path) else {
                throw BridgeError.requiredFileMissing(file.path)
            }
        }
        return paths
    }
}

public struct BridgeService {
    private let configuration: AppConfiguration
    private let fileManager = FileManager.default

    public init(configuration: AppConfiguration) throws {
        self.configuration = try configuration.normalized()
    }

    public func detect() throws -> InterfaceDetection {
        try InterfaceDetector().detect(dnsServers: configuration.dnsServers)
    }

    public func update() throws -> UpdateOutcome {
        let paths = try BridgePaths.current(configuration: configuration)
        let appData = try AppDataPaths.current()
        let detected = try detect()

        let originalScript = try String(contentsOf: paths.globalScript, encoding: .utf8)
        let originalRuntime = try String(contentsOf: paths.runtimeConfig, encoding: .utf8)

        let updatedScript = try ConfigTransformer.updateGlobalScript(
            originalScript,
            interface: detected.name,
            internalDomains: configuration.internalDomains
        )
        let updatedRuntime = try ConfigTransformer.updateRuntimeConfig(
            originalRuntime,
            interface: detected.name,
            dnsServers: configuration.dnsServers,
            internalDomains: configuration.internalDomains
        )
        var updates = [
            FileUpdate(url: paths.globalScript, original: originalScript, updated: updatedScript),
        ]
        if !configuration.internalDomains.isEmpty {
            let originalDNS = try String(contentsOf: paths.dnsConfig, encoding: .utf8)
            let updatedDNS = try ConfigTransformer.updateDNSConfig(
                originalDNS,
                dnsServers: configuration.dnsServers,
                internalDomains: configuration.internalDomains
            )
            updates.append(FileUpdate(url: paths.dnsConfig, original: originalDNS, updated: updatedDNS))
        }
        updates.append(FileUpdate(url: paths.runtimeConfig, original: originalRuntime, updated: updatedRuntime))

        let changedUpdates = updates.filter(\.hasChanges)
        let backupDirectory = changedUpdates.isEmpty
            ? appData.backups
            : try createBackup(sources: changedUpdates.map(\.url), appData: appData)

        do {
            for update in changedUpdates {
                try atomicWrite(update.updated, to: update.url)
            }
            try validate(runtimeConfig: paths.runtimeConfig, paths: paths)

            let runtimeChanged = changedUpdates.contains { $0.url == paths.runtimeConfig }
            let reloaded = runtimeChanged && fileManager.fileExists(atPath: paths.mihomoSocket.path)
            if reloaded {
                try reload(runtimeConfig: paths.runtimeConfig, socket: paths.mihomoSocket)
            }

            return UpdateOutcome(
                interface: detected,
                backupDirectory: backupDirectory.path,
                runtimeReloaded: reloaded,
                changedFileCount: changedUpdates.count
            )
        } catch {
            for update in changedUpdates {
                try? atomicWrite(update.original, to: update.url)
            }
            let runtimeChanged = changedUpdates.contains { $0.url == paths.runtimeConfig }
            if runtimeChanged, fileManager.fileExists(atPath: paths.mihomoSocket.path) {
                try? reload(runtimeConfig: paths.runtimeConfig, socket: paths.mihomoSocket)
            }
            throw error
        }
    }

    private func createBackup(sources: [URL], appData: AppDataPaths) throws -> URL {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyyMMdd-HHmmss-SSS"
        let directory = appData.backups.appendingPathComponent(formatter.string(from: Date()))
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
        try? fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)

        for source in sources {
            let destination = directory.appendingPathComponent(source.lastPathComponent)
            try fileManager.copyItem(at: source, to: destination)
            try? fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: destination.path)
        }
        return directory
    }

    private func atomicWrite(_ text: String, to url: URL) throws {
        let permissions = (try? fileManager.attributesOfItem(atPath: url.path)[.posixPermissions]) as? NSNumber
        try Data(text.utf8).write(to: url, options: .atomic)
        if let permissions {
            try? fileManager.setAttributes([.posixPermissions: permissions], ofItemAtPath: url.path)
        }
    }

    private func validate(runtimeConfig: URL, paths: BridgePaths) throws {
        let result = try Shell.run(paths.mihomoCore.path, [
            "-t",
            "-d", paths.clashHome.path,
            "-f", runtimeConfig.path,
        ])
        guard result.exitCode == 0 else {
            let detail = concise(result.standardError.isEmpty ? result.standardOutput : result.standardError)
            throw BridgeError.validationFailed(detail)
        }
    }

    private func reload(runtimeConfig: URL, socket: URL) throws {
        let config = try String(contentsOf: runtimeConfig, encoding: .utf8)
        let secret = yamlScalar(named: "secret", in: config) ?? ""
        let payload = try JSONSerialization.data(withJSONObject: ["path": runtimeConfig.path])
        let payloadString = String(decoding: payload, as: UTF8.self)
        var arguments = [
            "--silent", "--show-error",
            "--unix-socket", socket.path,
            "-H", "Content-Type: application/json",
        ]
        var standardInput: Data?
        if !secret.isEmpty {
            arguments += ["-H", "@-"]
            standardInput = Data("Authorization: Bearer \(secret)\n".utf8)
        }
        arguments += [
            "-X", "PUT",
            "--data", payloadString,
            "http://localhost/configs?force=true",
            "-o", "/dev/null",
            "-w", "%{http_code}",
        ]

        let result = try Shell.run("/usr/bin/curl", arguments, standardInput: standardInput)
        guard result.exitCode == 0,
              result.standardOutput.trimmingCharacters(in: .whitespacesAndNewlines) == "204"
        else {
            let detail = concise(result.standardError.isEmpty ? result.standardOutput : result.standardError)
            throw BridgeError.reloadFailed(detail)
        }
    }

    private func yamlScalar(named name: String, in source: String) -> String? {
        for line in source.components(separatedBy: .newlines) {
            guard line.hasPrefix("\(name):") else { continue }
            let value = String(line.dropFirst(name.count + 1)).trimmingCharacters(in: .whitespaces)
            if value.count >= 2,
               (value.first == "'" && value.last == "'" || value.first == "\"" && value.last == "\"")
            {
                return String(value.dropFirst().dropLast())
            }
            return value
        }
        return nil
    }

    private func concise(_ text: String) -> String {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.count <= 500 { return trimmed }
        return String(trimmed.prefix(500)) + "..."
    }
}

private struct FileUpdate {
    let url: URL
    let original: String
    let updated: String

    var hasChanges: Bool { original != updated }
}
