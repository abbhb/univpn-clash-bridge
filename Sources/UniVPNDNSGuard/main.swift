import CoreFoundation
import Foundation
import SystemConfiguration

private struct GuardConfiguration: Codable {
    let enabled: Bool
    let serviceID: String?
    let serverAddresses: [String]
    let rootMatchOnly: Bool?

    var requiresRootMatch: Bool { rootMatchOnly ?? true }

    static func load(from path: String) throws -> GuardConfiguration {
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        return try JSONDecoder().decode(GuardConfiguration.self, from: data)
    }
}

private enum RunMode {
    case watch
    case once
    case inspect
    case selfTest
}

private final class DNSGuard {
    private let configuration: GuardConfiguration
    private let pattern = "State:/Network/Service/.*/DNS"
    private var store: SCDynamicStore?

    init(configuration: GuardConfiguration) {
        self.configuration = configuration
    }

    func runOnce(inspectOnly: Bool) -> Int {
        guard validateConfiguration() else { return 2 }
        guard let store = makeStore(callback: nil, context: nil) else {
            log("cannot open the SystemConfiguration dynamic store")
            return 3
        }
        self.store = store
        let result = processAll(inspectOnly: inspectOnly)
        if !inspectOnly, result.matched > 0, result.removed == 0, result.failed > 0 {
            return 4
        }
        return 0
    }

    func watch() -> Never {
        guard validateConfiguration() else { exit(2) }

        let callback: SCDynamicStoreCallBack = { _, changedKeys, info in
            guard let info else { return }
            let guardInstance = Unmanaged<DNSGuard>.fromOpaque(info).takeUnretainedValue()
            let keys = changedKeys as NSArray as? [String] ?? []
            guardInstance.process(keys: keys, inspectOnly: false)
        }
        var context = SCDynamicStoreContext(
            version: 0,
            info: Unmanaged.passUnretained(self).toOpaque(),
            retain: nil,
            release: nil,
            copyDescription: nil
        )
        guard let store = makeStore(callback: callback, context: &context) else {
            log("cannot open the SystemConfiguration dynamic store")
            exit(3)
        }
        self.store = store

        guard SCDynamicStoreSetNotificationKeys(store, nil, [pattern] as CFArray),
              let source = SCDynamicStoreCreateRunLoopSource(nil, store, 0)
        else {
            log("cannot subscribe to DNS dynamic-store changes")
            exit(3)
        }

        let result = processAll(inspectOnly: false)
        log("watching DNS state; matched=\(result.matched) removed=\(result.removed) failed=\(result.failed)")
        CFRunLoopAddSource(CFRunLoopGetCurrent(), source, .defaultMode)
        CFRunLoopRun()
        fatalError("CFRunLoopRun unexpectedly returned")
    }

    fileprivate func isTarget(key: String, value: [String: Any]) -> Bool {
        let configuredServiceID = configuration.serviceID ?? ""
        let serviceMatches = !configuredServiceID.isEmpty && key.contains("/\(configuredServiceID)/")

        let interfaceName = value["InterfaceName"] as? String ?? ""
        let isTunnelResolver = interfaceName.hasPrefix("utun")
        let currentServers = Set(stringArray(value["ServerAddresses"]))
        let configuredServers = Set(configuration.serverAddresses)
        let serverMatches = !currentServers.isDisjoint(with: configuredServers)
        let matchDomains = stringArray(value["SupplementalMatchDomains"])
        let capturesRoot = matchDomains.contains("") || matchDomains.contains(".")

        let identityMatches = serviceMatches || (isTunnelResolver && serverMatches)
        return identityMatches && (!configuration.requiresRootMatch || capturesRoot)
    }

    private func validateConfiguration() -> Bool {
        guard configuration.enabled else {
            log("disabled by configuration")
            return false
        }
        guard !configuration.serverAddresses.isEmpty || !(configuration.serviceID ?? "").isEmpty else {
            log("configuration must contain a serviceID or serverAddresses")
            return false
        }
        return true
    }

    private func makeStore(
        callback: SCDynamicStoreCallBack?,
        context: UnsafeMutablePointer<SCDynamicStoreContext>?
    ) -> SCDynamicStore? {
        SCDynamicStoreCreate(nil, "UniVPNClashBridgeDNSGuard" as CFString, callback, context)
    }

    @discardableResult
    private func processAll(inspectOnly: Bool) -> (matched: Int, removed: Int, failed: Int) {
        guard let store,
              let values = SCDynamicStoreCopyMultiple(store, nil, [pattern] as CFArray) as? [String: Any]
        else {
            log("cannot enumerate DNS dynamic-store keys")
            return (0, 0, 1)
        }
        return process(keys: values.keys.sorted(), inspectOnly: inspectOnly)
    }

    @discardableResult
    private func process(keys: [String], inspectOnly: Bool) -> (matched: Int, removed: Int, failed: Int) {
        guard let store else { return (0, 0, 1) }
        var matched = 0
        var removed = 0
        var failed = 0

        for key in keys.sorted() {
            guard let value = SCDynamicStoreCopyValue(store, key as CFString) as? [String: Any],
                  isTarget(key: key, value: value)
            else {
                continue
            }
            matched += 1

            let interfaceName = value["InterfaceName"] as? String ?? ""
            if inspectOnly {
                let serverCount = stringArray(value["ServerAddresses"]).count
                log("candidate interface=\(interfaceName) serverCount=\(serverCount)")
                continue
            }

            if SCDynamicStoreRemoveValue(store, key as CFString) {
                removed += 1
                log("removed matching root DNS state interface=\(interfaceName)")
            } else {
                failed += 1
                log("failed to remove matching root DNS state: \(lastSCError())")
            }
        }
        return (matched, removed, failed)
    }

    private func stringArray(_ value: Any?) -> [String] {
        if let strings = value as? [String] { return strings }
        if let array = value as? NSArray { return array.compactMap { $0 as? String } }
        return []
    }
}

private func log(_ message: String) {
    let timestamp = ISO8601DateFormatter().string(from: Date())
    FileHandle.standardError.write(Data("\(timestamp) \(message)\n".utf8))
}

private func lastSCError() -> String {
    let code = SCError()
    return "\(String(cString: SCErrorString(code))) (\(code))"
}

private func usage() -> Never {
    let text = """
    Usage: univpn-dns-guard [--watch|--once|--inspect|--self-test] [--config PATH]
    """
    FileHandle.standardError.write(Data((text + "\n").utf8))
    exit(64)
}

private func parseArguments() -> (mode: RunMode, configPath: String) {
    var mode: RunMode = .watch
    var configPath = "/Library/Application Support/UniVPN Clash Bridge/dns-guard.json"
    var index = 1
    while index < CommandLine.arguments.count {
        switch CommandLine.arguments[index] {
        case "--watch": mode = .watch
        case "--once": mode = .once
        case "--inspect": mode = .inspect
        case "--self-test": mode = .selfTest
        case "--config":
            index += 1
            guard index < CommandLine.arguments.count else { usage() }
            configPath = CommandLine.arguments[index]
        case "--help", "-h": usage()
        default: usage()
        }
        index += 1
    }
    return (mode, configPath)
}

private func runSelfTest() -> Int {
    let configuration = GuardConfiguration(
        enabled: true,
        serviceID: nil,
        serverAddresses: ["192.0.2.53"],
        rootMatchOnly: true
    )
    let guardInstance = DNSGuard(configuration: configuration)
    let rootResolver: [String: Any] = [
        "InterfaceName": "utun5",
        "ServerAddresses": ["192.0.2.53"],
        "SupplementalMatchDomains": [""],
    ]
    let splitResolver: [String: Any] = [
        "InterfaceName": "utun5",
        "ServerAddresses": ["192.0.2.53"],
        "SupplementalMatchDomains": ["corp.example.com"],
    ]
    guard guardInstance.isTarget(key: "State:/Network/Service/EXAMPLE/DNS", value: rootResolver),
          !guardInstance.isTarget(key: "State:/Network/Service/EXAMPLE/DNS", value: splitResolver)
    else {
        log("self-test failed")
        return 1
    }
    log("self-test passed")
    return 0
}

private let arguments = parseArguments()
if arguments.mode == .selfTest {
    exit(Int32(runSelfTest()))
}

do {
    let configuration = try GuardConfiguration.load(from: arguments.configPath)
    let guardInstance = DNSGuard(configuration: configuration)
    switch arguments.mode {
    case .watch:
        guardInstance.watch()
    case .once:
        exit(Int32(guardInstance.runOnce(inspectOnly: false)))
    case .inspect:
        exit(Int32(guardInstance.runOnce(inspectOnly: true)))
    case .selfTest:
        fatalError("handled above")
    }
} catch {
    log("cannot load configuration: \(error.localizedDescription)")
    exit(2)
}
