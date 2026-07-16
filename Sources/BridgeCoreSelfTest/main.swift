import BridgeCore
import Foundation

private enum SelfTestError: Error {
    case failed(String)
}

private func expect(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    guard condition() else { throw SelfTestError.failed(message) }
}

private let exampleDNS = ["192.0.2.53", "198.51.100.53"]
private let exampleDomains = ["corp.example.com", "internal.example"]

do {
    let route = """
       route to: 192.0.2.53
    destination: 192.0.2.53
      interface: utun5
    """
    try expect(InterfaceDetector.parseInterface(fromRouteOutput: route) == "utun5", "route parser")

    let ifconfig = """
    utun5: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500
        inet 192.0.2.10 --> 192.0.2.10 netmask 0xffffffff
    """
    try expect(
        InterfaceDetector.parseIPAddresses(fromIfconfigOutput: ifconfig) == ["192.0.2.10"],
        "ifconfig parser"
    )
    try expect(!InterfaceDetector.isClashInterface(addresses: ["192.0.2.10"]), "VPN identification")
    try expect(InterfaceDetector.isClashInterface(addresses: ["198.18.0.1"]), "Clash rejection")

    let script = """
    function main(config, profileName) {
      return config;
    }
    """
    let firstScript = try ConfigTransformer.updateGlobalScript(
        script,
        interface: "utun5",
        internalDomains: exampleDomains
    )
    let secondScript = try ConfigTransformer.updateGlobalScript(
        firstScript,
        interface: "utun7",
        internalDomains: exampleDomains
    )
    try expect(
        secondScript.components(separatedBy: "UNIVPN_CLASH_BRIDGE_BEGIN").count == 2,
        "script marker idempotence"
    )
    try expect(secondScript.contains("const __univpnBridgeInterface = \"utun7\";"), "script interface update")
    try expect(!secondScript.contains("const __univpnBridgeInterface = \"utun5\";"), "stale script interface")
    try expect(secondScript.contains("corp.example.com"), "configured domain injection")

    let interfaceOnlyScript = try ConfigTransformer.updateGlobalScript(
        script,
        interface: "utun9",
        internalDomains: []
    )
    try expect(interfaceOnlyScript.contains("const __univpnBridgeDomains = [];"), "empty domain declaration")
    try expect(
        interfaceOnlyScript.contains("if (__univpnBridgeDomains.length > 0)"),
        "optional rule management guard"
    )

    let dns = """
    dns:
      nameserver:
      - 192.0.2.53
      - 203.0.113.53
      nameserver-policy:
        +.corp.example.com:
        - 192.0.2.53
        +.public.example:
        - 203.0.113.53
      prefer-h3: true
    """
    let updatedDNS = try ConfigTransformer.updateDNSConfig(
        dns,
        dnsServers: exampleDNS,
        internalDomains: exampleDomains
    )
    try expect(!updatedDNS.contains("\n  - 192.0.2.53"), "general VPN DNS removal")
    try expect(updatedDNS.contains("'udp://192.0.2.53#UNIVPN-DIRECT'"), "policy proxy reference")
    try expect(updatedDNS.contains("+.public.example:"), "unmanaged policy preservation")
    try expect(updatedDNS.contains("- 203.0.113.53"), "unmanaged policy value preservation")
    let untouchedDNS = try ConfigTransformer.updateDNSConfig(
        dns,
        dnsServers: exampleDNS,
        internalDomains: []
    )
    try expect(untouchedDNS == dns, "interface-only DNS preservation")

    let runtime = """
    dns:
      nameserver:
      - 203.0.113.53
      nameserver-policy:
        +.corp.example.com:
        - 192.0.2.53
    proxies:
    - name: node
      type: socks5
      server: 203.0.113.1
      port: 1080
    proxy-groups: []
    rules:
    - DOMAIN-SUFFIX,corp.example.com,DIRECT
    - MATCH,node
    """
    let firstRuntime = try ConfigTransformer.updateRuntimeConfig(
        runtime,
        interface: "utun5",
        dnsServers: exampleDNS,
        internalDomains: exampleDomains
    )
    let secondRuntime = try ConfigTransformer.updateRuntimeConfig(
        firstRuntime,
        interface: "utun8",
        dnsServers: exampleDNS,
        internalDomains: exampleDomains
    )
    try expect(
        secondRuntime.components(separatedBy: "name: UNIVPN-DIRECT").count == 2,
        "runtime proxy idempotence"
    )
    try expect(secondRuntime.contains("interface-name: utun8"), "runtime interface update")
    try expect(!secondRuntime.contains("interface-name: utun5"), "stale runtime interface")
    try expect(
        secondRuntime.components(separatedBy: "DOMAIN-SUFFIX,corp.example.com,UNIVPN-DIRECT").count == 2,
        "runtime rule idempotence"
    )
    try expect(secondRuntime.contains("- MATCH,node"), "unmanaged rule preservation")

    let interfaceOnlyRuntime = try ConfigTransformer.updateRuntimeConfig(
        runtime,
        interface: "utun9",
        dnsServers: exampleDNS,
        internalDomains: []
    )
    try expect(interfaceOnlyRuntime.contains("interface-name: utun9"), "interface-only direct proxy")
    try expect(
        interfaceOnlyRuntime.contains("- DOMAIN-SUFFIX,corp.example.com,DIRECT"),
        "interface-only rule preservation"
    )
    try expect(!interfaceOnlyRuntime.contains("udp://"), "interface-only DNS preservation")

    let normalized = try AppConfiguration(
        dnsServers: exampleDNS,
        internalDomains: ["+.corp.example.com", "CORP.EXAMPLE.COM", "*.internal.example"],
        clashConfigDirectory: "/private/tmp",
        dnsGuardEnabled: true
    ).normalized()
    try expect(normalized.internalDomains == exampleDomains, "configuration normalization")
    let interfaceOnlyConfiguration = try AppConfiguration(
        dnsServers: exampleDNS,
        internalDomains: ["", "  "],
        clashConfigDirectory: "/private/tmp",
        dnsGuardEnabled: true
    ).normalized()
    try expect(interfaceOnlyConfiguration.internalDomains.isEmpty, "optional domain configuration")

    if CommandLine.arguments.count == 6, CommandLine.arguments[1] == "--transform-real" {
        let sourceDirectory = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true)
        let interface = CommandLine.arguments[3]
        let configurationURL = URL(fileURLWithPath: CommandLine.arguments[4])
        let outputDirectory = URL(fileURLWithPath: CommandLine.arguments[5], isDirectory: true)
        let privateConfiguration = try JSONDecoder().decode(
            AppConfiguration.self,
            from: Data(contentsOf: configurationURL)
        ).normalized()
        try FileManager.default.createDirectory(at: outputDirectory, withIntermediateDirectories: true)

        let globalScript = try String(
            contentsOf: sourceDirectory.appendingPathComponent("profiles/Script.js"),
            encoding: .utf8
        )
        let dnsConfig = try String(
            contentsOf: sourceDirectory.appendingPathComponent("dns_config.yaml"),
            encoding: .utf8
        )
        let runtimeConfig = try String(
            contentsOf: sourceDirectory.appendingPathComponent("clash-verge.yaml"),
            encoding: .utf8
        )

        try ConfigTransformer.updateGlobalScript(
            globalScript,
            interface: interface,
            internalDomains: privateConfiguration.internalDomains
        ).write(to: outputDirectory.appendingPathComponent("Script.js"), atomically: true, encoding: .utf8)
        try ConfigTransformer.updateDNSConfig(
            dnsConfig,
            dnsServers: privateConfiguration.dnsServers,
            internalDomains: privateConfiguration.internalDomains
        ).write(to: outputDirectory.appendingPathComponent("dns_config.yaml"), atomically: true, encoding: .utf8)
        try ConfigTransformer.updateRuntimeConfig(
            runtimeConfig,
            interface: interface,
            dnsServers: privateConfiguration.dnsServers,
            internalDomains: privateConfiguration.internalDomains
        ).write(to: outputDirectory.appendingPathComponent("clash-verge.yaml"), atomically: true, encoding: .utf8)
        print("Private integration output written outside the repository")
    }

    print("BridgeCore self-test passed")
} catch {
    FileHandle.standardError.write(Data("BridgeCore self-test failed: \(error)\n".utf8))
    exit(1)
}
