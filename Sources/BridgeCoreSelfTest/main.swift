import BridgeCore
import Foundation
import JavaScriptCore

private enum SelfTestError: Error {
    case failed(String)
}

private func expect(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    guard condition() else { throw SelfTestError.failed(message) }
}

private let exampleDNS = ["192.0.2.53", "198.51.100.53"]
private let internalDNSDomains = ["corp.example.com", "internal.example"]
private let vpnRouteDomains = ["vpn-only.example"]

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
    let clashCandidate = InterfaceDetection(
        name: "utun0",
        addresses: ["198.18.0.1"],
        routeTarget: "192.0.2.53"
    )
    let vpnCandidate = InterfaceDetection(
        name: "utun5",
        addresses: ["192.0.2.10"],
        routeTarget: "198.51.100.53"
    )
    try expect(
        InterfaceDetector.firstUsableVPN(in: [clashCandidate, vpnCandidate]) == vpnCandidate,
        "later real VPN wins over an earlier Clash route"
    )
    try expect(
        InterfaceDetector.isExpectedRouteMiss(
            exitCode: 77,
            standardOutput: "",
            standardError: "route: writing to routing socket: not in table"
        ),
        "an explicit route miss can enter DIRECT mode"
    )
    try expect(
        !InterfaceDetector.isExpectedRouteMiss(
            exitCode: 1,
            standardOutput: "",
            standardError: "route: socket: Operation not permitted"
        ),
        "route permission failures are not treated as DIRECT mode"
    )

    let script = """
    function main(config, profileName) {
      return config;
    }
    """
    let scriptWithDomains = """
    const internalDomains = [
      "corp.example.com",
      "*.internal.example",
    ];

    function main(config, profileName) {
      const oldRules = Array.isArray(config.rules) ? config.rules : [];
      const directRules = internalDomains.map(function(domain) {
        return "DOMAIN-SUFFIX," + domain + ",DIRECT";
      });
      config.rules = directRules.concat(oldRules);
      return config;
    }
    """
    let discoveredInternalDomains = try ConfigTransformer.discoverInternalDomains(in: scriptWithDomains)
    try expect(discoveredInternalDomains == internalDNSDomains, "script DNS domain discovery")
    let absentInternalDomains = try ConfigTransformer.discoverInternalDomains(in: script)
    try expect(absentInternalDomains.isEmpty, "missing script DNS domains are optional")
    let singleQuotedDomains = try ConfigTransformer.discoverInternalDomains(
        in: "const internalDomains = ['single.example', '*.second.example'];\n" + script
    )
    try expect(
        singleQuotedDomains == ["single.example", "second.example"],
        "single-quoted script DNS domains are supported"
    )
    var rejectedMalformedDomainDeclaration = false
    do {
        _ = try ConfigTransformer.discoverInternalDomains(
            in: "const internalDomains = loadDomains();\n" + script
        )
    } catch {
        rejectedMalformedDomainDeclaration = true
    }
    try expect(
        rejectedMalformedDomainDeclaration,
        "a malformed internalDomains declaration is not treated as an empty list"
    )
    let legacyManagedScript = """
    // UNIVPN_CLASH_BRIDGE_BEGIN
    const __univpnBridgeDomains = ["cwoa.net", "*.internal.example"];
    // UNIVPN_CLASH_BRIDGE_END
    """
    let discoveredLegacyRoutes = try ConfigTransformer.discoverLegacyVPNRouteDomains(in: legacyManagedScript)
    try expect(
        discoveredLegacyRoutes == ["cwoa.net", "internal.example"],
        "legacy bridge route discovery"
    )
    let unrelatedLegacyName = "const __univpnBridgeDomains = [\"user.example\"];\n" + script
    let unrelatedLegacyRoutes = try ConfigTransformer.discoverLegacyVPNRouteDomains(in: unrelatedLegacyName)
    try expect(
        unrelatedLegacyRoutes.isEmpty,
        "legacy ownership is read only from the managed script block"
    )

    let firstScript = try ConfigTransformer.updateGlobalScript(
        scriptWithDomains,
        interface: "utun5",
        vpnRouteDomains: vpnRouteDomains
    )
    let secondScript = try ConfigTransformer.updateGlobalScript(
        firstScript,
        interface: "utun7",
        vpnRouteDomains: vpnRouteDomains
    )
    try expect(
        secondScript.components(separatedBy: "UNIVPN_CLASH_BRIDGE_BEGIN").count == 2,
        "script marker idempotence"
    )
    try expect(secondScript.contains("const __univpnBridgeInterface = \"utun7\";"), "script interface update")
    try expect(!secondScript.contains("const __univpnBridgeInterface = \"utun5\";"), "stale script interface")
    try expect(
        secondScript.contains("const __univpnBridgeRouteDomains = [\"vpn-only.example\"]"),
        "route-only domain injection"
    )
    let discoveredManagedRoutes = try ConfigTransformer.discoverManagedVPNRouteDomains(in: secondScript)
    try expect(discoveredManagedRoutes == vpnRouteDomains, "current bridge route ownership discovery")
    try expect(secondScript.contains("DOMAIN-SUFFIX," + "\" + domain + \"" + ",DIRECT"), "original DIRECT logic preserved")
    try expect(
        secondScript.contains("managedRules.indexOf(rule) === -1"),
        "script removes only exact bridge-owned route rules"
    )

    let noRouteScript = try ConfigTransformer.updateGlobalScript(
        scriptWithDomains,
        interface: "utun9",
        vpnRouteDomains: []
    )
    try expect(
        noRouteScript.contains("const __univpnBridgeRouteDomains = [];"),
        "empty route configuration stays empty"
    )
    try expect(noRouteScript.contains("internalDomains.map"), "script DNS domains do not become VPN routes")
    let restoredScript = try ConfigTransformer.restoreGlobalScript(secondScript)
    try expect(!restoredScript.contains("UNIVPN_CLASH_BRIDGE_BEGIN"), "DIRECT mode removes script bridge block")
    try expect(restoredScript.contains("internalDomains.map"), "DIRECT mode preserves original script")
    let restoredScriptAgain = try ConfigTransformer.restoreGlobalScript(restoredScript)
    try expect(
        restoredScriptAgain == restoredScript,
        "script restore is idempotent"
    )
    var rejectedIncompleteScriptMarker = false
    do {
        _ = try ConfigTransformer.restoreGlobalScript(script + "\n// UNIVPN_CLASH_BRIDGE_BEGIN\n")
    } catch {
        rejectedIncompleteScriptMarker = true
    }
    try expect(rejectedIncompleteScriptMarker, "incomplete script marker is rejected")

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
        +.stale.example:
        - 'udp://192.0.2.53#UNIVPN-DIRECT'
      prefer-h3: true
    """
    let updatedDNS = try ConfigTransformer.updateDNSConfig(
        dns,
        dnsServers: exampleDNS,
        internalDNSDomains: internalDNSDomains
    )
    try expect(!updatedDNS.contains("\n  - 192.0.2.53"), "general VPN DNS removal")
    try expect(updatedDNS.contains("+.corp.example.com:"), "script DNS policy domain")
    try expect(updatedDNS.contains("'udp://192.0.2.53#UNIVPN-DIRECT'"), "DNS policy proxy binding")
    try expect(updatedDNS.contains("+.public.example:"), "unmanaged DNS policy preservation")
    try expect(updatedDNS.contains("- 203.0.113.53"), "unmanaged DNS policy value preservation")
    try expect(updatedDNS.contains("+.stale.example:"), "unowned VPN-bound DNS policy preservation")

    let restoredDNS = try ConfigTransformer.restoreDNSConfig(
        updatedDNS,
        dnsServers: exampleDNS,
        internalDNSDomains: internalDNSDomains
    )
    try expect(
        restoredDNS.contains("+.stale.example:")
            && restoredDNS.contains("'udp://192.0.2.53#UNIVPN-DIRECT'"),
        "DIRECT mode preserves unowned VPN-bound DNS policy"
    )
    try expect(restoredDNS.contains("'udp://192.0.2.53#DIRECT'"), "DIRECT mode binds internal DNS directly")
    try expect(restoredDNS.contains("UNIVPN_CLASH_BRIDGE_DNS_BEGIN"), "DIRECT DNS policy stays identifiable")
    try expect(restoredDNS.contains("+.public.example:"), "DIRECT mode preserves unmanaged DNS policy")
    try expect(!restoredDNS.contains("\n  - 192.0.2.53"), "DIRECT mode keeps VPN DNS out of general pool")
    let reactivatedDNS = try ConfigTransformer.updateDNSConfig(
        restoredDNS,
        dnsServers: exampleDNS,
        internalDNSDomains: internalDNSDomains
    )
    try expect(
        reactivatedDNS.contains("'udp://192.0.2.53#UNIVPN-DIRECT'")
            && !reactivatedDNS.contains("'udp://192.0.2.53#DIRECT'"),
        "VPN mode replaces DIRECT DNS binding"
    )
    let reducedDirectDNS = try ConfigTransformer.restoreDNSConfig(
        restoredDNS,
        dnsServers: exampleDNS,
        internalDNSDomains: ["internal.example"]
    )
    try expect(!reducedDirectDNS.contains("+.corp.example.com:"), "DIRECT mode removes stale managed domains")
    try expect(
        reducedDirectDNS.components(separatedBy: "UNIVPN_CLASH_BRIDGE_DNS_BEGIN").count == 2,
        "DIRECT DNS marker is idempotent"
    )
    var rejectedIncompleteDNSMarker = false
    do {
        _ = try ConfigTransformer.restoreDNSConfig(
            dns + "\n    # UNIVPN_CLASH_BRIDGE_DNS_BEGIN\n",
            dnsServers: exampleDNS,
            internalDNSDomains: internalDNSDomains
        )
    } catch {
        rejectedIncompleteDNSMarker = true
    }
    try expect(rejectedIncompleteDNSMarker, "incomplete DNS marker is rejected")

    let clearedDNS = try ConfigTransformer.updateDNSConfig(
        updatedDNS,
        dnsServers: exampleDNS,
        internalDNSDomains: []
    )
    try expect(!clearedDNS.contains("+.corp.example.com:"), "managed DNS policy cleanup when script list is empty")
    try expect(clearedDNS.contains("+.stale.example:"), "unowned DNS policy survives empty script list")
    try expect(clearedDNS.contains("+.public.example:"), "unmanaged DNS policy survives cleanup")
    try expect(!clearedDNS.contains("\n  - 192.0.2.53"), "VPN DNS cleanup without script domains")

    let runtime = """
    dns:
      nameserver:
      - 192.0.2.53
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
    - DOMAIN-SUFFIX,old-vpn.example,UNIVPN-DIRECT
    - DOMAIN-SUFFIX,corp.example.com,DIRECT
    - MATCH,node
    """
    let firstRuntime = try ConfigTransformer.updateRuntimeConfig(
        runtime,
        interface: "utun5",
        dnsServers: exampleDNS,
        internalDNSDomains: internalDNSDomains,
        vpnRouteDomains: vpnRouteDomains
    )
    try expect(firstRuntime.contains("interface-name: utun5"), "runtime direct proxy")
    try expect(
        firstRuntime.contains("DOMAIN-SUFFIX,vpn-only.example,UNIVPN-DIRECT"),
        "App route domain becomes a VPN rule"
    )
    try expect(
        firstRuntime.contains("DOMAIN-SUFFIX,corp.example.com,DIRECT"),
        "script DNS domain does not overwrite original DIRECT rule"
    )
    try expect(firstRuntime.contains("old-vpn.example"), "unowned VPN route preservation")
    try expect(
        firstRuntime.contains("UNIVPN_CLASH_BRIDGE_RULES_BEGIN"),
        "managed VPN routes carry ownership markers"
    )
    try expect(firstRuntime.contains("+.internal.example:"), "runtime receives script DNS policy")
    let managedRouteRange = try firstRuntime.range(of: "DOMAIN-SUFFIX,vpn-only.example,UNIVPN-DIRECT")
        .unwrap(or: SelfTestError.failed("managed route missing"))
    let directRouteRange = try firstRuntime.range(of: "DOMAIN-SUFFIX,corp.example.com,DIRECT")
        .unwrap(or: SelfTestError.failed("direct route missing"))
    try expect(managedRouteRange.lowerBound < directRouteRange.lowerBound, "managed VPN routes are prepended")

    let explicitlyOwnedRuntime = try ConfigTransformer.updateRuntimeConfig(
        runtime,
        interface: "utun5",
        dnsServers: exampleDNS,
        internalDNSDomains: internalDNSDomains,
        vpnRouteDomains: [],
        previousVPNRouteDomains: ["old-vpn.example"]
    )
    try expect(
        !explicitlyOwnedRuntime.contains("DOMAIN-SUFFIX,old-vpn.example,UNIVPN-DIRECT"),
        "an unmarked route is removed only with prior ownership evidence"
    )

    let extendedRuleRuntime = runtime.replacingOccurrences(
        of: "- DOMAIN-SUFFIX,old-vpn.example,UNIVPN-DIRECT",
        with: "- DOMAIN-SUFFIX,old-vpn.example,UNIVPN-DIRECT,no-resolve"
    )
    let preservedExtendedRuleRuntime = try ConfigTransformer.updateRuntimeConfig(
        extendedRuleRuntime,
        interface: "utun5",
        dnsServers: exampleDNS,
        internalDNSDomains: internalDNSDomains,
        vpnRouteDomains: [],
        previousVPNRouteDomains: ["old-vpn.example"]
    )
    try expect(
        preservedExtendedRuleRuntime.contains(
            "DOMAIN-SUFFIX,old-vpn.example,UNIVPN-DIRECT,no-resolve"
        ),
        "extended user rules are not claimed as legacy bridge output"
    )

    let secondRuntime = try ConfigTransformer.updateRuntimeConfig(
        firstRuntime,
        interface: "utun8",
        dnsServers: exampleDNS,
        internalDNSDomains: internalDNSDomains,
        vpnRouteDomains: vpnRouteDomains
    )
    try expect(
        secondRuntime.components(separatedBy: "name: UNIVPN-DIRECT").count == 2,
        "runtime proxy idempotence"
    )
    try expect(secondRuntime.contains("interface-name: utun8"), "runtime interface update")
    try expect(!secondRuntime.contains("interface-name: utun5"), "stale runtime interface")
    try expect(
        secondRuntime.components(separatedBy: "DOMAIN-SUFFIX,vpn-only.example,UNIVPN-DIRECT").count == 2,
        "runtime route idempotence"
    )
    try expect(secondRuntime.contains("- MATCH,node"), "unmanaged rule preservation")

    let noRouteRuntime = try ConfigTransformer.updateRuntimeConfig(
        secondRuntime,
        interface: "utun9",
        dnsServers: exampleDNS,
        internalDNSDomains: internalDNSDomains,
        vpnRouteDomains: []
    )
    try expect(!noRouteRuntime.contains("vpn-only.example"), "route removal when App list becomes empty")
    try expect(
        noRouteRuntime.contains("DOMAIN-SUFFIX,corp.example.com,DIRECT"),
        "DIRECT fallback remains after VPN route cleanup"
    )
    try expect(noRouteRuntime.contains("#UNIVPN-DIRECT"), "DNS policy remains independent of route list")

    let restoredRuntime = try ConfigTransformer.restoreRuntimeConfig(
        secondRuntime,
        dnsServers: exampleDNS,
        internalDNSDomains: internalDNSDomains
    )
    try expect(restoredRuntime.contains("name: UNIVPN-DIRECT"), "DIRECT runtime retains a safe direct proxy")
    try expect(!restoredRuntime.contains("interface-name:"), "DIRECT runtime removes the VPN interface binding")
    try expect(
        !restoredRuntime.contains("DOMAIN-SUFFIX,vpn-only.example,UNIVPN-DIRECT"),
        "DIRECT runtime removes only marker-owned VPN routes"
    )
    try expect(
        restoredRuntime.contains("DOMAIN-SUFFIX,old-vpn.example,UNIVPN-DIRECT"),
        "DIRECT runtime preserves unowned routes that use the safe direct proxy"
    )
    let restoredRuntimeAgain = try ConfigTransformer.restoreRuntimeConfig(
        restoredRuntime,
        dnsServers: exampleDNS,
        internalDNSDomains: internalDNSDomains
    )
    try expect(restoredRuntimeAgain == restoredRuntime, "DIRECT runtime restore is idempotent")
    try expect(restoredRuntime.contains("name: node"), "DIRECT runtime preserves unmanaged proxies")
    try expect(
        restoredRuntime.contains("DOMAIN-SUFFIX,corp.example.com,DIRECT"),
        "DIRECT runtime preserves original routes"
    )
    try expect(restoredRuntime.contains("'udp://192.0.2.53#DIRECT'"), "DIRECT runtime restores DNS outbound")
    let reactivatedRuntime = try ConfigTransformer.updateRuntimeConfig(
        restoredRuntime,
        interface: "utun11",
        dnsServers: exampleDNS,
        internalDNSDomains: internalDNSDomains,
        vpnRouteDomains: vpnRouteDomains
    )
    try expect(reactivatedRuntime.contains("interface-name: utun11"), "VPN runtime can reactivate after restore")
    try expect(
        reactivatedRuntime.contains("DOMAIN-SUFFIX,vpn-only.example,UNIVPN-DIRECT"),
        "VPN route returns after reactivation"
    )
    try expect(
        reactivatedRuntime.contains("'udp://192.0.2.53#UNIVPN-DIRECT'"),
        "VPN DNS binding returns after reactivation"
    )

    let customReferenceRuntime = secondRuntime.replacingOccurrences(
        of: "- MATCH,node",
        with: "- DOMAIN,custom.example,UNIVPN-DIRECT\n- IP-CIDR,192.0.2.0/24,UNIVPN-DIRECT,no-resolve\n- MATCH,node"
    )
    let directWithCustomReferences = try ConfigTransformer.restoreRuntimeConfig(
        customReferenceRuntime,
        dnsServers: exampleDNS,
        internalDNSDomains: internalDNSDomains
    )
    try expect(
        directWithCustomReferences.contains("DOMAIN,custom.example,UNIVPN-DIRECT")
            && directWithCustomReferences.contains("IP-CIDR,192.0.2.0/24,UNIVPN-DIRECT,no-resolve")
            && directWithCustomReferences.contains("name: UNIVPN-DIRECT")
            && !directWithCustomReferences.contains("interface-name:"),
        "DIRECT mode keeps custom outbound references valid without binding them to VPN"
    )

    var rejectedProxyTypeConflict = false
    do {
        _ = try ConfigTransformer.updateRuntimeConfig(
            runtime.replacingOccurrences(
                of: "- name: node\n  type: socks5",
                with: "- name: UNIVPN-DIRECT\n  type: socks5"
            ),
            interface: "utun5",
            dnsServers: exampleDNS,
            internalDNSDomains: internalDNSDomains,
            vpnRouteDomains: vpnRouteDomains
        )
    } catch {
        rejectedProxyTypeConflict = true
    }
    try expect(rejectedProxyTypeConflict, "a non-direct proxy name collision is rejected")

    var rejectedIncompleteRouteMarker = false
    do {
        _ = try ConfigTransformer.restoreRuntimeConfig(
            secondRuntime + "\n# UNIVPN_CLASH_BRIDGE_RULES_BEGIN\n",
            dnsServers: exampleDNS,
            internalDNSDomains: internalDNSDomains
        )
    } catch {
        rejectedIncompleteRouteMarker = true
    }
    try expect(rejectedIncompleteRouteMarker, "incomplete route ownership markers are rejected")

    let legacyRuntime = """
    dns:
      nameserver:
      - 203.0.113.53
    proxies:
    - name: node
      type: socks5
      server: 203.0.113.1
      port: 1080
    proxy-groups: []
    rules:
    - DOMAIN-SUFFIX,cwoa.net,UNIVPN-DIRECT
    - DOMAIN,secure.cwoa.net,node
    - MATCH,node
    """
    let generatedCheckConfig = """
    rules:
    - DOMAIN,secure.cwoa.net,node
    - DOMAIN-SUFFIX,cwoa.net,DIRECT
    - MATCH,node
    """
    let migratedRuntime = try ConfigTransformer.updateRuntimeConfig(
        legacyRuntime,
        interface: "utun9",
        dnsServers: exampleDNS,
        internalDNSDomains: ["cwoa.net"],
        vpnRouteDomains: [],
        routeRecoverySource: generatedCheckConfig,
        legacyVPNRouteDomains: ["cwoa.net"]
    )
    try expect(
        migratedRuntime.contains("DOMAIN-SUFFIX,cwoa.net,DIRECT"),
        "legacy bridge route restores Clash-generated fallback"
    )
    try expect(
        !migratedRuntime.contains("DOMAIN-SUFFIX,cwoa.net,UNIVPN-DIRECT"),
        "legacy forced VPN route is removed"
    )
    let specificRouteRange = try migratedRuntime.range(of: "DOMAIN,secure.cwoa.net,node")
        .unwrap(or: SelfTestError.failed("specific route missing"))
    let recoveredRouteRange = try migratedRuntime.range(of: "DOMAIN-SUFFIX,cwoa.net,DIRECT")
        .unwrap(or: SelfTestError.failed("recovered route missing"))
    let fallbackRouteRange = try migratedRuntime.range(of: "MATCH,node")
        .unwrap(or: SelfTestError.failed("fallback route missing"))
    try expect(
        specificRouteRange.lowerBound < recoveredRouteRange.lowerBound
            && recoveredRouteRange.lowerBound < fallbackRouteRange.lowerBound,
        "legacy route recovery preserves generated rule priority"
    )
    let migratedAgain = try ConfigTransformer.updateRuntimeConfig(
        migratedRuntime,
        interface: "utun9",
        dnsServers: exampleDNS,
        internalDNSDomains: ["cwoa.net"],
        vpnRouteDomains: [],
        routeRecoverySource: generatedCheckConfig,
        legacyVPNRouteDomains: ["cwoa.net"]
    )
    try expect(
        migratedAgain.components(separatedBy: "DOMAIN-SUFFIX,cwoa.net,DIRECT").count == 2,
        "legacy route recovery is idempotent"
    )
    var rejectedMissingRecoverySource = false
    do {
        _ = try ConfigTransformer.updateRuntimeConfig(
            legacyRuntime,
            interface: "utun9",
            dnsServers: exampleDNS,
            internalDNSDomains: ["cwoa.net"],
            vpnRouteDomains: [],
            legacyVPNRouteDomains: ["cwoa.net"]
        )
    } catch {
        rejectedMissingRecoverySource = true
    }
    try expect(
        rejectedMissingRecoverySource,
        "legacy route cleanup refuses to lose rules without a recovery source"
    )

    let retainedLegacyRoute = try ConfigTransformer.updateRuntimeConfig(
        legacyRuntime,
        interface: "utun9",
        dnsServers: exampleDNS,
        internalDNSDomains: ["cwoa.net"],
        vpnRouteDomains: ["cwoa.net"],
        routeRecoverySource: generatedCheckConfig,
        legacyVPNRouteDomains: ["cwoa.net"]
    )
    let retainedVPNRange = try retainedLegacyRoute.range(
        of: "DOMAIN-SUFFIX,cwoa.net,UNIVPN-DIRECT"
    ).unwrap(or: SelfTestError.failed("retained VPN route missing"))
    let retainedDirectRange = try retainedLegacyRoute.range(
        of: "DOMAIN-SUFFIX,cwoa.net,DIRECT"
    ).unwrap(or: SelfTestError.failed("retained fallback route missing"))
    try expect(
        retainedVPNRange.lowerBound < retainedDirectRange.lowerBound,
        "legacy migration keeps VPN override above the restored fallback"
    )
    let removedRetainedRoute = try ConfigTransformer.updateRuntimeConfig(
        retainedLegacyRoute,
        interface: "utun9",
        dnsServers: exampleDNS,
        internalDNSDomains: ["cwoa.net"],
        vpnRouteDomains: []
    )
    try expect(
        !removedRetainedRoute.contains("DOMAIN-SUFFIX,cwoa.net,UNIVPN-DIRECT")
            && removedRetainedRoute.contains("DOMAIN-SUFFIX,cwoa.net,DIRECT"),
        "later removal of a migrated VPN route reveals its restored fallback"
    )

    let routeOnlyRuntime = try ConfigTransformer.updateRuntimeConfig(
        runtime,
        interface: "utun10",
        dnsServers: exampleDNS,
        internalDNSDomains: [],
        vpnRouteDomains: vpnRouteDomains
    )
    try expect(routeOnlyRuntime.contains("vpn-only.example,UNIVPN-DIRECT"), "route list works without DNS domains")
    try expect(!routeOnlyRuntime.contains("#UNIVPN-DIRECT"), "route list does not create DNS policy")
    try expect(!routeOnlyRuntime.contains("\n  - 192.0.2.53"), "general VPN DNS always removed")

    let normalized = try AppConfiguration(
        dnsServers: exampleDNS,
        vpnRouteDomains: ["+.VPN-ONLY.EXAMPLE", "vpn-only.example", "*.second.example"],
        clashConfigDirectory: "/private/tmp",
        dnsGuardEnabled: true
    ).normalized()
    try expect(
        normalized.vpnRouteDomains == ["vpn-only.example", "second.example"],
        "VPN route configuration normalization"
    )
    try expect(normalized.schemaVersion == 2, "configuration schema upgrade")

    let legacyJSON = """
    {
      "schemaVersion": 1,
      "dnsServers": ["192.0.2.53"],
      "internalDomains": ["legacy-route.example"],
      "clashConfigDirectory": "/private/tmp",
      "dnsGuardEnabled": true
    }
    """
    let legacyConfiguration = try JSONDecoder().decode(
        AppConfiguration.self,
        from: Data(legacyJSON.utf8)
    )
    try expect(
        legacyConfiguration.vpnRouteDomains == ["legacy-route.example"],
        "legacy App domain migration"
    )
    let migratedData = try JSONEncoder().encode(legacyConfiguration)
    let migratedJSON = String(decoding: migratedData, as: UTF8.self)
    try expect(migratedJSON.contains("\"vpnRouteDomains\""), "new App route key is encoded")
    try expect(!migratedJSON.contains("\"internalDomains\""), "legacy App key is not encoded")

    let bothKeysJSON = """
    {
      "schemaVersion": 2,
      "dnsServers": ["192.0.2.53"],
      "vpnRouteDomains": [],
      "internalDomains": ["must-not-revive.example"],
      "clashConfigDirectory": "/private/tmp",
      "dnsGuardEnabled": true
    }
    """
    let bothKeysConfiguration = try JSONDecoder().decode(
        AppConfiguration.self,
        from: Data(bothKeysJSON.utf8)
    )
    try expect(
        bothKeysConfiguration.vpnRouteDomains.isEmpty,
        "new empty route key takes precedence over legacy key"
    )

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
        let generatedCheckConfig = try? String(
            contentsOf: sourceDirectory.appendingPathComponent("clash-verge-check.yaml"),
            encoding: .utf8
        )
        let discoveredInternalDNSDomains = try ConfigTransformer.discoverInternalDomains(in: globalScript)
        let legacyVPNRouteDomains = try ConfigTransformer.discoverLegacyVPNRouteDomains(in: globalScript)
        let previousVPNRouteDomains = try ConfigTransformer.discoverManagedVPNRouteDomains(in: globalScript)

        try ConfigTransformer.updateGlobalScript(
            globalScript,
            interface: interface,
            vpnRouteDomains: privateConfiguration.vpnRouteDomains
        ).write(to: outputDirectory.appendingPathComponent("Script.js"), atomically: true, encoding: .utf8)
        try ConfigTransformer.updateDNSConfig(
            dnsConfig,
            dnsServers: privateConfiguration.dnsServers,
            internalDNSDomains: discoveredInternalDNSDomains
        ).write(to: outputDirectory.appendingPathComponent("dns_config.yaml"), atomically: true, encoding: .utf8)
        try ConfigTransformer.updateRuntimeConfig(
            runtimeConfig,
            interface: interface,
            dnsServers: privateConfiguration.dnsServers,
            internalDNSDomains: discoveredInternalDNSDomains,
            vpnRouteDomains: privateConfiguration.vpnRouteDomains,
            routeRecoverySource: generatedCheckConfig,
            legacyVPNRouteDomains: legacyVPNRouteDomains,
            previousVPNRouteDomains: previousVPNRouteDomains
        ).write(to: outputDirectory.appendingPathComponent("clash-verge.yaml"), atomically: true, encoding: .utf8)
        print("Private integration output written outside the repository")
    }

    if CommandLine.arguments.count == 5, CommandLine.arguments[1] == "--restore-real" {
        let sourceDirectory = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true)
        let configurationURL = URL(fileURLWithPath: CommandLine.arguments[3])
        let outputDirectory = URL(fileURLWithPath: CommandLine.arguments[4], isDirectory: true)
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
        let generatedCheckConfig = try? String(
            contentsOf: sourceDirectory.appendingPathComponent("clash-verge-check.yaml"),
            encoding: .utf8
        )
        let discoveredInternalDNSDomains = try ConfigTransformer.discoverInternalDomains(in: globalScript)
        let legacyVPNRouteDomains = try ConfigTransformer.discoverLegacyVPNRouteDomains(in: globalScript)
        let previousVPNRouteDomains = try ConfigTransformer.discoverManagedVPNRouteDomains(in: globalScript)

        try ConfigTransformer.restoreGlobalScript(globalScript)
            .write(to: outputDirectory.appendingPathComponent("Script.js"), atomically: true, encoding: .utf8)
        try ConfigTransformer.restoreDNSConfig(
            dnsConfig,
            dnsServers: privateConfiguration.dnsServers,
            internalDNSDomains: discoveredInternalDNSDomains
        ).write(to: outputDirectory.appendingPathComponent("dns_config.yaml"), atomically: true, encoding: .utf8)
        try ConfigTransformer.restoreRuntimeConfig(
            runtimeConfig,
            dnsServers: privateConfiguration.dnsServers,
            internalDNSDomains: discoveredInternalDNSDomains,
            routeRecoverySource: generatedCheckConfig,
            legacyVPNRouteDomains: legacyVPNRouteDomains,
            previousVPNRouteDomains: previousVPNRouteDomains
        ).write(to: outputDirectory.appendingPathComponent("clash-verge.yaml"), atomically: true, encoding: .utf8)
        print("Private DIRECT integration output written outside the repository")
    }

    if CommandLine.arguments.count > 2, CommandLine.arguments[1] == "--probe-dns" {
        let available = try DNSReachabilityProbe().availableServers(Array(CommandLine.arguments.dropFirst(2)))
        print("Responding DNS servers: " + available.joined(separator: ", "))
    }
    if CommandLine.arguments.count == 4, CommandLine.arguments[1] == "--dns-snapshot" {
        let source = URL(fileURLWithPath: CommandLine.arguments[2])
        let destination = URL(fileURLWithPath: CommandLine.arguments[3])
        let script = try String(contentsOf: source.appendingPathComponent("profiles/Script.js"), encoding: .utf8)
        let domains = try ConfigTransformer.discoverInternalDomains(in: script)
        for (mode, servers) in [("public", [String]()), ("internal", ["192.0.2.53"])] {
            let directory = destination.appendingPathComponent(mode)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            for name in ["dns_config.yaml", "clash-verge.yaml"] {
                let original = try String(contentsOf: source.appendingPathComponent(name), encoding: .utf8)
                let transformed = try ConfigTransformer.synchronizeDNSPolicy(original, servers: servers, domains: domains, outbound: "DIRECT")
                try transformed.write(to: directory.appendingPathComponent(name), atomically: true, encoding: .utf8)
            }
            let transformed = try ConfigTransformer.synchronizeDNSScript(script, servers: servers, domains: domains, outbound: "DIRECT")
            try transformed.write(to: directory.appendingPathComponent("Script.js"), atomically: true, encoding: .utf8)
        }
    }
    let probeResponse: [UInt8] = [0, 42, 0x80, 5, 0, 1, 0, 0, 0, 0, 0, 0]
    try expect(DNSReachabilityProbe.hasDNSResponse(probeResponse, transactionID: 42), "DNS response recognized")
    try expect(!DNSReachabilityProbe.hasDNSResponse(probeResponse, transactionID: 43), "Wrong transaction rejected")
    try expect(!DNSReachabilityProbe.hasDNSResponse([], transactionID: 42), "Empty response rejected")
    let dnsFixture = """
    dns:
      nameserver:
        - https://dns.example/dns-query
      nameserver-policy:
        +.corp.example:
          - 'udp://192.0.2.53#DIRECT'
        +.other.example:
          - 'https://other.example/dns-query'
    """
    let publicDNS = try ConfigTransformer.synchronizeDNSPolicy(dnsFixture, servers: [], domains: ["corp.example"], outbound: "DIRECT")
    try expect(!publicDNS.contains("+.corp.example:"), "Public mode removes managed DNS")
    try expect(publicDNS.contains("+.other.example:") && publicDNS.contains("https://dns.example/dns-query"), "Other policies and resolvers retained")
    let recoveredDNS = try ConfigTransformer.synchronizeDNSPolicy(publicDNS, servers: ["192.0.2.54"], domains: ["corp.example"], outbound: "DIRECT")
    try expect(recoveredDNS.contains("udp://192.0.2.54#DIRECT") && !recoveredDNS.contains("192.0.2.53"), "Only available DNS restored")
    let publicAgain = try ConfigTransformer.synchronizeDNSPolicy(recoveredDNS, servers: [], domains: ["corp.example"], outbound: "DIRECT")
    try expect(publicAgain == publicDNS, "DNS roundtrip stable")
    var reachabilityScript = """
    const internalDomains = ["corp.example"];
    function main(config) {
      config.dns = {"nameserver-policy": {"+.corp.example": ["old"], "+.other.example": ["keep"]}};
      return config;
    }
    """
    for servers: [String] in [[], ["192.0.2.54"], [], ["192.0.2.53", "192.0.2.54"]] {
        if servers.isEmpty {
            reachabilityScript = try ConfigTransformer.restoreGlobalScript(reachabilityScript)
        } else {
            reachabilityScript = try ConfigTransformer.updateGlobalScript(reachabilityScript, interface: "utun9", vpnRouteDomains: [])
        }
        reachabilityScript = try ConfigTransformer.synchronizeDNSScript(reachabilityScript, servers: servers, domains: ["corp.example"], outbound: "UNIVPN-DIRECT")
        let context = JSContext()!
        context.evaluateScript(reachabilityScript)
        let value = context.evaluateScript("JSON.stringify(main({}))")?.toString() ?? ""
        try expect(context.exception == nil, "Repeated script regeneration executes without recursion")
        try expect(value.contains("keep"), "Script retains unrelated DNS policy")
        try expect(value.contains("+.corp.example") == !servers.isEmpty, "Script enforces reachability after original main")
        let savedDomains = try ConfigTransformer.discoverInternalDomains(in: reachabilityScript)
        try expect(savedDomains == ["corp.example"], "Domain manifest retained")
    }

    print("BridgeCore self-test passed")
} catch {
    FileHandle.standardError.write(Data("BridgeCore self-test failed: \(error)\n".utf8))
    exit(1)
}

private extension Optional {
    func unwrap(or error: @autoclosure () -> Error) throws -> Wrapped {
        guard let self else { throw error() }
        return self
    }
}
