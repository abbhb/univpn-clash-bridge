import Foundation

public enum ConfigTransformer {
    private static let scriptBegin = "// UNIVPN_CLASH_BRIDGE_BEGIN"
    private static let scriptEnd = "// UNIVPN_CLASH_BRIDGE_END"
    private static let dnsPolicyBegin = "# UNIVPN_CLASH_BRIDGE_DNS_BEGIN"
    private static let dnsPolicyEnd = "# UNIVPN_CLASH_BRIDGE_DNS_END"
    private static let routeRulesBegin = "# UNIVPN_CLASH_BRIDGE_RULES_BEGIN"
    private static let routeRulesEnd = "# UNIVPN_CLASH_BRIDGE_RULES_END"

    public static func discoverInternalDomains(in source: String) throws -> [String] {
        try discoverDomainArray(named: "internalDomains", in: source)
    }

    public static func discoverLegacyVPNRouteDomains(in source: String) throws -> [String] {
        guard let block = try managedScriptBlock(in: source) else { return [] }
        return try discoverDomainArray(named: "__univpnBridgeDomains", in: block)
    }

    public static func discoverManagedVPNRouteDomains(in source: String) throws -> [String] {
        guard let block = try managedScriptBlock(in: source) else { return [] }
        return try discoverDomainArray(named: "__univpnBridgeRouteDomains", in: block)
    }

    private static func discoverDomainArray(named variableName: String, in source: String) throws -> [String] {
        let escapedName = NSRegularExpression.escapedPattern(for: variableName)
        let declarationPattern = "(?m)^[ \\t]*(?:const|let|var)\\s+\(escapedName)\\s*="
        let declarationExpression = try NSRegularExpression(pattern: declarationPattern)
        let sourceRange = NSRange(source.startIndex..<source.endIndex, in: source)
        guard declarationExpression.firstMatch(in: source, range: sourceRange) != nil else { return [] }

        let arrayPattern = declarationPattern + "\\s*(\\[[^\\]]*\\])"
        let arrayExpression = try NSRegularExpression(
            pattern: arrayPattern,
            options: [.dotMatchesLineSeparators]
        )
        guard let match = arrayExpression.firstMatch(in: source, range: sourceRange),
              let arrayRange = Range(match.range(at: 1), in: source)
        else {
            throw BridgeError.unsupportedConfig("\(variableName) 必须是字符串数组字面量")
        }

        let arrayLiteral = String(source[arrayRange])
        let values = try parseDomainArrayLiteral(arrayLiteral, variableName: variableName)

        var seen = Set<String>()
        var result: [String] = []
        for value in values {
            guard let domain = normalizeDiscoveredDomain(value) else {
                throw BridgeError.unsupportedConfig("\(variableName) 包含无效域名：\(value)")
            }
            if seen.insert(domain).inserted {
                result.append(domain)
            }
        }
        return result
    }

    private static func parseDomainArrayLiteral(
        _ literal: String,
        variableName: String
    ) throws -> [String] {
        guard literal.first == "[", literal.last == "]" else {
            throw BridgeError.unsupportedConfig("\(variableName) 必须是字符串数组字面量")
        }
        let interior = String(literal.dropFirst().dropLast())
        let expression = try NSRegularExpression(pattern: #"(["'])([^"'\\]*)\1"#)
        let range = NSRange(interior.startIndex..<interior.endIndex, in: interior)
        let matches = expression.matches(in: interior, range: range)
        let values = matches.compactMap { match -> String? in
            guard let valueRange = Range(match.range(at: 2), in: interior) else { return nil }
            return String(interior[valueRange])
        }

        var residual = interior
        for match in matches.reversed() {
            guard let matchRange = Range(match.range, in: residual) else { continue }
            residual.removeSubrange(matchRange)
        }
        residual.removeAll { $0.isWhitespace || $0 == "," }
        guard residual.isEmpty else {
            throw BridgeError.unsupportedConfig("\(variableName) 只能包含字符串域名")
        }
        return values
    }

    private static func managedScriptBlock(in source: String) throws -> String? {
        let beginRange = source.range(of: scriptBegin)
        let endRange = source.range(of: scriptEnd)
        guard beginRange != nil || endRange != nil else { return nil }
        guard let beginRange, let endRange else {
            throw BridgeError.unsupportedConfig("全局脚本中的托管标记不完整")
        }
        guard beginRange.lowerBound < endRange.lowerBound else {
            throw BridgeError.unsupportedConfig("全局脚本中的托管标记顺序错误")
        }
        return String(source[beginRange.lowerBound..<endRange.upperBound])
    }

    public static func updateGlobalScript(
        _ source: String,
        interface: String,
        vpnRouteDomains: [String]
    ) throws -> String {
        guard interface.range(of: #"^utun\d+$"#, options: .regularExpression) != nil else {
            throw BridgeError.invalidVPNInterface(interface)
        }

        let base = try removingManagedScriptBlock(from: source)

        guard base.range(of: #"\bfunction\s+main\s*\(|\bmain\s*="#,
                         options: .regularExpression) != nil
        else {
            throw BridgeError.unsupportedConfig("全局脚本没有 main 函数")
        }

        let domainJSON = try jsonString(vpnRouteDomains)
        let block = """
        \(scriptBegin)
        const __univpnBridgeInterface = \(try jsonString(interface));
        const __univpnBridgeProxyName = \(try jsonString(BridgeConstants.proxyName));
        const __univpnBridgeRouteDomains = \(domainJSON);
        const __univpnBridgeOriginalMain = main;

        main = function(config, profileName) {
          config = __univpnBridgeOriginalMain(config, profileName) || config;

          const oldProxies = Array.isArray(config.proxies) ? config.proxies : [];
          config.proxies = [{
            name: __univpnBridgeProxyName,
            type: "direct",
            udp: true,
            "ip-version": "ipv4",
            "interface-name": __univpnBridgeInterface,
          }].concat(oldProxies.filter(function(proxy) {
            return !proxy || proxy.name !== __univpnBridgeProxyName;
          }));

          const managedRules = __univpnBridgeRouteDomains.map(function(domain) {
            return "DOMAIN-SUFFIX," + domain + "," + __univpnBridgeProxyName;
          });
          const oldRules = Array.isArray(config.rules) ? config.rules : [];
          const keptRules = oldRules.filter(function(rule) {
            return typeof rule !== "string" || managedRules.indexOf(rule) === -1;
          });
          config.rules = managedRules.concat(keptRules);

          return config;
        };
        \(scriptEnd)
        """

        return base.trimmingCharacters(in: .whitespacesAndNewlines) + "\n\n" + block + "\n"
    }

    public static func restoreGlobalScript(_ source: String) throws -> String {
        let base = try removingManagedScriptBlock(from: source)
        guard base != source else { return source }
        return base.trimmingCharacters(in: .whitespacesAndNewlines) + "\n"
    }

    private static func removingManagedScriptBlock(from source: String) throws -> String {
        var base = source
        let beginRange = base.range(of: scriptBegin)
        let endRange = base.range(of: scriptEnd)
        if let beginRange, let endRange {
            guard beginRange.lowerBound < endRange.lowerBound else {
                throw BridgeError.unsupportedConfig("全局脚本中的托管标记顺序错误")
            }
            var removalEnd = endRange.upperBound
            if removalEnd < base.endIndex, base[removalEnd] == "\n" {
                removalEnd = base.index(after: removalEnd)
            }
            base.removeSubrange(beginRange.lowerBound..<removalEnd)
        } else if beginRange != nil || endRange != nil {
            throw BridgeError.unsupportedConfig("全局脚本中的托管标记不完整")
        }
        return base
    }

    /// Applies the same reachability snapshot to saved DNS and runtime YAML.
    public static func synchronizeDNSPolicy(
        _ source: String, servers: [String], domains: [String], outbound: String
    ) throws -> String {
        var lines = source.components(separatedBy: "\n")
        try upsertInternalDNSPolicy(&lines, dnsServers: servers,
            internalDNSDomains: domains, outboundName: outbound, enabled: !servers.isEmpty)
        return lines.joined(separator: "\n")
    }

    /// Runs after the user's main function, preventing it from restoring stale DNS policies.
    public static func synchronizeDNSScript(
        _ source: String, servers: [String], domains: [String], outbound: String
    ) throws -> String {
        let begin = "// UNIVPN_DNS_REACHABILITY_BEGIN"
        let end = "// UNIVPN_DNS_REACHABILITY_END"
        var base = source
        if let b = base.range(of: begin), let e = base.range(of: end), b.lowerBound < e.lowerBound {
            base.removeSubrange(b.lowerBound..<e.upperBound)
        } else if base.contains(begin) || base.contains(end) {
            throw BridgeError.unsupportedConfig("DNS 探测脚本标记不完整")
        }
        // The wrapper must follow both the user script and the VPN wrapper.
        guard base.range(of: #"\bfunction\s+main\s*\(|\bmain\s*="#,
                         options: .regularExpression) != nil else {
            throw BridgeError.unsupportedConfig("全局脚本没有 main 函数")
        }
        let resolvers = servers.map { "udp://" + ($0.contains(":") ? "[" + $0 + "]" : $0) + "#" + outbound }
        return base.trimmingCharacters(in: .whitespacesAndNewlines) + "\n\n" + """
        \(begin)
        const __univpnDNSOriginalMain = main;
        main = function(config, profileName) {
          config = __univpnDNSOriginalMain(config, profileName) || config;
          const domains = \(try jsonString(domains));
          const servers = \(try jsonString(resolvers));
          if (domains.length) {
            config.dns = config.dns || {};
            const policy = config.dns["nameserver-policy"] || {};
            domains.forEach(function(domain) {
              delete policy["+." + domain];
              if (servers.length) policy["+." + domain] = servers.slice();
            });
            config.dns["nameserver-policy"] = policy;
          }
          return config;
        };
        \(end)
        """ + "\n"
    }

    public static func updateDNSConfig(
        _ source: String,
        dnsServers: [String],
        internalDNSDomains: [String]
    ) throws -> String {
        var lines = source.components(separatedBy: "\n")
        removeCompanyServersFromGeneralNameservers(&lines, dnsServers: dnsServers)
        try upsertInternalDNSPolicy(
            &lines,
            dnsServers: dnsServers,
            internalDNSDomains: internalDNSDomains,
            outboundName: BridgeConstants.proxyName
        )
        return lines.joined(separator: "\n")
    }

    public static func restoreDNSConfig(
        _ source: String,
        dnsServers: [String],
        internalDNSDomains: [String]
    ) throws -> String {
        var lines = source.components(separatedBy: "\n")
        removeCompanyServersFromGeneralNameservers(&lines, dnsServers: dnsServers)
        try upsertInternalDNSPolicy(
            &lines,
            dnsServers: dnsServers,
            internalDNSDomains: internalDNSDomains,
            outboundName: "DIRECT"
        )
        return lines.joined(separator: "\n")
    }

    public static func updateRuntimeConfig(
        _ source: String,
        interface: String,
        dnsServers: [String],
        internalDNSDomains: [String],
        vpnRouteDomains: [String],
        routeRecoverySource: String? = nil,
        legacyVPNRouteDomains: [String] = [],
        previousVPNRouteDomains: [String] = []
    ) throws -> String {
        var result = try updateDNSConfig(
            source,
            dnsServers: dnsServers,
            internalDNSDomains: internalDNSDomains
        )
        result = try upsertDirectProxy(result, interface: interface)
        result = try upsertVPNRouteRules(
            result,
            vpnRouteDomains: vpnRouteDomains,
            routeRecoverySource: routeRecoverySource,
            legacyVPNRouteDomains: legacyVPNRouteDomains,
            previousVPNRouteDomains: previousVPNRouteDomains
        )
        return result
    }

    public static func restoreRuntimeConfig(
        _ source: String,
        dnsServers: [String],
        internalDNSDomains: [String],
        routeRecoverySource: String? = nil,
        legacyVPNRouteDomains: [String] = [],
        previousVPNRouteDomains: [String] = []
    ) throws -> String {
        var result = try restoreDNSConfig(
            source,
            dnsServers: dnsServers,
            internalDNSDomains: internalDNSDomains
        )
        result = try restoreDirectProxy(result)
        result = try upsertVPNRouteRules(
            result,
            vpnRouteDomains: [],
            routeRecoverySource: routeRecoverySource,
            legacyVPNRouteDomains: legacyVPNRouteDomains,
            previousVPNRouteDomains: previousVPNRouteDomains
        )
        return result
    }

    private static func removeCompanyServersFromGeneralNameservers(
        _ lines: inout [String],
        dnsServers: [String]
    ) {
        guard let start = lines.firstIndex(where: { $0.trimmingCharacters(in: .whitespaces) == "nameserver:" })
        else { return }

        let baseIndent = indentation(of: lines[start])
        let end = sectionEnd(lines, start: start, baseIndent: baseIndent)
        let companyServers = Set(dnsServers)

        for index in (start + 1..<end).reversed() {
            let value = listScalar(from: lines[index])
            if let value, companyServers.contains(unquote(value)) {
                lines.remove(at: index)
            }
        }
    }

    private static func upsertInternalDNSPolicy(
        _ lines: inout [String],
        dnsServers: [String],
        internalDNSDomains: [String],
        outboundName: String,
        enabled: Bool = true
    ) throws {
        guard !enabled || !dnsServers.isEmpty else {
            throw BridgeError.invalidConfiguration("DNS 列表为空")
        }
        try removeManagedDNSPolicyBlock(&lines)
        if let start = lines.firstIndex(where: {
            mappingKey(from: $0) == "nameserver-policy"
        }) {
            let baseIndent = indentation(of: lines[start])
            // Clash serializes an empty block as null (or {}). Reuse its key instead of appending another.
            let declaration = lines[start]
            let colon = declaration.firstIndex(of: ":")!
            let value = declaration[declaration.index(after: colon)...]
                .split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)[0]
                .trimmingCharacters(in: .whitespaces)
            guard value.isEmpty || ["null", "Null", "NULL", "~"].contains(value)
                    || value.range(of: #"^\{\s*\}$"#, options: .regularExpression) != nil else {
                throw BridgeError.unsupportedConfig("nameserver-policy 包含暂不支持的行内值，未修改配置")
            }
            lines[start] = String(repeating: " ", count: baseIndent) + "nameserver-policy:"
            var end = sectionEnd(lines, start: start, baseIndent: baseIndent)
            let managedDomains = Set(internalDNSDomains.map { "+." + $0 })
            var index = start + 1

            while index < end {
                guard let key = mappingKey(from: lines[index]) else {
                    index += 1
                    continue
                }

                let keyIndent = indentation(of: lines[index])
                var blockEnd = index + 1
                while blockEnd < end {
                    let trimmed = lines[blockEnd].trimmingCharacters(in: .whitespaces)
                    let indent = indentation(of: lines[blockEnd])
                    if !trimmed.isEmpty,
                       !trimmed.hasPrefix("#"),
                       !trimmed.hasPrefix("-"),
                       indent <= keyIndent
                    {
                        break
                    }
                    blockEnd += 1
                }
                guard managedDomains.contains(key) else {
                    index = blockEnd
                    continue
                }
                lines.removeSubrange(index..<blockEnd)
                end -= blockEnd - index
            }

            if enabled && !internalDNSDomains.isEmpty {
                lines.insert(
                    contentsOf: managedPolicyLines(
                        baseIndent: baseIndent,
                        dnsServers: dnsServers,
                        internalDNSDomains: internalDNSDomains,
                        outboundName: outboundName
                    ),
                    at: start + 1
                )
            }
            return
        }

        guard enabled && !internalDNSDomains.isEmpty else { return }

        guard let dnsStart = lines.firstIndex(where: {
            indentation(of: $0) == 0 && $0.trimmingCharacters(in: .whitespaces) == "dns:"
        }) else {
            throw BridgeError.unsupportedConfig("找不到 dns 或 nameserver-policy 段")
        }

        let dnsEnd = sectionEnd(lines, start: dnsStart, baseIndent: 0)
        var block = ["  nameserver-policy:"]
        block.append(contentsOf: managedPolicyLines(
            baseIndent: 2,
            dnsServers: dnsServers,
            internalDNSDomains: internalDNSDomains,
            outboundName: outboundName
        ))
        lines.insert(contentsOf: block, at: dnsEnd)
    }

    private static func removeManagedDNSPolicyBlock(_ lines: inout [String]) throws {
        while let begin = lines.firstIndex(where: {
            $0.trimmingCharacters(in: .whitespaces) == dnsPolicyBegin
        }) {
            guard let end = lines[(begin + 1)...].firstIndex(where: {
                $0.trimmingCharacters(in: .whitespaces) == dnsPolicyEnd
            }) else {
                throw BridgeError.unsupportedConfig("DNS policy 托管标记不完整")
            }
            lines.removeSubrange(begin...end)
        }
        if lines.contains(where: { $0.trimmingCharacters(in: .whitespaces) == dnsPolicyEnd }) {
            throw BridgeError.unsupportedConfig("DNS policy 托管标记顺序错误")
        }
    }

    private static func managedPolicyLines(
        baseIndent: Int,
        dnsServers: [String],
        internalDNSDomains: [String],
        outboundName: String
    ) -> [String] {
        let markerIndent = String(repeating: " ", count: baseIndent + 2)
        return ["\(markerIndent)\(dnsPolicyBegin)"]
            + policyLines(
                baseIndent: baseIndent,
                dnsServers: dnsServers,
                internalDNSDomains: internalDNSDomains,
                outboundName: outboundName
            )
            + ["\(markerIndent)\(dnsPolicyEnd)"]
    }

    private static func policyLines(
        baseIndent: Int,
        dnsServers: [String],
        internalDNSDomains: [String],
        outboundName: String
    ) -> [String] {
        let keyIndent = String(repeating: " ", count: baseIndent + 2)
        let valueIndent = String(repeating: " ", count: baseIndent + 4)
        var result: [String] = []
        for domain in internalDNSDomains {
            result.append("\(keyIndent)+.\(domain):")
            for server in dnsServers {
                let host = server.contains(":") ? "[\(server)]" : server
                result.append("\(valueIndent)- 'udp://\(host)#\(outboundName)'")
            }
        }
        return result
    }

    private static func upsertDirectProxy(_ source: String, interface: String) throws -> String {
        guard interface.range(of: #"^utun\d+$"#, options: .regularExpression) != nil else {
            throw BridgeError.invalidVPNInterface(interface)
        }
        return try transformDirectProxy(source, interface: interface, createIfMissing: true)
    }

    private static func restoreDirectProxy(_ source: String) throws -> String {
        try transformDirectProxy(source, interface: nil, createIfMissing: false)
    }

    private static func transformDirectProxy(
        _ source: String,
        interface: String?,
        createIfMissing: Bool
    ) throws -> String {
        var lines = source.components(separatedBy: "\n")
        guard let start = lines.firstIndex(where: {
            indentation(of: $0) == 0 && $0.trimmingCharacters(in: .whitespaces) == "proxies:"
        }) else {
            throw BridgeError.unsupportedConfig("运行配置没有 proxies 段")
        }

        let end = sectionEnd(lines, start: start, baseIndent: 0)
        var index = start + 1
        var matchingRange: Range<Int>?
        while index < end {
            let trimmed = lines[index].trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("-") else {
                index += 1
                continue
            }

            let itemIndent = indentation(of: lines[index])
            var itemEnd = index + 1
            while itemEnd < end {
                let nextTrimmed = lines[itemEnd].trimmingCharacters(in: .whitespaces)
                if nextTrimmed.hasPrefix("-") && indentation(of: lines[itemEnd]) == itemIndent {
                    break
                }
                itemEnd += 1
            }

            let item = lines[index..<itemEnd].joined(separator: "\n")
            if proxyItem(item, hasName: BridgeConstants.proxyName) {
                guard matchingRange == nil else {
                    throw BridgeError.unsupportedConfig("运行配置存在重复的 \(BridgeConstants.proxyName) proxy")
                }
                guard proxyItem(item, hasType: "direct") else {
                    throw BridgeError.unsupportedConfig(
                        "运行配置中的 \(BridgeConstants.proxyName) 不是 direct 类型"
                    )
                }
                matchingRange = index..<itemEnd
            }
            index = itemEnd
        }

        if let matchingRange {
            if let interface {
                let block = updatingDirectProxyLines(
                    Array(lines[matchingRange]),
                    interface: interface
                )
                lines.replaceSubrange(matchingRange, with: block)
            } else {
                for lineIndex in matchingRange.reversed() {
                    if yamlKey(lines[lineIndex]) == "interface-name" {
                        lines.remove(at: lineIndex)
                    }
                }
            }
        } else if createIfMissing, let interface {
            lines.insert(contentsOf: directProxyLines(interface: interface), at: end)
        }
        return lines.joined(separator: "\n")
    }

    private static func directProxyLines(interface: String) -> [String] {
        [
            "- name: \(BridgeConstants.proxyName)",
            "  type: direct",
            "  udp: true",
            "  ip-version: ipv4",
            "  interface-name: \(interface)",
        ]
    }

    private static func updatingDirectProxyLines(
        _ existing: [String],
        interface: String
    ) -> [String] {
        var result = existing
        let managedKeys = Set(["udp", "ip-version", "interface-name"])
        for index in result.indices.reversed() {
            if let key = yamlKey(result[index]), managedKeys.contains(key) {
                result.remove(at: index)
            }
        }
        let itemIndent = existing.first.map(indentation(of:)) ?? 0
        let propertyIndent = String(repeating: " ", count: itemIndent + 2)
        result.append("\(propertyIndent)udp: true")
        result.append("\(propertyIndent)ip-version: ipv4")
        result.append("\(propertyIndent)interface-name: \(interface)")
        return result
    }

    private static func upsertVPNRouteRules(
        _ source: String,
        vpnRouteDomains: [String],
        routeRecoverySource: String?,
        legacyVPNRouteDomains: [String],
        previousVPNRouteDomains: [String]
    ) throws -> String {
        var lines = source.components(separatedBy: "\n")
        guard let start = lines.firstIndex(where: {
            indentation(of: $0) == 0 && $0.trimmingCharacters(in: .whitespaces) == "rules:"
        }) else {
            throw BridgeError.unsupportedConfig("运行配置没有 rules 段")
        }

        try removeManagedRouteRuleBlock(&lines)
        var end = sectionEnd(lines, start: start, baseIndent: 0)
        let legacyManagedDomains = Set(legacyVPNRouteDomains)
        let managedDomains = legacyManagedDomains
            .union(previousVPNRouteDomains)
            .union(vpnRouteDomains)
        var removedLegacyDomains = Set<String>()
        for index in (start + 1..<end).reversed() {
            let trimmed = lines[index].trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("-") else { continue }
            guard let rule = parseDomainSuffixRule(trimmed) else { continue }
            if rule.fieldCount == 3,
               rule.target == BridgeConstants.proxyName,
               managedDomains.contains(rule.domain)
            {
                if legacyManagedDomains.contains(rule.domain) {
                    removedLegacyDomains.insert(rule.domain)
                }
                lines.remove(at: index)
                end -= 1
            }
        }

        let currentRuleDomains = Set(lines[(start + 1)..<end].compactMap {
            parseDomainSuffixRule($0)?.domain
        })
        let recovery = try recoveredRouteRules(
            from: routeRecoverySource,
            domains: removedLegacyDomains.subtracting(currentRuleDomains)
        )
        try insertRecoveredRouteRules(
            recovery,
            into: &lines,
            rulesStart: start,
            rulesEnd: &end
        )
        if !vpnRouteDomains.isEmpty {
            let rules = [routeRulesBegin]
                + vpnRouteDomains.map { "- DOMAIN-SUFFIX,\($0),\(BridgeConstants.proxyName)" }
                + [routeRulesEnd]
            lines.insert(contentsOf: rules, at: start + 1)
        }
        return lines.joined(separator: "\n")
    }

    private static func removeManagedRouteRuleBlock(_ lines: inout [String]) throws {
        while let begin = lines.firstIndex(where: {
            $0.trimmingCharacters(in: .whitespaces) == routeRulesBegin
        }) {
            guard let end = lines[(begin + 1)...].firstIndex(where: {
                $0.trimmingCharacters(in: .whitespaces) == routeRulesEnd
            }) else {
                throw BridgeError.unsupportedConfig("VPN 分流规则托管标记不完整")
            }
            lines.removeSubrange(begin...end)
        }
        if lines.contains(where: { $0.trimmingCharacters(in: .whitespaces) == routeRulesEnd }) {
            throw BridgeError.unsupportedConfig("VPN 分流规则托管标记顺序错误")
        }
    }

    private struct RouteRecovery {
        let checkRules: [String]
        let rules: [(position: Int, raw: String)]
    }

    private static func recoveredRouteRules(
        from source: String?,
        domains: Set<String>
    ) throws -> RouteRecovery? {
        guard !domains.isEmpty else { return nil }
        guard let source else {
            throw BridgeError.unsupportedConfig(
                "检测到旧版 VPN 分流，但缺少 Clash Verge 生成配置；请先在 Clash Verge 中重新激活当前配置"
            )
        }
        let lines = source.components(separatedBy: "\n")
        guard let start = lines.firstIndex(where: {
            indentation(of: $0) == 0 && $0.trimmingCharacters(in: .whitespaces) == "rules:"
        }) else {
            throw BridgeError.unsupportedConfig("Clash Verge 生成配置没有 rules 段，无法恢复旧版分流")
        }

        let end = sectionEnd(lines, start: start, baseIndent: 0)
        let checkRules = lines[(start + 1)..<end].compactMap(ruleScalar)
        var remaining = domains
        var recovered: [(position: Int, raw: String)] = []
        for (position, raw) in checkRules.enumerated() {
            guard let rule = parseDomainSuffixRule("- \(raw)"),
                  remaining.contains(rule.domain),
                  rule.target != BridgeConstants.proxyName
            else { continue }
            recovered.append((position: position, raw: rule.raw))
            remaining.remove(rule.domain)
        }
        guard remaining.isEmpty else {
            throw BridgeError.unsupportedConfig(
                "无法从 Clash Verge 生成配置恢复旧版分流：\(remaining.sorted().joined(separator: ", "))"
            )
        }
        return RouteRecovery(checkRules: checkRules, rules: recovered)
    }

    private static func insertRecoveredRouteRules(
        _ recovery: RouteRecovery?,
        into lines: inout [String],
        rulesStart: Int,
        rulesEnd: inout Int
    ) throws {
        guard let recovery else { return }

        for recovered in recovery.rules {
            let followingRules = recovery.checkRules.dropFirst(recovered.position + 1)
            let precedingRules = recovery.checkRules.prefix(recovered.position).reversed()
            let insertionIndex: Int

            if let following = followingRules.first(where: { candidate in
                currentRuleIndex(candidate, in: lines, start: rulesStart, end: rulesEnd) != nil
            }), let index = currentRuleIndex(following, in: lines, start: rulesStart, end: rulesEnd) {
                insertionIndex = index
            } else if let preceding = precedingRules.first(where: { candidate in
                currentRuleIndex(candidate, in: lines, start: rulesStart, end: rulesEnd) != nil
            }), let index = currentRuleIndex(preceding, in: lines, start: rulesStart, end: rulesEnd) {
                insertionIndex = index + 1
            } else if rulesEnd == rulesStart + 1 {
                insertionIndex = rulesStart + 1
            } else {
                throw BridgeError.unsupportedConfig(
                    "Clash Verge 生成配置与当前运行规则不匹配，无法安全恢复旧版分流"
                )
            }

            lines.insert("- \(recovered.raw)", at: insertionIndex)
            rulesEnd += 1
        }
    }

    private static func currentRuleIndex(
        _ raw: String,
        in lines: [String],
        start: Int,
        end: Int
    ) -> Int? {
        (start + 1..<end).first { ruleScalar(lines[$0]) == raw }
    }

    private static func ruleScalar(_ line: String) -> String? {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard trimmed.hasPrefix("-") else { return nil }
        return String(trimmed.dropFirst()).trimmingCharacters(in: .whitespaces)
    }

    private static func parseDomainSuffixRule(
        _ line: String
    ) -> (domain: String, target: String, raw: String, fieldCount: Int)? {
        guard let raw = ruleScalar(line) else { return nil }
        let fields = raw.split(separator: ",", omittingEmptySubsequences: false).map {
            String($0).trimmingCharacters(in: .whitespaces)
        }
        guard fields.count >= 3, fields[0] == "DOMAIN-SUFFIX" else { return nil }
        return (domain: fields[1], target: fields[2], raw: raw, fieldCount: fields.count)
    }

    private static func sectionEnd(_ lines: [String], start: Int, baseIndent: Int) -> Int {
        var index = start + 1
        while index < lines.count {
            let trimmed = lines[index].trimmingCharacters(in: .whitespaces)
            if !trimmed.isEmpty,
               !trimmed.hasPrefix("#"),
               !trimmed.hasPrefix("-"),
               indentation(of: lines[index]) <= baseIndent
            {
                break
            }
            index += 1
        }
        return index
    }

    private static func indentation(of line: String) -> Int {
        line.prefix(while: { $0 == " " }).count
    }

    private static func mappingKey(from line: String) -> String? {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard !trimmed.hasPrefix("-"), let colon = trimmed.firstIndex(of: ":") else { return nil }
        return unquote(String(trimmed[..<colon]).trimmingCharacters(in: .whitespaces))
    }

    private static func listScalar(from line: String) -> String? {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard trimmed.hasPrefix("-") else { return nil }
        return String(trimmed.dropFirst()).trimmingCharacters(in: .whitespaces)
    }

    private static func unquote(_ value: String) -> String {
        guard value.count >= 2 else { return value }
        if (value.first == "'" && value.last == "'") || (value.first == "\"" && value.last == "\"") {
            return String(value.dropFirst().dropLast())
        }
        return value
    }

    private static func yamlKey(_ line: String) -> String? {
        var trimmed = line.trimmingCharacters(in: .whitespaces)
        if trimmed.hasPrefix("-") {
            trimmed = String(trimmed.dropFirst()).trimmingCharacters(in: .whitespaces)
        }
        guard let colon = trimmed.firstIndex(of: ":") else { return nil }
        return String(trimmed[..<colon]).trimmingCharacters(in: .whitespaces)
    }

    private static func proxyItem(_ item: String, hasName name: String) -> Bool {
        item.components(separatedBy: "\n").contains { line in
            var trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("-") {
                trimmed = String(trimmed.dropFirst()).trimmingCharacters(in: .whitespaces)
            }
            guard trimmed.hasPrefix("name:"), let colon = trimmed.firstIndex(of: ":") else { return false }
            let value = String(trimmed[trimmed.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            return unquote(value) == name
        }
    }

    private static func proxyItem(_ item: String, hasType type: String) -> Bool {
        item.components(separatedBy: "\n").contains { line in
            guard yamlKey(line) == "type", let colon = line.firstIndex(of: ":") else { return false }
            let value = String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            return unquote(value) == type
        }
    }

    private static func normalizeDiscoveredDomain(_ value: String) -> String? {
        var domain = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        for prefix in ["+.", "*."] where domain.hasPrefix(prefix) {
            domain.removeFirst(prefix.count)
        }
        while domain.hasPrefix(".") { domain.removeFirst() }
        while domain.hasSuffix(".") { domain.removeLast() }

        let labels = domain.split(separator: ".", omittingEmptySubsequences: false)
        guard !labels.isEmpty, domain.count <= 253 else { return nil }
        for label in labels {
            guard !label.isEmpty,
                  label.count <= 63,
                  label.first?.isLetter == true || label.first?.isNumber == true,
                  label.last?.isLetter == true || label.last?.isNumber == true,
                  label.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "-" })
            else { return nil }
        }
        return domain
    }

    private static func jsonString<T: Encodable>(_ value: T) throws -> String {
        let data = try JSONEncoder().encode(value)
        return String(decoding: data, as: UTF8.self)
    }
}
