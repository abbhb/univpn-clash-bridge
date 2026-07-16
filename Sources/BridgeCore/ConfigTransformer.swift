import Foundation

public enum ConfigTransformer {
    private static let scriptBegin = "// UNIVPN_CLASH_BRIDGE_BEGIN"
    private static let scriptEnd = "// UNIVPN_CLASH_BRIDGE_END"

    public static func updateGlobalScript(
        _ source: String,
        interface: String,
        internalDomains: [String]
    ) throws -> String {
        guard interface.range(of: #"^utun\d+$"#, options: .regularExpression) != nil else {
            throw BridgeError.invalidVPNInterface(interface)
        }

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

        guard base.range(of: #"\bfunction\s+main\s*\(|\bmain\s*="#,
                         options: .regularExpression) != nil
        else {
            throw BridgeError.unsupportedConfig("全局脚本没有 main 函数")
        }

        guard !internalDomains.isEmpty else {
            throw BridgeError.invalidConfiguration("内网域名列表为空")
        }
        let domainJSON = try jsonString(internalDomains)
        let block = """
        \(scriptBegin)
        const __univpnBridgeInterface = \(try jsonString(interface));
        const __univpnBridgeProxyName = \(try jsonString(BridgeConstants.proxyName));
        const __univpnBridgeDomains = \(domainJSON);
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

          const oldRules = Array.isArray(config.rules) ? config.rules : [];
          const keptRules = oldRules.filter(function(rule) {
            if (typeof rule !== "string") return true;
            return !__univpnBridgeDomains.some(function(domain) {
              return rule.indexOf("DOMAIN-SUFFIX," + domain + ",") === 0;
            });
          });
          const managedRules = __univpnBridgeDomains.map(function(domain) {
            return "DOMAIN-SUFFIX," + domain + "," + __univpnBridgeProxyName;
          });
          config.rules = managedRules.concat(keptRules);

          return config;
        };
        \(scriptEnd)
        """

        return base.trimmingCharacters(in: .whitespacesAndNewlines) + "\n\n" + block + "\n"
    }

    public static func updateDNSConfig(
        _ source: String,
        dnsServers: [String],
        internalDomains: [String]
    ) throws -> String {
        var lines = source.components(separatedBy: "\n")
        removeCompanyServersFromGeneralNameservers(&lines, dnsServers: dnsServers)
        try upsertInternalDNSPolicy(&lines, dnsServers: dnsServers, internalDomains: internalDomains)
        return lines.joined(separator: "\n")
    }

    public static func updateRuntimeConfig(
        _ source: String,
        interface: String,
        dnsServers: [String],
        internalDomains: [String]
    ) throws -> String {
        var result = try updateDNSConfig(
            source,
            dnsServers: dnsServers,
            internalDomains: internalDomains
        )
        result = try upsertDirectProxy(result, interface: interface)
        result = try upsertInternalRules(result, internalDomains: internalDomains)
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

        for index in stride(from: end - 1, through: start + 1, by: -1) {
            let value = listScalar(from: lines[index])
            if let value, companyServers.contains(unquote(value)) {
                lines.remove(at: index)
            }
        }
    }

    private static func upsertInternalDNSPolicy(
        _ lines: inout [String],
        dnsServers: [String],
        internalDomains: [String]
    ) throws {
        guard !dnsServers.isEmpty, !internalDomains.isEmpty else {
            throw BridgeError.invalidConfiguration("DNS 或内网域名列表为空")
        }
        if let start = lines.firstIndex(where: {
            $0.trimmingCharacters(in: .whitespaces) == "nameserver-policy:"
        }) {
            let baseIndent = indentation(of: lines[start])
            var end = sectionEnd(lines, start: start, baseIndent: baseIndent)
            let managedDomains = Set(internalDomains.map { "+." + $0 })
            var index = start + 1

            while index < end {
                guard let key = mappingKey(from: lines[index]), managedDomains.contains(key) else {
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
                lines.removeSubrange(index..<blockEnd)
                end -= blockEnd - index
            }

            lines.insert(
                contentsOf: policyLines(
                    baseIndent: baseIndent,
                    dnsServers: dnsServers,
                    internalDomains: internalDomains
                ),
                at: start + 1
            )
            return
        }

        guard let dnsStart = lines.firstIndex(where: {
            indentation(of: $0) == 0 && $0.trimmingCharacters(in: .whitespaces) == "dns:"
        }) else {
            throw BridgeError.unsupportedConfig("找不到 dns 或 nameserver-policy 段")
        }

        let dnsEnd = sectionEnd(lines, start: dnsStart, baseIndent: 0)
        var block = ["  nameserver-policy:"]
        block.append(contentsOf: policyLines(
            baseIndent: 2,
            dnsServers: dnsServers,
            internalDomains: internalDomains
        ))
        lines.insert(contentsOf: block, at: dnsEnd)
    }

    private static func policyLines(
        baseIndent: Int,
        dnsServers: [String],
        internalDomains: [String]
    ) -> [String] {
        let keyIndent = String(repeating: " ", count: baseIndent + 2)
        let valueIndent = String(repeating: " ", count: baseIndent + 4)
        var result: [String] = []
        for domain in internalDomains {
            result.append("\(keyIndent)+.\(domain):")
            for server in dnsServers {
                let host = server.contains(":") ? "[\(server)]" : server
                result.append("\(valueIndent)- 'udp://\(host)#\(BridgeConstants.proxyName)'")
            }
        }
        return result
    }

    private static func upsertDirectProxy(_ source: String, interface: String) throws -> String {
        guard interface.range(of: #"^utun\d+$"#, options: .regularExpression) != nil else {
            throw BridgeError.invalidVPNInterface(interface)
        }

        var lines = source.components(separatedBy: "\n")
        guard let start = lines.firstIndex(where: {
            indentation(of: $0) == 0 && $0.trimmingCharacters(in: .whitespaces) == "proxies:"
        }) else {
            throw BridgeError.unsupportedConfig("运行配置没有 proxies 段")
        }

        var end = sectionEnd(lines, start: start, baseIndent: 0)
        var index = start + 1
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
                lines.removeSubrange(index..<itemEnd)
                end -= itemEnd - index
                continue
            }
            index = itemEnd
        }

        let block = [
            "- name: \(BridgeConstants.proxyName)",
            "  type: direct",
            "  udp: true",
            "  ip-version: ipv4",
            "  interface-name: \(interface)",
        ]
        lines.insert(contentsOf: block, at: end)
        return lines.joined(separator: "\n")
    }

    private static func upsertInternalRules(_ source: String, internalDomains: [String]) throws -> String {
        var lines = source.components(separatedBy: "\n")
        guard let start = lines.firstIndex(where: {
            indentation(of: $0) == 0 && $0.trimmingCharacters(in: .whitespaces) == "rules:"
        }) else {
            throw BridgeError.unsupportedConfig("运行配置没有 rules 段")
        }

        var end = sectionEnd(lines, start: start, baseIndent: 0)
        let managedDomains = Set(internalDomains)
        for index in stride(from: end - 1, through: start + 1, by: -1) {
            let trimmed = lines[index].trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("-") else { continue }
            let rule = trimmed.dropFirst().trimmingCharacters(in: .whitespaces)
            let fields = rule.split(separator: ",", omittingEmptySubsequences: false)
            if fields.count >= 3,
               fields[0] == "DOMAIN-SUFFIX",
               managedDomains.contains(String(fields[1]))
            {
                lines.remove(at: index)
                end -= 1
            }
        }

        let rules = internalDomains.map {
            "- DOMAIN-SUFFIX,\($0),\(BridgeConstants.proxyName)"
        }
        lines.insert(contentsOf: rules, at: start + 1)
        return lines.joined(separator: "\n")
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

    private static func jsonString<T: Encodable>(_ value: T) throws -> String {
        let data = try JSONEncoder().encode(value)
        return String(decoding: data, as: UTF8.self)
    }
}
