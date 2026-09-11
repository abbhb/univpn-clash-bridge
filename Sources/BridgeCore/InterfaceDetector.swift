import Foundation

public struct InterfaceDetector: Sendable {
    public init() {}

    public func detect(dnsServers: [String]) throws -> InterfaceDetection {
        var nonVPNCandidates: [String] = []
        var tunnelCandidates: [InterfaceDetection] = []
        var probeFailures: [String] = []

        for target in dnsServers {
            let arguments = target.contains(":")
                ? ["-n", "get", "-inet6", target]
                : ["-n", "get", target]
            let route = try Shell.run("/sbin/route", arguments)
            if route.exitCode != 0 {
                if Self.isExpectedRouteMiss(
                    exitCode: route.exitCode,
                    standardOutput: route.standardOutput,
                    standardError: route.standardError
                ) {
                    continue
                }
                probeFailures.append(
                    Self.failureDescription(command: "route", target: target, result: route)
                )
                continue
            }
            guard let interface = Self.parseInterface(fromRouteOutput: route.standardOutput) else {
                probeFailures.append("route 查询 \(target) 成功，但输出中没有 interface")
                continue
            }

            guard interface.range(of: #"^utun\d+$"#, options: .regularExpression) != nil else {
                nonVPNCandidates.append(interface)
                continue
            }

            let ifconfig = try Shell.run("/sbin/ifconfig", [interface])
            guard ifconfig.exitCode == 0 else {
                probeFailures.append(
                    Self.failureDescription(command: "ifconfig", target: interface, result: ifconfig)
                )
                continue
            }
            let addresses = Self.parseIPAddresses(fromIfconfigOutput: ifconfig.standardOutput)
            guard !addresses.isEmpty else {
                probeFailures.append("ifconfig \(interface) 成功，但没有可识别的 IP 地址")
                continue
            }
            tunnelCandidates.append(
                InterfaceDetection(name: interface, addresses: addresses, routeTarget: target)
            )
        }

        if let detected = Self.firstUsableVPN(in: tunnelCandidates) {
            return detected
        }
        if !probeFailures.isEmpty {
            throw BridgeError.commandFailed(probeFailures.joined(separator: "；"))
        }
        if let candidate = tunnelCandidates.first {
            throw BridgeError.clashInterfaceDetected(candidate.name)
        }
        if let candidate = nonVPNCandidates.first {
            throw BridgeError.nonVPNInterfaceDetected(candidate)
        }
        throw BridgeError.vpnRouteMissing(dnsServers)
    }

    public static func firstUsableVPN(in candidates: [InterfaceDetection]) -> InterfaceDetection? {
        candidates.first { candidate in
            candidate.name.range(of: #"^utun\d+$"#, options: .regularExpression) != nil
                && !isClashInterface(addresses: candidate.addresses)
        }
    }

    public static func parseInterface(fromRouteOutput output: String) -> String? {
        for line in output.components(separatedBy: .newlines) {
            let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
            if fields.count >= 2, fields[0] == "interface:" {
                return String(fields[1])
            }
        }
        return nil
    }

    public static func parseIPAddresses(fromIfconfigOutput output: String) -> [String] {
        output.components(separatedBy: .newlines).compactMap { line in
            let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
            guard fields.count >= 2, fields[0] == "inet" || fields[0] == "inet6" else { return nil }
            return String(fields[1])
        }
    }

    public static func isClashInterface(addresses: [String]) -> Bool {
        addresses.contains { $0 == "198.18.0.1" || $0.hasPrefix("198.18.") }
    }

    public static func isExpectedRouteMiss(
        exitCode: Int32,
        standardOutput: String,
        standardError: String
    ) -> Bool {
        guard exitCode != 0 else { return false }
        let detail = (standardOutput + "\n" + standardError).lowercased()
        let fatalMessages = [
            "operation not permitted",
            "permission denied",
            "unknown option",
            "usage:",
        ]
        if fatalMessages.contains(where: { detail.contains($0) }) {
            return false
        }
        let expectedMessages = [
            "not in table",
            "no route to host",
            "network is unreachable",
            "rtm_miss",
            "lookup failed",
        ]
        return expectedMessages.contains { detail.contains($0) }
    }

    private static func failureDescription(
        command: String,
        target: String,
        result: CommandResult
    ) -> String {
        let rawDetail = result.standardError.isEmpty ? result.standardOutput : result.standardError
        let detail = rawDetail.trimmingCharacters(in: .whitespacesAndNewlines)
        if detail.isEmpty {
            return "\(command) \(target) 退出码 \(result.exitCode)"
        }
        return "\(command) \(target) 退出码 \(result.exitCode)：\(detail)"
    }
}
