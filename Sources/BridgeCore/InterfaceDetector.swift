import Foundation

public struct InterfaceDetector: Sendable {
    public init() {}

    public func detect(dnsServers: [String]) throws -> InterfaceDetection {
        var invalidCandidates: [String] = []

        for target in dnsServers {
            let arguments = target.contains(":")
                ? ["-n", "get", "-inet6", target]
                : ["-n", "get", target]
            let route = try Shell.run("/sbin/route", arguments)
            guard route.exitCode == 0,
                  let interface = Self.parseInterface(fromRouteOutput: route.standardOutput)
            else {
                continue
            }

            guard interface.range(of: #"^utun\d+$"#, options: .regularExpression) != nil else {
                invalidCandidates.append(interface)
                continue
            }

            let ifconfig = try Shell.run("/sbin/ifconfig", [interface])
            guard ifconfig.exitCode == 0 else {
                invalidCandidates.append(interface)
                continue
            }
            let addresses = Self.parseIPAddresses(fromIfconfigOutput: ifconfig.standardOutput)
            if Self.isClashInterface(addresses: addresses) {
                throw BridgeError.clashInterfaceDetected(interface)
            }

            return InterfaceDetection(name: interface, addresses: addresses, routeTarget: target)
        }

        if let candidate = invalidCandidates.first {
            throw BridgeError.invalidVPNInterface(candidate)
        }
        throw BridgeError.vpnRouteMissing(dnsServers)
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
}
