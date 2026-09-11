import Darwin
import Foundation

public struct DNSReachabilityProbe {
    public init() {}

    public func availableServers(_ servers: [String]) throws -> [String] {
        try servers.filter { try probe($0) }
    }

    private func interface(for server: String) throws -> String {
        func route(_ target: String) throws -> String {
            let result = try Shell.run("/sbin/route", ["-n", "get", target])
            guard result.exitCode == 0,
                  let name = InterfaceDetector.parseInterface(fromRouteOutput: result.standardOutput) else {
                throw BridgeError.commandFailed("无法确定 DNS 探测出口")
            }
            return name
        }
        func isClash(_ name: String) throws -> Bool {
            let result = try Shell.run("/sbin/ifconfig", [name])
            guard result.exitCode == 0 else { throw BridgeError.commandFailed("无法检查 DNS 探测出口") }
            return InterfaceDetector.isClashInterface(addresses:
                InterfaceDetector.parseIPAddresses(fromIfconfigOutput: result.standardOutput))
        }
        var name = try route(server)
        if try isClash(name) { name = try route("default") }
        guard try !isClash(name) else {
            throw BridgeError.commandFailed("未找到绕过 Clash TUN 的 DNS 探测出口")
        }
        return name
    }

    private func probe(_ server: String) throws -> Bool {
        let name = try interface(for: server)
        var hints = addrinfo()
        hints.ai_flags = AI_NUMERICHOST
        hints.ai_socktype = SOCK_DGRAM
        hints.ai_protocol = IPPROTO_UDP
        var address: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(server, "53", &hints, &address) == 0, let address else {
            throw BridgeError.commandFailed("DNS 探测地址无效")
        }
        defer { freeaddrinfo(address) }
        let info = address.pointee
        let fd = socket(info.ai_family, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { throw BridgeError.commandFailed("无法创建 DNS 探测 socket") }
        defer { close(fd) }
        var index = if_nametoindex(name)
        let level = info.ai_family == AF_INET6 ? IPPROTO_IPV6 : IPPROTO_IP
        let option = info.ai_family == AF_INET6 ? IPV6_BOUND_IF : IP_BOUND_IF
        guard index != 0, setsockopt(fd, level, option, &index, socklen_t(MemoryLayout.size(ofValue: index))) == 0 else {
            throw BridgeError.commandFailed("无法绑定 DNS 探测出口")
        }
        var timeout = timeval(tv_sec: 2, tv_usec: 0)
        guard setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout.size(ofValue: timeout))) == 0 else {
            throw BridgeError.commandFailed("无法设置 DNS 探测超时")
        }
        if connect(fd, info.ai_addr, info.ai_addrlen) != 0 { return try networkFailure() }
        let id = UInt16.random(in: 0...UInt16.max)
        // Non-recursive root NS question. Any matching DNS response proves reachability.
        let query: [UInt8] = [UInt8(id >> 8), UInt8(id & 255), 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1]
        let sent = query.withUnsafeBytes { send(fd, $0.baseAddress, $0.count, 0) }
        guard sent == query.count else { return try networkFailure() }
        var response = [UInt8](repeating: 0, count: 4096)
        let count = response.withUnsafeMutableBytes { recv(fd, $0.baseAddress, $0.count, 0) }
        guard count >= 0 else { return try networkFailure() }
        return Self.hasDNSResponse(Array(response.prefix(count)), transactionID: id)
    }

    private func networkFailure() throws -> Bool {
        let code = errno
        if [EAGAIN, ETIMEDOUT, ECONNREFUSED, EHOSTUNREACH, ENETUNREACH, EHOSTDOWN, ENETDOWN].contains(code) {
            return false
        }
        throw BridgeError.commandFailed("DNS 探测 socket 错误（errno \(code)）")
    }

    public static func hasDNSResponse(_ packet: [UInt8], transactionID: UInt16) -> Bool {
        packet.count >= 12 && packet[0] == UInt8(transactionID >> 8)
            && packet[1] == UInt8(transactionID & 255) && packet[2] & 0xf8 == 0x80
    }
}
