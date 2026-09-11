import Foundation

public enum BridgeConstants {
    public static let proxyName = "UNIVPN-DIRECT"
    public static let appSupportDirectoryName = "UniVPN Clash Bridge"
    public static let dnsGuardLabel = "io.github.abbhb.univpn-clash-bridge.dns-guard"
}

public struct InterfaceDetection: Sendable, Equatable {
    public let name: String
    public let addresses: [String]
    public let routeTarget: String

    public init(name: String, addresses: [String], routeTarget: String) {
        self.name = name
        self.addresses = addresses
        self.routeTarget = routeTarget
    }
}

public enum BridgeMode: Sendable, Equatable {
    case vpn
    case direct
}

public struct UpdateOutcome: Sendable, Equatable {
    public let mode: BridgeMode
    public let interface: InterfaceDetection?
    public let backupDirectory: String
    public let runtimeReloaded: Bool
    public let changedFileCount: Int

    public init(
        mode: BridgeMode,
        interface: InterfaceDetection?,
        backupDirectory: String,
        runtimeReloaded: Bool,
        changedFileCount: Int
    ) {
        self.mode = mode
        self.interface = interface
        self.backupDirectory = backupDirectory
        self.runtimeReloaded = runtimeReloaded
        self.changedFileCount = changedFileCount
    }
}

public enum DNSGuardStatus: Sendable, Equatable {
    case notInstalled
    case stopped
    case running

    public var displayName: String {
        switch self {
        case .notInstalled: "未安装"
        case .stopped: "已停止"
        case .running: "运行中"
        }
    }
}

public enum BridgeError: LocalizedError, Sendable {
    case clashHomeMissing(String)
    case requiredFileMissing(String)
    case commandFailed(String)
    case vpnRouteMissing([String])
    case nonVPNInterfaceDetected(String)
    case invalidVPNInterface(String)
    case clashInterfaceDetected(String)
    case invalidConfiguration(String)
    case unsupportedConfig(String)
    case validationFailed(String)
    case reloadFailed(String)
    case dnsGuardFailed(String)

    public var errorDescription: String? {
        switch self {
        case let .clashHomeMissing(path):
            return "找不到 Clash Verge 配置目录：\(path)"
        case let .requiredFileMissing(path):
            return "缺少必要文件：\(path)"
        case let .commandFailed(message):
            return "系统命令执行失败：\(message)"
        case let .vpnRouteMissing(targets):
            return "没有找到通往 VPN DNS 的隧道路由（\(targets.joined(separator: ", "))）"
        case let .nonVPNInterfaceDetected(name):
            return "通往 VPN DNS 的路由当前使用普通网络接口：\(name)"
        case let .invalidVPNInterface(name):
            return "路由命中了无效接口：\(name)"
        case let .clashInterfaceDetected(name):
            return "检测到的是 Clash TUN（\(name)），没有更新配置"
        case let .invalidConfiguration(message):
            return "配置无效：\(message)"
        case let .unsupportedConfig(message):
            return "配置结构无法安全更新：\(message)"
        case let .validationFailed(message):
            return "Mihomo 配置校验失败：\(message)"
        case let .reloadFailed(message):
            return "Mihomo 热重载失败，已回滚：\(message)"
        case let .dnsGuardFailed(message):
            return "DNS 根域防护操作失败：\(message)"
        }
    }
}
