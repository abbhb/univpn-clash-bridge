import AppKit
import BridgeCore
import SwiftUI

private struct ConfigurationDraft: Sendable {
    var dnsText: String
    var domainsText: String
    var clashDirectory: String
    var dnsGuardEnabled: Bool

    init(configuration: AppConfiguration?) {
        dnsText = configuration?.dnsServers.joined(separator: "\n") ?? ""
        domainsText = configuration?.internalDomains.joined(separator: "\n") ?? ""
        clashDirectory = configuration?.clashConfigDirectory
            ?? AppConfiguration.suggestedClashConfigDirectory()
        dnsGuardEnabled = configuration?.dnsGuardEnabled ?? true
    }

    func makeConfiguration() -> AppConfiguration {
        AppConfiguration(
            dnsServers: splitValues(dnsText),
            internalDomains: splitValues(domainsText),
            clashConfigDirectory: clashDirectory,
            dnsGuardEnabled: dnsGuardEnabled
        )
    }

    private func splitValues(_ text: String) -> [String] {
        text.split(whereSeparator: { $0.isNewline || $0 == "," || $0 == ";" })
            .map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }
}

@MainActor
final class AppModel: ObservableObject {
    @Published var configuration: AppConfiguration?
    @Published var isBusy = false
    @Published var interfaceName = "未检测"
    @Published var interfaceAddresses = "-"
    @Published var statusMessage = ""
    @Published var statusKind: StatusKind = .idle
    @Published var dnsGuardStatus: DNSGuardStatus = .notInstalled
    @Published var showSettings = false

    enum StatusKind {
        case idle
        case success
        case warning
        case failure

        var color: Color {
            switch self {
            case .idle: .secondary
            case .success: .green
            case .warning: .orange
            case .failure: .red
            }
        }

        var icon: String {
            switch self {
            case .idle: "circle.dashed"
            case .success: "checkmark.circle.fill"
            case .warning: "exclamationmark.circle.fill"
            case .failure: "exclamationmark.triangle.fill"
            }
        }
    }

    init() {
        do {
            configuration = try ConfigurationStore().load()
            if let configuration {
                _ = try? ConfigurationStore().migrateLegacyBackups(for: configuration)
                statusMessage = "请先连接 VPN"
                dnsGuardStatus = DNSGuardManager().status()
            } else {
                statusMessage = "首次使用需要完成配置"
            }
        } catch {
            configuration = nil
            statusKind = .failure
            statusMessage = error.localizedDescription
        }
    }

    fileprivate func saveConfiguration(_ draft: ConfigurationDraft) {
        guard !isBusy else { return }
        isBusy = true
        statusKind = .idle
        statusMessage = "正在保存配置..."
        let candidate = draft.makeConfiguration()

        Task {
            let result = await Task.detached(priority: .userInitiated) {
                do {
                    let store = ConfigurationStore()
                    let normalized = try store.save(candidate)
                    _ = try store.migrateLegacyBackups(for: normalized)

                    let guardManager = DNSGuardManager()
                    var warning: String?
                    if normalized.dnsGuardEnabled {
                        do {
                            try guardManager.installOrUpdate(configuration: normalized)
                        } catch {
                            warning = error.localizedDescription
                        }
                    } else if guardManager.status() != .notInstalled {
                        do {
                            try guardManager.uninstall()
                        } catch {
                            warning = error.localizedDescription
                        }
                    }

                    return ConfigurationOperationResult(
                        configuration: normalized,
                        guardStatus: guardManager.status(),
                        warning: warning,
                        errorMessage: nil
                    )
                } catch {
                    return ConfigurationOperationResult(
                        configuration: nil,
                        guardStatus: .notInstalled,
                        warning: nil,
                        errorMessage: error.localizedDescription
                    )
                }
            }.value

            isBusy = false
            if let configuration = result.configuration {
                self.configuration = configuration
                dnsGuardStatus = result.guardStatus
                showSettings = false
                if let warning = result.warning {
                    statusKind = .warning
                    statusMessage = "配置已保存；\(warning)"
                } else {
                    statusKind = .success
                    statusMessage = "配置已保存"
                }
            } else {
                statusKind = .failure
                statusMessage = result.errorMessage ?? "配置保存失败"
            }
        }
    }

    func detectAndUpdate() {
        guard !isBusy, let configuration else { return }
        isBusy = true
        statusKind = .idle
        statusMessage = "正在检测 VPN DNS 路由..."

        Task {
            let result = await Task.detached(priority: .userInitiated) {
                do {
                    let outcome = try BridgeService(configuration: configuration).update()
                    return UpdateOperationResult(outcome: outcome, errorMessage: nil)
                } catch {
                    return UpdateOperationResult(outcome: nil, errorMessage: error.localizedDescription)
                }
            }.value

            isBusy = false
            if let outcome = result.outcome {
                interfaceName = outcome.interface.name
                interfaceAddresses = outcome.interface.addresses.isEmpty
                    ? "无可见 IP 地址"
                    : outcome.interface.addresses.joined(separator: ", ")
                statusKind = .success
                statusMessage = outcome.runtimeReloaded
                    ? "全局配置已更新，Mihomo 已热重载"
                    : "全局配置已更新；Clash Verge 启动后自动生效"
            } else {
                statusKind = .failure
                statusMessage = result.errorMessage ?? "更新失败"
            }
            dnsGuardStatus = DNSGuardManager().status()
        }
    }

    func installDNSGuard() {
        guard !isBusy, let configuration else { return }
        isBusy = true
        statusKind = .idle
        statusMessage = "正在安装 DNS 根域防护..."

        Task {
            let result = await Task.detached(priority: .userInitiated) {
                do {
                    let manager = DNSGuardManager()
                    try manager.installOrUpdate(configuration: configuration)
                    return GuardOperationResult(status: manager.status(), errorMessage: nil)
                } catch {
                    return GuardOperationResult(
                        status: DNSGuardManager().status(),
                        errorMessage: error.localizedDescription
                    )
                }
            }.value

            isBusy = false
            dnsGuardStatus = result.status
            if let errorMessage = result.errorMessage {
                statusKind = .failure
                statusMessage = errorMessage
            } else {
                statusKind = .success
                statusMessage = "DNS 根域防护已运行"
            }
        }
    }

    func openBackups() {
        guard let paths = try? AppDataPaths.current() else { return }
        NSWorkspace.shared.open(paths.backups)
    }
}

private struct ConfigurationOperationResult: Sendable {
    let configuration: AppConfiguration?
    let guardStatus: DNSGuardStatus
    let warning: String?
    let errorMessage: String?
}

private struct UpdateOperationResult: Sendable {
    let outcome: UpdateOutcome?
    let errorMessage: String?
}

private struct GuardOperationResult: Sendable {
    let status: DNSGuardStatus
    let errorMessage: String?
}

struct RootView: View {
    @StateObject private var model = AppModel()

    var body: some View {
        Group {
            if model.configuration == nil {
                ConfigurationEditor(model: model, configuration: nil, isFirstRun: true)
            } else {
                DashboardView(model: model)
            }
        }
        .sheet(isPresented: $model.showSettings) {
            ConfigurationEditor(
                model: model,
                configuration: model.configuration,
                isFirstRun: false
            )
        }
    }
}

private struct DashboardView: View {
    @ObservedObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(spacing: 12) {
                Image(nsImage: NSApplication.shared.applicationIconImage)
                    .resizable()
                    .scaledToFit()
                    .frame(width: 48, height: 48)

                VStack(alignment: .leading, spacing: 2) {
                    Text("UniVPN Clash Bridge")
                        .font(.title2.weight(.semibold))
                    Text("VPN 出口同步")
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button {
                    model.showSettings = true
                } label: {
                    Image(systemName: "gearshape")
                }
                .help("设置")
                .disabled(model.isBusy)
            }

            GroupBox {
                Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 11) {
                    GridRow {
                        Text("接口").foregroundStyle(.secondary)
                        Text(model.interfaceName).font(.system(.body, design: .monospaced))
                    }
                    GridRow {
                        Text("地址").foregroundStyle(.secondary)
                        Text(model.interfaceAddresses)
                            .font(.system(.body, design: .monospaced))
                            .lineLimit(2)
                    }
                    GridRow {
                        Text("DNS 防护").foregroundStyle(.secondary)
                        HStack(spacing: 6) {
                            Circle()
                                .fill(model.dnsGuardStatus == .running ? Color.green : Color.orange)
                                .frame(width: 8, height: 8)
                            Text(model.dnsGuardStatus.displayName)
                        }
                    }
                    GridRow {
                        Text("分流范围").foregroundStyle(.secondary)
                        Text("\(model.configuration?.internalDomains.count ?? 0) 个域名后缀")
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.vertical, 4)
            }

            HStack(alignment: .top, spacing: 9) {
                Image(systemName: model.statusKind.icon)
                    .foregroundStyle(model.statusKind.color)
                    .frame(width: 18)
                Text(model.statusMessage)
                    .foregroundStyle(model.statusKind == .idle ? .secondary : .primary)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            Spacer(minLength: 0)

            HStack(spacing: 10) {
                Button {
                    model.openBackups()
                } label: {
                    Image(systemName: "folder")
                }
                .help("打开应用备份目录")
                .disabled(model.isBusy)

                if model.configuration?.dnsGuardEnabled == true,
                   model.dnsGuardStatus != .running
                {
                    Button {
                        model.installDNSGuard()
                    } label: {
                        Label("安装 DNS 防护", systemImage: "shield.lefthalf.filled")
                    }
                    .disabled(model.isBusy)
                }

                Spacer()

                Button {
                    model.detectAndUpdate()
                } label: {
                    if model.isBusy {
                        ProgressView().controlSize(.small)
                        Text("处理中")
                    } else {
                        Label("检测并更新", systemImage: "arrow.triangle.2.circlepath")
                    }
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(model.isBusy)
                .keyboardShortcut(.defaultAction)
                .help("探测 VPN 接口并同步 Clash Verge 全局配置")
            }
        }
        .padding(22)
        .frame(width: 560, height: 430)
    }
}

private struct ConfigurationEditor: View {
    @ObservedObject var model: AppModel
    let isFirstRun: Bool

    @State private var draft: ConfigurationDraft

    init(model: AppModel, configuration: AppConfiguration?, isFirstRun: Bool) {
        self.model = model
        self.isFirstRun = isFirstRun
        _draft = State(initialValue: ConfigurationDraft(configuration: configuration))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                Image(nsImage: NSApplication.shared.applicationIconImage)
                    .resizable()
                    .scaledToFit()
                    .frame(width: 44, height: 44)
                VStack(alignment: .leading, spacing: 2) {
                    Text(isFirstRun ? "首次配置" : "设置")
                        .font(.title2.weight(.semibold))
                    Text("UniVPN Clash Bridge")
                        .foregroundStyle(.secondary)
                }
            }

            VStack(alignment: .leading, spacing: 6) {
                Text("VPN DNS / 探测 IP").font(.headline)
                TextEditor(text: $draft.dnsText)
                    .font(.system(.body, design: .monospaced))
                    .frame(height: 72)
                    .padding(5)
                    .background(Color(nsColor: .textBackgroundColor))
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                Text("每行一个地址，用于识别 VPN 接口和转发内网 DNS。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            VStack(alignment: .leading, spacing: 6) {
                Text("内网域名后缀").font(.headline)
                TextEditor(text: $draft.domainsText)
                    .font(.system(.body, design: .monospaced))
                    .frame(height: 92)
                    .padding(5)
                    .background(Color(nsColor: .textBackgroundColor))
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                Text("每行一个域名；无需填写 +. 或 *. 前缀。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            VStack(alignment: .leading, spacing: 6) {
                Text("Clash Verge 配置目录").font(.headline)
                HStack(spacing: 8) {
                    TextField("配置目录", text: $draft.clashDirectory)
                        .font(.system(.body, design: .monospaced))
                    Button {
                        chooseClashDirectory()
                    } label: {
                        Image(systemName: "folder")
                    }
                    .help("选择 Clash Verge 配置目录")
                }
            }

            Toggle("阻止 VPN 接管系统根 DNS", isOn: $draft.dnsGuardEnabled)
                .help("开启后仅移除匹配已配置 DNS IP 的 VPN 根域解析器")

            if model.statusKind == .failure || model.statusKind == .warning {
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: model.statusKind.icon)
                        .foregroundStyle(model.statusKind.color)
                    Text(model.statusMessage)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            HStack {
                if !isFirstRun {
                    Button("取消") {
                        model.showSettings = false
                    }
                    .disabled(model.isBusy)
                }
                Spacer()
                Button {
                    model.saveConfiguration(draft)
                } label: {
                    if model.isBusy {
                        ProgressView().controlSize(.small)
                        Text("保存中")
                    } else {
                        Text(isFirstRun ? "保存并继续" : "保存")
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(
                    model.isBusy
                        || draft.dnsText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                        || draft.domainsText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                        || draft.clashDirectory.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                )
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(22)
        .frame(width: 620, height: 610)
    }

    private func chooseClashDirectory() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.directoryURL = URL(fileURLWithPath: draft.clashDirectory)
        if panel.runModal() == .OK, let selected = panel.url {
            draft.clashDirectory = selected.path
        }
    }
}

@main
struct UniVPNClashBridgeApp: App {
    var body: some Scene {
        WindowGroup {
            RootView()
        }
        .defaultSize(width: 620, height: 610)
        .windowResizability(.contentSize)
        .commands {
            CommandGroup(replacing: .newItem) {}
        }
    }
}
