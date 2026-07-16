import Dispatch
import Foundation

struct CommandResult: Sendable {
    let exitCode: Int32
    let standardOutput: String
    let standardError: String
}

enum Shell {
    static func run(
        _ executable: String,
        _ arguments: [String],
        standardInput: Data? = nil
    ) throws -> CommandResult {
        let process = Process()
        let stdout = Pipe()
        let stderr = Pipe()
        let stdin = standardInput == nil ? nil : Pipe()

        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardOutput = stdout
        process.standardError = stderr
        process.standardInput = stdin

        do {
            try process.run()
        } catch {
            throw BridgeError.commandFailed("\(executable): \(error.localizedDescription)")
        }

        let stdoutBox = DataBox()
        let stderrBox = DataBox()
        let readers = DispatchGroup()
        readers.enter()
        DispatchQueue.global(qos: .utility).async {
            stdoutBox.value = stdout.fileHandleForReading.readDataToEndOfFile()
            readers.leave()
        }
        readers.enter()
        DispatchQueue.global(qos: .utility).async {
            stderrBox.value = stderr.fileHandleForReading.readDataToEndOfFile()
            readers.leave()
        }

        if let standardInput, let stdin {
            try? stdin.fileHandleForWriting.write(contentsOf: standardInput)
            try? stdin.fileHandleForWriting.close()
        }

        process.waitUntilExit()
        readers.wait()

        return CommandResult(
            exitCode: process.terminationStatus,
            standardOutput: String(decoding: stdoutBox.value, as: UTF8.self),
            standardError: String(decoding: stderrBox.value, as: UTF8.self)
        )
    }
}

private final class DataBox: @unchecked Sendable {
    var value = Data()
}
