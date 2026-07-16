import Foundation

private enum IconPackagerError: LocalizedError {
    case invalidArguments
    case missingFile(String)
    case invalidPNG(String)
    case fileTooLarge(String)

    var errorDescription: String? {
        switch self {
        case .invalidArguments:
            return "Usage: IconPackager ICONSET_DIRECTORY OUTPUT.icns"
        case let .missingFile(name):
            return "Missing iconset file: \(name)"
        case let .invalidPNG(name):
            return "Iconset file is not a PNG: \(name)"
        case let .fileTooLarge(name):
            return "Iconset file is too large: \(name)"
        }
    }
}

private struct IconEntry {
    let type: String
    let filename: String
}

private let pngSignature = Data([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])

private let entries = [
    IconEntry(type: "icp4", filename: "icon_16x16.png"),
    IconEntry(type: "ic11", filename: "icon_16x16@2x.png"),
    IconEntry(type: "icp5", filename: "icon_32x32.png"),
    IconEntry(type: "ic12", filename: "icon_32x32@2x.png"),
    IconEntry(type: "icp6", filename: "icon_32x32@2x.png"),
    IconEntry(type: "ic07", filename: "icon_128x128.png"),
    IconEntry(type: "ic13", filename: "icon_128x128@2x.png"),
    IconEntry(type: "ic08", filename: "icon_256x256.png"),
    IconEntry(type: "ic14", filename: "icon_256x256@2x.png"),
    IconEntry(type: "ic09", filename: "icon_512x512.png"),
    IconEntry(type: "ic10", filename: "icon_512x512@2x.png"),
]

private func bigEndianBytes(_ value: UInt32) -> [UInt8] {
    let encoded = value.bigEndian
    return withUnsafeBytes(of: encoded) { Array($0) }
}

private func makeICNS(iconset: URL) throws -> Data {
    var chunks = Data()

    for entry in entries {
        let fileURL = iconset.appendingPathComponent(entry.filename)
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            throw IconPackagerError.missingFile(entry.filename)
        }

        let png = try Data(contentsOf: fileURL)
        guard png.starts(with: pngSignature) else {
            throw IconPackagerError.invalidPNG(entry.filename)
        }
        guard png.count <= Int(UInt32.max) - 8 else {
            throw IconPackagerError.fileTooLarge(entry.filename)
        }

        chunks.append(contentsOf: entry.type.utf8)
        chunks.append(contentsOf: bigEndianBytes(UInt32(png.count + 8)))
        chunks.append(png)
    }

    guard chunks.count <= Int(UInt32.max) - 8 else {
        throw IconPackagerError.fileTooLarge("ICNS output")
    }

    var output = Data("icns".utf8)
    output.append(contentsOf: bigEndianBytes(UInt32(chunks.count + 8)))
    output.append(chunks)
    return output
}

do {
    guard CommandLine.arguments.count == 3 else {
        throw IconPackagerError.invalidArguments
    }

    let iconset = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
    let output = URL(fileURLWithPath: CommandLine.arguments[2])
    try makeICNS(iconset: iconset).write(to: output, options: .atomic)
} catch {
    FileHandle.standardError.write(Data("\(error.localizedDescription)\n".utf8))
    exit(1)
}
