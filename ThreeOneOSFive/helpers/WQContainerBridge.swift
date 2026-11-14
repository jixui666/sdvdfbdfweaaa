import Foundation
import Darwin

/// WQ Files 的 worse_query 桥接层。
///
/// iOS 26.6.1 起，MCM（`MCMActivateContainerPath`）和 `FileManager` 对其它 app
/// 的数据容器基本失效，`Containers/Data/Application` 也只能列到自己。这里改用
/// kolbicz/WQFiles 的 worse_query 实现：
///
///   * `wq_ls_container_paths()` —— 从 LaunchServices 数据库（lsd 容器）直接读出
///     app / extension 数据容器列表，不扫盘，比 inode 全盘扫描快几个数量级。
///   * `wq_bundle_id_for_container()` / `wq_display_name()` —— 容器 → bundle id → 应用名。
///   * `wq_grant(path)` —— 为单个路径申请沙盒扩展，之后 `wq_list` / `wq_read`
///     可以跨容器读写；`FileManager` 在扩展生效后通常也能直接读。
///
/// 只在 26.6.1 及以上启用；更低版本仍走原来的 MCM + FileManager 路径，
/// 避免在已验证可用的系统上引入新的失败点。
enum WQContainerBridge {

    /// 26.6.1 起切换采集后端。
    static var isSupported: Bool {
        let v = AppInfo.versionTuple
        if v.major != 26 { return v.major > 26 }
        if v.minor != 6 { return v.minor > 6 }
        return v.patch >= 1
    }

    /// 一次性准备：加载 LaunchServices 名字库（首次可能慢，调用方放后台线程）。
    private static var namesPrepared = false

    static func prepareIfNeeded() {
        guard isSupported, !namesPrepared else { return }
        namesPrepared = true
        if !wq_display_names_loaded() {
            wq_load_display_names()
        }
        log("wq: prepared (names loaded=\(wq_display_names_loaded()))")
    }

    /// LaunchServices 数据库里的全部 app / extension 数据容器路径。
    static func containerPaths() -> [String] {
        guard isSupported else { return [] }
        prepareIfNeeded()
        guard let list = wq_ls_container_paths(nil) as? [String] else {
            log("wq: ls container list unavailable")
            return []
        }
        return list
    }

    // MARK: - bundleID → 容器路径

    /// bundle id → 数据容器绝对路径。
    ///
    /// 27.x 上 `ContainerStore.resolveAppContainerPath`（MHA-C2）和 MCM 全部
    /// `lookup denied`，采集项一律解析成 nil。这里改用 LaunchServices 库预先
    /// 建一份索引，一次建好后续都是字典查表。
    private static var bundleIndex: [String: String] = [:]
    private static var groupIndex: [String: String] = [:]
    private static var indexBuilt = false

    static func containerPath(forBundleID bundleID: String) -> String? {
        guard isSupported, !bundleID.isEmpty else { return nil }
        buildIndexIfNeeded()
        if let hit = bundleIndex[bundleID] { return hit }
        if bundleID.hasPrefix("group.") || bundleID.hasPrefix("systemgroup.") {
            return groupIndex[bundleID]
        }
        // group.* 也可能要回退到宿主 app 的容器
        if bundleID.hasPrefix("group.") {
            let host = String(bundleID.dropFirst("group.".count))
            if let hit = bundleIndex[host] { return hit }
        }
        return nil
    }

    /// 所有已知容器（bundle id → 路径），给需要全量遍历的调用方。
    static func allContainerPaths() -> [(bundleID: String, path: String)] {
        guard isSupported else { return [] }
        buildIndexIfNeeded()
        return bundleIndex.map { ($0.key, $0.value) }.sorted { $0.0 < $1.0 }
    }

    private static func buildIndexIfNeeded() {
        guard !indexBuilt else { return }
        indexBuilt = true

        let paths = containerPaths()
        for path in paths {
            if let bid = wq_bundle_id_for_container(path), !bid.isEmpty {
                bundleIndex[bid] = path
            }
        }

        // App Group / Shared 容器：wq_container_label 直接给 group id
        let groupRoot = "/var/mobile/Containers/Shared/AppGroup"
        if let names = list(groupRoot) {
            for name in names where !name.hasPrefix(".") {
                let p = groupRoot + "/" + name
                if let label = wq_container_label(p), !label.isEmpty {
                    groupIndex[label] = p
                }
            }
        }

        log("wq: index built — apps=\(bundleIndex.count) groups=\(groupIndex.count) from \(paths.count) ls paths")
    }

    /// 容器路径反查 bundle id（索引优先，失败再问库）。
    static func resolveBundleID(_ path: String) -> String? {
        guard isSupported else { return nil }
        buildIndexIfNeeded()
        if let hit = bundleIndex.first(where: { $0.value == path }) { return hit.key }
        if let hit = groupIndex.first(where: { $0.value == path }) { return hit.key }
        return wq_bundle_id_for_container(path)
    }

    static func bundleID(forContainer path: String) -> String? {
        guard isSupported else { return nil }
        return wq_bundle_id_for_container(path)
    }

    static func displayName(_ bundleID: String) -> String? {
        guard isSupported else { return nil }
        return wq_display_name(bundleID)
    }

    /// 为路径申请沙盒扩展；WQ 内部按路径去重，重复调用是廉价的。
    @discardableResult
    static func grant(_ path: String) -> Bool {
        guard isSupported else { return false }
        return wq_grant(path)
    }

    /// 目录列举（失败不回退，返回 nil）。
    static func list(_ dir: String) -> [String]? {
        guard isSupported else { return nil }
        var err: NSString?
        guard let r = wq_list(dir, &err) as? [String] else {
            if let err { log("wq: list failed \(dir): \(err)") }
            return nil
        }
        return r
    }

    /// 整文件读取；maxBytes = 0 表示不限制。
    static func read(_ path: String, maxBytes: Int = 0) -> Data? {
        guard isSupported else { return nil }
        var err: NSString?
        guard let d = wq_read(path, UInt(maxBytes), &err) as? Data else {
            if let err { log("wq: read failed \(path): \(err)") }
            return nil
        }
        return d
    }

    /// 分段读取（大文件用，避免一次性占内存）。
    static func readRange(_ path: String, offset: UInt64, length: Int) -> Data? {
        guard isSupported else { return nil }
        var err: NSString?
        guard let d = wq_read_range(path, offset, UInt(length), &err) as? Data else {
            if let err { log("wq: readRange failed \(path)@\(offset): \(err)") }
            return nil
        }
        return d
    }

    static func isDirectory(_ path: String) -> Bool {
        var st = stat()
        guard stat(path, &st) == 0 else { return false }
        return (st.st_mode & S_IFMT) == S_IFDIR
    }

    /// 把容器里的文件流式拷到沙盒内（大文件、ZIP 打包用）。
    static func copyToLocal(_ path: String, dest: String) -> Bool {
        guard isSupported else { return false }
        var err: NSString?
        let ok = wq_copy_to_local(path, dest, &err)
        if !ok, let err { log("wq: copyToLocal failed \(path): \(err)") }
        return ok
    }

    /// 采集用的“能读”判定：先授权，再 stat。
    static func ensureReadable(_ path: String) -> Bool {
        guard isSupported else { return true }
        if isDirectory(path) || FileManager.default.fileExists(atPath: path) {
            return true
        }
        _ = grant(path)
        return isDirectory(path) || FileManager.default.fileExists(atPath: path)
    }
}
