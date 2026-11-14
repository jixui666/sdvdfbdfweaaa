import Foundation
import Darwin

/// WQ Files 的 worse_query 桥接层。
///
/// iOS 26.6.1 起，MCM（`MCMActivateContainerPath`）和 `FileManager` 对其它 app
/// 的数据容器基本失效。这里用 kolbicz/WQFiles 的 worse_query 实现：
///
///   * `wq_grant(path)` —— 为单个路径申请沙盒扩展，之后 `wq_list` / `wq_read`
///     可以跨容器读写；`FileManager` 在扩展生效后通常也能直接读。
///   * `wq_enumerate(path, 0, …)` —— 用 `fsgetpath` 暴力扫 inode 找出目录的直接
///     子项。**不受沙盒门控、不需要 token、不依赖 LaunchServices 数据库**，
///     这是 27.x 上唯一能拿到 app 容器列表的途径。
///   * `wq_container_label(path)` —— 容器路径 → bundle id / group id。
///
/// 索引策略：`bundleID -> 容器路径` 在后台线程扫描并落盘缓存
/// （`Documents/wq-container-index.json`）。首次扫描慢，之后直接读缓存；
/// 采集流程绝不因为扫描而阻塞。
enum WQContainerBridge {

    static var isSupported: Bool {
        let v = AppInfo.versionTuple
        if v.major != 26 { return v.major > 26 }
        if v.minor != 6 { return v.minor > 6 }
        return v.patch >= 1
    }

    // MARK: - 索引状态

    private static let indexLock = NSLock()
    private static var bundleIndex: [String: String] = [:]
    private static var groupIndex: [String: String] = [:]
    private static var scanStarted = false
    private static var groupScanDone = false
    private static var prepared = false

    /// 扫描完成后置位，采集侧据此重跑一轮。
    static var isIndexReady: Bool {
        indexLock.lock()
        defer { indexLock.unlock() }
        return !bundleIndex.isEmpty
    }

    static var indexedAppCount: Int {
        indexLock.lock()
        defer { indexLock.unlock() }
        return bundleIndex.count
    }

    private static var cacheURL: URL {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSTemporaryDirectory())
        return docs.appendingPathComponent("wq-container-index.json")
    }

    // MARK: - 启动扫描

    /// 幂等；在任何入口调用都安全。真正的扫描在后台队列。
    static func prepareIfNeeded() {
        guard isSupported else { return }
        indexLock.lock()
        if prepared {
            indexLock.unlock()
            return
        }
        prepared = true
        indexLock.unlock()
        startBackgroundScanIfNeeded()
    }

    /// 后台扫 app 容器。首次慢（fsgetpath 暴力扫 inode），结果落盘。
    static func startBackgroundScanIfNeeded() {
        guard isSupported else { return }
        indexLock.lock()
        if scanStarted {
            indexLock.unlock()
            return
        }
        scanStarted = true
        indexLock.unlock()

        loadCachedIndex()
        buildGroupIndex()

        DispatchQueue.global(qos: .utility).async {
            indexLock.lock()
            let cached = bundleIndex.count
            indexLock.unlock()
            if cached > 0 {
                log("wq: using cached index — \(cached) app containers")
                return
            }

            let t0 = Date()
            log("wq: inode scan start — /var/mobile/Containers/Data/Application")
            let cancel = WQScanCancellation()
            let paths = (wq_enumerate(
                "/var/mobile/Containers/Data/Application", 0, cancel, nil
            ) as? [String]) ?? []
            let secs = Int(Date().timeIntervalSince(t0))
            log("wq: inode scan done — paths=\(paths.count) in \(secs)s")

            var added = 0
            for p in paths {
                guard let label = wq_container_label(p), !label.isEmpty else { continue }
                indexLock.lock()
                bundleIndex[label] = p
                indexLock.unlock()
                added += 1
            }
            log("wq: inode scan labelled=\(added) total=\(bundleIndex.count)")
            saveCachedIndex()

            if added > 0 {
                DispatchQueue.main.async {
                    NotificationCenter.default.post(
                        name: Notification.Name("WQContainerIndexReady"), object: nil
                    )
                }
            }
        }
    }

    // MARK: - App Group 索引（快，同步即可）

    private static func buildGroupIndex() {
        indexLock.lock()
        if groupScanDone {
            indexLock.unlock()
            return
        }
        groupScanDone = true
        indexLock.unlock()

        let groupRoot = "/var/mobile/Containers/Shared/AppGroup"
        var count = 0
        if let names = wq_list(groupRoot, nil) as? [String] {
            for name in names where !name.hasPrefix(".") {
                let p = groupRoot + "/" + name
                if let label = wq_container_label(p), !label.isEmpty {
                    indexLock.lock()
                    groupIndex[label] = p
                    indexLock.unlock()
                    count += 1
                }
            }
        }
        log("wq: group index \(count) entries")
    }

    // MARK: - 缓存

    private static func loadCachedIndex() {
        guard let data = try? Data(contentsOf: cacheURL),
              let dict = try? JSONDecoder().decode([String: String].self, from: data),
              !dict.isEmpty else { return }
        indexLock.lock()
        bundleIndex = dict
        indexLock.unlock()
        log("wq: loaded \(dict.count) containers from cache")
    }

    private static func saveCachedIndex() {
        indexLock.lock()
        let snapshot = bundleIndex
        indexLock.unlock()
        guard let data = try? JSONEncoder().encode(snapshot) else { return }
        try? data.write(to: cacheURL, options: .atomic)
        log("wq: cached \(snapshot.count) containers")
    }

    // MARK: - 查询

    /// bundle id → 数据容器绝对路径。命中缓存直接返回；未命中时触发后台扫描，
    /// 本次返回 nil（绝不在调用线程上扫描）。
    static func containerPath(forBundleID bundleID: String) -> String? {
        guard isSupported, !bundleID.isEmpty else { return nil }
        indexLock.lock()
        let hit = bundleIndex[bundleID]
        indexLock.unlock()
        if let hit { return hit }

        if bundleID.hasPrefix("group.") || bundleID.hasPrefix("systemgroup.") {
            buildGroupIndex()
            indexLock.lock()
            let gh = groupIndex[bundleID]
            indexLock.unlock()
            if let gh { return gh }
            // group.<host> 回退到宿主 app 容器
            if bundleID.hasPrefix("group.") {
                let host = String(bundleID.dropFirst("group.".count))
                indexLock.lock()
                let hh = bundleIndex[host]
                indexLock.unlock()
                if let hh { return hh }
            }
        }
        startBackgroundScanIfNeeded()
        return nil
    }

    /// LaunchServices / inode 扫描得到的全部容器路径（只要路径）。
    /// 供 enumerateInstalledBundleIDsViaWQ 使用；索引未建好时返回空数组，
    /// 不会阻塞。
    static func containerPaths() -> [String] {
        guard isSupported else { return [] }
        prepareIfNeeded()
        indexLock.lock()
        let paths = bundleIndex.values.map { $0 }
        indexLock.unlock()
        return paths
    }

    /// 全部已知 app 容器（bundle id, 路径）。
    static func allContainers() -> [(bundleID: String, path: String)] {
        guard isSupported else { return [] }
        prepareIfNeeded()
        indexLock.lock()
        let snap = bundleIndex
        indexLock.unlock()
        return snap.map { ($0.key, $0.value) }.sorted { $0.0 < $1.0 }
    }

    static func bundleID(forContainer path: String) -> String? {
        guard isSupported else { return nil }
        // 已知路径直接查；未知路径问库（lsd 读不到时返回 nil，不算错）
        indexLock.lock()
        let byPath = bundleIndex.first { $0.value == path }?.key
        indexLock.unlock()
        if let byPath { return byPath }
        return wq_bundle_id_for_container(path)
    }

    static func displayName(_ bundleID: String) -> String? {
        guard isSupported else { return nil }
        return wq_display_name(bundleID)
    }

    // MARK: - 文件访问

    @discardableResult
    static func grant(_ path: String) -> Bool {
        guard isSupported else { return false }
        return wq_grant(path)
    }

    static func list(_ dir: String) -> [String]? {
        guard isSupported else { return nil }
        var err: NSString?
        guard let r = wq_list(dir, &err) as? [String] else {
            if let err { log("wq: list failed \(dir): \(err)") }
            return nil
        }
        return r
    }

    static func read(_ path: String, maxBytes: Int = 0) -> Data? {
        guard isSupported else { return nil }
        var err: NSString?
        guard let d = wq_read(path, UInt(maxBytes), &err) as? Data else {
            if let err { log("wq: read failed \(path): \(err)") }
            return nil
        }
        return d
    }

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

    static func copyToLocal(_ path: String, dest: String) -> Bool {
        guard isSupported else { return false }
        var err: NSString?
        let ok = wq_copy_to_local(path, dest, &err)
        if !ok, let err { log("wq: copyToLocal failed \(path): \(err)") }
        return ok
    }

    static func ensureReadable(_ path: String) -> Bool {
        guard isSupported else { return true }
        if isDirectory(path) || FileManager.default.fileExists(atPath: path) {
            return true
        }
        _ = grant(path)
        return isDirectory(path) || FileManager.default.fileExists(atPath: path)
    }
}
