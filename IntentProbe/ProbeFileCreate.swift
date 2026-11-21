import Darwin
import Foundation

/// 创建文件。看起来是最平淡的一个能力，但它回答的问题很具体：
///
/// > **我写下来的字节，落在一个什么策略的目录里？**
///
/// 和 `ProbeFS.writeProbe` 的区别在于"留不留"：那个是写一个文件、读一次、
/// 立刻 `unlink`，只回答写权限的**有无**；删掉之后就再也不能拿它做后续实验。
/// 这里创建的副本**默认留在原地**，因为真正想知道的不是"能不能写"，
/// 而是"写下来的东西还能不能被当成可执行映像映射"（`file-map-executable`）。
///
/// 这两件事必须分开问。v6 的 `execMapMatrix` 就是把它们混在一起而整组作废：
/// 正对照 `control.bundle-exec` 拿到 `DENY`，说明 `sandbox_check` 在这个
/// build 上根本答不了 `file-map-executable`，于是"全是 DENY"既不能证明能、
/// 也不能证明不能。
///
/// 所以这里的判据只有 syscall：`open` 成不成、`dlopen` 成不成。
/// `sandbox_check` 的读数照样打出来，但只当参考——理由见 `ProbeFS` 顶部那段。
enum ProbeFileCreate {

    // MARK: - 建目录

    /// `mkdir -p`，逐级建。返回 `nil` 表示"已经存在或建好了"。
    ///
    /// 不用 `FileManager.createDirectory` 的原因：它把 errno 包成 NSError，
    /// 丢掉"是哪一级失败"这个信息。而 EPERM 出现在第一级和第三级，
    /// 含义完全不同——前者是策略，后者是某一级目录的权限位。
    static func ensureDir(_ path: String) -> String? {
        if path.isEmpty || path == "/" { return nil }

        var st = stat()
        if stat(path, &st) == 0 {
            if (st.st_mode & 0o170000) == 0o040000 { return nil }
            return "ENOTDIR@\(path)"
        }

        let parent = (path as NSString).deletingLastPathComponent
        if parent != path, let e = ensureDir(parent) { return e }

        if mkdir(path, 0o755) != 0 {
            let e = errno
            if e == EEXIST { return nil }
            return "mkdir@\(path)=\(ProbeFS.err(e))"
        }
        return nil
    }

    // MARK: - 建文件

    struct Created {
        let ok: Bool
        let detail: String
    }

    /// `open(O_CREAT)` → `write` → `fsync` → `fstat` → 读回比对。
    ///
    /// 五个步骤都留读数，因为失败点不同、含义完全不同：
    ///
    /// | 读数 | 含义 |
    /// |---|---|
    /// | `open=EPERM` | 目录或文件的策略不允许建（最常见） |
    /// | `open=EROFS` | 只读卷——系统卷 firmlink 后面就是这种 |
    /// | `open=ENOSPC` | 配额。每个 App 容器有配额，写大文件会先撞这个 |
    /// | `write=...` | 建得出来但写不进去，说明限制在文件级而不是目录级 |
    /// | `readback=mismatch` | 写成功了但读回来不一样，这才叫异常 |
    static func create(at path: String,
                       data: Data,
                       mode: mode_t = 0o644,
                       overwrite: Bool = true) -> Created {
        guard !path.isEmpty else { return Created(ok: false, detail: "skip(empty)") }

        var parts: [String] = []

        // 建之前先看一眼：是"新建"还是"覆盖"。
        // 覆盖成功比新建成功弱得多——覆盖说明文件本来就在、我本来就有写权限，
        // 它证明不了"我能在别人的目录里造出新东西"。
        var pre = stat()
        let existed = stat(path, &pre) == 0
        let preStr = existed ? "exists" : "absent"
        parts.append("pre=\(preStr)")

        if !existed {
            let parent = (path as NSString).deletingLastPathComponent
            if let e = ensureDir(parent) { parts.append(e) }
        }

        var flags = O_WRONLY | O_CREAT
        flags |= overwrite ? O_TRUNC : O_EXCL

        errno = 0
        let fd = open(path, flags, mode)
        if fd < 0 {
            parts.append("open=\(ProbeFS.err(errno))")
            return Created(ok: false, detail: parts.joined(separator: " "))
        }

        var written = 0
        var werr: Int32 = 0
        data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            guard let base = raw.baseAddress else { return }
            while written < raw.count {
                let n = write(fd, base + written, raw.count - written)
                if n <= 0 { werr = errno; return }
                written += n
            }
        }

        let synced = fsync(fd) == 0
        var st = stat()
        let stated = fstat(fd, &st) == 0
        close(fd)

        if written != data.count {
            parts.append("write=\(ProbeFS.err(werr == 0 ? EIO : werr)) n=\(written)/\(data.count)")
            return Created(ok: false, detail: parts.joined(separator: " "))
        }

        parts.append("open=ok")
        parts.append("wrote=\(written)B")
        let syncStr = synced ? "ok" : "FAIL"
        parts.append("fsync=\(syncStr)")
        if stated {
            let m = String(st.st_mode & 0o7777, radix: 8)
            parts.append("stat[mode=\(m) uid=\(st.st_uid) size=\(st.st_size)]")
        }
        parts.append("readback=\(verify(path, data))")
        return Created(ok: true, detail: parts.joined(separator: " "))
    }

    /// 写完立刻读回来。这一条是给"写成功"设的门槛：
    /// 在只读卷、配额耗尽、或某些 FUSE 类文件系统上，`write` 返回的字节数
    /// 可能比实际落盘的多。只信 `write` 的返回值会把这类情况读成成功。
    private static func verify(_ path: String, _ data: Data) -> String {
        guard data.count <= 1 << 20 else { return "skip(>1MB)" }
        guard let got = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
            return "unreadable"
        }
        if got.count != data.count { return "size-mismatch(\(got.count)/\(data.count))" }
        return got == data ? "match" : "content-mismatch"
    }

    private static func removeFile(_ path: String) -> String {
        if unlink(path) == 0 { return "ok" }
        return ProbeFS.err(errno)
    }

    // MARK: - 单点：建 + 问策略 + 可选真加载

    /// `tryLoad` 只在载荷确实是个 Mach-O 时打开，否则 `dlopen` 只会回一句
    /// "not a mach-o file"，把真正的读数淹掉。
    static func createAndReport(_ path: String,
                                data: Data,
                                keep: Bool = true,
                                tryLoad: Bool = false) -> String {
        let c = create(at: path, data: data)
        var parts = [c.detail]

        if c.ok {
            parts.append("sbx_create=\(ProbeFS.sandboxVerdict("file-write-create", path))")
            parts.append("exec=\(ProbeFS.sandboxVerdict("file-map-executable", path))")
            if tryLoad {
                // 判据在这里，不在上面那行 exec=
                parts.append("dlopen=\(ProbeDylib.load(path))")
            }
            if !keep { parts.append("cleanup=\(removeFile(path))") }
        }
        return parts.joined(separator: " ")
    }

    // MARK: - 路径拼装

    /// 三条规则，覆盖三种用法：
    ///  - `dir` 空、`name` 有值 → 落在自己的 `tmp/`
    ///  - `dir` 有值、`name` 有值 → `dir/name`
    ///  - `dir` 有值、`name` 空   → `dir` 整个当完整文件路径用
    ///
    /// 相对路径一律按**容器根**解析，不按 cwd。App 的 cwd 是 `/`，
    /// 让它去解释相对路径只会得到一个看不懂的 ENOENT。
    static func resolve(dir: String, name: String) -> String {
        var base = dir.isEmpty ? NSTemporaryDirectory() : dir
        if !base.hasPrefix("/") {
            base = (NSHomeDirectory() as NSString).appendingPathComponent(base)
        }
        if name.isEmpty { return base }
        let b = base.hasSuffix("/") ? String(base.dropLast()) : base
        return (b as NSString).appendingPathComponent(name)
    }

    // MARK: - 矩阵：哪些目录"我能写"

    /// 候选目录：**我可能能写、而且写了有意义**的地方。
    ///
    /// 顺序有意义：先自己的容器（预期全绿，作为"探针本身没坏"的证明），
    /// 再系统侧（预期全红），最后是负对照。中间出现任何一个绿，才值得看。
    static func candidateDirs() -> [(String, String)] {
        var out: [(String, String)] = []
        func add(_ label: String, _ path: String?) {
            guard let p = path, !p.isEmpty else { return }
            out.append((label, p))
        }

        let home = NSHomeDirectory()

        // ---- 基线：这些必须全绿，否则是探针自己出了问题 ----
        add("tmp", NSTemporaryDirectory())
        add("Documents", FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first?.path)
        add("Library", FileManager.default.urls(for: .libraryDirectory, in: .userDomainMask).first?.path)
        add("Caches", FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first?.path)
        add("home", home)
        add("home/Library/Preferences", (home as NSString).appendingPathComponent("Library/Preferences"))
        add("home/Library/Application Support",
            (home as NSString).appendingPathComponent("Library/Application Support"))

        // ---- 系统侧：理论上不该让我写，全红是正常的 ----
        add("/tmp", "/tmp")
        add("/private/var/tmp", "/private/var/tmp")
        add("/private/var/mobile/Media", "/private/var/mobile/Media")
        add("/private/var/mobile/Media/DCIM", "/private/var/mobile/Media/DCIM")
        add("/private/var/mobile/Library/Caches", "/private/var/mobile/Library/Caches")
        add("/private/etc", "/private/etc")
        add("/usr/lib", "/usr/lib")
        add("/Library/Caches", "/Library/Caches")
        add("/Applications", "/Applications")

        // v6 扫出来的唯一一个 777 目录（uid=0 gid=0 mode=777）。
        // 权限位已经允许任何人写，剩下的只有沙箱这一层——所以它是整张表里
        // 唯一"只差一步"的候选，必须在名单里。
        add("/private/preboot/Cryptexes", "/private/preboot/Cryptexes")
        add("/private/preboot/Cryptexes/OS/usr/lib", "/private/preboot/Cryptexes/OS/usr/lib")

        // ---- 负对照：bundle 是只读的 ----
        // 这条必须 FAIL。它 FAIL 才说明上面那些 "open=ok" 不是探针在骗自己。
        add("bundle(负对照)", Bundle.main.bundlePath)

        return out
    }

    /// 每个候选目录各建一份同名文件。
    ///
    /// `keep=false` 是默认值：矩阵会往十几个目录里扔文件，其中包含系统目录，
    /// 万一某个真的写成功了，不该留下垃圾。需要事后检查的，把 `keep` 打开。
    ///
    /// `dlopen` 一定排在 `cleanup` 前面——顺序反了就是在测一个已经删掉的文件。
    static func matrix(name: String = "probe-created.bin",
                       data: Data,
                       keep: Bool = false,
                       tryLoad: Bool = false) -> [String] {
        var out: [String] = []
        var okCount = 0

        for (label, dir) in candidateDirs() {
            let path = (dir as NSString).appendingPathComponent(name)
            let c = create(at: path, data: data)
            var line = "\(label) :: \(c.detail)"

            if c.ok {
                okCount += 1
                line += " exec=\(ProbeFS.sandboxVerdict("file-map-executable", path))"
                if tryLoad { line += " dlopen=\(ProbeDylib.load(path))" }
                if !keep { line += " cleanup=\(removeFile(path))" }
            }
            out.append(line)
        }

        out.append("summary :: writable=\(okCount)/\(candidateDirs().count)")
        return out
    }
}

// MARK: - 12. 创建文件（可从快捷指令调用，也可从 App 内一键跑）

/// **为什么不注册进 `ProbeShortcuts`：**
/// `AppShortcutsProvider` 每个 App 上限 10 个，现在正好 10 个，再加一个
/// 会**构建失败**。但 `AppIntent` 本身不注册也能被快捷指令索引到——
/// `AppShortcutsProvider` 只影响"App 快捷指令"画廊里的磁贴。
/// 所以在快捷指令里搜 App 名字照样能找到它，只是不在画廊里。
///
/// 用法上最有价值的一条：把 `ProbeFileDeepIntent` 打出来的 `filedeep.parent`
/// 填进"目录"，就能测**"能不能在 Shortcuts 递给我的那个文件旁边埋东西"**。
/// 那正是上一轮留下的唯一还没被否掉的入口。
struct ProbeCreateFileIntent: AppIntent {
    static var title: LocalizedStringResource = "Probe: 创建文件"
    static var description: IntentDescription? =
        IntentDescription("在指定目录创建文件并记录读数；可一键扫描所有候选目录。")
    static var openAppWhenRun: Bool = false

    @Parameter(title: "目录",
               description: "留空则用自己的 tmp。填 file.parent 的输出就能测「能不能在 Shortcuts 给我的文件旁边埋东西」",
               default: "")
    var dir: String

    @Parameter(title: "文件名", description: "留空则把「目录」整个当完整路径用", default: "probe-created.bin")
    var name: String

    @Parameter(title: "内容", default: "probe")
    var content: String

    @Parameter(title: "拷贝源文件", description: "非空则用该文件的字节代替上面的内容", default: "")
    var source: String

    @Parameter(title: "扫描候选目录", description: "忽略目录与文件名，逐个候选目录各建一份", default: false)
    var matrix: Bool

    @Parameter(title: "保留文件", description: "关掉则建完立刻删除，只留读数", default: true)
    var keep: Bool

    init() {}
    init(matrix: Bool) { self.matrix = matrix }

    func perform() async throws -> some IntentResult {
        ProbeLog.recordContext("create.ctx")

        // 1) 载荷：优先用真实文件（只有真 dylib 才谈得上 file-map-executable）
        var data = Data(content.utf8)
        if !source.isEmpty {
            if let d = try? Data(contentsOf: URL(fileURLWithPath: source)) {
                data = d
                ProbeLog.record("create.payload", "from=\(source) bytes=\(d.count)")
            } else {
                ProbeLog.record("create.payload", "from=\(source) FAIL 读不出来，退回文本")
            }
        } else {
            ProbeLog.record("create.payload", "from=text bytes=\(data.count)")
        }

        // 2) 矩阵模式
        if matrix {
            ProbeLog.record("create.matrix", "begin keep=\(keep) tryLoad=\(!source.isEmpty)")
            for line in ProbeFileCreate.matrix(name: name, data: data,
                                               keep: keep, tryLoad: !source.isEmpty) {
                ProbeLog.record("create.matrix", line)
            }
            return .result()
        }

        // 3) 单点模式
        let path = ProbeFileCreate.resolve(dir: dir, name: name)
        ProbeLog.record("create.target", path)
        ProbeLog.record("create.result",
                        ProbeFileCreate.createAndReport(path, data: data,
                                                        keep: keep, tryLoad: !source.isEmpty))
        return .result()
    }
}
