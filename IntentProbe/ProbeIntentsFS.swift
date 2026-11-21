import AppIntents
import Foundation

// MARK: - 7. 环境扫描：一次点按，拿到整张地图

/// 无参数。跑完看 `probe.log` 就能知道：
///  - 我的容器在哪、能写哪几个目录
///  - 19 条关键系统路径分别是什么状态（沙箱怎么说 vs 内核怎么做）
///  - 匿名 RWX 映射能不能建
///  - 系统库和容器内文件的 dlopen 差异
struct ProbeSweepIntent: AppIntent {
    static var title: LocalizedStringResource = "Probe: 环境扫描"
    static var description: IntentDescription? =
        IntentDescription("扫描容器、沙箱策略、关键系统路径与代码加载能力。")
    static var openAppWhenRun: Bool = false

    func perform() async throws -> some IntentResult {
        ProbeLog.recordContext("sweep.ctx")

        for line in ProbeFS.containerInfo() {
            ProbeLog.record("sweep.container", line)
        }

        // 第一行就要回答"我是不是在越狱环境里"——否则后面每条绿色都是误判
        ProbeLog.record("sweep.dyld", ProbeDylib.loadedImages())

        for p in ProbeFS.interesting {
            ProbeLog.record("sweep.path", "\(p) :: \(ProbeFS.report(p))")
        }

        ProbeLog.record("sweep.exec", "rwx=\(ProbeDylib.execMmap())")

        // dlsym 能不能拿到 sys_icache_invalidate —— P11 的结论依赖这一条
        let icache = ProbeCodeExec.icacheFlushAvailable ? "dlsym-ok" : "unavailable"
        ProbeLog.record("sweep.icache", "sys_icache_invalidate=\(icache)")

        // 关键的一组：同一个 dylib，位置变了还能不能加载；签名坏了还认不认
        // 自我拷贝（MH_EXECUTE）已证伪——dyld 一律拒绝，对照没有变量，见 v5 记录
        ProbeLog.record("sweep.staged", "about-to-run")
        for line in ProbeCodeExec.stagedDylib() {
            ProbeLog.record("sweep.staged", line)
        }

        for (name, path) in ProbeDylib.battery() {
            ProbeLog.record("sweep.dlopen", "\(name) :: \(ProbeDylib.load(path))")
        }

        for lib in ProbeDylib.bundledLibraries() {
            ProbeLog.record("sweep.bundled", lib)
        }

        return .result()
    }
}

// MARK: - 8. 探测任意路径：读 / 列 / 写 / 建链接

/// 这是最核心的一个。给一个路径，它会把五件事全做一遍：
///  1. `lstat` + `sandbox_check`（只问不做）
///  2. 在**父目录**写文件 —— 测写权限归属，不是测这个文件本身
///  3. 在自己可写区建**软链接**指向它 —— 验证"创建链接不需要目标权限"
///  4. 建**硬链接** —— 通常 EXDEV（跨卷）或 EPERM（目录）
///  5. 在自己容器里写一遍作为基线对照
struct ProbePathIntent: AppIntent {
    static var title: LocalizedStringResource = "Probe: 探测路径"
    static var description: IntentDescription? =
        IntentDescription("对任意路径做 stat/读/列目录/写/建链接，并直接询问沙箱策略。")
    static var openAppWhenRun: Bool = false

    @Parameter(title: "路径", description: "绝对路径，例如 /private/etc/passwd")
    var path: String

    @Parameter(title: "写入内容", default: "probe")
    var content: String

    init() {}
    init(path: String, content: String = "probe") {
        self.path = path
        self.content = content
    }

    func perform() async throws -> some IntentResult {
        ProbeLog.recordContext("path.ctx")
        ProbeLog.record("path.input", "<\(path)>")
        ProbeLog.record("path.report", ProbeFS.report(path))

        // 1) 父目录写权限 —— 真正决定"能不能在这里埋东西"的是它
        let parent = (path as NSString).deletingLastPathComponent
        ProbeLog.record("path.write.parent", "\(parent) :: \(ProbeFS.writeProbe(in: parent, content: content))")

        // 2) 软链接：创建时完全不检查目标权限
        let linkPath = (NSTemporaryDirectory() as NSString).appendingPathComponent("probe-link")
        ProbeLog.record("path.symlink", ProbeFS.symlinkProbe(target: path, at: linkPath))

        // 3) 硬链接：跨卷 EXDEV，目录 EPERM，同卷文件才可能成功
        let hardPath = (NSTemporaryDirectory() as NSString).appendingPathComponent("probe-hard")
        ProbeLog.record("path.hardlink", ProbeFS.hardlinkProbe(target: path, at: hardPath))

        // 4) 基线：自己的 Documents 一定能写
        if let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first {
            ProbeLog.record("path.write.own", "\(docs.path) :: \(ProbeFS.writeProbe(in: docs.path, content: content))")
        }

        // 5) 如果目标是可执行映像，顺手试一下加载
        if path.hasSuffix(".dylib") || path.hasSuffix(".so") {
            ProbeLog.record("path.dlopen", ProbeDylib.load(path))
            ProbeLog.record("path.mmap", ProbeDylib.execMmapFile(path))
        }

        return .result()
    }
}

// MARK: - 9. 加载动态库

struct ProbeDylibIntent: AppIntent {
    static var title: LocalizedStringResource = "Probe: 加载动态库"
    static var description: IntentDescription? =
        IntentDescription("对指定路径执行 dlopen，记录完整失败原因。")
    static var openAppWhenRun: Bool = false

    @Parameter(title: "路径", description: "dylib / framework 的绝对路径")
    var path: String

    init() {}
    init(path: String) { self.path = path }

    func perform() async throws -> some IntentResult {
        ProbeLog.recordContext("dlopen.ctx")
        ProbeLog.record("dlopen.stat", "\(path) :: \(ProbeFS.statLine(path))")
        ProbeLog.record("dlopen.sbx", "read=\(ProbeFS.sandboxVerdict("file-read-data", path)) " +
                                      "exec=\(ProbeFS.sandboxVerdict("file-map-executable", path))")
        ProbeLog.record("dlopen.result", ProbeDylib.load(path))
        ProbeLog.record("dlopen.mmap", "anon=\(ProbeDylib.execMmap()) file=\(ProbeDylib.execMmapFile(path))")
        return .result()
    }
}

// MARK: - 10. 文件深挖：Shortcuts 递过来的文件到底在哪、能摸多远

/// 和老的 `ProbeFileIntent` 的区别：那个只记录路径，这个会把
/// security-scoped 访问、父目录、兄弟文件、dlopen 全试一遍。
struct ProbeFileDeepIntent: AppIntent {
    static var title: LocalizedStringResource = "Probe: 文件深挖"
    static var description: IntentDescription? =
        IntentDescription("分析传入文件的真实落盘位置、可访问范围与加载可能性。")

    @Parameter(title: "文件")
    var file: IntentFile

    init() {}
    init(file: IntentFile) { self.file = file }

    func perform() async throws -> some IntentResult {
        ProbeLog.recordContext("filedeep.ctx")
        ProbeLog.record("filedeep.meta",
                        "filename=<\(file.filename)> size=\(file.data.count) type=\(file.type?.identifier ?? "-")")

        guard let u = file.fileURL else {
            ProbeLog.record("filedeep.url", "(nil) —— 说明只给了 data，没给真实路径")
            return .result()
        }
        ProbeLog.record("filedeep.url", u.path)
        ProbeLog.record("filedeep.report", ProbeFS.report(u.path))

        // security-scoped 资源：Shortcuts 给的 URL 可能带 scope，
        // 解锁后能访问的范围可能比解锁前大 —— 这个差值就是越权面
        let scoped = u.startAccessingSecurityScopedResource()
        ProbeLog.record("filedeep.scoped", "startAccessing=\(scoped)")
        defer { if scoped { u.stopAccessingSecurityScopedResource() } }

        // 父目录：能列到什么，就是"用户给了我一个文件"实际上给了我多少
        let parent = u.deletingLastPathComponent()
        ProbeLog.record("filedeep.parent", "\(parent.path) :: \(ProbeFS.report(parent.path))")

        // 兄弟文件：同目录下别的文件能不能读
        if let sibs = try? FileManager.default.contentsOfDirectory(atPath: parent.path) {
            let others = sibs.filter { $0 != u.lastPathComponent }.prefix(5)
            for s in others {
                let sp = (parent.path as NSString).appendingPathComponent(s)
                ProbeLog.record("filedeep.sibling", "\(s) :: \(ProbeFS.statLine(sp))")
            }
        }

        // 当成 dylib 试加载：这一步能区分"沙箱放行了"和"签名拦住了"
        let ext = u.pathExtension.lowercased()
        if ext == "dylib" || ext == "so" {
            ProbeLog.record("filedeep.dlopen", ProbeDylib.load(u.path))
        }

        // 文件名可被构造 —— 反向写回时是否穿越
        if let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first {
            let target = docs.appendingPathComponent(file.filename)
            ProbeLog.record("filedeep.writeback", "target=\(target.path)")
            do {
                try file.data.write(to: target)
                ProbeLog.record("filedeep.writeback", "ok")
            } catch {
                let ns = error as NSError
                ProbeLog.record("filedeep.writeback", "error=\(ns.code) <\(ns.localizedDescription)>")
            }
        }

        return .result()
    }
}

// MARK: - 11. 代码执行：唯一一个可能把 App 弄崩的探针

/// 为什么单独一个：
///  - `mmap(RWX)=ok` 只说明映射成功，能不能执行要看取指时页表给不给 EXEC
///  - 要判定，只能真的跳进去
///
/// **v4 实测结果（iPhone11,6 / iOS 18.5）：**
/// ```
/// exec.jump :: icache_flush=true ptr=0x104640000 opcode=ret
/// exec.jump :: about-to-jump
/// → SIGBUS, KERN_PROTECTION_FAILURE at 0x104640000, ESR.DFSC=0xF (level-3 perm fault)
/// → vmRegionInfo: VM_ALLOCATE 104640000-104644000 [16K] rw-/rwx
/// ```
/// `rw-/rwx` 是关键：max prot 有 EXEC，当前 prot 没有。也就是说
/// **`mmap(PROT_EXEC)` 没报错，但内核把 EXEC 从当前保护位里抹掉了**，
/// 取指时才在页表上 fault。这不是 AMFI 的签名校验（那样会 SIGKILL），
/// 是纯 VM 级 NX。v5 因此加了 `mprotect(RX)` 一步，把"显式拒绝"和
/// "接受了但不生效"分开。
///
/// 如果打出 `RETURNED NORMALLY`，那就是真的能跑自生成代码——这条要立刻深挖。
struct ProbeCodeExecIntent: AppIntent {
    static var title: LocalizedStringResource = "Probe: 代码执行（可能崩溃）"
    static var description: IntentDescription? =
        IntentDescription("测试容器内 dylib 加载、签名校验、以及匿名可执行内存。可能使 App 退出。")
    static var openAppWhenRun: Bool = true

    func perform() async throws -> some IntentResult {
        ProbeLog.recordContext("exec.ctx")

        for line in ProbeCodeExec.fullBattery() {
            ProbeLog.record("exec.battery", line)
        }

        // 下面这一步可能直接终止进程，之前的所有记录都已落盘
        let r = ProbeCodeExec.jumpTest()
        ProbeLog.record("exec.result", r)

        return .result()
    }
}
