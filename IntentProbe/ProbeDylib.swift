import Darwin
import Foundation

/// 代码加载探测。iOS 上"能不能执行自己的代码"由三道闸门依次把守：
///
/// 1. **沙箱**——能不能读到那个文件（`ProbeFS.report` 已经回答了）
/// 2. **代码签名**——dylib 必须由 Apple 或同 team 签名；未签名/ad-hoc 的
///    会拿到 `code signature invalid`
/// 3. **W^X / JIT 硬化**——`mmap(PROT_EXEC)` 需要 `dynamic-codesigning`
///    entitlement，普通 App 一定拿不到，返回 EPERM
///
/// 三道闸门里，第 3 道是硬墙，第 2 道在开发签名（`get-task-allow`）下有时能松，
/// 第 1 道取决于沙箱策略。所以先测 1 和 3，再测 2 —— 顺序反了会得到误导性的结论。
enum ProbeDylib {

    /// 加载失败时 `dlerror()` 的字符串本身就是情报：
    /// "no such file" = 沙箱或路径问题
    /// "code signature invalid" = 签名强制，说明沙箱已经放行了
    /// "not a mach-o file" = 走到了文件解析，说明前两层都过了
    static func load(_ path: String) -> String {
        guard !path.isEmpty else { return "skip(empty)" }

        _ = dlerror()   // 清掉上一条
        if let h = dlopen(path, RTLD_NOW) {
            var s = "dlopen=ok"
            if let sym = dlsym(h, "main") { s += " dlsym(main)=\(sym)" }
            dlclose(h)
            return s
        }
        let ep = dlerror()
        let msg = ep != nil ? String(cString: ep!) : "(nil)"
        return "dlopen=FAIL <\(msg)>"
    }

    /// 匿名 RWX 映射。这是"能不能跑自己生成的代码"最直接的一问。
    /// 普通 App 期望结果：EPERM。
    static func execMmap() -> String {
        let p = mmap(nil, 4096,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANON, -1, 0)
        if p == MAP_FAILED { return "mmap(rwx)=\(ProbeFS.err(errno))" }
        munmap(p, 4096)
        return "mmap(rwx)=ok"
    }

    /// 只读 + 可执行的映射：某些配置下 RWX 被拒但 RX 允许（先写文件再映射执行）
    static func execMmapFile(_ path: String) -> String {
        let fd = open(path, O_RDONLY)
        if fd < 0 { return "mmap(rx,file)=\(ProbeFS.err(errno))" }
        defer { close(fd) }
        let p = mmap(nil, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0)
        if p == MAP_FAILED { return "mmap(rx,file)=\(ProbeFS.err(errno))" }
        munmap(p, 4096)
        return "mmap(rx,file)=ok"
    }

    /// 一批固定目标，用来画基线：
    /// 系统库应该全绿，容器里的东西应该全红。**中间那个"半绿"才是要找的。**
    static func battery() -> [(String, String)] {
        var out: [(String, String)] = [
            ("system-libSystem", "/usr/lib/libSystem.B.dylib"),
            ("system-libobjc",   "/usr/lib/libobjc.A.dylib"),
            ("system-Foundation", "/System/Library/Frameworks/Foundation.framework/Foundation"),
            ("system-dyld",      "/usr/lib/dyld"),
        ]
        if let fw = Bundle.main.privateFrameworksPath {
            out.append(("own-Frameworks-dir", fw))
        }
        out.append(("own-executable", Bundle.main.executablePath ?? ""))
        out.append(("tmp-absent", (NSTemporaryDirectory() as NSString)
            .appendingPathComponent("absent.dylib")))
        return out
    }

    /// 把 bundle 里的 dylib 全列出来，方便挑一个真实存在的目标做对照
    static func bundledLibraries() -> [String] {
        guard let fw = Bundle.main.privateFrameworksPath else { return [] }
        let items = (try? FileManager.default.contentsOfDirectory(atPath: fw)) ?? []
        return items.filter { $0.hasSuffix(".dylib") }
    }

    /// **本进程被注入了什么。**
    ///
    /// 这一项是 v5 加的，起因是 v4 的结果无法解释：`sandbox_check` 对每条路径
    /// 都说 DENY，而 `open`/`read` 实际都能成功。看崩溃报告的 `usedImages`
    /// 才发现进程里挂着
    /// `/private/preboot/<hash>/dopamine-xxxx/procursus/basebin/systemhook.dylib`
    /// —— 设备是越狱的，`sandbox_check` 本身被 hook 了。
    ///
    /// 越狱环境下的沙箱读数**全部作废**，必须在每次扫描的第一行就标出来，
    /// 否则会把"越狱给的权限"读成"App 的漏洞"。
    ///
    /// `_dyld_image_count` / `_dyld_get_image_name` 声明在 `<mach-o/dyld.h>`，
    /// iOS SDK 的 Swift overlay 同样**不导出**（和 `sys_icache_invalidate`
    /// 一个毛病），所以还是走 dlsym。链接期零依赖，取不到就明说取不到。
    private typealias ImageCountFn = @convention(c) () -> UInt32
    private typealias ImageNameFn = @convention(c) (UInt32) -> UnsafePointer<CChar>?

    private static let imageCount: ImageCountFn? = {
        guard let h = dlopen(nil, RTLD_NOW) else { return nil }
        guard let s = dlsym(h, "_dyld_image_count") else { return nil }
        return unsafeBitCast(s, to: ImageCountFn.self)
    }()

    private static let imageName: ImageNameFn? = {
        guard let h = dlopen(nil, RTLD_NOW) else { return nil }
        guard let s = dlsym(h, "_dyld_get_image_name") else { return nil }
        return unsafeBitCast(s, to: ImageNameFn.self)
    }()

    static func loadedImages() -> String {
        guard let count = imageCount, let nameAt = imageName else {
            return "unavailable(dlsym _dyld_image_count)"
        }

        let n = count()
        var sus: [String] = []
        for i in 0..<n {
            guard let c = nameAt(i) else { continue }
            let p = String(cString: c)
            let low = p.lowercased()
            if low.contains("systemhook") || low.contains("dopamine")
                || low.contains("substitute") || low.contains("ellekit")
                || low.contains("/var/jb") || low.contains("tweak") {
                sus.append(p)
            }
        }
        let list = sus.isEmpty ? "none" : sus.joined(separator: ",")
        return "count=\(n) injected=\(list)"
    }
}
