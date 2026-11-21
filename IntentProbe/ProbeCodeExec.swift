import Darwin
import Foundation

/// 代码执行能力的决定性实验。
///
/// 前面 `sweep.exec :: mmap(rwx)=ok` 只说明**映射成功**，不说明能执行。
/// iOS 的代码签名是在**缺页时**强制的：页可以映射，跳进去才被拦。
/// 所以要分三步走，每步分离一个变量：
///
/// 1. 把自己（已签名）拷到容器里再 dlopen → 测**位置**是否影响加载
/// 2. 把拷贝改坏一个字节再 dlopen       → 测**签名**是否被校验
/// 3. 往 RWX 页写 `ret` 然后真的跳进去   → 测**执行**是否被允许
///
/// 第 3 步会杀进程（预期），所以日志必须先写后跳。
///
/// **本文件所有可能崩的步骤都先落盘再执行。** v3 的教训是：
/// `sweep.selfcopy` 那一行在设备日志里整条缺失，因为没有一行日志能证明
/// 它到底走到了哪一步 —— 崩了和没调用，在日志上长得一模一样。
enum ProbeCodeExec {

    // MARK: - 0. 指令缓存刷新

    /// `sys_icache_invalidate` 声明在 `<libkern/OSCacheControl.h>`，iOS SDK 的
    /// Darwin overlay **不导出**这个符号，直接调用会在编译期报
    /// `cannot find 'sys_icache_invalidate' in scope`（CI 就是这么挂的）。
    ///
    /// 两种修法：
    ///  - `@_silgen_name` 声明 → 编译期过，但把符号依赖推给链接期，仍然可能挂
    ///  - dlsym 运行时取   → 链接期零依赖，取不到就退化为不刷新
    ///
    /// 选后者。取不到这件事本身也会写进日志，不再静默。
    private typealias ICacheInvalidateFn =
        @convention(c) (UnsafeMutableRawPointer?, Int) -> Void

    private static let icacheInvalidate: ICacheInvalidateFn? = {
        // dlopen(nil) 拿的是主镜像句柄，dlsym 会在全局作用域里找，
        // libsystem_platform 是所有进程的依赖，一定在
        guard let h = dlopen(nil, RTLD_NOW) else { return nil }
        guard let s = dlsym(h, "sys_icache_invalidate") else { return nil }
        return unsafeBitCast(s, to: ICacheInvalidateFn.self)
    }()

    /// 返回是否真的刷新了。没刷新不代表跳不过去，但结论要打折。
    static var icacheFlushAvailable: Bool { icacheInvalidate != nil }

    private static func flushICache(_ p: UnsafeMutableRawPointer, _ len: Int) -> Bool {
        guard let f = icacheInvalidate else { return false }
        f(p, len)
        return true
    }

    // MARK: - 1 & 2：位置 vs 签名

    private static func step(_ msg: String) { ProbeLog.record("selfcopy.step", msg) }

    private static func tmp(_ name: String) -> String {
        (NSTemporaryDirectory() as NSString).appendingPathComponent(name)
    }

    /// 拷一份自己到容器里，返回 (路径, 大小)；失败返回 nil 并把原因落盘。
    private static func copySelf(to dst: String) -> Int? {
        guard let exec = Bundle.main.executablePath else {
            step("fail no-exec-path")
            return nil
        }
        step("exec=\(exec)")

        // 用 copyItem 而不是「读进 Data 再写出」：
        //  - 不把整个可执行文件（几十 MB）塞进内存
        //  - 保留原文件的权限位，两个副本的差异只剩「路径」一个变量
        try? FileManager.default.removeItem(atPath: dst)
        do {
            try FileManager.default.copyItem(atPath: exec, toPath: dst)
        } catch {
            let ns = error as NSError
            step("fail copy \(ns.code) <\(ns.localizedDescription)>")
            return nil
        }

        var size = -1
        if let attrs = try? FileManager.default.attributesOfItem(atPath: dst),
           let n = attrs[.size] as? Int { size = n }
        step("copy=ok dst=\(dst) size=\(size)")
        return size
    }

    /// 把 App 自己的可执行文件拷进容器再加载。
    /// 这一组的价值在于：同一个文件，**只有位置和签名完整性不同**。
    ///  - 拷贝后仍能加载 → 位置无关，签名才是指纹
    ///  - 拷贝后不能加载 → 有路径/容器相关的策略
    ///
    /// **两次加载用两个不同的文件名。** 同一个路径 dlopen 两次，dyld 会命中
    /// 自己的 image 缓存直接返回旧句柄，第二次根本不重新验签 —— 那样「改坏后
    /// 还能加载」就是假阳性，结论会整个反过来。
    static func dlopenSelfCopy() -> String {
        step("start")
        var out = ""

        // ---- 组 A：签名完整，只有位置变了
        let intact = tmp("selfcopy-intact.bin")
        if let size = copySelf(to: intact) {
            out += "size=\(size)"
            let sbxExec = ProbeFS.sandboxVerdict("file-map-executable", intact)
            out += " sbx_exec=\(sbxExec)"
            step("about-to-dlopen intact")
            out += " dlopen_intact=\(ProbeDylib.load(intact))"
            step("dlopen intact returned")
            try? FileManager.default.removeItem(atPath: intact)
        } else {
            out += "dlopen_intact=skip(copy failed)"
        }

        // ---- 组 B：位置同样在容器里，但签名坏了
        let broken = tmp("selfcopy-corrupt.bin")
        if let size = copySelf(to: broken), size > 8192 {
            // 文件中部必定落在 __TEXT 或 __DATA 的签名覆盖范围内。
            // 用 pread/pwrite 就地改，避免再复制一份完整副本。
            let fd = open(broken, O_RDWR)
            if fd < 0 {
                out += " dlopen_corrupt=skip(open \(ProbeFS.err(errno)))"
                step("fail open-rdwr \(ProbeFS.err(errno))")
            } else {
                let off = off_t(size / 2)
                var b: UInt8 = 0
                if pread(fd, &b, 1, off) == 1 {
                    let orig = b
                    b ^= 0xFF
                    let wrote = pwrite(fd, &b, 1, off)
                    step("corrupt off=\(off) \(hex(orig))->\(hex(b)) wrote=\(wrote)")
                    out += " corrupt=ok@\(off)"
                    step("about-to-dlopen corrupt")
                    out += " dlopen_corrupt=\(ProbeDylib.load(broken))"
                    step("dlopen corrupt returned")
                } else {
                    out += " dlopen_corrupt=skip(pread \(ProbeFS.err(errno)))"
                    step("fail pread \(ProbeFS.err(errno))")
                }
                close(fd)
            }
            try? FileManager.default.removeItem(atPath: broken)
        } else {
            out += " dlopen_corrupt=skip(copy failed or too small)"
        }

        step("done")
        return out
    }

    private static func hex(_ v: UInt8) -> String {
        let s = String(v, radix: 16)
        return v < 16 ? "0" + s : s
    }

    // MARK: - 3：真的跳进去

    /// 三种结局，对应三种完全不同的安全含义：
    ///  - 正常返回 → 匿名可执行内存可用，等价于 JIT
    ///  - 进程被杀 → 代码签名在缺页时强制（**预期**，说明 W^X 是硬墙）
    ///  - 段错误    → 页不可执行，但内核没杀进程
    ///
    /// **这个函数可能直接杀死 App。** 日志在跳之前就落盘，所以崩了也能看到走到哪。
    static func jumpTest() -> String {
        let len = 4096
        let raw = mmap(nil, len,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANON, -1, 0)
        if raw == MAP_FAILED || raw == nil {
            ProbeLog.record("exec.jump", "mmap=FAIL \(ProbeFS.err(errno))")
            return "mmap=\(ProbeFS.err(errno))"
        }
        let page = raw!

        // arm64: `ret`（0xD65F03C0，小端存 C0 03 5F D6）
        let ret: UInt32 = 0xD65F03C0
        page.storeBytes(of: ret, as: UInt32.self)

        let flushed = flushICache(page, len)
        ProbeLog.record("exec.jump", "icache_flush=\(flushed) ptr=\(page) opcode=ret")
        ProbeLog.record("exec.jump", "about-to-jump")
        ProbeLog.record("exec.jump", "if the app dies here, code signing is enforced at fault time")

        typealias Fn = @convention(c) () -> Void
        let f = unsafeBitCast(page, to: Fn.self)
        f()

        ProbeLog.record("exec.jump", "RETURNED NORMALLY —— 匿名可执行内存真的可用")
        munmap(page, len)
        return "jump=ok(returned) icache_flush=\(flushed)"
    }

    // MARK: - 汇总

    /// P11 的前半段。**不含 jumpTest** —— 那一步单独调用，因为它会终止进程。
    static func fullBattery() -> [String] {
        var out: [String] = []

        ProbeLog.record("battery.step", "1/2 selfcopy")
        out.append("dlopen.selfcopy :: \(dlopenSelfCopy())")
        ProbeLog.record("battery.step", "1/2 done")

        ProbeLog.record("battery.step", "2/2 exec-mmap")
        out.append("exec.mmap :: rwx=\(ProbeDylib.execMmap())")
        ProbeLog.record("battery.step", "2/2 done")

        return out
    }
}
