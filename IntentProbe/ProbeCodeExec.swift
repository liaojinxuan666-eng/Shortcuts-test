import Darwin
import Foundation

/// 代码执行能力的决定性实验。
///
/// ## 已经拿到的答案（v4，iPhone11,6 / iOS 18.5）
///
/// `mmap(RWX)` 成功、写 `ret` 成功、跳进去 → `SIGBUS / KERN_PROTECTION_FAILURE`，
/// `ESR.ISS.DFSC = 0xF`（level-3 permission fault on instruction fetch），
/// 崩在 pc == 刚 mmap 的那个地址，`vmRegionInfo` 显示该区间 `rw-/rwx`。
///
/// 三件事同时成立，含义很具体：
///  - `mmap(PROT_EXEC)` **不报错**——内核接受了请求，把 EXEC 记进 max prot
///  - 但**当前保护位没有 EXEC**（`rw-`），所以取指就在页表被拦
///  - 拦截方式是 **VM 级 NX**，不是 AMFI 的签名校验：进程没被 SIGKILL，
///    也没出现 `Code Signature Invalid`，就是一条普通的缺页权限错
///
/// 所以 `sweep.exec :: mmap(rwx)=ok` 是内核说的谎。判据只能是"跳不跳"。
///
/// ## 一个已经证伪的对照（v4）
///
/// 拷贝自己的**可执行文件**再 dlopen，问不出"签名是否被校验"：
/// dyld 对 `MH_EXECUTE` 一律拒绝，`cannot dlopen a main executable`。
/// 完整副本和改坏副本拿到的是同一句话，这组对照没有变量。
/// 换成真实 dylib —— 见 `stagedDylib()`。
enum ProbeCodeExec {

    // MARK: - 0. 指令缓存刷新

    /// `sys_icache_invalidate` 声明在 `<libkern/OSCacheControl.h>`，iOS SDK 的
    /// Darwin overlay **不导出**这个符号，直接调用会编译失败
    /// （`cannot find 'sys_icache_invalidate' in scope`）。
    ///
    /// 用 dlsym 而不是 `@_silgen_name`：后者把失败推到链接期，拿到的是一条
    /// `ld: symbol not found`，还得再猜一轮；前者失败只会让日志里出现
    /// `sweep.icache :: unavailable`，实验照跑，结论打折但不丢。
    private typealias ICacheInvalidateFn =
        @convention(c) (UnsafeMutableRawPointer?, Int) -> Void

    private static let icacheInvalidate: ICacheInvalidateFn? = {
        guard let h = dlopen(nil, RTLD_NOW) else { return nil }
        guard let s = dlsym(h, "sys_icache_invalidate") else { return nil }
        return unsafeBitCast(s, to: ICacheInvalidateFn.self)
    }()

    static var icacheFlushAvailable: Bool { icacheInvalidate != nil }

    private static func flushICache(_ p: UnsafeMutableRawPointer, _ len: Int) -> Bool {
        guard let f = icacheInvalidate else { return false }
        f(p, len)
        return true
    }

    // MARK: - 小工具

    private static func tmp(_ name: String) -> String {
        (NSTemporaryDirectory() as NSString).appendingPathComponent(name)
    }

    private static func fileSize(_ path: String) -> Int {
        if let attrs = try? FileManager.default.attributesOfItem(atPath: path),
           let n = attrs[.size] as? Int { return n }
        return -1
    }

    private static func copyFile(_ from: String, to: String) -> Bool {
        try? FileManager.default.removeItem(atPath: to)
        do {
            try FileManager.default.copyItem(atPath: from, toPath: to)
            return true
        } catch {
            let ns = error as NSError
            ProbeLog.record("staged.step", "copy FAIL \(ns.code) \(from) -> \(to)")
            return false
        }
    }

    /// 就地翻一个字节。用 pread/pwrite，不把整个文件读进内存。
    private static func flipByte(_ path: String, at off: Int) -> (UInt8, UInt8)? {
        let fd = open(path, O_RDWR)
        if fd < 0 { return nil }
        defer { close(fd) }
        var b: UInt8 = 0
        if pread(fd, &b, 1, off_t(off)) != 1 { return nil }
        let orig = b
        b ^= 0xFF
        if pwrite(fd, &b, 1, off_t(off)) != 1 { return nil }
        return (orig, b)
    }

    // MARK: - Mach-O：找 __TEXT 里的一个代码偏移

    /// 改坏哪个字节，决定了这一问在问什么：
    ///  - 改在 `__LINKEDIT`（签名 blob 本身）→ dyld 报 "malformed"，问的是解析器
    ///  - 改在 `__TEXT` 的代码段          → 报 "code signature invalid"，问的才是签名
    ///
    /// 所以要真的读一下 Mach-O 头。只读前 4KB，够装下所有 load command。
    /// 全部用字节手工拼整数，不碰对齐问题。
    private static func u32(_ b: [UInt8], _ o: Int) -> UInt32? {
        guard o >= 0, o + 4 <= b.count else { return nil }
        return UInt32(b[o]) | UInt32(b[o + 1]) << 8 | UInt32(b[o + 2]) << 16 | UInt32(b[o + 3]) << 24
    }

    private static func u64(_ b: [UInt8], _ o: Int) -> UInt64? {
        guard o >= 0, o + 8 <= b.count else { return nil }
        var v: UInt64 = 0
        for i in (0..<8).reversed() { v = (v << 8) | UInt64(b[o + i]) }
        return v
    }

    /// 返回 `__TEXT` 段内部的一个文件偏移（取段中部，避开头部与 load command）。
    private static func textCodeOffset(_ path: String) -> Int? {
        guard let fh = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? fh.close() }
        guard let d = try? fh.read(upToCount: 4096) else { return nil }
        let b = [UInt8](d)

        guard let magic = u32(b, 0), magic == 0xfeedfacf else { return nil }  // MH_MAGIC_64, arm64 LE
        guard let ncmds = u32(b, 16) else { return nil }

        var p = 32
        for _ in 0..<ncmds {
            guard let cmd = u32(b, p), let sz = u32(b, p + 4), sz >= 8, sz < 4096 else { return nil }
            if cmd == 0x19 {   // LC_SEGMENT_64
                let nameEnd = p + 24
                guard nameEnd <= b.count else { return nil }
                let raw = b[(p + 8)..<nameEnd].map { $0 == 0 ? UInt8(32) : $0 }
                let name = (String(bytes: raw, encoding: .utf8) ?? "")
                    .trimmingCharacters(in: .whitespaces)
                if name == "__TEXT",
                   let fileoff = u64(b, p + 40),
                   let filesize = u64(b, p + 48),
                   filesize > 0x4000 {
                    return Int(fileoff) + Int(min(filesize / 2, 0x8000))
                }
            }
            p += Int(sz)
        }
        return nil
    }

    // MARK: - 1 & 2：位置 vs 签名（用真实 dylib）

    /// 候选：**磁盘上真的存在**的 dylib。
    ///
    /// 不能拿 `/usr/lib/libSystem.B.dylib` 那种——它在 dyld shared cache 里，
    /// 磁盘上 `lstat=ENOENT`，dlopen 走的是缓存，压根不读文件，问不出任何东西。
    ///
    /// `libobjc-trampolines.dylib` 是实测确认存在于 cryptex 里的（崩溃报告里
    /// 它以独立 image 被映射，路径 `/private/preboot/Cryptexes/OS/usr/lib/`）。
    private static func stagedCandidates() -> [String] {
        var c: [String] = []
        if let fw = Bundle.main.privateFrameworksPath {
            let items = (try? FileManager.default.contentsOfDirectory(atPath: fw)) ?? []
            c += items.filter { $0.hasSuffix(".dylib") }
                .map { (fw as NSString).appendingPathComponent($0) }
        }
        c += [
            "/private/preboot/Cryptexes/OS/usr/lib/libobjc-trampolines.dylib",
            "/usr/lib/libRPAC.dylib",
            "/usr/lib/libCoreLSKD.dylib",
            "/usr/lib/libMainThreadChecker.dylib",
        ]
        return c
    }

    /// 三段对照，**每次只变一个变量**：
    ///
    /// | 条件 | 变了什么 | 能回答什么 |
    /// |---|---|---|
    /// | `dlopen(原路径)`   | —              | 基线：这个 dylib 本身能不能加载 |
    /// | `dlopen(完整副本)` | 位置            | 换到我的容器里还认不认 |
    /// | `dlopen(改坏副本)` | 位置相同、签名坏 | 签名到底校不校验 |
    ///
    /// 两个副本用**不同文件名**：同一路径 dlopen 两次会命中 dyld 的 image 缓存，
    /// 第二次不重新验签，"改坏后仍 ok" 就是假阳性。
    static func stagedDylib() -> [String] {
        var out: [String] = []

        var src: String?
        for c in stagedCandidates() {
            let fd = open(c, O_RDONLY)
            if fd >= 0 {
                close(fd)
                src = c
                out.append("pick :: \(c) size=\(fileSize(c))")
                break
            }
            out.append("skip :: \(c) open=\(ProbeFS.err(errno))")
        }
        guard let path = src else {
            out.append("result :: 没有可读的 dylib，这一组无法进行")
            return out
        }

        out.append("dlopen(src) :: \(ProbeDylib.load(path))")

        let intact = tmp("staged-intact.dylib")
        let broken = tmp("staged-corrupt.dylib")
        guard copyFile(path, to: intact), copyFile(path, to: broken) else {
            out.append("result :: 拷贝失败，见 staged.step")
            return out
        }

        out.append("dlopen(intact) :: \(ProbeDylib.load(intact))")

        let textOff = textCodeOffset(broken)
        let off = textOff ?? (fileSize(broken) / 2)
        let flipped = flipByte(broken, at: off)
        if let f = flipped {
            let where_ = textOff != nil ? "__TEXT" : "fallback(mid-file)"
            out.append("corrupt :: off=\(off) \(hex(f.0))->\(hex(f.1)) in=\(where_)")
            out.append("dlopen(corrupt) :: \(ProbeDylib.load(broken))")
        } else {
            out.append("corrupt :: FAIL 无法就地改写")
        }

        try? FileManager.default.removeItem(atPath: intact)
        try? FileManager.default.removeItem(atPath: broken)
        return out
    }

    private static func hex(_ v: UInt8) -> String {
        let s = String(v, radix: 16)
        return v < 16 ? "0" + s : s
    }

    // MARK: - 已证伪：拷贝自己的可执行文件

    /// 保留是因为它是**否定结果**的记录，而且它意外暴露了 dyld 的搜索路径：
    ///
    /// ```
    /// tried: '<tmp>/selfcopy-intact.bin' (cannot dlopen a main executable ...),
    ///        '/private/preboot/Cryptexes/OS/<tmp>/selfcopy-intact.bin' (no such file)
    /// ```
    ///
    /// 第二条说明 dyld 会在 **cryptex 根**下再找一次——iOS 18 的 `/` 是
    /// cryptex 的 firmlink 视图，不是真根。这一点对后面所有"路径归一化"的
    /// 判断都有影响：同一个路径在 dyld 眼里有两个名字。
    static func dlopenSelfCopy() -> String {
        guard let exec = Bundle.main.executablePath else { return "skip(no exec path)" }
        let dst = tmp("selfcopy.bin")
        guard copyFile(exec, to: dst) else { return "copy=FAIL" }
        let r = ProbeDylib.load(dst)
        try? FileManager.default.removeItem(atPath: dst)
        return "note=MH_EXECUTE不能dlopen \(r)"
    }

    // MARK: - 3：真的跳进去

    /// 三种结局，对应三种完全不同的安全含义：
    ///  - 正常返回 → 匿名可执行内存可用，等价于 JIT
    ///  - SIGBUS / 权限错 → 页表级 NX，内核在 mmap 时就悄悄把 EXEC 抹了（**实测**）
    ///  - 被 SIGKILL 且报 code signature → AMFI 在缺页时校验签名
    ///
    /// 加了一步 `mprotect(RX)`：它能把"显式拒绝"和"接受了但不生效"分开。
    /// 前者返回 EPERM，后者返回 0 但取指仍然 fault。
    ///
    /// **这个函数会终止进程。** 日志在跳之前就落盘。
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

        // W^X 的标准顺序：写完再降到 RX。这一步的返回值是关键情报。
        errno = 0
        let mpr = mprotect(page, len, PROT_READ | PROT_EXEC)
        let mprStr = mpr == 0 ? "ok" : ProbeFS.err(errno)
        ProbeLog.record("exec.jump", "mprotect(rx)=\(mprStr)")

        let flushed = flushICache(page, len)
        ProbeLog.record("exec.jump", "icache_flush=\(flushed) ptr=\(page) opcode=ret")
        ProbeLog.record("exec.jump", "about-to-jump")
        ProbeLog.record("exec.jump", "SIGBUS=page-table NX; SIGKILL+codesign=AMFI")

        typealias Fn = @convention(c) () -> Void
        let f = unsafeBitCast(page, to: Fn.self)
        f()

        ProbeLog.record("exec.jump", "RETURNED NORMALLY —— 匿名可执行内存真的可用")
        munmap(page, len)
        return "jump=ok(returned) mprotect=\(mprStr) icache_flush=\(flushed)"
    }

    // MARK: - 汇总

    /// P11 的前半段。**不含 jumpTest** —— 那一步单独调用，因为它会终止进程。
    static func fullBattery() -> [String] {
        var out: [String] = []

        ProbeLog.record("battery.step", "1/2 staged-dylib")
        out += stagedDylib()
        ProbeLog.record("battery.step", "1/2 done")

        ProbeLog.record("battery.step", "2/2 exec-mmap")
        out.append("exec.mmap :: rwx=\(ProbeDylib.execMmap())")
        ProbeLog.record("battery.step", "2/2 done")

        return out
    }
}
