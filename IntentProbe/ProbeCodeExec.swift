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
enum ProbeCodeExec {

    // MARK: - 1 & 2：位置 vs 签名

    /// 把 App 自己的可执行文件拷进容器再加载。
    /// 这一组的价值在于：同一个文件，**只有位置和签名完整性不同**。
    ///  - 拷贝后仍能加载 → 位置无关，签名才是指纹
    ///  - 拷贝后不能加载 → 有路径/容器相关的策略
    static func dlopenSelfCopy() -> String {
        guard let exec = Bundle.main.executablePath else { return "skip(no exec path)" }
        guard let data = FileManager.default.contents(atPath: exec) else {
            return "read=FAIL(\(ProbeFS.err(errno)))"
        }

        let dst = (NSTemporaryDirectory() as NSString).appendingPathComponent("selfcopy.bin")
        try? FileManager.default.removeItem(atPath: dst)
        guard FileManager.default.createFile(atPath: dst, contents: data) else {
            return "copy=FAIL(\(ProbeFS.err(errno)))"
        }

        var out = "size=\(data.count)"
        out += " sbx_exec=\(ProbeFS.sandboxVerdict("file-map-executable", dst))"
        out += " dlopen_intact=\(ProbeDylib.load(dst))"

        // 改坏一个字节：位置在文件中部，必定落在 __TEXT 或 __DATA 的签名覆盖范围内
        var broken = data
        if broken.count > 8192 {
            let off = broken.count / 2
            broken[off] ^= 0xFF
            try? broken.write(to: URL(fileURLWithPath: dst))
            out += " dlopen_corrupt=\(ProbeDylib.load(dst))"
        }

        try? FileManager.default.removeItem(atPath: dst)
        return out
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
            return "mmap=\(ProbeFS.err(errno))"
        }
        let page = raw!

        // arm64: `ret`（0xD65F03C0，小端存 C0 03 5F D6）
        let ret: UInt32 = 0xD65F03C0
        page.storeBytes(of: ret, as: UInt32.self)
        sys_icache_invalidate(page, len)

        ProbeLog.record("exec.jump", "about-to-jump ptr=\(page) opcode=ret")
        ProbeLog.record("exec.jump", "if the app dies here, code signing is enforced at fault time")

        typealias Fn = @convention(c) () -> Void
        let f = unsafeBitCast(page, to: Fn.self)
        f()

        ProbeLog.record("exec.jump", "RETURNED NORMALLY —— 匿名可执行内存真的可用")
        munmap(page, len)
        return "jump=ok(returned)"
    }

    // MARK: - 汇总

    static func fullBattery() -> [String] {
        var out: [String] = []
        out.append("dlopen.selfcopy :: \(dlopenSelfCopy())")
        out.append("exec.mmap :: rwx=\(ProbeDylib.execMmap())")
        return out
    }
}
