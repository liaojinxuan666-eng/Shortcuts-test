import Darwin
import Foundation

/// 这个进程跑在什么环境里。
///
/// 存在的理由只有一条：**同一段代码，在越狱设备上会得到完全相反的结论。**
///
/// v6 和 v8 的 `exec.jump` 是同一份实现、同一台设备（iPhone11,6 / 18.5），
/// 唯一可观测的差别是 dyld 镜像表：
///
/// ```
/// v6: sweep.dyld :: count=550 injected=none                          → jump → SIGKILL / Invalid Page
/// v8: sweep.dyld :: count=551 injected=.../systemhook.dylib          → jump → RETURNED NORMALLY
/// ```
///
/// 也就是说"匿名可执行内存可用"是**越狱给的**，不是 iOS 的洞。
/// 不把这一行钉在每条 ctx 上，下一个读日志的人（包括我自己）就会把它读成 finding。
///
/// 两条判据都留着，因为它们会分开失效：
///  - dyld 镜像表：注入发生得早才看得见；晚注入或换注入方式就漏
///  - bootstrap 落盘文件：进程没被注入时也可能存在（越狱已装但没生效）
enum ProbeEnv {
    /// dyld 里那些不属于 Apple 的镜像。判据和 `ProbeDylib.loadedImages` 共用一份。
    static let injected: [String] = ProbeDylib.suspiciousImages()

    /// 第二条独立信号：bootstrap 把 systemhook 落到了这两个位置之一。
    /// rootless 布局在 `/var/jb`，早期 Dopamine 直接铺到 `/usr/lib`。
    static let bootstrapFile: Bool = {
        let fm = FileManager.default
        return fm.fileExists(atPath: "/usr/lib/systemhook.dylib")
            || fm.fileExists(atPath: "/var/jb/usr/lib/systemhook.dylib")
    }()

    static var isJailbroken: Bool { !injected.isEmpty || bootstrapFile }

    /// 打进日志的短标签，例如 `clean` / `jailbroken(systemhook.dylib)`。
    static var label: String {
        if let first = injected.first {
            return "jailbroken(\((first as NSString).lastPathComponent))"
        }
        if bootstrapFile { return "jailbroken(/usr/lib/systemhook.dylib)" }
        return "clean"
    }

    /// 给 exec 这类"结论会被环境翻转"的实验用的一句话判词。
    /// 打印在跳转之前，这样即使进程随后被 SIGKILL，日志里也有归属。
    static var verdict: String {
        isJailbroken
            ? "env=\(label) → 本轮结果不能当成 iOS 的行为"
            : "env=clean → 结果可以当成 iOS 的行为"
    }
}
