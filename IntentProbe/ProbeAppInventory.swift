#if canImport(UIKit)
import Foundation
import UIKit

/// 已安装 App 清单 —— 回答「系统里到底有哪些软件」。
///
/// 前面所有探针都是「我能不能做某件事」，这一条问的是另一个方向：
/// **系统愿不愿意告诉我它装了些什么。**
///
/// 用的是 `LSApplicationWorkspace`（LaunchServices 的私有入口，
/// 在 `MobileCoreServices` 里）。它有两个能力值得量：
///
///  - `allInstalledApplications` —— 返回**每一个**已安装 App 的 proxy，
///    含系统 App。第三方 App 名义上只能看到自己，但历史上这个口子一直是开的。
///  - `openSensitiveURL:withOptions:` —— 和 `UIApplication.open` 的区别只有一处：
///    **不检查「sensitive URL」名单**。`prefs:` 系列就是被那个名单挡住的。
///    如果这个能过，前面 `sysapp` 那一层测出来的 `refused` 就要重新解释。
///
/// 全部走 `objc_msgSend` + `dlsym`，不 `import` 任何私有头文件：
/// 私有 framework 的 module 在 SDK 里不存在，写了整包编不过，又是一轮 CI。
///
/// ## 读法
///
/// | 行 | 含义 |
/// |---|---|
/// | `appinv.api` | 类/选择器在不在。缺了就是这条路彻底不通，不用再看后面 |
/// | `appinv.list` | `count=N` 加每个 App 一行。**N=0 是干净的负结果**，不是失败 |
/// | `appinv.sel` | 每个关键选择器 `respondsTo` 的结果 |
/// | `appinv.sensitive` | 真发一次 `openSensitiveURL`，看进程有没有被切走 |
@MainActor
enum ProbeAppInventory {

    // MARK: - objc_msgSend 的几种形状

    // 只声明用得到的四种。返回值一律用 `Unmanaged`，让 ARC 自己接。
    private typealias Send0       = @convention(c) (AnyObject, Selector) -> Unmanaged<AnyObject>?
    private typealias Send1       = @convention(c) (AnyObject, Selector, AnyObject) -> Unmanaged<AnyObject>?
    private typealias SendBool0   = @convention(c) (AnyObject, Selector) -> Bool
    private typealias SendBool2   = @convention(c) (AnyObject, Selector, AnyObject, AnyObject?) -> Bool

    /// `RTLD_DEFAULT` 在 Swift 里没有导出，值是 -2（`(void *)-2`）。
    private static let rtldDefault = UnsafeMutableRawPointer(bitPattern: -2)

    private static func msgSend() -> UnsafeMutableRawPointer? {
        dlsym(rtldDefault, "objc_msgSend")
    }

    private static func sel(_ name: String) -> Selector { NSSelectorFromString(name) }

    /// 实例选择器在不在。`responds(to:)` 是 NSObject 的方法，`AnyObject` 上点不出来，
    /// 所以先桥回 NSObject；桥不回去就走 runtime（`object_getClass` 对 metaclass 也成立）。
    private static func hasSel(_ obj: AnyObject, _ name: String) -> Bool {
        let s = sel(name)
        if let nso = obj as? NSObject { return nso.responds(to: s) }
        guard let c = object_getClass(obj) else { return false }
        return class_getInstanceMethod(c, s) != nil
    }

    /// 类方法在不在。**不能拿类对象去 `as? NSObject`**：metaclass 不是 NSObject 实例，
    /// 那个转换会失败，然后所有类级 `responds` 都变成 false——一个很安静的假阴性。
    private static func hasClassSel(_ cls: AnyClass, _ name: String) -> Bool {
        class_getClassMethod(cls, sel(name)) != nil
    }

    private static func send0(_ obj: AnyObject, _ name: String) -> AnyObject? {
        guard let p = msgSend() else { return nil }
        let f = unsafeBitCast(p, to: Send0.self)
        return f(obj, sel(name))?.takeUnretainedValue()
    }

    private static func send1(_ obj: AnyObject, _ name: String, _ a: AnyObject) -> AnyObject? {
        guard let p = msgSend() else { return nil }
        let f = unsafeBitCast(p, to: Send1.self)
        return f(obj, sel(name), a)?.takeUnretainedValue()
    }

    private static func sendBool0(_ obj: AnyObject, _ name: String) -> Bool? {
        guard let p = msgSend(), hasSel(obj, name) else { return nil }
        let f = unsafeBitCast(p, to: SendBool0.self)
        return f(obj, sel(name))
    }

    private static func sendBool2(_ obj: AnyObject, _ name: String,
                                  _ a: AnyObject, _ b: AnyObject?) -> Bool? {
        guard let p = msgSend(), hasSel(obj, name) else { return nil }
        let f = unsafeBitCast(p, to: SendBool2.self)
        return f(obj, sel(name), a, b)
    }

    // MARK: - 入口

    /// 清单是纯读，无副作用，所以**不需要串行**，一次跑完。
    /// 唯一的例外是最后那一次 `openSensitiveURL`——它会把进程切走，所以放最后。
    static func runAll(probeSensitive: Bool = true) {
        ProbeLog.recordContext("appinv.ctx")

        guard let cls = NSClassFromString("LSApplicationWorkspace") else {
            ProbeLog.record("appinv.api", "note=class-missing name=LSApplicationWorkspace")
            return
        }
        ProbeLog.record("appinv.api",
                        "note=class-found name=LSApplicationWorkspace "
                        + "self=\(Bundle.main.bundleIdentifier ?? "-")")

        // 类对象本身就是 id，直接当 AnyObject 用，不用 unsafeBitCast。
        let clsObj: AnyObject = cls

        // 先量选择器：类在、方法不在，和类不在，是两件事。
        for name in ["defaultWorkspace", "allInstalledApplications",
                     "openSensitiveURL:withOptions:", "openURL:withOptions:"] {
            ProbeLog.record("appinv.sel",
                            "target=LSApplicationWorkspace sel=<\(name)> responds=\(hasClassSel(cls, name))")
        }

        guard let ws = send0(clsObj, "defaultWorkspace") else {
            ProbeLog.record("appinv.api", "note=defaultWorkspace-nil")
            return
        }
        ProbeLog.record("appinv.api", "note=workspace-ok class=\(type(of: ws))")

        for name in ["allInstalledApplications", "applicationsForBundleIdentifier:",
                     "openSensitiveURL:withOptions:"] {
            ProbeLog.record("appinv.sel",
                            "target=workspace sel=<\(name)> responds=\(hasSel(ws, name))")
        }

        dumpInstalled(ws)

        if probeSensitive { fireSensitive(ws) }
    }

    // MARK: - 清单

    private static func dumpInstalled(_ ws: AnyObject) {
        guard let raw = send0(ws, "allInstalledApplications") as? [AnyObject] else {
            ProbeLog.record("appinv.list", "count=0 note=not-an-array")
            return
        }

        var system = 0, user = 0
        ProbeLog.record("appinv.list", "count=\(raw.count) note=begin")

        for p in raw {
            let id = (send0(p, "applicationIdentifier") as? String) ?? "-"
            let type = (send0(p, "applicationType") as? String) ?? "-"
            let del = sendBool0(p, "isDeletable")
            let url = (send0(p, "bundleURL") as? URL)?.path ?? "-"
            let team = (send0(p, "teamID") as? String) ?? "-"

            if type == "User" { user += 1 } else { system += 1 }

            // 每个 App 一行。不做截断：这条日志的全部价值就在于「完整」，
            // 少一行就少一个 App，事后没法补。
            ProbeLog.record("appinv.app",
                            "id=\(id) type=\(type) deletable=\(del.map { $0 ? "1" : "0" } ?? "?") "
                            + "team=\(team) path=\(url)")
        }

        ProbeLog.record("appinv.list",
                        "count=\(raw.count) system=\(system) user=\(user) note=done")
    }

    // MARK: - 绕过 sensitive URL 名单

    /// 只发一次，且**只发这一个**：`openSensitiveURL` 会真的把进程切走，
    /// 发第二个的时候本进程已经在后台，读数是假的。
    ///
    /// 选 `App-prefs:root=Privacy` 而不是别的，是因为它在 `sysapp` 那层
    /// 大概率已经有一条 `refused` 的读数——两条并排，差值就是「名单」本身。
    private static func fireSensitive(_ ws: AnyObject) {
        let target = "App-prefs:root=Privacy"
        guard let u = URL(string: target) else { return }

        let before = ProbeLog.appState
        let handled = sendBool2(ws, "openSensitiveURL:withOptions:", u as AnyObject, nil)

        var after = ProbeLog.appState
        for _ in 0..<10 {
            if after != before { break }
            Thread.sleep(forTimeInterval: 0.1)
            after = ProbeLog.appState
        }

        ProbeLog.record("appinv.sensitive",
                        "url=<\(target)> before=\(before) after=\(after) "
                        + "returned=\(handled.map { $0 ? "true" : "false" } ?? "nil") "
                        + "note=\(after == "background" ? "switched" : "inert")")
    }
}

#endif  // canImport(UIKit)
