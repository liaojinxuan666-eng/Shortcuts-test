#if canImport(UIKit)
import Foundation
import Combine

/// mach 服务可达性矩阵。
///
/// 只回答一个问题：**一个没有私有 entitlement 的沙箱 App，能不能跟系统守护进程说上话。**
///
/// 结构上预期是"不能"：mach-lookup 归沙箱 profile 管，第三方 App 的 profile
/// 里没有放行项，也没有对应 entitlement。所以这里大概率全表
/// `Connection invalid`。测它的价值不在"打通"，在**把边界钉死**——
/// 和前面 mmap(RWX) 的 max prot、AMFI、file:// 那几条一样，
/// 负结果本身就是结论，而且是个能引用的结论。
///
/// 实现上全部走 `dlsym`，**不 `import XPC`**：iOS SDK 里 XPC 的 Swift module
/// 不一定存在，引错了整包编不过，那就又浪费一轮 CI。dlsym 顺便还多量一件事——
/// 这些符号在这个进程里到底在不在。
final class XPCProbe: ObservableObject {

    static let shared = XPCProbe()

    @Published var summary: String = "-"
    @Published var lastLine: String = "-"

    private var running = false

    struct Target {
        let name: String
        let note: String
    }

    /// 只做 lookup + 发一个空字典，不发任何有语义的请求。
    /// 目标是"能不能连上"，不是"连上之后能干什么"。
    static let targets: [Target] = [
        .init(name: "com.apple.cfprefsd.daemon",              note: "偏好设置后端"),
        .init(name: "com.apple.cfprefsd.agent",               note: "偏好设置 agent"),
        .init(name: "com.apple.system.notification_center",   note: "分布式通知"),
        .init(name: "com.apple.distributed_notifications.2",  note: "分布式通知 v2"),
        .init(name: "com.apple.securityd",                    note: "keychain"),
        .init(name: "com.apple.analyticsd",                   note: "分析"),
        .init(name: "com.apple.installd",                     note: "安装"),
        .init(name: "com.apple.mobile.installd",              note: "安装 mobile"),
        .init(name: "com.apple.backboardd",                   note: "背板/事件"),
        .init(name: "com.apple.springboard.services",         note: "SpringBoard"),
        .init(name: "com.apple.frontboard.systemappservices", note: "前台应用服务"),
        .init(name: "com.apple.runningboardd",                note: "进程管理"),
        .init(name: "com.apple.tccd",                         note: "隐私授权"),
        .init(name: "com.apple.nsurlsessiond",                note: "网络会话"),
        .init(name: "com.apple.WebKit.Networking",            note: "WebKit 网络进程"),
        .init(name: "com.apple.WebKit.WebContent",            note: "WebKit 渲染进程"),
        .init(name: "com.apple.pasteboard.pasted",            note: "剪贴板"),
        .init(name: "com.apple.UIKit.KeyboardManagement",     note: "键盘"),
    ]

    // MARK: - libxpc 的最小绑定

    private typealias FnCreate = @convention(c) (UnsafePointer<CChar>,
                                                 UnsafeMutableRawPointer?,
                                                 UInt64) -> UnsafeMutableRawPointer?
    private typealias FnSetEH  = @convention(c) (UnsafeMutableRawPointer,
                                                 @convention(block) (UnsafeMutableRawPointer) -> Void) -> Void
    private typealias FnResume = @convention(c) (UnsafeMutableRawPointer) -> Void
    private typealias FnCancel = @convention(c) (UnsafeMutableRawPointer) -> Void
    private typealias FnSend   = @convention(c) (UnsafeMutableRawPointer,
                                                 UnsafeMutableRawPointer) -> Void
    private typealias FnDict   = @convention(c) (UnsafePointer<UnsafePointer<CChar>?>?,
                                                 UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
                                                 Int) -> UnsafeMutableRawPointer?
    private typealias FnDesc   = @convention(c) (UnsafeMutableRawPointer) -> UnsafeMutablePointer<CChar>?

    private struct API {
        let create: FnCreate
        let setEH: FnSetEH
        let resume: FnResume
        let cancel: FnCancel
        let send: FnSend
        let dict: FnDict
        let desc: FnDesc
    }

    /// 三个来源依次试，**不要只写死路径**。
    ///
    /// v14 就是栽在这上面：`dlopen("/usr/lib/libxpc.dylib")` 返回 nil，
    /// 于是整张矩阵一行都没跑，日志里只有三行 `libxpc-symbols-missing`。
    /// 原因不是「libxpc 不可用」，而是 iOS 17 之后 `/usr/lib` 下的实体文件
    /// 基本被抽空了——同一次 sweep 里 `/usr/lib` 只列出 21 个条目，
    /// 连 `/usr/lib/libSystem.B.dylib` 都是 `lstat=ENOENT`。
    /// 真身都在 dyld shared cache 里，只有 install name 能命中。
    ///
    /// 所以顺序是：先在**已加载镜像**里找符号（RTLD_DEFAULT），
    /// 再用 install name dlopen，最后才回退到路径。
    private static func loadAPI() -> API? {
        func lookup(_ n: String) -> UnsafeMutableRawPointer? {
            if let p = dlsym(UnsafeMutableRawPointer(bitPattern: -2), n) { return p }  // RTLD_DEFAULT
            for name in ["libxpc.dylib", "/usr/lib/libxpc.dylib", "libxpc.A.dylib"] {
                if let h = dlopen(name, RTLD_LAZY), let p = dlsym(h, n) { return p }
            }
            return nil
        }
        func sym(_ n: String) -> UnsafeMutableRawPointer? { lookup(n) }
        guard let c  = sym("xpc_connection_create_mach_service"),
              let eh = sym("xpc_connection_set_event_handler"),
              let rs = sym("xpc_connection_resume"),
              let cx = sym("xpc_connection_cancel"),
              let sd = sym("xpc_connection_send_message"),
              let dc = sym("xpc_dictionary_create"),
              let de = sym("xpc_copy_description") else { return nil }
        return API(create: unsafeBitCast(c,  to: FnCreate.self),
                   setEH:  unsafeBitCast(eh, to: FnSetEH.self),
                   resume: unsafeBitCast(rs, to: FnResume.self),
                   cancel: unsafeBitCast(cx, to: FnCancel.self),
                   send:   unsafeBitCast(sd, to: FnSend.self),
                   dict:   unsafeBitCast(dc, to: FnDict.self),
                   desc:   unsafeBitCast(de, to: FnDesc.self))
    }

    /// `runSerial` 是 nonisolated async，跑在通用执行器上，不在主线程。
    /// `@Published` 从后台改会让 SwiftUI 在错误的线程上更新，Release 下是竞态，
    /// 不是崩溃但也别赌。统一回主线程发布。
    private func publish(_ s: String, line: String? = nil) {
        DispatchQueue.main.async {
            self.summary = s
            if let line = line { self.lastLine = line }
        }
    }

    private func publishLine(_ s: String) {
        DispatchQueue.main.async { self.lastLine = s }
    }

    /// 事件回调在 XPC 自己的队列上，不在主线程。用一个带锁的槽接住它。
    private final class Slot: @unchecked Sendable {
        private let lock = NSLock()
        private var v: String?
        func set(_ s: String) { lock.lock(); if v == nil { v = s }; lock.unlock() }
        var value: String? { lock.lock(); defer { lock.unlock() }; return v }
    }

    private static func describe(_ api: API, _ obj: UnsafeMutableRawPointer) -> String {
        guard let p = api.desc(obj) else { return "no-description" }
        defer { free(p) }
        let s = String(cString: p)
        return s.count > 140 ? String(s.prefix(140)) : s
    }

    /// 三档判词。`silent` 和 `denied` 必须分开：
    /// `no-event` 表示"没收到 CONNECTION_INVALID"，即 lookup 大概率成功了，
    /// 只是服务不理会这个空消息。把它算成失败会低估可达面，算成成功会高估。
    private static func classify(_ d: String) -> String {
        let low = d.lowercased()
        if low.contains("connection invalid")      { return "denied" }
        if low.contains("connection interrupted")  { return "interrupted" }
        if low.contains("connection")              { return "conn-error" }
        if low.hasPrefix("<dictionary") || low.hasPrefix("<string")
            || low.hasPrefix("<data") || low.hasPrefix("<array") { return "replied" }
        return "other"
    }

    // MARK: - 跑

    func runAll() {
        guard !running else {
            ProbeLog.record("xpc.busy", "note=already-running")
            return
        }
        running = true
        Task { await runSerial() }
    }

    private func runSerial() async {
        guard let api = XPCProbe.loadAPI() else {
            // 三个来源都试过还是缺，才下这个结论。附带把 /usr/lib 的实际情况记下来，
            // 免得下一轮又以为是「路径写错了」。
            ProbeLog.record("xpc.api",
                            "note=libxpc-symbols-missing tried=RTLD_DEFAULT,libxpc.dylib,/usr/lib/libxpc.dylib "
                            + "hint=ios17+_usr_lib_is_mostly_dyld_cache")
            publish("libxpc 符号缺失")
            running = false
            return
        }

        let n = XPCProbe.targets.count
        ProbeLog.record("xpc.ctx",
                        "build=\(ProbeLog.buildTag) targets=\(n) "
                        + "note=lookup-only-no-payload")

        var denied = 0, silent = 0, replied = 0, other = 0

        for (i, t) in XPCProbe.targets.enumerated() {
            let slot = Slot()

            t.name.withCString { cname in
                guard let conn = api.create(cname, nil, 0) else {
                    slot.set("create-nil")
                    return
                }
                let block: @convention(block) (UnsafeMutableRawPointer) -> Void = { ev in
                    slot.set(XPCProbe.describe(api, ev))
                }
                api.setEH(conn, block)
                api.resume(conn)
                if let msg = api.dict(nil, nil, 0) {
                    api.send(conn, msg)
                }
                // 1.4s 后收掉连接。CONNECTION_INVALID 通常在 resume 之后
                // 几十毫秒内就到，1.4s 足够；留这么长只是为了不误杀慢的。
                DispatchQueue.global().asyncAfter(deadline: .now() + 1.4) {
                    api.cancel(conn)
                }
            }

            try? await Task.sleep(nanoseconds: 1_200_000_000)

            let raw = slot.value
            let verdict: String
            if let raw = raw {
                verdict = XPCProbe.classify(raw)
            } else {
                verdict = "silent"   // 没收到任何事件 = 没有 CONNECTION_INVALID
            }

            switch verdict {
            case "denied":      denied += 1
            case "silent":      silent += 1
            case "replied":     replied += 1
            default:            other += 1
            }

            ProbeLog.record("xpc.probe",
                            "idx=\(i + 1)/\(n) name=\(t.name) note=\(t.note) "
                            + "verdict=\(verdict) raw=<\(raw ?? "-")>")
            publishLine("\(t.name) → \(verdict)")
        }

        ProbeLog.record("xpc.summary",
                        "denied=\(denied) silent=\(silent) replied=\(replied) "
                        + "other=\(other) total=\(n) note=lookup-only")
        publish("denied \(denied) · silent \(silent) · replied \(replied)")
        running = false
    }
}
#endif
