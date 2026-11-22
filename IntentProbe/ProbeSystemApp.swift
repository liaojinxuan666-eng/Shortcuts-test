import AppIntents
import Foundation

// 整个文件都依赖 UIKit：`canOpenURL` / `open` 都是 UIApplication 的方法。
// macOS 版编译的是**同一批源码**，那边 canImport(UIKit) 为假，所以整段都要关掉，
// 否则 macOS target 会报 "cannot find 'UIApplication' in scope"。
// 这个 target 在 CI 里是 continue-on-error，但"能编过"和"靠 continue-on-error 兜住"
// 是两件事，别混。
#if canImport(UIKit)
import UIKit

/// 把活交给系统 App 做。
///
/// 这一组问的不是"我能不能做"，而是"**我能不能让一个比我权限高的进程替我做**"。
/// 后者才是 App Intents 这条边界上真正的攻击面：28 个 Shortcuts CVE 里 0 个
/// 内存破坏，全是这类逻辑问题。
///
/// ## 三种交接机制，差别本身就是结论
///
/// | 机制 | 谁在执行 | 需要我在前台吗 |
/// |---|---|---|
/// | `canOpenURL` | 没人执行，只问策略 | 不需要 |
/// | `UIApplication.open` | **我的进程**发起请求 | 大概率需要 |
/// | 返回 `opensIntent: OpenURLIntent` | **系统**在 intent 返回后自己去做 | 不需要 |
///
/// 第三行是重点。它不是私有 API，是 App Intents 官方给 intent 用的"把 URL 交给系统"，
/// 由系统在 intent 返回之后执行——也就是说执行的发起者不是我的进程。
/// 如果 #3 在后台能成而 #2 不能，那这个差值就是一条真实的信任边界不对称：
/// **同一个动作，走 intent 返回值比走 App API 的权限更大。**
///
/// ## 一个必须提前说清的局限
///
/// 这里只能量到"系统接不接"，量不到 Safari / Shortcuts 接到之后做了什么。
/// `open=accepted` 只证明 URL 被收下了，不证明目标 App 执行了任何操作。
/// 所以这一组的产出是**线索**，不是 finding——要变成 finding，得在接收侧
/// 证明它没校验来源。
enum ProbeSystemApp {

    struct Target {
        let label: String
        let url: String
        let note: String
    }

    /// 候选表。**正负对照必须排最前面**，否则"全是 false"读不出任何东西。
    ///
    /// 挑的原则：每个都是"如果我做不到、但系统 App 做得到"的那一类。
    /// 预期大部分是 false，那不是发现，是 `LSApplicationQueriesSchemes` 的
    /// 既定门槛——`canOpenURL` 对未声明的 scheme 一律返回 false，
    /// **哪怕目标 App 装着**。所以 false 不能读成"没装"。
    static func targets() -> [Target] {
        [
            // ---- 对照 ----
            Target(label: "control.https",
                   url: "https://example.com",
                   note: "正对照：http/https 不需要声明，必须 true"),
            Target(label: "control.bogus",
                   url: "probe-nonexistent-scheme://x",
                   note: "负对照：必须 false。它 true 了整张表就作废"),

            // ---- Shortcuts：最值得看的一组 ----
            Target(label: "shortcuts.run",
                   url: "shortcuts://run-shortcut?name=ProbeNoSuchShortcut&input=text&text=probe",
                   note: "按名字触发用户已有的快捷指令。名字故意不存在，只会失败"),
            Target(label: "shortcuts.import",
                   url: "shortcuts://import-workflow?url=file:///private/etc/passwd&name=probe",
                   note: "drive-by 导入。指向一个导不进来的文件，所以只会失败——问的是「接不接」而不是「能不能成」"),
            Target(label: "shortcuts.gallery",
                   url: "shortcuts://gallery/search?query=probe",
                   note: "画廊搜索页"),
            Target(label: "shortcuts.create",
                   url: "shortcuts://create-shortcut",
                   note: "空工作流"),

            // ---- 设置：历史上被封过又放开过 ----
            Target(label: "prefs.privacy",
                   url: "App-prefs:root=Privacy",
                   note: "跳隐私页"),
            Target(label: "prefs.passwords",
                   url: "App-prefs:PASSWORDS",
                   note: "密码页"),
            Target(label: "prefs.legacy",
                   url: "prefs:root=Privacy",
                   note: "老写法，iOS 10 之后基本失效"),

            // ---- 文件与媒体 ----
            Target(label: "files",
                   url: "shareddocuments://",
                   note: "文件 App"),
            Target(label: "photos",
                   url: "photos-redirect://",
                   note: "照片"),
            Target(label: "music",
                   url: "music://",
                   note: "音乐"),

            // ---- 通信 ----
            Target(label: "tel",
                   url: "tel:10086",
                   note: "会弹拨号确认"),
            Target(label: "sms",
                   url: "sms:10086&body=probe",
                   note: "会弹信息确认"),
            Target(label: "mailto",
                   url: "mailto:probe@example.invalid?subject=probe",
                   note: "邮件"),
            Target(label: "maps",
                   url: "maps://?q=probe",
                   note: "地图"),

            // ---- Safari 自己的入口 ----
            Target(label: "safari.web-search",
                   url: "x-web-search://?probe",
                   note: "Safari 的搜索入口。历史上被用来免交互唤起搜索"),
            Target(label: "safari.x-https",
                   url: "x-safari-https://example.com",
                   note: "私有写法，部分系统组件用它唤起 Safari。和 control.https 对比就知道它是不是等价物"),

            // ---- 历史上真正出过事的两个入口 ----
            Target(label: "safari.file",
                   url: "file:///private/etc/passwd",
                   note: "让 Safari 读本地文件。预期被拒，但值得量一次留底"),
            Target(label: "safari.data",
                   url: "data:text/html,%3Cb%3Eprobe%3C%2Fb%3E",
                   note: "data: URL。iOS 9 之后基本封死"),
            Target(label: "itms-services",
                   url: "itms-services://?action=download-manifest&url=https://127.0.0.1:1/probe.plist",
                   note: "只测接不接。manifest 指向必然连不上的地址，装不了任何东西"),
        ]
    }

    // MARK: - 只问不做

    /// `canOpenURL` 对未声明的 scheme 一律 false，且会往控制台打一条警告。
    /// 这条读数的意义**只在于和 `open` 的结果对比**，单独看没有信息量。
    @MainActor
    static func canOpenLines() -> (lines: [String], yes: Int) {
        var out: [String] = []
        var yes = 0
        for t in targets() {
            guard let u = URL(string: t.url) else {
                out.append("\(t.label) :: url=invalid <\(t.url)>")
                continue
            }
            let ok = UIApplication.shared.canOpenURL(u)
            if ok { yes += 1 }
            out.append("\(t.label) :: canOpen=\(ok)")
        }
        return (out, yes)
    }

    @MainActor
    static func canOpenMatrix() -> [String] { canOpenLines().lines }

    // MARK: - 真交出去

    /// 三件事一起记，缺一个就判不了：
    ///
    ///  - `open=` → completion 回调说什么（`no-callback` 说明回调根本没被调）
    ///  - `before=` / `after=` → 本进程有没有被切走。**这才是"系统真的接了"的证据**
    ///  - 超时 → 后台状态下 open 常常既不回调也不切走，只能靠轮询发现
    ///
    /// 最容易误判的形态是 `open=accepted` 而 `after == before`：
    /// URL 被收下了，但什么都没发生。只看 open 会把它读成成功。
    @MainActor
    static func openOne(_ t: Target, pollTicks: Int = 10) async -> (String, Bool) {
        guard let u = URL(string: t.url) else {
            return ("\(t.label) :: url=invalid", false)
        }

        let before = ProbeLog.appState
        var cb = "no-callback"
        UIApplication.shared.open(u, options: [:]) { ok in
            cb = ok ? "accepted" : "refused"
        }

        // 先读再睡：切走的第一步是 inactive，往往在几十毫秒内就发生。
        // 如果先睡 100ms 再读，很可能已经错过这一拍——尤其当系统很快又把
        // 我拉回前台时，`after` 会等于 `before`，整条读数就变成假阴性。
        var after = ProbeLog.appState
        for _ in 0..<pollTicks {
            if after != before { break }
            try? await Task.sleep(nanoseconds: 100_000_000)
            after = ProbeLog.appState
        }

        let line = "\(t.label) :: before=\(before) after=\(after) open=\(cb)"
        return (line, cb == "accepted")
    }

    @MainActor
    static func openMatrix() async -> [String] {
        var out: [String] = []
        var accepted = 0
        for t in targets() {
            let (line, ok) = await openOne(t)
            if ok { accepted += 1 }
            out.append(line)
        }
        out.append("summary :: accepted=\(accepted)/\(targets().count)")
        return out
    }

    // MARK: - App 内一键跑完整矩阵

    /// 存在的理由和 P12 那个工具栏按钮一样：21 个 scheme 来回改快捷指令参数太慢。
    ///
    /// 两个副作用必须处理，否则跑出来的表是假的：
    ///
    ///  1. **每 open 一次，本进程就被切到后台。** 第一行是前台发起，之后都是后台发起。
    ///     这不是缺陷——`before=` 字段自己会写清楚每一行是从什么状态发起的，
    ///     等于一次拿到两种条件。想单独要前台基线，就每次只跑一个目标。
    ///  2. **后台大约 30 秒后会被挂起**，21 个目标跑不完。用 background task 要一段
    ///     额外时间，并把轮询压到 3 拍（300ms）：切走的第一步是 inactive，
    ///     300ms 足够，再多只是白等。
    @MainActor
    static func runAll(origin: String, pollTicks: Int = 3) async -> String {
        var bg: UIBackgroundTaskIdentifier = .invalid
        bg = UIApplication.shared.beginBackgroundTask(withName: "probe.sysapp", expirationHandler: { })
        defer {
            if bg != .invalid { UIApplication.shared.endBackgroundTask(bg) }
        }

        ProbeLog.recordContext("sysapp.ctx")
        ProbeLog.record("sysapp.origin", "origin=\(origin) targets=\(targets().count)")

        let can = canOpenLines()
        for line in can.lines { ProbeLog.record("sysapp.canopen", line) }

        var accepted = 0
        for t in targets() {
            let (line, ok) = await openOne(t, pollTicks: pollTicks)
            if ok { accepted += 1 }
            ProbeLog.record("sysapp.open", line)
        }

        let n = targets().count
        let summary = "origin=\(origin) canopen_true=\(can.yes)/\(n) open_accepted=\(accepted)/\(n)"
        ProbeLog.record("sysapp.summary", summary)
        return summary
    }
}

// MARK: - 13. 交给系统 App（矩阵）

/// `openAppWhenRun = false` 是有意的：从快捷指令触发时本进程通常在后台，
/// 而"后台的 App 能不能让系统打开 URL"正是这一组要问的问题之一。
/// 想拿前台基线，就在 App 里点一次、再从快捷指令跑一次，对比两份日志的 `before=`。
struct ProbeSystemAppIntent: AppIntent {
    static var title: LocalizedStringResource = "Probe: 交给系统 App"
    static var description: IntentDescription? =
        IntentDescription("枚举 URL scheme，记录 canOpenURL 与 open 的差异，以及交接后本进程的去向。")
    static var openAppWhenRun: Bool = false

    /// `canopen` = 只问不做；`open` = 真交给系统。
    @Parameter(title: "模式（canopen / open）", default: "open")
    var mode: String

    init() {}
    init(mode: String) { self.mode = mode }

    func perform() async throws -> some IntentResult {
        ProbeLog.recordContext("sysapp.ctx")
        ProbeLog.record("sysapp.mode", "mode=<\(mode)>")

        if mode == "canopen" {
            for line in await ProbeSystemApp.canOpenMatrix() {
                ProbeLog.record("sysapp.canopen", line)
            }
            return .result()
        }

        for line in await ProbeSystemApp.openMatrix() {
            ProbeLog.record("sysapp.open", line)
        }
        return .result()
    }
}

// MARK: - 14. 交给系统 App（单点，由系统执行）

/// 和上面那个的关键区别：**这里不调 `UIApplication.open`。**
///
/// 返回 `.result(opensIntent: OpenURLIntent(url))` 之后，是**系统**在 intent
/// 返回、本进程可能已经退到后台的时刻，替我把 URL 打开。发起者不是我的进程。
///
/// 所以同一个 URL 用两条路各跑一次，结果可能不同：
///
/// ```
/// sysapp.open      :: shortcuts.run :: before=background after=background open=no-callback
/// handoff.executed :: shortcuts.run :: returned-to-system
/// ```
///
/// 如果第二条真的把快捷指令拉起来了，而第一条没有，那说明**"从 intent 返回值
/// 交出去"比"从 App 调 open"权限更大**。这是一个可以被证伪的具体命题。
///
/// `OpenURLIntent` 是 iOS 18 才有的类型，而本工程的部署目标是 17.0。
/// 整个 struct 挂 `@available` 而不是在函数体里写 `if #available`——后者会让
/// 两条分支的返回类型不同，见 `perform()` 里的注释。
@available(iOS 18.0, *)
struct ProbeHandoffIntent: AppIntent {
    static var title: LocalizedStringResource = "Probe: 交给系统打开"
    static var description: IntentDescription? =
        IntentDescription("把 URL 放进 intent 返回值，由系统在 intent 结束后执行。")
    static var openAppWhenRun: Bool = false

    @Parameter(title: "URL",
               default: "shortcuts://run-shortcut?name=ProbeNoSuchShortcut&input=text&text=probe")
    var target: String

    init() {}
    init(target: String) { self.target = target }

    func perform() async throws -> some IntentResult {
        ProbeLog.recordContext("handoff.ctx")
        ProbeLog.record("handoff.url", "<\(target)>")
        ProbeLog.record("handoff.state", "before-return=\(ProbeLog.appState)")

        // 只留一条 return 路径。`some IntentResult` 是不透明返回类型，
        // 所有 return 的底层类型必须一致：
        //   .result()                  → IntentResultContainer<Never,Never,Never,Never>
        //   .result(opensIntent: ...)  → IntentResultContainer<Never,OpenURLIntent,Never,Never>
        // 混着写会报 "return statements in its body do not have matching
        // underlying types"。所以 URL 非法时给一个必然失败的 scheme，
        // 而不是提前 return 一个空结果。
        let parsed = URL(string: target)
        let url = parsed ?? URL(fileURLWithPath: "/probe-invalid-handoff")

        // 日志先落盘：系统接管之后这个进程可能立刻被挂起，
        // 返回之后再写就来不及了。
        ProbeLog.record("handoff.result",
                        "returned-to-system url=\(url.scheme ?? "-") parsed=\(parsed == nil ? "invalid" : "ok")")
        return .result(opensIntent: OpenURLIntent(url))
    }
}

#endif  // canImport(UIKit)
