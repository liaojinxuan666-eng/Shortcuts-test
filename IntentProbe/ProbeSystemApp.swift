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
///
/// ## v11 的核心改动：串行，一次激活只发一个
///
/// v10 是一次循环发 21 个，跑出来 `open_accepted=3/21`。这个数字是假的，原因很硬：
///
/// ```
/// 第一个 open 成功 → 本进程被切到后台 → 之后每一次 open 都从后台发起
///                → iOS 对后台发起的 open 一律拒绝
/// ```
///
/// 证据是**完美的相关性**：`before=active` 的 3 行全部 `accepted`，
/// `before!=active` 的 18 行全部 `refused` 或 `no-callback`，零例外。
/// 也就是说 `open_accepted` 这个指标测的是"我当时在不在前台"，不是"这个 scheme 通不通"。
/// 只要有一行是 `before=background`，那一行的 open 结果就没有信息量。
///
/// 所以 v11 把矩阵拆成"一次激活发一个"：发完就被切走，用户回到本 App，
/// 下一次 `scenePhase == .active` 自动发下一个。每个目标都在 active 下发出，
/// 每一行都可判读。代价是要点 6 次（重点组）或 22 次（全量组）。
///
/// ## 第二个改动：判据从 completion handler 换成"有没有真的被切走"
///
/// v10 里 `safari.x-https` 报 `open=refused`，但屏幕上 Safari 确实起来了。
/// 两个可能，v10 的数据分不开：
///  (a) 后台调用时 handler 返回 false，但 URL 仍然被投递了（假阴性）
///  (b) 屏幕上那个页面其实是**第一个** `control.https` 打开的，跟 x-https 无关
///
/// 从时间线看 (b) 更可能：`control.https` 是 00:37:54 第一个发的，
/// 之后所有行 `before=` 都是 inactive/background，说明 Safari 一直在前台待着。
/// 但"更可能"不是"确定"，所以 v11 同时做三件事把它钉死：
///
///  1. **每个目标的 URL 带自己的名字**（`?probe=<label>`）。截图一拍就知道是哪个目标开的。
///  2. **监听 `didEnterBackgroundNotification` 并打时间戳**。发出后 3 秒内被切走
///     = 系统真的接了这个 URL，跟 handler 说什么无关。这是主判据。
///  3. handler 的返回值降级成辅助字段，不再当结论用。
///
/// ## 第三个改动：把"我声明了什么"自己打出来
///
/// v10 里 `x-web-search` 和 `x-safari-https` **没有**写进 `LSApplicationQueriesSchemes`
/// （见 project.yml），`canOpenURL` 却返回 true。这跟"未声明一律 false"的文档说法冲突。
/// 要么是系统 App 的 handler 绕过了声明门槛，要么是打包出来的 plist 跟我以为的不一样。
/// v11 运行时把 `Bundle.main` 里真实的声明列表 dump 出来，这条歧义就没了。
enum ProbeSystemApp {

    struct Target {
        let label: String
        let url: String
        let note: String
        /// 重点组：真正值得为它多点一次的。
        let priority: Bool

        init(_ label: String, _ url: String, _ note: String, priority: Bool = false) {
            self.label = label
            self.url = url
            self.note = note
            self.priority = priority
        }
    }

    /// 候选表。**正负对照必须排最前面**，否则"全是 false"读不出任何东西。
    ///
    /// 每个 URL 都带 `?probe=<label>`（能带的都带），这样任何一张截图都能自证身份——
    /// v10 就是栽在这上面：屏幕上那个 example.com 到底是哪个目标开的，说不清。
    static let all: [Target] = [
        // ---- 对照：这两行不过，整张表作废 ----
        Target("control.https",
               "https://example.com/?probe=control.https",
               "正对照：http/https 不需要声明，必须 canOpen=true 且真的把 Safari 拉起来",
               priority: true),
        Target("control.bogus",
               "probe-nonexistent-scheme://x?probe=control.bogus",
               "负对照：没 handler 又没声明，必须 false / refused。它 true 了整张表就作废",
               priority: true),

        // ---- Safari 私有入口：v10 里唯一"看着矛盾"的一组 ----
        Target("safari.x-https",
               "x-safari-https://example.com/?probe=safari.x-https",
               "私有写法。跟 control.https 打同一个域名，只有 URL 里的 probe 值不同——"
               + "这样截图能直接分辨是谁开的",
               priority: true),
        Target("safari.x-http",
               "x-safari-http://example.com/?probe=safari.x-http",
               "同族的第二个样本。如果它也 canOpen=true，说明整个 x-safari-* 都绕过声明门槛，"
               + "而不是某一个 scheme 的偶然",
               priority: true),
        Target("safari.web-search",
               "x-web-search://?probe=safari.web-search",
               "Safari 搜索入口。历史上被用来免交互唤起搜索",
               priority: true),

        // ---- Shortcuts：最值得看的一组 ----
        Target("shortcuts.run",
               "shortcuts://run-shortcut?name=ProbeNoSuchShortcut&input=text&text=probe",
               "按名字触发用户已有的快捷指令。名字故意不存在，只会失败——问的是「接不接」",
               priority: true),
        Target("shortcuts.import",
               "shortcuts://import-workflow?url=file:///private/etc/passwd&name=probe",
               "drive-by 导入。指向一个导不进来的文件，所以只会失败"),
        Target("shortcuts.gallery",
               "shortcuts://gallery/search?query=probe",
               "画廊搜索页"),
        Target("shortcuts.create",
               "shortcuts://create-shortcut",
               "空工作流"),

        // ---- 设置：历史上被封过又放开过 ----
        Target("prefs.privacy",
               "App-prefs:root=Privacy",
               "跳隐私页"),
        Target("prefs.passwords",
               "App-prefs:PASSWORDS",
               "密码页"),
        Target("prefs.legacy",
               "prefs:root=Privacy",
               "老写法，iOS 10 之后基本失效。预期 false，是 canOpen 表在不在干活的证据"),

        // ---- 文件与媒体 ----
        Target("files", "shareddocuments://", "文件 App"),
        Target("photos", "photos-redirect://", "照片"),
        Target("music", "music://", "音乐"),

        // ---- 通信 ----
        Target("tel", "tel:10086", "会弹拨号确认"),
        Target("sms", "sms:10086&body=probe", "会弹信息确认"),
        Target("mailto", "mailto:probe@example.invalid?subject=probe", "邮件"),
        Target("maps", "maps://?q=probe", "地图"),

        // ---- 历史上真正出过事的两个入口 ----
        Target("safari.file", "file:///private/etc/passwd",
               "让 Safari 读本地文件。预期被拒，但值得量一次留底"),
        Target("safari.data", "data:text/html,%3Cb%3Eprobe%3C%2Fb%3E",
               "data: URL。iOS 9 之后基本封死"),
        Target("itms-services",
               "itms-services://?action=download-manifest&url=https://127.0.0.1:1/probe.plist",
               "只测接不接。manifest 指向必然连不上的地址。"
               + "v10 里它 accepted 但弹了个「无法连接 127.0.0.1」——"
               + "这就是 accepted≠worked 的实物标本"),
    ]

    static func targets() -> [Target] { all }
    static var priorityTargets: [Target] { all.filter(\.priority) }

    // MARK: - 自定义 URL 的前缀表

    /// **第一项是 `x-safari-https`**，因为这一组就是为它加的；
    /// 最后一项 `raw` 是"自己写全"，用来打完整 URL。
    ///
    /// 用 struct 不用元组：`ForEach` 的 `id:` 要 KeyPath，
    /// 而 Swift 的 KeyPath 不能指向元组元素（`\.key` 编不过）。
    struct Prefix: Identifiable {
        let key: String
        let title: String
        var id: String { key }
    }

    static let prefixes: [Prefix] = [
        Prefix(key: "x-safari-https", title: "x-safari-https"),
        Prefix(key: "x-safari-http",  title: "x-safari-http"),
        Prefix(key: "https",          title: "https"),
        Prefix(key: "http",           title: "http"),
        Prefix(key: "x-web-search",   title: "x-web-search（当搜索词）"),
        Prefix(key: "raw",            title: "原样（自己写全）"),
    ]

    // MARK: - 只问不做

    /// `canOpenURL` 是同步的、无副作用的，所以这一整列**不受串行/前后台影响**，
    /// v10 那 21 行 canOpen 到现在依然有效。
    @MainActor
    static func canOpenLines(_ list: [Target] = all) -> (lines: [String], yes: Int) {
        var out: [String] = []
        var yes = 0
        for t in list {
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

    /// 把 `Bundle.main` 里真实的 `LSApplicationQueriesSchemes` 打出来。
    ///
    /// v10 的 `x-web-search` / `x-safari-https` 明明没写进 project.yml 却 canOpen=true。
    /// 这一行是那条歧义的唯一解药：如果这里也没有它们，那就是"系统 App 的 handler
    /// 绕过声明门槛"这个结论，而不是"我记错了自己声明了什么"。
    static func declaredSchemes() -> [String] {
        let raw = Bundle.main.object(forInfoDictionaryKey: "LSApplicationQueriesSchemes")
        return (raw as? [String]) ?? []
    }

    // MARK: - 真交出去（单点，必须在前台调用）

    /// 三件事一起记，缺一个就判不了：
    ///
    ///  - `open=` → completion 回调说什么（**辅助字段**，后台调用时会假阴性）
    ///  - `after=` → 本进程被切走了没有
    ///  - `left=` → 发出后 3 秒内有没有 `didEnterBackground`（**主判据**）
    ///
    /// 最容易误判的两种形态：
    ///  - `accepted` + 没被切走 = URL 收下了，什么都没发生（v10 的 itms-services）
    ///  - `refused` + 被切走了 = handler 在说谎，URL 其实投递了（v10 疑似 x-safari-https）
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

        var after = ProbeLog.appState
        for _ in 0..<pollTicks {
            if after != before { break }
            try? await Task.sleep(nanoseconds: 100_000_000)
            after = ProbeLog.appState
        }

        let line = "\(t.label) :: before=\(before) after=\(after) open=\(cb)"
        return (line, cb == "accepted")
    }
}

// MARK: - 串行执行器

/// UserDefaults 的键。
///
/// **故意放在 `@MainActor` 类型外面。** 键只是字符串常量，但一旦写进
/// `@MainActor` 的 enum 里就变成 main-actor-isolated，而
/// `didEnterBackground` 的观察闭包是 `@Sendable` 的——Xcode 16.4 会直接报
/// "main actor-isolated static property 'kBgAt' can not be referenced from
/// a Sendable closure"。现在只是警告，Swift 6 语言模式下是错误。
/// 挪出来就没有这个问题，也不需要 `nonisolated(unsafe)` 这种掩耳盗铃的写法。
private enum SysAppKeys {
    static let cursor = "sysapp.cursor"
    static let run = "sysapp.run"
    static let armed = "sysapp.armed"
    static let lastFire = "sysapp.lastfire"
    static let bgAt = "sysapp.bgat"
    static let mode = "sysapp.mode"        // "priority" | "all"
}

/// 一次激活只发一个目标。
///
/// 状态全放 UserDefaults：进程会被挂起、可能被系统回收，
/// 内存里的 cursor 丢了就得从头再来一遍 22 次点击。
@MainActor
enum SysAppRunner {

    static var mode: String {
        get { UserDefaults.standard.string(forKey: SysAppKeys.mode) ?? "priority" }
        set { UserDefaults.standard.set(newValue, forKey: SysAppKeys.mode) }
    }

    static var queue: [ProbeSystemApp.Target] {
        mode == "all" ? ProbeSystemApp.all : ProbeSystemApp.priorityTargets
    }

    static var cursor: Int {
        get { UserDefaults.standard.integer(forKey: SysAppKeys.cursor) }
        set { UserDefaults.standard.set(newValue, forKey: SysAppKeys.cursor) }
    }
    static var runId: String {
        get { UserDefaults.standard.string(forKey: SysAppKeys.run) ?? "-" }
        set { UserDefaults.standard.set(newValue, forKey: SysAppKeys.run) }
    }
    static var armed: Bool {
        get { UserDefaults.standard.bool(forKey: SysAppKeys.armed) }
        set { UserDefaults.standard.set(newValue, forKey: SysAppKeys.armed) }
    }
    static var lastFire: Date? {
        get { UserDefaults.standard.object(forKey: SysAppKeys.lastFire) as? Date }
        set { UserDefaults.standard.set(newValue, forKey: SysAppKeys.lastFire) }
    }
    static var bgAt: Date? {
        get { UserDefaults.standard.object(forKey: SysAppKeys.bgAt) as? Date }
        set { UserDefaults.standard.set(newValue, forKey: SysAppKeys.bgAt) }
    }

    static var progress: String {
        armed ? "\(cursor)/\(queue.count)" : "未开始"
    }

    /// 只记一次 `left=`，所以用一个 flag 挡住重复写。
    private static var flushed = false
    /// `.onAppear` 可能被调多次，observer 不能跟着重复注册。
    private static var installed = false

    static func install() {
        guard !installed else { return }
        installed = true
        _ = NotificationCenter.default.addObserver(
            forName: UIApplication.didEnterBackgroundNotification,
            object: nil, queue: .main
        ) { _ in
            let now = Date()
            UserDefaults.standard.set(now, forKey: SysAppKeys.bgAt)
            Task { @MainActor in flushPending(left: .background, bgAt: now) }
        }
    }

    static func reset(to newMode: String) {
        mode = newMode
        cursor = 0
        armed = true
        flushed = false
        lastFire = nil
        bgAt = nil
        runId = ISO8601DateFormatter().string(from: Date())
        ProbeLog.record("sysapp.run",
                        "run=\(runId) mode=\(newMode) queue=\(queue.count) "
                        + "declared=\(ProbeSystemApp.declaredSchemes().joined(separator: ",")) "
                        + "os=\(UIDevice.current.systemVersion) model=\(UIDevice.current.model)")
        // 队列顺序也落盘：日志里只写 idx=3/6 的话，事后没人知道第 3 个是什么。
        ProbeLog.record("sysapp.queue",
                        "run=\(runId) order=\(queue.map(\.label).joined(separator: ">"))")
    }

    static func stop() {
        armed = false
        ProbeLog.record("sysapp.stop", "run=\(runId) at=\(cursor)/\(queue.count)")
    }

    /// 发出一个 URL 之后，本进程最终落到了哪个状态。
    ///
    /// **这三档就是"有没有弹确认框"的判据**，之前只有两档，漏掉了最关键的一档：
    ///
    /// | 落点 | 含义 | 用户看到什么 |
    /// |---|---|---|
    /// | `.background` | 真的被切走了 | Safari 直接起来了，**没有确认框** |
    /// | `.inactive` | 被盖住但没切走 | 屏幕上多半压着一个系统确认框在等用户点 |
    /// | `.none` | 什么都没变 | URL 收下了，但没有任何反应 |
    ///
    /// iOS 的"要在 XX 中打开吗？"是 SpringBoard 的 alert，它只让前台 App
    /// 变成 `inactive`，不会让它进 `background`。所以 `.inactive` 这一档
    /// 恰恰是"弹了框"的指纹——这正是这轮要量的东西。
    enum Left { case none, inactive, background }

    private struct Pending {
        let kind: String       // "sysapp.open" | "sysapp.custom"
        let tag: String        // "idx=3/6" | "url=<...>"
        let label: String
        let cb: () -> String
    }
    private static var pending: Pending?
    /// 轮询期间见过的最深状态。
    private static var observed: String = "active"

    private static func flushPending(left: Left, bgAt: Date?) {
        guard !flushed, let p = pending else { return }
        flushed = true
        pending = nil

        let after: String
        let leftStr: String
        let verdict: String
        switch left {
        case .background:
            after = "background"; leftStr = "yes";     verdict = "switched"
        case .inactive:
            after = "inactive";   leftStr = "partial"; verdict = "possibly-prompted"
        case .none:
            after = "active";     leftStr = "no";      verdict = "inert"
        }

        var latency = "-"
        if case .background = left, let f = lastFire, let b = bgAt {
            latency = String(format: "%.2fs", b.timeIntervalSince(f))
        }

        ProbeLog.record(p.kind,
                        "run=\(runId) \(p.tag) \(p.label) :: "
                        + "before=active after=\(after) open=\(p.cb()) "
                        + "left=\(leftStr) verdict=\(verdict) latency=\(latency)")

        // 自定义那一路要当场把结论回显到界面上：日志在最底下，
        // 而这一组是"点一下就想知道发生了什么"。
        if p.kind == "sysapp.custom" {
            lastCustom = "\(verdict) · left=\(leftStr) · open=\(p.cb()) · \(p.tag)"
        }
    }

    /// 真正的"交出去 + 判读"。串行队列和自定义 URL 共用这一份，
    /// 否则两边的判据会慢慢漂开，读数就没法横向比。
    private static func deliver(url: URL, label: String, kind: String, tag: String) async {
        var cb = "no-callback"
        flushed = false
        observed = "active"
        lastFire = Date()
        pending = Pending(kind: kind, tag: tag, label: label, cb: { cb })

        UIApplication.shared.open(url, options: [:]) { ok in
            cb = ok ? "accepted" : "refused"
        }

        // 8 × 150ms = 1.2 秒。切走的第一步是 inactive，几十毫秒内就到；
        // 停在 inactive 不动，就是被系统 alert 盖住了。
        for _ in 0..<8 {
            if flushed { break }
            let s = ProbeLog.appState
            if s == "background" { observed = "background"; break }
            if s == "inactive" { observed = "inactive" }
            try? await Task.sleep(nanoseconds: 150_000_000)
        }

        if !flushed {
            flushPending(left: observed == "inactive" ? .inactive : .none, bgAt: nil)
        }
    }

    // MARK: - 自定义 URL（手动，一次一发）

    /// 把用户输入拼成 URL。
    ///
    /// 输入里已经带 `://` 的先剥掉，这样"example.com/a?b=c" 和
    /// "https://example.com/a?b=c" 选同一个前缀会得到同一个结果——
    /// 不然两个看起来一样的输入打出两种 URL，读数就没法比。
    static func compose(prefix: String, raw: String) -> URL? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else { return nil }

        if prefix == "raw" { return URL(string: s) }

        if prefix == "x-web-search" {
            let q = s.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? s
            return URL(string: "x-web-search://?\(q)")
        }

        var body = s
        if let r = body.range(of: "://") {
            body = String(body[r.upperBound...])
        }
        return URL(string: "\(prefix)://\(body)")
    }

    private static let kLastCustom = "sysapp.custom.last"

    /// 上一次自定义的结果，给 UI 回显用。**这是唯一能当场看到结论的地方**——
    /// 日志要滚到最底下才看得见，而这一组恰恰是"我点一下就想知道发生了什么"。
    static var lastCustom: String {
        get { UserDefaults.standard.string(forKey: kLastCustom) ?? "-" }
        set { UserDefaults.standard.set(newValue, forKey: kLastCustom) }
    }

    /// 自定义 URL：不消费 cursor、不 arm，随时可以打一发。
    ///
    /// 和串行队列走同一个 `deliver`，所以 `verdict` 的含义完全一致：
    /// `switched` = 直接进 Safari 没弹框，`possibly-prompted` = 停在 inactive，
    /// `inert` = 什么都没发生。
    static func fireCustom(raw: String, prefix: String) async {
        guard let u = compose(prefix: prefix, raw: raw) else {
            lastCustom = "URL 拼不出来 :: <\(raw)> prefix=\(prefix)"
            ProbeLog.record("sysapp.custom", "invalid raw=<\(raw)> prefix=\(prefix)")
            return
        }

        let before = ProbeLog.appState
        guard before == "active" else {
            lastCustom = "没发：当前 \(before)，必须在 active 下发起"
            ProbeLog.record("sysapp.custom",
                            "invalid url=<\(u.absoluteString)> before=\(before) note=not-active")
            return
        }

        ProbeLog.record("sysapp.fire",
                        "run=\(runId) custom prefix=\(prefix) url=<\(u.absoluteString)> "
                        + "trigger=bar-custom before=active")

        bgAt = nil
        await deliver(url: u, label: "prefix=\(prefix)", kind: "sysapp.custom",
                      tag: "url=<\(u.absoluteString)>")
    }

    /// 发下一个。**只有 `before == active` 才消费 cursor**，
    /// 否则记一条 invalid 直接返回——不能拿后台的读数去充数。
    static func fireNext(trigger: String) async {
        guard armed else { return }

        let q = queue
        let n = q.count
        let i = cursor
        guard i < n else {
            armed = false
            ProbeLog.record("sysapp.summary",
                            "run=\(runId) mode=\(mode) done=\(n)/\(n) "
                            + "note=serial-one-per-activation")
            return
        }

        let before = ProbeLog.appState
        guard before == "active" else {
            ProbeLog.record("sysapp.invalid",
                            "run=\(runId) idx=\(i + 1)/\(n) label=\(q[i].label) "
                            + "before=\(before) note=not-consumed")
            return
        }

        let t = q[i]
        guard let u = URL(string: t.url) else { return }

        // 先落盘再调用：进程可能立刻被挂起，回调不一定等得到。
        // 这条 `fire` 行就是"确实在 active 下发出去了"的凭证。
        ProbeLog.record("sysapp.fire",
                        "run=\(runId) idx=\(i + 1)/\(n) label=\(t.label) "
                        + "trigger=\(trigger) before=active url=\(t.url)")

        cursor = i + 1
        bgAt = nil

        await deliver(url: u, label: t.label, kind: "sysapp.open", tag: "idx=\(i + 1)/\(n)")
    }

    /// 回到前台时补一条。`launched=yes` 是这一轮唯一可信的"系统真的接了"的证据。
    static func noteReturn() {
        guard armed, let f = lastFire, let b = bgAt else { return }
        let away = b.timeIntervalSince(f)
        ProbeLog.record("sysapp.ret",
                        "run=\(runId) next=\(cursor + 1)/\(queue.count) "
                        + String(format: "launched=%@ away=%.2fs", away < 3.0 ? "yes" : "late", away))
        lastFire = nil
        bgAt = nil
    }
}

// MARK: - 13. 交给系统 App（矩阵，非串行）

/// 保留 v10 的整批模式，只用于"我就想看后台批量调用会怎样"。
/// **别用它出结论**——见文件头。
struct ProbeSystemAppIntent: AppIntent {
    static var title: LocalizedStringResource = "Probe: 交给系统 App"
    static var description: IntentDescription? =
        IntentDescription("枚举 URL scheme，记录 canOpenURL 与 open 的差异，以及交接后本进程的去向。")
    static var openAppWhenRun: Bool = false

    @Parameter(title: "模式（canopen / open）", default: "canopen")
    var mode: String

    init() {}
    init(mode: String) { self.mode = mode }

    func perform() async throws -> some IntentResult {
        ProbeLog.recordContext("sysapp.ctx")
        ProbeLog.record("sysapp.mode", "mode=<\(mode)>")
        ProbeLog.record("sysapp.decl",
                        "declared=\(ProbeSystemApp.declaredSchemes().joined(separator: ","))")

        if mode == "canopen" {
            for line in await ProbeSystemApp.canOpenMatrix() {
                ProbeLog.record("sysapp.canopen", line)
            }
            return .result()
        }

        // 批量 open：第一行 active，之后全 background，读数不可用。
        for t in ProbeSystemApp.all {
            let (line, _) = await ProbeSystemApp.openOne(t, pollTicks: 3)
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
/// 如果这条路在后台也能成，而 `UIApplication.open` 在后台一律 refused，
/// 那这个差值就是一条真实的信任边界不对称：
/// **同一个动作，走 intent 返回值比走 App API 的权限更大。**
///
/// `OpenURLIntent` 是 iOS 18 才有的类型，而本工程部署目标是 17.0。
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

        // 只留一条 return 路径：`some IntentResult` 是不透明返回类型，
        // 所有 return 的底层类型必须一致，否则报
        // "return statements in its body do not have matching underlying types"。
        let parsed = URL(string: target)
        let url = parsed ?? URL(fileURLWithPath: "/probe-invalid-handoff")

        // 日志先落盘：系统接管之后这个进程可能立刻被挂起。
        ProbeLog.record("handoff.result",
                        "returned-to-system url=\(url.scheme ?? "-") parsed=\(parsed == nil ? "invalid" : "ok")")
        return .result(opensIntent: OpenURLIntent(url))
    }
}

#endif  // canImport(UIKit)
