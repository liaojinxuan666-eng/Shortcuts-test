import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

@main
struct IntentProbeApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

struct ContentView: View {
    @State private var log: String = ""
    /// 串行执行器的进度要靠它刷新：UserDefaults 不是 @Published，改了自己不会触发重绘。
    @State private var tick: Int = 0

    /// 自定义 URL：想打哪个站点就打哪个，不用改代码重装。
    @State private var customURL: String = "example.com/?probe=custom"
    @State private var customPrefix: String = "x-safari-https"
    @State private var lastCustom: String = "-"

    /// 内置 WebView 的开关。file:// 那条线在外面（Safari）是死路，
    /// 只能拿到"网址无效"；要量"本 App 能不能读"，得自己渲染。
    @State private var showWebProbe = false

    @Environment(\.scenePhase) private var scenePhase

    private let refreshTimer = Timer.publish(every: 1.5, on: .main, in: .common).autoconnect()

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                sysAppBar
                Divider()
                customBar
                Divider()
                ScrollView {
                    Text(log.isEmpty ? "(空)\n\n让一个快捷指令调用本 App 的 intent，这里会出现记录。" : log)
                        .font(.system(.caption, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding()
                        .textSelection(.enabled)
                }
            }
            .navigationTitle("Probe Log · \(ProbeLog.buildTag)")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    // 直接在 App 里跑一遍环境扫描。省掉"改快捷指令 → 跑 → 看日志"的往返，
                    // 结果和从 Shortcuts 触发完全一致：同一个进程、同一个沙箱。
                    Button {
                        Task { @MainActor in
                            _ = try? await ProbeSweepIntent().perform()
                            reload()
                        }
                    } label: {
                        Image(systemName: "bolt.horizontal")
                    }
                }
                ToolbarItem(placement: .primaryAction) {
                    // 一键扫"哪些目录我能写"。和走快捷指令完全等价（同进程同沙箱），
                    // 但省掉改快捷指令的往返——矩阵有 19 个目录，来回改参数太慢。
                    Button {
                        Task { @MainActor in
                            _ = try? await ProbeCreateFileIntent(matrix: true).perform()
                            reload()
                        }
                    } label: {
                        Image(systemName: "folder.badge.plus")
                    }
                }
                ToolbarItem(placement: .primaryAction) {
                    // 自己渲染 URL。`open` 那条路只能递给 Safari，
                    // 而 Safari 对 file: 一律判"网址无效"，量不到 sandbox 边界。
                    Button {
                        showWebProbe = true
                    } label: {
                        Image(systemName: "globe")
                    }
                }
                ToolbarItem(placement: .primaryAction) {
                    ShareLink(item: ProbeLog.url) {
                        Image(systemName: "square.and.arrow.up")
                    }
                }
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        reload()
                    } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                }
            }
            .onAppear {
                SysAppRunner.install()
                reload()
            }
            .onReceive(refreshTimer) { _ in reload() }
            .sheet(isPresented: $showWebProbe) {
                WebProbeSheet()
            }
            .onChange(of: scenePhase) { _, phase in
                guard phase == .active else { return }
                Task { @MainActor in
                    // 顺序不能反：先补上"上一个目标有没有把系统叫起来"，
                    // 再发下一个。反了的话 noteReturn 会读到下一轮的 lastFire。
                    SysAppRunner.noteReturn()
                    await SysAppRunner.fireNext(trigger: "became-active")
                    reload()
                }
            }
        }
    }

    /// 自定义 URL：验证"没有提示就直接进 Safari"这件事。
    ///
    /// 判据不在屏幕上，在日志的 `verdict=` 字段：
    ///
    /// ```
    /// verdict=switched           真的切走了 → Safari 直接起来，没有确认框
    /// verdict=possibly-prompted  停在 inactive → 多半压着一个系统确认框
    /// verdict=inert              什么都没发生 → URL 收下了但没反应
    /// ```
    ///
    /// 只改前缀、不改域名，跑两次就能把 `https` 和 `x-safari-https` 分开：
    /// 如果两个都 `switched`，说明私有 scheme 没有额外权限；
    /// 如果 `https` 被系统换成了默认浏览器而 `x-safari-https` 硬进 Safari，
    /// 那才是这两者真正的差别。
    private var customBar: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                TextField("example.com 或完整 URL", text: $customURL)
                    .font(.system(size: 12, design: .monospaced))
                    .textFieldStyle(.roundedBorder)
                    .keyboardType(.URL)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .submitLabel(.go)
                    .onSubmit { fireCustom() }
            }

            HStack(spacing: 6) {
                Picker("", selection: $customPrefix) {
                    ForEach(ProbeSystemApp.prefixes) { p in
                        Text(p.title).tag(p.key)
                    }
                }
                .pickerStyle(.menu)
                .labelsHidden()
                .font(.system(size: 11))

                Spacer()

                Button {
                    fireCustom()
                } label: {
                    Label("打开", systemImage: "safari")
                        .font(.system(size: 11))
                }
                .buttonStyle(.borderedProminent)
            }

            HStack(spacing: 6) {
                // 结论单独做成色块。上一版只把它塞在一行灰色小字里，
                // `inert` 和"没点上"在屏幕上长得一样——那轮你连点三次就是这个原因。
                Text(SysAppRunner.lastVerdict)
                    .font(.system(size: 10, weight: .bold, design: .monospaced))
                    .foregroundStyle(verdictColor)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(verdictColor.opacity(0.14), in: Capsule())

                Text(lastCustom)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            Text(verdictHint)
                .font(.system(size: 10))
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    /// 结论上色。四象限 + 两个异常档，跟 `flushPending` 里的 switch 一一对应，
    /// 两边改一边就得改另一边——所以这里不再做字符串切分，直接读独立的 `lastVerdict`。
    private var verdictColor: Color {
        switch SysAppRunner.lastVerdict {
        case "switched":                return .green
        case "silent-delivered":        return .blue
        case "possibly-prompted":       return .orange
        case "prompted-then-refused":   return .orange
        case "anomaly-false-negative":  return .purple
        case "inert":                   return .red
        case "no-callback-inert":       return .gray
        default:                        return .gray
        }
    }

    /// 一句话解释这一档到底意味着什么。判据越细，越需要在屏幕上直接说人话，
    /// 否则读日志的人还得回来翻文档。
    private var verdictHint: String {
        switch SysAppRunner.lastVerdict {
        case "switched":
            return "投递 + 抢前台：目标真的起来了，全程没有确认框"
        case "silent-delivered":
            return "投递了但没抢前台：URL 送到了，目标在后台处理（不是失败）"
        case "possibly-prompted":
            return "停在 inactive：多半压着一个系统确认框在等你点"
        case "inert":
            return "真没投递：scheme 不被接受，什么都没发生"
        case "anomaly-false-negative":
            return "handler 说谎：进程被切走了，回调却报 refused"
        case "prompted-then-refused":
            return "被盖住又报 refused：可能弹了框，但没送成"
        case "no-callback-inert":
            return "三秒内没回调也没切走：不能断言被拒，只能说没反应"
        default:
            return "还没打过，或者读数不完整"
        }
    }

    private func fireCustom() {
        let raw = customURL
        let prefix = customPrefix
        Task { @MainActor in
            await SysAppRunner.fireCustom(raw: raw, prefix: prefix)
            reload()
        }
    }

    /// 串行执行器的小控制条。
    ///
    /// 为什么不放工具栏：iPhone 上 5 个图标已经挤满了，再加就折叠进溢出菜单，
    /// 而这一组恰恰是"必须看到进度、必须知道下一步该干什么"的那种。
    private var sysAppBar: some View {
        let armed = SysAppRunner.armed
        let cur = SysAppRunner.cursor
        let total = SysAppRunner.queue.count
        let done = cur >= total && total > 0

        return VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Image(systemName: "paperplane")
                    .font(.caption)
                Text(done ? "已完成 \(total)/\(total)" : (armed ? "串行 \(cur)/\(total)" : "串行 · 未开始"))
                    .font(.system(.caption, design: .monospaced).weight(.semibold))
                Spacer()
                if armed && !done {
                    Button("停") {
                        SysAppRunner.stop()
                        reload()
                    }
                    .font(.caption)
                    .buttonStyle(.bordered)
                }
                Button(done ? "再来一轮" : (armed ? "继续" : "开始")) {
                    Task { @MainActor in
                        if !armed || done {
                            SysAppRunner.reset(to: "priority")
                            await SysAppRunner.fireNext(trigger: "bar-start")
                        } else {
                            await SysAppRunner.fireNext(trigger: "bar-tap")
                        }
                        reload()
                    }
                }
                .font(.caption)
                .buttonStyle(.borderedProminent)
            }

            if armed && !done {
                Text("下一个：\(SysAppRunner.queue[min(cur, total - 1)].label) · 发完会切走，点回本 App 继续")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(.secondary)
            } else if !armed {
                Text("6 个重点目标，一次发一个。每次都在前台发起，读数才有效。")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(.secondary)
            }

            HStack(spacing: 8) {
                Button("全量 22 个") {
                    Task { @MainActor in
                        SysAppRunner.reset(to: "all")
                        await SysAppRunner.fireNext(trigger: "bar-all")
                        reload()
                    }
                }
                .font(.system(size: 10))
                .buttonStyle(.bordered)

                Button("只看 canOpen") {
                    Task { @MainActor in
                        for line in await ProbeSystemApp.canOpenMatrix() {
                            ProbeLog.record("sysapp.canopen", line)
                        }
                        ProbeLog.record("sysapp.decl",
                                        "declared=\(ProbeSystemApp.declaredSchemes().joined(separator: ","))")
                        reload()
                    }
                }
                .font(.system(size: 10))
                .buttonStyle(.bordered)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(.thinMaterial)
    }

    private func reload() {
        log = (try? String(contentsOf: ProbeLog.url, encoding: .utf8)) ?? ""
        lastCustom = SysAppRunner.lastCustom
        tick &+= 1
    }
}
