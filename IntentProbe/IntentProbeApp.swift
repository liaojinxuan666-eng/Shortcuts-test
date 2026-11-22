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

            Text("上次：\(lastCustom)")
                .font(.system(size: 10, design: .monospaced))
                .foregroundStyle(.secondary)
                .lineLimit(2)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
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
