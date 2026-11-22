import SwiftUI

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

    private let refreshTimer = Timer.publish(every: 2, on: .main, in: .common).autoconnect()

    var body: some View {
        NavigationStack {
            ScrollView {
                Text(log.isEmpty ? "(空)\n\n让一个快捷指令调用本 App 的 intent，这里会出现记录。" : log)
                    .font(.system(.caption, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
                    .textSelection(.enabled)
            }
            .navigationTitle("Probe Log · \(ProbeLog.buildTag)")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    // 直接在 App 里跑一遍环境扫描。省掉"改快捷指令 → 跑 → 看日志"的往返，
                    // 结果和从 Shortcuts 触发完全一致：同一个进程、同一个沙箱。
                    Button {
                        Task {
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
                        Task {
                            _ = try? await ProbeCreateFileIntent(matrix: true).perform()
                            reload()
                        }
                    } label: {
                        Image(systemName: "folder.badge.plus")
                    }
                }
                ToolbarItem(placement: .primaryAction) {
                    // 一键把 21 个 URL 交给系统 App。这是唯一能真正触发
                    // ProbeSystemApp 的入口——它没注册进 AppShortcutsProvider
                    // （上限 10 个，画廊满了），从快捷指令里搜得到但很难找。
                    //
                    // 注意：每 open 一次本进程就被切走，所以第一行是前台发起、
                    // 后面都是后台发起。`before=` 字段会自己写清楚。
                    Button {
                        Task {
                            _ = await ProbeSystemApp.runAll(origin: "foreground")
                            reload()
                        }
                    } label: {
                        Image(systemName: "paperplane")
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
            .onAppear { reload() }
            .onReceive(refreshTimer) { _ in reload() }
        }
    }

    private func reload() {
        log = (try? String(contentsOf: ProbeLog.url, encoding: .utf8)) ?? ""
    }
}
