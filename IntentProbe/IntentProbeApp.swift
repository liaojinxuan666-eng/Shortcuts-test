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
            .navigationTitle("Probe Log")
            .toolbar {
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
