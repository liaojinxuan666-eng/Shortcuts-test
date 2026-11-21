import Foundation

#if canImport(UIKit)
import UIKit
#elseif canImport(AppKit)
import AppKit
#endif

/// 所有 intent 收到的东西都写到这里，App 内可查看 / 可导出。
enum ProbeLog {
    static var url: URL {
        let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return dir.appendingPathComponent("probe.log")
    }

    static func record(_ kind: String, _ payload: String) {
        let ts = ISO8601DateFormatter().string(from: Date())
        let line = "[\(ts)] \(kind) :: \(payload)\n"
        guard let data = line.data(using: .utf8) else { return }

        if FileManager.default.fileExists(atPath: url.path),
           let h = try? FileHandle(forWritingTo: url) {
            defer { try? h.close() }
            _ = try? h.seekToEnd()
            _ = try? h.write(contentsOf: data)
        } else {
            try? data.write(to: url)
        }
    }

    /// 记录"我是谁、在什么状态下被调用"——判断是前台还是后台触发，决定了
    /// 实验 7（自动化零点击）能不能成立。
    static func recordContext(_ kind: String) {
        let b = Bundle.main
        let bid = b.bundleIdentifier ?? "?"
        let pid = ProcessInfo.processInfo.processIdentifier
        record(kind, "bundle=\(bid) pid=\(pid) appState=\(appState)")
    }

    static var appState: String {
#if canImport(UIKit)
        switch UIApplication.shared.applicationState {
        case .active:     return "active"
        case .inactive:   return "inactive"
        case .background: return "background"
        @unknown default: return "unknown"
        }
#elseif canImport(AppKit)
        return NSApplication.shared.isActive ? "active" : "background"
#else
        return "unknown"
#endif
    }
}

/// 故意构造的"有毒"实体标识符——用来观察 Shortcuts 怎么持久化它们。
enum ProbeHostileIdentifiers {
    static let all: [String] = [
        // 1. 超长：测试 workflow 文件的长度限制与截断行为
        String(repeating: "A", count: 10_000),

        // 2. 路径穿越：如果这个 ID 后续被当路径用
        "../../../../../../etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",

        // 3. plist 注入尝试：看导出时是否被转义
        "</string><key>WFWorkflowActions</key><array><dict/>",
        "\u{0}<script>",

        // 4. Unicode 双向覆盖：视觉上伪装显示内容
        "invoice\u{202E}gnp.exe",
        "abc\u{200B}\u{200B}\u{200B}def",

        // 5. 格式化字符串 / 模板注入探测
        "%@%@%@%n%n",
        "${jndi:ldap://127.0.0.1/a}",
        "{{7*7}}",
        "$(whoami)",

        // 6. 正常对照
        "normal-entity-1",
    ]
}
