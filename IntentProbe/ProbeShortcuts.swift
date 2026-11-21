import AppIntents

/// 注册进"App 快捷指令"画廊，让本 App 出现在 快捷指令 → App 快捷指令 列表里。
///
/// 注意：`phrases` 在**编译期**就被校验（必须含 \(.applicationName)），
/// 但 `AppEntity` 的 `suggestedEntities()` 是**运行时**返回的——
/// 也就是说画廊里显示的内容有一部分是我们运行时可任意控制的字符串。
///
/// 上限：Apple 规定每个 App 最多 10 个 AppShortcut，超了构建会报错。
struct ProbeShortcuts: AppShortcutsProvider {
    static var shortcutTileColor: ShortcutTileColor = .blue

    static var appShortcuts: [AppShortcut] {
        // ---- 输入边界（原有 5 个）----
        AppShortcut(
            intent: ProbeTextIntent(),
            phrases: ["用 \(.applicationName) 接收文本"],
            shortTitle: "接收文本",
            systemImageName: "doc.text"
        )

        AppShortcut(
            intent: ProbeFileIntent(),
            phrases: ["用 \(.applicationName) 接收文件"],
            shortTitle: "接收文件",
            systemImageName: "doc"
        )

        AppShortcut(
            intent: ProbeEntityIntent(),
            phrases: ["用 \(.applicationName) 接收实体"],
            shortTitle: "接收实体",
            systemImageName: "list.bullet"
        )

        AppShortcut(
            intent: ProbeURLIntent(),
            phrases: ["用 \(.applicationName) 接收链接"],
            shortTitle: "接收链接",
            systemImageName: "link"
        )

        AppShortcut(
            intent: ProbeSpoofIntent(),
            phrases: ["用 \(.applicationName) 弹窗"],
            shortTitle: "伪装弹窗",
            systemImageName: "exclamationmark.shield"
        )

        // ---- 沙箱与代码加载（新增 4 个）----
        AppShortcut(
            intent: ProbeSweepIntent(),
            phrases: ["用 \(.applicationName) 扫描环境"],
            shortTitle: "环境扫描",
            systemImageName: "map"
        )

        AppShortcut(
            intent: ProbePathIntent(),
            phrases: ["用 \(.applicationName) 探测路径"],
            shortTitle: "探测路径",
            systemImageName: "folder.badge.questionmark"
        )

        AppShortcut(
            intent: ProbeDylibIntent(),
            phrases: ["用 \(.applicationName) 加载动态库"],
            shortTitle: "加载动态库",
            systemImageName: "shippingbox"
        )

        AppShortcut(
            intent: ProbeFileDeepIntent(),
            phrases: ["用 \(.applicationName) 深挖文件"],
            shortTitle: "文件深挖",
            systemImageName: "doc.text.magnifyingglass"
        )

        // 第 10 个，正好到 Apple 的上限
        AppShortcut(
            intent: ProbeCodeExecIntent(),
            phrases: ["用 \(.applicationName) 测试代码执行"],
            shortTitle: "代码执行",
            systemImageName: "cpu"
        )
    }
}
