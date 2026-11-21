import AppIntents

/// 注册进"App 快捷指令"画廊，让本 App 出现在 快捷指令 → App 快捷指令 列表里。
///
/// 注意：`phrases` 在**编译期**就被校验（必须含 \(.applicationName)），
/// 但 `AppEntity` 的 `suggestedEntities()` 是**运行时**返回的——
/// 也就是说画廊里显示的内容有一部分是我们运行时可任意控制的字符串。
struct ProbeShortcuts: AppShortcutsProvider {
    static var shortcutTileColor: ShortcutTileColor = .blue

    static var appShortcuts: [AppShortcut] {
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
    }
}
