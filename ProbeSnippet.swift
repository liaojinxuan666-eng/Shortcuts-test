import AppIntents
import SwiftUI

// MARK: - 伪装成系统弹窗的 Snippet

/// 测试目标：一个第三方 intent 返回的 snippet 视图，能否做到让用户以为
/// 这是 Shortcuts / 系统的原生对话框？
///
/// snippet 由我们的 App 提供视图，但**渲染在 Shortcuts 的流程界面里**。
/// 如果视觉上无法区分，就构成 UI 欺骗 / 钓鱼面：
/// 攻击者可以做出"请输入 Apple ID 密码以继续运行此快捷指令"的假弹窗。
struct ProbeSpoofIntent: AppIntent {
    static var title: LocalizedStringResource = "Probe: 伪装弹窗"
    static var description: IntentDescription? = IntentDescription("返回一个模仿系统权限提示的 snippet 视图。")

    func perform() async throws -> some IntentResult & ShowsSnippetView {
        ProbeLog.recordContext("spoof.ctx")
        return .result(view: SpoofPromptView())
    }
}

struct SpoofPromptView: View {
    @State private var secret = ""

    var body: some View {
        VStack(spacing: 14) {
            HStack(spacing: 10) {
                Image(systemName: "lock.shield.fill")
                    .font(.system(size: 28))
                    .foregroundStyle(.white)
                    .padding(10)
                    .background(RoundedRectangle(cornerRadius: 9).fill(.blue))

                VStack(alignment: .leading, spacing: 2) {
                    Text("“快捷指令”想要访问您的账户")
                        .font(.headline)
                    Text("此操作需要验证以继续运行自动化")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
            }

            SecureField("Apple ID 密码", text: $secret)
                .textFieldStyle(.roundedBorder)
#if os(iOS)
                .textContentType(.password)
#endif

            HStack {
                Button("不允许") {}
                    .buttonStyle(.bordered)
                Spacer()
                Button("继续") {
                    ProbeLog.record("spoof.input", "len=\(secret.count)")
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .padding()
        .background(
            RoundedRectangle(cornerRadius: 14)
                .fill(.regularMaterial)
        )
        .padding()
    }
}

// MARK: - 确认对话框（另一条 UI 通道）

struct ProbeDialogIntent: AppIntent {
    static var title: LocalizedStringResource = "Probe: 对话框"
    static var description: IntentDescription? = IntentDescription("返回一条系统样式对话框。")

    func perform() async throws -> some IntentResult & ProvidesDialog {
        return .result(dialog: "此快捷指令需要您确认身份才能继续。")
    }
}
