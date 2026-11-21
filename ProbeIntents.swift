import AppIntents
import Foundation

// MARK: - 1. 字符串：TCC 绕过的核心探针

/// 用途：让用户（或恶意 shortcut）把"剪贴板 / 照片 / 通讯录"的结果作为变量传进来。
/// 关键观察点：TCC 弹窗是否出现在"读取数据源"那一步？
/// 如果数据能一路流进本 intent 而我们拿到了明文，说明这条链上没有二次检查。
struct ProbeTextIntent: AppIntent {
    static var title: LocalizedStringResource = "Probe: 接收文本"
    static var description: IntentDescription? = IntentDescription("接收任意字符串并落盘记录。")
    static var openAppWhenRun: Bool = false

    static var parameterSummary: some ParameterSummary {
        Summary("Probe \(\.$input)")
    }

    @Parameter(title: "输入", description: "任意字符串，建议接一个变量")
    var input: String

    init() {}
    init(input: String) { self.input = input }

    func perform() async throws -> some IntentResult {
        ProbeLog.recordContext("text.ctx")
        ProbeLog.record("text", "len=\(input.count) value=<\(input)>")
        return .result()
    }
}

// MARK: - 2. 多值：测试数组展开与数量上限

struct ProbeArrayIntent: AppIntent {
    static var title: LocalizedStringResource = "Probe: 接收数组"
    static var description: IntentDescription? = IntentDescription("接收字符串数组。")

    @Parameter(title: "输入列表")
    var inputs: [String]

    init() {}
    init(inputs: [String]) { self.inputs = inputs }

    func perform() async throws -> some IntentResult {
        ProbeLog.recordContext("array.ctx")
        ProbeLog.record("array", "count=\(inputs.count) first=<\(inputs.first ?? "")>")
        return .result()
    }
}

// MARK: - 3. 文件：跨进程的文件句柄

/// 关键观察点：
///  - fileURL 指向哪里？是我的容器，还是 Shortcuts 的临时目录，还是别处？
///  - 如果是别处，我能不能读到超出"用户明确给我的那个文件"范围的东西？
///  - 文件名（filename）是否可被构造，从而在我的容器里造成路径穿越？
struct ProbeFileIntent: AppIntent {
    static var title: LocalizedStringResource = "Probe: 接收文件"
    static var description: IntentDescription? = IntentDescription("接收一个文件并记录其来源路径与大小。")

    @Parameter(title: "文件")
    var file: IntentFile

    init() {}
    init(file: IntentFile) { self.file = file }

    func perform() async throws -> some IntentResult {
        ProbeLog.recordContext("file.ctx")
        let data = file.data
        ProbeLog.record("file", "filename=<\(file.filename)> size=\(data.count) type=\(file.type?.identifier ?? "-")")

        if let u = file.fileURL {
            ProbeLog.record("file.url", u.path)
            // 试着从该 URL 往上走，看能不能触及父目录（路径逃逸探测）
            let parent = u.deletingLastPathComponent()
            ProbeLog.record("file.parent", parent.path)
            if let items = try? FileManager.default.contentsOfDirectory(atPath: parent.path) {
                ProbeLog.record("file.parent.list", "count=\(items.count) sample=\(items.prefix(5).joined(separator: ","))")
            }
        } else {
            ProbeLog.record("file.url", "(nil)")
        }

        // 顺手把内容也存一份，验证是否完整
        if let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first {
            try? data.write(to: dir.appendingPathComponent("received.bin"))
        }
        return .result()
    }
}

// MARK: - 4. URL：看 URL 解析器在哪一侧

struct ProbeURLIntent: AppIntent {
    static var title: LocalizedStringResource = "Probe: 接收 URL"
    static var description: IntentDescription? = IntentDescription("接收 URL，记录 scheme/host/path 的解析结果。")

    @Parameter(title: "URL")
    var url: URL

    init() {}
    init(url: URL) { self.url = url }

    func perform() async throws -> some IntentResult {
        ProbeLog.recordContext("url.ctx")
        let c = URLComponents(url: url, resolvingAgainstBaseURL: false)
        ProbeLog.record("url", "raw=<\(url.absoluteString)> scheme=\(c?.scheme ?? "-") host=\(c?.host ?? "-") path=\(c?.path ?? "-") query=\(c?.query ?? "-")")
        return .result()
    }
}

// MARK: - 5. 实体：运行时由我们提供，标识符完全可控

struct ProbeEntityIntent: AppIntent {
    static var title: LocalizedStringResource = "Probe: 接收实体"
    static var description: IntentDescription? = IntentDescription("接收一个由本 App 提供的实体。")

    @Parameter(title: "实体")
    var entity: ProbeEntity

    init() {}
    init(entity: ProbeEntity) { self.entity = entity }

    func perform() async throws -> some IntentResult {
        ProbeLog.recordContext("entity.ctx")
        ProbeLog.record("entity.received", "id.len=\(entity.id.count) id=<\(entity.id)>")
        return .result()
    }
}

// MARK: - 6. 返回文件：反向边界

/// 关键观察点：我返回的 IntentFile 会不会被后续 action 直接读取？
/// 如果能，我就可以塞任意内容（包括超长 / 特殊命名）进别人的流程。
struct ProbeEmitFileIntent: AppIntent {
    static var title: LocalizedStringResource = "Probe: 输出文件"
    static var description: IntentDescription? = IntentDescription("返回一个文件名被刻意构造的文件。")

    func perform() async throws -> some IntentResult & ReturnsValue<IntentFile> {
        let payload = Data("PROBE-PAYLOAD".utf8)
        let f = IntentFile(data: payload, filename: "../../../probe-escape.txt")
        return .result(value: f)
    }
}
