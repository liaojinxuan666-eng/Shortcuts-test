import AppIntents
import Foundation

// MARK: - 实体

struct ProbeEntity: AppEntity {
    static var typeDisplayRepresentation: TypeDisplayRepresentation = "Probe 实体"
    static var defaultQuery = ProbeEntityQuery()

    /// 这个 id 完全由我们的 App 控制。
    /// 它会被 Shortcuts 持久化进 workflow 文件——也就是会被导出、分享、在别人设备上重新解析。
    var id: String

    init(id: String) { self.id = id }

    var displayRepresentation: DisplayRepresentation {
        let short = String(id.prefix(80))
        let sub = "len=" + String(id.count)
        return DisplayRepresentation(
            title: LocalizedStringResource(stringLiteral: short),
            subtitle: LocalizedStringResource(stringLiteral: sub)
        )
    }
}

// MARK: - 查询

/// 三个入口都会被调用，全部记录：
///  - entities(for:)      ← Shortcuts 拿着已持久化的 ID 回来解析（最危险：ID 来自文件）
///  - entities(matching:) ← 用户在搜索框里输入
///  - suggestedEntities() ← 填充 Shortcuts 的"App 快捷指令"画廊
struct ProbeEntityQuery: EntityStringQuery {
    func entities(for identifiers: [String]) async throws -> [ProbeEntity] {
        ProbeLog.recordContext("entity.for.ctx")
        ProbeLog.record("entity.for", "count=\(identifiers.count) ids=<\(identifiers.joined(separator: " | "))>")
        return identifiers.map { ProbeEntity(id: $0) }
    }

    func entities(matching string: String) async throws -> [ProbeEntity] {
        ProbeLog.record("entity.match", "<\(string)>")
        return ProbeHostileIdentifiers.all.map { ProbeEntity(id: $0) }
    }

    func suggestedEntities() async throws -> [ProbeEntity] {
        ProbeLog.record("entity.suggested", "returned \(ProbeHostileIdentifiers.all.count)")
        return ProbeHostileIdentifiers.all.map { ProbeEntity(id: $0) }
    }
}

// MARK: - 枚举

enum ProbeMode: String, AppEnum {
    case safe
    case hostile

    static var typeDisplayRepresentation: TypeDisplayRepresentation = "Probe 模式"
    static var caseDisplayRepresentations: [ProbeMode: DisplayRepresentation] = [
        .safe: "安全",
        .hostile: "对抗",
    ]
}
