#if canImport(UIKit)
import SwiftUI
import WebKit

/// App 内 WebView 探针：把 URL 交给自己渲染，而不是递给 Safari。
///
/// 为什么要单开这一条通道：
///
/// `UIApplication.open` 只能把 URL 递给别的 App。Safari 拿到 `file:` 之后
/// 一律判"网址无效"并弹框——那条线上量到的**全是 Safari 的策略**，
/// 量不到"本 App 能不能读这个文件"。所以前面几轮 `file://` 全是死路，
/// 不是 sandbox 拦的，是接收侧根本不处理。
///
/// `WKWebView.loadFileURL(_:allowingReadAccessTo:)` 是另一条路：它会把一个
/// 沙箱扩展下发给 WebContent 进程，读取范围由**调用方**指定。于是真正值得问的
/// 问题变成：这个扩展能不能越过 App 自己的沙箱边界？
///
/// 三档读数正好把边界卡出来：
///   - 容器内文件 + `documents` 根  → 应该成功（正对照，证明通道没坏）
///   - 系统文件 + `disk` 根（/）    → 成 / 不成，就是沙箱边界的答案
///   - 任何 file URL + `none`       → 不给扩展时的基线
///
/// 不加 `@MainActor`：`WebProbeSheet` 的属性初始化器不在主 actor 上，
/// 引用一个 main-actor 隔离的 `shared` 会直接编译失败。而 WKWebView 的
/// delegate 回调和 `evaluateJavaScript` 的 completion 本来就在主线程，
/// 不需要靠标注来保证。
final class WebProbe: NSObject, ObservableObject {

    static let shared = WebProbe()

    /// `loadFileURL` 的读取根。决定 WebContent 进程能读到哪一层。
    enum Root: String, CaseIterable, Identifiable {
        case noAccess, container, documents, disk

        var id: String { rawValue }

        var title: String {
            switch self {
            case .noAccess:  return "不给读权限 · load(URLRequest)"
            case .container: return "App 容器根"
            case .documents: return "容器 Documents"
            case .disk:      return "/ 整盘（撞沙箱边界）"
            }
        }

        var url: URL? {
            switch self {
            case .noAccess:  return nil
            case .container: return URL(fileURLWithPath: NSHomeDirectory())
            case .documents: return URL(fileURLWithPath: NSHomeDirectory())
                                   .appendingPathComponent("Documents", isDirectory: true)
            case .disk:      return URL(fileURLWithPath: "/", isDirectory: true)
            }
        }
    }

    @Published var headline: String = "还没加载过"
    @Published var detail: String = "-"

    private var web: WKWebView?

    /// 只建一次。每次重建会丢掉 WKWebView 的进程池，加载会明显变慢，
    /// 而且旧实例的 delegate 回调会晚到，把新的读数盖掉。
    func webView() -> WKWebView {
        if let w = web { return w }
        let cfg = WKWebViewConfiguration()
        cfg.defaultWebpagePreferences.allowsContentJavaScript = true
        let w = WKWebView(frame: .zero, configuration: cfg)
        w.navigationDelegate = self
        w.allowsBackForwardNavigationGestures = true
        web = w
        return w
    }

    func load(_ raw: String, root: Root) {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else { return }
        guard let u = URL(string: s) else {
            headline = "URL 解析失败"
            ProbeLog.record("web.parse", "raw=<\(s)> note=invalid-url")
            return
        }

        headline = "加载中…"
        detail = u.absoluteString

        // 这一行要在 load 之前落盘：file:// 的失败可能发生在很早期的
        // WebContent 启动阶段，晚一点写就可能等不到。
        ProbeLog.record("web.load",
                        "url=<\(u.absoluteString)> scheme=\(u.scheme ?? "-") "
                        + "isFile=\(u.isFileURL) root=\(root.rawValue) "
                        + "rootpath=<\(root.url?.path ?? "-")>")

        let w = webView()
        if u.isFileURL, let r = root.url {
            w.loadFileURL(u, allowingReadAccessTo: r)
        } else {
            w.load(URLRequest(url: u))
        }
    }

    /// 读回渲染结果。**这一步才是"真的读到了"的证据**——
    /// `didFinish` 只证明导航结束，一个空白页也会 `didFinish`。
    private func readback(_ w: WKWebView) {
        let js = "JSON.stringify({t:document.title,"
            + "n:(document.body?document.body.innerText.length:-1),"
            + "h:(document.body?document.body.innerText.slice(0,160):'')})"
        w.evaluateJavaScript(js) { any, err in
            // 回调在主线程，和 delegate 一致，不需要再切队列。
            if let err = err {
                let e = err as NSError
                ProbeLog.record("web.js", "err_domain=\(e.domain) err_code=\(e.code) "
                                + "desc=<\(e.localizedDescription)>")
                self.headline = "已加载，JS 读不回来"
                return
            }
            let s = (any as? String) ?? "<\(String(describing: any))>"
            ProbeLog.record("web.js", "result=\(s)")
            self.headline = "已渲染 · \(s)"
        }
    }

    private func fail(_ error: Error, phase: String) {
        let e = error as NSError
        // 错误码能分清三种失败，别混着读：
        //   257 NSURLErrorNoPermissionsToReadFile        → 读不到，权限/沙箱
        //   101 WebKitErrorCannotShowURL                → WebKit 不认这个 scheme
        //   102 WebKitErrorFrameLoadInterruptedByPolicyChange → 被策略掐断
        //   1   NSURLErrorUnknown                       → 常见于 file 扩展被拒后的兜底
        ProbeLog.record("web.fail",
                        "phase=\(phase) domain=\(e.domain) code=\(e.code) "
                        + "desc=<\(e.localizedDescription)> "
                        + "url=\(e.userInfo[NSURLErrorFailingURLStringErrorKey] as? String ?? "-")")
        headline = "失败 · \(e.domain) \(e.code)"
        detail = e.localizedDescription
    }
}

extension WebProbe: WKNavigationDelegate {

    func webView(_ webView: WKWebView,
                 didStartProvisionalNavigation navigation: WKNavigation!) {
        ProbeLog.record("web.start", "url=<\(webView.url?.absoluteString ?? "-")>")
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        ProbeLog.record("web.finish", "url=<\(webView.url?.absoluteString ?? "-")>")
        readback(webView)
    }

    func webView(_ webView: WKWebView,
                 didFail navigation: WKNavigation!, withError error: Error) {
        fail(error, phase: "commit")
    }

    func webView(_ webView: WKWebView,
                 didFailProvisionalNavigation navigation: WKNavigation!,
                 withError error: Error) {
        fail(error, phase: "provisional")
    }
}

/// 把 `WebProbe` 那个单例包进 SwiftUI。`updateUIView` 故意留空：
/// 加载由按钮驱动，不跟着 SwiftUI 的刷新走——否则每敲一个字就会重新导航。
struct WebProbeContainer: UIViewRepresentable {
    func makeUIView(context: Context) -> WKWebView {
        WebProbe.shared.webView()
    }
    func updateUIView(_ uiView: WKWebView, context: Context) {}
}

struct WebProbeSheet: View {

    @ObservedObject private var probe = WebProbe.shared
    @Environment(\.dismiss) private var dismiss

    @State private var url: String = "file:///private/etc/passwd"
    @State private var root: WebProbe.Root = .noAccess

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                VStack(alignment: .leading, spacing: 8) {
                    TextField("URL，支持 file://", text: $url)
                        .font(.system(size: 12, design: .monospaced))
                        .textFieldStyle(.roundedBorder)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                        .submitLabel(.go)
                        .onSubmit { probe.load(url, root: root) }

                    HStack(spacing: 6) {
                        Picker("", selection: $root) {
                            ForEach(WebProbe.Root.allCases) { r in
                                Text(r.title).tag(r)
                            }
                        }
                        .pickerStyle(.menu)
                        .labelsHidden()
                        .font(.system(size: 11))

                        Spacer()

                        Button {
                            probe.load(url, root: root)
                        } label: {
                            Label("加载", systemImage: "globe")
                                .font(.system(size: 11))
                        }
                        .buttonStyle(.borderedProminent)
                    }

                    Text(probe.headline)
                        .font(.system(size: 10, weight: .semibold, design: .monospaced))
                        .lineLimit(3)
                    Text(probe.detail)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 10)

                Divider()

                WebProbeContainer()
            }
            .navigationTitle("内置 WebView")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("关闭") { dismiss() }
                }
            }
        }
    }
}
#endif
