# IntentProbe

一个用来**从不受信任的一侧顶 Shortcuts / App Intents 信任边界**的探针 App。

不逆向 Shortcuts，而是自己挂上去：看系统愿意把什么交给第三方 App、愿意替它做什么。

> 配套文档：
> - [`PROBES.md`](PROBES.md) —— **9 个探针各自回答什么问题、结果怎么判读**（先看这个）
> - [`EXPERIMENTS.md`](EXPERIMENTS.md) —— 5 个可证伪假设 + 8 个实验
>
> 上游背景：28 个 Shortcuts CVE 里 **0 个内存破坏漏洞**，全是 TCC / 路径 / 沙箱逻辑问题。

---

## 一键构建

推到 GitHub 就有了。Actions 会自动：

1. `xcodegen` 生成工程
2. 编译 iOS（有证书就签名，没有就出未签名 IPA）
3. 编译 macOS 版（未签名）
4. 打包成 `.ipa` / `.zip`
5. **把 `Metadata.appintents` 导出来**——这是 H3 研究的原始素材

产物发布到 **Release**（tag `probe-latest`），每次构建自动覆盖更新：

```
https://github.com/<你>/intent-probe/releases/tag/probe-latest
```

Actions 的 Artifacts 也会存一份，但那只是备份——**Release 才是主下载入口**。


## 推送前自检

```bash
./scripts/verify.sh
```

10 秒内检查：6 个 `.swift` 是否都在、git 有没有真的跟踪、根目录有没有游离文件。
**推之前跑一下，能省掉一整轮 CI。**

---

## 签名配置

仓库 → Settings → Secrets and variables → Actions，添加：

| Secret | 必填 | 说明 |
|---|---|---|
| `BUILD_CERTIFICATE_BASE64` | 签名时必填 | `.p12` 的 base64 |
| `P12_PASSWORD` | 签名时必填 | `.p12` 的导出密码 |
| `PROVISIONING_PROFILE_BASE64` | 签名时必填 | `.mobileprovision` 的 base64 |
| `KEYCHAIN_PASSWORD` | 建议填 | 临时 keychain 的密码，随便设一个 |
| `TEAM_ID` | 签名时必填 | 10 位 Team ID（`security find-identity -v -p codesigning` 能看到） |
| `BUNDLE_ID` | 可选 | 默认 `com.probe.intentprobe`。**必须和描述文件的 App ID 匹配**，否则签名失败 |

生成 base64：

```bash
base64 -i cert.p12              -o cert.b64
base64 -i profile.mobileprovision -o profile.b64
# 然后 cat 出来贴进 Secrets
```

> 用**通配符 App ID**（如 `com.probe.*`）的描述文件最省事，`BUNDLE_ID` 随便改都不会失败。

**不配置也行**：会产出未签名 IPA，用 Sideloadly / AltStore / TrollStore 自己签。

---

## 探针列表（9 个）

| 探针 | 输入 | 回答的问题 |
|---|---|---|
| 接收文本 | String | 变量展开后 TCC 是否二次检查 |
| 接收文件 | IntentFile | `fileURL` 指向哪里 |
| 接收实体 | AppEntity | 标识符能否被持久化、长度上限 |
| 接收链接 | URL | `file://` scheme 是否被拒 |
| 伪装弹窗 | 无 | Snippet 视图能否冒充系统提示 |
| **环境扫描** | 无 | 容器、19 条系统路径、代码加载能力的全貌 |
| **探测路径** | String 路径 | stat / 读 / 列 / 写 / 建链接，五件事一次问完 |
| **加载动态库** | String 路径 | dlopen 卡在沙箱、签名、还是 W^X |
| **文件深挖** | IntentFile | security-scope、父目录、兄弟文件、能否当 dylib 加载 |

判读方法见 [`PROBES.md`](PROBES.md)。

---

## 产物（Release 附件）

| 文件 | 用途 |
|---|---|
| `IntentProbe-unsigned.ipa` | 手机安装用。未签名版本需自行签名 |
| `IntentProbe.app` | 裸 app，方便直接看 bundle 结构 |
| `IntentProbeMac-macos.zip` | macOS 版，**H3 元数据变异专用** |
| `metadata/**` | `Metadata.appintents` 原始文件，H3 的输入 |

### 安装

```bash
# 已签名 IPA：直接装
# 未签名 IPA：
#   - Sideloadly / AltStore：拖进去，用你自己的 Apple ID 签
#   - TrollStore：直接装（需要支持的系统版本）
#   - Xcode：Window → Devices and Simulators → 拖 .app 进去
```

### macOS 版运行

```bash
unzip IntentProbeMac-macos.zip
xattr -cr IntentProbeMac.app          # 去掉隔离属性
codesign --force --deep -s - IntentProbeMac.app   # ad-hoc 重签
open IntentProbeMac.app
```

> macOS 版存在的唯一理由：**H3（元数据变异）在 macOS 上成本极低**——改文件、ad-hoc 重签、双击运行，不需要证书也不需要真机。iOS 上做同样的实验要重签 + 装一次，慢一个数量级。

---

## 本地构建

```bash
brew install xcodegen
xcodegen generate
open IntentProbe.xcodeproj
```

或者命令行：

```bash
xcodebuild -project IntentProbe.xcodeproj -scheme IntentProbe \
  -configuration Release -sdk iphoneos -destination 'generic/platform=iOS' \
  -derivedDataPath build CODE_SIGNING_ALLOWED=NO build
./scripts/make_ipa.sh
```

---

## 仓库结构

```
.
├── .github/workflows/build.yml   CI：编译 + 签名 + 打包
├── project.yml                   XcodeGen 工程定义（不提交 .xcodeproj）
├── IntentProbe/
│   ├── IntentProbeApp.swift      入口 + 日志查看界面
│   ├── ProbeLog.swift            日志落盘 + 有毒标识符样本集
│   ├── ProbeIntents.swift        6 个探针 intent（文本/数组/文件/URL/实体/输出文件）
│   ├── ProbeEntity.swift         AppEntity + 三个查询入口
│   ├── ProbeSnippet.swift        伪装成系统弹窗的 snippet
│   └── ProbeShortcuts.swift      AppShortcutsProvider（让 App 出现在画廊里）
├── Support/                      Info.plist（由 xcodegen 生成）
├── scripts/make_ipa.sh           打包脚本
├── tools/fuzz_metadata.py        extract.actionsdata 变异器
└── EXPERIMENTS.md                实验手册 ★ 先看这个
```

---

## 五个假设速览

| | 假设 | 成立意味着 |
|---|---|---|
| **H1** | 敏感数据经变量流入第三方 intent 时，TCC 不二次检查 | 剪贴板/照片/通讯录可被静默外送 |
| **H2** | `AppEntity.id` 会被持久化进 workflow 文件 | shortcut 文件成为可控载荷载体 |
| **H3** | `extract.actionsdata` 在索引时被解析 | 畸形 blob = 安装即触发 |
| **H4** | snippet 视图渲染在 Shortcuts 界面里 | UI 欺骗 / 钓鱼 |
| **H5** | `IntentFile.fileURL` 暴露真实磁盘位置 | 读到超出授权范围的文件 |

详细实验步骤、观察点、判定标准见 [`EXPERIMENTS.md`](EXPERIMENTS.md)。

---

## 边界

- 只在**自己持有的设备**上测试
- 不要用真实用户数据做样本
- 发现漏洞走 [security.apple.com](https://security.apple.com) 报送，修复前不公开细节
- 这个仓库是研究工具，不是攻击工具。别拿它去搞别人的设备
