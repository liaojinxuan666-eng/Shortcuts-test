# IntentProbe

一个用来**从不受信任的一侧顶 Shortcuts / App Intents 信任边界**的探针 App。

不逆向 Shortcuts，而是自己挂上去：看系统愿意把什么交给第三方 App、愿意替它做什么。

> 配套文档：
> - [`PROBES.md`](PROBES.md) —— **每个探针回答什么问题、结果怎么判读**（先看这个）
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

## 先看环境，再看结论

每条 `*.ctx` 都带 `env=` 字段：

```
sweep.ctx :: build=v9-env env=clean bundle=com.probe.intentprobe ...
sweep.ctx :: build=v9-env env=jailbroken(systemhook.dylib) bundle=...
```

`env=jailbroken(...)` 时，**代码执行类的结果一律不能当成 iOS 的行为**——
v6（`injected=none`）和 v8（`injected=systemhook`）是同一份 exec 代码、
同一台设备，结果一个是 SIGKILL、一个是正常返回，唯一变量就是这一行。

判据两条，分开失效所以都留着：dyld 镜像表里的非 Apple 镜像；
`/usr/lib/systemhook.dylib` 或 `/var/jb/usr/lib/systemhook.dylib` 是否存在。

## 探针列表（16 个 intent，画廊里只放 10 个）

`AppShortcutsProvider` 每个 App 上限 10 个，所以画廊里只有前 10 个；
其余的不注册也能被快捷指令索引到（搜 App 名字即可）。

| 探针 | 输入 | 回答的问题 |
|---|---|---|
| 接收文本 | String | 变量展开后 TCC 是否二次检查 |
| 接收数组 | [String] | 数组展开与数量上限 |
| 接收文件 | IntentFile | `fileURL` 指向哪里 |
| 接收实体 | AppEntity | 标识符能否被持久化、长度上限 |
| 接收链接 | URL | `file://` scheme 是否被拒 |
| 输出文件 | 无 | 返回的 `filename` 能否穿越到容器外 |
| 伪装弹窗 | 无 | Snippet 视图能否冒充系统提示 |
| 伪装对话框 | 无 | `ProvidesDialog` 这条 UI 通道长什么样 |
| **环境扫描** | 无 | 容器、28 条系统路径、代码加载能力的全貌 |
| **探测路径** | String 路径 | stat / 读 / 列 / 写 / 建链接，五件事一次问完 |
| **加载动态库** | String 路径 | dlopen 卡在沙箱、签名、还是 W^X |
| **文件深挖** | IntentFile | security-scope、父目录、兄弟文件、能否当 dylib 加载 |
| **代码执行** | 无 | 匿名 RWX 到底能不能取指（**会让 App 退出**） |
| **创建文件** | 目录/文件名/内容 | 写下来的字节落在一个什么策略的目录里 |
| **交给系统 App** | 模式 | 19 个 scheme 的 canOpen / open 差值，交接后进程去向 |
| **交给系统打开** | URL | 由系统执行 open，不是我的进程（`opensIntent`） |

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
│   ├── IntentProbeApp.swift      入口 + 日志界面 + 工具栏两个一键按钮
│   ├── ProbeLog.swift            日志落盘 + build 标记 + 有毒标识符样本集
│   ├── ProbeIntents.swift        6 个输入边界 intent（文本/数组/文件/URL/实体/输出文件）
│   ├── ProbeIntentsFS.swift      5 个沙箱 intent（扫描/路径/加载/文件深挖/代码执行）
│   ├── ProbeFileCreate.swift     创建文件 + 可写目录矩阵（v7）
│   ├── ProbeSystemApp.swift      URL scheme 交接矩阵 + 系统执行（v8）
│   ├── ProbeEnv.swift            越狱环境判据：dyld 注入 + bootstrap 落盘（v9）
│   ├── ProbeEntity.swift         AppEntity + 三个查询入口
│   ├── ProbeSnippet.swift        伪装弹窗 + 对话框两条 UI 通道
│   ├── ProbeShortcuts.swift      AppShortcutsProvider（画廊磁贴，上限 10 个）
│   ├── ProbeFS.swift             三路探测：Foundation / POSIX / sandbox_check
│   ├── ProbeDylib.swift          dlopen、匿名 RWX、注入镜像检测
│   └── ProbeCodeExec.swift       代码执行决定性实验（会让进程退出）
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
