# IntentProbe：从"不受信任的一侧"顶 Shortcuts 的信任边界

> 思路：不去逆向 Shortcuts，而是**写一个 App 挂上去**，看系统愿意把什么交给它、愿意替它做什么。
> Kirin (@Pwnrin) 拿到 6 个 Shortcuts CVE，用的基本就是这条路。

---

## 一、五个可证伪的假设

| 编号 | 假设 | 如果成立意味着 |
|---|---|---|
| **H1** | 变量从"敏感数据源 action"流入第三方 `AppIntent` 参数时，TCC 只在数据源那一步检查，跨进程传递不再二次检查 | 一个恶意 shortcut 可以把剪贴板/照片/通讯录**静默**送给第三方 App。这正是 CVE-2024-23203/23204/40835 的形态 |
| **H2** | `AppEntity.id` 由 App 运行时控制，会被持久化进 workflow 文件 | shortcut 文件成为**可控 blob 的载体**，且能通过 AEA 签名（签名发生在用户设备导出时，此时 payload 已存在） |
| **H3** | `Metadata.appintents/extract.actionsdata` 是二进制 blob，Shortcuts / `shortcutsd` 在**索引已安装 App** 时解析它 | 畸形 blob = **安装即触发**，零交互 |
| **H4** | `SnippetIntent` 返回的视图由 App 提供，但渲染在 Shortcuts 流程界面里 | **UI 欺骗**：伪造"请输入密码以继续运行此快捷指令" |
| **H5** | `IntentFile.fileURL` 暴露了文件在磁盘上的真实位置 | 可能读到超出"用户明确给的那个文件"范围的内容；返回时 `filename` 可构造路径穿越 |

**H1 是主攻方向。** 它对应 11 个 CVE 中的大部分。

---

## 二、拿到可安装的包

**方式 A（推荐）：GitHub Actions**

推到 GitHub → Actions 跑完 → 下载 Artifacts 里的 `IntentProbe-unsigned.ipa`（或已签名版，取决于有没有配 Secrets，见 `README.md`）→ 用 Sideloadly / AltStore / TrollStore 装到真机。

**方式 B：本地**

```bash
brew install xcodegen && xcodegen generate && open IntentProbe.xcodeproj
```

装好后打开 **快捷指令 → App 快捷指令**，应该能看到本 App 的 5 个快捷指令。

> 模拟器也能跑，但第三方 intent 的索引在模拟器上不稳定，**建议真机**。

---

## 三、八个实验

每个实验做完，回 App 看 `probe.log`（右上角可导出）。

### 实验 1：剪贴板 → 我的 intent（H1 核心）

在快捷指令 App 里新建：
```
[获取剪贴板] → [Probe: 接收文本]  输入 = 剪贴板变量
```

| 观察 | 判定 |
|---|---|
| 运行时**是否弹**"允许读取剪贴板" | 不弹 + `probe.log` 里有明文 → **H1 成立** |
| 弹了，但弹在什么时候 | 弹在"获取剪贴板"那一步 = 设计如此；弹在传入我的 intent 时 = 也有意思 |
| `probe.log` 里 `text` 行的 `value=<...>` | 是否是我复制的内容 |

**对照实验**：同样内容改成 `[获取剪贴板] → [显示结果]`，看系统是否弹窗。如果"显示结果"会弹而"我的 intent"不弹，差异就是漏洞。

### 实验 2：照片 / 通讯录 / 位置 重复实验 1

把数据源换成"获取最新照片""查找联系人""获取当前位置"。三类权限的 TCC 行为可能不同。

### 实验 3：文件来源（H5）

```
[文件] → [Probe: 接收文件]
```
看 `file.url` 那一行指向哪里：
- 我的容器 → 正常
- Shortcuts 的临时目录 → **记下来，这是共享可写区**
- 其他 App 的容器 → **重大发现**

再看 `file.parent.list`，能不能列出同级文件。

### 实验 4：实体标识符的持久化（H2）

1. 建一个 shortcut，参数选"接收实体"，从画廊里挑一个**有毒 ID**（`../../../etc/passwd`、10K 长字符串、`\u{202E}` 反转等）
2. 保存 → 导出为 `.shortcut` 文件
3. 用 `plutil -p` 或直接看 plist，搜那个 ID 是否**原样存在**
4. 换一台设备导入，看 `entity.for` 日志里回来的是什么

| 观察 | 判定 |
|---|---|
| 有毒 ID 原样躺在 workflow 文件里 | H2 成立，文件可作载荷载体 |
| 导入后 ID 被截断/转义/拒绝 | 有校验，记下校验点在哪 |
| 导入时 Shortcuts 崩溃 | **更好**，直接是 bug |

### 实验 5：返回文件的命名（H5 反向）

跑 `Probe: 输出文件`（返回 `filename = "../../../probe-escape.txt"`），接一个"存储文件"或"快速查看"。
看文件最终落在哪里、名字被改成什么。如果真跑出容器 → 路径穿越。

### 实验 6：伪装弹窗（H4）

跑 `Probe: 伪装弹窗`，把手机递给同事/朋友，问："这是系统弹的还是 App 弹的？"

**判定**：如果对方分不出来，且截图里看不出区别 → UI 欺骗面成立。这条不是内存漏洞，但是 Apple 会认的产品安全问题。

### 实验 7：自动化 + 我的 intent（零点击）

设置 → 快捷指令 → 自动化 → 新建"到达某位置时" → 运行调用我 intent 的 shortcut。
看后台触发时：
- `probe.log` 的 `appState=` 是 `background` 还是 `active`
- 数据是否照样传进来

如果后台也能拿到敏感数据 → 组合 H1 就是**持续静默外泄**。

### 实验 8：跨 App 可见性

我的 intent 收到的实体，ID 里会不会带出别的 App 的信息？（例如用户在同一个 shortcut 里先调了别的 App 的 action）
看 `entity.for` 的 `ids=` 内容。

---

## 四、H3：元数据变异（价值最高，但门槛也最高）

`Metadata.appintents/extract.actionsdata` 是 Xcode 生成的二进制 blob。正常手段做不出畸形文件——但**构建后直接改 bundle 再重签**就行。

**在 macOS 上做最省事**（不用重签证书，ad-hoc 就行）：

```bash
# 1. 找到文件
find /Applications/IntentProbe.app -name "extract.actionsdata"

# 2. 备份
cp -R /Applications/IntentProbe.app /tmp/IntentProbe.app

# 3. 变异
python3 tools/fuzz_metadata.py /tmp/IntentProbe.app/Metadata.appintents/extract.actionsdata --mode truncate --at 512

# 4. 重签（ad-hoc）
codesign --force --deep -s - /tmp/IntentProbe.app

# 5. 启动，观察是否崩溃 / 行为异常
open /tmp/IntentProbe.app
```

**崩溃日志位置**
- macOS：`~/Library/Logs/DiagnosticReports/`
- iOS：设置 → 隐私与安全性 → 分析与改进 → 分析数据（找 `Shortcuts` / `shortcutsd` 开头的）

**iOS 上做**需要重签（`ldid -S` 或 Xcode 重签）+ 开发者模式，或越狱设备。

---

## 五、判定标准：什么算 finding，什么算"设计如此"

这一步很重要，能省掉大量无用功。

| 现象 | 判定 |
|---|---|
| 第三方 intent 收到用户明确传入的数据 | **设计如此**，不是 bug |
| 敏感数据流入第三方 intent 时**完全没有 TCC 提示**，而同样的数据流向系统 action 会提示 | **bug**（H1） |
| 我返回的恶意 `filename` 真的写到容器外 | **bug**（H5） |
| 畸形 metadata 导致崩溃 | **bug**（H3），但要确认是 Shortcuts 进程崩，不是我的 App 崩 |
| 导出文件里原样保留了有毒 ID，且导入端不校验 | **弱发现**，需要能证明危害 |
| 用户分不清我的 snippet 和系统弹窗 | **产品安全问题**，Apple 会认 |
| Shortcuts 对超长 ID 做了截断 | 有防护，记下来，换个方向 |

---

## 六、报告

走 `security.apple.com` 的 Apple Security Bounty。Shortcuts 属于 **"Apple ID / 隐私"** 或 **"沙箱逃逸"** 类目，具体金额看影响。

注意事项：
- 只在**自己持有的设备**上测
- 不要用真实用户数据做测试样本
- 不要在修复前公开细节

---

## 七、如果 H1 成立，攻击链长这样

```
攻击者准备一个 .shortcut 文件（或 iCloud 共享链接）
        ↓  受害者导入（1 次点击）
快捷指令：[获取剪贴板] → [攻击者的 App: 接收文本]
        ↓  运行时无 TCC 提示
明文进入攻击者 App 的容器
        ↓
下次联网时外发
```

配合实验 7 的自动化触发，就是**持续**外泄。

---

*与 `shortcuts-static-analysis.md` 的关系：那份是静态侧（找检查点在哪），这份是动态侧（验证检查点有没有生效）。两边对上，才是完整证据链。*

---

## 附：v6 / v7 的结论不在这里

代码执行与文件写入的实验记录写在 `PROBES.md` 的「结论十四 / 十五」和
「v7 改了什么」里——它们和 Shortcuts 的 H1–H5 不是同一条链，混在一起
会让"哪个结论推翻了哪个"变得看不出来。

一句话版本：

- v6 的 exec-map 矩阵**作废**：正对照 `control.bundle-exec=DENY`，判不了
- 代码执行路线是被**页表 max prot** 关掉的，不是被沙箱：区间 `r--/rw-`，上限没有 X
- v7 换问题：不再问"我能不能执行自己的代码"，改问"我能不能把文件放到别人会执行的位置"
