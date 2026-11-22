# 探针清单与判读手册

每个探针都对应一个**可以用一句话回答的问题**。看到结果不要先想"这是不是漏洞"，
先回答那个问题——问题答完，漏洞自然浮出来或者自然排除。

---

## 第二轮新增：沙箱与代码加载

### P6 · 环境扫描（无参数）

**问：我这个进程到底被允许做什么？**

一次跑完三组：

| 组 | 内容 |
|---|---|
| 容器 | `home` / `tmp` / `Documents` / `Library` / `Caches` / `bundle` / `exec` / App Group |
| 路径 | 19 条关键系统路径，每条给 `lstat` + `sandbox_check(读/写)` + `opendir` + `FileManager` |
| 代码加载 | 匿名 `mmap(RWX)`、4 个系统库、自己的可执行文件、容器内不存在的 dylib |

**判读**：这是基线。后面任何"异常"都要跟这张表对比——如果 `/private/etc/passwd` 在这里就是 `allow`，
那说明你的设备/系统版本本来就这样，不是你的功劳。

---

### P7 · 探测路径（输入：路径字符串）

**问：给定一个路径，我能对它做什么？**

这是最核心的一个，一条路径跑五件事：

| # | 动作 | 它在回答什么 |
|---|---|---|
| 1 | `lstat` + `sandbox_check(read/write)` | 策略层怎么判（**只问不做**，不会留痕迹） |
| 2 | 在**父目录**写文件 | 真正决定"能不能在这里埋东西"的是父目录写权限 |
| 3 | 在自己 `tmp/` 建**软链接**指向它 | **创建链接不需要目标权限**——全红里出现一个绿的就是它 |
| 4 | 建**硬链接** | 跨卷 `EXDEV`、目录 `EPERM`、同卷文件才可能成功 |
| 5 | 在自己 `Documents/` 写一遍 | 基线对照，证明写入代码本身没问题 |

**关键判读**：

```
path.write.parent :: /private/etc :: write=EPERM
path.symlink      :: symlink=ok readlink=</private/etc/passwd> follow=EPERM
```

这个组合意味着：**我不能读它，但我能在自己的目录里造一个指向它的链接**。
单看没危害；一旦有另一个权限更高的进程会跟随这个链接（备份、同步、解压、文件提供者），
危害就转移过去了。这就是"检查在 A、使用在 B"的经典形态。

---

### P8 · 加载动态库（输入：路径字符串）

**问：我能不能让这个进程执行磁盘上的代码？**

三道闸门，必须按顺序看，顺序错了会得出错误结论：

| 闸门 | 失败时的表现 | 说明 |
|---|---|---|
| ① 沙箱读 | `no such file or directory` | 压根没读到，后面两道不用看了 |
| ② 代码签名 | `code signature invalid` | **沙箱已经放行**，是签名拦住的 |
| ③ W^X / JIT | `mmap(RWX)` 返回 `EPERM` | 硬墙，需要 `dynamic-codesigning` entitlement |

**这三条错误信息必须区分开**。`no such file` 和 `code signature invalid` 的差别，
就是"沙箱管住了"和"沙箱没管住、但签名管住了"的差别——后者才是可研究的位置。

**期望结果**（普通开发签名 App）：

```
mmap(rwx)=EPERM
system-libSystem      :: dlopen=ok
system-Foundation     :: dlopen=ok
own-executable        :: dlopen=FAIL <not a mach-o file>      ← 可执行文件不是 dylib，正常
tmp-absent            :: dlopen=FAIL <no such file or directory>
```

如果 `own-executable` 报的是 `code signature invalid` 而不是 `not a mach-o file`，
说明连签名检查都没走到就失败了，换一个真实的 dylib 再试。

---

### P9 · 文件深挖（输入：文件）

**问：Shortcuts 说"用户给了我一个文件"，实际上给了我多少？**

| 检查项 | 为什么重要 |
|---|---|
| `fileURL` 是否为 nil | nil 说明只给了 data，路径边界不存在 |
| `startAccessingSecurityScopedResource()` 返回值 | **true 表示这个 URL 带 scope**，解锁后能访问的范围可能比解锁前大 |
| 父目录能列到什么 | 这是"给了你一个文件"实际暴露的目录范围 |
| 同目录下的兄弟文件能否 `lstat` | 能 stat 就能判断存在性，能读就是横向越权 |
| 文件名回写是否穿越 | `filename` 完全由传入方控制，`../` 是否生效 |
| 当 dylib 加载的结果 | 区分"沙箱放行"和"签名拦住" |

**判读**：

```
filedeep.url      :: /private/var/mobile/Containers/Data/Application/<UUID>/tmp/Inbox/x.txt
filedeep.scoped   :: startAccessing=true
filedeep.parent   :: .../Inbox :: entries=3 [...]
filedeep.sibling  :: other.txt :: lstat=ok type=reg
```

`startAccessing=true` + 父目录可列 = Shortcuts 给的是**带 scope 的真实路径**，
不是拷贝。这条链上"用户选了一个文件"的语义比想象中宽。

---

## 第三轮新增：创建文件

### P12 · 创建文件（输入：目录 / 文件名 / 内容 / 拷贝源文件）

**问：我写下来的字节，落在一个什么策略的目录里？**

和 P7 的"写一次就删"不同，这里默认**把文件留在原地**。区别不是洁癖：

| | P7 `writeProbe` | P12 `create` |
|---|---|---|
| 目的 | 有没有写权限 | 写下来的东西**还能不能被当成可执行映像** |
| 文件 | 建完立刻 `unlink` | 默认保留，可以接着 `dlopen` |
| 判据 | `open` 返回值 | `open` + 读回比对 + `dlopen` |

三个参数决定它测什么：

```
目录 = file.parent 的输出        → 能不能在 Shortcuts 递给我的文件旁边埋东西
拷贝源文件 = /usr/lib/libRPAC.dylib → 埋下去的那份还能不能被映射执行
扫描候选目录 = 开                → 19 个目录一次过，看哪些能写
```

**输出长这样**：

```
create.target :: /var/mobile/.../tmp/probe-created.bin
create.result :: pre=absent open=ok wrote=68176B fsync=ok
                 stat[mode=644 uid=501 size=68176] readback=match
                 sbx_create=DENY exec=DENY dlopen=FAIL <...file system sandbox blocked mmap()...>
```

**判读**，按顺序看，前一条不成立就不用看后一条：

| # | 条件 | 说明 |
|---|---|---|
| 1 | `open=ok` | 目录可写。`pre=absent` 才算"新建"，`pre=exists` 只说明能覆盖 |
| 2 | `readback=match` | 写进去的和读出来的一样。不一样才是异常 |
| 3 | `exec=` | **只当参考**——`sandbox_check` 在这个 build 上连主可执行文件都答 DENY |
| 4 | `dlopen=ok(loaded)` | **唯一有效判据**。`already-loaded` 不算，那是缓存命中 |

矩阵模式下多一行 `summary :: writable=N/19`。基线是"自己的容器全绿、系统侧全红、
bundle 负对照 FAIL"——负对照 FAIL 才说明上面那些绿不是探针在骗自己。

**为什么 `/private/preboot/Cryptexes` 在名单里**：v6 扫出来它是 `mode=777 uid=0`。
权限位已经允许任何人写，剩下的只有沙箱一层。整张表里只有它"只差一步"。

**为什么这个探针不注册进 App 快捷指令画廊**：`AppShortcutsProvider` 每个 App
上限 10 个，现在正好 10 个，再加一个会**构建失败**。`AppIntent` 不注册也能被
快捷指令索引到，只是不在画廊里显示磁贴。App 内工具栏的文件夹按钮走的是同一条路径。

---

## 第四轮新增：交给系统 App

### P13 · 交给系统 App（输入：模式 / URL）

**问：我能不能让一个比我权限高的进程替我做这件事？**

这一问和前面所有探针都不同：前面问"我能不能"，这里问"**能不能推给别人**"。
后者才是 App Intents 这条边界上的主战场——28 个 Shortcuts CVE 里 0 个内存破坏，
全是这类 confused deputy。

三种交接机制，差别本身就是结论：

| 机制 | 谁在执行 | 需要我在前台 |
|---|---|---|
| `canOpenURL` | 没人执行，只问策略 | 不需要 |
| `UIApplication.open` | **我的进程**发起请求 | 大概率需要 |
| 返回 `opensIntent: OpenURLIntent` | **系统**在 intent 返回后执行 | 不需要 |

第三种不是私有 API，是 App Intents 官方给 intent 用的出口。它和第二种的差值，
就是这一轮要量的东西。

**输出**：

```
sysapp.mode  :: mode=<open>
sysapp.open  :: control.https :: before=background after=background open=no-callback
sysapp.open  :: control.bogus :: before=background after=background open=refused
sysapp.open  :: shortcuts.run :: before=background after=background open=no-callback
sysapp.summary :: origin=foreground canopen_true=6/21 open_accepted=2/21
```

**判读**（前一条不成立，后一条就不用看）：

| 组合 | 含义 | 陷阱 |
|---|---|---|
| `control.bogus` 不是 refused | 整张表作废 | 负对照是唯一的防伪标记 |
| `control.https` 不是 accepted | 探针本身坏了 | http/https 不需要声明，必须通 |
| `canOpen=false` + `open=refused` | 没声明或没装 | 这是**默认状态**，不是发现 |
| `canOpen=false` + `open=accepted` | 没声明，但 open 照样收下 | **真差值**：声明只约束 canOpenURL，不约束 open |
| `open=accepted` + `after=background` | 系统真的接过去了 | 这才是"交接成功" |
| `open=accepted` + `after=active` | URL 收下了，什么都没发生 | **最容易读成成功** |
| `open=no-callback` | 回调没被调用，多半在后台 | 不是"失败"，是"没结论" |

**这个探针的产出是线索，不是 finding。** 它只能量到"系统接不接"，
量不到 Safari / Shortcuts 接到之后做了什么。要变成 finding，
得在接收侧证明它没校验来源。

**前置条件**：`LSApplicationQueriesSchemes` 里没声明的 scheme，`canOpenURL`
一律返回 false——**哪怕目标 App 装着**。所以 false 不能读成"没装"。
反过来，`open()` 不需要声明也能用，这个不对称本身就是 P13 的一条读数。

**怎么跑（v10 才有的入口）**：App 工具栏的纸飞机按钮，一次跑完 canOpen + open。
之前它只以 `AppIntent` 形式存在，而 `AppShortcutsProvider` 上限 10 个、画廊已满，
所以从来没有被触发过——四版日志里 `sysapp.*` 一直是 **0 行**。工具存在 ≠ 工具被用过。

App 内跑会引入一个必然的混淆，别试图消除它：

> 每 `open` 一次，本进程就被切到后台。**第一行是前台发起，之后都是后台发起。**

`before=` 每行都写，自己就能分开读；真要纯前台基线，就一次只跑一个目标。
另外用 `beginBackgroundTask` 多要了约 30 秒，并把轮询压到 3 拍（300ms）——
切走的第一步是 `inactive`，300ms 足够，再多只是白等。

**四个 Safari 入口**：`safari.web-search`（`x-web-search://`）、
`safari.x-https`（`x-safari-https://`）、`safari.file`（`file://`）、
`safari.data`（`data:`）。前两个是"能不能让 Safari 替我搜/打开"，
后两个是历史上真正被利用过的两个方向。`safari.x-https` 和 `control.https`
放一起对比，就知道私有写法是不是等价物。

## 第一轮：输入边界（原有 5 个）

| 探针 | 问题 | 已知结果 |
|---|---|---|
| 接收文本 | 变量展开后 TCC 是否二次检查 | `appState=background`，全部静默通过 |
| 接收文件 | `fileURL` 指向哪里 | 见 P9 |
| 接收实体 | 标识符能否被持久化 / 长度上限 | **4096 字节截断** |
| 接收链接 | `file://` scheme 是否被拒 | 未拒绝，原样透传 |
| 伪装弹窗 | Snippet 视图能否冒充系统提示 | `spoof.ctx` 正常记录 |

### 实体标识符的实测结论

送 10,000 字节进去，收到 4096：

```
entity.for      :: count=1 ids=<AAAA...>
entity.received :: id.len=4096
```

4096 这个数字太整，不像随机截断，说明链路上某处有固定上限。下一步值得查：
截断发生在 **Shortcuts 写入 workflow 文件**时，还是 **AppIntents 反序列化参数**时。
两者的安全含义完全不同——前者说明 workflow 文件本身有长度纪律，后者说明参数通道有缓冲边界。

其余载荷全部原样通过，无一被处理：

| 载荷 | 结果 |
|---|---|
| `$(whoami)` | 原样，**无 shell 展开** |
| `../../../../../../etc/passwd` | 原样 |
| `..%2f..%2f..%2fetc%2fpasswd` | 原样，**无 URL 解码** |
| `invoice‮gnp.exe` | 原样，RTL 覆盖保留 |
| `</string><key>WFWorkflowActions</key>` | 原样，plist 注入未生效（被正确转义） |

"原样通过"本身是好事——说明这一层没做任何归一化，也就没做任何检查。
危险不在这一层，而在**下游某个把字符串当路径/当命令用的地方**。

---

## 操作顺序建议

1. 先跑 **P6 环境扫描**，把基线存下来（`probe.log` 导出）
2. 再跑 **P7** 打几条关键路径：`/private/etc/passwd`、`/private/var/mobile/Library`、`/System`
3. 用 **P8** 打 `/usr/lib/libSystem.B.dylib`（对照组，应该 ok）和容器内任意文件（实验组）
4. 最后用 **P9** 传一个 `.dylib` 进去，看能不能加载

**每一步只改一个变量。** 同时改两个，出结果也不知道是谁的功劳。

---

## 先确认：设备上跑的是哪一版

这是最容易浪费一轮实验的地方。**新探针没输出 ≠ 探针失败，很可能是旧二进制根本没执行到那段代码。**

两个自查点，任选其一：

1. **App 标题栏**：显示 `Probe Log · v2-9probes`。看不到这个后缀就是旧包。
2. **日志每行都带 `build=`**：

```
[2026-11-21T12:48:10Z] text.ctx :: build=v2-9probes bundle=... container=<UUID> appState=background
```

同时 `container=` 给出了自己的容器 UUID。**拿它跟 `file.url` 里的 UUID 比一下**，
立刻能回答"Shortcuts 递给我的文件在我自己容器里，还是别人容器里"——这是两个完全不同的问题，
混在一起会导致整个结论跑偏。

### 还有一个更快的入口

App 右上角有个 ⚡ 按钮，**直接在 App 内跑环境扫描**，不用绕 Shortcuts。
结果和从快捷指令触发完全一致（同一进程、同一沙箱），但省掉"改快捷指令 → 跑 → 看日志"的往返。

---

# 第一轮实测结果（v2-9probes，iOS 真机）

设备：`/var/mobile/Containers/Data/Application/9444FA67-...`，开发签名，无 App Group。

## 结论一：`sandbox_check` 不是权威

```
/etc/passwd :: sbx_read=DENY  sbx_write=DENY
               head[n=64 ... txt=<##.# User Database.#.# This file is the authoritativ...>]
```

**策略查询说 DENY，实际读到了明文。** 原因：`sandbox_check` 评估的是你传进去的**字符串**，
而真正的 `open` 会先解析软链接、再用 vnode 路径匹配规则。两条路径不同。

同理，对**目录**问 `file-read-data` 一定是 DENY——目录枚举走的是 `file-read-metadata`。
所以第一版 `sbx_read=DENY` 加 `entries=17` 看着矛盾，其实是我问错了问题。
v3 已补上 `sbx_meta=` 一路。

**方法论修正**：`sandbox_check` 只能用来**发现可疑点**，判定必须靠真实操作。

## 结论二：目录枚举基本全通，内容读取基本全拒

| 路径 | lstat | opendir | 内容 |
|---|---|---|---|
| `/` | ok | **17 条** | — |
| `/System/Library` | ok | **138 条** | — |
| `/System/Library/Frameworks` | ok | **245 条** | — |
| `/System/Library/PrivateFrameworks` | ok | **2447 条** | — |
| `/usr/lib` | ok | **22 条** | — |
| `/private/preboot` | ok | **4 条** | 待测 |
| `/private/var` | ok | EPERM | — |
| `/private/var/mobile` | ok (mode 711) | EPERM | — |
| `/Library`、`/Applications` | ok | EPERM | — |
| `/etc/passwd` | ok | — | **读到 64B** |
| `/private/etc/master.passwd` | 待测 | — | 待测 |

**规律**：`file-read-metadata`（stat / 枚举目录）几乎不受限；`file-read-data`（读内容）严格限制。
这是 iOS 沙箱的设计，不是漏洞。但它给出两个实际能力：

1. **存在性预言机**——任意路径的 `lstat` 都能拿到 `mode` / `uid` / `size` / `nlink`
2. **构建指纹**——2447 个私有框架的名字 + `/private/preboot` 里的 cryptex 哈希，
   足以精确判定系统版本，进而对上已知未修复 CVE

## 结论三：`/private/preboot` 能枚举（值得深挖）

```
/private/preboot :: lstat=ok mode=755 uid=0
  posix[entries=4 [cryptex1, 5F6D13F786782F0D...B38, Cryptexes, active]]
```

preboot 卷存的是系统 cryptex（SSV 封印的根），第三方 App 理论上不该看到目录结构。
现在拿到了 4 个条目，包括 cryptex 的哈希目录名。

**下一步**：`/private/preboot/active` 是软链接，跟过去看指向哪；
`/private/preboot/Cryptexes/OS` 是系统卷的挂载源，试能不能往下走一层。
v3 的 `interesting` 已加入这三条。

## 结论四：`mmap(RWX)=ok` 不等于能执行

```
sweep.exec :: rwx=mmap(rwx)=ok
```

iOS 的代码签名在**缺页时**强制，不在 `mmap` 时。映射成功只说明虚拟地址空间拿到了。
要判定必须真的跳进去——见 P11。

## 结论五：dlopen 的 ok 全是 dyld shared cache

```
/usr/lib/libSystem.B.dylib :: lstat=ENOENT     ← 磁盘上没有这个文件
sweep.dlopen :: system-libSystem :: dlopen=ok   ← 但从共享缓存加载成功
```

iOS 把系统库全部塞进 dyld shared cache，磁盘上不存在独立文件。
所以"系统库 dlopen 成功"这一组**没有信息量**，它绕过了文件系统。

真正该测的是**容器里的真实 dylib**，v2 漏了。v3 补上 `sweep.selfcopy`：
把自己的可执行文件拷进容器再加载，然后把拷贝改坏一个字节再加载。
同一个文件，只有**位置**和**签名完整性**不同。

## 结论六：链接与写入

```
path.write.parent :: / :: write=EPERM
path.symlink      :: symlink=ok readlink=</tmp> follow=EPERM
path.hardlink     :: link=EPERM
path.write.own    :: .../Documents :: write=ok
```

- **软链接创建成功，跟随失败**——创建时完全不检查目标权限，这一点已验证
- 硬链接 EPERM（跨卷，且目录本身禁止）
- 写入只有自己容器可用

这条组合的含义：**能在自己容器里造任意指向的软链接，但沙箱会拦住跟随**。
所以单靠它不构成越权，必须找到一个"会跟随链接且权限更高"的下游进程。

## v3 要回答的三个问题

| # | 问题 | 对应探针 | 期望 |
|---|---|---|---|
| 1 | 容器里的 dylib 能不能加载 | `sweep.selfcopy` | 完整签名 ok / 改坏后 cs invalid |
| 2 | 匿名 RWX 能不能真的执行 | P11 代码执行 | App 闪退（说明硬墙在） |
| 3 | `/private/preboot` 能走多深 | `sweep.path` | 只能看目录名 |

---

# v4 修复记录（v4-selfcopy-trail）

这一版没有加新探针，只修两处**会让结论失真**的问题。

## 修复一：`sys_icache_invalidate` 编译不过

CI 报：

```
ProbeCodeExec.swift:73:9: error: cannot find 'sys_icache_invalidate' in scope
```

这个符号声明在 `<libkern/OSCacheControl.h>`。macOS 的 Swift Darwin overlay 会
把它带进来，**iOS 不会**——所以本地写起来没感觉，一上 `-sdk iphoneos` 就挂。

两种修法，差别在"失败发生在哪一期"：

| 修法 | 编译期 | 链接期 | 运行期 |
|---|---|---|---|
| `@_silgen_name("sys_icache_invalidate")` | 过 | **可能挂**（符号不在就给 undefined） | 正常 |
| `dlsym` 运行时取 | 过 | 不依赖 | 取不到则退化为不刷新 |

选 dlsym。理由不是"更优雅"，是**失败可观测**：`@_silgen_name` 一旦链接失败，
拿到的是一个 `ld: symbol not found`，你还得再猜一轮；dlsym 取不到只会让
`sweep.icache :: unavailable` 出现在日志里，实验照跑，结论打折但不丢。

## 修复二：同一个路径 dlopen 两次会命中 dyld image 缓存

v3 的写法是：拷到 `selfcopy.bin` → dlopen → 改坏同一个文件 → 再 dlopen。

问题在第二步：**dyld 按 realpath 缓存已加载的 image**。第一次 dlopen 成功后，
第二次对同一路径的调用很可能直接返回旧句柄，**根本不重新验签**。于是
`dlopen_corrupt=ok` 会被读成"签名不校验"，而真相只是"没重新加载"。

一个假阳性足以把整个结论反过来。改成两个文件名：

```
selfcopy-intact.bin   → dlopen_intact
selfcopy-corrupt.bin  → dlopen_corrupt
```

两个文件都是刚拷的、都在容器里、都完整，唯一差别是其中一个被 XOR 了一个字节。

## 修复三：崩溃点可归因

v3 在设备上的日志里，`sweep.selfcopy` **整条不存在**。而"没跑到"和"跑到一半崩了"
在日志上完全同形——这是设计缺陷，不是运气差。

现在每一步前后各落一行 `selfcopy.step`：

```
selfcopy.step :: start
selfcopy.step :: exec=/private/var/containers/Bundle/Application/.../IntentProbe
selfcopy.step :: copy=ok dst=.../selfcopy-intact.bin size=...
selfcopy.step :: about-to-dlopen intact
selfcopy.step :: dlopen intact returned
...
```

崩在哪一行，下一行就是死因的位置。同时 `sweep` 里调用前后也各补了一行
`about-to-run`。

## 附带：`/private/preboot` 子路径

`interesting` 数组里已确认包含 `active` / `Cryptexes` / `Cryptexes/OS` 三条。
v3 日志里没出现，最可能的原因就是**设备上跑的不是编译了这三条的二进制**——
现在 `build=` 标记会直接回答这一点，先看它是不是 `v4-selfcopy-trail` 再判读其余内容。

---

# v4 实测结果（iPhone11,6 / iOS 18.5 22F76 / build v4-selfcopy-trail）

这一轮拿到了 P11 的答案，同时暴露出**这台设备不能用来回答沙箱问题**。

## 结论七：`mmap(RWX)=ok` 是内核说的谎，墙在页表，不在 AMFI

崩溃报告逐字解码：

```
pc            0x104640000          ← 就是刚 mmap 出来的那个地址
exception     EXC_BAD_ACCESS / SIGBUS
subtype       KERN_PROTECTION_FAILURE
ESR           0x8200000F
  EC   = 0x20   Instruction Abort from lower EL（取指错，不是数据访问错）
  DFSC = 0xF    Permission fault, level 3（页表项存在，但缺执行权限）
vmRegionInfo  VM_ALLOCATE 104640000-104644000 [16K]  rw-/rwx
                                                      ↑当前   ↑上限
```

三件事同时成立：

1. `mmap(PROT_READ|PROT_WRITE|PROT_EXEC)` **返回成功**，没有 EPERM
2. 但该区间的**当前**保护位是 `rw-`，没有 `x`；`rwx` 只存在于 max prot
3. 取指时在**末级页表**上因权限位被拦 —— 这是硬件 NX

**这不是代码签名校验。** 签名校验失败的表现是进程被 SIGKILL、终止原因写
`Code Signature Invalid`、通常连崩溃报告都不留。这里是普通缺页权限错，
`codeSigningMonitor: 1` 全程没参与。

所以判据只能是一条：**跳不跳**。`mmap` 的返回值、`mprotect` 的返回值都不算数。

> 对研究的意义：想要"跑自生成代码"，缺的不是绕过签名，是拿到
> `dynamic-codesigning` entitlement。这两条路的成本差一个数量级。

## 结论八：这台设备是越狱的，之前所有"绿色"全部作废

崩溃报告的 `usedImages` 里有一条：

```
/private/preboot/5F6D13F7…B38/dopamine-iHw65x/procursus/basebin/systemhook.dylib
```

**Dopamine 的 systemhook 被注入进了本进程。** 佐证不止这一条：

| 观测 | 原以为的含义 | 实际含义 |
|---|---|---|
| `/etc/passwd` 读出前 64 字节 | 沙箱可绕过 | 越狱给的（stock 上必然 EPERM） |
| `/System/Library/Frameworks` 枚举到 245 条 | 目录遍历漏洞 | 同上 |
| `/usr/lib` 里出现 `systemhook.dylib` | 系统库清单 | 越狱的注入器就在这 |
| `sandbox_check` 对**每一条**路径都说 DENY，而 `open` 实际成功 | 策略层与内核不一致 | `sandbox_check` 本身被 hook 了 |
| `/bin/sh`、`/dev/disk0` 的 `sandbox_check` 返回 `err(-1,EFAULT)` | 未解 | hook 处理不了这两个路径，`EFAULT` 是它的 bug |

**这是本轮最重要的发现，也是最坏的消息**：`sandbox_check` 是我整套判读逻辑的
锚点（"策略怎么说" vs "内核怎么做"），而它在这台设备上被替换了。所有
`sweep.path` 的读数都是在问一个已经被改过的函数。

`/private/preboot` 那 4 个条目也是同一个来源 —— 不是 App 的权限，是越狱的权限。

### 哪些结论还活着

| 结论 | 状态 |
|---|---|
| 结论七（RWX 不生效，页表级 NX） | **成立**，且不依赖沙箱读数 |
| 结论五（系统库 dlopen 走 shared cache） | 成立，与越狱无关 |
| 结论六（软链接创建不检查目标） | 待重测，可能是越狱给的 |
| 结论二（目录枚举全通） | **作废** |
| 结论三（`/private/preboot` 可枚举） | **作废** |
| 任何 `sbx_*` 读数 | **作废** |

## 结论九：`selfcopy` 这组对照没有变量（我的设计错误）

```
dlopen_intact  = FAIL <cannot dlopen a main executable '<tmp>/selfcopy-intact.bin'>
dlopen_corrupt = FAIL <cannot dlopen a main executable '<tmp>/selfcopy-corrupt.bin'>
```

dyld 对 `MH_EXECUTE` 一律拒绝，**在任何签名检查之前**。完整副本和改坏副本
拿到的是同一句话，这一组测不出任何东西。我用"拷自己"来隔离签名变量，
但拷贝的对象根本不具备被 dlopen 的资格。

顺带捡到一条有用信息：失败信息里的搜索路径是

```
tried: '<tmp>/selfcopy-intact.bin' (cannot dlopen a main executable),
       '/private/preboot/Cryptexes/OS/<tmp>/selfcopy-intact.bin' (no such file)
```

dyld 会在 **cryptex 根**下再找一次。iOS 18 的 `/` 是 cryptex 的 firmlink 视图，
同一个路径在 dyld 眼里有两个名字。后面所有"路径归一化"的判断都要记住这点。

## v5 改了什么

| 改动 | 为什么 |
|---|---|
| `stagedDylib()` 取代 `dlopenSelfCopy()` | 用**真实 dylib**（cryptex 里的 `libobjc-trampolines.dylib` 等）做三段对照：原路径 / 容器内完整副本 / 容器内改坏副本 |
| 改坏位置按 Mach-O 解析定位到 `__TEXT` | 改在 `__LINKEDIT` 只会得到 "malformed"，问的是解析器不是签名 |
| `jumpTest()` 加 `mprotect(RX)` | 把"显式拒绝"（EPERM）和"接受但不生效"（返回 0 仍 fault）分开 |
| `sweep.dyld :: loadedImages()` | 每次扫描第一行就报**本进程被注入了什么**，越狱环境立刻可见 |

### 顺带：这一类编译错误不该再烧第三轮

v5 第一次构建挂在 `_dyld_image_count` / `_dyld_get_image_name`，和 v4 的
`sys_icache_invalidate` 是同一个毛病：**符号在 macOS 的 Swift Darwin overlay 里
有，iOS 没有**。本地写起来毫无感觉，一上 `-sdk iphoneos` 就 `cannot find X in scope`。

`scripts/verify.sh` 现在有一条规则：`sys_icache_invalidate` / `_dyld_*` /
`_sandbox_*` 这类符号**只能出现在 dlsym 的字符串里**，出现裸调用就警告。
推之前跑一遍，比等 CI 快 5 分钟。

**v7 又栽了一次，同一类，第四次**：新建的 `ProbeFileCreate.swift` 只写了
`import Darwin` / `import Foundation`，忘了 `import AppIntents`。CI 报的是

```
error: cannot find type 'AppIntent' in scope
error: unknown attribute 'Parameter'
error: cannot find type 'IntentResult' in scope
```

十几条，看着像整份代码崩了，其实只缺一行 import。共同点还是**只在
`-sdk iphoneos` 下才暴露**——和缺符号是同一件事的两种形态：本地那套环境
比目标环境宽松，所以"本地没报错"从来不构成证据。

现在 `verify.sh` 加了对应的一条：任何文件只要出现 `: AppIntent`、`@Parameter`、
`some IntentResult`，就必须有 `^import AppIntents`，否则直接判 MISS。

## 需要先定的一件事

这台设备上量到的所有沙箱数据都不可用。两条路，选一条再往下走：

**A. 换一台未越狱设备**跑同一份包，重建基线。之后所有结论才谈得上"iOS 18.5
的行为"。代价是要重新装一次，好处是 `sandbox_check` 恢复可信，
`/etc/passwd` 那种"绿"会立刻变回 EPERM，噪声归零。

**B. 承认研究对象是"越狱设备上的 App"**。那么问题就变了：不再是"沙箱能不能
绕过"（已经绕过了），而是"在已越狱前提下，Shortcuts/App Intents 这条链路
还能不能扩大战果"。这条路的前提是先接受：任何 App 都能做这些事，
研究价值从"权限提升"转向"持久化 / 隐蔽性 / 供应链"。

不选就继续跑，只会得到更多无法归因的绿色。

---

# v5 实测结果（重启后，build v5-staged-dylib）

重启清掉了注入：`sweep.dyld :: count=550 injected=none`，`usedImages` 里
dopamine 那条消失，`/usr/lib` 从 22 项变成 21 项（`systemhook.dylib` 没了）。

## 结论十：我上一条的越狱结论是错的

重启前后逐项对比：

| 观测 | 越狱时 | 重启后（无注入） | 变了吗 |
|---|---|---|---|
| `injected` | systemhook.dylib | none | **变了** |
| `/usr/lib` 条目数 | 22 | 21 | **变了** |
| `/etc/passwd` 读前 64 字节 | 成功 | **成功** | 没变 |
| `/System/Library/Frameworks` | 245 条 | **245 条** | 没变 |
| `/private/preboot` | 4 条 | **4 条** | 没变 |
| `/private/preboot/Cryptexes` | 3 条 | **3 条** | 没变 |
| `sbx_*` | 全 DENY | **全 DENY** | 没变 |
| `/bin/sh`、`/dev/disk0` 的 `err(-1,EFAULT)` | 有 | **有** | 没变 |

越狱只贡献了 `systemhook.dylib` 和注入本身，**没有改变任何一条文件访问结果**。
我上一条把这些绿色全判成"越狱给的"，判过头了。撤回。

修正后的结论是更有意思的那一个：

> **未越狱、普通签名的 App，在 iOS 18.5 上可以读 `/etc/passwd`、
> 枚举 `/private/preboot` 和 `/System/Library/PrivateFrameworks`；
> 而 `/private/var/mobile`、`/private/var/db`、`/private/var/containers` 一律 `opendir=EPERM`。**

分界线不在"系统 vs 用户"，而在**系统侧 vs 用户数据侧**。系统分区本来就
world-readable（755/644），沙箱只把用户数据圈起来。这不是漏洞，是设计；
但它意味着"读系统文件"这一类结果**没有研究价值**，别再往那个方向挖。

### 方法论修正：`sandbox_check` 不能当判据

同一批路径上，`sandbox_check` 说 DENY，`open`/`read` 说成功，重启前后都是如此。
所以不是被 hook，是**这个函数问的问题和内核实际判断的不是同一件事**
（不展开 firmlink、不展开系统侧的 allow 规则）。以后判读只看 syscall 结果，
`sandbox_check` 降级为"仅供参考"。

## 结论十一：沙箱在 `file-map-executable` 先拦，签名校验根本没被问到

```
pick           :: /private/preboot/Cryptexes/OS/usr/lib/libobjc-trampolines.dylib size=68176
dlopen(src)    :: dlopen=ok
dlopen(intact) :: FAIL <file system sandbox blocked mmap() of '.../tmp/staged-intact.dylib'>
dlopen(corrupt):: FAIL <file system sandbox blocked mmap() of '.../tmp/staged-corrupt.dylib'>
```

两次失败**原因完全相同**，而且都不是签名错。对照还是没有变量——但这次
原因从"dyld 不认 MH_EXECUTE"变成了"沙箱不让映射"，这比签名问题更靠前一层。

同时它独立验证了 v4 的 `sbx_exec=DENY`：容器内路径的 `file-map-executable` 是拒绝的。

于是问题应该换成：**有没有哪个"我能写"的目录同时也允许 `file-map-executable`？**
有 → 那就是代码执行的落点；没有 → 这条路闭合。v6 就是去测这个矩阵。

## 结论十二：`mprotect(PROT_EXEC)` 返回 ok 也是谎，这次死在 CODESIGNING

v5 的 jump 变成了完全不同的死法：

| | v4 | v5 |
|---|---|---|
| 调用 | `mmap(RWX)` 直接跳 | `mmap(RWX)` → `mprotect(RX)` → 跳 |
| `mprotect` 返回 | — | **ok** |
| 区间保护位 | `rw-/rwx` | `r--/rw-` |
| 终止方式 | `SIGNAL / SIGBUS` | **`CODESIGNING` / `Invalid Page`** |
| 签名标志 | `VALID,REQUIRE_LV` | `VALID,HARD,KILL,REQUIRE_LV` |

`mprotect(RX)` 返回 0，但结果区间是 `r--/rw-`：**X 没进去，连 max prot 里的 X 也没了**。
然后取指 → 内核按 CODESIGNING 归类，`Invalid Page`，SIGKILL。

这次有两个变量同时变了（我加了 mprotect；这一版签名带上了 `CS_HARD|CS_KILL`），
**不能把死法差异归给其中任何一个**。但两条路都指向同一个结论：
没有 X 的页，取指必死；死法取决于签名标志，不取决于调用方式。

## 结论十三：v5 的"基线"其实是缓存命中

```
own-executable :: dlopen=ok dlsym(main)=0x...
dlopen(src)    :: dlopen=ok
```

两条都是 `already-loaded`——`libobjc-trampolines.dylib` 本来就在 `usedImages` 里，
主可执行文件更是。`dlopen` 对已加载的路径直接返回旧句柄，**不读文件、不验签**。
所以这两条"ok"证明不了任何事。v6 在 `load()` 里加了 `isLoaded` 前置判断，
输出区分 `dlopen=ok(loaded)` 和 `dlopen=ok(already-loaded)`。

## v6 改了什么

| 改动 | 为什么 |
|---|---|
| `execMapMatrix()` | 对每个可写目录：拷一个 dylib 进去 → 问 `file-map-executable` → 真 dlopen。找"能写 + 能执行映射"的交集 |
| `control.bundle-exec` 正对照 | 必须先拿到一个 `allow`，否则"全是 DENY"什么也说明不了 |
| `isLoaded()` 缓存命中标记 | 把"加载成功"和"早就加载了"分开 |
| 源 dylib 优先挑未加载的 | 否则 dlopen 永远命中缓存 |

## 结论十四：v6 的 exec-map 矩阵作废——正对照自己就是 DENY

```
sweep.execmap :: control.bundle-exec :: sbx=DENY
sweep.execmap :: src :: /usr/lib/libRPAC.dylib already_loaded=false
sweep.execmap :: ~/tmp :: write=ok sbx=DENY dlopen=FAIL <file system sandbox blocked mmap()>
```

`control.bundle-exec` 是正对照：主可执行文件**一定**允许被映射执行，否则 App 根本起不来。
它返回 `DENY`，只有两种解释——要么 `sandbox_check` 答不了 `file-map-executable`
这个问题（主可执行文件是 dyld 在沙箱生效前映射的，事后再问策略，路径已经不在
"可执行"白名单的语义里），要么这个函数整体坏了。

无论哪种，结论都一样：**这组矩阵既不能证明能，也不能证明不能。**
v6 之前定下的判读规则（"全是 DENY 而正对照 allow → 路线闭合"）没有被满足，
所以 v6 什么也没关掉。这是我自己写的规则，我自己没遵守。

`staged.step :: copy FAIL 513` 顺带解释了另外两行：513 是 `NSFileWriteNoPermissionError`，
bundle 只读、`Frameworks/` 压根不存在。对一个 `write=FAIL` 的目录拿 `sbx=DENY`
去解释没有意义——文件都不存在。

## 结论十五：崩溃报告给出了比矩阵更硬的答案——max prot 里没有 X

v6 的 jump 死法和 v5 一样是 `CODESIGNING / Invalid Page`，但报告细节不一样：

| 字段 | 值 |
|---|---|
| `vmRegionInfo` | `VM_ALLOCATE 0x102850000-0x102854000 [16K] r--/rw- SM=PRV` |
| thread 1 `esr` | `(Instruction Abort) Permission fault` |
| thread 1 `pc` / `far` | 都等于 `0x102850000` |
| `termination` | `CODESIGNING` / `Invalid Page`，`SIGKILL` |
| `codeSigningFlags` | `VALID,HARD,KILL,REQUIRE_LV` |

`r--/rw-` 是 `PRT/MAX`：**当前保护位 `r--`，上限 `rw-`**。上限里就没有 X。

这比 v4 那次硬。v4 是 `rw-/rwx`（上限有 X、当前没有），还能解释成"mprotect 没生效"；
现在上限本身没有 X，意味着 `mmap(PROT_EXEC)` 返回成功时，内核已经把 EXEC 从
max prot 里抹掉了，`mprotect(RX)` 返回 0 只是把同一个谎重复一遍——它不可能
授予一个 max prot 不允许的位。

三件事同时成立：取指 fault 的地址 == mmap 的地址（`pc == far`）、fault 类型是
**instruction abort / permission fault**（不是缺页、不是对齐）、区间上限不含 X
且被 AMFI 归类为 `Invalid Page`。

**没有 `dynamic-codesigning` entitlement，匿名页的 maxprot 永远不含 X。**
这条路不是被沙箱关的，是被 VM 层关的。改调用顺序、换 `mprotect` 时机、用 `MAP_JIT`
都绕不过去，因为要改的是 max prot，而它由 entitlement 决定。

## v7 改了什么：加"创建文件"

代码执行路线闭合之后，能问的问题换了一层：不是"我能不能执行自己的代码"，
而是"**我能不能把文件放到一个别人会执行的位置**"。两件事的判据完全不同。

| 新增 | 为什么 |
|---|---|
| `ProbeFileCreate.create()` | `open`→`write`→`fsync`→`fstat`→**读回比对**。只信 `write` 的返回值会把配额耗尽、只读卷读成成功 |
| `createAndReport()` | 建完立刻问 `file-map-executable` 并**真 dlopen**。判据是 dlopen，不是 `sandbox_check` |
| `matrix()` | 19 个候选目录各建一份，输出 `writable=N/19`。基线 = 自己容器全绿 + 系统侧全红 + bundle 负对照 FAIL |
| `resolve()` | 相对路径按**容器根**解析，不按 cwd。App 的 cwd 是 `/`，让它解释相对路径只会得到看不懂的 ENOENT |
| `/private/preboot/Cryptexes` 进名单 | v6 扫出它是 `mode=777 uid=0`，权限位已放行，只差沙箱一层 |
| App 工具栏加文件夹按钮 | 矩阵有 19 个目录，来回改快捷指令参数太慢；同进程同沙箱，结论等价 |

**没做的事**：没注册进 `AppShortcutsProvider`。上限 10 个，现在正好 10 个，
第 11 个会构建失败。`AppIntent` 不注册也能被快捷指令索引到，只是不在画廊里显示磁贴。

## 结论十六：写面 = 6 个目录，全在自己容器内

v7 实测（两次，App 重启过一次，结果一致）：

```
create.matrix :: tmp                                :: open=ok   ... exec=DENY
create.matrix :: Documents                          :: open=ok   ... exec=DENY
create.matrix :: Library                            :: open=ok   ... exec=DENY
create.matrix :: Caches                             :: open=ok   ... exec=DENY
create.matrix :: home                               :: open=EPERM          ← 容器根自己不可写
create.matrix :: home/Library/Preferences           :: open=ok   ... exec=DENY
create.matrix :: home/Library/Application Support   :: open=ok   ... exec=DENY
create.matrix :: bundle(负对照)                     :: open=EPERM          ← 负对照按预期失败
create.matrix :: summary :: writable=6/19
```

三条读数：

1. **负对照 FAIL** → 上面的 `open=ok` 不是探针在骗自己。这张表这次可以信
2. **`home` 是 EPERM** → iOS 的写授权是**按枚举子目录**给的，不是按整棵子树。
   推论：Shortcuts 递给我一个文件时，给的是"这一个文件"的扩展权限，
   不是"这个目录"。所以在它旁边埋东西大概率也是 EPERM
3. **`/private/preboot/Cryptexes`（mode=777）→ EPERM** → 权限位在沙箱面前
   根本轮不到被检查。这条候选正式关闭，以后不用再试

我上一轮预测基线是 7/19（把 `home` 算进去了），实际 6/19。**预测错了一格，
而且错在没量就断言。**

## 结论十七：`/private/etc` 返回 ENOENT，`/usr/lib` 两次 errno 不一样

```
第一次: /private/etc :: open=ENOENT      /usr/lib :: open=EPERM
第二次: /private/etc :: open=ENOENT      /usr/lib :: open=EROFS
```

`/private/etc/passwd` 在同一份日志里 `lstat=ok`、内容读得出来，目录明确存在。
**创建文件时返回"目录不存在"不是正常的拒绝码。**

两个可能，得用 `statfs` 才能分开：

- 卷本身只读（SSV 快照）→ VFS 直接 `EROFS`，firmlink 目标在某些路径上 `ENOENT`
- 沙箱先拒绝 → `EPERM`

如果 `f_flags & MNT_RDONLY` 成立，这两个异常就都解释完了，而且**都不是发现**——
系统卷只读是设计。定性只要 20 行：

```
statfs(dir) → f_flags & MNT_RDONLY     // 卷是不是只读
open(已存在的文件, O_WRONLY)            // 不创建，只问写
```

## 下一步该问的

1. **P13 的那个命题**：`opensIntent: OpenURLIntent` 交得出去、`UIApplication.open`
   交不出去——同进程同沙箱，换个出口结果不同，这才叫不对称
2. **`shortcuts.run` 这一行**：第三方 App 能不能按名字触发用户已有的快捷指令。
   能，就是一条不需要任何越狱的"委派"原语
3. **`statfs` 那 20 行**：把 ENOENT / EROFS / EPERM 收敛成一个事实
4. 用户数据侧（`/private/var/mobile`）、`/private/preboot/Cryptexes`、
   `sandbox_check` 当判据——这三条都已关闭，不用再试

## v8 改了什么：把活交给系统 App

代码执行那条线关掉之后，问题换了方向：不是"我能不能执行"，而是
"我能不能让系统 App 替我执行"。这一层不需要任何越狱级 primitive，
只要系统没校验来源，就是真问题。

| 新增 | 为什么 |
|---|---|
| `ProbeSystemApp.targets()` | 21 个 scheme，正负对照排最前，含 4 个 Safari 入口 |
| `canOpenMatrix()` | 只问不做。单独看没有信息量，价值全在跟 `open` 对比 |
| `openMatrix()` | 真交出去，同时记 `before/after` appState 与回调状态 |
| `ProbeHandoffIntent` | 返回 `opensIntent: OpenURLIntent`，由**系统**执行 |
| `LSApplicationQueriesSchemes` | 不声明，`canOpen` 那一列全是 false，整列作废 |

**一个具体、可证伪的命题**：

> 同一个 URL，走 `UIApplication.open` 交不出去（后台，或系统拒绝），
> 但走 `opensIntent: OpenURLIntent` 能交出去。

成立 → "intent 返回值"这条通道的权限比 App API 大：同一个进程、同一个沙箱，
换个出口结果不同。不成立 → 这条也关掉，和 `mprotect` 一样记成"设计如此"。

注意 `openAppWhenRun = false` 是有意的：从快捷指令触发时本进程在后台，
而"后台的 App 能不能让系统打开 URL"正是要问的问题之一。想要前台基线，
就在 App 里点一次、再从快捷指令跑一次，对比两份日志的 `before=`。

**这一版只用了验证过的 API 形式。** `@Parameter(title:description:default:)`
这个三参数组合从没被编译器验证过（v7 在 import 阶段就挂了，参数根本没轮到类型检查），
所以全部退回 `@Parameter(title:default:)`——这个形式在 v6 里编过。
说明挪进标题和 `///` 注释，代价是快捷指令里标签长一点，换掉一次可能的构建失败。

## 结论十八：`OpenURLIntent` 的名字和签名是对的，版本门槛没对

CI 第一轮报了两条，其实是**两个独立的错**，只是撞在同一行：

```
ProbeSystemApp.swift:270:37: error: 'OpenURLIntent' is only available in iOS 18.0 or newer
ProbeSystemApp.swift:257:10: error: function declares an opaque return type 'some IntentResult',
    but the return statements in its body do not have matching underlying types
```

**第一条是好消息。** 编译器没报 `cannot find 'OpenURLIntent' in scope`、也没报
`extra argument 'opensIntent'`——说明这两个 API 的名字和签名我猜对了，唯一的问题是
部署目标写的是 17.0，而这个类型 18.0 才有。上一条笔记里那句"如果报错就退回
`UIApplication.open`"因此作废：不需要退，只是要挂 `@available`。

**第二条是真 bug，和版本无关。** `some IntentResult` 是不透明返回类型，
函数体里每个 `return` 的底层类型必须完全一致：

| 写法 | 底层类型 |
|---|---|
| `.result()` | `IntentResultContainer<Never, Never, Never, Never>` |
| `.result(opensIntent:)` | `IntentResultContainer<Never, OpenURLIntent, Never, Never>` |

原来的 `guard let url = ... else { return .result() }` 让两条路径类型不同，
就算 `OpenURLIntent` 可用也会报错。改法不是加 `if #available`（那只会把
两条分支都留下、错得更明显），而是**只留一条 return**：URL 解析失败时
用一个必然打不开的 `file://` 兜底，把 `parsed=invalid` 写进日志。

这两条合起来说明一件事：`@available` 要挂在**类型**上，不能挂在函数体分支上。
挂在 `struct` 上，`perform()` 里就只剩一种可用性上下文，返回类型也只剩一种。

**同一类错误的第五次**，但形态又变了：第一次是缺符号（`sys_icache_invalidate`），
第二次还是缺符号（`_dyld_*`），第四次是缺 import（`AppIntents`），
这次是**缺版本门槛**。共同点一次没变：**只在 `-sdk iphoneos` 下暴露，
本地永远看不出来**。所以 `verify.sh` 又长了一条：

```
=== iOS 版本门槛（部署目标 17.0） ===
  OK    18.0 专属 API 都挂了 @available
```

规则：非注释行里出现 `OpenURLIntent`，文件里就必须有 `@available(iOS 18`。
以后再引入 18.0 专属 API，把符号名加进那个 `for sym in` 列表即可。

**一个备用方案**：如果 AppIntents 的元数据提取（`appintentsmetadataprocessor`）
对 `@available` 门控的 intent 报错，就把 iOS 部署目标从 17.0 提到 18.0——
探针跑在 18.5 上，提上去没有任何功能损失。这一步没做，因为它是全局改动，
而 `@available` 是局部改动；先试小的。

## 结论十九：这次"不闪退了"，原因是越狱，不是漏洞

v8 的 exec 第一次返回正常：

```
exec.jump :: icache_flush=true ptr=0x00000001017d4000 opcode=ret
exec.jump :: about-to-jump
exec.jump :: RETURNED NORMALLY —— 匿名可执行内存真的可用
exec.result :: jump=ok(returned) mprotect=ok icache_flush=true
```

同一份日志的第一行给出了原因：

```
sweep.dyld :: count=551 injected=/private/preboot/5F6D13F7.../dopamine-iHw65x/procursus/basebin/systemhook.dylib
```

对比 v6 / v7：

```
v6/v7: sweep.dyld :: count=550 injected=none
v8   : sweep.dyld :: count=551 injected=.../dopamine-iHw65x/.../systemhook.dylib
```

**两条独立信号指向同一件事**，不是单点读数：

| 信号 | 干净（v6/v7） | 越狱（v8） |
|---|---|---|
| dyld 镜像数 | `count=550` | `count=551`，多出的那个是 systemhook |
| `/usr/lib` 条目 | 21 条 | 22 条，多出 `systemhook.dylib` |
| `injected=` | `none` | `.../dopamine-iHw65x/.../systemhook.dylib` |

第二条尤其重要：它不依赖 dyld 枚举，是文件系统层面的旁证。镜像表多一个、目录多一个，恰好都是 systemhook——这不是巧合能解释的。

### 这是一次受控对比，不是相关性猜测

| | v6 | v8 |
|---|---|---|
| `exec.jump` 代码 | 同一份 | 同一份 |
| 设备 | iPhone11,6 / 18.5 | iPhone11,6 / 18.5 |
| `mmap(RWX)` | ok | ok |
| `mprotect(RX)` | ok | ok |
| **`injected=`** | **none** | **systemhook** |
| 跳转结果 | SIGKILL / `Invalid Page` | 正常返回 |

唯一变化的可观测变量是 `injected=`。所以正确表述是：

> **匿名可执行内存在这台越狱设备上可用；这不能推广到未越狱的 iOS。**

`systemhook` 干的事正是给进程打补丁、让 AMFI 不再对缺页做签名校验——它拆的就是结论十五里那堵墙（max prot 不含 X，由 `dynamic-codesigning` entitlement 决定）。也就是说 v6 的结论没有被推翻：**墙是真的，是越狱把墙拆了**，而不是"墙本来就不存在，之前测错了"。

### 沙箱那堵墙没倒，这才是这组数据里最干净的一条

同一份日志里，沙箱的表现一点没变：

```
sweep.staged :: dlopen(intact) :: dlopen=FAIL <file system sandbox blocked mmap() of '<tmp>/staged-intact.dylib'>
sweep.execmap :: ~/tmp :: write=ok sbx=DENY dlopen=FAIL <... file system sandbox blocked mmap() ...>
create.matrix :: summary :: writable=6/19
create.matrix :: bundle(负对照) :: open=EPERM
```

越狱状态下、同一个进程里：

| 墙 | 越狱前 | 越狱后 | 结论 |
|---|---|---|---|
| 匿名页取指（AMFI / 页表 NX） | 挡 | **放行** | systemhook 拆了 |
| 从自己容器 `dlopen`（sandbox `file-map-executable`） | 挡 | **仍挡** | 没动 |

两堵墙是**独立**的。这一条以前只能推断（"可能是两层"），现在有差分实测。顺带说明：Dopamine 这类 systemhook 主要补的是代码签名/AMFI 路径，不负责给 App 解沙箱 profile，所以容器内的 `file-map-executable` 限制照旧。

### `sandbox_check` 第三次被判死，这次是决定性的

```
sweep.execmap :: control.bundle-exec :: sbx=DENY
```

这台设备上，主可执行文件的代码**正在运行**——它百分之百允许被映射执行。`sandbox_check` 仍然答 `DENY`。前两次（v6 正对照失败、v7 与 syscall 矛盾）还能辩解成"这个 build 更严"；现在环境反过来帮它作弊（墙已被拆），它还是答 DENY。

**结论：这个函数答不了 `file-map-executable` 这个问题。** 不是严，是坏。以后任何用它当判据的结论一律作废，包括 v6 那张矩阵。

### v4 那次不能回溯解释

v4 的区间是 `rw-/rwx`（上限含 X），和 v6 的 `r--/rw-` 不同，当时我据此说"重启推翻了越狱假设"。现在看，v4 **根本没有 `injected=` 这一行**，它跑在什么环境里是未知的。给它补一个"当时是越狱/当时不是越狱"的解释，都是事后编故事——这正是这一轮要避免的错误，方向反过来而已（上次把越狱当结论，这次差点把越狱的功劳当发现）。

能说的只有：`max prot` 含 X 是必要条件，不是充分条件。v4 有 X 却仍崩，说明当时还有别的东西在拦（比如 icache 没刷、或 `mprotect` 生效时序）。这条留作开放问题，不结案。

### 协议变更：环境标签进日志

这一轮之后，`env=` 是每条 `*.ctx` 的固定字段：

```
sweep.ctx :: build=v9-env env=clean bundle=com.probe.intentprobe pid=... appState=active
sweep.ctx :: build=v9-env env=jailbroken(systemhook.dylib) bundle=... appState=active
```

`exec.jump` 的判词也不再由那行代码决定，而是由环境决定：

| 环境 | 日志 |
|---|---|
| clean | `RETURNED NORMALLY —— env=clean，匿名可执行内存真的可用` |
| 越狱 | `RETURNED NORMALLY —— 但 jailbroken(systemhook.dylib)，不构成 finding` |

判据写在 `ProbeEnv` 里，两条信号（dyld 镜像表 + bootstrap 落盘文件）分开失效，所以都留着。`exec.env` 那一行在跳转**之前**落盘——进程随后被 SIGKILL 也留得下归属。

### 下一步：把相关变成因果

现在只差一步就能把"越狱导致"从相关升级成因果：**同一台设备重启（越狱失效，`injected` 回到 `none`），再跑一次 exec**。

| 重启后结果 | 含义 |
|---|---|
| 又崩在 `Invalid Page` | 同机同码前后对照成立，"越狱拆墙"从相关变因果 |
| 仍然正常返回 | `injected=none` 不足以证明环境干净，得再找第三条信号 |

这个 A/B 不需要改代码，只需要一次重启和一次点击。它比再加任何新探针都值钱——因为它检验的是**判据本身**。

## 结论二十：A/B 做成了——墙是真的，越狱是唯一变量

v9 那次重启之后：

```
sweep.ctx :: build=v9-env env=clean ...            ← injected 回到 none
exec.env  :: env=clean → 结果可以当成 iOS 的行为
exec.jump :: about-to-jump
（没有下一行）
```

三份日志拼起来，是一个完整的前后对照：

| | v6 | v8 | v9 |
|---|---|---|---|
| `injected=` | `none` | `systemhook` | `none` |
| `env=` | —（当时还没这个字段） | `jailbroken(systemhook.dylib)` | `clean` |
| 跳转 | SIGKILL / `Invalid Page` | 正常返回 | SIGKILL / `Invalid Page` |

同机、同码、同一个 `mmap(RWX)` 返回值，结果随 `injected` 翻转，并且**翻转回去了**。
这比单次的"越狱时成功"强得多：如果 v9 仍然正常返回，就说明 `injected=none`
不足以证明环境干净，判据本身要重写。它没有——判据成立。

所以代码执行这条线，最终状态是：

> 未越狱 iOS 上，匿名可执行页不可用（max prot 无 X，AMFI 兜底）。
> 这是设计，不是缺陷。越狱能拆，但那是越狱的能力，不是 App 的。

## v10 改了什么：让"交给系统 App"真的能跑

一句话：**功能早就写好了，但四版日志里 `sysapp.*` 出现 0 次。**

| 新增 | 为什么 |
|---|---|
| 工具栏纸飞机按钮 | `ProbeSystemApp` 没注册进 `AppShortcutsProvider`（上限 10 个），从快捷指令里搜得到但很难找，结果就是从来没跑过 |
| `runAll(origin:)` | canOpen + open 一次跑完，输出一行 `canopen_true=N/21 open_accepted=M/21` |
| `beginBackgroundTask` | 每 open 一次本进程就被切走，后台约 30 秒会被挂起，21 个目标跑不完 |
| 轮询降到 3 拍 | 切走的第一步是 `inactive`，300ms 足够；10 拍会让整轮慢到被挂起 |
| `safari.web-search` / `safari.x-https` | 用户真正问的是"Safari 能不能替我做"，原来表里只有 `file:` 和 `data:` 两个负面样本 |

`canOpenMatrix` 顺手拆成 `canOpenLines() -> (lines, yes)`，
矩阵和计数共用一份实现，避免"表里数着 6 个 true、summary 写 5"这种漂移。

---

## v10 跑完了：一半结论当场作废

### 原始读数

```
sysapp.summary :: origin=foreground canopen_true=17/21 open_accepted=3/21
```

`control.bogus` → `canOpen=false` / `open=refused`，`control.https` → `canOpen=true` / `open=accepted`。
两道闸门都过了，表本身是有效的。**无效的是 `open_accepted=3/21` 这个数字。**

### 为什么 3/21 不能读

把 21 行按 `before=` 分组，相关性是**完美**的：

| `before=` | 行数 | `open=accepted` |
|---|---|---|
| `active` | 3（control.https / tel / itms-services） | **3** |
| `inactive` 或 `background` | 18 | **0** |

零例外。也就是说 `open_accepted` 测的不是"这个 scheme 通不通"，
而是"我发这一枪的时候在不在前台"。

机制很硬：

```
第一个 open 成功 → 本进程被切到后台 → 之后每一次 open 都从后台发起
                → iOS 对后台发起的 open 一律拒绝（refused / no-callback）
```

v10 的设计是"一次循环发 21 个"，所以第一个之后全部塌掉。
这不是 iOS 的缺陷，是我把实验做成了单次可用。

**判读规则（从这轮起硬性生效）**：`before != active` 的行，
`open=` 字段一律作废，不管它写的是 `refused` 还是 `accepted`。

### 这轮真正有效的读数

**1. `canOpen` 那一列 21 行全部有效。** `canOpenURL` 是同步、无副作用、
不改变进程状态的，整批在 `00:37:54` 一瞬间跑完，全在 active 下。

| 结果 | 数量 | 目标 |
|---|---|---|
| `true` | 17 | https、4 个 shortcuts、2 个 prefs、files/photos/music、tel/sms/mailto/maps、**x-web-search**、**x-safari-https**、itms-services |
| `false` | 4 | `control.bogus`、`prefs.legacy`、`safari.file`、`safari.data` |

四个 false 全是**应该** false 的：bogus 没 handler、`prefs:` 老写法早废、
`file:` 和 `data:` 在 iOS 9 之后封死。说明这张表在挑，不是一律返回 true。

**2. 这里有个和文档冲突的读数。**

`project.yml` 的 `LSApplicationQueriesSchemes` 只声明了 11 个：
`shortcuts / prefs / App-prefs / shareddocuments / photos-redirect / music / tel / sms / mailto / maps / itms-services`。

`x-web-search` 和 `x-safari-https` **不在里面**，`canOpenURL` 却返回 `true`。
而同一张表里 `control.bogus`（同样未声明、且没有 handler）返回 `false`。

两个可能，v10 的数据分不开：

- (a) 声明门槛只约束"没有系统 handler 的 scheme"，Safari 的私有 scheme 走系统 App 的通道，绕过去了
- (b) 打包出来的 Info.plist 跟 project.yml 不一致（比如 xcodegen 合并了别处的配置）

v11 在运行时把 `Bundle.main` 里的 `LSApplicationQueriesSchemes` 原样 dump 出来（`sysapp.decl`），
并加了 `x-safari-http` 作为同族第二个样本。**(a) 成立的话，整个 `x-safari-*` 族都该是 true。**

**3. `itms-services` 是 `accepted ≠ worked` 的实物标本。**

`open=accepted`，然后屏幕上弹了「无法连接 127.0.0.1」——iOS 收下了，
去拉 manifest，拉不到。这正好把"收下了"和"做成了"这两种状态钉在一起给人看。

### 截图和日志打架，这一条必须说清

日志：`safari.x-https :: open=refused`。
屏幕：Safari 停在 `example.com`，状态栏左上角写着 `◀ IntentProbe`。

看着像"handler 说谎"，但**更可能是另一回事**：

`control.https` 的 URL 就是 `https://example.com`，而且它是**第一个**发的（`00:37:54`，
`open=accepted`，`after=inactive`）。之后 18 行的 `before=` 全是 inactive/background，
说明 Safari 从那以后一直在前台。所以屏幕上那个页面，大概率是 `control.https` 开的，
跟 `x-safari-https` 没关系。

v10 分不开这两者，因为两个目标的 URL 打的是同一个域名、屏幕上长得一模一样。
这是我的设计漏洞，不是数据的问题。

**v11 的修法**：每个目标的 URL 都带自己的名字（`?probe=<label>`）。
以后任何一张截图都能自证是哪个目标开的，这种歧义不会再出现。

## v11 改了什么：把"一次激活一个"做成机制

| 改动 | 为什么 |
|---|---|
| 串行执行器 `SysAppRunner` | 一次激活只发一个目标，发完就被切走，用户点回来发下一个。每个目标都在 `before=active` 下发出 |
| cursor 存 UserDefaults | 进程会被挂起甚至回收，内存里的进度丢了就得从头点 22 次 |
| `before != active` 不消费 cursor | 记一条 `sysapp.invalid` 就返回，绝不拿后台读数充数 |
| 主判据换成 `didEnterBackground` 时间戳 | 发出后 3 秒内被切走 = 系统真接了，跟 handler 说什么无关 |
| `sysapp.fire` 先落盘再调 `open` | 进程可能立刻被挂起，回调等不到，但"确实在 active 下发出去了"这个事实必须留下 |
| URL 带 `?probe=<label>` | 截图自证身份，见上一节 |
| `sysapp.decl` dump 真实声明列表 | 解掉"未声明却 canOpen=true"的歧义 |
| 重点组 6 个 / 全量 22 个 | 22 次点击没人会做完；6 次是能做完的 |

> `runAll(origin:)` 和工具栏纸飞机**已删除**。它产出的 `open_accepted` 是
> 一个被前后台状态污染的指标，留着只会有人再去读它。
> 现在唯一的批量入口是 intent 的 `mode=open`，而且注释里写明了"别用它出结论"。

重点组就 6 个，都是"不跑完这一轮就没法往下走"的：

```
control.https      control.bogus      safari.x-https
safari.x-http      safari.web-search  shortcuts.run
```

### 这一轮的判读顺序（按这个顺序读，别跳）

```
1. sysapp.decl 里有没有 x-safari-https
      有 → 我记错了自己声明什么，v10 的"冲突"不存在，收工
      没有 → (a) 成立：系统 App 的 handler 绕过声明门槛，这是个真结论

2. control.bogus 的 left 必须是 no、open 必须是 refused
      不是 → 整轮作废

3. control.https 的 left 必须是 yes
      不是 → 探针坏了，不是 iOS 的问题

4. safari.x-https / x-safari.x-http 的 left
      yes → 未声明的私有 scheme 能把 Safari 拉起来，且不需要用户确认

5. safari.web-search 的 left
      yes → 免交互唤起 Safari 搜索

6. shortcuts.run 的 left
      yes → 第三方 App 能按名字触发用户已有的快捷指令（不需要 Shortcuts 在前台）
```

`left=yes` 但 `open=refused` 的组合是**最值得注意**的一种：它说明
completion handler 在后台路径上会假阴性，任何用它当判据的代码都会漏报。

---

## 自定义 URL：直接看"没有提示就进 Safari"

串行队列是固定表，验证不了"我随便打个站会怎样"。所以加了一条手动通路：
输入框 + 前缀下拉，想打哪个打哪个，不用改代码重装。

### 判据：`verdict` 三档

真正回答"有没有弹确认框"的不是屏幕上有没有看到框——是**本进程落到了哪个状态**。

| `verdict` | `after=` | 含义 | 屏幕上 |
|---|---|---|---|
| `switched` | `background` | 真的被切走了 | Safari 直接起来，**没有确认框** |
| `possibly-prompted` | `inactive` | 被盖住但没切走 | 多半压着一个系统确认框在等用户点 |
| `inert` | `active` | 什么都没变 | URL 收下了，但没有任何反应 |

中间那一档是这轮补的。iOS 的"要在 XX 中打开吗？"是 SpringBoard 的 alert，
它只让前台 App 变成 `inactive`，**不会**让它进 `background`。
所以 `inactive` 这个落点本身就是"弹了框"的指纹——之前的实现只有两档，把它和
"什么都没发生"混在一起了。

### 怎么用这一次实验把两个 scheme 分开

只改前缀，不改域名，各打一次：

```
输入：example.com/?probe=A    前缀：https            → verdict=?
输入：example.com/?probe=B    前缀：x-safari-https   → verdict=?
```

| 组合 | 结论 |
|---|---|
| 两个都 `switched` | 私有 scheme 没有额外权限，`https` 本来就能免交互进浏览器 |
| `https` 的 `after` 不是 Safari（被默认浏览器接走）、`x-safari-https` 硬进 Safari | **这才是这两者真正的差别**：私有写法能绕过"默认浏览器"这个用户选择 |
| `x-safari-https` 是 `possibly-prompted` | 有确认框，免交互不成立 |
| `x-safari-https` 是 `inert` | URL 收下了但 Safari 没动，v10 那个 `open=refused` 就是这种情况 |

**唯一能区分第一种和第二种的办法**：看屏幕上开的是不是 Safari。
如果设备把默认浏览器改成了 Chrome / Edge，`https` 会进那个，`x-safari-https` 仍然进 Safari。
这也是为什么每个 URL 都带 `?probe=<label>`——截图自证身份。

### 输入框的行为

- 输入里已经带 `://` 的先剥掉再拼前缀，所以 `example.com/a` 和 `https://example.com/a`
  选同一个前缀得到同一个 URL。不这么做的话，两个看起来一样的输入打出两种结果，没法比。
- 选 `原样` 就完全不拼，用来打完整 URL（比如 `data:`、`file:`、`itms-services:`）。
- 选 `x-web-search` 时输入被当成**搜索词**，拼成 `x-web-search://?<词>`。
- 每次打完，界面上直接回显 `verdict · left · open · url`，不用滚到日志底部。

### 两条容易读错的

1. **`open=refused` 但 `verdict=switched`**：completion handler 假阴性，
   URL 其实投递了。以 `verdict` 为准，`open=` 只当辅助。
2. **`open=accepted` 但 `verdict=inert`**：URL 收下了，什么都没发生。
   v10 的 `itms-services` 就是这一种（然后弹了个连不上 127.0.0.1 的框）。
   `accepted` 只证明"有人接单"，不证明"送到了"。

---

## 09:23 那张截图：最后一环补上了

### 看到的东西

```
隐私
允许"ProbeNoSuchShortcut"输出 1 个文本项目吗？
[不允许]  [允许一次]  [始终允许]
```

背景是 Shortcuts，中间显示 `test`，左上角 `◀ IntentProbe`。

### 它证明了什么

`shortcuts://run-shortcut?name=X` 不是"把 Shortcuts 拉到前台就完了"。
Shortcuts 拿到 name、找到快捷指令、**跑完了**（否则不会有"1 个文本项目"这个输出），
然后才在返回结果这一步问权限。

所以 `shortcuts.run` 的定性从 `switched`（唤起了）升级为：

> **第三方 App 能按名字执行用户已有的快捷指令，执行本身不需要任何确认。**

### 但这里有个必须分清的地方

弹的这个框**不是执行权限，是返回通道权限**。两件事被一个弹框挡在一起，很容易读错：

| 环节 | 有没有闸门 |
|---|---|
| 第三方 App → 按名字触发快捷指令 | **没有**。静默 |
| 快捷指令体内的动作（写文件、读照片…） | **没有**。用快捷指令自己的权限跑 |
| 快捷指令把结果回传给调用方 | **有**。就是这张截图 |

推论，也是下一轮要验的东西：

> **点「不允许」只挡回传，不挡副作用。**
> 文件如果已经被追加了，点不允许它也已经写完了。

### 还有一件更值得注意的

这个框有「始终允许」。点一次之后，整条链——触发、执行、写文件、回传——
**永久静默**，不会再问第二次。

这才是完整的权限链：不是"每次都要用户点头"，而是"点一次头，之后全部自动"。

### 想彻底不弹框的办法

在快捷指令最后加一步「停止此快捷指令」（Stop This Shortcut）。
没有输出，就没有回传，也就没有这个框。**副作用照做，一个提示都不出。**

### 下一轮要跑的三条

1. **副作用与回传解耦**（最关键）
   重打 `shortcuts.run`，这次点「不允许」。然后看 `示例.txt` 里有没有多一行。
   - 多了 → 回传权限只管回传，副作用无条件执行。这是结论。
   - 没多 → 这个框其实挡住了整个执行。那前面的定性要退回去。

2. **「始终允许」之后是否真的不再问**
   点一次始终允许，连打三次，看还弹不弹。

3. **加「停止此快捷指令」的版本**
   看是不是真的一个框都没有。

> 注意 09:23 那次跑的版本里还没有「追加到文件」这一步（09:28 才加的），
> 所以那张截图只证明了"执行 + 输出回传"，**没有**证明文件被写过。
> 这两件事别混。

## v12 改了什么

| 改动 | 为什么 |
|---|---|
| `verdict` 拆成四象限 + 三个异常档 | 上一版只按 `left` 一维判，把 `accepted+没抢前台` 和 `refused+没抢前台` 压成同一个 `inert` |
| 轮询窗口 1.2s → 3.0s | 实测 `switched` 落在 0.84–1.19s，最慢那条离上限差 10ms，尾巴必然漏 |
| `refused` 时提前收工 | 已确定没投递，等满 3 秒没意义，只多等 0.6s 抓假阴性 |
| 界面按结论上色 + 一句话解释 | `inert` 和"没点上"在屏幕上长得一样，那轮连点三次就是这个原因 |
| 修 `observed == "background"` 掉进 `.none` 分支 | 通知晚一拍就会把"切走了"记成 `inert`，这正是那个混淆的源头 |
| `cb` 换成带锁的 `CBBox` | 裸 `var` 被两线程读写，`-enforce-exclusivity=checked` 下可能直接 trap |

### 新的判据表

| `open` | `left` | `verdict` | 含义 |
|---|---|---|---|
| accepted | background | `switched` | 投递 + 抢前台 |
| accepted | inactive | `possibly-prompted` | 被盖住，多半压着确认框 |
| accepted | **active** | **`silent-delivered`** | 投递了，目标没抢前台（不是失败） |
| refused | active | `inert` | 真没投递 |
| refused | **background** | `anomaly-false-negative` | handler 说谎，拿它当判据会漏报 |
| refused | inactive | `prompted-then-refused` | 弹了框但没送成 |
| no-callback | active | `no-callback-inert` | 三秒内没回调也没切走，比 refused 弱一档 |

上一版只有三档，`silent-delivered` 和 `inert` 是一回事——
`https://localhost/...plist` 那条被记成 `inert`，我当成了"解释不了的怪现象"。
其实不怪，是标签少了一格。
