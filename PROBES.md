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
