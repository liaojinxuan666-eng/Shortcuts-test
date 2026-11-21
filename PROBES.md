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
