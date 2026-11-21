import Darwin
import Foundation

/// 三路探测同一个路径，**结论不一致的地方就是研究价值所在**：
///
/// 1. **Foundation**（`FileManager`）—— 先做 URL 标准化，可能被上层预检拦掉，
///    报错是 Swift Error 而不是 errno，丢失了内核的真实回答
/// 2. **POSIX**（`open`/`lstat`/`opendir`）—— 直达 vnode，`errno` 更接近内核答案
/// 3. **`sandbox_check`**（dlsym 取符号）—— 不真的做操作，直接问内核"我能不能做"
///
/// 判读规则：
///  - 3 说 allow、2 报 EPERM  → 还有一层非沙箱的检查（TCC / 代码签名 / MACF）
///  - 2 成功、3 说 DENY       → 沙箱策略没覆盖这条路径，值得深挖
///  - 2 和 3 都拒绝、Foundation 也拒绝 → 这条路径是干净的，换下一条
enum ProbeFS {

    // MARK: - errno 名字

    private static let errnoNames: [Int32: String] = [
        EPERM: "EPERM", ENOENT: "ENOENT", EACCES: "EACCES", ELOOP: "ELOOP",
        ENOTDIR: "ENOTDIR", EISDIR: "EISDIR", ENAMETOOLONG: "ENAMETOOLONG",
        EROFS: "EROFS", ENOSPC: "ENOSPC", EXDEV: "EXDEV", EMLINK: "EMLINK",
        EEXIST: "EEXIST", EINVAL: "EINVAL", ENODEV: "ENODEV", EBADF: "EBADF",
        EFAULT: "EFAULT", ENOMEM: "ENOMEM", EIO: "EIO", ENOTSUP: "ENOTSUP",
    ]

    static func err(_ e: Int32) -> String { errnoNames[e] ?? "E\(e)" }

    // MARK: - POSIX stat

    static func statLine(_ path: String) -> String {
        var st = stat()
        if lstat(path, &st) != 0 { return "lstat=\(err(errno))" }

        let mode = UInt32(st.st_mode)
        let kind: String
        switch mode & 0o170000 {
        case 0o040000: kind = "dir"
        case 0o100000: kind = "reg"
        case 0o120000: kind = "lnk"
        case 0o020000: kind = "chr"
        case 0o060000: kind = "blk"
        case 0o010000: kind = "fifo"
        case 0o140000: kind = "sock"
        default:       kind = "?"
        }

        var s = "lstat=ok type=\(kind) mode=\(String(mode & 0o7777, radix: 8))"
        s += " uid=\(st.st_uid) gid=\(st.st_gid) nlink=\(st.st_nlink) size=\(st.st_size)"

        // 软链接顺手读出目标串 —— APFS 上它存在 xattr 里，数据分支是空的
        if kind == "lnk" {
            var buf = [CChar](repeating: 0, count: 1024)
            let n = readlink(path, &buf, buf.count - 1)
            if n > 0 { s += " -> <\(String(cString: buf))>" }
        }
        return s
    }

    // MARK: - POSIX 列目录（绕开 FileManager 的预检）

    static func listPOSIX(_ path: String, limit: Int = 10) -> String {
        guard let d = opendir(path) else { return "opendir=\(err(errno))" }
        defer { closedir(d) }

        var total = 0
        var names: [String] = []
        while let ent = readdir(d) {
            var raw = ent.pointee.d_name
            let name = withUnsafePointer(to: &raw) {
                $0.withMemoryRebound(to: CChar.self, capacity: 1024) { String(cString: $0) }
            }
            if name == "." || name == ".." { continue }
            total += 1
            if names.count < limit { names.append(name) }
        }
        return "entries=\(total) [\(names.joined(separator: ","))]"
    }

    // MARK: - Foundation 对照

    static func fmList(_ path: String) -> String {
        do {
            let items = try FileManager.default.contentsOfDirectory(atPath: path)
            return "count=\(items.count) sample=[\(items.prefix(6).joined(separator: ","))]"
        } catch {
            let ns = error as NSError
            return "error=\(ns.code) <\(ns.localizedDescription)>"
        }
    }

    // MARK: - sandbox_check：直接问策略，不真做操作

    private typealias SandboxCheckFn =
        @convention(c) (Int32, UnsafePointer<CChar>?, Int32, UnsafePointer<CChar>?) -> Int32

    /// `int sandbox_check(pid_t, const char *op, enum sandbox_filter_type, ...)`
    /// SANDBOX_FILTER_PATH == 1。返回 0=允许 / 1=拒绝 / -1=出错。
    private static let sandboxCheck: SandboxCheckFn? = {
        // 不 dlclose：这是主镜像的句柄，关掉会把符号一起带走
        guard let h = dlopen(nil, RTLD_NOW) else { return nil }
        guard let sym = dlsym(h, "sandbox_check") else { return nil }
        return unsafeBitCast(sym, to: SandboxCheckFn.self)
    }()

    static func sandboxVerdict(_ op: String, _ path: String) -> String {
        guard let fn = sandboxCheck else { return "unavailable" }
        let r: Int32 = op.withCString { o in
            path.withCString { p in fn(getpid(), o, 1, p) }
        }
        switch r {
        case 0:  return "allow"
        case 1:  return "DENY"
        default: return "err(\(r))"
        }
    }

    // MARK: - 读写

    static func readHead(_ path: String, max: Int = 64) -> String {
        let fd = open(path, O_RDONLY)
        if fd < 0 { return "open=\(err(errno))" }
        var buf = [UInt8](repeating: 0, count: max)
        let n = read(fd, &buf, max)
        let e = errno
        close(fd)
        if n < 0 { return "read=\(err(e))" }

        let slice = Array(buf.prefix(n))
        let hex = slice.map { String(format: "%02x", $0) }.joined()
        let txt = String(bytes: slice.map { ($0 >= 32 && $0 < 127) ? $0 : 46 }, encoding: .utf8) ?? ""
        return "n=\(n) hex=\(hex) txt=<\(txt)>"
    }

    /// 在指定目录里建一个临时文件写点东西再删掉。返回 ok 说明对该目录有写权限。
    static func writeProbe(in dir: String, content: String = "probe") -> String {
        guard !dir.isEmpty else { return "write=skip(empty dir)" }
        let p = (dir as NSString).appendingPathComponent("probe-write-test.txt")
        let data = Data(content.utf8)

        let fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0o644)
        if fd < 0 { return "write=\(err(errno))" }

        let n = data.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
        let e = errno
        close(fd)
        unlink(p)
        return n == data.count ? "write=ok" : "write=\(err(e))"
    }

    // MARK: - 链接

    /// 关键验证点：**创建指向某个路径的软链接，不需要对该路径有任何权限**。
    /// 所以即使 write 全红，这一项也可能是绿的 —— 绿了就说明能提前埋雷。
    static func symlinkProbe(target: String, at path: String) -> String {
        unlink(path)
        if symlink(target, path) != 0 { return "symlink=\(err(errno))" }

        var buf = [CChar](repeating: 0, count: 1024)
        let n = readlink(path, &buf, buf.count - 1)
        var s = "symlink=ok"
        if n > 0 { s += " readlink=<\(String(cString: buf))>" }

        // 跟随：通过链接能不能真的读到目标
        let fd = open(path, O_RDONLY)
        if fd >= 0 {
            var b = [UInt8](repeating: 0, count: 16)
            let got = read(fd, &b, 16)
            close(fd)
            s += " follow=ok(\(got)B)"
        } else {
            s += " follow=\(err(errno))"
        }
        unlink(path)
        return s
    }

    static func hardlinkProbe(target: String, at path: String) -> String {
        unlink(path)
        if link(target, path) != 0 { return "link=\(err(errno))" }
        var st = stat()
        let r = stat(path, &st)
        unlink(path)
        return r == 0 ? "link=ok nlink=\(st.st_nlink)" : "link=ok(stat failed)"
    }

    // MARK: - 容器信息

    static func containerInfo() -> [String] {
        var out: [String] = []
        out.append("home=\(NSHomeDirectory())")
        out.append("tmp=\(NSTemporaryDirectory())")
        for (name, dir) in [
            ("Documents", FileManager.SearchPathDirectory.documentDirectory),
            ("Library",   FileManager.SearchPathDirectory.libraryDirectory),
            ("Caches",    FileManager.SearchPathDirectory.cachesDirectory),
        ] {
            if let u = FileManager.default.urls(for: dir, in: .userDomainMask).first {
                out.append("\(name)=\(u.path)")
            }
        }
        out.append("bundle=\(Bundle.main.bundlePath)")
        out.append("exec=\(Bundle.main.executablePath ?? "-")")

        // 共享容器要 entitlement 才拿得到；拿到 nil 本身就是结论
        for g in ["group.com.probe.intentprobe", "group.com.apple.shortcuts"] {
            let u = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: g)
            out.append("appgroup[\(g)]=\(u?.path ?? "nil")")
        }
        return out
    }

    // MARK: - 一次问全

    static func report(_ path: String) -> String {
        guard !path.isEmpty else { return "(empty path)" }

        let st = statLine(path)
        var parts: [String] = [st]
        parts.append("sbx_read=\(sandboxVerdict("file-read-data", path))")
        parts.append("sbx_write=\(sandboxVerdict("file-write-data", path))")

        if st.contains("type=dir") {
            parts.append("posix[\(listPOSIX(path))]")
            parts.append("fm[\(fmList(path))]")
        } else if st.contains("type=reg") {
            parts.append("head[\(readHead(path))]")
        } else if st.contains("type=lnk") {
            // 链接：既要看它指向哪，也要看能不能跟过去
            parts.append("follow[\(readHead(path, max: 32))]")
        }
        return parts.joined(separator: " ")
    }

    // MARK: - 预置探测路径

    /// 挑的都是"理论上不该让我碰"的位置。全红是正常的，出现一个绿的就有意义。
    static let interesting: [String] = [
        "/",
        "/System",
        "/System/Library",
        "/System/Library/Frameworks",
        "/System/Library/PrivateFrameworks",
        "/usr/lib",
        "/usr/lib/libSystem.B.dylib",
        "/bin/sh",
        "/etc/passwd",
        "/private/etc/passwd",
        "/private/var",
        "/private/var/mobile",
        "/private/var/mobile/Library",
        "/private/var/mobile/Library/SMS",
        "/private/var/mobile/Containers",
        "/private/var/mobile/Containers/Data/Application",
        "/private/var/mobile/Containers/Shared/AppGroup",
        "/private/var/containers/Bundle/Application",
        "/private/preboot",
        "/dev/null",
        "/dev/disk0",
        "/Library",
        "/Applications",
    ]
}
