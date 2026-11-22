#!/usr/bin/env python3
"""
extract.actionsdata 变异工具

用途：生成畸形的 App Intents 元数据 blob，测试 Shortcuts / shortcutsd 在索引
已安装 App 时的解析器健壮性（README 里的 H3）。

用法：
  # 单次变异，直接覆盖原文件（记得先备份）
  python3 fuzz_metadata.py path/to/extract.actionsdata --mode truncate --at 512

  # 批量生成 200 个变体到目录
  python3 fuzz_metadata.py path/to/extract.actionsdata --batch 200 --out ./variants

  # 指定变异类型
  python3 fuzz_metadata.py path/to/extract.actionsdata --batch 50 --out ./v --modes flip,truncate,huge

注意：只在你自己构建的 App 上跑。变异后的 bundle 必须重签名才能安装。
"""

import argparse
import os
import random
import struct
import sys


def load(path):
    with open(path, "rb") as f:
        return bytearray(f.read())


def m_flip(data, rng):
    """随机翻转 1~8 个 bit。最温和的变异，适合找边界检查缺失。"""
    n = rng.randint(1, 8)
    for _ in range(n):
        i = rng.randrange(len(data))
        data[i] ^= 1 << rng.randrange(8)
    return data, f"flip{n}"


def m_truncate(data, rng):
    """在随机位置截断。最容易触发"读越界"或"长度字段与实际不符"。"""
    at = rng.randrange(1, len(data))
    return data[:at], f"trunc@{at}"


def m_huge(data, rng):
    """
    把某处的 4 字节小整数替换成极大值。
    针对的是"长度字段 / 数量字段 / 偏移字段"这类经典目标。
    优先挑原本就是小整数（< 0x10000）的位置，命中率更高。
    """
    candidates = []
    for i in range(0, len(data) - 4, 4):
        v = struct.unpack_from("<I", data, i)[0]
        if 0 < v < 0x10000:
            candidates.append(i)
    if not candidates:
        return m_flip(data, rng)

    at = rng.choice(candidates)
    big = rng.choice([0xFFFFFFFF, 0x7FFFFFFF, 0x10000000, 0xFFFF, 0x7FFF])
    struct.pack_into("<I", data, at, big)
    return data, f"huge@{at}=0x{big:X}"


def m_insert(data, rng):
    """插入随机字节，打乱后续所有偏移。"""
    at = rng.randrange(len(data))
    n = rng.randint(1, 64)
    junk = bytes(rng.randrange(256) for _ in range(n))
    return data[:at] + bytearray(junk) + data[at:], f"ins{at}+{n}"


def m_splice(data, rng):
    """把一段随机区间复制到另一个位置，制造重复结构（递归/环的温床）。"""
    n = min(len(data) // 8, rng.randint(16, 512))
    src = rng.randrange(0, len(data) - n)
    dst = rng.randrange(0, len(data) - n)
    data[dst:dst + n] = data[src:src + n]
    return data, f"splice{src}->{dst}({n})"


MODES = {
    "flip": m_flip,
    "truncate": m_truncate,
    "huge": m_huge,
    "insert": m_insert,
    "splice": m_splice,
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="extract.actionsdata 路径")
    ap.add_argument("--mode", default="flip", choices=sorted(MODES))
    ap.add_argument("--modes", default="", help="批量模式下用逗号分隔多个变异类型")
    ap.add_argument("--at", type=int, default=-1, help="truncate 模式的截断位置")
    ap.add_argument("--batch", type=int, default=0, help="批量生成 N 个变体")
    ap.add_argument("--out", default="", help="批量输出目录")
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()

    if not os.path.isfile(args.target):
        sys.exit(f"找不到文件: {args.target}")

    original = load(args.target)
    print(f"[+] 原始大小: {len(original)} 字节")

    # ---- 单次模式 ----
    if args.batch == 0:
        rng = random.Random(args.seed)
        data = bytearray(original)
        if args.mode == "truncate" and args.at >= 0:
            data = data[:args.at]
            tag = f"trunc@{args.at}"
        else:
            data, tag = MODES[args.mode](data, rng)

        with open(args.target, "wb") as f:
            f.write(data)
        print(f"[+] 已写入 {args.target}  ({tag})")
        print("[!] 别忘了重签名:  codesign --force --deep -s - <App.app>")
        return

    # ---- 批量模式 ----
    os.makedirs(args.out, exist_ok=True)
    names = [m.strip() for m in args.modes.split(",")] if args.modes else sorted(MODES)
    rng = random.Random(args.seed)

    manifest = []
    for i in range(args.batch):
        name = names[i % len(names)]
        data, tag = MODES[name](bytearray(original), rng)
        fn = f"v{i:04d}_{name}.actionsdata"
        with open(os.path.join(args.out, fn), "wb") as f:
            f.write(data)
        manifest.append(f"{fn}\t{tag}\t{len(data)}")

    with open(os.path.join(args.out, "MANIFEST.tsv"), "w") as f:
        f.write("file\tmutation\tsize\n" + "\n".join(manifest) + "\n")

    print(f"[+] 生成 {args.batch} 个变体 -> {args.out}")
    print(f"[+] 清单: {os.path.join(args.out, 'MANIFEST.tsv')}")
    print("""
[下一步] macOS 上跑变体的最快循环：

  APP=/tmp/IntentProbe.app
  ORIG="$APP/Metadata.appintents/extract.actionsdata"
  cp "$ORIG" /tmp/orig.actionsdata

  for f in variants/*.actionsdata; do
      cp "$f" "$ORIG"
      codesign --force --deep -s - "$APP" 2>/dev/null
      open "$APP"
      sleep 3
      osascript -e 'tell application "IntentProbe" to quit' 2>/dev/null
      # 检查是否产生新的崩溃报告
      ls -t ~/Library/Logs/DiagnosticReports/ | head -1
  done

崩溃报告里如果出现 Shortcuts / shortcutsd / AppIntents，就是 H3 命中。
""")


if __name__ == "__main__":
    main()
