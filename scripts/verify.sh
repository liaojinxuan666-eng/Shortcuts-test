#!/bin/bash
# 推送前自检 —— 在仓库根目录运行，10 秒内告诉你有没有漏文件
set -uo pipefail

RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; DIM=$'\033[2m'; RST=$'\033[0m'
fail=0

# 源文件总数。改这里一处，下面三处检查跟着变——之前三处各写一个 10，
# 加文件时漏改一个就会在 CI 里报"MISS 源文件不全"，排查半天。
N=11

ok()   { printf '  %sOK%s    %-34s %s\n' "$GRN" "$RST" "$1" "${2:-}"; }
miss() { printf '  %sMISS%s  %-34s %s\n' "$RED" "$RST" "$1" "${2:-}"; fail=1; }
warn() { printf '  %sWARN%s  %-34s %s\n' "$YEL" "$RST" "$1" "${2:-}"; }

echo "=== 仓库根目录 ==="
pwd
echo

# ------------------------------------------------------------------ 必需文件
echo "=== 必需文件 ==="
for f in project.yml README.md .gitignore \
         .github/workflows/build.yml \
         scripts/make_ipa.sh \
         tools/fuzz_metadata.py; do
  if [ -e "$f" ]; then ok "$f"; else miss "$f"; fi
done
echo

# ------------------------------------------------------------------ 源文件
echo "=== 源文件（$N 个，一个都不能少） ==="
EXPECTED="IntentProbeApp.swift ProbeLog.swift ProbeIntents.swift ProbeEntity.swift ProbeSnippet.swift ProbeShortcuts.swift ProbeFS.swift ProbeDylib.swift ProbeIntentsFS.swift ProbeCodeExec.swift ProbeFileCreate.swift"
for f in $EXPECTED; do
  if [ -f "IntentProbe/$f" ]; then
    ok "IntentProbe/$f" "$(wc -c < "IntentProbe/$f" | tr -d ' ') bytes"
  else
    miss "IntentProbe/$f"
  fi
done
echo

# ------------------------------------------------------------------ git 是否跟踪
echo "=== git 跟踪状态 ==="
if git rev-parse --git-dir >/dev/null 2>&1; then
  untracked=$(git ls-files --others --exclude-standard)
  if [ -n "$untracked" ]; then
    warn "有未跟踪的文件" "（不会进仓库）"
    echo "$untracked" | sed 's/^/         /'
  else
    ok "没有未跟踪文件"
  fi

  n=$(git ls-files 'IntentProbe/*.swift' | wc -l | tr -d ' ')
  if [ "$n" = "$N" ]; then
    ok "git 已跟踪 $N 个 .swift"
  else
    miss "git 只跟踪了 $n 个 .swift" "应为 $N"
  fi
else
  warn "当前目录不是 git 仓库"
fi
echo

# ------------------------------------------------------------------ 常见陷阱
echo "=== 常见陷阱 ==="
if ls ./*.swift >/dev/null 2>&1; then
  warn "根目录有 .swift 文件" "（多半是上传时平铺了，应移到 IntentProbe/）"
  ls ./*.swift | sed 's/^/         /'
else
  ok "根目录没有游离的 .swift"
fi

if [ -d IntentProbe ]; then
  n=$(ls IntentProbe/*.swift 2>/dev/null | wc -l | tr -d ' ')
  [ "$n" = "$N" ] && ok "IntentProbe/ 下有 $N 个 .swift" || miss "IntentProbe/ 下有 $n 个 .swift" "应为 $N"
fi
echo

# ------------------------------------------------------------------ 可执行位
echo "=== 脚本可执行位 ==="
# 网页上传 / zip 导入会丢失 exec 位，CI 里 ./script 就会 Permission denied
for f in scripts/make_ipa.sh scripts/verify.sh tools/fuzz_metadata.py; do
  [ -e "$f" ] || continue
  if [ -x "$f" ]; then
    ok "$f" "可执行"
  else
    warn "$f" "缺少 +x（CI 用 bash 调用，但建议修）"
  fi
done
if git rev-parse --git-dir >/dev/null 2>&1; then
  for f in scripts/make_ipa.sh scripts/verify.sh tools/fuzz_metadata.py; do
    mode=$(git ls-files -s -- "$f" 2>/dev/null | awk '{print $1}')
    if [ -n "$mode" ] && [ "$mode" != "100755" ]; then
      warn "$f" "git 模式是 $mode，应为 100755"
      echo "        修复：git update-index --chmod=+x $f"
    fi
  done
fi
echo

# ------------------------------------------------------------------ iOS 不导出的符号
# 这一类错误已经烧掉两轮 CI：macOS 的 Swift Darwin overlay 有，iOS 没有。
# 本地看着能编，一上 -sdk iphoneos 就 "cannot find X in scope"。
# 规则：只能出现在 dlsym 的字符串里，不能直接调用。
echo "=== iOS 不导出的符号（必须走 dlsym） ==="
BAD='sys_icache_invalidate|_dyld_[a-z_]+|_sandbox_[a-z_]+|_os_activity_[a-z_]+'
hits=$(grep -rnE "($BAD)[[:space:]]*\(" IntentProbe/*.swift 2>/dev/null | grep -v '"' || true)
if [ -n "$hits" ]; then
  while IFS= read -r l; do
    [ -n "$l" ] && warn "直接调用 iOS 不导出符号" "$l"
  done <<< "$hits"
  echo "        ${DIM}修法：dlsym(dlopen(nil, RTLD_NOW), \"符号名\")，别用 @_silgen_name${RST}"
else
  ok "没有直接调用" "全部在 dlsym 字符串里"
fi
echo

# ------------------------------------------------------------------ AppIntents 依赖
# 和上面那类错误同一性质：只在 -sdk iphoneos 编译时才炸。
# 用了 AppIntent / @Parameter / IntentResult 却没 import AppIntents 的文件，
# 报错是 "cannot find type 'AppIntent' in scope" + "unknown attribute 'Parameter'"，
# 一次能刷出十几条，看着像全盘崩，其实只缺一行 import。
echo "=== AppIntents 依赖（用了就必须 import） ==="
noimp=0
for f in IntentProbe/*.swift; do
  if grep -qE '(:[[:space:]]*AppIntent\b|@Parameter|some IntentResult)' "$f"; then
    if ! grep -qE '^import AppIntents' "$f"; then
      miss "缺 import AppIntents" "$f"
      noimp=1
    fi
  fi
done
[ "$noimp" = "0" ] && ok "全部已 import AppIntents"
echo

# ------------------------------------------------------------------ 结论
if [ "$fail" = "1" ]; then
  echo "${RED}自检未通过${RST}：把上面标记 MISS 的文件补齐再推。"
  echo "${DIM}提示：git ls-files | grep IntentProbe 可以看 git 到底跟踪了哪些。${RST}"
  exit 1
fi

echo "${GRN}自检通过${RST}，可以 push 了。"
