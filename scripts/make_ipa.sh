#!/bin/bash
# 把 xcodebuild 产物打成可分发的 IPA / zip
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DIST="$ROOT/dist"
rm -rf "$DIST"
mkdir -p "$DIST"

info() { printf '\033[1;34m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }

# ------------------------------------------------------------------ iOS
APP=$(find build/Build/Products -maxdepth 3 -name "IntentProbe.app" -type d 2>/dev/null | head -1 || true)

if [ -n "${APP:-}" ]; then
  info "iOS app: $APP"

  # 检查关键产物是否真的被编译进去了
  if [ -d "$APP/Metadata.appintents" ]; then
    info "Metadata.appintents 已生成"
    find "$APP/Metadata.appintents" -type f -exec ls -la {} \;
  else
    warn "Metadata.appintents 缺失！App Intents 不会被系统索引，所有实验都做不了"
  fi

  if [ -f "$APP/IntentProbe" ] || [ -f "$APP/IntentProbe.debug.dylib" ]; then
    info "主二进制存在"
  fi

  # IPA 结构：Payload/App.app
  mkdir -p "$DIST/Payload"
  cp -R "$APP" "$DIST/Payload/"
  # -y 保留符号链接（框架里的版本链接靠它）
  ( cd "$DIST" && zip -qry IntentProbe-unsigned.ipa Payload )
  rm -rf "$DIST/Payload"
  info "生成 $DIST/IntentProbe-unsigned.ipa ($(du -h "$DIST/IntentProbe-unsigned.ipa" | cut -f1))"

  # 顺便留一份裸 .app，方便直接看结构
  cp -R "$APP" "$DIST/IntentProbe.app"
else
  warn "没找到 iOS .app，跳过 IPA 打包"
fi

# ------------------------------------------------------------------ macOS
MACAPP=$(find build-mac/Build/Products -maxdepth 3 -name "IntentProbeMac.app" -type d 2>/dev/null | head -1 || true)

if [ -n "${MACAPP:-}" ]; then
  info "macOS app: $MACAPP"
  ( cd "$(dirname "$MACAPP")" && zip -qry "$DIST/IntentProbeMac-macos.zip" "IntentProbeMac.app" )
  info "生成 $DIST/IntentProbeMac-macos.zip"
else
  warn "没找到 macOS .app，跳过"
fi

# ------------------------------------------------------------------ 汇总
echo
info "产物清单："
ls -lh "$DIST" 2>/dev/null || true

if [ -z "${APP:-}" ] && [ -z "${MACAPP:-}" ]; then
  echo
  warn "两个平台都没产物，请检查编译日志"
  exit 1
fi
