#!/bin/bash
# 从 QQ macOS dmg 里取出 wrapper.node。
#
# 腾讯的 dmg 结构特殊：外层是 bzip2，解开后是带保护性 MBR 的 UDRW 镜像，
# 而且分区表经常是坏的，hdiutil 不一定能挂载。所以按顺序尝试：
#   1. hdiutil attach（最干净；挂上就能在原位跑，依赖 framework 也能找到）
#   2. 解开 bzip2 后再 hdiutil attach
#   3. 直接扫描 fat Mach-O + `_libsecO3Sign` 符号（只拿到单文件）
#
# 用法：extract_wrapper.sh <qq.dmg> <输出路径>
#
# 输出：stdout 打印最终的 wrapper.node 路径；挂载点保留到脚本退出后
# （由调用方负责 detach，或整个 runner 销毁）。为了能原地 dlopen，
# 挂载成功时**不复制**，直接返回挂载点里的路径。

set -euo pipefail

DMG="$1"
OUT="$2"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
MOUNT="$WORK/mnt"

log() { echo "[extract] $*" >&2; }

find_in_dir() {
  find "$1" -name wrapper.node -type f 2>/dev/null | head -1
}

try_mount() {
  local image="$1"
  # host 上的 hdiutil 偶尔会卡在 compressed image / 坏分区表上；给它一个硬超时。
  if perl -e 'alarm shift; exec @ARGV' 120 \
      hdiutil attach -nobrowse -readonly -mountpoint "$MOUNT" "$image" >/dev/null 2>&1; then
    local found
    found="$(find_in_dir "$MOUNT")"
    if [ -n "$found" ]; then
      log "挂载成功，wrapper.node: $found"
      # 原地返回，保留依赖 framework；不复制。
      echo "$found"
      exit 0
    fi
    hdiutil detach "$MOUNT" >/dev/null 2>&1 || true
  fi
  return 1
}

# 先按原样挂载：腾讯的 .dmg 虽是 bzip2 外层，但 macOS 的 hdiutil 能直接处理，
# 且只有挂载路径才能保留 ScreenCaptureAgent.framework 等 @loader_path 依赖。
# 挂载本身有 120 秒超时，失败后再解压/扫描。
log "尝试直接 hdiutil attach"
try_mount "$DMG" && exit 0

RAW="$DMG"
if head -c 3 "$DMG" | grep -q 'BZh'; then
  log "直接挂载失败，解压后再试"
  bunzip2 -c "$DMG" > "$WORK/raw.dmg" 2>/dev/null || cp "$DMG" "$WORK/raw.dmg"
  RAW="$WORK/raw.dmg"
  log "尝试挂载解压后的镜像"
  try_mount "$RAW" && exit 0
fi

# 兜底：扫描 fat Mach-O（只得到单文件，依赖 framework 会缺失）
log "hdiutil 挂载失败，改为扫描镜像"
python3 "$HERE/scan_wrapper.py" "$RAW" "$OUT"
log "提取完成: ${OUT}（仅单文件）"
echo "$OUT"
