#!/usr/bin/env bash
# 从 QQ Linux 安装包里取出 wrapper.node **及整个 app 目录**。
#
# 为什么不能只拷 wrapper.node：它是 ELF 共享库，DT_NEEDED 里有 libbugly.so、
# libcrbase.so 等同目录依赖，单独拿出来 dlopen 会失败。
#
# 只解包、不安装，因此**不需要 root/sudo**：
#   * .deb -> ar + tar（dpkg-deb 在部分 CI 镜像里没有）
#   * .AppImage/.rpm 不支持，需要时再补
#
# 用法: extract_wrapper.sh <package> <output-dir>
# 成功时把 `resources/app/` 整个拷到 <output-dir>/app，
# 并打印其中的 wrapper.node 路径。

set -euo pipefail

if [ $# -ne 2 ]; then
  sed -n '2,10p' "$0" >&2
  exit 2
fi

pkg=$1
out=$2
# 下面会 cd 到临时目录，先固化成绝对路径。
pkg=$(realpath "$pkg")
out=$(realpath -m "$out")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

case "$pkg" in
  *.deb)
    mkdir -p "$work/deb"
    ( cd "$work/deb" && ar x "$pkg" )
    shopt -s nullglob
    for archive in "$work"/deb/data.tar.*; do
      case "$archive" in
        *.zst) tar --zstd -xf "$archive" -C "$work" ;;
        *.xz)  tar -Jxf   "$archive" -C "$work" ;;
        *.gz)  tar -zxf   "$archive" -C "$work" ;;
        *)     tar -xf    "$archive" -C "$work" ;;
      esac
    done
    ;;
  *)
    echo "不支持的安装包类型: $pkg" >&2
    exit 3
    ;;
esac

src=$(find "$work" -type f -name wrapper.node -print -quit)
if [ -z "$src" ]; then
  echo "安装包里没有 wrapper.node" >&2
  exit 4
fi

# 整个 app 目录一起拷贝：DT_NEEDED 依赖同目录的 .so。
app_dir=$(dirname "$src")
mkdir -p "$out"
rm -rf "$out/app"
cp -a "$app_dir" "$out/app"
echo "$out/app/wrapper.node"
