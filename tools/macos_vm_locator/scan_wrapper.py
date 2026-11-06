#!/usr/bin/env python3
"""从 QQ macOS 镜像里按符号特征扫描出 wrapper.node。

腾讯的 dmg 分区表经常损坏，hdiutil 挂不上。但文件数据本身是完整的，
所以这里直接扫 fat Mach-O 头，用 `_libsecO3Sign` 符号确认是 wrapper.node。

用法: scan_wrapper.py <image> <output>
"""

import struct
import sys

FAT_MAGIC = b"\xca\xfe\xba\xbe"
NEEDLE = b"_libsecO3Sign"


def fat_size(mm, off):
    """返回这个 fat 文件的总长度（头部 + 所有切片），越界返回 None。"""
    if off + 8 > len(mm):
        return None
    nfat = struct.unpack(">I", mm[off + 4:off + 8])[0]
    if nfat not in (1, 2, 3, 4):
        return None
    total = 8 + nfat * 20
    for k in range(nfat):
        base = off + 8 + k * 20
        if base + 20 > len(mm):
            return None
        a_off, a_size = struct.unpack(">II", mm[base + 8:base + 16])
        total = max(total, a_off + a_size)
    return total


def main():
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    image, output = sys.argv[1:]

    with open(image, "rb") as f:
        mm = f.read()

    off = 0
    while True:
        i = mm.find(FAT_MAGIC, off)
        if i < 0:
            break
        size = fat_size(mm, i)
        if size and i + size <= len(mm):
            if NEEDLE in mm[i:i + size]:
                print(f"[scan] wrapper.node 在 {i:#x}，{size} 字节", file=sys.stderr)
                with open(output, "wb") as out:
                    out.write(mm[i:i + size])
                print(f"[scan] 写入 {output}", file=sys.stderr)
                return 0
        off = i + 1

    print("没找到含 _libsecO3Sign 的 fat Mach-O", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
