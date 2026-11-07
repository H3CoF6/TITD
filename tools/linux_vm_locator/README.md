# linux_vm_locator

定位 Linux QQ `wrapper.node` 里的 sign core 与 VM 适配器，并验证签名长度。

**不使用任何字节特征码**：全部靠 ELF 元数据（`.eh_frame_hdr` 的函数边界、重定位
表、PLT 符号表）与指令语义。

## 构建

```sh
make
```

`-rdynamic` 是必须的：工具导出一个空的 `qq_magic_napi_register` 桩，`wrapper.node`
在动态链接时需要解析这个名字。

## 用法

```sh
./linux_vm_locator <wrapper.node> [--arch x86_64|aarch64] [--repeat N] \
                   [--target vm|sign|both] [--no-call]
```

- `--arch`：默认本机架构。异架构只做静态定位，不 dlopen。
- `--repeat`：每个目标连续调用次数（每次 fork 一个子进程，崩溃不影响后续）。
- `--no-call`：只做静态定位。

## 输出

```
== /opt/QQ/resources/app/wrapper.node ==
size      : 152017008
machine   : x86_64
fde count : 321764
relocs    : 350309
typeinfo  : 0x8e1c838
vtable    : 0x8e1c810
callback  : 0x34ee370
sign core : 0x67f28d4  (RVA)
vm adapter: 0x6ded71c  (RVA)
load base : 0x7f18eda00000

=== 验证目标: sign ===
call 1/1 ... ok  1BBF0BD6...（48 字节）
结果[sign]: 成功 1 / 崩溃 0 / 错误 0（共 1 次）

=== 验证目标: vm ===
call 1/1 ... ok  FF82D97F...（48 字节）
结果[vm]: 成功 1 / 崩溃 0 / 错误 0（共 1 次）
```

## 定位原理

### sign core —— RTTI 链

```
RTTI 名字 "N2nt8internal23MSFSecuritySignCallbackE"
  -> typeinfo   （存 &名字 的重定位点位于 typeinfo + 8）
  -> vtable     （存 &typeinfo 的重定位点位于 vtable - 8）
  -> 虚函数      （vtable 槽位里的 RELATIVE 重定位指向 .text）
  -> sign core  （虚函数的直接调用里，那个写满 +0xFF/+0x1FF/+0x2FF 的函数）
```

每一步都是 C++ 对象模型的不变量，跨版本稳定；只有类型名本身是字符串。

「写满三个偏移」是按**指令语义**判定的：解码函数体，找目的操作数为内存的写指令，
其位移恰好是 `0xFF` / `0x1FF` / `0x2FF`。x86-64 用一个最小的长度解码器（不是完整
反汇编器），aarch64 只认 `STRB imm12`。

### VM 适配器

从 sign core 出发，按直接 `call` / `bl` 展开三层调用闭包，挑出同时满足：

1. 函数长度 ≤ 8 KB（VM 内核是几 MB 的解释器，自然被排除）；
2. 函数里有「把 `0x1e` 写进某个结构 `+4`」的指令 —— 适配器 malloc 一个
   `{ u32 len; u16 tag; u16 pad; void *data }` 描述符并写 tag；
3. 函数直接调用过 `malloc`（用 `.rela.plt` + `.dynsym` 确认，不猜 plt 地址）。

### 函数边界

`.eh_frame_hdr` 的 FDE 表是链接器产物，每个函数一项，相邻两项之差就是精确长度。

但 QQ 的 O3 混淆器把大片 `.text` 折成了单个巨大 FDE（实测 x86-64 上有一个
`0x6ad010` 的洞）。那些区域没有精确边界，只能从函数入口线性解码到第一个
`ret`——注意不能一见 `ret` 就停：混淆器会在函数中间插入对齐用的 `ret`。

## 动态验证

`dlopen` 的 `wrapper.node` 依赖 Node 的 N-API 符号，所以用 `RTLD_LAZY` 加载：
sign core 与 VM 都不碰这些符号，只在真正调用时才解析。

`wrapper.node` 的间接依赖 `libbugly.so` 需要 gnutls 的符号，所以要先把
`libgnutls.so.30` 以 `RTLD_GLOBAL` 预载进来。

调用时 fork 子进程，崩溃只影响那一次，父进程通过管道收结果。

### 两个目标的 ABI

| 目标 | 签名 |
|---|---|
| sign core | `int f(const char *cmd, const u8 *src, size_t len, int seq, u8 *out)`，`out[0x200]` 起是 sign，长度在 `out[0x2FF]` |
| VM 适配器 | `VmBlob *f(std::string *cmd, const void *b1, size_t n1, const void *b2, size_t n2)`，`std::string` 是 libstdc++ 布局，返回 `{ u32 len; u16 tag; u16 pad; void *data }` |

两者在 Linux 上产出的 sign 都是 48 字节。

## 从安装包提取 wrapper.node

`extract_wrapper.sh` 只用 `ar` + `tar` 解包，**不需要 root/sudo**，也不安装任何东西：

```sh
WRAPPER="$(./extract_wrapper.sh linuxqq_3.2.34-53644_amd64.deb /tmp/wrapper.node)"
./linux_vm_locator "$WRAPPER"
```

## 验证过的结果

在 GitHub Actions 上真机跑过（`ubuntu-latest` / `ubuntu-24.04-arm`），
sign core 与 VM 两条路径都成功：

| 版本 | 架构 | sign core | VM 适配器 | sign |
|---|---|---|---|---|
| 3.2.34 | x86_64 | `0x67f28d4` | `0x6ded71c` | 48 字节 |
| 3.2.34 | aarch64 | `0x43d07dc` | `0x449e500` | 48 字节 |
| 3.2.33 | x86_64 | `0x677ad71` | `0x6d6eea7` | 32 字节 |
| 3.2.33 | aarch64 | `0x438035c` | `0x444e338` | 32 字节 |

两点结论：

* **sign 长度随版本变化**（3.2.34 是 48，3.2.33 是 32），任何消费者都不能
  硬编码长度。
* 同一版本两个架构的 RVA 完全不同，但**定位出的结构形状一致**（sign core →
  成员函数 → VM 适配器 → loader → 解释器），说明这套判据是跨架构稳定的。

x86_64 的地址与 nt_helper 的 `src/sign` 定位结果、以及 IDA 静态分析一致。

## GitHub Actions

`.github/workflows/linux-vm-detect.yml` 每个版本 × 架构一个 job：

- `amd64` 跑在 `ubuntu-latest`（x64）
- `arm64` 跑在 `ubuntu-24.04-arm`（GitHub 免费 arm 跑器，公开仓可用）

触发方式：

- `workflow_dispatch`：手动填版本过滤 / 架构过滤 / 重复次数。
- `push` 到 `weq/linux-vm-detect` 分支：commit message 里可写
  `run-versions: 3.2.34`、`run-repeat: 3`。

runner 是一次性的，安装包解包后立即删除，不会把大文件留在本地或共享目录。
