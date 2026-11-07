# macos_vm_locator

定位 macOS QQ `wrapper.node` 里的 sign core 与 VM 分发器，并验证 sign 长度（28 字节）。

只支持 macOS 的 Mach-O（universal 或 thin），需要显式指定 `intel` 或 `arm`。

> 这个目录只放 macOS 的验证工具。以后 Linux / Windows 的同类工具会放在
> `tools/linux_vm_locator`、`tools/windows_vm_locator`。

## 构建

```sh
make
```

## 用法

```sh
./macos_vm_locator /Applications/QQ.app/Contents/Resources/app/wrapper.node intel
./macos_vm_locator /Applications/QQ.app/Contents/Resources/app/wrapper.node arm
```

## 输出

```
sign core RVA  : 0x2f4f60f  (_libsecO3Sign)
VM dispatcher  : 0x2faa9db  (RVA)
dyld slide     : 0x113134000
sign core addr : 0x1161822d7
sign length    : 28 字节
sign           : E87AF49F2D2548A87D5E1048E8B8698F74FB11373D874FF885F994FE
OK: sign 为 28 字节
```

## 定位原理

### sign core

从 Mach-O 符号表直接取 `_libsecO3Sign`。macOS 的 `wrapper.node` 保留了导出符号，
所以不需要 RTTI 链或反汇编。

### VM 分发器

分发器把两个加密指针分别与 `0x23381121` / `0x23381120` 做 XOR，再交给字节码
加载器算出真实 VM 入口。这对魔数是 O3 保护层的一部分，跨版本稳定。

| 架构 | 指令序列 |
|---|---|
| x86_64 | `lea rcx,[rip+d]` + `xor rcx,0x23381121`，随后 `lea r8,[rip+d]` + `xor r8,0x23381120` |
| arm64 | `mov w?,#0x1121` + `movk w?,#0x2338,lsl#16`，随后 `mov w?,#0x1120` + `movk` |

命中后回退到函数入口：

- x86_64：向前找 `push rbp; mov rbp,rsp`（`55 48 89 e5`）。
- arm64：向前找 `sub sp,sp,#imm`（`0xD10003FF` 家族）；若先遇到 `ret`/`b`，
  说明越过了函数边界。

### 动态验证

`dlopen` 的 `wrapper.node` 依赖 Node 的 N-API 符号（`_napi_call_function` 等），
所以用 `RTLD_LAZY` 加载：sign core 不碰这些符号，只有被真正调用时才解析。

`wrapper.node` 还引用宿主提供的 `qq_magic_napi_register`，工具导出同名空桩并把
自身提升为 `RTLD_GLOBAL`。

只能验证与宿主同架构的切片。在 x86_64 机器上选 `arm` 时跳过动态验证，只做静态定位。

## 从 dmg 提取 wrapper.node

`extract_wrapper.sh` 处理腾讯的 dmg：

```sh
WRAPPER="$(./extract_wrapper.sh QQ_v7.0.2.53644.dmg /tmp/wrapper.node)"
./macos_vm_locator "$WRAPPER" intel
```

腾讯的 dmg 外层是 bzip2，解开后是带保护性 MBR 的 UDRW 镜像，分区表经常损坏，
`hdiutil` 不一定挂得上。脚本按顺序尝试：

1. `hdiutil attach`（成功时**原地**返回挂载点里的路径，保留依赖 framework）
2. 解开 bzip2 后再挂载
3. 扫描 fat Mach-O + `_libsecO3Sign` 符号（`scan_wrapper.py`，只拿到单文件）

第 3 步拿到的单文件缺 `ScreenCaptureAgent.framework` 等依赖，动态验证会失败，
但静态定位仍然可用。

## 验证过的结果

| 版本 | 架构 | `_libsecO3Sign` | VM 分发器 | sign |
|---|---|---|---|---|
| 7.0.0.52194 | x86_64 | `0x2f4f60f` | `0x2faa9db` | 28 字节 |
| 7.0.0.52194 | arm64 | `0x2ad1d98` | `0x2b3dbd4` | — |
| 7.0.2.53644 | x86_64 | `0x304e2d7` | `0x3098f89` | 28 字节 |
| 7.0.2.53644 | arm64 | `0x2b30e10` | `0x2b80ce8` | — |
| 7.0.3.54395 | x86_64 | `0x3079237` | `0x30c3ee9` | 28 字节 |
| 7.0.3.54395 | arm64 | `0x2b571f0` | `0x2ba70c8` | — |

x86_64 的地址都与 lldb 断点实测一致。

## GitHub Actions

`.github/workflows/macos-vm-detect.yml` 每个版本 × 架构一个 job：

- `intel` 跑在 `macos-15-intel`（x64 runner）
- `arm` 跑在 `macos-15`（arm64 runner）

（macOS 13/14 的 runner 已退役。）

触发方式：

- `workflow_dispatch`：非默认分支上不会出现在手动触发列表，需在默认分支上才有。
- `push`：推到 `weq/vm-detect` 分支时自动跑。

两个架构都能做动态验证。结果写入 job summary，并上传 artifact。
