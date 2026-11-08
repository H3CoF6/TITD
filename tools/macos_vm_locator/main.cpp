// macOS QQ wrapper.node 的 sign / VM 定位与验证工具。
//
// 只支持 macOS 的 wrapper.node（universal 或 thin 的 Mach-O），可选 x86_64 / arm64。
//
// 它做三件事：
//   1. 静态解析 Mach-O，取 `_libsecO3Sign`（sign core）的 RVA；
//   2. 用 VM 分发器的魔数锚点定位分发器 RVA；
//   3. dlopen wrapper.node，调用 sign core，验证输出 sign 为 28 字节。
//
// 构建：
//   clang++ -std=c++17 -O2 -o macos_vm_locator main.cpp
// 用法：
//   ./macos_vm_locator /Applications/QQ.app/Contents/Resources/app/wrapper.node intel
//   ./macos_vm_locator /Applications/QQ.app/Contents/Resources/app/wrapper.node arm

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <csignal>
#include <dlfcn.h>
#include <unistd.h>

#include <execinfo.h>

#include <sys/wait.h>
#include <mach-o/dyld.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

namespace {

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

constexpr uint32_t kCpuX86_64 = CPU_TYPE_X86_64;
constexpr uint32_t kCpuArm64 = CPU_TYPE_ARM64;

template <typename T>
T read_le(const uint8_t *p) {
  T v;
  std::memcpy(&v, p, sizeof(T));
  return v;
}

uint32_t read_be32(const uint8_t *p) {
  return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) |
         uint32_t(p[3]);
}

struct Range {
  uint64_t vmaddr;
  uint64_t vmsize;
  uint64_t fileoff;
  uint64_t filesize;
};

// 一个架构切片：文件字节 + 段表 + 符号表 + 解析结果。
struct Slice {
  const uint8_t *data = nullptr;
  size_t size = 0;
  uint32_t cputype = 0;
  std::vector<Range> segments;

  // 符号名 -> n_value（虚拟地址）。
  std::vector<std::pair<std::string, uint64_t>> symbols;

  // 文件偏移 -> 虚拟地址（仅 __TEXT 等有 fileoff 的段）。
  bool offset_to_addr(uint64_t off, uint64_t *out) const {
    for (const Range &s : segments) {
      if (off >= s.fileoff && off < s.fileoff + s.filesize) {
        *out = s.vmaddr + (off - s.fileoff);
        return true;
      }
    }
    return false;
  }

  // 虚拟地址 -> 文件偏移。
  bool addr_to_offset(uint64_t addr, uint64_t *out) const {
    for (const Range &s : segments) {
      if (addr >= s.vmaddr && addr < s.vmaddr + s.vmsize) {
        uint64_t delta = addr - s.vmaddr;
        if (delta < s.filesize) {
          *out = s.fileoff + delta;
          return true;
        }
      }
    }
    return false;
  }

  const uint8_t *at(uint64_t addr, size_t len) const {
    uint64_t off = 0;
    if (!addr_to_offset(addr, &off) || off + len > size) return nullptr;
    return data + off;
  }
};

// 解析一个 thin Mach-O 切片的段表与符号表。
bool parse_thin(const uint8_t *data, size_t size, Slice *slice, std::string *err) {
  if (size < sizeof(mach_header_64)) {
    *err = "文件太小，不是 64 位 Mach-O";
    return false;
  }
  const auto *hdr = reinterpret_cast<const mach_header_64 *>(data);
  if (hdr->magic != MH_MAGIC_64) {
    *err = "不是 64 位 little-endian Mach-O";
    return false;
  }
  slice->data = data;
  slice->size = size;
  slice->cputype = hdr->cputype;

  const uint8_t *p = data + sizeof(mach_header_64);
  const uint8_t *end = p + hdr->sizeofcmds;
  if (hdr->sizeofcmds > size - sizeof(mach_header_64)) {
    *err = "load command 表越界";
    return false;
  }

  uint64_t symtab_off = 0, symtab_count = 0, strtab_off = 0, strtab_size = 0;
  bool has_symtab = false;

  for (uint32_t i = 0; i < hdr->ncmds && p + sizeof(load_command) <= end; ++i) {
    const auto *lc = reinterpret_cast<const load_command *>(p);
    if (lc->cmdsize < sizeof(load_command) || p + lc->cmdsize > end) {
      *err = "load command 越界";
      return false;
    }
    if (lc->cmd == LC_SEGMENT_64) {
      const auto *seg = reinterpret_cast<const segment_command_64 *>(lc);
      Range r{seg->vmaddr, seg->vmsize, seg->fileoff, seg->filesize};
      slice->segments.push_back(r);
    } else if (lc->cmd == LC_SYMTAB) {
      const auto *st = reinterpret_cast<const symtab_command *>(lc);
      symtab_off = st->symoff;
      symtab_count = st->nsyms;
      strtab_off = st->stroff;
      strtab_size = st->strsize;
      has_symtab = true;
    }
    p += lc->cmdsize;
  }

  if (!has_symtab || symtab_off + symtab_count * sizeof(nlist_64) > size ||
      strtab_off + strtab_size > size) {
    *err = "没有可用的符号表";
    return false;
  }

  for (uint64_t i = 0; i < symtab_count; ++i) {
    const auto *sym = reinterpret_cast<const nlist_64 *>(data + symtab_off + i * sizeof(nlist_64));
    if (sym->n_un.n_strx == 0 || strtab_off + sym->n_un.n_strx >= size) continue;
    const char *name = reinterpret_cast<const char *>(data + strtab_off + sym->n_un.n_strx);
    size_t max_len = strtab_size - sym->n_un.n_strx;
    size_t len = strnlen(name, max_len);
    if (len == 0 || len == max_len) continue;
    if (!(sym->n_type & N_STAB)) {
      slice->symbols.emplace_back(std::string(name, len), sym->n_value);
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// VM 分发器定位
// ---------------------------------------------------------------------------
//
// 分发器把两个加密指针分别与 0x23381121 / 0x23381120 做 XOR，然后交给
// 字节码加载器算出真实 VM 入口。这两个魔数是保护层设计的一部分，跨版本稳定。
//
//   x86_64: 48 8d 0d <d32>   lea rcx,[rip+d]
//           48 81 f1 21 11 38 23  xor rcx,0x23381121
//           4c 8d 05 <d32>   lea r8,[rip+d]
//           49 81 f0 20 11 38 23  xor r8,0x23381120
//
//   arm64:  52 82 24 0?   mov  w?,#0x1121
//           72 a4 67 0?   movk w?,#0x2338,lsl#16
//           52 82 24 0?   mov  w?,#0x1120
//           72 a4 67 0?   movk w?,#0x2338,lsl#16
//           ca 0? 01 0?   eor  x?,x?,x?

// 在字节流里找 "lea rXX,[rip+disp32]"（48/4c 8d /r，modrm.rm=101）。
bool is_lea_rip(const uint8_t *p, size_t avail, uint32_t *reg_out) {
  if (avail < 7) return false;
  if ((p[0] != 0x48 && p[0] != 0x4c) || p[1] != 0x8d) return false;
  if ((p[2] & 0xc7) != 0x05) return false;
  *reg_out = (p[2] >> 3) & 7;
  return true;
}

// 找 "xor r64, imm32"（48/49 81 /6 id，modrm.reg=110）。
bool is_xor_imm32(const uint8_t *p, size_t avail, uint32_t *reg_out, uint32_t *imm_out) {
  if (avail < 7) return false;
  if ((p[0] != 0x48 && p[0] != 0x49) || p[1] != 0x81) return false;
  if (((p[2] >> 3) & 7) != 6) return false;
  *reg_out = p[2] & 7;
  *imm_out = read_le<uint32_t>(p + 3);
  return true;
}

// x86_64：找 xor rcx,0x23381121 / xor r8,0x23381120 这对指令。
bool find_dispatcher_x86(const Slice &s, uint64_t *rva_out) {
  const uint8_t *d = s.data;
  size_t n = s.size;
  for (size_t i = 0; i + 7 <= n; ++i) {
    uint32_t reg = 0, imm = 0;
    if (!is_xor_imm32(d + i, n - i, &reg, &imm)) continue;
    if (imm != 0x23381121) continue;
    // 往前看是否紧邻一条 lea rcx,[rip+...]（4 字节对齐不强制）。
    bool has_lea = false;
    for (size_t back = 1; back <= 8 && i >= back; ++back) {
      uint32_t lreg = 0;
      if (is_lea_rip(d + i - back, 7, &lreg) && lreg == reg) {
        has_lea = true;
        break;
      }
    }
    if (!has_lea) continue;
    // 往后找 xor r8,0x23381120（同函数内，允许若干指令间隔）。
    for (size_t j = i + 7; j + 7 <= n && j < i + 64; ++j) {
      uint32_t reg2 = 0, imm2 = 0;
      if (is_xor_imm32(d + j, n - j, &reg2, &imm2) && imm2 == 0x23381120) {
        uint64_t addr = 0;
        if (!s.offset_to_addr(i, &addr)) return false;
        // 回退到函数起点：往前找最近的 push rbp; mov rbp,rsp（55 48 89 e5）。
        uint64_t start = addr;
        for (size_t k = i; k > 0 && k + 4 <= n; --k) {
          if (d[k] == 0x55 && d[k + 1] == 0x48 && d[k + 2] == 0x89 && d[k + 3] == 0xe5) {
            uint64_t a = 0;
            if (s.offset_to_addr(k, &a)) start = a;
            break;
          }
        }
        *rva_out = start;
        return true;
      }
    }
  }
  return false;
}

// arm64：找 "mov wX,#0x1121; movk wX,#0x2338,lsl#16"（0x23381121 的构造），
// 再回退到函数起点（sub sp,sp,#N 或 stp x29,x30,...）。
bool find_dispatcher_arm(const Slice &s, uint64_t *rva_out) {
  const uint8_t *d = s.data;
  size_t n = s.size;
  for (size_t i = 0; i + 8 <= n; i += 4) {
    uint32_t w0 = read_le<uint32_t>(d + i);
    uint32_t w1 = read_le<uint32_t>(d + i + 4);
    // mov w?, #0x1121 : 0x52800000 | (imm16<<5) | rd
    if ((w0 & 0xFFE00000) != 0x52800000 || ((w0 >> 5) & 0xFFFF) != 0x1121) continue;
    // movk w?, #0x2338, lsl #16 : 0x72A00000 | (hw<<21) | (imm16<<5) | rd
    if ((w1 & 0xFFE00000) != 0x72A00000 || ((w1 >> 21) & 3) != 1 ||
        ((w1 >> 5) & 0xFFFF) != 0x2338)
      continue;
    uint32_t rd = w0 & 0x1F;
    if ((w1 & 0x1F) != rd) continue;
    // 回退到函数起点：从魔数处往前找第一条 "sub sp,sp,#imm"（0xD10003FF 家族）。
    // 找到它即函数入口；若先遇到 ret/b 则说明已越过边界，退回上一个候选。
    uint64_t start = 0;
    if (!s.offset_to_addr(i, &start)) return false;
    bool found_start = false;
    for (size_t k = i; k >= 4; k -= 4) {
      uint32_t w = read_le<uint32_t>(d + k - 4);
      // sub sp, sp, #imm：0xD10003FF 的 imm12 变体
      if ((w & 0xFFC003FF) == 0xD10003FF) {
        uint64_t a = 0;
        if (s.offset_to_addr(k - 4, &a)) {
          start = a;
          found_start = true;
        }
        break;
      }
      // ret (0xD65F03C0) 或无条件 b（0x14000000 家族）：越过函数边界
      if ((w & 0xFFFFFC1F) == 0xD65F0000 || (w & 0xFC000000) == 0x14000000) break;
      if (k - 4 == 0) break;
    }
    if (!found_start) {
      // 有些叶子函数没有 sub sp；退回到第一条 stp x29,x30 之后对齐的位置。
      for (size_t k = i; k >= 4; k -= 4) {
        uint32_t w = read_le<uint32_t>(d + k - 4);
        if ((w & 0xFFC07FFF) == 0xA9807BFD || (w & 0xFFC07FFF) == 0xA9007BFD) {
          uint64_t a = 0;
          if (s.offset_to_addr(k - 4, &a)) start = a;
          break;
        }
        if ((w & 0xFFFFFC1F) == 0xD65F0000 || (w & 0xFC000000) == 0x14000000) break;
        if (k - 4 == 0) break;
      }
    }
    *rva_out = start;
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// sign core
// ---------------------------------------------------------------------------

// 从符号表里取 _libsecO3Sign 的虚拟地址。
bool find_sign_core(const Slice &s, uint64_t *rva_out) {
  static const char *kNames[] = {"_libsecO3Sign", "libsecO3Sign"};
  for (const auto &[name, value] : s.symbols) {
    for (const char *want : kNames) {
      if (name == want) {
        *rva_out = value;
        return true;
      }
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// 动态验证
// ---------------------------------------------------------------------------

// wrapper.node 引用了宿主提供的 qq_magic_napi_register；本工具导出同名桩并
// 把自己提升为 RTLD_GLOBAL，让 dlopen 的 wrapper.node 能解析它。
extern "C" void qq_magic_napi_register(void *) {}

using SignFn = int (*)(const char *cmd, const uint8_t *src, size_t len, int seq, uint8_t *out);

// macOS 的 libc++ `std::string`（old ABI）在两个架构上布局不同：
//
//   arm64: `{ ptr; size; cap_and_flag }`，最高位是长串标记，低 63 位是容量；
//   x86_64: `{ cap_and_flag; size; ptr }`，最低位是长串标记，`cap = value >> 1`。
//
// 这不是可以统一的结构，必须按目标架构分开，否则 VM 会把容量当指针写回。
struct LcxxStringArm64 {
  char *ptr;
  size_t size;
  size_t cap_and_flag;
};
struct LcxxStringX86 {
  size_t cap_and_flag;
  size_t size;
  char *ptr;
};
static_assert(sizeof(LcxxStringArm64) == 24, "arm64 libc++ string is 24 bytes");
static_assert(sizeof(LcxxStringX86) == 24, "x86_64 libc++ string is 24 bytes");
#if defined(__aarch64__)
using LcxxString = LcxxStringArm64;
#else
using LcxxString = LcxxStringX86;
#endif

// x86_64 VM 分发器的真实签名（lldb 实测，7.0.0）：
//   vm(out, b1, b2, cmd, mode, ctx)
// 五个参数都是 std::string*，`mode` 是 int（实测 3）。
// `out` 由调用方提供并被原地写入；`ctx` 必须是合法 string（可为空），
// 分发器会直接解引用它，传 NULL 会 SIGSEGV。
//
// arm64 的显式参数少一个：`out` 走 AAPCS64 的隐藏 sret 寄存器 x8，
// 所以真实调用约定是 `vm(b1, b2, cmd, mode, ctx)`，返回值写入 x8。
using VmFn = void (*)(LcxxString *, const LcxxString *, const LcxxString *, const LcxxString *,
                      int, const LcxxString *);

constexpr int kMacVmMode = 3;

#if defined(__aarch64__)
// AAPCS64 passes a >16-byte return value through the indirect-result register
// x8. The dispatcher saves x0..x4 and x8 before decrypting, restores them, and
// branches to the real VM. The explicit arguments are therefore b1, b2, cmd,
// mode, ctx (five, not six); `out` must be supplied in x8. Because the
// dispatcher tail-branches, `blr` must save the caller's x30 on the stack or
// the final `ret` returns to itself.
__attribute__((naked)) void call_vm_arm64(void *fn, const LcxxString *b1,
                                          const LcxxString *b2, const LcxxString *cmd, int mode,
                                          const LcxxString *ctx, LcxxString *out) {
  __asm__ volatile(
      "sub sp, sp, #16\n"
      "str x30, [sp, #8]\n"  // caller LR: blr below overwrites x30
      "mov x9, x0\n"         // fn
      "mov x0, x1\n"         // b1
      "mov x1, x2\n"         // b2
      "mov x2, x3\n"         // cmd
      "mov w3, w4\n"         // mode
      "mov x4, x5\n"         // ctx
      "mov x8, x6\n"         // hidden sret: out
      "blr x9\n"
      "ldr x30, [sp, #8]\n"
      "add sp, sp, #16\n"
      "ret\n");
}
#endif

// 运行时 slide：wrapper.node 在 dyld 里的加载基址。
uint64_t module_slide(const char *path);

// 宿主进程的 CPU 类型（决定哪个切片能被 dlopen 执行）。
uint32_t host_cpu_type();

constexpr size_t kOutBuf = 0x400;
constexpr size_t kSignLenOff = 0x2FF;
constexpr size_t kSignDataOff = 0x200;

// 调用 sign core 时若崩溃（arm64 上可能因为缺少初始化或依赖），
// 捕获信号后打印诊断并退出，避免日志里只剩一个“段错误”。
volatile sig_atomic_t g_in_sign_call = 0;

// 本次运行验证的是 VM 还是 sign core（决定子进程调哪个）。
bool g_use_vm = false;

const char *signal_name(int sig) {
  switch (sig) {
    case SIGSEGV: return "SIGSEGV";
    case SIGBUS: return "SIGBUS";
    case SIGILL: return "SIGILL";
    case SIGABRT: return "SIGABRT";
    case SIGALRM: return "SIGALRM(timeout)";
    default: return "signal";
  }
}

// async-signal-safe 的十六进制输出。
void write_hex(uintptr_t v) {
  char buf[2 + sizeof(uintptr_t) * 2];
  buf[0] = '0';
  buf[1] = 'x';
  int n = 2;
  for (int shift = (int)(sizeof(uintptr_t) * 8) - 4; shift >= 0; shift -= 4) {
    int d = (int)((v >> shift) & 0xf);
    buf[n++] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
  }
  (void)!write(STDERR_FILENO, buf, (size_t)n);
}

void write_str(const char *s) {
  size_t n = 0;
  while (s[n]) ++n;
  (void)!write(STDERR_FILENO, s, n);
}

void crash_handler(int sig) {
  const char *name = signal_name(sig);
  if (g_in_sign_call) {
    write_str("[crash] sign core 调用期间崩溃: ");
    write_str(name);
    write_str("\n[crash] 调用栈:\n");

    // backtrace()/backtrace_symbols_fd() 在信号处理器里可用，
    // 但为了拿到模块 + 偏移（比符号名更有用），这里逐个 dladdr。
    void *frames[64];
    int n = backtrace(frames, 64);
    for (int i = 0; i < n; ++i) {
      Dl_info info{};
      uintptr_t pc = (uintptr_t)frames[i];
      write_str("  #");
      char idx[8];
      int m = 0;
      if (i == 0) {
        idx[m++] = '0';
      } else {
        int v = i, t[8], k = 0;
        while (v) { t[k++] = v % 10; v /= 10; }
        while (k) idx[m++] = (char)('0' + t[--k]);
      }
      (void)!write(STDERR_FILENO, idx, (size_t)m);
      write_str("  ");
      write_hex(pc);
      if (dladdr(frames[i], &info) && info.dli_fname) {
        // 只输出文件名，避免路径太长。
        const char *base = info.dli_fname;
        for (const char *q = info.dli_fname; *q; ++q) {
          if (*q == '/') base = q + 1;
        }
        write_str("  ");
        write_str(base);
        if (info.dli_fbase) {
          write_str("+");
          write_hex(pc - (uintptr_t)info.dli_fbase);
        }
        if (info.dli_sname) {
          write_str("  ");
          write_str(info.dli_sname);
        }
      }
      write_str("\n");
    }
  }
  _exit(128 + sig);
}

// dlopen wrapper.node 并返回 sign core 的地址；失败时 err 里带原因。
bool open_library(const char *path, uint64_t sign_rva, void **fn_out, uint64_t *slide_out,
                  std::string *err) {
  // 提升自身为 RTLD_GLOBAL。
  Dl_info info{};
  if (dladdr(reinterpret_cast<void *>(&qq_magic_napi_register), &info) == 0 || !info.dli_fname) {
    *err = "dladdr 失败，无法提升 RTLD_GLOBAL";
    return false;
  }
  void *self = dlopen(info.dli_fname, RTLD_NOW | RTLD_GLOBAL | RTLD_NOLOAD);
  if (!self) {
    *err = std::string("提升 RTLD_GLOBAL 失败: ") + dlerror();
    return false;
  }

  // 先用 RTLD_LAZY：wrapper.node 依赖 Node 的 N-API 等宿主符号，
  // RTLD_NOW 会立刻失败。sign core 本身不碰这些符号，所以懒绑定可行。
  void *lib = dlopen(path, RTLD_LAZY | RTLD_LOCAL);
  if (!lib) {
    *err = std::string("dlopen wrapper.node 失败: ") + dlerror();
    return false;
  }

  // 顺带探一下 RTLD_NOW 缺什么符号，只用于诊断（不参与实际调用）。
  dlerror();
  void *probe = dlopen(path, RTLD_NOW | RTLD_LOCAL);
  if (!probe) {
    const char *e = dlerror();
    std::printf("RTLD_NOW 未解析的符号 : %s\n", e ? e : "(未知)");
  } else {
    dlclose(probe);
  }

  uint64_t slide = module_slide(path);
  if (slide == 0) {
    *err = "dlopen 之后仍找不到 wrapper.node 的 dyld slide";
    return false;
  }

  *slide_out = slide;
  *fn_out = reinterpret_cast<void *>(slide + sign_rva);
  return true;
}

// 调一次 sign core。返回 0 表示成功，否则是 errno 风格的错误码。
// 崩溃时由 crash_handler 打印栈并 _exit，不会返回。
int call_sign(void *fn_ptr, int seq, std::vector<uint8_t> *sign_out) {
  auto *fn = reinterpret_cast<SignFn>(fn_ptr);
  std::vector<uint8_t> out(kOutBuf, 0);
  const uint8_t payload[] = {0x08, 0x01};
  const char *cmd = "trpc.qq_new_tech.status_svc.StatusService.SsoHeartBeat";

  std::signal(SIGSEGV, crash_handler);
  std::signal(SIGBUS, crash_handler);
  std::signal(SIGILL, crash_handler);
  std::signal(SIGABRT, crash_handler);
  g_in_sign_call = 1;
  int ret = fn(cmd, payload, sizeof(payload), seq, out.data());
  g_in_sign_call = 0;

  size_t sign_len = out[kSignLenOff];
  if (sign_len == 0 || sign_len > 0x100) {
    return (ret != 0) ? ret : -1;
  }
  sign_out->assign(out.begin() + kSignDataOff, out.begin() + kSignDataOff + sign_len);
  return 0;
}

// 构造 libc++ 长串：内容拷进 `storage`，返回指向它的描述符。
// 一律用长串，避免 SSO 的自引用结构——VM 只读 size/ptr。
LcxxString make_lcxx(std::vector<char> *storage, const void *data, size_t len) {
  storage->assign(static_cast<const char *>(data), static_cast<const char *>(data) + len);
  storage->push_back('\0');
  LcxxString s{};
#if defined(__aarch64__)
  s.ptr = storage->data();
  s.size = len;
  s.cap_and_flag = (size_t{1} << 63) | static_cast<size_t>(len);
#else
  s.cap_and_flag = (static_cast<size_t>(len) << 1) | 1;
  s.size = len;
  s.ptr = storage->data();
#endif
  return s;
}

// 调一次 VM 分发器。与 `call_sign` 的区别：不经过 sign core，自己算 md5
// 后直接喂给 VM，因此不依赖 wrapper 内的会话单例。
// 崩溃时由 crash_handler 打印栈并 _exit，不会返回。
int call_vm(void *fn_ptr, int seq, std::vector<uint8_t> *sign_out) {
  auto *fn = reinterpret_cast<VmFn>(fn_ptr);
  const char *cmd = "trpc.qq_new_tech.status_svc.StatusService.SsoHeartBeat";

  // 与 sign core 路径相同的输入：空 token/extra → payload `\x08\x01` 的 MD5。
  // 这里直接喂那个实测常量，也可以用 md5 库；seq 只影响 sign core 的分支，
  // VM 只看 md5。
  (void)seq;
  static const uint8_t kMd5[16] = {0xF7, 0xC5, 0x7F, 0x06, 0xA1, 0xD3, 0xCE, 0x11,
                                   0x77, 0x49, 0xFC, 0x98, 0xE2, 0x11, 0x16, 0x68};

  std::vector<char> cmd_buf, md5_buf, empty_buf, ctx_buf;
  LcxxString s_cmd = make_lcxx(&cmd_buf, cmd, std::strlen(cmd));
  LcxxString s_md5 = make_lcxx(&md5_buf, kMd5, sizeof(kMd5));
  LcxxString s_empty = make_lcxx(&empty_buf, "", 0);
  LcxxString s_ctx = make_lcxx(&ctx_buf, "", 0);  // 不能是 NULL
  LcxxString out{};

  std::signal(SIGSEGV, crash_handler);
  std::signal(SIGBUS, crash_handler);
  std::signal(SIGILL, crash_handler);
  std::signal(SIGABRT, crash_handler);
  std::signal(SIGALRM, crash_handler);
  g_in_sign_call = 1;
  std::fprintf(stderr, "[vm] calling dispatcher fn=%p b1=%p b2=%p cmd=%p mode=%d ctx=%p out=%p\n",
               fn_ptr, static_cast<const void *>(&s_md5), static_cast<const void *>(&s_empty),
               static_cast<const void *>(&s_cmd), kMacVmMode, static_cast<const void *>(&s_ctx),
               static_cast<void *>(&out));
  std::fflush(stderr);
  alarm(30);
#if defined(__aarch64__)
  call_vm_arm64(reinterpret_cast<void *>(fn), &s_md5, &s_empty, &s_cmd, kMacVmMode, &s_ctx,
                &out);
  std::fprintf(stderr, "[vm] out=%p/%zu\n", static_cast<void *>(out.ptr), out.size);
  const LcxxString &result = out;
#else
  fn(&out, &s_md5, &s_empty, &s_cmd, kMacVmMode, &s_ctx);
  const LcxxString &result = out;
#endif
  alarm(0);
  std::fprintf(stderr, "[vm] returned out=%p/%zu\n", static_cast<void *>(out.ptr), out.size);
  std::fflush(stderr);
  g_in_sign_call = 0;

  if (result.size == 0 || result.size > 0x100 || !result.ptr) {
    return -1;
  }
  sign_out->assign(reinterpret_cast<uint8_t *>(result.ptr),
                   reinterpret_cast<uint8_t *>(result.ptr) + result.size);
  return 0;
}

// 在子进程里调一次，父进程通过退出码/管道收集结果。
// 返回：0=成功；>0=sign core 返回的错误；128+sig=信号崩溃；-1=子进程异常。
int call_in_child(void *fn_ptr, int seq, std::vector<uint8_t> *sign_out) {
  int fds[2];
  if (pipe(fds) != 0) return -1;

  pid_t pid = fork();
  if (pid < 0) {
    close(fds[0]);
    close(fds[1]);
    return -1;
  }

  if (pid == 0) {
    // 子进程：关闭读端，结果打包成 [len][bytes] 写回。
    close(fds[0]);
    std::vector<uint8_t> sign;
    int rc = g_use_vm ? call_vm(fn_ptr, seq, &sign) : call_sign(fn_ptr, seq, &sign);
    if (rc == 0) {
      uint8_t len = (uint8_t)sign.size();
      (void)!write(fds[1], &len, 1);
      (void)!write(fds[1], sign.data(), sign.size());
      _exit(0);
    }
    _exit(rc > 0 ? (rc & 0x7f) : 0);  // 退出码只有低 8 位
  }

  close(fds[1]);
  uint8_t len = 0;
  ssize_t got = read(fds[0], &len, 1);
  (void)got;
  if (got == 1 && len > 0 && len <= 64) {
    sign_out->resize(len);
    size_t off = 0;
    while (off < len) {
      ssize_t n = read(fds[0], sign_out->data() + off, len - off);
      if (n <= 0) break;
      off += (size_t)n;
    }
    if (off != len) sign_out->clear();
  }
  close(fds[0]);

  int status = 0;
  waitpid(pid, &status, 0);
  if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
  if (WIFEXITED(status)) return WEXITSTATUS(status);
  return -1;
}

uint32_t host_cpu_type() {
#if defined(__aarch64__)
  return static_cast<uint32_t>(CPU_TYPE_ARM64);
#elif defined(__x86_64__)
  return static_cast<uint32_t>(CPU_TYPE_X86_64);
#else
  return 0;
#endif
}

// 运行时 slide：wrapper.node 在 dyld 里的加载基址。
//
// dlopen 之后 dyld 记录的路径可能被规范化（解析符号链接、去掉 ./ 等），
// 所以先按完整路径匹配，再退回到按文件名匹配。
uint64_t module_slide(const char *path) {
  uint32_t count = _dyld_image_count();
  for (uint32_t i = 0; i < count; ++i) {
    const char *name = _dyld_get_image_name(i);
    if (name && std::strcmp(name, path) == 0) {
      return static_cast<uint64_t>(_dyld_get_image_vmaddr_slide(i));
    }
  }
  const char *base = std::strrchr(path, '/');
  base = base ? base + 1 : path;
  for (uint32_t i = 0; i < count; ++i) {
    const char *name = _dyld_get_image_name(i);
    if (!name) continue;
    const char *nbase = std::strrchr(name, '/');
    nbase = nbase ? nbase + 1 : name;
    if (std::strcmp(nbase, base) == 0) {
      return static_cast<uint64_t>(_dyld_get_image_vmaddr_slide(i));
    }
  }
  return 0;
}

}  // namespace

int main(int argc, char **argv) {
  if (argc < 3) {
    std::fprintf(stderr,
                 "用法: %s <wrapper.node> <intel|arm> [--repeat N] [--target vm|sign|both]\n"
                 "  intel      = x86_64 切片\n"
                 "  arm        = arm64 切片\n"
                 "  --repeat N = 连续调用 N 次（每次 fork 子进程，崩溃不影响后续轮次）\n"
                 "               VM 与 sign core 各调 N 次\n"
                 "  --target   = vm: 只验证 VM 分发器；sign: 只验证 sign core；\n"
                 "               both（默认）: 两者都验证并对比输出\n",
                 argv[0]);
    return 2;
  }
  const char *path = argv[1];
  std::string arch = argv[2];
  int repeat = 0;
  std::string target = "both";
  for (int i = 3; i + 1 < argc; ++i) {
    if (std::strcmp(argv[i], "--repeat") == 0) {
      repeat = std::atoi(argv[i + 1]);
      if (repeat < 0) repeat = 0;
      ++i;
    } else if (std::strcmp(argv[i], "--target") == 0) {
      target = argv[i + 1];
      ++i;
    }
  }
  bool want_vm = (target == "vm" || target == "both");
  bool want_sign = (target == "sign" || target == "both");
  uint32_t want_cpu = 0;
  if (arch == "intel" || arch == "x86_64" || arch == "amd64") {
    want_cpu = kCpuX86_64;
  } else if (arch == "arm" || arch == "arm64" || arch == "aarch64") {
    want_cpu = kCpuArm64;
  } else {
    std::fprintf(stderr, "未知架构: %s（用 intel 或 arm）\n", arch.c_str());
    return 2;
  }

  // 读文件。
  FILE *f = std::fopen(path, "rb");
  if (!f) {
    std::perror("open");
    return 1;
  }
  std::fseek(f, 0, SEEK_END);
  long fsize = std::ftell(f);
  std::fseek(f, 0, SEEK_SET);
  std::vector<uint8_t> file(static_cast<size_t>(fsize));
  if (std::fread(file.data(), 1, file.size(), f) != file.size()) {
    std::fprintf(stderr, "读取文件失败\n");
    std::fclose(f);
    return 1;
  }
  std::fclose(f);

  // 选切片。
  Slice slice;
  std::string err;
  uint32_t magic = read_be32(file.data());
  if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
    uint32_t nfat = read_be32(file.data() + 4);
    bool found = false;
    for (uint32_t i = 0; i < nfat; ++i) {
      const uint8_t *fa = file.data() + 8 + i * sizeof(fat_arch);
      if (8 + (i + 1) * sizeof(fat_arch) > file.size()) break;
      uint32_t cputype = read_be32(fa);
      uint32_t offset = read_be32(fa + 8);
      uint32_t size = read_be32(fa + 12);
      if (cputype != want_cpu) continue;
      if (offset + size > file.size()) {
        err = "切片越界";
        break;
      }
      if (!parse_thin(file.data() + offset, size, &slice, &err)) break;
      found = true;
      break;
    }
    if (!found) {
      std::fprintf(stderr, "fat 文件里没有 %s 切片（%s）\n", arch.c_str(), err.c_str());
      return 1;
    }
  } else {
    if (!parse_thin(file.data(), file.size(), &slice, &err)) {
      std::fprintf(stderr, "解析 Mach-O 失败: %s\n", err.c_str());
      return 1;
    }
    if (slice.cputype != want_cpu) {
      std::fprintf(stderr, "文件架构不匹配（文件是 %s，要求 %s）\n",
                   slice.cputype == kCpuX86_64 ? "x86_64" : "其他", arch.c_str());
      return 1;
    }
  }

  std::printf("== wrapper.node (%s) ==\n", arch.c_str());
  std::printf("cputype        : 0x%x\n", slice.cputype);
  std::printf("segments       : %zu\n", slice.segments.size());
  std::printf("symbols        : %zu\n", slice.symbols.size());

  // 1) sign core
  uint64_t sign_rva = 0;
  if (!find_sign_core(slice, &sign_rva)) {
    std::fprintf(stderr, "符号表里找不到 _libsecO3Sign\n");
    return 1;
  }
  std::printf("sign core RVA  : 0x%llx  (_libsecO3Sign)\n", (unsigned long long)sign_rva);

  // 2) VM 分发器
  uint64_t dispatcher_rva = 0;
  bool ok = slice.cputype == kCpuX86_64 ? find_dispatcher_x86(slice, &dispatcher_rva)
                                        : find_dispatcher_arm(slice, &dispatcher_rva);
  if (!ok) {
    std::fprintf(stderr, "未定位到 VM 分发器（魔数 0x23381121/0x23381120 未命中）\n");
    return 1;
  }
  std::printf("VM dispatcher  : 0x%llx  (RVA)\n", (unsigned long long)dispatcher_rva);

  // 3) 动态验证（dlopen 之后才能取到 slide）。
  // 只能验证宿主同架构的切片；在 x86_64 机器上选 arm 切片时跳过。
  if (slice.cputype != static_cast<uint32_t>(CPU_TYPE_X86_64) &&
      slice.cputype != static_cast<uint32_t>(CPU_TYPE_ARM64)) {
    std::fprintf(stderr, "未知 cputype，跳过动态验证\n");
    return 1;
  }
  if (slice.cputype != host_cpu_type()) {
    std::printf("动态验证     : 跳过（宿主是 %s，目标切片是 %s）\n",
                host_cpu_type() == static_cast<uint32_t>(CPU_TYPE_X86_64) ? "x86_64" : "arm64",
                slice.cputype == static_cast<uint32_t>(CPU_TYPE_X86_64) ? "x86_64" : "arm64");
    std::printf("OK: 静态定位完成\n");
    return 0;
  }

  // 先 dlopen，再分别解析 VM 分发器与 sign core 的运行时地址。
  uint64_t slide = 0;
  {
    // open_library 顺带完成 RTLD_GLOBAL 提升；这里只是拿 slide。
    void *dummy = nullptr;
    if (!open_library(path, sign_rva, &dummy, &slide, &err)) {
      std::fprintf(stderr, "加载失败: %s\n", err.c_str());
      return 1;
    }
  }
  std::printf("dyld slide     : 0x%llx\n", (unsigned long long)slide);
  std::printf("sign core addr : 0x%llx\n", (unsigned long long)(slide + sign_rva));
  std::printf("vm dispatcher  : 0x%llx  (addr)\n", (unsigned long long)(slide + dispatcher_rva));

  int rounds = repeat > 0 ? repeat : 1;
  int total_crash = 0, total_err = 0;
  bool any_ok = false;

  // 逐个目标跑：VM 与 sign core 各 N 次。
  struct Plan {
    const char *name;
    bool use_vm;
    void *fn;
    size_t want_len;
  } plans[2] = {
      {"vm", true, reinterpret_cast<void *>(slide + dispatcher_rva), 28},
      {"sign", false, reinterpret_cast<void *>(slide + sign_rva), 28},
  };

  for (const Plan &p : plans) {
    if (p.use_vm ? !want_vm : !want_sign) continue;
    std::printf("\n=== 验证目标: %s ===\n", p.name);
    g_use_vm = p.use_vm;
    int n_ok = 0, n_crash = 0, n_err = 0;
    std::vector<uint8_t> first_sign;

    for (int i = 0; i < rounds; ++i) {
      std::vector<uint8_t> sign;
      std::printf("call %d/%d ... ", i + 1, rounds);
      std::fflush(stdout);

      int rc = call_in_child(p.fn, i + 1, &sign);
      if (rc == 0 && sign.size() == p.want_len) {
        ++n_ok;
        std::printf("ok  %s\n", [&] {
          static char buf[128];
          int n = 0;
          for (uint8_t b : sign) n += std::snprintf(buf + n, sizeof(buf) - n, "%02X", b);
          return std::string(buf, (size_t)n);
        }().c_str());
        if (first_sign.empty()) first_sign = sign;
      } else if (rc >= 128) {
        ++n_crash;
        std::printf("CRASH signal=%s (exit=%d)\n", signal_name(rc - 128), rc);
      } else {
        ++n_err;
        std::printf("ERROR rc=%d len=%zu\n", rc, sign.size());
      }
      std::fflush(stdout);
    }

    std::printf("结果[%s]: 成功 %d / 崩溃 %d / 错误 %d（共 %d 次）\n", p.name, n_ok, n_crash, n_err,
                rounds);
    if (!first_sign.empty()) {
      std::printf("sign[%s]      : ", p.name);
      for (uint8_t b : first_sign) std::printf("%02X", b);
      std::printf("\n");
    }
    if (n_ok > 0) any_ok = true;
    total_crash += n_crash;
    total_err += n_err;
  }

  if (!any_ok) {
    std::fprintf(stderr, "FAIL: 没有一次成功\n");
    return 1;
  }
  if (total_crash > 0 || total_err > 0) {
    std::fprintf(stderr, "PARTIAL: 有 %d 次崩溃 / %d 次错误\n", total_crash, total_err);
    return 1;
  }
  std::printf("\nOK: 所有目标 %d 次调用全部成功，sign 28 字节\n", rounds);
  return 0;
}
