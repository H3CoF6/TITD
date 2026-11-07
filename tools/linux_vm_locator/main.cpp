// Linux QQ wrapper.node 的 sign / VM 定位与验证工具。
//
// 只依赖 ELF 元数据与指令语义，**不用任何字节特征码**：
//
//   1. sign core —— 走 C++ 的 RTTI 链（与 nt_helper 的 locate.rs 同一思路）：
//        typeinfo name -> typeinfo -> vtable -> 虚函数 -> 直接调用里写满
//        +0xFF / +0x1FF / +0x2FF 的那个函数
//   2. VM 适配器 —— 从 sign core 出发按直接 call 展开三层调用闭包，挑出同时
//      满足「往 16 字节描述符的 +4 写 tag 0x1e」和「调用 malloc」的小函数
//   3. 动态验证 —— dlopen wrapper.node，分别调 sign core 和 VM，各跑 N 次
//
// 函数边界来自 `.eh_frame_hdr` 的 FDE 表（链接器产物）。QQ 的 O3 混淆器把大片
// .text 折成单个巨大 FDE，那些区域没有精确边界，只能回退到「解码到终止符」。
//
// 构建：g++ -std=c++17 -O2 -o linux_vm_locator main.cpp
// 用法：
//   ./linux_vm_locator <wrapper.node> [--arch x86_64|aarch64] [--repeat N]
//                      [--target vm|sign|both] [--no-call]

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

// ---------------------------------------------------------------------------
// ELF64 解析
// ---------------------------------------------------------------------------

constexpr uint16_t EM_X86_64 = 62;
constexpr uint16_t EM_AARCH64 = 183;

struct Section {
  std::string name;
  uint32_t type = 0;
  uint64_t flags = 0;
  uint64_t addr = 0;
  uint64_t offset = 0;
  uint64_t size = 0;
  uint64_t entsize = 0;
};

struct ProgramHeader {
  uint32_t type = 0;
  uint32_t flags = 0;
  uint64_t offset = 0;
  uint64_t vaddr = 0;
  uint64_t filesz = 0;
};

struct Elf {
  const uint8_t *data = nullptr;
  size_t size = 0;
  uint16_t machine = 0;
  std::vector<Section> sections;
  std::vector<ProgramHeader> phdrs;

  // 重定位：(site -> target) 与 (target -> sites)
  std::unordered_map<uint64_t, uint64_t> rel_by_site;
  std::unordered_map<uint64_t, std::vector<uint64_t>> rel_by_target;

  // .eh_frame_hdr 的 FDE 起始地址（升序）。
  std::vector<uint64_t> fde_starts;
  // PLT 槽：导入符号 -> 跳转地址。
  std::map<std::string, uint64_t> plt_syms;

  const Section *find(const char *name) const {
    for (const Section &s : sections)
      if (s.name == name) return &s;
    return nullptr;
  }

  bool addr_to_off(uint64_t addr, uint64_t *out) const {
    for (const Section &s : sections) {
      if ((s.flags & 2) && s.type != 8 && addr >= s.addr && addr < s.addr + s.size) {
        *out = s.offset + (addr - s.addr);
        return true;
      }
    }
    for (const ProgramHeader &p : phdrs) {
      if (p.type == 1 && addr >= p.vaddr && addr < p.vaddr + p.filesz) {
        *out = p.offset + (addr - p.vaddr);
        return true;
      }
    }
    return false;
  }

  bool off_to_addr(uint64_t off, uint64_t *out) const {
    for (const Section &s : sections) {
      if ((s.flags & 2) && s.type != 8 && off >= s.offset && off < s.offset + s.size) {
        *out = s.addr + (off - s.offset);
        return true;
      }
    }
    for (const ProgramHeader &p : phdrs) {
      if (p.type == 1 && off >= p.offset && off < p.offset + p.filesz) {
        *out = p.vaddr + (off - p.offset);
        return true;
      }
    }
    return false;
  }

  const uint8_t *at(uint64_t addr, size_t len) const {
    uint64_t off = 0;
    if (!addr_to_off(addr, &off) || off + len > size) return nullptr;
    return data + off;
  }

  bool is_exec(uint64_t addr) const {
    for (const Section &s : sections)
      if ((s.flags & 4) && addr >= s.addr && addr < s.addr + s.size) return true;
    for (const ProgramHeader &p : phdrs)
      if (p.type == 1 && (p.flags & 1) && addr >= p.vaddr && addr < p.vaddr + p.filesz) return true;
    return false;
  }

  uint64_t resolve_ptr(uint64_t site) const {
    auto it = rel_by_site.find(site);
    if (it != rel_by_site.end()) return it->second;
    const uint8_t *p = at(site, 8);
    if (!p) return 0;
    uint64_t v;
    std::memcpy(&v, p, 8);
    return v;
  }

  std::vector<uint64_t> sites_pointing_to(uint64_t target) const {
    auto it = rel_by_target.find(target);
    if (it == rel_by_target.end()) return {};
    return it->second;
  }

  // 精确函数结束：addr 必须恰是某个 FDE 起点。
  bool fde_end(uint64_t addr, uint64_t *out) const {
    auto it = std::lower_bound(fde_starts.begin(), fde_starts.end(), addr);
    if (it == fde_starts.end() || *it != addr) return false;
    if (std::next(it) == fde_starts.end()) return false;
    *out = *std::next(it);
    return true;
  }
};

template <typename T>
T read_le(const uint8_t *p) {
  T v;
  std::memcpy(&v, p, sizeof(T));
  return v;
}

bool parse_elf(const uint8_t *data, size_t size, Elf *e, std::string *err) {
  if (size < 64 || std::memcmp(data, "\x7f" "ELF", 4) != 0 || data[4] != 2 || data[5] != 1) {
    *err = "不是 64 位小端 ELF";
    return false;
  }
  e->data = data;
  e->size = size;
  e->machine = read_le<uint16_t>(data + 0x12);

  uint64_t shoff = read_le<uint64_t>(data + 0x28);
  uint16_t shentsize = read_le<uint16_t>(data + 0x3a);
  uint16_t shnum = read_le<uint16_t>(data + 0x3c);
  uint16_t shstrndx = read_le<uint16_t>(data + 0x3e);
  uint64_t phoff = read_le<uint64_t>(data + 0x20);
  uint16_t phentsize = read_le<uint16_t>(data + 0x36);
  uint16_t phnum = read_le<uint16_t>(data + 0x38);

  if (shentsize < 64 || (shnum && shoff + (uint64_t)shnum * shentsize > size)) {
    *err = "section 表越界";
    return false;
  }
  for (uint16_t i = 0; i < shnum; ++i) {
    const uint8_t *p = data + shoff + (uint64_t)i * shentsize;
    Section s;
    s.type = read_le<uint32_t>(p + 4);
    s.flags = read_le<uint64_t>(p + 8);
    s.addr = read_le<uint64_t>(p + 0x10);
    s.offset = read_le<uint64_t>(p + 0x18);
    s.size = read_le<uint64_t>(p + 0x20);
    s.entsize = read_le<uint64_t>(p + 0x38);
    e->sections.push_back(s);
  }
  if (shstrndx < e->sections.size()) {
    const Section &str = e->sections[shstrndx];
    if (str.offset + str.size <= size) {
      for (Section &s : e->sections) {
        const uint8_t *p = data + shoff + ((uint64_t)(&s - &e->sections[0])) * shentsize;
        uint32_t name_off = read_le<uint32_t>(p);
        if (name_off < str.size) {
          const char *n = reinterpret_cast<const char *>(data + str.offset + name_off);
          size_t max = str.size - name_off;
          size_t len = strnlen(n, max);
          if (len != max) s.name.assign(n, len);
        }
      }
    }
  }
  if (phentsize < 56 || (phnum && phoff + (uint64_t)phnum * phentsize > size)) {
    *err = "program header 表越界";
    return false;
  }
  for (uint16_t i = 0; i < phnum; ++i) {
    const uint8_t *p = data + phoff + (uint64_t)i * phentsize;
    ProgramHeader ph;
    ph.type = read_le<uint32_t>(p);
    ph.flags = read_le<uint32_t>(p + 4);
    ph.offset = read_le<uint64_t>(p + 8);
    ph.vaddr = read_le<uint64_t>(p + 0x10);
    ph.filesz = read_le<uint64_t>(p + 0x20);
    e->phdrs.push_back(ph);
  }

  // RELATIVE 重定位：x86-64 是 8，aarch64 是 1027。
  for (const Section &s : e->sections) {
    if (s.type != 4) continue;  // SHT_RELA
    uint64_t entsize = s.entsize ? s.entsize : 24;
    if (entsize < 24 || s.offset + s.size > size) continue;
    for (uint64_t o = 0; o + entsize <= s.size; o += entsize) {
      const uint8_t *p = data + s.offset + o;
      uint64_t site = read_le<uint64_t>(p);
      uint64_t info = read_le<uint64_t>(p + 8);
      int64_t addend = read_le<int64_t>(p + 16);
      uint32_t rtype = (uint32_t)(info & 0xffffffff);
      if (rtype == 8 || rtype == 1027) {
        e->rel_by_site[site] = (uint64_t)addend;
        e->rel_by_target[(uint64_t)addend].push_back(site);
      }
    }
  }

  // .eh_frame_hdr：GNU ld 固定用 datarel|sdata4（0x3b）编码表偏移。
  if (const Section *h = e->find(".eh_frame_hdr")) {
    if (h->size >= 12 && h->offset + h->size <= size) {
      const uint8_t *p = data + h->offset;
      uint32_t count = read_le<uint32_t>(p + 8);
      if (p[0] == 1 && p[3] == 0x3b && 12 + (uint64_t)count * 8 <= h->size) {
        e->fde_starts.reserve(count);
        for (uint32_t i = 0; i < count; ++i) {
          int32_t rel = read_le<int32_t>(p + 12 + (uint64_t)i * 8);
          e->fde_starts.push_back((uint64_t)((int64_t)h->addr + rel));
        }
        std::sort(e->fde_starts.begin(), e->fde_starts.end());
      }
    }
  }

  // PLT 槽：.rela.plt 的条目顺序与 .plt 的槽位一一对应。
  const Section *plt = e->find(".plt");
  const Section *dynsym = e->find(".dynsym");
  const Section *dynstr = e->find(".dynstr");
  const Section *rela_plt = nullptr;
  for (const Section &s : e->sections)
    if (s.type == 4 && s.name == ".rela.plt") rela_plt = &s;
  if (plt && dynsym && dynstr && rela_plt) {
    uint64_t relasz = rela_plt->entsize ? rela_plt->entsize : 24;
    uint64_t symentsize = dynsym->entsize ? dynsym->entsize : 24;
    const uint64_t header = e->machine == EM_X86_64 ? 16 : 32;
    if (rela_plt->offset + rela_plt->size <= size && dynsym->offset + dynsym->size <= size &&
        dynstr->offset + dynstr->size <= size) {
      for (uint64_t i = 0; i * relasz + relasz <= rela_plt->size; ++i) {
        const uint8_t *p = data + rela_plt->offset + i * relasz;
        uint64_t info = read_le<uint64_t>(p + 8);
        uint64_t symidx = info >> 32;
        if (symidx * symentsize + 4 > dynsym->size) continue;
        uint32_t name_off = read_le<uint32_t>(data + dynsym->offset + symidx * symentsize);
        if (name_off >= dynstr->size) continue;
        const char *n = reinterpret_cast<const char *>(data + dynstr->offset + name_off);
        size_t len = strnlen(n, dynstr->size - name_off);
        if (len == 0 || len == dynstr->size - name_off) continue;
        e->plt_syms.emplace(std::string(n, len), plt->addr + header + i * 16);
      }
    }
  }

  return true;
}

// ---------------------------------------------------------------------------
// 指令语义（只做定位需要的判断）
// ---------------------------------------------------------------------------

struct Insn {
  uint64_t addr = 0;
  uint32_t len = 0;
  // 归一化后的模板：助记符编号 + 关键字段
  int kind = 0;
};

// 极简 x86-64 / aarch64 扫描器。我们不需要完整反汇编器：
//   * 拿直接调用目标（x86 `E8 rel32`，aarch64 `BL imm26`）
//   * 判断「0x1e 被写进 [reg+4]」
// 两者都只看固定编码，不依赖任何魔数常量。

bool x86_is_call(const uint8_t *p, size_t avail, uint64_t addr, uint64_t *target) {
  if (avail < 5 || p[0] != 0xE8) return false;
  int32_t rel = read_le<int32_t>(p + 1);
  *target = addr + 5 + rel;
  return true;
}

bool a64_is_bl(uint32_t w, uint64_t addr, uint64_t *target) {
  if ((w & 0xFC000000) != 0x94000000) return false;
  int32_t imm = (int32_t)(w & 0x03FFFFFF);
  if (imm & 0x02000000) imm -= 0x04000000;
  *target = addr + (uint64_t)((int64_t)imm * 4);
  return true;
}

// x86-64：`0x1e` 是否被写进某个结构的 `+4`。
//
// 只认识两种真实形态，别的字节一律按「长度未知」跳过：
//   * `mov word ptr [reg+4], 0x1e`      (66 C7 /0, mod=01, rm!=100, disp8=4)
//   * `mov rX, 0x1e` 之后再 `mov word ptr [reg+4], rX`  (66 [REX] 89 /r)
//
// 这里不做完整反汇编：候选函数很小（< 8 KB），而这几个模板的编码唯一，
// 按指令长度推进就不会错位。
bool x86_tag_store(const uint8_t *d, size_t n) {
  // 寄存器 -> 是否持有 0x1e。REX.R 扩展到 16 个 64 位寄存器。
  bool holds[16] = {false};
  size_t i = 0;
  while (i < n) {
    const uint8_t *p = d + i;
    size_t left = n - i;

    // 前缀：REX（0x40..0x4F）与 0x66。
    bool rex_w = false, rex_r = false, rex_b = false, has_66 = false;
    size_t k = 0;
    while (k < left && (p[k] == 0x66 || (p[k] & 0xF0) == 0x40)) {
      if (p[k] == 0x66) has_66 = true;
      else {
        rex_w = (p[k] & 0x08) != 0;
        rex_r = (p[k] & 0x04) != 0;
        rex_b = (p[k] & 0x01) != 0;
      }
      ++k;
    }
    (void)rex_w;
    if (k >= left) break;
    const uint8_t op = p[k];

    // mov r/m16, imm16  (66 C7 /0)
    if (has_66 && op == 0xC7 && k + 5 <= left) {
      uint8_t modrm = p[k + 1];
      size_t oplen = k + 5;  // 前缀 + C7 + modrm + disp8 + imm16
      if ((modrm & 0xF8) == 0xC0) {  // mod=11：写寄存器
        i += oplen;
        continue;
      }
      if (modrm >> 6 == 1 && (modrm & 7) != 4) {
        uint8_t disp = p[k + 2];
        uint16_t imm = read_le<uint16_t>(p + k + 3);
        if (disp == 4 && imm == 0x1E) return true;
        i += oplen;
        continue;
      }
    }
    // mov r/m16, r16  (66 [REX] 89 /r)
    if (has_66 && op == 0x89 && k + 2 <= left) {
      uint8_t modrm = p[k + 1];
      int reg = (int)((modrm >> 3) & 7) + (rex_r ? 8 : 0);
      if ((modrm >> 6) == 1 && (modrm & 7) != 4 && k + 3 <= left) {
        if (p[k + 2] == 4 && holds[reg]) return true;
        i += k + 3;
        continue;
      }
    }
    // mov r32/r64, imm32/imm64  (B8+r)
    if ((op & 0xF8) == 0xB8) {
      int reg = (int)(op & 7) + (rex_b ? 8 : 0) + (rex_r ? 8 : 0);
      if (reg > 15) reg &= 7;
      size_t imm_len = rex_w ? 8 : 4;
      if (k + 1 + imm_len <= left) {
        uint64_t imm = rex_w ? read_le<uint64_t>(p + k + 1) : read_le<uint32_t>(p + k + 1);
        holds[reg] = (imm == 0x1E);
        i += k + 1 + imm_len;
        continue;
      }
    }
    i += 1;
  }
  return false;
}

// aarch64: movz wN,#0x1e 之后 strh wN,[xM,#4]（imm12 按元素 2 字节缩放）
bool a64_tag_store(const uint8_t *d, size_t n) {
  int holder = -1;
  for (size_t i = 0; i + 4 <= n; i += 4) {
    uint32_t w = read_le<uint32_t>(d + i);
    if ((w & 0xFF800000) == 0x52800000) {  // MOVZ Wd
      int rd = (int)(w & 0x1F);
      uint32_t imm = (w >> 5) & 0xFFFF;
      holder = (imm == 0x1E) ? rd : -1;
      continue;
    }
    if ((w & 0xFFC00000) == 0x79000000) {  // STRH imm12
      int rt = (int)(w & 0x1F);
      uint64_t off = ((uint64_t)((w >> 10) & 0xFFF)) * 2;
      if (off == 4 && rt == holder) return true;
    }
  }
  return false;
}

// 直接调用目标
std::vector<uint64_t> direct_calls(const Elf &e, uint64_t start, uint64_t end) {
  std::vector<uint64_t> out;
  const uint8_t *d = e.at(start, (size_t)(end - start));
  if (!d) return out;
  if (e.machine == EM_X86_64) {
    for (size_t i = 0; i + 5 <= end - start; ++i) {
      uint64_t t = 0;
      if (x86_is_call(d + i, end - start - i, start + i, &t)) {
        out.push_back(t);
        i += 4;
      }
    }
  } else {
    for (size_t i = 0; i + 4 <= end - start; i += 4) {
      uint64_t t = 0;
      if (a64_is_bl(read_le<uint32_t>(d + i), start + i, &t)) out.push_back(t);
    }
  }
  return out;
}

// 极简 x86-64 指令长度解码器。
//
// 只要「指令多长」和「目的操作数是不是 [reg+disp]」，不需要完整语义。
// 覆盖编译器实际会生成的编码：前缀、opcode、MODRM/SIB、disp、imm。
struct X86Insn {
  uint8_t len = 0;
  bool op0_is_mem = false;   // 目的操作数是内存（写）
  int64_t op0_disp = 0;      // 内存操作数的位移
  bool valid = false;
};

// opcode 的 imm 长度（-1 表示由 MODRM.reg 决定，-2 表示需特殊处理）
int x86_imm_len(uint8_t op, int modrm_reg, bool rex_w) {
  switch (op) {
    // 1 字节 imm
    case 0x04: case 0x0C: case 0x14: case 0x1C: case 0x24: case 0x2C: case 0x34: case 0x3C:
    case 0x6A: case 0xA8: case 0xB0: case 0xB1: case 0xB2: case 0xB3:
    case 0xB4: case 0xB5: case 0xB6: case 0xB7: case 0xCD:
    case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75: case 0x76: case 0x77:
    case 0x78: case 0x79: case 0x7A: case 0x7B: case 0x7C: case 0x7D: case 0x7E: case 0x7F:
    case 0xEB:
      return 1;
    // 2 字节 imm
    case 0x68: case 0xA9: case 0xC2: case 0xCA:
      return rex_w ? 2 : 4;
    // 4 字节 imm
    case 0x05: case 0x0D: case 0x15: case 0x1D: case 0x25: case 0x2D: case 0x35: case 0x3D:
    case 0xE8: case 0xE9:
      return 4;
    case 0xB8: case 0xB9: case 0xBA: case 0xBB: case 0xBC: case 0xBD: case 0xBE: case 0xBF:
      return rex_w ? 8 : 4;
    case 0xC7:
      return 2;  // 只有 0x66 前缀时是 2，其余 4；由调用方按前缀修正
    case 0x81: case 0x69:
      return 4;
    case 0x83: case 0x6B: case 0x80: case 0xC0: case 0xC1: case 0xC6:
    case 0xD0: case 0xD1: case 0xD2: case 0xD3:
      return 1;
    case 0xF7:
      return modrm_reg == 0 ? 4 : 0;
    case 0xF6:
      return modrm_reg == 0 ? 1 : 0;
    default:
      break;
  }
  // 无 imm 的常见 opcode
  if (op == 0x50 || op == 0x58) return 0;  // push/pop r64 家族由 &0xF8 处理
  if ((op & 0xF8) == 0x50 || (op & 0xF8) == 0x58) return 0;
  if (op == 0x90 || op == 0xC3 || op == 0xCB || op == 0xCC || op == 0xC9) return 0;
  if (op == 0x0F) return -2;  // 两字节 opcode
  return 0;
}

X86Insn x86_decode(const uint8_t *p, size_t avail) {
  X86Insn out;
  size_t k = 0;
  bool rex_w = false;
  bool has_66 = false;
  // 前缀
  while (k < avail) {
    uint8_t b = p[k];
    if (b == 0x66) { has_66 = true; ++k; }
    else if (b == 0xF2 || b == 0xF3 || b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
             b == 0x64 || b == 0x65 || b == 0x67) { ++k; }
    else if ((b & 0xF0) == 0x40) {
      rex_w = (b & 0x08) != 0;
      ++k;
    } else break;
  }
  if (k >= avail) return out;
  uint8_t op = p[k++];

  if (op == 0x0F) {
    if (k >= avail) return out;
    uint8_t op2 = p[k++];
    // jcc rel32
    if (op2 >= 0x80 && op2 <= 0x8F) {
      if (k + 4 > avail) return out;
      k += 4;
      out.len = (uint8_t)k;
      out.valid = true;
      return out;
    }
    // 无 MODRM、无 imm 的两字节 opcode（cpuid/rdtsc/endbr/syscall 等）
    switch (op2) {
      case 0x05: case 0x06: case 0x07: case 0x08: case 0x09: case 0x0B: case 0x0E:
      case 0x30: case 0x31: case 0x32: case 0x33: case 0x34: case 0x35: case 0x77:
      case 0xA2: case 0xAA:
        out.len = (uint8_t)k;
        out.valid = true;
        return out;
      default:
        break;
    }
    // bswap r32/r64: 0F C8+rd。
    if (op2 >= 0xC8 && op2 <= 0xCF) {
      out.len = (uint8_t)k;
      out.valid = true;
      return out;
    }
    if (k >= avail) return out;
    uint8_t modrm = p[k++];
    uint8_t mod = modrm >> 6;
    uint8_t rm = modrm & 7;
    bool mem = mod != 3;
    int64_t disp = 0;
    if (mem) {
      if (rm == 4) {
        if (k >= avail) return out;
        uint8_t sib = p[k++];
        if (mod == 0 && (sib & 7) == 5) { if (k + 4 > avail) return out; k += 4; }
        else if (mod == 1) { if (k >= avail) return out; disp = (int8_t)p[k]; k += 1; }
        else if (mod == 2) { if (k + 4 > avail) return out; disp = read_le<int32_t>(p + k); k += 4; }
      } else if (mod == 0 && rm == 5) {
        if (k + 4 > avail) return out;
        k += 4;
        out.len = (uint8_t)k;
        out.valid = true;
        return out;
      } else if (mod == 1) {
        if (k >= avail) return out;
        disp = (int8_t)p[k];
        k += 1;
      } else if (mod == 2) {
        if (k + 4 > avail) return out;
        disp = read_le<int32_t>(p + k);
        k += 4;
      }
    }
    // movzx/movsx 家族无 imm；imul/shl 等有 imm8。
    if (op2 == 0xAF || op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF ||
        op2 == 0x1F || op2 == 0x10 || op2 == 0x11 || op2 == 0x28 || op2 == 0x29 ||
        op2 == 0x6E || op2 == 0x7E || op2 == 0xD6 || op2 == 0xEF || op2 == 0x60 ||
        op2 == 0x61 || op2 == 0x62 || op2 == 0x63 || op2 == 0x64 || op2 == 0x65 || op2 == 0x66 ||
        op2 == 0x67 || op2 == 0x68 || op2 == 0x69 || op2 == 0x6A || op2 == 0x6B || op2 == 0x6C) {
      // 无 imm
    } else if (op2 >= 0x70 && op2 <= 0x73) {
      if (k >= avail) return out;
      k += 1;  // imm8
    } else if (op2 == 0xBA) {
      if (k >= avail) return out;
      k += 1;
    }
    if (k > avail) return out;
    out.len = (uint8_t)k;
    out.op0_is_mem = mem && (op2 == 0x89 || op2 == 0x88 || op2 == 0x11 || op2 == 0x10 ||
                             op2 == 0x13 || op2 == 0x29 || op2 == 0x01 || op2 == 0x09 ||
                             op2 == 0x31 || op2 == 0x21 || op2 == 0x2B || op2 == 0x63);
    out.op0_disp = disp;
    out.valid = true;
    return out;
  }

  bool two_byte_op0 = false;
  switch (op) {
    case 0x00: case 0x01: case 0x02: case 0x03:
    case 0x08: case 0x09: case 0x0A: case 0x0B:
    case 0x10: case 0x11: case 0x12: case 0x13:
    case 0x18: case 0x19: case 0x1A: case 0x1B:
    case 0x20: case 0x21: case 0x22: case 0x23:
    case 0x28: case 0x29: case 0x2A: case 0x2B:
    case 0x30: case 0x31: case 0x32: case 0x33:
    case 0x38: case 0x39: case 0x3A: case 0x3B:
    case 0x84: case 0x85: case 0x86: case 0x87:
    case 0x88: case 0x89: case 0x8A: case 0x8B:
    case 0x8C: case 0x8D: case 0x8E: case 0x8F:
    case 0xD0: case 0xD1: case 0xD2: case 0xD3:
    case 0xFE: case 0xFF:
    case 0xC0: case 0xC1: case 0xC6: case 0xC7:
    case 0xD8: case 0xD9: case 0xDA: case 0xDB: case 0xDC: case 0xDD: case 0xDE: case 0xDF:
    case 0xF6: case 0xF7:
    case 0x80: case 0x81: case 0x82: case 0x83:
    case 0x69: case 0x6B:
      two_byte_op0 = true;   // 有 MODRM
      break;
    case 0x63:                 // movsxd：有 MODRM
      two_byte_op0 = true;
      break;
    case 0x62:                 // EVEX，遇到就放弃
      return out;
    default:
      break;
  }

  if (two_byte_op0) {
    if (k >= avail) return out;
    uint8_t modrm = p[k++];
    uint8_t mod = modrm >> 6;
    uint8_t rm = modrm & 7;
    bool mem = mod != 3;
    int64_t disp = 0;
    if (mem) {
      if (rm == 4) {  // SIB
        if (k >= avail) return out;
        uint8_t sib = p[k++];
        if (mod == 0 && (sib & 7) == 5) { if (k + 4 > avail) return out; k += 4; }
        if (mod == 1) { if (k >= avail) return out; disp = (int8_t)p[k]; k += 1; }
        else if (mod == 2) { if (k + 4 > avail) return out; disp = read_le<int32_t>(p + k); k += 4; }
      } else if (mod == 0 && rm == 5) {  // RIP-rel
        if (k + 4 > avail) return out;
        k += 4;
        out.len = (uint8_t)k;
        out.valid = true;
        return out;  // RIP 相对不是结果缓冲
      } else if (mod == 1) {
        if (k >= avail) return out;
        disp = (int8_t)p[k];
        k += 1;
      } else if (mod == 2) {
        if (k + 4 > avail) return out;
        disp = read_le<int32_t>(p + k);
        k += 4;
      }
    }
    int modrm_reg = (modrm >> 3) & 7;
    int imm = x86_imm_len(op, modrm_reg, rex_w);
    if (imm == -2) return out;
    if (op == 0xC7 && has_66) imm = 2;
    if (op == 0xC7 && !has_66 && rex_w) imm = 4;
    if (op == 0xC7 && !has_66 && !rex_w) imm = 4;
    if (imm > 0) {
      if (k + (size_t)imm > avail) return out;
      k += (size_t)imm;
    }
    if (k > avail) return out;
    out.len = (uint8_t)k;
    out.op0_is_mem = mem;
    out.op0_disp = disp;
    out.valid = true;
    return out;
  }

  int imm = x86_imm_len(op, 0, rex_w);
  if (imm > 0) {
    if (k + (size_t)imm > avail) return out;
    k += (size_t)imm;
  }
  out.len = (uint8_t)k;
  out.valid = true;
  return out;
}

// 函数体里是否写满三个结果偏移（按「目的操作数是内存的写指令」收集位移）。
bool writes_result_buffer(const Elf &e, uint64_t start, uint64_t end) {
  if (end <= start) return false;
  const uint8_t *d = e.at(start, (size_t)(end - start));
  if (!d) return false;
  size_t n = (size_t)(end - start);
  bool has_ff = false, has_1ff = false, has_2ff = false;

  if (e.machine == EM_X86_64) {
    size_t i = 0;
    while (i < n) {
      X86Insn ins = x86_decode(d + i, n - i);
      if (!ins.valid || ins.len == 0) { ++i; continue; }
      if (ins.op0_is_mem) {
        if (ins.op0_disp == 0xFF) has_ff = true;
        else if (ins.op0_disp == 0x1FF) has_1ff = true;
        else if (ins.op0_disp == 0x2FF) has_2ff = true;
        if (has_ff && has_1ff && has_2ff) return true;
      }
      i += ins.len;
    }
  } else {
    for (size_t i = 0; i + 4 <= n; i += 4) {
      uint32_t w = read_le<uint32_t>(d + i);
      if ((w & 0xFFC00000) == 0x39000000) {  // STRB imm12
        uint64_t off = (w >> 10) & 0xFFF;
        if (off == 0xFF) has_ff = true;
        else if (off == 0x1FF) has_1ff = true;
        else if (off == 0x2FF) has_2ff = true;
      }
      if (has_ff && has_1ff && has_2ff) return true;
    }
  }
  return false;
}

// 函数结束地址：优先 FDE；落在巨型 FDE / 表外时解码到第一个真正的终止符。
//
// 注意不能一见 ret 就停：O3 混淆器会在函数中间插入对齐用的 `ret`，真正的
// 结尾在更后面。所以这里只把 ret 当作终止符，并且要求它后面不是代码
// （用「连续 0xCC 填充」或「下一条不是有效指令起始」判定太脆弱），
// 改为沿用 nt_helper 的策略：线性解码，遇到 ret 就停，但如果后续还能
// 解出合法指令就继续——只在明显的数据/填充处收尾。
uint64_t function_end(const Elf &e, uint64_t start, bool *exact) {
  uint64_t end = 0;
  if (e.fde_end(start, &end)) {
    if (exact) *exact = true;
    return end;
  }
  if (exact) *exact = false;
  const uint64_t cap = 0x40000;
  const uint8_t *d = e.at(start, cap);
  if (!d) return start + cap;

  if (e.machine == EM_X86_64) {
    size_t i = 0;
    while (i < cap) {
      X86Insn ins = x86_decode(d + i, cap - i);
      if (!ins.valid || ins.len == 0) {
        // 解不动：可能是数据或 padding，收尾
        return start + i;
      }
      uint8_t op = d[i + ins.len - 1];
      (void)op;
      // 看指令本身是不是 ret（前缀后 1 字节 opcode）
      size_t k = 0;
      while (k < ins.len && (d[i + k] == 0x66 || (d[i + k] & 0xF0) == 0x40 ||
                             d[i + k] == 0xF2 || d[i + k] == 0xF3)) ++k;
      uint8_t opcode = k < ins.len ? d[i + k] : 0;
      if (opcode == 0xC3 || opcode == 0xCB) return start + i + ins.len;
      if ((opcode == 0xC2 || opcode == 0xCA) && k + 3 <= ins.len) return start + i + ins.len;
      i += ins.len;
    }
  } else {
    for (uint64_t i = 0; i + 4 <= cap; i += 4) {
      uint32_t w = read_le<uint32_t>(d + i);
      if ((w & 0xFFFFFC1F) == 0xD65F0000) return start + i + 4;  // RET
      if ((w & 0xFFFFFC1F) == 0xD61F0000) return start + i + 4;  // BR
    }
  }
  return start + cap;
}

// ---------------------------------------------------------------------------
// 定位
// ---------------------------------------------------------------------------

const char kRttiName[] = "N2nt8internal23MSFSecuritySignCallbackE";

struct Result {
  uint64_t typeinfo = 0;
  uint64_t vtable = 0;
  uint64_t callback = 0;
  uint64_t sign_core = 0;
  std::vector<uint64_t> vm_candidates;
  uint64_t vm = 0;
};

bool locate(const Elf &e, Result *r, std::string *err) {
  // 1) RTTI 名字 -> typeinfo -> vtable
  const size_t name_len = sizeof(kRttiName) - 1;
  std::vector<uint64_t> name_addrs;
  for (uint64_t off = 0; off + name_len <= e.size; ++off) {
    if (std::memcmp(e.data + off, kRttiName, name_len) == 0) {
      uint64_t a = 0;
      if (e.off_to_addr(off, &a)) name_addrs.push_back(a);
    }
  }
  if (name_addrs.empty()) {
    *err = "找不到 RTTI 类型名";
    return false;
  }
  for (uint64_t name_addr : name_addrs) {
    for (uint64_t site : e.sites_pointing_to(name_addr)) {
      uint64_t typeinfo = site - 8;
      for (uint64_t vsite : e.sites_pointing_to(typeinfo)) {
        uint64_t vtable = vsite + 8;
        // 2) vtable 的虚函数 -> 直接调用里写满结果缓冲的那个
        std::vector<uint64_t> slots;
        for (int k = 0; k < 16; ++k) {
          uint64_t p = e.resolve_ptr(vtable + (uint64_t)k * 8);
          if (!p || !e.is_exec(p)) break;
          slots.push_back(p);
        }
        for (uint64_t f : slots) {
          uint64_t fe = function_end(e, f, nullptr);
          for (uint64_t callee : direct_calls(e, f, fe)) {
            if (!e.is_exec(callee)) continue;
            uint64_t ce = function_end(e, callee, nullptr);
            if (writes_result_buffer(e, callee, ce)) {
              r->typeinfo = typeinfo;
              r->vtable = vtable;
              r->callback = f;
              r->sign_core = callee;
              goto found_sign;
            }
          }
        }
      }
    }
  }
  *err = "RTTI 链上没有找到写满结果缓冲的签名函数";
  return false;

found_sign:
  // 3) VM 适配器：sign core 的三层调用闭包里，写 tag 0x1e 且调用 malloc 的小函数
  {
    auto malloc_it = e.plt_syms.find("malloc");
    uint64_t malloc_plt = malloc_it == e.plt_syms.end() ? 0 : malloc_it->second;
    std::vector<uint64_t> seen = {r->sign_core};
    std::vector<uint64_t> frontier = {r->sign_core};
    for (int depth = 0; depth < 3 && !frontier.empty(); ++depth) {
      std::vector<uint64_t> next;
      for (uint64_t f : frontier) {
        uint64_t fe = function_end(e, f, nullptr);
        for (uint64_t callee : direct_calls(e, f, fe)) {
          if (!e.is_exec(callee) || std::find(seen.begin(), seen.end(), callee) != seen.end()) continue;
          seen.push_back(callee);
          next.push_back(callee);
          uint64_t ce = function_end(e, callee, nullptr);
          if (ce <= callee || ce - callee > 0x2000) continue;
          const uint8_t *body = e.at(callee, (size_t)(ce - callee));
          if (!body) continue;
          bool tag = e.machine == EM_X86_64 ? x86_tag_store(body, (size_t)(ce - callee))
                                           : a64_tag_store(body, (size_t)(ce - callee));
          if (!tag) continue;
          if (malloc_plt) {
            auto cs = direct_calls(e, callee, ce);
            if (std::find(cs.begin(), cs.end(), malloc_plt) == cs.end()) continue;
          }
          r->vm_candidates.push_back(callee);
        }
      }
      frontier.swap(next);
    }
    if (!r->vm_candidates.empty()) r->vm = r->vm_candidates.front();
  }
  return true;
}

// ---------------------------------------------------------------------------
// 动态验证
// ---------------------------------------------------------------------------

// wrapper.node 引用宿主提供的 qq_magic_napi_register；导出同名空桩。
extern "C" void qq_magic_napi_register(void *) {}

using SignFn = int (*)(const char *cmd, const uint8_t *src, size_t len, int seq, uint8_t *out);

// Linux 的 libstdc++ std::string：{ptr, len, union{buf[16], cap}}。
struct CxxString {
  char *ptr;
  size_t len;
  char buf[16];
};

// VM 返回的 blob 描述符：{ u32 len; u16 tag(0x1e); u16 pad; void *data }
struct VmBlob {
  uint32_t len;
  uint16_t tag;
  uint16_t pad;
  void *data;
};

using VmFn = VmBlob *(*)(CxxString *, const void *, size_t, const void *, size_t);

constexpr size_t kOutBuf = 0x400;
constexpr size_t kTokenLenOff = 0xFF;
constexpr size_t kExtraDataOff = 0x100;
constexpr size_t kExtraLenOff = 0x1FF;
constexpr size_t kSignDataOff = 0x200;
constexpr size_t kSignLenOff = 0x2FF;

const char *signal_name(int sig) {
  switch (sig) {
    case SIGSEGV: return "SIGSEGV";
    case SIGBUS: return "SIGBUS";
    case SIGILL: return "SIGILL";
    case SIGABRT: return "SIGABRT";
    default: return "signal";
  }
}

volatile sig_atomic_t g_in_call = 0;

void write_str(const char *s) {
  size_t n = 0;
  while (s[n]) ++n;
  (void)!write(STDERR_FILENO, s, n);
}

void crash_handler(int sig) {
  if (g_in_call) {
    write_str("[crash] 调用期间崩溃: ");
    write_str(signal_name(sig));
    write_str("\n");
  }
  _exit(128 + sig);
}

// `path` 是不是当前进程的主程序（而非按路径加载的共享库）。
//
// 比较的是设备号 + inode，不用路径字符串：主程序路径与 dladdr 返回的可能
// 一个是 /proc 符号一个是真实路径。
bool is_main_program(const char *path) {
  struct stat self_st{}, path_st{};
  if (stat("/proc/self/exe", &self_st) != 0) return false;
  if (stat(path, &path_st) != 0) return false;
  return self_st.st_dev == path_st.st_dev && self_st.st_ino == path_st.st_ino;
}

bool open_library(const char *path, uint64_t *load_base, std::string *err) {
  Dl_info info{};
  if (dladdr(reinterpret_cast<void *>(&qq_magic_napi_register), &info) == 0 || !info.dli_fname) {
    *err = "dladdr 失败，无法提升 RTLD_GLOBAL";
    return false;
  }
  // 以共享库形式加载时必须显式提升为 RTLD_GLOBAL；本工具是可执行文件
  // （PIE 也是 ET_DYN，所以不能靠 ELF 头区分），它天然在全局作用域里，
  // 用 dl_iterate_phdr 判断「这个路径是不是主程序」即可。
  if (!is_main_program(info.dli_fname)) {
    void *self = dlopen(info.dli_fname, RTLD_NOW | RTLD_GLOBAL | RTLD_NOLOAD);
    if (!self) {
      const char *msg = dlerror();
      *err = std::string("提升 RTLD_GLOBAL 失败: ") + (msg ? msg : "(unknown)");
      return false;
    }
  }
  // dlopen 需要能定位到文件本身：相对路径会按库搜索路径解析而失败。
  char resolved[PATH_MAX];
  const char *open_path = realpath(path, resolved) ? resolved : path;
  std::string dir(open_path);
  auto slash = dir.find_last_of('/');
  if (slash != std::string::npos) dir.resize(slash + 1);

  // libbugly.so 的间接依赖需要 gnutls 的符号，且必须在全局作用域里才能被解析
  // （nt_helper 的 preload_deps 做的是同一件事）。
  dlopen("libgnutls.so.30", RTLD_LAZY | RTLD_GLOBAL);
  // wrapper.node 的同目录依赖（libbugly.so / libcrbase.so 等）不在默认搜索
  // 路径里：显式按绝对路径以全局作用域预载，比依赖 LD_LIBRARY_PATH 稳。
  for (const char *dep : {"libbugly.so", "libcrbase.so"}) {
    dlopen((dir + dep).c_str(), RTLD_LAZY | RTLD_GLOBAL);
  }
  // RTLD_LAZY：wrapper.node 依赖 N-API 等宿主符号，sign core / VM 不碰它们。
  void *lib = dlopen(open_path, RTLD_LAZY | RTLD_LOCAL);
  if (!lib) {
    const char *msg = dlerror();
    *err = std::string("dlopen wrapper.node 失败: ") + (msg ? msg : "(unknown)");
    return false;
  }
  // 取加载基址：/proc/self/maps 里该路径 offset=0 的那段。
  FILE *f = std::fopen("/proc/self/maps", "r");
  if (!f) {
    *err = "打不开 /proc/self/maps";
    return false;
  }
  char line[4096];
  char real[PATH_MAX];
  const char *want = realpath(path, real) ? real : path;
  bool found = false;
  while (std::fgets(line, sizeof(line), f)) {
    char *sp = std::strchr(line, ' ');
    if (!sp) continue;
    char *p = std::strchr(sp + 1, '/');
    if (!p) continue;
    p[std::strcspn(p, "\n")] = 0;
    if (std::strcmp(p, want) != 0) continue;
    // 格式：start-end perms offset ...
    char *dash = std::strchr(line, '-');
    char *perms = sp + 1;
    char *off_field = perms + 4;
    while (*off_field == ' ') ++off_field;
    char *off_end = off_field;
    while (*off_end && *off_end != ' ') ++off_end;
    if ((size_t)(off_end - off_field) != 8 || std::strncmp(off_field, "00000000", 8) != 0) continue;
    *load_base = std::strtoull(line, nullptr, 16);
    (void)dash;
    found = true;
    break;
  }
  std::fclose(f);
  if (!found) {
    *err = "dlopen 后 /proc/self/maps 里找不到该模块的基址段";
    return false;
  }
  return true;
}

int call_in_child(void *sign_ptr, void *vm_ptr, bool use_vm, int seq, std::vector<uint8_t> *out) {
  int fds[2];
  if (pipe(fds) != 0) return -1;
  pid_t pid = fork();
  if (pid < 0) {
    close(fds[0]);
    close(fds[1]);
    return -1;
  }
  if (pid == 0) {
    close(fds[0]);
    signal(SIGSEGV, crash_handler);
    signal(SIGBUS, crash_handler);
    signal(SIGILL, crash_handler);
    signal(SIGABRT, crash_handler);
    g_in_call = 1;
    const char *cmd = "trpc.qq_new_tech.status_svc.StatusService.SsoHeartBeat";
    const uint8_t payload[] = {0x08, 0x01};
    std::vector<uint8_t> sign;

    if (use_vm) {
      static const uint8_t kMd5[16] = {0xF7, 0xC5, 0x7F, 0x06, 0xA1, 0xD3, 0xCE, 0x11,
                                       0x77, 0x49, 0xFC, 0x98, 0xE2, 0x11, 0x16, 0x68};
      auto *fn = reinterpret_cast<VmFn>(vm_ptr);
      std::vector<char> cmd_buf(cmd, cmd + std::strlen(cmd));
      CxxString s{cmd_buf.data(), cmd_buf.size(), {}};
      VmBlob *blob = fn(&s, kMd5, sizeof(kMd5), nullptr, 0);
      g_in_call = 0;
      if (!blob || blob->len == 0 || blob->len > 0x1000 || !blob->data) _exit(3);
      auto *p = reinterpret_cast<uint8_t *>(blob->data);
      sign.assign(p, p + blob->len);
      std::free(blob->data);
      std::free(blob);
    } else {
      auto *fn = reinterpret_cast<SignFn>(sign_ptr);
      std::vector<uint8_t> buf(kOutBuf, 0);
      int rc = fn(cmd, payload, sizeof(payload), seq, buf.data());
      g_in_call = 0;
      if (rc != 0) _exit(rc > 0 && rc < 128 ? rc : 4);
      size_t len = buf[kSignLenOff];
      if (len == 0 || len > 0x100) _exit(5);
      (void)kExtraDataOff;
      (void)kExtraLenOff;
      (void)kTokenLenOff;
      sign.assign(buf.begin() + kSignDataOff, buf.begin() + kSignDataOff + (std::ptrdiff_t)len);
    }

    uint8_t len8 = (uint8_t)sign.size();
    (void)!write(fds[1], &len8, 1);
    (void)!write(fds[1], sign.data(), sign.size());
    _exit(0);
  }
  close(fds[1]);
  uint8_t len8 = 0;
  ssize_t got = read(fds[0], &len8, 1);
  if (got == 1 && len8 > 0 && len8 <= 64) {
    out->resize(len8);
    size_t off = 0;
    while (off < len8) {
      ssize_t n = read(fds[0], out->data() + off, len8 - off);
      if (n <= 0) break;
      off += (size_t)n;
    }
    if (off != len8) out->clear();
  }
  close(fds[0]);
  int status = 0;
  waitpid(pid, &status, 0);
  if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
  if (WIFEXITED(status)) return WEXITSTATUS(status);
  return -1;
}

std::string hex(const std::vector<uint8_t> &v) {
  static const char *k = "0123456789ABCDEF";
  std::string s;
  s.reserve(v.size() * 2);
  for (uint8_t b : v) {
    s.push_back(k[b >> 4]);
    s.push_back(k[b & 0xF]);
  }
  return s;
}

uint32_t host_machine() {
#if defined(__aarch64__)
  return EM_AARCH64;
#else
  return EM_X86_64;
#endif
}

}  // namespace

int main(int argc, char **argv) {
  if (argc < 2) {
    std::fprintf(stderr,
                 "用法: %s <wrapper.node> [--arch x86_64|aarch64] [--repeat N]\n"
                 "      [--target vm|sign|both] [--no-call]\n"
                 "  --arch    默认本机架构；异架构只做静态定位\n"
                 "  --repeat  每个目标连续调用次数（默认 1）\n"
                 "  --target  默认 both\n"
                 "  --no-call 只做静态定位，不 dlopen\n",
                 argv[0]);
    return 2;
  }
  const char *path = argv[1];
  int repeat = 1;
  std::string target = "both";
  bool no_call = false;
  uint16_t want_machine = host_machine();
  for (int i = 2; i < argc; ++i) {
    if (!std::strcmp(argv[i], "--arch") && i + 1 < argc) {
      std::string a = argv[++i];
      want_machine = (a == "aarch64" || a == "arm64") ? EM_AARCH64 : EM_X86_64;
    } else if (!std::strcmp(argv[i], "--repeat") && i + 1 < argc) {
      repeat = std::atoi(argv[++i]);
      if (repeat < 1) repeat = 1;
    } else if (!std::strcmp(argv[i], "--target") && i + 1 < argc) {
      target = argv[++i];
    } else if (!std::strcmp(argv[i], "--no-call")) {
      no_call = true;
    }
  }
  const bool want_vm = target == "vm" || target == "both";
  const bool want_sign = target == "sign" || target == "both";

  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    std::perror("open");
    return 1;
  }
  struct stat st{};
  if (fstat(fd, &st) != 0 || st.st_size <= 0) {
    std::fprintf(stderr, "fstat 失败\n");
    return 1;
  }
  void *map = mmap(nullptr, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);
  if (map == MAP_FAILED) {
    std::perror("mmap");
    return 1;
  }

  std::printf("== %s ==\n", path);
  std::printf("size      : %lld\n", (long long)st.st_size);

  Elf e;
  std::string err;
  if (!parse_elf(static_cast<const uint8_t *>(map), (size_t)st.st_size, &e, &err)) {
    std::fprintf(stderr, "解析 ELF 失败: %s\n", err.c_str());
    return 1;
  }
  std::printf("machine   : %s\n", e.machine == EM_AARCH64 ? "aarch64" : "x86_64");
  std::printf("fde count : %zu\n", e.fde_starts.size());
  std::printf("relocs    : %zu\n", e.rel_by_site.size());

  if (e.machine != want_machine) {
    std::fprintf(stderr, "架构不匹配（文件是 %s，要求 %s）\n",
                 e.machine == EM_AARCH64 ? "aarch64" : "x86_64",
                 want_machine == EM_AARCH64 ? "aarch64" : "x86_64");
    return 1;
  }

  Result r;
  if (!locate(e, &r, &err)) {
    std::fprintf(stderr, "定位失败: %s\n", err.c_str());
    return 1;
  }
  std::printf("typeinfo  : 0x%llx\n", (unsigned long long)r.typeinfo);
  std::printf("vtable    : 0x%llx\n", (unsigned long long)r.vtable);
  std::printf("callback  : 0x%llx\n", (unsigned long long)r.callback);
  std::printf("sign core : 0x%llx  (RVA)\n", (unsigned long long)r.sign_core);
  for (size_t i = 0; i < r.vm_candidates.size(); ++i) {
    std::printf("vm cand#%zu : 0x%llx  (RVA)\n", i, (unsigned long long)r.vm_candidates[i]);
  }
  if (r.vm) {
    std::printf("vm adapter: 0x%llx  (RVA)\n", (unsigned long long)r.vm);
  } else {
    std::printf("vm adapter: 未定位到\n");
  }

  if (no_call) {
    std::printf("动态验证  : 跳过（--no-call）\n");
    return r.vm ? 0 : 3;
  }
  if (e.machine != host_machine()) {
    std::printf("动态验证  : 跳过（异架构静态定位）\n");
    return r.vm ? 0 : 3;
  }

  uint64_t base = 0;
  if (!open_library(path, &base, &err)) {
    std::fprintf(stderr, "加载失败: %s\n", err.c_str());
    return 1;
  }
  std::printf("load base : 0x%llx\n", (unsigned long long)base);
  void *sign_ptr = reinterpret_cast<void *>(base + r.sign_core);
  void *vm_ptr = r.vm ? reinterpret_cast<void *>(base + r.vm) : nullptr;

  struct Plan {
    const char *name;
    bool use_vm;
    void *fn;
  } plans[2] = {{"sign", false, sign_ptr}, {"vm", true, vm_ptr}};

  int total_fail = 0;
  bool any_ok = false;
  for (const Plan &p : plans) {
    if (p.use_vm ? !want_vm : !want_sign) continue;
    std::printf("\n=== 验证目标: %s ===\n", p.name);
    if (!p.fn) {
      std::printf("结果[%s]: 跳过（未定位到）\n", p.name);
      ++total_fail;
      continue;
    }
    int n_ok = 0, n_crash = 0, n_err = 0;
    std::vector<uint8_t> first;
    for (int i = 0; i < repeat; ++i) {
      std::vector<uint8_t> sign;
      std::printf("call %d/%d ... ", i + 1, repeat);
      std::fflush(stdout);
      int rc = call_in_child(sign_ptr, vm_ptr, p.use_vm, i + 1, &sign);
      if (rc == 0 && !sign.empty()) {
        ++n_ok;
        if (first.empty()) first = sign;
        std::printf("ok  %s\n", hex(sign).c_str());
      } else if (rc >= 128) {
        ++n_crash;
        std::printf("CRASH signal=%s (exit=%d)\n", signal_name(rc - 128), rc);
      } else {
        ++n_err;
        std::printf("ERROR rc=%d len=%zu\n", rc, sign.size());
      }
      std::fflush(stdout);
    }
    std::printf("结果[%s]: 成功 %d / 崩溃 %d / 错误 %d（共 %d 次）\n", p.name, n_ok, n_crash,
                n_err, repeat);
    if (!first.empty()) {
      std::printf("sign[%s]   : %s（%zu 字节）\n", p.name, hex(first).c_str(), first.size());
    }
    if (n_ok == 0) ++total_fail;
    if (n_ok > 0) any_ok = true;
  }

  if (!any_ok) {
    std::fprintf(stderr, "FAIL: 没有一次成功\n");
    return 1;
  }
  if (total_fail) return 1;
  std::printf("\nOK: 全部目标 %d 次调用成功\n", repeat);
  return 0;
}
