# Chapter 2: Kiến Trúc Hệ Thống

> Chương này mô tả tổng quan kiến trúc Windows — từ hardware abstraction
> lên đến user-mode subsystems. Hiểu kiến trúc này là nền tảng để đi sâu
> vào từng component ở các chương sau.

---

## 2.1 Mục Tiêu Thiết Kế

Windows NT được thiết kế với các mục tiêu:

| Mục tiêu | Cách thực hiện |
|-----------|----------------|
| **Portability** | HAL layer tách biệt hardware-specific code |
| **Security** | Object-based security, access tokens, ACLs |
| **Compatibility** | Subsystem architecture (Win32, POSIX, OS/2) |
| **Scalability** | SMP support, fine-grained kernel locking |
| **Extensibility** | Layered driver model, loadable subsystems |
| **Reliability** | Protected memory, structured exception handling |
| **Performance** | Hybrid kernel (không phải pure microkernel) |

### 2.1.1 Hybrid Kernel — Không Phải Microkernel

Windows thường bị gọi nhầm là microkernel. Thực tế nó là **hybrid kernel**:

```
Pure Microkernel (Minix, QNX):
┌────────────────────────────────────────┐
│ User Mode: File System, Network,       │
│            Drivers, Memory Manager     │
├────────────────────────────────────────┤
│ Kernel: IPC, Scheduling, Basic VMM     │  ← Rất nhỏ
└────────────────────────────────────────┘

Monolithic (Linux):
┌────────────────────────────────────────┐
│ Kernel: Tất cả — FS, Network, Drivers,│
│         Memory, Scheduling, ...        │  ← Rất lớn
├────────────────────────────────────────┤
│ User Mode: Applications               │
└────────────────────────────────────────┘

Hybrid (Windows):
┌────────────────────────────────────────┐
│ User Mode: Subsystems, Applications    │
├────────────────────────────────────────┤
│ Executive: I/O Manager, Object Manager,│
│            Memory Manager, Security,   │
│            Process Manager, ...        │  ← Trong kernel mode
│ Kernel: Scheduling, Interrupt dispatch,│
│         Synchronization primitives     │
│ Drivers: File systems, Network stack,  │
│          Device drivers                │
│ HAL: Hardware abstraction              │
└────────────────────────────────────────┘
```

Ban đầu NT có design gần microkernel hơn (graphics subsystem ở user mode), nhưng từ NT 4.0, Window Manager và GDI được chuyển vào kernel mode vì lý do performance.

---

## 2.2 Kiến Trúc Tổng Quan

```
╔══════════════════════════════════════════════════════════════════╗
║                        USER MODE                                ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐   ║
║  │  Win32   │ │  UWP     │ │  .NET    │ │  Subsystem       │   ║
║  │  Apps    │ │  Apps    │ │  Apps    │ │  Processes        │   ║
║  └────┬─────┘ └────┬─────┘ └────┬─────┘ │  csrss.exe       │   ║
║       │            │            │        │  smss.exe        │   ║
║       ▼            ▼            ▼        └──────────────────┘   ║
║  ┌──────────────────────────────────────────┐                   ║
║  │  Subsystem DLLs                          │                   ║
║  │  kernel32.dll, user32.dll, gdi32.dll,    │                   ║
║  │  advapi32.dll, combase.dll, ...          │                   ║
║  └────────────────┬─────────────────────────┘                   ║
║                   ▼                                              ║
║  ┌──────────────────────────────────────────┐                   ║
║  │  ntdll.dll (Native API + Runtime)        │                   ║
║  └────────────────┬─────────────────────────┘                   ║
║                   │ syscall                                      ║
╠═══════════════════╪══════════════════════════════════════════════╣
║                   │         KERNEL MODE                          ║
╠═══════════════════╪══════════════════════════════════════════════╣
║                   ▼                                              ║
║  ┌──────────────────────────────────────────────────────────┐   ║
║  │                    EXECUTIVE                              │   ║
║  │  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌──────────┐ │   ║
║  │  │ I/O Mgr   │ │ Object    │ │ Memory    │ │ Process  │ │   ║
║  │  │           │ │ Manager   │ │ Manager   │ │ Manager  │ │   ║
║  │  └───────────┘ └───────────┘ └───────────┘ └──────────┘ │   ║
║  │  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌──────────┐ │   ║
║  │  │ Security  │ │ Cache     │ │ Config    │ │ PnP      │ │   ║
║  │  │ Ref Mon   │ │ Manager   │ │ Manager   │ │ Manager  │ │   ║
║  │  └───────────┘ └───────────┘ └───────────┘ └──────────┘ │   ║
║  │  ┌───────────┐ ┌───────────┐ ┌───────────────────────┐  │   ║
║  │  │ Power     │ │ ALPC      │ │ Executive Runtime     │  │   ║
║  │  │ Manager   │ │           │ │ (Ex*, Rtl*, ...)      │  │   ║
║  │  └───────────┘ └───────────┘ └───────────────────────┘  │   ║
║  └──────────────────────┬───────────────────────────────────┘   ║
║                         │                                        ║
║  ┌──────────────────────┴───────────────────────────────────┐   ║
║  │                      KERNEL                               │   ║
║  │  Thread scheduling, Interrupt/Exception dispatching,      │   ║
║  │  Synchronization primitives, Timer management             │   ║
║  └──────────────────────┬───────────────────────────────────┘   ║
║                         │                                        ║
║  ┌──────────────────────┴───────────────────────────────────┐   ║
║  │  DEVICE DRIVERS                                           │   ║
║  │  File systems, Network, Storage, Display, USB, ...        │   ║
║  └──────────────────────┬───────────────────────────────────┘   ║
║                         │                                        ║
║  ┌──────────────────────┴───────────────────────────────────┐   ║
║  │  HAL (Hardware Abstraction Layer)                         │   ║
║  │  Interrupt controllers, Timers, DMA, BIOS interface       │   ║
║  └──────────────────────┬───────────────────────────────────┘   ║
╠═══════════════════════════════════════════════════════════════════╣
║                     HYPERVISOR (Hyper-V)                         ║
║  VTL management, Second-Level Address Translation (SLAT),       ║
║  Virtual processor scheduling, Intercept handling               ║
╠═══════════════════════════════════════════════════════════════════╣
║                        HARDWARE                                  ║
║  CPU, RAM, Storage, Network, GPU, TPM, ...                      ║
╚══════════════════════════════════════════════════════════════════╝
```

---

## 2.3 Portability

### 2.3.1 Hardware Abstraction Layer (HAL)

HAL (`hal.dll`) là lớp thấp nhất của kernel mode, tách biệt hardware differences:

**Chức năng HAL:**

| Chức năng | API ví dụ |
|-----------|-----------|
| Interrupt controller | `HalRequestSoftwareInterrupt()`, `HalEndSystemInterrupt()` |
| Timer/Clock | `HalQueryPerformanceCounter()` |
| Spinlock support | `KeAcquireSpinLock()` (dùng HAL internally) |
| DMA operations | `HalAllocateCommonBuffer()` |
| Bus access | `HalTranslateBusAddress()` |
| BIOS interface | `HalCallBios()` (legacy) |
| System reset | `HalReturnToFirmware()` |

**[UPDATE 2026]** Trên Windows 10 build 2004+, HAL được compile trực tiếp vào `ntoskrnl.exe` (linked statically). File `hal.dll` vẫn tồn tại trên disk nhưng chỉ là stub để tương thích. Điều này cải thiện performance bằng cách loại bỏ indirection.

**Các biến thể HAL:**

Trước đây Windows có nhiều HAL variants (ACPI multiprocessor, ACPI uniprocessor, ...). Hiện tại chỉ còn một HAL duy nhất trên mỗi architecture:

| Architecture | HAL |
|--------------|-----|
| x64 | `hal.dll` (ACPI, single variant) |
| ARM64 | `hal.dll` (ARM-specific) |

### 2.3.2 Supported Architectures

| Architecture | Status | Từ phiên bản |
|--------------|--------|-------------|
| x86 (IA-32) | Legacy (không còn trong Win11) | NT 3.1 |
| x64 (AMD64) | Primary | XP x64 Edition |
| ARM64 (AArch64) | Growing | Windows 10 1709 |
| IA-64 (Itanium) | Dropped | XP → Server 2008 R2 |
| Alpha, MIPS, PowerPC | Dropped | NT 3.x-4.0 |

**[UPDATE 2026]** Windows 11 24H2 không hỗ trợ x86 (32-bit) nữa. Chỉ x64 và ARM64.

---

## 2.4 Symmetric Multiprocessing (SMP)

Windows dùng SMP — bất kỳ thread nào có thể chạy trên bất kỳ CPU nào:

```
CPU 0          CPU 1          CPU 2          CPU 3
  │              │              │              │
  ▼              ▼              ▼              ▼
┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
│ Thread A │ │ Thread B │ │ Thread C │ │ Idle     │
└──────────┘ └──────────┘ └──────────┘ └──────────┘
       │              │              │              │
       └──────────────┴──────────────┴──────────────┘
                              │
                     Shared Memory (RAM)
```

**Không dùng Master-Slave:**
- Kernel code chạy trên BẤT KỲ CPU nào (không có "master CPU")
- Mọi CPU đều có thể xử lý interrupts
- Fine-grained locking (spinlocks, push locks) bảo vệ shared data

**Scalability:**

| Feature | Mô tả |
|---------|--------|
| Per-processor structures | Mỗi CPU có KPCR, KPRCB, DPC queue, ready queue riêng |
| Per-processor lookaside lists | Giảm lock contention cho pool allocations |
| NUMA awareness | Scheduler và memory manager biết NUMA topology |
| Processor groups | Hỗ trợ >64 logical processors (group 0, 1, ...) |

**NUMA (Non-Uniform Memory Access):**

```
┌───────────────────────┐   ┌───────────────────────┐
│      NUMA Node 0       │   │      NUMA Node 1       │
│  ┌──────┐ ┌──────┐    │   │  ┌──────┐ ┌──────┐    │
│  │CPU 0 │ │CPU 1 │    │   │  │CPU 2 │ │CPU 3 │    │
│  └──────┘ └──────┘    │   │  └──────┘ └──────┘    │
│  ┌──────────────────┐  │   │  ┌──────────────────┐  │
│  │  Local Memory    │  │   │  │  Local Memory    │  │
│  │  (fast access)   │  │   │  │  (fast access)   │  │
│  └──────────────────┘  │   │  └──────────────────┘  │
└───────────┬───────────┘   └───────────┬───────────┘
            │       Interconnect         │
            └───────────────────────────┘
                 (slower cross-node access)
```

Windows Memory Manager ưu tiên allocate memory từ local NUMA node của thread đang chạy.

---

## 2.5 Sự Khác Biệt Client vs Server

Cùng kernel codebase (`ntoskrnl.exe`), nhưng behavior khác nhau dựa trên product type:

```
Registry: HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions
  ProductType: WinNT (client) | ServerNT (server) | LanmanNT (DC)
```

**API kiểm tra:**
```c
BOOL isServer;
IsOS(OS_ANYSERVER);  // từ shlwapi.dll

// Hoặc kernel mode:
MmIsThisAnNtAsSystem()  // TRUE nếu server
```

**Khác biệt chính:**

| Tính năng | Client (Win 11) | Server (2025) |
|-----------|-----------------|----------------|
| Default quantum | Short (biến thiên, tốt cho interactive) | Long (fixed, tốt cho throughput) |
| Foreground priority boost | Có (boost foreground app) | Không |
| Default scheduling | Favor foreground app | Equal scheduling |
| Memory pool sizes | Nhỏ hơn (tuned for desktop) | Lớn hơn |
| System cache size | Nhỏ hơn | Lớn hơn (tuned for file server) |
| Max physical memory | Giới hạn theo edition | Lên đến 48 TB |
| Max CPUs | 128 (2 groups) | 2048 (32 groups) |
| Simultaneous TCP connections | Giới hạn inbound | Unlimited |
| Simultaneous RDP sessions | 1-2 | Unlimited (với RDS CALs) |

---

## 2.6 Các Component Chính Chi Tiết

### 2.6.1 Executive

Executive là phần lớn nhất của `ntoskrnl.exe`, chứa các subsystem managers:

#### I/O Manager

Quản lý toàn bộ hệ thống I/O:
- Nhận I/O requests từ user mode
- Tạo IRP (I/O Request Packet)
- Route IRP xuống driver stack
- Quản lý I/O completion

```
Application → NtReadFile() → I/O Manager
    → Create IRP
    → IoCallDriver() → FileSystem Driver
                        → Storage Driver
                        → Disk Driver
                        → Hardware
    ← IoCompleteRequest()
    ← Return data to application
```

#### Object Manager

Quản lý tất cả kernel objects:
- Tạo/xóa objects
- Quản lý object namespace (`\Device`, `\BaseNamedObjects`, ...)
- Handle management
- Reference counting
- Security (access checks khi mở handle)

#### Memory Manager

Quản lý virtual và physical memory:
- Virtual address space management
- Page fault handling
- Working set management (per-process và system)
- Section objects (memory-mapped files)
- Page file management
- Modified/standby page lists

#### Process Manager

Quản lý process và thread lifecycle:
- `PspCreateProcess()` — tạo process
- `PspCreateThread()` — tạo thread
- Process/thread termination
- Job object management

#### Security Reference Monitor (SRM)

Thực thi security policy:
- Access check (`SeAccessCheck()`)
- Privilege check (`SeSinglePrivilegeCheck()`)
- Token management
- Audit generation

#### Configuration Manager

Quản lý registry:
- Load/unload hives
- Registry cell allocation
- Key/value operations
- Registry notifications
- Transaction support (KTM)

#### Cache Manager

Cache file system data:
- Unified cache cho mọi file systems
- Lazy write
- Read-ahead
- Memory-mapped interface với Memory Manager

#### Plug and Play (PnP) Manager

Quản lý device enumeration và driver loading:
- Device tree management
- Driver loading/unloading
- Resource arbitration (IRQ, memory, I/O ports)
- Power management coordination

#### Power Manager

Quản lý power state:
- System power states (S0-S5)
- Device power states (D0-D3)
- Connected Standby / Modern Standby
- Power requests từ drivers và applications

#### Ntoskrnl.exe Export Prefixes — Bản Đồ Hệ Thống

Hiểu prefix giúp xác định ngay function thuộc component nào:

| Prefix | Component | Ví dụ |
|--------|-----------|-------|
| `Ex` | Executive Support | `ExAllocatePool2`, `ExAcquirePushLockExclusive` |
| `Ke` | Kernel (exported) | `KeInitializeEvent`, `KeWaitForSingleObject` |
| `Ki` | Kernel (internal) | `KiSystemCall64`, `KiDispatchInterrupt` |
| `Ob` | Object Manager | `ObReferenceObjectByHandle`, `ObOpenObjectByName` |
| `Mm` | Memory Manager | `MmMapLockedPagesSpecifyCache`, `MmGetPhysicalAddress` |
| `Io` | I/O Manager | `IoCreateDevice`, `IoCallDriver`, `IoCompleteRequest` |
| `Se` | Security Reference Monitor | `SeAccessCheck`, `SeSinglePrivilegeCheck` |
| `Ps` | Process/Thread Manager | `PsCreateSystemThread`, `PsLookupProcessByProcessId` |
| `Cm` | Configuration Manager (Registry) | `CmRegisterCallbackEx` |
| `Cc` | Cache Manager | `CcCopyRead`, `CcFlushCache` |
| `Pp`/`Pnp` | PnP Manager | `PnpCallDriverEntry` |
| `Po` | Power Manager | `PoRequestPowerIrp`, `PoStartNextPowerIrp` |
| `Rtl` | Runtime Library | `RtlInitUnicodeString`, `RtlCopyMemory` |
| `Nt` | Native API (exported to user) | `NtCreateFile`, `NtOpenProcess` |
| `Zw` | Native API (kernel caller wrapper) | `ZwCreateFile` (forces KernelMode) |
| `Hal` | HAL functions | `HalRequestSoftwareInterrupt` |
| `Wdi`/`Wdf` | WDF framework | `WdfDriverCreate` |
| `Flt` | Filter Manager | `FltRegisterFilter`, `FltStartFiltering` |
| `Fs`/`FsRtl` | File System Runtime Library | `FsRtlIsNameInExpression` |
| `Etw` | Event Tracing | `EtwWrite`, `EtwRegister` |
| `Tm`/`Ktm` | Kernel Transaction Manager | `TmCreateTransaction` |
| `Wmi` | WMI support | `WmiTraceMessage` |
| `Dbgk` | Debug framework | `DbgkCreateThread` |

```
;; WinDbg — xem tất cả exports theo prefix:
kd> x nt!Ob*                ; Object Manager functions
kd> x nt!Se*                ; Security functions  
kd> x nt!Ps*                ; Process/Thread functions
kd> x nt!Mm*                ; Memory Manager functions
kd> x nt!Io*                ; I/O Manager functions
kd> x nt!Cm*                ; Config Manager (Registry) functions
kd> x nt!Cc*                ; Cache Manager functions
```

#### System Service Descriptor Table (SSDT)

```
SSDT là bảng mapping syscall numbers → kernel function addresses:

KeServiceDescriptorTable (ntoskrnl syscalls):
┌──────────────────────────────────────────────────┐
│ ServiceTable:       → KiServiceTable             │
│ CounterTable:       → (NULL on retail, used for  │
│                       profiling on checked)      │
│ NumberOfServices:   → ~470 entries (varies by    │
│                       Windows version)           │
│ ArgumentTable:      → KiArgumentTable            │
│                       (bytes of stack args per   │
│                       syscall)                   │
└──────────────────────────────────────────────────┘

KeServiceDescriptorTableShadow (includes win32k syscalls):
┌──────────────────────────────────────────────────┐
│ [0] ntoskrnl entry (same as above)               │
│ [1] win32k entry:                                │
│     ServiceTable: → W32pServiceTable             │
│     NumberOfServices: ~1200+ entries              │
│     (GUI syscalls: NtUser*, NtGdi*)              │
└──────────────────────────────────────────────────┘

Trên x64, entries dùng relative offsets (compact encoding):
  KiServiceTable[i] = 4-byte signed value
  Real address = KiServiceTable + (entry >> 4)
  Bit 0-3 = number of parameters passed on stack

Security implication:
  SSDT hooking (rootkit technique):
    ✗ Blocked bởi PatchGuard (KPP) trên x64
    ✗ Blocked bởi HVCI (VTL 1 prevents code modification)
    ✓ Vẫn khả thi nếu disable PatchGuard (nhưng HVCI chặn)
  Alternative: Kernel callbacks (ObRegisterCallbacks,
    PsSetCreateProcessNotifyRoutineEx, CmRegisterCallbackEx)
    → Documented, supported, không bị PatchGuard chặn
```

```
;; WinDbg — Xem SSDT:
kd> dps nt!KeServiceDescriptorTable L4
kd> dd nt!KiServiceTable L20                ; First 32 entries
kd> ? poi(nt!KeServiceDescriptorTable+10)   ; Number of services

;; Decode entry N:
kd> r $t0 = poi(nt!KeServiceDescriptorTable)  ; KiServiceTable base
kd> r $t1 = dwo(@$t0 + N*4)                   ; Entry N (raw)
kd> ? @$t0 + (@$t1 >> 4)                      ; Resolved address
kd> ln @$t0 + (@$t1 >> 4)                     ; Symbol name

;; Win32k SSDT (shadow table):
kd> dps nt!KeServiceDescriptorTableShadow+20 L4
```

### 2.6.2 Kernel

Phần "Kernel" trong `ntoskrnl.exe` (prefix `Ki`, `Ke`) cung cấp cơ chế cơ bản:

| Chức năng | Mô tả |
|-----------|--------|
| Thread scheduling | Dispatcher, ready queues, quantum management |
| Interrupt dispatching | IDT, IRQL, ISR chaining |
| Exception dispatching | SEH, unhandled exception processing |
| DPC (Deferred Procedure Call) | Deferred work at DISPATCH_LEVEL |
| Timer management | System clock, timer expiration |
| Synchronization | Dispatcher objects (events, mutexes, semaphores) |
| APC (Asynchronous Procedure Call) | User-mode và kernel-mode APCs |

**Phân biệt Executive vs Kernel:**

| Executive | Kernel |
|-----------|--------|
| Policy (what to do) | Mechanism (how to do it) |
| Object Manager quyết định access rights | Kernel implements synchronization primitives |
| Process Manager quyết định process creation steps | Kernel implements context switching |
| Complex objects (processes, files) | Simple objects (events, mutexes) |

### 2.6.3 Device Drivers

```
┌──────────────────────────────────────────────────────────┐
│                    Driver Types                           │
├────────────────┬─────────────────────────────────────────┤
│ WDM Drivers    │ Legacy driver model, vẫn supported      │
│ WDF Drivers    │ Windows Driver Framework (KMDF / UMDF)  │
│ File System    │ NTFS, ReFS, FAT, exFAT                  │
│ File System    │ Mini-filters (antivirus, encryption)     │
│   Minifilters  │                                         │
│ Network        │ NDIS miniport, protocol, filter drivers  │
│ Storage        │ Storport miniport drivers                │
│ Display        │ WDDM display miniport drivers            │
│ Software       │ Kernel extensions (không có hardware)     │
│ Bus Drivers    │ PCI, USB, ACPI bus enumeration            │
└────────────────┴─────────────────────────────────────────┘
```

**Driver stack (ví dụ disk I/O):**

```
                    I/O Manager
                        │
                ┌───────▼───────┐
                │ NTFS.sys       │  File System Driver
                │ (Function)     │
                └───────┬───────┘
                        │
                ┌───────▼───────┐
                │ VolMgr/VolSnap │  Volume Manager
                │ (Filter)       │
                └───────┬───────┘
                        │
                ┌───────▼───────┐
                │ Disk.sys       │  Disk Class Driver
                │ (Function)     │
                └───────┬───────┘
                        │
                ┌───────▼───────┐
                │ Storport.sys   │  Storage Port Driver
                │ + Miniport     │
                └───────┬───────┘
                        │
                    Hardware
```

**KMDF vs UMDF:**

| Feature | KMDF | UMDF |
|---------|------|------|
| Runs in | Kernel mode | User mode (host process) |
| Crash impact | BSOD | Process crash, auto-restart |
| Performance | Fastest | Slight overhead |
| Hardware access | Direct | Via kernel proxy |
| Use case | Performance-critical, low-level | USB, sensors, cameras |

**[UPDATE 2026]** UMDF 2.x API gần giống KMDF, giúp port driver giữa hai frameworks dễ dàng.

### 2.6.4 Ntdll.dll — Cầu Nối User-Kernel

`ntdll.dll` là DLL đặc biệt nhất — nó được load vào MỌI process (kể cả native processes):

**Các vai trò:**

| Component | Chức năng |
|-----------|-----------|
| System call stubs | `Nt*` / `Zw*` functions → `syscall` instruction |
| Image loader (Ldr*) | Load DLLs, resolve imports, TLS initialization |
| Heap manager | `RtlAllocateHeap()`, `RtlFreeHeap()` |
| User-mode runtime | `Rtl*` functions (string, bitmap, AVL tree, ...) |
| Thread startup | `LdrInitializeThunk()` → entry point |
| Exception handling | SEH dispatcher (`KiUserExceptionDispatcher`) |
| APC dispatcher | `KiUserApcDispatcher` |
| CSR client | Communication với csrss.exe |
| ETW support | User-mode ETW logging |

### 2.6.5 Subsystem DLLs

Subsystem DLLs translate API sets thành Native API calls:

```
CreateFileW() [kernel32.dll]
  → Mở file? → NtCreateFile()
  → Console? → Console server call (conhost)
  → Convert Win32 flags → NT flags
  
RegOpenKeyExW() [advapi32.dll]
  → NtOpenKey()
  → Convert HKEY_* → \Registry\... path
  
CreateWindowExW() [user32.dll]
  → NtUserCreateWindowEx() (win32k.sys system call)
```

**[UPDATE 2026]** API Sets — Windows 10+ dùng "API sets" để decouple API từ DLL implementation:

```
api-ms-win-core-file-l1-1-0.dll → kernelbase.dll (thật sự)
api-ms-win-core-processthreads-l1-1-0.dll → kernelbase.dll

Mapping nằm trong: apisetschema.dll (data-only DLL, loaded vào mọi process)
```

### 2.6.6 Environment Subsystems

#### Windows Subsystem (csrss.exe + win32k.sys)

Subsystem chính và duy nhất còn tồn tại:

**csrss.exe** (Client-Server Runtime SubSystem):
- Chạy 1 instance per session
- Console window management (chia sẻ với conhost.exe)
- Process/thread creation/termination notification
- Side-by-side (SxS/WinSxS) support
- Shutdown management

**win32k.sys** (Windows Subsystem kernel-mode component):
- Window Manager (USER)
- Graphics Device Interface (GDI)
- DirectComposition
- Desktop Window Manager (DWM) support
- System call table riêng (KeServiceDescriptorTableShadow)

**win32k.sys chi tiết:**

```
win32k.sys là kernel-mode component lớn nhất sau ntoskrnl.exe:

┌────────────────────────────────────────────────────────┐
│ win32k.sys (Windows Subsystem Kernel Driver)            │
│                                                        │
│  ┌─────────────────────────────────────────────┐       │
│  │ Window Manager (USER)                        │       │
│  │ ├── Window creation/destruction              │       │
│  │ ├── Message queues (per-thread)              │       │
│  │ ├── Window messaging (SendMessage/PostMessage)│      │
│  │ ├── Input processing (keyboard/mouse)        │       │
│  │ ├── Hit testing, window positioning          │       │
│  │ ├── Menus, scrollbars, carets, cursors       │       │
│  │ ├── Clipboard management                     │       │
│  │ ├── Hooks (SetWindowsHookEx)                 │       │
│  │ ├── Desktop/Window Station management        │       │
│  │ └── DWM integration (DirectComposition)      │       │
│  ├─────────────────────────────────────────────┤       │
│  │ Graphics Device Interface (GDI)              │       │
│  │ ├── Device contexts (HDC)                    │       │
│  │ ├── GDI objects (pens, brushes, fonts, bitmaps)│    │
│  │ ├── Drawing operations                       │       │
│  │ ├── Region management                        │       │
│  │ └── Printer support                          │       │
│  ├─────────────────────────────────────────────┤       │
│  │ DirectComposition                            │       │
│  │ ├── Visual tree management                   │       │
│  │ ├── Animation support                        │       │
│  │ └── Composition with DWM                     │       │
│  └─────────────────────────────────────────────┘       │
│                                                        │
│  Syscall table: W32pServiceTable                       │
│  → NtUserCreateWindowEx, NtUserDestroyWindow, ...      │
│  → NtGdiCreateDC, NtGdiSelectObject, ...               │
│  → ~1200 syscalls (separate from ntoskrnl SSDT)        │
└────────────────────────────────────────────────────────┘
```

**[UPDATE 2026]** win32k.sys đã được modular hóa:
```
win32kfull.sys  — Full window manager (interactive sessions)
win32kmin.sys   — Minimal (non-interactive sessions like containers)
win32kbase.sys  — Shared base code
win32k.sys      — Loader/dispatcher

→ Session 0 (services) load win32kmin.sys = nhỏ hơn, ít attack surface
→ Interactive sessions load win32kfull.sys = đầy đủ
→ Container silos chỉ cần win32kmin.sys hoặc không cần win32k
```

**Security implication — win32k attack surface:**
```
win32k.sys historically là nguồn vulnerabilities lớn nhất:
  - Complex syscall surface (~1200 syscalls)
  - Parse untrusted data (fonts, images)
  - Callback mechanism cho user-mode hooks
  - GDI object management (use-after-free, pool corruption)

Mitigations:
  - Win32k System Call Disable Policy: block win32k syscalls cho
    non-GUI processes (Edge browser, sandboxed processes)
  - ProcessSystemCallDisablePolicy = 0x1 → disable win32k
  - Kernel pool hardening (pool NX, randomization)
  - win32kmin.sys reduces surface for Session 0
```

#### Windows Subsystem for Linux (WSL)

**[UPDATE 2026]** WSL đã trải qua 2 thế hệ:

| Feature | WSL 1 | WSL 2 |
|---------|-------|-------|
| Architecture | Pico processes + LxCore.sys | Hyper-V lightweight VM |
| Linux kernel | Syscall translation | Real Linux kernel |
| File system perf | Slow (translation) | Fast (ext4 native) |
| Windows interop | Direct (shared NT kernel) | Via 9P protocol |
| Networking | Shared with host | NAT (hoặc mirrored mode) |
| GPU support | Không | Có (GPU-PV) |
| systemd | Không | Có (từ 2022) |

WSL 2 chạy một Linux kernel thật trong lightweight Hyper-V VM:

```
Windows Host
├── Hyper-V Hypervisor
├── Windows Kernel (VTL 0)
├── WSL 2 VM
│   ├── Linux Kernel (Microsoft custom)
│   ├── /init (Microsoft init)
│   ├── Linux userspace (Ubuntu, Debian, ...)
│   └── 9P file server ←→ Windows file system
└── User applications
```

#### Windows Subsystem for Android (WSA)

**[UPDATE 2026]** WSA đã bị discontinued (tháng 3/2025). Nó dùng Hyper-V VM chạy Android runtime tương tự WSL 2.

---

## 2.7 System Processes

Các processes hệ thống quan trọng (chạy trước khi user logon):

### 2.7.1 Boot Sequence Processes

```
Thứ tự tạo:

1. System (PID 4)           ← Kernel process, host system threads
2. Secure System            ← [VBS] VTL 1 secure kernel process
3. Registry                 ← Registry worker process
4. smss.exe                 ← Session Manager Subsystem
5. csrss.exe (Session 0)    ← Windows Subsystem (services session)
6. wininit.exe              ← Windows Initialization
7. csrss.exe (Session 1)    ← Windows Subsystem (user session)
8. winlogon.exe             ← Logon process
9. services.exe             ← Service Control Manager
10. lsass.exe               ← Local Security Authority
11. svchost.exe (nhiều)     ← Service host processes
12. ...
```

### 2.7.2 Chi Tiết Từng Process

#### System Process (PID 4)

- Luôn có PID 4 (hardcoded)
- Kernel threads chạy trong context process này
- Không có user-mode address space thật (chỉ kernel space)
- Mọi kernel-mode system threads thuộc process này

```
kd> !process 4 0
PROCESS ffffxxxx...
    SessionId: none
    Image: System
    ...threads...
```

#### smss.exe — Session Manager

- Process **native** đầu tiên chạy (dùng trực tiếp Native API, không qua Win32)
- Khởi tạo system:
  - Load subsystems (`\Registry\Machine\System\CurrentControlSet\Control\Session Manager\SubSystems`)
  - Tạo environment variables hệ thống
  - Khởi chạy `autochk.exe` (disk check) nếu cần
  - Tạo Session 0 và Session 1
  - Launch `csrss.exe` và `wininit.exe` (Session 0) / `winlogon.exe` (Session 1)
- Sau khi khởi tạo xong, SMSS chính trở thành master SMSS
- Mỗi session mới tạo một child SMSS instance

#### csrss.exe — Client-Server Runtime

- Critical process — nếu crash → BSOD
- 1 instance per session
- Chức năng chính:
  - Console hosting (phối hợp với conhost.exe)
  - Process/thread create/delete notification
  - Win32 shutdown handling
  - Các legacy subsystem functions

#### wininit.exe — Windows Initialization (Session 0)

Khởi chạy:
- `services.exe` (Service Control Manager)
- `lsass.exe` (Local Security Authority)
- `lsaiso.exe` (Credential Guard — nếu VBS enabled)

#### winlogon.exe — Logon Process (Session 1+)

- Xử lý Secure Attention Sequence (Ctrl+Alt+Delete)
- Load user profile
- Khởi chạy user shell (explorer.exe)
- Handle logoff/lock/unlock

#### services.exe — Service Control Manager (SCM)

- Quản lý Windows services
- Load services theo configuration trong `HKLM\SYSTEM\CurrentControlSet\Services`
- Dependency management
- Service failure recovery (restart, run program, reboot)

#### lsass.exe — Local Security Authority Subsystem

- Authentication (validate credentials)
- Security policy enforcement
- Token creation
- Audit log generation
- **Target ưa thích của attackers** — credential dumping (mimikatz)

**[UPDATE 2026]** Protection:
- **Credential Guard**: Isolate secrets trong VTL 1 (`lsaiso.exe`)
- **LSA Protection**: `lsass.exe` chạy as PPL (Protected Process Light)
- **RunAsPPL**: Registry `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1`

#### svchost.exe — Service Host

- Host cho các services chạy trong DLLs (thay vì standalone .exe)
- Mỗi instance host 1+ services
- **[UPDATE 2026]** Từ Windows 10 1703 (trên máy >3.5GB RAM), mỗi service có svchost riêng (service splitting)

```cmd
:: Xem services trong mỗi svchost
tasklist /svc /fi "imagename eq svchost.exe"

:: Hoặc PowerShell
Get-WmiObject Win32_Service | Where-Object {$_.ProcessId -in (Get-Process svchost).Id} |
    Select-Object ProcessId, Name, DisplayName | Sort-Object ProcessId
```

---

## 2.8 Kernel-Mode System Threads

System threads chạy trong context System process (PID 4):

| Thread | Chức năng |
|--------|-----------|
| Balance Set Manager | Quản lý working sets, aging |
| Memory Manager worker | Background page writing, trimming |
| Cache Manager lazy writer | Flush dirty cache pages |
| Modified Page Writer | Write modified pages to pagefile |
| Mapped Page Writer | Write modified mapped file pages |
| Zero Page Thread | Zero-fill free pages (background) |
| Power Manager threads | Power state transitions |
| PnP Manager threads | Device enumeration |

---

## 2.9 Virtualization-Based Security (VBS) Architecture

**[UPDATE 2026]** VBS là kiến trúc bảo mật quan trọng nhất của Windows hiện đại.

### 2.9.1 Tổng Quan

```
┌────────────────────────────────────────────────────────┐
│                    VTL 1 (Secure World)                 │
│  ┌──────────────┐  ┌──────────────────────────────┐   │
│  │ Secure Kernel │  │ Trustlets (IUM processes)     │   │
│  │ (SK)          │  │ - lsaiso.exe (Cred Guard)    │   │
│  │               │  │ - hvloader.exe               │   │
│  │               │  │ - vmsp.exe                   │   │
│  └──────────────┘  └──────────────────────────────┘   │
├────────────────────────────────────────────────────────┤
│                    VTL 0 (Normal World)                 │
│  ┌──────────────────────────────────────────────────┐  │
│  │ Windows Kernel (ntoskrnl.exe)                     │  │
│  │ Drivers, Services, Applications                   │  │
│  └──────────────────────────────────────────────────┘  │
├────────────────────────────────────────────────────────┤
│              Hyper-V Hypervisor                         │
│  Manages VTL transitions, SLAT, intercepts             │
├────────────────────────────────────────────────────────┤
│                    Hardware                             │
│  CPU (VT-x/AMD-V + SLAT), TPM 2.0, IOMMU             │
└────────────────────────────────────────────────────────┘
```

### 2.9.2 VBS Features

**Credential Guard:**
- NTLM hashes, Kerberos TGTs lưu trong VTL 1
- Ngay cả kernel compromise ở VTL 0 cũng không lấy được credentials
- `lsaiso.exe` (LSA Isolated) chạy như Trustlet trong VTL 1

**HVCI (Hypervisor-protected Code Integrity):**
- Kernel mode code phải được signed
- Ngăn load unsigned drivers
- W^X enforcement: memory pages không thể vừa writable vừa executable
- Page table modifications bị hypervisor kiểm soát

**Secure Launch (DRTM — Dynamic Root of Trust for Measurement):**
- Dùng Intel TXT hoặc AMD Skinit
- Verify boot chain integrity sau khi firmware khởi động
- Đo (measure) mọi thứ load vào kernel

**Kernel DMA Protection:**
- Dùng IOMMU (VT-d / AMD-Vi)
- Block DMA attacks qua Thunderbolt/PCIe
- External devices không thể đọc/ghi arbitrary kernel memory

---

## 2.10 Driver Loading Deep Dive

### 2.10.1 Driver Registration

```
Drivers được đăng ký tại:
  HKLM\SYSTEM\CurrentControlSet\Services\<DriverName>

Key values:
  Type         = SERVICE_KERNEL_DRIVER (1) hoặc SERVICE_FILE_SYSTEM_DRIVER (2)
  Start        = Boot(0), System(1), Auto(2), Demand(3), Disabled(4)
  ErrorControl = Ignore(0), Normal(1), Severe(2), Critical(3)
  ImagePath    = \SystemRoot\System32\drivers\mydriver.sys
  Group        = Boot Bus Extender, System Bus Extender, SCSI miniport, ...
  Tag          = Load order within group
  DependOnService = Dependencies
```

### 2.10.2 Driver Loading Process

```
Boot drivers (Start=0):
  winload.efi loads them TRƯỚC khi kernel chạy
  → Mapped vào memory → kernel calls DriverEntry() at Phase 0
  → Critical cho boot: disk, filesystem, encryption (BitLocker)

System drivers (Start=1):
  Loaded bởi I/O Manager tại kernel initialization Phase 1
  → PnP enumeration → match driver → IoLoadDriver()

Auto-start drivers (Start=2):
  Loaded bởi PnP Manager sau khi system initialization
  → Có thể bị delay nếu dependency chưa sẵn sàng

On-demand drivers (Start=3):
  Loaded khi requested (sc start, device insertion)

Load flow:
  1. MmLoadSystemImage() — map PE file vào kernel space
  2. Verify digital signature (CI.dll — Code Integrity)
  3. HVCI check — if enabled, pages must be WHQL/attestation signed
  4. Initialize DRIVER_OBJECT structure
  5. Call DriverEntry(DriverObject, RegistryPath)
  6. Driver registers dispatch routines via DriverObject->MajorFunction[]
  7. Driver creates device objects (IoCreateDevice)
  8. Driver attaches to device stack (IoAttachDeviceToDeviceStack)
```

### 2.10.3 Driver Object Structure

```
_DRIVER_OBJECT:
├── Type                    = IO_TYPE_DRIVER (4)
├── Size                    = sizeof(DRIVER_OBJECT)  
├── DeviceObject            → First device object in chain
├── Flags
├── DriverStart             → Base address in kernel memory
├── DriverSize              → Size of loaded image
├── DriverSection           → Pointer to LDR_DATA_TABLE_ENTRY
├── DriverExtension         → Additional info
│   └── AddDevice           → PnP AddDevice routine
├── DriverName              → UNICODE_STRING "\Driver\MyDriver"
├── HardwareDatabase        → Registry hardware path
├── FastIoDispatch          → Fast I/O function table
├── DriverInit              → DriverEntry address
├── DriverStartIo           → StartIo routine (for serialized I/O)
├── DriverUnload            → Unload routine (NULL = cannot unload)
└── MajorFunction[28]       → IRP dispatch table
    ├── [IRP_MJ_CREATE]      = 0x00  → Open handle
    ├── [IRP_MJ_CLOSE]       = 0x02  → Close handle
    ├── [IRP_MJ_READ]        = 0x03  → Read data
    ├── [IRP_MJ_WRITE]       = 0x04  → Write data
    ├── [IRP_MJ_DEVICE_CONTROL] = 0x0E → IOCTL
    ├── [IRP_MJ_INTERNAL_DEVICE_CONTROL] = 0x0F
    ├── [IRP_MJ_PNP]         = 0x1B  → PnP events
    ├── [IRP_MJ_POWER]       = 0x16  → Power events
    └── ... (28 major function codes total)
```

```
;; WinDbg — Inspect driver:
kd> !drvobj \Driver\NTFS 7          ; NTFS driver object + dispatch routines
kd> !drvobj \Driver\HTTP 2          ; HTTP.sys driver
kd> dt nt!_DRIVER_OBJECT <addr>     ; Raw structure dump
kd> !devobj <addr>                  ; Device object details
kd> !devstack <devobj>              ; Full device stack
kd> !devnode 0 1                    ; Device tree (PnP)

;; List all loaded drivers:
kd> lm t n                          ; All modules with timestamps
kd> !object \Driver                 ; Driver objects in namespace

;; Find unsigned/suspicious drivers:
kd> lm m mydriver                   ; Check if symbols available
;; Sigcheck -e -u C:\Windows\System32\drivers\*.sys  (Sysinternals)
```

---

## 2.11 OneCore và Windows Core OS

**[UPDATE 2026]** OneCore là initiative để thống nhất Windows kernel across devices:

```
OneCore Architecture:
┌─────────────────────────────────────────────────┐
│ Device-specific components                       │
│ (Desktop shell, HoloLens shell, Xbox shell, ...) │
├─────────────────────────────────────────────────┤
│ Universal Windows Platform (UWP/WinUI)           │
├─────────────────────────────────────────────────┤
│ OneCore — Shared OS component layer              │
│ ├── ntoskrnl.exe (same binary cross-device)      │
│ ├── Core services                                │
│ ├── Networking stack                             │
│ ├── Multimedia                                   │
│ └── API Sets (api-ms-win-*)                      │
├─────────────────────────────────────────────────┤
│ HAL (device-specific)                            │
├─────────────────────────────────────────────────┤
│ Hardware                                         │
└─────────────────────────────────────────────────┘

Devices sharing OneCore:
  - Windows Desktop (10/11)
  - Windows Server (2022/2025)
  - Xbox System OS
  - HoloLens 2
  - Windows IoT Core/Enterprise
  - Surface Hub
```

---

## 2.12 Checked Build (Debug Build)

**[UPDATE 2026]** Checked build đã bị loại bỏ từ Windows 10 1803. Thay thế bằng:

- **Driver Verifier**: `verifier.exe` — runtime checking cho drivers
- **Application Verifier**: `appverif.exe` — runtime checking cho apps
- **Kernel debugging**: luôn available trên retail builds
- **ETW tracing**: detailed tracing mà không cần debug build

---

## 2.13 Xem Thông Tin Hệ Thống

### Experiment 2.1: Kernel Modules

```
kd> lm                              ; List loaded kernel modules
kd> lm m nt                         ; ntoskrnl.exe details
kd> !lmi nt                         ; Detailed module info
kd> lm m hal                        ; HAL details
```

### Experiment 2.2: System Version

```
kd> vertarget                        ; OS version, build, service pack
kd> !version                         ; Detailed version info

# User mode
Get-ComputerInfo | Select Os*
[System.Environment]::OSVersion
```

### Experiment 2.3: Product Type

```
kd> dd nt!MmProductType L1          ; 1=WinNT, 3=ServerNT/LanmanNT
kd> db nt!NtBuildNumber L4          ; Build number
kd> !reg querykey \Registry\Machine\SYSTEM\CurrentControlSet\Control\ProductOptions
```

### Experiment 2.4: System Architecture Visualization

Dùng **Process Explorer**:
1. Mở Process Explorer as Administrator
2. View → Show Lower Pane → DLLs
3. Click vào process bất kỳ → xem chain:
   - ntdll.dll (luôn có)
   - kernel32.dll → kernelbase.dll (Win32 subsystem)
   - user32.dll + win32u.dll (nếu có GUI)
4. Options → Show processes from all users
5. Quan sát cây process: System → smss → csrss, wininit, winlogon → ...

---

## 2.14 Tóm Tắt

| Component | Vai trò |
|-----------|---------|
| HAL | Tách biệt hardware, giờ tích hợp vào ntoskrnl |
| Kernel (Ke/Ki) | Scheduling, interrupts, sync primitives |
| Executive (Ex, Io, Ob, Se, Mm, ...) | Policy managers — I/O, objects, security, memory |
| Drivers | Extend kernel — file systems, network, devices |
| ntdll.dll | User↔Kernel bridge, loader, runtime |
| Subsystem DLLs | Win32 API → Native API translation |
| csrss.exe | Windows subsystem process |
| smss.exe | Session manager — bootstrap |
| Hypervisor | VBS foundation, VTL isolation |

> **Tiếp theo: [Chapter 3 — Processes và Jobs](Chapter_03_Processes_and_Jobs.md)**
> Đi sâu vào cấu trúc process, protected processes, process creation flow.
