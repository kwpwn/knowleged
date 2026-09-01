# Chapter 1: Khái Niệm Nền Tảng và Công Cụ

> Chương này thiết lập nền tảng kiến thức cần thiết cho toàn bộ tài liệu.
> Mọi khái niệm ở đây sẽ được tham chiếu xuyên suốt các chương sau.

---

## 1.1 Lịch Sử Phiên Bản Windows

### 1.1.1 Dòng Windows NT

Windows NT (New Technology) được thiết kế từ đầu bởi Dave Cutler — người trước đó thiết kế VMS cho Digital Equipment Corporation (DEC). NT kernel được viết từ scratch, không dựa trên MS-DOS hay Windows 9x.

**Các mốc quan trọng:**

| Năm | Phiên bản | Điểm nổi bật |
|-----|-----------|-------------|
| 1993 | NT 3.1 | Phiên bản đầu tiên, microkernel hybrid |
| 1996 | NT 4.0 | Chuyển GDI/Window Manager vào kernel mode |
| 2000 | Windows 2000 | Active Directory, Plug and Play, WDM |
| 2001 | Windows XP | Hợp nhất dòng consumer (9x) và NT |
| 2003 | Server 2003 | Kernel cải tiến hiệu năng, DEP |
| 2006 | Vista | ASLR, UAC, WDDM, Integrity Levels |
| 2009 | Windows 7 | MinWin refactoring, kernel diet |
| 2012 | Windows 8 | WinRT, UEFI Secure Boot, Hyper-V integration |
| 2015 | Windows 10 | OneCore convergence, WSL |
| 2021 | Windows 11 | VBS yêu cầu TPM 2.0, Android subsystem |
| 2024 | Windows 11 24H2 | Sudo for Windows, Wi-Fi 7, Rust in kernel |

### 1.1.2 Mô Hình Phiên Bản Hiện Đại

**[UPDATE 2026]** Kể từ Windows 10, Microsoft chuyển sang mô hình "Windows as a Service" (WaaS):

- **Feature Updates**: phát hành hàng năm (trước đây 2 lần/năm)
- **Quality Updates**: vá lỗi hàng tháng (Patch Tuesday — thứ Ba thứ hai mỗi tháng)
- **Build numbers**: tăng liên tục, ví dụ 22631 (23H2), 26100 (24H2)

Cách xác định phiên bản từ kernel:

```
C:\> winver
C:\> ver
C:\> systeminfo | findstr /B /C:"OS"

# Trong WinDbg:
kd> vertarget
kd> !version
```

### 1.1.3 OneCore và Convergence

Từ Windows 10 trở đi, tất cả các nền tảng chia sẻ cùng một kernel codebase gọi là **OneCore**:

```
Desktop / Laptop     ─┐
Server               ─┤
Xbox One / Series X  ─┼── OneCore Kernel (ntoskrnl.exe)
HoloLens             ─┤
IoT                  ─┤
Surface Hub          ─┘
```

Sự khác biệt giữa các SKU (Stock Keeping Unit) nằm ở:
- **Edition-specific features**: được kiểm soát bằng registry và license keys
- **Component packages**: mỗi SKU chỉ cài các component cần thiết
- **API surface**: một số API chỉ available trên desktop, không có trên IoT

**[UPDATE 2026]** Windows Server 2025 và Windows 11 24H2 chia sẻ cùng kernel build 26100, chỉ khác configuration.

---

## 1.2 Các Khái Niệm Nền Tảng

### 1.2.1 Windows API

Windows API (trước đây gọi là Win32 API) là giao diện lập trình chính để tương tác với hệ điều hành. Đây là API ở user mode — nó KHÔNG phải giao diện trực tiếp với kernel.

**Kiến trúc phân lớp:**

```
┌─────────────────────────────────────────────────┐
│              Ứng dụng (Application)              │
├─────────────────────────────────────────────────┤
│         Windows API (Win32 / WinRT / .NET)       │  ← User mode
├─────────────────────────────────────────────────┤
│    Subsystem DLLs: kernel32.dll, user32.dll,     │
│    advapi32.dll, gdi32.dll, ws2_32.dll, ...      │
├─────────────────────────────────────────────────┤
│              ntdll.dll (Native API)              │
╞═════════════════════════════════════════════════╡
│         System Call Interface (syscall/int 2Eh)  │  ← Ranh giới kernel
├─────────────────────────────────────────────────┤
│         Executive / Kernel (ntoskrnl.exe)        │  ← Kernel mode
├─────────────────────────────────────────────────┤
│         HAL (hal.dll)                            │
├─────────────────────────────────────────────────┤
│                  Hardware                        │
└─────────────────────────────────────────────────┘
```

**Ví dụ chuỗi gọi khi tạo file:**

```
CreateFileW()           ← kernel32.dll (Windows API)
  → NtCreateFile()      ← ntdll.dll (Native API, user-mode stub)
    → syscall            ← CPU chuyển sang kernel mode
      → NtCreateFile()  ← ntoskrnl.exe (kernel-mode implementation)
        → IopCreateFile() → IoCallDriver() → Driver dispatch
```

**Các thư viện API chính:**

| DLL | Chức năng |
|-----|-----------|
| `kernel32.dll` | Process, thread, memory, file, console |
| `kernelbase.dll` | Implementation thật của nhiều API kernel32 (từ Win7+) |
| `ntdll.dll` | Native API stubs, NT runtime, loader |
| `user32.dll` | Window management, messages, input |
| `gdi32.dll` | Graphics Device Interface |
| `advapi32.dll` | Registry, security, services, crypto |
| `ws2_32.dll` | Winsock — networking |
| `sechost.dll` | Service control, ETW (từ Win7+) |
| `combase.dll` | COM runtime (từ Win8+) |

### 1.2.2 Native API

Native API là tập hợp các system calls thật sự của Windows kernel. Nó được export bởi `ntdll.dll` và **KHÔNG được documented chính thức** (undocumented hoặc semi-documented).

**Quy ước đặt tên:**

| Prefix | Ý nghĩa |
|--------|---------|
| `Nt` | System call stub trong ntdll.dll (user mode) |
| `Zw` | System call stub thay đổi previous mode thành KernelMode |
| `Rtl` | Runtime Library — helper functions |
| `Ldr` | Loader functions (load DLL, resolve imports) |
| `Csr` | Client-Server Runtime functions (giao tiếp với csrss.exe) |
| `Dbg` | Debug support functions |
| `Etw` | Event Tracing for Windows |
| `Tp` | Thread Pool functions |

**Sự khác biệt Nt vs Zw:**

Khi gọi từ **user mode**: `NtCreateFile` và `ZwCreateFile` hoàn toàn giống nhau — đều là syscall stubs.

Khi gọi từ **kernel mode** (driver):
- `NtCreateFile()`: giữ nguyên `PreviousMode = UserMode` → kernel kiểm tra tham số, validate buffer addresses
- `ZwCreateFile()`: đặt `PreviousMode = KernelMode` → bỏ qua kiểm tra, tin tưởng caller

```c
// Trong kernel driver, LUÔN dùng Zw* versions:
ZwCreateFile(&handle, GENERIC_READ, &oa, &iosb, NULL,
             FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN,
             FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
```

### 1.2.3 API Sets — Cơ Chế Trừu Tượng DLL Hiện Đại

**[UPDATE 2026]** Từ Windows 7 (hoàn thiện từ Windows 10), Windows dùng **API Sets** để tách API name khỏi DLL implementation:

```
Ứng dụng link tới:    api-ms-win-core-file-l1-1-0.dll
                              │
                              ▼
                       ApiSet Schema (apisetschema.dll)
                       Maps name → real DLL
                              │
                              ▼
                       kernelbase.dll (implementation thật)
```

**Cấu trúc tên API Set:**

```
api-ms-win-core-file-l1-2-0.dll
│   │   │    │    │  │ │ │
│   │   │    │    │  │ │ └── Revision (0)
│   │   │    │    │  │ └──── Minor version (2)
│   │   │    │    │  └────── Major version (1)
│   │   │    │    └───────── Layer: l=lower, none=normal
│   │   │    └────────────── Functional area: file, processthreads, memory, ...
│   │   └─────────────────── Subsystem: core, security, networking, ...
│   └─────────────────────── Platform: win
└─────────────────────────── Type: api (stable) hoặc ext (extension)
```

**Xem API Set mappings:**

```powershell
# Dùng tool ApiSetView hoặc parse trực tiếp
# apisetschema.dll được map vào mọi process tại PEB.ApiSetMap

# WinDbg:
0:000> dt ntdll!_PEB @$peb ApiSetMap
0:000> !apisets                         ; Extension command
```

**Tại sao API Sets quan trọng:**

1. **Forward compatibility**: app link tới API set name, không link tới DLL cụ thể
2. **OneCore**: cùng API set name → map tới DLL khác nhau trên Desktop vs IoT vs Xbox
3. **Minwin separation**: tách core OS APIs khỏi legacy DLLs
4. **DLL không thể bị hijack**: API set resolution xảy ra trước DLL search order

```
Ví dụ mapping trên Desktop:
  api-ms-win-core-file-l1-1-0       → kernelbase.dll
  api-ms-win-core-processthreads-l1 → kernelbase.dll
  api-ms-win-core-synch-l1          → kernelbase.dll
  api-ms-win-core-registry-l1       → kernelbase.dll
  api-ms-win-security-base-l1       → kernelbase.dll
  api-ms-win-core-com-l1            → combase.dll
  api-ms-win-core-winrt-l1          → combase.dll

Trên IoT Core (stripped down):
  api-ms-win-core-file-l1-1-0       → mincore.dll (minimal implementation)
```

### 1.2.4 COM, WinRT, và .NET — Các API Layer Khác

Ngoài Win32 API thuần, Windows có nhiều API layers khác:

**COM (Component Object Model):**

```
COM là binary interface standard cho cross-language interop:

Client                              COM Object
┌───────────────┐                  ┌──────────────────┐
│ CoCreateInstance()                │ │ IUnknown          │
│       │                          │ │ ├── QueryInterface │
│       ▼                          │ │ ├── AddRef         │
│ Interface pointer ───────────────┼→│ └── Release        │
│ (vtable-based)                   │ │                    │
│                                  │ │ IMyInterface       │
│ pObj->Method()  ─────────────────┼→│ ├── Method()       │
└───────────────┘                  │ └── ...             │
                                   └──────────────────┘

COM Threading Models:
  STA (Single-Threaded Apartment): UI objects, Excel automation
  MTA (Multi-Threaded Apartment): server objects
  Free-threaded: object handles own synchronization

COM Activation:
  CLSID (Class ID) → Registry lookup → DLL/EXE path → load → create
  Registry: HKCR\CLSID\{guid}\InprocServer32 = path\to\dll.dll

COM trong kernel:
  COM không tồn tại trong kernel mode
  Nhưng nhiều kernel concepts tương tự (interface tables, reference counting)
```

**WinRT (Windows Runtime):**

```
WinRT = COM-based API cho modern Windows development (từ Win8+):

┌──────────────────────────────────────────┐
│ Language Projections:                     │
│   C++/WinRT, C#, JavaScript, Rust/WinRT  │
├──────────────────────────────────────────┤
│ WinRT API Surface:                       │
│   Windows.Storage, Windows.Networking,   │
│   Windows.UI.Xaml, Windows.Media, ...    │
├──────────────────────────────────────────┤
│ Windows Runtime (COM-based ABI)          │
│   IInspectable : IUnknown                │
│   Activation Factories                   │
│   HSTRING (immutable strings)            │
├──────────────────────────────────────────┤
│ Implementation: WinRT DLLs               │
│   (registered in manifests, not registry)│
└──────────────────────────────────────────┘

WinRT vs Win32:
  WinRT: sandboxed (AppContainer), async-first, modern types
  Win32: full access, sync default, C-style types
  Cả hai đều gọi xuống Native API cuối cùng
```

**[UPDATE 2026]** WinUI 3 và Windows App SDK cho phép dùng WinRT APIs từ non-UWP desktop apps.

### 1.2.5 Ntoskrnl.exe Variants

Windows có nhiều phiên bản ntoskrnl.exe tùy theo configuration:

```
Trước Windows 10:
  ntoskrnl.exe  — Uniprocessor, no PAE (x86 only)
  ntkrnlpa.exe  — Uniprocessor, PAE enabled (x86 only)
  ntkrnlmp.exe  — Multiprocessor, no PAE (x86 only)
  ntkrpamp.exe  — Multiprocessor, PAE enabled (x86 only)

Windows 10+ (x64):
  ntoskrnl.exe  — Chỉ còn 1 variant duy nhất
                  (SMP, 64-bit, tất cả features compiled in)
                  
  Có thể có debug variant:
    ntoskrnl.exe (retail) — optimized, no extra checks
    Checked build: removed từ 1803+
    Thay thế: Driver Verifier + ETW tracing

Boot loader chọn variant nào:
  winload.efi đọc BCD settings
  → Load ntoskrnl.exe tương ứng
  → Rename thành "ntoskrnl.exe" trong memory
```

```
kd> lm m nt
  start             end                 module name
  fffff800`12345000 fffff800`12e00000   nt  (pdb symbols)
  
kd> !lmi nt
  Module:   nt (ntoskrnl.exe)
  Build:    26100.1.amd64fre.ge_release.240331-1435
```

### 1.2.6 PE (Portable Executable) Format — Nền Tảng

Hiểu PE format là bắt buộc để hiểu image loading, security, và malware analysis:

```
PE File Layout:
┌──────────────────────────────────────────┐
│ DOS Header (IMAGE_DOS_HEADER)             │
│   e_magic: "MZ" (0x5A4D)                 │
│   e_lfanew: offset tới PE header          │
├──────────────────────────────────────────┤
│ DOS Stub (optional, "This program...")    │
├──────────────────────────────────────────┤
│ PE Signature: "PE\0\0" (0x00004550)      │
├──────────────────────────────────────────┤
│ COFF File Header (IMAGE_FILE_HEADER)      │
│   Machine: 0x8664 (x64), 0xAA64 (ARM64)  │
│   NumberOfSections                        │
│   TimeDateStamp                           │
│   SizeOfOptionalHeader                    │
│   Characteristics                         │
├──────────────────────────────────────────┤
│ Optional Header (IMAGE_OPTIONAL_HEADER64) │
│   Magic: 0x20B (PE32+)                   │
│   AddressOfEntryPoint                     │
│   ImageBase (preferred load address)      │
│   SectionAlignment (4096 = page size)     │
│   SizeOfImage                             │
│   Subsystem: GUI(2), Console(3), Native(1)│
│   DllCharacteristics:                     │
│     DYNAMIC_BASE (ASLR)                   │
│     NX_COMPAT (DEP)                       │
│     FORCE_INTEGRITY (mandatory signing)   │
│     GUARD_CF (CFG enabled)                │
│     HIGH_ENTROPY_VA (high entropy ASLR)   │
│     APPCONTAINER                          │
│   DataDirectory[16]:                      │
│     [0]  Export Table                      │
│     [1]  Import Table                      │
│     [2]  Resource Table                    │
│     [3]  Exception Table (.pdata)          │
│     [4]  Certificate Table (Authenticode)  │
│     [5]  Base Relocation Table             │
│     [6]  Debug Directory                   │
│     [10] Load Config (SEH, CFG, CET data)  │
│     [11] Bound Import                      │
│     [12] IAT (Import Address Table)        │
│     [13] Delay Import                      │
│     [14] CLR Header (.NET metadata)        │
├──────────────────────────────────────────┤
│ Section Headers:                          │
│   .text   — executable code               │
│   .rdata  — read-only data, imports       │
│   .data   — read-write data               │
│   .pdata  — exception unwind info (x64)   │
│   .rsrc   — resources (icons, strings)    │
│   .reloc  — base relocations (for ASLR)   │
│   PAGE    — pageable code (drivers)       │
│   INIT    — init-time only code (drivers) │
├──────────────────────────────────────────┤
│ Section Data (raw content)                │
└──────────────────────────────────────────┘
```

**Import Address Table (IAT) — Quan trọng cho hooking/injection:**

```
Import flow:
1. PE file có Import Directory liệt kê DLLs cần load
2. Mỗi DLL entry có:
   ├── Name: "kernel32.dll"
   ├── OriginalFirstThunk → INT (Import Name Table, read-only)
   │   └── Array of function names/ordinals
   └── FirstThunk → IAT (Import Address Table, writable)
       └── Array of function addresses (filled by loader)

Trước load: IAT chứa hints (name RVAs)
Sau load:   IAT chứa actual function addresses

IAT Hooking (common malware technique):
  Thay đổi IAT entry → redirect function calls
  Ví dụ: IAT[CreateFileW] = &MyHookFunction
  → Mọi lần app gọi CreateFileW → gọi MyHookFunction trước
```

**Authenticode Signature:**

```
PE Signature verification chain:
  PE file → Authenticode signature (DataDirectory[4])
    → Certificate chain → Root CA (Microsoft Root)
    → Timestamp (proves signing time)
    → Catalog signature (alternative — .cat file)
    
  Driver signing:
    Kernel-mode drivers PHẢI được signed:
    ├── WHQL (Windows Hardware Quality Labs) — Microsoft tested
    ├── Attestation signing — developer portal
    ├── EV (Extended Validation) — cross-signed
    └── Test signing — development only (bcdedit /set testsigning on)
```

```cmd
:: Verify PE signature
sigcheck.exe -i -v notepad.exe          ; Sysinternals
signtool.exe verify /pa /v mydriver.sys  ; SDK

:: Xem PE headers
dumpbin /headers ntoskrnl.exe
dumpbin /imports kernel32.dll
dumpbin /exports ntdll.dll
CFF Explorer (GUI PE editor)
PE-bear (modern PE viewer)
```

### 1.2.7 SharedUserData (KUSER_SHARED_DATA)

Một page đặc biệt được map ở cùng virtual address trong MỌI process (và kernel):

```
User mode address:   0x7FFE0000 (luôn cố định, KHÔNG bị ASLR)
Kernel mode address: 0xFFFFF780'00000000 (x64)

_KUSER_SHARED_DATA tại 0x7FFE0000:
├── TickCountLowDeprecated          ← System tick count
├── TickCountMultiplier             ← Convert ticks → time
├── InterruptTime                   ← Interrupt time (100ns units)
├── SystemTime                      ← Current system time (UTC)
├── TimeZoneBias                    ← UTC offset
├── ImageNumberLow/High             ← Supported PE machine types
├── NtSystemRoot                    ← L"C:\\Windows"
├── MaxStackTraceDepth
├── NtProductType                   ← WinNt(1), LanmanNt(2), Server(3)
├── ProductTypeIsValid
├── NtMajorVersion                  ← 10
├── NtMinorVersion                  ← 0
├── ProcessorFeatures[64]           ← CPU feature flags
├── MitigationPolicies              ← System-wide mitigations
├── NtBuildNumber                   ← OS build number
├── KdDebuggerEnabled               ← Kernel debugger active
├── ActiveConsoleId                 ← Active console session
├── ActiveGroupCount                ← Processor groups
├── NumberOfPhysicalPages           ← Total RAM pages
├── ...
└── Cookie                          ← Stack cookie value for /GS

Tại sao đặc biệt:
  - KHÔNG cần system call để đọc system time, tick count, OS version
  - Rất nhanh: đọc trực tiếp từ user mode
  - API QueryPerformanceCounter, GetTickCount, GetSystemTime
    đọc từ đây (fast path, không vào kernel)
  - Kernel cập nhật page này mỗi clock interrupt
```

```c
// Đọc trực tiếp (mọi process):
KUSER_SHARED_DATA* shared = (KUSER_SHARED_DATA*)0x7FFE0000;
ULONG buildNumber = shared->NtBuildNumber;
BOOLEAN debugger = shared->KdDebuggerEnabled;
```

```
;; WinDbg
kd> dt nt!_KUSER_SHARED_DATA 0xFFFFF78000000000
kd> dd 0x7FFE0000+0x260 L1     ; NtBuildNumber offset
```

**Anti-debug note:** `KdDebuggerEnabled` tại offset 0x2D4 — malware check byte này để detect kernel debugger.

### 1.2.8 Services, Functions, và Routines

Windows documentation dùng các thuật ngữ này với ý nghĩa cụ thể:

- **Windows API functions**: hàm documented trong Windows SDK (ví dụ: `CreateProcess`, `ReadFile`)
- **Native system services** (system calls): hàm trong ntdll.dll gọi vào kernel (ví dụ: `NtCreateProcess`)
- **Kernel support functions**: hàm mà kernel export cho drivers dùng (ví dụ: `ExAllocatePool2`, `IoCreateDevice`)
- **Windows services**: processes chạy nền do Service Control Manager (SCM) quản lý (ví dụ: `Spooler`, `DHCP Client`)
- **DLL routines**: hàm exported từ DLL (ví dụ: `RtlInitUnicodeString` từ ntdll)

### 1.2.9 Processes

**Process** là một container cho việc thực thi code. Bản thân process KHÔNG chạy — threads bên trong process mới là thứ thực thi.

**Mỗi process bao gồm:**

| Thành phần | Mô tả |
|------------|-------|
| Virtual Address Space (VAS) | Không gian địa chỉ ảo riêng |
| Executable code | Image file (.exe) được map vào VAS |
| Handle table | Bảng các kernel object handles |
| Access token | Token bảo mật xác định identity và privileges |
| Process ID (PID) | Số định danh duy nhất (bội số của 4) |
| Ít nhất 1 thread | Thread thực thi chính |

**Cấu trúc kernel đại diện cho process:**

```
_EPROCESS (Executive Process Block)
├── _KPROCESS (Kernel Process Block / PCB)
│   ├── DirectoryTableBase     ← CR3, page directory
│   ├── ThreadListHead         ← Danh sách threads
│   ├── BasePriority           ← Priority mặc định cho threads
│   ├── Affinity               ← CPU affinity mask
│   └── ...
├── UniqueProcessId            ← PID
├── ActiveProcessLinks        ← Linked list tất cả processes
├── Token                      ← Security access token
├── ObjectTable                ← Handle table
├── Peb                        ← Process Environment Block (user mode)
├── ImageFileName              ← Tên file exe (15 chars)
├── SeAuditProcessCreationInfo ← Full image path
├── VadRoot                    ← Virtual Address Descriptor tree
├── WorkingSetPage             ← Working set management
├── InheritedFromUniqueProcessId ← Parent PID
└── ...
```

**Xem processes bằng WinDbg:**

```
kd> !process 0 0                    ; Liệt kê tất cả processes
kd> !process <EPROCESS_addr> 7      ; Chi tiết process (bao gồm threads)
kd> dt nt!_EPROCESS <addr>          ; Dump cấu trúc _EPROCESS
kd> !peb <PEB_addr>                 ; Process Environment Block
```

**Xem bằng PowerShell:**

```powershell
Get-Process | Select-Object Id, ProcessName, HandleCount, WorkingSet64
(Get-Process -Id $pid).Modules      # Liệt kê loaded modules
```

### 1.2.10 Threads

**Thread** là đơn vị thực thi cơ bản mà Windows scheduler quản lý. Mỗi thread có:

| Thành phần | Mô tả |
|------------|-------|
| Thread ID (TID) | Số định danh duy nhất |
| CPU context | Registers (RIP, RSP, RFLAGS, ...) |
| User-mode stack | Stack cho code user mode |
| Kernel-mode stack | Stack cho code kernel mode (syscalls, interrupts) |
| TEB | Thread Environment Block (user mode) |
| Priority | Dynamic priority (0-31) |
| State | Running, Ready, Waiting, ... |

**Cấu trúc kernel:**

```
_ETHREAD (Executive Thread Block)
├── _KTHREAD (Kernel Thread Block / TCB)
│   ├── InitialStack / StackLimit    ← Kernel stack bounds
│   ├── TrapFrame                    ← Saved CPU state khi vào kernel
│   ├── State                        ← Ready, Running, Waiting, ...
│   ├── Priority                     ← Current priority (0-31)
│   ├── BasePriority                 ← Base priority
│   ├── Quantum                      ← Time quantum remaining
│   ├── WaitReason                   ← Lý do đang wait
│   ├── Teb                          ← Thread Environment Block
│   └── ...
├── Cid                              ← Client ID (PID + TID)
├── StartAddress                     ← Thread start function
├── Win32StartAddress                ← User-mode start address
├── ThreadListEntry                  ← Link trong process thread list
└── ...
```

**Thread states:**

```
                    ┌──────────┐
    Initialized ──→│  Ready   │←──────────────────────┐
                    └────┬─────┘                       │
                         │ Selected by                 │ Preempted /
                         │ dispatcher                  │ Quantum expired
                         ▼                             │
                    ┌──────────┐                       │
                    │ Standby  │ (next to run on CPU)  │
                    └────┬─────┘                       │
                         │ Context switch              │
                         ▼                             │
                    ┌──────────┐                       │
                    │ Running  │───────────────────────┘
                    └────┬─────┘
                         │ Wait on object
                         ▼
                    ┌──────────┐
                    │ Waiting  │
                    └────┬─────┘
                         │ Wait satisfied
                         ▼
                    ┌──────────────┐
                    │ Deferred     │──→ Ready
                    │ Ready        │
                    └──────────────┘
```

### 1.2.11 Fibers và User-Mode Scheduling (UMS)

**Fibers** là "lightweight threads" được schedule hoàn toàn ở user mode:

```c
// Chuyển thread hiện tại thành fiber
LPVOID mainFiber = ConvertThreadToFiber(NULL);

// Tạo fiber mới
LPVOID workerFiber = CreateFiber(0, FiberFunc, param);

// Chuyển đổi thủ công (cooperative scheduling)
SwitchToFiber(workerFiber);
```

- Kernel KHÔNG biết fibers tồn tại — nó chỉ thấy thread
- Fiber scheduling là cooperative (không preemptive)
- Ít được dùng trong thực tế vì dễ gây bugs (TLS issues, callback issues)

**UMS (User-Mode Scheduling)**: cho phép ứng dụng tự schedule threads mà không cần kernel transition. Chỉ available trên 64-bit Windows. **[UPDATE 2026]** UMS đã bị deprecated từ Windows 11 — Microsoft khuyến khích dùng thread pools thay thế.

### 1.2.12 Jobs

**Job object** là cơ chế nhóm các processes lại để quản lý chung:

```
┌─────────────────────────────────────┐
│              Job Object              │
│                                     │
│  ┌──────────┐  ┌──────────┐        │
│  │ Process A │  │ Process B │        │
│  │  ├ Thread │  │  ├ Thread │        │
│  │  └ Thread │  │  └ Thread │        │
│  └──────────┘  └──────────┘        │
│                                     │
│  Limits: CPU time, Memory, Priority │
│  IO Rate, Network bandwidth         │
│  Process count                       │
└─────────────────────────────────────┘
```

**Các loại limits:**

| Limit | Mô tả |
|-------|-------|
| CPU time | Giới hạn tổng CPU time hoặc rate (%) |
| Memory | Working set size, committed memory |
| Process count | Số lượng process tối đa trong job |
| Priority class | Không cho process tự nâng priority |
| Affinity | Giới hạn CPU cores được phép dùng |
| I/O rate | Giới hạn disk I/O bandwidth |
| Network | Giới hạn network bandwidth |
| UI restrictions | Cấm access clipboard, desktop, ... |

**Nested Jobs**: Từ Windows 8+, jobs có thể lồng nhau (nested). Trước đó, một process chỉ thuộc được 1 job. Nested jobs cho phép áp dụng nhiều lớp policy.

**Silos (Windows Containers)**: **[UPDATE 2026]** Job objects là nền tảng của Windows Containers. Một **Server Silo** là job object đặc biệt tạo ra namespace isolation:

```
Server Silo (Container)
├── Isolated Object Namespace
├── Isolated Registry Hive
├── Isolated File System View
├── Isolated Network Stack
├── Isolated Process List
└── Resource Limits (CPU, Memory, I/O)
```

### 1.2.13 Virtual Memory

Windows dùng **flat virtual address space** cho mỗi process. Mỗi process "nhìn thấy" một không gian địa chỉ liên tục, riêng biệt.

**Address space layout (64-bit):**

```
0x0000'0000'0000'0000  ┌──────────────────────┐
                        │    NULL pointer zone   │  ← 64KB, access violation
0x0000'0000'0001'0000  ├──────────────────────┤
                        │                        │
                        │   User Space           │  ← 128 TB (mặc định)
                        │   Code, data, heap,    │
                        │   stacks, mapped files  │
                        │                        │
0x0000'7FFF'FFFF'0000  ├──────────────────────┤
                        │   64KB No-access guard  │
0x0000'8000'0000'0000  ├──────────────────────┤
                        │                        │
                        │   Kernel Space          │  ← 128 TB
                        │   Kernel code, HAL,     │
                        │   drivers, system cache, │
                        │   paged/nonpaged pool   │
                        │                        │
0xFFFF'FFFF'FFFF'FFFF  └──────────────────────┘
```

**Page states:**

| State | Mô tả |
|-------|-------|
| **Free** | Chưa được allocated — access gây access violation |
| **Reserved** | Đã reserved range nhưng chưa có physical memory — access vẫn gây AV |
| **Committed** | Có physical storage (RAM hoặc pagefile) — access được |

**Page protection flags:**

| Flag | Ý nghĩa |
|------|---------|
| `PAGE_READONLY` | Chỉ đọc |
| `PAGE_READWRITE` | Đọc/ghi |
| `PAGE_EXECUTE` | Chỉ thực thi |
| `PAGE_EXECUTE_READ` | Thực thi + đọc |
| `PAGE_EXECUTE_READWRITE` | Full access |
| `PAGE_NOACCESS` | Cấm mọi access |
| `PAGE_GUARD` | Guard page — trigger exception lần đầu access |
| `PAGE_WRITECOPY` | Copy-on-Write (CoW) |

**Copy-on-Write (CoW):**

Khi nhiều processes map cùng một DLL, Windows dùng CoW để chia sẻ physical pages. Nếu một process ghi vào page đó:

```
Process A ──→ Shared Page (read-only copy) ← Process B
                     │
        Process A ghi vào page
                     ▼
Process A ──→ Private Copy (writable)
              Shared Page (unchanged) ← Process B
```

### 1.2.14 Kernel Mode vs User Mode

CPU x64 có 4 ring levels (0-3), nhưng Windows chỉ dùng 2:

```
┌─────────────────────────────────────────────┐
│                Ring 3 (User Mode)            │
│   Applications, services, subsystems        │
│   - Không thể access hardware trực tiếp     │
│   - Không thể thực thi privileged CPU instr │
│   - Mỗi process có address space riêng      │
│   - Crash → chỉ process đó terminate        │
├─────────────────────────────────────────────┤
│                Ring 0 (Kernel Mode)          │
│   Kernel, drivers, HAL                      │
│   - Full access hardware                    │
│   - Thực thi mọi CPU instructions           │
│   - Chia sẻ chung address space             │
│   - Crash → Blue Screen of Death (BSOD)     │
└─────────────────────────────────────────────┘
```

**Chuyển đổi User → Kernel mode:**

Trên x64, instruction `syscall` được dùng (thay vì `int 2Eh` trên x86):

```
User mode:
  ntdll!NtCreateFile:
    mov   r10, rcx          ; rcx bị dùng bởi syscall
    mov   eax, 0x55         ; System call number
    syscall                 ; → chuyển sang kernel mode
    ret

Kernel mode:
  nt!KiSystemCall64:
    swapgs                  ; Load kernel GS base (KPCR)
    mov   gs:[...], rsp     ; Lưu user RSP
    mov   rsp, gs:[...]     ; Load kernel stack
    ...
    call  nt!NtCreateFile   ; Gọi implementation thật
    ...
    sysret                  ; → quay lại user mode
```

**[UPDATE 2026]** Trên Windows 11, Kernel CET (Control-flow Enforcement Technology) bảo vệ return addresses trên kernel stack bằng shadow stack.

### 1.2.15 Hypervisor

**[UPDATE 2026]** Hyper-V hypervisor đóng vai trò ngày càng quan trọng:

```
Ring 3:  Applications
Ring 0:  Windows Kernel + Drivers
         ─────────────────────────
Ring -1: Hyper-V Hypervisor        ← VTL 0 (Normal World)
         ═════════════════════════
         Secure Kernel (SK)        ← VTL 1 (Secure World)
```

**Virtual Trust Levels (VTL):**

| VTL | Tên | Chạy gì |
|-----|-----|---------|
| VTL 0 | Normal World | Windows kernel, drivers, apps bình thường |
| VTL 1 | Secure World | Secure Kernel, Trustlets (IUM processes) |

**Virtualization-Based Security (VBS):**

VBS dùng hypervisor để tạo isolated memory regions mà ngay cả kernel ở VTL 0 cũng không access được:

- **Credential Guard**: lưu NTLM hashes, Kerberos tickets trong VTL 1
- **HVCI** (Hypervisor-protected Code Integrity): kernel chỉ chạy signed code
- **Secure Launch**: (DRTM) xác minh boot chain integrity

### 1.2.16 Firmware và Boot

**UEFI vs Legacy BIOS:**

| Tính năng | Legacy BIOS | UEFI |
|-----------|-------------|------|
| Bit mode | 16-bit Real Mode | 32/64-bit Protected Mode |
| Partition table | MBR (max 2TB) | GPT (max 9.4 ZB) |
| Secure Boot | Không | Có |
| Boot loader | Sector đầu tiên | EFI application (.efi) |
| Driver model | INT 13h | EFI drivers |
| Network boot | PXE (hạn chế) | Full network stack |

**Secure Boot flow:**

```
UEFI Firmware ──→ Verify bootmgfw.efi (Microsoft signed)
                   ──→ Verify winload.efi
                        ──→ Verify ntoskrnl.exe
                             ──→ Verify all boot drivers
```

**[UPDATE 2026]** Windows 11 yêu cầu UEFI + Secure Boot + TPM 2.0 bắt buộc.

### 1.2.17 Terminal Services và Sessions

Windows hỗ trợ nhiều interactive sessions đồng thời:

```
Session 0:  Services (isolated từ Vista+, không có UI)
Session 1:  Console user đầu tiên
Session 2:  RDP user hoặc Fast User Switching
Session N:  Thêm users...
```

**Session 0 Isolation**: Từ Windows Vista, services chạy trong Session 0 riêng biệt:
- Services không thể hiển thị UI cho user
- Ngăn **Shatter Attacks** (gửi messages từ low-privilege service lên high-privilege window)
- Services giao tiếp UI qua Interactive Services Detection

**Mỗi session có:**
- Window Station riêng (thường `WinSta0`)
- Desktop objects riêng
- Clipboard riêng (trong mỗi window station)

### 1.2.18 Objects và Handles

Kernel quản lý resources thông qua **objects**. Mỗi object type có header chung:

```
_OBJECT_HEADER
├── PointerCount          ← Reference count (kernel pointers)
├── HandleCount           ← Number of open handles
├── TypeIndex             ← Index vào ObTypeIndexTable
├── SecurityDescriptor    ← DACL/SACL
├── Body                  ← Object-specific data
│   (ví dụ: _FILE_OBJECT, _EPROCESS, _ETHREAD, ...)
└── Optional headers:
    ├── _OBJECT_HEADER_NAME_INFO    ← Tên object
    ├── _OBJECT_HEADER_CREATOR_INFO ← Process tạo
    ├── _OBJECT_HEADER_HANDLE_INFO  ← Handle database entry
    └── _OBJECT_HEADER_QUOTA_INFO   ← Quota charges
```

**Object types phổ biến:**

| Type | Mô tả | Ví dụ |
|------|--------|-------|
| Process | Process object | `_EPROCESS` |
| Thread | Thread object | `_ETHREAD` |
| File | File/device/pipe/mailslot | `_FILE_OBJECT` |
| Section | Memory-mapped file | Shared memory |
| Key | Registry key | `_CM_KEY_BODY` |
| Event | Synchronization event | Auto/Manual reset |
| Mutant | Mutex (user-mode name) | Named mutex |
| Semaphore | Counting semaphore | |
| Timer | Waitable timer | |
| Token | Access token | `_TOKEN` |
| Desktop | Window station desktop | |
| Directory | Object namespace directory | `\BaseNamedObjects` |
| SymbolicLink | Object namespace link | `\DosDevices\C:` → `\Device\HarddiskVolume3` |
| Job | Job object | |
| IoCompletion | I/O completion port | |
| TpWorkerFactory | Thread pool | |
| ALPC Port | Advanced Local Procedure Call | |

**Handle:**

Handle là index vào process handle table. Handle table là 3-level structure (tương tự page table):

```
Handle value: 0x0004, 0x0008, 0x000C, ...  (bội số của 4)

Process Handle Table (3 levels):
Level 0 ──→ Level 1 ──→ Level 2 ──→ _HANDLE_TABLE_ENTRY
                                      ├── Object pointer
                                      ├── GrantedAccess
                                      └── Attributes
```

**Xem objects:**
```
# WinDbg
kd> !handle 0 7 <process_addr>        ; List all handles
kd> !object \BaseNamedObjects          ; Browse object namespace
kd> !object \Device                    ; List device objects

# Sysinternals
Process Explorer → Properties → Handles tab
WinObj.exe → browse object namespace
Handle.exe -p <pid>                    ; Command line
```

### 1.2.19 Security — Tổng Quan

Security model của Windows dựa trên:

**1. Access Tokens** — gắn với mỗi process/thread:
```
Token
├── User SID            (S-1-5-21-...-1001)
├── Group SIDs          (Administrators, Users, ...)
├── Privileges          (SeDebugPrivilege, SeBackupPrivilege, ...)
├── Integrity Level     (Untrusted, Low, Medium, High, System)
├── Logon Session ID
├── Token Type          (Primary / Impersonation)
└── Restricted SIDs     (sandbox)
```

**2. Security Descriptors** — gắn với mỗi securable object:
```
Security Descriptor
├── Owner SID
├── Group SID
├── DACL (Discretionary ACL)
│   ├── ACE: Allow BUILTIN\Administrators Full Control
│   ├── ACE: Allow BUILTIN\Users Read
│   └── ACE: Deny Guest Any Access
└── SACL (System ACL — auditing)
    └── ACE: Audit Everyone Write (success + failure)
```

**3. Access Check** — khi process mở object:
```
Process Token + Object Security Descriptor → AccessCheck()
→ Kết quả: GRANTED hoặc DENIED + bitmask of granted rights
```

**Integrity Levels (Mandatory Integrity Control):**

| Level | SID | Ví dụ |
|-------|-----|-------|
| Untrusted (0) | S-1-16-0 | Rarely used |
| Low (1) | S-1-16-4096 | Protected Mode IE, sandboxed apps |
| Medium (2) | S-1-16-8192 | Normal user applications |
| High (3) | S-1-16-12288 | Elevated (admin) applications |
| System (4) | S-1-16-16384 | Services, kernel |

Rule: process KHÔNG THỂ ghi vào object có integrity level cao hơn mình (No Write Up).

### 1.2.20 Registry

Registry là database phân cấp lưu trữ configuration cho OS và applications.

**Cấu trúc logic:**

```
HKEY_LOCAL_MACHINE (HKLM)     ← System-wide settings
├── SYSTEM                     ← Boot config, drivers, services
│   └── CurrentControlSet      ← Symlink → ControlSet00x hiện tại
├── SOFTWARE                   ← Installed software settings
├── HARDWARE                   ← Hardware info (volatile, runtime)
├── SAM                        ← Security Account Manager
├── SECURITY                   ← LSA secrets, policies
└── BCD00000000               ← Boot Configuration Data

HKEY_CURRENT_USER (HKCU)      ← Per-user settings
├── Software
├── Environment
└── ...

HKEY_CLASSES_ROOT (HKCR)      ← Merged view: HKLM\SOFTWARE\Classes + HKCU\SOFTWARE\Classes
HKEY_USERS (HKU)              ← All loaded user profiles
HKEY_CURRENT_CONFIG           ← Symlink → HKLM\SYSTEM\CurrentControlSet\Hardware Profiles\Current
```

**Lưu trữ vật lý (Hive files):**

| Hive | File |
|------|------|
| SYSTEM | `%SystemRoot%\System32\config\SYSTEM` |
| SOFTWARE | `%SystemRoot%\System32\config\SOFTWARE` |
| SAM | `%SystemRoot%\System32\config\SAM` |
| SECURITY | `%SystemRoot%\System32\config\SECURITY` |
| DEFAULT | `%SystemRoot%\System32\config\DEFAULT` |
| NTUSER.DAT | `%UserProfile%\NTUSER.DAT` |
| UsrClass.dat | `%LocalAppData%\Microsoft\Windows\UsrClass.dat` |

**[UPDATE 2026]** Windows 11 lưu thêm registry differential hives cho UWP apps trong `%ProgramData%\Microsoft\Windows\AppRepository\`.

### 1.2.21 Unicode

Windows kernel dùng **UTF-16LE** (Little Endian) nội bộ cho tất cả strings:

```c
// Kernel string type
typedef struct _UNICODE_STRING {
    USHORT Length;           // Bytes hiện tại (không tính null terminator)
    USHORT MaximumLength;   // Bytes tối đa
    PWSTR  Buffer;          // Con trỏ tới UTF-16LE buffer
} UNICODE_STRING;
```

- Mọi API "W" (Wide) dùng UTF-16: `CreateFileW`, `RegOpenKeyExW`
- API "A" (ANSI) chỉ là wrapper chuyển ANSI → UTF-16 rồi gọi "W" version
- Trong kernel, CHỈ có Unicode — không có ANSI functions

**[UPDATE 2026]** Từ Windows 10 1903, có thể bật UTF-8 làm ANSI codepage hệ thống (Settings → Region → Beta: Use Unicode UTF-8). Điều này khiến API "A" dùng UTF-8 thay vì legacy codepage.

---

## 1.3 Công Cụ Khám Phá Windows Internals

### 1.3.1 Sysinternals Suite

Bộ công cụ do Mark Russinovich tạo, hiện thuộc Microsoft. Đây là công cụ QUAN TRỌNG NHẤT để nghiên cứu Windows internals.

**Download:** https://learn.microsoft.com/en-us/sysinternals/

| Công cụ | Mô tả | Dùng khi |
|---------|--------|----------|
| **Process Explorer** | Task Manager nâng cao | Xem processes, threads, handles, DLLs, GPU, .NET |
| **Process Monitor** (ProcMon) | Real-time file/registry/process monitor | Debug "file not found", registry access, app behavior |
| **Autoruns** | Tất cả auto-start locations | Tìm malware persistence, optimize boot |
| **TCPView** | Real-time network connections | Xem process nào đang connect đi đâu |
| **PsExec** | Remote execution | Chạy commands trên remote machines hoặc as SYSTEM |
| **Handle** | List open handles | Tìm file lock, leak handles |
| **ListDLLs** | List loaded DLLs | Detect DLL injection |
| **VMMap** | Virtual memory viewer | Phân tích memory usage chi tiết |
| **RAMMap** | Physical memory viewer | Xem RAM được dùng như thế nào |
| **WinObj** | Object namespace browser | Khám phá kernel objects |
| **AccessChk** | Security analysis | Kiểm tra permissions |
| **Strings** | Extract strings from binary | Phân tích malware, tìm thông tin |
| **DebugView** | View debug output | Capture OutputDebugString / DbgPrint |
| **LiveKd** | Local kernel debugging | Khám phá kernel mà không cần remote debug |
| **Disk2VHD** | Create VHD from live disk | Backup / virtualization |

**Process Explorer — Những gì cần biết:**

```
Màu sắc mặc định:
- Xanh lá sáng  → Process vừa tạo (fade sau vài giây)
- Đỏ            → Process vừa terminate
- Xanh dương nhạt → Process chạy as same user
- Hồng          → Services
- Tím           → Packed/compressed images
- Xanh đậm     → Immersive (UWP) processes
```

Cách dùng Process Explorer thay thế Task Manager:
```
Options → Replace Task Manager → Ctrl+Shift+Esc sẽ mở ProcExp
```

**Process Monitor — Filter quan trọng:**

```
Ví dụ: Debug tại sao app không tìm thấy config file
Filter:
  Process Name is MyApp.exe
  AND Operation is CreateFile
  AND Result is NAME NOT FOUND
  
→ Thấy ngay MyApp tìm config ở đâu và tại sao fail
```

### 1.3.2 Windows Debuggers (WinDbg)

**WinDbg** là kernel/user-mode debugger chính thức của Microsoft.

**[UPDATE 2026]** WinDbg Preview (từ Microsoft Store) đã trở thành phiên bản chính, với UI mới và Time Travel Debugging (TTD).

**Các chế độ debugging:**

| Chế độ | Mô tả | Setup |
|--------|--------|-------|
| Local Kernel Debug | Read-only inspect local kernel | `WinDbg → File → Kernel Debug → Local` |
| Remote Kernel Debug | Full kernel debugging | Serial/Network/USB connection |
| User-mode Debug | Debug application | Attach to process hoặc launch |
| Crash Dump Analysis | Phân tích BSOD dump | `WinDbg → Open Crash Dump` |
| TTD (Time Travel) | Record & replay | WinDbg Preview |

**Thiết lập kernel debugging qua network:**

```cmd
:: Trên target machine (máy bị debug):
bcdedit /debug on
bcdedit /dbgsettings net hostip:<debugger_IP> port:50000

:: Trên host machine (máy chạy WinDbg):
WinDbg → File → Kernel Debug → Net → Port: 50000, Key: <auto-generated>
```

**Các lệnh WinDbg thiết yếu:**

```
;; === GENERAL ===
.sympath srv*C:\Symbols*https://msdl.microsoft.com/download/symbols
.reload                          ; Reload symbols
lm                               ; List loaded modules
x nt!Ke*                         ; Search symbols matching pattern

;; === PROCESS / THREAD ===
!process 0 0                     ; List all processes (brief)
!process 0 0 explorer.exe        ; Find specific process
!process <addr> 7                ; Detailed process info
!thread <addr>                   ; Thread details
!teb                             ; Thread Environment Block
!peb                             ; Process Environment Block

;; === MEMORY ===
!address                         ; Virtual memory summary
!vprot <addr>                    ; Page protection
!pool <addr>                     ; Pool allocation info
!poolused                        ; Pool usage by tag
dc <addr>                        ; Display memory as DWORD + ASCII
dps <addr>                       ; Display pointers with symbols

;; === OBJECTS ===
!object \                        ; Root of object namespace
!object \Device                  ; Device objects
!handle 0 7                      ; All handles in current process
!devobj <addr>                   ; Device object details
!drvobj <name>                   ; Driver object

;; === SYSTEM ===
!idt                             ; Interrupt Descriptor Table
!pcr                             ; Processor Control Region
!irql                            ; Current IRQL
!cpuinfo                         ; CPU information
!sysinfo                         ; System information

;; === CRASH ANALYSIS ===
!analyze -v                      ; Verbose crash analysis
.bugcheck                        ; Bugcheck code
!errrec                          ; Error records
```

### 1.3.3 Windows SDK và WDK

**Windows SDK** (Software Development Kit):
- Headers cho Windows API (`windows.h`, `winnt.h`, ...)
- Libraries (.lib files)
- Tools: `dumpbin`, `link`, `midl`, `mc`, ...
- Documentation (online tại docs.microsoft.com)

**WDK** (Windows Driver Kit):
- Headers cho kernel-mode development
- Libraries cho driver development
- Build tools cho drivers
- Sample drivers
- Static analysis tools (Code Analysis, SDV)
- **[UPDATE 2026]** WDK hiện được phân phối qua NuGet packages thay vì standalone installer

**Dumpbin — công cụ hữu ích từ SDK:**

```cmd
:: Xem exports của DLL
dumpbin /exports kernel32.dll

:: Xem imports của executable
dumpbin /imports notepad.exe

:: Xem headers
dumpbin /headers ntoskrnl.exe

:: Xem sections
dumpbin /sections ntdll.dll
```

### 1.3.4 Performance Monitor và Resource Monitor

**Performance Monitor (perfmon.exe):**

Dùng performance counters để theo dõi hệ thống real-time hoặc log data.

**Counters quan trọng cho internals research:**

| Counter | Ý nghĩa |
|---------|---------|
| `Process(*)\% Processor Time` | CPU usage per process |
| `Process(*)\Working Set` | Physical memory per process |
| `Process(*)\Handle Count` | Open handles per process |
| `Process(*)\Thread Count` | Threads per process |
| `Memory\Available MBytes` | RAM còn trống |
| `Memory\Pages/sec` | Page fault rate |
| `Memory\Pool Nonpaged Bytes` | Nonpaged pool usage |
| `Memory\Pool Paged Bytes` | Paged pool usage |
| `System\Context Switches/sec` | Thread context switches |
| `System\System Calls/sec` | System call rate |
| `PhysicalDisk(*)\% Disk Time` | Disk busy percentage |
| `PhysicalDisk(*)\Avg. Disk Queue Length` | Pending I/O requests |

**Resource Monitor (resmon.exe):**

Cung cấp overview nhanh:
- **CPU tab**: per-process CPU, services, associated handles/modules
- **Memory tab**: working set, private, shareable, commit
- **Disk tab**: per-file I/O activity, read/write bytes/sec
- **Network tab**: per-process network activity, TCP connections, listening ports

### 1.3.5 Event Tracing for Windows (ETW)

**[UPDATE 2026]** ETW là hệ thống tracing chính của Windows, được sử dụng rộng rãi hơn bao giờ hết.

**Kiến trúc ETW:**

```
Providers ──→ Sessions (Buffers) ──→ Consumers
(Kernel,       (ETL files hoặc        (WPA, PerfView,
 Drivers,       real-time)              xperf, tracelog,
 Applications)                          logman)
```

**Kernel providers quan trọng:**

| Provider | GUID / Keyword | Trace gì |
|----------|---------------|-----------|
| Process | `{22FB2CD6-...}` | Process create/exit |
| Thread | `{22FB2CD6-...}` | Thread create/exit |
| ImageLoad | `{22FB2CD6-...}` | DLL/driver load |
| DiskIO | `{22FB2CD6-...}` | Disk reads/writes |
| FileIO | `{22FB2CD6-...}` | File operations |
| NetworkTCPIP | `{22FB2CD6-...}` | TCP/UDP/IP activity |
| Registry | `{22FB2CD6-...}` | Registry access |
| VirtualAlloc | `{22FB2CD6-...}` | Memory allocation |
| SystemCall | `{22FB2CD6-...}` | System calls |

**Sử dụng nhanh:**

```cmd
:: Bắt đầu trace
logman create trace MyTrace -p "Microsoft-Windows-Kernel-Process" -o trace.etl
logman start MyTrace

:: Dừng trace
logman stop MyTrace
logman delete MyTrace

:: Phân tích bằng Windows Performance Analyzer (WPA)
wpa.exe trace.etl
```

### 1.3.6 Các Công Cụ Bổ Sung

**PowerShell — for quick investigation:**

```powershell
# System information
Get-ComputerInfo | Select-Object OsName, OsVersion, OsBuildNumber

# Processes với details
Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 10

# Services
Get-Service | Where-Object Status -eq Running

# Drivers
Get-WmiObject Win32_SystemDriver | Where-Object State -eq Running

# Open files/handles
# (Cần Sysinternals Handle.exe hoặc NtQuerySystemInformation)

# Network connections
Get-NetTCPConnection | Where-Object State -eq Established

# Loaded kernel modules
Get-WmiObject Win32_SystemDriver | Select-Object Name, PathName, State
```

**NirSoft tools — bổ sung cho Sysinternals:**

| Công cụ | Mô tả |
|---------|--------|
| CurrPorts | Network connections chi tiết |
| OpenedFilesView | Files đang mở trên network shares |
| DeviceIOView | Monitor DeviceIoControl calls |
| DriverView | List loaded kernel drivers |
| InstalledCodec | Installed codecs |
| WifiInfoView | WiFi networks chi tiết |

**API Monitor (rohitab.com):**

Monitor API calls real-time — hữu ích để hiểu app gọi Windows API như thế nào:
- Hook bất kỳ API function nào
- Xem parameters và return values
- Filter theo module, process, thread
- Decode structures và flags

---

## 1.4 Kiến Trúc Nội Bộ — Nhìn Từ Bên Trong

### 1.4.1 System Call Flow Chi Tiết

Khi ứng dụng gọi `ReadFile()`:

```
1. ReadFile() [kernel32.dll / kernelbase.dll]
   ├── Validate handle
   ├── Chuyển đổi parameters
   └── Gọi NtReadFile()

2. NtReadFile() [ntdll.dll — user-mode stub]
   ├── mov eax, <syscall_number>     ; Load system call number
   ├── mov r10, rcx                   ; Save first parameter
   ├── syscall                        ; CPU transitions to kernel mode
   │   ├── RIP → nt!KiSystemCall64
   │   ├── RSP → kernel stack
   │   ├── RFLAGS saved
   │   └── CS/SS → kernel segments

3. KiSystemCall64 [ntoskrnl.exe — kernel-mode entry]
   ├── swapgs                         ; Load kernel GS (KPCR)
   ├── Save user RSP to KPCR
   ├── Load kernel stack pointer
   ├── Build KTRAP_FRAME on kernel stack
   ├── Lookup KeServiceDescriptorTable[eax]
   ├── Validate parameter count
   ├── Copy parameters from user stack (if needed)
   └── Call nt!NtReadFile (kernel implementation)

4. NtReadFile() [ntoskrnl.exe — kernel implementation]
   ├── ObReferenceObjectByHandle()    ; Handle → FILE_OBJECT
   ├── Build IRP (I/O Request Packet)
   ├── IoCallDriver()                 ; Send to device driver
   ├── Driver processes request
   ├── IoCompleteRequest()            ; Driver completes IRP
   └── Return STATUS_SUCCESS / error

5. Trở về user mode:
   ├── sysret (hoặc iretq)
   ├── Restore user RSP, RIP
   └── Tiếp tục execute ở user mode
```

### 1.4.2 Processor Control Region (KPCR)

Mỗi logical CPU có một KPCR — structure chứa per-CPU state:

```
_KPCR (Kernel Processor Control Region)
├── GdtBase              ← Global Descriptor Table
├── IdtBase              ← Interrupt Descriptor Table
├── TssBase              ← Task State Segment
├── Self                 ← Pointer tới chính nó
├── CurrentPrcb          ← → _KPRCB
│   _KPRCB (Processor Control Block)
│   ├── CurrentThread    ← Thread đang chạy trên CPU này
│   ├── NextThread       ← Thread sẽ chạy tiếp
│   ├── IdleThread       ← Idle thread của CPU này
│   ├── Number           ← CPU number
│   ├── InterruptCount   ← Số interrupt đã xử lý
│   ├── DpcData          ← DPC queue
│   ├── DispatcherReadyListHead ← Ready queue
│   └── ...
├── Irql                 ← Current IRQL
├── Number               ← Processor number
└── ...
```

Trên x64, `KPCR` được trỏ bởi `GS` segment base trong kernel mode:

```
kd> !pcr                    ; Hiển thị KPCR
kd> dt nt!_KPCR @$pcr       ; Dump structure
kd> dt nt!_KPRCB @$prcb     ; Dump KPRCB
```

---

## 1.5 Thực Hành — Experiments

### Experiment 1.1: Xem System Call Table

```
kd> dps nt!KeServiceDescriptorTable L4
kd> dd nt!KiServiceTable L10          ; Đọc syscall table entries

# Trên x64, entries là relative offsets (4 bytes mỗi entry)
# Actual address = KiServiceTable + (entry >> 4)
```

### Experiment 1.2: Theo Dõi Process Creation

Dùng Process Monitor:
1. Mở ProcMon
2. Set filter: `Operation is Process Create`
3. Mở Notepad
4. Quan sát chuỗi: `explorer.exe` → `notepad.exe`
5. Xem properties: command line, environment variables, loaded DLLs

### Experiment 1.3: Khám Phá Object Namespace

Dùng WinObj:
1. Mở WinObj (Run as Administrator)
2. Navigate tới `\Device` — thấy tất cả device objects
3. Navigate tới `\BaseNamedObjects` — thấy named mutexes, events, sections
4. Navigate tới `\DosDevices` — thấy drive letters → device links
5. Navigate tới `\KernelObjects` — thấy kernel events

### Experiment 1.4: Xem Kernel Memory Layout

```
kd> !address                          ; Summary toàn bộ address space
kd> lm                                ; Loaded modules (kernel + drivers)
kd> !vm                               ; Virtual memory statistics
kd> !poolused 2                       ; Pool usage by tag (sorted by size)
```

### Experiment 1.5: Xem Security Token

```powershell
# Xem token của process hiện tại
whoami /all

# Output:
# User: DESKTOP\User (SID)
# Groups: Administrators, Users, ...
# Privileges: SeDebugPrivilege (Disabled), ...
```

```
# Trong WinDbg
kd> !token                            ; Current thread's token
kd> !token -n                         ; With names resolved
```

### Experiment 1.6: Native API — Syscall Number Enumeration

```
Mỗi Nt* function trong ntdll.dll có syscall number riêng.
Syscall numbers THAY ĐỔI giữa các Windows versions.

;; Xem syscall number của NtCreateFile:
0:000> u ntdll!NtCreateFile
ntdll!NtCreateFile:
  mov   r10,rcx
  mov   eax,55h           ← Syscall number = 0x55
  test  byte ptr [SharedUserData+0x308],1
  jne   ntdll!NtCreateFile+0x15
  syscall
  ret
  int   2Eh               ← Fallback cho HyperGuard/Xen
  ret

;; Enumeration bằng script:
;; PowerShell - parse ntdll exports
$ntdll = [System.IO.File]::ReadAllBytes("C:\Windows\System32\ntdll.dll")
# Hoặc dùng tool:
# NtCall64 - enumerate syscalls
# SyscallExtract - dump table

;; WinDbg - dump toàn bộ syscall table:
kd> r $t0 = poi(nt!KeServiceDescriptorTable)    ; KiServiceTable base
kd> r $t1 = poi(nt!KeServiceDescriptorTable+10) ; Number of entries
kd> .for (r $t2=0; @$t2<@$t1; r $t2=@$t2+1) {
      r $t3 = dwo(@$t0 + @$t2 * 4);
      .printf "Syscall %03x: %y\n", @$t2, (@$t0 + (@$t3 >> 4))
    }
```

**Syscall number thay đổi qua các version:**

Syscall numbers KHÔNG ổn định — Microsoft có thể thay đổi giữa các bản build.
Bảng dưới là ví dụ cho x64 Win11 24H2 — KHÔNG hardcode, luôn resolve dynamically.

| Function | Win11 24H2 (x64) |
|----------|-----------|
| NtCreateFile | 0x55 |
| NtOpenProcess | 0x26 |
| NtAllocateVirtualMemory | 0x18 |
| NtProtectVirtualMemory | 0x50 |
| NtWriteVirtualMemory | 0x3A |
| NtCreateThreadEx | 0xC7 |

**Syscall number quan trọng cho security research:**

```
0x18 NtAllocateVirtualMemory   — Allocate memory (shellcode injection)
0x3A NtWriteVirtualMemory      — Write to other process memory
0x50 NtProtectVirtualMemory    — Change page protection (RWX)
0x26 NtOpenProcess             — Open process handle
0xC7 NtCreateThreadEx          — Create remote thread
0x55 NtCreateFile              — File operations
0x0F NtClose                   — Close handle
0x23 NtQueryInformationProcess — Query process info (anti-debug)
0x1C NtQueryInformationThread  — Query thread info

Direct syscall technique (bypass API hooking):
  Thay vì gọi qua ntdll.dll (có thể bị hook bởi EDR):
  → Trực tiếp dùng syscall instruction với number đúng
  → EDR inline hook trong ntdll bị bypass
  → Phòng thủ: ETW TI provider, kernel callbacks vẫn detect được
```

### Experiment 1.7: Nt vs Zw Function Prefix Deep Dive

```
Ntoskrnl.exe export CẢ HAI phiên bản: NtCreateFile và ZwCreateFile.

Sự khác biệt quan trọng (CHỈ có ý nghĩa trong kernel mode):

Gọi từ USER MODE:
  NtCreateFile → ntdll stub → syscall → kernel NtCreateFile
  ZwCreateFile → ntdll stub → syscall → kernel NtCreateFile
  → KHÔNG có sự khác biệt (cả hai đều đi qua syscall)

Gọi từ KERNEL MODE (driver code):
  NtCreateFile:
    → Gọi trực tiếp implementation
    → PreviousMode = KernelMode (nếu caller là kernel)
    → NHƯNG nếu caller nhận buffer từ user:
      PreviousMode KHÔNG được set lại
      → Kernel PHẢI tự validate buffers
      
  ZwCreateFile:
    → Đi qua syscall wrapper
    → Force PreviousMode = KernelMode
    → Kernel TUYỆT ĐỐI tin tưởng tất cả buffers
    → Không có ProbeForRead/ProbeForWrite checks
    → An toàn hơn cho kernel callers dùng kernel buffers

Quy tắc cho driver developers:
  ✓ Dùng Zw* khi gọi với kernel-mode buffers
  ✗ KHÔNG dùng Zw* với user-mode buffers (skip validation = vulnerability)
  ✓ Dùng Nt* khi cần proper validation (nhưng phải set PreviousMode)
```

```
;; WinDbg - xem sự khác biệt:
kd> u nt!ZwCreateFile
nt!ZwCreateFile:
  mov   rax, rsp
  cli
  sub   rsp, 10h
  push  rax
  pushfq
  push  10h            ; KGDT64_R0_CODE
  lea   rax, [KiServiceInternal]
  push  rax
  mov   eax, 55h       ; Syscall number (same as NtCreateFile)
  jmp   KiServiceInternal

;; Zw* wrapper forces PreviousMode = KernelMode
;; Nt* is the direct implementation
```

### Experiment 1.8: Deep WinDbg — Extensions và Scripting

**Essential WinDbg Extensions:**

```
;; Built-in extensions:
!analyze -v              ; Auto crash analysis
!irp <addr>              ; IRP structure
!devstack <devobj>       ; Device stack
!drvobj <name> 7         ; Driver object + dispatch routines
!locks                   ; Kernel locks (deadlock hunting)
!running -it             ; Currently running threads (all CPUs)
!stacks 2                ; All thread stacks (kernel mode)
!vm                      ; Virtual memory statistics
!pfn <frame>             ; Page Frame Number info
!pte <va>                ; Page Table Entry for virtual address
!vad <addr>              ; Virtual Address Descriptor tree

;; External extensions:
.load mex.dll            ; Microsoft Extension — enhanced output
!mex.us                  ; Unique stacks
!mex.grep                ; Grep through output
!mex.t                   ; Enhanced thread list

.load SwishDbgExt.dll    ; Community extension
!ssdt                    ; System Service Descriptor Table
!idt_                    ; Enhanced IDT display
```

**WinDbg JavaScript Scripting (dx command):**

```javascript
// List all processes with handle count > 1000
dx @$cursession.Processes.Where(p => p.HandleCount > 1000)
   .Select(p => new { Name = p.Name, PID = p.Id, Handles = p.HandleCount })

// Find process by name
dx @$cursession.Processes.Where(p => p.Name == "explorer.exe")

// List threads of a process
dx @$cursession.Processes[<pid>].Threads
   .Select(t => new { TID = t.Id, State = t.KernelObject.State, 
                       Priority = t.KernelObject.Priority })

// Walk loaded modules
dx @$cursession.Processes[<pid>].Modules
   .Select(m => new { Name = m.Name, Base = m.BaseAddress, Size = m.Size })

// Conditional breakpoint (JavaScript)
bp /w "this.Parameters[0] == 0x80000001" ntdll!NtOpenKey

// Save as .js file and load:
// .scriptload C:\scripts\my_analysis.js
```

**Time Travel Debugging (TTD):**

```
;; Record execution:
;; WinDbg Preview → File → Launch executable (record) → Start

;; Replay commands:
!tt 0                    ; Go to beginning
!tt 100                  ; Go to end (100%)
!tt 50                   ; Go to middle
g-                       ; Reverse-continue
p-                       ; Reverse step
!positions               ; Show recorded time positions

;; Find when memory was written:
ba w4 <addr> ".if (poi(<addr>) == <value>) { !tt } .else { gc }"

;; TTD queries — find all calls to a function:
dx @$cursession.TTD.Calls("ntdll!NtCreateFile")
   .Select(c => new { TimeStart = c.TimeStart, ReturnValue = c.ReturnValue })

;; Find all memory writes to an address range:
dx @$cursession.TTD.Memory(<start_addr>, <end_addr>, "w")
```

### Experiment 1.9: Kernel Object Internals Deep Dive

```
;; Xem Object Manager TypeIndex obfuscation (từ Win10):
kd> dt nt!_OBJECT_HEADER
   +0x000 PointerCount     : Int8B
   +0x008 HandleCount      : Int8B
   +0x010 NextToFree       : Ptr64
   +0x018 Lock             : _EX_PUSH_LOCK
   +0x020 TypeIndex        : UChar        ← XOR'd với cookie
   +0x021 TraceFlags       : UChar
   +0x022 InfoMask         : UChar        ← Which optional headers exist
   +0x023 Flags            : UChar
   +0x028 SecurityDescriptor : Ptr64
   +0x030 Body             : _QUAD

;; Decode TypeIndex:
kd> db nt!ObHeaderCookie L1      ; Cookie byte
kd> r $t0 = byte(@$proc+20)     ; TypeIndex from header
;; RealTypeIndex = TypeIndex XOR ObHeaderCookie XOR (HeaderAddress >> 8)

;; InfoMask bits (which optional headers are present):
;;   0x01 = _OBJECT_HEADER_CREATOR_INFO (32 bytes before header)
;;   0x02 = _OBJECT_HEADER_NAME_INFO    
;;   0x04 = _OBJECT_HEADER_HANDLE_INFO
;;   0x08 = _OBJECT_HEADER_QUOTA_INFO
;;   0x10 = _OBJECT_HEADER_PROCESS_INFO
;;   0x20 = _OBJECT_HEADER_AUDIT_INFO
;;   0x40 = _OBJECT_HEADER_EXTENDED_INFO
;;   0x80 = _OBJECT_HEADER_PADDING_INFO

;; Optional header offsets are computed from ObpInfoMaskToOffset table:
kd> db nt!ObpInfoMaskToOffset L80

;; List all object types:
kd> dx (nt!_OBJECT_TYPE**)@@(nt!ObTypeIndexTable)
kd> !object \ObjectTypes
    Directory Object: ffff8a0123456780  Name: ObjectTypes
    - Type (Object Type)
    - Directory (Object Type)
    - SymbolicLink (Object Type)
    - Token (Object Type)
    - Job (Object Type)
    - Process (Object Type)
    - Thread (Object Type)
    - Event (Object Type)
    - Mutant (Object Type)
    - ...
```

**Object Reference Counting:**

```
Reference counting rules:
  PointerCount: kernel pointer references
  HandleCount:  user/kernel handle references

  ObReferenceObject()     → PointerCount++
  ObDereferenceObject()   → PointerCount--
  Handle open             → HandleCount++ AND PointerCount++
  Handle close            → HandleCount-- AND PointerCount--
  
  Object freed khi: PointerCount == 0 AND HandleCount == 0
  
  Type callback:
    ObjectType.TypeInfo.OpenProcedure    — called on new handle
    ObjectType.TypeInfo.CloseProcedure   — called on handle close
    ObjectType.TypeInfo.DeleteProcedure  — called on object deletion
    ObjectType.TypeInfo.ParseProcedure   — called during name lookup
    ObjectType.TypeInfo.SecurityProcedure — called for access check
```

### Experiment 1.10: System Information Classes

```c
// NtQuerySystemInformation — gateway to system internals:
NTSTATUS NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength
);

// Các classes quan trọng:
//  0  SystemBasicInformation           — # of processors, page size
//  2  SystemPerformanceInformation     — idle time, I/O counters
//  3  SystemTimeOfDayInformation       — boot time, current time
//  5  SystemProcessInformation         — ALL processes + threads
//  8  SystemProcessorPerformanceInfo   — per-CPU performance
// 11  SystemModuleInformation          — loaded kernel modules
// 16  SystemHandleInformation          — ALL open handles system-wide
// 23  SystemInterruptInformation       — per-CPU interrupt counts
// 44  SystemKernelDebuggerInformation  — debugger attached?
// 51  SystemExtendedHandleInformation  — enhanced handle info
// 53  SystemBigPoolInformation         — large pool allocations
// 76  SystemCodeIntegrityInformation   — CI status
// 103 SystemSecureBootInformation      — Secure Boot status
// 196 SystemShadowStackInformation     — CET shadow stack info

// Ví dụ: enumerate tất cả kernel modules
typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION;

// Security note:
// SystemHandleInformation (class 16) leaks kernel addresses
// → Used for KASLR bypass in older exploits
// Windows 10 1607+: requires SeDebugPrivilege or returns 0 addresses
```

```powershell
# PowerShell - dùng P/Invoke để gọi NtQuerySystemInformation:
# Hoặc đơn giản dùng WMI/CIM:
Get-CimInstance Win32_OperatingSystem | Select-Object *
Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors
Get-CimInstance Win32_PhysicalMemory | Measure-Object Capacity -Sum
```

### Experiment 1.11: Security-Relevant Experiments

```powershell
# 1. Xem process integrity levels:
Get-Process | ForEach-Object {
    $h = $_.Handle
    # (Cần P/Invoke OpenProcessToken + GetTokenInformation)
}
# Hoặc dùng Process Explorer → View → Select Columns → Integrity Level

# 2. Xem privileges của process:
whoami /priv
# SeDebugPrivilege     = Attach debugger tới ANY process (bao gồm LSASS)
# SeBackupPrivilege    = Bypass DACL để đọc ANY file
# SeRestorePrivilege   = Bypass DACL để ghi ANY file
# SeLoadDriverPrivilege = Load kernel driver (code execution in ring 0)
# SeImpersonatePrivilege = Impersonate tokens (potato attacks)
# SeTakeOwnershipPrivilege = Take ownership of ANY object

# 3. Detect API hooking (EDR presence):
# So sánh ntdll.dll in-memory vs on-disk
$ondisk = [System.IO.File]::ReadAllBytes("C:\Windows\System32\ntdll.dll")
# Compare .text section bytes — differences = inline hooks

# 4. Check Secure Boot và VBS status:
Confirm-SecureBootUEFI          # True = Secure Boot enabled
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
# VirtualizationBasedSecurityStatus: 2 = Running
# CodeIntegrityPolicyEnforcementStatus: 2 = Enforced (HVCI on)
```

```
;; WinDbg — Security experiments:

;; Xem token của một process:
kd> !process 0 1 lsass.exe
kd> !token <token_address>
    User: S-1-5-18 (NT AUTHORITY\SYSTEM)
    Groups:
        S-1-5-32-544 (BUILTIN\Administrators) (SE_GROUP_ENABLED)
        S-1-16-16384 (Mandatory Label\System) (SE_GROUP_INTEGRITY)
    Privileges:
        SeAssignPrimaryTokenPrivilege (SE_PRIVILEGE_ENABLED_BY_DEFAULT)
        SeTcbPrivilege (SE_PRIVILEGE_ENABLED)
        SeDebugPrivilege (SE_PRIVILEGE_ENABLED)
        ...

;; Xem Security Descriptor của một object:
kd> !sd <security_descriptor_address> 1

;; Xem object protection:
kd> !process 0 0 csrss.exe
;; csrss.exe là Protected Process Light (PPL)
;; → Cannot be killed, debugged, or memory-read by admin processes

;; Check kernel debugging detection:
kd> db nt!KdDebuggerEnabled L1
kd> db nt!KdDebuggerNotPresent L1
kd> dt nt!_KUSER_SHARED_DATA KdDebuggerEnabled 0xFFFFF78000000000
```

---

## 1.6 Tóm Tắt

| Khái niệm | Điểm chính |
|------------|------------|
| Windows API | Lớp trừu tượng user-mode, gọi xuống Native API (ntdll) |
| API Sets | Virtual DLL names map tới real implementations, tách API khỏi DLL |
| COM/WinRT | COM = binary interop standard; WinRT = modern COM-based API |
| PE Format | MZ→PE→Optional→Sections; IAT cho imports; DataDirectory cho features |
| SharedUserData | Fixed address 0x7FFE0000, system time/version không cần syscall |
| Native API | System call stubs, prefix Nt (direct) / Zw (force kernel PreviousMode) |
| Syscall Numbers | Per-version; enumerable từ ntdll stubs hoặc SSDT |
| Process | Container: address space + handles + token + threads |
| Thread | Đơn vị thực thi, có stack riêng, được kernel schedule |
| Virtual Memory | Mỗi process có address space riêng, paging tự động, CoW |
| Kernel/User mode | Ranh giới bảo vệ phần cứng, chuyển qua syscall/sysret |
| Hypervisor | Ring -1, VBS/HVCI bảo vệ ngay cả khi kernel bị compromise |
| Objects | Object header + TypeIndex (XOR obfuscated) + reference counting |
| Security | Token + Security Descriptor + Access Check + Integrity Levels |
| Registry | Hierarchical database, hive files, per-key security descriptors |
| Tools | Sysinternals + WinDbg (TTD, dx, JavaScript) + ETW = bộ 3 quan trọng nhất |

> **Tiếp theo: [Chapter 2 — Kiến Trúc Hệ Thống](Chapter_02_System_Architecture.md)**
> Đi sâu vào kiến trúc tổng thể: Executive, Kernel, HAL, drivers, subsystems.
