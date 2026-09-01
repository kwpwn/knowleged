# Chapter 3: Processes và Jobs

> Chương này đi sâu vào cấu trúc nội bộ của processes, cách Windows tạo process,
> Protected Processes, Pico processes, Trustlets, và Job objects cho resource management.

---

## 3.1 Tạo Process — CreateProcess Flow

### 3.1.1 CreateProcess API Family

```c
// Standard
BOOL CreateProcessW(
    LPCWSTR lpApplicationName,    // Đường dẫn exe (optional)
    LPWSTR  lpCommandLine,        // Command line
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL    bInheritHandles,      // Kế thừa handles từ parent
    DWORD   dwCreationFlags,      // CREATE_SUSPENDED, DEBUG_PROCESS, ...
    LPVOID  lpEnvironment,        // Environment block
    LPCWSTR lpCurrentDirectory,   // Working directory
    LPSTARTUPINFOW lpStartupInfo, // Window attributes
    LPPROCESS_INFORMATION lpProcessInformation  // Output: handles + IDs
);

// Extended (Vista+)
BOOL CreateProcessAsUserW(...)    // Chạy as different user
BOOL CreateProcessWithLogonW(...) // Chạy with logon credentials
BOOL CreateProcessWithTokenW(...) // Chạy with duplicated token

// Mới hơn (Win10+):
// PROC_THREAD_ATTRIBUTE_LIST cho extended attributes
```

**Creation flags quan trọng:**

| Flag | Giá trị | Ý nghĩa |
|------|---------|---------|
| `CREATE_SUSPENDED` | 0x4 | Tạo thread chính nhưng không chạy |
| `CREATE_NEW_CONSOLE` | 0x10 | Console window mới |
| `CREATE_NO_WINDOW` | 0x08000000 | Không tạo console window |
| `DEBUG_PROCESS` | 0x1 | Debug process và children |
| `CREATE_BREAKAWAY_FROM_JOB` | 0x01000000 | Thoát khỏi parent job |
| `EXTENDED_STARTUPINFO_PRESENT` | 0x80000 | Dùng STARTUPINFOEX |

### 3.1.2 Bảy Giai Đoạn Tạo Process

```
CreateProcessW()
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│ Stage 1: Chuyển đổi và validate parameters               │
│  - Resolve application name                               │
│  - Parse command line                                      │
│  - Merge creation flags                                    │
└───────────────────────┬─────────────────────────────────┘
                        ▼
┌─────────────────────────────────────────────────────────┐
│ Stage 2: Mở image file để thực thi                       │
│  - NtOpenFile() → mở .exe file                           │
│  - NtCreateSection() → tạo image section                  │
│  - Kiểm tra image type: Win32, POSIX, MS-DOS, WoW64...   │
│  - Nếu batch/cmd → chạy cmd.exe                          │
│  - Nếu 16-bit → chạy ntvdm.exe                           │
└───────────────────────┬─────────────────────────────────┘
                        ▼
┌─────────────────────────────────────────────────────────┐
│ Stage 3: Tạo Windows Executive process object             │
│  - NtCreateProcessEx() / NtCreateUserProcess()            │
│  - Allocate EPROCESS structure                             │
│  - Tạo address space (page directory)                      │
│  - Tạo kernel process (KPROCESS) block                     │
│  - Map ntdll.dll vào process address space                 │
│  - Tạo PEB (Process Environment Block)                     │
│  - Clone parent's handle table (nếu inherit)               │
│  - Set up access token (copy hoặc assigned)                │
└───────────────────────┬─────────────────────────────────┘
                        ▼
┌─────────────────────────────────────────────────────────┐
│ Stage 4: Tạo initial thread và stack                      │
│  - NtCreateThread() / NtCreateThreadEx()                  │
│  - Allocate ETHREAD structure                              │
│  - Tạo kernel stack                                        │
│  - Tạo TEB (Thread Environment Block)                      │
│  - Tạo user-mode stack                                     │
│  - Set initial context (RIP = ntdll!RtlUserThreadStart)    │
└───────────────────────┬─────────────────────────────────┘
                        ▼
┌─────────────────────────────────────────────────────────┐
│ Stage 5: Thông báo Windows subsystem (csrss.exe)          │
│  - Gửi message tới csrss cho session tương ứng            │
│  - csrss tạo internal data structures                      │
│  - Allocate CSR_PROCESS và CSR_THREAD                     │
└───────────────────────┬─────────────────────────────────┘
                        ▼
┌─────────────────────────────────────────────────────────┐
│ Stage 6: Resume initial thread                            │
│  - NtResumeThread() (trừ khi CREATE_SUSPENDED)            │
│  - Thread bắt đầu execute                                 │
└───────────────────────┬─────────────────────────────────┘
                        ▼
┌─────────────────────────────────────────────────────────┐
│ Stage 7: Process initialization trong context mới         │
│  - ntdll!LdrInitializeThunk()                             │
│  - Initialize PEB fields                                   │
│  - Initialize heap (RtlCreateHeap)                         │
│  - Load imported DLLs (LdrLoadDll)                         │
│  - Call DLL_PROCESS_ATTACH cho mỗi DLL                     │
│  - Call CRT initialization                                 │
│  - Jump to application entry point (WinMainCRTStartup)     │
└─────────────────────────────────────────────────────────┘
```

### 3.1.3 Bảy Giai Đoạn — Phân Tích Chi Tiết Từng Stage

#### Stage 1: Validate Parameters và Resolve Image Path

Kernel32.dll thực hiện toàn bộ Stage 1 ở **user mode** trước khi gọi vào kernel:

```
CreateProcessW() / CreateProcessInternalW()
│
├── 1a. Parse lpApplicationName + lpCommandLine
│   - Nếu lpApplicationName == NULL → tách exe path từ lpCommandLine
│   - Resolve path: SearchPathW() nếu không có full path
│   - Handle special prefixes: "\\?\" , UNC paths
│   - Kiểm tra PATHEXT nếu không có extension
│
├── 1b. Detect image type (trước khi gọi kernel)
│   - Đọc header bytes đầu tiên (MZ signature check)
│   - .bat/.cmd → khởi chạy cmd.exe /c "script.bat"
│   - .com → legacy DOS stub check
│   - POSIX executable → chạy posix.exe wrapper
│   - 16-bit NE → chạy ntvdm.exe (nếu supported)
│
├── 1c. Merge creation flags
│   - DEBUG_PROCESS / DEBUG_ONLY_THIS_PROCESS → set debug flags
│   - CREATE_SUSPENDED → ghi nhớ để không resume ở Stage 6
│   - EXTENDED_STARTUPINFO_PRESENT → validate PROC_THREAD_ATTRIBUTE_LIST
│     - PROC_THREAD_ATTRIBUTE_PARENT_PROCESS → override parent
│     - PROC_THREAD_ATTRIBUTE_HANDLE_LIST → specific handle inheritance
│     - PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY → mitigation flags
│     - PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL → PP/PPL level
│
├── 1d. Build RTL_USER_PROCESS_PARAMETERS
│   - RtlCreateProcessParametersEx() tạo normalized block:
│     ImagePathName, CommandLine, CurrentDirectory
│     Environment (clone hoặc inherit)
│     WindowTitle, DesktopInfo, ShellInfo
│     StandardInput/Output/Error handles
│
└── 1e. Call NtCreateUserProcess() → chuyển sang kernel mode
```

**Error cases quan trọng ở Stage 1:**
- `ERROR_FILE_NOT_FOUND` — không tìm được exe
- `ERROR_BAD_EXE_FORMAT` — file không phải PE valid
- `ERROR_ELEVATION_REQUIRED` — cần UAC elevation (manifest yêu cầu)

#### Stage 2: Tạo Executive Process Object (Kernel Mode)

`NtCreateUserProcess()` → `PspAllocateProcess()`:

```
PspAllocateProcess()
│
├── 2a. Validate caller's access rights
│   - SeAssignPrimaryTokenPrivilege nếu assign custom token
│   - SeTcbPrivilege cho một số flags
│
├── 2b. Open image file và tạo section
│   - IoCreateFileEx() → mở .exe file
│   - MmCreateSection() → IMAGE section object
│     - Parse PE headers (DOS Header → NT Headers → Section Headers)
│     - Validate checksum nếu required
│     - Kiểm tra digital signature (CI.dll - Code Integrity)
│     - Xác định machine type: IMAGE_FILE_MACHINE_AMD64/I386/ARM64
│
├── 2c. Allocate EPROCESS structure
│   - ObCreateObjectEx(PsProcessType, sizeof(EPROCESS), ...)
│   - Zero-initialize toàn bộ structure
│   - Generate unique PID: ExCreateHandle() trong PspCidTable
│   - PID là index vào global handle table (PspCidTable)
│
├── 2d. Initialize KPROCESS block (Pcb)
│   - KeInitializeProcess()
│   - DirectoryTableBase = MmCreateProcessAddressSpace()
│     → Allocate page directory (PML4 on x64)
│     → Map shared system space entries
│     → Map hyperspace page
│   - BasePriority = PROCESS_PRIORITY_CLASS → base value
│   - Affinity = system default hoặc inherited from parent
│   - QuantumReset = system quantum value
│
├── 2e. Setup address space
│   - MmInitializeProcessAddressSpace()
│   - Map image section → user-mode VA (thường 0x00007FF6`XXXXXXXX)
│   - Map ntdll.dll section (từ KnownDlls hoặc disk)
│   - Map locale/NLS data sections
│   - Map API Set schema (apisetschema.dll)
│
├── 2f. Create PEB (Process Environment Block)
│   - MmCreatePeb()
│   - Allocate 1 page trong user-mode space
│   - Initialize: ImageBaseAddress, OSVersion, NumberOfProcessors
│   - Copy RTL_USER_PROCESS_PARAMETERS vào new address space
│   - Setup ProcessHeap = NULL (sẽ tạo ở Stage 7)
│
├── 2g. Clone/assign access token
│   - Nếu không specify token → duplicate parent's primary token
│   - SeSubProcessToken() → reference counting
│   - Token chứa: SIDs, privileges, integrity level
│
├── 2h. Handle table
│   - ObInitProcess() → tạo handle table
│   - Nếu bInheritHandles = TRUE:
│     ExDupHandleTable() → copy inheritable handles
│   - Handle 0 luôn reserved (invalid handle value)
│
└── 2i. Register notifications
    - PspCallProcessNotifyRoutines(CREATE)
    - ETW event: Microsoft-Windows-Kernel-Process
    - Security audit log nếu enabled
```

#### Stage 3: Tạo Initial Thread

```
PspAllocateThread()
│
├── 3a. Allocate ETHREAD structure
│   - ObCreateObjectEx(PsThreadType, sizeof(ETHREAD), ...)
│   - Generate unique TID trong PspCidTable
│
├── 3b. Initialize KTHREAD block (Tcb)
│   - KeInitializeThread()
│   - Priority = process BasePriority
│   - State = Initialized (chưa Ready)
│   - WaitIrql, WaitMode, WaitReason
│
├── 3c. Allocate kernel stack
│   - MmCreateKernelStack()
│   - Default size: 24KB (x64), 12KB (x86)
│   - Large stack: 256KB nếu cần (driver callbacks)
│   - Stack guard page ở bottom
│
├── 3d. Create TEB (Thread Environment Block)
│   - MmCreateTeb()
│   - Allocate trong user-mode space (thường 0x000000XX`XXXFE000)
│   - TEB chứa: StackBase, StackLimit, PEB pointer
│   - TEB.Self = linear address của chính TEB
│   - gs:[0x30] (x64) / fs:[0x18] (x86) → TEB address
│
├── 3e. Allocate user-mode stack
│   - MmCreateStack() / NtAllocateVirtualMemory()
│   - Default size: 1MB reserved, 1 page committed + guard page
│   - Stack grows downward: StackBase (high) → StackLimit (low)
│
└── 3f. Set initial thread context
    - CONTEXT structure:
      Rip = ntdll!RtlUserThreadStart
      Rcx = real entry point (exe's AddressOfEntryPoint)
      Rdx = PEB address
      Rsp = top of user stack
    - Thread ở trạng thái Suspended
```

#### Stage 4: Subsystem Notification (csrss.exe)

```
CsrClientCallServer(BASESRV_API_CREATE_PROCESS)
│
├── 4a. Send ALPC message tới csrss.exe cho session hiện tại
│   - Mỗi session có riêng csrss.exe instance
│   - Session 0: system services
│   - Session 1+: interactive user sessions
│
├── 4b. csrss allocate CSR_PROCESS structure
│   - CsrAllocateProcess()
│   - Link vào internal process list
│   - Copy process/thread handles
│   - Set console group (nếu console app)
│
├── 4c. csrss allocate CSR_THREAD structure
│   - CsrAllocateThread()
│   - Associate với CSR_PROCESS
│
├── 4d. csrss setup console (nếu console application)
│   - Allocate console buffer
│   - Create console window (conhost.exe)
│   - Connect standard handles
│
└── 4e. csrss notify kernel32
    - BaseSrvCreateProcess callback
    - Update internal tracking structures
```

#### Stage 5: Debug Port Setup (nếu Debugger Attached)

```
Nếu DEBUG_PROCESS hoặc DEBUG_ONLY_THIS_PROCESS:
│
├── 5a. DbgkCreateThread() cho initial thread
│   - Tạo debug object (nếu chưa có)
│   - NtCreateDebugObject() → DebugPort trên EPROCESS
│
├── 5b. Gửi debug events:
│   - CREATE_PROCESS_DEBUG_EVENT → debugger
│   - LOAD_DLL_DEBUG_EVENT cho ntdll.dll
│   - Process ở trạng thái suspended chờ debugger continue
│
└── 5c. Nếu DEBUG_PROCESS (không phải ONLY_THIS):
    - Tất cả child processes cũng inherit debug port
    - Toàn bộ process tree sẽ bị debug
```

#### Stage 6: Resume Initial Thread

```
NtResumeThread()
│
├── 6a. Kiểm tra CREATE_SUSPENDED flag
│   - Nếu set → return ngay, thread vẫn suspended
│   - Caller phải manually gọi ResumeThread() sau
│
├── 6b. KiReadyThread()
│   - Thread chuyển từ Initialized → Ready
│   - Insert vào ready queue của processor
│   - Scheduler sẽ dispatch thread khi có CPU time
│
└── 6c. CreateProcessW() return SUCCESS
    - lpProcessInformation filled:
      hProcess, hThread, dwProcessId, dwThreadId
    - Caller có handles tới new process/thread
```

#### Stage 7: Process Initialization (New Process Context)

Stage 7 chạy trong **context của process mới**, không phải parent:

```
ntdll!LdrInitializeThunk()
│
├── 7a. LdrpInitialize()
│   ├── Initialize thread-local structures
│   ├── Setup structured exception handling (SEH)
│   └── Call LdrpInitializeProcess() cho first thread
│
├── 7b. LdrpInitializeProcess()
│   ├── Initialize PEB fields còn thiếu
│   │   - NtGlobalFlag (từ registry Image File Execution Options)
│   │   - ProcessHeap = RtlCreateHeap(HEAP_GROWABLE, ...)
│   │   - NumberOfHeaps = 1
│   │   - TlsBitmap, TlsExpansionBitmap
│   │
│   ├── Initialize Ldr data tables
│   │   - PEB_LDR_DATA initialization
│   │   - InLoadOrderModuleList → add exe entry
│   │   - InMemoryOrderModuleList → add exe entry
│   │   - InInitializationOrderModuleList (sẽ fill sau)
│   │
│   ├── LdrpMapDll() cho main executable
│   │   - Verify PE image headers
│   │   - Process bound imports (nếu có)
│   │
│   ├── LdrpWalkImportDescriptor()
│   │   - Duyệt Import Directory Table
│   │   - Cho mỗi imported DLL:
│   │     LdrpLoadDll() → recursive load
│   │     LdrpSnapThunks() → resolve function pointers
│   │     Fill IAT (Import Address Table) entries
│   │
│   ├── LdrpRunInitializeRoutines()
│   │   - Gọi DllMain(DLL_PROCESS_ATTACH) cho mỗi DLL
│   │   - Thứ tự: dependencies trước, rồi mới DLL phụ thuộc
│   │   - Nếu DllMain return FALSE → DLL load failure
│   │   - TLS callbacks gọi TRƯỚC DllMain
│   │
│   └── Hoàn thành initialization
│
├── 7c. NtContinue() / ZwContinue()
│   - Restore initial context
│   - Jump tới RtlUserThreadStart
│
└── 7d. RtlUserThreadStart()
    ├── Call application entry point
    │   - GUI app: wWinMainCRTStartup → wWinMain
    │   - Console app: wmainCRTStartup → wmain
    │   - DLL: _DllMainCRTStartup → DllMain
    ├── CRT initialization: __initterm, _cinit
    │   - C++ static constructors
    │   - atexit registration
    └── Entry point returns → ExitProcess()
```

**Debug observation - Stage 7 timing:**
```
;; WinDbg: Break tại LdrInitializeThunk để observe Stage 7
sxe ld:ntdll          ; Break khi ntdll load
bp ntdll!LdrInitializeThunk
bp ntdll!LdrpInitializeProcess
bp ntdll!LdrpLoadDll  ; Mỗi DLL load
bp ntdll!LdrpRunInitializeRoutines  ; DllMain calls
```

### 3.1.4 NtCreateUserProcess — Modern Path

Từ Windows Vista, `NtCreateUserProcess()` thay thế `NtCreateProcessEx()` + `NtCreateThread()`:

- Một system call duy nhất tạo cả process VÀ initial thread
- Atomic operation — không thể observe process mà chưa có thread
- Kernel thực hiện tất cả steps trong kernel mode
- Tránh race conditions và security issues của phương pháp cũ

```c
NTSTATUS NtCreateUserProcess(
    PHANDLE ProcessHandle,
    PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess,
    ACCESS_MASK ThreadDesiredAccess,
    POBJECT_ATTRIBUTES ProcessObjectAttributes,
    POBJECT_ATTRIBUTES ThreadObjectAttributes,
    ULONG ProcessFlags,           // PROCESS_CREATE_FLAGS_*
    ULONG ThreadFlags,            // THREAD_CREATE_FLAGS_*
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    PPS_CREATE_INFO CreateInfo,
    PPS_ATTRIBUTE_LIST AttributeList
);
```

---

## 3.2 Process Internals

### 3.2.1 _EPROCESS Structure (Chi Tiết)

```
_EPROCESS
│
├── _KPROCESS (Pcb)                     ← Kernel Process Block
│   ├── Header                          ← DISPATCHER_HEADER (waitable)
│   ├── ProfileListHead                 ← Profiling
│   ├── DirectoryTableBase              ← CR3 — page table root
│   ├── ThreadListHead                  ← Linked list of KTHREAD
│   ├── ProcessLock                     ← Push lock
│   ├── Affinity                        ← KAFFINITY_EX
│   ├── ReadyListHead                   ← Threads ready to run
│   ├── ProcessFlags                    ← Misc flags
│   ├── BasePriority                    ← Default thread priority
│   ├── QuantumReset                    ← Default quantum
│   ├── IdealNode                       ← Preferred NUMA node
│   ├── UserTime / KernelTime           ← CPU time accounting
│   └── InstrumentationCallback         ← Instrumentation callback
│
├── UniqueProcessId                     ← PID
├── ActiveProcessLinks                  ← Linked list of all processes
├── RundownProtect                      ← Process rundown protection
│
├── Flags / Flags2 / Flags3            ← Nhiều behavioral flags
│   ├── VmDeleted                       ← Address space deleted
│   ├── ProcessDelete                   ← Being deleted
│   ├── Wow64Process                    ← 32-bit on 64-bit
│   ├── ProtectedProcess                ← Protected process
│   ├── DefaultHardErrorProcessing      ← Hard error handling
│   └── ...
│
├── CreateTime                          ← Process creation timestamp
├── ExitTime                            ← Process exit timestamp
├── ExitStatus                          ← Exit code
│
├── ObjectTable                         ← Handle table (HANDLE_TABLE*)
├── Token (EX_FAST_REF)                ← Primary access token
│
├── Peb                                 ← Process Environment Block (user-mode)
├── PeakVirtualSize                     ← Peak virtual memory
├── VirtualSize                         ← Current virtual memory
├── WorkingSetPage                      ← Working set list page
│
├── InheritedFromUniqueProcessId        ← Parent PID
├── ImageFileName[16]                   ← Short name (15 chars + null)
├── SeAuditProcessCreationInfo          ← Full image path
│
├── Job                                 ← Job object (nếu trong job)
├── Wow64Process                        ← WoW64 data (32-bit processes)
├── VadRoot                             ← Virtual Address Descriptor AVL tree
│
├── SectionBaseAddress                  ← Image base address
├── SectionObject                       ← Executable image section
│
├── Session                             ← Session pointer
├── SessionProcessLinks                 ← Per-session process list
│
├── DebugPort                           ← Debug port (nếu đang bị debug)
├── ExceptionPortData                   ← Exception port
│
├── MitigationFlags / MitigationFlags2  ← Exploit mitigations
│   ├── DEP (NX)
│   ├── ASLR (High Entropy, Force, Bottom-up)
│   ├── CFG (Control Flow Guard)
│   ├── CIG (Code Integrity Guard)
│   ├── ACG (Arbitrary Code Guard)
│   ├── CET Shadow Stacks
│   └── ...
│
├── DiskCounters                        ← Per-process I/O stats
├── EnergyValues                        ← Energy usage tracking
└── ...
```

### 3.2.2 Process Environment Block (PEB)

PEB nằm ở **user-mode** address space — accessible bởi cả user code và kernel:

```
_PEB
├── InheritedAddressSpace              ← Inherited from parent
├── BeingDebugged                       ← TRUE nếu đang bị debug
├── ImageBaseAddress                    ← Base address of .exe
├── Ldr (PEB_LDR_DATA*)                ← Loaded module database
│   ├── InLoadOrderModuleList           ← DLLs theo thứ tự load
│   ├── InMemoryOrderModuleList         ← DLLs theo thứ tự memory
│   └── InInitializationOrderModuleList ← DLLs theo thứ tự init
├── ProcessParameters                   ← Command line, environment, ...
│   ├── ImagePathName                   ← Full .exe path
│   ├── CommandLine                     ← Full command line
│   ├── Environment                     ← Environment variables block
│   ├── CurrentDirectory                ← Working directory
│   ├── DllPath                         ← DLL search path
│   ├── WindowTitle                     ← Console window title
│   └── ...
├── SubSystemData
├── ProcessHeap                         ← Default heap handle
├── FastPebLock                         ← PEB synchronization
├── NumberOfProcessors                  ← CPU count
├── NtGlobalFlag                        ← Debugging flags
├── OSMajorVersion / OSMinorVersion     ← OS version
├── OSBuildNumber                       ← Build number
├── SessionId                           ← Session ID
└── ...
```

**Anti-debug trick phổ biến — kiểm tra PEB:**

```c
// Kiểm tra BeingDebugged flag
BOOL IsDebuggerPresent() {
    return NtCurrentPeb()->BeingDebugged;
}

// Kiểm tra NtGlobalFlag
// Nếu đang debug: NtGlobalFlag chứa FLG_HEAP_ENABLE_TAIL_CHECK |
//                  FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
DWORD flags = NtCurrentPeb()->NtGlobalFlag;
if (flags & 0x70) { /* debugger detected */ }

// Kiểm tra ProcessDebugPort
DWORD_PTR debugPort = 0;
NtQueryInformationProcess(GetCurrentProcess(),
    ProcessDebugPort, &debugPort, sizeof(debugPort), NULL);
if (debugPort) { /* debugger detected */ }
```

### 3.2.3 PEB Deep Dive — Field Offsets và Khai Thác

**PEB Structure chi tiết với x64 offsets:**

```
_PEB (x64 offsets)
+0x000 InheritedAddressSpace    : UChar
+0x001 ReadImageFileExecOptions : UChar
+0x002 BeingDebugged            : UChar        ← Anti-debug check #1
+0x003 BitField                 : UChar
        ├── ImageUsesLargePages      : Pos 0
        ├── IsProtectedProcess       : Pos 1
        ├── IsImageDynamicallyRelocated : Pos 2
        ├── SkipPatchingUser32Forwarders : Pos 3
        ├── IsPackagedProcess        : Pos 4
        ├── IsAppContainer           : Pos 5
        ├── IsProtectedProcessLight  : Pos 6
        └── IsLongPathAwareProcess   : Pos 7
+0x008 Mutant                   : Ptr64        ← Thường là -1 (INVALID)
+0x010 ImageBaseAddress          : Ptr64        ← Base address của .exe
+0x018 Ldr                       : Ptr64 _PEB_LDR_DATA  ← Module database
+0x020 ProcessParameters         : Ptr64 _RTL_USER_PROCESS_PARAMETERS
+0x028 SubSystemData             : Ptr64
+0x030 ProcessHeap               : Ptr64        ← Default heap handle
+0x038 FastPebLock               : Ptr64 _RTL_CRITICAL_SECTION
+0x040 AtlThunkSListPtr          : Ptr64
+0x048 IFEOKey                   : Ptr64        ← Image File Exec Options
+0x050 CrossProcessFlags         : Uint4B
+0x058 KernelCallbackTable       : Ptr64        ← Win32k callback table
+0x060 SystemReserved            : Uint4B
+0x064 AtlThunkSListPtr32        : Uint4B
+0x068 ApiSetMap                 : Ptr64        ← API Set redirection map
+0x070 TlsExpansionCounter       : Uint4B
+0x078 TlsBitmap                 : Ptr64
+0x080 TlsBitmapBits[2]          : Uint4B[2]
+0x088 ReadOnlySharedMemoryBase  : Ptr64
+0x098 AnsiCodePageData          : Ptr64
+0x0A0 OemCodePageData           : Ptr64
+0x0A8 UnicodeCaseTableData      : Ptr64
+0x0B0 NumberOfProcessors        : Uint4B
+0x0B4 NtGlobalFlag              : Uint4B       ← Anti-debug check #2
+0x0BC CriticalSectionTimeout    : _LARGE_INTEGER
+0x0C8 HeapSegmentReserve        : Uint8B
+0x0D0 HeapSegmentCommit         : Uint8B
+0x0D8 HeapDeCommitTotalFreeThreshold : Uint8B
+0x0E0 HeapDeCommitFreeBlockThreshold : Uint8B
+0x0F0 NumberOfHeaps             : Uint4B
+0x0F4 MaximumNumberOfHeaps      : Uint4B
+0x0F8 ProcessHeaps              : Ptr64        ← Array of heap handles
+0x118 OSMajorVersion            : Uint4B
+0x11C OSMinorVersion            : Uint4B
+0x120 OSBuildNumber             : Uint2B
+0x124 ImageSubsystem            : Uint4B
+0x128 ImageSubsystemMajorVersion : Uint4B
+0x2C0 SessionId                 : Uint4B
```

**Truy cập PEB từ user-mode code:**

```c
// Cách 1: Inline assembly / intrinsic (x64)
// TEB nằm tại gs:[0x30], PEB pointer tại TEB+0x60
PEB* peb = (PEB*)__readgsqword(0x60);

// Cách 2: NtCurrentTeb() → PEB
PEB* peb = NtCurrentTeb()->ProcessEnvironmentBlock;

// Cách 3: NtQueryInformationProcess
PROCESS_BASIC_INFORMATION pbi;
NtQueryInformationProcess(GetCurrentProcess(),
    ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
PEB* peb = pbi.PebBaseAddress;

// Đọc PEB của process KHÁC (cần PROCESS_VM_READ + PROCESS_QUERY_INFORMATION)
PROCESS_BASIC_INFORMATION pbi;
NtQueryInformationProcess(hTargetProcess,
    ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
PEB remotePeb;
ReadProcessMemory(hTargetProcess, pbi.PebBaseAddress,
    &remotePeb, sizeof(remotePeb), NULL);
```

**WinDbg - Xem PEB chi tiết:**
```
;; Kernel-mode debugger
kd> !process 0 0 notepad.exe        ; Tìm EPROCESS address
kd> .process /i /p <EPROCESS>       ; Switch context
kd> !peb                             ; Formatted PEB output
kd> dt ntdll!_PEB @$peb             ; Raw PEB structure

;; Xem PEB->Ldr chi tiết
kd> dt ntdll!_PEB @$peb Ldr
kd> dt ntdll!_PEB_LDR_DATA poi(@$peb+0x18)

;; User-mode debugger
0:000> r $peb                       ; PEB address
0:000> dt ntdll!_PEB @$peb
0:000> !peb
0:000> dt ntdll!_PEB @$peb BeingDebugged NtGlobalFlag ProcessHeap
```

#### PEB_LDR_DATA — Loaded Module Database

PEB_LDR_DATA quản trị **ba linked lists** chứa thông tin tất cả DLLs đã load:

```
_PEB_LDR_DATA
+0x000 Length                          : Uint4B
+0x004 Initialized                     : UChar
+0x008 SsHandle                        : Ptr64
+0x010 InLoadOrderModuleList           : _LIST_ENTRY    ← Thứ tự load
+0x020 InMemoryOrderModuleList         : _LIST_ENTRY    ← Thứ tự memory address
+0x030 InInitializationOrderModuleList : _LIST_ENTRY    ← Thứ tự DllMain() call
+0x040 EntryInProgress                 : Ptr64
+0x048 ShutdownInProgress              : UChar
+0x050 ShutdownThreadId                : Ptr64

Mỗi entry trong list là _LDR_DATA_TABLE_ENTRY:
+0x000 InLoadOrderLinks           : _LIST_ENTRY
+0x010 InMemoryOrderLinks         : _LIST_ENTRY
+0x020 InInitializationOrderLinks : _LIST_ENTRY
+0x030 DllBase                    : Ptr64       ← Mapped base address
+0x038 EntryPoint                 : Ptr64       ← DllMain address
+0x040 SizeOfImage                : Uint4B
+0x048 FullDllName                : _UNICODE_STRING
+0x058 BaseDllName                : _UNICODE_STRING
+0x068 FlagGroup[4]               : UChar[4]
+0x068 Flags                      : Uint4B
        ├── LDRP_PACKAGED_BINARY           : Pos 0
        ├── LDRP_STATIC_LINK               : Pos 1
        ├── LDRP_IMAGE_DLL                 : Pos 2
        ├── LDRP_LOAD_NOTIFICATIONS_SENT   : Pos 3
        ├── LDRP_ENTRY_PROCESSED           : Pos 14
        ├── LDRP_DONT_CALL_FOR_THREADS     : Pos 18
        ├── LDRP_PROCESS_ATTACH_CALLED     : Pos 19
        └── LDRP_IMAGE_NOT_AT_BASE         : Pos 27
+0x070 ObsoleteLoadCount           : Uint2B
+0x072 TlsIndex                    : Uint2B
+0x074 HashLinks                   : _LIST_ENTRY
+0x084 TimeDateStamp               : Uint4B
```

**Duyệt module list từ WinDbg:**
```
;; Liệt kê tất cả modules theo load order
0:000> !dlls -l     ; InLoadOrderModuleList
0:000> !dlls -m     ; InMemoryOrderModuleList
0:000> !dlls -i     ; InInitializationOrderModuleList

;; Manual traversal
0:000> dt ntdll!_PEB_LDR_DATA poi(@$peb+0x18)
0:000> !list -x "dt ntdll!_LDR_DATA_TABLE_ENTRY @$extret"  \
       poi(poi(@$peb+0x18)+0x10)

;; Tìm một DLL cụ thể
0:000> lm m kernel32   ; Module info
0:000> !dlls -c kernel32
```

#### PEB Manipulation bởi Malware

Malware thường thao tác PEB để ẩn DLL hoặc bypass anti-debug:

```
Kỹ thuật 1: Unlink DLL khỏi module lists
==============================================
Malware tự unlink LDR_DATA_TABLE_ENTRY khỏi cả 3 lists:

void UnlinkModule(HMODULE hDll) {
    PEB* peb = (PEB*)__readgsqword(0x60);
    PEB_LDR_DATA* ldr = peb->Ldr;
    LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
    LIST_ENTRY* curr = head->Flink;

    while (curr != head) {
        LDR_DATA_TABLE_ENTRY* entry =
            CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY,
                              InLoadOrderLinks);
        if (entry->DllBase == hDll) {
            // Unlink từ InLoadOrderModuleList
            curr->Blink->Flink = curr->Flink;
            curr->Flink->Blink = curr->Blink;
            // Tương tự cho InMemoryOrderModuleList
            // và InInitializationOrderModuleList
            break;
        }
        curr = curr->Flink;
    }
}

Hậu quả: Tool dùng PEB để liệt kê modules sẽ không thấy DLL đã unlink.
Phát hiện: So sánh PEB module list với VAD tree hoặc
           NtQueryVirtualMemory() MEM_IMAGE regions.

Kỹ thuật 2: Patch BeingDebugged flag
==============================================
// Anti-anti-debug: clear BeingDebugged
PEB* peb = (PEB*)__readgsqword(0x60);
peb->BeingDebugged = 0;

// Patch NtGlobalFlag (clear debug heap flags)
peb->NtGlobalFlag &= ~0x70;
// 0x70 = FLG_HEAP_ENABLE_TAIL_CHECK (0x10)
//      | FLG_HEAP_ENABLE_FREE_CHECK (0x20)
//      | FLG_HEAP_VALIDATE_PARAMETERS (0x40)

Kỹ thuật 3: Thay đổi ProcessHeap flags
==============================================
Khi debugger attached, heap được tạo với debug flags:
  HEAP_TAIL_CHECKING_ENABLED  (0x20)
  HEAP_FREE_CHECKING_ENABLED  (0x40)

// Anti-debug check
DWORD heapFlags = *(DWORD*)((BYTE*)peb->ProcessHeap + 0x70);
if (heapFlags & 0x60) { /* debugger detected */ }

// Patch để bypass
*(DWORD*)((BYTE*)peb->ProcessHeap + 0x70) = HEAP_GROWABLE;
```

**Phát hiện PEB manipulation:**
```
;; WinDbg: So sánh PEB modules vs VAD
kd> !vad <VadRoot>         ; Liệt kê tất cả VADs
kd> !dlls                  ; Modules từ PEB
;; VADs có MEM_IMAGE nhưng không có trong !dlls → suspicious

;; Volatility (memory forensics):
vol.py -f memory.dmp --profile=Win10x64 ldrmodules
;; So sánh InLoad / InInit / InMem → FALSE entries = hidden module
```

### 3.2.4 Xem Process Data

```
;; WinDbg — kernel mode
kd> !process 0 0 notepad.exe           ; Tìm EPROCESS
kd> !process <addr> 17                  ; Full details + threads + stacks
kd> dt nt!_EPROCESS <addr>             ; Raw structure
kd> dt nt!_KPROCESS <addr>             ; Kernel process block
kd> dt nt!_PEB <peb_addr>              ; PEB (switch context first)

;; Process-specific context
kd> .process /i /p <EPROCESS_addr>      ; Switch context
kd> !peb                                ; PEB in current context
kd> !dlls                               ; Loaded DLLs
kd> !vad                                ; Virtual Address Descriptors
kd> !token                              ; Security token

;; User-mode debugger
0:000> !peb                             ; PEB
0:000> dt ntdll!_PEB @$peb             ; PEB structure
0:000> lm                               ; Loaded modules
0:000> !address                         ; Address space layout
```

---

## 3.3 Protected Processes

### 3.3.1 Protected Process (PP)

Giới thiệu từ Vista cho DRM (Digital Rights Management):
- Ngăn mọi process (kể cả admin) đọc memory hoặc inject code
- Chỉ có thể query limited information (PID, image name)
- Executable phải được signed bằng Windows Media Certificate

```
Protected Process Access Restrictions:
  ✗ PROCESS_VM_READ
  ✗ PROCESS_VM_WRITE
  ✗ PROCESS_VM_OPERATION
  ✗ PROCESS_CREATE_THREAD
  ✗ PROCESS_DUP_HANDLE
  ✓ PROCESS_QUERY_LIMITED_INFORMATION
  ✓ PROCESS_TERMINATE (with restrictions)
```

### 3.3.2 Protected Process Light (PPL)

Mở rộng từ Windows 8.1 — dùng cho system protection (không chỉ DRM):

**PPL Signer Levels (thứ tự ưu tiên giảm dần):**

| Level | Signer | Ví dụ |
|-------|--------|-------|
| PP (Protected Process) | WinSystem | Chỉ System process |
| PP | WinTcb | Kernel, critical system |
| PPL | WinTcb | csrss.exe, smss.exe |
| PPL | Windows | services.exe, svchost.exe |
| PPL | Antimalware | Windows Defender, AV 3rd party |
| PPL | Lsa | lsass.exe |
| PPL | Authenticode | Signed drivers |
| PPL | CodeGen | .NET NGEN |
| PPL | None | Unprotected |

**Rule:** PP/PPL ở level cao hơn có thể open process ở level thấp hơn với full access. Level thấp KHÔNG THỂ open level cao.

```
csrss.exe (PPL-WinTcb)
  ↓ CAN open
lsass.exe (PPL-Lsa)
  ↓ CAN open
notepad.exe (unprotected)

notepad.exe
  ✗ CANNOT open lsass.exe with PROCESS_VM_READ
  ✗ CANNOT open csrss.exe
```

**Xem PP/PPL status:**

```
kd> dt nt!_EPROCESS <addr> -y Protection
   +0x87a Protection : _PS_PROTECTION
      Level    : 0x41 (PPL-Antimalware)
      Type     : 2 (PsProtectedTypeProtectedLight)
      Signer   : 3 (PsProtectedSignerAntimalware)

# Process Explorer: Properties → Security tab → Protected
```

### 3.3.3 Third-Party PPL (Antimalware)

**[UPDATE 2026]** AV vendors đăng ký ELAM (Early Launch Antimalware) driver để chạy PPL:

```
1. AV vendor đăng ký ELAM certificate với Microsoft
2. ELAM driver load rất sớm trong boot process
3. ELAM driver đánh giá boot-start drivers (GOOD / BAD / UNKNOWN)
4. AV service process chạy as PPL-Antimalware
5. PPL protection ngăn malware tamper AV process
```

---

### 3.3.4 PP/PPL Signer Levels — Bảng Đầy Đủ

Hệ thống PP/PPL dùng **hai trường** trong `_PS_PROTECTION`:
- `Type`: Protected (2) hoặc ProtectedLight (1) hoặc None (0)
- `Signer`: xác định trust level

```
_PS_PROTECTION (1 byte)
  Bits [0:2] = Type
  Bits [3:7] = Signer

Encoding: Level = (Signer << 3) | Type

Signer Values (thứ tự ưu tiên giảm dần):
+-------+-------------------+------+------------------------------------+
| Value | Signer            | Type | Ví dụ processes                    |
+-------+-------------------+------+------------------------------------+
|   6   | WinSystem         | PP   | System process                     |
|   6   | WinSystem         | PPL  | (reserved)                         |
|   5   | WinTcb            | PP   | Secure System, minimal processes   |
|   5   | WinTcb            | PPL  | csrss.exe, smss.exe, wininit.exe   |
|   4   | Windows           | PP   | (reserved)                         |
|   4   | Windows           | PPL  | services.exe, svchost.exe (some)   |
|   3   | Antimalware       | PPL  | MsMpEng.exe (Defender), 3rd AV     |
|   2   | Lsa               | PPL  | lsass.exe (khi LSA Protection on)  |
|   1   | Authenticode      | PPL  | (signed with Authenticode cert)    |
|   7   | CodeGen           | PPL  | .NET NGEN worker processes         |
|   8   | App               | PPL  | Store/MSIX apps                    |
|   0   | None              | None | Tất cả process bình thường          |
+-------+-------------------+------+------------------------------------+

Access Rules:
  PP  CAN open PP/PPL với SAME OR LOWER signer
  PPL CAN open PPL với SAME OR LOWER signer
  PPL CANNOT open PP (bất kể signer level)
  PP  CAN always open PPL (bất kể signer level)
```

**PP vs PPL — Sự khác biệt chi tiết:**

| Khía cạnh | PP (Protected Process) | PPL (Protected Process Light) |
|-----------|------------------------|-------------------------------|
| Mức độ bảo vệ | Cao nhất | Cao nhưng thấp hơn PP |
| Access rights bị chặn | Hầu hết PROCESS_* rights | Tương tự nhưng có exceptions |
| PP có thể open PPL? | Có, với full access | N/A |
| PPL có thể open PP? | Không, bất kể signer | N/A |
| Debug | Không thể debug | Không thể debug từ unprot. |
| Use case chính | DRM, System kernel | AV, LSA, system services |
| Unsigned driver load | Bị chặn | Bị chặn |
| Code injection | Bị chặn hoàn toàn | Bị chặn hoàn toàn |

**Xem PP/PPL status chi tiết từ WinDbg:**
```
;; Liệt kê tất cả protected processes
kd> !for_each_process "
    r @$t0 = (@@(((nt!_EPROCESS*)@#Process)->Protection.Level));
    .if (@$t0 != 0) {
        .printf \"PID: %04x Level: %02x - %ma\\n\",
        @@(((nt!_EPROCESS*)@#Process)->UniqueProcessId),
        @$t0,
        @@(((nt!_EPROCESS*)@#Process)->ImageFileName)
    }"

;; Decode protection level
kd> dt nt!_PS_PROTECTION poi(<EPROCESS>+0x87a)
   +0x000 Level : 0x2A
   ;; 0x2A = Signer 5 (0x2A >> 3 = 5), Type 2 (PP)
   ;; 0x2A = WinTcb-PP (Signer=WinTcb, Type=ProtectedProcess)
```

### 3.3.5 PP/PPL Attack Research

**Attack surface phân tích cho researchers:**

```
Attack Vector 1: Vulnerable Signed Drivers
============================================
Problem: PPL chỉ check signer level, không check logic bugs.
Nếu một signed driver (PPL-Windows) có vulnerability:
  → Attacker load driver đó
  → Exploit vulnerability để đọc/ghi memory của PPL process
  → VD: Capcom.sys, DBUtil_2_3.sys (CVE-2021-21551)

Mitigation: Microsoft revoke certificates của vulnerable drivers
            → Windows Defender Vulnerable Driver Blocklist

Attack Vector 2: Handle Duplication
============================================
EPROCESS->ObjectTable chứa handles.
Nếu process A (protected) có handle tới process B (unprotected),
và process B bị compromise:
  → Attacker KHÔNG thể duplicate handle từ B → A (access denied)
  → Kernel check protection level khi DuplicateHandle()

Nhưng: Nếu Admin process ĐÃ có handle tới PPL trước khi
       PPL được protect → handle vẫn valid (grandfathered)
       → Đây là lý do boot-time protection quan trọng

Attack Vector 3: PROCESS_DUP_HANDLE abuse
============================================
Nếu attacker có handle với PROCESS_DUP_HANDLE tới một process
mà process đó có high-privilege handle:
  → DuplicateHandle() có thể leak handle từ target
  → Nhưng PROCESS_DUP_HANDLE bị chặn cho PPL targets

Attack Vector 4: Kernel callback overwrite
============================================
PEB->KernelCallbackTable (offset 0x58 trên x64)
  → Pointer table dùng bởi win32k.sys để callback vào user-mode
  → Malware overwrite entries → code execution khi kernel callback
  → PPL chặn PROCESS_VM_WRITE nên không thể modify từ bên ngoài
  → Nhưng nếu exploit từ BÊN TRONG process → vẫn possible
```

**Windows processes chạy as PP/PPL (mặc định):**
```
PP-WinSystem:
  System (PID 4)

PP-WinTcb:
  Secure System (VTL 1)
  Registry (Registry process)
  Minimal processes

PPL-WinTcb:
  csrss.exe (Client/Server Runtime)
  smss.exe (Session Manager)
  wininit.exe (Windows Init)
  services.exe (Service Control Manager)

PPL-Windows:
  svchost.exe (một số instances)
  spoolsv.exe (Print Spooler - có thể)

PPL-Antimalware:
  MsMpEng.exe (Windows Defender engine)
  MsSense.exe (Defender for Endpoint sensor)
  3rd party AV engine (nếu ELAM registered)

PPL-Lsa:
  lsass.exe (khi RunAsPPL=1 trong registry)
  HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1

PPL-CodeGen:
  ngen.exe (.NET Native Image Generator - khi chạy bởi service)
```

---

## 3.4 Minimal Processes và Pico Processes

### 3.4.1 Minimal Process

Process không có user-mode address space bình thường:
- Không có PEB
- Không có ntdll.dll
- Không có user-mode threads
- Chỉ dùng nội bộ kernel

Ví dụ: **Memory Compression** process (System process child), **Secure System** process.

### 3.4.2 Pico Processes

Pico process = Minimal process + **Pico Provider** driver:

```
┌──────────────────────────────────┐
│          Pico Process             │
│  ┌────────────────────────────┐  │
│  │ Linux binary / other OS    │  │
│  │ (NOT Windows executables)  │  │
│  └────────────┬───────────────┘  │
│               │ Linux syscall     │
│               ▼                   │
│  ┌────────────────────────────┐  │
│  │ Pico Provider Driver       │  │
│  │ (lxcore.sys cho WSL 1)     │  │
│  │ Translates syscalls        │  │
│  └────────────────────────────┘  │
└──────────────────────────────────┘
```

- WSL 1 dùng Pico processes: Linux system calls → translated bởi `lxcore.sys`
- WSL 2 dùng VM nên không cần Pico processes nữa

### 3.4.3 Trustlets (Secure Processes / IUM)

Trustlets chạy trong **VTL 1** (Secure World) dưới Secure Kernel:

```
VTL 1 (Secure World):
┌──────────────────────────────────────────┐
│ Secure Kernel (securekernel.exe)          │
│                                          │
│ ┌──────────────┐ ┌──────────────────┐   │
│ │ lsaiso.exe    │ │ vmsp.exe          │   │
│ │ (Credential   │ │ (VM Security      │   │
│ │  Guard)       │ │  Process)         │   │
│ └──────────────┘ └──────────────────┘   │
│                                          │
│ Trustlet requirements:                   │
│ - Microsoft signed (specific EKU)        │
│ - IDT (Isolated Dynamic Trust) or       │
│   IDKS (Isolated Dynamic Key Store)      │
│ - Cannot be debugged from VTL 0          │
└──────────────────────────────────────────┘
```

**Trustlet attributes:**
- `IMAGE_ENCLAVE_POLICY_DEBUGGABLE` — cho phép debug (dev only)
- `SECURE_PROCESS_REQUIRED_SIGNING` — yêu cầu specific signing

---

## 3.5 Image Loader Chi Tiết

### 3.5.1 Loader Initialization

Khi process mới bắt đầu chạy, thread đầu tiên execute tại `ntdll!LdrInitializeThunk()`:

```
LdrInitializeThunk()
├── LdrpInitialize()
│   ├── LdrpInitializeProcess()
│   │   ├── Initialize PEB
│   │   ├── Initialize heap (RtlCreateHeap)
│   │   ├── Initialize thread pool (TpAllocPool)
│   │   ├── LdrpInitializeNlsSection()     ← NLS (locale)
│   │   ├── LdrpMapDll()                    ← Map .exe image
│   │   ├── LdrpWalkImportDescriptor()      ← Parse imports
│   │   │   ├── LdrpLoadDll() cho mỗi imported DLL
│   │   │   │   ├── Tìm DLL (search order)
│   │   │   │   ├── Map DLL vào address space
│   │   │   │   ├── Parse DLL's imports (recursive)
│   │   │   │   └── Snap thunks (resolve function addresses)
│   │   │   └── Repeat cho tất cả dependencies
│   │   ├── LdrpRunInitializeRoutines()      ← DllMain(DLL_PROCESS_ATTACH)
│   │   └── Return to CRT startup
│   └── NtContinue() → jump to entry point
└── App entry point (WinMainCRTStartup / mainCRTStartup)
```

### 3.5.2 DLL Search Order

Khi loader cần tìm DLL, nó search theo thứ tự:

**Standard search order (SafeDllSearchMode enabled — default):**

```
1. DLL Redirection (.local file) / API Set redirection
2. SxS manifest (WinSxS / Side-by-side)
3. Known DLLs (\KnownDlls object directory)
4. Directory chứa .exe
5. System directory (System32)
6. 16-bit system directory (System)
7. Windows directory
8. Current directory
9. PATH environment variable directories
```

**Known DLLs optimization:**

```
kd> !object \KnownDlls

\KnownDlls:
  kernel32.dll → Section object (pre-mapped)
  ntdll.dll → Section object
  user32.dll → Section object
  ...
```

Known DLLs là section objects đã được tạo sẵn khi boot. Loader dùng trực tiếp thay vì search disk → nhanh hơn VÀ an toàn hơn (chống DLL hijacking).

### 3.5.3 DLL Name Resolution và Redirection

**API Sets (Windows 10+):**
```
api-ms-win-core-file-l1-1-0.dll
→ Resolved bởi apisetschema.dll mapping
→ Thực tế là kernelbase.dll
```

**SxS (Side-by-Side / WinSxS):**
```
App manifest declares:
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.VC90.CRT"
                        version="9.0.21022.8" />
    </dependentAssembly>
  </dependency>

→ Loader tìm trong C:\Windows\WinSxS\x86_microsoft.vc90.crt_..._9.0.21022.8_...\ 
```

**DLL Redirection (.local):**

Nếu tồn tại file `myapp.exe.local` (hoặc folder `myapp.exe.local\`), loader tìm DLL ở đó trước.

---

### 3.5.4 Image Loader — LdrpInitializeProcess Deep Dive

`LdrpInitializeProcess()` là hàm core của image loader, chạy trong context
của process mới ngay sau khi kernel setup xong:

```
LdrpInitializeProcess() - Chi tiết từng bước:
│
├── 1. LdrpInitSecurityCookie()
│   - Tạo __security_cookie cho stack buffer overrun detection
│   - Random value khác nhau mỗi lần process start
│   - Compiler insert check: __security_check_cookie()
│
├── 2. LdrpInitializeExecutionOptions()
│   - Đọc registry: HKLM\SOFTWARE\Microsoft\Windows NT\
│     CurrentVersion\Image File Execution Options\<exe_name>
│   - GlobalFlag → PEB->NtGlobalFlag
│   - MitigationOptions → process mitigation flags
│   - Debugger → auto-attach debugger (IFEO redirect)
│   - VerifierDlls → Application Verifier DLLs
│
├── 3. LdrpInitializeNlsSection()
│   - Map NLS (National Language Support) section
│   - Locale data, code page tables
│
├── 4. RtlCreateHeap() → PEB->ProcessHeap
│   - Default heap: HEAP_GROWABLE
│   - Nếu debug mode: HEAP_TAIL_CHECKING_ENABLED |
│     HEAP_FREE_CHECKING_ENABLED | HEAP_VALIDATE_PARAMETERS
│   - Initial size: typically 1MB reserved, 4KB committed
│
├── 5. LdrpInitializeTls()
│   - Parse TLS Directory trong PE header
│   - Allocate TLS slots
│   - Copy TLS template data
│   - TLS callbacks (gọi TRƯỚC DllMain!)
│
├── 6. LdrpWalkImportDescriptor()
│   - Parse IMAGE_IMPORT_DESCRIPTOR array
│   └── Cho mỗi imported DLL:
│       ├── LdrpLoadDll()
│       │   ├── LdrpFindKnownDll() → check KnownDlls first
│       │   ├── LdrpSearchPath() → tìm DLL theo search order
│       │   ├── LdrpMapDll() → NtMapViewOfSection()
│       │   ├── LdrpAllocateDataTableEntry() → LDR_DATA_TABLE_ENTRY
│       │   ├── Insert vào PEB->Ldr lists
│       │   └── Recursive: LdrpWalkImportDescriptor() cho DLL này
│       └── LdrpSnapThunks()
│           ├── Duyệt Import Name Table (INT)
│           ├── Cho mỗi imported function:
│           │   ├── Tìm export trong target DLL's Export Directory
│           │   ├── Resolve forwarded exports (VD: kernel32 → kernelbase)
│           │   └── Ghi address vào Import Address Table (IAT)
│           └── Handle ordinal imports (import by number)
│
├── 7. LdrpRunInitializeRoutines()
│   - Dependency order: load trước → init trước
│   - Cho mỗi DLL (theo InInitializationOrderModuleList):
│     a. Gọi TLS callbacks (IMAGE_TLS_CALLBACK) nếu có
│     b. Gọi DllMain(hModule, DLL_PROCESS_ATTACH, lpReserved)
│     c. Nếu return FALSE → LdrpReportError() → có thể fail
│
└── 8. Return → NtContinue → entry point
```

#### DLL Search Order chi tiết với Security Implications

```
SafeDllSearchMode = ENABLED (default):

┌─ Priority 0: DLL Redirection ─────────────────────────────────┐
│  a. .local file redirection (app.exe.local\target.dll)        │
│  b. API Set redirection (api-ms-win-* → actual DLL)           │
│  c. SxS manifest redirection (WinSxS assembly)               │
│                                                                │
│  → Nếu tìm thấy ở đây, KHÔNG search tiếp                    │
└────────────────────────────────────────────────────────────────┘
         │ Không tìm thấy
         ▼
┌─ Priority 1: Known DLLs ──────────────────────────────────────┐
│  \KnownDlls object directory                                  │
│  - Pre-loaded section objects (kernel32, ntdll, user32, ...)  │
│  - Registry: HKLM\SYSTEM\CurrentControlSet\Control\           │
│    Session Manager\KnownDLLs                                  │
│  - SECURE: không thể bị hijack (admin cũng không modify được) │
└────────────────────────────────────────────────────────────────┘
         │ Không tìm thấy
         ▼
┌─ Priority 2: Application Directory ───────────────────────────┐
│  Thư mục chứa .exe file                                      │
│  → DLL Hijacking target #1: đặt malicious DLL ở đây          │
└────────────────────────────────────────────────────────────────┘
         │ Không tìm thấy
         ▼
┌─ Priority 3: System32 ────────────────────────────────────────┐
│  C:\Windows\System32                                          │
│  (C:\Windows\SysWOW64 cho 32-bit processes)                   │
└────────────────────────────────────────────────────────────────┘
         │ Không tìm thấy
         ▼
┌─ Priority 4: System (16-bit) ─────────────────────────────────┐
│  C:\Windows\System (legacy, ít dùng)                          │
└────────────────────────────────────────────────────────────────┘
         │ Không tìm thấy
         ▼
┌─ Priority 5: Windows Directory ───────────────────────────────┐
│  C:\Windows                                                   │
└────────────────────────────────────────────────────────────────┘
         │ Không tìm thấy
         ▼
┌─ Priority 6: Current Directory ───────────────────────────────┐
│  Thư mục hiện tại (GetCurrentDirectory)                       │
│  → DLL Hijacking target #2 (CWD attack)                      │
│  → Binary planting: attacker kiểm soát CWD                   │
└────────────────────────────────────────────────────────────────┘
         │ Không tìm thấy
         ▼
┌─ Priority 7: PATH Directories ────────────────────────────────┐
│  Mỗi thư mục trong %PATH% environment variable               │
│  → DLL Hijacking target #3: writeable PATH entries            │
└────────────────────────────────────────────────────────────────┘
```

#### Delay-Load DLLs

```
Delay-load DLL không được load ngay khi process start.
Chỉ load khi function được GỌI LẦN ĐẦU:

Compiler tạo delay-load thunk:
  1. Khi code gọi delay-loaded function
  2. Thunk gọi __delayLoadHelper2()
  3. __delayLoadHelper2():
     a. LoadLibraryExW(dll_name) → load DLL
     b. GetProcAddress(hDll, func_name) → resolve function
     c. Patch IAT entry → direct call lần sau
  4. Jump to resolved function

PE Structure:
  IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT (index 13)
  → IMAGE_DELAYLOAD_DESCRIPTOR[]
    - DllNameRVA: tên DLL
    - ModuleHandleRVA: nơi lưu handle sau khi load
    - ImportAddressTableRVA: IAT cho delay-load
    - ImportNameTableRVA: INT cho delay-load
    - BoundImportAddressTableRVA: bound IAT
    - UnloadInformationTableRVA: unload info

;; WinDbg: Xem delay-load imports
0:000> !dh <module> -f     ; Full headers
0:000> lm vm <module>       ; Module info với delay-load directory
```

#### TLS Callbacks — Sử Dụng Bởi Malware

TLS (Thread Local Storage) callbacks được gọi **TRƯỚC entry point**
và trước DllMain — malware dùng để:

```
TLS Callback Execution Order:
  1. Image mapped vào memory
  2. TLS callbacks gọi (DLL_PROCESS_ATTACH)    ← TRƯỚC DllMain
  3. DllMain(DLL_PROCESS_ATTACH)
  4. CRT startup
  5. main() / WinMain()

Malware dùng TLS callback để:
  - Anti-debug check trước khi debugger break tại entry point
  - Unpack code trước khi analysis tools attach
  - Environment detection (VM, sandbox)
  - Overwrite entry point với real code

// Khai báo TLS callback
#pragma comment(linker, "/INCLUDE:_tls_used")
void NTAPI TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
    if (Reason == DLL_PROCESS_ATTACH) {
        // Anti-debug: check BeingDebugged TRƯỚC entry point
        if (NtCurrentPeb()->BeingDebugged) {
            ExitProcess(0);
        }
        // Decrypt và execute real payload
    }
}
#pragma data_seg(".CRT$XLB")
PIMAGE_TLS_CALLBACK callbacks[] = { TlsCallback, NULL };
#pragma data_seg()

;; WinDbg: Tìm TLS callbacks
0:000> !dh <module> -f    ; Tìm TLS Directory
0:000> dt ntdll!_IMAGE_TLS_DIRECTORY64 <tls_dir_addr>
;; AddressOfCallBacks → array of function pointers
0:000> dps poi(<AddressOfCallBacks>)
```

#### DLL Notification Callbacks — LdrRegisterDllNotification

API cho phép monitor DLL load/unload events:

```c
// Đăng ký notification callback (Windows Vista+)
typedef VOID (CALLBACK *PLDR_DLL_NOTIFICATION_FUNCTION)(
    ULONG NotificationReason,     // LDR_DLL_NOTIFICATION_REASON_LOADED
                                  // LDR_DLL_NOTIFICATION_REASON_UNLOADED
    PLDR_DLL_NOTIFICATION_DATA NotificationData,
    PVOID Context
);

// NotificationData structure
typedef struct _LDR_DLL_NOTIFICATION_DATA {
    union {
        LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
        LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
    };
} LDR_DLL_NOTIFICATION_DATA;

typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
    ULONG Flags;
    PUNICODE_STRING FullDllName;   // Full path
    PUNICODE_STRING BaseDllName;   // DLL name only
    PVOID DllBase;                 // Mapped address
    ULONG SizeOfImage;            // Image size
} LDR_DLL_LOADED_NOTIFICATION_DATA;

// Registration
typedef NTSTATUS (NTAPI *LdrRegisterDllNotification_t)(
    ULONG Flags,
    PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction,
    PVOID Context,
    PVOID *Cookie
);

LdrRegisterDllNotification_t pLdrRegister =
    (LdrRegisterDllNotification_t)GetProcAddress(
        GetModuleHandle(L"ntdll.dll"),
        "LdrRegisterDllNotification");

PVOID cookie;
pLdrRegister(0, MyDllCallback, NULL, &cookie);

// Security tool dùng để:
// - Detect DLL injection (unexpected DLL loads)
// - Monitor DLL hijacking attempts
// - Log all module loading for forensics
// - Block specific DLLs from loading (return error in callback)
```

---

## 3.6 Process Termination

### 3.6.1 Cách Process Terminate

```
Voluntary:
  ExitProcess() → NtTerminateProcess() → PspExitProcess()

Involuntary:
  TerminateProcess() → NtTerminateProcess() → PspExitProcess()

Unhandled exception:
  → UnhandledExceptionFilter() → TerminateProcess()
```

### 3.6.2 Cleanup Steps

```
PspExitProcess():
1. Set ExitStatus
2. Terminate all threads
3. Close all handles (ObCloseAllHandles)
4. Deref all objects
5. Release address space (MmCleanProcessAddressSpace)
6. Notify registered callbacks (PsSetCreateProcessNotifyRoutine)
7. Notify csrss.exe
8. Dereference token
9. EPROCESS vẫn tồn tại cho đến khi:
   - Tất cả handles tới process được close
   - Tất cả references được release
```

---

## 3.7 Jobs Chi Tiết

### 3.7.1 Job Object Structure

```
_EJOB
├── Event                       ← Signaled khi job limits hit
├── TotalUserTime               ← Total CPU time (user mode)
├── TotalKernelTime             ← Total CPU time (kernel mode)
├── TotalCycleTime              ← CPU cycles
├── ThisPeriodTotalUserTime     ← Time in current period
├── TotalPageFaultCount         ← Page faults across all processes
├── TotalProcesses              ← Total processes ever in job
├── ActiveProcesses             ← Current active processes
├── TotalTerminatedProcesses    ← Processes terminated by limit
├── ProcessListHead             ← Linked list of processes
│
├── LimitFlags                  ← JOB_OBJECT_LIMIT_*
│   ├── JOB_OBJECT_LIMIT_PROCESS_TIME
│   ├── JOB_OBJECT_LIMIT_JOB_TIME
│   ├── JOB_OBJECT_LIMIT_ACTIVE_PROCESS
│   ├── JOB_OBJECT_LIMIT_PROCESS_MEMORY
│   ├── JOB_OBJECT_LIMIT_JOB_MEMORY
│   ├── JOB_OBJECT_LIMIT_WORKINGSET
│   ├── JOB_OBJECT_LIMIT_PRIORITY_CLASS
│   ├── JOB_OBJECT_LIMIT_AFFINITY
│   ├── JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
│   ├── JOB_OBJECT_LIMIT_NET_RATE_CONTROL
│   └── JOB_OBJECT_LIMIT_IO_RATE_CONTROL
│
├── CompletionPort              ← I/O completion port for notifications
├── CompletionKey               ← Key for completion port
│
├── PerProcessUserTimeLimit     ← Max CPU time per process
├── PerJobUserTimeLimit         ← Max CPU time for entire job
├── MinimumWorkingSetSize       ← Min working set
├── MaximumWorkingSetSize       ← Max working set
├── ActiveProcessLimit          ← Max concurrent processes
├── ProcessMemoryLimit          ← Max memory per process
├── JobMemoryLimit              ← Max memory for entire job
│
├── CpuRateControl              ← CPU rate limiting
│   ├── Weight                   ← Relative weight
│   └── CpuRate                  ← Hard cap (parts per 10000)
│
├── NetRateControl              ← Network bandwidth control
└── IoRateControl               ← Disk I/O rate control
```

### 3.7.2 Tạo và Quản Lý Job

```c
// Tạo job
HANDLE hJob = CreateJobObject(NULL, L"MyJobName");

// Set limits
JOBOBJECT_EXTENDED_LIMIT_INFORMATION info = {0};
info.BasicLimitInformation.LimitFlags =
    JOB_OBJECT_LIMIT_PROCESS_MEMORY |
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
info.ProcessMemoryLimit = 100 * 1024 * 1024;  // 100 MB per process
SetInformationJobObject(hJob, JobObjectExtendedLimitInformation,
                        &info, sizeof(info));

// CPU rate limit (50%)
JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpuRate = {0};
cpuRate.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE |
                       JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
cpuRate.CpuRate = 5000;  // 50.00% (parts per 10000)
SetInformationJobObject(hJob, JobObjectCpuRateControlInformation,
                        &cpuRate, sizeof(cpuRate));

// Assign process vào job
AssignProcessToJobObject(hJob, hProcess);

// Query statistics
JOBOBJECT_BASIC_ACCOUNTING_INFORMATION acct;
QueryInformationJobObject(hJob, JobObjectBasicAccountingInformation,
                          &acct, sizeof(acct), NULL);
printf("Active processes: %d\n", acct.ActiveProcesses);
printf("Total CPU time: %lld\n", acct.TotalUserTime.QuadPart);
```

### 3.7.3 Nested Jobs

Từ Windows 8+, jobs có thể nested:

```
Root Job (CPU limit: 80%)
├── Child Job A (Memory limit: 2GB)
│   ├── Process 1
│   └── Process 2
└── Child Job B (Memory limit: 1GB)
    └── Process 3

→ Process 1: subject to BOTH CPU 80% AND Memory 2GB
→ Process 3: subject to BOTH CPU 80% AND Memory 1GB
```

### 3.7.4 EJOB Structure — Key Fields Chi Tiết

```
_EJOB (Kernel structure)
│
├── Event                          ← KEVENT, signaled khi limit hit
├── ProcessListHead                ← LIST_ENTRY: linked list EPROCESS
├── JobLinks                       ← LIST_ENTRY: link to parent/child jobs
├── ParentJob                      ← EJOB* pointer to parent job
│
├── Accounting Fields:
│   ├── TotalUserTime              ← LARGE_INTEGER: total user CPU (100ns units)
│   ├── TotalKernelTime            ← LARGE_INTEGER: total kernel CPU
│   ├── TotalCycleTime             ← UINT64: CPU cycles consumed
│   ├── ThisPeriodTotalUserTime    ← User time trong period hiện tại
│   ├── ThisPeriodTotalKernelTime  ← Kernel time trong period hiện tại
│   ├── TotalPageFaultCount        ← Total page faults tất cả processes
│   ├── TotalProcesses             ← Số processes TỪNG join job
│   ├── ActiveProcesses            ← Số processes HIỆN TẠI trong job
│   ├── TotalTerminatedProcesses   ← Processes bị terminate do limit
│   │
│   ├── I/O Accounting:
│   │   ├── ReadOperationCount     ← Total read I/O operations
│   │   ├── WriteOperationCount    ← Total write I/O operations
│   │   ├── OtherOperationCount    ← Total other I/O operations
│   │   ├── ReadTransferCount      ← Total bytes read
│   │   ├── WriteTransferCount     ← Total bytes written
│   │   └── OtherTransferCount     ← Total bytes other I/O
│   │
│   └── Memory Accounting:
│       ├── PeakProcessMemoryUsed  ← Peak memory single process
│       ├── PeakJobMemoryUsed      ← Peak memory entire job
│       └── CurrentJobMemoryUsed   ← Current job memory usage
│
├── Limit Fields:
│   ├── LimitFlags                 ← UINT32: JOB_OBJECT_LIMIT_* bitmask
│   ├── MinimumWorkingSetSize      ← SIZE_T
│   ├── MaximumWorkingSetSize      ← SIZE_T
│   ├── ActiveProcessLimit         ← UINT32: max concurrent processes
│   ├── ProcessMemoryLimit         ← SIZE_T: per-process memory cap
│   ├── JobMemoryLimit             ← SIZE_T: entire job memory cap
│   ├── PerProcessUserTimeLimit    ← LARGE_INTEGER: per-process CPU limit
│   ├── PerJobUserTimeLimit        ← LARGE_INTEGER: job-wide CPU limit
│   └── PriorityClass              ← UINT32: forced priority class
│
├── Rate Control:
│   ├── CpuRateControl
│   │   ├── ControlFlags           ← Enable, HardCap, Weight, MinMax
│   │   ├── CpuRate                ← Parts per 10000 (5000 = 50%)
│   │   ├── Weight                 ← Relative weight (1-9)
│   │   ├── MinRate                ← Minimum guaranteed rate
│   │   └── MaxRate                ← Maximum cap rate
│   ├── IoRateControlEntry         ← Disk I/O rate limits
│   └── NetRateControlEntry        ← Network bandwidth limits
│
├── Security:
│   ├── Token                      ← Forced job token (if set)
│   ├── Filter                     ← Security filter (SID/privilege restrictions)
│   │   ├── FilteredSids[]         ← SIDs removed from processes' tokens
│   │   ├── FilteredPrivileges[]   ← Privileges removed
│   │   └── RestrictedSids[]       ← Added restricted SIDs
│   └── SecurityLimitFlags         ← JOB_OBJECT_SECURITY_*
│
├── UI Restrictions:
│   ├── UIRestrictionsClass        ← JOB_OBJECT_UILIMIT_*
│   │   ├── UILIMIT_HANDLES        ← Restrict handle access
│   │   ├── UILIMIT_READCLIPBOARD  ← Block clipboard read
│   │   ├── UILIMIT_WRITECLIPBOARD ← Block clipboard write
│   │   ├── UILIMIT_SYSTEMPARAMETERS ← Block SystemParametersInfo
│   │   ├── UILIMIT_DISPLAYSETTINGS ← Block display changes
│   │   ├── UILIMIT_GLOBALATOMS    ← Restrict global atoms
│   │   ├── UILIMIT_DESKTOP        ← Restrict desktop access
│   │   └── UILIMIT_EXITWINDOWS    ← Block ExitWindowsEx
│   └── UserHandleGrantAccess()    ← Whitelist specific handles
│
└── Container (Silo):
    ├── ServerSiloGlobals          ← Silo-specific global data
    └── SiloType                    ← Application / Server Silo
```

**WinDbg: Xem Job structure và accounting:**
```
kd> !job <EJOB_addr> 1           ; Basic job info
kd> !job <EJOB_addr> 2           ; Limits
kd> !job <EJOB_addr> 4           ; Process list
kd> dt nt!_EJOB <addr>           ; Raw structure
kd> dt nt!_EJOB <addr> TotalUserTime TotalKernelTime
kd> dt nt!_EJOB <addr> ActiveProcesses TotalProcesses

;; Tìm job của một process
kd> dt nt!_EPROCESS <proc_addr> Job
kd> !process <proc_addr> 0       ; "Job" field trong output
```

### 3.7.5 Windows Containers (Server Silos)

**[UPDATE 2026]** Windows Containers dùng Job objects dạng **Silo**:

```
Server Silo = Job + Namespace Isolation + Resource Controls

┌──────────────────────────────────────────────┐
│ Host (Infrastructure Silo)                    │
│                                              │
│  ┌───────────────────┐ ┌──────────────────┐ │
│  │ Container A (Silo) │ │ Container B       │ │
│  │ ┌───────────────┐  │ │ (Silo)            │ │
│  │ │ Own registry   │  │ │ ┌──────────────┐ │ │
│  │ │ Own filesystem │  │ │ │ Isolated     │ │ │
│  │ │ Own network    │  │ │ │ environment  │ │ │
│  │ │ Own processes  │  │ │ └──────────────┘ │ │
│  │ └───────────────┘  │ └──────────────────┘ │
│  └───────────────────┘                       │
└──────────────────────────────────────────────┘
```

**Silo types:**
- **Application Silo**: lightweight isolation (UWP apps, Centennial)
- **Server Silo**: full container isolation (Docker Windows containers)

Server Silo cung cấp:
- **Object namespace isolation**: `\Device`, `\BaseNamedObjects` riêng
- **Registry isolation**: overlay registry hive
- **File system isolation**: union filesystem view
- **Network isolation**: virtual network adapter
- **Process isolation**: `NtQuerySystemInformation` chỉ thấy processes trong silo

---

### 3.7.6 Silo Internals — Namespace Isolation

```
Server Silo Object Structure:
┌─────────────────────────────────────────────────────────┐
│ EJOB (base job object)                                   │
│  └── SERVER_SILO_GLOBALS                                │
│      ├── ObRootDirectoryObject   ← Riêng Object namespace│
│      │   \Device, \BaseNamedObjects, \Sessions riêng     │
│      ├── RegistryHiveOverlay     ← Registry isolation    │
│      │   Software hive overlay on host registry         │
│      ├── NetworkCompartmentId    ← Network compartment   │
│      │   Virtual NIC, own IP, own routing table          │
│      ├── FileSystemFilter        ← FS layer redirection  │
│      │   Union FS: container layer + base image layers   │
│      ├── HostName               ← Container hostname     │
│      ├── DomainName             ← Domain membership      │
│      └── SiloId                  ← Unique silo identifier│
└─────────────────────────────────────────────────────────┘

Object Namespace Isolation:
  Host:      \BaseNamedObjects\MyMutex
  Silo A:    \Silos\<SiloId_A>\BaseNamedObjects\MyMutex
  Silo B:    \Silos\<SiloId_B>\BaseNamedObjects\MyMutex
  → Process trong Silo A thấy \BaseNamedObjects là của riêng nó
  → Không thể thấy objects của Silo B hoặc Host

Registry Isolation:
  Host registry:     HKLM\SOFTWARE\App → real key
  Container registry: HKLM\SOFTWARE\App → overlay (copy-on-write)
  → Ghi tới registry → ghi vào overlay, không ảnh hưởng host
  → Đọc: tìm overlay trước, fallback to host base image

Network Compartments:
  Mỗi Silo có riêng:
  - Virtual network adapter (vNIC)
  - IP address(es)
  - Routing table
  - DNS resolver config
  - Firewall rules (WFP filters)
  → Process trong silo chỉ thấy network của silo

Process Isolation:
  NtQuerySystemInformation(SystemProcessInformation) trong silo:
  → Chỉ return processes THUỘC silo đó
  → Host processes ẩn với silo processes
  → Silo A processes ẩn với Silo B processes
```

**WinDbg: Xem Silo information:**
```
kd> !silo                         ; Liệt kê tất cả silos
kd> !silo <silo_id>               ; Chi tiết một silo
kd> dt nt!_EJOB <addr> ServerSiloGlobals
kd> !process 0 0                  ; Trong silo context chỉ thấy silo processes
```

---

## 3.8 Process Mitigations

**[UPDATE 2026]** Windows cung cấp per-process exploit mitigations:

### 3.8.1 Mitigation Policies

```c
// Set mitigations khi tạo process
DWORD64 policy = 0;
policy |= PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE;
policy |= PROCESS_CREATION_MITIGATION_POLICY_ASLR_FORCE_RELOCATE_IMAGES_ALWAYS_ON;
policy |= PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_ALWAYS_ON;
policy |= PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_ON;

UpdateProcThreadAttribute(attrList, 0,
    PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
    &policy, sizeof(policy), NULL, NULL);
```

**Các mitigations quan trọng:**

| Mitigation | Mô tả |
|------------|--------|
| **DEP/NX** | Data pages không thể execute |
| **ASLR** | Randomize image base, stack, heap addresses |
| **High Entropy ASLR** | 64-bit wide randomization |
| **Force ASLR** | Force relocate images that don't opt-in |
| **Bottom-up ASLR** | Randomize heap/stack bottom-up allocations |
| **CFG** (Control Flow Guard) | Validate indirect call targets |
| **XFG** (eXtended Flow Guard) | Type-based CFG (stricter) |
| **CIG** (Code Integrity Guard) | Only load signed DLLs |
| **ACG** (Arbitrary Code Guard) | Prevent dynamic code generation (W^X) |
| **CET Shadow Stacks** | Hardware return address protection |
| **Block Remote Images** | Block DLL load from network shares |
| **Block Low Label Images** | Block DLL load from low integrity locations |
| **Import Address Filtering** | Restrict resolved import addresses |
| **Restrict Indirect Branch Prediction** | Spectre mitigation |

### 3.8.2 Mitigation Chi Tiết — Từng Chính Sách

#### DEP/NX (Data Execution Prevention)

```
Attack ngăn chặn: Stack buffer overflow → shellcode execution

Nguyên lý:
  - Memory pages được đánh dấu NX (No-eXecute) bit trong page table
  - Stack, heap = Read/Write nhưng KHÔNG Execute
  - Code section = Read/Execute nhưng KHÔNG Write
  - CPU hardware enforce (AMD: NX bit, Intel: XD bit)

Bypass techniques (để học phòng thủ):
  - ROP (Return-Oriented Programming): chain existing code gadgets
  - JOP (Jump-Oriented Programming): tương tự với indirect jumps
  - VirtualProtect() call: thay đổi page permission

PROCESS_MITIGATION_DEP_POLICY:
  +0x000 Flags : Uint4B
    Enable    : Pos 0  ← DEP on
    DisableAtlThunkEmulation : Pos 1  ← Block ATL thunk DEP exceptions
    Permanent : Pos 8  ← Không thể tắt DEP sau khi enable
```

#### ASLR (Address Space Layout Randomization)

```
Attack ngăn chặn: Hardcoded address exploitation,
                  ROP gadget location prediction

Sub-policies:
┌──────────────────────────────────────────────────────────────┐
│ BottomUpASLR: Randomize allocations growing upward           │
│   - Heap base addresses                                     │
│   - Thread stack bases                                       │
│   - MEM_RESERVE allocations (VirtualAlloc bottom-up)         │
│   Entropy: 8 bits (256 positions) trên x86                  │
│            24 bits trên x64 với High Entropy                │
│                                                              │
│ HighEntropyASLR: x64 only                                   │
│   - Image base: 17 bits entropy (1TB range)                  │
│   - Heap: 24 bits entropy                                    │
│   - Stack: 17 bits entropy                                   │
│   - Rất khó brute-force (2^17 = 131072 possibilities)        │
│                                                              │
│ ForceRelocateImages: ASLR cho images KHÔNG có                │
│   /DYNAMICBASE linker flag                                   │
│   - Relocate mọi image bất kể PE flag                        │
│   - Image không có relocation table → fail to load           │
│                                                              │
│ DisallowStrippedImages: Chặn images đã strip relocations     │
│   - Block DLLs removed RELOC section                         │
└──────────────────────────────────────────────────────────────┘

PROCESS_MITIGATION_ASLR_POLICY:
  +0x000 Flags : Uint4B
    EnableBottomUpRandomization     : Pos 0
    EnableForceRelocateImages       : Pos 1
    EnableHighEntropy               : Pos 2
    DisallowStrippedImages          : Pos 3
```

#### CFG (Control Flow Guard)

```
Attack ngăn chặn: Indirect call hijacking, vtable overwrite, 
                  function pointer corruption

Nguyên lý:
  Compiler tạo bitmap của TẤT CẢ valid call targets trong module.
  Trước mọi indirect call, insert validation check:

  ; Assembly (x64) — trước indirect call
  mov  rax, [target_ptr]         ; Load function pointer
  call __guard_check_icall_fptr  ; Validate target in CFG bitmap
  call rax                       ; Thực hiện indirect call

  __guard_check_icall_fptr:
    → ntdll!LdrpValidateUserCallTarget()
    → Check bit trong CFG bitmap
    → Nếu INVALID → RaiseException(STATUS_CFG_VIOLATION)

CFG Bitmap Structure:
  - Process-wide bitmap mapped vào user space
  - Mỗi bit đại diện 8 bytes aligned address
  - Bitmap size ≈ (UserAddressSpaceSize / 8) bits
  - Trên x64: ~8TB / 8 = ~1TB bitmap space (sparse mapped)
  - Lưu trong SharedUserData region

  Ví dụ:
  Nếu valid function tại 0x00007FFB`12345000:
    Bit index = 0x00007FFB`12345000 / 8 = offset trong bitmap
    Bit value = 1 (valid target)

  Nếu attacker redirect tới 0x00007FFB`12345004:
    Bit index = khác (vì alignment)
    Bit value = 0 → CFG VIOLATION → process crash

;; WinDbg: Xem CFG bitmap
0:000> !cfgbitmap <address>
0:000> dt ntdll!_LDR_DATA_TABLE_ENTRY <module> GuardCFCheckFunctionPointer
```

#### XFG (eXtended Flow Guard)

```
Attack ngăn chặn: CFG bypass qua valid-but-wrong function targets

CFG chỉ check: "địa chỉ này có phải function không?"
XFG thêm check: "địa chỉ này có phải function ĐÚNG TYPE không?"

Nguyên lý:
  - Compiler hash function prototype → XFG hash
  - Hash bao gồm: return type, parameter types, calling convention
  - Trước indirect call: check cả address VÀ hash match

  ; XFG validation pseudocode
  target_hash = *(uint64_t*)(target_addr - 8);  // Hash stored 8 bytes before function
  expected_hash = XFG_HASH(function_prototype);
  if (target_hash != expected_hash) {
      RaiseException(STATUS_XFG_VIOLATION);
  }

  VD: void (*callback)(int, char*) chỉ có thể gọi functions
      có cùng signature void(int, char*)
```

#### CET Shadow Stacks

```
Attack ngăn chặn: ROP attacks, return address overwrite

Nguyên lý:
  - Hardware feature: Intel CET (Control-flow Enforcement Technology)
  - CPU duy trì SHADOW STACK riêng biệt
  - Mỗi CALL instruction: push return address lên CẢ hai stacks
  - Mỗi RET instruction: compare return address từ cả hai stacks
  - Nếu KHÔNG MATCH → #CP exception (Control Protection fault)

  Normal execution:
    call func
    ┌─────────────┐  ┌──────────────┐
    │ Regular Stack│  │ Shadow Stack │
    │ ret_addr     │  │ ret_addr     │
    └─────────────┘  └──────────────┘
    → RET: both match → OK

  ROP attack:
    Buffer overflow overwrites regular stack
    ┌─────────────┐  ┌──────────────┐
    │ Regular Stack│  │ Shadow Stack │
    │ ROP_gadget   │  │ ret_addr     │  ← MISMATCH!
    └─────────────┘  └──────────────┘
    → RET: ROP_gadget != ret_addr → #CP FAULT → process crash

PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY:
  EnableUserShadowStack          : Pos 0
  AuditUserShadowStack           : Pos 1
  SetContextIpValidation         : Pos 2  ← Validate RIP in SetThreadContext
  AuditSetContextIpValidation    : Pos 3
  EnableUserShadowStackStrictMode: Pos 4
  BlockNonCetBinaries            : Pos 5  ← Block DLLs không support CET
```

#### ACG (Arbitrary Code Guard)

```
Attack ngăn chặn: Dynamic code generation/modification attacks
                  (JIT spray, shellcode injection vào RWX pages)

Nguyên lý:
  - Enforce W^X (Write XOR Execute) strictly
  - Không thể tạo page với BOTH Write + Execute
  - VirtualAlloc(PAGE_EXECUTE_READWRITE) → FAIL
  - VirtualProtect(PAGE_READWRITE → PAGE_EXECUTE) → FAIL
  - Ngoại trừ: signed code mapped từ file (image sections)

Giới hạn:
  - JIT compilers (V8, .NET JIT) không hoạt động với ACG
  - Browsers dùng separate "JIT process" (không có ACG) để compile
    rồi map compiled code vào "content process" (có ACG) as read-execute
```

#### CIG (Code Integrity Guard)

```
Attack ngăn chặn: DLL injection với unsigned/malicious DLLs

Nguyên lý:
  - Chỉ cho phép load DLLs được Microsoft signed
  - LoadLibrary() với unsigned DLL → FAIL
  - Map unsigned image → FAIL
  - IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY trong PE header

PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY:
  MicrosoftSignedOnly     : Pos 0  ← Chỉ Microsoft signed
  StoreSignedOnly         : Pos 1  ← Microsoft Store signed
  MitigationOptIn         : Pos 2  ← Opt-in flag
  AuditMicrosoftSignedOnly: Pos 3  ← Audit mode (log, không block)
  AuditStoreSignedOnly    : Pos 4
```

#### Extension Point Disable

```
Attack ngăn chặn: DLL injection qua legacy extension mechanisms

Các extension points bị disable:
  - AppInit_DLLs: DLLs load vào MỌI process dùng user32.dll
    Registry: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows
    → Malware thường dùng để inject persistence DLL
  - SetWindowsHookEx(): Global hooks inject DLL vào target process
    → Keyloggers, screen capture malware
  - Winsock LSP (Layered Service Provider): Network DLL injection
  - AppCertDlls: DLLs loaded when CreateProcess is called

PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY:
  DisableExtensionPoints : Pos 0
```

#### Disable Win32k System Calls

```
Attack ngăn chặn: Win32k.sys kernel exploitation từ sandboxed process

Win32k.sys là kernel driver cho Windows GUI subsystem.
Attack surface lớn (>1000 syscalls, complex code, legacy).
Sandboxed processes (VD: browser renderer) không cần GUI
→ Disable win32k syscalls để giảm attack surface.

PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY:
  DisallowWin32kSystemCalls : Pos 0
  AuditDisallowWin32kSystemCalls : Pos 1

;; Khi process gọi NtUserXxx (win32k syscall) → STATUS_ACCESS_DENIED
```

### 3.8.3 Xem Mitigations

```powershell
# PowerShell
Get-ProcessMitigation -Name notepad.exe
Get-ProcessMitigation -System       # System-wide defaults

# Process Explorer: Properties → Security tab → Mitigation policies
```

```
;; WinDbg
kd> dt nt!_EPROCESS <addr> MitigationFlags
kd> dt nt!_EPROCESS <addr> MitigationFlags2
```

---

## 3.9 Experiments

### Experiment 3.1: Theo Dõi Process Creation Chi Tiết

```
1. Mở Process Monitor
2. Add filter: Operation is "Process Create"
3. Mở notepad.exe
4. Double-click event → xem:
   - Call stack (thấy CreateProcessW → NtCreateUserProcess)
   - Process ID, Parent PID
   - Command line
   - Integrity Level
   - Environment
```

### Experiment 3.2: Xem EPROCESS

```
kd> !process 0 0 notepad.exe
kd> dt nt!_EPROCESS <addr>
kd> dt nt!_EPROCESS <addr> ImageFileName
kd> dt nt!_EPROCESS <addr> Token
kd> !token <token_addr>
```

### Experiment 3.3: Protected Process

```powershell
# Xem PPL status
Get-Process | ForEach-Object {
    $p = $_
    try {
        $handle = $p.Handle  # Fails nếu protected
        [PSCustomObject]@{Name=$p.ProcessName; PID=$p.Id; Protected=$false}
    } catch {
        [PSCustomObject]@{Name=$p.ProcessName; PID=$p.Id; Protected=$true}
    }
}
```

### Experiment 3.4: Job Objects

```powershell
# Tạo job giới hạn memory
$job = [System.Diagnostics.Process]::Start("notepad.exe")
# (Cần P/Invoke hoặc C code cho full job API)
# Process Explorer: Properties → Job tab
```

---

### Experiment 3.5: Process Hollowing Detection

Process hollowing là kỹ thuật malware: tạo process hợp lệ (VD: svchost.exe)
ở trạng thái suspended, thay thế image bằng malicious code, rồi resume.

```
Process Hollowing Steps:
  1. CreateProcess("svchost.exe", ..., CREATE_SUSPENDED)
  2. NtUnmapViewOfSection() → xóa original image
  3. VirtualAllocEx() → allocate memory tại image base
  4. WriteProcessMemory() → ghi malicious PE image
  5. SetThreadContext() → update entry point (RCX register)
  6. ResumeThread() → execute malicious code

Detection:
  ┌──────────────────────────────────────────────────────┐
  │ Indicator                    │ Tool                   │
  ├──────────────────────────────┼────────────────────────┤
  │ Image path != memory content │ Hollows Hunter, PE-sieve│
  │ Section mismatch             │ Volatility malfind     │
  │ PEB.ImageBaseAddress khác    │ WinDbg manual check    │
  │   section base               │                        │
  │ CREATE_SUSPENDED → resume    │ Process Monitor        │
  │ NtUnmapViewOfSection call    │ ETW / API monitoring   │
  └──────────────────────────────┴────────────────────────┘

;; WinDbg detection: so sánh disk image vs memory image
0:000> lm m svchost      ; Module base + size
0:000> !dh <base>        ; PE header từ memory
;; Compare với PE header từ disk file
;; Nếu entry point, sections khác nhau → hollowed

;; Volatility detection
vol.py -f memory.dmp windows.malfind
;; Tìm processes có executable memory không backed bởi file
```

### Experiment 3.6: DLL Injection Methods — Tổng Quan

```
Method 1: CreateRemoteThread + LoadLibrary
=============================================
Phổ biến nhất. Cần: PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                     PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION

1. OpenProcess(target_pid, ...)
2. VirtualAllocEx() → allocate memory cho DLL path string
3. WriteProcessMemory() → ghi DLL path vào target process
4. GetProcAddress(kernel32, "LoadLibraryW") → LoadLibrary address
5. CreateRemoteThread(target, LoadLibraryW, dll_path_addr)
   → Thread mới trong target gọi LoadLibraryW("malicious.dll")
6. DllMain(DLL_PROCESS_ATTACH) → malicious code executes

Detection:
  - Thread start address trỏ vào kernel32!LoadLibraryW
  - Thread không belong to any loaded module's code
  - ETW: Microsoft-Windows-Kernel-Process thread creation events

Method 2: APC Injection (QueueUserAPC)
=============================================
Không cần tạo thread mới. Dùng APC (Asynchronous Procedure Call)
queue vào existing thread.

1. OpenProcess / OpenThread
2. VirtualAllocEx + WriteProcessMemory (DLL path)
3. QueueUserAPC(LoadLibraryW, target_thread, dll_path_addr)
4. APC execute khi target thread enters alertable wait
   (SleepEx, WaitForSingleObjectEx, etc.)

Ưu điểm: Không tạo suspicious remote thread.
Nhược điểm: Target thread phải enter alertable wait state.

Method 3: SetWindowsHookEx
=============================================
Đặt global hook → Windows auto-inject DLL vào target processes.

1. LoadLibrary("hook.dll") trong attacker process
2. GetProcAddress → hook procedure trong hook.dll
3. SetWindowsHookEx(WH_KEYBOARD, HookProc, hDll, 0)
   → 0 = global hook, inject vào MỌI process dùng keyboard
4. Khi target process nhận keyboard input:
   → Windows inject hook.dll vào target process
   → HookProc() execute trong target context

Detection: Liệt kê hooks với WH_* constants.

Method 4: AtomBombing (không dùng VirtualAllocEx)
=============================================
Sử dụng Global Atom Table + APC để ghi code vào target.

1. GlobalAddAtom() → store shellcode/DLL path trong atom table
2. QueueUserAPC(GlobalGetAtomName, target_thread, writable_addr)
   → Copy atom data vào writable memory trong target process
3. Modify target's code hoặc data để redirect execution

Ưu điểm: Không dùng VirtualAllocEx/WriteProcessMemory → bypass monitors.

Method 5: Process Doppelganging (NTFS Transactions)
=============================================
Sử dụng NTFS transactions để tạo process từ "phantom" file.

1. NtCreateTransaction() → tạo NTFS transaction
2. Trong transaction: tạo file và ghi malicious PE
3. NtCreateSection() từ transacted file → image section
4. NtRollbackTransaction() → file KHÔNG CÒN trên disk
5. NtCreateProcessEx() từ section → process từ "ghost" file

Detection khó: file không tồn tại trên disk để scan.
```

### Experiment 3.7: Detect Injected Threads

```
Phương pháp: Kiểm tra thread start address

// Enum threads → check start address nằm trong known module range
foreach (Thread t in Process.Threads) {
    void* startAddr = NtQueryInformationThread(t, ThreadQuerySetWin32StartAddress);

    // Kiểm tra startAddr có nằm trong bất kỳ loaded module nào không
    bool found = false;
    foreach (Module m in Process.Modules) {
        if (startAddr >= m.BaseAddress &&
            startAddr < m.BaseAddress + m.Size) {
            found = true;
            break;
        }
    }
    if (!found) {
        // Thread start address KHÔNG thuộc module nào
        // → Possible injected thread (shellcode hoặc unbacked code)
        printf("SUSPICIOUS Thread %d: start=0x%p\n", t.Id, startAddr);
    }
}

;; WinDbg: Kiểm tra thread start addresses
0:000> ~* k              ; Stack traces tất cả threads
0:000> !threads           ; Danh sách threads với start address
;; Thread bắt đầu từ LoadLibraryW hoặc unknown address → suspicious
```

### Experiment 3.8: Process Access Rights và Security Impact

```
Process Access Rights và rủi ro bảo mật:

┌────────────────────────────────┬──────┬─────────────────────────────────┐
│ Access Right                   │ Mask │ Security Impact                 │
├────────────────────────────────┼──────┼─────────────────────────────────┤
│ PROCESS_VM_READ                │ 0x10 │ Đọc memory: dump credentials,   │
│                                │      │ keys, tokens, passwords         │
├────────────────────────────────┼──────┼─────────────────────────────────┤
│ PROCESS_VM_WRITE               │ 0x20 │ Ghi memory: modify code/data,   │
│                                │      │ inject shellcode, patch hooks   │
├────────────────────────────────┼──────┼─────────────────────────────────┤
│ PROCESS_VM_OPERATION           │ 0x08 │ Thay đổi memory protection:     │
│                                │      │ VirtualProtectEx → RWX pages    │
├────────────────────────────────┼──────┼─────────────────────────────────┤
│ PROCESS_CREATE_THREAD          │ 0x02 │ Tạo thread mới: remote code     │
│                                │      │ execution trong target process  │
├────────────────────────────────┼──────┼─────────────────────────────────┤
│ PROCESS_DUP_HANDLE             │ 0x40 │ Duplicate handles: steal tokens,│
│                                │      │ file handles, socket handles    │
├────────────────────────────────┼──────┼─────────────────────────────────┤
│ PROCESS_SET_INFORMATION        │ 0x200│ Thay đổi priority, affinity,    │
│                                │      │ DEP policy                      │
├────────────────────────────────┼──────┼─────────────────────────────────┤
│ PROCESS_QUERY_INFORMATION      │ 0x400│ Đọc tokens, PEB, debug port     │
│                                │      │ → information disclosure        │
├────────────────────────────────┼──────┼─────────────────────────────────┤
│ PROCESS_SUSPEND_RESUME         │ 0x800│ Suspend process: DoS,           │
│                                │      │ race condition exploitation     │
├────────────────────────────────┼──────┼─────────────────────────────────┤
│ PROCESS_TERMINATE              │ 0x01 │ Kill process: DoS against       │
│                                │      │ security tools, services        │
├────────────────────────────────┼──────┼─────────────────────────────────┤
│ PROCESS_ALL_ACCESS             │0x1FFFFF│ Tất cả rights: full control   │
└────────────────────────────────┴──────┴─────────────────────────────────┘

Attack chain ví dụ:
  PROCESS_VM_WRITE + PROCESS_VM_OPERATION + PROCESS_CREATE_THREAD
  → Classic DLL injection combo
  → Ghi DLL path, thay đổi protection, tạo remote thread

  PROCESS_DUP_HANDLE
  → Steal token handle từ privileged process
  → DuplicateHandle() → get token → impersonate
  → Escalate privileges

  PROCESS_QUERY_INFORMATION + PROCESS_VM_READ
  → Dump lsass.exe memory → extract credentials
  → Mimikatz sekurlsa::minidump technique

;; WinDbg: Kiểm tra process DACL (ai có quyền gì)
kd> !object <EPROCESS>
kd> !sd <security_descriptor_addr>
;; Hoặc dùng Process Explorer: Properties → Security tab → Permissions
```

---

## 3.10 Tóm Tắt

| Khái niệm | Điểm chính |
|------------|------------|
| Process creation | 7 stages, NtCreateUserProcess atomic |
| EPROCESS | ~1500 bytes, chứa KPROCESS, token, VAD, handles |
| PEB | User-mode structure, chứa loaded modules, heap |
| PP/PPL | Hardware-enforced process protection, signer levels |
| Pico Processes | WSL 1, syscall translation |
| Trustlets | VTL 1, Secure Kernel, Credential Guard |
| Image Loader | LdrInitializeThunk, DLL search order, Known DLLs |
| Jobs | Resource limits, nested jobs, CPU/memory/IO rate control |
| Silos | Windows Containers, namespace isolation |
| Mitigations | Per-process exploit protection (CFG, CET, ACG, ...) |

> **Tiếp theo: [Chapter 4 — Threads](Chapter_04_Threads.md)**
> Thread scheduling, priority, quantum, multiprocessor scheduling.
