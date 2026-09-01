# Chapter 8: Cơ Chế Hệ Thống (System Mechanisms)

> Chương lớn nhất trong bộ tài liệu, bao gồm: processor execution model,
> side-channel mitigations, trap dispatching, WoW64, Object Manager,
> synchronization, ALPC, WNF, debugging, và packaged applications.

---

## 8.1 Processor Execution Model

### 8.1.1 Segmentation (x64)

x64 mode sử dụng flat segment model — segmentation hầu như bị loại bỏ:

```
Segment Registers (x64 Long Mode):
  CS: Code segment  → flat, base=0, limit=max
  DS: Data segment   → flat (ignored by CPU)
  ES: Extra segment  → flat (ignored)
  SS: Stack segment  → flat
  FS: Thread-local   → user-mode TEB (32-bit compatibility)
  GS: Thread-local   → kernel-mode KPCR / user-mode TEB (x64)
```

Chỉ `FS` và `GS` còn ý nghĩa — dùng cho per-thread/per-CPU data:

```
User mode (x64):
  GS base → TEB (Thread Environment Block)
  mov rax, gs:[0x30]   ; TEB self-pointer
  mov rax, gs:[0x60]   ; PEB pointer

Kernel mode (x64):
  GS base → KPCR (Kernel Processor Control Region)
  mov rax, gs:[0x188]  ; KPCR.CurrentThread
  
swapgs instruction:
  Swaps GS base between user and kernel values
  Used at syscall entry/exit
```

### 8.1.2 Task State Segment (TSS)

x64 Windows dùng TSS chủ yếu cho stack switching khi interrupt/exception:

```
TSS (per-CPU):
├── RSP0    ← Kernel stack for Ring 0 (syscall entry)
├── RSP1    ← Not used
├── RSP2    ← Not used
├── IST1    ← NMI stack
├── IST2    ← Double Fault stack
├── IST3    ← Machine Check stack
├── IST4-7  ← Available
└── IOPB    ← I/O Permission Bitmap offset
```

**Interrupt Stack Table (IST):** cho phép dùng stack cố định cho critical exceptions — ngăn stack overflow gây double fault loop.

---

## 8.2 Hardware Side-Channel Vulnerabilities

### 8.2.1 Spectre và Meltdown Background

```
CPU Pipeline (simplified):
  Fetch → Decode → Execute → Memory → Writeback
                      │
                      ├── Branch Prediction: CPU đoán branch direction
                      ├── Out-of-Order Execution: thực thi instruction trước khi biết kết quả
                      └── Speculative Execution: thực thi cả hai paths, rollback sai

Side-Channel:
  Speculative execution thay đổi CPU cache state
  → Timing cache access tiết lộ speculated data
  → Data leak qua cache timing side-channel
```

### 8.2.2 Attack Types

| Attack | CVE | Mô tả |
|--------|-----|-------|
| Meltdown | CVE-2017-5754 | Read kernel memory từ user mode |
| Spectre v1 | CVE-2017-5753 | Bounds check bypass |
| Spectre v2 | CVE-2017-5715 | Branch target injection |
| L1TF | CVE-2018-3646 | L1 Terminal Fault |
| MDS | CVE-2018-12126+ | Microarchitectural Data Sampling |
| SSBD | CVE-2018-3639 | Speculative Store Bypass |

### 8.2.3 Windows Mitigations

**KVA Shadow (Kernel Virtual Address Shadow) — Meltdown fix:**

```
Without KVA Shadow:
  User mode: can see kernel page table entries
  Speculate read → kernel data in cache → timing leak

With KVA Shadow:
  User mode page tables: kernel addresses REMOVED
  ├── Minimal kernel mapping: only syscall entry/exit code
  ├── Full kernel mapping: loaded on syscall entry
  └── Removed on sysret (return to user mode)

  → User mode speculative reads: kernel PTEs not present
  → No data to leak

Performance impact: 5-30% on syscall-heavy workloads
PCID optimization reduces impact significantly
```

**Retpoline — Spectre v2 fix:**

```
Normal indirect branch:
  jmp [rax]           ; CPU predicts target → speculative execution

Retpoline:
  call retpoline_target
  .loop:
  pause
  jmp .loop           ; Infinite loop (never executed, traps speculator)
  retpoline_target:
  mov [rsp], rax      ; Replace return address
  ret                 ; Return to actual target
  
  → Branch predictor speculates into infinite loop
  → No useful speculation occurs
  → Real execution follows correct path via ret
```

**[UPDATE 2026]** Modern CPUs (Intel 12th gen+, AMD Zen 3+): hardware mitigations (eIBRS, STIBP, SSBD) built into silicon, software retpoline being phased out.

---

## 8.3 Trap Dispatching

### 8.3.1 Trap Types

| Type | Trigger | Handler |
|------|---------|---------|
| Interrupt | Hardware/software signal | IDT → ISR |
| Exception | CPU fault/trap | IDT → exception handler |
| System call | syscall instruction | MSR → KiSystemCall64 |

### 8.3.2 Interrupt Descriptor Table (IDT)

```
IDT (256 entries, per-CPU):
┌──────┬──────────────────────────────────────┐
│ 0x00 │ #DE Divide Error                     │
│ 0x01 │ #DB Debug                            │
│ 0x02 │ NMI (Non-Maskable Interrupt)         │
│ 0x03 │ #BP Breakpoint (INT 3)               │
│ 0x04 │ #OF Overflow                         │
│ 0x05 │ #BR Bound Range Exceeded             │
│ 0x06 │ #UD Invalid Opcode                   │
│ 0x07 │ #NM Device Not Available (FPU)       │
│ 0x08 │ #DF Double Fault (IST2)              │
│ 0x09 │ Reserved                             │
│ 0x0A │ #TS Invalid TSS                      │
│ 0x0B │ #NP Segment Not Present              │
│ 0x0C │ #SS Stack-Segment Fault              │
│ 0x0D │ #GP General Protection               │
│ 0x0E │ #PF Page Fault                       │
│ 0x10 │ #MF x87 FPU Error                    │
│ 0x11 │ #AC Alignment Check                  │
│ 0x12 │ #MC Machine Check (IST3)             │
│ 0x13 │ #XM SIMD Exception                   │
│ 0x14 │ #VE Virtualization Exception         │
│ 0x15 │ #CP Control Protection (CET)         │
│ ...  │                                      │
│ 0x21-│ Hardware device interrupts            │
│ 0xFF │ (mapped by APIC)                     │
│ ...  │                                      │
│ 0x2C │ KiRaiseAssertion                     │
│ 0x2D │ Debug service (INT 2D)               │
│ 0x2E │ KiSystemCall (legacy x86 INT 2E path)│
└──────┴──────────────────────────────────────┘

kd> !idt                            ; Dump IDT
kd> !idt -a                         ; All entries with symbols
```

### 8.3.3 Interrupt Flow (Hardware)

```
1. Device asserts interrupt line
2. APIC signals CPU (vector number)
3. CPU:
   ├── Finish current instruction
   ├── Push RFLAGS, CS, RIP, (error code) on IST/kernel stack
   ├── Clear IF (disable further interrupts)
   ├── Load handler from IDT[vector]
   └── Jump to handler

4. Windows interrupt handler (KiInterruptDispatch):
   ├── Save trap frame (all registers)
   ├── Raise IRQL to device IRQL
   ├── Call ISR (Interrupt Service Routine)
   │   └── Driver's ISR does minimal work
   │       └── Queue DPC if more work needed
   ├── Lower IRQL
   ├── Drain DPC queue if pending
   └── Return from interrupt (iretq)

5. If DPCs queued:
   ├── IRQL = DISPATCH_LEVEL
   ├── Execute DPC routines
   │   └── Complete IRPs, process data
   └── Lower IRQL back to previous
```

### 8.3.4 Exception Dispatching

```
Exception occurs (e.g., access violation):

Kernel mode exception:
1. KiExceptionDispatch
2. Try kernel debugger first break
3. RtlDispatchException → walk SEH chain
4. If unhandled → kernel debugger second break
5. If still unhandled → KeBugCheckEx (BSOD)

User mode exception:
1. KiExceptionDispatch (in kernel)
2. Copy exception to user mode trap frame
3. KiUserExceptionDispatcher (ntdll.dll)
4. RtlDispatchException → walk SEH/VEH handlers
   ├── Vectored Exception Handlers (VEH) — first
   ├── Frame-based SEH handlers (__try/__except) — second
   └── Vectored Continue Handlers — after handled
5. If unhandled → NtRaiseException → kernel
6. Kernel → debugger (if attached)
7. If still unhandled → UnhandledExceptionFilter
8. → Default: TerminateProcess (or WER crash report)
```

### 8.3.5 Structured Exception Handling (SEH)

```c
// User mode SEH
__try {
    int* p = NULL;
    *p = 42;  // Access violation
}
__except(EXCEPTION_EXECUTE_HANDLER) {
    printf("Caught exception!\n");
}

// Filter expressions:
// EXCEPTION_EXECUTE_HANDLER (1)  → handle here
// EXCEPTION_CONTINUE_SEARCH (0) → try next handler
// EXCEPTION_CONTINUE_EXECUTION (-1) → retry faulting instruction
```

x64 SEH: table-based (no runtime setup, unwind data in PE):
```
.pdata section → RUNTIME_FUNCTION entries
Each entry: begin address, end address, unwind info
Unwind info → exception handler, scope table
→ No performance cost when no exception occurs
```

### 8.3.6 System Call Dispatching

```
User mode:
  NtReadFile stub (ntdll.dll):
    mov r10, rcx          ; r10 = 1st param (rcx used by syscall)
    mov eax, 0x0006       ; System call number
    syscall               ; CPU: RIP→MSR_LSTAR, switch to Ring 0

Kernel mode entry (KiSystemCall64):
    swapgs                ; GS → KPCR
    mov gs:[...], rsp     ; Save user RSP to KPCR
    mov rsp, gs:[...]     ; Load kernel stack from TSS.RSP0
    
    ; Build KTRAP_FRAME
    push rbp              ; User RBP
    sub rsp, KTRAP_FRAME_SIZE
    mov [rsp+...], rcx    ; Save registers
    ...
    
    ; Validate syscall number
    cmp eax, NumberOfSystemServiceRoutines
    jae invalid
    
    ; Look up in SSDT (System Service Descriptor Table)
    lea r10, KiServiceTable
    movsxd r10, dword ptr [r10+eax*4]  ; 4-byte relative offset (sign-extended)
    sar r10, 4            ; Remove argument count bits (low 4 bits)
    add r10, KiServiceTable ; Actual function address
    
    ; Check argument count, copy from user stack if needed
    ; Call service routine
    call r10              ; e.g., nt!NtReadFile
    
    ; Return
    mov [trap_frame+rax_offset], rax  ; Save return value
    ...
    swapgs
    sysret                ; Back to user mode
```

**System Service Descriptor Table (SSDT):**

```
KeServiceDescriptorTable:
├── ServiceTable → KiServiceTable (ntoskrnl system calls)
├── CounterTable → (performance counters, optional)
├── NumberOfServices → ~470 (varies by build)
└── ArgumentTable → bytes of stack args per syscall

KeServiceDescriptorTableShadow:
├── [0] = same ntoskrnl table
└── [1] = win32k.sys system calls (W32pServiceTable)
    ├── NtUserCreateWindow, NtGdiCreateBitmap, ...
    └── ~1200+ additional system calls
```

---

## 8.4 WoW64 (Windows on Windows 64-bit)

### 8.4.1 Architecture

```
32-bit Application (x86):
┌───────────────────────────────────┐
│ 32-bit code                       │
│ kernel32.dll (32-bit)             │
│ ntdll.dll (32-bit)                │
├───────────────────────────────────┤
│ wow64.dll                         │ ← WoW64 core
│ wow64cpu.dll                      │ ← x86 ↔ x64 thunking
│ wow64win.dll                      │ ← Win32k thunking
├───────────────────────────────────┤
│ ntdll.dll (64-bit)                │ ← Real syscall stubs
└───────────────────────────────────┘
        │ syscall (64-bit)
        ▼
64-bit Kernel (ntoskrnl.exe)
```

### 8.4.2 Thunking Process

```
32-bit app calls CreateFileW():
1. kernel32.dll (32-bit) → NtCreateFile() [ntdll 32-bit]
2. ntdll (32-bit) → special syscall thunk
3. wow64cpu.dll:
   ├── Switch CPU from 32-bit to 64-bit mode
   │   (far jump to 64-bit code segment)
   ├── Convert 32-bit parameters to 64-bit
   │   (pointer extension, structure conversion)
   └── Call NtCreateFile() [ntdll 64-bit]
4. ntdll (64-bit) → real syscall → kernel
5. Return path: reverse conversion
```

### 8.4.3 File System Redirection

```
32-bit app accesses:              Actually goes to:
C:\Windows\System32\              C:\Windows\SysWOW64\ (32-bit DLLs)
C:\Windows\System32\drivers\etc\  C:\Windows\System32\drivers\etc\ (not redirected)

Disable redirection (for specific call):
  Wow64DisableWow64FsRedirection()
  ... access real System32 ...
  Wow64RevertWow64FsRedirection()
```

### 8.4.4 Registry Redirection

```
32-bit app accesses:                     Actually goes to:
HKLM\SOFTWARE\                           HKLM\SOFTWARE\WOW6432Node\
HKLM\SOFTWARE\Classes\CLSID\            HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\

Shared keys (not redirected):
  HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\
  HKLM\SOFTWARE\Classes\.ext (file associations)
```

### 8.4.5 ARM Emulation

**[UPDATE 2026]** Windows on ARM supports multiple emulation layers:

```
ARM64 Windows:
├── ARM64 native → direct execution
├── ARM32 apps → wow64 (ARM32-on-ARM64)
├── x86 apps → wow64 + xtajit.dll (x86-on-ARM64 JIT emulation)
└── x64 apps → wow64 + xtajit64.dll (x64-on-ARM64 JIT emulation)
    ← New in Windows 11

Prism (xtajit64.dll):
  - JIT compilation: x64 → ARM64 translation
  - Code caching for performance
  - ~60-90% native performance for most apps
  - Some SIMD/AVX instructions not fully supported
```

---

## 8.5 Object Manager Chi Tiết

### 8.5.1 Object Types

```
kd> !object \ObjectTypes

\ObjectTypes:
    Type            ALPC Port
    Directory       Section
    SymbolicLink    Event
    Token           EventPair
    Job             Mutant
    Process         Callback
    Thread          Semaphore
    UserApcReserve  Timer
    IoCompletion    Profile
    IoCompletionReserve  KeyedEvent
    TpWorkerFactory Session
    WaitCompletionPacket  Key
    ...
```

### 8.5.2 Object Header

```
                        Optional Headers (before body)
                             │
┌────────────────────────────┼────────────────────────┐
│ OBJECT_HEADER_CREATOR_INFO │ (who created object)   │
│ OBJECT_HEADER_NAME_INFO    │ (object name)          │
│ OBJECT_HEADER_HANDLE_INFO  │ (handle database)      │
│ OBJECT_HEADER_QUOTA_INFO   │ (quota charges)        │
│ OBJECT_HEADER_PROCESS_INFO │ (exclusive process)    │
│ OBJECT_HEADER_AUDIT_INFO   │ (audit info)           │
│ OBJECT_HEADER_PADDING_INFO │ (alignment padding)    │
├────────────────────────────┼────────────────────────┤
│ OBJECT_HEADER               │                        │
│   PointerCount              │ ← kernel references    │
│   HandleCount               │ ← open handles         │
│   Lock                      │ ← push lock            │
│   TypeIndex                 │ ← encoded type index   │
│   InfoMask                  │ ← which optional headers│
│   Flags                     │ ← permanent, name only │
│   SecurityDescriptor        │ ← DACL/SACL            │
├────────────────────────────┤                        │
│ OBJECT BODY                 │ ← actual object data   │
│ (_EPROCESS, _FILE_OBJECT,  │                        │
│  _KEVENT, etc.)             │                        │
└────────────────────────────┘
```

### 8.5.3 Object Namespace

```
\ (Root)
├── \ArcName                    ← Boot device arc names
├── \BaseNamedObjects           ← Per-session named objects (events, mutexes)
│   ├── MyMutex
│   ├── SharedMemory1
│   └── ...
├── \Callback                   ← Callback objects
├── \Device                     ← Device objects
│   ├── \Device\HarddiskVolume1 ← C: drive
│   ├── \Device\Tcp             ← TCP driver
│   ├── \Device\Null            ← Null device
│   └── \Device\NamedPipe       ← Named pipe filesystem
├── \DosDevices → \??           ← Symlink to per-session DOS devices
├── \??                         ← DOS device names
│   ├── C: → \Device\HarddiskVolume3
│   ├── D: → \Device\CdRom0
│   ├── NUL → \Device\Null
│   ├── CON → \Device\ConDrv
│   └── GLOBALROOT → \          ← Access root namespace
├── \Driver                     ← Driver objects
│   ├── \Driver\Ntfs
│   ├── \Driver\Tcpip
│   └── ...
├── \FileSystem                 ← File system driver objects
├── \GLOBAL??                   ← System-wide DOS devices
├── \KernelObjects              ← Kernel notification events
│   ├── HighMemoryCondition
│   ├── LowMemoryCondition
│   ├── HighPagedPoolCondition
│   └── ...
├── \KnownDlls                 ← Pre-loaded DLL sections
├── \NLS                        ← National Language Support
├── \ObjectTypes                ← Type objects
├── \RPC Control                ← RPC endpoint objects
├── \Security                   ← LSA objects
├── \Sessions                   ← Per-session namespaces
│   ├── \Sessions\0\BaseNamedObjects  ← Session 0
│   └── \Sessions\1\BaseNamedObjects  ← Session 1
└── \Windows                    ← Window Station objects
    └── \Windows\WindowStations
        └── WinSta0
```

### 8.5.4 Handle Table

```
3-Level Handle Table:

Handle value = index × 4 (0x0004, 0x0008, 0x000C, ...)

Level 0: HANDLE_TABLE
├── TableCode          ← Pointer to table (level encoded in low bits)
├── QuotaProcess       ← Process charged
├── UniqueProcessId    ← PID
├── HandleCount        ← Total open handles
└── Flags

Level 1 table: array of HANDLE_TABLE_ENTRY
Each entry:
├── ObjectPointerBits  ← Pointer to object (encoded)
├── GrantedAccessBits  ← Access mask granted
├── Attributes         ← OBJ_INHERIT, OBJ_PROTECT_CLOSE, ...
└── Lock bit           ← Used for synchronization

Capacity:
  Single level: 256 handles
  2 levels: 256 × 256 = 65,536 handles
  3 levels: 256 × 256 × 256 = 16,777,216 handles
```

---

## 8.6 Synchronization

### 8.6.1 Kernel Synchronization Primitives

**High-IRQL (DISPATCH_LEVEL and above):**

| Primitive | Use Case |
|-----------|----------|
| Spinlock | Short critical sections at DISPATCH_LEVEL+ |
| Queued Spinlock | Reduce cache bouncing on multiprocessor |
| In-Stack Queued Spinlock | No global storage needed |
| Executive Spinlock | Raise IRQL + acquire |
| Interrupt Spinlock | Synchronize with ISR |

**Low-IRQL (below DISPATCH_LEVEL):**

| Primitive | Features |
|-----------|----------|
| Dispatcher Objects | Waitable (KeWaitForSingleObject) |
| ├── Event | Auto-reset or Manual-reset |
| ├── Mutex / Mutant | Ownership, recursive, abandon detection |
| ├── Semaphore | Counting, up to max count |
| ├── Timer | Waitable, periodic |
| └── Process/Thread | Wait for exit |
| Fast Mutex | Non-waitable, disables APCs |
| Guarded Mutex | Like fast mutex, disables APCs via region |
| Push Lock | Reader-writer, compact, scalable |
| Executive Resource | Reader-writer, ownership tracking |
| Run-Once | One-time initialization |
| Critical Section | User-mode, spin+wait hybrid |
| SRW Lock | User-mode reader-writer, very lightweight |
| Condition Variable | User-mode, wait for condition |

### 8.6.2 Spinlocks

```c
// Kernel spinlock
KSPIN_LOCK Lock;
KeInitializeSpinLock(&Lock);

KIRQL OldIrql;
KeAcquireSpinLock(&Lock, &OldIrql);    // Raises to DISPATCH_LEVEL
// Critical section — MUST be short (no paging, no waiting)
KeReleaseSpinLock(&Lock, OldIrql);     // Restores IRQL

// Implementation (x64):
AcquireSpinLock:
  lock bts [Lock], 0     ; Atomically test-and-set bit 0
  jc spin                ; If already set → spin
  ret

spin:
  pause                  ; CPU hint: spin-wait loop
  test [Lock], 1         ; Check without locking bus
  jnz spin               ; Still held → keep spinning
  jmp AcquireSpinLock    ; Try again
```

### 8.6.3 Push Locks

Compact reader-writer lock, heavily used in kernel:

```
Push Lock value (pointer-size):
  Bit 0: Locked (exclusive)
  Bit 1: Waiting (waiters exist)
  Bit 2: Waking (wake in progress)
  Bit 3: Multiple shared (>1 shared owner)
  Bits 4+: Share count OR wait block pointer

Advantages over Executive Resource:
  - 1 pointer size (8 bytes) vs ~100 bytes
  - Faster for uncontended case
  - Auto-blocking (no spinning)
  - Cache-friendly

kd> dt nt!_EX_PUSH_LOCK
```

### 8.6.4 User-Mode: Critical Section

```c
CRITICAL_SECTION cs;
InitializeCriticalSection(&cs);

EnterCriticalSection(&cs);
// Internally:
//   1. Try InterlockedCompareExchange (lock-free fast path)
//   2. If contention: SpinCount iterations of spinning
//   3. If still contended: NtWaitForAlertByThreadId (or keyed event)
LeaveCriticalSection(&cs);

// With spin count (for short critical sections):
InitializeCriticalSectionAndSpinCount(&cs, 4000);
```

### 8.6.5 User-Mode: SRW Lock (Slim Reader/Writer)

```c
SRWLOCK lock = SRWLOCK_INIT;

// Shared (reader) access:
AcquireSRWLockShared(&lock);
// ... read data ...
ReleaseSRWLockShared(&lock);

// Exclusive (writer) access:
AcquireSRWLockExclusive(&lock);
// ... write data ...
ReleaseSRWLockExclusive(&lock);

// Size: single pointer (8 bytes on x64)
// Cannot be recursively acquired
// No ownership tracking (debug limitations)
```

---

## 8.7 Advanced Local Procedure Call (ALPC)

### 8.7.1 ALPC Overview

ALPC là IPC mechanism chính của Windows kernel:

```
Client Process                    Server Process
┌──────────────┐                 ┌──────────────┐
│ Client       │                 │ Server       │
│ sends msg    │─── ALPC Port ──→│ receives msg │
│              │←── ALPC Port ───│ sends reply  │
└──────────────┘                 └──────────────┘

Used by:
  - RPC (Remote Procedure Call)
  - COM activation
  - Windows Error Reporting
  - Power management notifications
  - csrss.exe communication
  - LSA authentication
  - Service Control Manager
  - Debug port communication
```

### 8.7.2 Connection Model

```
1. Server creates connection port:
   NtAlpcCreatePort(&ServerPort, &ObjectAttributes, &PortAttributes)

2. Client connects:
   NtAlpcConnectPort(&ClientPort, &ServerPortName, ...)

3. Server accepts:
   NtAlpcAcceptConnectPort(&Port, ...)

4. Communication:
   Client → NtAlpcSendWaitReceivePort(ClientPort, ...)
   Server → NtAlpcSendWaitReceivePort(ServerPort, ...)
```

### 8.7.3 Message Types

| Type | Size | Use |
|------|------|-----|
| Short message | ≤ ~256 bytes | Inline in port message |
| Section (shared memory) | Any size | Large data transfer |
| Handle passing | n/a | Pass kernel handles between processes |

### 8.7.4 Performance Features

```
Zero-copy for large messages:
  Client creates ALPC section (shared memory)
  Client maps view, writes data
  Server maps same section → direct access
  → No data copy between processes

Completion list:
  Server can receive notifications via completion list
  → Similar to I/O completion ports
  → Efficient for high-volume servers
```

---

## 8.8 Windows Notification Facility (WNF)

### 8.8.1 WNF Overview

**[UPDATE 2026]** WNF là publish-subscribe system cho state notifications:

```
Publisher ──→ Update WNF State Name ──→ Subscribers notified
                                        ├── Subscriber A
                                        ├── Subscriber B
                                        └── Subscriber C

Ví dụ:
  Network status changed → WNF notification
  Power state changed → WNF notification
  Theme changed → WNF notification
  Shell ready → WNF notification
```

### 8.8.2 WNF State Names

```
WNF State Name = 64-bit value encoding:
  Bits 0-3:   Version
  Bits 4-7:   Lifetime (Well-Known, Permanent, Volatile, Temporary)
  Bits 8-11:  Data Scope (System, Session, User, Process, Machine)
  Bits 12-63: Unique identifier

Lifetime types:
  Well-Known:  Defined at compile time, always available
  Permanent:   Persisted in registry across reboots
  Volatile:    Exists until system shuts down
  Temporary:   Exists until creator deletes
```

### 8.8.3 WNF Usage

```
Kernel WNF subscribers:
  - PoFx (Power Framework)
  - Memory Manager (memory pressure)
  - Shell (desktop ready, theme changes)
  - Network (connectivity changes)
  - Storage (disk arrival/removal)

User-mode WNF:
  RtlSubscribeWnfStateChangeNotification()
  RtlPublishWnfStateData()
  RtlQueryWnfStateData()
```

---

## 8.9 User-Mode Debugging

### 8.9.1 Debug Architecture

```
Debugger Process                    Debuggee Process
┌──────────────┐                   ┌──────────────┐
│ WinDbg /     │                   │ Application  │
│ Visual Studio│                   │              │
│              │                   │ Exception    │
│              │                   │ occurs       │
│              │                   └──────┬───────┘
│              │                          │
│              │                   KiUserExceptionDispatcher
│              │                          │
│              │     ┌────────────────────┤
│              │     │ Kernel Debug Port  │
│              │     │ (NtWaitForDebugEvent)
│              │←────┤                    │
│ Receives     │     │ DEBUG_EVENT:       │
│ debug event  │     │ - EXCEPTION        │
│              │     │ - CREATE_THREAD    │
│              │     │ - CREATE_PROCESS   │
│              │     │ - EXIT_PROCESS     │
│              │     │ - LOAD_DLL         │
│              │     │ - OUTPUT_STRING    │
│              │     └────────────────────┘
│              │
│ ContinueDebugEvent()
│              │────→ Resume debuggee
└──────────────┘
```

### 8.9.2 Breakpoint Implementation

```
Software breakpoint:
  Original: mov eax, [rcx]     ; 8B 01
  Patched:  int 3              ; CC 01
  
  When hit: #BP exception → debugger notified
  Debugger: restore original byte, single-step, re-patch

Hardware breakpoint (DR0-DR3):
  DR0-DR3: breakpoint addresses (up to 4)
  DR7: control register (enable, type, length)
  
  Types: Execute, Write, I/O, Read/Write
  No code patching required
  Limited to 4 simultaneous breakpoints
```

---

## 8.10 Packaged Applications (UWP / MSIX)

### 8.10.1 UWP Application Model

**[UPDATE 2026]** 

```
UWP App Lifecycle:
  Not Running → Activated → Running → Suspended → Terminated
                    ↑                      │
                    └──────────────────────┘ (Resumed)

Suspension:
  - App moved to background (5 seconds to save state)
  - Threads suspended (deep freeze)
  - Memory can be reclaimed
  - No background CPU usage (unless background task registered)

AppContainer:
  - Each UWP app runs in AppContainer sandbox
  - Package SID unique per app
  - Capabilities declared in manifest
  - File access limited to app's local storage + declared libraries
```

### 8.10.2 MSIX / Centennial (Desktop Bridge)

```
Win32 app packaged as MSIX:
├── Runs in lightweight AppContainer
├── File system virtualization (copy-on-write overlay)
├── Registry virtualization
├── Clean uninstall (no leftover files/registry)
├── Auto-update via Microsoft Store
└── Can declare capabilities for additional access
```

### 8.10.3 State Repository

```
State Repository:
├── Central database for packaged app state
├── Stores: installation info, registration, permissions
├── File: %ProgramData%\Microsoft\Windows\AppRepository\StateRepository-*.srd
├── SQLite database
└── Queries via StateRepository COM API
```

---

## 8.11 Experiments

### Experiment 8.1: System Call Table

```
kd> dps nt!KeServiceDescriptorTable L4
kd> dd nt!KiServiceTable L20         ; First 20 syscall entries
kd> u nt!NtCreateFile                ; Disassemble syscall handler
```

### Experiment 8.2: Object Namespace

```
;; WinObj (Sysinternals) — GUI browser
;; WinDbg:
kd> !object \
kd> !object \Device
kd> !object \BaseNamedObjects
kd> !object \KnownDlls
kd> !handle 0 3 <process>            ; All handles with types
```

### Experiment 8.3: ALPC Ports

```
kd> !alpc /lpc                       ; List ALPC ports
kd> !alpc /port <port_addr>          ; Port details
kd> !alpc /msg <msg_addr>            ; Message details

Process Explorer: process → Properties → Handles → Filter: ALPC Port
```

### Experiment 8.4: IDT và Interrupt Handling

```
kd> !idt                             ; Full IDT dump

;; Key IDT entries:
;;   Vector 0x00: #DE — Divide Error
;;   Vector 0x01: #DB — Debug (hardware breakpoint, single step)
;;   Vector 0x02: NMI — Non-Maskable Interrupt (hardware failure)
;;   Vector 0x03: #BP — Breakpoint (INT 3, software breakpoint)
;;   Vector 0x06: #UD — Invalid Opcode
;;   Vector 0x08: #DF — Double Fault (IST entry, own stack)
;;   Vector 0x0E: #PF — Page Fault
;;   Vector 0x12: #MC — Machine Check (IST entry)
;;   Vector 0x2E: System call (legacy x86 INT 2E path)
;;   Vectors 0x30-0xFF: External hardware interrupts (APIC)

kd> !idt 0x0E                       ; Page fault handler
kd> dt nt!_KIDTENTRY64 <addr>
    +0x000 OffsetLow        : Uint2B     ; Handler address bits 0-15
    +0x002 Selector         : Uint2B     ; Code segment selector
    +0x004 IstIndex         : Pos 0, 3   ; IST stack (0=none, 1-7=IST)
    +0x004 Type             : Pos 8, 5   ; Gate type (0xE=interrupt, 0xF=trap)
    +0x004 Dpl              : Pos 13, 2  ; DPL (3=callable from user)
    +0x004 Present          : Pos 15, 1  ; Present bit
    +0x006 OffsetMiddle     : Uint2B     ; Handler address bits 16-31
    +0x008 OffsetHigh       : Uint4B     ; Handler address bits 32-63

;; IST (Interrupt Stack Table):
;;   IST 1: NMI — cannot be interrupted, needs own stack
;;   IST 2: #DF (Double Fault) — needs own stack because main stack may be bad
;;   IST 3: #MC (Machine Check) — hardware error, needs own stack
;;   IST 4: #DB (Debug) — debug stack
;;
;; Each IST entry points to a pre-allocated stack in TSS
```

### Experiment 8.5: Spinlock Contention Analysis

```
;; Find lock contention issues:
kd> !locks                           ; Display all kernel locks
kd> !qlocks                          ; Queued spinlock statistics

;; Per-CPU spinlock wait times (ETW):
;; xperf -on SPINLOCK → records every spinlock acquire/release
;; Fields: AcquireCount, ContentionCount, SpinCount

;; Common high-contention locks:
;;   PFN lock (MmPfnLock) — page frame database
;;   Dispatcher lock (KiDispatcherLock) — scheduler
;;   Cancel spinlock (IopCancelSpinLock) — I/O cancellation

;; Push lock analysis:
kd> dt nt!_EX_PUSH_LOCK <addr>
    +0x000 Locked           : Pos 0, 1
    +0x000 Waiting          : Pos 1, 1
    +0x000 Waking           : Pos 2, 1
    +0x000 MultipleShared   : Pos 3, 1
    +0x000 Shared           : Pos 4, 60  ; Shared count (readers)
    +0x000 Value            : Uint8B
```

### Experiment 8.6: WoW64 Deep Inspection

```
;; Inspect WoW64 process:
kd> !process 0 0 notepad32.exe
kd> dt nt!_EPROCESS <addr> WoW64Process
    +0x... WoW64Process : Ptr64 _EWOW64PROCESS
    ;; Non-NULL = WoW64 process

;; WoW64 address space:
;;   0x00000000 - 0x7FFE0000 : 32-bit user space (2GB or 4GB with LAA)
;;   0x7FFE0000 - 0x7FFFFFFF : SharedUserData (32-bit)
;;   Above 4GB             : 64-bit ntdll, wow64*.dll, kernel space

;; WoW64 DLLs loaded in 64-bit address range:
;;   wow64.dll     — WoW64 core
;;   wow64cpu.dll  — x86 CPU emulation (mode switching)
;;   wow64win.dll  — Win32k syscall translation
;;   wow64base.dll — Base support
;;   ntdll.dll (64-bit) — 64-bit Native API
;;   ntdll.dll (32-bit, at low addr) — 32-bit Native API stubs

;; Syscall flow for WoW64 process:
;;   32-bit code calls NtCreateFile (32-bit ntdll)
;;   → Heaven's Gate: far jump to 64-bit code segment
;;   → wow64cpu!CpuSimulate switches CS to 64-bit
;;   → wow64.dll converts 32-bit params → 64-bit params
;;   → 64-bit ntdll!NtCreateFile → syscall → kernel
;;   → Kernel always sees 64-bit syscall
;;   → Result converted back → 32-bit caller

;; ARM64 (Prism/x86-on-ARM):
;; [UPDATE 2026] Windows 11 on ARM:
;;   xtajit64.dll — x64 JIT emulator
;;   xtajit.dll   — x86 JIT emulator
;;   JIT compilation: x86/x64 → ARM64 at runtime
;;   Cache: compiled code cached for reuse
;;   Performance: ~80% native for most workloads
```

### Experiment 8.7: Handle Table Internals

```
;; 3-level handle table structure:
;;
;; Level 0 → Level 1 → Level 2 → HANDLE_TABLE_ENTRY
;;
;; Handle value encoding (x64):
;;   Bits 0-1:  Table index (always 0 for normal handles)
;;   Bits 2-9:  Level 2 index (256 entries)  
;;   Bits 10-17: Level 1 index (256 entries)
;;   Bits 18-25: Level 0 index (256 entries)
;;   Max handles per process: 16,777,216 (2^24)
;;
;; Handle values: 0x04, 0x08, 0x0C, ... (multiples of 4)
;; Pseudo-handles: -1 (current process), -2 (current thread)

kd> !handle 0 f <process>           ; All handles with types
kd> dt nt!_HANDLE_TABLE_ENTRY <addr>
    +0x000 VolatileLowValue : Int8B
    +0x000 LowValue         : Int8B
    +0x000 InfoTable        : Ptr64
    +0x008 HighValue        : Int8B
    +0x008 NextFreeHandleEntry : Ptr64
    +0x008 LeafHandleValue  : _EXHANDLE
    +0x010 GrantedAccessBits : Uint4B  ; Access mask granted to handle
    ;; Object pointer XOR'd with handle table cookie

;; Decode object pointer from handle entry:
kd> ? (<entry_value> >> 0x10) & 0xFFFFFFFFFFFF0  ; Mask + shift
;; Result: actual _OBJECT_HEADER address

;; Handle auditing:
;; Handle tracing: set HKLM\SYSTEM\CCS\Control\Session Manager\Kernel\HandleTracing = 1
;; → Tracks who opened/closed each handle (debug handle leaks)
```

### Experiment 8.8: ALPC Message Tracing

```
;; ALPC (Advanced Local Procedure Call) — primary Windows IPC:

kd> !alpc /lpc                       ; List all ALPC connection ports
kd> !alpc /port <addr>               ; Port details
    Port: <addr>
    CommunicationInfo: <addr>
    ConnectionPort: <addr>
    OwnerProcess: <EPROCESS>
    Type: Connection(1) / Server(2) / Client(3)
    
kd> !alpc /msg <addr>                ; Message details
    MessageId: <id>
    Type: Request(1) / Reply(2) / Datagram(3)
    DataLength: <bytes>
    TotalLength: <bytes>

;; ALPC is used by:
;;   - RPC runtime (ncalrpc transport)
;;   - csrss.exe communication
;;   - LSA/SRM communication
;;   - Power broker
;;   - WNF notifications
;;   - COM activation
;;   - UWP broker services

;; Security relevance:
;;   - ALPC ports have security descriptors
;;   - Connection requires passing access check
;;   - Server can impersonate client (ImpersonateClientOfPort)
;;   - ALPC message contains: SID, token info of sender
;;   - Malicious ALPC server → impersonate connecting clients
```

### Experiment 8.9: WNF (Windows Notification Facility)

```
;; WNF state names:
kd> !wnf                            ; List registered WNF state names
kd> !wnf <state_name>               ; Details of specific state

;; WNF State Name format (ULONG64):
;;   Bits 0-3:   Version
;;   Bits 4-7:   Lifetime (Well-Known=0, Permanent=1, 
;;                         Volatile=2, Temporary=3)
;;   Bits 8-11:  Data Scope (System=0, Session=1, User=2, Process=3)
;;   Bits 12-63: Unique number

;; Well-Known WNF names (used by OS):
;;   WNF_SHEL_DESKTOP_APPLICATION_STARTED
;;   WNF_SHEL_LOGON_COMPLETE
;;   WNF_CI_POLICY_CHANGED
;;   WNF_DX_MODE_CHANGE_NOTIFICATION

;; WNF for security monitoring:
;;   Attacker can subscribe to WNF notifications
;;   to detect security state changes
;;   (e.g., Defender status changes, policy updates)
;;   → Potentially useful for evasion timing
```

---

## 8.12 Tóm Tắt

| Khái niệm | Điểm chính |
|------------|------------|
| Segmentation | Flat model, FS/GS cho per-thread/CPU data |
| Side-channels | Spectre/Meltdown, KVA Shadow, Retpoline |
| IDT | 256 entries, traps + interrupts + exceptions |
| System calls | syscall instruction, SSDT lookup, ~470 entries |
| WoW64 | 32-on-64 emulation, file/registry redirection |
| ARM emulation | x86/x64-on-ARM64 via JIT (Prism) |
| Object Manager | Objects, headers, namespace, handle table |
| Synchronization | Spinlocks, push locks, dispatcher objects, SRW |
| ALPC | Primary kernel IPC, zero-copy sections |
| WNF | Publish-subscribe notifications |
| Debugging | Debug port, software/hardware breakpoints |
| UWP/MSIX | AppContainer sandbox, lifecycle management |

> **Tiếp theo: [Chapter 9 — Công Nghệ Ảo Hóa](Chapter_09_Virtualization.md)**
> Hyper-V, VTL, SLAT, nested virtualization, containers.
