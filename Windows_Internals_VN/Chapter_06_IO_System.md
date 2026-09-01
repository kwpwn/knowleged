# Chapter 6: Hệ Thống I/O (I/O System)

> Chương này mô tả kiến trúc I/O của Windows: I/O Manager, IRP (I/O Request Packet),
> driver stacks, I/O completion ports, PnP Manager, và Power Manager.

---

## 6.1 Tổng Quan I/O System

### 6.1.1 Các Component

```
┌──────────────────────────────────────────────────────────┐
│                    USER MODE                              │
│                                                          │
│  Application → CreateFile/ReadFile/WriteFile/DeviceIoCtl │
│       ↓                                                  │
│  kernel32.dll / kernelbase.dll                           │
│       ↓                                                  │
│  ntdll.dll → NtCreateFile / NtReadFile / NtWriteFile     │
│       ↓ syscall                                          │
╠══════════════════════════════════════════════════════════╣
│                    KERNEL MODE                            │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │              I/O Manager                            │  │
│  │  - Tạo/quản lý IRPs                                │  │
│  │  - Route IRPs xuống driver stack                    │  │
│  │  - Manage I/O completion                            │  │
│  │  - Handle buffers (buffered/direct/neither)         │  │
│  └───────────────────┬────────────────────────────────┘  │
│                      ↓                                    │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────┐    │
│  │  Filter     │ │  Function   │ │    Bus           │    │
│  │  Driver     │ │  Driver     │ │    Driver        │    │
│  │  (optional) │→│  (main)     │→│  (enumeration)   │    │
│  └─────────────┘ └─────────────┘ └─────────────────┘    │
│                      ↓                                    │
│  ┌────────────────────────────────────────────────────┐  │
│  │              HAL (Hardware Abstraction)              │  │
│  └────────────────────────────────────────────────────┘  │
│                      ↓                                    │
│                  HARDWARE                                 │
└──────────────────────────────────────────────────────────┘
```

### 6.1.2 I/O Manager Responsibilities

| Chức năng | Mô tả |
|-----------|--------|
| IRP management | Allocate, route, complete IRPs |
| Driver loading | Load/unload driver images |
| Device namespace | `\Device\HarddiskVolume1`, `\Device\Tcp`, ... |
| Buffer management | Buffered I/O, Direct I/O, Neither |
| I/O completion | Completion ports, APC-based completion |
| Error handling | Retry logic, error logging |
| Security | Access checks on device opens |

---

## 6.2 Driver Model

### 6.2.1 Driver Object

Mỗi loaded driver được đại diện bởi `DRIVER_OBJECT`:

```
_DRIVER_OBJECT
├── Type / Size                      ← Object type identifier
├── DeviceObject                     ← Linked list device objects
├── Flags                            ← Driver flags
├── DriverStart                      ← Image base address
├── DriverSize                       ← Image size
├── DriverSection                    ← LDR_DATA_TABLE_ENTRY
├── DriverExtension                  ← Extension data
│   └── AddDevice                    ← PnP AddDevice callback
├── DriverName                       ← e.g., \Driver\Ntfs
├── HardwareDatabase                 ← Registry hardware path
├── FastIoDispatch                   ← Fast I/O table (shortcut path)
├── DriverInit                       ← DriverEntry function
├── DriverStartIo                    ← StartIo serialization
├── DriverUnload                     ← Unload function
└── MajorFunction[28]               ← IRP dispatch table
    ├── [IRP_MJ_CREATE]              ← CreateFile
    ├── [IRP_MJ_CLOSE]               ← CloseHandle
    ├── [IRP_MJ_READ]                ← ReadFile
    ├── [IRP_MJ_WRITE]               ← WriteFile
    ├── [IRP_MJ_DEVICE_CONTROL]      ← DeviceIoControl
    ├── [IRP_MJ_INTERNAL_DEVICE_CONTROL] ← Internal IOCTL
    ├── [IRP_MJ_CLEANUP]             ← Last handle close
    ├── [IRP_MJ_QUERY_INFORMATION]   ← GetFileInformationByHandle
    ├── [IRP_MJ_SET_INFORMATION]     ← SetFileInformationByHandle
    ├── [IRP_MJ_PNP]                 ← Plug and Play
    ├── [IRP_MJ_POWER]               ← Power management
    └── [IRP_MJ_SYSTEM_CONTROL]      ← WMI
```

### 6.2.2 Device Object

Mỗi driver tạo 1+ device objects:

```
_DEVICE_OBJECT
├── Type / Size
├── ReferenceCount                   ← Open handles
├── DriverObject                     ← → DRIVER_OBJECT
├── NextDevice                       ← Next device in driver's list
├── AttachedDevice                   ← Device attached on top
├── CurrentIrp                       ← Current IRP (StartIo)
├── Flags
│   ├── DO_BUFFERED_IO               ← Use buffered I/O
│   ├── DO_DIRECT_IO                 ← Use direct I/O (MDL)
│   └── DO_DEVICE_INITIALIZING       ← Still initializing
├── DeviceType                       ← FILE_DEVICE_DISK, FILE_DEVICE_NETWORK, ...
├── StackSize                        ← I/O stack locations needed
├── DeviceExtension                  ← Driver-specific data
├── SecurityDescriptor               ← Device security
└── DeviceQueue                      ← Serialized I/O queue
```

### 6.2.3 Device Stack

I/O requests flow through a stack of device objects:

```
     I/O Manager
         │ IRP
         ▼
┌─────────────────┐
│ Upper Filter    │  Filter driver (e.g., antivirus file filter)
│ Device Object   │
└────────┬────────┘
         │ IoCallDriver
         ▼
┌─────────────────┐
│ Function        │  Main driver (e.g., NTFS)
│ Device Object   │
└────────┬────────┘
         │ IoCallDriver
         ▼
┌─────────────────┐
│ Lower Filter    │  Filter driver (e.g., encryption)
│ Device Object   │
└────────┬────────┘
         │ IoCallDriver
         ▼
┌─────────────────┐
│ Bus/Port        │  Bus driver (e.g., storport + miniport)
│ Device Object   │
└────────┬────────┘
         │
     Hardware
```

---

## 6.3 IRP (I/O Request Packet)

### 6.3.1 IRP Structure

```
_IRP
├── Type / Size
├── MdlAddress                       ← MDL for direct I/O buffer
├── Flags                            ← IRP_PAGING_IO, IRP_NOCACHE, ...
├── AssociatedIrp
│   └── SystemBuffer                 ← Kernel buffer for buffered I/O
├── ThreadListEntry                  ← Link in thread's IRP list
├── IoStatus                         ← Final status + information
│   ├── Status                       ← NTSTATUS result
│   └── Information                  ← Bytes transferred
├── RequestorMode                    ← UserMode or KernelMode
├── PendingReturned                  ← IoMarkIrpPending called
├── Cancel / CancelRoutine           ← Cancellation support
├── UserBuffer                       ← Original user buffer (neither I/O)
├── Overlay
│   └── AsynchronousParameters
│       └── UserApcRoutine           ← APC for async completion
├── Tail
│   └── Overlay
│       ├── Thread                   ← Requesting thread
│       ├── OriginalFileObject       ← Target FILE_OBJECT
│       └── AuxiliaryBuffer
│
└── IO_STACK_LOCATION[]              ← Per-driver parameters
    ├── [0] Top driver
    ├── [1] Middle driver
    └── [2] Bottom driver
```

### 6.3.2 I/O Stack Location

Mỗi driver trong stack có I/O Stack Location riêng:

```
_IO_STACK_LOCATION
├── MajorFunction                    ← IRP_MJ_READ, IRP_MJ_WRITE, ...
├── MinorFunction                    ← Sub-operation
├── Flags
├── Control                          ← SL_INVOKE_ON_SUCCESS/ERROR/CANCEL
├── Parameters                       ← Union based on MajorFunction:
│   ├── Create:
│   │   ├── SecurityContext
│   │   ├── Options (CreateOptions)
│   │   ├── FileAttributes
│   │   └── ShareAccess
│   ├── Read:
│   │   ├── Length
│   │   ├── Key
│   │   └── ByteOffset
│   ├── Write:
│   │   ├── Length
│   │   ├── Key
│   │   └── ByteOffset
│   ├── DeviceIoControl:
│   │   ├── OutputBufferLength
│   │   ├── InputBufferLength
│   │   ├── IoControlCode
│   │   └── Type3InputBuffer
│   └── ...
├── DeviceObject                     ← Target device for this level
├── FileObject                       ← Target file object
├── CompletionRoutine                ← IoSetCompletionRoutine callback
└── Context                          ← CompletionRoutine context
```

### 6.3.3 IRP Flow — Read Example

```
1. Application: ReadFile(hFile, buffer, 4096, ...)

2. NtReadFile() [kernel]:
   ├── ObReferenceObjectByHandle(hFile) → FILE_OBJECT
   ├── Get DEVICE_OBJECT from FILE_OBJECT
   ├── IoAllocateIrp(StackSize)
   ├── Fill I/O Stack Location:
   │   ├── MajorFunction = IRP_MJ_READ
   │   ├── Parameters.Read.Length = 4096
   │   └── Parameters.Read.ByteOffset = current position
   ├── Buffer handling:
   │   ├── Buffered I/O → allocate SystemBuffer, copy later
   │   ├── Direct I/O → IoAllocateMdl, MmProbeAndLockPages
   │   └── Neither → pass UserBuffer pointer
   └── IoCallDriver(DeviceObject, Irp)

3. Filter Driver (optional):
   ├── Inspect/modify IRP
   ├── IoSetCompletionRoutine() ← set callback for when done
   ├── IoCopyCurrentIrpStackLocationToNext()
   └── IoCallDriver(NextDevice, Irp) ← pass down

4. Function Driver (e.g., NTFS):
   ├── Process read request
   ├── May create sub-IRPs for lower drivers
   ├── IoCallDriver(LowerDevice, Irp)
   └── ... or pend: IoMarkIrpPending, return STATUS_PENDING

5. Port/Miniport Driver:
   ├── Program DMA transfer
   ├── Start hardware operation
   └── Return STATUS_PENDING

6. Hardware completes → Interrupt → ISR → DPC:
   ├── DPC routine:
   │   ├── Irp->IoStatus.Status = STATUS_SUCCESS
   │   ├── Irp->IoStatus.Information = 4096 (bytes read)
   │   └── IoCompleteRequest(Irp, IO_DISK_INCREMENT)

7. Completion unwinds stack (bottom → top):
   ├── Each driver's CompletionRoutine called
   ├── Filter driver logs/inspects result
   └── I/O Manager:
       ├── Copy SystemBuffer → UserBuffer (buffered I/O)
       ├── Unlock MDL pages (direct I/O)
       ├── Signal event or queue APC
       └── Application ReadFile() returns with data
```

---

## 6.4 Buffer Methods

### 6.4.1 Buffered I/O

```
User Buffer ──copy──→ System Buffer (nonpaged pool) ──→ Driver
                            ↓
                      Driver works on system buffer
                            ↓
Driver completes ──→ System Buffer ──copy──→ User Buffer

Pros: Safe — driver works with kernel buffer
Cons: Double-copy overhead
Use: Small transfers (registry, device control)
Flag: DO_BUFFERED_IO
```

### 6.4.2 Direct I/O

```
User Buffer ──→ MDL (Memory Descriptor List) ──→ Driver
                     │
                     ├── Pages locked in memory (won't page out)
                     ├── Driver gets physical addresses for DMA
                     └── No copy — hardware reads/writes directly

Pros: Zero-copy, best for large transfers
Cons: Pages locked in RAM
Use: Disk I/O, network, large data
Flag: DO_DIRECT_IO
```

MDL structure:
```
_MDL
├── Next                  ← Linked list
├── Size                  ← MDL size
├── MdlFlags              ← MDL_PAGES_LOCKED, MDL_MAPPED_TO_SYSTEM_VA, ...
├── Process               ← Owning process
├── MappedSystemVa        ← Kernel virtual address (if mapped)
├── StartVa               ← Start of virtual range
├── ByteCount             ← Total bytes
├── ByteOffset             ← Offset within first page
└── PFN array[]           ← Physical Page Frame Numbers
```

### 6.4.3 Neither I/O

```
User Buffer pointer ──passed directly──→ Driver

Driver MUST:
  - Probe user buffer (ProbeForRead/ProbeForWrite)
  - Access inside try/except
  - Be in context of requesting thread

Pros: Fastest (no copy, no MDL)
Cons: Dangerous — buffer can be paged out, freed, or corrupted
Use: File system drivers (they handle this carefully)
```

### 6.4.4 Buffer Method Security Implications

```
Buffer method vulnerabilities (common CVE sources):

METHOD_BUFFERED (safest):
  I/O Manager handles copy → hard to get wrong
  But: InputBuffer and OutputBuffer SHARE SystemBuffer
  → Write past OutputBufferLength → overwrite InputBuffer data
  → Double-fetch: TOCTOU if driver reads SystemBuffer multiple times

METHOD_NEITHER (most dangerous):
  Driver receives raw user-mode pointers
  Common bugs:
  1. Missing ProbeForRead/ProbeForWrite → BSOD on invalid ptr
  2. Missing try/except → exception in kernel = BSOD
  3. Not checking alignment → alignment fault
  4. TOCTOU: user changes buffer between probe and use
     → Driver probes buffer OK, user remaps page, driver reads bad data
     → Fix: capture (copy) user data first, then validate copy
  
  Exploitation:
  → Arbitrary kernel read: driver copies kernel data to user buffer
  → Arbitrary kernel write: driver writes user-controlled data to kernel addr
  → Both: full kernel compromise → SYSTEM privileges
```

### 6.4.5 Fast I/O

```
Fast I/O bypasses IRP creation for cached file I/O:

Normal path:                    Fast I/O path:
  NtReadFile()                    NtReadFile()
    → IoAllocateIrp              → Check if FastIoRead registered
    → IoCallDriver               → Call FastIoRead directly
    → Driver dispatch            → Cache Manager CcCopyRead
    → Completion                 → Return (no IRP ever created)
    → IoFreeIrp
    
Fast I/O:
  - Shortcut for cached I/O (cache hit only)
  - No IRP allocation/deallocation overhead
  - If Fast I/O handler returns FALSE → fall back to IRP path
  - File systems always register Fast I/O
  - Minifilters can intercept Fast I/O too

FAST_IO_DISPATCH structure (in DRIVER_OBJECT):
  ├── FastIoCheckIfPossible
  ├── FastIoRead                 ← Cached read shortcut
  ├── FastIoWrite                ← Cached write shortcut
  ├── FastIoQueryBasicInfo       ← GetFileAttributes shortcut
  ├── FastIoQueryStandardInfo
  ├── FastIoLock / FastIoUnlockSingle / FastIoUnlockAll
  ├── FastIoDeviceControl        ← IOCTL shortcut
  ├── AcquireFileForNtCreateSection
  ├── ReleaseFileForNtCreateSection
  ├── FastIoQueryNetworkOpenInfo
  ├── MdlRead / MdlReadComplete  ← MDL-based read
  ├── MdlWrite / MdlWriteComplete
  └── PrepareMdlWrite
```

---

## 6.5 I/O Completion Mechanisms

### 6.5.1 Synchronous I/O

```c
// Default — thread blocks until I/O completes
DWORD bytesRead;
ReadFile(hFile, buffer, 4096, &bytesRead, NULL);
// Thread blocked here until data arrives
```

### 6.5.2 Asynchronous I/O (Overlapped)

```c
// File opened with FILE_FLAG_OVERLAPPED
OVERLAPPED ov = {0};
ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
ReadFile(hFile, buffer, 4096, NULL, &ov);
// Returns immediately (STATUS_PENDING)

// Option 1: Wait on event
WaitForSingleObject(ov.hEvent, INFINITE);

// Option 2: GetOverlappedResult
DWORD bytesRead;
GetOverlappedResult(hFile, &ov, &bytesRead, TRUE);
```

### 6.5.3 I/O Completion Ports (IOCP)

Scalable async I/O mechanism cho high-performance servers:

```
                    ┌───────────────────────────────┐
                    │      I/O Completion Port       │
                    │                               │
Async I/O results ──→│ ┌───┐ ┌───┐ ┌───┐ ┌───┐     │
                    │ │ C1│ │ C2│ │ C3│ │...│     │
                    │ └───┘ └───┘ └───┘ └───┘     │ ← FIFO Queue
                    │                               │
                    └─┬──────┬──────┬──────┬────────┘
                      │      │      │      │
                      ▼      ▼      ▼      ▼
                    Worker Worker Worker Worker
                    Thread Thread Thread Thread
                    (waiting via GetQueuedCompletionStatus)
```

```c
// Create completion port
HANDLE hPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE,
                                       NULL, 0, NumThreads);

// Associate file handle
CreateIoCompletionPort(hFile, hPort, (ULONG_PTR)fileContext, 0);

// Worker thread loop
void WorkerThread(HANDLE hPort) {
    DWORD bytes;
    ULONG_PTR key;
    OVERLAPPED* ov;
    
    while (GetQueuedCompletionStatus(hPort, &bytes, &key, &ov, INFINITE)) {
        // Process completed I/O
        // key = per-file context
        // ov = overlapped structure
        // bytes = bytes transferred
    }
}
```

**Concurrency control:**
- IOCP limits concurrent threads = number of CPUs
- If worker blocks (e.g., on lock), IOCP releases another thread
- Prevents thread explosion while maximizing CPU utilization

### 6.5.4 Alertable I/O (APC-based)

```c
// Queue I/O with APC callback
ReadFileEx(hFile, buffer, 4096, &ov, CompletionRoutine);

// Thread must enter alertable wait
SleepEx(INFINITE, TRUE);  // TRUE = alertable

// Callback fired when I/O completes
VOID CALLBACK CompletionRoutine(DWORD error, DWORD bytes, OVERLAPPED* ov) {
    // Process result
}
```

---

## 6.6 I/O Priority

**[UPDATE 2026]** I/O requests have priority:

| Priority | Value | Use Case |
|----------|-------|----------|
| Critical | 4 | Memory Manager paging I/O |
| High | 3 | Rarely used |
| Normal | 2 | Default for all applications |
| Low | 1 | Background tasks (indexing, backup) |
| Very Low | 0 | Idle priority I/O |

```c
// Set thread I/O priority
SetThreadPriority(hThread, THREAD_MODE_BACKGROUND_BEGIN);
// All I/O from this thread now Low priority

// Or per-file:
FILE_IO_PRIORITY_HINT_INFO info;
info.PriorityHint = IoPriorityHintLow;
SetFileInformationByHandle(hFile, FileIoPriorityHintInfo,
                           &info, sizeof(info));
```

---

## 6.7 I/O Cancellation

```c
// Cancel all I/O for a file handle on current thread
CancelIo(hFile);

// Cancel all I/O for a file handle on any thread
CancelIoEx(hFile, NULL);

// Cancel specific I/O
CancelIoEx(hFile, &specificOverlapped);
```

Kernel side:
```
IoCancelIrp(Irp):
1. Set Irp->Cancel = TRUE
2. Call Irp->CancelRoutine (if set by driver)
3. Driver MUST complete the IRP from cancel routine
```

---

## 6.8 Interrupt Request Levels (IRQL)

### 6.8.1 IRQL Hierarchy

```
x64 IRQL levels (0-15):

15  HIGH_LEVEL          ← Highest, disables all interrupts
14  IPI_LEVEL           ← Inter-processor interrupt (POWER_LEVEL = 14)
13  CLOCK_LEVEL         ← Clock interrupt
 ⋮
3-12  DIRQL              ← Device interrupts (hardware IRQLs)
 ⋮
 2  DISPATCH_LEVEL      ← Thread scheduler, DPCs
 1  APC_LEVEL           ← Asynchronous Procedure Calls
 0  PASSIVE_LEVEL       ← Normal thread execution

Lưu ý: x86 dùng 32 IRQL levels (0-31), x64 giảm xuống 16 levels (0-15).
```

**Rules:**
- CPU tại IRQL X chỉ bị interrupt bởi IRQL > X
- DISPATCH_LEVEL và cao hơn: KHÔNG THỂ page fault → chỉ dùng nonpaged memory
- DISPATCH_LEVEL: KHÔNG THỂ wait on dispatcher objects (events, mutexes)
- PASSIVE_LEVEL: mọi thứ allowed

```
Application code          → PASSIVE_LEVEL (0)
Most kernel code          → PASSIVE_LEVEL (0) hoặc APC_LEVEL (1)
DPC routine               → DISPATCH_LEVEL (2)
ISR (interrupt handler)   → DIRQL (device-specific, 3-12 on x64)
```

### 6.8.2 DPC (Deferred Procedure Call)

```
Hardware Interrupt Flow:

1. Hardware asserts interrupt
2. CPU saves state, enters ISR at DIRQL
3. ISR does MINIMUM work:
   ├── Acknowledge interrupt
   ├── Save device status
   ├── Queue DPC
   └── Return (IRQL drops)
4. DPC runs at DISPATCH_LEVEL (2):
   ├── Process data
   ├── Complete IRPs (IoCompleteRequest)
   └── More complex processing
5. After DPC, IRQL drops to PASSIVE/APC
   └── Normal thread execution resumes

Why DPC?
  ISR runs at high IRQL → blocks other interrupts
  Keep ISR short → defer work to DPC
  DPC at DISPATCH_LEVEL → allows higher device interrupts
```

---

## 6.9 Plug and Play (PnP) Manager

### 6.9.1 Device Enumeration

```
Boot / Device Arrival:

1. Bus driver detects device (USB insertion, PCI scan, ...)
2. Bus driver reports child device to PnP Manager:
   └── IoReportTargetDeviceChange / IoInvalidateDeviceRelations

3. PnP Manager:
   ├── Query device ID (Hardware ID, Compatible ID)
   ├── Search driver store for matching driver (.inf)
   ├── Load driver
   ├── Call driver AddDevice()
   │   └── Driver creates Function Device Object (FDO)
   │       └── Attaches to device stack
   ├── Send IRP_MN_START_DEVICE
   │   └── Driver initializes hardware
   └── Device ready for I/O
```

### 6.9.2 Device Tree

```
Root (ACPI)
├── PCI Bus
│   ├── Display Adapter
│   │   └── Monitor
│   ├── Network Adapter
│   ├── Storage Controller
│   │   ├── Disk 0
│   │   │   ├── Volume 1 (C:)
│   │   │   └── Volume 2 (D:)
│   │   └── Disk 1
│   └── USB Host Controller
│       ├── USB Hub
│       │   ├── USB Keyboard
│       │   ├── USB Mouse
│       │   └── USB Flash Drive
│       │       └── Volume 3 (E:)
│       └── USB Hub 2
│           └── USB Camera
├── ACPI Devices
│   ├── Embedded Controller
│   ├── Battery
│   └── Thermal Zone
└── Software Devices
    ├── Volume Manager
    └── Network Protocol Drivers
```

Xem device tree:
```cmd
:: Device Manager
devmgmt.msc

:: Command line
pnputil /enum-devices
pnputil /enum-drivers

:: WinDbg
kd> !devnode 0 1         ; Dump device tree
kd> !devobj <addr>       ; Device object details
kd> !drvobj <name> 7     ; Driver object + device list
```

---

## 6.10 File System Filter Drivers (Minifilters)

### 6.10.1 Filter Manager Architecture

```
Application
    │ ReadFile()
    ▼
I/O Manager
    │ IRP_MJ_READ
    ▼
┌──────────────────────┐
│   Filter Manager      │  (fltmgr.sys)
│   (FltMgr)            │
├──────────────────────┤
│ Altitude 385xxx       │  Antivirus minifilter (pre-operation)
│ Altitude 365xxx       │  Encryption minifilter
│ Altitude 320xxx       │  Replication minifilter
│ Altitude 180xxx       │  HSM (tiered storage)
└──────────┬───────────┘
           │
           ▼
     File System (NTFS)
           │
           ▼
     Storage Driver
```

**Altitude:** mỗi minifilter có altitude number xác định vị trí trong stack.
Higher altitude = closer to application.

### 6.10.2 Minifilter Callbacks

```c
// Minifilter registration
const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,  0, PreCreate,  PostCreate },
    { IRP_MJ_READ,    0, PreRead,    PostRead },
    { IRP_MJ_WRITE,   0, PreWrite,   PostWrite },
    { IRP_MJ_CLEANUP, 0, PreCleanup, NULL },
    { IRP_MJ_OPERATION_END }
};

// Pre-operation: called BEFORE file system processes request
FLT_PREOP_CALLBACK_STATUS PreRead(PFLT_CALLBACK_DATA Data, ...) {
    // Inspect, modify, or block the I/O
    // Return:
    //   FLT_PREOP_SUCCESS_WITH_CALLBACK → continue, call PostRead
    //   FLT_PREOP_COMPLETE → I/O done (blocked/handled here)
    //   FLT_PREOP_PENDING → pend for async processing
}

// Post-operation: called AFTER file system completes request
FLT_POSTOP_CALLBACK_STATUS PostRead(PFLT_CALLBACK_DATA Data, ...) {
    // Inspect/modify results
    // E.g., decrypt data after read
}
```

---

## 6.11 Driver Verifier

Phát hiện driver bugs tại runtime:

```cmd
verifier.exe                    ; GUI
verifier /standard /driver ntfs.sys   ; Enable for specific driver
verifier /query                 ; Check status
verifier /reset                 ; Disable all
```

**Verification options:**

| Option | Phát hiện |
|--------|-----------|
| Special pool | Buffer overflows/underflows |
| Pool tracking | Memory leaks |
| Force IRQL checking | Accesses to pageable memory at elevated IRQL |
| Deadlock detection | Lock hierarchy violations |
| I/O verification | IRP/driver interface violations |
| DMA checking | DMA buffer misuse |
| Security checks | Security vulnerabilities |
| Force pending I/O | Test async I/O paths |
| Low resources simulation | Behavior under memory pressure |

---

## 6.12 Power Manager

### 6.12.1 System Power States

| State | Name | Description |
|-------|------|-------------|
| S0 | Working | Normal operation |
| S1 | Sleep (low latency) | CPU cache maintained |
| S2 | Sleep | CPU cache lost |
| S3 | Sleep (Suspend to RAM) | RAM powered, rest off |
| S4 | Hibernate | RAM saved to disk, power off |
| S5 | Soft Off | Powered off |
| G3 | Mechanical Off | Power cord unplugged |

### 6.12.2 Modern Standby

**[UPDATE 2026]** Modern Standby thay thế S3:

```
Modern Standby (S0 Low Power Idle):
├── System stays in S0 (working state)
├── Screen off, CPU enters deep C-states
├── Network maintains connection (push email, VoIP)
├── Periodic wake to:
│   ├── Check email
│   ├── Update tiles
│   ├── Sync data
│   └── Run maintenance
├── Instant wake (< 1 second)
└── Connected vs Disconnected modes:
    ├── Connected: WiFi/LTE stays on
    └── Disconnected: radio off, lower power
```

### 6.12.3 Device Power States

| State | Name | Description |
|-------|------|-------------|
| D0 | Full Power | Device operational |
| D1 | Light Sleep | Device context retained |
| D2 | Deep Sleep | Driver may need to restore context |
| D3hot | Off (bus power) | Device off, bus power on |
| D3cold | Off (no power) | Device completely off |

---

## 6.13 Experiments

### Experiment 6.1: Trace I/O Flow

```
Process Monitor:
1. Filter: Process Name is notepad.exe
2. Filter: Operation contains "Read" OR "Write"
3. Edit text in Notepad → Save
4. Observe: CreateFile → WriteFile → CloseFile
5. Stack tab: see full call stack from app through kernel
```

### Experiment 6.2: Device Stack

```
kd> !devnode 0 1                    ; Full device tree
kd> !devstack \Device\HarddiskVolume1   ; Device stack for C:
kd> !drvobj \Driver\Ntfs 7          ; NTFS driver details

Device Manager → View → Devices by Connection
```

### Experiment 6.3: Pending IRPs

```
kd> !irpfind                        ; Find all pending IRPs
kd> !irp <irp_address>              ; IRP details
kd> !irp <irp_address> 1            ; With all stack locations
```

### Experiment 6.4: IRQL

```
kd> !irql                           ; Current IRQL per CPU
kd> !idt                            ; Interrupt Descriptor Table
kd> !dpcs                           ; Pending DPCs
```

### Experiment 6.5: I/O Completion Port Analysis

```c
// IOCP là scalable async I/O mechanism, dùng cho high-perf servers

// Tạo IOCP:
HANDLE hIOCP = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 
    0 /* concurrent threads = # CPUs */);

// Associate file handle với IOCP:
CreateIoCompletionPort(hFile, hIOCP, (ULONG_PTR)pContext, 0);

// Post async I/O:
ReadFile(hFile, buffer, size, NULL, &overlapped);
// → Khi I/O complete → completion packet queued to IOCP

// Worker thread dequeue:
DWORD bytes;
ULONG_PTR key;
LPOVERLAPPED pOv;
GetQueuedCompletionStatus(hIOCP, &bytes, &key, &pOv, INFINITE);
// → Process completion
```

```
;; WinDbg — IOCP analysis:
kd> !handle 0 f <pid> IoCompletion    ; Find IOCP handles
kd> !object <iocp_object>             ; IOCP object details
kd> dt nt!_KQUEUE <addr>
    +0x000 Header           ; DISPATCHER_HEADER
    +0x018 EntryListHead    ; Completed I/O packets
    +0x028 CurrentCount     ; Currently active threads
    +0x02c MaximumCount     ; Concurrency limit
    +0x030 ThreadListHead   ; Waiting threads
```

### Experiment 6.6: IOCTL and Device Communication

```
DeviceIoControl — send control codes to drivers:

IOCTL code format (32 bits):
┌──────┬────────┬──────────┬───────┬──────┐
│ bits │ 31-16  │  15-14   │ 13-2  │ 1-0  │
├──────┼────────┼──────────┼───────┼──────┤
│ name │ Device │ Required │ Func  │ Xfer │
│      │ Type   │ Access   │ Code  │ Type │
└──────┴────────┴──────────┴───────┴──────┘

Transfer types:
  METHOD_BUFFERED     (0) — safest, kernel copies
  METHOD_IN_DIRECT    (1) — input buffered, MDL read (caller→driver data)
  METHOD_OUT_DIRECT   (2) — input buffered, MDL write (driver→caller data)
  METHOD_NEITHER      (3) — raw pointers, DANGEROUS

Security implications of IOCTLs:
  - Vulnerable IOCTL handlers = kernel code execution
  - METHOD_NEITHER + no ProbeForRead/Write = arbitrary R/W
  - Many CVEs from IOCTL input validation failures
  - IOCTLFuzzer / ioctlbf tools for testing
```

### Experiment 6.7: Minifilter Altitude Inspection

```powershell
# List all registered minifilters with altitudes:
fltmc.exe

# Output example:
# Filter Name           Num Instances  Altitude    Frame
# -----------           -------------  --------    -----
# WdFilter                   6          328010      0     ← Windows Defender
# Wof                        3          40700       0     ← Windows Overlay Filter
# FileInfo                  11          45000       0     ← File information
# storqosflt                 0          244000      0     ← Storage QoS
# bindflt                    1          409800      0     ← Bind filter (containers)
# CldFlt                     3          180451      0     ← Cloud Files filter

# Altitude ranges:
#   FSFilter Anti-Virus:     320000-329999  (WdFilter, CrowdStrike, etc.)
#   FSFilter Encryption:     140000-149999  (EFS, BitLocker)
#   FSFilter Compression:    160000-169999  (WOF)
#   FSFilter Virtualization:  180000-189999 (Cloud Files)
#   FSFilter Physical Quota: 220000-229999
#   FSFilter Copy Protection: 300000-309999
#   FSFilter Security Enhancer: 310000-319999
#   FSFilter Continuous Backup: 330000-339999
#   FSFilter Replication:    340000-349999
#   FSFilter HSM:            400000-409999

# Higher altitude = earlier in the stack (sees I/O first)
# Lower altitude = closer to file system
```

```
;; WinDbg — Minifilter analysis:
kd> !fltkd.filters               ; List all filters
kd> !fltkd.filter WdFilter       ; Details of Windows Defender filter
kd> !fltkd.instances             ; All instances
kd> !fltkd.volumes               ; Volumes with attached filters
kd> !fltkd.cbd <callback_data>   ; Callback data inspection
```

### Experiment 6.8: I/O Priority và Bandwidth

```
I/O priority levels:
┌─────────────────────────────┬────────┐
│ Level                       │ Value  │
├─────────────────────────────┼────────┤
│ Critical (paging I/O)       │   4    │
│ High                        │   3    │
│ Normal (default)            │   2    │
│ Low (background)            │   1    │
│ Very Low (idle)             │   0    │
└─────────────────────────────┴────────┘

Background I/O (Very Low priority):
  SetPriorityClass(hProcess, PROCESS_MODE_BACKGROUND_BEGIN)
  → All I/O from this process gets Very Low priority
  → Disk scheduler serves these last
  → Used by: Windows Search, Superfetch, Defender scans

;; WinDbg:
kd> !irp <addr>
    → IoStack shows IRP priority
kd> dt nt!_IRP <addr> Flags
    → IRP_PAGING_IO = paging I/O (highest priority)
```

---

## 6.14 Tóm Tắt

| Khái niệm | Điểm chính |
|------------|------------|
| I/O Manager | Central dispatcher, creates/routes IRPs |
| Driver Object | Per-driver, MajorFunction dispatch table |
| Device Object | Per-device, forms device stacks |
| IRP | I/O request packet with per-driver stack locations |
| Buffered I/O | Kernel copy — safe, overhead |
| Direct I/O | MDL + locked pages — zero-copy, DMA |
| IOCP | Scalable async I/O, limits concurrent threads |
| IRQL | Interrupt priority, DISPATCH_LEVEL critical boundary |
| DPC | Deferred work from ISR, runs at DISPATCH_LEVEL |
| PnP Manager | Device enumeration, driver loading, resource mgmt |
| Minifilters | Layered file system filtering (altitude-based) |
| Power Manager | System/device power states, Modern Standby |

> **Tiếp theo: [Chapter 7 — Bảo Mật](Chapter_07_Security.md)**
> Access control, tokens, privileges, UAC, exploit mitigations, Credential Guard.
