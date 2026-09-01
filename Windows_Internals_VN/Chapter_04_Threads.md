# Chapter 4: Threads

> Chương này đi sâu vào threads: cấu trúc nội bộ, scheduling algorithm,
> priority system, quantum, multiprocessor scheduling, và thread pools.

---

## 4.1 Thread Internals

### 4.1.1 _ETHREAD Structure

```
_ETHREAD
│
├── _KTHREAD (Tcb)                     ← Kernel Thread Block
│   ├── Header                         ← DISPATCHER_HEADER (waitable)
│   │
│   ├── ── Stack ──
│   ├── InitialStack                   ← Top of kernel stack
│   ├── StackLimit                     ← Bottom (guard page)
│   ├── StackBase                      ← Base of kernel stack
│   ├── KernelStack                    ← Current kernel RSP
│   │
│   ├── ── Scheduling ──
│   ├── State                          ← Running, Ready, Waiting, ...
│   ├── WaitReason                     ← Executive, UserRequest, ...
│   ├── Priority                       ← Current (dynamic) priority 0-31
│   ├── BasePriority                   ← Base priority
│   ├── PriorityDecrement              ← Boost decay
│   ├── Quantum                        ← Remaining quantum
│   ├── QuantumReset                   ← Quantum reset value
│   ├── Affinity                       ← CPU affinity mask
│   ├── IdealProcessor                 ← Preferred CPU
│   ├── LastProcessor                  ← Last CPU ran on
│   │
│   ├── ── Context ──
│   ├── TrapFrame                      ← KTRAP_FRAME (saved regs on syscall)
│   ├── Teb                            ← Thread Environment Block (user mode)
│   ├── ApcState                       ← APC queue state
│   │   ├── ApcListHead[2]             ← Kernel + User APC queues
│   │   ├── Process                    ← Owner EPROCESS
│   │   └── KernelApcPending/UserApcPending
│   │
│   ├── ── Wait ──
│   ├── WaitBlockList                  ← KWAIT_BLOCK array
│   ├── WaitListEntry                  ← Link in wait list
│   ├── WaitTime                       ← When wait started
│   ├── WaitMode                       ← KernelMode / UserMode
│   │
│   ├── ── Timing ──
│   ├── UserTime                       ← User-mode CPU ticks
│   ├── KernelTime                     ← Kernel-mode CPU ticks
│   ├── CycleTime                      ← CPU cycles consumed
│   │
│   ├── ── Synchronization ──
│   ├── Mutant                         ← Owned mutexes list
│   ├── ThreadLock                     ← Thread push lock
│   │
│   └── ── Misc ──
│       ├── Process                    ← Parent KPROCESS
│       ├── ThreadFlags / ThreadFlags2
│       ├── SystemCallNumber           ← Current/last system call
│       └── Win32Thread                ← Win32k per-thread data
│
├── Cid                                ← CLIENT_ID (PID + TID)
├── StartAddress                       ← Kernel start address
├── Win32StartAddress                  ← User-mode start address
├── ThreadListEntry                    ← Link in process thread list
├── CrossThreadFlags                   ← Terminated, DeadThread, ...
├── SameThreadApcFlags                 ← APC-related flags
├── DeviceToVerify                     ← Volume verify
├── ImpersonationInfo                  ← Impersonation token
│
├── CreateTime                         ← Thread creation time
├── ExitTime                           ← Thread exit time
├── ExitStatus                         ← Exit code
└── ...
```

### 4.1.2 Thread Environment Block (TEB)

TEB nằm ở user-mode, accessible via `GS:[0]` (x64) hoặc `FS:[0]` (x86):

```
_TEB
├── NtTib                              ← NT_TIB (Thread Information Block)
│   ├── ExceptionList                  ← SEH chain head (x86 only)
│   ├── StackBase                      ← Top of user-mode stack
│   ├── StackLimit                     ← Bottom of user-mode stack
│   ├── SubSystemTib                   ← Subsystem-specific
│   ├── ArbitraryUserPointer           ← Available for app use
│   └── Self                           ← Pointer to TEB itself
│
├── EnvironmentPointer                 ← Environment data
├── ClientId                           ← PID + TID
├── ActiveRpcHandle                    ← RPC handle
├── ThreadLocalStoragePointer          ← TLS array
├── ProcessEnvironmentBlock            ← → PEB
├── LastErrorValue                     ← GetLastError() value
├── CountOfOwnedCriticalSections       ← Owned CRITICAL_SECTIONs
├── Win32ThreadInfo                    ← USER thread info
├── CurrentLocale                      ← Thread locale
├── GdiTebBatch                        ← GDI batching buffer
├── RealClientId                       ← Real PID + TID
├── LastStatusValue                    ← Last NTSTATUS
├── StaticUnicodeString                ← Buffer for conversions
├── DeallocationStack                  ← Reserve stack base
├── TlsSlots[64]                       ← TLS slots 0-63
├── TlsExpansionSlots                  ← TLS slots 64-1088
├── Instrumentation                    ← Instrumentation data
└── ...
```

**Truy cập TEB:**

```c
// User mode
_TEB* teb = NtCurrentTeb();             // intrinsic
DWORD tid = teb->ClientId.UniqueThread;

// Hoặc inline asm / intrinsic
// x64: mov rax, gs:[0x30]
// x86: mov eax, fs:[0x18]

// TLS access
DWORD value = TlsGetValue(tlsIndex);     // → teb->TlsSlots[index]
```

### 4.1.3 Kernel Stack

Mỗi thread có kernel stack riêng, allocated từ kernel address space:

| Platform | Default Size | Expansion |
|----------|-------------|-----------|
| x64 | 24 KB initial, expandable | Max ~256 KB |
| ARM64 | 24 KB initial | Max ~256 KB |

```
High address:
┌──────────────────┐ ← InitialStack (top)
│ KTRAP_FRAME      │ ← CPU state khi enter kernel
│ (saved regs)     │
├──────────────────┤
│ Local variables  │
│ Stack frames     │
│ for kernel calls │
├──────────────────┤ ← Current RSP (KernelStack)
│ (unused space)   │
├──────────────────┤ ← StackLimit
│ Guard page       │ ← ACCESS_VIOLATION nếu overflow
└──────────────────┘
Low address
```

### 4.1.4 User-Mode Stack

```
High address:
┌──────────────────┐ ← StackBase (TEB.NtTib.StackBase)
│ Thread parameter │
│ Return address   │
├──────────────────┤
│ Stack frames     │
│ Local variables  │
│ Function calls   │
├──────────────────┤ ← Current RSP
│ (committed but   │
│  unused)          │
├──────────────────┤ ← StackLimit (TEB.NtTib.StackLimit)
│ Guard page       │ ← Triggers stack growth
├──────────────────┤
│ Reserved but     │
│ uncommitted      │
├──────────────────┤
│ Final guard page │ ← Stack overflow exception
└──────────────────┘ ← DeallocationStack (allocation base)
Low address

Default: 1 MB reserved, grows on demand (commit guard pages)
```

---

## 4.2 Thread Scheduling

### 4.2.1 Tổng Quan Scheduler

Windows scheduler là **preemptive, priority-based, round-robin** scheduler:

- **Preemptive**: thread có priority cao hơn luôn được chạy trước
- **Priority-based**: 32 priority levels (0-31)
- **Round-robin**: threads cùng priority được chia đều CPU time (quantum)

```
Priority 31: ■ Thread A chạy (highest ready)
Priority 30:
Priority 29:
  ...
Priority 8:  ■ Thread B (waiting)  ■ Thread C (ready, đợi A xong quantum)
  ...
Priority 1:  ■ Thread D (starved nếu không có boosting)
Priority 0:  ■ Zero Page Thread (idle work)
```

### 4.2.2 Priority Levels

```
31 ┐
   │ Real-time priorities (16-31)
   │ ← Thường dùng cho: audio, video, device drivers
   │ ← CẢNH BÁO: threads ở đây starve mọi thứ khác
16 ┘
15 ┐
   │ Dynamic priorities (1-15)
   │ ← Normal applications
   │ ← Kernel có thể boost tạm thời
1  ┘
0  ← Zero Page Thread ONLY (idle work, zero-fill pages)
```

**Priority Classes và Relative Priority:**

Windows dùng 2-level system: Process Priority Class + Thread Relative Priority = Actual Base Priority:

| Process Priority Class | Base Priority |
|----------------------|---------------|
| Idle | 4 |
| Below Normal | 6 |
| Normal | 8 |
| Above Normal | 10 |
| High | 13 |
| Realtime | 24 |

| Thread Relative Priority | Offset |
|--------------------------|--------|
| Idle | 1 (hoặc 16 for RT) |
| Lowest | -2 |
| Below Normal | -1 |
| Normal | 0 |
| Above Normal | +1 |
| Highest | +2 |
| Time Critical | 15 (hoặc 31 for RT) |

**Ví dụ:**
```
Process class = Normal (base 8)
Thread relative = Above Normal (+1)
→ Base priority = 9

Process class = High (base 13)
Thread relative = Highest (+2)
→ Base priority = 15

Process class = Realtime (base 24)
Thread relative = Normal (0)
→ Base priority = 24
```

### 4.2.3 Thread States

```
┌───────────────┐
│  Initialized  │ → Thread object created
└───────┬───────┘
        │ Insert vào ready queue
        ▼
┌───────────────┐ ◄──────────────────────────────────────┐
│    Ready      │ → Đợi được chọn để chạy                │
└───────┬───────┘                                         │
        │ Dispatcher chọn                                 │
        ▼                                                 │
┌───────────────┐                                         │
│   Standby     │ → Đã chọn, đợi context switch          │
└───────┬───────┘                                         │
        │ Context switch hoàn thành                        │
        ▼                                                 │
┌───────────────┐ ──Preempted──────────────────────────────┘
│   Running     │ ──Quantum expired────────────────────────┘
└───────┬───────┘
        │ Wait on object (Event, Mutex, I/O, ...)
        ▼
┌───────────────┐
│   Waiting     │ → Blocked, đợi event/object
└───────┬───────┘
        │ Wait satisfied (object signaled)
        ▼
┌───────────────┐
│Deferred Ready │ → Ready nhưng chưa add vào queue
└───────┬───────┘   (transition state, multiprocessor)
        │
        ▼
     → Ready

┌───────────────┐
│  Transition   │ → Kernel stack paged out, đợi page-in
└───────────────┘

┌───────────────┐
│  Terminated   │ → Thread đã exit
└───────────────┘
```

### 4.2.4 Dispatcher Database

Per-CPU ready queues:

```
KPRCB (per CPU):
├── ReadyListHead[32]     ← 32 priority queues (0-31)
│   ├── [31]: Thread M ←→ Thread N
│   ├── [30]: (empty)
│   ├── ...
│   ├── [8]:  Thread P ←→ Thread Q ←→ Thread R
│   ├── ...
│   └── [0]:  (Zero Page Thread)
│
├── ReadySummary          ← Bitmask: 1 nếu queue[i] không empty
│   = 0x00000100          ← Bit 8 set → có thread ở priority 8
│
├── CurrentThread         ← Thread đang chạy
├── NextThread            ← Thread sẽ chạy (đã preempt)
└── IdleThread            ← Idle thread cho CPU này
```

**Chọn thread:**
```
1. Scan ReadySummary bitmask từ bit cao nhất xuống
2. Bit cao nhất set = priority level cao nhất có ready thread
3. Dequeue thread đầu tiên từ queue đó
4. Set thread state = Standby → Running
5. Context switch
```

### 4.2.5 Quantum

Quantum = lượng CPU time mỗi thread được chạy trước khi bị preempt.

**Quantum units:**

- 1 quantum unit = 1/3 clock interval
- Clock interval ≈ 15.625 ms (64 Hz) trên hầu hết systems
- Default quantum: **6 units (client)** hoặc **36 units (server)**

```
Client (Windows 11):
  Foreground thread: 6 × 3 = 18 quantum units
  Background thread: 6 quantum units
  → 6 units × (1/3 × 15.625ms) ≈ 31.25 ms

Server (Server 2025):
  All threads: 36 quantum units
  → 36 units × (1/3 × 15.625ms) ≈ 187.5 ms
```

**[UPDATE 2026]** Timer resolution:
- Default: 15.625 ms (64 Hz)
- Multimedia timer: có thể giảm xuống 0.5 ms
- Windows 11: `timeBeginPeriod()` giờ chỉ ảnh hưởng process gọi (per-process timer resolution)

**Quantum flow:**

```
Thread A (quantum = 6):
┌──────────────────────────────────────────────┐
│ ████████████████████ → quantum expired       │
│ 6    5    4    3    2    1    0               │
│                              ↓               │
│                         Preempt → Ready queue│
└──────────────────────────────────────────────┘

Nếu Thread A wait trước khi hết quantum:
┌──────────────────────────────────────────────┐
│ ████████████ → Wait (quantum = 3 remaining)  │
│ 6    5    4    3                              │
│              ↓                               │
│         Lưu quantum, chuyển sang Waiting     │
│         Khi resume: quantum = 3 (giữ lại)    │
└──────────────────────────────────────────────┘
```

### 4.2.6 Priority Boosting

Kernel tạm thời tăng priority để cải thiện responsiveness:

| Scenario | Boost Amount | Decay |
|----------|-------------|-------|
| I/O completion | +1 (disk) đến +8 (sound) | -1 mỗi quantum |
| Wait on event/semaphore released | +1 | -1 mỗi quantum |
| Foreground process thread | +2 (PsForegroundQuantumBoost) | Maintained |
| GUI thread wakes (window input) | Boost to 14 | -1 mỗi quantum |
| Starvation prevention | Boost to 15 | Reset sau 1 quantum |
| Lock contention | +1 | -1 mỗi quantum |
| Multimedia (MMCSS) | Boost to RT range | Via MMCSS service |

**Priority boost flow:**

```
Base Priority = 8
                                    Boost Priority
                                         │
I/O complete (disk, +1) ──→  9          │
Next quantum ──────────→  8 (decay)     │
                                         │
GUI input (boost to 14) ──→ 14          │
Next quantum ──────────→ 13             │
Next quantum ──────────→ 12             │
Next quantum ──────────→ 11             │
  ...                                    │
Eventually ────────────→  8 (base)      │
                                         │
CEILING: boost không vượt quá 15        │
(real-time range 16-31 chỉ set explicit)│
```

**Starvation Prevention (Balance Set Manager):**

```
Cứ 1 giây, Balance Set Manager scan:
  Tìm ready threads chờ > 4 giây (300+ quantum)
  → Boost priority lên 15
  → Set double quantum (12 units)
  → Sau 1 quantum, reset về base priority
  → Ngăn priority inversion indefinite
```

### 4.2.7 Context Switch

Khi scheduler chuyển từ Thread A sang Thread B:

```
Trigger: quantum expired / preempt / wait

1. KiDispatchInterrupt / KiSwapThread
2. Save Thread A state:
   ├── Push registers (RBX, RBP, RSI, RDI, R12-R15) lên kernel stack
   ├── Save RSP vào KTHREAD.KernelStack
   ├── Save floating-point state (nếu cần)
   └── Save debug registers (nếu cần)
   
3. Address space switch (nếu khác process):
   ├── Load new CR3 (DirectoryTableBase)
   ├── Flush TLB entries
   └── Update GS base (KPCR.CurrentThread)

4. Restore Thread B state:
   ├── Load RSP từ KTHREAD.KernelStack
   ├── Pop registers
   ├── Restore floating-point state
   └── Restore debug registers

5. Return → Thread B resumes execution
```

**Cost của context switch:**

| Action | Approximate Cost |
|--------|-----------------|
| Register save/restore | ~100-200 ns |
| Same-process switch (no CR3 change) | ~1-2 μs |
| Cross-process switch (CR3 change + TLB flush) | ~3-10 μs |
| TLB refill (indirect cost) | ~10-100 μs over next execution |

**[UPDATE 2026]** PCID (Process Context ID) trên Intel CPUs giảm TLB flush cost khi switch process:

```
Mỗi process được assign 1 PCID (12-bit, max 4096)
TLB entries tagged với PCID
→ Khi switch process: CR3 load with NOFLUSH bit
→ TLB entries của process cũ KHÔNG bị flush
→ Trở lại process cũ: TLB vẫn warm
```

---

## 4.3 Multiprocessor Scheduling

### 4.3.1 Processor Selection

Khi thread trở thành ready, scheduler chọn CPU:

```
Thread becomes Ready
    │
    ├── Ideal Processor set? ──→ Try ideal processor
    │                              │
    │                    Idle? ────→ Run there ✓
    │                    Busy? ────→ Check other options
    │
    ├── Last Processor ──→ Try last CPU (cache warm)
    │                       │
    │                Idle? ──→ Run there ✓
    │                Busy? ──→ Continue
    │
    ├── Scan for idle processor
    │   (prefer same NUMA node, same group)
    │   Found? ──→ Run there ✓
    │
    └── Preempt lowest-priority running thread
        (if lower priority than new thread)
```

### 4.3.2 Ideal Processor

Mỗi thread có "ideal processor" — CPU ưa thích:

```c
// Set ideal processor
SetThreadIdealProcessor(hThread, 2);     // CPU 2
SetThreadIdealProcessorEx(hThread, &procNumber, NULL);

// Kernel
SetIdealProcessor:
  ├── Try to run on ideal processor
  ├── Benefit: cache affinity
  └── Hint only — scheduler can choose differently
```

### 4.3.3 CPU Affinity

Hard constraint — thread CHỈ được chạy trên CPUs trong affinity mask:

```c
// Process affinity (affects all threads)
SetProcessAffinityMask(hProcess, 0x0F);  // CPUs 0-3

// Thread affinity (subset of process affinity)
SetThreadAffinityMask(hThread, 0x03);    // CPUs 0-1

// Affinity mask: bit N = CPU N
//   0x01 = CPU 0
//   0x03 = CPU 0,1
//   0x0F = CPU 0,1,2,3
//   0xFF = CPU 0-7
```

### 4.3.4 Processor Groups

Hỗ trợ >64 logical processors:

```
Group 0: CPU 0-63   (64 processors)
Group 1: CPU 0-63   (64 processors)
...
Group 31: CPU 0-63

Max: 32 groups × 64 CPUs = 2048 logical processors
```

- Default: thread chỉ thấy CPUs trong group 0
- Explicitly dùng Group-aware APIs (`SetThreadGroupAffinity`) cho cross-group

### 4.3.5 Heterogeneous Scheduling (big.LITTLE)

**[UPDATE 2026]** Windows 11 hỗ trợ Intel hybrid (P-core/E-core) và ARM big.LITTLE:

```
┌──────────────────────┐  ┌──────────────────────┐
│ Performance Cores     │  │ Efficiency Cores      │
│ (P-cores / big)       │  │ (E-cores / LITTLE)    │
│                       │  │                       │
│ - Higher clock        │  │ - Lower clock         │
│ - More IPC            │  │ - Lower power         │
│ - SMT (Hyperthreading)│  │ - No SMT              │
│ - Foreground apps     │  │ - Background tasks    │
│ - Gaming              │  │ - Services            │
└──────────────────────┘  └──────────────────────┘
```

**Thread Director** (Intel Thread Director / Windows Scheduler):
- Hardware hints about thread behavior (compute-heavy, memory-bound, ...)
- Windows scheduler maps threads to appropriate core type
- `EcoQoS` quality of service: hint to run on E-cores

```c
// Set thread to prefer efficiency cores
THREAD_POWER_THROTTLING_STATE state = {0};
state.Version = THREAD_POWER_THROTTLING_CURRENT_VERSION;
state.ControlMask = THREAD_POWER_THROTTLING_EXECUTION_SPEED;
state.StateMask = THREAD_POWER_THROTTLING_EXECUTION_SPEED;
SetThreadInformation(hThread, ThreadPowerThrottling,
                     &state, sizeof(state));
```

### 4.3.6 Dynamic Fair Share Scheduling (DFSS)

**[UPDATE 2026]** Trên Server editions, DFSS đảm bảo mỗi session nhận fair CPU share:

```
Terminal Server với 3 sessions:

Không có DFSS:
  Session 1 (100 threads) ──→ Chiếm gần hết CPU
  Session 2 (5 threads)   ──→ Bị starve
  Session 3 (2 threads)   ──→ Bị starve nặng

Có DFSS:
  Session 1 (100 threads) ──→ ~33% CPU
  Session 2 (5 threads)   ──→ ~33% CPU
  Session 3 (2 threads)   ──→ ~33% CPU
  
  Scheduler giảm effective priority của threads trong sessions
  dùng quá nhiều CPU relative to fair share.
```

---

## 4.4 Thread Suspension và Freeze

### 4.4.1 Suspend

```c
SuspendThread(hThread);    // → APC-based suspension
ResumeThread(hThread);     // Resume

// Suspend count: mỗi Suspend tăng 1, mỗi Resume giảm 1
// Thread chỉ chạy khi count = 0
```

Internally: kernel APC queued → thread suspends tại "alertable" point.

### 4.4.2 Deep Freeze

**[UPDATE 2026]** Deep freeze dùng cho UWP apps / Modern Standby:

```
Process States:
  Running → Suspended → Deep Frozen

Deep Frozen:
  - Working set trimmed (memory reclaimed)
  - Threads không thể resume bằng ResumeThread
  - Process vẫn tồn tại nhưng không dùng resources
  - Dùng cho: UWP lifecycle, Modern Standby
  
  NtSetInformationProcess(ProcessFreezeInformation)
```

---

## 4.5 Worker Factories (Thread Pools)

### 4.5.1 Windows Thread Pool Architecture

```
Application
    │
    ▼
┌──────────────────────────────────────────────┐
│ Thread Pool API                               │
│ CreateThreadpoolWork / SubmitThreadpoolWork    │
│ CreateThreadpoolTimer                         │
│ CreateThreadpoolIo                            │
│ CreateThreadpoolWait                          │
└──────────┬───────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────────────┐
│ Worker Factory (Kernel Object)                │
│                                              │
│ ┌──────┐ ┌──────┐ ┌──────┐                 │
│ │Worker│ │Worker│ │Worker│ ... (dynamic)    │
│ │Thread│ │Thread│ │Thread│                  │
│ └──┬───┘ └──┬───┘ └──┬───┘                 │
│    │        │        │                       │
│    ▼        ▼        ▼                       │
│ I/O Completion Port (shared queue)           │
└──────────────────────────────────────────────┘
```

### 4.5.2 Thread Pool Types

```c
// Work items — one-shot tasks
PTP_WORK work = CreateThreadpoolWork(WorkCallback, context, &env);
SubmitThreadpoolWork(work);

// Timer callbacks — periodic or one-shot
PTP_TIMER timer = CreateThreadpoolTimer(TimerCallback, context, &env);
FILETIME ft = ...; // due time
SetThreadpoolTimer(timer, &ft, 1000, 0);  // period 1000ms

// I/O callbacks — triggered on I/O completion
PTP_IO io = CreateThreadpoolIo(hFile, IoCallback, context, &env);
StartThreadpoolIo(io);
ReadFile(hFile, buffer, size, NULL, &overlapped);

// Wait callbacks — triggered when handle signaled
PTP_WAIT wait = CreateThreadpoolWait(WaitCallback, context, &env);
SetThreadpoolWait(wait, hEvent, NULL);
```

### 4.5.3 Worker Factory Kernel Implementation

```
_TP_WORKER_FACTORY
├── MinThreads           ← Minimum worker threads
├── MaxThreads           ← Maximum worker threads (default: 500)
├── PendingWorkerCount   ← Threads waiting for work
├── WaitingWorkerCount   ← Threads blocked on I/O CP
├── ReleaseCount         ← Threads to release
├── CompletionPort       ← I/O Completion Port for dispatch
└── ThreadList           ← List of worker threads
```

Kernel dynamically adjusts:
- Create new thread khi: all workers busy AND queue has pending work
- Destroy thread khi: worker idle > threshold
- Rate limit: không create quá nhanh (500ms interval)

---

## 4.6 Thread Creation Internals

### 4.6.1 NtCreateThreadEx Flow

```
CreateThread() [kernel32.dll]
│
├── Validate parameters, convert stack size
└── NtCreateThreadEx() [ntdll.dll → syscall → kernel]
    │
    ├── 1. Create ETHREAD/KTHREAD
    │   ├── ObCreateObject(ThreadType) → allocate ETHREAD
    │   ├── Initialize _KTHREAD:
    │   │   ├── KeInitializeThread()
    │   │   ├── Allocate kernel stack (KiAllocateKernelStack)
    │   │   │   └── Typically 24KB (x64), 12KB (x86)
    │   │   ├── Set initial stack frame for KiStartUserThread
    │   │   ├── Initialize DISPATCHER_HEADER (waitable object)
    │   │   ├── Initialize APC queues (Kernel + User mode)
    │   │   ├── Set BasePriority from parent process
    │   │   ├── Set Affinity from parent process
    │   │   └── Set QuantumReset from system settings
    │   └── Initialize _ETHREAD:
    │       ├── Cid.UniqueThread = PspCidTable handle
    │       ├── StartAddress = kernel entry point
    │       ├── Win32StartAddress = user entry point
    │       ├── ThreadListEntry → add to process thread list
    │       └── CreateTime = KeQuerySystemTimePrecise()
    │
    ├── 2. Allocate TEB
    │   ├── MmCreateTeb()
    │   ├── Map in user address space
    │   ├── Set StackBase, StackLimit
    │   ├── Set Self pointer (TEB self-reference)
    │   └── Copy PEB pointer
    │
    ├── 3. Setup user-mode stack
    │   ├── MmStackSwappable → KeSetContextThread
    │   ├── Initialize user stack:
    │   │   ├── CONTEXT with RIP = RtlUserThreadStart (ntdll)
    │   │   ├── RCX = lpStartAddress (user entry point)
    │   │   └── RDX = lpParameter
    │   └── RtlUserThreadStart eventually calls lpStartAddress(lpParam)
    │
    ├── 4. Notify subsystem
    │   ├── PspUserThreadStartup() queued as kernel APC
    │   ├── LdrInitializeThunk → initializes CRT, TLS, etc.
    │   └── csrss.exe notified of new thread (CsrCreateThread)
    │
    ├── 5. Insert into scheduler
    │   ├── KeReadyThread() → add to ready queue
    │   └── Thread begins execution when selected by dispatcher
    │
    └── 6. Return handle to caller
        └── Handle with THREAD_ALL_ACCESS (or requested access)
```

### 4.6.2 Remote Thread Creation (Security-relevant)

```
CreateRemoteThread() / NtCreateThreadEx():
  Tạo thread TRONG process khác — core technique cho:
  - DLL injection (thread executes LoadLibrary)
  - Shellcode injection (thread executes shellcode)
  - Process hollowing (replace process image)

Required access rights:
  PROCESS_CREATE_THREAD  (0x0002) — create the thread
  PROCESS_VM_OPERATION   (0x0008) — allocate memory in target
  PROCESS_VM_WRITE       (0x0020) — write shellcode/DLL path
  PROCESS_QUERY_INFORMATION (0x0400) — optional

Detection:
  - ETW: Microsoft-Windows-Kernel-Process, Event ID 3 (ThreadStart)
    → CrossProcess = TRUE nếu remote thread
  - Sysmon Event ID 8 (CreateRemoteThread)
  - Kernel callback: PsSetCreateThreadNotifyRoutineEx()
    → Driver nhận notification cho MỌI thread creation
    → Check if thread's process != creator's process

  - Win11 24H2: [UPDATE 2026] NtCreateThreadEx có thêm
    thread creation mitigation attributes để restrict
    remote thread creation cho specific processes
```

### 4.6.3 Asynchronous Procedure Calls (APC)

```
APC cho phép execute code trong context của thread cụ thể:

APC Types:
  ┌─────────────────────────────────────────────┐
  │ Kernel-mode APC (Special)                    │
  │   IRQL: APC_LEVEL (1)                       │
  │   Preempts user-mode code immediately       │
  │   Used by: I/O completion (IRP_MJ_READ)      │
  │   Cannot be disabled                         │
  ├─────────────────────────────────────────────┤
  │ Kernel-mode APC (Normal)                     │
  │   IRQL: PASSIVE_LEVEL (0)                    │
  │   Can be disabled (KeEnterGuardedRegion)     │
  │   Used by: I/O completion to user buffer     │
  ├─────────────────────────────────────────────┤
  │ User-mode APC                                │
  │   Delivered khi thread in alertable wait:    │
  │   SleepEx(INFINITE, TRUE)                    │
  │   WaitForSingleObjectEx(..., TRUE)           │
  │   NtTestAlert()                              │
  │   Used by: QueueUserAPC(), ReadFileEx()      │
  └─────────────────────────────────────────────┘

APC Injection (attack technique):
  1. OpenProcess(target) → get handle
  2. VirtualAllocEx(target, shellcode) → allocate + write
  3. QueueUserAPC(shellcode_addr, target_thread, 0)
  4. Wait for target thread to enter alertable wait
  → Shellcode executes in target process context

  Detection:
    - NtQueueApcThread / NtQueueApcThreadEx syscalls
    - Cross-process APC → suspicious
    - ETW Threat Intelligence events

  Early Bird Injection (variant):
    1. CreateProcess(SUSPENDED)
    2. QueueUserAPC(shellcode, main_thread)
    3. ResumeThread()
    → APC executes BEFORE entry point (before AV hooks)
```

### 4.6.4 Context Switch Deep Dive

```
Context switch: save thread A state → load thread B state

Full flow (same process):
  1. Enter KiSwapContext (IRQL = DISPATCH_LEVEL)
  2. Save Thread A state:
     ├── Push non-volatile registers (RBX, RBP, RSI, RDI, R12-R15)
     ├── Save RSP to KTHREAD.KernelStack
     ├── Save floating point / AVX state (XSAVE)
     └── Save debug registers (if DR7 active)
  3. Switch stack:
     ├── Load RSP from Thread B KTHREAD.KernelStack
     └── Now executing on Thread B's kernel stack
  4. Load Thread B state:
     ├── Pop non-volatile registers
     ├── Restore floating point / AVX state (XRSTOR)
     ├── Restore debug registers (if needed)
     └── Update KPRCB.CurrentThread = Thread B
  5. If different process:
     ├── Load new CR3 (DirectoryTableBase) → TLB flush
     ├── PCID optimization: tag TLB entries → no full flush
     ├── Swap GS base (different TEB/PEB)
     ├── Update address space bits
     └── Cost: ~3000-5000 cycles (vs ~1000 same-process)
  6. Return to Thread B's last execution point

Context switch cost breakdown:
  ┌──────────────────────────────┬──────────┐
  │ Operation                    │ Cycles   │
  ├──────────────────────────────┼──────────┤
  │ Direct switch cost (min)     │ ~1000    │
  │ TLB pollution (cache miss)   │ ~2000    │
  │ CR3 switch (cross-process)   │ ~2000    │
  │ FPU/AVX save/restore         │ ~500     │
  │ Spectre mitigations          │ ~500-1000│
  │ Total (same process)         │ ~2000    │
  │ Total (cross process)        │ ~5000    │
  │ Total with Spectre mitigation│ ~6000+   │
  └──────────────────────────────┴──────────┘
```

```
;; WinDbg — Context switch analysis:
kd> !running -it                    ; Currently running threads (all CPUs)
kd> !ready                          ; Ready queue snapshot
kd> !thread @$thread                ; Current thread details

;; Per-CPU context switch counter:
kd> dt nt!_KPRCB @$prcb ContextSwitches
kd> !cpuinfo                        ; Per-CPU stats including switches

;; ETW — Precise context switch tracing:
;; xperf -on CSWITCH → records every context switch
;; Fields: NewThreadId, OldThreadId, NewPriority, OldPriority,
;;         NewWaitReason, OldWaitReason, ReadyTime, WaitTime
```

### 4.6.5 Thread Suspension và Deep Freeze

```
SuspendThread / NtSuspendThread:
  SuspendCount++ trên target thread
  Thread transitions to Wait state
  Kernel APC queued cho target → target suspends khi APC delivered
  
  Multiple suspends: SuspendCount increments each time
  ResumeThread decrements → thread runs khi SuspendCount == 0

Deep Freeze (từ Windows 10):
  Process chuyển sang "frozen" state
  ALL threads suspended + marked as "deep frozen"
  Process không nhận DPCs, APCs, hoặc I/O completions
  
  Used by:
  - UWP lifecycle management (app suspension)
  - Modern Standby power saving
  - Background app resource management
  
  API: NtSetInformationProcess(ProcessFreezeInformation)
  Internal: PsFreezeProcess() / PsThawProcess()
```

---

## 4.7 Multimedia Class Scheduler Service (MMCSS)

**[UPDATE 2026]** MMCSS boost threads cho multimedia workloads:

```
DWORD taskIndex = 0;
HANDLE hTask = AvSetMmThreadCharacteristics(L"Pro Audio", &taskIndex);
// Thread nhận priority boost to real-time range
// Đảm bảo audio/video không bị skip

AvRevertMmThreadCharacteristics(hTask);
```

**MMCSS Categories:**

| Category | Priority Range | Use Case |
|----------|---------------|----------|
| Pro Audio | 26-30 | DAW, music production |
| Audio | 24-28 | Media playback |
| Playback | 22-26 | Video playback |
| Window Manager | 22-26 | DWM composition |
| Games | 8-14 | Gaming |
| Capture | 22-26 | Screen/audio capture |
| Distribution | 16-20 | Streaming |

---

## 4.8 Experiments

### Experiment 4.1: Observe Thread Scheduling

```
# WinDbg
kd> !ready                           ; Ready queue summary
kd> !running                         ; Currently running threads
kd> !thread <ETHREAD_addr>           ; Thread details

# Xem thread priority / state
kd> dt nt!_KTHREAD <addr> State Priority BasePriority
```

### Experiment 4.2: Context Switch Rate

```powershell
# Performance Monitor counter
Get-Counter '\System\Context Switches/sec'

# Hoặc
typeperf "\System\Context Switches/sec" -si 1
```

### Experiment 4.3: Priority Boost in Action

```
1. Mở Process Explorer
2. Properties → Threads tab
3. Quan sát Base Priority vs Dynamic Priority
4. Move mouse / type → thấy GUI threads boost
5. Dynamic Priority > Base Priority = đang boosted
```

### Experiment 4.4: CPU Affinity

```powershell
# Set affinity cho process
$p = Get-Process notepad
$p.ProcessorAffinity = 0x03   # CPUs 0 and 1 only

# Verify
$p.ProcessorAffinity
```

---

### Experiment 4.5: Thread Stack Analysis

```
;; Kernel stack:
kd> !thread <addr>                  ; Shows kernel stack trace
kd> dt nt!_KTHREAD <addr> InitialStack StackLimit StackBase KernelStack

;; Kernel stack size:
;;   Default: 24 KB (x64), 12 KB (x86)
;;   6 pages: 3 committed + 1 guard + 2 reserved
;;   Overflow → KERNEL_STACK_INPAGE_ERROR bugcheck

;; User stack:
kd> .thread <addr>                  ; Switch to thread context
kd> !teb                            ; Show TEB with stack info
kd> dt ntdll!_TEB @$teb StackBase StackLimit DeallocationStack

;; User stack layout:
;;   DeallocationStack → reserve base
;;   StackLimit        → committed limit (grows down)
;;   Guard page        → triggers stack growth on access
;;   StackBase         → top of stack (initial RSP)
;;   Default: 1MB reserved, first page committed + guard
```

### Experiment 4.6: APC Queue Inspection

```
;; View APC queues for a thread:
kd> dt nt!_KTHREAD <addr> ApcState
kd> dt nt!_KAPC_STATE <apcstate_addr>
    +0x000 ApcListHead      : [2] _LIST_ENTRY   ← [0]=Kernel, [1]=User
    +0x020 Process          : Ptr64 _KPROCESS
    +0x028 InProgressFlags
    +0x029 KernelApcPending
    +0x02a UserApcPendingAll

;; Walk kernel APC list:
kd> dl <ApcListHead[0].Flink> 3    ; Follow linked list
;; Each entry is a _KAPC structure:
kd> dt nt!_KAPC <addr>
    +0x000 Type              ; APC type
    +0x020 KernelRoutine      ; Kernel-mode APC function
    +0x028 RundownRoutine     ; Cleanup if thread exits
    +0x030 NormalRoutine      ; Normal APC function
    +0x038 NormalContext
    +0x040 SystemArgument1
    +0x048 SystemArgument2
```

### Experiment 4.7: Thread Security — Impersonation

```
;; Check if thread is impersonating:
kd> dt nt!_ETHREAD <addr> ImpersonationInfo
kd> dt nt!_PS_IMPERSONATION_INFORMATION <imp_addr>
    +0x000 Token            : Ptr64 _TOKEN      ← Impersonation token
    +0x008 CopyOnOpen       : UChar
    +0x009 EffectiveOnly    : UChar
    +0x00a ImpersonationLevel : _SECURITY_IMPERSONATION_LEVEL
        ;; 0 = Anonymous, 1 = Identification, 2 = Impersonation, 3 = Delegation

;; Security implication:
;; Thread impersonation allows a server thread to act as client
;; Named pipe impersonation is common privilege escalation vector:
;;   1. Create named pipe with specific name
;;   2. Wait for privileged service to connect
;;   3. ImpersonateNamedPipeClient()
;;   4. Thread now has SYSTEM token
;;   → "Potato" attack family (Hot/Juicy/Sweet/God Potato)
```

---

## 4.9 Tóm Tắt

| Khái niệm | Điểm chính |
|------------|------------|
| ETHREAD/KTHREAD | ~1500 bytes, chứa stack pointers, priority, state |
| TEB | User-mode per-thread data, truy cập qua GS/FS segment |
| Priority | 32 levels (0-31), dynamic range 1-15, realtime 16-31 |
| Quantum | ~30ms client, ~180ms server, variable foreground boost |
| Scheduling | Preemptive + priority-based + round-robin |
| Context switch | ~1-10μs, expensive cross-process (CR3 change) |
| Priority boost | I/O completion, GUI, starvation prevention |
| Multiprocessor | Ideal processor, affinity, NUMA-aware |
| Heterogeneous | P-core/E-core, Thread Director, EcoQoS |
| Thread pools | Worker Factory kernel object, I/O completion port dispatch |
| MMCSS | Multimedia thread priority management |

> **Tiếp theo: [Chapter 5 — Quản Lý Bộ Nhớ](Chapter_05_Memory_Management.md)**
> Virtual memory, page tables, page faults, working sets, pools.
