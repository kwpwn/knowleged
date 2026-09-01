# Chapter 5: Quản Lý Bộ Nhớ (Memory Management)

> Chương dài nhất và phức tạp nhất. Memory Manager là component lớn nhất của
> Windows kernel, quản lý virtual memory, physical memory, page files, working
> sets, pools, và nhiều cơ chế tối ưu khác.

---

## 5.1 Tổng Quan Memory Manager

### 5.1.1 Chức Năng Chính

```
Memory Manager (Mm*)
├── Virtual Address Space management
│   ├── Per-process user space
│   └── Shared kernel space
├── Physical Memory management
│   ├── Page Frame Number (PFN) database
│   ├── Page lists (free, zeroed, standby, modified)
│   └── NUMA-aware allocation
├── Paging
│   ├── Demand paging (lazy allocation)
│   ├── Page fault handling
│   └── Page file management
├── Memory-Mapped Files (Sections)
├── Copy-on-Write (CoW)
├── Working Set management
├── Kernel Pools (paged + nonpaged)
├── Memory Compression
├── SuperFetch / Prefetch
└── Memory Enclaves (SGX)
```

### 5.1.2 Page Sizes

| Platform | Small Page | Large Page | Huge Page |
|----------|-----------|------------|-----------|
| x64 | 4 KB | 2 MB | 1 GB |
| ARM64 | 4 KB | 2 MB | 1 GB |

Large pages:
- Dùng 1 PDE entry thay vì 512 PTE entries
- Giảm TLB misses
- Không thể paged out (pinned in RAM)
- Yêu cầu `SeLockMemoryPrivilege`

```c
// Allocate large pages
SIZE_T size = GetLargePageMinimum();  // 2 MB
void* p = VirtualAlloc(NULL, size,
    MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES, PAGE_READWRITE);
```

---

## 5.2 Virtual Address Space

### 5.2.1 x64 Address Space Layout

```
                        Canonical Address Space (48-bit)
                        
0x0000'0000'0000'0000  ┌──────────────────────────────────┐
                        │ NULL page (64 KB)                 │ ← Access violation
0x0000'0000'0001'0000  ├──────────────────────────────────┤
                        │                                    │
                        │    USER SPACE (128 TB)             │
                        │                                    │
                        │ ┌──────────────────────────────┐  │
                        │ │ PE Image (.exe)               │  │ ← ASLR randomized
                        │ ├──────────────────────────────┤  │
                        │ │ Heaps                         │  │ ← Bottom-up ASLR
                        │ ├──────────────────────────────┤  │
                        │ │ DLLs (ntdll, kernel32, ...)   │  │ ← ASLR randomized
                        │ ├──────────────────────────────┤  │
                        │ │ Thread stacks                 │  │ ← Top-down ASLR
                        │ ├──────────────────────────────┤  │
                        │ │ Mapped files / shared memory  │  │
                        │ ├──────────────────────────────┤  │
                        │ │ PEB, TEBs                     │  │
                        │ └──────────────────────────────┘  │
                        │                                    │
0x0000'7FFF'FFFF'0000  ├──────────────────────────────────┤
                        │ No-access guard (64 KB)           │
0x0000'7FFF'FFFF'FFFF  ├──────────────────────────────────┤
                        │                                    │
                        │ ═══ Non-canonical hole ═══         │ ← CPU fault if accessed
                        │ (16 million TB)                    │
                        │                                    │
0xFFFF'8000'0000'0000  ├──────────────────────────────────┤
                        │                                    │
                        │    KERNEL SPACE (128 TB)           │
                        │                                    │
                        │ ┌──────────────────────────────┐  │
                        │ │ System PTE region             │  │
                        │ ├──────────────────────────────┤  │
                        │ │ Paged Pool                    │  │
                        │ ├──────────────────────────────┤  │
                        │ │ Nonpaged Pool                 │  │
                        │ ├──────────────────────────────┤  │
                        │ │ System Cache                  │  │
                        │ ├──────────────────────────────┤  │
                        │ │ PFN Database                  │  │
                        │ ├──────────────────────────────┤  │
                        │ │ Kernel + HAL + Drivers        │  │
                        │ ├──────────────────────────────┤  │
                        │ │ Hyperspace                    │  │
                        │ ├──────────────────────────────┤  │
                        │ │ System page table entries      │  │
                        │ └──────────────────────────────┘  │
                        │                                    │
0xFFFF'FFFF'FFFF'FFFF  └──────────────────────────────────┘
```

**[UPDATE 2026]** 5-Level Paging (LA57):
- Trên CPUs hỗ trợ: address space tăng lên 128 PB (57-bit)
- User space: 64 PB, Kernel space: 64 PB
- Windows 11 24H2 bắt đầu hỗ trợ experimental

### 5.2.2 Memory Regions

```
kd> !address

  BaseAddress      EndAddress+1        RegionSize     Type       State    Protect
  0`00000000     0`7ffe0000     0`7ffe0000   FREE                        
  0`7ffe0000     0`7ffe1000     0`00001000   Mapped   MEM_COMMIT PAGE_READONLY  ← SharedUserData
  ...
  7ff6`43210000  7ff6`43456000  0`00246000   Image    MEM_COMMIT PAGE_EXECUTE_READ ← .exe
  7ffa`12340000  7ffa`12567000  0`00227000   Image    MEM_COMMIT PAGE_EXECUTE_READ ← ntdll.dll
  ...
  ffff8`00000000  fffff`ffffffff                      Kernel space
```

### 5.2.3 Virtual Address Descriptors (VAD Tree)

Kernel quản lý virtual address space của mỗi process bằng cây AVL gọi là **VAD tree**. Mỗi node là một `_MMVAD` structure mô tả một memory region.

```
EPROCESS
 └── VadRoot → _MMVAD (AVL tree root)
                 ├── Left  → _MMVAD (lower address range)
                 └── Right → _MMVAD (higher address range)

Mỗi _MMVAD node mô tả 1 region:
┌──────────────────────────────────────────────────────────────┐
│ _MMVAD                                                       │
│                                                              │
│ StartingVpn      : 0x7FF6'4321 (VPN = VA >> 12)             │
│ EndingVpn        : 0x7FF6'4345                               │
│ VadNode          : AVL tree links (Parent, Left, Right)      │
│                                                              │
│ Flags (_MMVAD_FLAGS):                                        │
│   VadType        : VadNone / VadImageMap / VadAwe / ...      │
│   Protection     : MM_READWRITE, MM_EXECUTE_READ, ...        │
│   PrivateMemory  : 1 = private, 0 = mapped/shared            │
│   MemCommit      : 1 = entire range committed                │
│   Commit         : number of committed pages (nếu partial)   │
│                                                              │
│ Subsection       : → _SUBSECTION (cho mapped files/images)   │
│ FirstPrototypePte: → prototype PTE array (shared sections)   │
│ ControlArea      : → _CONTROL_AREA (section object info)     │
└──────────────────────────────────────────────────────────────┘
```

**VAD Types:**

| VadType | Giá trị | Mô tả |
|---------|---------|-------|
| `VadNone` | 0 | Private memory (VirtualAlloc) |
| `VadDevicePhysicalMemory` | 1 | Device physical memory mapping |
| `VadImageMap` | 2 | Image mapping (DLL, EXE) |
| `VadAwe` | 3 | Address Windowing Extensions |
| `VadWriteWatch` | 4 | Write-watch region (GetWriteWatch) |
| `VadLargePages` | 5 | Large page allocation |
| `VadRotatePhysical` | 6 | Rotate physical pages (AWE variant) |
| `VadLargePageSection` | 7 | Large page backed by section |

**VirtualAlloc và VAD:**

```
VirtualAlloc(addr, size, MEM_RESERVE, PAGE_READWRITE)
  │
  ├── 1. Tìm vùng trống trong VAD tree (hoặc dùng addr hint)
  ├── 2. Tạo _MMVAD node mới:
  │       StartingVpn = addr >> 12
  │       EndingVpn   = (addr + size - 1) >> 12
  │       Protection  = PAGE_READWRITE
  │       PrivateMemory = 1
  │       MemCommit   = 0 (chỉ reserve, chưa commit)
  ├── 3. Insert vào AVL tree
  └── 4. Return address

VirtualAlloc(addr, size, MEM_COMMIT, PAGE_READWRITE)
  │
  ├── 1. Tìm VAD chứa range [addr, addr+size)
  ├── 2. Tăng commit charge (Commit field)
  ├── 3. Page vẫn CHƯA được allocate (demand paging)
  └── 4. Khi access → page fault → allocate physical page

VirtualProtect(addr, size, PAGE_EXECUTE_READ)
  │
  ├── 1. Tìm VAD chứa range
  ├── 2. Nếu protection khác → có thể split VAD thành 2-3 nodes
  └── 3. Update Protection flags
```

**WinDbg: Phân tích VAD tree:**

```
kd> !process 0 0 notepad.exe
kd> .process /i /p <EPROCESS_addr>

kd> !vad <VAD_root_addr>
VAD     Level  Start       End         Commit
ffff... 0      7ff6`4321   7ff6`4345   36      Mapped  Exe  EXECUTE_WRITECOPY  \notepad.exe
ffff... 1      7ffa`1234   7ffa`1456   35      Mapped  Exe  EXECUTE_WRITECOPY  \ntdll.dll
ffff... 2      1a0`0000    1a0`00ff    10      Private      READWRITE
ffff... 2      7ffe`0000   7ffe`0000    1      Mapped       READONLY           SharedUserData
...

kd> !vad <specific_VAD_addr> 1    ; Chi tiết 1 VAD node
VAD @ ffff...
  StartingVpn:   7ff64321  EndingVpn:   7ff64345
  Flags:         VadImageMap, Protection = EXECUTE_WRITECOPY
  ControlArea:   ffff...
  FileObject:    ffff...   \Windows\System32\notepad.exe
  Commit Charge: 36 pages
```

**Ứng dụng bảo mật:** VAD analysis là kỹ thuật quan trọng trong malware analysis:
- Code injection: tìm VAD với `PAGE_EXECUTE_READWRITE` + `PrivateMemory=1` (nghi ngờ shellcode)
- Hollowed process: VAD `VadImageMap` nhưng nội dung đã bị thay đổi
- Hidden allocation: so sánh VAD tree với thực tế PTE mapping

---

## 5.3 Address Translation

### 5.3.1 x64 4-Level Page Table

```
Virtual Address (48-bit):
┌────────┬────────┬────────┬────────┬──────────┐
│ PML4   │ PDPT   │  PD    │  PT    │  Offset  │
│(9 bits)│(9 bits)│(9 bits)│(9 bits)│(12 bits) │
│[47:39] │[38:30] │[29:21] │[20:12] │[11:0]    │
└───┬────┴───┬────┴───┬────┴───┬────┴────┬─────┘
    │        │        │        │         │
    ▼        ▼        ▼        ▼         │
┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐ │
│PML4E  │→│PDPTE  │→│ PDE   │→│ PTE   │─┘
│Table  │ │Table  │ │Table  │ │Table  │ Physical
│(512)  │ │(512)  │ │(512)  │ │(512)  │ Page
└───────┘ └───────┘ └───────┘ └───────┘ Frame

CR3 register → PML4 Table physical address (per-process)
```

**Page Table Entry (PTE) format:**

```
63                                                    0
┌─┬─┬──────────────────────────┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┐
│X│ │   Physical Frame Number  │G│ │D│A│C│T│U│W│P│ │ │
│D│ │   (bits 51:12)           │ │ │ │ │D│ │S│R│ │ │ │
└─┴─┴──────────────────────────┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┘
 │                                  │ │ │ │ │ │ │ │ └─ Present (1=in RAM)
 │                                  │ │ │ │ │ │ │ └─── Read/Write
 │                                  │ │ │ │ │ │ └───── User/Supervisor
 │                                  │ │ │ │ │ └─────── Write-Through
 │                                  │ │ │ │ └───────── Cache Disabled
 │                                  │ │ │ └─────────── Accessed
 │                                  │ │ └───────────── Dirty
 │                                  │ └─────────────── Global (not flushed on CR3 switch)
 └──────────────────────────────────────────────────── NX (No Execute)
```

### 5.3.2 Translation Look-aside Buffer (TLB)

TLB cache virtual→physical address translations:

```
Virtual Address ──→ TLB Lookup
                     │
                TLB Hit? ──Yes──→ Physical Address (fast, ~1 ns)
                     │
                    No (TLB Miss)
                     │
                     ▼
                Page Table Walk (4 memory accesses, ~100 ns)
                     │
                     ▼
                TLB Entry Created
                     │
                     ▼
                Physical Address
```

**TLB Flush triggers:**
- `CR3` reload (process context switch)
- `invlpg` instruction (single page invalidation)
- IPI TLB shootdown (multiprocessor)

**PCID optimization:** mỗi process có 12-bit ID, TLB entries tagged → no flush on switch.

### 5.3.3 Large Page Translation

```
For 2 MB large pages:
Virtual Address → PML4 → PDPT → PDE (with PS bit set)
                                  └→ Direct 2MB mapping (no PT level)

For 1 GB huge pages:
Virtual Address → PML4 → PDPTE (with PS bit set)
                           └→ Direct 1GB mapping (no PD, no PT)
```

### 5.3.4 CR3 và KPROCESS.DirectoryTableBase

Mỗi process có page table riêng. Địa chỉ physical của PML4 table được lưu trong:

```
KPROCESS (nằm trong EPROCESS):
  +0x028 DirectoryTableBase : Uint8B   ← Physical address của PML4

Khi context switch:
  1. Scheduler chọn process mới
  2. Load KPROCESS.DirectoryTableBase vào thanh ghi CR3
  3. CPU từ đó dùng PML4 mới để translate addresses
  4. TLB bị flush (trừ khi dùng PCID)

kd> !process 0 0 notepad.exe
PROCESS ffff8a0123456780
    ...
    DirBase: 1a2b3000        ← Physical address của PML4 table
    ...

kd> r cr3
cr3=000000001a2b3000          ← Trùng với DirBase của current process
```

**KPTI (Kernel Page Table Isolation) và CR3:**

```
Từ Windows 10 1709+ (Meltdown mitigation, patched Jan 2018):
  Mỗi process có 2 page tables:
  
  ┌─────────────────────────────┐
  │ User CR3 (DirBase | 0x02)    │ ← Dùng khi chạy user mode
  │ Chỉ map user pages +         │    Kernel pages KHÔNG có mặt
  │ minimal kernel entry points  │    (trừ shadow mapping)
  ├─────────────────────────────┤
  │ Kernel CR3 (DirectoryTableBase)│ ← Dùng khi chạy kernel mode  
  │ Map cả user + kernel pages   │    Full kernel address space
  └─────────────────────────────┘
  
  Syscall/interrupt entry:
    1. Swap CR3 từ User → Kernel (bit 1 cleared)
    2. Execute kernel code
    3. Swap CR3 từ Kernel → User (bit 1 set)
    4. Return to user mode
```

### 5.3.5 Self-Referencing Page Table (PTE_BASE)

Windows sử dụng thủ thuật **self-referencing** để truy cập các page table entries mà không cần biết địa chỉ physical:

```
Nguyên lý:
  Một entry trong PML4 table trỏ ngược về chính PML4 table

  PML4[idx_self] = physical address của PML4 table
  
  Khi CPU translate address dùng index này:
    PML4 → PML4 (vì self-reference)
    → PDPT entry được đọc NHƯ LÀ PDE
    → PD entry được đọc NHƯ LÀ PTE
    → "Data" chính là nội dung page table!

Mapping (x64, 48-bit):
  PTE_BASE      = 0xFFFFF680'00000000
  PDE_BASE      = 0xFFFFF6FB'40000000
  PPE_BASE      = 0xFFFFF6FB'7DA00000
  PXE_BASE      = 0xFFFFF6FB'7DBED000

Tính PTE address từ virtual address:
  PTE_address = PTE_BASE + (VA >> 12) * 8
  PDE_address = PDE_BASE + (VA >> 21) * 8
  PPE_address = PPE_BASE + (VA >> 30) * 8
  PXE_address = PXE_BASE + (VA >> 39) * 8

Ví dụ: VA = 0x00007FF6'43210000
  PTE = PTE_BASE + (0x7FF643210 * 8) = 0xFFFFF6FB'E3219080
```

**Lưu ý bảo mật:** Từ Windows 10 1607, PTE_BASE được **randomize** mỗi lần boot để chống kernel exploit. Attacker không còn biết trước PTE_BASE.

```
kd> ? poi(nt!MmPteBase)
Evaluate expression: -10486036774912 = fffff680`00000000    ; (trước randomization)

; Sau randomization, mỗi boot sẽ khác
kd> ? poi(nt!MmPteBase)  
Evaluate expression: ... = ffffXX00`00000000              ; Randomized
```

### 5.3.6 Chi Tiết Định Dạng PTE (Các Trạng Thái)

PTE không chỉ có 2 trạng thái (present/not-present). Windows sử dụng nhiều trạng thái khác nhau:

```
1. VALID PTE (Present = 1):
63    62    51-12           11-9  8  7  6  5  4  3  2  1  0
┌──┬──┬────────────────┬─────┬──┬──┬──┬──┬──┬──┬──┬──┬──┐
│NX│  │ Physical PFN   │AvSW │G │PS│D │A │CD│WT│US│RW│ 1│
└──┴──┴────────────────┴─────┴──┴──┴──┴──┴──┴──┴──┴──┴──┘
  │                      │     │  │  │  │  │  │  │  │  └ Present=1
  │                      │     │  │  │  │  │  │  │  └── Read/Write
  │                      │     │  │  │  │  │  │  └───── User/Supervisor
  │                      │     │  │  │  │  │  └──────── Write-Through
  │                      │     │  │  │  │  └─────────── Cache Disabled
  │                      │     │  │  │  └────────────── Accessed
  │                      │     │  │  └───────────────── Dirty
  │                      │     │  └──────────────────── Page Size (large page)
  │                      │     └─────────────────────── Global
  │                      └── Available for Software (Windows dùng cho WS info)
  └─── No Execute (NX/XD bit)

2. TRANSITION PTE (Present = 0, Transition = 1):
63    62    51-12          11  10   4   3   2   1   0
┌──┬──┬────────────────┬───┬───┬───┬───┬───┬───┬───┐
│NX│  │ Physical PFN   │ T │Pro│ W │   │   │   │ 0 │
└──┴──┴────────────────┴───┴───┴───┴───┴───┴───┴───┘
  Page vẫn còn trong RAM (standby/modified list)
  T = Transition bit = 1
  Pro = Prototype bit = 0
  Chỉ cần re-validate PTE → soft fault

3. PAGE FILE PTE (Present = 0, Transition = 0, Prototype = 0):
63-32              31-12                11  10    4-0
┌────────────────┬──────────────────┬───┬───┬───────┐
│ PageFile Offset│  PageFile Offset │ 0 │ 0 │Protect│
│ (high bits)    │  (bits 31:12)    │   │   │       │
└────────────────┴──────────────────┴───┴───┴───────┘
  Page đã bị page out → cần đọc từ pagefile
  PageFile Offset chỉ vị trí trong pagefile
  Hard fault required

4. DEMAND ZERO PTE:
┌────────────────────────────────────────────────────┐
│ All zeros except Protection bits                    │
│ PageFileOffset = 0, Present = 0, Trans = 0, Proto = 0│
└────────────────────────────────────────────────────┘
  First access → allocate zeroed page → soft fault

5. PROTOTYPE PTE (Present = 0, Prototype = 1):
63-16                              11  10   4-0
┌──────────────────────────────┬───┬───┬───────┐
│ Prototype PTE Address         │   │ 1 │Protect│
│ (index into prototype array)  │   │   │       │
└──────────────────────────────┴───┴───┴───────┘
  Shared page (DLL, mapped file)
  Cần resolve qua prototype PTE để tìm physical page
```

### 5.3.7 Large Page (2 MB) và Huge Page (1 GB) PDE Format

```
Large Page PDE (2 MB): PS bit = 1 trong Page Directory Entry
63    62    51-21              12  8  7  6  5  4  3  2  1  0
┌──┬──┬────────────────────┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┐
│NX│  │ Physical Base (2MB)│PA│G │PS│D │A │CD│WT│US│RW│ P│
│  │  │ aligned to 2MB     │T │  │=1│  │  │  │  │  │  │  │
└──┴──┴────────────────────┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┘
  Bits [20:12] = reserved (phải = 0)
  Bits [51:21] = Physical address >> 21 (2MB aligned)
  Không có Page Table level → TLB chỉ cần 3 lookups

Huge Page PDPTE (1 GB): PS bit = 1 trong PDPT Entry
63    62    51-30              12  8  7  6  5  4  3  2  1  0
┌──┬──┬────────────────────┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┐
│NX│  │ Physical Base (1GB)│PA│G │PS│D │A │CD│WT│US│RW│ P│
│  │  │ aligned to 1GB     │T │  │=1│  │  │  │  │  │  │  │
└──┴──┴────────────────────┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┘
  Bits [29:12] = reserved
  Bits [51:30] = Physical address >> 30 (1GB aligned)
  TLB chỉ cần 2 lookups

Bộ nhớ cho Page Table pages:
  4-level page table cho 128 TB address space:
  - 1 PML4 page         = 4 KB
  - 512 PDPT pages      = 2 MB    (tối đa)
  - 512*512 PD pages    = 1 GB    (tối đa)
  - 512^3 PT pages      = 512 GB  (tối đa)
  
  Thực tế: chỉ allocate page table pages cho regions ĐANG ĐƯỢC SỬ DỤNG
  Process nhỏ: ~10-50 page table pages (40-200 KB)
  Process lớn: ~1000-5000 page table pages (4-20 MB)
```

---

## 5.4 Page Fault Handling

### 5.4.1 Page Fault Flow

```
CPU accesses virtual address
    │
    ├── PTE Present = 1 → Normal access (no fault)
    │
    └── PTE Present = 0 → #PF exception → nt!KiPageFault
                              │
            ┌─────────────────┤
            │                 │
      MmAccessFault()    MmCheckForInvalidAddress()
            │
            ▼
    ┌───────────────────────────────────────────┐
    │ Classify fault:                            │
    │                                           │
    │ 1. Valid fault (demand paging)             │
    │    - First access to committed page        │
    │    - → Allocate physical page              │
    │    - → Map PTE, resume                     │
    │                                           │
    │ 2. Page file fault                         │
    │    - Page was paged out to disk            │
    │    - → Read from pagefile                  │
    │    - → Map PTE, resume                     │
    │                                           │
    │ 3. Copy-on-Write fault                     │
    │    - Write to shared/CoW page              │
    │    - → Copy page to private                │
    │    - → Update PTE, resume                  │
    │                                           │
    │ 4. Standby/Modified transition             │
    │    - Page in standby/modified list         │
    │    - → Re-validate PTE (soft fault)        │
    │    - → Very fast (no I/O)                  │
    │                                           │
    │ 5. Prototype PTE fault                     │
    │    - Shared section (DLL, mapped file)      │
    │    - → Resolve via prototype PTE            │
    │                                           │
    │ 6. Guard page fault                        │
    │    - Stack growth                          │
    │    - → Commit next guard page              │
    │                                           │
    │ 7. Access violation                        │
    │    - Invalid address / wrong protection     │
    │    - → STATUS_ACCESS_VIOLATION exception   │
    └───────────────────────────────────────────┘
```

### 5.4.2 MmAccessFault Chi Tiết: 12+ Loại Page Fault

`MmAccessFault` là hàm chính xử lý mọi page fault. Dưới đây là flowchart chi tiết:

```
MmAccessFault(FaultStatus, VirtualAddress, PreviousMode, TrapFrame)
    │
    ├── 1. Kiểm tra address có canonical không
    │      Non-canonical → BUGCHECK (kernel) hoặc AV (user)
    │
    ├── 2. Tìm VAD chứa VirtualAddress
    │      Không tìm thấy → ACCESS_VIOLATION
    │
    ├── 3. Đọc PTE chain (PXE → PPE → PDE → PTE)
    │
    └── 4. Phân loại dựa trên PTE state:
         │
         ├─[A] PTE = 0 (Demand Zero)
         │    Và VAD cho phép access
         │    → MiResolveDemandZeroFault()
         │    → Lấy page từ zeroed list (hoặc free list + zero)
         │    → Ghi PTE với PFN mới, set Valid=1
         │    → Soft fault (~1-5 us)
         │
         ├─[B] PTE Valid=0, Transition=1, Prototype=0
         │    (Transition Fault - page trong standby/modified list)
         │    → MiResolveTransitionFault()
         │    → Tìm page trong PFN database
         │    → Remove từ standby/modified list
         │    → Set PTE Valid=1 (re-validate)
         │    → Soft fault (~1 us, nhanh nhất)
         │
         ├─[C] PTE Valid=0, Transition=0, Prototype=0, PageFileOffset != 0
         │    (Page File Fault)
         │    → MiResolvePageFileFault()
         │    → Allocate physical page
         │    → Đọc từ pagefile (I/O request)
         │    → Copy data vào physical page
         │    → Update PTE
         │    → Hard fault (~5-15 ms với HDD, ~0.1 ms với SSD)
         │
         ├─[D] PTE Valid=0, Prototype=1
         │    (Prototype PTE Fault - shared page)
         │    → MiResolveProtoPteFault()
         │    → Tìm prototype PTE
         │    ├── Proto PTE valid → share physical page
         │    ├── Proto PTE transition → reclaim từ list
         │    ├── Proto PTE pagefile → đọc từ pagefile
         │    └── Proto PTE demand-zero → allocate new page
         │    → Update process PTE trỏ tới physical page
         │
         ├─[E] Copy-on-Write Fault
         │    PTE Valid=1, Write access, PTE.CopyOnWrite=1
         │    → MiCopyOnWrite()
         │    → Allocate page mới
         │    → Copy nội dung từ original page
         │    → Update PTE trỏ tới page mới, set Private
         │    → Giảm ShareCount của original page
         │    → Soft fault (~2-5 us)
         │
         ├─[F] Guard Page Fault
         │    VAD có PAGE_GUARD flag
         │    → MiCheckForGuardPageFault()
         │    → Commit trang guard page
         │    → Đặt guard page MỚI phía sau (stack growth)
         │    → Raise STATUS_GUARD_PAGE_VIOLATION
         │    → Dùng cho stack auto-growth
         │
         ├─[G] Write Protection Fault
         │    PTE Valid=1, Write access, PTE.ReadWrite=0
         │    → Kiểm tra VAD protection
         │    → Nếu VAD cho phép write → lỗi PTE (nên xảy ra với CoW)
         │    → Nếu VAD không cho phép → ACCESS_VIOLATION
         │
         ├─[H] Execute Disable (NX) Fault
         │    PTE Valid=1, Execute access, PTE.NX=1
         │    → STATUS_ACCESS_VIOLATION
         │    → DEP enforcement: ngăn chạy code từ data pages
         │    → Quan trọng cho security (buffer overflow protection)
         │
         ├─[I] In-Page Error
         │    Hard fault nhưng I/O FAIL (disk error, network error)
         │    → STATUS_IN_PAGE_ERROR (0xC0000006)
         │    → Kernel: BUGCHECK KERNEL_DATA_INPAGE_ERROR (0x7A)
         │    → User: exception delivered to process
         │
         ├─[J] Mapped File Fault
         │    Page từ memory-mapped file (không phải pagefile)
         │    → MiResolveMappedFileFault()
         │    → Đọc từ file gốc (section object → file object)
         │    → Hard fault nhưng từ file, không phải pagefile
         │
         ├─[K] Compressed Page Fault (Windows 10+)
         │    Page đã bị compressed (trong compression store)
         │    → Đọc từ compressed store
         │    → Decompress (Xpress/Huffman)
         │    → Nhanh hơn pagefile (~0.01 ms)
         │
         └─[L] Collided Page Fault
              Nhiều threads fault trên cùng 1 page CÙNG LÚC
              → Thread đầu tiên xử lý fault
              → Các threads khác WAIT cho đến khi page ready
              → MiWaitForInPageComplete()
              → Tránh duplicate I/O reads
```

**Fault Resolution Summary:**

| Loại | I/O? | Latency | PTE trước | PTE sau |
|------|------|---------|-----------|---------|
| Demand Zero | Không | ~1-5 us | All zeros | Valid + PFN |
| Transition | Không | ~1 us | Trans=1, PFN | Valid + PFN |
| Copy-on-Write | Không | ~2-5 us | Valid, CoW | Valid, Private |
| Guard Page | Không | ~2 us | Guard flag | Valid, new Guard |
| Compressed | Không | ~10 us | Compressed ref | Valid + PFN |
| Page File | Có | ~0.1-15 ms | PageFile offset | Valid + PFN |
| Mapped File | Có | ~0.1-15 ms | Proto PTE | Valid + PFN |
| Access Violation | N/A | Exception | N/A | Không thay đổi |

### 5.4.3 Soft vs Hard Page Faults

| Type | I/O Required? | Latency | Cause |
|------|--------------|---------|-------|
| **Soft fault** | No | ~1-10 μs | Page in standby/modified list, demand zero |
| **Hard fault** | Yes (disk read) | ~5-15 ms | Page in pagefile or mapped file |
| **Transition fault** | No | ~1 μs | Page being transitioned between lists |

**Soft fault** = page vẫn trong RAM nhưng PTE đã bị invalidate (ví dụ: working set trimming). Chỉ cần update PTE.

**Hard fault** = page phải đọc từ disk. Rất expensive — 1000x chậm hơn soft fault.

---

## 5.5 Page Files

### 5.5.1 Pagefile Mechanism

```
Commit Charge Flow:

VirtualAlloc(MEM_COMMIT)
    │
    ├── Increase process commit charge
    ├── Increase system commit charge
    ├── Check: total commit ≤ commit limit?
    │   ├── Yes → Success (page NOT allocated yet — demand paging)
    │   └── No → STATUS_COMMITMENT_LIMIT → grows pagefile or fails
    │
    └── Page physically allocated only on FIRST ACCESS (page fault)
```

**Commit Charge vs Physical Memory:**

```
Committed Memory:     8 GB  ← "Promise" rằng memory sẽ có nếu cần
Physical RAM used:    4 GB  ← Thực tế đang dùng
Pagefile space:       2 GB  ← Đã page out to disk
Not yet accessed:     2 GB  ← Committed nhưng chưa access lần nào

Commit Limit = RAM + Pagefile sizes
```

### 5.5.2 Pagefile Configuration

```
Default: 1 pagefile, managed size (min = RAM, max = 3 × RAM hoặc 4GB, whichever larger)
Location: C:\pagefile.sys (hidden, system)

Registry: HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management
  PagingFiles: C:\pagefile.sys 4096 8192    (min 4GB, max 8GB)
  
Multiple pagefiles:
  C:\pagefile.sys 4096 8192
  D:\pagefile.sys 2048 4096    ← Spread I/O across disks
```

**[UPDATE 2026]** Recommendations:
- SSD: pagefile trên SSD giảm hard fault latency 10-100x
- Server: fixed size (min = max) tránh fragmentation
- RAM ≥ 32 GB: có thể disable pagefile nếu workload phù hợp (nhưng không recommended — crash dumps cần pagefile)

---

## 5.6 Kernel Memory Pools

### 5.6.1 Pool Types

```
┌─────────────────────────────────────────────────────────┐
│                    NONPAGED POOL                         │
│  - Luôn resident trong RAM (never paged out)            │
│  - Dùng cho: DPC, ISR, spinlock-held code               │
│  - Accessible tại IRQL ≥ DISPATCH_LEVEL                  │
│  - Expensive — giữ physical pages permanently            │
│  - Ví dụ: NDIS buffers, IRP, MDL                        │
├─────────────────────────────────────────────────────────┤
│                     PAGED POOL                           │
│  - Có thể bị page out to disk                            │
│  - CHỈ accessible tại IRQL < DISPATCH_LEVEL              │
│  - Cheaper — virtual memory backed                       │
│  - Ví dụ: Registry data, security descriptors, paths     │
└─────────────────────────────────────────────────────────┘
```

### 5.6.2 Pool Allocation

```c
// Kernel pool allocation
PVOID buffer = ExAllocatePool2(
    POOL_FLAG_NON_PAGED,    // Hoặc POOL_FLAG_PAGED
    1024,                    // Size in bytes
    'tseT'                   // 4-byte pool tag (reversed: "Test")
);

// Free
ExFreePoolWithTag(buffer, 'tseT');
```

**[UPDATE 2026]** `ExAllocatePoolWithTag` deprecated → dùng `ExAllocatePool2`:

| Old API | New API (Win10 2004+) |
|---------|----------------------|
| `ExAllocatePoolWithTag(NonPagedPool, ...)` | `ExAllocatePool2(POOL_FLAG_NON_PAGED, ...)` |
| `ExAllocatePoolWithTag(PagedPool, ...)` | `ExAllocatePool2(POOL_FLAG_PAGED, ...)` |
| `ExAllocatePoolWithTag(NonPagedPoolNx, ...)` | `ExAllocatePool2(POOL_FLAG_NON_PAGED, ...)` |

`ExAllocatePool2` mặc định zero-initialize và non-executable (NX).

### 5.6.3 Pool Tags

Mỗi allocation tagged với 4-byte identifier → debug memory leaks:

```
kd> !poolused 2                      ; Sort by usage
kd> !poolused 4                      ; Sort by nonpaged usage

 Tag   Type  Paged    NonPaged    #Allocs
 Ntff  Paged  123456     0         1234    ← NTFS file object
 MmSt  NP     0        567890      890     ← Memory Manager
 Thre  NP     0        234567      456     ← Thread objects
 Proc  NP     0        345678      234     ← Process objects
 FMfn  Paged  456789     0         567     ← Filter Manager

kd> !pooltag Ntff                    ; Find driver for tag
```

**PoolMon** (SDK tool):
```cmd
poolmon.exe -b              ; Sort by bytes
poolmon.exe -p              ; Show paged pool
poolmon.exe -t Ntff         ; Filter by tag
```

### 5.6.4 Pool Sizes

```
kd> !vm

*** Virtual Memory Usage ***
 Physical Memory:    16773752 (   67095008 Kb)
 Page File: \??\C:\pagefile.sys
   Current:  8388608 Kb  Free Space:  8123456 Kb
   
 NonPaged Pool Usage:      123456 (     493824 Kb)
 Paged Pool Usage:         234567 (     938268 Kb)

NonPaged Pool default limit (x64):
  RAM < 2 GB:  75% of RAM hoặc 2 GB (smaller)
  RAM ≥ 2 GB:  RAM-size dependent, max ~128 GB
  
Paged Pool default limit (x64):
  2 × RAM hoặc 384 GB (smaller)
```

### 5.6.5 Lookaside Lists

Lookaside lists = per-processor free lists cho fixed-size allocations:

```
Mục đích: tránh pool lock contention cho frequent small allocations

Lookaside List (per-CPU):
┌────┬────┬────┬────┬────┐
│Free│Free│Free│Free│    │ ← Pre-allocated blocks
│Blk │Blk │Blk │Blk │    │
└────┴────┴────┴────┴────┘
  ↑ ExAllocateFromLookasideListEx → rất nhanh, no lock
  ↓ ExFreeToLookasideListEx → return to list

Nếu list empty → fallback tới ExAllocatePool2
Nếu list full → fallback tới ExFreePoolWithTag
```

### 5.6.6 Pool Header Structure

Mỗi pool allocation có header (_POOL_HEADER) 16 bytes phía trước:

```
_POOL_HEADER (16 bytes trên x64):
┌──────────────────────────────────────────────────────┐
│ Offset  Field             Size    Mô tả              │
├──────────────────────────────────────────────────────┤
│ +0x000  PreviousSize      8 bits  Kích thước block trước/16│
│         PoolIndex         8 bits  Pool descriptor index │
│         BlockSize         8 bits  Kích thước block/16   │
│         PoolType          8 bits  Paged/NonPaged/flags  │
│ +0x004  PoolTag           ULONG   4-byte tag identifier │
│ +0x008  ProcessBilled     PTR     Process bị charge     │
│         (hoặc AllocatorBackTraceIndex + PoolTagHash)    │
└──────────────────────────────────────────────────────┘

Allocation layout trong memory:
┌────────────┬──────────────────────────┬────────────┐
│POOL_HEADER │   Caller's Data          │  Padding   │
│  (16 bytes)│   (requested size)       │ (alignment)│
└────────────┴──────────────────────────┴────────────┘
     ^              ^
     │              └── Con trỏ trả về cho caller
     └── Header ẩn trước data

kd> !pool <address>
Pool page ffff8a01`23456780 region is Nonpaged pool
  ffff8a01`23456760 size:   80 previous size:   40  (Allocated) Thre
                     ← PoolTag = "Thre" (Thread object)
  ffff8a01`234567e0 size:   40 previous size:   80  (Free)      ....
```

### 5.6.7 Special Pool (Debug)

Special Pool phát hiện buffer overrun và underrun:

```
Enable Special Pool cho 1 tag:
  gflags.exe /r +spp              ; Enable special pool system-wide
  
Registry:
  HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management
    PoolTag = 0x74736554          ; "Test" tag → special pool

Overrun Detection (default):
┌──────────┬──────────────────┬────────────┐
│ Filler   │  Allocation      │ Guard Page │
│ (pattern)│  (caller data)   │ (NO ACCESS)│
└──────────┴──────────────────┴────────────┘
                                    ^
                                    └── Overrun 1 byte → IMMEDIATE bugcheck
                                        SPECIAL_POOL_DETECTED_MEMORY_CORRUPTION

Underrun Detection:
┌────────────┬──────────────────┬──────────┐
│ Guard Page │  Allocation      │ Filler   │
│ (NO ACCESS)│  (caller data)   │ (pattern)│
└────────────┴──────────────────┴──────────┘
  ^
  └── Underrun 1 byte → IMMEDIATE bugcheck

Verify tool:
  verifier.exe /driver mydriver.sys /flags 0x1    ; Special pool cho driver
```

### 5.6.8 Pool Security Mitigations

```
Pool Security (tiến hóa qua các version Windows):

1. Pool Tag Enforcement (Vista+):
   - Mỗi allocation PHẢI có tag
   - ExAllocatePool (không tag) → deprecated, removed

2. Safe Unlinking (Win7+):
   - Verify forward/backward links trước khi unlink free block
   - Ngăn heap corruption exploit (unlink attack)
   Validate: entry->Flink->Blink == entry
             entry->Blink->Flink == entry

3. NonPaged Pool NX - NpNx (Win8+):
   - Tách NonPagedPool thành 2:
     NonPagedPool      → executable (legacy, cho drivers cũ)
     NonPagedPoolNx    → non-executable (default cho drivers mới)
   - ExAllocatePool2 luôn trả về NX memory
   - Ngăn kernel exploit execute shellcode từ pool

4. Pool Randomization (Win8+):
   - Randomize thứ tự allocation trong pool pages
   - Ngăn attacker dự đoán vị trí allocation

5. Pool Overflow Detection (Win10+):
   - Random canary/cookie trong pool header
   - Phát hiện corruption khi free

6. Kernel Pool Quota:
   - Mỗi process có giới hạn pool usage
   - EPROCESS.QuotaBlock → PagedPoolUsage, NonPagedPoolUsage
   - Ngăn 1 process exhaust tất cả kernel pool

kd> !process 0 0 notepad.exe
    ...
    QuotaPoolUsage[PagedPool]:   123456
    QuotaPoolUsage[NonPagedPool]: 78901
    ...
```

**ExAllocatePool2 vs Legacy APIs:**

```c
// Legacy (deprecated):
PVOID p1 = ExAllocatePoolWithTag(NonPagedPool, 100, 'tseT');
// → Executable memory! Security risk

PVOID p2 = ExAllocatePoolWithTag(NonPagedPoolNx, 100, 'tseT');
// → NX memory, nhưng không zero-init

// Modern (recommended, Win10 2004+):
PVOID p3 = ExAllocatePool2(POOL_FLAG_NON_PAGED, 100, 'tseT');
// → NX + zero-initialized by default
// → Caller phải opt-in executable: POOL_FLAG_NON_PAGED_EXECUTE

// Flags:
//   POOL_FLAG_PAGED              = 0x0000000000000001
//   POOL_FLAG_NON_PAGED          = 0x0000000000000040 (NX)
//   POOL_FLAG_NON_PAGED_EXECUTE  = 0x0000000000000080
//   POOL_FLAG_RAISE_ON_FAILURE   = 0x0000000000000020
//   POOL_FLAG_UNINITIALIZED      = 0x0000000000000002
```

---

## 5.7 Heap Manager

### 5.7.1 Heap Types

Windows có 3 heap implementations:

```
┌─────────────────────────────────────────────────┐
│              User-Mode Heap Manager              │
│                                                  │
│  ┌──────────────┐  ┌──────────────────────────┐ │
│  │ NT Heap       │  │ Segment Heap (mới)       │ │
│  │ (legacy)      │  │ └── Low-Frag Heap (LFH)  │ │
│  │ └── LFH       │  │ └── Variable-size        │ │
│  │ └── VS alloc  │  │ └── Large blocks (VirtualAlloc)│ │
│  └──────────────┘  └──────────────────────────┘ │
│                                                  │
│  Process default heap + additional heaps         │
│  HeapCreate() / HeapAlloc() / HeapFree()         │
│  malloc/free = CRT → HeapAlloc/HeapFree          │
└─────────────────────────────────────────────────┘
```

**[UPDATE 2026]** Segment Heap là default cho:
- UWP apps (từ Windows 10 1709)
- Mọi processes (Windows 11, opt-in via Image File Execution Options hoặc default)
- System processes

### 5.7.2 NT Heap Architecture

```
Heap Handle → _HEAP structure
├── Segments[]                    ← Memory segments
│   ├── Segment 0 (initial)
│   │   ├── Free list entries
│   │   └── Allocated blocks
│   ├── Segment 1 (growth)
│   └── ...
├── FreeLists                     ← Free block lists (by size)
├── FrontEndHeap → LFH            ← Low Fragmentation Heap
│   ├── Buckets[128]              ← Size-class buckets
│   │   ├── Bucket 1: 1-16 bytes
│   │   ├── Bucket 2: 17-32 bytes
│   │   ├── ...
│   │   └── Bucket 128: up to 16 KB
│   └── Subsegments               ← Per-bucket allocator
├── LockVariable                  ← Heap lock
├── Flags                         ← HEAP_NO_SERIALIZE, etc.
└── TotalFreeSize                 ← Total free bytes
```

### 5.7.3 Low-Fragmentation Heap (LFH)

Giải quyết fragmentation cho small allocations:

```
LFH Bucket (e.g., 16-byte blocks):
┌────┬────┬────┬────┬────┬────┬────┬────┐
│Used│Free│Used│Used│Free│Used│Free│Used│
│ 16B│ 16B│ 16B│ 16B│ 16B│ 16B│ 16B│ 16B│
└────┴────┴────┴────┴────┴────┴────┴────┘

Subsegment:
- Fixed-size blocks
- Bitmap tracks free/used
- Randomized allocation order (ASLR cho heap)
- Lock-free for single-CPU (InterlockedCompareExchange)
```

**LFH activation:** automatic khi heap detects pattern of same-size allocations.

### 5.7.4 Heap Security

| Feature | Mô tả |
|---------|--------|
| Encoded free list pointers | Mã hóa forward/backward pointers bằng XOR cookie |
| Guard pages | Random guard pages inserted |
| Allocation randomization | LFH randomize order → mitigate heap spray |
| RtlpHeapProtectFreedAllocations | Decommit freed memory on large heaps |
| Heap metadata validation | Detect corruption early |
| UST (User Stack Trace) | Record stack trace per allocation (debug) |

### 5.7.5 Heap Debugging

```cmd
:: Enable Page Heap (full page heap)
gflags.exe /p /enable myapp.exe /full

:: Result: mỗi allocation có guard page riêng
:: Buffer overflow → IMMEDIATE access violation (không chờ free)
:: Cost: ~10x memory overhead

:: Disable
gflags.exe /p /disable myapp.exe
```

```
;; WinDbg
0:000> !heap -s                  ; Heap summary
0:000> !heap -a <heap_addr>      ; Detailed heap info
0:000> !heap -flt s 1024         ; Find 1024-byte allocations
0:000> !heap -l                  ; Detect leaks
0:000> !heap -p -a <addr>        ; Page heap info for address
```

---

## 5.8 Working Sets

### 5.8.1 Concept

Working set = set of physical pages currently mapped cho process:

```
Process Virtual Address Space:
┌──────────────────────────────────────────┐
│ ████░░░░████████░░░░░░██████░░░░░░░░░░  │
│ In WS    Not in WS   In WS               │
└──────────────────────────────────────────┘

████ = In Working Set (resident, PTE valid)
░░░░ = Not in WS (committed nhưng paged out hoặc chưa accessed)
```

### 5.8.2 Working Set Management

```
Per-Process Working Set:
├── MinimumWorkingSetSize (default: 50 pages)
│   ← Guaranteed pages, không bị trim dưới mức này
├── MaximumWorkingSetSize (default: 345 pages)
│   ← Soft limit, trimmer targets này khi memory pressure
├── CurrentSize
│   ← Số pages hiện tại trong WS
└── PeakWorkingSetSize
    ← Maximum đã đạt được

Working Set Trimming:
  Memory pressure detected
    → Balance Set Manager kích hoạt WS trimmer
    → Trimmer duyệt processes (aging algorithm)
    → Pages không dùng gần đây → trimmed (PTE invalidated)
    → Pages vào Standby list (vẫn trong RAM, có thể reclaim)
```

### 5.8.3 Aging Algorithm

```
Mỗi PTE có Accessed bit (bit 5):

CPU set Accessed = 1 khi page được access
Working Set Manager periodically:
  1. Clear Accessed bit trên tất cả PTEs
  2. Đợi aging period
  3. Check Accessed bit:
     - Bit = 1 → Page được dùng → giữ lại
     - Bit = 0 → Page không dùng → candidate for trimming
  4. Trim candidates → page chuyển từ WS sang Standby list
```

### 5.8.4 Working Set List Structure

```
Working Set List (_MMWSL):
┌──────────────────────────────────────────────────────────┐
│ FirstFree          : Index của first free WSLE           │
│ FirstDynamic       : Index bắt đầu của dynamic entries   │
│ LastEntry          : Index cuối cùng                     │
│ NextSlot           : Vị trí hiện tại của aging scanner   │
│ NumberOfCommittedPageTables                               │
│ HashTable          : Hash table để lookup nhanh VA→WSLE  │
│                                                          │
│ Wsle[] array:                                            │
│ ┌──────────────────────────────────────────────────────┐ │
│ │ WSLE[0]: VirtualAddress=0x7FF643210, Age=3, Locked  │ │
│ │ WSLE[1]: VirtualAddress=0x7FFA12340, Age=0          │ │
│ │ WSLE[2]: (free)                                     │ │
│ │ WSLE[3]: VirtualAddress=0x1A00000,   Age=2          │ │
│ │ ...                                                 │ │
│ └──────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘

Working Set List Entry (WSLE) format:
  Bits [63:12]: Virtual Page Number
  Bits [3:2]:   Age (0-3, 0=mới dùng, 3=lâu không dùng)
  Bit  [1]:     LockedInWs (không bị trim)
  Bit  [0]:     LockedInMemory (MDL locked)
```

### 5.8.5 Age-Based Trimming Chi Tiết

```
Aging Process (Balance Set Manager, mỗi ~1 giây):

  Round 0: Clear Accessed bit trên tất cả PTEs trong working set
  
  Round 1: Kiểm tra Accessed bit
    Accessed=1 → Age = 0 (reset, page được dùng)
    Accessed=0 → Age += 1
  
  Round 2: Tiếp tục aging
    Accessed=1 → Age = 0
    Accessed=0 → Age += 1
  
  Round 3: 
    Accessed=1 → Age = 0
    Accessed=0 → Age = 3 (MAX) → Candidate for trim
  
  Trimming priority (khi memory pressure):
    1. Trim pages với Age = 3 (lâu nhất không dùng)
    2. Rồi Age = 2
    3. Rồi Age = 1
    4. Age = 0 chỉ trim khi SEVERE pressure
  
  MemoryPriority ảnh hưởng trimming order:
    Priority 0-1 (MEMORY_PRIORITY_VERY_LOW/LOW):
      → Trim TRƯỚC các process priority cao hơn
    Priority 5 (MEMORY_PRIORITY_NORMAL):
      → Trim bình thường
    Priority 7 (MEMORY_PRIORITY_HIGHEST - không có API set):
      → Trim SAU CÙNG (reserved for foreground)

API điều chỉnh working set:
  SetProcessWorkingSetSizeEx(hProcess, minSize, maxSize, flags):
    QUOTA_LIMITS_HARDWS_MIN_ENABLE  → hard minimum
    QUOTA_LIMITS_HARDWS_MAX_DISABLE → no hard maximum
```

### 5.8.6 Balance Set Manager và Memory Notifications

```
Balance Set Manager Thread (KeBalanceSetManager):
  │
  ├── Chạy trong System process (PID 4)
  ├── Priority 16 (realtime class)
  ├── Wake up mỗi ~1 giây HOẶC khi memory event
  │
  ├── Kiểm tra memory conditions:
  │   │
  │   ├── Available pages > HighMemoryThreshold
  │   │   → KeSetEvent(HighMemoryCondition)
  │   │   → Thông báo cho apps: "memory đủ, có thể dùng nhiều"
  │   │
  │   ├── Available pages < LowMemoryThreshold  
  │   │   → KeSetEvent(LowMemoryCondition)
  │   │   → Thông báo cho apps: "memory thấp, hãy giảm usage"
  │   │   → Bắt đầu aggressive working set trimming
  │   │
  │   └── Available pages < VeryLowMemoryThreshold
  │       → Modified page writer được đẩy mạnh
  │       → Compression store được đẩy mạnh
  │       → Processes bị trim mạnh hơn
  │
  └── Điều chỉnh working set min/max dynamically

Memory Notification API (user mode):
  HANDLE hLowMem = CreateMemoryResourceNotification(
      LowMemoryResourceNotification);
  
  // Wait for low memory condition
  WaitForSingleObject(hLowMem, INFINITE);
  // → Giảm cache, free unused buffers, etc.

  // Hoặc query:
  BOOL isLow;
  QueryMemoryResourceNotification(hLowMem, &isLow);

kd> !vm
  ...
  Available Pages:     1234567  (   4938268 Kb)
  Free System PTEs:    4294967295
  Modified Pages:      12345
  ...
  Low Memory Threshold:  32768 pages (128 MB)
  High Memory Threshold: 49152 pages (192 MB)
```

### 5.8.7 WinDbg: Working Set Analysis

```
kd> !wsle <EPROCESS_addr>
Working Set List @ ...
  VirtualAddress       Age  Locked
  0x00007ff6`43210000   0    Yes     ← Image page, age=0 (mới dùng)
  0x00007ffa`12340000   2    No      ← DLL page, age=2 (có thể bị trim)
  0x000001a0`00001000   0    No      ← Private page
  ...
  Total: 12345 entries
  Locked: 234 entries

kd> !process 0 0 notepad.exe
  ...
  Working Set Sizes (now,min,max)  (12345, 50, 345) (49380KB, 200KB, 1380KB)
  PeakWorkingSetSize               23456
  VirtualSize                      2345678 Kb
  PeakVirtualSize                  3456789 Kb
  ...

PowerShell:
  Get-Process notepad | Select WorkingSet64, MinWorkingSet, MaxWorkingSet,
      PeakWorkingSet64, PrivateMemorySize64
```

---

## 5.9 Page Frame Number (PFN) Database

### 5.9.1 PFN Entry

Mỗi physical page có 1 entry trong PFN database:

```
_MMPFN (1 entry per physical page)
├── ListEntry / OriginalPte        ← Link in page list / original PTE value
├── PteAddress                     ← PTE pointing to this page
├── ShareCount                     ← Number of PTEs referencing this page
├── ReferenceCount                 ← Reference count
├── PageState                      ← Active, Standby, Modified, Free, Zeroed, Bad
├── Priority                       ← Memory priority (0-7)
├── Modified                       ← Page has been written to
├── ReadInProgress / WriteInProgress
└── ...
```

### 5.9.2 Page Lists

```
Physical Page Lifecycle:

                    VirtualAlloc
                    Page Fault
                        │
   ┌────────────────────▼────────────────────┐
   │              Active                      │ ← In use by process
   │              (in working set)            │
   └────────┬──────────────────┬──────────────┘
            │ Trimmed           │ Trimmed
            │ (clean)           │ (dirty)
            ▼                   ▼
   ┌──────────────┐    ┌──────────────┐
   │   Standby    │    │  Modified    │ ← Dirty, needs write to disk
   │   List       │    │  List        │
   │ (clean cache)│    └──────┬───────┘
   └──────┬───────┘           │ Modified Page Writer
          │                   │ writes to disk
          │                   ▼
          │           ┌──────────────┐
          │           │   Standby    │ ← Now clean
          │           └──────┬───────┘
          │                  │
          └──────┬───────────┘
                 │ Memory pressure / repurpose
                 ▼
          ┌──────────────┐
          │    Free      │ ← Available but not zeroed
          └──────┬───────┘
                 │ Zero Page Thread
                 ▼
          ┌──────────────┐
          │   Zeroed     │ ← Ready for immediate use
          └──────────────┘

Soft Page Fault: Standby/Modified → Active (no I/O, fast!)
Hard Page Fault: Pagefile → Active (disk I/O, slow)
```

### 5.9.3 Memory Priority

**[UPDATE 2026]** Pages have priority 0-7:

```
Priority 7: Foreground application pages
Priority 5: Normal application pages
Priority 3: Background/prefetch pages
Priority 1: Low priority (SuperFetch speculation)
Priority 0: Lowest (will be repurposed first)

Standby list is ordered by priority:
  Repurpose lowest priority pages first
  → Foreground app pages survive longer
```

---

## 5.10 Memory Compression

**[UPDATE 2026]** Từ Windows 10, Memory Manager compress pages thay vì page out to disk:

```
Traditional paging:
  Active → Modified → Pagefile (disk I/O, ~5-15ms)

With compression:
  Active → Modified → Compressed (in-memory, ~0.01ms)
                        ├── Compression ratio: ~60%
                        ├── Stored in Memory Compression process
                        └── Only page to disk if RAM really full

Memory Compression Process (System → MemCompression):
┌───────────────────────────────────────────┐
│ Compressed Store                           │
│ ┌────────┐ ┌────────┐ ┌────────┐          │
│ │ Region │ │ Region │ │ Region │ ...      │
│ │ Pages  │ │ Pages  │ │ Pages  │          │
│ │ XPRESS │ │ XPRESS │ │ XPRESS │          │
│ │ codec  │ │ codec  │ │ codec  │          │
│ └────────┘ └────────┘ └────────┘          │
│                                           │
│ Stats:                                    │
│   Compressed: 8 GB worth of pages         │
│   Using:      3 GB of RAM                  │
│   Ratio:      37.5%                        │
│   Saved:      5 GB of pagefile I/O         │
└───────────────────────────────────────────┘
```

### 5.10.1 Compression Store Architecture

```
Memory Compression Pipeline:

Modified Page List
    │
    ▼
Compression Worker Threads (per-NUMA node)
    │
    ├── Chọn compression algorithm:
    │   ├── XPRESS (nhanh, ratio ~50-60%)
    │   ├── XPRESS + Huffman (chậm hơn, ratio ~40-50%)
    │   └── Tự động chọn dựa trên CPU load và memory pressure
    │
    ▼
Compression Store (Virtual Store Manager)
    │
    ├── Store structure:
    │   ┌──────────────────────────────────────────────┐
    │   │ Compression Store                             │
    │   │                                              │
    │   │ ┌─────────────┐ ┌─────────────┐             │
    │   │ │ Region 0    │ │ Region 1    │ ...         │
    │   │ │ ┌─────────┐ │ │ ┌─────────┐ │             │
    │   │ │ │Chunk 0  │ │ │ │Chunk 0  │ │             │
    │   │ │ │4KB→~2KB │ │ │ │4KB→~2KB │ │             │
    │   │ │ ├─────────┤ │ │ ├─────────┤ │             │
    │   │ │ │Chunk 1  │ │ │ │Chunk 1  │ │             │
    │   │ │ │4KB→~1KB │ │ │ │4KB→~3KB │ │             │
    │   │ │ └─────────┘ │ │ └─────────┘ │             │
    │   │ └─────────────┘ └─────────────┘             │
    │   │                                              │
    │   │ Metadata: page → (region, offset, comp_size) │
    │   └──────────────────────────────────────────────┘
    │
    └── Nếu RAM vẫn thấp sau compression:
        → Compressed pages có thể bị page out to pagefile
        → Double savings: compression + pagefile

Decompression on Access:
  Page fault trên compressed page
    → Tìm compressed chunk trong store (via metadata)
    → Allocate physical page
    → Decompress chunk vào physical page
    → Update PTE → valid
    → Latency: ~10-50 us (nhanh hơn pagefile I/O 100-1000x)
```

### 5.10.2 SuperFetch/SysMain Integration

```
SysMain Service (trước đây là SuperFetch):
  │
  ├── Thu thập usage patterns:
  │   ├── Apps nào thường được mở
  │   ├── Thời gian nào trong ngày
  │   ├── Files nào thường được access
  │   └── Lưu trong %SystemRoot%\Prefetch\*.pf
  │
  ├── Proactive caching:
  │   ├── Pre-load pages vào standby list (priority thấp)
  │   ├── Ưu tiên pages cho apps sắp được mở
  │   └── Standby list = disk cache
  │
  ├── Integration với Compression:
  │   ├── Compressed pages vẫn được SysMain quản lý
  │   ├── Khi app được mở lại:
  │   │   → Pages đã compressed được decompress
  │   │   → Nhanh hơn đọc từ pagefile
  │   └── SysMain quyết định khi nào compress vs page out
  │
  └── Monitoring:
      kd> !vm
        ...
        Compression: 
          Compressed:    2345678 pages (9382712 KB)
          Expanded:      4567890 pages (18271560 KB)  
          Ratio:         51.3%
          
      PowerShell:
        Get-Process "Memory Compression" | Select WorkingSet64
        # → Cho biết lượng RAM dùng cho compressed store
        
      Task Manager:
        Performance → Memory:
          In use:      12.3 GB
          Compressed:   3.2 GB
          Available:    3.5 GB
          Committed:   15.1/24.0 GB
```

---

## 5.11 Section Objects (Memory-Mapped Files)

### 5.11.1 Concept

```c
// Map file into memory
HANDLE hFile = CreateFile(L"data.bin", GENERIC_READ, ...);
HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
PVOID view = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);

// Access file as memory pointer
BYTE firstByte = ((BYTE*)view)[0];

// Unmap
UnmapViewOfFile(view);
CloseHandle(hMapping);
CloseHandle(hFile);
```

### 5.11.2 Shared Memory via Section

```
Process A:                              Process B:
┌──────────────────┐                   ┌──────────────────┐
│ Virtual Address   │                   │ Virtual Address   │
│ 0x1000'0000 ─────┼──→ Physical ←─────┼── 0x2000'0000    │
│                   │    Page Frame     │                   │
└──────────────────┘                   └──────────────────┘

Both processes see the SAME physical memory
Writes by A are visible to B (and vice versa)

Named section: CreateFileMapping(..., L"SharedMem")
Process B: OpenFileMapping(FILE_MAP_READ, FALSE, L"SharedMem")
```

### 5.11.3 Prototype PTEs

DLLs và shared sections dùng Prototype PTEs:

```
Process A PTE → Prototype PTE → Physical Page
Process B PTE ↗                     ↑
Process C PTE ↗                     │
                                    │
Prototype PTE quản lý shared page:
  - 1 prototype PTE per shared page
  - Multiple process PTEs point to it
  - Khi page paged out: update prototype PTE once
    (instead of updating every process PTE)
```

---

## 5.12 ASLR (Address Space Layout Randomization)

```
Without ASLR:
  exe always at 0x00400000
  ntdll always at 0x7FFE0000
  stack always at same location
  heap always at same location
  → Attacker knows exact addresses

With ASLR:
  exe at 0x7FF6'XXXX'XXXX        ← Randomized per-boot
  ntdll at 0x7FFA'XXXX'XXXX      ← Randomized per-boot
  stack at 0xXXXX'XXXX'XXXX      ← Randomized per-process
  heap at 0xXXXX'XXXX'XXXX       ← Randomized per-process
```

**[UPDATE 2026]** High-Entropy ASLR (x64):
- Image base: 17 bits entropy (131,072 possible locations)
- Stack: 17 bits entropy
- Heap: 8 bits entropy
- Bottom-up randomization: 8 bits (VirtualAlloc)

---

## 5.13 AWE (Address Windowing Extensions)

### 5.13.1 Concept

AWE cho phép process allocate physical memory TRỰC TIẾP và map vào address space theo ý muốn. Dùng khi cần quản lý physical memory vượt qua giới hạn virtual address space (trước đây quan trọng với 32-bit, nay vẫn hữu ích cho performance).

```
AWE Flow:

1. AllocateUserPhysicalPages()
   → Allocate physical pages (PFN array)
   → Pages KHÔNG có virtual address nào
   → Yêu cầu SeLockMemoryPrivilege

2. VirtualAlloc(MEM_RESERVE | MEM_PHYSICAL)
   → Reserve virtual address window
   → AWE region trong VAD tree (VadType = VadAwe)

3. MapUserPhysicalPages()
   → Map physical pages vào virtual window
   → Có thể re-map bất kỳ lúc nào (nhanh, chỉ thay đổi PTEs)
   → Không cần free/re-allocate

Virtual Window (1 GB):              Physical Pages (64 GB):
┌───────────────────┐               ┌───────────┐
│ View A            │ ──map──→      │ Pages 0-  │
│ (mapped to        │               │ 262143    │
│  pages 0-262143)  │               ├───────────┤
└───────────────────┘               │ Pages     │
       │                            │ 262144-   │
       │ Re-map                     │ 524287    │
       ▼                            ├───────────┤
┌───────────────────┐               │ ...       │
│ View B            │ ──map──→      │           │
│ (mapped to        │               │ Pages     │
│  pages 262144-    │               │ 16M-      │
│  524287)          │               │ 16M+262K  │
└───────────────────┘               └───────────┘
```

### 5.13.2 AWE API

```c
// 1. Enable privilege
// (yêu cầu SeLockMemoryPrivilege trong Local Security Policy)

// 2. Allocate physical pages
ULONG_PTR numberOfPages = 1024;  // 4 MB
ULONG_PTR *pfnArray = (ULONG_PTR*)malloc(
    numberOfPages * sizeof(ULONG_PTR));
    
BOOL result = AllocateUserPhysicalPages(
    GetCurrentProcess(),
    &numberOfPages,
    pfnArray);

// 3. Reserve AWE region
PVOID window = VirtualAlloc(NULL, 
    numberOfPages * 4096,
    MEM_RESERVE | MEM_PHYSICAL, 
    PAGE_READWRITE);

// 4. Map physical pages into window
MapUserPhysicalPages(window, numberOfPages, pfnArray);

// 5. Use memory normally
memset(window, 0, numberOfPages * 4096);

// 6. Re-map different pages (fast, no I/O)
MapUserPhysicalPages(window, numberOfPages, pfnArray2);

// 7. Cleanup
MapUserPhysicalPages(window, numberOfPages, NULL);  // unmap
FreeUserPhysicalPages(GetCurrentProcess(), 
    &numberOfPages, pfnArray);
VirtualFree(window, 0, MEM_RELEASE);
```

**Use cases:**
- Database servers (SQL Server Buffer Pool Extension)
- Virtual machines (map guest physical memory)
- Scientific computing (large datasets vượt qua virtual address space)
- Real-time systems (locked pages, no page faults)

**Limitations:**
- Pages luôn locked trong RAM (không thể page out)
- Yêu cầu SeLockMemoryPrivilege
- Pages không được Protection per-page (toàn bộ window cùng protection)
- Không hỗ trợ large pages trong AWE

---

## 5.14 Secure Memory

### 5.14.1 VBS Enclaves (Virtualization-Based Security)

```
VBS Architecture:
┌─────────────────────────────────────────────────────┐
│                    Hypervisor (Hyper-V)               │
├──────────────────────┬──────────────────────────────┤
│     VTL 0            │         VTL 1                 │
│  (Normal World)      │   (Secure World)              │
│                      │                               │
│  Windows Kernel      │  Secure Kernel                │
│  Drivers             │  (securekernel.exe)           │
│  User Apps           │                               │
│                      │  Credential Guard             │
│  ┌────────────────┐  │  (lsaiso.exe)                │
│  │ VBS Enclave    │  │                               │
│  │ (user mode)    │──┼──→ Secure memory region       │
│  │ Sensitive data │  │    VTL 1 pages:               │
│  │ Crypto keys    │  │    - Kernel VTL 0 KHÔNG đọc   │
│  └────────────────┘  │      được                     │
│                      │    - Even rootkit không        │
│                      │      access được              │
└──────────────────────┴──────────────────────────────┘

Enclave API:
  CreateEnclave()     → Tạo enclave region
  LoadEnclaveData()   → Load code/data vào enclave
  InitializeEnclave() → Seal enclave (không thể modify)
  CallEnclave()       → Gọi function trong enclave
  DeleteEnclave()     → Xóa enclave
```

### 5.14.2 Intel SGX Enclaves

```
SGX (Software Guard Extensions):
  - Hardware-level memory encryption
  - Enclave memory encrypted trong RAM (AES-128)
  - CPU decrypt khi access từ TRONG enclave
  - OS/Hypervisor KHÔNG đọc được enclave memory
  - EPC (Enclave Page Cache): vùng RAM dành cho enclaves
  
Windows hỗ trợ SGX enclaves thông qua:
  - ENCLAVE_TYPE_SGX flag trong CreateEnclave()
  - Driver: sgx_urts.dll, sgx_enclave.dll
  - Limitations: EPC size giới hạn (128-256 MB)
```

### 5.14.3 Secure Pool và Memory Partitions

```
Secure Pool (VTL 1):
  - Pool allocations trong VTL 1 address space
  - Chỉ Secure Kernel và trusted code mới access được
  - Dùng cho: Credential Guard secrets, HVCI metadata

Memory Partitions (Windows 10+):
  - Chia physical memory thành partitions
  - Mỗi partition: quản lý pages độc lập
  - Use case: Hyper-V VM isolation
    ├── Host partition: chạy Windows host
    ├── Guest partition 1: chạy VM 1
    └── Guest partition 2: chạy VM 2
  - API: NtCreatePartition, NtManagePartition (undocumented)
  
kd> !vm
  ...
  Partition Pages:
    Partition 0 (Host):    8388608 pages (32 GB)
    Partition 1 (Guest):   2097152 pages (8 GB)
```

---

## 5.15 Memory Forensics

### 5.15.1 Volatility Framework

Volatility là công cụ phân tích memory dump phổ biến nhất:

```
# Tạo memory dump:
# 1. WinDbg: .dump /f C:\memory.dmp
# 2. FTK Imager: Capture Memory
# 3. DumpIt.exe (Comae)
# 4. LiveKd: livekd.exe -o C:\memory.dmp

# Volatility 3 commands:

# Liệt kê processes:
vol.py -f memory.dmp windows.pslist.PsList
vol.py -f memory.dmp windows.psscan.PsScan      # Tìm hidden processes

# So sánh pslist vs psscan:
#   PsList: duyệt ActiveProcessLinks (EPROCESS linked list)
#   PsScan: scan TOÀN BỘ memory tìm _EPROCESS pattern
#   Process DKOM (Direct Kernel Object Manipulation):
#     → Process bị unlink khỏi ActiveProcessLinks
#     → PsList KHÔNG thấy, nhưng PsScan VẪN tìm được

# Pool tag scanning:
vol.py -f memory.dmp windows.poolscanner.PoolScanner
#   Scan memory tìm pool tags: Proc, Thre, File, ...
#   Tìm được objects ngay cả khi freed (residual data)

# VAD analysis:
vol.py -f memory.dmp windows.vadinfo.VadInfo --pid 1234
#   Liệt kê tất cả VAD entries của process
#   Tìm vùng nhớ nghi ngờ: EXECUTE_READWRITE + Private
#     → Có thể là injected shellcode

vol.py -f memory.dmp windows.malfind.Malfind
#   Tự động tìm suspicious memory regions:
#   - PAGE_EXECUTE_READWRITE + private memory
#   - MZ header trong private memory (injected PE)
#   - Shellcode patterns

# DLL injection detection:
vol.py -f memory.dmp windows.dlllist.DllList --pid 1234
#   So sánh với VAD tree → tìm DLLs loaded nhưng không trong PEB
```

### 5.15.2 WinDbg Memory Forensics

```
; Tìm hidden processes (pool tag scan):
kd> !poolused 2
;   Tìm tag "Proc" - allocation lớn bất thường?

kd> !poolfind Proc
;   Tìm tất cả pool blocks với tag "Proc"
;   Mỗi block là 1 EPROCESS structure
;   So sánh với !process 0 0 → tìm process không trong list

; PTE analysis cho hidden executable pages:
kd> !pte <address>
                    VA 00007ff643210000
PXE at ... PPE at ... PDE at ... PTE at ...
contains ...
pfn 1234 ---DA--UWEV    ← U=User, W=Write, E=Execute, V=Valid
;   Tìm pages với UWE (User+Write+Execute) → nghi ngờ

; Scan executable PTEs trong user space:
; (Thủ công: duyệt PTE table, tìm entries với RWX)

; Kernel callbacks analysis:
kd> !callback
;   Liệt kê tất cả registered callbacks
;   Rootkit hay đăng ký callbacks để intercept operations

; SSDT hooking detection:
kd> dps nt!KiServiceTable L100
;   Kiểm tra mỗi entry có trỏ vào ntoskrnl không
;   Entry trỏ ra ngoài ntoskrnl → SSDT hook (rootkit)

; Driver analysis:
kd> lm
;   Liệt kê loaded drivers
;   Tìm drivers không xác định / không có ký số

kd> !drvobj \Driver\<name> 7
;   Xem dispatch routines của driver
;   IRP handlers trỏ tới code nghi ngờ?
```

### 5.15.3 PFN Database Forensics

```
; PFN database chứa thông tin về MỌI physical page:

kd> !pfn <PFN_number>
    PFN 00001234
    flink      00005678  blink   00004321  
    pteaddress FFFFF680'01234560
    reference  1    color   0
    restore    0    modified 0
    contain    0    active
    Share      1    Lock     0
    
;   PTE address → biết page được map ở đâu trong virtual space
;   Active vs Standby vs Modified → trạng thái hiện tại
;   Share count → bao nhiêu PTEs reference page này

; Tìm tất cả pages của 1 process:
kd> !memusage
;   Thống kê sử dụng memory theo loại
;   Active pages, Standby, Modified, Free, Zeroed

; Tìm page có nội dung cụ thể:
;   Scan physical memory cho pattern (VD: MZ header)
kd> s -a 0 L?FFFFFFFF "MZ"
;   Tìm MZ headers trong physical memory
;   Kết hợp với !pfn để biết page thuộc process nào
```

---

## 5.16 Experiments

### Experiment 5.1: Virtual Memory Statistics

```
kd> !vm                             ; VM summary
kd> !memusage                       ; Physical page usage
kd> !pfn <PFN_number>               ; PFN entry details

PowerShell:
Get-Process notepad | Select *Memory*, *WorkingSet*, *PagedMemory*
```

### Experiment 5.2: Address Translation

```
kd> !process 0 0 notepad.exe        ; Get EPROCESS
kd> .process /i /p <EPROCESS>       ; Switch context
kd> !pte <virtual_address>           ; Show PTE chain
kd> !pfn <PFN>                       ; Physical page info
```

### Experiment 5.3: Pool Usage

```
kd> !poolused 2                      ; Sorted by paged usage
kd> !pool <address>                  ; Pool info for address
kd> !poolval <address>               ; Validate pool block
```

### Experiment 5.4: VMMap

Dùng Sysinternals VMMap:
1. Mở VMMap → chọn process
2. Xem: Image, Mapped File, Shareable, Private Data, Stack, Heap
3. Observe committed vs reserved
4. Protection per-region

### Experiment 5.5: !pfn - PFN Database Analysis

```
; Bước 1: Tìm PFN từ PTE
kd> !pte 00007ff6`43210000
                    VA 00007ff643210000
PXE at FFFFABC123456788  PPE at FFFFABC234567890  
PDE at FFFFABC345678900  PTE at FFFFABC456789010
contains 8000000012345867
pfn 12345 ---DA--UWEV

; Bước 2: Xem PFN entry chi tiết
kd> !pfn 12345
    PFN 00012345 at address FFFFFA80'00091A28
    flink       00000000  blink / share count  00000001
    pteaddress  FFFFABC4'56789010
    reference   1           color  0
    restore pte 00000080    containing page   00004567
    Active      M          Priority  5
    
;   Active: page đang được sử dụng
;   M: Modified (đã bị ghi, dirty)
;   Priority 5: Normal priority
;   Share count 1: 1 PTE reference
;   Containing page 4567: page table page chứa PTE này

; Bước 3: Xem nội dung physical page
kd> !db 12345*1000 L100
;   Đọc 256 bytes đầu của physical page 0x12345
```

### Experiment 5.6: !pool và !poolval - Pool Analysis

```
; Xem pool block tại 1 address:
kd> !pool ffff8a01`23456780
Pool page ffff8a01`23456780 region is Nonpaged pool
 ffff8a01`23456700 size:   80 previous size:    0  (Allocated)  Irp 
 ffff8a01`23456780 size:  120 previous size:   80  (Allocated)  Thre *
                    ← * = block chứa address cần tìm
 ffff8a01`234568a0 size:   40 previous size:  120  (Free)       ....
 ffff8a01`234568e0 size:   60 previous size:   40  (Allocated)  File

;   size: kích thước block (hex, đơn vị 16 bytes)
;   Irp/Thre/File: pool tags
;   Allocated vs Free: trạng thái

; Validate pool block:
kd> !poolval ffff8a01`23456780
Pool block ffff8a01`23456780 is valid
  Tag: Thre
  Size: 0x120 (288 bytes)
  Type: NonPagedPool
  Process: ffff8a01`11111111

; Tìm tất cả allocations của 1 tag:
kd> !poolfind Thre -nonpaged
;   Scan toàn bộ nonpaged pool tìm tag "Thre"
;   Mỗi result là 1 _ETHREAD structure
```

### Experiment 5.7: !vm - Virtual Memory Statistics Chi Tiết

```
kd> !vm

*** Virtual Memory Usage ***
        Physical Memory:          4193552 (    16774208 Kb)
        Available Pages:          1234567 (     4938268 Kb)
        ResAvail Pages:           3456789 (    13827156 Kb)
        Locked IO Pages:             1234 (        4936 Kb)
        Free System PTEs:     4294967295
        
        Modified Pages:            12345 (       49380 Kb)
        Modified PF Pages:          6789 (       27156 Kb)
        Modified No Write Pages:     123 (         492 Kb)
        
        NonPaged Pool Usage:       23456 (       93824 Kb)
        NonPaged Pool Max:        333333 (     1333332 Kb)
        Paged Pool Usage:          45678 (      182712 Kb)
        Paged Pool Max:           666666 (     2666664 Kb)
        
        Commit Charge:           1234567 (     4938268 Kb)
        Commit Limit:            3456789 (    13827156 Kb)
        Peak Commit:             2345678 (     9382712 Kb)
        
;   Physical Memory: tổng RAM (pages)
;   Available: pages sẵn sàng cấp phát
;   Modified: dirty pages cần ghi ra disk
;   Commit Charge: tổng committed memory (RAM + pagefile)
;   Commit Limit: RAM + pagefile size (giới hạn tối đa)
;   Peak Commit: commit charge cao nhất từ khi boot

; Kiểm tra memory pressure:
;   Available / Physical < 10% → LOW memory
;   Commit Charge / Commit Limit > 90% → NEAR commit limit
;   Modified Pages cao → modified page writer bị chậm
```

### Experiment 5.8: !memusage - Physical Memory Usage

```
kd> !memusage
 loading PFN database
..........

Control   Valid  Standby  Modified  SharedRW  Locked  PageTables  name
ffffa123  1234     567       89        12       0          0      mapped_file
ffffa456  5678    1234      123        56       0          0      \Windows\System32\ntdll.dll
ffffa789  3456     890       45        23       0          0      \Windows\System32\kernel32.dll
...

Summary:
  Pages     Description
  1234567   Active pages (in working sets)
   567890   Standby pages (cache, reclaimable)
    12345   Modified pages (dirty, need write)
    23456   Free pages
    45678   Zeroed pages
      123   Bad pages
  4193552   Total physical pages

;   Active: đang được process sử dụng
;   Standby: đã bị trim nhưng vẫn trong RAM (soft fault reclaim)
;   Modified: dirty, chờ modified page writer ghi ra disk
;   Free: available nhưng chưa zeroed
;   Zeroed: sẵn sàng cấp phát ngay (zero page thread đã zero)
;   Bad: pages bị lỗi hardware
```

### Experiment 5.9: Process Memory Deep Dive

```
; Full process memory analysis:
kd> !process 0 0 notepad.exe
PROCESS ffff8a01`23456780
    SessionId: 1  Cid: 1234    Peb: 00000012`3456789a
    DirBase: 1a2b3000
    Image: notepad.exe
    
    VadRoot ffff8a01`aabbccdd Vads 123 Clone 0
    
    Working Set Sizes (now,min,max)  (4567, 50, 345)
    PeakWorkingSetSize               8901
    VirtualSize                      234567 Kb
    PageFaultCount                   12345
    MemoryPriority                   BACKGROUND
    
    CommitCharge                     2345

; Phân tích:
;   DirBase: CR3 value (page table root)
;   VadRoot: root của VAD tree
;   Vads 123: có 123 VAD entries (memory regions)
;   PageFaultCount: tổng số page faults (soft + hard)
;   CommitCharge: pages đã committed
;   MemoryPriority: ảnh hưởng working set trimming order
```

---

## 5.17 Tóm Tắt

| Khái niệm | Điểm chính |
|------------|------------|
| Virtual Address Space | 128 TB user + 128 TB kernel (48-bit, mở rộng 57-bit) |
| Page Tables | 4-level (PML4→PDPT→PD→PT), entry 8 bytes |
| TLB | Cache translations, PCID avoids flush on switch |
| Page Faults | Soft (<10μs, no I/O) vs Hard (~10ms, disk read) |
| Pagefile | Backs committed memory, size = commit limit - RAM |
| Pools | Nonpaged (always RAM) vs Paged (can page out), tagged |
| Heaps | NT Heap + Segment Heap + LFH, page heap for debug |
| Working Sets | Per-process resident pages, aging-based trimming |
| PFN Database | Tracks every physical page, lists by state |
| Compression | In-memory compression before pagefile I/O |
| Sections | Memory-mapped files, shared memory, prototype PTEs |
| ASLR | Randomize image/stack/heap, high-entropy on x64 |

> **Tiếp theo: [Chapter 6 — Hệ Thống I/O](Chapter_06_IO_System.md)**
> I/O Manager, IRPs, driver stacks, I/O completion ports, Plug and Play.
