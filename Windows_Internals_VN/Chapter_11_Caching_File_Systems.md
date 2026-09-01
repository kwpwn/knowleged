# Chapter 11: Caching và Hệ Thống Tập Tin (File Systems)

> Chương này cover: Cache Manager internals, NTFS deep dive (MFT, journaling,
> B+ tree indexes, reparse points, security), ReFS architecture, file system
> filter drivers (minifilters), storage stack (Storage Spaces, NVMe, DAX),
> BitLocker encryption, và security/forensics implications.
>
> Dành cho security researcher cần hiểu sâu về Windows storage subsystem.

---

## Mục Lục

- [11.1 Cache Manager](#111-cache-manager)
- [11.2 NTFS Internals](#112-ntfs-internals)
- [11.3 NTFS Journaling và Recovery](#113-ntfs-journaling-va-recovery)
- [11.4 USN Journal](#114-usn-journal)
- [11.5 ReFS (Resilient File System)](#115-refs-resilient-file-system)
- [11.6 File System Filter Drivers](#116-file-system-filter-drivers)
- [11.7 Storage Stack](#117-storage-stack)
- [11.8 BitLocker](#118-bitlocker)
- [11.9 Security và Forensics](#119-security-va-forensics)
- [11.10 Experiments](#1110-experiments)
- [11.11 Tóm Tắt](#1111-tom-tat)

---

## 11.1 Cache Manager

### 11.1.1 Unified Cache Architecture

Windows sử dụng một **unified cache** duy nhất cho toàn bộ hệ thống file.
Cache Manager (Cc*) không tự đọc/ghi disk — nó làm việc thông qua Memory
Manager (Mm*) bằng cách map file vào system cache address space.

```
Kiến trúc tổng thể:

 ┌────────────────────────────────────────────────────────────┐
 │ Application I/O                                            │
 │   ReadFile() / WriteFile() / Memory-mapped file            │
 ├────────────────────────────────────────────────────────────┤
 │ I/O Manager (IoCallDriver, IRP dispatch)                   │
 ├────────────────────────────────────────────────────────────┤
 │ File System Driver (ntfs.sys, refs.sys, fastfat.sys ...)   │
 │   ├── Fast I/O path (FastIoRead/FastIoWrite)               │
 │   │     └── Bypass IRP allocation → direct cache access    │
 │   ├── Cached I/O: CcCopyRead / CcCopyWrite                │
 │   │     ├── Cache hit → copy from/to system cache          │
 │   │     └── Cache miss → page fault → Mm reads disk        │
 │   └── Non-cached I/O (FILE_FLAG_NO_BUFFERING)              │
 │         └── Bypass cache → direct to storage stack          │
 ├────────────────────────────────────────────────────────────┤
 │ Cache Manager (Cc*)                                        │
 │   ├── System cache virtual address space                   │
 │   ├── Virtual Address Control Blocks (VACBs)               │
 │   ├── Shared Cache Map (per-file section object)           │
 │   ├── Private Cache Map (per-file-handle)                  │
 │   ├── Lazy Writer thread pool                              │
 │   ├── Read-Ahead thread pool                               │
 │   ├── Write throttling (dirty page threshold)              │
 │   └── Tightly coupled với Memory Manager                   │
 ├────────────────────────────────────────────────────────────┤
 │ Memory Manager (Mm*)                                       │
 │   ├── Section objects (file-backed mappings)                │
 │   ├── Page fault handler (MmAccessFault)                   │
 │   │     └── I/O to disk khi page chưa có trong memory      │
 │   ├── Modified page writer (write dirty pages to disk)     │
 │   ├── Working set manager (trim cache khi memory pressure) │
 │   └── Standby list management                              │
 ├────────────────────────────────────────────────────────────┤
 │ Storage Driver Stack                                       │
 │   Volume Manager → Class Driver → Port/Miniport → HW      │
 └────────────────────────────────────────────────────────────┘
```

Điểm quan trọng: Cache Manager và Memory Manager **chia sẻ cùng một physical
page**. Khi user map file bằng MapViewOfFile và khi Cache Manager cache cùng
file đó, cả hai đều reference đến cùng section object → **cache coherency
được đảm bảo tự động**.

### 11.1.2 Shared Cache Map

Mỗi file được cache có một **Shared Cache Map** (SHARED_CACHE_MAP structure).
Nó được tạo khi file system gọi `CcInitializeCacheMap()`.

```
SHARED_CACHE_MAP structure (key fields):

  +0x000 NodeTypeCode          : SHORT (0x02FC)
  +0x008 FileSize              : LARGE_INTEGER  ← kích thước file hiện tại
  +0x010 ValidDataLength       : LARGE_INTEGER  ← valid data (phía sau là zero)
  +0x018 SectionSize            : LARGE_INTEGER  ← section object size
  +0x020 LargestLSN            : LARGE_INTEGER  ← cho cache coherency với log
  +0x028 Section               : PSECTION       ← section object pointer
  +0x030 FileObject            : PFILE_OBJECT   ← primary file object
  +0x038 DirtyPages            : ULONG          ← số dirty pages hiện tại
  +0x040 LogHandle             : PVOID          ← log handle cho transacted ops
  +0x048 InitialVacbs[4]       : VACB*          ← inline VACB array (nhỏ)
  +0x068 Vacbs                 : PVACB*         ← pointer to VACB array (lớn)
  +0x070 OpenCount             : ULONG          ← số file objects đang reference
  +0x078 PrivateList           : LIST_ENTRY     ← danh sách Private Cache Maps
  +0x088 Callbacks             : CC_CALLBACKS   ← acquire/release cho FS
  +0x0A0 LazyWritePassCount    : ULONG          ← tracking lazy write
  +0x0A8 BcbList               : LIST_ENTRY     ← pinned BCB list
  +0x0B8 SharedCacheMapLinks   : LIST_ENTRY     ← global linked list

VACB index tính như sau:
  VACB index = File_Offset / VACB_MAPPING_GRANULARITY
  VACB_MAPPING_GRANULARITY = 256 KB (0x40000)

Ví dụ: File offset 0x80000 (512KB) → VACB index = 0x80000 / 0x40000 = 2
```

### 11.1.3 Private Cache Map

Mỗi **file handle** (FILE_OBJECT) có một **Private Cache Map** riêng. Nó theo
dõi access pattern cho file handle đó để phục vụ read-ahead.

```
PRIVATE_CACHE_MAP structure (key fields):

  +0x000 NodeTypeCode          : SHORT
  +0x008 FileObject            : PFILE_OBJECT
  +0x010 FileOffset1           : LARGE_INTEGER  ← 2 lần read cuối
  +0x018 BeyondLastByte1       : LARGE_INTEGER  ← vị trí kết thúc read 1
  +0x020 FileOffset2           : LARGE_INTEGER
  +0x028 BeyondLastByte2       : LARGE_INTEGER  ← vị trí kết thúc read 2
  +0x030 ReadAheadOffset[2]    : LARGE_INTEGER  ← read-ahead tracking
  +0x040 ReadAheadLength[2]    : ULONG          ← read-ahead sizes
  +0x050 ReadAheadSpinLock     : KSPIN_LOCK
  +0x058 PrivateLinks          : LIST_ENTRY     ← link vào Shared Cache Map
  +0x068 ReadAheadEnabled      : BOOLEAN
  +0x069 ReadAheadActive       : BOOLEAN

Read-ahead sử dụng 2 cặp (Offset, BeyondLastByte) để detect pattern:
  - Nếu read 2 liên tiếp tạo thành sequential → enable read-ahead
  - Stride detection: khoảng cách giữa reads không đổi → predict next
```

### 11.1.4 VACB (Virtual Address Control Block)

VACB là đơn vị cơ bản của cache mapping. Mỗi VACB ánh xạ 256 KB của file vào
system cache virtual address space.

```
VACB structure:

  +0x000 BaseAddress           : PVOID    ← địa chỉ ảo trong system cache
  +0x008 SharedCacheMap        : PSHARED_CACHE_MAP
  +0x010 Overlay.FileOffset    : LARGE_INTEGER  ← file offset mà VACB ánh xạ
  +0x010 Overlay.ActiveCount   : ULONG    ← reference count (union với above)
  +0x018 Links                 : LIST_ENTRY ← LRU list links

VACB Array Management:
  - File < 1 MB  : 4 inline VACBs trong Shared Cache Map (InitialVacbs[4])
  - File 1-32 MB : single VACB array allocated riêng
  - File > 32 MB : multi-level VACB tree (sparse, giống page table)
  - File > 2 TB  : 3-level VACB tree

VACB Array layout cho file nhỏ (< 1 MB):
  ┌──────────────────────────┐
  │ SharedCacheMap           │
  │   InitialVacbs[0] ──────┼──→ VACB (offset 0x00000 - 0x3FFFF)
  │   InitialVacbs[1] ──────┼──→ VACB (offset 0x40000 - 0x7FFFF)
  │   InitialVacbs[2] ──────┼──→ VACB (offset 0x80000 - 0xBFFFF)
  │   InitialVacbs[3] ──────┼──→ VACB (offset 0xC0000 - 0xFFFFF)
  └──────────────────────────┘

VACB Array layout cho file lớn (multi-level):
  SharedCacheMap.Vacbs ──→ Level-1 Array
    [0] ──→ Level-2 Array ──→ [0] VACB, [1] VACB, ...
    [1] ──→ Level-2 Array ──→ [0] VACB, [1] VACB, ...
    [2] ──→ NULL  (chưa truy cập vùng này)
    ...

Tổng số VACBs tối đa:
  System cache size / 256 KB
  Với system cache 1 GB → ~4096 VACBs
```

### 11.1.5 Cache Coherency với Memory Manager

Cache Manager không đọc disk trực tiếp. Thay vào đó, nó map file vào VA space
thông qua section objects, và để Memory Manager xử lý page faults.

```
Flow khi CcCopyRead gặp cache miss:

1. File system gọi CcCopyRead(FileObject, Offset, Length, Buffer)
2. Cache Manager tìm VACB cho vùng [Offset, Offset+Length)
3. Nếu VACB chưa mapped:
   a. CcGetVirtualAddress() → tìm/allocate VACB
   b. MmMapViewInSystemCache() → map file section vào system cache VA
4. RtlCopyMemory(UserBuffer, CacheVA + OffsetWithinVACB, Length)
   → Nếu page chưa có trong physical memory:
     a. CPU generates #PF (page fault)
     b. MmAccessFault() được gọi
     c. Memory Manager kiểm tra section object
     d. Nếu page chưa đọc → IoPageRead() → IRP_MJ_READ gửi tới storage
     e. Page được đọc vào physical memory
     f. PTE được update → page accessible
     g. RtlCopyMemory tiếp tục

Kết quả: Cache Manager và memory-mapped files LUÔN nhìn thấy cùng data
vì chúng dùng chung section object và physical pages.

             ┌─────────────────────┐
             │ Physical Page Frame  │
             │ (actual file data)   │
             └──────────┬──────────┘
                ┌───────┴────────┐
                │                │
    ┌───────────▼───┐    ┌──────▼──────────┐
    │ System Cache  │    │ User Process    │
    │ VA (VACB map) │    │ VA (MapView)    │
    │ Used by       │    │ Used by         │
    │ CcCopyRead    │    │ MapViewOfFile   │
    └───────────────┘    └─────────────────┘
```

### 11.1.6 Intelligent Read-Ahead

Cache Manager theo dõi pattern truy cập để dự đoán và pre-fetch data.

```
Read-ahead algorithm:

1. HISTORY TRACKING:
   Private Cache Map lưu 2 lần read gần nhất:
     Read N-1: [FileOffset1, BeyondLastByte1)
     Read N:   [FileOffset2, BeyondLastByte2)

2. SEQUENTIAL DETECTION:
   Nếu FileOffset2 == BeyondLastByte1 (read liên tiếp):
     → Sequential pattern detected
     → Read-ahead được kích hoạt

3. STRIDE DETECTION:
   Nếu FileOffset2 - FileOffset1 == FileOffset1 - FileOffset0:
     → Stride pattern detected
     → Read-ahead theo stride length

4. READ-AHEAD SIZE:
   - Bắt đầu: 2x current request size
   - Tăng dần theo sequential history strength
   - Maximum: 64 pages = 256 KB (bằng 1 VACB)
   - Có thể tự động increase lên 2 VACB (512 KB) với strong pattern

5. ASYNC EXECUTION:
   - Read-ahead request được queue lên system worker thread
   - CcScheduleReadAhead() → post work item
   - Worker thread gọi CcPerformReadAhead()
   - Data được đọc async → sẵn sàng khi app đọc tiếp

6. GRANULARITY:
   - Read-ahead làm tròn lên page boundary (4 KB)
   - Tránh đọc quá ValidDataLength của file
   - Tránh đọc quá EndOfFile

Ví dụ sequential read:
  App đọc: [0, 4KB) → [4KB, 8KB) → [8KB, 12KB)
  Cache Manager detect sequential, read-ahead:
    Pre-fetch: [12KB, 20KB) async ← app sẽ đọc tiếp từ 12KB
  Kết quả: app đọc [12KB, 16KB) → cache hit, không wait I/O
```

### 11.1.7 Write-Back Caching và Write Throttling

```
Write-back flow:

1. App gọi WriteFile() → NtWriteFile()
2. File system gọi CcCopyWrite(FileObject, Offset, Length, Buffer)
3. Cache Manager:
   a. Map VACB (giống read)
   b. RtlCopyMemory(CacheVA, UserBuffer, Length)
   c. Mark pages DIRTY trong PFN database
   d. Return SUCCESS → app thấy write xong ngay
4. Lazy Writer (background):
   a. Timer callback mỗi ~1 giây
   b. Scan dirty pages cần write
   c. Gọi MmFlushSection() hoặc IoAsynchronousPageWrite()
   d. Dirty pages được ghi xuống disk

WRITE THROTTLING (tránh overwhelming disk):

  CcCanIWrite(FileObject, BytesToWrite, Wait, Retrying):
    - Kiểm tra dirty page count vs threshold
    - Threshold = percentage của physical memory
    - Nếu dirty pages quá nhiều → return FALSE

  CcDeferWrite(FileObject, PostRoutine, Context1, Context2,
               BytesToWrite, Retrying):
    - Khi CcCanIWrite() trả FALSE
    - Queue write request để thử lại sau
    - PostRoutine được gọi khi dirty pages giảm dưới threshold
    - Tránh disk saturation và memory exhaustion

  Dirty Page Thresholds:
    ┌─────────────────────────────┬──────────────┐
    │ Threshold                   │ Default      │
    ├─────────────────────────────┼──────────────┤
    │ CcDirtyPageThreshold        │ Phụ thuộc RAM│
    │  (system-wide max dirty)    │ ~RAM/8 pages │
    │ CcAggressiveZeroThreshold   │ Lower bound  │
    │  (start aggressive flush)   │ for zeroing  │
    │ Per-file throttle           │ Proportional │
    │  (share of system limit)    │ to file size │
    └─────────────────────────────┴──────────────┘

  Registry tuning (HKLM\SYSTEM\CurrentControlSet\Control\Session Manager
                    \Memory Management):
    LargeSystemCache  = 1  → tăng cache size cho file server
    IoPageLockLimit        → giới hạn pages locked for I/O
```

### 11.1.8 Cache Flushing

```
CcFlushCache(SectionObjectPointer, FileOffset, Length, IoStatus):
  - Flush dirty pages cho một file/range cụ thể
  - Synchronous — đợi cho đến khi write hoàn tất
  - File system gọi khi cần đảm bảo data on disk
  - Ví dụ: trước khi set EndOfFile, trước khi truncate

CcPurgeCacheSection(SectionObjectPointer, FileOffset, Length,
                     UninitializeCacheMaps):
  - Loại bỏ cached data không cần flush
  - Dùng khi file data invalidated (ví dụ: file bị truncate)
  - Nếu UninitializeCacheMaps = TRUE → uninit cache maps luôn
  - NTFS sử dụng khi thay đổi file extents

CcCoherencyFlushAndPurgeCache(SectionObjectPointer, FileOffset,
                               Length, IoStatus, Flags):
  - Kết hợp flush + purge, đảm bảo coherency
  - [UPDATE 2026] Thêm flags mới cho ReFS integration

Flush triggers:
  1. FlushFileBuffers() API (explicit app request)
  2. File close (last handle close → flush dirty data)
  3. Volume dismount
  4. System shutdown
  5. Dirty page threshold exceeded
  6. Lazy Writer periodic scan
  7. Memory pressure (working set trimmer)
```

### 11.1.9 Fast I/O Path

```
Fast I/O bypass IRP overhead:

Normal I/O path:
  App → NtReadFile → IoAllocateIrp → IoCallDriver → FS dispatch
    → CcCopyRead → return → IoCompleteRequest → free IRP
  (IRP allocation và completion có overhead)

Fast I/O path:
  App → NtReadFile → check Fast I/O table → FastIoRead()
    → CcCopyRead → return (SUCCESS or FAIL)
  (Nếu FAIL → fallback to normal IRP path)

Fast I/O dispatch table (FAST_IO_DISPATCH):
  FastIoCheckIfPossible  ← FS kiểm tra có thể Fast I/O không
  FastIoRead             ← cached read không cần IRP
  FastIoWrite            ← cached write không cần IRP
  FastIoQueryBasicInfo   ← nhanh hơn IRP_MJ_QUERY_INFORMATION
  FastIoQueryStandardInfo
  FastIoLock             ← byte-range lock
  FastIoUnlockSingle
  FastIoQueryNetworkOpenInfo  ← network redirector optimization
  MdlRead                ← trả MDL trực tiếp vào cache pages
  MdlWrite               ← ghi trực tiếp vào cache pages

FastIoRead fail cases (fallback to IRP):
  - File có oplocks cần xử lý
  - File system filter cần intercept
  - File có byte-range locks conflict
  - Non-cached I/O requested
  - File system không support Fast I/O cho trường hợp cụ thể
```

### 11.1.10 Mapped vs Pinned Access

```
HAI CÁCH TRUY CẬP CACHE DATA:

1. CcCopyRead / CcCopyWrite:
   - Copy data giữa cache và user buffer
   - Data có thể bị evict bất cứ lúc nào sau khi copy
   - Dùng cho file DATA access bình thường

2. CcMapData / CcPinRead / CcPinMappedData:
   - Trả về pointer trực tiếp vào cache pages
   - Pages được PIN trong memory — không bị evict
   - NTFS sử dụng cho METADATA (MFT records, index nodes)
   - Cần unpin sau khi xong (CcUnpinData)

CcMapData(FileObject, FileOffset, Length, Flags, &Bcb, &Buffer):
  - Map data read-only
  - Trả về Buffer pointer vào cache
  - Bcb = Buffer Control Block, dùng để unpin sau

CcPinRead(FileObject, FileOffset, Length, Flags, &Bcb, &Buffer):
  - Map và PIN data cho modification
  - Caller có thể modify trực tiếp qua Buffer pointer
  - Phải gọi CcSetDirtyPinnedData(Bcb) sau khi modify
  - Phải gọi CcUnpinData(Bcb) khi xong

Ví dụ NTFS sử dụng pinned access cho MFT:
  1. CcPinRead(MftFileObject, MftRecordOffset, MftRecordSize, ...)
  2. Modify MFT record fields trực tiếp trong cache
  3. CcSetDirtyPinnedData(Bcb) → mark dirty
  4. CcUnpinData(Bcb) → release pin
  → MFT record được ghi lazy bởi Lazy Writer

Buffer Control Block (BCB):
  ┌──────────────────────┐
  │ NodeTypeCode         │  ← 0x02FE
  │ Pinned / Mapped flag │
  │ FileOffset           │  ← vị trí trong file
  │ Length               │  ← kích thước data
  │ MappedVA             │  ← virtual address
  │ SharedCacheMap       │  ← parent cache map
  │ PinCount             │  ← reference count
  │ Bcb Links            │  ← list của pinned BCBs
  └──────────────────────┘
```

### 11.1.11 Cache Size Management

```
System cache size phụ thuộc vào hệ điều hành và RAM:

  ┌──────────────────────┬────────────────────────────┐
  │ Cấu hình             │ System cache max           │
  ├──────────────────────┼────────────────────────────┤
  │ 32-bit Windows       │ ~1 GB (system VA limited)  │
  │ 64-bit, < 4 GB RAM   │ ~256 MB – 512 MB          │
  │ 64-bit, 4-16 GB      │ ~1-4 GB                   │
  │ 64-bit, 16+ GB       │ ~8 GB+ (dynamic)          │
  │ Server workload      │ LargeSystemCache=1 → lớn  │
  └──────────────────────┴────────────────────────────┘

Working Set Trimming:
  - Khi memory pressure xảy ra
  - MmWorkingSetManager trim system cache working set
  - Cache pages chuyển sang Standby list
  - Vẫn có thể reuse nhanh (soft fault) nếu chưa bị repurpose

Cache Manager Callbacks (CACHE_MANAGER_CALLBACKS):
  AcquireForLazyWrite    ← FS acquire lock trước lazy write
  ReleaseFromLazyWrite   ← FS release lock sau lazy write
  AcquireForReadAhead    ← FS acquire lock trước read-ahead
  ReleaseFromReadAhead   ← FS release lock sau read-ahead

  NTFS dùng các callbacks này để coordinate cache ops với
  transaction logging và file locking.
```

---

## 11.2 NTFS Internals

### 11.2.1 NTFS Driver Architecture

```
ntfs.sys — NTFS file system driver

Dispatch routines:
  IRP_MJ_CREATE          → NtfsCommonCreate()    ← open/create files
  IRP_MJ_READ            → NtfsCommonRead()      ← read file data
  IRP_MJ_WRITE           → NtfsCommonWrite()     ← write file data
  IRP_MJ_CLOSE           → NtfsCommonClose()     ← close handle
  IRP_MJ_CLEANUP         → NtfsCommonCleanup()   ← last handle close
  IRP_MJ_SET_INFORMATION → NtfsCommonSetInfo()   ← rename, delete, etc.
  IRP_MJ_QUERY_INFORMATION → NtfsCommonQueryInfo()
  IRP_MJ_DIRECTORY_CONTROL → NtfsCommonDirControl() ← directory enum
  IRP_MJ_FILE_SYSTEM_CONTROL → NtfsUserFsRequest() ← FSCTL codes
  IRP_MJ_FLUSH_BUFFERS   → NtfsCommonFlushBuffers()
  IRP_MJ_DEVICE_CONTROL  → NtfsCommonDeviceControl()

NTFS sử dụng exception handling nặng:
  try { ... } except(NtfsExceptionFilter()) { NtfsProcessException(); }
  → Mọi operation được wrap trong SEH
  → Exception có thể trigger transaction rollback

Volume mounting flow:
  1. Mount manager detect new volume
  2. IoVerifyVolume() → NTFS nhận IRP_MJ_FILE_SYSTEM_CONTROL
  3. NtfsMountVolume():
     a. Đọc boot sector → kiểm tra OEM ID "NTFS    "
     b. Đọc MFT record 0 ($MFT) → locate MFT trên disk
     c. Đọc MFT record 3 ($Volume) → kiểm tra version, flags
     d. Kiểm tra $LogFile → chạy recovery nếu cần
     e. Load $Bitmap → cluster allocation state
     f. Load $UpCase → uppercase mapping
     g. Tạo Volume Device Object (VDO)
     h. Mount thành công → volume sẵn sàng sử dụng
```

### 11.2.2 NTFS Volume Layout

```
NTFS Volume:
┌───────────────────────────────────────────────────────┐
│ Sector 0: Boot Sector (VBR)                           │
│   ├── Jump instruction (3 bytes)                      │
│   ├── OEM ID: "NTFS    " (8 bytes)                    │
│   ├── BIOS Parameter Block (BPB):                     │
│   │     Bytes per sector (512)                         │
│   │     Sectors per cluster (1-128)                    │
│   │     Media descriptor                               │
│   │     Total sectors on volume                        │
│   │     MFT start cluster (LCN of $MFT)               │
│   │     MFT mirror start cluster (LCN of $MFTMirr)    │
│   │     Clusters per MFT record (usually -10 = 1024B) │
│   │     Clusters per index block                       │
│   │     Volume serial number                           │
│   └── Bootstrap code                                   │
├───────────────────────────────────────────────────────┤
│ MFT Zone (reserved cho MFT growth)                    │
│   ├── MFT records 0-15 (system metadata)              │
│   ├── MFT records 16-23 (reserved)                    │
│   ├── MFT records 24+ (user files)                    │
│   └── Zone = 12.5% của volume (default)               │
│         Có thể thay đổi: fsutil behavior set mftzone N │
│         N=1 (12.5%), N=2 (25%), N=3 (37.5%), N=4 (50%)│
├───────────────────────────────────────────────────────┤
│ Data Area                                              │
│   ├── File data clusters                               │
│   ├── Directory index allocation                       │
│   ├── $LogFile data                                    │
│   ├── $UsnJrnl data                                    │
│   └── $Bitmap data                                     │
├───────────────────────────────────────────────────────┤
│ Sector cuối: Boot sector backup                        │
└───────────────────────────────────────────────────────┘

MFT Zone:
  - NTFS reserve một vùng liên tục cho MFT để giảm fragmentation
  - Nếu volume gần đầy → MFT zone bị thu hẹp
  - MFT fragmentation gây performance degradation nghiêm trọng
  - fsutil behavior set mftzone 2  ← tăng MFT zone lên 25%
```

### 11.2.3 MFT Record Header Detail

```
MFT Record (FILE_RECORD_SEGMENT_HEADER) — 1024 bytes default:

Offset  Size  Field                     Description
──────  ────  ──────────────────────    ───────────────────────────
0x00    4     Signature                 "FILE" (0x454C4946)
0x04    2     UpdateSeqArrayOffset      Offset đến fixup array
0x06    2     UpdateSeqArrayCount       Số entries trong fixup + 1
0x08    8     LogFileSequenceNumber     LSN của thay đổi cuối
0x10    2     SequenceNumber            Tăng mỗi khi record reuse
0x12    2     HardLinkCount             Số hard links
0x14    2     FirstAttributeOffset      Offset đến attribute đầu
0x16    2     Flags                     0x01=InUse, 0x02=Directory
0x18    4     UsedSize                  Bytes sử dụng trong record
0x1C    4     AllocatedSize             Kích thước record (1024)
0x20    8     BaseFileRecordSegment     0 nếu là base, else ref
0x28    2     NextAttributeId           ID cho attribute tiếp theo
0x2A    2     Alignment                 Padding
0x2C    4     MFTRecordNumber           Số thứ tự record (Win XP+)
0x30    ...   FixupArray                Multi-sector protection
      ...   Attributes                Bắt đầu từ FirstAttributeOffset

FIXUP ARRAY (Multi-sector Protection):
  Vấn đề: MFT record 1024 bytes = 2 disk sectors (512 bytes/sector)
  Nếu write bị gián đoạn giữa 2 sectors → data corruption

  Giải pháp — Update Sequence Array (USA):
    ┌────────────────────────────────────────────────────┐
    │ USA Header:                                        │
    │   UpdateSeqNumber = 0x0005 (tăng mỗi khi write)    │
    │   Entry[0] = original last 2 bytes of sector 1     │
    │   Entry[1] = original last 2 bytes of sector 2     │
    │                                                    │
    │ Khi WRITE:                                         │
    │   1. Save last 2 bytes của mỗi sector vào USA      │
    │   2. Replace last 2 bytes với UpdateSeqNumber      │
    │   3. Write toàn bộ record                          │
    │                                                    │
    │ Khi READ:                                          │
    │   1. Kiểm tra last 2 bytes mỗi sector == UpdateSeqNum│
    │   2. Nếu không khớp → MULTI_SECTOR_ERROR            │
    │      → write bị gián đoạn, record bị corrupt       │
    │   3. Nếu khớp → restore original bytes từ USA       │
    │      → record được đọc chính xác                   │
    └────────────────────────────────────────────────────┘

  Sequence Number Reuse (stale handle detection):
    - Khi file bị delete → MFT record freed
    - Khi record được reuse cho file mới → SequenceNumber++
    - FILE_REFERENCE = (MFTRecordNumber, SequenceNumber)
    - Nếu handle cũ reference (RecordN, SeqOld) nhưng record
      đã có SeqNew → STATUS_INVALID_PARAMETER
    → Ngăn stale handle truy cập file mới
```

### 11.2.4 NTFS Attributes Detail

```
Attribute Header (chung cho mọi attribute):

  ┌────────────────────────────────────────────┐
  │ AttributeType    (4 bytes)  ← 0x10, 0x30..│
  │ Length           (4 bytes)  ← toàn bộ attr │
  │ NonResident      (1 byte)   ← 0=resident   │
  │ NameLength       (1 byte)   ← tên attribute │
  │ NameOffset       (2 bytes)                  │
  │ Flags            (2 bytes)  ← compressed... │
  │ AttributeId      (2 bytes)  ← unique trong  │
  │                               MFT record    │
  ├────────────────────────────────────────────┤
  │ NẾU RESIDENT:                               │
  │   ValueLength    (4 bytes)                  │
  │   ValueOffset    (2 bytes)                  │
  │   Flags          (1 byte)                   │
  │   [Value data inline]                       │
  ├────────────────────────────────────────────┤
  │ NẾU NON-RESIDENT:                           │
  │   LowestVCN      (8 bytes) ← start VCN     │
  │   HighestVCN     (8 bytes) ← end VCN       │
  │   RunListOffset  (2 bytes)                  │
  │   CompressionUnit(2 bytes) ← 0 or 4 (2^4=16│
  │                               clusters)     │
  │   AllocatedSize  (8 bytes) ← on-disk alloc  │
  │   RealSize       (8 bytes) ← actual data    │
  │   InitializedSize(8 bytes) ← valid data     │
  │   [Data Run List]                           │
  └────────────────────────────────────────────┘

Data Run List encoding:
  Mỗi entry: [header_byte] [length_bytes] [offset_bytes]
  header_byte = (offset_size << 4) | length_size

  Ví dụ: 0x31 0x05 0x00 0x10 0x20
    header = 0x31 → offset_size=3, length_size=1
    length = 0x05 → 5 clusters
    offset = 0x201000 → LCN 0x201000 (3 bytes little-endian: 00 10 20)
  
  Tiếp theo: 0x21 0x03 0xF0 0x01
    header = 0x21 → offset_size=2, length_size=1
    length = 0x03 → 3 clusters
    offset = 0x01F0 → RELATIVE to previous = LCN 0x2011F0

  Terminator: 0x00

$STANDARD_INFORMATION (0x10) chi tiết:
  ┌───────────────────────────────┬──────────┐
  │ Field                         │ Size     │
  ├───────────────────────────────┼──────────┤
  │ CreationTime                  │ 8 bytes  │
  │ ModificationTime              │ 8 bytes  │
  │ MFTModificationTime           │ 8 bytes  │
  │ AccessTime                    │ 8 bytes  │
  │ FileAttributes (R,H,S,A,...) │ 4 bytes  │
  │ MaxVersions                   │ 4 bytes  │
  │ VersionNumber                 │ 4 bytes  │
  │ ClassId                       │ 4 bytes  │
  │ OwnerId                       │ 4 bytes  │  ← (NTFS 3.0+)
  │ SecurityId                    │ 4 bytes  │  ← index vào $Secure
  │ QuotaCharged                  │ 8 bytes  │
  │ USN                           │ 8 bytes  │  ← USN Journal seq
  └───────────────────────────────┴──────────┘

Timestamps dùng format FILETIME (100-nanosecond intervals từ 1601-01-01)
```

### 11.2.5 B+ Tree Indexes

NTFS sử dụng B+ tree cho directories và nhiều loại index khác.

```
Directory Index Structure:

  $INDEX_ROOT attribute (0x90) — resident, node gốc:
    ┌──────────────────────────────────────┐
    │ Index Root Header:                    │
    │   AttributeType = 0x30 ($FILE_NAME)   │
    │   CollationRule = 0x01 (filename)      │
    │   IndexBlockSize = 4096               │
    │   ClustersPerBlock = 1                │
    ├──────────────────────────────────────┤
    │ Index Header:                         │
    │   EntriesOffset = offset đến entries  │
    │   TotalSize                            │
    │   AllocatedSize                       │
    │   Flags: 0x01 = has children nodes    │
    ├──────────────────────────────────────┤
    │ Index Entries (sorted by filename):   │
    │   Entry 1: [MFT ref][data][subnode]   │
    │   Entry 2: [MFT ref][data][subnode]   │
    │   ...                                 │
    │   Last Entry (end marker, no data)    │
    └──────────────────────────────────────┘

  Index Entry structure:
    ┌──────────────────────────────────────┐
    │ FileReference    (8 bytes) MFT ref   │
    │ EntryLength      (2 bytes)            │
    │ DataLength       (2 bytes)            │
    │ Flags            (4 bytes)            │
    │   0x01 = has sub-node pointer         │
    │   0x02 = last entry (end marker)      │
    │ [Inline data: $FILE_NAME attribute]   │
    │ [Sub-node VCN if flag 0x01 set]       │
    └──────────────────────────────────────┘

  $INDEX_ALLOCATION attribute (0xA0) — non-resident, B+ tree nodes:
    Mỗi node là 1 index block (4096 bytes default)
    Chứa header + sorted index entries
    Mỗi entry có thể có pointer đến child node

  $BITMAP attribute (0xB0) — bit map của allocated index blocks

B+ Tree structure (directory với nhiều files):

              ┌──────────────────────┐
              │     INDEX_ROOT       │
              │  D.txt  │  M.txt     │
              │ /    \  │  /    \    │
              └──────────────────────┘
                /     |       \
    ┌──────────┐ ┌──────────┐ ┌──────────┐
    │ Block 0  │ │ Block 1  │ │ Block 2  │
    │ A.txt    │ │ F.txt    │ │ P.txt    │
    │ B.txt    │ │ G.txt    │ │ R.txt    │
    │ C.txt    │ │ K.txt    │ │ Z.txt    │
    └──────────┘ └──────────┘ └──────────┘
    (INDEX_ALLOCATION — non-resident blocks)

  Lookup "G.txt":
    1. Root: G < M → follow left-of-M child → Block 1
    2. Block 1: sequential scan → found G.txt
    3. Return MFT reference từ index entry

  Các loại index khác trong NTFS:
    $SDH  — Security Descriptor Hash index (trong $Secure)
    $SII  — Security Id Index (trong $Secure)
    $O    — Object ID index (trong $ObjId)
    $Q    — Quota index (trong $Quota)
    $R    — Reparse point index (trong $Extend\$Reparse)
```

### 11.2.6 Sparse Files và Hard Links

```
SPARSE FILES:
  File có vùng chưa ghi → không cần allocate clusters cho vùng đó
  
  Ví dụ: file 1 GB nhưng chỉ ghi ở offset 0 và offset 999 MB
    Data runs:
      [LCN 100, 1 cluster]       ← data ở offset 0
      [sparse, 255743 clusters]   ← zero — không trên disk
      [LCN 5000, 1 cluster]      ← data ở offset 999 MB
    Trên disk chỉ chiếm ~8 KB thay vì 1 GB
  
  API:
    FSCTL_SET_SPARSE              ← mark file as sparse
    FSCTL_SET_ZERO_DATA           ← deallocate range → sparse
    FSCTL_QUERY_ALLOCATED_RANGES  ← tìm vùng có data

HARD LINKS:
  Nhiều $FILE_NAME attributes trong cùng MFT record
  Hoặc nhiều MFT records trỏ về cùng data

  Tạo: CreateHardLink() / fsutil hardlink create
  
  Giới hạn: 
    - Chỉ trong cùng volume
    - Không cho directories
    - Max 1024 hard links per file (NTFS giới hạn)
  
  MFT impact:
    HardLinkCount trong record header tăng
    Mỗi link thêm 1 $FILE_NAME attribute
    Khi delete: HardLinkCount-- 
    Khi HardLinkCount == 0 → file data được free
    
  Ví dụ: file.txt và link.txt cùng trỏ đến MFT record #1000
    MFT Record #1000:
      $FILE_NAME: "file.txt" (parent: dir A)
      $FILE_NAME: "link.txt" (parent: dir B)  
      $DATA: [data runs...]
      HardLinkCount: 2
```

### 11.2.7 Reparse Points

```
REPARSE POINTS — extension mechanism của NTFS

Khi file system gặp file với $REPARSE_POINT attribute:
  1. Dừng xử lý IRP_MJ_CREATE
  2. Return STATUS_REPARSE với reparse data
  3. I/O Manager kiểm tra có filter nào registered cho tag này
  4. Filter xử lý và redirect I/O

$REPARSE_POINT attribute structure:
  ┌───────────────────────────────────────┐
  │ ReparseTag           (4 bytes)         │  ← loại reparse point
  │ ReparseDataLength    (2 bytes)         │  ← kích thước data
  │ Reserved             (2 bytes)         │
  │ ReparseData          (variable)        │  ← tag-specific data
  └───────────────────────────────────────┘

IO_REPARSE_TAG values:
  ┌─────────────────────────────┬──────────────┬─────────────────────┐
  │ Tag Name                     │ Value         │ Mô tả               │
  ├─────────────────────────────┼──────────────┼─────────────────────┤
  │ IO_REPARSE_TAG_MOUNT_POINT  │ 0xA0000003   │ Junction / volume   │
  │                              │               │ mount point         │
  │ IO_REPARSE_TAG_SYMLINK      │ 0xA000000C   │ Symbolic link       │
  │ IO_REPARSE_TAG_HSM          │ 0xC0000004   │ Hierarchical Storage│
  │ IO_REPARSE_TAG_HSM2         │ 0x80000006   │ HSM variant 2       │
  │ IO_REPARSE_TAG_SIS          │ 0x80000007   │ Single Instance     │
  │ IO_REPARSE_TAG_WIM          │ 0x80000008   │ WIM mount           │
  │ IO_REPARSE_TAG_CSV          │ 0x80000009   │ Cluster Shared Vol  │
  │ IO_REPARSE_TAG_DFS          │ 0x8000000A   │ DFS namespace       │
  │ IO_REPARSE_TAG_DEDUP        │ 0x80000013   │ Deduplication       │
  │ IO_REPARSE_TAG_NFS          │ 0x80000014   │ NFS symlink         │
  │ IO_REPARSE_TAG_WOF          │ 0x80000017   │ Windows Overlay     │
  │                              │               │ Filter (CompactOS)  │
  │ IO_REPARSE_TAG_WCI          │ 0x80000018   │ Windows Container   │
  │                              │               │ Isolation           │
  │ IO_REPARSE_TAG_CLOUD        │ 0x9000001A   │ Cloud Files         │
  │                              │               │ (OneDrive, etc.)    │
  │ IO_REPARSE_TAG_APPEXECLINK  │ 0x8000001B   │ App execution alias │
  │ IO_REPARSE_TAG_GVFS         │ 0x9000001C   │ Git VFS             │
  │ IO_REPARSE_TAG_LX_SYMLINK   │ 0xA000001D   │ WSL symlink         │
  │ IO_REPARSE_TAG_AF_UNIX      │ 0x80000023   │ Unix domain socket  │
  │ IO_REPARSE_TAG_LX_FIFO      │ 0x80000024   │ WSL FIFO            │
  │ IO_REPARSE_TAG_LX_CHR       │ 0x80000025   │ WSL char device     │
  │ IO_REPARSE_TAG_LX_BLK       │ 0x80000026   │ WSL block device    │
  └─────────────────────────────┴──────────────┴─────────────────────┘

Symlink vs Junction:
  Symlink:     có thể cross-volume, support files và dirs, relative path
  Junction:    chỉ directories, chỉ absolute path, chỉ local volume
  Mount point: junction mount volume vào empty NTFS folder

Security relevance:
  - Attacker tạo symlink/junction để redirect file operations
  - Privilege escalation: redirect system service write → overwrite
    critical file
  - TOCTOU: race condition giữa check và use với symlinks
  - Reparse point abuse trong sandbox escape scenarios
```

### 11.2.8 NTFS Security ($Secure File)

```
NTFS PERMISSIONS:

NTFS sử dụng ACLs (Access Control Lists) gán trực tiếp vào file/folder.
Security descriptors được lưu TẬP TRUNG trong $Secure file để tiết kiệm
không gian (nhiều files có cùng permissions → share 1 descriptor).

$Secure file structure:
  ┌─────────────────────────────────────────────────┐
  │ $SDS stream (Security Descriptor Stream):        │
  │   Chứa tất cả security descriptors liên tiếp     │
  │   Mỗi descriptor có header:                      │
  │     HashOfSecurityDescriptor  (4 bytes)           │
  │     SecurityId                (4 bytes)           │
  │     Offset                    (8 bytes)           │
  │     Size                      (4 bytes)           │
  │   Tiếp theo là SECURITY_DESCRIPTOR data           │
  ├─────────────────────────────────────────────────┤
  │ $SDH index (Security Descriptor Hash):            │
  │   B+ tree index by hash value                     │
  │   Dùng khi tạo file mới: tính hash → lookup       │
  │   → nếu đã có descriptor giống → reuse SecurityId │
  ├─────────────────────────────────────────────────┤
  │ $SII index (Security Id Index):                   │
  │   B+ tree index by SecurityId                     │
  │   Dùng khi access check: file có SecurityId       │
  │   → lookup $SII → tìm offset trong $SDS           │
  │   → đọc security descriptor → evaluate ACL        │
  └─────────────────────────────────────────────────┘

SecurityId lookup flow:
  1. File's $STANDARD_INFORMATION.SecurityId = 0x1234
  2. Lookup $SII index cho SecurityId 0x1234
  3. Lấy offset trong $SDS stream
  4. Đọc SECURITY_DESCRIPTOR tại offset đó
  5. Evaluate DACL (Discretionary ACL) cho access check

NTFS ACLs vs Share Permissions:
  ┌──────────────────┬───────────────────────────────────┐
  │ NTFS ACLs         │ Share Permissions                 │
  ├──────────────────┼───────────────────────────────────┤
  │ Per-file/folder   │ Per-share (network level)         │
  │ Apply local+remote│ Apply remote access only          │
  │ Granular (13+     │ 3 levels: Read, Change,           │
  │  permissions)     │   Full Control                    │
  │ Stored in $Secure │ Stored in registry                │
  │ Inherited+explicit│ Only explicit                     │
  └──────────────────┴───────────────────────────────────┘
  
  Effective permission = intersection(NTFS ACL, Share Permission)
  Most restrictive wins.
```

### 11.2.9 Quota, Object ID, Distributed Link Tracking

```
QUOTA ($Quota — $Extend\$Quota):
  - Track disk usage per user (by SID)
  - $O index: SID → QuotaControlEntry
  - $Q index: OwnerId → usage data
  - Quota states: track only, enforce (warn), enforce (deny)
  - $STANDARD_INFORMATION.QuotaCharged: bytes charged to user
  - Admin set quota per volume:
      fsutil quota modify C: 1073741824 2147483600 <SID>
      (warning at 1 GB, limit at 2 GB)

OBJECT ID ($ObjId — $Extend\$ObjId):
  - $OBJECT_ID attribute (0x40) trong MFT record
  - 16-byte GUID assigned cho file
  - Dùng cho Distributed Link Tracking (DLT)
  - Khi shortcut target bị move → DLT dùng ObjectId để tìm lại
  
  Object ID structure:
    ObjectId           (16 bytes)  ← GUID của file
    BirthVolumeId      (16 bytes)  ← GUID volume gốc
    BirthObjectId      (16 bytes)  ← GUID ban đầu
    DomainId           (16 bytes)  ← domain (unused)

DISTRIBUTED LINK TRACKING (DLT):
  - Service: TrkWks (Distributed Link Tracking Client)
  - Khi file có shortcut được move:
    1. Source volume ghi ObjectId của file
    2. Target volume nhận file, giữ ObjectId
    3. DLT service update tracking database
    4. Khi shortcut resolve fail → query DLT → tìm file mới
  - Enterprise: TrkSvr service cho cross-server tracking
  - [UPDATE 2026] TrkSvr đã bị deprecated; chỉ TrkWks còn hoạt động
```

---

## 11.3 NTFS Journaling và Recovery

### 11.3.1 $LogFile Format

```
$LogFile — Transaction log cho NTFS metadata consistency

$LogFile layout:
  ┌──────────────────────────────────────────────────┐
  │ Restart Area (page 0 và page 1 — 2 bản sao)     │
  │   ├── CurrentLsn: LSN cuối cùng commit           │
  │   ├── LogClients: array of client records         │
  │   ├── ClientFreeList / ClientInUseList            │
  │   ├── Flags                                       │
  │   ├── FileSize                                    │
  │   └── CheckpointLsn: LSN của last checkpoint     │
  ├──────────────────────────────────────────────────┤
  │ Log Record Area (còn lại của file)                │
  │   ├── Log Page Header mỗi 4 KB page               │
  │   │     PageCount, PagePosition, LastLsn            │
  │   ├── Log Records (variable size, packed)          │
  │   │     Mỗi Record:                                │
  │   │       ThisLsn          ← LSN của record này    │
  │   │       ClientPreviousLsn← link ngược (undo)     │
  │   │       ClientUndoNextLsn← undo chain next       │
  │   │       ClientId         ← NTFS client           │
  │   │       RecordType       ← ClientRecord/Restart   │
  │   │       TransactionId    ← nhóm operations        │
  │   │       RedoOp           ← redo operation code    │
  │   │       UndoOp           ← undo operation code    │
  │   │       RedoOffset, RedoLength                    │
  │   │       UndoOffset, UndoLength                    │
  │   │       TargetAttribute  ← MFT attr affected      │
  │   │       TargetVcn        ← VCN trong attribute     │
  │   │       RecordOffset     ← offset trong target     │
  │   │       [RedoData]       ← data cho redo           │
  │   │       [UndoData]       ← data cho undo           │
  │   └── Circular buffer (wraps around)               │
  └──────────────────────────────────────────────────┘

LSN (Log Sequence Number):
  - 64-bit, monotonically increasing
  - Encode: (FileOffset << shift) | SeqNumber
  - Mỗi metadata change được assigned 1 LSN
  - MFT record header lưu LSN của modification cuối
  - LSN trong MFT record phải >= LSN trong $LogFile
    → Đảm bảo metadata nhất quán
```

### 11.3.2 Log Record Types (RedoOp / UndoOp)

```
NTFS log operation codes:

  ┌────────────────────────────────────┬──────────────────────────────┐
  │ Operation                          │ Mô tả                        │
  ├────────────────────────────────────┼──────────────────────────────┤
  │ Noop                               │ Không làm gì (padding)       │
  │ CompensationLogRecord              │ CLR — undo đã thực hiện      │
  │ InitializeFileRecordSegment        │ Tạo MFT record mới           │
  │ DeallocateFileRecordSegment        │ Free MFT record              │
  │ WriteEndOfFileRecordSegment        │ Update end marker            │
  │ CreateAttribute                    │ Thêm attribute vào record    │
  │ DeleteAttribute                    │ Xóa attribute                │
  │ UpdateResidentValue                │ Modify resident attr data    │
  │ UpdateNonresidentValue             │ Modify nonresident data      │
  │ UpdateMappingPairs                 │ Update data run list         │
  │ DeleteDirtyClusters                │ Remove dirty cluster tracking│
  │ SetNewAttributeSizes               │ Thay đổi attr sizes          │
  │ AddIndexEntryRoot                  │ Thêm entry vào $INDEX_ROOT   │
  │ DeleteIndexEntryRoot               │ Xóa entry từ $INDEX_ROOT     │
  │ AddIndexEntryAllocation            │ Thêm entry vào index block   │
  │ DeleteIndexEntryAllocation         │ Xóa entry từ index block     │
  │ SetIndexEntryVcnRoot               │ Update child VCN trong root  │
  │ SetIndexEntryVcnAllocation         │ Update child VCN trong block │
  │ UpdateFileNameRoot                 │ Update filename trong root   │
  │ UpdateFileNameAllocation           │ Update filename trong block  │
  │ SetBitsInNonresidentBitMap         │ Set bits (allocate clusters) │
  │ ClearBitsInNonresidentBitMap       │ Clear bits (free clusters)   │
  │ PrepareTransaction                 │ Begin transaction            │
  │ CommitTransaction                  │ Commit (make durable)        │
  │ ForgetTransaction                  │ Abort/rollback               │
  │ OpenNonresidentAttribute           │ Open attr cho logging        │
  │ DirtyPageTableDump                 │ Checkpoint dirty pages       │
  │ TransactionTableDump               │ Checkpoint transactions      │
  │ UpdateRecordDataRoot               │ Update record data           │
  └────────────────────────────────────┴──────────────────────────────┘

  Mỗi log record có cả RedoOp và UndoOp:
    Ví dụ: CreateAttribute
      RedoOp = CreateAttribute (data = attribute content)
      UndoOp = DeleteAttribute (data = attribute identifier)
    → Nếu cần rollback, chạy UndoOp
```

### 11.3.3 Recovery Process (3 Passes)

```
Khi NTFS mount volume sau crash, recovery chạy 3 passes:

PASS 1 — ANALYSIS:
  - Bắt đầu từ CheckpointLsn trong Restart Area
  - Scan forward qua log records
  - Rebuild Dirty Page Table (DPT): pages nào dirty lúc crash
  - Rebuild Transaction Table (TT): transactions nào đang open
  - Xác định OldestLsn = min(DPT entries) → điểm bắt đầu redo

PASS 2 — REDO:
  - Bắt đầu từ OldestLsn
  - Scan forward, redo mỗi operation:
    Nếu page version (LSN) < record LSN → operation chưa on disk
      → Execute RedoOp (apply thay đổi)
    Nếu page version >= record LSN → đã on disk
      → Skip (không cần redo)
  - Đảm bảo mọi committed change được apply

PASS 3 — UNDO:
  - Từ Transaction Table, tìm transactions chưa committed
  - Với mỗi uncommitted transaction:
    Follow ClientPreviousLsn chain ngược lại
    Execute UndoOp cho mỗi record
    Write CompensationLogRecord (CLR) để log việc undo
  - Đảm bảo partial transactions được rollback hoàn toàn

Diagram:
  Log:  ...──[CP]──[T1:Op1]──[T2:Op1]──[T1:Op2]──[CRASH]
                                                     ↑
  Analysis: rebuild DPT và TT từ CP forward         
  Redo:     T1:Op1 → T2:Op1 → T1:Op2 (apply nếu cần)
  Undo:     T1 committed → keep; T2 uncommitted → undo T2:Op1

Kết quả: metadata consistent, volume mount nhanh (~2 giây)
  → Không cần full chkdsk scan
```

### 11.3.4 NTFS Self-Healing và Chkdsk

```
NTFS SELF-HEALING (Online Repair):
  Từ Windows Vista+, NTFS có khả năng tự sửa lỗi online

  Khi detect corruption:
    1. NTFS log lỗi vào System event log
    2. Nếu có thể sửa online → tự động fix
    3. Nếu không → mark volume dirty, yêu cầu chkdsk at boot

  Registry: HKLM\SYSTEM\CurrentControlSet\Control\FileSystem
    NtfsDisableLastAccessUpdate = 1  (default Win10+, performance)
    NtfsBugcheckOnCorrupt      = 0  (default, không BSOD)

  fsutil repair:
    fsutil repair query C:        ← query self-healing state
    fsutil repair set C: 0x01     ← enable self-healing
    fsutil repair initiate C: 0   ← trigger proactive scan

CHKDSK PHASES:
  Phase 1: File verification
    - Đọc mọi MFT record
    - Kiểm tra record header, fixup array
    - Kiểm tra attribute consistency
    - Verify data runs không overlap

  Phase 2: Index verification
    - Đọc mọi directory index
    - Kiểm tra B+ tree structure
    - Verify mọi index entry trỏ đến valid MFT record
    - Cross-reference: mọi file phải có entry trong parent dir index

  Phase 3: Security descriptor verification
    - Verify $Secure file
    - Kiểm tra mọi SecurityId có valid descriptor
    - Rebuild $SDH và $SII indexes nếu cần

  Phase 4: USN Journal verification
    - Kiểm tra $UsnJrnl consistency
    - Verify journal records

  Phase 5: Free space verification (chỉ khi /R)
    - Scan toàn bộ data area cho bad sectors
    - Rebuild $BadClus
    - Test surface (slow, time consuming)

  chkdsk C: /F           ← fix errors
  chkdsk C: /R           ← fix + scan bad sectors
  chkdsk C: /B           ← re-evaluate bad clusters (NTFS only)
  chkdsk C: /scan        ← online scan (Win8+, không cần dismount)
  chkdsk C: /spotfix     ← offline fix only spotted issues
```

---

## 11.4 USN Journal

### 11.4.1 USN_RECORD Structure

```
USN_RECORD_V2 (phổ biến nhất):

  ┌───────────────────────────────────┬──────────┐
  │ Field                             │ Size     │
  ├───────────────────────────────────┼──────────┤
  │ RecordLength                      │ 4 bytes  │
  │ MajorVersion (2)                  │ 2 bytes  │
  │ MinorVersion (0)                  │ 2 bytes  │
  │ FileReferenceNumber               │ 8 bytes  │  ← MFT ref (48-bit record
  │                                    │          │     + 16-bit sequence)
  │ ParentFileReferenceNumber          │ 8 bytes  │  ← parent dir MFT ref
  │ Usn                               │ 8 bytes  │  ← USN offset trong journal
  │ TimeStamp                         │ 8 bytes  │  ← FILETIME
  │ Reason                            │ 4 bytes  │  ← reason flags (OR'd)
  │ SourceInfo                        │ 4 bytes  │  ← source flags
  │ SecurityId                        │ 4 bytes  │  ← file's security ID
  │ FileAttributes                    │ 4 bytes  │  ← file attributes
  │ FileNameLength                    │ 2 bytes  │
  │ FileNameOffset                    │ 2 bytes  │
  │ FileName                          │ variable │  ← Unicode filename
  └───────────────────────────────────┴──────────┘

USN_RECORD_V3 (Windows 8+):
  - Giống V2 nhưng FileReferenceNumber là 16 bytes (128-bit)
  - Hỗ trợ ReFS file IDs (128-bit)

USN_RECORD_V4 (Windows 10+):
  - Range tracking: chỉ record ranges thay đổi, không full reason
  - RemainingExtents: array of (Offset, Length) tuples
  - Dùng cho block-level change tracking (ReFS)
```

### 11.4.2 Reason Codes

```
USN_REASON flags (có thể OR nhiều flags):

  ┌──────────────────────────────────┬────────────┬──────────────────┐
  │ Flag                              │ Value       │ Mô tả             │
  ├──────────────────────────────────┼────────────┼──────────────────┤
  │ USN_REASON_DATA_OVERWRITE        │ 0x00000001 │ File data ghi đè  │
  │ USN_REASON_DATA_EXTEND           │ 0x00000002 │ File data mở rộng  │
  │ USN_REASON_DATA_TRUNCATION       │ 0x00000004 │ File data cắt ngắn │
  │ USN_REASON_NAMED_DATA_OVERWRITE  │ 0x00000010 │ ADS data ghi đè   │
  │ USN_REASON_NAMED_DATA_EXTEND     │ 0x00000020 │ ADS data mở rộng   │
  │ USN_REASON_NAMED_DATA_TRUNCATION │ 0x00000040 │ ADS data cắt ngắn  │
  │ USN_REASON_FILE_CREATE           │ 0x00000100 │ File được tạo      │
  │ USN_REASON_FILE_DELETE           │ 0x00000200 │ File bị xóa        │
  │ USN_REASON_EA_CHANGE             │ 0x00000400 │ Extended attrs     │
  │ USN_REASON_SECURITY_CHANGE       │ 0x00000800 │ ACL thay đổi       │
  │ USN_REASON_RENAME_OLD_NAME       │ 0x00001000 │ Tên cũ (rename)    │
  │ USN_REASON_RENAME_NEW_NAME       │ 0x00002000 │ Tên mới (rename)   │
  │ USN_REASON_INDEXABLE_CHANGE      │ 0x00004000 │ Indexing property  │
  │ USN_REASON_BASIC_INFO_CHANGE     │ 0x00008000 │ Timestamps/attrs   │
  │ USN_REASON_HARD_LINK_CHANGE      │ 0x00010000 │ Hard link add/del  │
  │ USN_REASON_COMPRESSION_CHANGE    │ 0x00020000 │ Compression state  │
  │ USN_REASON_ENCRYPTION_CHANGE     │ 0x00040000 │ EFS state          │
  │ USN_REASON_OBJECT_ID_CHANGE      │ 0x00080000 │ Object ID changed  │
  │ USN_REASON_REPARSE_POINT_CHANGE  │ 0x00100000 │ Reparse point      │
  │ USN_REASON_STREAM_CHANGE         │ 0x00200000 │ Stream add/del     │
  │ USN_REASON_TRANSACTED_CHANGE     │ 0x00400000 │ TxF transaction    │
  │ USN_REASON_INTEGRITY_CHANGE      │ 0x00800000 │ Integrity stream   │
  │ USN_REASON_CLOSE                 │ 0x80000000 │ File handle closed │
  └──────────────────────────────────┴────────────┴──────────────────┘

  Chú ý: USN_REASON_CLOSE thường OR với reason khác
  Ví dụ: FILE_CREATE | CLOSE = 0x80000100 → file được tạo và handle đóng
```

### 11.4.3 USN Journal FSCTL Operations

```
QUERYING USN JOURNAL:

  FSCTL_QUERY_USN_JOURNAL:
    Input:  (none)
    Output: USN_JOURNAL_DATA_V0/V1/V2
      UsnJournalID        ← GUID của journal instance
      FirstUsn             ← USN nhỏ nhất còn available
      NextUsn              ← USN tiếp theo sẽ được assigned
      LowestValidUsn       ← lowest valid USN
      MaxUsn               ← giới hạn trên
      MaximumSize          ← kích thước tối đa journal
      AllocationDelta      ← đơn vị allocation

  Ví dụ: fsutil usn queryjournal C:

READING USN RECORDS:

  FSCTL_READ_USN_JOURNAL:
    Input:  READ_USN_JOURNAL_DATA_V0/V1
      StartUsn             ← bắt đầu đọc từ đây
      ReasonMask           ← chỉ đọc records match mask
      ReturnOnlyOnClose    ← chỉ return CLOSE records
      Timeout              ← đợi records mới (real-time monitoring)
      BytesToWaitFor       ← minimum bytes trước khi return
    Output: USN + array of USN_RECORD_V2

  Forensic usage pattern:
    StartUsn = 0  → đọc từ đầu journal
    Loop:
      DeviceIoControl(FSCTL_READ_USN_JOURNAL, ...)
      Parse mọi USN_RECORD trong output buffer
      NextStartUsn = *(USN*)output_buffer  ← first 8 bytes
      Repeat until no more records

ENUMERATING ALL FILES (không chỉ changes):

  FSCTL_ENUM_USN_DATA:
    Input:  MFT_ENUM_DATA_V0
      StartFileReferenceNumber = 0
      LowUsn = 0
      HighUsn = MAX
    Output: array of USN_RECORD_V2 (1 per file on volume)
    
  Dùng để: list TẤT CẢ files trên volume nhanh hơn FindFirstFile
  Vì sao nhanh: đọc MFT trực tiếp, không traverse directory tree

  Ví dụ code (pseudocode):
    MFT_ENUM_DATA med = {0, 0, MaxUsn};
    while (DeviceIoControl(hVol, FSCTL_ENUM_USN_DATA, &med, ...)) {
      USN nextUsn = *(USN*)buffer;
      USN_RECORD* rec = (USN_RECORD*)(buffer + sizeof(USN));
      while ((BYTE*)rec < buffer + bytesReturned) {
        printf("%.*S  MFT:%lld\n", 
               rec->FileNameLength/2, rec->FileName,
               rec->FileReferenceNumber & 0xFFFFFFFFFFFF);
        rec = (USN_RECORD*)((BYTE*)rec + rec->RecordLength);
      }
      med.StartFileReferenceNumber = nextUsn; // actually next MFT ref
    }
```

### 11.4.4 USN Journal cho Forensics và Backup

```
FORENSIC ANALYSIS với USN Journal:

  1. ACTIVITY TIMELINE:
     - Đọc toàn bộ USN records → sort by TimeStamp
     - Reconstruct: file nào được tạo/xóa/rename/modify khi nào
     - Quan trọng: USN journal có thể retain data TỪ TRƯỚC
       khi investigator bắt đầu (không giống Event Log)

  2. DELETED FILE DETECTION:
     - Tìm records với USN_REASON_FILE_DELETE
     - Có tên file, parent dir, timestamp
     - Map FileReferenceNumber đến MFT record → recover data

  3. ANTI-FORENSICS DETECTION:
     - Gaps trong USN sequence → journal bị clear
     - FSCTL_DELETE_USN_JOURNAL → attacker xóa journal
     - Kiểm tra: UsnJournalID thay đổi → journal bị recreate

  4. MALWARE HUNTING:
     - Tìm FILE_CREATE cho suspicious paths
     - Tìm RENAME_NEW_NAME cho masquerading
     - Tìm DATA_OVERWRITE cho DLL hijacking
     - Correlate với process creation events

BACKUP SOFTWARE sử dụng USN Journal:
  1. Ghi nhớ NextUsn tại thời điểm backup trước
  2. FSCTL_READ_USN_JOURNAL với StartUsn = saved NextUsn
  3. Chỉ backup files có changes → incremental backup nhanh
  4. Không cần scan toàn bộ file system

Tools:
  - fsutil usn queryjournal C:
  - fsutil usn readjournal C: csv    ← CSV output
  - fsutil usn enumdata 1 0 1 C:
  - UsnJrnl2Csv (forensic tool)
  - ANJP (Another NTFS Journal Parser)
  - Velociraptor artifact: Windows.NTFS.MFT
```

---

## 11.5 ReFS (Resilient File System)

### 11.5.1 ReFS Architecture

```
ReFS vs NTFS comparison:
  ┌─────────────────────────┬──────────────┬──────────────┐
  │ Feature                 │ NTFS          │ ReFS         │
  ├─────────────────────────┼──────────────┼──────────────┤
  │ Max volume size         │ 256 TB        │ 35 PB        │
  │ Max file size           │ 256 TB        │ 35 PB        │
  │ Integrity streams       │ No            │ Yes          │
  │ Block clone             │ No            │ Yes          │
  │ Sparse VDL              │ No            │ Yes          │
  │ Compression             │ Yes           │ No           │
  │ EFS encryption          │ Yes           │ No           │
  │ Deduplication           │ Yes           │ Yes          │
  │ Quotas                  │ Yes           │ No           │
  │ Boot volume             │ Yes           │ Partial*     │
  │ Removable media         │ Yes           │ No           │
  │ Named streams (ADS)     │ Yes           │ Limited      │
  │ Hard links              │ Yes           │ No           │
  │ Short names (8.3)       │ Yes           │ No           │
  │ Object IDs              │ Yes           │ No           │
  │ Allocate-on-write       │ No            │ Yes          │
  │ B+ tree metadata        │ MFT + B+tree  │ All B+ tree  │
  │ Self-healing            │ Limited       │ Automatic    │
  └─────────────────────────┴──────────────┴──────────────┘
  * [UPDATE 2026] ReFS boot support đang được mở rộng trong
    Windows 11 24H2+ (Dev Drive, và experimental boot)
```

### 11.5.2 ReFS On-Disk Format

```
ReFS on-disk structures:

SUPERBLOCK (offset 0x1E của volume):
  ┌──────────────────────────────────┐
  │ Signature: "ReFS"                │
  │ Version                          │
  │ Checkpoint offsets (2 bản sao)   │
  │ Volume serial number             │
  └──────────────────────────────────┘

CHECKPOINT (2 bản sao, alternate khi write):
  ┌──────────────────────────────────┐
  │ Checkpoint header                 │
  │ VirtualClock (version counter)   │
  │ Object Table pointer              │
  │ Medium Allocator pointer          │
  │ Container Table pointer           │
  │ Schema Table pointer              │
  │ Container Allocator pointer       │
  │ Checksum                          │
  └──────────────────────────────────┘

  ReFS dùng 2 checkpoints alternating:
    - Write checkpoint A
    - Khi cần update: write checkpoint B
    - Superblock trỏ đến valid checkpoint
    → Crash-safe: luôn có 1 valid checkpoint

OBJECT TABLE:
  - B+ tree mapping Object IDs → on-disk locations
  - Mọi file/directory có 1 Object ID
  - Giống như MFT của NTFS, nhưng là B+ tree thay vì flat table

B+ TREE TABLES (core của ReFS):
  ReFS lưu TẤT CẢ metadata dạng B+ trees
  
  ┌──────────────────────────────────┐
  │ B+ Tree Node (page-sized)        │
  │   Node Header:                    │
  │     NodeSignature                 │
  │     VirtualClock                  │
  │     NodeLevel                     │
  │     NumberOfKeys                  │
  │     Checksum                      │
  │   Keys + Values (sorted)          │
  │   Child pointers (internal nodes) │
  └──────────────────────────────────┘

  Allocate-on-Write:
    - Khi modify node → write vào vị trí MỚI
    - Update parent pointer đến vị trí mới
    - Parent cũng write vào vị trí mới (cascade up)
    - Cuối cùng update checkpoint
    → KHÔNG BAO GIỜ ghi đè data cũ
    → Crash bất cứ lúc nào: roll back đến checkpoint trước
    → Không cần $LogFile như NTFS

  Directory: B+ tree by filename
  File: B+ tree of extent references
  Metadata: B+ tree of attribute key-value pairs
```

### 11.5.3 Integrity Streams và Scrubbing

```
INTEGRITY STREAMS:

  Metadata: LUÔN CÓ checksum (bắt buộc)
  Data:     TÙY CHỌN (per-file flag)
  
  Checksum algorithm: CRC-64 (mặc định)
  
  Enable integrity cho file:
    fsutil integrity set C:\data\important.vhdx
    Set-FileIntegrity -FileName C:\data -Enable $true

  Read flow với integrity:
    1. Đọc data block từ disk
    2. Tính checksum trên data vừa đọc
    3. So sánh với stored checksum
    4. Match → return data
    5. Mismatch → có thể là silent corruption
       a. Nếu Storage Spaces Mirror: đọc từ bản sao khác
       b. Nếu valid copy found → tự động repair corrupt copy
       c. Nếu không có mirror → return error

  SCRUBBING:
    - Background process định kỳ scan toàn bộ data
    - Tính và verify checksums
    - Detect + repair silent corruption trước khi data được truy cập
    - Chạy với low priority I/O → không ảnh hưởng performance
    - [UPDATE 2026] Windows 11 cho phép configure scrubbing schedule
      qua Storage Spaces settings
```

### 11.5.4 Tiered Storage và Storage Spaces Direct

```
ReFS + Storage Spaces Direct (S2D):

  Tiered storage:
    ┌────────────────────┐
    │ HOT tier (SSD/NVMe)│  ← frequently accessed data
    ├────────────────────┤
    │ COLD tier (HDD)    │  ← infrequently accessed data
    └────────────────────┘
  
  ReFS automatically move data giữa tiers dựa trên access pattern
  
  S2D Architecture:
    ┌──────────────────────────────────────┐
    │ Cluster Shared Volume (CSV)          │
    │   ReFS volume spanning nodes         │
    ├──────────────────────────────────────┤
    │ Storage Spaces Virtual Disk          │
    │   Mirror / Parity / Mirror-Accelerated│
    ├──────────────────────────────────────┤
    │ Storage Pool                          │
    │   Aggregated local storage from       │
    │   multiple cluster nodes              │
    ├──────────────────────────────────────┤
    │ Physical disks (NVMe, SSD, HDD)      │
    │   Each node contributes local storage │
    └──────────────────────────────────────┘

ReFS BLOCK CLONE:
  - FSCTL_DUPLICATE_EXTENTS_TO_FILE
  - Copy file instantly: chỉ copy metadata references
  - Source và clone share same physical extents
  - Write vào clone → allocate-on-write → new extent
  - Use cases: VM checkpoint, file copy optimization
  - Không hỗ trợ cross-volume

ReFS DEDUPLICATION:
  - Kết hợp ReFS block clone với Data Deduplication service
  - Dedup process identify duplicate blocks
  - Replace duplicates với references (block clone)
  - Space saving cho VM storage, backup repos
```

### 11.5.5 ReFS Dev Drive

```
[UPDATE 2026] Dev Drive — Dành cho developers

  Windows 11 22H2+ giới thiệu Dev Drive:
    - ReFS volume tối ưu cho developer workloads
    - Package cache (npm, NuGet, pip, cargo) và source code
    - Special "performance mode" cho Microsoft Defender
    - Giảm scan overhead cho build processes

  Tạo Dev Drive:
    Settings → System → Storage → Disks & Volumes
    → Create Dev Drive (tối thiểu 50 GB)
    
    Hoặc bằng command:
    Format-Volume -DriveLetter D -FileSystem ReFS -DevDrive

  Performance mode:
    - Defender chuyển từ synchronous scan sang async
    - File system filter overhead giảm
    - Build times có thể cải thiện 10-30%

  Trust: Dev Drive sử dụng "trusted" folders
    - Chỉ trusted processes được phép modify
    - Cấu hình qua Group Policy hoặc Intune

  Giới hạn:
    - Không hỗ trợ BitLocker (trực tiếp)
    - Không hỗ trợ EFS
    - Không hỗ trợ compression
    - Chỉ local volume (không network share)
```

---

## 11.6 File System Filter Drivers

### 11.6.1 Filter Model: Legacy vs Minifilter

```
LEGACY FILTER MODEL (deprecated):
  - Filter driver chèn vào giữa I/O Manager và file system
  - IoRegisterFsRegistrationChange() + IoAttachDeviceToDeviceStack()
  - Phải tự quản lý device stack, IRP forwarding
  - Thứ tự attach không đảm bảo → conflict giữa filters
  - Complex, error-prone development

MINIFILTER MODEL (hiện đại):
  - FltRegisterFilter() với Filter Manager (FltMgr.sys)
  - Altitude-based ordering → thứ tự xử lý được đảm bảo
  - Pre-operation và Post-operation callbacks
  - Filter Manager xử lý phức tạp của IRP management
  - Đơn giản hóa development đáng kể

Filter Manager Frame:
  ┌──────────────────────────────────────────────────┐
  │ I/O Manager                                       │
  ├──────────────────────────────────────────────────┤
  │ Filter Manager (FltMgr.sys)                       │
  │   ┌─────────────────────────────────────────┐    │
  │   │ Altitude 328010: AV minifilter (WdFilter)│    │
  │   │   Pre-Create, Post-Create, Pre-Read...   │    │
  │   ├─────────────────────────────────────────┤    │
  │   │ Altitude 325000: EDR minifilter          │    │
  │   │   Pre-Create, Pre-Write, Pre-SetInfo...  │    │
  │   ├─────────────────────────────────────────┤    │
  │   │ Altitude 189900: Encryption minifilter   │    │
  │   │   Pre-Read (decrypt), Pre-Write (encrypt)│    │
  │   ├─────────────────────────────────────────┤    │
  │   │ Altitude 145000: BitLocker (fvevol.sys)  │    │
  │   │   volume-level encryption                │    │
  │   └─────────────────────────────────────────┘    │
  ├──────────────────────────────────────────────────┤
  │ File System (ntfs.sys, refs.sys)                  │
  └──────────────────────────────────────────────────┘

  IRP flow:
    1. I/O Manager gửi IRP đến Filter Manager
    2. Filter Manager gọi Pre-operation callbacks (cao → thấp altitude)
    3. File system xử lý IRP
    4. Filter Manager gọi Post-operation callbacks (thấp → cao altitude)
    5. I/O completed
```

### 11.6.2 Altitude Allocation

```
ALTITUDE RANGES (Microsoft managed):

  ┌───────────────────────────────┬────────────────────────┐
  │ Range                         │ Filter Group           │
  ├───────────────────────────────┼────────────────────────┤
  │ 400000 - 409999               │ FSFilter Top           │
  │ 360000 - 389999               │ FSFilter Activity Mon  │
  │ 340000 - 349999               │ FSFilter Undelete      │
  │ 320000 - 329999               │ FSFilter Anti-Virus    │
  │ 300000 - 309999               │ FSFilter Replication   │
  │ 280000 - 289999               │ FSFilter Cont Backup   │
  │ 260000 - 269999               │ FSFilter Content Screen│
  │ 240000 - 249999               │ FSFilter Quota Mgmt    │
  │ 220000 - 229999               │ FSFilter System Recov  │
  │ 200000 - 209999               │ FSFilter Cluster FS    │
  │ 180000 - 189999               │ FSFilter HSM           │
  │ 170000 - 174999               │ FSFilter Imaging       │
  │ 160000 - 169999               │ FSFilter Compression   │
  │ 140000 - 149999               │ FSFilter Encryption    │
  │ 130000 - 139999               │ FSFilter Virtualization│
  │ 120000 - 129999               │ FSFilter Physical Quota│
  │ 100000 - 109999               │ FSFilter Open File     │
  │ 80000  - 89999                │ FSFilter Security Enh  │
  │ 60000  - 69999                │ FSFilter Copy Protect  │
  │ 40000  - 49999                │ FSFilter Bottom        │
  └───────────────────────────────┴────────────────────────┘

  Ví dụ các minifilters phổ biến:
    WdFilter.sys        ← Windows Defender (328010)
    wcnfs.sys           ← Windows Container (340000)
    luafv.sys           ← LUA File Virtualization (135000)
    wof.sys             ← Windows Overlay Filter (180410)
    cldFlt.sys          ← Cloud Files Filter (180451)
    bindflt.sys         ← Bind Filter (409800)
    wcifs.sys           ← Windows Container Isolation (180451)

  Kiểm tra filters đang load:
    fltMC.exe filters            ← list all loaded minifilters
    fltMC.exe instances          ← list instances per volume
    fltMC.exe volumes            ← list volumes với filters
```

### 11.6.3 Minifilter Callbacks

```
MINIFILTER REGISTRATION và CALLBACKS:

FLT_REGISTRATION structure:
  Size, Version, Flags
  ContextRegistration     ← context types supported
  OperationRegistration   ← array of {MajorFunction, Pre, Post}
  FilterUnloadCallback    ← cleanup khi unload
  InstanceSetupCallback   ← khi attach tới volume
  InstanceTeardownCallbacks

Key Operation Callbacks:

  IRP_MJ_CREATE (PreCreate / PostCreate):
    PreCreate:
      - Intercept file open
      - Kiểm tra filename, access requested
      - AV: scan file trước khi cho phép access
      - EDR: log file access attempts
      - Block: return FLT_PREOP_COMPLETE với STATUS_ACCESS_DENIED
    PostCreate:
      - File đã được mở thành công
      - Set per-file context
      - Start monitoring file

  IRP_MJ_READ (PreRead / PostRead):
    PreRead:
      - Encryption filter: setup decrypt buffer
    PostRead:
      - AV: scan data vừa đọc
      - Encryption filter: decrypt data trong buffer
      - Modify data trước khi trả về user

  IRP_MJ_WRITE (PreWrite / PostWrite):
    PreWrite:
      - Encryption filter: encrypt data trước khi ghi
      - Content screening: block certain content
      - Ransomware detection: detect mass encryption pattern
    PostWrite:
      - Log write activity

  IRP_MJ_SET_INFORMATION (PreSetInfo / PostSetInfo):
    PreSetInfo:
      - Intercept rename, delete operations
      - Block file deletion (undelete filter)
      - EDR: log file rename/delete
    PostSetInfo:
      - Confirm operation completed

  IRP_MJ_CLEANUP:
    - Last handle close
    - Filter cleanup per-file state

Callback return values:
  FLT_PREOP_SUCCESS_WITH_CALLBACK    ← continue, call PostOp
  FLT_PREOP_SUCCESS_NO_CALLBACK      ← continue, skip PostOp
  FLT_PREOP_PENDING                   ← pend operation
  FLT_PREOP_COMPLETE                  ← complete immediately (block)
  FLT_PREOP_DISALLOW_FASTIO          ← deny fast I/O, force IRP
  FLT_PREOP_SYNCHRONIZE              ← PostOp in same thread
```

### 11.6.4 AV/EDR Minifilter Patterns

```
ANTIVIRUS MINIFILTER:
  Altitude: 320000-329999

  Typical implementation:
    PreCreate:
      - Lưu filename, check against whitelist
    PostCreate:
      - Nếu file executable → scan content
      - Tính hash → check against signature database
      - Nếu malware → FltCancelFileOpen() + STATUS_ACCESS_DENIED
    PreWrite:
      - Re-scan nếu file content thay đổi
    Cleanup:
      - Free per-file scan context

  Challenges:
    - Performance: scan mỗi file open là expensive
    - Solution: cache scan results, re-scan chỉ khi file modified
    - File locking: AV giữ lock khi scan → app wait
    - Kernel crash: AV bug → BSOD (common!)

EDR (Endpoint Detection and Response) MINIFILTER:
  Altitude: 320000-389999 (activity monitor range)

  Typical telemetry:
    - File create/open: process nào, đường dẫn nào, access mask
    - File write: process ghi vào file nào
    - File rename: đổi tên file nào (detect ransomware)
    - File delete: process xóa file nào
    - Send events to user-mode service via FltSendMessage()

  Ransomware detection pattern:
    - Monitor write operations across files
    - Detect pattern: nhiều files bị modify nhanh
    - Detect pattern: file extension thay đổi (.docx → .encrypted)
    - Detect pattern: file entropy tăng (data bị encrypt)
    - Response: block process, alert user, isolate machine

  Bypass techniques (for security research):
    - Direct NTFS parsing (bypass file system layer entirely)
    - Kernel driver load → unload minifilter
    - Minifilter altitude conflict → force higher altitude
    - FltUnregisterFilter() từ kernel mode
    - Rename filter driver file → prevent load at boot
    NOTE: Đây là kỹ thuật attacker sử dụng, cần hiểu để phòng thủ
```

---

## 11.7 Storage Stack

### 11.7.1 Full I/O Stack Detail

```
                        ┌──────────────────────┐
                        │ Application           │
                        │ ReadFile() / WriteFile│
                        └──────────┬───────────┘
                                   │
                        ┌──────────▼───────────┐
                        │ I/O Manager           │
                        │ NtReadFile/NtWriteFile│
                        └──────────┬───────────┘
                                   │ IRP
                        ┌──────────▼───────────┐
                        │ Filter Manager        │
                        │ (FltMgr.sys)          │
                        │ Minifilter callbacks  │
                        └──────────┬───────────┘
                                   │
                        ┌──────────▼───────────┐
                        │ File System           │
                        │ ntfs.sys / refs.sys   │
                        │ Cache hit → CcCopy*   │
                        │ Cache miss → paging IO│
                        └──────────┬───────────┘
                                   │
                        ┌──────────▼───────────┐
                        │ Volume Snapshot        │
                        │ volsnap.sys            │
                        │ (VSS copy-on-write)   │
                        └──────────┬───────────┘
                                   │
                        ┌──────────▼───────────┐
                        │ Volume Manager         │
                        │ volmgr.sys             │
                        │ basic + dynamic disks  │
                        └──────────┬───────────┘
                                   │
                        ┌──────────▼───────────┐
                        │ BitLocker Filter       │
                        │ fvevol.sys             │
                        │ encrypt/decrypt blocks │
                        └──────────┬───────────┘
                                   │
                        ┌──────────▼───────────┐
                        │ Partition Manager      │
                        │ partmgr.sys            │
                        │ partition → disk offset│
                        └──────────┬───────────┘
                                   │
                        ┌──────────▼───────────┐
                        │ Disk Class Driver      │
                        │ disk.sys               │
                        │ SCSI CDB construction  │
                        └──────────┬───────────┘
                                   │
                    ┌───────────────┼───────────────┐
                    │               │               │
          ┌─────────▼──┐  ┌────────▼───┐  ┌───────▼──────┐
          │ StorPort     │  │ NVMe direct│  │ USB Storage  │
          │ storport.sys │  │ stornvme   │  │ usbstor.sys  │
          │ + miniport   │  │ .sys       │  │              │
          └─────────┬──┘  └────────┬───┘  └───────┬──────┘
                    │              │               │
          ┌─────────▼──────────────▼───────────────▼──────┐
          │ Physical Storage Hardware                       │
          │ (HDD, SSD, NVMe, USB, SAN)                     │
          └────────────────────────────────────────────────┘
```

### 11.7.2 Volume Manager và Dynamic Disks

```
BASIC DISKS vs DYNAMIC DISKS:

  Basic Disks:
    - MBR (max 4 primary partitions, 2 TB max)
    - GPT (max 128 partitions, 18 EB max)
    - Đơn giản, supported everywhere
    - Mỗi partition độc lập

  Dynamic Disks (LDM — Logical Disk Manager):
    - LDM database trong cuối disk (1 MB)
    - Support volume types:
      ┌────────────────┬─────────────────────────────┐
      │ Volume Type    │ Mô tả                        │
      ├────────────────┼─────────────────────────────┤
      │ Simple         │ 1 vùng trên 1 disk           │
      │ Spanned        │ Nối nhiều disk thành 1 volume│
      │ Striped (RAID-0)│ Data chia đều across disks  │
      │                │ Nhanh, nhưng mất tất cả      │
      │                │ nếu 1 disk fail              │
      │ Mirrored(RAID-1)│ 2 bản sao trên 2 disks     │
      │                │ Redundancy, read performance │
      │ RAID-5         │ Parity across 3+ disks       │
      │                │ 1 disk fail → rebuild từ     │
      │                │ parity (Server only)          │
      └────────────────┴─────────────────────────────┘

  [UPDATE 2026] Dynamic disks deprecated, thay thế bởi Storage Spaces
```

### 11.7.3 Storage Spaces

```
STORAGE SPACES (Win8+ client, Server 2012+):

  Architecture:
    ┌──────────────────────────────────┐
    │ Virtual Disks (volumes)          │
    │   - ReFS or NTFS formatted       │
    │   - Thin provisioned             │
    ├──────────────────────────────────┤
    │ Storage Pool                      │
    │   - Aggregated physical disks     │
    │   - Managed by SpacePort.sys      │
    ├──────────────────────────────────┤
    │ Physical Disks                    │
    │   - HDD, SSD, NVMe mixed          │
    │   - USB, SATA, SAS               │
    └──────────────────────────────────┘

  Resiliency types:
    Simple:   không redundancy (testing only)
    Mirror:   2-way hoặc 3-way mirror
    Parity:   single hoặc dual parity (chậm write)
    Mirror-Accelerated Parity:
      Hot data → mirror tier (fast write)
      Cold data → parity tier (space efficient)

  Tiered Storage:
    - SSD tier: frequently accessed, hot data
    - HDD tier: infrequently accessed, cold data
    - Auto-tiering: background service di chuyển data
    - Write-back cache: SSD làm cache cho HDD writes
    
  PowerShell management:
    New-StoragePool -FriendlyName "Pool1" `
      -StorageSubSystemFriendlyName "Windows*" `
      -PhysicalDisks (Get-PhysicalDisk -CanPool $true)
    
    New-VirtualDisk -StoragePoolFriendlyName "Pool1" `
      -FriendlyName "VDisk1" `
      -ResiliencySettingName Mirror `
      -Size 500GB -ProvisioningType Thin

MULTIPATH I/O (MPIO):
  - mpio.sys — cho phép nhiều physical paths đến cùng storage
  - Active/Active: load balance across paths
  - Active/Passive: failover khi active path die
  - Dùng cho SAN (Fibre Channel, iSCSI) environments
  - Device-Specific Module (DSM): vendor-specific logic

STORAGE QoS:
  - Giới hạn IOPS và bandwidth per VM hoặc per volume
  - Policy-based: minimum và maximum IOPS
  - Dùng trong Hyper-V và Storage Spaces Direct
  - Đảm bảo noisy neighbor không ảnh hưởng VM khác
```

### 11.7.4 NVMe và Persistent Memory

```
NVMe DRIVER STACK:

  stornvme.sys — Microsoft NVMe driver (inbox):
    - Direct access, không qua SCSI translation
    - Support NVMe command sets:
      Admin commands: Identify, Create/Delete I/O Queue
      I/O commands:   Read, Write, Flush, Compare
    - NVMe queue pairs: Submission Queue + Completion Queue
    - MSI-X interrupt per CPU core → avoid lock contention

  NVMe Namespaces:
    - 1 NVMe controller có thể có nhiều namespaces
    - Mỗi namespace như 1 "virtual disk"
    - Visible as separate disk devices

  [UPDATE 2026] NVMe 2.0 features:
    - Zoned Namespaces (ZNS): optimized cho SSD wear
    - Key-Value commands: bypass file system
    - Computational storage: offload processing to SSD

PERSISTENT MEMORY (PMEM / DAX):
  - Non-volatile memory (Intel Optane, CXL memory)
  - Byte-addressable, không cần block I/O
  - DAX (Direct Access): bypass cache, map trực tiếp vào user VA

  DAX mode:
    1. File system mở file trên PMEM volume
    2. Nếu DAX enabled → MmMapViewInSystemCache skip
    3. Application map file → VA trỏ trực tiếp đến PMEM
    4. Load/Store instructions → truy cập PMEM, KHÔNG page fault
    5. No cache manager, no I/O stack → maximum performance

  NTFS DAX support: DAX volume attribute
  ReFS DAX support: limited (không dùng integrity streams)

  Relevance cho security:
    - PMEM data persist across reboot → forensic interest
    - Direct access bypass security filters → potential bypass
    - clflush/clwb instructions để flush CPU cache đến PMEM
```

### 11.7.5 iSCSI

```
iSCSI STACK:

  iSCSI Initiator (client side):
    ┌──────────────────────────────┐
    │ iscsiprt.sys (port driver)    │
    │   ├── Login to iSCSI target   │
    │   ├── SCSI CDB over TCP/IP    │
    │   ├── CHAP authentication     │
    │   └── iSCSI sessions/connections│
    ├──────────────────────────────┤
    │ TCP/IP stack                  │
    │   Port 3260 (default)         │
    └──────────────────────────────┘

  Configuration:
    iscsicli.exe — command line tool
    iSCSI Initiator GUI — Control Panel
    
    Connect: iscsicli QAddTargetPortal <ip>
    Login:   iscsicli LoginTarget <target_name> T * * * * * * * * * * * * * * 0
    
  Security:
    - CHAP authentication
    - IPsec encryption cho data in transit
    - VLAN isolation cho iSCSI traffic
    - Mutual CHAP (target xác thực initiator và ngược lại)
```

---

## 11.8 BitLocker

### 11.8.1 Key Architecture

```
BITLOCKER KEY CHAIN:

  ┌─────────────────────────────────────────┐
  │ Full Volume Encryption Key (FVEK)       │
  │   - AES key that encrypts volume data    │
  │   - Generated once, never changes        │
  │   - Stored encrypted by VMK              │
  ├─────────────────────────────────────────┤
  │ Volume Master Key (VMK)                  │
  │   - Intermediate key                     │
  │   - Encrypted by one or more protectors  │
  │   - Allows key rotation without re-encrypt│
  │   - Stored in BitLocker metadata          │
  ├─────────────────────────────────────────┤
  │ Key Protectors (one or more):            │
  │   ├── TPM (sealed to PCR values)         │
  │   ├── TPM + PIN                          │
  │   ├── TPM + Startup Key (USB)            │
  │   ├── Password                           │
  │   ├── Recovery Password (48-digit)       │
  │   ├── Recovery Key (USB file)            │
  │   ├── Certificate (smart card/DRA)       │
  │   ├── Auto-unlock (stored in registry)   │
  │   └── Network Unlock (DHCP/certificate)  │
  └─────────────────────────────────────────┘

  Key flow:
    Boot → TPM unseal VMK → VMK decrypt FVEK → FVEK decrypt data

    Nếu TPM PCR values không match (boot config thay đổi):
      → TPM refuse unseal → recovery mode
      → User nhập 48-digit recovery password
      → Recovery password decrypt VMK → continue

  Why 2-level keys (VMK + FVEK)?
    - Thay đổi protector (ví dụ: add PIN) chỉ cần re-encrypt VMK
    - FVEK không thay đổi → không cần re-encrypt toàn bộ volume
    - Giả sử re-encrypt 1 TB volume mỗi khi thay đổi password = mất hours
```

### 11.8.2 Encryption Algorithms

```
BITLOCKER ENCRYPTION MODES:

  ┌────────────────────┬──────────────────────────────────┐
  │ Algorithm          │ Mô tả                             │
  ├────────────────────┼──────────────────────────────────┤
  │ AES-CBC 128-bit    │ Legacy, compatible               │
  │ AES-CBC 256-bit    │ Legacy, stronger                 │
  │ AES-XTS 128-bit    │ Default (Win10+), fixed-disk only│
  │ AES-XTS 256-bit    │ Strongest, fixed-disk only       │
  └────────────────────┴──────────────────────────────────┘

  AES-CBC (Cipher Block Chaining):
    - Block cipher với diffuser (Elephant diffuser trong Vista/7, bỏ từ Win8)
    - Sector number dùng làm IV (Initialization Vector)
    - Removable media vẫn dùng AES-CBC (compatibility)

  AES-XTS (XEX-based Tweaked-codebook mode with ciphertext Stealing):
    - Thiết kế cho disk encryption
    - Tweak value = sector number
    - Không cần diffuser
    - Không support removable media (USB = AES-CBC)
    - Default cho fixed disks từ Windows 10

  Group Policy: Computer Configuration → Administrative Templates
    → Windows Components → BitLocker Drive Encryption
    → Choose drive encryption method and cipher strength

USED SPACE ONLY ENCRYPTION:
  - Chỉ encrypt sectors đã có data
  - Free space không được encrypt
  - Nhanh hơn full encryption (ví dụ: 30 phút vs 5 giờ cho 500 GB)
  - An toàn cho new disk, KHÔNG an toàn cho disk đã sử dụng
    (free space có thể chưa chứa deleted data fragments)
  - manage-bde -on C: -UsedSpaceOnly
```

### 11.8.3 BitLocker Management

```
MANAGE-BDE COMMANDS:

  manage-bde -status                    ← trạng thái tất cả volumes
  manage-bde -status C:                 ← chi tiết volume C:
  manage-bde -on C: -RecoveryPassword   ← bật, tạo recovery password
  manage-bde -on C: -TPMAndPIN          ← bật với TPM + PIN
  manage-bde -off C:                    ← decrypt volume
  manage-bde -pause C:                  ← tạm dừng encrypt/decrypt
  manage-bde -resume C:                 ← tiếp tục
  manage-bde -lock D:                   ← lock removable drive
  manage-bde -unlock D: -RecoveryPassword 123456-...  ← unlock
  manage-bde -protectors -add C: -TPMAndPIN           ← thêm protector
  manage-bde -protectors -delete C: -id {GUID}        ← xóa protector
  manage-bde -protectors -get C:        ← list protectors
  manage-bde -changepin C:              ← đổi PIN
  manage-bde -forcerecovery C:          ← force recovery mode at boot

BITLOCKER TO GO (removable media):
  - Encrypt USB drives
  - AES-CBC (cho compatibility với older Windows)
  - BitLocker To Go Reader cho Windows 7 (read-only access)
  - manage-bde -on D: -Password ← encrypt USB với password

BITLOCKER NETWORK UNLOCK (enterprise):
  - DHCP-based unlock tại boot
  - Yêu cầu:
    1. UEFI DHCP client (firmware support)
    2. WDS server với Network Unlock certificate
    3. Certificate-based protector trên client
  - Flow:
    1. Client boot, DHCP request với Network Unlock extension
    2. WDS server respond với encrypted key
    3. Client decrypt → VMK → unlock volume
    4. Chỉ hoạt động trong corporate network
    → Reboot servers tự động không cần nhập PIN

BITLOCKER CSP (Configuration Service Provider):
  - MDM management (Intune, SCCM)
  - ./Device/Vendor/MSFT/BitLocker
  - RequireDeviceEncryption: enforce encryption
  - EncryptionMethodByDriveType: set algorithm
  - SystemDrivesRecoveryOptions: configure recovery
  - [UPDATE 2026] Intune now supports full BitLocker
    reporting và compliance status
```

### 11.8.4 BitLocker Metadata và Recovery

```
BITLOCKER METADATA:

  Stored in 3 locations trên volume:
    1. Đầu volume (trước data area)
    2. Giữa volume
    3. Cuối volume
  → Redundancy: bất kỳ 1 copy đủ để unlock

  Metadata structure:
    ┌──────────────────────────────┐
    │ Signature: "-FVE-FS-"        │
    │ Version                       │
    │ Encryption method             │
    │ Creation time                 │
    │ Number of entries             │
    ├──────────────────────────────┤
    │ VMK Entry 1 (TPM protector)  │
    │   Type: TPM                   │
    │   Nonce + MAC                 │
    │   Encrypted VMK blob          │
    ├──────────────────────────────┤
    │ VMK Entry 2 (Recovery pwd)   │
    │   Type: Recovery password     │
    │   Salt                        │
    │   Encrypted VMK blob          │
    ├──────────────────────────────┤
    │ FVEK Entry                    │
    │   Encrypted by VMK            │
    │   AES-CCM encrypted blob      │
    └──────────────────────────────┘

RECOVERY:
  - 48-digit recovery password (8 groups of 6 digits)
  - Mỗi group là số 0-720895 (< 2^20)
  - Tổng cộng 128 bits entropy
  - Backup locations:
    1. Azure AD / Entra ID (corporate)
    2. Microsoft Account (personal)
    3. USB drive (file .bek)
    4. Printed paper
    5. Active Directory (Group Policy configured)
  - manage-bde -protectors -get C: -Type RecoveryPassword
```

---

## 11.9 Security và Forensics

### 11.9.1 NTFS Forensics Techniques

```
DELETED FILE RECOVERY:
  - Khi delete file: MFT record marked as NOT in-use
  - Data clusters marked as FREE trong $Bitmap
  - NHƯNG data vẫn còn trên disk cho đến khi bị overwrite
  - Recovery: scan MFT cho not-in-use records với valid data runs
  - Tools: Autopsy, FTK, Recuva, R-Studio

TIMESTAMP ANALYSIS (MACE times):

  $STANDARD_INFORMATION (0x10):
    M — Modified        ← content thay đổi
    A — Accessed        ← file được đọc
    C — Changed (MFT)   ← MFT record thay đổi
    E — Entry created   ← file được tạo

  $FILE_NAME (0x30):
    M, A, C, E — duplicate timestamps
    ← Cập nhật ít thường xuyên hơn SI timestamps
    ← KHÓ thay đổi từ user-mode → useful cho forensics

  Timestamp resolution: 100 nanoseconds

  Ví dụ analysis:
    SI.Created = 2024-01-15 10:00:00
    FN.Created = 2024-06-20 14:30:00
    → SI.Created < FN.Created là BẤT THƯỜNG
    → Có thể file bị timestomped (SI times bị sửa)
    → FN times phản ánh thời gian thực (khó fake)

ALTERNATE DATA STREAMS (ADS) — Data Hiding:
  - Attacker giấu malware trong ADS
  - ADS không hiện trong dir listing bình thường
  - ADS không tính vào file size hiển thị
  - Kiểm tra: dir /R, streams.exe -s, hoặc forensic tools
  
  Ví dụ:
    echo "malware payload" > legit.txt:hidden.exe
    wmic process call create "C:\path\legit.txt:hidden.exe"
    (Older Windows — modern versions ngăn chặn execution từ ADS)

  Zone.Identifier ADS:
    - Tự động tạo khi download file từ Internet
    - [ZoneTransfer] ZoneId=3 → Internet zone
    - Khi execute: SmartScreen warning
    - Attacker có thể xóa ADS này để bypass MOTW:
        (echo.) > file.exe:Zone.Identifier
```

### 11.9.2 Timeline Reconstruction

```
SỬ DỤNG $UsnJrnl VÀ $LogFile cho Timeline:

  $UsnJrnl timeline:
    1. Parse tất cả USN records
    2. Sort by timestamp
    3. Filter by:
       - Specific file/folder
       - Specific reason codes (CREATE, DELETE, RENAME)
       - Time range
    4. Reconstruct: ai đã làm gì, khi nào

  $LogFile timeline:
    1. Parse log records
    2. Tìm CreateAttribute, DeleteAttribute, etc.
    3. Map TargetAttribute đến MFT record/attribute
    4. Reconstruct metadata changes chi tiết hơn USN

  Kết hợp USN + LogFile:
    USN: "file.exe was CREATED at 14:30"
    LogFile: "MFT record 12345 initialized,
              $DATA attribute created, data runs allocated"
    → Chi tiết hơn về CÁCH file được tạo

  Tools:
    - ANJP (Another NTFS Journal Parser) — parse $LogFile
    - MFTECmd (Eric Zimmerman) — parse $MFT
    - usn.py (PythonForensics) — parse $UsnJrnl
    - Velociraptor: Windows.NTFS.MFT artifact
    - Plaso/log2timeline — super-timeline từ nhiều nguồn
```

### 11.9.3 Anti-Forensics Techniques

```
TIMESTOMPING:
  - Sử dụng SetFileTime() API để thay đổi SI timestamps
  - Tools: timestomp (Metasploit), NirSoft BulkFileChanger
  - Detection: so sánh SI và FN timestamps
    Nếu SI.Created < FN.Created → suspicious
    (Normally SI.Created >= FN.Created)

  Advanced timestomping:
    - Modify FN timestamps trực tiếp trong MFT
    - Cần kernel-mode access hoặc raw disk write
    - Rất khó detect, nhưng để lại dấu vết trong $LogFile

LOG CLEARING:
  - fsutil usn deletejournal /D C:    ← xóa USN journal
  - Detection: UsnJournalID thay đổi, FirstUsn lớn bất thường
  - $LogFile: khó xóa riêng, nhưng có thể format volume

SECURE DELETE:
  - Overwrite data trước khi delete → recovery khó hơn
  - cipher /W:C:\path  ← Windows built-in, ghi đè free space
  - SSD: TRIM command làm data unrecoverable nhanh
  - TRIM là tự động trên NTFS/SSD → deleted data mất nhanh

MFT SLACK SPACE:
  - MFT record 1024 bytes, nhưng file metadata thường nhỏ hơn
  - Slack space (phần thừa) có thể chứa old attribute data
  - Forensic: đọc slack space để tìm thông tin đã xóa
```

### 11.9.4 EFS Attack Surface

```
EFS (Encrypting File System) Attacks:

  1. DPAPI DEPENDENCY:
     - EFS private key encrypted by DPAPI
     - DPAPI master key encrypted by user password
     - Nếu có user password hash → decrypt DPAPI → decrypt EFS key
     - Mimikatz: sekurlsa::dpapi + dpapi::masterkey

  2. RECOVERY AGENT:
     - Default: Administrator là Data Recovery Agent (DRA)
     - Nếu compromise DRA private key → decrypt TẤT CẢ EFS files
     - DRA certificate in AD → target cho lateral movement

  3. RAW DISK ACCESS:
     - EFS encrypt data nhưng không protect metadata
     - File name, size, timestamps vẫn visible
     - $LOGGED_UTILITY_STREAM chứa encrypted FEK → có thể extract

  4. MEMORY FORENSICS:
     - Decrypted file data có thể tồn tại trong memory
     - Page file có thể chứa decrypted content
     - Hibernate file (hiberfil.sys) có thể chứa keys

  5. TEMP FILES:
     - App có thể tạo temp files từ EFS-encrypted data
     - Temp files không encrypted → data leak
     - %TEMP% folder thường không encrypted
```

### 11.9.5 BitLocker Attacks

```
BITLOCKER ATTACK VECTORS:

  1. COLD BOOT ATTACK:
     - RAM giữ data vài giây sau khi tắt nguồn
     - Làm lạnh RAM (compressed air) → kéo dài thời gian
     - Boot từ USB → dump RAM → extract FVEK/VMK
     - Mitigation: TPM + PIN (FVEK không còn trong RAM khi locked)
     - [UPDATE 2026] Modern CPUs có memory encryption (TME/MKTME)
       làm cold boot khó hơn

  2. DMA ATTACK:
     - Thiết bị PCIe/Thunderbolt có thể DMA vào system memory
     - Plug malicious device → read RAM → extract keys
     - Tools: PCILeech, Inception
     - Mitigation:
       - Kernel DMA Protection (Win10 1803+)
       - IOMMU / VT-d enforcement
       - Group Policy: disable new DMA devices khi locked

  3. EVIL MAID ATTACK:
     - Physical access khi machine tắt
     - Modify boot process để capture PIN/password
     - Ví dụ: replace bootloader với keylogger
     - Mitigation: Secure Boot, TPM PCR validation
     - Measured Boot: mỗi boot component được hash vào PCR

  4. TPM SNIFFING:
     - TPM communicate với CPU qua LPC/SPI bus
     - Probe bus → capture VMK khi TPM unseal
     - Tools: logic analyzer, custom hardware
     - Chỉ apply cho discrete TPM (không fTPM)
     - Mitigation: TPM + PIN (TPM chỉ unseal sau khi verify PIN)
     - [UPDATE 2026] fTPM (firmware TPM) trong AMD/Intel CPUs
       không có external bus → immune to sniffing

  5. BITLOCKER BYPASS với RECOVERY KEY:
     - Social engineering: thuyết phục IT admin cung cấp recovery key
     - Azure AD: compromise admin → truy cập recovery keys
     - Active Directory: recovery key stored in AD → LDAP query

  6. BOOTKITS:
     - Modify boot process trước BitLocker unlock
     - Ví dụ: UEFI rootkit persist trong firmware
     - Mitigation: Secure Boot, UEFI firmware update
     - [UPDATE 2026] Pluton security processor cung cấp
       hardware root of trust mới
```

---

## 11.10 Experiments

### 11.10.1 MFT Analysis

```cmd
:: View file MFT record number
fsutil file queryFileID C:\Windows\notepad.exe

:: View file extents (data runs)
fsutil file queryExtents C:\Windows\notepad.exe

:: View file attributes
fsutil file queryAllocRanges C:\file.txt

:: Check alternate data streams
dir /R C:\Users\Downloads\
streams.exe -s C:\Users\

:: NtfsInfo — Sysinternals NTFS volume information
ntfsinfo.exe C:

:: DiskView — Sysinternals visual cluster map
diskview.exe
```

### 11.10.2 Cache Manager Debugging (WinDbg)

```
:: === CACHE MANAGER ===

kd> !filecache
  ; Hiển thị tổng quát cache manager statistics
  ; VACB count, dirty pages, read-ahead stats

kd> !finddata <address>
  ; Tìm shared cache map từ 1 địa chỉ trong system cache

kd> dt nt!_SHARED_CACHE_MAP <address>
  ; Dump Shared Cache Map structure
  ;   +0x000 NodeTypeCode
  ;   +0x008 FileSize
  ;   +0x038 DirtyPages
  ;   +0x068 Vacbs

kd> dt nt!_VACB <address>
  ; Dump VACB structure
  ;   +0x000 BaseAddress
  ;   +0x008 SharedCacheMap
  ;   +0x010 Overlay

kd> dt nt!_PRIVATE_CACHE_MAP <address>
  ; Dump Private Cache Map
  ;   Read-ahead tracking fields

kd> !fileobj <FileObject_address>
  ; Dump FILE_OBJECT — show filename, related cache maps

:: === NTFS STRUCTURES ===

kd> !ntfs <address>
  ; Basic NTFS volume info

kd> dt ntfs!_FCB <address>
  ; NTFS File Control Block

kd> dt ntfs!_SCB <address>
  ; NTFS Stream Control Block

:: === PERFORMANCE COUNTERS ===

Performance Monitor counters:
  Cache\Copy Reads/sec         ; cached read operations
  Cache\Copy Read Hits %       ; percentage of cache hits
  Cache\Lazy Write Flushes/sec ; lazy writer activity
  Cache\Data Map Pins/sec      ; pinned data operations
  Cache\Read Aheads/sec        ; read-ahead operations
  Cache\Data Flushes/sec       ; flush operations
  
  Memory\Cache Bytes           ; total system cache size
  Memory\Cache Faults/sec      ; cache miss rate
  
  LogicalDisk\Disk Read Bytes/sec  ; actual disk I/O
  PhysicalDisk\% Disk Time        ; disk utilization
```

### 11.10.3 USN Journal Forensics

```cmd
:: Query USN Journal info
fsutil usn queryjournal C:

:: Enumerate USN data (list all files on volume)
fsutil usn enumdata 1 0 1 C:

:: Read recent journal entries
fsutil usn readjournal C: csv

:: Create USN journal (if not exists)
fsutil usn createjournal m=1073741824 a=8388608 C:
:: m = max size (1 GB), a = allocation delta (8 MB)

:: Delete USN journal (anti-forensics — for awareness)
:: fsutil usn deletejournal /D C:
:: WARNING: destroys forensic evidence
```

### 11.10.4 BitLocker Experiments

```cmd
:: Check BitLocker status
manage-bde -status

:: Detailed volume status
manage-bde -status C:

:: List protectors
manage-bde -protectors -get C:

:: Enable BitLocker with TPM and recovery password
manage-bde -on C: -TPMAndRecoveryPassword

:: Suspend protection (for BIOS update)
manage-bde -protectors -disable C:

:: Resume protection
manage-bde -protectors -enable C:

:: PowerShell alternatives
Get-BitLockerVolume
Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 `
  -RecoveryPasswordProtector
```

### 11.10.5 File System Filter Experiments

```cmd
:: List loaded minifilters
fltMC.exe filters

:: List filter instances per volume
fltMC.exe instances

:: List volumes with attached filters
fltMC.exe volumes

:: Unload a minifilter (requires admin, dangerous)
fltMC.exe unload <FilterName>

:: Load a minifilter
fltMC.exe load <FilterName>

:: Attach minifilter to volume
fltMC.exe attach <FilterName> <Volume> [Altitude]

:: Detach minifilter from volume
fltMC.exe detach <FilterName> <Volume> [InstanceName]
```

### 11.10.6 Storage Diagnostics

```cmd
:: fsutil tổng hợp
fsutil fsinfo drives                    ; list drives
fsutil fsinfo volumeinfo C:             ; volume info (FS type, features)
fsutil fsinfo ntfsinfo C:               ; NTFS-specific info
fsutil fsinfo refsinfo D:               ; ReFS-specific info
fsutil fsinfo sectorinfo C:             ; physical sector size

:: File system behavior
fsutil behavior query DisableLastAccess  ; tắt NTFS last access update?
fsutil behavior query DisableDeleteNotify; TRIM disabled?
fsutil behavior query EncryptPagingFile  ; pagefile encrypted?
fsutil behavior query MftZone            ; MFT zone size

:: Repair
fsutil repair query C:                  ; query self-healing state

:: Storage Spaces
Get-StoragePool                         ; list pools
Get-VirtualDisk                         ; list virtual disks
Get-PhysicalDisk                        ; list physical disks
Get-PhysicalDisk | Get-StorageReliabilityCounter  ; disk health

:: NVMe info
Get-PhysicalDisk | Where MediaType -eq SSD | 
  Get-StorageReliabilityCounter
winsat disk                             ; Windows System Assessment
```

---

## 11.11 Tóm Tắt

| Khái niệm | Điểm chính |
|-----------|------------|
| Cache Manager | Unified cache, VACB 256KB views, lazy write, intelligent read-ahead với stride detection, write throttling (CcCanIWrite/CcDeferWrite) |
| Shared Cache Map | Per-file, chứa VACB array, dirty page count, section pointer, callbacks |
| Private Cache Map | Per-handle, track read pattern cho read-ahead, 2 recent reads |
| VACB | 256KB mapping unit, inline (4) hoặc multi-level array cho file lớn |
| Cache Coherency | Cache Manager và Memory Manager share section objects và physical pages |
| Fast I/O | Bypass IRP overhead cho cached reads/writes, fallback nếu cần |
| Mapped/Pinned Access | CcMapData (read-only), CcPinRead (modify) — NTFS dùng cho metadata |
| MFT Record | 1KB, fixup array bảo vệ multi-sector, sequence number chống stale handle |
| B+ Tree Index | $INDEX_ROOT (resident gốc) + $INDEX_ALLOCATION (non-resident nodes) |
| Reparse Points | Extension mechanism, tags cho symlinks, mount points, cloud files, WSL |
| $Secure | Shared security descriptors, $SDH hash index, $SII SecurityId index |
| $LogFile | Write-ahead log, LSN-based, 3-pass recovery (Analysis/Redo/Undo) |
| $UsnJrnl | Change journal, USN_RECORD_V2/V3, reason codes, forensic timeline |
| USN FSCTL | QUERY_USN_JOURNAL, READ_USN_JOURNAL, ENUM_USN_DATA cho forensics |
| ReFS | Allocate-on-write, B+ tree everything, integrity streams, block clone |
| ReFS Dev Drive | [UPDATE 2026] Developer-optimized ReFS volume, performance mode Defender |
| Minifilters | Altitude-ordered, pre/post callbacks, Filter Manager framework |
| AV/EDR Filters | Altitude 320K-389K, scan on create/read, monitor writes, detect ransomware |
| Storage Spaces | Pool physical disks, mirror/parity/tiered, replace dynamic disks |
| NVMe | stornvme.sys, queue pairs per core, namespaces |
| Persistent Memory | DAX mode, bypass cache/I/O stack, byte-addressable NVDIMM |
| BitLocker Keys | FVEK (encrypt data) ← VMK (intermediate) ← Protectors (TPM/PIN/pwd) |
| BitLocker Algo | AES-XTS 128/256 (fixed), AES-CBC 128/256 (removable), used-space-only option |
| BitLocker Recovery | 48-digit password, backup to AD/Azure AD/USB, Network Unlock enterprise |
| NTFS Forensics | MACE timestamps, ADS data hiding, deleted file recovery, MFT slack |
| Anti-Forensics | Timestomping (SI vs FN detection), USN journal delete, secure delete |
| BitLocker Attacks | Cold boot, DMA, evil maid, TPM sniffing — mitigated by TPM+PIN, IOMMU |

> **Tiếp theo: [Chapter 12 — Startup và Shutdown](Chapter_12_Startup_Shutdown.md)**
