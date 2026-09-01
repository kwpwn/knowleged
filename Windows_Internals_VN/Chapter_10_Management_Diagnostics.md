# Chapter 10: Quản Lý, Chẩn Đoán và Tracing

> Chương này bao gồm: Registry internals (hive format, cell structures, registry
> virtualization, transactional registry, registry callbacks), ETW (provider types,
> Threat Intelligence provider, ETW evasion/detection), WMI (CIM repository, event
> subscriptions, WMI persistence), Windows Error Reporting (crash dump types, WinDbg
> analysis, pool corruption), Task Scheduler internals, Performance Counters,
> Security-relevant diagnostics (Sysmon, EVTX, PowerShell logging, Security Event IDs),
> và các cập nhật Windows 11 24H2.

---

## 10.1 Registry Internals

Registry là cơ sở dữ liệu phân cấp lưu trữ cấu hình của hệ điều hành, driver, service,
và ứng dụng. Với security researcher, hiểu sâu về registry internals rất quan trọng cho
forensics, malware analysis, và persistence detection.

### 10.1.1 Registry Hive Architecture

Mỗi hive là một file nhị phân trên disk được map vào memory bởi Configuration Manager
(Cm) của kernel.

```
Registry namespace:
  HKEY_LOCAL_MACHINE (HKLM)
    ├── SYSTEM        → %SystemRoot%\System32\config\SYSTEM
    ├── SOFTWARE      → %SystemRoot%\System32\config\SOFTWARE
    ├── SAM           → %SystemRoot%\System32\config\SAM
    ├── SECURITY      → %SystemRoot%\System32\config\SECURITY
    ├── DEFAULT       → %SystemRoot%\System32\config\DEFAULT
    ├── DRIVERS       → (volatile, memory only)
    ├── HARDWARE      → (volatile, memory only)
    └── BCD00000000   → \Boot\BCD

  HKEY_USERS (HKU)
    ├── .DEFAULT      → DEFAULT hive
    ├── S-1-5-18      → SYSTEM profile
    ├── S-1-5-xx-xxx  → NTUSER.DAT của user (đã load)
    └── S-1-5-xx_Classes → UsrClass.dat

  HKEY_CURRENT_USER (HKCU) → shortcut tới HKU\<current SID>
  HKEY_CLASSES_ROOT (HKCR) → merged view: HKLM\SOFTWARE\Classes + HKCU\SOFTWARE\Classes
  HKEY_CURRENT_CONFIG → HKLM\SYSTEM\CurrentControlSet\Hardware Profiles\Current
```

### 10.1.2 Hive File Format - Base Block (Header)

Base block là 4096 bytes đầu tiên của hive file, chứa metadata quan trọng:

```
Hive Base Block (regf header) - 4096 bytes:
┌─────────────────────────────────────────────────────────┐
│ Offset  Size   Field                                    │
├─────────────────────────────────────────────────────────┤
│ 0x0000  4      Signature: "regf" (0x66676572)           │
│ 0x0004  4      Primary Sequence Number                  │
│ 0x0008  4      Secondary Sequence Number                │
│ 0x000C  8      Last Written Timestamp (FILETIME)        │
│ 0x0014  4      Major Version (1)                        │
│ 0x0018  4      Minor Version (3, 4, 5, or 6)           │
│ 0x001C  4      Type (0 = Primary)                       │
│ 0x0020  4      Format (1 = Direct memory load)          │
│ 0x0024  4      Root Cell Offset (relative to first hbin)│
│ 0x0028  4      Hive Data Size (total bins)              │
│ 0x002C  4      Clustering Factor                        │
│ 0x0030  64     File Name (UTF-16, null-terminated)      │
│ 0x0070  ...    Padding / Reserved                       │
│ 0x00FC  4      Repair flags (RmId, LogId, etc.)         │
│ 0x01FC  4      Checksum (XOR of first 508 bytes / 4)    │
│ 0x0200  ...    Boot Recover / Boot Type (v1.4+)         │
│ 0x1000  ---    (End of base block, start of first hbin) │
└─────────────────────────────────────────────────────────┘

Consistency check:
  - Primary Sequence == Secondary Sequence → hive clean
  - Primary Sequence != Secondary Sequence → crash during write
    → Recovery: replay .LOG1 or .LOG2 transaction log
  - Checksum = XOR của từng 4-byte block trong 508 bytes đầu
```

**Forensics note**: Khi phân tích hive offline, kiểm tra sequence numbers trước.
Nếu không khớp, hive có thể bị corrupt hoặc đang trong quá trình write khi system crash.

### 10.1.3 Hive Bin (hbin)

Sau base block, dữ liệu được tổ chức thành các hive bin. Mỗi bin bắt đầu bằng
hbin header và chứa nhiều cells:

```
Hive Bin structure:
┌──────────────────────────────────────────────────────────┐
│ hbin Header (32 bytes)                                    │
│  Offset  Size  Field                                      │
│  0x0000  4     Signature: "hbin" (0x6E696268)             │
│  0x0004  4     Offset của bin này từ đầu hive data        │
│  0x0008  4     Size của bin (bội số của 4096 bytes)       │
│  0x000C  8     Reserved (timestamp trong versions cũ)      │
│  0x0014  4     Spare                                       │
├──────────────────────────────────────────────────────────┤
│ Cell 1 (allocated or free)                                │
│  ┌──────────────────────────────────────────────────┐    │
│  │ Cell Size (4 bytes, signed)                       │    │
│  │   > 0 = Free cell (positive)                      │    │
│  │   < 0 = Allocated cell (negative, |size| = length)│    │
│  │ Cell Data (key node, value, security, etc.)       │    │
│  └──────────────────────────────────────────────────┘    │
│ Cell 2                                                    │
│ Cell 3                                                    │
│ ...                                                       │
│ Free space (if any)                                       │
└──────────────────────────────────────────────────────────┘

Quan trọng:
  - Cell size âm (negative) = cell đang được sử dụng (allocated)
  - Cell size dương (positive) = cell đã bị xóa hoặc chưa được dùng (free)
  - Đây là cơ sở của DELETED KEY RECOVERY trong forensics!
```

### 10.1.4 Cell Types Chi Tiết

#### Key Node Cell (nk)

```
Key Node (nk) cell - chứa thông tin về một registry key:
┌──────────────────────────────────────────────────────────┐
│ Offset  Size   Field                Description          │
├──────────────────────────────────────────────────────────┤
│ 0x0000  4      Cell Size            (negative = in use)  │
│ 0x0004  2      Signature            "nk" (0x6B6E)       │
│ 0x0006  2      Flags                                     │
│                  0x0001 = KEY_VOLATILE (not persisted)    │
│                  0x0002 = KEY_HIVE_EXIT (mount point)    │
│                  0x0004 = KEY_HIVE_ENTRY (root key)      │
│                  0x0008 = KEY_NO_DELETE                   │
│                  0x0010 = KEY_SYM_LINK (symbolic link)   │
│                  0x0020 = KEY_COMP_NAME (compressed name)│
│                  0x0040 = KEY_PREDEF_HANDLE               │
│ 0x0008  8      Last Written Timestamp (FILETIME)         │
│ 0x0010  4      Access Bits / Spare                       │
│ 0x0014  4      Parent Key offset                         │
│ 0x0018  4      Number of stable subkeys                  │
│ 0x001C  4      Number of volatile subkeys                │
│ 0x0020  4      Subkeys List offset (stable)              │
│ 0x0024  4      Subkeys List offset (volatile)            │
│ 0x0028  4      Number of values                          │
│ 0x002C  4      Value List offset                         │
│ 0x0030  4      Security Key (sk) offset                  │
│ 0x0034  4      Class Name offset                         │
│ 0x0038  4      Max Subkey Name Length                     │
│ 0x003C  4      Max Class Name Length                      │
│ 0x0040  4      Max Value Name Length                      │
│ 0x0044  4      Max Value Data Length                      │
│ 0x0048  4      WorkVar                                    │
│ 0x004C  2      Key Name Length                            │
│ 0x004E  2      Class Name Length                          │
│ 0x0050  var    Key Name (ASCII if compressed, UTF-16 else)│
└──────────────────────────────────────────────────────────┘

Forensics: Last Written Timestamp rất quan trọng cho timeline analysis.
Mỗi khi key hoặc value của key bị thay đổi, timestamp này được cập nhật.
```

#### Value Cell (vk)

```
Value (vk) cell - chứa thông tin về một registry value:
┌──────────────────────────────────────────────────────────┐
│ Offset  Size   Field                Description          │
├──────────────────────────────────────────────────────────┤
│ 0x0000  4      Cell Size                                 │
│ 0x0004  2      Signature            "vk" (0x6B76)       │
│ 0x0006  2      Name Length           (0 = default value) │
│ 0x0008  4      Data Length                                │
│                  Bit 31 set = data stored inline (<=4 B) │
│                  Bit 31 clear = data at offset           │
│ 0x000C  4      Data Offset (or inline data if <= 4 bytes)│
│ 0x0010  4      Data Type                                 │
│ 0x0014  2      Flags                                     │
│                  0x0001 = VALUE_COMP_NAME (compressed)   │
│ 0x0016  2      Spare                                     │
│ 0x0018  var    Value Name                                 │
└──────────────────────────────────────────────────────────┘
```

#### Security Descriptor Cell (sk)

```
Security (sk) cell - chứa security descriptor của key:
┌──────────────────────────────────────────────────────────┐
│ Offset  Size   Field                                     │
├──────────────────────────────────────────────────────────┤
│ 0x0000  4      Cell Size                                 │
│ 0x0004  2      Signature            "sk" (0x6B73)       │
│ 0x0006  2      Reserved                                  │
│ 0x0008  4      Forward Link (next sk cell)               │
│ 0x000C  4      Back Link (previous sk cell)              │
│ 0x0010  4      Reference Count (keys sharing this sk)    │
│ 0x0014  4      Security Descriptor Size                  │
│ 0x0018  var    Security Descriptor (self-relative)       │
└──────────────────────────────────────────────────────────┘

Lưu ý: sk cells được CHIA SẺ giữa nhiều keys có cùng security.
Chúng tạo thành doubly-linked list. Reference count theo dõi
bao nhiêu key đang tham chiếu tới sk cell này.
```

#### Subkey List Cells (lf, lh, ri)

```
Fast Leaf (lf) - subkey list với 4-byte name hint:
┌──────────────────────────────────────────────────────────┐
│ 0x0000  4   Cell Size                                     │
│ 0x0004  2   Signature "lf" (0x666C)                      │
│ 0x0006  2   Number of entries                             │
│ 0x0008  var  Array of { Key Offset (4), Name Hint (4) }  │
│              Name Hint = 4 ký tự đầu của key name (ASCII)│
└──────────────────────────────────────────────────────────┘

Hash Leaf (lh) - subkey list với hash (thay thế lf từ version 1.4+):
┌──────────────────────────────────────────────────────────┐
│ 0x0000  4   Cell Size                                     │
│ 0x0004  2   Signature "lh" (0x686C)                      │
│ 0x0006  2   Number of entries                             │
│ 0x0008  var  Array of { Key Offset (4), Name Hash (4) }  │
│              Name Hash = hash của toàn bộ key name        │
└──────────────────────────────────────────────────────────┘

Index Root (ri) - cho keys có nhiều subkeys (>500-1000):
┌──────────────────────────────────────────────────────────┐
│ 0x0000  4   Cell Size                                     │
│ 0x0004  2   Signature "ri" (0x6972)                      │
│ 0x0006  2   Number of entries                             │
│ 0x0008  var  Array of { Subkey List Offset (4) }          │
│              Mỗi offset trỏ tới một lf/lh cell            │
└──────────────────────────────────────────────────────────┘

Lookup flow:
  1. Từ nk cell, lấy subkey list offset
  2. Nếu là lh: tính hash của key name cần tìm, so sánh với hash entries
  3. Nếu hash khớp: theo offset đến nk cell, so sánh full name
  4. Nếu là ri: duyệt từng lh/lf con để tìm
```

#### Big Data Cell (db)

```
Big Data (db) cell - cho values lớn hơn 16344 bytes:
┌──────────────────────────────────────────────────────────┐
│ 0x0000  4   Cell Size                                     │
│ 0x0004  2   Signature "db" (0x6264)                      │
│ 0x0006  2   Number of data segments                       │
│ 0x0008  4   Offset to segment list cell                   │
└──────────────────────────────────────────────────────────┘

Segment list cell chứa array của offsets, mỗi offset trỏ tới
một data cell chứa một phần dữ liệu (max 16344 bytes/segment).

Big data handling:
  - Value data > 16344 bytes được chia thành nhiều segments
  - vk cell chứa offset tới db cell
  - db cell chứa offset tới segment list
  - Segment list chứa offsets tới các data cells
  
  vk → db → segment_list[] → data_cell_1, data_cell_2, ...
```

### 10.1.5 Registry Value Types

| Type | ID | Mô tả | Ví dụ |
|------|----|-------|-------|
| REG_NONE | 0 | Không có type | Marker hoặc placeholder |
| REG_SZ | 1 | Null-terminated Unicode string | `"C:\Windows"` |
| REG_EXPAND_SZ | 2 | String với environment variables | `"%SystemRoot%\System32"` |
| REG_BINARY | 3 | Binary data tùy ý | Security descriptors, certificates |
| REG_DWORD | 4 | 32-bit integer (little-endian) | `0x00000001` (enabled) |
| REG_DWORD_BIG_ENDIAN | 5 | 32-bit integer (big-endian) | Hiếm gặp |
| REG_LINK | 6 | Unicode symbolic link | Registry key redirection |
| REG_MULTI_SZ | 7 | Array của null-terminated strings | DependOnService list |
| REG_RESOURCE_LIST | 8 | Hardware resource list | Device Manager |
| REG_FULL_RESOURCE_DESCRIPTOR | 9 | Hardware resource descriptor | Driver resources |
| REG_RESOURCE_REQUIREMENTS_LIST | 10 | Hardware requirements | PnP |
| REG_QWORD | 11 | 64-bit integer | Large counters, timestamps |

```
REG_MULTI_SZ format trong memory:
  "string1\0string2\0string3\0\0"
  Kết thúc bằng double null terminator.

REG_LINK:
  Tạo symbolic link giữa hai registry paths.
  Ví dụ: HKCR trỏ tới merged view của HKLM\SOFTWARE\Classes
  và HKCU\SOFTWARE\Classes bằng cách sử dụng REG_LINK.
  
  Chỉ tạo được bằng RegCreateKeyEx với REG_OPTION_CREATE_LINK.
  Khi mở link key, sẽ tới key đích (transparent).
  Mở link key trực tiếp: dùng REG_OPTION_OPEN_LINK.
```

### 10.1.6 Registry Write Flow và Transaction Logging

```
Registry modification flow chi tiết:

1. API call (RegSetValueEx, etc.)
     │
     ▼
2. Configuration Manager (Cm) modifies cells in memory
     │
     ▼
3. Mark changed bins as DIRTY trong dirty vector
     │
     ▼
4. Lazy Writer thread (5-second interval):
     │
     ├── Phase 1: Write dirty data to .LOG1
     │   a. Write log header
     │   b. Write dirty page bitmap
     │   c. Write dirty bin data
     │   d. Flush .LOG1 to disk
     │
     ├── Phase 2: Update primary hive file
     │   a. Increment primary sequence number trong base block
     │   b. Write dirty bins to hive file tại đúng offset
     │   c. Flush hive file to disk
     │   d. Increment secondary sequence number
     │   e. Flush base block
     │
     └── Phase 3: Clear dirty vector

Recovery scenarios:
  Crash during Phase 1 (LOG write):
    → LOG incomplete, primary hive intact
    → Recovery: ignore LOG, use primary as-is
    
  Crash during Phase 2 (hive write):
    → Primary sequence != Secondary sequence
    → Recovery: replay LOG1 to restore consistency
    
  Crash during Phase 2 while LOG1 also corrupt:
    → Use LOG2 (dual logging since Vista)
    
Dual logging (.LOG1, .LOG2):
  - Alternating giữa hai log files
  - Đảm bảo luôn có ít nhất một valid log
  - LOG1 và LOG2 không bao giờ bị write đồng thời
```

### 10.1.7 Volatile vs Stable Keys

```
Stable keys (KEY_VOLATILE flag = 0):
  - Được lưu trên disk trong hive file
  - Tồn tại qua reboot
  - Ví dụ: HKLM\SOFTWARE, HKCU settings

Volatile keys (KEY_VOLATILE flag = 1):
  - Chỉ tồn tại trong memory
  - Mất khi hive unload hoặc system shutdown
  - Ví dụ: HKLM\HARDWARE, HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters (volatile portions)
  
  Stable key có thể có volatile subkeys.
  Volatile key KHÔNG thể có stable subkeys.
  
  Volatile keys:
    - Không được lưu vào hive file
    - Subkey list offset cho volatile keys nằm trong trường riêng của nk cell
    - Configuration Manager quản lý volatile storage riêng biệt
    - Sử dụng cho hardware config, session-specific data, volatile caches
```

### 10.1.8 Registry Virtualization (UAC)

```
Registry Virtualization - compatibility cho legacy apps:

Vấn đề: Trước Vista, nhiều apps ghi trực tiếp vào HKLM (cần Admin rights).
Giải pháp: Redirect writes của non-elevated apps từ HKLM sang per-user location.

Virtualized paths:
  Write to: HKLM\SOFTWARE\<AppKey>
  Redirected to: HKCU\Software\Classes\VirtualStore\Machine\SOFTWARE\<AppKey>

Flow:
  ┌───────────────────────────────────────────────────┐
  │ Non-elevated app gọi RegSetValue(HKLM\SOFTWARE\X)│
  └─────────────────────┬─────────────────────────────┘
                        │
                        ▼
  ┌───────────────────────────────────────────────────┐
  │ Kernel kiểm tra:                                   │
  │   1. Process có elevated token? → KHÔNG            │
  │   2. Key có REG_KEY_DONT_VIRTUALIZE? → KHÔNG       │
  │   3. Process có DONT_VIRTUALIZE flag? → KHÔNG      │
  │   4. Key nằm trong virtualized path? → CÓ          │
  └─────────────────────┬─────────────────────────────┘
                        │
                        ▼
  ┌───────────────────────────────────────────────────┐
  │ Redirect write to:                                 │
  │ HKCU\Software\Classes\VirtualStore\MACHINE\...\X  │
  └───────────────────────────────────────────────────┘

Read order khi virtualization active:
  1. Đọc từ HKCU\...\VirtualStore\... trước (per-user override)
  2. Nếu không có → đọc từ HKLM\SOFTWARE\...

Excluded khỏi virtualization:
  - HKLM\SOFTWARE\Microsoft\Windows
  - HKLM\SOFTWARE\Microsoft\Windows NT
  - HKLM\SOFTWARE\Classes
  - Keys với REG_KEY_DONT_VIRTUALIZE flag
  - 64-bit applications (chỉ apply cho 32-bit WOW64 apps)

Kiểm tra virtualization:
  reg.exe FLAGS HKLM\SOFTWARE\YourApp QUERY
  Flags: REG_KEY_DONT_VIRTUALIZE, REG_KEY_DONT_SILENT_FAIL, REG_KEY_RECURSE_FLAG

Security note: Attackers có thể lợi dụng virtualization để plant data
được ưu tiên đọc trước HKLM data gốc. Kiểm tra VirtualStore khi
phân tích persistence.
```

### 10.1.9 Transactional Registry (TxR - KTM)

```
Transactional Registry (TxR):
  Sử dụng Kernel Transaction Manager (KTM) để đảm bảo ACID properties
  cho registry operations.

API:
  HANDLE hTransaction;
  hTransaction = CreateTransaction(NULL, NULL, 0, 0, 0, 0, NULL);
  
  HKEY hKey;
  RegOpenKeyTransacted(HKLM, "SOFTWARE\\Test", 0, KEY_ALL_ACCESS,
                       &hKey, hTransaction, NULL);
  
  RegSetValueEx(hKey, "Value1", 0, REG_DWORD, &data, sizeof(data));
  RegSetValueEx(hKey, "Value2", 0, REG_SZ, str, len);
  
  // Nếu thành công:
  CommitTransaction(hTransaction);  // Cả hai values được ghi atomic
  
  // Nếu thất bại:
  RollbackTransaction(hTransaction);  // Không có gì bị thay đổi

TxR internals:
  - Transaction logs: %SystemRoot%\System32\config\TxR\
  - Log files: {GUID}.TxR.0.regtrans-ms, {GUID}.TxR.1.regtrans-ms
  - CLFS (Common Log File System) used for transaction logging
  
  ┌──────────────────────────────────────────────────┐
  │ Application                                       │
  │   RegOpenKeyTransacted()                          │
  └──────────────┬───────────────────────────────────┘
                 │
                 ▼
  ┌──────────────────────────────────────────────────┐
  │ Configuration Manager                             │
  │   Associate key operations with KTM transaction   │
  │   Log changes to TxR log files                    │
  └──────────────┬───────────────────────────────────┘
                 │
                 ▼
  ┌──────────────────────────────────────────────────┐
  │ KTM (Kernel Transaction Manager)                  │
  │   Manage transaction state                        │
  │   Coordinate commit/rollback                      │
  │   CLFS for durable logging                        │
  └──────────────────────────────────────────────────┘

Forensics: TxR log files (.regtrans-ms) có thể chứa
registry changes chưa được commit. Phân tích các file này
để tìm pending transactions.
```

### 10.1.10 CmpKeyHash - Fast Key Lookup

```
CmpKeyHash:
  Configuration Manager sử dụng hash table để tối ưu hóa
  key lookup thay vì duyệt cây mỗi lần.

  Khi key được mở:
    1. Tính hash từ key path (case-insensitive)
    2. Lookup trong hash table (CmpCacheTable)
    3. Nếu hit → trả về KCB (Key Control Block) trực tiếp
    4. Nếu miss → duyệt cây từ root, tạo KCB, add vào hash

  Key Control Block (KCB):
    - In-memory structure đại diện cho một open key
    - Chứa cached key properties
    - Reference counted (nhiều handles có thể trỏ tới cùng KCB)
    - Link tới cell data trong hive

  Hash table size: configurable, default khoảng 2048 entries
  Collision resolution: chaining (linked list)

WinDbg kiểm tra KCB:
  kd> !reg kcb <address>
  kd> !reg findkcb \Registry\Machine\SOFTWARE\Microsoft
  kd> !reg baseblock <hive_address>
```

### 10.1.11 Registry Callbacks (CmRegisterCallbackEx)

```
Registry callbacks cho phép kernel-mode drivers nhận notification
về mọi registry operation. Đây là cơ chế chính được EDR/AV sử dụng.

Registration:
  LARGE_INTEGER Cookie;
  CmRegisterCallbackEx(
      RegistryCallback,   // Callback function
      &Altitude,          // Minifilter altitude string
      DriverObject,
      NULL,               // Context
      &Cookie,            // Output: cookie để unregister
      NULL
  );
  
  // Unregister:
  CmUnRegisterCallback(Cookie);

Callback prototype:
  NTSTATUS RegistryCallback(
      PVOID CallbackContext,
      PVOID Argument1,     // REG_NOTIFY_CLASS (operation type)
      PVOID Argument2      // Operation-specific data structure
  );

REG_NOTIFY_CLASS operations quan trọng:
  ┌─────────────────────────────────┬──────────────────────────────┐
  │ Pre-operation                   │ Post-operation               │
  ├─────────────────────────────────┼──────────────────────────────┤
  │ RegNtPreCreateKey               │ RegNtPostCreateKey           │
  │ RegNtPreCreateKeyEx             │ RegNtPostCreateKeyEx         │
  │ RegNtPreOpenKey                 │ RegNtPostOpenKey             │
  │ RegNtPreOpenKeyEx               │ RegNtPostOpenKeyEx           │
  │ RegNtPreDeleteKey               │ RegNtPostDeleteKey           │
  │ RegNtPreSetValueKey             │ RegNtPostSetValueKey         │
  │ RegNtPreDeleteValueKey          │ RegNtPostDeleteValueKey      │
  │ RegNtPreQueryKey                │ RegNtPostQueryKey            │
  │ RegNtPreQueryValueKey           │ RegNtPostQueryValueKey       │
  │ RegNtPreEnumerateKey            │ RegNtPostEnumerateKey        │
  │ RegNtPreEnumerateValueKey       │ RegNtPostEnumerateValueKey   │
  │ RegNtPreKeyHandleClose          │ RegNtPostKeyHandleClose      │
  │ RegNtPreSetKeySecurity          │ RegNtPostSetKeySecurity      │
  │ RegNtPreQueryKeySecurity        │ RegNtPostQueryKeySecurity    │
  │ RegNtPreSaveKey                 │ RegNtPostSaveKey             │
  │ RegNtPreRestoreKey              │ RegNtPostRestoreKey          │
  │ RegNtPreLoadKey                 │ RegNtPostLoadKey             │
  │ RegNtPreReplaceKey              │ RegNtPostReplaceKey          │
  └─────────────────────────────────┴──────────────────────────────┘

EDR/AV sử dụng để:
  - Detect/block malicious registry persistence (Run keys, Services)
  - Monitor HKLM\SYSTEM\CurrentControlSet\Services\ for new drivers
  - Block LSA config changes (RunAsPPL, etc.)
  - Log tất cả registry writes cho forensics

Pre-operation callback có thể BLOCK operation:
  Return STATUS_ACCESS_DENIED → operation bị deny
  Thay đổi data → operation thực hiện với data đã modified

Security research: Rootkits có thể đăng ký callback để HIDE
registry keys bằng cách filter kết quả enumerate.
Để detect: kiểm tra CmCallbackListHead trong ntoskrnl.
  kd> dps nt!CmpCallbackListHead
```

### 10.1.12 Registry Forensics

```
1. Deleted Key Recovery:
   - Cell size dương (positive) = free/deleted cell
   - Dữ liệu vẫn còn trong hive file cho đến khi bị overwrite
   - Tools: Registry Explorer (Eric Zimmerman), RegRipper, yarp
   
   Manual recovery logic:
     a. Scan toàn bộ hive file tìm cells với signature "nk" hoặc "vk"
     b. Kiểm tra cell size: nếu dương → deleted
     c. Parse cell data để khôi phục key/value info
     d. Last Written Timestamp trong nk cell → thời điểm cuối cùng bị modify

2. Timeline Analysis:
   - Mỗi key node (nk) có Last Written Timestamp
   - Timestamp cập nhật khi: key created, value added/modified/deleted
   - KHÔNG cập nhật khi: subkey của key bị modify (chỉ key trực tiếp)
   
   PowerShell timeline extraction:
   # Export all key timestamps
   Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft" -Recurse |
       Select-Object Name, 
       @{N='LastWriteTime';E={$_.GetValue($null); [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine','Default').OpenSubKey($_.Name.Replace('HKEY_LOCAL_MACHINE\','')).GetLastWriteTime()}} |
       Sort-Object LastWriteTime -Descending

3. Persistence Locations để kiểm tra:
   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
   HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
   HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon (Shell, Userinit)
   HKLM\SYSTEM\CurrentControlSet\Services\ (Type, ImagePath, Start)
   HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
     (Debugger value = persistence/hijack)
   HKLM\SOFTWARE\Classes\CLSID\ (COM hijacking)
   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects
   HKCU\SOFTWARE\Classes\CLSID\ (per-user COM hijack)

4. SAM Database Forensics:
   - HKLM\SAM\SAM\Domains\Account\Users\
   - Mỗi user = subkey với RID hex (e.g., 000001F4 = Administrator, 500)
   - F value: Account metadata (last logon, password age, flags)
   - V value: Username, fullname, comment, password hashes
   
   Offline extraction:
   reg.exe load HKU\offline_sam C:\Windows\System32\config\SAM
   reg.exe query HKU\offline_sam\SAM\Domains\Account\Users /s
   reg.exe unload HKU\offline_sam
```

### 10.1.13 Key Registry Locations for Internals

```
Driver/Service configuration:
  HKLM\SYSTEM\CurrentControlSet\Services\<name>
    Start: 0=Boot, 1=System, 2=Auto, 3=Manual, 4=Disabled
    Type: 1=KernelDriver, 2=FileSystem, 16=Win32OwnProcess,
          32=Win32ShareProcess, 256=InteractiveProcess
    ImagePath: driver/service file path
    ErrorControl: 0=Ignore, 1=Normal, 2=Severe, 3=Critical
    DependOnService: REG_MULTI_SZ của service dependencies
    ObjectName: Account to run under (LocalSystem, etc.)
    FailureActions: REG_BINARY định nghĩa hành động khi crash

Session Manager:
  HKLM\SYSTEM\CurrentControlSet\Control\Session Manager
    BootExecute: autocheck programs (chạy trước login)
    PendingFileRenameOperations: file thay thế sau reboot
    Memory Management: pagefile, pool sizes, large pages
    SubSystems: required subsystems (csrss)
    KnownDLLs: pre-loaded DLL list (chống DLL hijacking)

Security:
  HKLM\SYSTEM\CurrentControlSet\Control\Lsa
    RunAsPPL: 1 = LSASS chạy như Protected Process Light
    LimitBlankPasswordUse: 1 = block empty passwords
    Security Packages: authentication packages loaded
    DisableRestrictedAdmin: 0 = enable Restricted Admin RDP
    
  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
    EnableLUA: 1 = UAC enabled
    ConsentPromptBehaviorAdmin: 0-5 (UAC prompt behavior)
    FilterAdministratorToken: 1 = filter built-in Admin
    
Crash control:
  HKLM\SYSTEM\CurrentControlSet\Control\CrashControl
    CrashDumpEnabled: 1=Complete, 2=Kernel, 3=Small, 7=Automatic
    DumpFile: %SystemRoot%\MEMORY.DMP
    MinidumpsDir: %SystemRoot%\Minidump
    AutoReboot: 1 = auto reboot sau BSOD
    NMICrashDump: 1 = cho phép NMI trigger crash dump
```

---

## 10.2 Event Tracing for Windows (ETW)

ETW là hệ thống tracing hiệu suất cao được tích hợp vào Windows kernel.
Đối với security researcher, ETW là nguồn telemetry quan trọng nhất
của hệ điều hành.

### 10.2.1 ETW Architecture Chi Tiết

```
ETW Architecture - 3 components chính:
┌──────────────────────────────────────────────────────────────┐
│ PROVIDERS (nguồn event)                                       │
│                                                              │
│ ┌───────────────┐ ┌────────────────┐ ┌───────────────────┐  │
│ │ Kernel Logger  │ │ .NET Runtime   │ │ Security Auditing │  │
│ │ (SystemTrace)  │ │ Provider       │ │ Provider          │  │
│ │               │ │                │ │                   │  │
│ │ EventWrite()  │ │ EventWrite()   │ │ AuthZ events      │  │
│ └───────┬───────┘ └───────┬────────┘ └────────┬──────────┘  │
│         │                 │                    │              │
├─────────┴─────────────────┴────────────────────┴──────────────┤
│ ETW Infrastructure (ntoskrnl.exe + ntdll.dll)                 │
│                                                              │
│ ┌──────────────────────────────────────────────────────────┐ │
│ │ Trace Session "NT Kernel Logger"                          │ │
│ │   Mode: EVENT_TRACE_REAL_TIME_MODE                       │ │
│ │   Buffers: 64 x 64 KB per-CPU (lock-free)               │ │
│ │   Provider: SystemTraceControlGuid                       │ │
│ │   Keywords: PROC_THREAD | LOADER | DISK_IO               │ │
│ │   Level: TRACE_LEVEL_VERBOSE (5)                         │ │
│ ├──────────────────────────────────────────────────────────┤ │
│ │ Trace Session "EventLog-Security"                         │ │
│ │   Mode: FILE_MODE + REAL_TIME                            │ │
│ │   Provider: Microsoft-Windows-Security-Auditing           │ │
│ │   Output: Security.evtx                                  │ │
│ ├──────────────────────────────────────────────────────────┤ │
│ │ Trace Session "MyCustomTrace"                             │ │
│ │   Mode: EVENT_TRACE_FILE_MODE_SEQUENTIAL                 │ │
│ │   Output: trace.etl                                      │ │
│ └──────────────────────────────────────────────────────────┘ │
│                                                              │
├──────────────────────────────────────────────────────────────┤
│ CONSUMERS (phân tích)                                         │
│                                                              │
│ ┌─────────┐ ┌───────────┐ ┌────────┐ ┌──────────────────┐  │
│ │ WPA     │ │ PerfView  │ │ xperf  │ │ logman / tracerpt│  │
│ │(analyzer)│ │           │ │        │ │                  │  │
│ └─────────┘ └───────────┘ └────────┘ └──────────────────┘  │
│ ┌───────────┐ ┌──────────────┐ ┌─────────────────────┐     │
│ │ Sysmon    │ │ Process Mon  │ │ EDR consumers       │     │
│ └───────────┘ └──────────────┘ └─────────────────────┘     │
└──────────────────────────────────────────────────────────────┘

Buffer management (lock-free, per-CPU):
  - Mỗi CPU có riêng buffer pool
  - Provider ghi event vào buffer của CPU hiện tại (không cần lock)
  - Khi buffer đầy → flush to file hoặc real-time consumer
  - Nếu flush không kịp → event bị drop (có đếm trong lost events counter)
```

### 10.2.2 Provider Registration và EventWrite

```c
// Provider registration (manifest-based):
#include <evntprov.h>

REGHANDLE hProvider;
const GUID MyProviderGuid = {0x12345678, 0xABCD, ...};

// Register
EventRegister(&MyProviderGuid, NULL, NULL, &hProvider);

// Write event
EVENT_DESCRIPTOR EventDesc;
EventDescCreate(&EventDesc,
    1,      // Event ID
    0,      // Version
    0,      // Channel
    4,      // Level (Info)
    0,      // Opcode
    0,      // Task
    0x01    // Keywords
);

EVENT_DATA_DESCRIPTOR DataDesc[2];
EventDataDescCreate(&DataDesc[0], szName, (wcslen(szName)+1)*2);
EventDataDescCreate(&DataDesc[1], &dwValue, sizeof(DWORD));

EventWrite(hProvider, &EventDesc, 2, DataDesc);

// Unregister
EventUnregister(hProvider);
```

### 10.2.3 Provider Types Chi Tiết

```
1. Classic (MOF-based) Providers:
   - Legacy, dùng RegisterTraceGuids() / TraceEvent()
   - WPP (Windows PreProcessor) trace macros
   - Định nghĩa event trong MOF (Managed Object Format)
   - Vẫn được sử dụng bởi một số driver cũ
   - Khó maintain, khó decode events

2. Manifest-based Providers:
   - Modern (từ Vista), dùng EventRegister() / EventWrite()
   - Định nghĩa events trong XML manifest (.man file)
   - Manifest được compile thành resource trong binary
   - Events tự mô tả: consumer có thể decode không cần manifest
   - Manifest chứa: provider GUID, event IDs, keywords, levels, channels
   
   Ví dụ manifest:
   <instrumentationManifest>
     <instrumentation>
       <events>
         <provider name="MyProvider"
                   guid="{12345678-ABCD-...}"
                   symbol="MY_PROVIDER">
           <events>
             <event value="1" symbol="ProcessCreated"
                    level="win:Informational"
                    keywords="Process"
                    message="$(string.event.1)"/>
           </events>
           <keywords>
             <keyword name="Process" mask="0x1"/>
             <keyword name="Thread" mask="0x2"/>
           </keywords>
         </provider>
       </events>
     </instrumentation>
   </instrumentationManifest>

3. TraceLogging Providers:
   - Mới nhất, từ Windows 10
   - Self-describing: metadata được embed trong event data
   - Không cần manifest file riêng
   - Khó khai báo hơn manifest-based, nhưng deploy đơn giản hơn
   - Sử dụng TraceLoggingRegister() / TraceLoggingWrite()
   
   #include <TraceLoggingProvider.h>
   
   TRACELOGGING_DEFINE_PROVIDER(g_hProvider,
       "MyTraceLoggingProvider",
       (0x12345678, 0xABCD, ...));
   
   TraceLoggingRegister(g_hProvider);
   
   TraceLoggingWrite(g_hProvider,
       "MyEventName",
       TraceLoggingUInt32(pid, "ProcessId"),
       TraceLoggingWideString(name, "ProcessName")
   );
```

### 10.2.4 Session Types

```
1. NT Kernel Logger (System Trace):
   - Đặc biệt: chỉ có MỘT session kernel logger tại một thời điểm
   - GUID: SystemTraceControlGuid {9E814AAD-3204-11D2-9A82-006008A86939}
   - Trace kernel events: process, thread, disk, file, registry, network
   - Windows 8+: nhiều system trace sessions (SystemTraceProvider)
   
2. AutoLogger Sessions:
   - Bắt đầu từ boot, trước bất kỳ user logon
   - Cấu hình trong registry:
     HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\<name>
   - Quan trọng cho boot-time diagnostics và security monitoring
   - Ví dụ AutoLoggers mặc định:
     ├── EventLog-System      → ghi System event log
     ├── EventLog-Application → ghi Application event log
     ├── EventLog-Security    → ghi Security event log
     ├── DiagLog              → diagnostics
     └── WiFiSession          → wireless diagnostics

3. Private Logger Sessions:
   - Chỉ trong process của provider
   - Buffer được quản lý trong process space
   - Không cần admin rights
   - Giới hạn: chỉ một provider per session

4. Global Logger:
   - Boot-time tracing (trước ETW framework khởi tạo xong)
   - Được thay thế bởi AutoLogger từ Vista

Session control commands:
  logman query -ets                    # List active sessions
  logman query "EventLog-Security" -ets # Chi tiết một session
  logman query providers               # List all registered providers
  logman query providers "Microsoft-Windows-Kernel-Process"
```

### 10.2.5 ETW Logging Modes

```
Logging modes (có thể kết hợp bằng OR):

EVENT_TRACE_FILE_MODE_SEQUENTIAL  (0x0001)
  - Ghi tuần tự vào file .etl
  - Dừng khi file đạt MaxFileSize

EVENT_TRACE_FILE_MODE_CIRCULAR    (0x0002)
  - Ghi vòng tròn: khi đầy, ghi đè từ đầu
  - Hữu ích cho monitoring liên tục với limited disk space

EVENT_TRACE_REAL_TIME_MODE        (0x0100)
  - Events được deliver trực tiếp cho consumer (không qua file)
  - Consumer nhận events qua callback

EVENT_TRACE_BUFFERING_MODE        (0x0400)
  - Events chỉ lưu trong memory buffers
  - Không ghi file, không real-time delivery
  - Dùng FlushTrace() để snapshot vào file

EVENT_TRACE_SECURE_MODE           (0x0080) [Windows 8.1+]
  - Protected session: chỉ trusted consumers truy cập được
  - Sử dụng cho high-security events

EVENT_TRACE_SYSTEM_LOGGER_MODE    (0x2000000) [Windows 8+]
  - Cho phép session nhận system/kernel events
  - Thay thế cho giới hạn "1 kernel logger" cũ
```

### 10.2.6 Microsoft-Windows-Threat-Intelligence Provider

Đây là provider QUAN TRỌNG NHẤT cho security monitoring. Được sử dụng bởi
EDR products và Windows Defender.

```
Provider: Microsoft-Windows-Threat-Intelligence
GUID: {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}

YÊU CẦU: Chỉ có thể consume bởi Protected Process Light (PPL) hoặc
kernel-mode callers. Đây là anti-tamper measure.

Events chính:

1. ALLOCVM_REMOTE (ID: 1)
   Trigger: NtAllocateVirtualMemory với process handle của process KHÁC
   Fields: CallingProcessId, TargetProcessId, BaseAddress, RegionSize, 
           AllocationType, ProtectionMask
   Use case: Detect process injection (VirtualAllocEx stage)

2. PROTECTVM_REMOTE (ID: 2)
   Trigger: NtProtectVirtualMemory với process handle của process KHÁC
   Fields: CallingProcessId, TargetProcessId, BaseAddress, RegionSize,
           NewProtectionMask, OldProtectionMask
   Use case: Detect RWX permission changes (shellcode injection)

3. MAPVIEW_REMOTE (ID: 3)
   Trigger: NtMapViewOfSection với process handle của process KHÁC
   Fields: CallingProcessId, TargetProcessId, SectionOffset, ViewSize
   Use case: Detect section-based injection

4. QUEUEUSERAPC_REMOTE (ID: 4)
   Trigger: NtQueueApcThread với thread của process KHÁC
   Fields: CallingProcessId, TargetProcessId, TargetThreadId, ApcRoutine
   Use case: Detect APC injection

5. SETTHREADCONTEXT_REMOTE (ID: 5)
   Trigger: NtSetContextThread với thread của process KHÁC
   Fields: CallingProcessId, TargetProcessId, TargetThreadId
   Use case: Detect thread hijacking

6. WRITEVM_REMOTE (ID: 6)
   Trigger: NtWriteVirtualMemory với process handle của process KHÁC
   Fields: CallingProcessId, TargetProcessId, BaseAddress, BufferSize
   Use case: Detect WriteProcessMemory (shellcode write)

7. DRIVER_LOAD (ID: 7-8)
   Trigger: Driver load/unload
   Fields: DriverName, ImageBase, ImageSize, Flags
   Use case: Detect malicious driver loading

8. SUSPEND_PROCESS / RESUME_PROCESS (ID: 11-14)
   Trigger: Process/Thread suspend/resume targeting OTHER process
   Use case: Detect process freeze for injection
   
9. READVM_REMOTE (ID: 25)   [UPDATE 2026]
   Trigger: NtReadVirtualMemory on remote process
   Use case: Detect credential dumping (reading LSASS)

Detection pattern:
  Process injection thường theo flow:
    ALLOCVM_REMOTE → WRITEVM_REMOTE → PROTECTVM_REMOTE (RWX)
    → QUEUEUSERAPC_REMOTE hoặc CreateRemoteThread

  Credential dump:
    READVM_REMOTE targeting lsass.exe
```

### 10.2.7 Kernel Logger và Keywords

```
Kernel Logger provider keywords:

| Keyword Flag       | Hex Value     | Events                         |
|--------------------|--------------|---------------------------------|
| PROC_THREAD        | 0x00000001   | Process create/exit              |
| THREAD             | 0x00000002   | Thread create/exit               |
| LOADER / IMAGE     | 0x00000004   | Module (DLL/driver) load/unload  |
| DISK_IO            | 0x00000008   | Physical disk read/write         |
| FILE_IO            | 0x00000010   | File system operations           |
| FILE_IO_INIT       | 0x00000020   | File I/O initiation (not completion) |
| REGISTRY           | 0x00000040   | Registry operations              |
| DISK_FILE_IO       | 0x00000080   | Disk I/O with filename           |
| DISPATCHER         | 0x00000100   | Dispatcher (thread scheduling)   |
| MEMORY_PAGE_FAULTS | 0x00000200   | All page faults                  |
| MEMORY_HARD_FAULTS | 0x00000400   | Hard page faults only            |
| NETWORKTRACE       | 0x00000800   | TCP/UDP activity                 |
| CSWITCH            | 0x00001000   | Context switches                 |
| PROFILE            | 0x00002000   | CPU sampling profiling           |
| DPC                | 0x00004000   | DPC activity                     |
| INTERRUPT          | 0x00008000   | Interrupt activity               |
| SYSCALL            | 0x00010000   | System call entry/exit           |
| VAMAP              | 0x00020000   | VirtualAlloc/VirtualFree         |
| VIRT_ALLOC         | 0x00040000   | Virtual alloc commit/decommit    |

Trace commands:
  xperf -on PROC_THREAD+LOADER+DISK_IO+FILE_IO+REGISTRY -f kernel.etl
  xperf -stop
  wpa.exe kernel.etl
```

### 10.2.8 ETW cho Security Monitoring

```
Security-relevant ETW providers:

1. Microsoft-Windows-Kernel-Process
   GUID: {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
   Events: Process create (full command line), process exit
   
2. Microsoft-Windows-Kernel-File
   GUID: {EDD08927-9CC4-4E65-B970-C2560FB5C289}
   Events: File create, delete, rename
   
3. Microsoft-Windows-DNS-Client
   GUID: {1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}
   Events: DNS queries (domain resolution)
   
4. Microsoft-Windows-Security-Auditing
   Events: Logon (4624), process create (4688), service install (4697)
   
5. Microsoft-Windows-PowerShell
   GUID: {A0C1853B-5C40-4B15-8766-3CF1C58F985A}
   Events: PowerShell command execution, script blocks
   
6. Microsoft-Windows-Sysmon
   GUID: {5770385F-C22A-43E0-BF4C-06F5698FFBD9}
   Events: Sysmon events 1-29 (xem Section 10.7.1)

ETW consumer code ví dụ (C):
  EVENT_TRACE_LOGFILE trace;
  ZeroMemory(&trace, sizeof(trace));
  trace.LoggerName = L"MySession";
  trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME |
                           PROCESS_TRACE_MODE_EVENT_RECORD;
  trace.EventRecordCallback = EventRecordCallback;
  
  TRACEHANDLE hTrace = OpenTrace(&trace);
  ProcessTrace(&hTrace, 1, NULL, NULL);  // Blocks until session stops
  CloseTrace(hTrace);
  
  // Callback:
  void WINAPI EventRecordCallback(PEVENT_RECORD pEvent) {
      // pEvent->EventHeader.ProviderId = provider GUID
      // pEvent->EventHeader.EventDescriptor.Id = event ID
      // pEvent->UserData, pEvent->UserDataLength = event payload
      // Parse dựa vào event ID và provider
  }
```

### 10.2.9 ETW Evasion Techniques

```
ETW evasion - kỹ thuật malware dùng để tránh monitoring:

1. Patching EtwEventWrite trong ntdll.dll:
   - Ghi "ret" (0xC3) vào đầu hàm EtwEventWrite
   - Mọi event write từ user-mode sẽ return ngay
   - Chỉ ảnh hưởng process hiện tại (per-process ntdll mapping)
   
   // Malware code:
   HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
   void* pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
   DWORD oldProtect;
   VirtualProtect(pEtwEventWrite, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
   *(BYTE*)pEtwEventWrite = 0xC3;  // ret
   VirtualProtect(pEtwEventWrite, 1, oldProtect, &oldProtect);

2. Patching ETW provider registration:
   - Ghi đè ProviderEnableCallback để bỏ qua enable requests
   - Provider vẫn registered nhưng không bao giờ được enabled

3. Removing ETW provider GUIDs:
   - NtSetInformationThread với ThreadHideFromDebugger
   - Hoặc xóa provider registration từ memory

4. Session manipulation:
   - Enum và stop trace sessions của EDR
   - NtTraceControl syscall trực tiếp

Detection của ETW evasion:
  a. Inline hook detection: Kiểm tra EtwEventWrite prologue
     So sánh với on-disk ntdll.dll
     Expected prologue: 4C 8B DC 48 ... (x64)
     Patched: C3 (ret)
  
  b. Integrity check: Hash của .text section ntdll
     So sánh in-memory vs on-disk
  
  c. Kernel-mode monitoring: Kernel ETW không bị ảnh hưởng
     bởi user-mode patching. Sử dụng kernel providers cho
     critical events.
  
  d. PPL consumers: Threat Intelligence provider yêu cầu PPL
     → không bị tamper bởi user-mode techniques
```

### 10.2.10 ETW Protected Sessions

```
ETW Protected Sessions (Windows 8.1+):
  - EVENT_TRACE_SECURE_MODE flag
  - Chỉ consumers với đúng security permissions mới truy cập được
  - Sử dụng cho sensitive security events
  
  Threat Intelligence provider REQUIRE consumer là:
    1. Protected Process Light (PPL) với Anti-Malware signer
    2. Hoặc kernel-mode (driver)
  
  Đây là lý do tại sao EDR products cần PPL signing certificate
  từ Microsoft để consume Threat Intelligence events.
  
  [UPDATE 2026] Windows 11 24H2:
    - Thêm "Secure ETW Channel" cho tamper-resistant event delivery
    - Events được sign bởi kernel trước khi gửi cho consumer
    - Consumer có thể verify event integrity
    - Ngăn chặn man-in-the-middle attack giữa provider và consumer
```

---

## 10.3 WMI (Windows Management Instrumentation)

WMI là implementation của CIM (Common Information Model) trên Windows.
Đối với security researcher, WMI quan trọng vì:
- Malware sử dụng WMI event subscriptions cho persistence
- WMI lateral movement (DCOM/WinRM)
- Fileless malware qua WMI

### 10.3.1 WMI Architecture Chi Tiết

```
┌──────────────────────────────────────────────────────────────┐
│ Management Applications                                       │
│ ┌───────────────┐ ┌──────────┐ ┌────────┐ ┌──────────────┐ │
│ │ PowerShell    │ │ WMIC.exe │ │ SCCM   │ │ Custom apps  │ │
│ │ Get-CimInstance│ │ (legacy) │ │        │ │ (COM/Script) │ │
│ └───────┬───────┘ └────┬─────┘ └───┬────┘ └──────┬───────┘ │
│         └──────────────┴───────────┴──────────────┘          │
│                         │ COM/DCOM (IWbemServices)           │
│                         ▼                                     │
│ ┌──────────────────────────────────────────────────────────┐ │
│ │ WMI Service (WinMgmt) - svchost.exe -k netsvcs          │ │
│ │                                                          │ │
│ │ ┌──────────────┐  ┌──────────────┐  ┌────────────────┐ │ │
│ │ │ WQL Engine   │  │ Event Engine │  │ Provider Host  │ │ │
│ │ │ (query parse │  │ (subscription│  │ Management     │ │ │
│ │ │  & execute)  │  │  management) │  │                │ │ │
│ │ └──────────────┘  └──────────────┘  └────────────────┘ │ │
│ │                                                          │ │
│ │ CIM Repository: %SystemRoot%\System32\wbem\Repository\  │ │
│ │   OBJECTS.DATA    - object definitions                   │ │
│ │   INDEX.BTR       - index for fast lookup                │ │
│ │   MAPPING*.MAP    - mapping tables                       │ │
│ │                                                          │ │
│ └──────────────────────────┬───────────────────────────────┘ │
│                            │                                  │
│                            ▼                                  │
│ ┌──────────────────────────────────────────────────────────┐ │
│ │ WMI Providers (COM DLLs hoặc EXEs)                       │ │
│ │                                                          │ │
│ │ ┌─────────────────┐  ┌─────────────────────────────────┐│ │
│ │ │ Win32 Provider  │  │ StdProv (system events provider)││ │
│ │ │ cimwin32.dll    │  │ stdprov.dll                     ││ │
│ │ │                 │  │                                 ││ │
│ │ │ Win32_Process   │  │ __InstanceCreationEvent         ││ │
│ │ │ Win32_Service   │  │ __InstanceModificationEvent     ││ │
│ │ │ Win32_UserAccount│  │ __InstanceDeletionEvent        ││ │
│ │ │ Win32_OS        │  │ __TimerEvent                   ││ │
│ │ └─────────────────┘  └─────────────────────────────────┘│ │
│ │                                                          │ │
│ │ ┌─────────────────┐  ┌─────────────────────────────────┐│ │
│ │ │ Registry Prov.  │  │ Event Log Provider             ││ │
│ │ │ stdprov.dll     │  │ ntevt.dll                      ││ │
│ │ │                 │  │                                 ││ │
│ │ │ StdRegProv      │  │ Win32_NTLogEvent               ││ │
│ │ └─────────────────┘  └─────────────────────────────────┘│ │
│ └──────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘

Provider hosting models:
  - In-process (coupled): chạy trong WMI service process
  - Out-of-process (decoupled): chạy trong WmiPrvSE.exe riêng
  - SelfHost: provider tự host (EXE riêng)
```

### 10.3.2 WMI Namespaces

```
WMI Namespaces - phân cấp tổ chức classes:

root\
├── cimv2              # Namespace chính, chứa Win32_* classes
│   ├── Win32_Process
│   ├── Win32_Service
│   ├── Win32_OperatingSystem
│   ├── Win32_UserAccount
│   └── ...
├── default            # Default namespace
├── subscription       # WMI event subscriptions (PERSISTENCE!)
│   ├── __EventFilter
│   ├── __EventConsumer
│   ├── __FilterToConsumerBinding
│   └── CommandLineEventConsumer
├── SecurityCenter2    # AV/Firewall status
│   ├── AntiVirusProduct
│   ├── FirewallProduct
│   └── AntiSpywareProduct
├── Microsoft
│   ├── Windows
│   │   ├── Storage    # Disk/volume management
│   │   ├── Defender   # Windows Defender management
│   │   └── TaskScheduler
│   └── SecurityClient # SCEP/Defender
├── WMI                # ETW WMI bridge
├── RSOP               # Resultant Set of Policy (Group Policy)
└── directory
    └── LDAP           # Active Directory (domain-joined)

Enum namespaces:
  Get-CimInstance -Namespace root -ClassName __Namespace | Select Name
  
  # Recursive enum:
  function Get-WmiNamespaces($ns = 'root') {
      Get-CimInstance -Namespace $ns -ClassName __Namespace -ErrorAction SilentlyContinue |
      ForEach-Object {
          $child = "$ns\$($_.Name)"
          $child
          Get-WmiNamespaces $child
      }
  }
  Get-WmiNamespaces
```

### 10.3.3 WQL (WMI Query Language)

```sql
-- WQL là subset của SQL, chỉ hỗ trợ SELECT (không có INSERT/UPDATE/DELETE)

-- Liệt kê processes đang chạy
SELECT ProcessId, Name, CommandLine, ParentProcessId
FROM Win32_Process

-- Tìm process theo tên
SELECT * FROM Win32_Process WHERE Name = 'powershell.exe'

-- Services đang chạy với auto start
SELECT Name, PathName, StartMode, State
FROM Win32_Service
WHERE State = 'Running' AND StartMode = 'Auto'

-- User accounts (local)
SELECT Name, SID, Disabled, Lockout
FROM Win32_UserAccount WHERE LocalAccount = TRUE

-- Network connections (requires NetworkAdapterConfiguration)
SELECT IPAddress, MACAddress, DefaultIPGateway, DHCPEnabled
FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE

-- Installed hotfixes
SELECT HotFixID, InstalledOn, Description
FROM Win32_QuickFixEngineering

-- Shares (SMB)
SELECT Name, Path, Description, Type
FROM Win32_Share

-- Event subscription queries (intrinsic events):
-- Monitor mỗi 2 giây cho process mới
SELECT * FROM __InstanceCreationEvent WITHIN 2
WHERE TargetInstance ISA 'Win32_Process'

-- Monitor registry changes
SELECT * FROM RegistryValueChangeEvent
WHERE Hive = 'HKEY_LOCAL_MACHINE'
AND KeyPath = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
```

```powershell
# PowerShell execution:
Get-CimInstance -Query "SELECT * FROM Win32_Process WHERE Name = 'svchost.exe'" |
    Select ProcessId, Name, CommandLine

# Remote query (DCOM):
Get-CimInstance -ComputerName TARGET -Query "SELECT * FROM Win32_Process" `
    -Credential (Get-Credential)

# Remote query (WinRM/WSMan - preferred):
$session = New-CimSession -ComputerName TARGET -Credential (Get-Credential)
Get-CimInstance -CimSession $session -ClassName Win32_Process
```

### 10.3.4 WMI Event Subscriptions - Persistence Mechanism

Đây là một trong những persistence mechanisms phổ biến nhất của malware.

```
WMI Permanent Event Subscription - 3 components:

1. Event Filter (__EventFilter):
   Định nghĩa ĐIỀU KIỆN trigger (WQL query)

2. Event Consumer (__EventConsumer):
   Định nghĩa HÀNH ĐỘNG khi event xảy ra
   
   Consumer types:
   ├── CommandLineEventConsumer   → Chạy command line
   ├── ActiveScriptEventConsumer  → Chạy VBScript/JScript
   ├── LogFileEventConsumer       → Ghi vào log file
   ├── NTEventLogEventConsumer    → Ghi event log
   └── SMTPEventConsumer          → Gửi email

3. FilterToConsumerBinding (__FilterToConsumerBinding):
   Liên kết Filter với Consumer

┌──────────────────────────────────────────────────────────┐
│ WMI Event Subscription Persistence                        │
│                                                          │
│ ┌─────────────────────────────────────────────────────┐  │
│ │ __EventFilter "EvilFilter"                           │  │
│ │   Query: SELECT * FROM __InstanceModificationEvent   │  │
│ │          WITHIN 60                                   │  │
│ │          WHERE TargetInstance ISA 'Win32_PerfFormatted│  │
│ │          Data_PerfOS_System'                         │  │
│ │   (trigger: mỗi 60 giây khi system đang chạy)       │  │
│ └──────────────────────┬──────────────────────────────┘  │
│                        │                                  │
│ ┌──────────────────────┴──────────────────────────────┐  │
│ │ __FilterToConsumerBinding                            │  │
│ │   Filter = EvilFilter                                │  │
│ │   Consumer = EvilConsumer                             │  │
│ └──────────────────────┬──────────────────────────────┘  │
│                        │                                  │
│ ┌──────────────────────┴──────────────────────────────┐  │
│ │ CommandLineEventConsumer "EvilConsumer"               │  │
│ │   CommandLineTemplate:                                │  │
│ │     powershell.exe -enc <base64_payload>              │  │
│ │   (chạy malware payload)                              │  │
│ └─────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

```powershell
# === TẠO WMI PERSISTENCE (ví dụ cho hiểu, KHÔNG làm trên production) ===

# 1. Tạo Event Filter
$FilterArgs = @{
    EventNamespace = 'root\cimv2'
    Name = 'TestFilter'
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
    QueryLanguage = 'WQL'
}
$Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $FilterArgs

# 2. Tạo Event Consumer
$ConsumerArgs = @{
    Name = 'TestConsumer'
    CommandLineTemplate = 'cmd.exe /c echo owned > C:\test.txt'
}
$Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments $ConsumerArgs

# 3. Tạo Binding
$BindingArgs = @{
    Filter = $Filter
    Consumer = $Consumer
}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments $BindingArgs

# === DETECTION: Kiểm tra WMI persistence ===
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter
Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding

# === REMOVAL ===
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter |
    Where-Object Name -eq 'TestFilter' | Remove-CimInstance
Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer |
    Where-Object Name -eq 'TestConsumer' | Remove-CimInstance
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding |
    Remove-CimInstance
```

### 10.3.5 WMI Attacks và Detection

```
WMI Attack vectors:

1. Persistence (WMI Event Subscription) - đã trình bày ở trên

2. Lateral Movement:
   # Remote execution qua WMI (DCOM):
   wmic /node:TARGET /user:DOMAIN\admin process call create "cmd.exe /c whoami"
   
   # PowerShell WMI lateral movement:
   Invoke-WmiMethod -ComputerName TARGET -Class Win32_Process -Name Create `
       -ArgumentList "powershell.exe -enc <payload>"
   
   # CIM (WinRM-based, modern):
   Invoke-CimMethod -ComputerName TARGET -ClassName Win32_Process -MethodName Create `
       -Arguments @{CommandLine="cmd.exe /c whoami"} -Credential $cred

3. Reconnaissance:
   # AV detection:
   Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct |
       Select displayName, productState
   
   # Enumerate domain controllers:
   Get-CimInstance -Namespace root\directory\LDAP -ClassName ds_computer `
       -Filter "ds_userAccountControl=532480"

Detection strategies:
  Event IDs liên quan:
    Event Log: Microsoft-Windows-WMI-Activity/Operational
      Event ID 5857: Provider loaded
      Event ID 5858: Provider error
      Event ID 5860: Registration (temporary subscription)
      Event ID 5861: Registration (permanent subscription) ← QUAN TRỌNG
    
    Sysmon:
      Event ID 19: WmiEvent - WmiEventFilter activity detected
      Event ID 20: WmiEvent - WmiEventConsumer activity detected
      Event ID 21: WmiEvent - WmiEventConsumerToFilter activity detected

  CIM Repository forensics:
    Tool: PyWMIPersistenceFinder, WMI-Forensics
    Repository path: %SystemRoot%\System32\wbem\Repository\
    File: OBJECTS.DATA chứa toàn bộ class definitions và instances
```

---

## 10.4 Windows Error Reporting (WER) và Crash Dump Analysis

### 10.4.1 Application Crash Handling

```
Application crash flow chi tiết:

1. Exception xảy ra (access violation, stack overflow, etc.)
     │
     ▼
2. Kernel dispatch exception to user-mode handler chain:
   ├── Vectored Exception Handlers (VEH)
   ├── SEH chain (__try/__except)
   ├── Unhandled Exception Filter
   └── Default: WER handler
     │
     ▼
3. UnhandledExceptionFilter() trong KernelBase.dll:
   ├── Kiểm tra JIT debugger (AeDebug registry key)
   │   HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug
   │     Debugger: "path_to_debugger -p %ld -e %ld"
   │     Auto: "1" = auto attach, "0" = prompt
   ├── Nếu có JIT debugger và Auto=0 → hỏi user
   ├── Nếu có JIT debugger và Auto=1 → launch debugger
   └── Nếu không có JIT → WER
     │
     ▼
4. WerFault.exe launched (out-of-process crash collection):
   ├── Suspend crashing process
   ├── Collect crash data:
   │   ├── Exception record (code, address, parameters)
   │   ├── Thread context (registers)
   │   ├── All thread stacks
   │   ├── Loaded modules list
   │   ├── Process memory (minidump or full)
   │   ├── Process environment block
   │   └── System information
   ├── Generate WER report
   ├── Store locally:
   │   ├── %LOCALAPPDATA%\CrashDumps\  (app dumps)
   │   └── %ProgramData%\Microsoft\Windows\WER\
   │       ├── ReportArchive\   (submitted reports)
   │       └── ReportQueue\     (pending reports)
   ├── Display crash dialog (nếu configured)
   └── Submit to Microsoft (nếu allowed)
```

### 10.4.2 WER Local Dump Collection

```
Registry key để enable local crash dump collection cho specific app:

HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\<app.exe>
  DumpFolder: REG_EXPAND_SZ  Path lưu dump (default: %LOCALAPPDATA%\CrashDumps)
  DumpCount:  REG_DWORD      Số dump tối đa giữ (default: 10)
  DumpType:   REG_DWORD      0=Custom, 1=Mini, 2=Full (default: 1)
  CustomDumpFlags: REG_DWORD  MiniDumpWithFullMemory etc (khi DumpType=0)

Ví dụ: Enable full dump cho target app:
  reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\target.exe" /v DumpType /t REG_DWORD /d 2 /f
  reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\target.exe" /v DumpFolder /t REG_EXPAND_SZ /d "C:\Dumps" /f
  reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\target.exe" /v DumpCount /t REG_DWORD /d 5 /f

Global setting (tất cả apps):
  HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps
  (không có <app.exe> subkey = apply cho tất cả)

JIT Debugger configuration:
  HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug
    Debugger: REG_SZ  
      WinDbg: "\"C:\Debuggers\windbg.exe\" -p %ld -e %ld -g"
      VS:     "\"C:\...\vsJITDebugger.exe\" -p %ld -e %ld"
    Auto: REG_SZ  "1" (auto attach) hoặc "0" (prompt)

  # Install WinDbg as JIT debugger:
  windbg -I
  
  # Install for 32-bit apps on 64-bit OS:
  # Cấu hình riêng tại WOW6432Node
```

### 10.4.3 Kernel Crash (BSOD) Flow

```
Kernel crash (Blue Screen of Death) flow:

1. KeBugCheckEx(BugCheckCode, Param1, Param2, Param3, Param4)
     │  Hoặc KeBugCheck(BugCheckCode) - không có params
     │
     ▼
2. Raise IRQL to HIGH_LEVEL (chống scheduling)
     │
     ▼
3. Disable interrupts trên tất cả processors
     │
     ▼
4. Display blue/green screen:
   ├── Stop code và parameters
   ├── QR code (Windows 10+) link tới troubleshooting page
   ├── "Your PC ran into a problem" message
   └── Collection progress %
     │
     ▼
5. Write crash dump:
   ├── Dump data được ghi vào pagefile (hoặc dedicated dump partition)
   ├── Sử dụng I/O path đơn giản (bypass file system, direct disk writes)
   ├── Progress được hiển thị trên màn hình (0% → 100%)
   └── Sau reboot: crashdmp.sys copy từ pagefile sang DumpFile path
     │
     ▼
6. Reboot (nếu AutoReboot = 1)
     │
     ▼
7. Sau reboot:
   ├── SMSS.exe đọc pagefile header, phát hiện crash dump
   ├── Copy crash dump từ pagefile sang %SystemRoot%\MEMORY.DMP
   ├── WER gửi report (nếu enabled)
   └── Event Log: Event ID 1001 (BugCheck) trong System log
```

### 10.4.4 Crash Dump Types

| Type | Registry Value | Size | Nội dung |
|------|---------------|------|----------|
| Small (Minidump) | 3 | 256 KB - 2 MB | Thread stacks, loaded modules, stop code, limited process info |
| Kernel Memory | 2 | ~RAM/3 | Toàn bộ kernel memory, driver memory, KHÔNG có user pages |
| Automatic | 7 | Variable | Kernel memory + pages liên quan đến crash (smart selection) |
| Complete | 1 | = RAM size | Tất cả physical memory (bao gồm user-mode) |
| Active Memory | *Custom* | Variable | Tất cả memory trừ free pages và unmodified pages |

```
Configuration:
  HKLM\SYSTEM\CurrentControlSet\Control\CrashControl
    CrashDumpEnabled: REG_DWORD
      0 = None (không tạo dump)
      1 = Complete Memory Dump
      2 = Kernel Memory Dump
      3 = Small Memory Dump (minidump)
      7 = Automatic Memory Dump (default từ Windows 8)
    DumpFile: REG_EXPAND_SZ  "%SystemRoot%\MEMORY.DMP"
    MinidumpsDir: REG_EXPAND_SZ  "%SystemRoot%\Minidump"
    AutoReboot: REG_DWORD  1
    AlwaysKeepMemoryDump: REG_DWORD  0
    NMICrashDump: REG_DWORD  1 (cho phép NMI trigger dump)
    Overwrite: REG_DWORD  1 (ghi đè dump cũ)
    
    FilterPages: REG_DWORD  1 (loại bỏ pages không cần thiết)
    DedicatedDumpFile: REG_EXPAND_SZ  (dump file riêng, không dùng pagefile)
    DumpFileSize: REG_DWORD  (kích thước dedicated dump file, MB)

Lưu ý:
  - Automatic dump type tự động điều chỉnh pagefile size nếu cần
  - Complete dump cần pagefile >= RAM size + 1 MB
  - Kernel dump cần pagefile >= ~1/3 RAM
  - Minidump luôn được tạo thêm dù config là kernel/complete
```

### 10.4.5 Crash Dump Analysis với WinDbg

```
;; === BƯỚC 1: Mở dump file ===
;; File → Open Crash Dump → chọn MEMORY.DMP

;; === BƯỚC 2: Set symbol path ===
.sympath srv*C:\Symbols*https://msdl.microsoft.com/download/symbols
.reload /f

;; === BƯỚC 3: Automatic analysis ===
!analyze -v

;; Output của !analyze -v gồm:
;;   BUGCHECK_CODE: 0x000000D1
;;   BUGCHECK_P1-P4: parameters cụ thể
;;   FAULTING_MODULE: driver.sys
;;   PROCESS_NAME: process bị lỗi
;;   STACK_TEXT: call stack tại thời điểm crash
;;   FOLLOWUP_IP: instruction gây crash
;;   MODULE_NAME: module gây lỗi
;;   IMAGE_NAME: file name
;;   FAILURE_BUCKET_ID: unique identifier cho loại crash này

;; === BƯỚC 4: Kiểm tra chi tiết ===
.bugcheck              ;; Bug check code và params
!process 0 0           ;; List tất cả processes tại thời điểm crash
!process 0 7           ;; Chi tiết processes với threads và stacks
!thread                ;; Thread hiện tại (faulting thread)
.thread <addr>         ;; Switch sang thread khác
kb                     ;; Stack trace (basic)
kv                     ;; Stack trace với frame pointer và params
kp                     ;; Stack trace với full parameter info
knf                    ;; Stack trace với frame sizes

;; === BƯỚC 5: Memory inspection ===
!pool <addr>           ;; Pool allocation info tại address
!poolval               ;; Validate pool headers
!poolfind Tag          ;; Tìm pool allocations theo tag
dd <addr>              ;; Display DWORDs tại address
dps <addr>             ;; Display pointers với symbols
du <addr>              ;; Display Unicode string
da <addr>              ;; Display ASCII string
!address <addr>        ;; Address type và region info

;; === BƯỚC 6: Driver inspection ===
lm                     ;; List loaded modules
lmvm <module>          ;; Verbose info cho module
!drvobj <addr>         ;; Driver object details
!devobj <addr>         ;; Device object details
!object <addr>         ;; Object header

;; === BƯỚC 7: Page Table check ===
!pte <addr>            ;; Page table entry cho address
!pfn <pfn>             ;; Physical frame number details

;; === BƯỚC 8: VM và memory stats ===
!vm                    ;; Virtual memory statistics
!memusage              ;; Physical memory usage
!filecache             ;; File cache usage
```

### 10.4.6 Common Bugcheck Codes

```
Bugcheck Code              Nguyên nhân                        Fix/Investigation

0x0A IRQL_NOT_LESS_OR_EQUAL
  P1=Address accessed, P2=IRQL, P3=Read/Write, P4=Instruction
  Driver truy cập paged memory tại DISPATCH_LEVEL hoặc cao hơn.
  Fix: !analyze → tìm driver trong stack → cập nhật/gỡ driver.

0x1E KMODE_EXCEPTION_NOT_HANDLED
  P1=Exception code, P2=Address, P3/P4=Exception params
  Exception trong kernel mode không được handle.
  Fix: Xem exception code (0xC0000005=access violation).

0x3B SYSTEM_SERVICE_EXCEPTION
  P1=Exception code, P2=Address, P3=Exception record, P4=Context
  Exception trong system service (thường do driver kernel hook).
  Fix: Kiểm tra stack cho 3rd party driver.

0x50 PAGE_FAULT_IN_NONPAGED_AREA
  P1=Faulting address, P2=Read/Write, P3=Instruction, P4=Fault type
  Truy cập memory address không hợp lệ.
  Fix: Kiểm tra P1 - nếu gần 0 → null pointer dereference.

0x7E SYSTEM_THREAD_EXCEPTION_NOT_HANDLED
  P1=Exception code, P2=Address, P3=Exception record, P4=Context
  System worker thread throw exception không handled.
  Fix: !analyze tìm driver trong STACK_TEXT.

0x9F DRIVER_POWER_STATE_FAILURE
  P1=SubCode, P2/P3/P4=Context-dependent
  Driver không xử lý power transition đúng.
  Fix: !powertriage, !devpowerstate.

0xD1 DRIVER_IRQL_NOT_LESS_OR_EQUAL
  P1=Address, P2=IRQL, P3=Read/Write, P4=Instruction
  Giống 0x0A nhưng cụ thể xác định lỗi do driver.
  Fix: P4 → instruction address → lmva <P4> → tìm driver.

0xEF CRITICAL_PROCESS_DIED
  P1=Process object, P2-P4=Reserved
  Critical process (csrss, wininit, smss) bị terminate.
  Fix: !process P1 7 → xem tại sao process die.

0x109 CRITICAL_STRUCTURE_CORRUPTION
  P1=Signature, P2=Corrupted address, P3=Type, P4=Expected
  PatchGuard detected kernel structure tampering.
  Fix: Thường do rootkit hoặc incompatible security software.

0x133 DPC_WATCHDOG_VIOLATION
  P1=SubCode (0=DPC routine, 1=interrupt)
  DPC hoặc interrupt routine chạy quá lâu (>100ms default).
  Fix: Kiểm tra driver nào chiếm DPC time quá nhiều.

0x139 KERNEL_SECURITY_CHECK_FAILURE
  P1=Type (0=stack buffer overrun, etc.)
  Security check fail (buffer overflow detected by /GS).
  Fix: Có thể là exploit attempt hoặc driver bug.

0x1A MEMORY_MANAGEMENT
  P1=SubType
  Memory manager phát hiện data corruption.
  Fix: Chạy Windows Memory Diagnostic (mdsched.exe).

0x19A KERNEL_STORAGE_SLOT_IN_USE  [UPDATE 2026]
  Windows 11 24H2: new bugcheck cho storage slot conflicts.
  
0xE2 MANUALLY_INITIATED_CRASH
  Crash được trigger thủ công (NMI, keyboard, notmyfault.exe).
  Dùng cho testing crash dump infrastructure.
```

### 10.4.7 Pool Corruption Debugging

```
Pool corruption là một trong những crash khó debug nhất.

;; Pool inspection commands:
!pool <address>         ;; Xem pool block chứa address
!poolval <pool_type>    ;; Validate tất cả pool headers
!poolfind <tag>         ;; Tìm tất cả allocations với pool tag
!poolused              ;; Pool usage statistics theo tag

;; Pool tag identification:
!pooltag <tag>         ;; Lookup pool tag owner
                       ;; Hoặc xem file: %SystemRoot%\System32\drivers\pooltag.txt

;; Special Pool (detect pool corruption sớm):
;; Bật special pool cho specific tag:
;;   verifier /flags 1 /driver problematic.sys
;;   Hoặc: gflags /p /enable app.exe /full
;;
;; Special pool đặt guard pages trước/sau allocation:
;; ┌─────────┐┌──────────────┐┌─────────┐
;; │Guard    ││ Allocation   ││ Guard   │
;; │Page     ││ (your data)  ││ Page    │
;; │(NO ACC.)││              ││(NO ACC.)│
;; └─────────┘└──────────────┘└─────────┘
;; Buffer overrun → access guard page → IMMEDIATE crash
;; (thay vì corrupt silently và crash later)

;; Driver Verifier cho pool debugging:
verifier /standard /driver suspect.sys
;; Sau reboot, driver verifier sẽ bắt lỗi:
;;   - Pool buffer overrun/underrun
;;   - Double free
;;   - Free pool tại sai IRQL
;;   - Pool allocation không tag
```

---

## 10.5 Task Scheduler Internals

### 10.5.1 Task Store và Format

```
Task Scheduler Service: Schedule (svchost.exe -k netsvcs)

Task storage:
  %SystemRoot%\System32\Tasks\       ← XML task definitions
  %SystemRoot%\System32\Tasks\Microsoft\  ← Built-in tasks
  
  Registry metadata:
  HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\
    ├── Tree\       ← Folder hierarchy (key per folder/task)
    ├── Tasks\      ← Task definitions indexed by GUID
    │   └── {GUID}\
    │       ├── Path: REG_SZ         Task path
    │       ├── Hash: REG_BINARY     SHA-256 of XML
    │       ├── Triggers: REG_BINARY Serialized triggers
    │       ├── DynamicInfo: REG_BINARY Runtime state
    │       ├── Actions: REG_BINARY  Serialized actions
    │       └── Schema: REG_DWORD    Schema version
    ├── Boot\       ← Tasks triggered at boot
    ├── Logon\      ← Tasks triggered at logon
    ├── Plain\      ← Tasks với other triggers
    └── Maintenance\← Maintenance window tasks
```

### 10.5.2 Task XML Structure

```xml
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2026-01-15T10:00:00</Date>
    <Author>DOMAIN\User</Author>
    <Description>Task description</Description>
    <URI>\MyFolder\MyTask</URI>
  </RegistrationInfo>
  
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2026-01-15T08:00:00</StartBoundary>
      <Repetition>
        <Interval>PT1H</Interval>  <!-- Mỗi giờ -->
      </Repetition>
    </CalendarTrigger>
    <BootTrigger>
      <Delay>PT5M</Delay>  <!-- 5 phút sau boot -->
    </BootTrigger>
    <LogonTrigger>
      <UserId>DOMAIN\User</UserId>
    </LogonTrigger>
    <EventTrigger>
      <Subscription>
        <QueryList>
          <Query>
            <Select Path="Security">*[System[EventID=4625]]</Select>
          </Query>
        </QueryList>
      </Subscription>
    </EventTrigger>
  </Triggers>
  
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>  <!-- SYSTEM -->
      <LogonType>Password</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  
  <Settings>
    <Hidden>true</Hidden>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
  </Settings>
  
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-WindowStyle Hidden -File C:\script.ps1</Arguments>
    </Exec>
    <!-- COM handler action: -->
    <ComHandler>
      <ClassId>{CLSID-HERE}</ClassId>
      <Data>optional data</Data>
    </ComHandler>
  </Actions>
</Task>
```

### 10.5.3 Scheduled Task Persistence cho Malware

```
Malware sử dụng scheduled tasks cho persistence vì:
  - Có thể chạy với SYSTEM privileges
  - Hidden tasks (Hidden flag trong XML)
  - Trigger đa dạng: boot, logon, schedule, event-based
  - COM handler tasks khó detect hơn exec tasks
  - schtasks.exe là LOLBin (Living Off the Land Binary)

Attack techniques:

1. Command-line (schtasks):
   schtasks /create /tn "WindowsUpdate" /tr "C:\malware.exe" /sc onlogon /ru SYSTEM
   
   # Hidden task:
   schtasks /create /tn "\Microsoft\Windows\UpdateTask" /tr "cmd /c payload" /sc daily /st 03:00 /ru SYSTEM

2. COM API (stealthier, không để lại command line artifacts):
   $Service = New-Object -ComObject 'Schedule.Service'
   $Service.Connect()
   $Folder = $Service.GetFolder('\')
   $TaskDef = $Service.NewTask(0)
   $TaskDef.Settings.Hidden = $true
   # ... configure triggers and actions ...
   $Folder.RegisterTaskDefinition('EvilTask', $TaskDef, 6, 'SYSTEM', $null, 5)

3. COM Handler tasks:
   - Action type là ComHandler thay vì Exec
   - Trigger load một COM DLL khi task chạy
   - Khó detect vì không có command line rõ ràng
   - Cần kiểm tra CLSID → DLL path

Detection:
  # Liệt kê tất cả tasks:
  Get-ScheduledTask | Select TaskPath, TaskName, State,
      @{N='Actions';E={$_.Actions | ForEach-Object {
          if($_.Execute) {"Exec: $($_.Execute) $($_.Arguments)"}
          elseif($_.ClassId) {"COM: $($_.ClassId)"}
      }}}
  
  # Tìm tasks chạy với SYSTEM:
  Get-ScheduledTask |
      Where-Object { $_.Principal.UserId -eq 'SYSTEM' }
  
  # Tìm hidden tasks:
  Get-ScheduledTask | Where-Object { $_.Settings.Hidden -eq $true }
  
  # Kiểm tra tasks tạo bởi non-Microsoft:
  Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' }
  
  # Event Log:
  #   Microsoft-Windows-TaskScheduler/Operational
  #   Event ID 106: Task registered
  #   Event ID 140: Task updated
  #   Event ID 141: Task deleted
  #   Event ID 200: Action started
  #   Event ID 201: Action completed
  
  Sysmon: không có event ID riêng cho scheduled tasks,
  nhưng Sysmon Event ID 1 (Process Create) capture schtasks.exe execution
  với full command line.
```

---

## 10.6 Performance Counters và Diagnostics

### 10.6.1 Performance Counter Architecture

```
Performance Counter V1 (Legacy, Registry-based):
  - Counter data expose qua registry key:
    HKEY_PERFORMANCE_DATA (virtual, không hiện trong regedit)
  - Provider DLLs registered tại:
    HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Performance\
      Library: REG_SZ       Provider DLL path
      Open:    REG_SZ       Open function name
      Collect: REG_SZ       Collect function name
      Close:   REG_SZ       Close function name
  - Consumer gọi RegQueryValueEx(HKEY_PERFORMANCE_DATA, "counter_index", ...)
  - Chậm vì mỗi query gọi DLL functions
  - Extensible: 3rd party providers có thể thêm counters

Performance Counter V2 (Modern, Manifest-based, Vista+):
  - Counter definitions trong XML manifest
  - Provider registered với perflib thông qua:
    lodctr /m:manifest.man
  - Performance data expose qua PCW (Performance Counter for Windows)
  - Kernel-mode: PcwRegister(), PcwCreateInstance()
  - User-mode: PerfCreateInstance(), PerfSetCounterSetInfo()
  - Hiệu suất tốt hơn V1 (kernel-level collection)
  - Type safe, less error prone

Querying counters:
  # PowerShell:
  Get-Counter '\Process(*)\% Processor Time'
  Get-Counter '\Memory\Available MBytes'
  Get-Counter '\PhysicalDisk(*)\Disk Read Bytes/sec'
  
  # Continuous monitoring:
  Get-Counter '\Processor(_Total)\% Processor Time' -Continuous -SampleInterval 2
  
  # Performance Monitor GUI:
  perfmon.exe
  
  # Typeperf (command line):
  typeperf "\Process(*)\Working Set" -si 5 -sc 10 -o output.csv
```

### 10.6.2 Windows Performance Recorder (WPR) và Analyzer (WPA)

```
WPR (Windows Performance Recorder):
  - Thu thập ETW traces với predefined profiles
  - Tối ưu hơn logman/xperf cho comprehensive tracing
  - GUI: wprui.exe
  - CLI: wpr.exe

  # Start recording với built-in profile:
  wpr -start CPU               # CPU analysis
  wpr -start DiskIO             # Disk I/O
  wpr -start FileIO             # File operations
  wpr -start Network            # Network activity
  wpr -start Heap               # Heap usage
  wpr -start VirtualAllocation  # Virtual memory
  wpr -start GeneralProfile     # Comprehensive (CPU + Disk + Memory)
  
  # Multiple profiles:
  wpr -start CPU -start DiskIO -start Network
  
  # Stop và save:
  wpr -stop trace.etl "Description of trace"
  
  # Cancel:
  wpr -cancel

WPA (Windows Performance Analyzer):
  - Phân tích visual của ETW traces (.etl files)
  - Mở: wpa.exe trace.etl
  
  Analysis workflow:
  1. Mở trace trong WPA
  2. Chọn graph type (CPU Usage, Disk Usage, Memory, etc.)
  3. Zoom vào time range quan tâm
  4. Group by Process, Thread, Module, Stack
  5. Tìm bottleneck:
     - CPU: process/thread nào dùng nhiều CPU?
     - Disk: file nào bị đọc/ghi nhiều?
     - Memory: hard faults cho biết thrashing
     - Wait Analysis: thread chờ gì? (lock, I/O, network)

  Key WPA views cho security:
  - Generic Events: xem raw ETW events
  - Process Lifetimes: thời gian process tồn tại
  - System Activity: tổng quan system behavior
  - Regions of Interest: mark và phân tích time ranges
```

### 10.6.3 Reliability Monitor

```
Reliability Monitor:
  - Theo dõi system stability theo thời gian (1-10 scale)
  - Hiển thị application failures, Windows failures, informational events
  - Mở: perfmon /rel   hoặc   Settings → Reliability history

  Data source: RACAgent scheduled task thu thập data
  Storage: %ProgramData%\Microsoft\RAC\

  Quan trọng cho forensics:
  - Xem lịch sử crash của applications
  - Detect thời điểm system bắt đầu không ổn định
  - Correlate với malware installation timeline
```

---

## 10.7 Security-Relevant Diagnostics

### 10.7.1 Sysmon Configuration và Events

```
Sysmon (System Monitor) - tool từ Sysinternals:
  - Kernel driver ghi detailed system activity vào Event Log
  - Cấu hình bằng XML file
  - Event log: Microsoft-Windows-Sysmon/Operational
  - Install: sysmon.exe -i config.xml
  - Update config: sysmon.exe -c config.xml

Sysmon Event IDs:
  ┌─────┬───────────────────────────────────────────────────────┐
  │ ID  │ Event                                                  │
  ├─────┼───────────────────────────────────────────────────────┤
  │  1  │ Process Create (full command line, hash, parent)       │
  │  2  │ File creation time changed (timestomping detection)    │
  │  3  │ Network connection (source/dest IP, port, process)     │
  │  4  │ Sysmon service state changed                           │
  │  5  │ Process terminated                                      │
  │  6  │ Driver loaded (signed/unsigned, hash)                   │
  │  7  │ Image loaded (DLL load, hash, signature status)        │
  │  8  │ CreateRemoteThread (injection detection)                │
  │  9  │ RawAccessRead (direct disk read bypassing filesystem)  │
  │ 10  │ ProcessAccess (OpenProcess - credential dump detect)   │
  │ 11  │ FileCreate (new file creation)                          │
  │ 12  │ Registry Event - Create/Delete key or value            │
  │ 13  │ Registry Event - Value Set                              │
  │ 14  │ Registry Event - Key/Value Rename                       │
  │ 15  │ FileCreateStreamHash (ADS creation)                     │
  │ 16  │ Sysmon configuration changed                            │
  │ 17  │ PipeEvent - Pipe Created (named pipe)                   │
  │ 18  │ PipeEvent - Pipe Connected                              │
  │ 19  │ WmiEvent - WmiEventFilter activity                      │
  │ 20  │ WmiEvent - WmiEventConsumer activity                    │
  │ 21  │ WmiEvent - WmiEventConsumerToFilter activity            │
  │ 22  │ DNSEvent - DNS query (domain resolution)                │
  │ 23  │ FileDelete - File Delete archived                       │
  │ 24  │ ClipboardChange - Clipboard content changed             │
  │ 25  │ ProcessTampering - Process image change                 │
  │ 26  │ FileDeleteDetected - File Delete logged                 │
  │ 27  │ FileBlockExecutable - Blocked executable file write     │
  │ 28  │ FileBlockShredding - Blocked file shredding             │
  │ 29  │ FileExecutableDetected - Executable file write detected │
  │255  │ Error                                                    │
  └─────┴───────────────────────────────────────────────────────┘

Ví dụ Sysmon config (chọn lọc events quan trọng):

<Sysmon schemaversion="4.90">
  <EventFiltering>
    <!-- Process Creation - log everything except noise -->
    <RuleGroup name="ProcessCreate" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <Image condition="is">C:\Windows\System32\conhost.exe</Image>
        <Image condition="is">C:\Windows\System32\backgroundTaskHost.exe</Image>
      </ProcessCreate>
    </RuleGroup>
    
    <!-- Network connections -->
    <RuleGroup name="NetworkConnect" groupRelation="or">
      <NetworkConnect onmatch="include">
        <DestinationPort condition="is">443</DestinationPort>
        <DestinationPort condition="is">80</DestinationPort>
        <DestinationPort condition="is">445</DestinationPort>
        <DestinationPort condition="is">3389</DestinationPort>
      </NetworkConnect>
    </RuleGroup>
    
    <!-- CreateRemoteThread - injection detection -->
    <RuleGroup name="CreateRemoteThread" groupRelation="or">
      <CreateRemoteThread onmatch="include">
        <TargetImage condition="is">C:\Windows\System32\lsass.exe</TargetImage>
      </CreateRemoteThread>
    </RuleGroup>
    
    <!-- ProcessAccess - credential dumping detection -->
    <RuleGroup name="ProcessAccess" groupRelation="or">
      <ProcessAccess onmatch="include">
        <TargetImage condition="is">C:\Windows\System32\lsass.exe</TargetImage>
      </ProcessAccess>
    </RuleGroup>
    
    <!-- Registry persistence keys -->
    <RuleGroup name="RegistryEvent" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="contains">CurrentVersion\Run</TargetObject>
        <TargetObject condition="contains">\Services\</TargetObject>
        <TargetObject condition="contains">Image File Execution</TargetObject>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

### 10.7.2 Windows Event Log Architecture (EVTX)

```
EVTX File Format:
┌──────────────────────────────────────────────────────────────┐
│ File Header (4096 bytes)                                      │
│  Signature: "ElfFile\x00"                                    │
│  First/Last Chunk Number                                      │
│  Next Record ID                                               │
│  Header Size, Minor/Major Version                             │
│  Flags (dirty, full)                                          │
│  Checksum                                                     │
├──────────────────────────────────────────────────────────────┤
│ Chunk 0 (65536 bytes)                                         │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ Chunk Header (512 bytes)                                │  │
│  │  Signature: "ElfChnk\x00"                              │  │
│  │  First/Last Record Number                               │  │
│  │  First/Last Record ID                                   │  │
│  │  String Table (template caching)                        │  │
│  │  Template Table                                         │  │
│  ├────────────────────────────────────────────────────────┤  │
│  │ Event Record 1                                          │  │
│  │  Signature: "\x2a\x2a\x00\x00" (magic number)         │  │
│  │  Size, Record Number, Timestamp (FILETIME)              │  │
│  │  BinXml data (event content)                            │  │
│  ├────────────────────────────────────────────────────────┤  │
│  │ Event Record 2                                          │  │
│  │ ...                                                     │  │
│  │ Event Record N                                          │  │
│  └────────────────────────────────────────────────────────┘  │
├──────────────────────────────────────────────────────────────┤
│ Chunk 1                                                       │
│ Chunk 2                                                       │
│ ...                                                           │
└──────────────────────────────────────────────────────────────┘

Event Log storage:
  %SystemRoot%\System32\winevt\Logs\
    ├── System.evtx
    ├── Application.evtx
    ├── Security.evtx
    ├── Microsoft-Windows-Sysmon%4Operational.evtx
    ├── Microsoft-Windows-PowerShell%4Operational.evtx
    └── ...

Event Log channels:
  - Admin: events cho end-user (lỗi, cảnh báo)
  - Operational: events cho troubleshooting
  - Analytic: high-volume, không enable mặc định
  - Debug: developer debugging, không enable mặc định

Event Forwarding (WEF):
  - Windows Event Forwarding: thu thập logs từ nhiều máy về central collector
  - Source-initiated: client push events lên collector
  - Collector-initiated: collector pull events từ client
  
  Configuration:
    # Trên collector:
    wecutil qc          # Configure collector service
    
    # Trên source (via GPO hoặc manual):
    winrm quickconfig   # Enable WinRM
    # GPO: Computer → Admin Templates → Event Forwarding
    # Configure target Subscription Manager: Server=http://collector:5985/...
    
    # Tạo subscription trên collector:
    wecutil cs subscription.xml

EVTX forensics:
  - Deleted events: EVTX không thực sự xóa records, chỉ unlink
  - Carving tools có thể khôi phục deleted events
  - Tools: python-evtx, EVTXtract, EvtxECmd (Eric Zimmerman)
  - Kiểm tra: Event ID 1102 (Security log cleared) và Event ID 104 (System log cleared)
```

### 10.7.3 PowerShell Logging

```
PowerShell logging có 3 loại chính:

1. Module Logging:
   - Log tất cả pipeline execution output
   - GPO: Computer → Admin Templates → Windows Components →
          Windows PowerShell → Turn on Module Logging
   - Registry:
     HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging
       EnableModuleLogging: REG_DWORD = 1
     HKLM\...\ModuleLogging\ModuleNames
       *: REG_SZ = * (log tất cả modules)
   - Event Log: Microsoft-Windows-PowerShell/Operational
   - Event ID: 4103

2. Script Block Logging:
   - Log nội dung của script blocks TRƯỚC khi execute
   - BẮT được deobfuscated code (vì logging xảy ra sau deobfuscation)
   - GPO: Computer → Admin Templates → Windows Components →
          Windows PowerShell → Turn on PowerShell Script Block Logging
   - Registry:
     HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
       EnableScriptBlockLogging: REG_DWORD = 1
       EnableScriptBlockInvocationLogging: REG_DWORD = 1 (log invoke events)
   - Event ID: 4104 (Script Block text)
   - Event ID: 4105 (Script Block invoke start)
   - Event ID: 4106 (Script Block invoke complete)
   
   Quan trọng: Event ID 4104 là GOLD cho forensics vì
   nó capture actual code, kể cả khi attacker dùng
   -EncodedCommand hoặc obfuscation techniques.

3. Transcription:
   - Ghi toàn bộ PowerShell session vào text file
   - Bao gồm input và output
   - GPO: Computer → Admin Templates → Windows Components →
          Windows PowerShell → Turn on PowerShell Transcription
   - Registry:
     HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription
       EnableTranscripting: REG_DWORD = 1
       OutputDirectory: REG_SZ = "C:\PSTranscripts"
       EnableInvocationHeader: REG_DWORD = 1
   - Output: text files tại OutputDirectory

Recommended configuration cho security monitoring:
  - BẬT cả 3 loại logging
  - Script Block Logging là quan trọng nhất (bắt obfuscated code)
  - Forward PowerShell events về SIEM
  - Giám sát Event ID 4104 cho suspicious keywords:
    Invoke-Mimikatz, Invoke-Expression, IEX, DownloadString,
    Net.WebClient, System.Reflection, VirtualAlloc, kernel32,
    amsi, bypass, -enc, -encodedcommand
```

### 10.7.4 Key Security Event IDs

```
Security Event Log - Event IDs quan trọng nhất:

Account Logon:
  4624  - Logon thành công
         Logon Type: 2=Interactive, 3=Network, 4=Batch, 5=Service,
                     7=Unlock, 8=NetworkCleartext, 9=NewCredentials,
                     10=RemoteInteractive (RDP), 11=CachedInteractive
         Fields: TargetUserName, LogonType, IpAddress, WorkstationName
  4625  - Logon thất bại
         Status/SubStatus codes cho biết lý do thất bại
  4634  - Logoff
  4647  - User initiated logoff
  4648  - Explicit credentials logon (runas)
  4672  - Special privileges assigned (admin logon)

Account Management:
  4720  - User account created
  4722  - User account enabled
  4723  - Password change attempt
  4724  - Password reset attempt
  4725  - User account disabled
  4726  - User account deleted
  4728  - Member added to security-enabled global group
  4732  - Member added to security-enabled local group
  4735  - Security-enabled local group changed
  4738  - User account changed
  4756  - Member added to universal security group

Process Tracking:
  4688  - New process created
         Fields: NewProcessName, CommandLine (cần bật audit),
                 ParentProcessName, TokenElevationType, SubjectUserSid
  4689  - Process exited

Service:
  4697  - Service installed (Security log)
  7045  - Service installed (System log)
         Fields: ServiceName, ImagePath, ServiceType, StartType, AccountName
  7040  - Service start type changed

Object Access:
  4656  - Handle to object requested
  4663  - Attempt to access object
  4660  - Object deleted

Audit Policy:
  4719  - System audit policy changed
  1102  - Security log cleared ← RẤT QUAN TRỌNG - indicator của cover tracks
  
  104   - System log cleared (System log)

Other:
  4698  - Scheduled task created
  4699  - Scheduled task deleted
  4700  - Scheduled task enabled
  4701  - Scheduled task disabled
  4702  - Scheduled task updated
  
  5140  - Network share accessed
  5145  - Network share object access (detailed)
  
  4771  - Kerberos pre-authentication failed (password spray)
  4768  - Kerberos TGT requested
  4769  - Kerberos service ticket requested (Kerberoasting)
```

```powershell
# === TRUY VẤN SECURITY EVENTS ===

# Logon thành công gần đây
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 20 |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        [PSCustomObject]@{
            Time = $_.TimeCreated
            User = ($xml.Event.EventData.Data | Where Name -eq 'TargetUserName').'#text'
            LogonType = ($xml.Event.EventData.Data | Where Name -eq 'LogonType').'#text'
            SourceIP = ($xml.Event.EventData.Data | Where Name -eq 'IpAddress').'#text'
        }
    }

# Process creation với command line
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 50 |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        [PSCustomObject]@{
            Time = $_.TimeCreated
            Process = ($xml.Event.EventData.Data | Where Name -eq 'NewProcessName').'#text'
            CommandLine = ($xml.Event.EventData.Data | Where Name -eq 'CommandLine').'#text'
            Parent = ($xml.Event.EventData.Data | Where Name -eq 'ParentProcessName').'#text'
        }
    }

# Service installations (malware persistence)
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 20 |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        [PSCustomObject]@{
            Time = $_.TimeCreated
            ServiceName = ($xml.Event.EventData.Data | Where Name -eq 'ServiceName').'#text'
            ImagePath = ($xml.Event.EventData.Data | Where Name -eq 'ImagePath').'#text'
            Account = ($xml.Event.EventData.Data | Where Name -eq 'AccountName').'#text'
        }
    }

# Detect log clearing (cover tracks)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -ErrorAction SilentlyContinue
Get-WinEvent -FilterHashtable @{LogName='System'; Id=104} -ErrorAction SilentlyContinue

# Kerberoasting detection (Event 4769 với RC4 encryption)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} -MaxEvents 100 |
    Where-Object {
        $xml = [xml]$_.ToXml()
        ($xml.Event.EventData.Data | Where Name -eq 'TicketEncryptionType').'#text' -eq '0x17'
    }

# Enable command line auditing:
# GPO: Computer → Admin Templates → System → Audit Process Creation
#   → Include command line in process creation events = Enabled
# Registry:
# HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit
#   ProcessCreationIncludeCmdLine_Enabled: REG_DWORD = 1
```

### 10.7.5 Log Analysis cho Incident Response

```
Incident Response Log Analysis Workflow:

1. Thu thập logs:
   # Copy event logs:
   robocopy C:\Windows\System32\winevt\Logs C:\Evidence\EventLogs /MIR
   
   # Export specific log:
   wevtutil epl Security C:\Evidence\Security.evtx
   wevtutil epl System C:\Evidence\System.evtx
   wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\Evidence\Sysmon.evtx
   wevtutil epl "Microsoft-Windows-PowerShell/Operational" C:\Evidence\PowerShell.evtx

2. Timeline creation:
   # Dùng tools như:
   - EvtxECmd (Eric Zimmerman) → CSV output cho timeline
   - log2timeline (Plaso) → super timeline
   - Hayabusa → Sigma rule-based EVTX analysis
   
   # Hayabusa (open source, nhanh):
   hayabusa.exe csv-timeline -d C:\Evidence\EventLogs -o timeline.csv
   hayabusa.exe logon-summary -d C:\Evidence\EventLogs
   hayabusa.exe search -d C:\Evidence\EventLogs -k "mimikatz"

3. Key analysis areas:

   a. Initial Access:
      - Event 4624 Type 10 (RDP) từ IP lạ
      - Event 4625 bursts (brute force)
      - Event 4648 (runas với explicit creds)
   
   b. Execution:
      - Event 4688 / Sysmon 1: Process creation timeline
      - PowerShell 4104: Script block content
      - Sysmon 7: DLL loads (DLL sideloading)
   
   c. Persistence:
      - Event 7045 / 4697: Service installation
      - Sysmon 12/13: Registry Run key changes
      - Sysmon 19/20/21: WMI event subscriptions
      - Event 4698: Scheduled task creation
   
   d. Lateral Movement:
      - Event 4624 Type 3 (network logon) từ internal IPs
      - Event 5140/5145: Share access
      - Event 4769: Service ticket requests (PtT/Kerberoasting)
   
   e. Defense Evasion:
      - Event 1102: Security log cleared
      - Sysmon 2: Timestomping detected
      - Sysmon 25: Process tampering
   
   f. Credential Access:
      - Sysmon 10: ProcessAccess targeting lsass.exe
      - Event 4771: Kerberos pre-auth fail (password spray)
      - Event 4768 anomalies: unusual TGT requests
```

---

## 10.8 [UPDATE 2026] Cập Nhật Windows 11 24H2

### 10.8.1 ETW Improvements

```
[UPDATE 2026] Windows 11 24H2 ETW Changes:

1. Secure ETW Channel:
   - Events được ký bởi kernel trước khi gửi cho consumer
   - Ngăn chặn tampering giữa provider và consumer
   - API mới: EnableTraceEx3() với SECURE_CHANNEL flag
   - Consumer verify integrity qua EventVerifySignature()

2. Threat Intelligence Provider mới:
   - Event ID 25: READVM_REMOTE (detect credential dumping)
   - Event ID 30: SUSPENDTHREAD_REMOTE (thread manipulation)
   - Event ID 35: REGISTRY_SETVALUE_REMOTE (remote registry edit)
   - Enhanced metadata cho mỗi event: call stack hash, source module

3. ETW Stack Walking improvements:
   - Stack collection không còn yêu cầu SeDebugPrivilege cho user-mode stacks
   - Kernel-mode stack walking nhanh hơn 30% (optimized unwinding)
   
4. AutoLogger enhancements:
   - AutoLogger sessions có thể specify encryption cho .etl output
   - Built-in compression cho trace files (LZ4)
   - Max file size tăng lên 100 GB (từ 1 GB limit cũ)
```

### 10.8.2 Crash Dump Improvements

```
[UPDATE 2026] Windows 11 24H2 Crash Dump:

1. Smart Dump (CrashDumpEnabled = 8):
   - New dump type: ML-based page selection
   - Chỉ thu thập pages có xác suất liên quan cao đến crash
   - Kích thước dump giảm 40-60% so với Automatic dump
   - Hiệu quả hơn cho remote crash collection

2. Encrypted Crash Dumps:
   - HKLM\SYSTEM\CurrentControlSet\Control\CrashControl
     EncryptDump: REG_DWORD = 1
   - Sử dụng machine certificate để encrypt dump file
   - Bảo vệ sensitive data trong crash dumps (credentials, keys)

3. Crash Dump Analysis cải tiến:
   - !analyze -v hiển thị nhiều context hơn:
     ├── Related processes (processes giao tiếp với faulting process)
     ├── Recent ETW events trước crash
     ├── Memory corruption pattern analysis
     └── Suggested fix với confidence score
```

### 10.8.3 WMI Security Improvements

```
[UPDATE 2026] Windows 11 24H2 WMI:

1. WMI Subscription Hardening:
   - Permanent event subscriptions yêu cầu admin rights + confirmation
   - New Event ID 5862: WMI subscription blocked by policy
   - GPO mới: "Block WMI permanent event subscriptions"
   - Default: CommandLineEventConsumer bị disable trên new installs

2. WMI Access Audit:
   - Chi tiết hơn: log process, user, namespace, class cho mỗi WMI query
   - Event ID 5863: WMI query audit (khi audit policy enabled)
   - Correlation ID để link các WMI operations với nhau

3. WMI Namespace Security:
   - Default ACLs nghiêm ngặt hơn cho root\subscription
   - SYSTEM và Administrators only (trước đây Users có read access)
```

### 10.8.4 Event Log và Diagnostics Mới

```
[UPDATE 2026] Windows 11 24H2:

1. Windows Event Log:
   - EVTX file size limit tăng lên 4 GB (từ 1 GB)
   - Event Log forwarding hỗ trợ TLS 1.3
   - New channel: Microsoft-Windows-Security-Auditing-Advanced
     ├── Chi tiết hơn 4688: bao gồm environment variables
     ├── Network connection events với SNI information
     └── Enhanced token information

2. Sysmon v16 (2026 compatible):
   - Event ID 30: ProcessInjection (phát hiện tổng hợp injection)
     ├── Kết hợp: CreateRemoteThread + WriteProcessMemory + VirtualAllocEx
     ├── Single event thay vì phải correlate nhiều events
     └── Classification: Classic, APC, Section, Hollowing
   - Event ID 31: ETWTamper (phát hiện ETW manipulation)
   - DNS over HTTPS (DoH) detection trong Event ID 22

3. PowerShell 7.5:
   - AMSI v3 integration: scan deeper (JIT compiled code)
   - Constrained Language Mode v2: nghiêm ngặt hơn
   - New logging: Event ID 4107 cho PowerShell remoting sessions
```

---

## 10.9 Experiments

### Experiment 10.1: Registry Hive Analysis (Advanced)

```
;; === WinDbg Kernel Debugging ===

;; List loaded hives
kd> !reg hivelist
  HiveAddr         HiveFileSize  Path
  fffff803`12340000  0x00a00000  \REGISTRY\MACHINE\SYSTEM
  fffff803`12350000  0x03800000  \REGISTRY\MACHINE\SOFTWARE
  fffff803`12360000  0x00100000  \REGISTRY\MACHINE\SAM
  ...

;; Xem root key của hive
kd> !reg baseblock fffff803`12340000

;; Query specific key
kd> !reg querykey \Registry\Machine\System\CurrentControlSet\Services\Tcpip
  Key:   Tcpip
  Last Write: 2026-08-15 10:23:45
  SubKeys: 5
  Values: 3

;; List open keys trong hive
kd> !reg openkeys fffff803`12340000

;; === Offline Hive Parsing ===

# Load hive offline:
reg.exe load HKU\offline C:\Windows\System32\config\SYSTEM
reg.exe query HKU\offline\ControlSet001\Services /s | findstr ImagePath
reg.exe unload HKU\offline

# PowerShell offline parsing (mount VHD/image):
$hive = [Microsoft.Win32.RegistryKey]::OpenBaseKey('Users', 'Default')
# Hoặc sử dụng tool: RECmd.exe (Eric Zimmerman)
RECmd.exe --hive C:\evidence\NTUSER.DAT --kn "Software\Microsoft\Windows\CurrentVersion\Run"
RECmd.exe --hive C:\evidence\SYSTEM --bn C:\RECmd\BatchExamples\RECmd_Batch_MC.reb --csv C:\output

# Yara rule cho registry persistence:
# Scan hive file cho suspicious strings
yara -s registry_persistence.yar C:\evidence\NTUSER.DAT
```

### Experiment 10.2: ETW Trace cho Security Monitoring

```cmd
:: === Thu thập Process Creation Events ===
logman create trace ProcTrace -p "Microsoft-Windows-Kernel-Process" 0x10 -o proc.etl
logman start ProcTrace
:: ... thực hiện các hoạt động ...
logman stop ProcTrace
logman delete ProcTrace
tracerpt proc.etl -o report.html -of HTML

:: === Thu thập DNS queries ===
logman create trace DNSTrace -p "Microsoft-Windows-DNS-Client" -o dns.etl
logman start DNSTrace
:: ... browse web ...
logman stop DNSTrace
logman delete DNSTrace

:: === List active ETW sessions ===
logman query -ets

:: === Xem providers của một session ===
logman query "EventLog-Security" -ets

:: === PowerShell: Real-time ETW consumer ===
```

```powershell
# Real-time process creation monitoring (simplified):
$query = @"
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
    <Select Path="Microsoft-Windows-Sysmon/Operational">*[System[EventID=1]]</Select>
  </Query>
</QueryList>
"@

$watcher = New-Object System.Diagnostics.Eventing.Reader.EventLogWatcher $query
$watcher.EventRecordWritten.Add({
    param($sender, $e)
    $xml = [xml]$e.EventRecord.ToXml()
    $image = ($xml.Event.EventData.Data | Where Name -eq 'Image').'#text'
    $cmdline = ($xml.Event.EventData.Data | Where Name -eq 'CommandLine').'#text'
    $parent = ($xml.Event.EventData.Data | Where Name -eq 'ParentImage').'#text'
    Write-Host "[$($e.EventRecord.TimeCreated)] $parent -> $image"
    Write-Host "  CMD: $cmdline"
})
$watcher.Enabled = $true
Write-Host "Monitoring process creation... Press Enter to stop."
Read-Host
$watcher.Enabled = $false
```

### Experiment 10.3: WMI Persistence Detection

```powershell
# === Kiểm tra WMI persistence ===

Write-Host "=== Event Filters ===" -ForegroundColor Yellow
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter |
    Format-List Name, Query, QueryLanguage

Write-Host "`n=== Event Consumers ===" -ForegroundColor Yellow
Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer |
    Format-List Name, @{N='Type';E={$_.CimClass.CimClassName}},
    @{N='Detail';E={
        if($_.CommandLineTemplate) {"CMD: $($_.CommandLineTemplate)"}
        elseif($_.ScriptText) {"Script: $($_.ScriptText.Substring(0,100))..."}
        else {"Other consumer type"}
    }}

Write-Host "`n=== Bindings ===" -ForegroundColor Yellow
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding |
    Format-List @{N='Filter';E={$_.Filter.Name}}, @{N='Consumer';E={$_.Consumer.Name}}

# === Kiểm tra WMI event log ===
Write-Host "`n=== WMI Permanent Subscriptions (Event 5861) ===" -ForegroundColor Yellow
Get-WinEvent -LogName "Microsoft-Windows-WMI-Activity/Operational" -MaxEvents 50 |
    Where-Object Id -eq 5861 |
    Format-List TimeCreated, Message
```

### Experiment 10.4: Crash Dump Analysis Walkthrough

```
;; === Crash Dump Analysis Step-by-Step ===

;; 1. Mở dump file trong WinDbg:
;;    File → Open Crash Dump → chọn MEMORY.DMP

;; 2. Set symbols:
.sympath srv*C:\Symbols*https://msdl.microsoft.com/download/symbols
.reload /f

;; 3. Auto analyze:
!analyze -v

;; 4. Đọc kết quả !analyze -v:
;;
;; BUGCHECK_CODE:  d1                    ← DRIVER_IRQL_NOT_LESS_OR_EQUAL
;; BUGCHECK_P1:    fffff80012345678      ← Address accessed
;; BUGCHECK_P2:    00000002              ← IRQL (DISPATCH_LEVEL)
;; BUGCHECK_P3:    00000000              ← Read operation
;; BUGCHECK_P4:    fffff80011223344      ← Faulting instruction
;;
;; FAULTING_MODULE: fffff800`10000000 baddriver
;; PROCESS_NAME:    System
;;
;; STACK_TEXT:
;; fffff800`12340000 nt!KeBugCheckEx
;; fffff800`12340100 nt!KiBugCheckDispatch
;; fffff800`12340200 nt!KiPageFault
;; fffff800`12340300 baddriver!SomeFunction+0x42    ← ROOT CAUSE
;; fffff800`12340400 baddriver!DispatchRoutine+0x1a
;; fffff800`12340500 nt!IofCallDriver
;;
;; MODULE_NAME: baddriver
;; IMAGE_NAME: baddriver.sys

;; 5. Tìm driver info:
lmvm baddriver
;;   Loaded symbol image file: baddriver.sys
;;   Image path: \SystemRoot\System32\drivers\baddriver.sys
;;   Company: SomeSoftware Inc.
;;   Product: Some Security Product v2.1

;; 6. Xem disassembly tại fault:
u fffff800`11223344 L10

;; 7. Kiểm tra có phải driver 3rd party:
!lmi baddriver
;; → Nếu không phải Microsoft-signed → liên hệ vendor để update
```

### Experiment 10.5: Security Event Monitoring Script

```powershell
# === Comprehensive Security Event Monitor ===

function Start-SecurityMonitor {
    param(
        [int]$CheckIntervalSeconds = 30,
        [string]$OutputFile = "C:\SecurityAlerts.log"
    )
    
    $lastCheck = (Get-Date).AddMinutes(-5)
    
    while($true) {
        $now = Get-Date
        
        # Check suspicious events
        $events = @()
        
        # 1. New services (persistence)
        $events += Get-WinEvent -FilterHashtable @{
            LogName='System'; Id=7045; StartTime=$lastCheck; EndTime=$now
        } -ErrorAction SilentlyContinue | ForEach-Object {
            "[SERVICE] $($_.TimeCreated): $($_.Message.Substring(0,200))"
        }
        
        # 2. Log cleared (anti-forensics)
        $events += Get-WinEvent -FilterHashtable @{
            LogName='Security'; Id=1102; StartTime=$lastCheck; EndTime=$now
        } -ErrorAction SilentlyContinue | ForEach-Object {
            "[LOG_CLEAR] $($_.TimeCreated): Security log cleared!"
        }
        
        # 3. RDP logons (lateral movement)
        $events += Get-WinEvent -FilterHashtable @{
            LogName='Security'; Id=4624; StartTime=$lastCheck; EndTime=$now
        } -ErrorAction SilentlyContinue | Where-Object {
            $xml = [xml]$_.ToXml()
            ($xml.Event.EventData.Data | Where Name -eq 'LogonType').'#text' -eq '10'
        } | ForEach-Object {
            $xml = [xml]$_.ToXml()
            $user = ($xml.Event.EventData.Data | Where Name -eq 'TargetUserName').'#text'
            $ip = ($xml.Event.EventData.Data | Where Name -eq 'IpAddress').'#text'
            "[RDP_LOGON] $($_.TimeCreated): User=$user From=$ip"
        }
        
        # Output alerts
        foreach($evt in $events) {
            Write-Host $evt -ForegroundColor Red
            Add-Content -Path $OutputFile -Value $evt
        }
        
        $lastCheck = $now
        Start-Sleep -Seconds $CheckIntervalSeconds
    }
}

# Start-SecurityMonitor -CheckIntervalSeconds 60
```

---

## 10.10 Tóm Tắt

| Khái niệm | Điểm chính |
|-----------|------------|
| Registry Hive Format | Base block (regf header) + hive bins (hbin) chứa cells. Cell types: nk (key), vk (value), sk (security), lf/lh (subkey list), ri (index root), db (big data). Cell size âm = allocated, dương = free/deleted. |
| Registry Internals | Volatile vs stable keys, dual-log recovery (.LOG1/.LOG2), CmpKeyHash cho fast lookup, Key Control Blocks (KCB) cached trong memory. |
| Registry Virtualization | UAC redirect HKLM writes của non-elevated apps sang HKCU VirtualStore. Chỉ apply cho 32-bit legacy apps. |
| Transactional Registry | KTM-based ACID transactions, TxR log files (.regtrans-ms), atomic multi-value writes. |
| Registry Callbacks | CmRegisterCallbackEx cho kernel drivers. EDR/AV dùng để monitor/block registry ops. Pre-operation callbacks có thể deny operations. |
| Registry Forensics | Deleted key recovery (free cells), timeline analysis (nk timestamps), persistence location scanning, SAM database analysis. |
| ETW Architecture | Providers (EventWrite) → Sessions (buffers, routing) → Consumers. Lock-free per-CPU buffers. |
| ETW Provider Types | Classic (MOF/WPP), Manifest-based (XML), TraceLogging (self-describing). |
| ETW Session Types | NT Kernel Logger, AutoLogger (boot-time), Private, Global. Logging modes: Sequential, Circular, Real-time, Buffering. |
| Threat Intelligence ETW | GUID: {F4E1897C-...}. Require PPL consumer. Events cho: remote alloc/write/protect VM, APC inject, thread hijack, driver load. |
| ETW Evasion | Patch EtwEventWrite (ret), unhook provider registration, stop sessions. Detection: integrity check, kernel-mode monitoring. |
| WMI Architecture | WinMgmt service, CIM Repository (OBJECTS.DATA), COM-based providers, WQL queries. |
| WMI Persistence | EventFilter + EventConsumer + Binding. CommandLineEventConsumer, ActiveScriptEventConsumer. Fileless, survives reboot. |
| WMI Attacks | Lateral movement (DCOM/WinRM), recon (AV detection), persistence. Detect: Event 5861, Sysmon 19/20/21. |
| WER | Application crash: UnhandledExceptionFilter → WerFault.exe. Kernel crash: KeBugCheckEx → pagefile → MEMORY.DMP. LocalDumps registry key cho custom dump collection. |
| Crash Dump Analysis | !analyze -v, common bugcheck codes (0x0A, 0xD1, 0x50, 0x139, 0x109), pool corruption debugging (!pool, !poolval, special pool). |
| Task Scheduler | XML tasks trong %SystemRoot%\System32\Tasks\, registry metadata trong TaskCache. Persistence: schtasks, COM API, COM handler tasks. |
| Performance Counters | V1 (registry-based, legacy) vs V2 (manifest-based, kernel PCW). WPR/WPA cho detailed analysis. |
| Sysmon | Events 1-29: process create, network, registry, WMI, DNS, file create, injection detect. XML config cho filtering. |
| EVTX Format | File header + chunks (64KB) + records (BinXml). Forensics: deleted record recovery, Event 1102 (log clear detection). |
| PowerShell Logging | Module Logging (4103), Script Block Logging (4104 - QUAN TRỌNG NHẤT), Transcription. Bắt obfuscated code. |
| Security Event IDs | 4624 (logon), 4688 (process create), 7045 (service install), 1102 (log clear), 4698 (task create), 4769 (Kerberos ticket). |
| [UPDATE 2026] | Secure ETW Channel, Smart Dump type, WMI subscription hardening, EVTX 4GB limit, Sysmon Event 30/31, PowerShell AMSI v3. |

> **Tiếp theo: [Chapter 11 -- Caching và Hệ Thống Tập Tin](Chapter_11_Caching_File_Systems.md)**
