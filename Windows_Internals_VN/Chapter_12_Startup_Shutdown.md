# Chapter 12: Startup và Shutdown

> Chương cuối: UEFI boot process deep dive, Secure Boot, Boot Configuration Data,
> kernel initialization phases, Session Manager, service startup, user logon,
> shutdown sequence, fast startup/hibernate, boot security và security implications.

---

## 12.1 UEFI Boot Process

### 12.1.1 Tổng Quan Boot Flow

```
Power On
  |
  v
+================================================================+
| UEFI FIRMWARE                                                   |
|                                                                 |
|  SEC ──> PEI ──> DXE ──> BDS ──> TSL                          |
|  (Security) (Pre-EFI) (Driver  (Boot Dev  (Transient           |
|              Init)     Exec)   Selection)  System Load)         |
+================================================================+
  |
  v
+================================================================+
| WINDOWS BOOT MANAGER (bootmgfw.efi)                            |
|  ├── Đọc BCD store                                              |
|  ├── Hiển thị boot menu                                         |
|  ├── Kiểm tra Secure Boot                                       |
|  └── Chuyển quyền cho winload.efi                               |
+================================================================+
  |
  v
+================================================================+
| WINDOWS BOOT LOADER (winload.efi)                              |
|  ├── Load SYSTEM hive, ntoskrnl.exe, hal.dll                   |
|  ├── Load boot-start drivers (Start=0)                          |
|  ├── Khởi tạo hypervisor (nếu VBS enabled)                      |
|  └── Chuyển quyền cho kernel                                    |
+================================================================+
  |
  v
+================================================================+
| KERNEL INITIALIZATION                                           |
|  Phase 0 (BSP only) ──> Phase 1 (All CPUs) ──> smss.exe       |
+================================================================+
  |
  v
+================================================================+
| USER-MODE INITIALIZATION                                        |
|  smss.exe ──> csrss.exe + wininit.exe (Session 0)              |
|           ──> csrss.exe + winlogon.exe (Session 1)              |
|  services.exe ──> start services                                |
|  winlogon.exe ──> LogonUI ──> user shell                        |
+================================================================+
```

### 12.1.2 SEC Phase (Security Phase)

SEC là phase đầu tiên khi CPU bắt đầu thực thi sau power-on hoặc reset.

```
CPU Reset Vector (0xFFFFFFF0 - legacy, hoặc ResetVector trong flash)
  |
  v
SEC Code trong SPI Flash
  |
  ├── 1. CPU khởi động ở Real Mode (legacy) hoặc Long Mode
  │      - Tất cả APs (Application Processors) bị halt
  │      - Chỉ BSP (Bootstrap Processor) chạy
  │
  ├── 2. Chuyển sang Protected Mode (32-bit) hoặc Long Mode (64-bit)
  │
  ├── 3. Khởi tạo CAR (Cache-as-RAM):
  │      - Chưa có DRAM => không thể dùng RAM bình thường
  │      - Cấu hình CPU cache làm "temporary RAM"
  │      - MTRR (Memory Type Range Registers) được cấu hình
  │      - Cho phép thực thi C code với stack
  │
  │      Chi tiết CAR:
  │      ┌──────────────────────────────────────┐
  │      │ CPU L2/L3 Cache                       │
  │      │  ┌────────────────────────────────┐   │
  │      │  │ Temporary Stack (vd: 64KB)     │   │
  │      │  ├────────────────────────────────┤   │
  │      │  │ Temporary Heap                 │   │
  │      │  ├────────────────────────────────┤   │
  │      │  │ SEC Data Structures            │   │
  │      │  └────────────────────────────────┘   │
  │      └──────────────────────────────────────┘
  │
  ├── 4. Xác minh tính toàn vẹn firmware (optional):
  │      - Hash các FV (Firmware Volume) trong SPI flash
  │      - So sánh với giá trị trusted (fuse hoặc OTP)
  │      - Intel Boot Guard / AMD PSB xác minh trước SEC
  │
  ├── 5. Tìm và xác minh PEI Foundation (PEI Core):
  │      - Locate PEI FV (Firmware Volume)
  │      - Truyền EFI_SEC_PEI_HAND_OFF structure
  │
  └── 6. Chuyển quyền cho PEI Core
         - Truyền thông tin: CAR base/size, Boot FV, temp stack

Hardware Root of Trust (trước SEC):
  Intel Boot Guard:
    ├── ACM (Authenticated Code Module) chạy trước SEC
    ├── Xác minh SEC code bằng OTP key hash trong CPU fuses
    ├── Measured Boot: đo vào TPM PCR 0
    └── Verified Boot: halt nếu verification thất bại

  AMD Platform Secure Boot (PSB):
    ├── AMD PSP (Platform Security Processor) chạy trước x86
    ├── Xác minh UEFI firmware bằng fused key
    └── Tương tự Intel Boot Guard
```

### 12.1.3 PEI Phase (Pre-EFI Initialization)

```
PEI Core (PEI Foundation)
  |
  ├── 1. Khởi tạo PEI Services Table:
  │      ├── InstallPpi()       - cài đặt PPI (PEI-to-PEI Interface)
  │      ├── LocatePpi()        - tìm PPI
  │      ├── NotifyPpi()        - đăng ký callback
  │      ├── GetBootMode()      - lấy boot mode
  │      ├── SetBootMode()      - đặt boot mode (Normal, Recovery, S3 Resume)
  │      ├── CreateHob()        - tạo HOB (Hand-Off Block)
  │      ├── FfsFindNextVolume() - tìm Firmware Volume
  │      ├── FfsFindNextFile()   - tìm file trong FV
  │      └── InstallPeiMemory() - báo PEI Core biết DRAM đã sẵn sàng
  │
  ├── 2. Dispatch PEIMs (PEI Modules):
  │      Mỗi PEIM là một module thực thi một nhiệm vụ cụ thể.
  │      PEI Dispatcher load và chạy PEIMs theo thứ tự dependency.
  │
  │      Các PEIM quan trọng:
  │      ┌─────────────────────────────────────────────────┐
  │      │ CPU PEIM:                                       │
  │      │   - Khởi tạo microcode update                   │
  │      │   - Cấu hình CPU features (NX, VT-x, etc.)     │
  │      │   - Cấu hình MTRR                              │
  │      ├─────────────────────────────────────────────────┤
  │      │ Chipset/PCH PEIM:                               │
  │      │   - Cấu hình GPIO, PCH registers                │
  │      │   - Khởi tạo SPI controller                     │
  │      │   - Cấu hình PCIe root complex (cơ bản)         │
  │      ├─────────────────────────────────────────────────┤
  │      │ Memory Init PEIM (quan trọng nhất):             │
  │      │   - Đọc SPD (Serial Presence Detect) từ DIMM    │
  │      │   - Cấu hình Memory Controller                  │
  │      │   - Train DRAM timing (tRAS, tCAS, etc.)        │
  │      │   - Test memory cơ bản                          │
  │      │   - Gọi InstallPeiMemory() khi xong             │
  │      ├─────────────────────────────────────────────────┤
  │      │ S3 Resume PEIM (nếu boot mode = S3):            │
  │      │   - Restore memory controller config            │
  │      │   - Chuyển thẳng đến OS resume vector           │
  │      │   - Không đi qua DXE/BDS                        │
  │      └─────────────────────────────────────────────────┘
  │
  ├── 3. Memory Available:
  │      - Sau khi DRAM được khởi tạo, PEI Core:
  │      - Chuyển stack từ CAR sang DRAM
  │      - Tiếp tục dispatch PEIMs còn lại
  │      - PEIMs sau memory init có thể dùng DRAM bình thường
  │
  ├── 4. Tạo HOBs (Hand-Off Blocks):
  │      HOBs chứa thông tin truyền từ PEI sang DXE:
  │      ├── PHIT HOB: Phase Information Table (bắt buộc)
  │      ├── Resource Descriptor HOB: mô tả memory regions
  │      │   - System Memory, Memory Mapped I/O, Firmware Device
  │      ├── Memory Allocation HOB: memory đã được cấp phát
  │      ├── Firmware Volume HOB: các FV cần dispatch trong DXE
  │      ├── CPU HOB: số CPU, memory space/IO space sizes
  │      ├── Stack HOB: stack cho DXE Core
  │      └── End of HOB List marker
  │
  └── 5. Tìm DXE IPL (Initial Program Loader) PEIM:
         - Locate DXE Core trong Firmware Volume
         - Tạo HOB list hoàn chỉnh
         - Chuyển quyền cho DXE Core, truyền HOB list

HOB Memory Layout:
  ┌─────────────────────┐ High Address
  │ End of HOB List     │
  ├─────────────────────┤
  │ FV HOB (DXE FV)     │
  ├─────────────────────┤
  │ Memory Alloc HOB    │
  ├─────────────────────┤
  │ Resource Desc HOB   │
  ├─────────────────────┤
  │ CPU HOB             │
  ├─────────────────────┤
  │ PHIT HOB (header)   │
  └─────────────────────┘ Low Address (HOB List start)
```

### 12.1.4 DXE Phase (Driver Execution Environment)

DXE là phase chính của UEFI, nơi hầu hết các driver và services được khởi tạo.

```
DXE Core
  |
  ├── 1. Khởi tạo DXE Foundation:
  │      ├── Xử lý HOB list từ PEI
  │      ├── Tạo UEFI System Table
  │      ├── Tạo Boot Services Table
  │      ├── Tạo Runtime Services Table
  │      └── Khởi tạo DXE Dispatcher
  │
  ├── 2. UEFI System Table:
  │      ┌──────────────────────────────────────────┐
  │      │ EFI_SYSTEM_TABLE                          │
  │      │  ├── Hdr (table header, revision, CRC32) │
  │      │  ├── FirmwareVendor (L"AMI", L"Phoenix") │
  │      │  ├── FirmwareRevision                     │
  │      │  ├── ConIn, ConOut, StdErr (console I/O)  │
  │      │  ├── RuntimeServices *                    │
  │      │  ├── BootServices *                       │
  │      │  ├── NumberOfTableEntries                  │
  │      │  └── ConfigurationTable * (ACPI, SMBIOS)  │
  │      └──────────────────────────────────────────┘
  │
  ├── 3. Boot Services (chỉ khả dụng trước ExitBootServices):
  │      ├── Memory Services:
  │      │   - AllocatePages / FreePages
  │      │   - AllocatePool / FreePool
  │      │   - GetMemoryMap (OS cần gọi trước ExitBootServices)
  │      ├── Protocol Handler Services:
  │      │   - InstallProtocolInterface
  │      │   - HandleProtocol / OpenProtocol
  │      │   - LocateProtocol / LocateHandle
  │      ├── Image Services:
  │      │   - LoadImage / StartImage / UnloadImage
  │      │   - Exit / ExitBootServices
  │      ├── Event/Timer Services:
  │      │   - CreateEvent / SetTimer / WaitForEvent
  │      │   - SignalEvent / CloseEvent
  │      └── Driver Support Services:
  │          - ConnectController / DisconnectController
  │
  ├── 4. Runtime Services (vẫn khả dụng sau ExitBootServices):
  │      ├── Variable Services:
  │      │   - GetVariable / SetVariable / GetNextVariableName
  │      │   - (Secure Boot keys, Boot#### options lưu ở đây)
  │      ├── Time Services:
  │      │   - GetTime / SetTime
  │      ├── Virtual Memory Services:
  │      │   - SetVirtualAddressMap / ConvertPointer
  │      │   - (OS gọi để chuyển runtime services sang virtual address)
  │      ├── Reset Services:
  │      │   - ResetSystem (shutdown, restart, cold/warm reset)
  │      └── Capsule Services:
  │          - UpdateCapsule (firmware update mechanism)
  │
  ├── 5. DXE Dispatcher load và dispatch DXE Drivers:
  │
  │      DXE Driver types:
  │      ┌─────────────────────────────────────────────────────┐
  │      │ Boot Service Driver:                                │
  │      │   - Chỉ cần thiết trong boot, unload khi OS chạy    │
  │      │   - Ví dụ: USB driver, SATA driver cho boot         │
  │      ├─────────────────────────────────────────────────────┤
  │      │ Runtime Driver:                                     │
  │      │   - Vẫn chạy sau ExitBootServices                   │
  │      │   - Ví dụ: Variable driver (NVRAM access)           │
  │      │   - OS phải gọi SetVirtualAddressMap                │
  │      ├─────────────────────────────────────────────────────┤
  │      │ DXE Driver (general):                               │
  │      │   - Khởi tạo hardware, cài đặt protocols            │
  │      │   - Ví dụ: PCI bus driver, AHCI driver              │
  │      └─────────────────────────────────────────────────────┘
  │
  └── 6. Các UEFI Protocol quan trọng:

UEFI Protocol Interfaces:
┌──────────────────────────────────────────────────────────────┐
│ EFI_BLOCK_IO_PROTOCOL:                                       │
│   - ReadBlocks / WriteBlocks / FlushBlocks                   │
│   - Media info (block size, last block number)               │
│   - Cung cấp truy cập raw block cho disk devices             │
├──────────────────────────────────────────────────────────────┤
│ EFI_SIMPLE_FILE_SYSTEM_PROTOCOL:                             │
│   - OpenVolume() → EFI_FILE_PROTOCOL                        │
│   - EFI_FILE_PROTOCOL: Open, Close, Read, Write, GetInfo    │
│   - Cho phép đọc/ghi file trên FAT partition (ESP)           │
├──────────────────────────────────────────────────────────────┤
│ EFI_GRAPHICS_OUTPUT_PROTOCOL (GOP):                          │
│   - QueryMode / SetMode / Blt (Block Transfer)              │
│   - Thay thế legacy VGA BIOS                                │
│   - Framebuffer info: base address, resolution, pixel format │
├──────────────────────────────────────────────────────────────┤
│ EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL:                             │
│   - OutputString / SetAttribute / ClearScreen                │
│   - Console text output                                      │
├──────────────────────────────────────────────────────────────┤
│ EFI_SIMPLE_NETWORK_PROTOCOL:                                 │
│   - Start / Initialize / Transmit / Receive                  │
│   - PXE boot support                                         │
├──────────────────────────────────────────────────────────────┤
│ EFI_LOAD_FILE_PROTOCOL:                                      │
│   - LoadFile() - load file từ device (PXE, HTTP boot)        │
├──────────────────────────────────────────────────────────────┤
│ EFI_LOADED_IMAGE_PROTOCOL:                                   │
│   - Thông tin về image đã load: device handle, file path     │
│   - Mọi EFI application/driver đều có protocol này           │
└──────────────────────────────────────────────────────────────┘

UEFI Driver Model:
  ┌──────────────────────────────────────────────────┐
  │ UEFI Driver Binding Protocol                      │
  │                                                   │
  │ Supported() - kiểm tra driver có hỗ trợ device?   │
  │ Start()     - kết nối driver với device handle    │
  │ Stop()      - ngắt kết nối driver khỏi device     │
  │                                                   │
  │ Model UEFI driver:                                │
  │  1. Driver load → không làm gì với hardware       │
  │  2. ConnectController() gọi Supported()           │
  │  3. Nếu Supported() thành công → gọi Start()      │
  │  4. Start() cài đặt I/O protocols lên handle      │
  └──────────────────────────────────────────────────┘
```

### 12.1.5 BDS Phase (Boot Device Selection)

```
BDS (Boot Device Selection):
  |
  ├── 1. Đọc UEFI Variables liên quan boot:
  │      ├── BootOrder:    thứ tự các boot option (array of UINT16)
  │      │   Ví dụ: 0003,0001,0002,0000
  │      ├── Boot####:     mỗi entry là một boot option
  │      │   Boot0000: "Windows Boot Manager"
  │      │     - Attributes: ACTIVE, category=app
  │      │     - FilePathList: HD(...)/File(\EFI\Microsoft\Boot\bootmgfw.efi)
  │      │   Boot0001: "ubuntu"
  │      │     - FilePathList: HD(...)/File(\EFI\ubuntu\shimx64.efi)
  │      ├── Timeout:      số giây hiện boot menu (nếu > 1 option)
  │      ├── BootCurrent:  option đang boot hiện tại
  │      └── BootNext:     option cho lần boot tiếp (1 lần, xóa sau khi dùng)
  │
  ├── 2. Thử các boot option theo BootOrder:
  │      ├── Mỗi option: locate device, load EFI application
  │      ├── Nếu thất bại → thử option tiếp theo
  │      └── Nếu tất cả thất bại → vào UEFI Shell hoặc Recovery
  │
  ├── 3. Hiển thị Boot Menu (nếu Timeout > 0 và nhiều option):
  │      - Cho phép user chọn OS/device
  │      - Nhấn phím (F2/ESC/...) để vào setup
  │
  └── 4. Load và start boot loader EFI application:
         - BootServices->LoadImage()
         - BootServices->StartImage()
         - Với Windows: load bootmgfw.efi

Quản lý boot options với efibootmgr (Linux) hoặc bcdedit (Windows):
  # Linux: xem boot order
  efibootmgr -v

  # Windows: xem UEFI boot entries
  bcdedit /enum firmware

  # Thêm boot option mới
  efibootmgr -c -d /dev/sda -p 1 -L "Custom" -l '\EFI\custom\bootx64.efi'
```

### 12.1.6 TSL Phase và UEFI Shell

```
TSL (Transient System Load):
  - Giai đoạn giữa BDS và OS
  - Boot loader (vd: bootmgfw.efi) chạy trong giai đoạn này
  - Kết thúc khi ExitBootServices() được gọi

UEFI Shell:
  - Môi trường command-line trong UEFI (trước khi OS boot)
  - Cung cấp commands tương tự DOS/Linux shell
  
  Các lệnh UEFI Shell hữu ích cho security research:
  ┌──────────────────────────────────────────────────────────────┐
  │ Shell> map -b                 # Liệt kê các devices/partitions│
  │ Shell> ls fs0:\               # List files trên ESP           │
  │ Shell> fs0:                   # Chuyển sang ESP              │
  │ Shell> edit startup.nsh       # Edit startup script           │
  │ Shell> dmpstore               # Dump UEFI variables           │
  │ Shell> dmpstore -all          # Dump tất cả variables         │
  │ Shell> setvar <name> ...      # Set UEFI variable             │
  │ Shell> mm 0xFED40000          # Dump memory (MMIO registers)  │
  │ Shell> pci                    # Liệt kê PCI devices            │
  │ Shell> drivers                # Liệt kê UEFI drivers           │
  │ Shell> dh -d -v               # Dump all handles + protocols   │
  │ Shell> smbiosview             # Xem SMBIOS tables              │
  │ Shell> acpiview               # Xem ACPI tables                │
  └──────────────────────────────────────────────────────────────┘

  Security Research: dùng UEFI Shell để:
    - Kiểm tra Secure Boot state: dmpstore SecureBoot
    - Dump Secure Boot keys: dmpstore PK / dmpstore KEK / dmpstore db
    - Kiểm tra SPI flash protection: mm <SPI BAR registers>
    - Chạy các UEFI security tools (CHIPSEC modules)
```

---

## 12.2 Secure Boot

### 12.2.1 Key Hierarchy

```
Secure Boot Key Hierarchy:

  ┌──────────────────────────────────────────────────────┐
  │ Platform Key (PK)                                     │
  │   - "Root of Trust" cho Secure Boot                   │
  │   - Thường là OEM key (Dell, HP, Lenovo, etc.)        │
  │   - Chỉ có 1 PK được phép tại 1 thời điểm            │
  │   - PK có quyền: thay đổi PK, thay đổi KEK           │
  │   - Xóa PK = chuyển sang Setup Mode (tắt Secure Boot) │
  └───────────────────────┬──────────────────────────────┘
                          │ signs/authorizes
                          v
  ┌──────────────────────────────────────────────────────┐
  │ Key Exchange Key (KEK)                                │
  │   - Thường chứa Microsoft KEK + OEM KEK              │
  │   - KEK có quyền: thay đổi db và dbx                  │
  │   - Có thể có nhiều KEK certificates                  │
  │   - Microsoft KEK: cho phép MS cập nhật db/dbx       │
  └───────────────────────┬──────────────────────────────┘
                          │ authorizes changes to
                          v
  ┌──────────────────────────────────────────────────────┐
  │ db (Authorized Signatures Database)                   │
  │   - Danh sách certificates/hashes được phép boot     │
  │   - Thường chứa:                                      │
  │     - Microsoft Windows Production PCA 2011           │
  │     - Microsoft Corporation UEFI CA 2011              │
  │     - OEM certificates (optional)                     │
  │   - EFI binary được phép boot nếu:                    │
  │     - Signed bởi cert có trong db, HOẶC               │
  │     - Hash của binary có trong db                     │
  └──────────────────────────────────────────────────────┘
  ┌──────────────────────────────────────────────────────┐
  │ dbx (Forbidden Signatures Database)                   │
  │   - Danh sách certificates/hashes BỊ CẤM              │
  │   - Ưu tiên hơn db (dbx check trước db)               │
  │   - Chứa revoked bootloaders, known-bad hashes        │
  │   - Microsoft phát hành dbx updates qua Windows Update│
  │   - Ví dụ: revoked shim versions, BlackLotus hashes   │
  └──────────────────────────────────────────────────────┘

Certificate/Hash Formats trong db/dbx:
  ┌─────────────────────────────────────────────────┐
  │ EFI_CERT_X509_GUID:                              │
  │   - DER-encoded X.509 certificate                │
  │   - Dùng để verify Authenticode signatures       │
  │                                                   │
  │ EFI_CERT_SHA256_GUID:                             │
  │   - SHA-256 hash của EFI binary                   │
  │   - Cho phép/cấm 1 binary cụ thể                  │
  │                                                   │
  │ EFI_CERT_X509_SHA256_GUID:                        │
  │   - SHA-256 hash của TBS (To-Be-Signed) cert     │
  │   - Dùng trong dbx để revoke certificates         │
  └─────────────────────────────────────────────────┘
```

### 12.2.2 Quy Trình Xác Minh Secure Boot

```
Khi UEFI firmware load một EFI binary (bootloader, driver, app):

  1. Kiểm tra binary có Authenticode signature không?
     ├── KHÔNG có signature:
     │   ├── Tính SHA-256 hash của binary
     │   ├── Hash có trong db? → ALLOW
     │   └── Hash KHÔNG có trong db? → DENY (Security Violation)
     │
     └── CÓ signature:
         │
         ├── 2. Extract signer certificate từ PE Authenticode
         │
         ├── 3. Kiểm tra dbx (forbidden) TRƯỚC:
         │   ├── Signer cert có trong dbx? → DENY
         │   ├── Hash của binary có trong dbx? → DENY
         │   └── Cert chain có cert nào trong dbx? → DENY
         │
         ├── 4. Kiểm tra db (authorized):
         │   ├── Signer cert có trong db? → bước 5
         │   ├── Cert chain có cert nào trong db? → bước 5
         │   └── Không tìm thấy trong db? → DENY
         │
         └── 5. Verify Authenticode signature:
             ├── Verify certificate chain
             ├── Verify PE image hash khớp với signed hash
             ├── Kiểm tra timestamp (nếu có)
             ├── Thành công → ALLOW, load và execute binary
             └── Thất bại → DENY (Security Violation)

Secure Boot Modes:
  ┌─────────────────────────────────────────────────────────┐
  │ Setup Mode:                                              │
  │   - Không có PK được enroll                              │
  │   - Secure Boot DISABLED (SecureBoot variable = 0)       │
  │   - Có thể tự do enroll PK, KEK, db, dbx                │
  │   - Chuyển sang User Mode khi PK được enroll             │
  ├─────────────────────────────────────────────────────────┤
  │ User Mode:                                               │
  │   - PK đã được enroll                                    │
  │   - Secure Boot ENABLED (SecureBoot variable = 1)        │
  │   - Thay đổi db/dbx cần signed bởi KEK                   │
  │   - Thay đổi KEK cần signed bởi PK                       │
  │   - Xóa PK → quay lại Setup Mode                         │
  ├─────────────────────────────────────────────────────────┤
  │ Deployed Mode (optional, UEFI 2.5+):                     │
  │   - Khóa cứng: không cho phép quay lại Setup Mode        │
  │   - Không cho phép custom mode                            │
  │   - Bảo mật nhất, khó recovery nhất                      │
  ├─────────────────────────────────────────────────────────┤
  │ Audit Mode (optional):                                   │
  │   - Ghi log tất cả verification attempts                 │
  │   - Không enforce (allow all) nhưng ghi lại              │
  │   - Hữu ích cho testing và debugging                     │
  └─────────────────────────────────────────────────────────┘
```

### 12.2.3 Secure Boot Bypass History

**[UPDATE 2026]** Danh sách các Secure Boot bypass đáng chú ý:

```
1. BootHole (CVE-2020-10713) - Tháng 7/2020:
   ├── Buffer overflow trong GRUB2 khi parse grub.cfg
   ├── grub.cfg không được verify bởi Secure Boot
   ├── Attacker sửa grub.cfg → arbitrary code execution
   ├── Ảnh hưởng tất cả Linux distros dùng GRUB2
   └── Fix: cập nhật dbx để revoke vulnerable GRUB2 binaries

2. BlackLotus (CVE-2022-21894) - Tháng 3/2023:
   ├── UEFI bootkit đầu tiên bypass Secure Boot trong wild
   ├── Khai thác CVE-2022-21894 (Secure Boot bypass logic bug)
   ├── Sử dụng legitimately-signed nhưng vulnerable bootloader
   ├── Bootloader bị revoke trong dbx nhưng:
   │   ├── Tùy chọn dbx update là OPTIONAL
   │   └── Nhiều máy không apply dbx update
   ├── Sau khi bypass: load malicious UEFI driver
   ├── Disable Windows Defender, BitLocker, HVCI
   ├── Persistence: survive OS reinstall và disk format
   └── Fix: KB5025885 (dbx update), nhưng rollout chậm

   BlackLotus Attack Chain:
   ┌────────────────────────────────────────────────────┐
   │ 1. Ghi malicious files vào ESP                     │
   │ 2. Modify BCD để point đến vulnerable bootloader   │
   │ 3. Boot với vulnerable (nhưng signed) bootloader   │
   │ 4. Exploit CVE-2022-21894 trong bootloader         │
   │ 5. Load custom UEFI application (không signed)     │
   │ 6. Patch Windows Boot Manager trong memory          │
   │ 7. Boot Windows bình thường nhưng đã compromised    │
   │ 8. UEFI runtime driver duy trì persistence          │
   └────────────────────────────────────────────────────┘

3. Shim Vulnerabilities:
   ├── CVE-2023-40547: HTTP boot buffer overflow trong shim
   ├── Shim là pre-bootloader cho Linux Secure Boot
   ├── Signed bởi Microsoft UEFI CA → trusted
   ├── Vulnerable shim versions cần được add vào dbx
   └── Vấn đề: revoke shim = break Linux boot

4. CVE-2024-7344 (Reloader vulnerability) - Tháng 1/2025:
   ├── Bypass Secure Boot thông qua third-party UEFI app
   ├── Signed bởi Microsoft UEFI CA
   ├── Load unsigned EFI binaries từ ESP
   └── Fix: revoke signature trong dbx update

5. [UPDATE 2026] Secure Boot dbx Rotation Issues:
   ├── UEFI dbx có giới hạn kích thước (~32KB typical)
   ├── Số lượng revoked binaries tăng liên tục
   ├── Một số firmware không hỗ trợ dbx lớn → không apply update
   ├── Microsoft đang chuyển sang Secure Boot Advanced Targeting
   └── UEFI 2.10: EFI_CERT_X509_SHA256_GUID cho efficient revocation
```

### 12.2.4 Secure Boot Custom Keys và mokutil

```
Cài đặt Custom Secure Boot Keys:

1. Tạo keys:
   # Tạo PK (Platform Key)
   openssl req -new -x509 -newkey rsa:2048 -subj "/CN=My PK/" \
     -keyout PK.key -out PK.crt -days 3650 -sha256 -nodes
   cert-to-efi-sig-list -g "$(uuidgen)" PK.crt PK.esl
   sign-efi-sig-list -g "$(uuidgen)" -k PK.key -c PK.crt PK PK.esl PK.auth

   # Tạo KEK (Key Exchange Key)
   openssl req -new -x509 -newkey rsa:2048 -subj "/CN=My KEK/" \
     -keyout KEK.key -out KEK.crt -days 3650 -sha256 -nodes
   cert-to-efi-sig-list -g "$(uuidgen)" KEK.crt KEK.esl
   sign-efi-sig-list -g "$(uuidgen)" -k PK.key -c PK.crt KEK KEK.esl KEK.auth

   # Tạo db key
   openssl req -new -x509 -newkey rsa:2048 -subj "/CN=My db/" \
     -keyout db.key -out db.crt -days 3650 -sha256 -nodes
   cert-to-efi-sig-list -g "$(uuidgen)" db.crt db.esl
   sign-efi-sig-list -g "$(uuidgen)" -k KEK.key -c KEK.crt db db.esl db.auth

2. Enroll keys (trong UEFI Setup hoặc từ OS):
   # Clear PK trước (chuyển sang Setup Mode)
   efi-updatevar -e -f noPK.auth PK
   # Enroll db, KEK, PK (theo thứ tự)
   efi-updatevar -e -f db.auth db
   efi-updatevar -e -f KEK.auth KEK
   efi-updatevar -e -f PK.auth PK    # Enrolling PK → User Mode

mokutil (Machine Owner Key) cho Linux dual-boot:
  ┌──────────────────────────────────────────────────────────┐
  │ # Kiểm tra Secure Boot state                              │
  │ mokutil --sb-state                                        │
  │                                                           │
  │ # Import MOK (Machine Owner Key) cho shim                 │
  │ mokutil --import my_key.der                                │
  │ # → Reboot → MokManager hiển thị → nhập password → enroll│
  │                                                           │
  │ # List enrolled MOKs                                      │
  │ mokutil --list-enrolled                                    │
  │                                                           │
  │ # Export các MOKs hiện tại                                 │
  │ mokutil --export                                           │
  │                                                           │
  │ # Delete một MOK                                           │
  │ mokutil --delete my_key.der                                │
  │                                                           │
  │ # Tắt Secure Boot validation (không khuyến khích)          │
  │ mokutil --disable-validation                               │
  └──────────────────────────────────────────────────────────┘
```

---

## 12.3 Windows Boot Manager (bootmgfw.efi)

### 12.3.1 BCD Store Structure

```
BCD Store là một registry hive:
  - UEFI: \EFI\Microsoft\Boot\BCD
  - Legacy BIOS: \Boot\BCD (trên active partition)
  - Mounted tại: HKLM\BCD00000000 (khi Windows chạy)

BCD Hive Structure:
  BCD00000000\
    Objects\
      {9dea862c-5cdd-4e70-acc1-f32b344d4795}\   ← {bootmgr}
        Description\
          Type = 0x10100002   (Boot Manager)
        Elements\
          0x11000001\         ← BcdLibraryDevice_ApplicationDevice
            Element = ...
          0x12000002\         ← BcdLibraryString_ApplicationPath
            Element = "\EFI\MICROSOFT\BOOT\BOOTMGFW.EFI"
          0x23000003\         ← BcdBootMgrObject_DefaultObject
            Element = {current GUID}
          0x25000004\         ← BcdBootMgrInteger_Timeout
            Element = 30
          0x24000001\         ← BcdBootMgrObjectList_DisplayOrder
            Element = [{guid1}, {guid2}, ...]

      {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}\    ← OS Loader entry
        Description\
          Type = 0x10200003   (OS Loader)
        Elements\
          0x11000001\         ← Device
          0x12000002\         ← Path = "\Windows\system32\winload.efi"
          0x12000004\         ← Description = "Windows 11"
          0x22000002\         ← SystemRoot = "\Windows"
          ...
```

### 12.3.2 BCD Object Types

```
BCD Object Type Encoding (32-bit):
  Bits 31-28: Image type
    1 = Application
    2 = Inherit (settings group)
    3 = Device
  Bits 27-24: Application image type (khi Image type = 1)
    0 = Firmware
    1 = Boot sector (legacy)
    2 = OS Loader
    3 = Resume
    4 = Startup
  Bits 23-0: Application sub-type

Common Object Types:
  ┌──────────────────────────────────────────────────────────┐
  │ Type          │ Value       │ Mô tả                       │
  ├──────────────────────────────────────────────────────────┤
  │ Boot Manager  │ 0x10100002 │ bootmgfw.efi settings       │
  │ OS Loader     │ 0x10200003 │ winload.efi settings        │
  │ Resume Loader │ 0x10400005 │ winresume.efi settings      │
  │ Memory Diag   │ 0x10200005 │ memtest.efi                 │
  │ Ntldr         │ 0x10300006 │ Legacy OS boot (ntldr)      │
  │ Inherit       │ 0x20100000 │ Shared settings group       │
  │ Device        │ 0x30000000 │ RAM Disk device             │
  └──────────────────────────────────────────────────────────┘

Well-Known GUIDs:
  {9dea862c-5cdd-4e70-acc1-f32b344d4795} = {bootmgr}
  {a5a30fa2-3d06-4e9f-b5f4-a01df9d1fcba} = {fwbootmgr}
  {b2721d73-1db4-4c62-bf78-c548a880142d} = {memdiag}
  {466f5a88-0af2-4f76-9038-095b170dc21c} = {ntldr}
  {fa926493-6f1c-4193-a414-58f0b2456d1e} = {current}
  {6efb52bf-1766-41db-a6b3-0ee5eff72bd7} = {badmemory}
```

### 12.3.3 BCD Elements Quan Trọng

```
Các BCD Elements thường gặp (dùng với bcdedit):

Boot Manager elements:
  ├── device          - partition chứa bootmgfw.efi
  ├── path            - đường dẫn đến bootmgfw.efi
  ├── description     - tên hiển thị
  ├── default         - default OS loader entry
  ├── timeout         - thời gian hiện boot menu (giây)
  ├── displayorder    - thứ tự hiển thị các OS entries
  ├── toolsdisplayorder - thứ tự tools (memdiag, etc.)
  └── custom:*        - custom actions

OS Loader elements:
  ├── device          - partition chứa Windows
  ├── path            - đường dẫn winload.efi
  ├── description     - tên hiển thị (vd: "Windows 11")
  ├── locale          - ngôn ngữ (en-US, vi-VN, ...)
  ├── osdevice        - partition chứa \Windows
  ├── systemroot      - thư mục Windows (thường là \Windows)
  ├── resumeobject    - GUID của resume loader entry
  ├── nx              - DEP policy: OptIn, OptOut, AlwaysOn, AlwaysOff
  │
  ├── Debugging/Testing:
  │   ├── debug           - bật/tắt kernel debugging
  │   ├── debugtype       - Serial, 1394, USB, NET, Local
  │   ├── testsigning     - cho phép test-signed drivers
  │   ├── nointegritychecks - tắt driver signature checks
  │   ├── bootlog         - ghi boot log (ntbtlog.txt)
  │   ├── sos             - hiển thị tên driver khi load
  │   ├── bootdebug       - debug boot manager/loader
  │   └── dbgtransport    - custom debug transport DLL
  │
  ├── Security/Virtualization:
  │   ├── hypervisorlaunchtype  - Off, Auto
  │   ├── vsmlaunchtype         - Off, Auto (VBS)
  │   ├── hypervisordebug       - bật/tắt hypervisor debug
  │   ├── isolatedcontext       - VBS isolated user mode
  │   ├── disableelamdrivers    - tắt ELAM
  │   └── flightsigning         - cho phép flight-signed builds
  │
  ├── Recovery:
  │   ├── safeboot        - minimal, network, dsrepair
  │   ├── safebootalternateshell - cmd thay vì explorer
  │   ├── recoveryenabled - bật/tắt auto recovery
  │   └── recoverysequence - GUID của WinRE entry
  │
  └── Performance:
      ├── numproc         - giới hạn số CPU (testing)
      ├── truncatememory  - giới hạn RAM (testing)
      ├── pae             - PAE mode (32-bit)
      ├── increaseuserva  - tăng user-mode virtual address space
      └── bootmenupolicy  - Standard (legacy menu), Legacy
```

### 12.3.4 bcdedit Commands Reference

```cmd
:: === Xem thông tin ===
bcdedit /enum                     :: Liệt kê entries chính
bcdedit /enum all                 :: Liệt kê TẤT CẢ entries (bao gồm inherited)
bcdedit /enum {bootmgr}           :: Chỉ xem Boot Manager
bcdedit /enum {current}           :: Chỉ xem entry hiện tại
bcdedit /enum OSLOADER            :: Chỉ xem OS Loader entries
bcdedit /v                        :: Hiển thị GUID đầy đủ (không dùng alias)
bcdedit /enum firmware            :: Xem UEFI firmware entries

:: === Tạo và xóa entries ===
bcdedit /create /d "Test OS" /application osloader
:: → Trả về GUID mới, vd: {xxxxxxxx-xxxx-...}
bcdedit /delete {GUID}            :: Xóa entry
bcdedit /copy {current} /d "Clone Entry"  :: Copy entry

:: === Cấu hình debug ===
bcdedit /set {current} debug on
bcdedit /dbgsettings net hostip:192.168.1.100 port:50000
bcdedit /dbgsettings serial debugport:1 baudrate:115200
bcdedit /dbgsettings usb targetname:MYPC
bcdedit /dbgsettings local         :: WinDbg local debugging

:: === Testing và development ===
bcdedit /set {current} testsigning on     :: Cho phép test-signed drivers
bcdedit /set {current} nointegritychecks on :: Tắt driver integrity check
bcdedit /set {current} debug on           :: Kernel debugging

:: === Safe Mode ===
bcdedit /set {current} safeboot minimal
bcdedit /set {current} safeboot network
bcdedit /set {current} safeboot dsrepair  :: Directory Services Repair
bcdedit /deletevalue {current} safeboot   :: Tắt Safe Mode

:: === Virtualization ===
bcdedit /set {current} hypervisorlaunchtype auto   :: Bật Hyper-V
bcdedit /set {current} hypervisorlaunchtype off    :: Tắt Hyper-V
bcdedit /set {current} vsmlaunchtype auto          :: Bật VBS
bcdedit /set {current} hypervisordebug on          :: Debug hypervisor

:: === Boot menu ===
bcdedit /set {bootmgr} timeout 10         :: Timeout 10 giây
bcdedit /set {bootmgr} displaybootmenu yes
bcdedit /displayorder {GUID1} {GUID2}     :: Đặt thứ tự
bcdedit /default {GUID}                   :: Đặt default entry

:: === Recovery ===
bcdedit /set {current} recoveryenabled yes
reagentc /enable                           :: Bật WinRE
reagentc /info                             :: Xem trạng thái WinRE
reagentc /boottore                         :: Boot vào WinRE lần tới

:: === Export/Import BCD ===
bcdedit /export C:\BCD_backup              :: Backup BCD
bcdedit /import C:\BCD_backup              :: Restore BCD
```

### 12.3.5 Windows Boot Loader (winload.efi)

```
winload.efi tasks (theo thứ tự thực thi):

1. Đọc SYSTEM registry hive:
   ├── \Windows\System32\config\SYSTEM
   ├── Parse CurrentControlSet (Select key → CCS number)
   └── Lấy thông tin cấu hình boot-start drivers

2. Load kernel và HAL:
   ├── ntoskrnl.exe (hoặc ntkrnlpa.exe trên 32-bit PAE)
   ├── hal.dll (Hardware Abstraction Layer)
   ├── ci.dll (Code Integrity)
   ├── kdcom.dll (kernel debugger comms, nếu debug enabled)
   └── clfs.sys (Common Log File System - recovery)

3. Load boot-start drivers (Start=0):
   ├── Đọc SYSTEM hive: CCS\Services\*
   ├── Tìm drivers có Start=0
   ├── Sắp xếp theo:
   │   a. Group order (ServiceGroupOrder\List)
   │   b. Tag order (GroupOrderList\<GroupName>)
   │   c. Dependency
   ├── Load ELAM driver đầu tiên (nếu có):
   │   - WdBoot.sys (Windows Defender ELAM)
   │   - Signed với ELAM certificate
   │   - Evaluate các boot-start drivers khác
   └── Load các boot-start drivers còn lại

4. Cấu hình memory và paging:
   ├── Tạo page tables cho kernel address space
   ├── Map kernel, HAL, drivers vào virtual memory
   ├── Cấu hình NX (No-Execute) policy
   └── Reserve memory cho PFN database

5. Khởi tạo Hypervisor (nếu VBS enabled):
   ├── Load hvloader.efi (Hypervisor Loader)
   ├── Load hvix64.exe (Intel) hoặc hvax64.exe (AMD)
   ├── Hypervisor chạy trước kernel (Ring -1)
   ├── Thiết lập VTL 0 (Normal World) và VTL 1 (Secure World)
   └── Kernel sẽ chạy trong VTL 0

6. Gọi ExitBootServices():
   ├── Gọi GetMemoryMap() để lấy bản đồ memory cuối cùng
   ├── Gọi ExitBootServices() → UEFI Boot Services không còn khả dụng
   ├── Chỉ UEFI Runtime Services còn hoạt động
   └── Firmware không còn kiểm soát hardware

7. Chuyển quyền cho ntoskrnl.exe:
   ├── Truyền LOADER_PARAMETER_BLOCK:
   │   ├── Danh sách modules đã load (kernel, HAL, drivers)
   │   ├── Memory map
   │   ├── Boot options (BCD settings)
   │   ├── SYSTEM hive
   │   ├── NLS (National Language Support) data
   │   ├── ARC disk info
   │   └── Extension: firmware, hypervisor info
   └── Jump to KiSystemStartup()
```

---

## 12.4 Kernel Initialization

### 12.4.1 Phase 0 (Single-Processor Init)

```
KiSystemStartup() — chỉ chạy trên BSP (Bootstrap Processor):

  ┌──────────────────────────────────────────────────────────┐
  │ 1. KiInitializeBootStructures()                           │
  │    ├── Khởi tạo GDT, IDT, TSS cho BSP                    │
  │    ├── Cấu hình CR0, CR3, CR4 registers                   │
  │    ├── Enable paging (đã cấu hình bởi winload.efi)        │
  │    └── Set up initial kernel stack                         │
  │                                                           │
  │ 2. HalInitSystem(Phase 0):                                │
  │    ├── Khởi tạo APIC (Advanced Programmable Int Controller)│
  │    │   ├── Local APIC cho BSP                              │
  │    │   └── I/O APIC mapping                                │
  │    ├── Khởi tạo system clock (HPET hoặc APIC timer)       │
  │    ├── Khởi tạo HAL private data                           │
  │    ├── Cấu hình bus type (PCI, etc.)                       │
  │    └── Setup stall execution calibration                   │
  │                                                           │
  │ 3. KiInitializeKernel():                                   │
  │    ├── Khởi tạo KPCR (Kernel Processor Control Region)     │
  │    │   - Current IRQL, IDT base, GDT base                 │
  │    │   - Current thread, next thread                       │
  │    │   - DPC queue head                                    │
  │    ├── Khởi tạo KPRCB (Processor Control Block)            │
  │    │   - DPC queue, timer table                            │
  │    │   - Lookaside lists                                   │
  │    │   - Per-CPU scheduling data                           │
  │    ├── Khởi tạo Kernel Dispatcher:                         │
  │    │   - Ready queues (32 priority levels)                 │
  │    │   - Dispatcher database lock                          │
  │    ├── Khởi tạo DPC mechanism                              │
  │    ├── Khởi tạo APC mechanism                              │
  │    ├── Khởi tạo Timer subsystem                            │
  │    │   - Timer expiration DPC                              │
  │    │   - Timer table (hash table của KTIMER)               │
  │    └── Tạo Idle Thread cho BSP                             │
  └──────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────┐
  │ 4. Executive Initialization Phase 0:                      │
  │    Gọi ExInitializePhase0() → gọi từng subsystem:         │
  │                                                           │
  │  a. ExInitSystem():                                       │
  │     ├── Khởi tạo Executive resources (ERESOURCE)          │
  │     ├── Khởi tạo executive worker threads info             │
  │     ├── Khởi tạo pushlock mechanism                        │
  │     └── Khởi tạo lookaside lists                           │
  │                                                           │
  │  b. MmInitSystem(Phase 0):                                │
  │     ├── Xây dựng PFN Database:                             │
  │     │   - 1 MMPFN entry cho mỗi physical page              │
  │     │   - Track state: Active, Standby, Modified, Free,...  │
  │     │   - Có thể chiếm hàng GB RAM trên hệ thống lớn       │
  │     ├── Khởi tạo page table management                     │
  │     ├── Khởi tạo pool allocators:                          │
  │     │   - NonPagedPool (IRQL >= DISPATCH_LEVEL safe)       │
  │     │   - PagedPool (chỉ IRQL < DISPATCH_LEVEL)            │
  │     │   - NonPagedPoolNx (NX-compatible, Win 8+)           │
  │     ├── Khởi tạo system PTE management                     │
  │     ├── Khởi tạo section object structures                 │
  │     ├── Khởi tạo Working Set Manager structures            │
  │     └── Cấu hình memory limits từ BCD settings             │
  │                                                           │
  │  c. ObInitSystem(Phase 0):                                │
  │     ├── Tạo Object Type type object (meta-type)            │
  │     ├── Tạo các core type objects:                         │
  │     │   - Directory, SymbolicLink, Type                    │
  │     ├── Tạo root object directory "\"                      │
  │     ├── Tạo \ObjectTypes directory                         │
  │     └── Khởi tạo handle table infrastructure               │
  │                                                           │
  │  d. SeInitSystem(Phase 0):                                │
  │     ├── Tạo token type object                              │
  │     ├── Khởi tạo well-known SIDs:                          │
  │     │   - S-1-5-18 (SYSTEM), S-1-5-19 (LOCAL SERVICE)     │
  │     │   - S-1-5-20 (NETWORK SERVICE), etc.                │
  │     ├── Khởi tạo privilege definitions                     │
  │     ├── Tạo system token template                          │
  │     └── Khởi tạo LUID allocation (Logon IDs)               │
  │                                                           │
  │  e. PsInitSystem(Phase 0):                                │
  │     ├── Tạo Process và Thread type objects                 │
  │     ├── Tạo System Process (PID 4):                        │
  │     │   - EPROCESS cho "System"                            │
  │     │   - Root của process tree                            │
  │     │   - System threads chạy trong context này            │
  │     ├── Tạo Phase 1 initialization thread                  │
  │     ├── Khởi tạo Job object type                           │
  │     └── Khởi tạo process/thread list heads                 │
  │                                                           │
  │  f. PnpInitPhase0():                                      │
  │     ├── Tạo root device node (\Device\HTREE\ROOT\0)       │
  │     ├── Khởi tạo PnP device tree structure                 │
  │     ├── Khởi tạo device node state machine                 │
  │     └── Khởi tạo driver database structure                 │
  │                                                           │
  │  g. IoInitSystem(Phase 0):                                │
  │     ├── Tạo các I/O-related type objects:                  │
  │     │   - File, Device, Driver, IoCompletion               │
  │     │   - Adapter, Controller, WmiGuid                     │
  │     ├── Tạo I/O manager data structures                    │
  │     ├── Khởi tạo IRP allocation                            │
  │     └── Khởi tạo I/O completion port infrastructure        │
  │                                                           │
  │  h. CmInitSystem1() — Config Manager Phase 0:             │
  │     ├── Mount SYSTEM hive (đã load bởi winload.efi)       │
  │     ├── Khởi tạo registry key body type object             │
  │     ├── Link CCS (CurrentControlSet) → ControlSet00X      │
  │     └── Registry APIs sẵn sàng (limited)                   │
  └──────────────────────────────────────────────────────────┘

  5. BSP enters idle loop
     Phase 1 thread bắt đầu chạy

WinDbg: xem Phase 0 initialization:
  !process 4 0            ; Xem System process
  dt nt!_EPROCESS <addr>  ; Xem EPROCESS structure
  dt nt!_KPCR @$pcr       ; Xem KPCR của current CPU
  dt nt!_KPRCB @$prcb     ; Xem KPRCB
  !pfn <pfn_number>       ; Xem PFN entry
  !pool <address>         ; Xem pool allocation
  !object \               ; Xem root object directory
```

### 12.4.2 Phase 1 (Multi-Processor Init)

```
Phase 1 Thread (chạy trên BSP, các AP được start):

  ┌──────────────────────────────────────────────────────────┐
  │ 1. Start Application Processors (APs):                    │
  │    ├── HalStartNextProcessor() cho mỗi AP                 │
  │    │   ├── Gửi INIT-SIPI-SIPI IPI đến AP                  │
  │    │   ├── AP wake up tại trampoline code                  │
  │    │   └── AP chuyển sang Protected/Long Mode              │
  │    ├── Mỗi AP chạy KiSystemStartup():                      │
  │    │   ├── Khởi tạo KPCR/KPRCB riêng                      │
  │    │   ├── HalInitSystem(0) cho AP                         │
  │    │   ├── Khởi tạo per-CPU dispatcher structures          │
  │    │   ├── Tạo Idle Thread riêng                            │
  │    │   └── Enter idle loop (cho scheduler dispatch)        │
  │    └── Tất cả CPUs sẵn sàng cho scheduling                 │
  │                                                           │
  │ 2. Executive Phase 1 Initialization:                      │
  │                                                           │
  │  a. ObInitSystem(1):                                      │
  │     ├── Tạo các object directories con:                    │
  │     │   \DosDevices, \Device, \Driver, \FileSystem         │
  │     │   \GLOBAL??, \Sessions, \KernelObjects               │
  │     ├── Tạo symbolic links:                                │
  │     │   \DosDevices → \??                                  │
  │     └── Khởi tạo object namespace hoàn chỉnh               │
  │                                                           │
  │  b. SeInitSystem(1):                                      │
  │     ├── Tạo system default DACL                            │
  │     ├── Tạo anonymous logon token                          │
  │     ├── Khởi tạo audit subsystem                           │
  │     └── Security Reference Monitor sẵn sàng                │
  │                                                           │
  │  c. MmInitSystem(1):                                      │
  │     ├── Tạo section objects cho system DLLs:               │
  │     │   - ntdll.dll section object                         │
  │     ├── Khởi tạo Memory Manager threads:                   │
  │     │   - Modified Page Writer                             │
  │     │   - Mapped Page Writer                               │
  │     │   - Working Set Manager (Balance Set Manager)        │
  │     │   - Zero Page Thread                                 │
  │     │   - Dereference Segment Thread                       │
  │     └── Pool expansion sẵn sàng                            │
  │                                                           │
  │  d. CmInitSystem2() — Registry Phase 1:                   │
  │     ├── Mount SOFTWARE, SECURITY, SAM hives               │
  │     │   (load lazy — chỉ khi cần)                          │
  │     ├── Registry API fully functional                      │
  │     └── Notify callbacks registered                        │
  │                                                           │
  │  e. EmInitSystem() — Errata Manager:                      │
  │     └── Load CPU errata workarounds từ firmware/registry   │
  │                                                           │
  │  f. CcInitializeCacheManager():                           │
  │     ├── Khởi tạo cache manager data structures             │
  │     ├── Tạo lazy writer thread                             │
  │     ├── Tạo read-ahead thread                              │
  │     └── Cache manager sẵn sàng cho file I/O                │
  │                                                           │
  │  g. FsRtlInitSystem():                                    │
  │     └── Khởi tạo file system runtime library               │
  │                                                           │
  │  h. PoInitSystem(1) — Power Manager:                      │
  │     ├── Xác định power capabilities (S-states, C-states)   │
  │     ├── Đọc ACPI tables (FADT, DSDT)                       │
  │     ├── Khởi tạo power policy                              │
  │     └── Register power IRP handlers                        │
  │                                                           │
  │  i. IoInitSystem(1) — I/O Manager Phase 1 (QUAN TRỌNG):  │
  │     ├── Tạo \Device, \Driver, \FileSystem namespaces       │
  │     ├── Load boot-start drivers (Start=0):                 │
  │     │   ├── Gọi DriverEntry() cho mỗi driver               │
  │     │   ├── Boot-start drivers theo group order:            │
  │     │   │   System Bus Extender                            │
  │     │   │   → SCSI miniport                                │
  │     │   │   → Port → Primary Disk                          │
  │     │   │   → SCSI Class → Disk                            │
  │     │   │   → Boot File System (NTFS)                      │
  │     │   │   → File System (NTFS, FAT)                      │
  │     │   └── ELAM driver loaded và evaluated ở đây           │
  │     │                                                      │
  │     ├── ELAM evaluation của boot-start drivers:            │
  │     │   ├── ELAM driver nhận callback cho mỗi driver       │
  │     │   ├── Trả về: Known Good / Known Bad / Unknown       │
  │     │   ├── Known Bad → driver không được load              │
  │     │   ├── Unknown → policy quyết định (default: load)    │
  │     │   └── Boot-critical drivers: luôn load bất kể đánh giá│
  │     │                                                      │
  │     ├── Load system-start drivers (Start=1):               │
  │     │   ├── Đọc từ SYSTEM hive: CCS\Services               │
  │     │   ├── Các driver system không cần cho boot           │
  │     │   └── Gọi DriverEntry() cho mỗi driver               │
  │     │                                                      │
  │     ├── Gửi IRP_MN_QUERY_DEVICE_RELATIONS → root enumerator│
  │     └── PnP device enumeration bắt đầu                     │
  │                                                           │
  │  j. PnpInitPhase1() — PnP Manager:                       │
  │     ├── Enumerate root-enumerated devices                  │
  │     ├── Load function drivers cho devices                  │
  │     ├── Gửi IRP_MN_START_DEVICE cho tất cả devices         │
  │     └── Device tree được xây dựng                          │
  │                                                           │
  │  k. MmInitSystem(2) — Memory Manager Finalization:        │
  │     ├── Final memory configuration                         │
  │     ├── Large page support enabled (nếu đủ)                │
  │     └── Memory manager fully operational                   │
  └──────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────┐
  │ 3. Tạo smss.exe:                                          │
  │    ├── PsCreateSystemThread → RtlCreateUserProcess()      │
  │    ├── Image: \SystemRoot\System32\smss.exe                │
  │    ├── Process đầu tiên trong user mode                    │
  │    ├── Native process (không dùng Win32 API)               │
  │    └── Chỉ dùng NT native API (Nt*/Zw* functions)         │
  │                                                           │
  │ 4. Phase 1 thread đợi smss.exe hoàn thành init:           │
  │    ├── NtWaitForSingleObject() trên smss process handle    │
  │    ├── Nếu smss crash → BSOD:                              │
  │    │   SESSION5_INITIALIZATION_FAILED                      │
  │    └── Khi smss báo hiệu done → Phase 1 hoàn thành        │
  └──────────────────────────────────────────────────────────┘

Thứ Tự Khởi Tạo Kernel Structures:
  ┌──────────────────────────────────────────────────────────┐
  │ Thứ tự  │ Subsystem          │ Phase  │ Ghi chú           │
  ├──────────────────────────────────────────────────────────┤
  │ 1       │ HAL                │ 0      │ Hardware abstract  │
  │ 2       │ Kernel Dispatcher  │ 0      │ Scheduling         │
  │ 3       │ Executive (Ex)     │ 0      │ Resources, locks   │
  │ 4       │ Object Manager     │ 0      │ Type objects       │
  │ 5       │ Security (Se)      │ 0      │ SIDs, tokens       │
  │ 6       │ Memory Manager     │ 0      │ PFN, pools         │
  │ 7       │ Config Manager     │ 0      │ SYSTEM hive        │
  │ 8       │ Process Manager    │ 0      │ System process     │
  │ 9       │ PnP Manager        │ 0      │ Root device node   │
  │ 10      │ I/O Manager        │ 0      │ Type objects       │
  │ --- Phase 1 (multi-CPU) ---                               │
  │ 11      │ APs started        │ 1      │ All CPUs online    │
  │ 12      │ Object Manager     │ 1      │ Namespace          │
  │ 13      │ Security           │ 1      │ Default DACL       │
  │ 14      │ Memory Manager     │ 1      │ Sections, threads  │
  │ 15      │ Config Manager     │ 1      │ Full registry      │
  │ 16      │ Cache Manager      │ 1      │ Lazy writer        │
  │ 17      │ Power Manager      │ 1      │ ACPI, policies     │
  │ 18      │ I/O Manager        │ 1      │ Drivers, PnP       │
  │ 19      │ PnP Manager        │ 1      │ Device enum        │
  │ 20      │ Memory Manager     │ 2      │ Final config       │
  └──────────────────────────────────────────────────────────┘
```

### 12.4.3 WinDbg Kernel Init Debugging

```
WinDbg commands cho kernel initialization analysis:

  :: Break tại kernel entry point
  bp nt!KiSystemStartup
  bp nt!KiInitializeKernel

  :: Break tại các subsystem init functions
  bp nt!MmInitSystem
  bp nt!ObInitSystem
  bp nt!SeInitSystem
  bp nt!PsInitSystem
  bp nt!IoInitSystem
  bp nt!CmInitSystem1
  bp nt!PnpInitPhase0

  :: Xem init progress
  !sysinfo boottime          ; Boot timestamps
  dt nt!_LOADER_PARAMETER_BLOCK  ; Loader block truyền từ winload
  !drvobj \Driver\<name> 2   ; Xem driver object và dispatch routines
  !devnode 0 1               ; Xem device tree

  :: Xem boot-start driver order
  !devobj <address>           ; Xem device object
  lm                          ; List modules (drivers loaded)
  lm k                        ; Chỉ kernel modules
  lm t n                      ; Sorted by name
```

---

## 12.5 Session Manager (smss.exe)

### 12.5.1 smss.exe là gì?

```
smss.exe (Session Manager Subsystem):
  - Process user-mode ĐẦU TIÊN được kernel tạo
  - PID thường là 280-400 (thấp, ngay sau System PID 4)
  - Native process: chỉ dùng Nt*/Zw* system calls
  - KHÔNG depend vào Win32 subsystem (csrss.exe)
  - KHÔNG có GUI, không có console window
  - Chạy ở Session 0 (sau này trở thành "non-session")
  - Nếu smss crash → BSOD ngay lập tức

Process hierarchy:
  System (PID 4)
    └── smss.exe (master)
         ├── smss.exe (session 0 worker) → exits
         │    ├── csrss.exe (session 0)
         │    └── wininit.exe (session 0)
         │
         ├── smss.exe (session 1 worker) → exits
         │    ├── csrss.exe (session 1)
         │    └── winlogon.exe (session 1)
         │
         └── smss.exe (session N worker) → exits (cho mỗi session mới)
              ├── csrss.exe (session N)
              └── winlogon.exe (session N)

  Lưu ý: Worker smss instances EXIT sau khi tạo csrss + wininit/winlogon.
  Chỉ master smss.exe tồn tại vĩnh viễn.
```

### 12.5.2 Quy Trình Khởi Tạo Chi Tiết

```
smss.exe initialization sequence:

  ┌──────────────────────────────────────────────────────────┐
  │ 1. Đọc registry: HKLM\SYSTEM\CCS\Control\Session Manager │
  │                                                           │
  │ 2. Set up environment variables:                          │
  │    Source: Session Manager\Environment                     │
  │    ├── ComSpec = %SystemRoot%\system32\cmd.exe             │
  │    ├── Path = %SystemRoot%\system32;%SystemRoot%;...       │
  │    ├── TEMP = %SystemRoot%\TEMP                            │
  │    ├── TMP = %SystemRoot%\TEMP                             │
  │    ├── windir = %SystemRoot%                               │
  │    ├── OS = Windows_NT                                     │
  │    ├── PROCESSOR_ARCHITECTURE = AMD64                      │
  │    └── ... (user và system variables)                      │
  │                                                           │
  │ 3. Execute BootExecute programs:                          │
  │    Source: Session Manager\BootExecute                     │
  │    Default: "autocheck autochk *"                          │
  │                                                           │
  │    autocheck autochk.exe:                                  │
  │    ├── Native application (giống smss - không Win32)       │
  │    ├── Kiểm tra dirty bit của mỗi NTFS volume              │
  │    ├── Nếu dirty → chạy chkdsk automatic                   │
  │    ├── Chạy TRƯỚC file systems được mount đầy đủ            │
  │    └── * = kiểm tra tất cả volumes                          │
  │                                                           │
  │    Các chương trình BootExecute khác (malware thường dùng): │
  │    ├── BootExecute = "autocheck autochk *"                 │
  │    │   → Bình thường                                       │
  │    ├── BootExecute = "autocheck autochk *\0malware.exe"    │
  │    │   → ĐÁNG NGỜ! Malware persistence                     │
  │    └── PendingFileRenameOperations: đổi tên/xóa file       │
  │        (dùng bởi installers để thay thế files đang dùng)   │
  │                                                           │
  │ 4. Process KnownDlls:                                     │
  │    Source: Session Manager\KnownDLLs                       │
  │    ├── Đọc danh sách DLLs cần pre-load                     │
  │    ├── Tạo section objects trong \KnownDlls namespace      │
  │    ├── Các DLL như: kernel32.dll, ntdll.dll, user32.dll,   │
  │    │   advapi32.dll, gdi32.dll, shell32.dll, ...           │
  │    ├── Mục đích:                                           │
  │    │   a. Tăng hiệu năng (đã mapped, không cần tìm lại)    │
  │    │   b. Bảo mật: ngăn DLL search order hijacking         │
  │    │      cho các DLL này                                  │
  │    └── DllDirectory key chỉ định thư mục chứa KnownDlls    │
  │        (default: %SystemRoot%\System32)                    │
  │                                                           │
  │ 5. Tạo paging files:                                      │
  │    Source: Session Manager\Memory Management\PagingFiles   │
  │    ├── Default: "?:\pagefile.sys <min> <max>"              │
  │    │   ? = system-managed (boot volume)                    │
  │    ├── Gọi NtCreatePagingFile() cho mỗi entry              │
  │    ├── Paging file chưa tồn tại trước bước này             │
  │    └── Swapfile.sys cũng được tạo (cho modern apps)        │
  │                                                           │
  │ 6. Khởi tạo DOS device mappings:                          │
  │    ├── Tạo \Global?? và \?? directories                    │
  │    ├── Link symbolic: C: → \Device\HarddiskVolume3, etc.  │
  │    ├── NUL → \Device\Null                                  │
  │    ├── CON → (console device)                              │
  │    └── Các drive letters và device mappings cơ bản         │
  │                                                           │
  │ 7. Tạo Session 0 (Services Session):                      │
  │    ├── smss.exe tự-clone (tạo child smss.exe)              │
  │    ├── Child smss tạo:                                     │
  │    │   a. csrss.exe (Windows Subsystem) cho Session 0      │
  │    │   │   - Thư mục: \Windows\System32\csrss.exe          │
  │    │   │   - Cung cấp Win32 API support                    │
  │    │   │   - Console management                            │
  │    │   │   - Thread creation/deletion notifications        │
  │    │   │   - Shutdown coordination                         │
  │    │   │                                                   │
  │    │   b. wininit.exe cho Session 0                        │
  │    │      - Thay thế winlogon.exe cho session 0            │
  │    │        (Session 0 Isolation - Vista+)                 │
  │    │      - Khởi động services.exe (SCM)                   │
  │    │      - Khởi động lsass.exe (LSA)                      │
  │    │      - Khởi động lsaiso.exe (Credential Guard, VBS)   │
  │    │      - Khởi động fontdrvhost.exe                      │
  │    │                                                       │
  │    └── Child smss EXIT sau khi tạo xong csrss + wininit   │
  │                                                           │
  │ 8. Tạo Session 1 (First Interactive Session):             │
  │    ├── smss.exe tự-clone (tạo child smss.exe)              │
  │    ├── Child smss tạo:                                     │
  │    │   a. csrss.exe cho Session 1                          │
  │    │   b. winlogon.exe cho Session 1                       │
  │    │      - Hiển thị logon screen (LogonUI.exe)            │
  │    │      - Xử lý Ctrl+Alt+Del (SAS)                       │
  │    │      - Giao tiếp với LSA (lsass.exe) để authenticate  │
  │    └── Child smss EXIT                                     │
  │                                                           │
  │ 9. Master smss.exe continues running:                     │
  │    ├── Đợi session creation requests:                      │
  │    │   - Fast User Switching → session mới                 │
  │    │   - Remote Desktop → session mới                      │
  │    │   - RunAs different user (trong một số trường hợp)     │
  │    ├── Mỗi session mới: clone smss → csrss + winlogon      │
  │    ├── Giám sát csrss/wininit/winlogon:                    │
  │    │   - csrss crash → BSOD (CRITICAL_PROCESS_DIED)       │
  │    │   - wininit crash → BSOD                              │
  │    │   - winlogon crash → session terminate                │
  │    └── Không bao giờ exit (protected critical process)     │
  └──────────────────────────────────────────────────────────┘

WinDbg: phân tích smss.exe:
  !process 0 0 smss.exe            ; Tìm smss process(es)
  .process /i /p <smss EPROCESS>   ; Chuyển sang smss context
  !peb                             ; Xem Process Environment Block
  !handle 0 f                      ; Xem tất cả handles của smss
  lm                               ; Modules loaded bởi smss (chỉ ntdll.dll)
```

---

## 12.6 Service Startup

### 12.6.1 Service Control Manager (services.exe) Architecture

```
services.exe (Service Control Manager - SCM):
  ├── Được khởi động bởi wininit.exe (Session 0)
  ├── Chạy dưới SYSTEM account (NT AUTHORITY\SYSTEM)
  ├── Quản lý tất cả Windows services
  └── RPC server: nhận lệnh từ sc.exe, services.msc, API

SCM Architecture:
  ┌────────────────────────────────────────────────────────┐
  │                    User Applications                    │
  │  (sc.exe, services.msc, net start/stop, custom apps)   │
  │                         │                               │
  │                    RPC / Named Pipe                      │
  │                 (\\.\pipe\svcctl)                        │
  │                         │                               │
  │              ┌──────────────────────┐                    │
  │              │   services.exe (SCM) │                    │
  │              │                      │                    │
  │              │ ├── Service Database │                    │
  │              │ │   (in-memory)      │                    │
  │              │ │                    │                    │
  │              │ ├── Dependency       │                    │
  │              │ │   resolver         │                    │
  │              │ │                    │                    │
  │              │ ├── Service          │                    │
  │              │ │   Startup Engine   │                    │
  │              │ │                    │                    │
  │              │ └── Service          │                    │
  │              │     Monitoring       │                    │
  │              └─────────┬────────────┘                    │
  │                        │                                │
  │    ┌───────────────────┼───────────────────┐             │
  │    │                   │                   │             │
  │  svchost.exe     svchost.exe       custom.exe           │
  │  (nhóm 1)        (nhóm 2)          (own process)        │
  │  ├── SvcA        ├── SvcD          └── MyService        │
  │  ├── SvcB        └── SvcE                               │
  │  └── SvcC                                               │
  └────────────────────────────────────────────────────────┘

SCM Initialization:
  1. Đọc HKLM\SYSTEM\CurrentControlSet\Services\*
  2. Xây dựng service database trong memory
  3. Parse dependencies (DependOnService, DependOnGroup)
  4. Xây dựng dependency DAG (Directed Acyclic Graph)
  5. Tính thứ tự start dựa trên:
     a. ServiceGroupOrder (group ordering)
     b. Dependencies (DependOnService, DependOnGroup)
     c. Start type (Boot=0 > System=1 > Auto=2)
  6. Start services (có thể parallel khi không có dependency)
```

### 12.6.2 Service Database (Registry)

```
HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\

  Các values quan trọng:
  ┌─────────────────────────────────────────────────────────────┐
  │ Value              │ Type    │ Mô tả                         │
  ├─────────────────────────────────────────────────────────────┤
  │ Type               │ DWORD   │ Loại service (xem bảng dưới)  │
  │ Start              │ DWORD   │ Start type (0-4)              │
  │ ErrorControl       │ DWORD   │ 0=Ignore 1=Normal 2=Severe   │
  │                    │         │ 3=Critical (BSOD nếu fail)    │
  │ ImagePath          │ SZ/EXP  │ Đường dẫn exe/sys             │
  │ DisplayName        │ SZ      │ Tên hiển thị                  │
  │ Description        │ SZ      │ Mô tả service                 │
  │ ObjectName         │ SZ      │ Account chạy service          │
  │ DependOnService    │ MULTI_SZ│ Services phải start trước     │
  │ DependOnGroup      │ MULTI_SZ│ Groups phải start trước       │
  │ Group              │ SZ      │ Service group membership      │
  │ Tag                │ DWORD   │ Thứ tự trong group             │
  │ DelayedAutoStart   │ DWORD   │ 1 = delayed auto-start        │
  │ FailureActions     │ BINARY  │ Hành động khi service crash   │
  │ FailureCommand     │ SZ      │ Command chạy khi fail         │
  │ ServiceSidType     │ DWORD   │ 0=None 1=Unrestricted 2=Restr│
  │ RequiredPrivileges │ MULTI_SZ│ Privileges cần thiết           │
  │ PreShutdownTimeout │ DWORD   │ Timeout pre-shutdown (ms)     │
  │ TriggerInfo        │ BINARY  │ Service trigger conditions     │
  └─────────────────────────────────────────────────────────────┘

Service Type values:
  ┌────────────────────────────────────────────────────────┐
  │ Value │ Hex    │ Name                    │ Mô tả       │
  ├────────────────────────────────────────────────────────┤
  │ 1     │ 0x001  │ KERNEL_DRIVER           │ .sys file   │
  │ 2     │ 0x002  │ FILE_SYSTEM_DRIVER      │ FS driver   │
  │ 4     │ 0x004  │ ADAPTER                 │ (deprecated)│
  │ 8     │ 0x008  │ RECOGNIZER_DRIVER       │ FS recogn.  │
  │ 16    │ 0x010  │ WIN32_OWN_PROCESS       │ Own exe     │
  │ 32    │ 0x020  │ WIN32_SHARE_PROCESS     │ Shared svch │
  │ 48    │ 0x030  │ OWN+SHARE (either)      │ Flexible    │
  │ 256   │ 0x100  │ INTERACTIVE_PROCESS     │ (deprecated)│
  │ 80    │ 0x050  │ USER_OWN_PROCESS        │ Per-user    │
  │ 96    │ 0x060  │ USER_SHARE_PROCESS      │ Per-user sh │
  └────────────────────────────────────────────────────────┘
```

### 12.6.3 Service Start Types Chi Tiết

| Value | Name | Khi nào Start | Ai Start | Ví dụ |
|-------|------|--------------|----------|-------|
| 0 | Boot | winload.efi load | Boot Loader | Disk, file system, bus drivers |
| 1 | System | IoInitSystem Phase 1 | I/O Manager | NDIS, Tcpip (một số) |
| 2 | Automatic | Sau boot hoàn thành | SCM | Windows Update, Print Spooler |
| 2+D | Auto (Delayed) | ~2 phút sau boot | SCM | Windows Search, BITS |
| 3 | Manual | Khi được yêu cầu | SCM (on demand) | Remote Registry |
| 4 | Disabled | Không bao giờ | (không ai) | Telnet, deprecated services |

```
Trigger Start (Win 7+):
  Service tự động start khi một event xảy ra:
  ├── Device Interface Arrival:
  │   Service start khi device được cắm vào
  │   Ví dụ: USB device → start related service
  ├── IP Address Availability:
  │   Service start khi network available
  │   Ví dụ: DNS Client
  ├── Domain Join:
  │   Service start khi máy join domain
  ├── Firewall Port Event:
  │   Service start khi port được mở/đóng
  ├── Group Policy:
  │   Service start khi group policy thay đổi
  ├── Network Endpoint:
  │   RPC endpoint event
  └── Custom ETW Event:
      Service start khi ETW event được fire

  Registry: Services\<name>\TriggerInfo\<N>\
    Type:   trigger type (DWORD)
    Action: 1=Start, 2=Stop
    GUID:   trigger-specific GUID
    Data:   trigger-specific data
```

### 12.6.4 Service Account Types

```
Service Account Types:
  ┌──────────────────────────────────────────────────────────────┐
  │ Account               │ SID          │ Quyền                 │
  ├──────────────────────────────────────────────────────────────┤
  │ LocalSystem            │ S-1-5-18    │ Full admin, network   │
  │ (NT AUTHORITY\SYSTEM)  │             │ credentials = machine │
  │                        │             │ account. Quyền cao    │
  │                        │             │ nhất có thể.          │
  ├──────────────────────────────────────────────────────────────┤
  │ Local Service          │ S-1-5-19    │ Limited privileges,   │
  │ (NT AUTHORITY\         │             │ anonymous network     │
  │  LocalService)         │             │ (không có network     │
  │                        │             │ credentials)          │
  ├──────────────────────────────────────────────────────────────┤
  │ Network Service        │ S-1-5-20    │ Limited privileges,   │
  │ (NT AUTHORITY\         │             │ network credentials = │
  │  NetworkService)       │             │ machine account       │
  ├──────────────────────────────────────────────────────────────┤
  │ Virtual Account        │ S-1-5-80-  │ Per-service identity,  │
  │ (NT SERVICE\<name>)    │ <hash>     │ network = machine acct │
  │                        │             │ Default cho Win10+     │
  ├──────────────────────────────────────────────────────────────┤
  │ gMSA (Group Managed    │ domain SID │ Domain account, auto   │
  │  Service Account)      │             │ password rotation,     │
  │                        │             │ multi-server support   │
  └──────────────────────────────────────────────────────────────┘

Service Isolation (Vista+):
  ├── Session 0 Isolation:
  │   - Tất cả services chạy trong Session 0
  │   - Không có interactive desktop access
  │   - Ngăn shatter attack (service ↔ user GUI)
  │
  ├── Per-Service SID (ServiceSidType):
  │   - Mỗi service nhận SID riêng: S-1-5-80-<hash of name>
  │   - Type 1 (Unrestricted): SID thêm vào token
  │   - Type 2 (Restricted): SID = write-restricted
  │     → Chỉ ghi được vào resources có ACE cho service SID
  │
  └── RequiredPrivileges:
      - Service chỉ nhận privileges trong danh sách này
      - Các privileges khác bị strip khỏi token
      - Principle of Least Privilege
```

### 12.6.5 svchost.exe Service Hosting

```
svchost.exe:
  - Host process cho Win32 services chạy dạng DLL
  - Mỗi instance host một nhóm (group) services
  - Hoặc một service riêng (Win10 >= 3.5GB RAM)

svchost.exe Groups:
  HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost
  ├── DcomLaunch:     DCOM, Power, SystemEventsBroker, ...
  ├── RPCSS:          RpcSs, RpcEptMapper
  ├── LocalService:   nsi, EventLog, ...
  ├── NetworkService: Dnscache, NlaSvc, ...
  ├── LocalSystemNetworkRestricted: AudioSrv, Dhcp, ...
  ├── netsvcs:        wuauserv, BITS, ShellHWDetection, ...
  └── ... (nhiều groups khác)

Command line format:
  svchost.exe -k <group_name> [-p] [-s <service_name>]
    -k: tên group
    -p: enable process mitigation policies (CFG, dynamic code, etc.)
    -s: chỉ định service cụ thể (Win10 per-service split)

[UPDATE 2026] Per-Service Split (Win10 1703+):
  ├── Khi hệ thống có >= 3.5GB RAM:
  │   - Mỗi service chạy trong svchost.exe riêng
  │   - Ví dụ: svchost.exe -k netsvcs -p -s wuauserv
  │   - Mỗi svchost chỉ host 1 service
  ├── Ưu điểm:
  │   - Crash isolation: 1 service crash không ảnh hưởng service khác
  │   - Security: per-service mitigation policies
  │   - Debugging: dễ dàng xác định service nào dùng nhiều resource
  ├── Nhược điểm:
  │   - Nhiều process hơn → nhiều memory overhead
  │   - Nhiều handle, nhiều context switches
  └── Registry override:
      HKLM\SYSTEM\CCS\Control\SvcHostSplitThresholdInKB
      Default: 3670016 (3.5GB). Đặt = 0xFFFFFFFF để tắt split.

Xem services trong svchost:
  :: PowerShell
  Get-Process svchost | ForEach-Object {
    $id = $_.Id
    $svcs = (Get-WmiObject Win32_Service | Where-Object { $_.ProcessId -eq $id }).Name
    [PSCustomObject]@{ PID=$id; Services=($svcs -join ", ") }
  }

  :: Command line
  tasklist /svc /fi "imagename eq svchost.exe"
```

### 12.6.6 Service Dependencies và Group Order

```
ServiceGroupOrder:
  HKLM\SYSTEM\CCS\Control\ServiceGroupOrder\List (REG_MULTI_SZ)

  Thứ tự groups (rút gọn):
  ┌──────────────────────────────────────────────────────────┐
  │  1. System Reserved                                       │
  │  2. EMS (Emergency Management Services)                   │
  │  3. WdfLoadGroup                                          │
  │  4. Boot Bus Extender                                     │
  │  5. System Bus Extender                                   │
  │  6. SCSI miniport                                         │
  │  7. Port (serial, parallel ports)                         │
  │  8. Primary Disk                                          │
  │  9. SCSI Class                                            │
  │ 10. SCSI CDROM Class                                      │
  │ 11. FSFilter Infrastructure                               │
  │ 12. FSFilter System                                       │
  │ 13. FSFilter Bottom                                       │
  │ 14. Filter                                                │
  │ 15. Boot File System                                      │
  │ 16. Base                                                  │
  │ 17. Pointer Port                                          │
  │ 18. Keyboard Port                                         │
  │ 19. Pointer Class                                         │
  │ 20. Keyboard Class                                        │
  │ ... (nhiều groups trung gian) ...                         │
  │ 50. PNP_TDI (network transport)                           │
  │ 51. NDIS                                                  │
  │ 52. TDI                                                   │
  │ 53. NetworkProvider                                       │
  │ 54. SchedulerGroup                                        │
  │ 55. SpoolerGroup                                          │
  │ ... (services không có group → start cuối cùng) ...       │
  └──────────────────────────────────────────────────────────┘

Dependency resolution:
  1. SCM đọc DependOnService và DependOnGroup cho mỗi service
  2. Xây dựng DAG (phát hiện circular dependency → log error)
  3. Start services: bắt đầu với services không có dependency
  4. Khi dependency hoàn thành → start services phụ thuộc
  5. Parallel start khi không có dependency conflict

  Ví dụ dependency chain:
    Dnscache (DNS Client)
      └── DependOnService: Tdx
           └── DependOnService: (none, nhưng trong group TDI)
                └── TDI group phải start trước NetworkProvider group

Service Failure Recovery:
  Registry: Services\<name>\FailureActions (REG_BINARY)
  
  Structure:
    DWORD dwResetPeriod    ; Reset failure count sau X giây (86400=1 ngày)
    LPSTR lpRebootMsg      ; Message khi reboot (offset)
    LPSTR lpCommand        ; Command khi run program (offset)
    DWORD cActions         ; Số lượng failure actions
    SC_ACTION[]:           ; Mảng actions
      Type: 0=None, 1=Restart Service, 2=Reboot, 3=Run Command
      Delay: milliseconds trước khi thực hiện action

  sc.exe cấu hình failure:
    sc.exe failure <name> reset= 86400 actions= restart/60000/restart/120000/run/180000
    sc.exe failureflag <name> 1    ; Track failure cho non-crash exits
```

---

## 12.7 User Logon Sequence

### 12.7.1 Winlogon Initialization

```
winlogon.exe initialization (Session 1+):

  ┌──────────────────────────────────────────────────────────┐
  │ 1. Tạo Window Station và Desktops:                        │
  │    ├── WinSta0 (interactive window station)                │
  │    ├── Desktop: Default (user desktop)                     │
  │    ├── Desktop: Winlogon (secure desktop - SAS screen)     │
  │    ├── Desktop: Screen-saver                               │
  │    └── Chỉ WinSta0 có thể interactive                      │
  │                                                           │
  │ 2. Đăng ký SAS (Secure Attention Sequence):               │
  │    ├── Ctrl+Alt+Del (default SAS)                          │
  │    ├── Winlogon là process DUY NHẤT nhận SAS              │
  │    ├── SAS chuyển sang Winlogon desktop (secure)           │
  │    ├── Ngăn malware giả mạo logon screen                   │
  │    └── Smart card insertion cũng là SAS event              │
  │                                                           │
  │ 3. Load Credential Providers:                             │
  │    Registry: HKLM\SOFTWARE\Microsoft\Windows\              │
  │              CurrentVersion\Authentication\                │
  │              Credential Providers\{GUID}                   │
  │    ├── Password CP:      {60b78e88-...}                    │
  │    ├── Smart Card CP:    {8bf9a910-...}                    │
  │    ├── PIN (Hello) CP:   {cb82ea12-...}                    │
  │    ├── FIDO2 CP:         {882D0D36-...}                    │
  │    ├── Picture Password: {2135F72A-...}                    │
  │    ├── NGC (Next Gen Credential): ...                      │
  │    └── 3rd-party CPs: Duo, RSA, etc.                       │
  │                                                           │
  │ 4. Hiển thị LogonUI.exe:                                  │
  │    ├── Chạy trên Winlogon (secure) desktop                 │
  │    ├── Hiển thị các credential providers                   │
  │    ├── User nhập credentials                               │
  │    └── Trả credentials về winlogon                         │
  └──────────────────────────────────────────────────────────┘
```

### 12.7.2 LSA Authentication

```
Quy trình xác thực chi tiết:

winlogon.exe
  │ LsaLogonUser(LOGON32_LOGON_INTERACTIVE)
  v
lsass.exe (Local Security Authority)
  │
  ├── 1. Xác định Authentication Package:
  │    ├── Negotiate: tự chọn Kerberos hoặc NTLM
  │    ├── Kerberos: domain logon (ưu tiên)
  │    ├── NTLM: fallback, workgroup, legacy
  │    ├── Smart Card (Kerberos w/ certificate)
  │    └── CloudAP: Azure AD / Microsoft Account
  │
  ├── 2. Kerberos Authentication (domain):
  │    ├── AS-REQ → Domain Controller (KDC)
  │    │   - Encrypted timestamp (pre-auth)
  │    │   - Username, domain
  │    ├── KDC validates:
  │    │   - Lookup user trong AD
  │    │   - Verify pre-auth (decrypt timestamp)
  │    │   - Check account: locked? disabled? expired?
  │    ├── AS-REP ← DC:
  │    │   - TGT (Ticket Granting Ticket)
  │    │   - Session key
  │    └── TGT cached bởi Kerberos SSP
  │
  ├── 3. NTLM Authentication (workgroup/fallback):
  │    ├── Tính NT hash từ password: MD4(UTF16LE(password))
  │    ├── Challenge-Response protocol:
  │    │   a. Client gửi username → server/DC
  │    │   b. Server gửi challenge (8 bytes random)
  │    │   c. Client encrypt challenge với NT hash → response
  │    │   d. Server verify response (hoặc forward đến DC)
  │    └── NTLMv2: thêm timestamp, server name vào response
  │
  ├── 4. Local SAM Authentication (local accounts):
  │    ├── Đọc SAM database:
  │    │   HKLM\SAM\SAM\Domains\Account\Users\<RID>
  │    ├── Extract NT hash (encrypted với syskey)
  │    ├── Decrypt với syskey (boot key)
  │    ├── So sánh hash với hash từ password nhập vào
  │    └── Thành công nếu khớp
  │
  ├── 5. Azure AD Authentication:
  │    ├── CloudAP plugin xử lý
  │    ├── HTTPS request đến login.microsoftonline.com
  │    ├── OAuth2 / OpenID Connect flow
  │    ├── Primary Refresh Token (PRT) nhận được
  │    └── Có thể kết hợp với Windows Hello for Business
  │
  └── 6. Tạo Access Token:
       ├── Token chứa:
       │   ├── User SID (S-1-5-21-...-<RID>)
       │   ├── Group SIDs (Domain Users, etc.)
       │   ├── Privileges (SeChangeNotifyPrivilege, etc.)
       │   ├── Logon SID (unique per logon session)
       │   ├── Integrity Level (Medium cho user bình thường)
       │   ├── Session ID
       │   └── Logon type, authentication ID
       ├── Tạo restricted token (UAC filtered token)
       │   - Admin user nhận 2 tokens:
       │     a. Full token (elevated)
       │     b. Filtered token (standard user rights)
       │   - Explorer chạy với filtered token
       │   - UAC prompt để dùng full token
       └── Tạo Logon Session

Security implications:
  ├── Credential caching: NT hash cache trong LSASS memory
  │   → Mimikatz có thể dump bằng sekurlsa::logonPasswords
  ├── Credential Guard (VBS): cache credential trong VTL 1
  │   → LSASS không có credentials, chỉ có tickets
  └── Remote Credential Guard: không gửi credentials đến remote
```

### 12.7.3 User Profile Loading và Shell Startup

```
Sau khi LSA trả về token:

winlogon.exe:
  │
  ├── 1. Load User Profile:
  │    ├── Registry: HKLM\SOFTWARE\Microsoft\Windows NT\
  │    │             CurrentVersion\ProfileList\<User SID>
  │    ├── ProfileImagePath: C:\Users\<username>
  │    ├── NtLoadKey() → mount NTUSER.DAT as HKCU
  │    │   - NTUSER.DAT chứa user-specific settings
  │    │   - Desktop, Start Menu, app settings, etc.
  │    ├── NtLoadKey() → mount UsrClass.dat
  │    │   - HKCU\SOFTWARE\Classes
  │    │   - File associations, COM registrations per-user
  │    ├── Tạo environment variables cho user:
  │    │   - %USERPROFILE%, %APPDATA%, %LOCALAPPDATA%
  │    │   - %HOMEPATH%, %HOMEDRIVE%
  │    └── Apply Group Policy (nếu domain member):
  │        - gpupdate /force
  │        - Computer policies → User policies
  │        - Software restrictions, folder redirection, etc.
  │
  ├── 2. Launch userinit.exe:
  │    ├── Registry: Winlogon\Userinit = userinit.exe
  │    │   (malware có thể thêm vào đây: userinit.exe,malware.exe)
  │    ├── userinit.exe tasks:
  │    │   a. Process logon scripts:
  │    │      - HKCU\...\Windows\CurrentVersion\Run (Userinit)
  │    │      - Group Policy logon scripts
  │    │      - NETLOGON share scripts (domain)
  │    │   b. Map network drives
  │    │   c. Process Group Policy folder redirection
  │    │   d. Launch Shell (explorer.exe)
  │    │      - Registry: Winlogon\Shell = explorer.exe
  │    └── userinit.exe EXIT sau khi launch shell
  │
  ├── 3. explorer.exe initialization:
  │    ├── Khởi tạo desktop environment:
  │    │   ├── Taskbar
  │    │   ├── Start Menu
  │    │   ├── System Tray (notification area)
  │    │   ├── Desktop icons
  │    │   └── Widgets (Win11)
  │    │
  │    ├── Process Startup items:
  │    │   ├── HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
  │    │   │   - Tất cả users
  │    │   ├── HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
  │    │   │   - User hiện tại
  │    │   ├── HKLM\...\RunOnce (chạy 1 lần, xóa sau khi chạy)
  │    │   ├── HKCU\...\RunOnce
  │    │   ├── Startup folder:
  │    │   │   %APPDATA%\...\Start Menu\Programs\Startup\
  │    │   │   %ProgramData%\...\Start Menu\Programs\Startup\
  │    │   ├── Task Scheduler: tasks với trigger "At logon"
  │    │   └── ActiveSetup:
  │    │       HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components
  │    │       (chạy 1 lần per-user cho mỗi component)
  │    │
  │    └── Shell ready → user có thể tương tác
  │
  └── 4. winlogon.exe continues monitoring:
       ├── Đợi SAS events (Ctrl+Alt+Del)
       ├── Lock/Unlock workstation
       ├── Switch User
       ├── Sign Out
       └── Đợi csrss notification khi session kết thúc

Logon Timeline:
  ┌────────────────────────────────────────────────────────┐
  │ T+0s:    LogonUI hiển thị                              │
  │ T+?:     User nhập credentials                         │
  │ T+0.1s:  LSA xác thực (local: nhanh, domain: chậm hơn)│
  │ T+0.5s:  Token created, profile loading                │
  │ T+1s:    Group Policy processing bắt đầu               │
  │ T+2s:    userinit.exe chạy                             │
  │ T+3s:    explorer.exe bắt đầu khởi tạo                 │
  │ T+5s:    Desktop visible                               │
  │ T+10s:   Startup programs bắt đầu chạy                 │
  │ T+120s:  Delayed auto-start services bắt đầu           │
  │ T+~5min: Desktop fully responsive                      │
  └────────────────────────────────────────────────────────┘
```

### 12.7.4 Auto-Logon

```
Auto-Logon Configuration:
  Registry: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    AutoAdminLogon: "1"
    DefaultUserName: "username"
    DefaultPassword: "password"     ← PLAINTEXT! Không bảo mật
    DefaultDomainName: "DOMAIN"

  Bảo mật hơn: Sysinternals Autologon.exe
    ├── Lưu password dạng LSA Secret (encrypted)
    ├── HKLM\SECURITY\Policy\Secrets\DefaultPassword
    └── Vẫn có thể dump bởi local admin (mimikatz lsadump::secrets)

  [UPDATE 2026] Cách an toàn nhất:
    ├── Windows Hello for Business (passwordless)
    ├── FIDO2 security key
    └── Azure AD passwordless (Authenticator app)
```

---

## 12.8 Shutdown Sequence

### 12.8.1 Shutdown Flow Chi Tiết

```
User khởi động shutdown:
  ├── Start → Power → Shutdown
  ├── ExitWindowsEx(EWX_SHUTDOWN, reason)
  ├── shutdown.exe /s /t 0
  ├── NtShutdownSystem(ShutdownPowerOff)
  └── InitiateSystemShutdownEx() (remote shutdown)

Chi tiết shutdown flow:

  ┌──────────────────────────────────────────────────────────┐
  │ 1. User process notification (csrss.exe xử lý):          │
  │                                                          │
  │  a. Gửi WM_QUERYENDSESSION đến tất cả top-level windows: │
  │     ├── Mỗi window có HungAppTimeout giây để trả lời      │
  │     │   (default: 5000ms = 5 giây)                        │
  │     │   Registry: HKCU\Control Panel\Desktop\             │
  │     │             HungAppTimeout                          │
  │     ├── App trả lời TRUE → đồng ý shutdown                │
  │     ├── App trả lời FALSE → yêu cầu cancel shutdown       │
  │     │   ├── Hiển thị "This app is preventing shutdown"    │
  │     │   ├── User chọn: Force Shut Down hoặc Cancel        │
  │     │   └── ShutdownBlockReasonCreate() để giải thích     │
  │     └── App không trả lời (hung) → force terminate        │
  │                                                          │
  │  b. Gửi WM_ENDSESSION(wParam=TRUE) cho các app đồng ý:  │
  │     ├── App được thông báo: "shutdown đang xảy ra"        │
  │     ├── App nên save data và clean up                     │
  │     └── WaitToKillAppTimeout (default: 20000ms = 20s)     │
  │         Registry: HKCU\Control Panel\Desktop\             │
  │                   WaitToKillAppTimeout                    │
  │                                                          │
  │  c. Console processes:                                    │
  │     ├── Nhận CTRL_SHUTDOWN_EVENT qua console handler      │
  │     ├── Timeout: WaitToKillAppTimeout                     │
  │     └── Force terminate sau timeout                       │
  │                                                          │
  │  d. Terminate tất cả user processes còn lại               │
  └──────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────┐
  │ 2. Service Shutdown (SCM xử lý):                         │
  │                                                          │
  │  a. Pre-shutdown notification:                            │
  │     ├── Gửi SERVICE_CONTROL_PRESHUTDOWN đến services      │
  │     │   có đăng ký nhận pre-shutdown                       │
  │     ├── Default timeout: 180 giây (3 phút)                │
  │     │   Có thể override: PreShutdownTimeout trong registry│
  │     ├── Ví dụ services cần pre-shutdown:                   │
  │     │   - Database services (flush transactions)           │
  │     │   - Cluster services (failover preparation)          │
  │     │   - Windows Update (finalize installations)          │
  │     └── Mục đích: cho services cần nhiều thời gian hơn để clean up │
  │                                                          │
  │  b. Shutdown notification:                                │
  │     ├── Gửi SERVICE_CONTROL_SHUTDOWN đến tất cả services  │
  │     │   còn chạy                                          │
  │     ├── ServicesPipeTimeout: 30 giây (default)            │
  │     │   Registry: HKLM\SYSTEM\CCS\Control\               │
  │     │             ServicesPipeTimeout (DWORD, ms)          │
  │     ├── Parallel shutdown (khi safe, không dependency)    │
  │     └── Force terminate sau timeout                       │
  │                                                          │
  │  c. Terminate tất cả service processes                    │
  └──────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────┐
  │ 3. Kernel Shutdown:                                      │
  │                                                          │
  │  a. NtShutdownSystem() / NtSetSystemPowerState():        │
  │                                                          │
  │  b. Flush registry hives:                                 │
  │     ├── CmFlushKey() cho tất cả loaded hives              │
  │     ├── SYSTEM, SOFTWARE, SAM, SECURITY                   │
  │     ├── NTUSER.DAT cho tất cả users                       │
  │     └── Đảm bảo registry persistent                       │
  │                                                          │
  │  c. Flush file system caches:                             │
  │     ├── CcFlushCache() cho tất cả volumes                 │
  │     ├── Flush dirty pages từ cache → disk                 │
  │     └── File system clean shutdown marker                 │
  │                                                          │
  │  d. Flush disk write caches:                              │
  │     ├── IOCTL_DISK_FLUSH_CACHE → storage driver           │
  │     └── Đảm bảo data trên physical media                  │
  │                                                          │
  │  e. Dismount file systems:                                │
  │     ├── IoFlushAdapterBuffers                              │
  │     └── Lock volumes                                      │
  │                                                          │
  │  f. Power down:                                           │
  │     ├── Gửi IRP_MN_SET_POWER(PowerDeviceD3) cho devices   │
  │     ├── Devices chuyển sang low-power state               │
  │     ├── HalReturnToFirmware(HalPowerOff)                  │
  │     │   hoặc HalReturnToFirmware(HalRebootRoutine)        │
  │     └── ACPI: ghi vào PM1a_CNT register → power off       │
  └──────────────────────────────────────────────────────────┘
```

### 12.8.2 Shutdown Reason Codes và Event Tracking

```
Shutdown Reason Codes (dùng với shutdown.exe và API):

  Major reasons:
    0x00000000  Other (Unplanned)
    0x00000001  Hardware: Maintenance
    0x00000002  Hardware: Installation
    0x00000003  Operating System: Upgrade
    0x00000004  Operating System: Reconfig
    0x00000005  Application: Maintenance
    0x00000006  Application: Installation
    0x00000007  Application: Unresponsive
    0x00000008  Application: Unstable
    0x00000009  Operating System: Security Fix

  Flags:
    0x40000000  Planned shutdown
    0x80000000  User-defined reason

  shutdown.exe với reason:
    shutdown /s /t 0 /d p:4:1 /c "Planned OS reconfig"

Event Tracking:
  Event Log: System
    Event ID 1074: System shutdown/restart initiated
      - Process, User, Reason, Comment
    Event ID 6005: Event Log service started (boot)
    Event ID 6006: Event Log service stopped (clean shutdown)
    Event ID 6008: Unexpected shutdown (crash, power loss)
    Event ID 6009: OS version info (at boot)
    Event ID 6013: System uptime
    Event ID 41:   Kernel-Power (unexpected shutdown)

  PowerShell: đọc shutdown events:
    Get-WinEvent -FilterHashtable @{
      LogName='System';
      ID=1074,6005,6006,6008
    } | Format-Table TimeCreated, Id, Message -Wrap
```

### 12.8.3 Forced Shutdown

```
Forced shutdown scenarios:

  1. Force via shutdown.exe:
     shutdown /s /t 0 /f    ; Force close apps, không hỏi

  2. Force via API:
     ExitWindowsEx(EWX_SHUTDOWN | EWX_FORCE, reason)
     ; Không gửi WM_QUERYENDSESSION, terminate ngay

  3. Power button:
     ├── Ngắn press: ACPI power button event
     │   → OS xử lý theo power button policy
     │   → Shutdown/Sleep/Do nothing
     ├── Giữ 4+ giây: hardware force power off
     │   → Không clean shutdown
     │   → Có thể data loss
     └── Registry: HKLM\...\Power\PowerSettings\...

  4. BSOD (Blue Screen):
     ├── KeBugCheckEx() → dump memory → auto restart
     ├── CrashDumpEnabled registry controls dump type
     │   0 = None, 1 = Complete, 2 = Kernel, 3 = Small
     │   7 = Automatic
     └── AutoReboot: 1 = auto restart after BSOD
```

---

## 12.9 Fast Startup và Hibernate

### 12.9.1 Fast Startup (Hybrid Shutdown)

```
[UPDATE 2026] Fast Startup (default trong Win 10/11):

Traditional Shutdown vs Fast Startup:

  Traditional Shutdown:
    Close apps → Close user sessions → Stop services
    → Shutdown kernel → Power Off
    Boot: UEFI → winload → kernel init → services → logon
    (Full cold boot - chậm)

  Fast Startup (Hybrid Shutdown):
    Close apps → Close user sessions → Stop services
    → HIBERNATE kernel (session 0) → Power Off
    Boot: UEFI → winload → RESUME kernel từ hibernation → logon
    (Chỉ resume kernel + drivers, không init lại)

  So sánh thời gian (ví dụ):
    ├── Full cold boot:     ~30-60 giây
    ├── Fast Startup:       ~10-20 giây
    ├── Hibernate (full):   ~15-25 giây
    └── Sleep/Resume:       ~1-3 giây

Fast Startup Flow Chi Tiết:
  ┌──────────────────────────────────────────────────────────┐
  │ SHUTDOWN với Fast Startup:                                │
  │                                                           │
  │ 1. Đóng tất cả user applications                          │
  │ 2. Log off tất cả user sessions                           │
  │ 3. Stop tất cả services (giống shutdown bình thường)       │
  │ 4. Gửi hibernation notification đến drivers               │
  │ 5. Driver save state (nhưng chỉ session 0 state)          │
  │ 6. Ghi kernel + driver state vào hiberfil.sys             │
  │    ├── Chỉ ghi session 0 (kernel/driver memory)           │
  │    ├── User sessions đã logged off → không ghi            │
  │    └── File nhỏ hơn full hibernate                        │
  │ 7. Power off                                              │
  │                                                           │
  │ BOOT với Fast Startup:                                    │
  │                                                           │
  │ 1. UEFI firmware init (bình thường)                       │
  │ 2. bootmgfw.efi load (bình thường)                        │
  │ 3. Phát hiện hiberfil.sys có fast startup data             │
  │ 4. winresume.efi đọc và decompress hiberfil.sys            │
  │ 5. Kernel và drivers resume (không init lại)               │
  │ 6. SCM start services (đã loaded, chỉ re-init)            │
  │ 7. User logon bình thường                                  │
  └──────────────────────────────────────────────────────────┘

Registry:
  HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power
    HiberbootEnabled = 1 (default, enabled)
    HiberbootEnabled = 0 (disabled)

Implications và vấn đề:
  ├── shutdown.exe /s → thực ra là hibernate (fast startup)
  │   → Để force FULL shutdown:
  │     shutdown.exe /s /t 0 /f (force full shutdown)
  │     Giữ Shift + click Shut Down
  │
  ├── restart LUÔN là full restart (không hybrid)
  │   → shutdown.exe /r = full restart
  │
  ├── Dual-boot issues:
  │   ├── Windows filesystem vẫn "in use" (hibernated)
  │   ├── Linux mount NTFS → có thể corrupt data
  │   ├── Fix: tắt fast startup, hoặc mount read-only
  │   └── ntfs-3g: ro hoặc windows_names flag
  │
  ├── Windows Update:
  │   ├── Một số updates yêu cầu full restart
  │   ├── Pending updates → full restart thay vì fast startup
  │   └── Event log ghi khi restart type thay đổi
  │
  ├── Driver issues:
  │   ├── Driver state từ session trước được resume
  │   ├── Hardware thay đổi giữa sessions → có thể conflict
  │   ├── USB devices: có thể không được re-enumerate
  │   └── Fix: full restart để re-init tất cả drivers
  │
  └── Forensics:
      ├── Fast startup = file system không "clean unmount"
      ├── $LogFile và $MFT có thể có stale data
      └── Registry hives từ hibernated session
```

### 12.9.2 Hibernate Chi Tiết

```
Hibernate (S4 state):

  ┌──────────────────────────────────────────────────────────┐
  │ HIBERNATE:                                                │
  │                                                           │
  │ 1. Gửi IRP_MN_QUERY_POWER(PowerSystemHibernate) → drivers│
  │    ├── Drivers có thể veto hibernate                      │
  │    └── Nếu ok → proceed                                   │
  │                                                           │
  │ 2. Gửi IRP_MN_SET_POWER(PowerSystemHibernate) → drivers  │
  │    ├── Drivers save device state                           │
  │    ├── Chuyển devices sang low-power state                 │
  │    └── DMA stopped, interrupts masked                      │
  │                                                           │
  │ 3. Ghi memory vào hiberfil.sys:                           │
  │    ├── Nén với Xpress hoặc Xpress Huffman algorithm        │
  │    ├── Ghi trực tiếp qua raw disk I/O (bypass file system)│
  │    ├── Ghi header: signature, checksum, memory layout     │
  │    ├── Ghi tất cả physical memory pages (có nén)          │
  │    ├── Ghi CPU context (registers, control registers)     │
  │    └── Ghi RESUME context (entry point cho resume)        │
  │                                                           │
  │ 4. Power off hoàn toàn (mất điện)                         │
  └──────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────┐
  │ RESUME FROM HIBERNATE:                                    │
  │                                                           │
  │ 1. UEFI firmware boot bình thường:                        │
  │    SEC → PEI → DXE → BDS                                 │
  │                                                           │
  │ 2. bootmgfw.efi load:                                     │
  │    ├── Kiểm tra hiberfil.sys có valid header               │
  │    ├── Phát hiện hibernate data → load winresume.efi      │
  │    └── Nếu invalid → fall through to normal boot          │
  │                                                           │
  │ 3. winresume.efi:                                         │
  │    ├── Đọc hiberfil.sys header                             │
  │    ├── Verify integrity (checksum, signature)              │
  │    ├── [Secure Boot] Verify Measured Boot measurements     │
  │    ├── [BitLocker] Unseal key dùng TPM PCR values          │
  │    │   → Nếu PCR values thay đổi → không unseal → fail     │
  │    ├── Decompress memory data                              │
  │    ├── Restore physical memory content                     │
  │    ├── Restore CPU context (registers)                     │
  │    ├── Resume execution tại saved instruction pointer      │
  │    └── Kernel "wakes up" như chưa bao giờ tắt              │
  │                                                           │
  │ 4. Post-resume:                                           │
  │    ├── Gửi IRP_MN_SET_POWER(PowerSystemWorking) → drivers │
  │    ├── Drivers restore device state                        │
  │    ├── Re-enumerate USB và hot-plug devices                │
  │    ├── Network stack reconnect                             │
  │    └── System chạy bình thường                             │
  └──────────────────────────────────────────────────────────┘

hiberfil.sys:
  ┌──────────────────────────────────────────────────────────┐
  │ Location: C:\hiberfil.sys                                  │
  │ Attributes: Hidden, System, ReadOnly                       │
  │ Cannot be read by normal programs                          │
  │                                                           │
  │ Types:                                                     │
  │  ├── Full:    size = 100% của physical RAM                 │
  │  │            Sử dụng cho: full hibernate (S4)              │
  │  │            Ghi toàn bộ memory                            │
  │  │                                                         │
  │  └── Reduced: size = 40% của physical RAM (default)        │
  │               Sử dụng cho: Fast Startup only                │
  │               Chỉ ghi session 0 memory                     │
  │                                                           │
  │ Commands:                                                   │
  │   powercfg /h on              ; Bật hibernate               │
  │   powercfg /h off             ; Tắt hibernate (xóa file)    │
  │   powercfg /h /type full      ; Chuyển sang full type       │
  │   powercfg /h /type reduced   ; Chuyển sang reduced type    │
  │   powercfg /h /size 100       ; Full size (100% RAM)        │
  │   powercfg /h /size 40        ; Reduced size (40% RAM)      │
  │   powercfg /h /size 0         ; Minimum possible            │
  │                                                           │
  │ File format (simplified):                                   │
  │  ┌──────────────┐                                          │
  │  │ PO_MEMORY_IMAGE header                                  │
  │  │   Signature: "hibr" hoặc "HIBR"                         │
  │  │   CheckSum                                              │
  │  │   NumPages                                              │
  │  │   PageSize                                              │
  │  │   ImageType: full/reduced                               │
  │  ├──────────────┤                                          │
  │  │ Compressed Memory Pages                                 │
  │  │   (Xpress Huffman compressed)                           │
  │  ├──────────────┤                                          │
  │  │ CPU Context                                             │
  │  │   (registers, MTRR, control regs)                       │
  │  ├──────────────┤                                          │
  │  │ Resume Context                                          │
  │  │   (entry point, page directory)                         │
  │  └──────────────┘                                          │
  └──────────────────────────────────────────────────────────┘
```

### 12.9.3 Sleep States và Modern Standby

```
Windows Power States:
  ┌──────────────────────────────────────────────────────────────┐
  │ State  │ ACPI │ Mô tả                  │ Resume │ Power      │
  ├──────────────────────────────────────────────────────────────┤
  │ Working│ S0   │ Fully on               │ N/A    │ Full       │
  │ Sleep  │ S1   │ CPU stop, RAM powered  │ Fast   │ Low        │
  │ Sleep  │ S2   │ CPU off, RAM powered   │ Fast   │ Lower      │
  │ Sleep  │ S3   │ Suspend to RAM (STR)   │ ~3s    │ Very low   │
  │ Hibern │ S4   │ Suspend to disk        │ ~15s   │ None       │
  │ Off    │ S5   │ Soft off               │ Boot   │ Standby    │
  │ Off    │ G3   │ Mechanical off         │ Boot   │ None       │
  └──────────────────────────────────────────────────────────────┘

  [UPDATE 2026] Modern Standby (S0 Low Power Idle):

  S3 (Traditional Sleep) vs Modern Standby (S0ix):
  ┌────────────────────────────────────────────────────────────┐
  │ S3 (Suspend to RAM):                                       │
  │ ├── CPU và devices OFF                                     │
  │ ├── Chỉ RAM được powered (refresh DRAM)                    │
  │ ├── Không có network activity                              │
  │ ├── Không có background processing                         │
  │ ├── Resume: BIOS re-init devices → OS resume               │
  │ └── Đang bị loại bỏ dần trên modern hardware               │
  ├────────────────────────────────────────────────────────────┤
  │ Modern Standby / Connected Standby (S0ix):                 │
  │ ├── CPU ở lowest power state (C10) nhưng KHÔNG OFF         │
  │ ├── Network vẫn ACTIVE (WiFi/LTE maintain connection)      │
  │ ├── Background tasks vẫn chạy:                             │
  │ │   - Email sync                                           │
  │ │   - VoIP incoming calls                                  │
  │ │   - Push notifications                                   │
  │ │   - Windows Update downloads                             │
  │ ├── "Instant On" — resume gần như ngay lập tức             │
  │ ├── Giống smartphone sleep behavior                         │
  │ ├── Yêu cầu hardware support (DRIPS - Deepest Runtime      │
  │ │   Idle Platform State)                                   │
  │ ├── Hai variants:                                          │
  │ │   - Connected Standby: network maintained                │
  │ │   - Disconnected Standby: network off (tiết kiệm pin)    │
  │ └── Platform phải support S0 Low Power Idle trong FADT      │
  └────────────────────────────────────────────────────────────┘

  Kiểm tra power capabilities:
    powercfg /a                    ; Liệt kê các power states được hỗ trợ
    powercfg /sleepstudy           ; Báo cáo chi tiết về sleep/standby
    powercfg /systempowerreport    ; Báo cáo power tổng hợp
    powercfg /energy               ; Phân tích energy efficiency
    powercfg /batteryreport        ; Báo cáo pin

    :: Kiểm tra Modern Standby support
    powercfg /a
    :: Output: "Standby (S0 Low Power Idle) Network Connected"
    :: → Modern Standby được hỗ trợ và enabled
```

---

## 12.10 Boot Security

### 12.10.1 Measured Boot và TPM

```
Measured Boot — đo lường tính toàn vẹn của boot process:

  TPM PCR (Platform Configuration Register) Assignments:
  ┌──────────────────────────────────────────────────────────────┐
  │ PCR  │ Measured Content                                      │
  ├──────────────────────────────────────────────────────────────┤
  │ 0    │ UEFI firmware code (SEC, PEI, DXE core)               │
  │      │ - Hash của firmware executables                       │
  │ 1    │ UEFI firmware configuration                           │
  │      │ - UEFI Setup settings, hardware config                │
  │ 2    │ Option ROM code (add-in card firmware)                │
  │      │ - RAID controller ROM, network boot ROM               │
  │ 3    │ Option ROM configuration/data                         │
  │ 4    │ MBR/IPL code (legacy) hoặc Boot Manager (UEFI)       │
  │      │ - bootmgfw.efi hash                                   │
  │ 5    │ GPT/Partition table                                   │
  │      │ - Boot partition information                          │
  │ 6    │ Resume from S4 (hibernate) events                    │
  │ 7    │ Secure Boot state và policy                           │
  │      │ - SecureBoot variable (on/off)                        │
  │      │ - PK, KEK, db, dbx content                           │
  │      │ - Separators giữa firmware và OS boot                 │
  │ 8-9  │ winload.efi measurements                              │
  │      │ - ntoskrnl.exe hash                                   │
  │      │ - hal.dll hash                                        │
  │      │ - Boot-start driver hashes                            │
  │ 10   │ Reserved (Boot Manager measurements)                  │
  │ 11   │ BitLocker access control                              │
  │      │ - Used by BitLocker to seal/unseal keys               │
  │      │ - Thay đổi PCR 11 → BitLocker recovery required       │
  │ 12   │ Data events, highly volatile events                   │
  │      │ - Boot data that changes frequently                   │
  │ 13   │ Boot Module Details                                   │
  │      │ - Additional module measurements                      │
  │ 14   │ Boot Authorities                                      │
  │      │ - Certificates used during boot                       │
  │ 23   │ Application support (cho measured launch)             │
  └──────────────────────────────────────────────────────────────┘

  Measured Boot Flow:
    1. UEFI firmware extends PCR 0 với hash của firmware code
    2. Trước khi load mỗi component, hash và extend PCR tương ứng
    3. Extend = PCR_new = SHA-256(PCR_old || measurement)
       → Không thể "undo" — chỉ có thể "add"
    4. Tất cả measurements ghi vào TCG Event Log (binary log)
    5. OS có thể đọc event log để verify

  BitLocker dùng TPM PCRs:
    ├── BitLocker seal VMK (Volume Master Key) vào TPM
    ├── TPM chỉ unseal khi PCR values khớp
    ├── Boot process thay đổi → PCR thay đổi → không unseal
    ├── Default PCRs: 0, 2, 4, 7, 11
    │   → Firmware update thay đổi PCR 0 → BitLocker recovery
    │   → Secure Boot policy thay đổi PCR 7 → recovery
    └── manage-bde -protectors -get C: (xem protectors)

DRTM (Dynamic Root of Trust for Measurement):
  ┌──────────────────────────────────────────────────────────┐
  │ SRTM (Static): đo từ power-on, include tất cả firmware   │
  │   → Trust chain dài, nhiều code phải trust                │
  │                                                           │
  │ DRTM (Dynamic): reset PCRs và bắt đầu lại từ 1 điểm      │
  │   ├── Intel TXT (Trusted Execution Technology):           │
  │   │   - GETSEC[SENTER] instruction                        │
  │   │   - Load ACM (Authenticated Code Module)              │
  │   │   - Reset PCR 17-22                                   │
  │   │   - Đo MLE (Measured Launch Environment)              │
  │   │   - Hypervisor có thể làm MLE                         │
  │   │                                                       │
  │   └── AMD SEV / AMD SKINIT:                               │
  │       - SKINIT instruction                                 │
  │       - Load SLB (Secure Launch Block)                     │
  │       - Reset PCR 17-22                                    │
  │       - Tương tự Intel TXT                                 │
  │                                                           │
  │ [UPDATE 2026] Windows DRTM:                               │
  │   - System Guard Secure Launch (Win 10 1809+)             │
  │   - Sử dụng Intel TXT / AMD SKINIT                        │
  │   - Hypervisor measured launch                             │
  │   - Measurements trong PCR 17-22                           │
  │   - Remote attestation qua Azure Attestation              │
  └──────────────────────────────────────────────────────────┘
```

### 12.10.2 ELAM (Early Launch Anti-Malware)

```
ELAM Driver:
  ├── Boot-start driver đặc biệt load TRƯỚC tất cả drivers khác
  ├── Signed với ELAM certificate (khác với WHQL cert)
  ├── Phải nhỏ, nhanh, reliable (không được crash)
  ├── Nhận callback cho mỗi boot-start driver khác
  └── Đánh giá và phân loại driver

  ELAM Callback flow:
    IoRegisterBootDriverCallback()
    → Mỗi khi boot-start driver được load:
       ELAM nhận callback với:
       ├── Driver image hash
       ├── Driver certificate (publisher info)
       ├── Driver registry key
       └── Driver image name

    ELAM trả về classification:
    ┌──────────────────────────────────────────────────┐
    │ Classification   │ Action                         │
    ├──────────────────────────────────────────────────┤
    │ Known Good       │ Load driver                    │
    │ Known Bad        │ Do NOT load driver             │
    │ Unknown          │ Policy-dependent:              │
    │                  │   Default: Load                │
    │                  │   Strict: Do NOT load          │
    │ Boot Critical    │ ALWAYS load (bất kể đánh giá)  │
    │                  │ Ví dụ: disk, file system driver │
    └──────────────────────────────────────────────────┘

  Windows Defender ELAM: WdBoot.sys
    ├── Load đầu tiên trong boot-start drivers
    ├── Chứa signature database (compact) cho boot drivers
    ├── Evaluate mỗi boot driver trước khi cho DriverEntry() chạy
    └── Nếu phát hiện malicious driver → prevent loading

  ELAM Policy:
    HKLM\SYSTEM\CCS\Control\EarlyLaunch\DriverLoadPolicy
      Values:
        1 = Good only (chỉ load known good)
        3 = Good + Unknown (default)
        7 = Good + Unknown + Bad (load tất cả — testing)
        8 = No signature validation (tắt ELAM)

  Disable ELAM:
    bcdedit /set {current} disableelamdrivers yes
    → CHỈ dùng cho debugging/testing
    → Attacker có thể dùng để bypass ELAM
```

### 12.10.3 Boot Logging và Safe Mode

```
Boot Logging:
  bcdedit /set {current} bootlog yes
  → Log file: %SystemRoot%\ntbtlog.txt

  ntbtlog.txt format:
    Service Pack 1  10 24 2024 15:30:21.325
    Loaded driver \SystemRoot\system32\ntoskrnl.exe
    Loaded driver \SystemRoot\system32\hal.dll
    Loaded driver \SystemRoot\system32\kdcom.dll
    Loaded driver \SystemRoot\system32\mcupdate_GenuineIntel.dll
    Loaded driver \SystemRoot\System32\drivers\werkernel.sys
    Loaded driver \SystemRoot\System32\drivers\CLFS.SYS
    Loaded driver \SystemRoot\System32\drivers\tm.sys
    Loaded driver \SystemRoot\System32\drivers\FLTMGR.SYS
    Loaded driver \SystemRoot\System32\drivers\msrpc.sys
    ...
    Did not load driver \SystemRoot\System32\drivers\suspicious.sys
    ...

  "Did not load" entries → drivers bị ELAM block hoặc load fail

Safe Mode:
  ┌──────────────────────────────────────────────────────────┐
  │ Mode           │ bcdedit command             │ Mô tả      │
  ├──────────────────────────────────────────────────────────┤
  │ Safe Mode      │ /set safeboot minimal       │ Minimum    │
  │ (Minimal)      │                             │ drivers và │
  │                │                             │ services   │
  ├──────────────────────────────────────────────────────────┤
  │ Safe Mode      │ /set safeboot network       │ + Network  │
  │ w/ Networking  │                             │ drivers    │
  ├──────────────────────────────────────────────────────────┤
  │ Safe Mode      │ /set safeboot minimal       │ cmd.exe    │
  │ w/ Cmd Prompt  │ /set safebootalternateshell  │ thay       │
  │                │ yes                         │ explorer   │
  ├──────────────────────────────────────────────────────────┤
  │ DS Repair      │ /set safeboot dsrepair      │ Domain     │
  │ (Server only)  │                             │ Controller │
  │                │                             │ repair     │
  └──────────────────────────────────────────────────────────┘

  Safe Mode chỉ load drivers/services có:
    Registry: HKLM\SYSTEM\CCS\Control\SafeBoot\
      Minimal\   → danh sách cho Safe Mode
      Network\   → danh sách cho Safe Mode w/ Networking
    Mỗi subkey = service/driver/group được phép load

  Safe Mode detection (cho malware hoặc admin tools):
    :: Check if running in Safe Mode
    reg query "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Option" /v OptionValue
    :: 0 = không Safe Mode
    :: 1 = Safe Mode (Minimal)
    :: 2 = Safe Mode with Networking

Boot Debugging Setup:
  :: Network debugging (phổ biến nhất)
  bcdedit /debug on
  bcdedit /dbgsettings net hostip:192.168.1.100 port:50000
  :: → Trả về key (dùng để kết nối từ debugger)

  :: Serial debugging
  bcdedit /dbgsettings serial debugport:1 baudrate:115200

  :: USB debugging
  bcdedit /dbgsettings usb targetname:TargetPC

  :: Local debugging (WinDbg chạy trên cùng máy)
  bcdedit /dbgsettings local

  :: 1394 (FireWire) debugging
  bcdedit /dbgsettings 1394 channel:1

  :: Boot debugger (debug bootmgr/winload)
  bcdedit /set {bootmgr} bootdebug on
  bcdedit /set {current} bootdebug on

Last Known Good Configuration:
  ├── Registry: HKLM\SYSTEM\Select
  │   Current:  ControlSet number hiện tại
  │   Default:  ControlSet sẽ dùng lần boot tới
  │   LastKnownGood: ControlSet cuối cùng boot thành công
  │   Failed:   ControlSet đã fail (nếu có)
  ├── Khi boot thành công: Default = Current
  ├── Khi boot thất bại 2 lần: dùng LastKnownGood
  └── Hiện tại: ít được dùng do WinRE tự động hiệu quả hơn
```

---

## 12.11 Security Implications

### 12.11.1 Bootkit và Rootkit Persistence

```
Boot Process Attack Surface:

  ┌──────────────────────────────────────────────────────────┐
  │ Attack Vector        │ Level    │ Persistence             │
  ├──────────────────────────────────────────────────────────┤
  │ UEFI firmware implant│ Firmware │ Survive disk format,    │
  │                      │          │ OS reinstall, SPI flash │
  │                      │          │ reflash needed          │
  ├──────────────────────────────────────────────────────────┤
  │ UEFI bootkit         │ ESP      │ Survive OS reinstall,   │
  │ (BlackLotus, etc.)   │          │ NOT disk format/wipe    │
  ├──────────────────────────────────────────────────────────┤
  │ VBR/MBR bootkit      │ Boot     │ Legacy BIOS only,       │
  │ (TDL4, Rovnix)       │ Sector   │ survive OS reinstall    │
  ├──────────────────────────────────────────────────────────┤
  │ Boot-start driver    │ Kernel   │ Start=0, load trước     │
  │ rootkit              │          │ most security software   │
  ├──────────────────────────────────────────────────────────┤
  │ Service persistence  │ User/    │ Auto-start service,     │
  │                      │ Kernel   │ survive reboot          │
  ├──────────────────────────────────────────────────────────┤
  │ Run key persistence  │ User     │ Survive reboot,         │
  │                      │          │ per-user or all-users   │
  ├──────────────────────────────────────────────────────────┤
  │ Scheduled task       │ User     │ Flexible triggers,      │
  │                      │          │ survive reboot          │
  └──────────────────────────────────────────────────────────┘

UEFI Bootkit Techniques:
  ┌──────────────────────────────────────────────────────────┐
  │ 1. ESP manipulation:                                      │
  │    ├── Thay thế bootmgfw.efi với malicious version         │
  │    ├── Thêm malicious EFI driver vào ESP                   │
  │    └── Sửa BCD để load malicious bootloader               │
  │                                                           │
  │ 2. UEFI Runtime Driver:                                   │
  │    ├── Install DXE Runtime driver trong ESP                │
  │    ├── Runtime driver tồn tại SAU ExitBootServices()       │
  │    ├── Có thể hook Runtime Services (SetVariable, etc.)    │
  │    └── OS không thể detect/remove (chạy trước OS)         │
  │                                                           │
  │ 3. SPI Flash implant:                                     │
  │    ├── Ghi malicious code vào SPI flash (firmware)          │
  │    ├── Cần bypass SPI write protection                     │
  │    │   - SMM (System Management Mode) vulnerability        │
  │    │   - SPI configuration unlock                          │
  │    ├── Survive: disk format, OS reinstall, disk thay mới   │
  │    └── Chỉ bị xóa khi reflash firmware                     │
  │                                                           │
  │ 4. Secure Boot bypass:                                    │
  │    ├── Sử dụng vulnerable nhưng validly-signed bootloader  │
  │    ├── Exploit vulnerability trong bootloader              │
  │    └── Load unsigned code sau khi bypass                   │
  │                                                           │
  │ [UPDATE 2026] 5. UEFI capsule update abuse:               │
  │    ├── Craft malicious firmware update capsule             │
  │    ├── Dùng UpdateCapsule() runtime service                │
  │    └── Yêu cầu bypass capsule signature verification       │
  └──────────────────────────────────────────────────────────┘

Ví dụ: BlackLotus Attack Chain chi tiết:
  1. Initial access: admin rights (post-exploitation)
  2. Ghi các files lên ESP:
     \EFI\Microsoft\Boot\bootmgfw.efi (backup original)
     \EFI\Microsoft\Boot\bootmgfw.efi  (vulnerable signed Windows bootloader)
     \EFI\Microsoft\Boot\BCD            (modified boot config)
     \EFI\Microsoft\Boot\BCD (modified)
  3. Sửa BCD entry: path → vulnerable bootmgfw.efi
  4. Boot: UEFI → bootmgfw.efi (validly signed, nhưng vulnerable)
  5. Windows Boot Manager vulnerability (CVE-2022-21894) exploited
  6. Malicious UEFI application load (unsigned)
  7. Patch Windows Boot Manager trong memory
  8. Boot Windows "bình thường" nhưng:
     - HVCI disabled
     - Windows Defender Credential Guard disabled
     - BitLocker suspended
  9. Malicious kernel driver load (đã bypass integrity checks)
  10. Runtime persistence: UEFI runtime hooks
```

### 12.11.2 Service Persistence Techniques (Malware)

```
Malware service persistence:

  1. Tạo service mới:
     sc create MalSvc binpath= "C:\mal\malware.exe" start= auto
     → HKLM\SYSTEM\CCS\Services\MalSvc

  2. Modify existing service:
     ├── Thay đổi ImagePath của service hiện có
     ├── Thêm DLL vào ServiceDll của svchost service
     │   HKLM\...\Services\<svc>\Parameters\ServiceDll
     └── Thay đổi DLL search order

  3. Driver service:
     sc create MalDrv type= kernel binpath= "mal.sys" start= boot
     → Load rất sớm, trước AV

  4. BootExecute:
     ├── Thêm entry vào BootExecute value
     ├── Chạy trước services, trước Win32
     └── Native application format (không Win32 API)

  Detection:
  ┌──────────────────────────────────────────────────────────┐
  │ Tool                  │ Cách dùng                         │
  ├──────────────────────────────────────────────────────────┤
  │ Autoruns (Sysinternals)│ Liệt kê tất cả auto-start points│
  │                       │ Verify digital signatures         │
  │                       │ Highlight unsigned entries         │
  ├──────────────────────────────────────────────────────────┤
  │ sc.exe query           │ List running services             │
  │ sc.exe qc <name>       │ Xem config của service            │
  ├──────────────────────────────────────────────────────────┤
  │ reg query              │ Đọc trực tiếp registry             │
  │ HKLM\...\Services\*   │ Tìm services lạ / modified        │
  ├──────────────────────────────────────────────────────────┤
  │ Get-Service (PS)       │ PowerShell service enumeration    │
  │ Get-WmiObject          │ WMI queries cho services           │
  ├──────────────────────────────────────────────────────────┤
  │ sigcheck (Sysinternals)│ Verify signatures của drivers     │
  │ sigcheck -e -u C:\Win\ │ Tìm unsigned executables          │
  └──────────────────────────────────────────────────────────┘
```

### 12.11.3 Boot Forensics

```
Boot Forensics Checklist:

  1. BCD Analysis:
     bcdedit /enum all /v         ; Xem tất cả entries với GUID đầy đủ
     bcdedit /store <BCD_path> /enum all  ; Offline BCD
     :: Tìm: paths lạ, entries thêm vào, testsigning, debug on

  2. ESP Inspection:
     mountvol B: /s              ; Mount ESP (admin required)
     dir B:\EFI /s               ; Liệt kê tất cả files trên ESP
     :: Tìm: files lạ ngoài Microsoft/OEM bootloaders
     :: Verify signatures: sigcheck -a B:\EFI\Microsoft\Boot\*.efi

  3. UEFI Variable Extraction:
     :: PowerShell (admin):
     Get-SecureBootUEFI -Name PK   ; Lấy Platform Key
     Get-SecureBootUEFI -Name KEK  ; Lấy KEK
     Get-SecureBootUEFI -Name db   ; Lấy authorized database
     Get-SecureBootUEFI -Name dbx  ; Lấy forbidden database
     Confirm-SecureBootUEFI        ; Verify Secure Boot state

     :: Linux:
     efivar -l                     ; List tất cả UEFI variables
     efivar -d -n <guid>-<name>    ; Dump variable content

  4. Boot Log Analysis:
     type %SystemRoot%\ntbtlog.txt | findstr "Did not load"
     :: Tìm drivers không được load và tại sao

  5. Driver Signature Verification:
     :: Verify tất cả kernel drivers
     sigcheck -accepteula -u -e C:\Windows\System32\drivers\
     :: -u: chỉ hiện unsigned files
     :: Tìm: unsigned drivers, test-signed drivers

  6. Service Registry Analysis:
     :: Export và review services
     reg export HKLM\SYSTEM\CurrentControlSet\Services C:\services.reg
     :: Tìm: ImagePath đến locations lạ
     :: Tìm: ServiceDll không phải system DLL
     :: Tìm: BootExecute entries lạ

  7. TPM PCR Verification:
     :: PowerShell (admin, Windows 10+):
     Get-Tpm                       ; TPM status
     Get-TpmEndorsementKeyInfo     ; TPM EK info
     :: Hoặc dùng tpm.msc

  8. Event Log Review:
     :: Boot/shutdown events
     Get-WinEvent -FilterHashtable @{LogName='System';ID=12,13} |
       Select TimeCreated, Message | Format-Table
     :: ID 12: OS started, ID 13: OS shutdown

     :: Audit events liên quan boot
     Get-WinEvent -FilterHashtable @{
       LogName='Microsoft-Windows-CodeIntegrity/Operational'
     } | Where { $_.LevelDisplayName -eq 'Warning' -or
                  $_.LevelDisplayName -eq 'Error' }
```

---

## 12.12 Experiments

### Experiment 12.1: Boot Trace với WPR

```cmd
:: Capture boot trace
wpr -start boot -filemode
:: ... reboot system ...
wpr -stop C:\BootTrace.etl

:: Phân tích với WPA (Windows Performance Analyzer)
wpa.exe C:\BootTrace.etl
:: Xem: Boot Phases, Process Lifetimes, Disk I/O, CPU Usage

:: Hoặc dùng xbootmgr (Windows Performance Toolkit)
xbootmgr -trace boot -resultPath C:\BootTrace
```

### Experiment 12.2: Service Startup Order và Dependencies

```powershell
# Xem boot-start drivers (Start=0)
Get-WmiObject Win32_SystemDriver |
  Where-Object { $_.StartMode -eq 'Boot' } |
  Select-Object Name, DisplayName, PathName |
  Sort-Object Name | Format-Table -AutoSize

# Xem service dependencies dạng đồ họa
sc.exe qc Dnscache
sc.exe enumdepend Dnscache

# Xem tất cả services và start types
Get-Service | Select-Object Name, Status, StartType |
  Sort-Object StartType, Name | Format-Table

# Xem svchost groups
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost" |
  Format-List
```

### Experiment 12.3: Boot Log và Driver Analysis

```cmd
:: Enable boot log
bcdedit /set {current} bootlog yes
:: Reboot
:: Kiểm tra boot log:
type %SystemRoot%\ntbtlog.txt

:: Phân tích boot log:
findstr "Did not load" %SystemRoot%\ntbtlog.txt
findstr "Loaded driver" %SystemRoot%\ntbtlog.txt | find /c /v ""

:: Verify driver signatures
sigcheck -accepteula -e -u C:\Windows\System32\drivers\

:: Xem ELAM status
reg query "HKLM\SYSTEM\CurrentControlSet\Control\EarlyLaunch" /v DriverLoadPolicy
```

### Experiment 12.4: BCD và Secure Boot Analysis

```cmd
:: Export BCD cho analysis
bcdedit /enum all /v > C:\bcd_dump.txt

:: Kiểm tra Secure Boot state
powershell -c "Confirm-SecureBootUEFI"

:: Mount ESP và kiểm tra
mountvol B: /s
dir B:\EFI /s /b
sigcheck -accepteula -a B:\EFI\Microsoft\Boot\bootmgfw.efi

:: Kiểm tra TPM
tpm.msc
:: hoặc PowerShell:
powershell -c "Get-Tpm"
```

### Experiment 12.5: Shutdown Event Analysis

```powershell
# Xem shutdown/boot events
Get-WinEvent -FilterHashtable @{
  LogName = 'System'
  ID = 12, 13, 41, 1074, 6005, 6006, 6008, 6009
} -MaxEvents 50 |
  Select-Object TimeCreated, Id,
    @{N='Message'; E={$_.Message.Split("`n")[0]}} |
  Format-Table -AutoSize

# Xem uptime
(Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime

# Xem Fast Startup status
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled
```

---

## 12.13 Tóm Tắt

| Khái niệm | Điểm chính |
|-----------|------------|
| UEFI Boot Phases | SEC (CPU init, CAR) → PEI (memory init, HOBs) → DXE (drivers, services tables) → BDS (boot selection) → TSL (bootloader) |
| Secure Boot | PK → KEK → db/dbx hierarchy, Authenticode verification, bypass history (BlackLotus, BootHole) |
| BCD Store | Registry hive, object types (boot mgr, OS loader, resume), bcdedit management |
| Windows Boot Loader | winload.efi: load kernel, HAL, drivers, init hypervisor, ExitBootServices |
| Kernel Phase 0 | Single CPU: HAL, dispatcher, Object/Security/Memory/Process/PnP/IO managers init |
| Kernel Phase 1 | Multi CPU: APs started, full executive init, driver loading, PnP enumeration |
| smss.exe | First user-mode process, BootExecute, KnownDlls, paging files, create sessions |
| Service Startup | SCM, dependency DAG, group order, parallel start, delayed auto-start, trigger start |
| svchost.exe | Service hosting, group model, per-service split (Win10 >= 3.5GB) |
| User Logon | Credential Providers → LSA (Kerberos/NTLM/CloudAP) → Token → Profile → Shell |
| Shutdown | WM_QUERYENDSESSION → WM_ENDSESSION → service shutdown → kernel flush → power off |
| Fast Startup | Hybrid shutdown: hibernate session 0, resume on boot, faster boot |
| Hibernate | Full memory save to hiberfil.sys, resume via winresume.efi |
| Modern Standby | S0ix, network maintained, instant-on, thay thế S3 |
| Measured Boot | TPM PCR measurements, remote attestation, BitLocker integration |
| ELAM | Early boot driver classification, boot-start driver security |
| Boot Security | DRTM, Secure Boot, boot logging, safe mode, boot debugging |
| Bootkit/Rootkit | UEFI implants, ESP manipulation, VBR infection, Secure Boot bypass |
| Boot Forensics | BCD analysis, ESP inspection, UEFI variable extraction, driver verification |

---

## Kết Luận

Bộ tài liệu 12 chương này bao quát kiến trúc nội bộ Windows từ boot process đến shutdown,
từ user-mode API đến kernel data structures. Với kiến thức này, bạn có thể:

- **Debug** hệ thống hiệu quả hơn bằng WinDbg, ETW, Sysinternals
- **Phân tích bảo mật**: hiểu attack surface, privilege escalation, credential theft, boot persistence
- **Phát triển drivers**: hiểu I/O model, IRQL, pool management, PnP
- **Tối ưu hiệu năng**: working sets, cache, scheduling, boot optimization
- **Nghiên cứu malware**: hiểu persistence mechanisms, bootkit/rootkit techniques, boot forensics
- **Ứng cứu sự cố**: boot troubleshooting, safe mode, WinRE, startup repair

Tài liệu được cập nhật đến Windows 11 24H2 / Server 2025 (2026).
Các mục đánh dấu **[UPDATE 2026]** là nội dung mới so với sách gốc Windows Internals 7th Edition.
