# Chapter 9: Công Nghệ Ảo Hóa (Virtualization Technologies)

> Chương này bao gồm: hardware virtualization extensions (VT-x/AMD-V), VMCS deep dive,
> SLAT/EPT internals, Hyper-V architecture, Virtual Trust Levels (VBS/VTL),
> VMBus protocol, Windows Containers, GPU-PV, bảo mật ảo hóa, và debug techniques.
> Dành cho security researcher cần hiểu sâu về cơ chế ảo hóa của Windows.

---

## 9.1 Hardware Virtualization Extensions

### 9.1.1 Tổng Quan VT-x / AMD-V

CPU hiện đại hỗ trợ ảo hóa bằng phần cứng thông qua hai chế độ hoạt động:

```
Without Virtualization:
  Ring 3: User applications
  Ring 0: OS Kernel
  -> Kernel có TOÀN QUYỀN kiểm soát phần cứng

With Virtualization (VMX Operation):
  VMX Root Mode (Host/Hypervisor):
    Ring 3: Host user-mode
    Ring 0: Hypervisor kernel     <-- Quyền cao nhất
  VMX Non-Root Mode (Guest):
    Ring 3: Guest applications
    Ring 0: Guest OS kernel       <-- TƯỞNG RẰNG mình có toàn quyền
                                  <-- Lệnh nhạy cảm -> VM Exit -> hypervisor xử lý

Transition:
  VM Entry: Root -> Non-Root (hypervisor trao quyền cho guest)
  VM Exit:  Non-Root -> Root (guest gặp lệnh nhạy cảm, CPU trap về hypervisor)
```

Khi bật VMX operation, CPU hoạt động ở 2 chế độ hoàn toàn tách biệt. Guest OS
chạy trong Non-Root mode và không thể phát hiện được rằng mình đang bị ảo hóa
(trừ khi sử dụng timing side-channels hoặc CPUID checks).

### 9.1.2 VMX Instructions (Tập Lệnh VMX)

Đây là các instruction đặc biệt chỉ có thể thực thi trong VMX Root mode:

```
VMX Lifecycle Instructions:
  VMXON   - Bật VMX operation, CPU chuyển sang VMX Root mode
            Yêu cầu: CR4.VMXE = 1, VMXON region (4KB aligned)
            Sau VMXON, CPU ở Root mode, chưa có VMCS nào active

  VMXOFF  - Tắt VMX operation, CPU trở lại normal mode
            Chỉ thực hiện được trong Root mode
            Thường dùng khi hypervisor shutdown

VMCS Management Instructions:
  VMCLEAR   - Khởi tạo/reset một VMCS region
              Đặt launch state = "clear"
              Đồng bộ VMCS data từ CPU cache về memory
              Cần thiết trước khi migrate VMCS sang CPU khác

  VMPTRLD   - Load VMCS pointer, đặt VMCS này làm "current" cho CPU hiện tại
              Mỗi logical processor chỉ có 1 current VMCS
              VMCS được load sẽ ở trạng thái "active"

  VMREAD    - Đọc một field từ current VMCS
              Syntax: VMREAD dest, encoding
              Encoding = 32-bit identifier cho mỗi field

  VMWRITE   - Ghi một field vào current VMCS
              Syntax: VMWRITE encoding, source
              Một số field là read-only (VM-exit information fields)

VM Execution Instructions:
  VMLAUNCH  - Khởi động guest từ VMCS đang ở trạng thái "clear"
              Thực hiện VM Entry lần đầu tiên
              VMCS launch state chuyển sang "launched"

  VMRESUME  - Tiếp tục chạy guest từ VMCS đã "launched"
              Dùng sau khi xử lý VM Exit xong
              Nhanh hơn VMLAUNCH vì không cần kiểm tra toàn bộ VMCS

Guest-to-Host Communication:
  VMCALL    - Guest gọi hypercall tới hypervisor
              Tạo VM Exit với reason = VMCALL (18)
              Dùng để guest yêu cầu dịch vụ từ hypervisor

  INVEPT    - Invalidate EPT TLB entries
              Dùng khi thay đổi EPT page tables
              2 loại: single-context và all-contexts

  INVVPID   - Invalidate TLB entries theo VPID (Virtual Processor ID)
              Tránh flush toàn bộ TLB khi switch VM
```

```
VMX Lifecycle Flow:

  Normal CPU Mode
       |
       v
  [VMXON] -----> VMX Root Mode (hypervisor đang chạy)
       |              |
       |         [VMCLEAR + VMPTRLD] -----> VMCS đã setup
       |              |
       |         [VMWRITE x N] -----> Cấu hình VMCS fields
       |              |
       |         [VMLAUNCH] -----> Guest bắt đầu chạy (VMX Non-Root)
       |              |                    |
       |              |            [VM Exit xảy ra]
       |              |                    |
       |              |<------- CPU trở về Root Mode
       |              |
       |         [Xử lý VM Exit]
       |              |
       |         [VMRESUME] -----> Guest tiếp tục chạy
       |              |                    |
       |              |            [VM Exit tiếp theo]
       |              |                    |
       |              |<------- CPU trở về Root Mode
       |              |
       |         ... (lặp lại) ...
       |              |
       |         [VMCLEAR] -----> Đóng VMCS
       |              |
  [VMXOFF] <----- Tắt VMX operation
       |
       v
  Normal CPU Mode
```

### 9.1.3 VMCS (Virtual Machine Control Structure) Chi Tiết

VMCS là cấu trúc 4KB chứa toàn bộ trạng thái của một virtual processor.
Mỗi vCPU có một VMCS riêng. VMCS được CPU đọc/ghi tự động khi VM Entry/Exit.

```
VMCS Layout (4KB region):
  Offset 0x000: VMCS revision identifier (32-bit)
  Offset 0x004: VMX-abort indicator
  Offset 0x008: VMCS data (phần còn lại)

VMCS Field Categories:
  +---------------------------------------------+
  | 1. Guest-State Area                          |
  |    Trạng thái CPU của guest, được load khi   |
  |    VM Entry, được save khi VM Exit           |
  +---------------------------------------------+
  | 2. Host-State Area                           |
  |    Trạng thái CPU của host, được load khi    |
  |    VM Exit                                   |
  +---------------------------------------------+
  | 3. VM-Execution Control Fields               |
  |    Cấu hình những gì gây ra VM Exit          |
  +---------------------------------------------+
  | 4. VM-Exit Control Fields                    |
  |    Cấu hình hành vi khi VM Exit              |
  +---------------------------------------------+
  | 5. VM-Entry Control Fields                   |
  |    Cấu hình hành vi khi VM Entry             |
  +---------------------------------------------+
  | 6. VM-Exit Information Fields (read-only)    |
  |    Thông tin về lý do VM Exit                 |
  +---------------------------------------------+
```

#### Guest-State Area

```
Guest-State Area - CPU registers được save/restore tự động:

  Control Registers:
    CR0, CR3, CR4           - Page table base, CPU features
    DR7                     - Debug registers
    
  Segment Registers (cho mỗi segment CS/SS/DS/ES/FS/GS/LDTR/TR):
    Selector                - Segment selector (16-bit)
    Base address            - Base (64-bit)
    Segment limit           - Limit (32-bit)
    Access rights           - Type, DPL, Present, etc.
    
  General-Purpose Registers:
    RSP, RIP, RFLAGS        - Stack, instruction pointer, flags
    
  MSRs tự động save/restore:
    IA32_DEBUGCTL
    IA32_SYSENTER_CS/ESP/EIP
    IA32_PERF_GLOBAL_CTRL
    IA32_PAT
    IA32_EFER
    IA32_BNDCFGS
    
  Other:
    GDTR, IDTR (base + limit)
    Guest activity state (active, HLT, shutdown, wait-for-SIPI)
    Guest interruptibility state
    Pending debug exceptions
    VMCS link pointer (cho VMCS shadowing / nested virt)
    Guest interrupt status (virtual APIC)
```

#### Host-State Area

```
Host-State Area - CPU state được load khi VM Exit:

  Control Registers: CR0, CR3, CR4
  Segment Selectors: CS, SS, DS, ES, FS, GS, TR
  Base addresses: FS base, GS base, TR base, GDTR base, IDTR base
  MSRs: IA32_SYSENTER_CS/ESP/EIP, IA32_PERF_GLOBAL_CTRL, IA32_PAT, IA32_EFER
  RSP, RIP  <- RIP = địa chỉ của VM Exit handler trong hypervisor

  Lưu ý: Host-State không lưu RFLAGS, LDTR, hay general-purpose registers
  (hypervisor phải tự save/restore chúng)
```

#### VM-Execution Control Fields (Quan trọng cho Security)

```
Primary Processor-Based VM-Execution Controls (32-bit):
  Bit  2: Interrupt-window exiting
  Bit  3: Use TSC offsetting (ẩn thời gian thật của guest)
  Bit  7: HLT exiting
  Bit  9: INVLPG exiting
  Bit 10: MWAIT exiting
  Bit 11: RDPMC exiting
  Bit 12: RDTSC exiting
  Bit 15: CR3-load exiting      <- Phát hiện guest switch process
  Bit 16: CR3-store exiting
  Bit 19: CR8-load exiting      <- Quản lý APIC priority
  Bit 20: CR8-store exiting
  Bit 21: Use TPR shadow
  Bit 22: NMI-window exiting
  Bit 23: MOV-DR exiting        <- Debug register monitoring
  Bit 24: Unconditional I/O exiting
  Bit 25: Use I/O bitmaps       <- Chọn lọc I/O port nào gây exit [*]
  Bit 28: Use MSR bitmaps       <- Chọn lọc MSR nào gây exit [*]
  Bit 29: MONITOR exiting
  Bit 30: PAUSE exiting
  Bit 31: Activate secondary controls

Secondary Processor-Based VM-Execution Controls (32-bit):
  Bit  0: Virtualize APIC accesses
  Bit  1: Enable EPT             <- SLAT
  Bit  2: Descriptor-table exiting (LGDT/LIDT/LLDT/LTR)
  Bit  3: Enable RDTSCP
  Bit  4: Virtualize x2APIC mode
  Bit  5: Enable VPID            <- TLB tagging per-VM
  Bit  6: WBINVD exiting
  Bit  7: Unrestricted guest     <- Guest có thể chạy real mode
  Bit  8: APIC-register virtualization
  Bit  9: Virtual-interrupt delivery
  Bit 10: PAUSE-loop exiting
  Bit 11: RDRAND exiting
  Bit 12: Enable INVPCID
  Bit 13: Enable VM functions
  Bit 14: VMCS shadowing         <- Nested virtualization
  Bit 15: Enable ENCLS exiting   <- SGX control
  Bit 18: Enable EPT violation #VE
  Bit 20: Enable XSAVES/XRSTORS
  Bit 22: Mode-based execute control (MBEC) [*]

[*] = Đặc biệt quan trọng cho security researcher
```

#### MSR Bitmaps và I/O Bitmaps (Security-Critical)

```
MSR Bitmaps (4KB x 2 = 8KB):
  Kiểm soát MSR nào gây VM Exit khi guest đọc/ghi
  
  MSR Bitmap Layout:
    Page 1 (Read bitmap):
      Offset 0x000-0x3FF: MSR 0x00000000 - 0x00001FFF (1 bit per MSR)
      Offset 0x400-0x7FF: MSR 0xC0000000 - 0xC0001FFF
    Page 2 (Write bitmap):
      Offset 0x800-0xBFF: MSR 0x00000000 - 0x00001FFF
      Offset 0xC00-0xFFF: MSR 0xC0000000 - 0xC0001FFF
      
  Bit = 1: RDMSR/WRMSR của MSR đó gây VM Exit
  Bit = 0: Cho phép guest đọc/ghi trực tiếp (không VM Exit)
  
  MSRs quan trọng cần intercept:
    IA32_SYSENTER_EIP (0x176)  - System call entry point
    IA32_LSTAR (0xC0000082)    - SYSCALL entry (64-bit)
    IA32_STAR (0xC0000081)     - SYSCALL selectors
    IA32_EFER (0xC0000080)     - Extended Feature Enable
    IA32_FS_BASE (0xC0000100)  - Per-thread data pointer
    IA32_KERNEL_GS_BASE (0xC0000102) - SwapGS target

I/O Bitmaps (4KB x 2 = 8KB):
  Kiểm soát I/O port nào gây VM Exit
  
  Bitmap A: Ports 0x0000 - 0x7FFF
  Bitmap B: Ports 0x8000 - 0xFFFF
  
  Bit = 1: IN/OUT trên port đó gây VM Exit
  Bit = 0: Cho phép guest truy cập trực tiếp
  
  I/O ports quan trọng:
    0x60, 0x64: PS/2 keyboard controller
    0xCF8-0xCFF: PCI configuration space
    0x3F8: COM1 serial port
    0x70-0x71: CMOS/RTC

Exception Bitmap (32-bit):
  Mỗi bit tương ứng với một exception vector (0-31)
  Bit = 1: Exception đó gây VM Exit thay vì deliver cho guest
  
  Vector 1:  #DB (Debug)         - Intercept debug events
  Vector 3:  #BP (Breakpoint)    - Intercept INT 3
  Vector 6:  #UD (Undefined)     - Bắt opcode không hợp lệ
  Vector 14: #PF (Page Fault)    - Page fault monitoring
  Vector 18: #MC (Machine Check)

CR Access Control:
  CR0 guest/host mask:  Bit = 1 -> guest đọc/ghi bit đó thì thấy shadow value
  CR0 read shadow:      Giá trị guest "thấy" khi đọc masked bits
  CR4 guest/host mask:  Tương tự
  CR4 read shadow:      Tương tự
  
  Ví dụ: Ẩn CR4.VMXE khỏi guest
    CR4 guest/host mask bit 13 = 1 (mask VMXE)
    CR4 read shadow bit 13 = 0 (guest thấy VMXE = 0)
    -> Guest đọc CR4 sẽ thấy VMXE = 0 (không biết VMX đang bật)
    -> Guest ghi CR4 với VMXE = 1 sẽ gây VM Exit
```

### 9.1.4 VM Exit Reasons (Mã Lý Do)

```
VM Exit Reason Codes (quan trọng cho debug và security research):

  Code  Name                          Ghi chú
  ----  ----                          -------
  0     Exception or NMI              Exception xảy ra (xem exception bitmap)
  1     External interrupt            Hardware interrupt
  2     Triple fault                  Guest crash
  3     INIT signal                   
  7     Interrupt window              
  9     Task switch                   Guest thực hiện task switch
  10    CPUID                         Guest chạy CPUID
  12    HLT                           Guest chạy HLT
  13    INVD                          
  14    INVLPG                        TLB invalidation
  15    RDPMC                         Performance counter read
  16    RDTSC                         Timestamp counter read
  18    VMCALL                        Guest gọi hypercall
  19    VMCLEAR                       Nested: guest VMCLEAR
  20    VMLAUNCH                      Nested: guest VMLAUNCH
  21    VMPTRLD                       Nested: guest VMPTRLD
  22    VMPTRST                       Nested: guest VMPTRST
  23    VMREAD                        Nested: guest VMREAD
  24    VMRESUME                      Nested: guest VMRESUME
  25    VMWRITE                       Nested: guest VMWRITE
  26    VMXOFF                        Nested: guest VMXOFF
  27    VMXON                         Nested: guest VMXON
  28    CR access                     Guest đọc/ghi control register
  29    MOV DR                        Guest đọc/ghi debug register
  30    I/O instruction               IN/OUT (xem I/O bitmap)
  31    RDMSR                         Guest đọc MSR (xem MSR bitmap)
  32    WRMSR                         Guest ghi MSR
  33    VM-entry failure (guest)      VMCS guest state invalid
  36    MWAIT                         
  37    Monitor trap flag             Single-step trong guest
  39    MONITOR                       
  40    PAUSE                         Spin-loop detection
  41    VM-entry failure (machine-check) Machine-check event
  43    TPR below threshold           Virtual APIC
  44    APIC access                   APIC page access
  45    Virtualized EOI               
  46    GDTR/IDTR access              Descriptor table
  47    LDTR/TR access                
  48    EPT violation                 SLAT permission failure [*]
  49    EPT misconfiguration          EPT entry invalid [*]
  50    INVEPT                        Nested
  51    RDTSCP                        
  52    VMX preemption timer          Timer expired
  53    INVVPID                       Nested
  55    XSETBV                        Extended state
  56    APIC write                    
  57    RDRAND                        
  58    INVPCID                       
  59    VMFUNC                        VM functions
  60    ENCLS                         SGX
  61    RDSEED                        
  63    XSAVES                        
  64    XRSTORS                       

[*] = EPT violation (48) và EPT misconfiguration (49) là hai exit reason
      quan trọng nhất cho SLAT-based security mechanisms (HVCI, memory monitoring)
```

### 9.1.5 Hardware Requirements cho Hyper-V

| Feature | Intel | AMD | Mục đích |
|---------|-------|-----|----------|
| Virtualization | VT-x | AMD-V (SVM) | CPU virtualization |
| SLAT | EPT | NPT (RVI) | Memory virtualization |
| IOMMU | VT-d | AMD-Vi | DMA protection |
| SR-IOV | VT-c | Same | Direct NIC access |
| MBEC | Mode-based Execute Control | GMET | User/kernel exec split |
| VPID | Virtual Processor ID | ASID | TLB optimization |
| Unrestricted Guest | Yes (needs EPT) | Always | Real mode in guest |
| Posted Interrupts | Yes | AVIC | Interrupt virtualization |

**[UPDATE 2026]** Windows 11 24H2 yêu cầu tối thiểu: VT-x/AMD-V + SLAT + IOMMU + TPM 2.0.
VBS và HVCI được bật mặc định trên cài đặt mới.

---

## 9.2 SLAT / EPT Deep Dive

### 9.2.1 Tại Sao Cần SLAT

```
Vấn đề với Shadow Page Tables (trước SLAT):

  Guest:  Guest VA --[Guest PT]--> Guest PA (GPA)
  Hypervisor phải duy trì Shadow Page Tables:
    Shadow PT: Guest VA --direct--> Host PA (HPA)
    
  Mỗi khi guest thay đổi page table (CR3 write, PTE update):
    -> VM Exit
    -> Hypervisor cập nhật shadow PT
    -> VM Resume
    -> Chi phí: ~1000-5000 cycles mỗi lần
    
  Guest có context switch (process switch) liên tục
    -> Mỗi switch = thay đổi CR3 = VM Exit
    -> Cực kỳ chậm!

Giải pháp: SLAT (EPT/NPT)
  CPU thực hiện 2 bước dịch địa chỉ bằng PHẦN CỨNG:
  
  Guest VA --[Guest PT]--> GPA --[EPT/NPT]--> HPA
  
  Không cần VM Exit cho page table changes
  Chỉ cần VM Exit khi EPT violation (permission check fail)
```

### 9.2.2 EPT Page Table Structure

EPT sử dụng cấu trúc paging 4 cấp tương tự x86-64 paging:

```
EPT Paging Structure (4-level, tương tự regular x86-64):

  EPTP (EPT Pointer, trong VMCS)
    |
    v
  PML4 (Page Map Level 4)
    |  512 entries, mỗi entry trỏ tới 1 PDPT
    v
  PDPT (Page Directory Pointer Table)
    |  512 entries, mỗi entry trỏ tới 1 PD (hoặc 1GB huge page)
    v
  PD (Page Directory)
    |  512 entries, mỗi entry trỏ tới 1 PT (hoặc 2MB large page)
    v
  PT (Page Table)
       512 entries, mỗi entry trỏ tới 1 4KB page

Address Translation:
  GPA [47:39] -> PML4 index (9 bits)
  GPA [38:30] -> PDPT index (9 bits)
  GPA [29:21] -> PD index   (9 bits)
  GPA [20:12] -> PT index   (9 bits)
  GPA [11:0]  -> Page offset (12 bits)
```

### 9.2.3 EPT PTE Format (Chi Tiết Từng Bit)

```
EPT Page Table Entry (64-bit):

  Bit  Name           Mục đích
  ---  ----           --------
  0    Read (R)       1 = Cho phép đọc GPA này
  1    Write (W)      1 = Cho phép ghi GPA này
  2    Execute (X)    1 = Cho phép thực thi từ GPA này
                      (MBEC off: áp dụng cho cả user và supervisor)
  [5:3] EPT Memory Type
         0 = UC (Uncacheable)
         1 = WC (Write-Combining)
         4 = WT (Write-Through)
         5 = WP (Write-Protected)
         6 = WB (Write-Back)
  6    Ignore PAT     1 = Bỏ qua guest PAT, dùng EPT memory type
  7    Large page     1 = Đây là 2MB page (ở PD level)
                      hoặc 1GB page (ở PDPT level)
  8    Accessed (A)   1 = Page đã được truy cập (nếu enable)
  9    Dirty (D)      1 = Page đã được ghi (nếu enable)
  10   Execute for    1 = User-mode execute allowed (MBEC)
       user-mode (XU) 0 = User-mode execute denied
                      (Chỉ có ý nghĩa khi MBEC enabled)
  [11]  Reserved
  [N-1:12] Physical address of next level / page frame
           (N = MAXPHYADDR, thường là 48 hoặc 52)
  [51:N]  Reserved (phải = 0)
  52-62   Reserved / available for software
  63      Suppress #VE
          1 = EPT violation trên page này gây VM Exit bình thường
          0 = EPT violation có thể được chuyển thành #VE exception
              (virtualization exception, vector 20)

EPTP (EPT Pointer) format:
  [2:0]   EPT paging structure type (0 = UC, 6 = WB)
  [5:3]   EPT page walk length - 1 (3 = 4-level)
  [6]     Enable accessed/dirty flags
  [11:7]  Reserved
  [N-1:12] Physical address của EPT PML4
```

### 9.2.4 EPT Violations vs EPT Misconfigurations

```
EPT Violation (VM Exit reason 48):
  Xảy ra khi: Guest truy cập memory mà EPT permissions không cho phép
  Ví dụ: Guest ghi vào page có EPT.Write = 0
  
  VM Exit Information:
    Exit qualification cho biết:
      Bit 0: Data read caused violation
      Bit 1: Data write caused violation  
      Bit 2: Instruction fetch caused violation
      Bit 3: EPT entry readable
      Bit 4: EPT entry writable
      Bit 5: EPT entry executable
      Bit 6: EPT entry user-mode executable (MBEC)
      Bit 7: Guest linear address valid
      Bit 8: Caused by GPA access (vs paging structure)
      Bit 12: NMI unblocking due to IRET
      Bit 13: Shadow-stack access
    
    Guest-physical address (64-bit): GPA gây violation
    Guest-linear address (64-bit): Guest VA (nếu valid)

EPT Misconfiguration (VM Exit reason 49):
  Xảy ra khi: EPT entry có cấu hình KHÔNG HỢP LỆ
  Ví dụ:
    - EPT PTE có Write = 1 nhưng Read = 0 (không cho phép)
    - Reserved bits được set
    - Memory type không hợp lệ
  Đây là LỖI CỦA HYPERVISOR, không phải lỗi của guest!
  
  So sánh:
  +-------------------+---------------------------+---------------------------+
  | Tình huống        | EPT Violation             | EPT Misconfiguration      |
  +-------------------+---------------------------+---------------------------+
  | Nguyên nhân       | Guest truy cập không phép | EPT entry sai format      |
  | Lỗi của ai        | Có thể là có ý (monitor)  | Lỗi của hypervisor        |
  | Guest address     | Có (GPA + GVA)            | Có (GPA)                  |
  | Xử lý             | Hypervisor quyết định      | Fix EPT entry, retry      |
  | Security dùng     | Memory monitoring, hook    | Không (đây là bug)        |
  +-------------------+---------------------------+---------------------------+
```

### 9.2.5 Dùng EPT cho Security Monitoring

EPT là công cụ cực kỳ mạnh cho security researcher:

```
Kỹ thuật 1: Stealth Hooking (EPT Hook / Invisible Hook)
  Mục đích: Hook hàm kernel MÀ KHÔNG thay đổi code gốc

  Nguyên lý:
    - Tạo 2 bản sao của page chứa hàm cần hook:
      Page A (Original): Code gốc, không thay đổi
      Page B (Hooked):   Code đã patch (JMP to hook handler)
    
    - Cấu hình EPT:
      Khi EXECUTE: EPT trỏ tới Page B (hooked code)
      Khi READ:    EPT trỏ tới Page A (original code)
    
  Flow:
    1. Guest execute function -> EPT trỏ tới Page B
    2. CPU chạy hooked code -> nhảy tới hook handler
    3. Guest đọc (integrity check) -> EPT trỏ tới Page A
    4. Guest thấy original code -> KHÔNG PHÁT HIỆN bị hook!
    
  Lưu ý: Cần dùng Execute-only EPT pages (R=0, W=0, X=1)
  Hoặc dùng MBEC để tách user/kernel execute

  +------------------+     +-------------------+
  | EPT Entry cho    |     | EPT Entry cho     |
  | EXECUTE access:  |     | READ access:      |
  | HPA = Page B     |     | HPA = Page A      |
  | (hooked code)    |     | (original code)   |
  +------------------+     +-------------------+
         |                        |
         v                        v
  +--------------+         +--------------+
  | Page B:      |         | Page A:      |
  | JMP hook_fn  |         | original     |
  | ...          |         | code intact  |
  +--------------+         +--------------+

Kỹ thuật 2: Memory Access Tracking
  Mục đích: Theo dõi khi nào một vùng nhớ bị đọc/ghi/execute

  1. Đặt EPT permissions = No Access (R=0, W=0, X=0)
  2. Guest truy cập vùng nhớ đó -> EPT Violation -> VM Exit
  3. Hypervisor log thông tin: GPA, GVA, access type, RIP
  4. Tạm thời grant access (đặt permission = cho phép)
  5. Bật MTF (Monitor Trap Flag) để single-step 1 instruction
  6. VM Resume -> Guest thực hiện 1 instruction -> VM Exit (MTF)
  7. Restore EPT = No Access lại
  8. VM Resume -> Tiếp tục theo dõi
  
  Ứng dụng:
    - Theo dõi SSDT modifications
    - Phát hiện unauthorized kernel memory access
    - Monitor sensitive data structures (PEB, TEB, EPROCESS)
    - Phát hiện rootkit đang patch kernel

Kỹ thuật 3: Code Integrity Enforcement (HVCI-style)
  1. Tất cả kernel code pages: EPT = R + X (không có W)
  2. Tất cả kernel data pages: EPT = R + W (không có X)
  3. Guest muốn ghi vào code page -> EPT Violation -> denied
  4. Guest muốn execute data page -> EPT Violation -> denied
  -> W^X enforcement bằng phần cứng, kernel không thể bypass!
```

### 9.2.6 Intel MBEC (Mode-Based Execute Control)

```
MBEC (Mode-Based Execute Control for EPT):
  Vấn đề: EPT chỉ có 1 Execute bit, áp dụng cho CẢ user-mode và kernel-mode
  
  Với MBEC:
    Bit 2 (X):  Supervisor-mode execute (Ring 0)
    Bit 10 (XU): User-mode execute (Ring 3)
    
  Ví dụ: HVCI với MBEC
    Kernel code page: X = 1, XU = 0
      -> Kernel có thể execute (đã verify signed)
      -> User-mode KHÔNG thể execute kernel page
    
    User code page: X = 0, XU = 1
      -> User-mode có thể execute
      -> Không cho phép kernel execute user page (SMEP enforcement via EPT)
    
  AMD tương đương: GMET (Guest Mode Execute Trap)
  
  Không có MBEC:
    Hypervisor phải dùng #PF interception hoặc CR3-load exiting
    để phân biệt user/kernel context -> chậm hơn nhiều

  +--------------------+--------+--------+--------+
  | Trạng thái EPT     |  Read  | Write  | Execute|
  +--------------------+--------+--------+--------+
  | Kernel code page   | R=1    | W=0    | X=1    |
  |                    |        |        | XU=0   |
  +--------------------+--------+--------+--------+
  | Kernel data page   | R=1    | W=1    | X=0    |
  |                    |        |        | XU=0   |
  +--------------------+--------+--------+--------+
  | User code page     | R=1    | W=0    | X=0    |
  |                    |        |        | XU=1   |
  +--------------------+--------+--------+--------+
  | User data page     | R=1    | W=1    | X=0    |
  |                    |        |        | XU=0   |
  +--------------------+--------+--------+--------+
  | Guard page (stack) | R=0    | W=0    | X=0    |
  |                    |        |        | XU=0   |
  +--------------------+--------+--------+--------+
```

### 9.2.7 EPT Address Translation Cost

```
Full Address Translation với EPT (worst case):

  Guest VA -> Guest PA: 4 levels x page table walk
  Mỗi level của guest PT cần 1 EPT walk (4 levels)
  Cuối cùng: GPA của target page cần 1 EPT walk
  
  Tổng: (4 guest levels + 1 final) x 4 EPT levels = 20 memory accesses
  Cộng thêm: 4 guest PT accesses = 24 memory accesses tổng cộng
  
  Guest VA
    |
    +-> Guest PML4 entry (at GPA_1)
    |     +-> EPT walk: GPA_1 -> HPA_1 (4 memory accesses)
    |     +-> Read guest PML4E from HPA_1 (1 access) = 5
    |
    +-> Guest PDPT entry (at GPA_2)  
    |     +-> EPT walk: GPA_2 -> HPA_2 (4 accesses)
    |     +-> Read guest PDPTE from HPA_2 (1 access) = 5
    |
    +-> Guest PD entry (at GPA_3)
    |     +-> EPT walk: GPA_3 -> HPA_3 (4 accesses)
    |     +-> Read guest PDE from HPA_3 (1 access) = 5
    |
    +-> Guest PT entry (at GPA_4)
    |     +-> EPT walk: GPA_4 -> HPA_4 (4 accesses)
    |     +-> Read guest PTE from HPA_4 (1 access) = 5
    |
    +-> Final page (at GPA_target)
          +-> EPT walk: GPA_target -> HPA_target (4 accesses) = 4
    
  Total = 5 + 5 + 5 + 5 + 4 = 24 memory accesses (worst case)
  
  Giải pháp: TLB caching
    - Combined TLB: Cache Guest VA -> HPA trực tiếp
    - VPID: TLB entries được tag theo VM, không cần flush khi VM switch
    - Sau first access, các access tiếp theo chỉ mất 1 cycle (TLB hit)
```

---

## 9.3 Hyper-V Architecture Deep Dive

### 9.3.1 Type 1 Hypervisor Layout

```
+------------------------------------------------------------------+
|                Root Partition (Host OS)                            |
|  +--------------------------------------------------------------+|
|  | Windows Host OS                                               ||
|  |  User-mode:                                                   ||
|  |   +- vmms.exe    (VM Management Service)                     ||
|  |   +- vmwp.exe    (VM Worker Process, 1 per VM)               ||
|  |   +- vmcompute.exe (Host Compute Service cho containers)     ||
|  |   +- vmsp.exe    (VM Security Process)                       ||
|  |   +- vmmem       (Memory allocation tracking)                ||
|  |                                                               ||
|  |  Kernel-mode:                                                 ||
|  |   +- winhv.sys    (Hyper-V API driver, hypercall interface)  ||
|  |   +- winhvr.sys   (Hyper-V root driver)                     ||
|  |   +- vid.sys      (Virtualization Infrastructure Driver)     ||
|  |   +- vmswitch.sys (Virtual switch, networking VSP)           ||
|  |   +- storvsp.sys  (Storage VSP)                              ||
|  |   +- vmbkmcl.sys  (VMBus kernel-mode client library)         ||
|  |   +- vmbusr.sys   (VMBus root driver)                       ||
|  +--------------------------------------------------------------+|
+------------------------------------------------------------------+
|   Child Partition 1    |   Child Partition 2    |  Child Part N   |
|  +------------------+  | +------------------+   | +----------+   |
|  | Guest OS (Win)   |  | | Guest OS (Linux) |   | | ...      |   |
|  | +- vmbusr.sys    |  | | +- hv_vmbus.ko   |   | |          |   |
|  | +- storvsc.sys   |  | | +- hv_storvsc.ko |   | |          |   |
|  | +- netvsc.sys    |  | | +- hv_netvsc.ko  |   | |          |   |
|  | +- VMBus client  |  | | +- VMBus client   |   | |          |   |
|  +------------------+  | +------------------+   | +----------+   |
+------------------------------------------------------------------+
|                    Hyper-V Hypervisor                              |
|  +--------------------------------------------------------------+|
|  | hvix64.exe (Intel) / hvax64.exe (AMD)                        ||
|  |                                                               ||
|  | Components:                                                   ||
|  |  +- VP Scheduler: vCPU -> pCPU mapping, time-slicing         ||
|  |  +- Memory Manager: EPT/NPT table management, SLAT          ||
|  |  +- Intercept Handler: VM Exit processing                    ||
|  |  +- Synthetic Interrupt Controller (SynIC): virtual APIC     ||
|  |  +- Timer: VMX preemption timer, synthetic timers            ||
|  |  +- VTL Manager: VTL 0/1 switching, secure call dispatch     ||
|  |  +- Nested Virtualization: L1/L2 EPT merging                 ||
|  |  +- I/O Handling: port I/O, MMIO intercepts                  ||
|  +--------------------------------------------------------------+|
+------------------------------------------------------------------+
|                        Hardware                                   |
|  CPU (VT-x/AMD-V + EPT/NPT) | RAM | NIC | Storage | GPU | TPM  |
+------------------------------------------------------------------+
```

### 9.3.2 Hypervisor Memory Layout

```
Hyper-V Hypervisor Physical Memory Layout:

  +-----------------------------------+ High address
  |  Partition memory (Guest RAM)      |
  |  - Mỗi partition được cấp một     |
  |    "GPA space" độc lập            |
  |  - EPT tables map GPA -> HPA     |
  +-----------------------------------+
  |  Hypervisor heap                   |
  |  - VMCS pages cho tất cả vCPUs    |
  |  - EPT page table pages           |
  |  - Internal data structures       |
  +-----------------------------------+
  |  Hypervisor code + data            |
  |  hvix64.exe / hvax64.exe          |
  |  - Text section (code)            |
  |  - Data section                    |
  |  - Per-processor data             |
  +-----------------------------------+
  |  Hypervisor stack                  |
  |  - Per-logical-processor stack    |
  +-----------------------------------+
  |  VMXON region (per-LP, 4KB each)  |
  +-----------------------------------+ Low address

  Hypervisor code chạy ở Ring 0, VMX Root mode
  -> KHÔNG CÓ kernel driver nào có thể truy cập hypervisor memory
  -> Hypervisor tự bảo vệ bằng EPT (không map HV memory vào guest EPT)
  -> Root partition cũng là guest từ góc nhìn của hypervisor
```

### 9.3.3 Hypercall Interface

Guest (bao gồm root partition) giao tiếp với hypervisor thông qua hypercalls:

```
Hypercall Calling Convention:

  Input:
    RCX = HV_X64_HYPERCALL_INPUT (64-bit)
    
    HV_X64_HYPERCALL_INPUT format:
      Bits [15:0]   Call code (hypercall number)
      Bit  [16]     Fast (1) vs Slow (0)
                     Fast: parameters in registers (RDX, R8)
                     Slow: parameters in input page (GPA in RDX)
      Bits [26:17]  Variable header size (64-bit units)
      Bit  [31]     Nested (1 = call từ nested hypervisor)
      Bits [43:32]  Rep count (số lần lặp cho rep hypercalls)
      Bits [55:48]  Rep start index
      Bits [63:56]  Reserved
    
  Output:
    RAX = HV_X64_HYPERCALL_OUTPUT (64-bit)
      Bits [15:0]   Call status (HV_STATUS)
      Bits [31:16]  Reserved
      Bits [43:32]  Reps completed
    
  Thực hiện:
    Guest VMCALL -> VM Exit -> Hypervisor dispatch -> VM Resume
    (Hyper-V dùng VMCALL instruction, không phải INT xx hay SYSCALL)

Hypercall Page:
  Hypervisor expose 1 page chứa VMCALL stub code
  Guest map page này và CALL tới nó (thay vì trực tiếp VMCALL)
  Địa chỉ: đọc từ MSR HV_X64_MSR_HYPERCALL (0x40000001)
  
  Nội dung page (pseudocode):
    hypercall_page:
      VMCALL
      RET

Các Hypercall Quan Trọng:
  Code   Name                          Mục đích
  ----   ----                          --------
  0x0001 HvCallSwitchVirtualAddressSpace  Switch address space
  0x0002 HvCallFlushVirtualAddressSpace   TLB flush
  0x0003 HvCallFlushVirtualAddressList    TLB flush (list)
  0x0004 HvCallGetLogicalProcessorRunTime Get VP runtime
  0x0008 HvCallNotifyLongSpinWait        Spin-lock notification
  0x0009 HvCallParkedVirtualProcessors   Park VP
  0x000B HvCallFlushVirtualAddressSpaceEx Extended TLB flush
  0x0011 HvCallVtlCall                   VTL 0 -> VTL 1 call
  0x0012 HvCallVtlReturn                 VTL 1 -> VTL 0 return
  0x0013 HvCallFlushVirtualAddressListEx Extended TLB flush (list)
  0x0050 HvCallPostMessage               VMBus message
  0x0051 HvCallSignalEvent               VMBus event signaling
  0x0054 HvCallPostDebugData             Debug data transfer
  0x0055 HvCallRetrieveDebugData         Debug data retrieval
  0x005C HvCallMapGpaPages               Map GPA range
  0x005D HvCallUnmapGpaPages             Unmap GPA range
  0x007E HvCallModifyVtlProtectionMask   Thay đổi VTL memory protection
  0x009E HvCallStartVirtualProcessor     Start VP
```

### 9.3.4 Enlightenments (Tối Ưu Hóa Cho Guest)

```
Hyper-V Enlightenments:
  Guest OS có thể phát hiện và sử dụng các tối ưu của Hyper-V
  thông qua synthetic MSRs và CPUID leaves.

CPUID Detection:
  CPUID leaf 0x40000000:
    EAX = Max leaf supported
    EBX:ECX:EDX = "Microsoft Hv" (signature string)
    
  CPUID leaf 0x40000001:
    EAX = Hypervisor interface signature
    "Hv#1" = Hyper-V interface
    
  CPUID leaf 0x40000003 (Features):
    EAX bit 0:  VP runtime MSR available
    EAX bit 1:  Partition reference counter available
    EAX bit 2:  Synthetic timers available
    EAX bit 3:  APIC access MSRs available
    EAX bit 4:  Hypercall MSRs available
    EAX bit 5:  VP index MSR available
    EAX bit 9:  Frequency MSRs available
    EBX bit 4:  Spinlock enlightenment available
    EBX bit 5:  Timer enlightenment available

Synthetic MSRs Quan Trọng:
  MSR Address   Name                    Mục đích
  -----------   ----                    --------
  0x40000000    HV_X64_MSR_GUEST_OS_ID  Guest OS identifier
                Guest phải ghi MSR này trước khi dùng hypercalls
                Format: [Vendor:4][OS:4][Major:8][Minor:8]
                
  0x40000001    HV_X64_MSR_HYPERCALL    Hypercall page enable + GPA
                Bit 0: Enable
                Bits [N-1:12]: GPA của hypercall page
                
  0x40000002    HV_X64_MSR_VP_INDEX     Virtual processor index
  
  0x40000010    HV_X64_MSR_SCONTROL     SynIC control
  0x40000011    HV_X64_MSR_SVERSION     SynIC version
  0x40000012    HV_X64_MSR_SIEFP        SynIC event flags page
  0x40000013    HV_X64_MSR_SIMP         SynIC message page
  0x40000020    HV_X64_MSR_EOM          End of message
  0x40000070    HV_X64_MSR_STIMER0_CONFIG Timer 0 config
  0x40000071    HV_X64_MSR_STIMER0_COUNT  Timer 0 count

Reference TSC Enlightenment:
  Cho phép guest đọc timestamp KHÔNG CẦN VM Exit
  
  Hypervisor cung cấp TSC reference page:
    struct HV_REFERENCE_TSC_PAGE {
        UINT32 TscSequence;    // Sequence counter (0 = invalid)
        UINT32 Reserved1;
        UINT64 TscScale;       // TSC scaling factor
        INT64  TscOffset;      // TSC offset
    };
    
  Guest tính timestamp:
    if (TscSequence != 0) {
        timestamp = ((RDTSC() * TscScale) >> 64) + TscOffset;
        // Không cần VM Exit!
    } else {
        // Fallback: đọc MSR (VM Exit) hoặc dùng CPUID timing
    }
```

### 9.3.5 Synthetic Interrupt Controller (SynIC)

```
SynIC Architecture:
  Hyper-V cung cấp virtual APIC cho mỗi vCPU
  Sử dụng APIC virtualization của CPU để giảm VM Exits

  +-------------------------+
  | Guest OS               |
  |  ISR handles interrupt |
  |  EOI (End of Interrupt)|
  +----------+-------------+
             |
  +----------v-----------+
  | SynIC (per-vCPU)     |
  | +- Message page      |  <- Nhận messages từ VMBus, hypervisor
  | +- Event flags page  |  <- Signal events (bitmap, 1 bit per event)
  | +- Synthetic timers  |  <- High-resolution timers
  | +- SINT[0..15]       |  <- 16 synthetic interrupt sources
  |    Mỗi SINT map tới  |     một IDT vector trong guest
  +----------------------+
  
  SynIC Message Delivery:
    1. Hypervisor/VMBus cần gửi message cho guest
    2. Ghi message vào SynIC message page (shared memory)
    3. Inject synthetic interrupt qua SINT
    4. Guest ISR đọc message từ message page
    5. Guest ghi EOM MSR (end of message) để ack
    -> Chỉ cần 1 VM Exit (interrupt injection), không cần I/O
  
  So sánh với emulated APIC:
    Emulated: Mỗi APIC register access = VM Exit (~1000 cycles)
    SynIC: APIC virtualization + posted interrupts (~10 cycles)
```

### 9.3.6 Virtual Processors và Scheduler

```
Hypervisor Scheduler Types:

1. Classic Scheduler:
   - Giống Windows thread scheduler
   - vCPUs là "threads" được schedule lên pCPUs
   - Time-slicing: mỗi vCPU được 1 quantum (~15ms)
   - Pro: Đơn giản, fair sharing
   - Con: Cache pollution khi vCPU migrate giữa cores

2. Core Scheduler (mặc định từ Windows Server 2019):
   - vCPU group được schedule lên physical core (cả 2 SMT threads)
   - Khi VM chỉ cần 1 vCPU, SMT sibling bị idle
   - Pro: Bảo vệ chống Spectre/MDS (không share core giữa VMs)
   - Con: Mất ~5-10% performance vì SMT thread bị waste

3. Root Scheduler (mặc định từ Windows 10/11):
   - Root partition Windows scheduler quyết định
   - vCPU của child VMs là threads trong root
   - Pro: Root OS lúc nào cũng responsive
   - Con: VM latency cao hơn

   +-----------+
   | Root OS   |  Windows Scheduler
   | scheduler |  quản lý tất cả
   +-----+-----+
         |
    +----+----+----+----+
    |    |    |    |    |
   VP0  VP1  VP0  VP1  VP0
   Root Root VM1  VM1  VM2
```

### 9.3.7 Hyper-V Event Tracing

```
ETW Providers cho Hyper-V monitoring:

  Microsoft-Windows-Hyper-V-Hypervisor
    GUID: {52FC89F8-995E-434C-A91E-199986449890}
    Events: hypercall stats, VP scheduling, intercept counts
    
  Microsoft-Windows-Hyper-V-Worker
    GUID: {51ddfa29-d5c8-4803-be4b-2ecb715570fe}
    Events: vmwp.exe activity, device emulation
    
  Microsoft-Windows-Hyper-V-VMMS
    GUID: {6066F867-7CA1-4418-8F54-32C6B2027AAA}
    Events: VM lifecycle, configuration changes
    
  Microsoft-Windows-Hyper-V-VmSwitch
    GUID: {67DC0D66-3695-47C0-9642-33F76F7BD7AD}
    Events: Virtual switch, network packet flow

PowerShell command:
  # Enable hypervisor performance counters
  Get-Counter -ListSet "Hyper-V Hypervisor*" | Select-Object CounterSetName
  
  # Xem intercept statistics
  Get-Counter "\Hyper-V Hypervisor Virtual Processor(*)\*"
  
  # Xem hypercall counts
  typeperf "\Hyper-V Hypervisor Root Virtual Processor(_Total)\Hypercalls/sec"
```

---

## 9.4 Virtual Trust Levels (VTLs) và VBS Deep Dive

### 9.4.1 VTL Architecture Chi Tiết

```
+================================================================+
| VTL 1 (Secure World)                                            |
|                                                                  |
|  +-----------------------------------------------------------+ |
|  | Secure Kernel (securekernel.exe)                            | |
|  |                                                             | |
|  | Chức năng:                                                  | |
|  |  +- Quản lý VTL 1 memory (riêng biệt với VTL 0)           | |
|  |  +- Xử lý secure calls từ VTL 0                            | |
|  |  +- Enforce HVCI policy (kiểm tra code signing)            | |
|  |  +- Quản lý Secure Kernel objects                          | |
|  |  +- Secure boot chain verification                        | |
|  |  +- Key management cho Credential Guard                   | |
|  |                                                             | |
|  | Secure Processes (Trustlets):                               | |
|  |  +- lsaiso.exe   Credential Guard (NTLM/Kerberos secrets) | |
|  |  +- bioiso.exe   Windows Hello biometric data              | |
|  |  +- keyiso.exe   CNG key isolation                        | |
|  |  +- vmsp.exe     VM shielding security                    | |
|  |  +- hvax64.exe   Hypervisor address extension             | |
|  |                                                             | |
|  | Secure Kernel có IDT, GDT, page tables riêng               | |
|  | Không dùng chung bất kỳ data structure nào với VTL 0       | |
|  +-----------------------------------------------------------+ |
|                                                                  |
|  Memory: Riêng biệt EPT/SLAT permissions                        |
|  -> VTL 0 KHÔNG THỂ truy cập VTL 1 memory                      |
|  -> VTL 1 CÓ THỂ đọc VTL 0 memory (để kiểm tra)                |
|  -> Hypervisor enforce bằng EPT                                  |
|                                                                  |
+================================================================+
| VTL 0 (Normal World)                                            |
|                                                                  |
|  +-----------------------------------------------------------+ |
|  | NT Kernel (ntoskrnl.exe)                                    | |
|  | Tất cả drivers, services, applications                      | |
|  | HAL, Executive, Memory Manager, I/O Manager, ...            | |
|  +-----------------------------------------------------------+ |
|                                                                  |
|  VTL 0 kernel KHÔNG BIẾT nội dung của VTL 1 memory             |
|  VTL 0 kernel KHÔNG THỂ tắt/thay đổi HVCI policy               |
|  VTL 0 kernel vẫn là "untrusted" từ góc nhìn của VTL 1         |
|                                                                  |
+================================================================+
| Hypervisor (hvix64.exe / hvax64.exe)                            |
|  +- Quản lý 2 bộ EPT tables riêng biệt cho VTL 0 và VTL 1     |
|  +- Xử lý VTL switching (HvCallVtlCall / HvCallVtlReturn)     |
|  +- Enforce memory protection rules                             |
|  +- Không thuộc VTL nào, ở dưới cả VTL 0 và VTL 1              |
+================================================================+
```

### 9.4.2 VTL Memory Access Rules

```
VTL Memory Protection Matrix:

  +--------------------+-----------+-----------+-----------+
  | Memory thuộc       | VTL 0     | VTL 1     | Hypervisor|
  | (owner)            | access    | access    | access    |
  +--------------------+-----------+-----------+-----------+
  | VTL 0 code page    | R + X     | R + W + X | Full      |
  |                    | (HVCI: no | (có thể   |           |
  |                    |  W access)| modify)   |           |
  +--------------------+-----------+-----------+-----------+
  | VTL 0 data page    | R + W     | R + W     | Full      |
  |                    | (no X,    |           |           |
  |                    |  HVCI)    |           |           |
  +--------------------+-----------+-----------+-----------+
  | VTL 1 code page    | NO ACCESS | R + X     | Full      |
  |                    | (EPT: 000)|           |           |
  +--------------------+-----------+-----------+-----------+
  | VTL 1 data page    | NO ACCESS | R + W     | Full      |
  |                    | (EPT: 000)|           |           |
  +--------------------+-----------+-----------+-----------+
  | Shared memory      | R + W     | R + W     | Full      |
  | (explicit share)   | (no X)    |           |           |
  +--------------------+-----------+-----------+-----------+
  | Hypervisor memory  | NO ACCESS | NO ACCESS | Full      |
  +--------------------+-----------+-----------+-----------+

  Note: "NO ACCESS" = EPT entry Read=0, Write=0, Execute=0
  Bất kỳ truy cập nào sẽ gây EPT Violation -> VM Exit -> denied
```

### 9.4.3 VTL Transitions Chi Tiết

```
VTL 0 -> VTL 1 (Secure Call / VtlCall):

  1. VTL 0 code chuẩn bị tham số trong thanh ghi
  2. Gọi HvCallVtlCall hypercall (VMCALL)
  3. CPU trap sang hypervisor (VM Exit)
  4. Hypervisor:
     a. Save VTL 0 register state (RSP, RIP, RFLAGS, GPRs)
     b. Switch EPT pointer từ VTL 0 EPT sang VTL 1 EPT
     c. Load VTL 1 register state (RSP, RIP, RFLAGS, GPRs)
     d. VM Resume vào VTL 1
  5. Secure Kernel bắt đầu chạy, xử lý secure call
  6. Secure Kernel gọi HvCallVtlReturn
  7. Hypervisor:
     a. Save VTL 1 state
     b. Switch EPT pointer về VTL 0 EPT
     c. Load VTL 0 state
     d. VM Resume vào VTL 0
  8. VTL 0 tiếp tục chạy

  Chi phí: ~2-5 microseconds (nhanh hơn full VM switch)
  
  +--------+    VMCALL     +-----------+   EPT switch   +--------+
  | VTL 0  | -----------> | Hypervisor | ------------> | VTL 1  |
  | (NT    |              | save VTL 0 |               | (SecKrn|
  | kernel)|              | load VTL 1 |               |  .exe) |
  +--------+              +-----------+                +--------+
       ^                                                    |
       |                  +-----------+   EPT switch        |
       +----------------- | Hypervisor | <-----------+------+
                          | save VTL 1 |    VMCALL (VtlReturn)
                          | load VTL 0 |
                          +-----------+

Normal Call vs Secure Call:
  +--------------+----------------------------+---------------------------+
  | Đặc điểm     | Normal Call (SYSCALL)       | Secure Call (VtlCall)     |
  +--------------+----------------------------+---------------------------+
  | Transition   | Ring 3 -> Ring 0            | VTL 0 -> VTL 1           |
  | Mechanism    | SYSCALL/SYSENTER instruction| VMCALL (hypercall)        |
  | Handler      | nt!KiSystemCall64           | securekernel dispatch     |
  | Chi phí      | ~100-200 ns                 | ~2-5 us                   |
  | Page tables  | Same CR3 (kernel mapping)   | Different EPT             |
  | Trust level  | Same VTL                    | Higher VTL                |
  | Isolation    | Software (SMEP/SMAP)        | Hardware (EPT)            |
  +--------------+----------------------------+---------------------------+
```

### 9.4.4 Credential Guard (lsaiso.exe) Architecture

```
Credential Guard Architecture:

  VTL 0:
  +------------------------------------------------------------------+
  | lsass.exe (LSA Server)                                           |
  |  +- Nhận authentication request từ user/network                  |
  |  +- Không giữ NTLM hashes hoặc Kerberos keys trong memory       |
  |  +- Gửi sensitive operations cho lsaiso.exe qua RPC             |
  +------------------------------------------------------------------+
        |  Secure RPC (qua shared memory + VtlCall)
        v
  VTL 1:
  +------------------------------------------------------------------+
  | lsaiso.exe (LSA Isolated)                                        |
  |  +- Chạy trong Secure World (VTL 1)                              |
  |  +- Lưu trữ:                                                     |
  |     +- NTLM password hashes                                     |
  |     +- Kerberos TGT (Ticket Granting Ticket)                    |
  |     +- Kerberos session keys                                    |
  |     +- Derived credentials                                      |
  |  +- Thực hiện:                                                   |
  |     +- NTLM challenge-response computation                      |
  |     +- Kerberos ticket operations                               |
  |     +- Key derivation                                            |
  |  +- KHÔNG BAO GIỜ expose raw credentials cho VTL 0              |
  +------------------------------------------------------------------+

  Attack scenario KHÔNG CÓ Credential Guard:
    1. Attacker có kernel access (admin/SYSTEM)
    2. Đọc lsass.exe memory (mimikatz)
    3. Lấy được NTLM hash, Kerberos keys
    4. Pass-the-Hash / Pass-the-Ticket
    
  Attack scenario CÓ Credential Guard:
    1. Attacker có kernel access (admin/SYSTEM, VTL 0)
    2. Đọc lsass.exe memory -> Chỉ thấy encrypted handles
    3. Không thể đọc lsaiso.exe memory (VTL 1, EPT blocks)
    4. Không thể tắt Credential Guard (hypervisor enforce)
    5. KHÔNG LẤY ĐƯỢC raw credentials!

  Hạn chế của Credential Guard:
    - Không bảo vệ local accounts (chỉ domain credentials)
    - Không bảo vệ chống keylogger (credentials tại thời điểm nhập)
    - Vẫn có thể bị bypass nếu attacker compromise UEFI/bootloader
    - Không bảo vệ cached logon (offline logon hashes vẫn ở VTL 0)
```

### 9.4.5 HVCI Implementation Chi Tiết

```
HVCI (Hypervisor-protected Code Integrity):

  Mục đích: Đảm bảo chỉ có SIGNED CODE mới chạy được trong kernel

  Implementation:
  
  1. CI.dll (Code Integrity) trong VTL 0 kiểm tra signature
  2. CI.dll gọi secure call sang Secure Kernel (VTL 1)
  3. Secure Kernel verify signature độc lập
  4. Nếu OK: Secure Kernel set EPT permissions cho code pages:
     EPT: Read = 1, Write = 0, Execute = 1
  5. Nếu FAIL: EPT: Read = 1, Write = 0, Execute = 0
     -> Guest execute -> EPT Violation -> blocked

  Workflow khi driver load:
  
  VTL 0 (Normal World):               VTL 1 (Secure World):
  +---------------------------+       +---------------------------+
  | 1. NtLoadDriver()        |       |                           |
  | 2. MmLoadSystemImage()   |       |                           |
  | 3. CI.dll verifies sig   |       |                           |
  | 4. VtlCall: "verify      | ----> | 5. SecKrn verify sig      |
  |    this driver"           |       |    independently          |
  |                           | <---- | 6. Result: OK/FAIL        |
  | 7. Map driver pages      |       |                           |
  | 8. VtlCall: "set EPT     | ----> | 9. Set EPT permissions:   |
  |    for these pages"       |       |    Code: R-X (no write)   |
  |                           |       |    Data: RW- (no execute) |
  |                           | <---- | 10. Done                  |
  | 11. Driver starts running |       |                           |
  +---------------------------+       +---------------------------+

  Protection examples:

  Scenario: Kernel rootkit cố patch SSDT
    VTL 0 PTE: PAGE_EXECUTE_READ (kernel thinks code is RX)
    VTL 1 SLAT: Write = 0
    Rootkit: memcpy(ssdt_entry, hook_addr, 8)
    -> CPU thực hiện write -> EPT Violation (Write = 0)
    -> Hypervisor blocks write -> rootkit FAIL

  Scenario: Attacker allocate executable kernel memory
    ExAllocatePool -> VTL 0 PTE: PAGE_EXECUTE_READWRITE
    VTL 1 SLAT: Execute = 0 (vì page chưa được verify)
    Attacker ghi shellcode vào page
    CPU jump to shellcode -> EPT Violation (Execute = 0)
    -> Hypervisor blocks execute -> shellcode FAIL

  Kết quả: Kể cả với kernel-level access, attacker KHÔNG THỂ:
    - Patch kernel code (SSDT, IDT handlers, etc.)
    - Load unsigned drivers
    - Execute shellcode trong kernel pool
    - Modify code integrity policies
    - Disable HVCI từ VTL 0
```

### 9.4.6 Secure System Process

```
Secure System Process (System process cho VTL 1):

  PID: do kernel gán (khác với System PID 4), chạy trong VTL 1
  
  Khi VBS enabled:
    System (PID 4) - Normal kernel threads (VTL 0)
    Secure System  - Secure kernel threads (VTL 1)
    
  Secure System hosts:
    - Secure kernel worker threads
    - VTL 1 page fault handler
    - Secure timer DPC processing
    - Trustlet (secure process) management
    
  Trong Task Manager:
    "Secure System" process visible nhưng KHÔNG THỂ:
    - Attach debugger
    - Read memory
    - Enumerate threads/handles
    - Kill/suspend
    
  WinDbg:
    kd> !process 0 0 "Secure System"
    -> Hiển thị process object nhưng memory không accessible từ VTL 0
```

---

## 9.5 VMBus Protocol Deep Dive

### 9.5.1 VMBus Architecture Chi Tiết

```
Root Partition                          Child Partition
+----------------------------+         +----------------------------+
| User mode:                 |         | User mode:                 |
|  vmwp.exe (emulated devs)  |         |  (applications)            |
+----------------------------+         +----------------------------+
| Kernel mode:               |         | Kernel mode:               |
|                            |         |                            |
| VSPs (Service Providers):  |         | VSCs (Service Consumers):  |
|  +- storvsp.sys (storage)  |         |  +- storvsc.sys (storage)  |
|  +- vmswitch.sys (network) |         |  +- netvsc.sys  (network)  |
|  +- vpcivsp.sys (PCI)      |         |  +- hid_mini.sys (input)   |
|  +- synthvid (video)       |         |  +- vmbusr.sys  (VMBus)    |
|  +- DMAs, clipboard, etc.  |         |                            |
|                            |         |                            |
| vmbusr.sys (VMBus root)    |         | vmbus.sys (VMBus client)   |
+--------+-------------------+         +--------+-------------------+
         |                                      |
         | Hypercalls (HvCallPostMessage,        | Hypercalls
         | HvCallSignalEvent)                    |
         |                                      |
+--------v--------------------------------------v---+
| Hypervisor                                        |
|  +- SynIC message delivery                       |
|  +- Event flag signaling                         |
|  +- Shared memory management (GPADL)             |
+---------------------------------------------------+
```

### 9.5.2 Ring Buffer Structure

```
VMBus Ring Buffer (shared memory giữa VSP và VSC):

  Mỗi VMBus channel có 2 ring buffers:
    - Outgoing ring: Gửi data (client -> server)
    - Incoming ring: Nhận data (server -> client)

  Ring Buffer Layout:
  +--------------------------------------------------+
  | Ring Buffer Header (1 page = 4KB)                 |
  |  +- Write Index (32-bit)                         |
  |  +- Read Index (32-bit)                          |
  |  +- Interrupt Mask (32-bit)                      |
  |  +- Pending Send Size (32-bit)                   |
  |  +- Reserved                                     |
  +--------------------------------------------------+
  | Data Region (N pages, cấu hình khi open channel) |
  |                                                  |
  |  [Message Header][Payload][Padding]              |
  |  [Message Header][Payload][Padding]              |
  |  [Message Header][Payload][Padding]              |
  |  ...                                             |
  |  [Free space]                                    |
  |                                                  |
  |  <- Circular buffer, wrap around                 |
  +--------------------------------------------------+

  Message Header format:
    struct VMBUS_CHANNEL_PACKET_HEADER {
        UINT16 Type;          // Packet type
        UINT16 DataOffset8;   // Data offset (in 8-byte units)
        UINT16 Length8;       // Total length (in 8-byte units)
        UINT16 Flags;         // VMBUS_DATA_PACKET_FLAG_*
        UINT64 TransactionId; // Correlation ID
    };

  Packet Types:
    VMBUS_PACKET_TYPE_DATA_IN_BAND       = 6  (data inline)
    VMBUS_PACKET_TYPE_DATA_USING_TRANSFER_PAGES = 7 (GPADL ref)
    VMBUS_PACKET_TYPE_DATA_USING_GPA_DIRECT     = 9
    VMBUS_PACKET_TYPE_COMPLETION         = 11 (response)

  Performance:
    - KHÔNG CẦN VM Exit cho data transfer (shared memory)
    - Chỉ cần hypercall để signal (HvCallSignalEvent)
    - Batching: nhiều messages trước khi signal 1 lần
    - Throughput: 10+ Gbps cho networking (netvsc)
```

### 9.5.3 VMBus Channel Lifecycle

```
VMBus Channel Lifecycle:

  1. OFFER
     Hypervisor/Root gửi channel offer cho child partition
     Offer chứa:
       - Channel type GUID (ví dụ: storage, network)
       - Instance GUID
       - Channel ID
       - Monitor allocation info
     
  2. OPEN
     Child partition accept offer và open channel:
       - Cấp phát ring buffer memory (guest physical pages)
       - Gửi OPEN_CHANNEL message với ring buffer GPA
       - Setup GPADL (Guest Physical Address Descriptor List)
     
  3. GPADL SETUP
     GPADL = Mapping guest memory pages cho DMA-style transfers
       - Child tạo GPADL_HEADER message:
         + GPADL handle (client-assigned)
         + Range count
         + Page frame numbers (PFNs) của guest memory
       - Nếu nhiều pages: gửi tiếp GPADL_BODY messages
       - Root/hypervisor map pages vào root address space
       - Root gửi GPADL_CREATED response
     
  4. DATA TRANSFER
     Sau khi channel open và GPADL setup:
       a. Client ghi data vào outgoing ring buffer
       b. Client gọi HvCallSignalEvent hypercall
       c. Hypervisor signal SynIC event cho target VP
       d. Server đọc data từ incoming ring buffer
       e. Server ghi response vào outgoing ring buffer  
       f. Server signal event
       g. Client đọc response
     
  5. CLOSE
     - CLOSE_CHANNEL message
     - GPADL_TEARDOWN (unmap shared pages)
     - Free ring buffer memory

  VMBus Message Types:
  +----+------------------------------------+
  | ID | Message Type                       |
  +----+------------------------------------+
  |  1 | CHANNELMSG_OFFERCHANNEL            |
  |  2 | CHANNELMSG_RESCIND_CHANNELOFFER     |
  |  3 | CHANNELMSG_REQUESTOFFERS           |
  |  4 | CHANNELMSG_ALLOFFERS_DELIVERED     |
  |  5 | CHANNELMSG_OPENCHANNEL             |
  |  6 | CHANNELMSG_OPENCHANNEL_RESULT      |
  |  7 | CHANNELMSG_CLOSECHANNEL            |
  |  8 | CHANNELMSG_GPADL_HEADER            |
  |  9 | CHANNELMSG_GPADL_BODY              |
  | 10 | CHANNELMSG_GPADL_CREATED           |
  | 11 | CHANNELMSG_GPADL_TEARDOWN          |
  | 12 | CHANNELMSG_GPADL_TORNDOWN          |
  | 13 | CHANNELMSG_RELID_RELEASED          |
  | 14 | CHANNELMSG_INITIATE_CONTACT        |
  | 15 | CHANNELMSG_VERSION_RESPONSE        |
  | 16 | CHANNELMSG_UNLOAD                  |
  | 17 | CHANNELMSG_UNLOAD_RESPONSE         |
  | 23 | CHANNELMSG_TL_CONNECT_REQUEST      |
  +----+------------------------------------+
```

### 9.5.4 Emulated vs Synthetic Devices

| Đặc điểm | Emulated Device | Synthetic (VMBus) Device |
|----------|----------------|--------------------------|
| I/O method | Port I/O / MMIO | Shared memory ring buffer |
| VM Exit | Mỗi I/O operation | Chỉ signaling |
| Latency | Cao (~us per I/O) | Thấp (~ns per batch) |
| Throughput | Thấp | Cao (10+ Gbps network) |
| Guest OS | Bất kỳ (dùng standard drivers) | Cần Integration Services |
| Ví dụ | IDE controller, RTL8139 NIC | storvsc, netvsc |
| Gen 2 VM | Có thể disable | Mặc định |

---

## 9.6 Nested Virtualization

### 9.6.1 Architecture

```
Nested Virtualization Levels:

  L0: Physical Hardware
       |
  L1: Hyper-V (host hypervisor)
       |  Quản lý EPT_L1 (GPA_guest -> HPA)
       |
  L2: Guest hypervisor (Hyper-V, KVM, VMware trong VM)
       |  Quản lý EPT_L2 (GPA_nested -> GPA_guest)
       |
  L3: Nested guest OS
       Chạy trong VM của L2

Address Translation (3-level):
  L3 VA -> L3 PT -> GPA_nested (L3 "physical")
  GPA_nested -> EPT_L2 -> GPA_guest (L2 "physical")
  GPA_guest -> EPT_L1 -> HPA (actual physical)
  
  Nếu không optimize: mỗi memory access cần đi qua 3 page walks
  -> Cực kỳ chậm!

Hyper-V Optimization: EPT Merging (EPT Composition)
  L1 hypervisor merge EPT_L1 và EPT_L2 thành 1 EPT duy nhất:
  EPT_merged: GPA_nested -> HPA (trực tiếp)
  
  -> Nested guest chỉ cần 1 EPT walk thay vì 2
  -> Performance gần nhất khoảng 85-90% so với non-nested
```

### 9.6.2 VMCS Shadowing

```
VMCS Shadowing cho nested virtualization:

  Vấn đề: L2 hypervisor thực hiện VMREAD/VMWRITE trên VMCS của L3
          Mỗi VMREAD/VMWRITE = VM Exit -> L1 phải emulate -> chậm

  Giải pháp: VMCS Shadowing
    L1 tạo "shadow VMCS" cho L2
    L2 VMREAD/VMWRITE truy cập shadow VMCS trực tiếp (không VM Exit)
    L1 đồng bộ shadow VMCS với real VMCS khi cần
    
  Flow:
    1. L2 VMWRITE field X vào shadow VMCS (không VM Exit)
    2. L2 VMLAUNCH -> VM Exit to L1
    3. L1 đọc shadow VMCS, merge với real VMCS
    4. L1 VMLAUNCH L3 với merged VMCS
    5. L3 VM Exit -> L1 cập nhật shadow VMCS
    6. L1 VMRESUME L2 -> L2 đọc shadow VMCS (no VM Exit)
```

**[UPDATE 2026]** Windows 11 24H2 hỗ trợ nested virtualization trên AMD processors
và ARM64 (preview). Performance cải thiện 15-20% so với phiên bản trước.

---

## 9.7 Windows Containers Internals

### 9.7.1 Server Silo Architecture

```
Windows Container = Server Silo (cơ chế isolation cấp kernel)

  Server Silo là extension của Job Objects:
  
  Regular Job Object:
    - Resource limits (CPU, memory, I/O)
    - Process group management
    
  Silo (App Container extension):
    - Volume namespace (file system)
    - Object namespace
    - Registry namespace
    
  Server Silo (full container):
    - Volume namespace
    - Object namespace isolation
    - Registry virtualization
    - Network namespace (compartment)
    - Riêng PID namespace
    - Riêng hostname
    - Riêng DNS
    - Riêng event log
    - Shared kernel với host

  +----------------------------------------------+
  | Host Windows                                  |
  |                                               |
  | +-----------------+ +-----------------+       |
  | | Server Silo 1   | | Server Silo 2   |       |
  | | (Container A)   | | (Container B)   |       |
  | |                 | |                 |       |
  | | Riêng:          | | Riêng:          |       |
  | |  +- FS overlay  | |  +- FS overlay  |       |
  | |  +- Registry    | |  +- Registry    |       |
  | |  +- ObjDir      | |  +- ObjDir      |       |
  | |  +- Network     | |  +- Network     |       |
  | |  +- Processes   | |  +- Processes   |       |
  | |                 | |                 |       |
  | | Chung:          | | Chung:          |       |
  | |  +- Kernel      | |  +- Kernel      |       |
  | |  +- Drivers     | |  +- Drivers     |       |
  | |  +- HAL         | |  +- HAL         |       |
  | +-----------------+ +-----------------+       |
  |                                               |
  | Shared: ntoskrnl.exe, drivers, HAL            |
  +----------------------------------------------+
```

### 9.7.2 Namespace Virtualization

```
1. Object Manager Namespace Isolation:

  Host:
    \                          <- Root object directory
    \Device\                   <- Device objects
    \BaseNamedObjects\         <- Named objects (mutexes, events)
    \Sessions\                 <- Per-session objects
    
  Container (Server Silo):
    \Silos\{SiloId}\           <- Silo root (không visible cho container)
    \Silos\{SiloId}\Device\    <- Container thấy như \Device\
    \Silos\{SiloId}\BaseNamedObjects\  <- Riêng biệt
    
  Container process gọi NtCreateMutex("Global\MyMutex"):
    -> Kernel redirect thành \Silos\{SiloId}\BaseNamedObjects\MyMutex
    -> Container KHÔNG THỂ thấy hoặc truy cập host's objects
    -> Host KHÔNG THỂ thấy container's objects (từ container namespace)

2. Registry Virtualization:

  Host registry:
    HKLM\SOFTWARE\...          <- Real registry
    HKLM\SYSTEM\...
    
  Container registry (overlay):
    Base layer: HKLM từ container image (read-only)
    Diff layer: Changes made by container (copy-on-write)
    
    Container process đọc HKLM\SOFTWARE\key1:
      1. Check diff layer -> không có
      2. Check base layer -> tìm thấy -> return
      
    Container process ghi HKLM\SOFTWARE\key1:
      1. Copy key1 từ base sang diff
      2. Modify trong diff layer
      -> Base layer KHÔNG BỊ THAY ĐỔI

  +------------------+     +-------------------+
  | Diff Hive        |     | Base Hive         |
  | (Container-only) |     | (From image,      |
  | (read-write)     |     |  read-only)       |
  +--------+---------+     +---------+---------+
           |                         |
           +------- Merged View -----+
                    (container sees)

3. Filesystem Virtualization (wcifs.sys):

  wcifs.sys = Windows Container Isolation Filter (minifilter driver)
  
  Layers:
    - Base layer: Image filesystem (read-only, shared giữa containers)
    - Sandbox layer: Container-specific changes (copy-on-write)
    
  Operations:
    CREATE (open file):
      1. Check sandbox -> có? return sandbox version
      2. Check base layer -> có? return base version (read-only)
      3. Không có? STATUS_OBJECT_NAME_NOT_FOUND
      
    WRITE:
      1. File ở base layer? Copy lên sandbox (copy-on-write)
      2. Write vào sandbox copy
      
    DELETE:
      1. Tạo tombstone marker trong sandbox
      2. File vẫn tồn tại trong base nhưng bị "hidden"

4. Network Namespace:

  Mỗi container có riêng:
    - Network compartment (Windows networking concept)
    - Virtual NIC (connected to host vSwitch)
    - IP address, routing table
    - DNS settings
    - Firewall rules (WFP filters)
    
  Host vSwitch modes:
    NAT:         Container có internal IP, NAT qua host
    Transparent: Container trực tiếp trên physical network
    L2Bridge:    Bridge với physical NIC
    Overlay:     VXLAN overlay cho multi-host
```

### 9.7.3 Host Compute Service (HCS) và Docker Integration

```
Container Management Stack:

  +-------------------------+
  | Docker CLI / containerd |
  +----------+--------------+
             |
  +----------v--------------+
  | HCS (Host Compute       |     hcsshim (Go library)
  | Service)                 |     Cầu nối giữa Docker và HCS
  | vmcompute.exe            |
  +----------+---------------+

             |
  +----------v--------------+
  | HNS (Host Network       |     Container networking
  | Service)                 |
  +----------+---------------+
             |
  +----------v--------------+
  | Kernel components:       |
  |  +- wcifs.sys (FS)       |
  |  +- Job/Silo objects     |
  |  +- Registry overlay     |
  |  +- WFP (firewall)       |
  +-------------------------+

  HCS API (vmcompute.exe):
    - HcsCreateComputeSystem()   Tạo container
    - HcsStartComputeSystem()    Start container
    - HcsShutdownComputeSystem() Shutdown
    - HcsTerminateComputeSystem() Force terminate
    - HcsGetComputeSystemProperties() Query state
    - HcsModifyComputeSystem()   Modify (add disk, network)
    - HcsCreateProcess()         Run process trong container
```

### 9.7.4 Hyper-V Container Isolation

```
Hyper-V Isolated Containers:

  Thay vì shared kernel, mỗi container chạy trong lightweight VM:
  
  +---------------------------------------------------+
  | Host                                               |
  |                                                    |
  | +--------------------+ +--------------------+      |
  | | Utility VM 1       | | Utility VM 2       |      |
  | | (Hyper-V container)| | (Hyper-V container)|      |
  | |                    | |                    |      |
  | | Minimal kernel:    | | Minimal kernel:    |      |
  | |  ntoskrnl.exe      | |  ntoskrnl.exe      |      |
  | |  (stripped)        | |  (stripped)        |      |
  | | Container process  | | Container process  |      |
  | | FS: overlay via    | | FS: overlay via    |      |
  | |     VSMB/Plan9     | |     VSMB/Plan9     |      |
  | +--------------------+ +--------------------+      |
  |                                                    |
  | Hypervisor isolation cho từng container            |
  +---------------------------------------------------+

  Utility VM kernel:
    - Lightweight Windows kernel (không full OS)
    - Boot trong ~2 giây
    - ~100-200 MB memory overhead
    - Mục đích: kernel isolation, không phải full VM
    
  Filesystem sharing:
    - VSMB (Virtual SMB): Share host filesystem cho container
    - Plan 9 redirect: Lightweight filesystem sharing protocol
    - Container image layers được mount từ host qua VSMB
    
  Khi nào dùng Hyper-V isolation:
    - Container image version khác với host kernel version
    - Cần strong isolation (multi-tenant, untrusted code)
    - Windows 10/11 (process isolation chỉ có trên Server)
```

### 9.7.5 HostProcess Containers (Windows Server 2022+)

```
HostProcess Containers (Kubernetes Windows):

  [UPDATE 2026]
  
  Đặc điểm:
    - Chạy TRỰC TIẾP trong host namespace (không isolation)
    - Tương tự "privileged containers" trên Linux
    - Truy cập full host filesystem, network, process
    - Dùng cho: cluster management, log collection, device plugins
    
  So sánh:
  +-------------------+-----------+-------------+----------------+
  | Feature           | Process   | Hyper-V     | HostProcess    |
  |                   | Isolation | Isolation   | Container      |
  +-------------------+-----------+-------------+----------------+
  | Kernel            | Shared    | Dedicated   | Shared (full)  |
  | FS isolation      | Overlay   | VM + VSMB   | None (host FS) |
  | Network           | Namespace | vNIC in VM  | Host network   |
  | Registry          | Overlay   | VM-private  | Host registry  |
  | Performance       | Near-bare | ~90%        | Bare metal     |
  | Security          | Medium    | High        | None (admin)   |
  | Startup time      | ~2s       | ~5s         | ~1s            |
  +-------------------+-----------+-------------+----------------+
```

---

## 9.8 GPU Virtualization (GPU-PV)

### 9.8.1 GPU-PV Architecture

```
GPU Paravirtualization (GPU-PV):

  Host:
  +--------------------------------------------------+
  | GPU Manager Service                               |
  |  +- dxgkrnl.sys (DirectX Graphics Kernel)        |
  |  +- Physical GPU driver (NVIDIA/AMD/Intel)        |
  |  +- GPU scheduler                                |
  +--------------------------------------------------+
         |  GPU-PV channel (VMBus)
         v
  Guest VM / WSL 2:
  +--------------------------------------------------+
  | dxgkrnl.sys (guest, paravirtual version)          |
  |  +- Không giao tiếp với physical GPU trực tiếp   |
  |  +- Forward GPU commands qua VMBus               |
  |                                                   |
  | Application:                                      |
  |  +- DirectX / Vulkan / OpenGL / CUDA              |
  |  +- Submit command buffers                        |
  |  +- GPU memory allocation (shared via SLAT)       |
  +--------------------------------------------------+

  GPU Memory Sharing:
    - Guest GPU memory được map qua EPT
    - Host và guest share GPU memory pages
    - Zero-copy cho command buffers
    
  [UPDATE 2026] GPU-PV Enhancements (Windows 11 24H2):
    - DirectX 12 Ultimate support trong VMs
    - Cải thiện CUDA performance trong WSL 2 (~95% native)
    - Multi-GPU support cho VMs
    - GPU live migration (preview)
    - Video encode/decode acceleration trong VMs
```

---

## 9.9 Security Implications của Virtualization

### 9.9.1 VM Escape Attack Surface

```
VM Escape Attack Vectors:

  1. Synthetic Device Exploitation (VMBus):
     - VSP (host-side) parsers có thể có vulnerabilities
     - Malformed VMBus packets từ guest -> buffer overflow trong host
     - Attack surface: storvsp, vmswitch, synthvid, clipboard
     - Ví dụ: CVE-2020-0904 (Hyper-V RemoteFX vGPU)
     
  2. Emulated Device Exploitation:
     - vmwp.exe (VM Worker Process) emulate legacy devices
     - Bugs trong: IDE controller, floppy, serial port emulation
     - vmwp.exe chạy trong user-mode -> tấn công có sandbox
     
  3. Hypercall Interface:
     - Guest có thể gọi hypercalls với malformed parameters
     - Integer overflows, buffer overruns trong hypercall handlers
     - Tấn công: fuzzing hypercall input parameters
     
  4. VMCS/EPT Manipulation (Nested Virt):
     - Nested hypervisor có thể craft malicious VMCS
     - EPT misconfiguration bugs khi merge L1+L2 EPT
     
  5. Interrupt/Exception Injection:
     - Race conditions trong interrupt delivery
     - NMI handling bugs
     
  6. Timing Side-Channels:
     - TSC-based covert channels giữa VMs
     - Cache timing attacks (Spectre variant 2 cross-VM)
     - L1TF (L1 Terminal Fault) EPT bypass

  Mitigation cho VM Escape:
    - vmwp.exe chạy với reduced privileges
    - AppContainer sandbox cho vmwp.exe
    - KVAS (Kernel VA Shadow) chống Meltdown
    - Core scheduler chống HyperThreading side-channels
    - Retpoline / IBRS chống Spectre
```

### 9.9.2 Hypercall Fuzzing

```
Hypercall Fuzzing (kỹ thuật tìm vulnerability trong hypervisor):

  Target: Hyper-V hypercall handlers trong hvix64.exe
  
  Approach:
    1. Enumerate hypercalls: CPUID leaf 0x40000003 cho biết features
    2. Với mỗi hypercall code:
       a. Craft HV_X64_HYPERCALL_INPUT với:
          - Valid call code
          - Random fast/slow bit
          - Random rep count/start
       b. Craft input parameters:
          - Valid format nhưng extreme values
          - Invalid GPA ranges
          - Overlapping memory regions
          - Null pointers, max values
       c. Execute VMCALL
       d. Monitor cho crashes, hangs, information leaks
    
  Tools:
    - hAFL1/hAFL2: Hyper-V fuzzer (Intel PT-based coverage)
    - kAFL: Kernel fuzzer có thể target hypervisor
    - Custom VMCALL stubs trong kernel driver
    
  Lưu ý: Fuzzing hypervisor có thể crash TOÀN BỘ host
         -> Chỉ thực hiện trong isolated test environment
```

### 9.9.3 VMCS/EPT-Based Rootkits

```
Hypervisor-Based Rootkits (Blue Pill concept):

  Ý tưởng: Cài đặt thin hypervisor bên dưới OS đang chạy
  
  1. SubVirt / Blue Pill approach:
     a. Attacker có kernel access
     b. Enable VMX (VMXON)
     c. Setup VMCS với current OS state
     d. VMLAUNCH -> OS trở thành guest
     e. Rootkit hypervisor kiểm soát tất cả
     
  2. EPT-based stealth:
     a. Hook kernel functions qua EPT (stealth hooking)
     b. Hide files/processes bằng cách intercept SYSCALL
     c. Ẩn mình bằng EPT: rootkit code invisible cho OS
     
  3. Detection challenges:
     - Timing analysis (RDTSC overhead)
     - CPUID leaf differences
     - TLB behavior anomalies
     - Hardware performance counters
     
  4. Countermeasures:
     - Secure Boot: Ngăn rootkit load trước OS
     - VBS/HVCI: Ngăn unsigned code trong kernel
     - IOMMU: Ngăn DMA attacks
     - Hypervisor self-protection (Hyper-V đã load trước)
     - Windows Defender Credential Guard
     
  Đối với security researcher:
    - Hiểu rootkit technique để phát triển detection
    - Xây dựng EPT-based monitoring tools
    - Nghiên cứu hypervisor-based sandboxing
```

### 9.9.4 VBS Bypass Research

```
VBS/HVCI Bypass Techniques (nghiên cứu bảo mật):

  1. Data-Only Attacks:
     HVCI ngăn code modification nhưng KHÔNG ngăn data modification
     -> ROP/JOP chains vẫn hoạt động (dùng existing signed code)
     -> Overwrite function pointers trong kernel data structures
     -> Thay đổi CFG bitmap (nếu có thể)
     
  2. Signed Driver Abuse:
     HVCI cho phép mọi signed driver chạy
     -> Tìm signed driver có vulnerable IOCTL
     -> "Bring Your Own Vulnerable Driver" (BYOVD)
     -> Ví dụ: capcom.sys, RTCore64.sys
     -> Sử dụng driver vulnerability để arbitrary R/W kernel memory
     
  3. UEFI/Bootloader Attack:
     VBS trust chain bắt đầu từ UEFI
     -> Compromise UEFI firmware -> tắt VBS trước khi boot
     -> BlackLotus bootkit (CVE-2023-24932)
     -> Secure Boot bypass -> load malicious bootloader
     
  4. Hardware Attacks:
     -> DMA attack qua Thunderbolt/PCIe (trước khi IOMMU init)
     -> Cold boot attack (đọc memory sau reboot)
     -> JTAG debugging của CPU

  5. Race Conditions:
     -> TOCTOU giữa CI verification và EPT setup
     -> Page table manipulation timing windows
     
  Mỗi bypass thường dẫn tới Microsoft update VBS/HVCI
  -> Đây là cuộc đua vũ khí liên tục giữa offensive và defensive
```

### 9.9.5 Side-Channel Attacks trong VMs

```
Side-Channel Attacks Across VM Boundaries:

  1. Spectre Variant 2 (Branch Target Injection) Cross-VM:
     - Attacker VM và victim VM share physical CPU core (SMT)
     - Attacker train branch predictor của shared BTB
     - Victim VM có speculative execution dựa trên poisoned BTB
     - Attacker đọc leaked data qua cache timing
     
     Mitigation: Core Scheduler (Hyper-V), IBRS, STIBP

  2. L1TF (L1 Terminal Fault) / Foreshadow:
     - Tấn công EPT: đọc memory của VM khác qua L1 cache
     - Đặc biệt nguy hiểm cho virtualization
     - Attacker craft terminal page table entry
     - CPU speculation đọc L1 cache với physical address
     
     Mitigation: L1D flush on VM entry, PTE inversion,
                 disable HyperThreading (Core Scheduler)

  3. MDS (Microarchitectural Data Sampling):
     - RIDL, Fallout, ZombieLoad
     - Đọc data từ CPU internal buffers (store buffer, fill buffer)
     - Cross-VM information leak
     
     Mitigation: MD_CLEAR on VM exit, Core Scheduler

  4. Cache-Based Covert Channels:
     - VM A và VM B share L3 cache
     - VM A encode data bằng cache line access patterns
     - VM B decode bằng measuring access times
     - Bandwidth: ~100 Kbps - 1 Mbps
     
     Mitigation: Cache partitioning (Intel CAT), noise injection

  Hyper-V Mitigations:
    - Core Scheduler: VMs không share physical core
    - L1D flush: Xóa L1 cache khi VM switch
    - IBRS/STIBP: Spectre mitigation per-VM
    - MD_CLEAR: Clear CPU buffers on transitions
    - Retpoline: Indirect branch protection
    - KVAS: Kernel VA Shadow (Meltdown mitigation)
```

### 9.9.6 Hardening Recommendations

```
Virtualization Security Hardening Checklist:

  Host Level:
    [ ] Enable VBS + HVCI (bắt buộc trên Windows 11)
    [ ] Enable Credential Guard
    [ ] Enable Secure Boot + UEFI
    [ ] Update microcode (CPU firmware)
    [ ] Bật Core Scheduler (chống side-channel)
    [ ] Enable IOMMU (VT-d / AMD-Vi)
    [ ] Disable unnecessary emulated devices
    [ ] Use Generation 2 VMs (UEFI boot, no legacy devices)
    [ ] Enable Shielded VMs (sensitive workloads)
    
  VM Level:
    [ ] Enable Secure Boot trong VM
    [ ] Sử dụng vTPM (Virtual TPM)
    [ ] Bật BitLocker trong guest
    [ ] Disable Integration Services không cần thiết
    [ ] Limit VM network exposure (microsegmentation)
    [ ] Enable VM resource metering
    
  Container Level:
    [ ] Sử dụng Hyper-V isolation cho untrusted workloads
    [ ] Không chạy containers với admin/SYSTEM
    [ ] Scan container images cho vulnerabilities
    [ ] Sử dụng read-only root filesystem
    [ ] Limit container capabilities (Job Object limits)
    [ ] Network policies (không cho containers giao tiếp tùy ý)
```

---

## 9.10 [UPDATE 2026] Windows 11 24H2 và Beyond

### 9.10.1 VBS Improvements

```
Windows 11 24H2 VBS Updates:

  1. VBS Mandatory:
     - VBS bật mặc định trên tất cả Windows 11 24H2 clean install
     - HVCI enforcement mặc định
     - Không thể tắt VBS từ Group Policy (chỉ từ UEFI settings)
     
  2. Kernel DMA Protection Enhanced:
     - IOMMU protection cho tất cả Thunderbolt/USB4 devices
     - Hot-plug DMA device protection
     - Pre-boot DMA protection
     
  3. Smart App Control + HVCI:
     - AI-based code trust decisions
     - Unsigned code bị block bởi HVCI + reputation check
     
  4. VBS Enclaves (Preview):
     - Application-level VTL 1 memory isolation
     - Không cần full Secure Process (trustlet)
     - API: CreateEnclave(), CallEnclave()
     - Dùng cho: key management, sensitive computation
```

### 9.10.2 ARM64 Virtualization Support

```
ARM64 Virtualization (Hyper-V on ARM):

  [UPDATE 2026]
  
  ARM64 hardware virtualization:
    - EL2 (Exception Level 2) = Hypervisor mode
    - Stage-2 translation = Tương đương EPT
    - Mỗi Exception Level tương ứng với x86 ring:
      EL0 = User mode (Ring 3)
      EL1 = Kernel mode (Ring 0)
      EL2 = Hypervisor (VMX Root)
      EL3 = Secure Monitor (TrustZone)
    
  Hyper-V on ARM64:
    - Windows 11 on ARM (Snapdragon X series)
    - Hỗ trợ VBS/HVCI trên ARM
    - Emulation: x86/x64 apps chạy trong ARM VM
    - Hỗ trợ nested virtualization (preview)
    
  +----------------------------------+
  | Comparison: x86 vs ARM64        |
  +----------------+-----------------+
  | x86 (VT-x)    | ARM64           |
  +----------------+-----------------+
  | VMX Root/      | EL2             |
  | Non-Root       | (hypervisor)    |
  +----------------+-----------------+
  | EPT            | Stage-2         |
  |                | Translation     |
  +----------------+-----------------+
  | VMCS           | VTTBR_EL2 +     |
  |                | HCR_EL2 config  |
  +----------------+-----------------+
  | VMCALL         | HVC (Hypervisor |
  |                | Call) instruction|
  +----------------+-----------------+
  | VT-d (IOMMU)  | SMMU            |
  +----------------+-----------------+
```

### 9.10.3 Confidential VMs

```
Confidential VMs (Windows 11 24H2 / Azure):

  [UPDATE 2026]
  
  Mục đích: Bảo vệ VM memory khỏi hypervisor/host admin
  
  AMD SEV-SNP (Secure Encrypted Virtualization - Secure Nested Paging):
    - VM memory được encrypt bằng AES key riêng của VM
    - Hypervisor KHÔNG THỂ đọc VM memory (dù có root access)
    - SNP (Secure Nested Paging) = integrity protection cho guest pages
    - Attestation: VM có thể chứng minh mình chạy trên genuine hardware
    
  Intel TDX (Trust Domain Extensions):
    - Tương tự AMD SEV-SNP
    - TD (Trust Domain) = encrypted VM
    - SEAM (Secure Arbitration Mode) = TDX module trong CPU
    - Memory encryption + integrity
    - Remote attestation
    
  Windows Support:
    - Azure confidential VMs (GA)
    - On-premises Hyper-V (preview)
    - Paravisor: Shim giữa guest OS và encrypted hardware
    - vTPM trong confidential VM
    
  Architecture:
  +------------------------------------------+
  | Confidential VM                           |
  |  Guest OS (encrypted memory)             |
  |  vTPM (sealed to VM)                     |
  |  Attestation report                      |
  +------------------------------------------+
  | Paravisor (thin translation layer)        |
  +------------------------------------------+
  | Hardware encryption engine               |
  |  AES-256 per-VM key                      |
  |  Integrity check per-page               |
  +------------------------------------------+
  | Hypervisor (CANNOT read VM memory)        |
  +------------------------------------------+
  | CPU firmware (SEV-SNP / TDX module)       |
  +------------------------------------------+
  
  Security model:
    Trusted:     CPU hardware, VM owner
    Untrusted:   Hypervisor, host admin, cloud provider
    -> Đối ngược hoàn toàn so với traditional VM!
```

---

## 9.11 Experiments và WinDbg

### Experiment 9.1: Kiểm Tra Hyper-V Status

```powershell
# Kiểm tra hypervisor đang chạy
Get-ComputerInfo | Select-Object HyperVisorPresent,
    HyperVRequirementDataExecutionPreventionAvailable,
    HyperVRequirementSecondLevelAddressTranslation,
    HyperVRequirementVirtualizationFirmwareEnabled

# Chi tiết hơn
systeminfo | findstr /i "hyper-v"

# Kiểm tra Hyper-V features bằng CPUID
# (Chạy trong guest để phát hiện hypervisor)
# PowerShell script:
$sig = [System.Runtime.InteropServices.Marshal]
# Hoặc dùng tool: cpuid.exe, coreinfo.exe (Sysinternals)

# Coreinfo (Sysinternals)
coreinfo.exe -v    # Hiển thị virtualization support
```

### Experiment 9.2: VBS và HVCI Status Chi Tiết

```powershell
# Kiểm tra VBS/HVCI status
$dg = Get-CimInstance -ClassName Win32_DeviceGuard `
    -Namespace root\Microsoft\Windows\DeviceGuard

$dg | Format-List *

# Các properties quan trọng:
#   VirtualizationBasedSecurityStatus:
#     0 = Not enabled
#     1 = Enabled but not running
#     2 = Running
#
#   SecurityServicesConfigured / SecurityServicesRunning:
#     1 = Credential Guard
#     2 = HVCI (Memory Integrity)
#     3 = System Guard Secure Launch
#     4 = SMM Firmware Measurement
#
#   CodeIntegrityPolicyEnforcementStatus:
#     0 = Off
#     1 = Audit mode
#     2 = Enforced

# Kiểm tra từ msinfo32
msinfo32.exe
# System Summary -> Virtualization-based security: Running
# System Summary -> Device Guard: ...

# Registry check
reg query "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity
reg query "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled
```

### Experiment 9.3: WinDbg Hypervisor Debugging

```
Kernel Debugging với Hyper-V:

  Cấu hình:
    bcdedit /hypervisorsettings serial debugport:1 baudrate:115200
    bcdedit /set hypervisordebug on
    Hoặc: bcdedit /set hypervisordebugenabled on
    
  WinDbg commands:

  === Hypervisor Information ===
  kd> !hypervisor
    Hiển thị hypervisor status: running, version, features
    
  kd> !hvcallstats
    Thống kê hypercall: count, time per call
    -> Xem hypercall nào được gọi nhiều nhất
    
  kd> !hvexts.help
    List tất cả hvexts commands (Hyper-V debugger extension)

  === VMCS Inspection (nested / research) ===
  kd> !vmcs
    Dump current VMCS content (nếu có nested virt)
    
  kd> !vmread <encoding>
    Đọc một VMCS field cụ thể
    Ví dụ: !vmread 0x681E  (Guest RIP)
           !vmread 0x4402  (VM-exit reason)
           !vmread 0x4000  (Pin-based controls)
           !vmread 0x4002  (Primary processor-based controls)
           !vmread 0x201A  (EPT pointer)
    
  VMCS Field Encodings (một số quan trọng):
    0x4000 - Pin-based VM-execution controls
    0x4002 - Primary processor-based controls
    0x401E - Secondary processor-based controls
    0x2000 - I/O bitmap A address
    0x2002 - I/O bitmap B address
    0x2004 - MSR bitmap address
    0x201A - EPT pointer (EPTP)
    0x4004 - Exception bitmap
    0x681E - Guest RIP
    0x681C - Guest RSP
    0x6820 - Guest RFLAGS
    0x6800 - Guest CR0
    0x6802 - Guest CR3
    0x6804 - Guest CR4
    0x4402 - VM-exit reason
    0x6400 - Exit qualification

  === EPT Table Examination ===
  kd> !eptp <eptp_value>
    Dump EPT page table structure
    
  kd> !ept_walk <eptp> <gpa>
    Hiển thị EPT walk cho một GPA cụ thể
    -> Xem EPT permissions (R/W/X) cho từng page
    
  kd> !ept_translate <gpa>
    Dịch GPA sang HPA qua EPT
    
  kd> !pte2 <gpa>
    Xem EPT PTE cho một GPA (trên một số phiên bản)

  === VTL Debugging ===
  kd> .reload /s securekernel.exe
    Load symbols cho Secure Kernel (VTL 1)
    Lưu ý: VTL 1 memory không trực tiếp accessible từ VTL 0 debugger
    
  kd> !vtl
    Hiển thị VTL status của current processor
    
  kd> !process 0 0 Secure System
    Xem Secure System process (VTL 1 system process)
```

### Experiment 9.4: Examining Hyper-V Performance Counters

```powershell
# Xem các performance counter categories liên quan Hyper-V
Get-Counter -ListSet "*Hyper-V*" | Select-Object CounterSetName

# Xem VM Exit/Intercept statistics
Get-Counter "\Hyper-V Hypervisor Virtual Processor(*)\Total Intercepts/sec"
Get-Counter "\Hyper-V Hypervisor Virtual Processor(*)\Hypercalls/sec"

# Xem EPT violations
Get-Counter "\Hyper-V Hypervisor Virtual Processor(*)\Address Space Invalidations/sec"

# Xem các hypercall types
typeperf "\Hyper-V Hypervisor Virtual Processor(_Total)\Logical Processor Migrations/sec" -sc 5

# Monitor VM performance
Get-Counter -Counter @(
    "\Hyper-V Hypervisor Logical Processor(_Total)\% Total Run Time",
    "\Hyper-V Hypervisor Virtual Processor(_Total)\% Total Run Time",
    "\Hyper-V Hypervisor Root Virtual Processor(_Total)\% Total Run Time"
) -SampleInterval 2 -MaxSamples 10
```

### Experiment 9.5: Container Experiments

```powershell
# Windows Containers setup
Enable-WindowsOptionalFeature -Online -FeatureName Containers
Install-Module DockerMsftProvider -Force
Install-Package Docker -ProviderName DockerMsftProvider -Force

# Chạy container với process isolation
docker run --isolation=process `
    mcr.microsoft.com/windows/nanoserver:ltsc2022 `
    cmd /c "hostname && whoami"

# Chạy container với Hyper-V isolation
docker run --isolation=hyperv `
    mcr.microsoft.com/windows/nanoserver:ltsc2022 `
    cmd /c "hostname && whoami"

# Xem container processes từ host
Get-Process -Name "CExecSvc" | Format-List *
# CExecSvc.exe = Container Execution Service (chạy trong mỗi container)

# Xem Server Silo từ kernel debugger
kd> !process 0 0 CExecSvc.exe
kd> !silo <silo_address>        ; Hiển thị silo information
kd> !job <job_address>          ; Hiển thị job object của container

# Xem wcifs.sys filter
fltmc instances
# Sẽ thấy wcifs filter attach vào container volumes

# HCS commands
hcsdiag.exe list    ; List running compute systems (containers/VMs)
hcsdiag.exe read <id> ; Đọc container config
```

### Experiment 9.6: Kiểm Tra Virtualization Features Bằng CPUID

```
Viết chương trình C/Assembly để kiểm tra:

  ; Check VMX support
  MOV EAX, 1
  CPUID
  TEST ECX, (1 << 5)    ; Bit 5 = VMX
  JNZ vmx_supported
  
  ; Check hypervisor present
  MOV EAX, 1
  CPUID
  TEST ECX, (1 << 31)   ; Bit 31 = Hypervisor present
  JNZ hypervisor_running
  
  ; Read hypervisor vendor
  MOV EAX, 0x40000000
  CPUID
  ; EBX:ECX:EDX = "Microsoft Hv" (Hyper-V)
  ;              = "KVMKVMKVM\0\0\0" (KVM)
  ;              = "VMwareVMware" (VMware)
  ;              = "XenVMMXenVMM" (Xen)
  
  ; Read Hyper-V features
  MOV EAX, 0x40000003
  CPUID
  ; EAX = partition privileges
  ; EBX = flags (enlightenments)

PowerShell equivalent:
  # Dùng CpuId class từ .NET (hoặc tool cpuid.exe)
  # Hoặc đơn giản:
  (Get-WmiObject Win32_Processor).VirtualizationFirmwareEnabled
  (Get-WmiObject Win32_Processor).SecondLevelAddressTranslationExtensions
```

### Experiment 9.7: Hyper-V Event Tracing

```powershell
# Bật ETW tracing cho Hyper-V hypervisor
logman create trace HyperVTrace -p "Microsoft-Windows-Hyper-V-Hypervisor" `
    -o "C:\traces\hyperv.etl" -ets

# Chạy workload (start/stop VM, etc.)

# Dừng trace
logman stop HyperVTrace -ets

# Phân tích
# Dùng Windows Performance Analyzer (WPA):
wpa.exe C:\traces\hyperv.etl

# Hoặc dùng xperf:
xperf -i C:\traces\hyperv.etl -o C:\traces\hyperv.txt -a dumper
```

---

## 9.12 Tóm Tắt

| Khái niệm | Điểm chính |
|-----------|------------|
| VT-x/AMD-V | VMX Root/Non-Root, VMCS, VM Exit/Entry lifecycle |
| VMCS | 6 field categories: Guest state, Host state, Execution/Exit/Entry controls, Exit info |
| VMX Instructions | VMXON/VMXOFF, VMCLEAR/VMPTRLD, VMLAUNCH/VMRESUME, VMREAD/VMWRITE, VMCALL |
| MSR/IO Bitmaps | Chọn lọc instruction nào gây VM Exit, critical cho security |
| SLAT (EPT/NPT) | 4-level paging, GPA->HPA, tối đa 24 memory accesses, TLB cached |
| EPT PTE | R/W/X bits, memory type, accessed/dirty, MBEC (XU bit) |
| EPT Security | Stealth hooking, memory tracking, W^X enforcement |
| MBEC | Tách user/supervisor execute permissions trong EPT |
| Hyper-V | Type 1 hypervisor, hvix64/hvax64, root/child partitions |
| Hypercalls | VMCALL-based, HV_X64_HYPERCALL_INPUT format, hypercall page |
| Enlightenments | Synthetic MSRs, Reference TSC, SynIC, CPUID leaves |
| VTL 0/1 | Normal world / Secure world, EPT-enforced isolation |
| Secure Kernel | securekernel.exe, manages VTL 1, trustlets |
| Credential Guard | lsaiso.exe trong VTL 1, bảo vệ NTLM/Kerberos credentials |
| HVCI | VTL 1 kiểm soát EPT của VTL 0, chỉ signed code chạy được |
| VMBus | Ring buffer IPC, GPADL shared memory, SynIC signaling |
| Nested Virt | L0/L1/L2, EPT merging, VMCS shadowing |
| Containers | Server Silo (process isolation), Hyper-V isolation, HostProcess |
| Namespace | Object Manager, Registry, Filesystem (wcifs.sys), Network isolation |
| GPU-PV | Paravirtual GPU qua VMBus, shared GPU memory via SLAT |
| VM Escape | VMBus parsing, emulated devices, hypercall fuzzing |
| Side-Channels | Spectre, L1TF, MDS cross-VM; mitigation: Core Scheduler |
| VBS Bypass | Data-only attacks, BYOVD, UEFI/bootloader attacks |
| ARM64 Virt | EL2, Stage-2 translation, HVC instruction |
| Confidential VMs | AMD SEV-SNP, Intel TDX, encrypted VM memory |
| WinDbg | !hypervisor, VMCS fields, EPT walk, VTL inspection |

> **Tiếp theo: [Chapter 10 -- Quản Lý, Chẩn Đoán và Tracing](Chapter_10_Management_Diagnostics.md)**
