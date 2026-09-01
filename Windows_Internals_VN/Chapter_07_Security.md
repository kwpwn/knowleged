# Chapter 7: Bảo Mật (Security)

> Chương này cover toàn bộ security subsystem: access control model, tokens,
> SIDs, ACLs, privileges, integrity levels, UAC, exploit mitigations,
> Credential Guard, AppContainer, và Kernel Patch Protection.

---

## 7.1 Security Architecture

### 7.1.1 Security Components

```
┌──────────────────────────────────────────────────────────┐
│                    USER MODE                              │
│                                                          │
│  ┌────────────────┐  ┌────────────────┐                 │
│  │ Logon Process   │  │ LSA Process    │                 │
│  │ (winlogon.exe)  │  │ (lsass.exe)    │                 │
│  │ - SAS handling  │  │ - Authentication│                │
│  │ - Logon UI      │  │ - Token creation│                │
│  └────────────────┘  │ - Audit logging │                 │
│                       │ - Policy mgmt   │                 │
│  ┌────────────────┐  │ - Secret storage│                 │
│  │ Security       │  └────────────────┘                 │
│  │ Account DB     │                                      │
│  │ (SAM / AD)     │  ┌────────────────┐                 │
│  └────────────────┘  │ Auth Packages   │                 │
│                       │ - MSV1_0 (NTLM) │                │
│                       │ - Kerberos       │                │
│                       │ - Negotiate      │                │
│                       │ - CloudAP        │                │
│                       └────────────────┘                 │
╠══════════════════════════════════════════════════════════╣
│                    KERNEL MODE                            │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │  Security Reference Monitor (SRM)                   │  │
│  │  - Access checking (SeAccessCheck)                  │  │
│  │  - Privilege checking                               │  │
│  │  - Audit generation                                 │  │
│  │  - Token management                                 │  │
│  └────────────────────────────────────────────────────┘  │
╠══════════════════════════════════════════════════════════╣
│                    VTL 1 (Secure World)                   │
│                                                          │
│  ┌────────────────┐                                     │
│  │ lsaiso.exe      │  ← Credential Guard                │
│  │ (LSA Isolated)  │  ← NTLM hashes, Kerberos tickets  │
│  └────────────────┘    protected from VTL 0             │
└──────────────────────────────────────────────────────────┘
```

---

## 7.2 Security Identifiers (SIDs)

### 7.2.1 SID Format

```
S-1-5-21-3623811015-3361044348-30300820-1013
│ │ │  │            │            │          │
│ │ │  │            │            │          └── RID (Relative ID)
│ │ │  │            │            └────────────── Sub-authority 3
│ │ │  │            └─────────────────────────── Sub-authority 2
│ │ │  └──────────────────────────────────────── Sub-authority 1
│ │ └─────────────────────────────────────────── Identifier Authority (5 = NT Authority)
│ └───────────────────────────────────────────── Revision (always 1)
└─────────────────────────────────────────────── SID prefix
```

### 7.2.2 Well-Known SIDs

| SID | Tên | Ý nghĩa |
|-----|-----|---------|
| `S-1-0-0` | Nobody | Null SID |
| `S-1-1-0` | Everyone | Tất cả users |
| `S-1-2-0` | Local | Users logged on locally |
| `S-1-3-0` | Creator Owner | Placeholder cho owner |
| `S-1-5-7` | Anonymous | Anonymous logon |
| `S-1-5-11` | Authenticated Users | Users đã authenticate |
| `S-1-5-18` | Local System | SYSTEM account |
| `S-1-5-19` | Local Service | Limited service account |
| `S-1-5-20` | Network Service | Service với network credentials |
| `S-1-5-32-544` | Administrators | BUILTIN\Administrators |
| `S-1-5-32-545` | Users | BUILTIN\Users |
| `S-1-5-32-551` | Backup Operators | Backup privileges |
| `S-1-5-21-...-500` | Administrator | Built-in admin account |
| `S-1-5-21-...-501` | Guest | Built-in guest |
| `S-1-5-21-...-512` | Domain Admins | Domain admin group |
| `S-1-5-21-...-513` | Domain Users | Domain user group |

### 7.2.3 Integrity Level SIDs

| SID | Level | Label |
|-----|-------|-------|
| `S-1-16-0` | 0 | Untrusted |
| `S-1-16-4096` | 4096 | Low |
| `S-1-16-8192` | 8192 | Medium |
| `S-1-16-8448` | 8448 | Medium Plus |
| `S-1-16-12288` | 12288 | High |
| `S-1-16-16384` | 16384 | System |
| `S-1-16-20480` | 20480 | Protected Process |

---

## 7.3 Access Tokens

### 7.3.1 Token Structure

```
_TOKEN
├── TokenSource                    ← Who created token ("User32", "NTLM", ...)
├── TokenId                        ← Unique token identifier (LUID)
├── AuthenticationId               ← Logon session identifier
├── ParentTokenId                  ← Token this was derived from
├── ExpirationTime                 ← Token expiration
├── ModifiedId                     ← Changes on modification
│
├── UserAndGroupCount              ← Number of SID entries
├── UserAndGroups[]                ← Array of SID_AND_ATTRIBUTES:
│   ├── [0] User SID               ← S-1-5-21-...-1001 (the user)
│   ├── [1] Administrators          ← S-1-5-32-544 (may be deny-only in filtered token)
│   ├── [2] Users                   ← S-1-5-32-545
│   ├── [3] Everyone                ← S-1-1-0
│   ├── [4] INTERACTIVE             ← S-1-5-4
│   ├── [5] Authenticated Users     ← S-1-5-11
│   └── ... more groups
│
├── RestrictedSidCount             ← Restricted SIDs (sandbox)
├── RestrictedSids[]               ← If present, BOTH normal AND restricted must match
│
├── PrivilegeCount                 ← Number of privileges
├── Privileges[]                   ← LUID_AND_ATTRIBUTES:
│   ├── SeDebugPrivilege           ← (Enabled/Disabled)
│   ├── SeBackupPrivilege          ← ...
│   └── ...
│
├── PrimaryGroup                   ← Default group for new objects
├── DefaultDacl                    ← Default DACL for new objects
│
├── TokenType                      ← TokenPrimary / TokenImpersonation
├── ImpersonationLevel             ← SecurityAnonymous → SecurityDelegation
│
├── IntegrityLevelIndex            ← → Integrity SID in UserAndGroups
├── MandatoryPolicy                ← No-Write-Up, No-Read-Up, ...
│
├── Flags
│   ├── TOKEN_HAS_ADMIN_GROUP
│   ├── TOKEN_IS_FILTERED
│   ├── TOKEN_IS_RESTRICTED
│   └── TOKEN_LOWBOX (AppContainer)
│
├── PackageSid                     ← AppContainer SID (UWP)
├── Capabilities[]                 ← AppContainer capabilities
└── TrustLevelSid                  ← PPL signer level
```

### 7.3.2 Token Types

**Primary Token:** gắn với process, xác định security context.

**Impersonation Token:** cho phép thread tạm thời "giả danh" identity khác.

```c
// Thread impersonation
ImpersonateLoggedOnUser(hToken);
// Thread giờ có security context của token
// Access checks dùng impersonation token thay vì process token

RevertToSelf();
// Quay lại process token
```

**Impersonation Levels:**

| Level | Cho phép |
|-------|---------|
| SecurityAnonymous | Server không thể identify client |
| SecurityIdentification | Server biết client identity, KHÔNG thể act as |
| SecurityImpersonation | Server act as client (local only) |
| SecurityDelegation | Server act as client (remote too) |

### 7.3.3 Filtered Token (UAC)

Khi admin user logon, Windows tạo 2 tokens:

```
Full Admin Token:
├── User: Admin (S-1-5-21-...-1001)
├── Groups: Administrators (ENABLED)
├── Privileges: ALL enabled
├── Integrity: High
└── Used by: Elevated processes

Filtered Token (used by default):
├── User: Admin (S-1-5-21-...-1001)
├── Groups: Administrators (USE_FOR_DENY_ONLY)  ← Cannot grant access
├── Privileges: Most REMOVED (not just disabled)
├── Integrity: Medium
└── Used by: Non-elevated processes (explorer, browsers, ...)

UAC Elevation:
  User clicks "Run as Administrator"
  → consent.exe shows prompt
  → Process created with Full Admin Token
```

---

## 7.4 Security Descriptors và ACLs

### 7.4.1 Security Descriptor

```
_SECURITY_DESCRIPTOR
├── Revision                  ← Always 1
├── Sbz1                      ← Padding
├── Control                   ← Flags:
│   ├── SE_DACL_PRESENT       ← Has DACL
│   ├── SE_SACL_PRESENT       ← Has SACL
│   ├── SE_DACL_DEFAULTED     ← DACL from default
│   ├── SE_DACL_AUTO_INHERITED ← Inherited from parent
│   ├── SE_DACL_PROTECTED     ← Prevent inheritance
│   └── SE_SELF_RELATIVE      ← Contiguous layout (stored)
├── Owner                     ← Owner SID
├── Group                     ← Primary group SID
├── Dacl                      ← Discretionary ACL (access control)
└── Sacl                      ← System ACL (auditing)
```

### 7.4.2 Access Control List (ACL)

```
DACL:
┌──────────────────────────────────────────────────┐
│ ACL Header                                        │
│   AclRevision: 2                                  │
│   AceCount: 4                                     │
├──────────────────────────────────────────────────┤
│ ACE 0: ACCESS_DENIED_ACE                          │
│   SID: Guest (S-1-5-21-...-501)                   │
│   AccessMask: GENERIC_ALL                         │
│   ← Deny entries FIRST (evaluated before allow)   │
├──────────────────────────────────────────────────┤
│ ACE 1: ACCESS_ALLOWED_ACE                         │
│   SID: BUILTIN\Administrators (S-1-5-32-544)     │
│   AccessMask: GENERIC_ALL (Full Control)           │
├──────────────────────────────────────────────────┤
│ ACE 2: ACCESS_ALLOWED_ACE                         │
│   SID: SYSTEM (S-1-5-18)                          │
│   AccessMask: GENERIC_ALL                          │
├──────────────────────────────────────────────────┤
│ ACE 3: ACCESS_ALLOWED_ACE                         │
│   SID: BUILTIN\Users (S-1-5-32-545)              │
│   AccessMask: GENERIC_READ | GENERIC_EXECUTE      │
└──────────────────────────────────────────────────┘
```

### 7.4.3 Access Check Algorithm

```
SeAccessCheck(SecurityDescriptor, Token, DesiredAccess):

1. Owner check:
   If caller is owner AND requests READ_CONTROL/WRITE_DAC → GRANT

2. No DACL (NULL DACL):
   → GRANT all access (dangerous!)

3. Empty DACL (0 ACEs):
   → DENY all access

4. Walk ACEs in order:
   For each ACE:
     If ACE.SID matches any token SID (user or groups):
       If ACE is ACCESS_DENIED:
         If ACE.AccessMask & DesiredAccess → DENY immediately
       If ACE is ACCESS_ALLOWED:
         Grant bits in ACE.AccessMask
         If all DesiredAccess bits granted → GRANT

5. After all ACEs: if not all bits granted → DENY

IMPORTANT:
  - Deny ACEs evaluated before Allow (if ordered correctly)
  - Evaluation stops at first definitive result
  - Group disabled (USE_FOR_DENY_ONLY) → only deny ACEs apply
```

### 7.4.4 Mandatory Integrity Control (MIC)

```
Before DACL check, integrity check runs:

Token Integrity Level vs Object Integrity Label:

Policy: No-Write-Up (default):
  Token IL < Object IL → DENY WRITE access
  
Policy: No-Read-Up:
  Token IL < Object IL → DENY READ access

Policy: No-Execute-Up:
  Token IL < Object IL → DENY EXECUTE access

Example:
  Process (Medium IL) wants to write to file (High IL):
  → DENIED before DACL check even runs
  → Even if DACL says "Allow Everyone Full Control"

  Process (High IL) wants to write to file (Medium IL):
  → Integrity check passes → DACL check runs
```

---

## 7.5 Privileges

### 7.5.1 Important Privileges

| Privilege | Constant | Ý nghĩa | Nguy hiểm? |
|-----------|----------|---------|------------|
| SeDebugPrivilege | 20 | Open ANY process | **Cực kỳ** — full system compromise |
| SeBackupPrivilege | 17 | Read any file (bypass ACL) | **Rất cao** |
| SeRestorePrivilege | 18 | Write any file (bypass ACL) | **Rất cao** |
| SeTakeOwnershipPrivilege | 9 | Take ownership of any object | **Rất cao** |
| SeLoadDriverPrivilege | 10 | Load kernel driver | **Cực kỳ** — kernel code exec |
| SeImpersonatePrivilege | 29 | Impersonate any token | **Rất cao** |
| SeCreateTokenPrivilege | 2 | Create arbitrary tokens | **Cực kỳ** |
| SeTcbPrivilege | 7 | Act as part of OS | **Cực kỳ** |
| SeAssignPrimaryTokenPrivilege | 3 | Replace process token | **Rất cao** |
| SeIncreaseQuotaPrivilege | 5 | Increase process quota | Medium |
| SeSecurityPrivilege | 8 | Manage audit/security log | High |
| SeSystemEnvironmentPrivilege | 22 | Modify firmware env vars | High |
| SeChangeNotifyPrivilege | 23 | Bypass traverse checking | Low (everyone has) |
| SeShutdownPrivilege | 19 | Shutdown system | Low |
| SeRemoteShutdownPrivilege | 24 | Remote shutdown | Medium |
| SeUndockPrivilege | 25 | Undock laptop | Low |
| SeManageVolumePrivilege | 28 | Manage volumes | High |
| SeCreateGlobalPrivilege | 30 | Create global objects | Low |
| SeIncreaseBasePriorityPrivilege | 14 | Increase scheduling priority | Low |
| SeSystemProfilePrivilege | 11 | Profile system | Low |

### 7.5.2 Privilege Exploitation

```
SeDebugPrivilege → GAME OVER:
  OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsass_pid)
  → Read LSASS memory → dump credentials
  → Inject code into any process
  → Full system compromise

SeBackupPrivilege:
  NtOpenFile with FILE_OPEN_FOR_BACKUP_INTENT (CreateOptions)
  → Read SAM database, SYSTEM hive
  → Extract local password hashes offline

SeRestorePrivilege:
  → Write DLL to System32
  → Overwrite any system file
  → Plant backdoors

SeLoadDriverPrivilege:
  → Load vulnerable/custom kernel driver
  → Arbitrary kernel code execution
  → Disable security products

SeImpersonatePrivilege:
  → Potato attacks (various)
  → Capture SYSTEM token from named pipe
  → Elevate service account → SYSTEM
```

### 7.5.3 Enable/Check Privileges

```c
// Enable privilege
BOOL EnablePrivilege(LPCWSTR privilege) {
    TOKEN_PRIVILEGES tp;
    HANDLE hToken;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);
    LookupPrivilegeValue(NULL, privilege, &tp.Privileges[0].Luid);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
    CloseHandle(hToken);
    return GetLastError() == ERROR_SUCCESS;
}
```

```powershell
# Check current privileges
whoami /priv

# Check for specific user
whoami /priv /fo csv | ConvertFrom-Csv
```

---

## 7.6 User Account Control (UAC)

### 7.6.1 UAC Architecture

```
User Logon (Admin user):
    │
    ├── Create Full Token (High IL, all privileges)
    ├── Create Filtered Token (Medium IL, stripped privileges)
    │
    └── Explorer.exe starts with Filtered Token
            │
            ├── Normal apps inherit Filtered Token
            │   └── Medium integrity, limited privileges
            │
            └── "Run as Administrator":
                ├── consent.exe → UAC prompt (Secure Desktop)
                ├── User approves
                └── New process with Full Token (High IL)
```

### 7.6.2 Auto-Elevation

Một số Microsoft executables tự elevate mà không prompt:

```
Requirements for auto-elevation:
1. Signed by Microsoft (Windows publisher)
2. Manifested with:
   <requestedExecutionLevel level="highestAvailable" />
   hoặc
   <requestedExecutionLevel level="requireAdministrator" />
3. Located in trusted directory (System32, etc.)
4. Listed in auto-elevation whitelist (hoặc auto-elevate manifest flag)

Examples: mmc.exe, taskmgr.exe, control.exe applets
```

### 7.6.3 UAC Bypass Techniques (For Research)

```
Common patterns (detected/patched over time):

1. DLL hijacking in auto-elevated process
   - Find auto-elevated exe that loads DLL from writable path
   - Place malicious DLL → auto-elevated process loads it

2. File system virtualization abuse
   - Write to virtualized System32 path
   - Auto-elevated process reads from virtual location

3. COM object hijacking
   - Register COM object in HKCU (Medium IL writable)
   - Auto-elevated process instantiates COM from HKCU

4. Environment variable manipulation
   - Modify env var used by auto-elevated process
   - windir, SystemRoot spoofing

5. Token manipulation
   - Duplicate elevated token from accessible process
```

### 7.6.4 File System và Registry Virtualization

```
UAC Virtualization (legacy app compatibility):

App writes to: C:\Program Files\MyApp\config.ini  (fails — Medium IL)
                    ↓ Redirected
Actual write:  %LOCALAPPDATA%\VirtualStore\Program Files\MyApp\config.ini

App reads from: C:\Program Files\MyApp\config.ini
                    ↓ Check VirtualStore first
Actual read:   %LOCALAPPDATA%\VirtualStore\... (if exists)
               C:\Program Files\MyApp\... (fallback)

Similarly for Registry:
  HKLM\Software\MyApp → HKCU\Software\Classes\VirtualStore\Machine\Software\MyApp
```

---

## 7.7 AppContainer

### 7.7.1 AppContainer Model

**[UPDATE 2026]** AppContainer là sandbox model cho UWP và modern apps:

```
Regular Process:
├── Token: User SID + Group SIDs
├── Access: Based on user permissions
└── Can access: most user-accessible resources

AppContainer Process:
├── Token: User SID + Package SID + Capabilities
├── DENY: everything by default
├── ALLOW: only resources with AppContainer ACEs
│   OR matching capability SIDs
└── Cannot access: network, files, devices (unless capability granted)
```

### 7.7.2 Capabilities

```
Capability                          Ý nghĩa
─────────────────────────────────────────────────
internetClient                      Outbound internet
internetClientServer                Inbound + outbound internet
privateNetworkClientServer          Local network access
picturesLibrary                     Access Pictures folder
musicLibrary                        Access Music folder
videosLibrary                       Access Videos folder
documentsLibrary                    Access Documents folder
removableStorage                    USB drives
webcam                              Camera access
microphone                         Microphone access
location                           GPS/location
bluetooth                          Bluetooth access
```

### 7.7.3 AppContainer Token

```
AppContainer Token:
├── User SID: S-1-5-21-...-1001 (regular user)
├── Package SID: S-1-15-2-... (unique per app)
├── Capabilities:
│   ├── S-1-15-3-1 (internetClient)
│   ├── S-1-15-3-2 (internetClientServer)
│   └── S-1-15-3-1024-... (custom capability)
├── Integrity Level: Low (S-1-16-4096)
├── AppContainer flag: TRUE
└── LPAC (Less Privileged AppContainer): optional stricter mode

Access Check for AppContainer:
1. Standard DACL check (token SIDs vs ACEs)
2. PLUS: Package SID check (object must have matching ACE)
3. PLUS: ALL capabilities must be met
4. → Much more restrictive than regular processes
```

---

## 7.8 Exploit Mitigations Chi Tiết

### 7.8.1 DEP / NX (Data Execution Prevention)

```
Trước DEP:
  Stack/Heap: READ + WRITE + EXECUTE
  → Buffer overflow → inject shellcode → execute

Với DEP:
  Stack/Heap: READ + WRITE (no EXECUTE)
  Code: READ + EXECUTE (no WRITE)
  → Buffer overflow → shellcode on stack → EXECUTE fails → crash

Hardware implementation:
  PTE NX bit (bit 63) = 1 → page not executable
  CPU enforces: attempt to execute → #PF exception

Bypass: ROP (Return-Oriented Programming)
  → Reuse existing executable code gadgets
  → Chain gadgets to build payload without injecting code
```

### 7.8.2 ASLR (Address Space Layout Randomization)

```
Without ASLR:                    With ASLR:
ntdll.dll: 0x7FFE0000           ntdll.dll: 0x7FFA'1234'5000
kernel32:  0x7FFD0000           kernel32:  0x7FF9'ABCD'0000
Stack:     0x0012F000           Stack:     0x000C'5678'F000
Heap:      0x00150000           Heap:      0x0001'9ABC'0000

→ ROP gadget addresses unknown → cannot build chain
```

**[UPDATE 2026]** Windows ASLR variants:

| Type | Entropy | When Randomized |
|------|---------|----------------|
| Image ASLR | ~17 bits (x64) | Per-boot |
| Stack ASLR | ~17 bits | Per-thread |
| Heap ASLR | ~8 bits | Per-process |
| Force ASLR | n/a | Relocate non-ASLR images |
| Bottom-up ASLR | ~8 bits | VirtualAlloc addresses |
| High Entropy ASLR | ~24 bits (full user space range) | x64 only, /HIGHENTROPYVA |

### 7.8.3 CFG (Control Flow Guard)

```
Indirect call without CFG:
  call [rax]    ; rax could point ANYWHERE
                ; → Attacker controls rax → arbitrary code execution

With CFG:
  ; Compiler inserts before every indirect call:
  call __guard_check_icall    ; Validate target address
  call [rax]                  ; Only if target is valid

__guard_check_icall:
  ; Check if rax is in bitmap of valid call targets
  ; Bitmap generated at compile time
  ; Invalid target → fast fail → process terminates

CFG Bitmap:
  Bit per 8-byte aligned address
  1 = valid call target (function entry point)
  0 = invalid → abort
```

### 7.8.4 XFG (eXtended Flow Guard)

**[UPDATE 2026]** Extends CFG with type information:

```
CFG: checks if target is ANY valid function
XFG: checks if target has MATCHING type signature

void (*callback)(int, char*);
callback = evil_function;  // evil_function takes (double)
call [callback]

CFG: ✓ evil_function is a valid target (it's a function entry point)
XFG: ✗ evil_function signature doesn't match (int,char*) → abort

→ Much smaller set of valid targets → harder to exploit
```

### 7.8.5 CET (Control-flow Enforcement Technology)

**[UPDATE 2026]** Hardware-based shadow stacks:

```
Normal Stack:              Shadow Stack (read-only):
┌──────────────┐           ┌──────────────┐
│ local vars   │           │              │
│ return addr  │ ══════════│ return addr  │ ← Must match
│ parameters   │           │              │
│ local vars   │           │              │
│ return addr  │ ══════════│ return addr  │ ← Must match
└──────────────┘           └──────────────┘

ROP attack:
  Overflow overwrites return addr on normal stack
  Shadow stack still has original return addr
  RET instruction: CPU compares both
  MISMATCH → #CP (Control Protection) exception → process crashes

  → ROP attacks DEFEATED by hardware
```

### 7.8.6 ACG (Arbitrary Code Guard)

```
Process with ACG enabled:
  ✗ VirtualAlloc with PAGE_EXECUTE_* → DENIED
  ✗ VirtualProtect to add EXECUTE → DENIED
  ✗ CreateFileMapping with SEC_IMAGE for unsigned → DENIED

  ✓ Execute existing signed code
  ✓ Load signed DLLs

→ Prevents JIT compilation attacks
→ Used by: Edge browser content process, some system processes
→ Incompatible with: JIT compilers (V8, .NET RyuJIT in some modes)
```

### 7.8.7 CIG (Code Integrity Guard)

```
Process with CIG enabled:
  ✗ LoadLibrary unsigned DLL → DENIED
  ✗ LoadLibrary DLL signed by untrusted publisher → DENIED
  ✓ Load only Microsoft-signed (or WHQL) DLLs

→ Prevents DLL injection with unsigned payloads
→ Used by: Protected processes, some system services
```

---

## 7.9 Kernel Patch Protection (PatchGuard)

### 7.9.1 What PatchGuard Protects

```
PatchGuard monitors for unauthorized modifications:

✗ SSDT (System Service Descriptor Table) hooking
✗ IDT (Interrupt Descriptor Table) modification
✗ GDT (Global Descriptor Table) modification
✗ MSR (Model-Specific Register) tampering
✗ Kernel code patching (ntoskrnl.exe, hal.dll)
✗ Critical kernel data structures modification
✗ Debug-related MSRs tampering
✗ Processor control registers modification
✗ Object type overwriting

Detection → BSOD: CRITICAL_STRUCTURE_CORRUPTION (0x109)
```

### 7.9.2 PatchGuard Implementation

```
PatchGuard characteristics:
├── Random timer-based checking (unpredictable intervals)
├── Multiple redundant check contexts
├── Obfuscated/encrypted check routines
├── Anti-debug detection
├── Self-integrity verification
├── DPC timer, work items, APC, exception handler contexts
└── Continuously updated/hardened each Windows release

Timeline:
  x64 Windows XP (2005): PatchGuard v1
  Vista: PatchGuard v2 (anti-bypass improvements)
  Windows 7: PatchGuard v3
  Windows 10/11: Continuously evolving
```

### 7.9.3 HyperGuard

**[UPDATE 2026]** HyperGuard extends PatchGuard using hypervisor:

```
PatchGuard:
  Runs in kernel mode (Ring 0)
  → Kernel rootkit at same privilege → can potentially bypass

HyperGuard:
  Runs in hypervisor / VTL 1 (Ring -1)
  → Kernel rootkit CANNOT reach hypervisor
  → Cannot disable checks
  → Cannot modify check routines

HyperGuard checks:
  ├── Kernel code integrity
  ├── Critical data structures
  ├── SSDT / IDT integrity
  ├── Secure kernel integrity
  └── VTL 0 → VTL 1 transition integrity
```

---

## 7.10 Authentication

### 7.10.1 Logon Process

```
1. User presses Ctrl+Alt+Del (Secure Attention Sequence)
   └── winlogon.exe receives SAS

2. Credential Provider (LogonUI.exe):
   ├── Password
   ├── Smart Card
   ├── Windows Hello (PIN, fingerprint, face)
   ├── FIDO2 security key
   └── Cloud AP (Azure AD)

3. winlogon.exe → LsaLogonUser()
   └── LSA selects authentication package:
       ├── MSV1_0: NTLM (local/workgroup)
       │   ├── Hash password → NT hash
       │   ├── Compare with SAM database
       │   └── Or challenge-response with DC
       ├── Kerberos: Domain authentication
       │   ├── TGT request to KDC
       │   ├── Validate credentials
       │   └── Issue TGT + session key
       └── Negotiate: Auto-select best (Kerberos > NTLM)

4. Success → LSA creates logon session:
   ├── Create access token
   ├── Store credentials in credential store
   └── Return token to winlogon

5. winlogon.exe:
   ├── Load user profile (NtLoadKey → NTUSER.DAT)
   ├── Apply Group Policy
   └── Create explorer.exe with user token
```

### 7.10.2 Credential Storage

```
Credential locations:
├── SAM Database (local accounts):
│   File: %SystemRoot%\System32\config\SAM
│   Format: NT hash (MD4 of UTF-16LE password)
│   Protection: SYSKEY encryption, kernel-locked
│
├── LSA Secrets:
│   Registry: HKLM\SECURITY\Policy\Secrets
│   Contents: Service account passwords, cached domain creds,
│             VPN passwords, auto-logon credentials
│
├── LSASS Memory (runtime):
│   Contains: plaintext passwords, NT hashes, Kerberos tickets,
│             WDigest credentials
│   Attack: mimikatz sekurlsa::logonpasswords
│
├── Credential Manager:
│   Location: %APPDATA%\Microsoft\Credentials\
│   Contains: Saved passwords (web, network)
│   API: CredRead/CredWrite
│
└── DPAPI:
    Master keys: %APPDATA%\Microsoft\Protect\
    Encrypts: Credential Manager, browser passwords, ...
    Key derivation: from user password + SID
```

### 7.10.3 Credential Guard

**[UPDATE 2026]** Isolates credentials in VTL 1:

```
Without Credential Guard:
  LSASS (VTL 0) stores: NT hashes, Kerberos tickets
  Kernel compromise → dump all credentials
  
With Credential Guard:
  LSASS (VTL 0): handles auth protocol, NO secrets stored
  lsaiso.exe (VTL 1): stores actual secrets
    ├── NT hashes
    ├── Kerberos TGTs
    └── Derived credentials
  
  Kernel compromise at VTL 0:
    ✗ Cannot read VTL 1 memory
    ✗ Cannot inject code into lsaiso.exe
    ✗ Cannot extract credential material
    → Credential theft BLOCKED
```

---

## 7.11 Security Auditing

### 7.11.1 Audit Categories

```
Advanced Audit Policy (auditpol.exe):

Category                          Subcategories
─────────────────────────────────────────────────
Account Logon                     Credential Validation
                                  Kerberos Authentication
                                  Kerberos Service Ticket

Account Management                User Account Management
                                  Computer Account Management
                                  Security Group Management

Detailed Tracking                 Process Creation (Event 4688)
                                  Process Termination (4689)
                                  DPAPI Activity
                                  PNP Activity

Logon/Logoff                      Logon (4624)
                                  Logoff (4634)
                                  Special Logon (4672)
                                  Network Policy Server

Object Access                     File System
                                  Registry
                                  Kernel Object
                                  Handle Manipulation
                                  Filtering Platform

Policy Change                     Audit Policy Change
                                  Auth Policy Change
                                  MPSSVC Rule-Level

Privilege Use                     Sensitive Privilege Use
                                  Non Sensitive Privilege Use

System                           Security State Change
                                  Security System Extension
                                  System Integrity
```

### 7.11.2 Key Security Events

| Event ID | Category | Ý nghĩa |
|----------|----------|---------|
| 4624 | Logon | Successful logon |
| 4625 | Logon | Failed logon |
| 4634 | Logon | Logoff |
| 4648 | Logon | Explicit credential logon (runas) |
| 4672 | Logon | Special privileges assigned |
| 4688 | Process | New process created |
| 4689 | Process | Process exited |
| 4697 | System | Service installed |
| 4698 | Object | Scheduled task created |
| 4720 | Account | User account created |
| 4722 | Account | User account enabled |
| 4732 | Account | Member added to local group |
| 4738 | Account | User account changed |
| 4768 | Kerberos | TGT requested |
| 4769 | Kerberos | Service ticket requested |
| 4776 | Account | NTLM auth attempt |
| 7045 | System | New service installed |

---

## 7.12 Experiments

### Experiment 7.1: Token Inspection

```powershell
whoami /all                          # Full token info
whoami /priv                         # Privileges
whoami /groups                       # Group memberships

# Process Explorer: process → Properties → Security tab
```

```
kd> !token                           ; Current thread token
kd> !token -n                        ; With SID name resolution
kd> dt nt!_TOKEN <addr>              ; Raw token structure
```

### Experiment 7.2: Access Check

```powershell
# Sysinternals AccessChk
accesschk.exe -l C:\Windows\System32\config\SAM
accesschk.exe -p lsass.exe
accesschk.exe -k HKLM\SAM
```

### Experiment 7.3: Security Descriptors

```
kd> !sd <addr>                       ; Parse security descriptor
kd> !acl <acl_addr>                  ; Parse ACL

# icacls for file permissions
icacls C:\Windows\System32\notepad.exe
```

### Experiment 7.4: Integrity Levels

```powershell
# Check process integrity
Get-Process | ForEach-Object {
    $p = $_
    try {
        $h = [System.Diagnostics.Process]::GetProcessById($p.Id).Handle
    } catch {}
}

# Sysinternals Process Explorer → Security tab → Integrity Level
```

### Experiment 7.5: Privilege Escalation Paths

```
;; Common Windows privilege escalation vectors for research:

1. Token Manipulation:
   ;; Steal SYSTEM token using SeDebugPrivilege:
   kd> !process 0 0 winlogon.exe       ; Find SYSTEM process
   kd> !token <winlogon_token_addr>    ; Verify it's SYSTEM
   ;; Tool: whoami /priv → SeDebugPrivilege Enabled
   ;; → OpenProcess(PROCESS_QUERY_INFORMATION, lsass_pid)
   ;; → OpenProcessToken → DuplicateToken → CreateProcessAsUser
   ;; → New process runs as SYSTEM

2. Named Pipe Impersonation (Potato family):
   ;; Setup: create pipe, trick SYSTEM service to connect
   ;; ImpersonateNamedPipeClient() → get SYSTEM token
   ;; Tools: JuicyPotato, PrintSpoofer, GodPotato
   ;; Detection: Event 4688 + 4648 sequence from service process

3. Service Misconfiguration:
   ;; accesschk.exe -uwcqv "Authenticated Users" * /accepteula
   ;; Find services where non-admin has SERVICE_CHANGE_CONFIG
   ;; → sc config VulnSvc binpath= "cmd /c net user attacker P@ss /add"
   ;; → sc stop VulnSvc && sc start VulnSvc

4. DLL Hijacking:
   ;; procmon.exe → Filter: Result=NAME NOT FOUND AND Path=*.dll
   ;; → Find DLLs loaded from writable paths
   ;; → Place malicious DLL → service restart → code execution

5. Unquoted Service Path:
   ;; wmic service get name,displayname,pathname,startmode | findstr /v /i "C:\Windows"
   ;; "C:\Program Files\Vulnerable App\service.exe"
   ;; → Place C:\Program.exe or C:\Program Files\Vulnerable.exe
```

### Experiment 7.6: Security Mitigation Analysis

```powershell
# Check process mitigations:
Get-ProcessMitigation -Name msedge.exe
# Shows: DEP, ASLR, CFG, CIG, ACG, Extension Points, Image Load

# System-wide mitigations:
Get-ProcessMitigation -System

# WinDbg — check mitigations for a process:
# kd> !process 0 0 msedge.exe
# kd> dt nt!_EPROCESS <addr> MitigationFlags MitigationFlags2
#   MitigationFlags:
#     ControlFlowGuardEnabled : 1
#     ControlFlowGuardExportSuppressionEnabled : 1
#     ControlFlowGuardStrict : 1
#   MitigationFlags2:
#     CetUserShadowStacks : 1
#     CetDynamicApisOutOfProcOnly : 1

# Check HVCI status:
# (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).CodeIntegrityPolicyEnforcementStatus
# 0 = Off, 1 = Audit, 2 = Enforced
```

### Experiment 7.7: AppContainer Sandbox Analysis

```
;; Inspect AppContainer token:
kd> !process 0 0 MicrosoftEdge.exe
kd> !token <addr>
  → AppContainer SID: S-1-15-2-...
  → Capabilities:
      internetClient (S-1-15-3-1)
      internetClientServer (S-1-15-3-2)
      privateNetworkClientServer (S-1-15-3-3)
      ...

;; AppContainer access rules:
;;   1. Standard DACL check (must pass)
;;   2. THEN AppContainer check:
;;      - Object must have AppContainer ACE
;;      - OR capability ACE matching container's capabilities
;;      - Otherwise: ACCESS_DENIED even if DACL allows
;;
;; Result: AppContainer process cannot:
;;   ✗ Read other users' files
;;   ✗ Access network without capability
;;   ✗ Access registry outside container hive
;;   ✗ Enumerate processes
;;   ✗ Access named objects from other containers

;; LPAC (Less Privileged AppContainer):
;;   Even more restricted — used by Chromium
;;   ALL:DENY ACE + specific ALLOW for needed resources only
```

### Experiment 7.8: Credential Storage Locations

```
Credential storage locations (forensics reference):

┌──────────────────────────────────────────────────────────┐
│ Location              │ Contents        │ Protection     │
├───────────────────────┼─────────────────┼────────────────┤
│ SAM database          │ NTLM hashes     │ SYSTEM key     │
│ %SystemRoot%\System32\│ (local users)   │ encryption     │
│ config\SAM            │                 │ + SYSKEY       │
├───────────────────────┼─────────────────┼────────────────┤
│ LSASS process memory  │ Plaintext (old),│ PPL protection │
│                       │ NTLM, Kerberos  │ Credential     │
│                       │ tickets, keys   │ Guard (VTL 1)  │
├───────────────────────┼─────────────────┼────────────────┤
│ NTDS.dit (DC only)    │ All domain      │ EDB encryption │
│                       │ hashes          │ + PEK key      │
├───────────────────────┼─────────────────┼────────────────┤
│ LSA Secrets           │ Service account │ DPAPI + SYSTEM │
│ HKLM\SECURITY\Policy\ │ passwords,     │ key            │
│ Secrets               │ autologon,     │                │
│                       │ VPN passwords   │                │
├───────────────────────┼─────────────────┼────────────────┤
│ DPAPI                 │ User's encrypted│ Master key     │
│ %AppData%\Microsoft\  │ blobs (browser  │ derived from   │
│ Protect\<SID>\        │ passwords, etc) │ user password  │
├───────────────────────┼─────────────────┼────────────────┤
│ Credential Manager    │ Stored creds    │ DPAPI          │
│ %LocalAppData%\       │ (Web, Windows)  │                │
│ Microsoft\Credentials │                 │                │
└──────────────────────────────────────────────────────────┘

With Credential Guard enabled (VTL 1):
  - Kerberos TGTs stored in lsaiso.exe (VTL 1) — NOT in lsass
  - NTLM hash derivation happens in VTL 1
  - Even kernel compromise at VTL 0 cannot extract
  - Mimikatz "sekurlsa::logonpasswords" returns encrypted blobs
```

---

## 7.13 Tóm Tắt

| Khái niệm | Điểm chính |
|------------|------------|
| SID | Unique identifier cho users, groups, computers |
| Access Token | Process identity: user, groups, privileges, IL |
| Security Descriptor | Object protection: owner, DACL, SACL |
| Access Check | Token vs SD → Grant/Deny per-access-right |
| Integrity Levels | Mandatory check before DACL, No-Write-Up |
| Privileges | 35+ special rights, some = full compromise |
| UAC | Filtered token cho admin, consent prompt for elevation |
| AppContainer | Deny-by-default sandbox, capability-based |
| DEP/NX | No-execute on data pages |
| ASLR | Randomize addresses, high entropy on x64 |
| CFG/XFG | Validate indirect call targets |
| CET | Hardware shadow stack, defeat ROP |
| ACG | Block dynamic code generation |
| PatchGuard/HyperGuard | Kernel integrity monitoring |
| Credential Guard | VTL 1 credential isolation |

> **Tiếp theo: [Chapter 8 — Cơ Chế Hệ Thống](Chapter_08_System_Mechanisms.md)**
> Trap dispatching, synchronization, ALPC, Object Manager internals.
