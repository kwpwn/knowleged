# Windows Internals — Tài Liệu Tham Khảo Tiếng Việt

> Tài liệu tham khảo chuyên sâu về kiến trúc nội bộ hệ điều hành Windows.
> Dựa trên kiến thức chung về Windows internals, cập nhật đến Windows 11 24H2 / Server 2025 (2026).
> Viết cho security researchers, system administrators, và kernel developers.

## Mục Lục

### Part 1 — Kiến Trúc Hệ Thống, Processes, Threads, Memory

| Chương | Tiêu đề | File |
|--------|---------|------|
| 1 | Khái niệm và công cụ | [Chapter_01](Chapter_01_Concepts_and_Tools.md) |
| 2 | Kiến trúc hệ thống | [Chapter_02](Chapter_02_System_Architecture.md) |
| 3 | Processes và Jobs | [Chapter_03](Chapter_03_Processes_and_Jobs.md) |
| 4 | Threads | [Chapter_04](Chapter_04_Threads.md) |
| 5 | Quản lý bộ nhớ | [Chapter_05](Chapter_05_Memory_Management.md) |
| 6 | Hệ thống I/O | [Chapter_06](Chapter_06_IO_System.md) |
| 7 | Bảo mật | [Chapter_07](Chapter_07_Security.md) |

### Part 2 — System Mechanisms, Virtualization, File Systems, Boot

| Chương | Tiêu đề | File |
|--------|---------|------|
| 8 | Cơ chế hệ thống | [Chapter_08](Chapter_08_System_Mechanisms.md) |
| 9 | Công nghệ ảo hóa | [Chapter_09](Chapter_09_Virtualization.md) |
| 10 | Quản lý, chẩn đoán và tracing | [Chapter_10](Chapter_10_Management_Diagnostics.md) |
| 11 | Caching và hệ thống tập tin | [Chapter_11](Chapter_11_Caching_File_Systems.md) |
| 12 | Startup và Shutdown | [Chapter_12](Chapter_12_Startup_Shutdown.md) |

## Quy ước

- **Kernel structure**: hiển thị dạng `_EPROCESS`, `_KTHREAD`
- **API functions**: hiển thị dạng `NtCreateProcess()`, `ZwOpenFile()`
- **Registry keys**: hiển thị dạng `HKLM\SYSTEM\CurrentControlSet\...`
- **Công cụ**: WinDbg, Process Explorer, Process Monitor, và các Sysinternals tools
- **[UPDATE 2026]**: đánh dấu nội dung mới so với Windows 10 1703/Server 2016

## Phiên bản Windows được đề cập

| Phiên bản | Build | Năm |
|-----------|-------|-----|
| Windows 10 1703 (Creators Update) | 15063 | 2017 |
| Windows 10 21H2 | 19044 | 2021 |
| Windows 11 21H2 | 22000 | 2021 |
| Windows 11 22H2 | 22621 | 2022 |
| Windows 11 23H2 | 22631 | 2023 |
| Windows 11 24H2 | 26100 | 2024 |
| Windows Server 2022 | 20348 | 2021 |
| Windows Server 2025 | 26100 | 2024 |
