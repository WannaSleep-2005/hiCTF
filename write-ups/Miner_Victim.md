# The Miner That Mined The Victim - Write-up

Đề cho mình một bộ triage ổ C của máy nạn nhân. Người dùng tải phần mềm CoinBoost Pro v3.2, tưởng là tool tối ưu đào coin miễn phí. Chạy xong thì các file văn bản bị mã hóa, Desktop xuất hiện thư đòi tiền chuộc. Nạn nhân sau đó xóa thư mục chứa tool.

Nhiệm vụ là dựng lại những gì đã xảy ra và trả lời 14 câu hỏi liên tiếp.

### Câu 1 - Phiên bản OS khi malware chạy

Mở file:

C:\Users\milon1\AppData\Local\Temp\ransomware_debug.log

Trong log có dòng:

OS Version: Microsoft Windows NT 10.0.26200.0

> Trả lời:

Microsoft Windows NT 10.0.26200.0

### Câu 2 - Múi giờ thực tế và ActiveTimeBias

Đọc hive SYSTEM, vào key:

ControlSet001\Control\TimeZoneInformation

Các giá trị đáng chú ý:

TimeZoneKeyName = Pacific Standard Time
Bias = 480
DaylightBias = -60
ActiveTimeBias = 420

ActiveTimeBias = 420 nghĩa là giờ địa phương chậm hơn UTC 420 phút, tức 7 tiếng.

Điều này cũng giải thích vì sao malware log ghi khoảng 07:26, còn Sysmon ghi 14:26.

> Trả lời:

UTC-7, 420

### Câu 3 - URL tải malware, bao gồm fragment

Kiểm tra database lịch sử Edge:

C:\Users\milon1\AppData\Local\Microsoft\Edge\User Data\Default\History

Trong bảng urls, tìm được trang Telegraph quảng cáo tool và link LimeWire:

https://telegra.ph/CoinBoost-Pro-v32--Free-Mining-Optimizer-05-12
https://limewire.com/d/Ak55K#Yrx3FgK3du

Phần sau dấu # cũng phải giữ nguyên.

> Trả lời:

https://limewire.com/d/Ak55K#Yrx3FgK3du

### Câu 4 - downloadId của URL chuyển hướng

Trong Sysmon Event ID 15, dữ liệu Zone.Identifier của miner.zip ghi:

ReferrerUrl=https://limewire.com/d/Ak55K
HostUrl=https://limewire.com/decrypt/download?downloadId=42d377fe-8948-4a32-809f-69a51e6dbcfa

> Trả lời:

42d377fe-8948-4a32-809f-69a51e6dbcfa

### Câu 5 - Thời điểm tải xong

Tiếp tục xem bảng downloads trong database History.

Bản ghi của miner.zip có:

received_bytes = 77944
total_bytes = 77944
end_time = 13423155936833030

Timestamp Chromium tính bằng microsecond kể từ 1601-01-01. Chuyển đổi bằng Python:

from datetime import datetime, timedelta

print(
datetime(1601, 1, 1) + timedelta(microseconds=13423155936833030)
)

Kết quả:

2026-05-13 14:25:36.833030

> Trả lời theo định dạng đề yêu cầu:

2026-05-13 14:25:36 UTC

### Câu 6 - Malware có chạy không, chạy lúc nào và bao nhiêu lần?

Có file Prefetch:

C:\Windows\Prefetch\MINER.EXE-9A2B223D.pf

Phân tích Prefetch cho thấy:

Run count: 1
Execution time: 2026-05-13 14:26:55.567595 UTC

UserAssist có timestamp 14:26:52, nhưng đây không phải thời điểm thực thi mà câu hỏi chấp nhận. Prefetch xác nhận executable đã thực sự chạy.

> Trả lời:

2026-05-13 14:26:55 UTC, 1

### Câu 7 - Assembly mã hóa được load

Lọc Sysmon Event ID 7 theo miner.exe và từ khóa Cryptography.

Tìm được:

ImageLoaded:
C:\Program Files\dotnet\shared\Microsoft.NETCore.App\9.0.16\System.Security.Cryptography.dll

UtcTime:
2026-05-13 14:26:58.931

Assembly được load ngay trước khi malware tạo các file .vibed.

> Trả lời:

C:\Program Files\dotnet\shared\Microsoft.NETCore.App\9.0.16\System.Security.Cryptography.dll, 2026-05-13 14:26:58 UTC

### Câu 8 - Registry value bị sửa thành công

Malware log ghi:

ERROR in DisableRealtimeProtection:
Requested registry access is not allowed.

SUCCESS: Set DisableAntiSpyware=1

Đối chiếu Sysmon Event ID 13:

TargetObject:
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware

Details:
DWORD (0x00000001)

> Trả lời:

HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware

Lưu ý nhỏ: ghi registry thành công chưa chứng minh Defender đã bị vô hiệu hóa. Defender còn ghi nhận thay đổi này là Ignored / Not Applicable.

### Câu 9 - MITRE ATT&CK technique hiện tại

Hành vi sửa cấu hình để vô hiệu hóa công cụ bảo vệ tương ứng với Disable or Modify Tools.

Đề hỏi ID hiện tại, nên dùng T1685. Có thể kiểm tra trên trang MITRE ATT&CK (https://attack.mitre.org/techniques/T1685/).

> Trả lời:

T1685

### Câu 10 - Khôi phục đoạn text quan trọng

Trong Documents có hai tên file khá lạ:

vzcbegnag.txt.vibed
vg'f fbzrjurer.txt.vibed

ROT13 hai tên này sẽ được:

important.txt
it's somewhere.txt

Mình tìm thêm trong $MFT. Một bản ghi chứa dữ liệu resident còn giữ nguyên đoạn:

hiCTF{finally_u_proved_ur_worthiness}

Đây là nội dung cần nộp cho câu 10, chưa phải flag cuối của instance.

> Trả lời:

hiCTF{finally_u_proved_ur_worthiness}

### Câu 11 - Thư mục bị xóa và thời điểm xóa

Trong $MFT, khôi phục được metadata Recycle Bin của file:

$IGDL3PH

File $I lưu đường dẫn gốc, kích thước và thời điểm xóa. Dữ liệu giải mã được:

Original path:
C:\Users\milon1\Downloads\miner

Deletion time:
2026-05-13 14:27:47.957 UTC

> Trả lời:

C:\Users\milon1\Downloads\miner, 2026-05-13 14:27:47 UTC

### Câu 12 - Kích thước thư mục đã xóa

Cũng trong metadata $I, trường kích thước có giá trị:

0x2BDA7 = 179623 bytes

> Trả lời:

179623

### Câu 13 - Plaintext của bar.txt

File hiện tại là:

bar.txt.vibed

Nội dung đã bị mã hóa. Tuy nhiên, khi kiểm tra các bản ghi $MFT, tìm được một bản sao văn bản còn lưu trong file cache có tên dạng hash:

I will always be there for you bro!

Nộp nội dung này và server xác nhận đúng.

> Trả lời:

I will always be there for you bro!

### Câu 14 - Chuỗi ASCII của shred pattern

Tìm sự kiện xóa noting.txt trong Sysmon Event ID 23:

TargetFilename:
C:\Users\milon1\Documents\noting.txt

Archived:
false - shredded file with pattern 0x706c6568

Đổi số 32-bit này thành byte theo thứ tự little-endian trên đĩa:

0x706c6568
↓
68 65 6c 70
↓
h e l p

> Trả lời:

help

Sau khi trả lời đủ 14 câu, instance in ra flag:

hiCTF{c4r3ful_4b0ut_cr4ck3d_t001s_b4c108e678}
