# Write-up: signal\_lock (hiCTF – Reverse Engineering)

*Thể loại: Reverse Engineering · Nền tảng: Erlang/OTP 26 (BEAM) · Flag format: `hiCTF{}`*

## 1. Đề bài

Một module anti-cheat của server xếp hạng được phát hành dưới dạng file `signal_lock.beam` đã strip, không có source. Hàm `signal_lock:verify/1` nhận một token. Token đúng trả về `{ok, <<"hiCTF{...}">>}`, token sai trả về lỗi. Mục tiêu là tìm token duy nhất mà validator chấp nhận và lấy flag. Đề yêu cầu Erlang/OTP 26 trở lên, vì module dùng opcode mới mà runtime cũ không nạp được.

**Kết quả:**

- Token: `g4m30v3r` (8 byte ASCII, tức số 64-bit `0x67346d3330763372`)
- Flag: `hiCTF{b34m_byt3c0d3_n3v3r_l13s_s3ss10n_unl0ck3d}`

## 2. Bước đầu: nhận diện file

```
$ file signal_lock.beam
signal_lock.beam: gzip compressed data ...
$ zcat signal_lock.beam > sl.beam
```

File thực chất là BEAM nén gzip. Erlang vẫn nạp được dạng này, nhưng các công cụ thông thường thì không. Sau khi giải nén, header là `FOR1....BEAM` với các chunk sau: `AtU8`, `Code`, `StrT`, `ImpT`, `ExpT`, `LitT`, `Line`, `Type`, `Meta`.

Lưu ý: SHA-256 của file tải lên (`18e6663e...`, và `4760a3e1...` sau khi giải nén) **không khớp** với hash đề cho (`93651d91...`). Có thể file đã bị nén lại khi upload, hoặc đề có nhiều bản build. Nếu nộp flag bị từ chối thì đây là chỗ đầu tiên cần kiểm tra.

## 3. Công cụ

Môi trường làm bài không có `erl`, nên mình tự parse BEAM bằng Python. Nếu bạn có Erlang, cách nhanh hơn là:

```erlang
1> {ok, {_, [{abstract_code, _}]}} = beam_lib:chunks("signal_lock.beam", [abstract_code]).
```

Cách này **không dùng được ở đây** vì module đã strip debug info. Khi đó dùng `erlc -S` không áp dụng được trên .beam, nên cần đọc trực tiếp chunk `Code` (hoặc dùng `beam_disasm:file/1` trên Erlang thật).

Những điểm cần xử lý khi tự viết disassembler cho OTP 26:

- Header của chunk `Code` có 5 trường 32-bit: độ dài header (16), instruction set (0), max opcode (**182**), số label (26), số hàm (10). Opcode 182 là `bs_match`, tức opcode OTP 26 mà đề nhắc tới.
- Toán hạng dùng *compact term encoding*: 3 bit thấp là tag (`u,i,a,x,y,f,h,z`). Số nguyên lớn dùng dạng 9 byte có byte `0x00` đầu để giữ số dương (ví dụ `0xafe7c5708f40ebc4`).
- Tag `z` có nhiều biến thể: `z1` là danh sách, `z4` là literal, và **`z5` là thanh ghi có kiểu** (typed register, dùng từ OTP 25). Thiếu `z5` thì decode lệch ngay từ lệnh đầu.
- Bảng atom (`AtU8`) và import (`ImpT`) cần để dịch chỉ số sang tên hàm. Literal nằm trong `LitT` (nén zlib, bỏ 4 byte đầu).

## 4. Bảng atom, import và export

Atom (đánh số từ 1): `signal_lock`, `verify`, `erlang`, `byte_size`, `no_fail`, `ensure_exactly`, `integer`, `ok`, `transform`, `bxor`, `*`, `band`, `+`, `rotl`, `bsl`, `bsr`, `bor`, `unlock`, `binary_to_list`, `lists`, `zip`, `list_to_binary`, `keystream`, `binary`, `part`, `sha256`, `crypto`, `hash`, `private_append`, `all`, `cipher`, ...

Import (chỉ số từ 0): `byte_size/1`, `bxor/2`, `*/2`, `band/2`, `+/2`, `bsl/2`, `bsr/2`, `bor/2`, `binary_to_list/1`, `lists:zip/2`, `list_to_binary/1`, `binary:part/3`, `crypto:hash/2`, ...

Export: `verify/1` (label 2), `module_info/0` và `module_info/1`.

Literal trong `LitT` gồm ba phần: `{error, locked}`, `{error, bad_token}` và một binary 48 byte (ciphertext của flag):

```
f3a78b575b93c60be646d9eefd1f0aa0ac5ac53a2b0107f1a5c84adf4d989dc0
6c09680db73f54ad89bdd8ae0530c27b
```

## 5. Phân tích từng hàm

### 5.1. `verify/1`

Từ disassembly (rút gọn):

```
is_binary   x0                    ; không phải binary -> {error,bad_token}
byte_size   x0 -> x1
is_eq_exact x1, 8                 ; phải đúng 8 byte
bs_match    ensure_exactly 64, integer(unsigned, big-endian, 64) -> x2
call        transform/1  (x2)
is_eq_exact x0, 0xafe7c5708f40ebc4  ; sai -> {error,locked}
call        unlock/1     (token)       ; đúng -> {ok, Flag}
```

Tương đương Erlang:

```erlang
verify(<<T:64>>) ->
    case transform(T) of
        16#afe7c5708f40ebc4 -> {ok, unlock(T)};
        _ -> {error, locked}
    end;
verify(_) -> {error, bad_token}.
```

### 5.2. `transform/1` và `rotl/2`

```erlang
transform(X) ->
    A = X bxor 16#a5a5a5a55a5a5a5a,
    B = (A * 16#9e3779b97f4a7c15) band 16#ffffffffffffffff,
    C = rotl(B, 29),
    (C + 16#0123456789abcdef) band 16#ffffffffffffffff.

rotl(X, 29) ->   % trong bytecode, 29 và 35 là hằng số
    ((X bsl 29) bor (X bsr 35)) band 16#ffffffffffffffff.
```

Đây là một hàm trộn 64-bit khá điển hình: XOR hằng, nhân với hằng số vàng (`0x9e3779b97f4a7c15` là hằng quen thuộc trong các hàm băm Fibonacci), xoay trái 29 bit, rồi cộng hằng.

### 5.3. `unlock/1`, `keystream/2`

`unlock/1` lấy ciphertext 48 byte (literal), tính keystream cùng độ dài từ token, rồi XOR từng byte (qua `lists:zip` và một list comprehension `A bxor B`).

```erlang
unlock(T) ->
    C = cipher(),
    KS = keystream(T, byte_size(C)),
    list_to_binary([A bxor B || {A, B} <- lists:zip(binary_to_list(C), binary_to_list(KS))]).

keystream(Seed, N) -> keystream(Seed, N, 0, <<>>).
keystream(Seed, N, Ctr, Acc) when byte_size(Acc) >= N ->
    binary:part(Acc, 0, N);
keystream(Seed, N, Ctr, Acc) ->
    D = crypto:hash(sha256, <<Seed:64, Ctr:32>>),
    keystream(Seed, N, Ctr + 1, <<Acc/binary, D/binary>>).
```

Quan trọng: seed của keystream là **token gốc** `T`, không phải giá trị sau `transform`. Vì vậy nếu không có đúng `T` thì không giải được flag, dù biết `transform(T)`.

## 6. Lời giải

Điều kiện chấp nhận là `transform(T) == 0xafe7c5708f40ebc4`. Mỗi bước trong `transform` đều khả nghịch trên vành modulo 2^64:

| Bước thuận | Bước nghịch |
| --- | --- |
| `x xor A` | `x xor A` |
| `x * G mod 2^64` | `x * G⁻¹ mod 2^64` (G lẻ nên có nghịch đảo) |
| `rotl(x, 29)` | `rotr(x, 29)` = `rotl(x, 35)` |
| `x + C mod 2^64` | `x - C mod 2^64` |

Vì vậy không cần brute-force 2^64 khả năng, chỉ cần đảo ngược theo thứ tự ngược lại.

```python
import struct, hashlib

M = (1 << 64) - 1
A = 0xa5a5a5a55a5a5a5a
G = 0x9e3779b97f4a7c15
C = 0x0123456789abcdef
TARGET = 0xafe7c5708f40ebc4

rotl = lambda x, k: ((x << k) | (x >> (64 - k))) & M
rotr = lambda x, k: rotl(x, 64 - k)

def transform(x):
    return (rotl(((x ^ A) * G) & M, 29) + C) & M

y = (TARGET - C) & M
y = rotr(y, 29)
T = ((y * pow(G, -1, 1 << 64)) & M) ^ A
assert transform(T) == TARGET
print(hex(T), struct.pack('>Q', T))   # 0x67346d3330763372 b'g4m30v3r'

cipher = bytes.fromhex(
    'f3a78b575b93c60be646d9eefd1f0aa0ac5ac53a2b0107f1a5c84adf4d989dc0'
    '6c09680db73f54ad89bdd8ae0530c27b')
ks, ctr = b'', 0
while len(ks) < len(cipher):
    ks += hashlib.sha256(struct.pack('>QI', T, ctr)).digest()
    ctr += 1
print(bytes(a ^ b for a, b in zip(cipher, ks)))
```

Kết quả:

```
0x67346d3330763372 b'g4m30v3r'
b'hiCTF{b34m_byt3c0d3_n3v3r_l13s_s3ss10n_unl0ck3d}'
```

## 7. Kiểm chứng

- `transform(T) == TARGET` được kiểm tra bằng `assert` trong script.
- Flag giải mã ra là chuỗi leetspeak đọc được ("beam bytecode never lies, session unlocked"). Nếu bất kỳ hằng số hay thứ tự phép toán nào bị đọc sai thì keystream sẽ sai và kết quả là byte rác, nên đây là bằng chứng gián tiếp khá mạnh rằng việc đọc bytecode là chính xác.
- **Hạn chế:** mình chưa chạy module trên Erlang thật. Để xác nhận cuối cùng:

```erlang
$ erl -pa .
1> signal_lock:verify(<<"g4m30v3r">>).
{ok,<<"hiCTF{b34m_byt3c0d3_n3v3r_l13s_s3ss10n_unl0ck3d}">>}
```

## 8. Bài học

- **Không có source không có nghĩa là an toàn.** BEAM là bytecode có cấu trúc rõ ràng; atom table, import table và literal table để lộ gần như toàn bộ ý đồ của chương trình dù đã strip.
- **Kiểm tra token bằng hàm trộn khả nghịch là vô nghĩa.** `transform` chỉ gồm XOR, nhân với số lẻ, rotate và cộng, toàn bộ đều đảo được trong O(1). Anti-cheat dạng này chỉ làm chậm kẻ tấn công vài phút. Muốn an toàn thật thì phải xác thực phía server bằng bí mật không nằm trong client (ví dụ HMAC với khóa server, hoặc chữ ký bất đối xứng).
- **Đừng nhúng ciphertext và logic giải mã cạnh nhau.** Khi token là seed, ai đảo được `transform` sẽ giải được flag ngay.
- **Mẹo kỹ thuật khi làm RE trên BEAM:** kiểm tra chunk `Code` header (max opcode) để biết cần OTP nào, nhớ xử lý typed register (`z5`) và số nguyên 9 byte, và đối chiếu import index với bảng `ImpT` thay vì đoán theo tên.
