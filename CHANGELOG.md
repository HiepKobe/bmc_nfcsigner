## Unreleased

### Bảo mật
* Android: log gỡ lỗi chỉ bật ở bản debuggable, ghi vào bộ nhớ riêng của app thay vì bộ nhớ ngoài; APDU được che (không còn ghi PIN, không ghi dữ liệu phản hồi). iOS/macOS: che APDU trong log DEBUG.

### Sửa lỗi
* `signXml`: viết lại theo đúng XML-DSig — C14N thật (inclusive và exclusive), DigestValue tính trên tài liệu, thẻ ký `SignedInfo` đã chuẩn hoá; sửa lỗi băm hai lần và lỗi tráo chữ ký với certificate. Thêm phụ thuộc `xml`.
* `signPdf` (Android, Linux): ký đúng hash của signed attributes trong CMS thay cho hash do phía gọi truyền vào — chữ ký PDF trước đây không verify được. `pdfHashBytes` chuyển thành tuỳ chọn và bị bỏ qua.
* `signPdf` (iOS): bản cũ chỉ vẽ hình chữ ký, không nhúng chữ ký số. Nay ký thật: PDF được cập nhật tăng dần và CMS được dựng bằng Dart, thẻ ký và trả certificate trong một lần chạm.
* `signPdf` (Dart): bản native không có thư viện PDF giờ trả lỗi thay vì trả PDF gốc như đã ký.
* Windows: bỏ tên người ký/email mặc định "BMC T&S JSC"; không còn dùng `pdfHashBytes`.
* Android: lệnh không phải thao tác thẻ (`isCardReaderAttached`, `cancelNfcWait`, `openSession`…) không còn bật đầu đọc NFC chờ chạm thẻ; từ chối lệnh thẻ chồng nhau (`BUSY`) thay vì làm treo Future trước đó; huỷ chờ thẻ hoạt động; báo lỗi khi NFC tắt.
* Linux: viết lại plugin theo API Flutter Linux (bản cũ không build được), sửa CMake.
* Gỡ khai báo nền tảng web (không có triển khai).
* Nền tảng chưa hỗ trợ một hàm trả `CardStatus.operationNotSupported` thay vì `unknownError`.

### Tính năng
* Ký PDF bằng SIM-PKI: `Nfcsigner.signPdfWithSim` gọi trực tiếp MSSP của Ban Cơ yếu (SOAP 1.2, TLS hai chiều), kèm mã xác thực giao dịch và ánh xạ mã lỗi MSSP. Thêm quyền INTERNET trên Android.
* Chữ ký (thẻ hoặc SIM) được kiểm tra bằng khoá công khai trong certificate trước khi ghi vào PDF.
* Android: `internalAuthenticate`, `getPinRetryCounter`, `isCardReaderAttached`, sự kiện `CardPrompt.events` và `CardReaderState.changes`.
* Windows, Linux: `internalAuthenticate`. iOS: nhận `cancelNfcWait`.
* macOS: `signPdf` (dùng chung bộ ký PDF bằng Dart).

## 2.0.2
* XML Android bugs fixed
* PDF, XML on iOS fixed
## 2.0.1
* Optimize
## 1.0.3
* Add Signature Image Size Settings
## 1.0.2

* Add PDF Signing Features
## 1.0.1

* Initial release of the nfcsigner plugin.
* Added features:
    * Generate digital signature.
    * Get RSA public key.
    * Get cardholder certificate.
* Support for Android and iOS.
