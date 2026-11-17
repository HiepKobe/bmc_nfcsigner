# nfcsigner

[![pub version](https://img.shields.io/pub/v/nfcsigner.svg)](https://pub.dev/packages/nfcsigner)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Một plugin Flutter để giao tiếp với thẻ thông minh BCard (chuẩn OpenPGP): ký số, giải mã, lấy khóa công khai và certificate qua NFC hoặc đầu đọc USB/PC-SC trên Android, iOS, macOS, Windows và Linux.

## ✨ Tính năng

* Tạo chữ ký số từ dữ liệu đã được băm (`DigestInfo`).
* Lấy khóa công khai RSA.
* Đọc Certificate của chủ thẻ.
* Giải mã RSA (PSO:DECIPHER) và ký bằng khóa xác thực (`internalAuthenticate`).
* Ký PDF (CMS/PAdES cơ bản) và ký XML (XML-DSig enveloped, C14N 1.0 / Exclusive C14N).
* Xử lý tự động các phản hồi APDU gồm nhiều phần (`GET RESPONSE`).
* API đơn giản, dễ sử dụng với các `enum` và lớp `ServiceResult` chi tiết.

## 🚀 Bắt đầu

Plugin này yêu cầu thiết bị phải có phần cứng NFC và được bật.

## ⚙️ Cài đặt

Thêm dependency này vào file `pubspec.yaml` của dự án Flutter của bạn:

```yaml
dependencies:
  nfcsigner: ^2.1.0
```
Hoặc get package qua github:
```yaml
dependencies:  
  nfcsigner:
    git:
      url: https://github.com/bmctechvn/nfcsigner.git
      ref: main # Hoặc một branch/tag cụ thể
```
Sau đó, chạy `flutter pub get`.

## 🛠 Cấu hình Bắt buộc

Bạn **bắt buộc** phải thực hiện các bước cấu hình native sau cho từng nền tảng.

### Android

Thêm quyền sử dụng NFC vào file `android/app/src/main/AndroidManifest.xml`:

```xml
<uses-permission android:name="android.permission.NFC" />
```

### iOS

1.  **Mở dự án iOS bằng Xcode:** Mở file `ios/Runner.xcworkspace`.
2.  **Thêm Capability:**
    * Đi đến tab `Signing & Capabilities`.
    * Nhấn `+ Capability`.
    * Tìm và thêm `Near Field Communication Tag Reading`.
3.  **Thêm mô tả quyền:** Mở file `ios/Runner/Info.plist` và thêm cặp key-value sau:
    ```xml
    <key>NFCReaderUsageDescription</key>
    <string>Sử dụng NFC để giao tiếp với thẻ thông minh của bạn.</string>
    ```

#### USB Smart Card Support (iOS 16+)

Plugin hỗ trợ ký số qua USB với đầu đọc CCID. Để kích hoạt:

1.  **Thêm Smartcard Entitlement:**
    * Tạo hoặc mở file `ios/Runner/Runner.entitlements`
    * Thêm entitlement sau:
    ```xml
    <key>com.apple.security.smartcard</key>
    <true/>
    ```

2.  **Yêu cầu phần cứng:**
    * iPhone với USB-C (iPhone 15+): Kết nối trực tiếp với đầu đọc CCID
    * iPhone với Lightning: Cần Lightning to USB adapter + powered USB hub
    
> **Lưu ý:** Plugin tự động ưu tiên USB khi phát hiện đầu đọc được kết nối. Nếu không có USB reader, sẽ fallback về NFC.

## 👨‍💻 Hướng dẫn sử dụng

Dưới đây là một ví dụ đầy đủ về cách sử dụng plugin.

```dart
import 'package:flutter/material.dart';
import 'package:nfcsigner/nfcsigner.dart';
import 'dart:convert';
import 'dart:typed_data';

// Hàm helper để băm dữ liệu và tạo DigestInfo (bạn nên có hàm này)
Uint8List createSha256DigestInfo(Uint8List dataToHash) {
  // ... (logic băm và tạo DigestInfo)
  return ...;
}


class MyCardScreen extends StatefulWidget {
  // ...
}

class _MyCardScreenState extends State<MyCardScreen> {
  String _status = "Sẵn sàng";
  
  Future<void> signData() async {
    setState(() { _status = "Đang chuẩn bị dữ liệu..."; });
    
    // 1. Chuẩn bị dữ liệu cần ký
    final originalMessage = Uint8List.fromList(utf8.encode('Dữ liệu cần ký'));
    final digestInfo = createSha256DigestInfo(originalMessage);

    setState(() { _status = "Vui lòng chạm thẻ..."; });

    // 2. Gọi hàm ký
    final result = await Nfcsigner.generateSignature(
      appletID: 'D27600012401', // AID của applet OpenPGP
      pin: '123456',
      dataToSign: digestInfo,
      keyIndex: 0,
    );
    
    // 3. Xử lý kết quả
    setState(() {
      if (result.isSuccess) {
        _status = "Ký thành công! Chữ ký: ${result.data}";
      } else {
        _status = "Lỗi: ${result.message} (Mã thẻ: ${result.sw1?.toRadixString(16)}${result.sw2?.toRadixString(16)})";
      }
    });
  }

  Future<void> getPublicKey() async {
    setState(() { _status = "Vui lòng chạm thẻ..."; });
    
    final result = await Nfcsigner.getRsaPublicKey(
      appletID: 'D27600012401',
      keyRole: KeyRole.signature,
    );

    setState(() {
      if (result.isSuccess) {
        _status = "Lấy khóa công khai thành công!";
        // Xử lý result.data (là một Uint8List)
      } else {
        _status = "Lỗi: ${result.message}";
      }
    });
  }

  // ... (Build method với các nút bấm gọi các hàm trên)
}
```

## 🗺 Hỗ trợ theo nền tảng

| Chức năng | Android | iOS | macOS | Windows | Linux |
|---|:-:|:-:|:-:|:-:|:-:|
| `generateSignature`, `getRsaPublicKey`, `getCertificate` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `decryptData` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `internalAuthenticate` | ✅ | — | — | ✅ | ✅ |
| `getPinRetryCounter` | ✅ | — | — | ✅ | ✅ |
| `signPdf` | ✅ | ✅ | ✅ | ✅ (cần PoDoFo) | ✅ (cần PoDoFo) |
| `signXml` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `CardPrompt.events` (lời nhắc chạm thẻ) | ✅ | (sheet hệ thống) | — | — | — |
| `CardReaderState` | ✅ | `attached` | — | `attached` | `attached` |

"—" nghĩa là chưa hỗ trợ: hàm trả `CardStatus.operationNotSupported`, không bao giờ giả vờ thành công.

### Ghi chú

* **`signPdf`**: thẻ ký hash của *signed attributes* trong CMS (`adbe.pkcs7.detached`, SHA-256), PDF được ghi bằng cập nhật tăng dần nên các chữ ký có sẵn vẫn hợp lệ. Tham số `pdfHashBytes` không còn được dùng. Trên iOS/macOS phần PDF chạy bằng Dart (iOS: một lần chạm thẻ); không hỗ trợ PDF đã mã hoá.
* **`signXml`**: chỉ hỗ trợ RSA-SHA256, chữ ký enveloped, tham chiếu `""` hoặc `"#id"`. `XmlSignatureConfig.xpath` là đường dẫn tuyệt đối đơn giản tới phần tử chứa chữ ký (ví dụ `/HDon/DSCKS/NBan`); mặc định là phần tử gốc.
* **Linux**: cần `libpcsclite-dev` và dịch vụ `pcscd`; muốn ký PDF thì cài thêm `libpodofo-dev` (PoDoFo ≥ 0.10).
* **Android**: log gỡ lỗi chỉ bật khi ứng dụng là bản debuggable và không bao giờ ghi PIN hay dữ liệu đã giải mã.
* **Giấy phép**: trên Android, plugin dùng iText 7 (AGPL). Ứng dụng phân phối kèm plugin phải tuân thủ AGPL hoặc mua giấy phép thương mại iText.

## 📱 Ký PDF bằng SIM-PKI (MSSP – Ban Cơ yếu Chính phủ)

Plugin gọi thẳng dịch vụ MSSP (`https://mpki1.ca.gov.vn:18083/soap/services/`), không cần máy chủ trung gian.

```dart
final config = MsspConfig(
  apId: apIdNguoiDungNhap,                 // APID do Cục CTSBMTT cấp
  apPassword: matKhauApNguoiDungNhap,      // mật khẩu AP — KHÔNG phải PIN SIM
  clientCertificate: p12Bytes,             // chứng thư số AP (.p12)
  clientCertificatePassword: matKhauP12,
);

final result = await Nfcsigner.signPdfWithSim(
  pdfBytes: pdf,
  phone: '0912345678',
  mssp: config,
  reason: 'Phê duyệt',
  signatureConfig: PdfSignatureConfig(signerName: 'Nguyễn Văn A'),
  // Hiện mã này cho người dùng đối chiếu với mã trên điện thoại trước khi nhập PIN.
  onVerificationCode: (code) => showCode(code),
);
```

* **PIN của SIM không đi qua app.** MSSP gửi yêu cầu xuống SIM, điện thoại hiện "Ma giao dich 123456…", người dùng nhập PIN trên hộp thoại của SIM. Hàm chờ tối đa 300 giây.
* Kết nối dùng TLS 1.2 hai chiều bằng chứng thư số AP; máy chủ MSSP được xác thực bằng RootCA/SubCA của Ban Cơ yếu (kèm plugin, hết hạn 03/2030) và kho CA hệ thống. Hỗ trợ cả `.p12` định dạng cũ (RC2/3DES) như file Cục cấp.
* **Điều kiện từ phía MSSP:** APID gắn với IP đã đăng ký. Nếu thiết bị ra Internet bằng IP khác, MSSP trả lỗi 104/105 — cần thống nhất với Cục CTSBMTT (ví dụ đi qua VPN của cơ quan).
* Lưu APID, mật khẩu AP và file `.p12` trong Keychain / Android Keystore; không gắn cứng trong mã nguồn.
* Mã lỗi MSSP (401 người dùng huỷ, 402 PIN bị khoá, 208 hết thời gian, 422 chưa có chứng thư…) được trả trong `ServiceResult.message`.

## 📚 API Chi tiết

### Lớp chính
* `Nfcsigner`: Lớp tĩnh chứa tất cả các phương thức.

### Các phương thức
* `Future<ServiceResult<Uint8List>> generateSignature(...)`
* `Future<ServiceResult<Uint8List>> getRsaPublicKey(...)`
* `Future<ServiceResult<Uint8List>> getCertificate(...)`
* `Future<ServiceResult<Uint8List>> internalAuthenticate(...)`
* `Future<ServiceResult<Uint8List>> decryptData(...)`
* `Future<ServiceResult<Uint8List>> signPdf(...)`
* `Future<ServiceResult<String>> signXml(...)`
* `CardSessionApi.open(...)`, `CardSessionApi.getPinRetryCounter(...)`

### Các `enum` và `Model`
* `KeyRole`: `sig`, `dec`, `aut`, `sm`.
* `CardStatus`: `ok`, `communicationError`, `authError`, và nhiều trạng thái lỗi chi tiết khác.
* `ServiceResult<T>`: Lớp chứa kết quả trả về, bao gồm `data`, `status`, `message`, `sw1`, `sw2`.

## 🐛 Báo lỗi và Đóng góp

Vui lòng tạo một issue trên kho [GitHub repository](https://github.com/bmctechvn/nfcsigner/issues) để báo lỗi hoặc đề xuất tính năng mới.# bmc_nfcsigner
