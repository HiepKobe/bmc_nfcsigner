import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'models/card_status.dart';
import 'models/service_result.dart'; // Import ServiceResult
import 'models/pdf_signature_config.dart';
import 'models/xml_signature_config.dart';
import 'src/xml_signer.dart';
import 'src/pdf/pdf_document.dart' show PdfFormatException;
import 'src/pdf/pdf_incremental_signer.dart';
import 'src/pdf/signature_appearance.dart';
import 'src/sim/mssp_client.dart';

// Xuất các model để người dùng plugin có thể truy cập dễ dàng
export 'models/service_result.dart';
export 'models/card_status.dart';
export 'models/pdf_signature_config.dart';
export 'models/xml_signature_config.dart';
export 'src/crypto_utils.dart';
export 'src/xml_signer.dart';
export 'src/card_session.dart';
export 'src/card_prompt.dart';
export 'src/card_reader_state.dart';
export 'src/sim/mssp_client.dart' show MsspConfig, MsspClient, MsspException;
/// Enum định nghĩa vai trò của khóa trên thẻ.
enum KeyRole {
  /// Khóa dùng để ký (Signature)
  sig,
  /// Khóa dùng để giải mã (Decryption)
  dec,
  /// Khóa dùng để xác thực (Authentication)
  aut,
  /// Khóa dùng cho Secure Messaging
  sm,
}
class Nfcsigner {
  static const MethodChannel _channel = MethodChannel('nfcsigner');

  /// Chỉ dùng cho test: ép [signPdf] đi đường ký PDF bằng Dart (mặc định
  /// dùng trên iOS và macOS).
  @visibleForTesting
  static bool? debugUseDartPdfSigner;

  /// Thực hiện chuỗi lệnh ký số hoàn chỉnh trên thẻ thông minh.
  ///
  /// Bao gồm các bước: Chọn Applet, Xác thực PIN, và Ký dữ liệu.
  /// Trả về một đối tượng [ServiceResult] chứa chữ ký hoặc thông tin lỗi chi tiết.
  static Future<ServiceResult<Uint8List>> generateSignature({
    required String appletID,
    required String pin,
    required Uint8List dataToSign,
    int keyIndex = 0,
  }) async {
    try {
      final Map<String, dynamic> arguments = {
        'appletID': appletID,
        'pin': pin,
        'dataToSign': dataToSign,
        'keyIndex': keyIndex,
      };

      // Gọi phương thức native
      final Uint8List? signature = await _channel.invokeMethod('generateSignature', arguments);

      // Nếu native trả về dữ liệu (không có exception), đó là thành công
      return ServiceResult.success(signature);

    } on PlatformException catch (e) {
      // Nếu native ném ra một exception, chuyển đổi nó thành một ServiceResult thất bại
      return ServiceResult.fromPlatformException(e);
    } on MissingPluginException {
      return ServiceResult.failure(
        status: CardStatus.operationNotSupported,
        message: 'Nền tảng này chưa hỗ trợ thao tác này',
      );
    } catch (e) {
      // Bắt các lỗi không mong muốn khác
      return ServiceResult.failure(
        status: CardStatus.unknownError,
        message: e.toString(),
      );
    }
  }
  /// Ký bằng khóa AUT (Authentication) qua APDU INTERNAL AUTHENTICATE (INS 0x88).
  ///
  /// Khác với [generateSignature] — vốn dùng khóa SIG qua PSO:CDS (INS 0x2A, PIN
  /// mode 0x81) cho ký tài liệu PDF/XML. Hàm này dùng khóa AUT (PKCS#11 id 3,
  /// PIN mode 0x82), là khóa dành cho xác thực client TLS, ví dụ OpenVPN với
  /// `management-external-key`.
  ///
  /// [dataToSign] là DigestInfo thuần — thẻ tự thêm padding PKCS#1 v1.5.
  /// Trả về chữ ký thô: RSA là chuỗi bằng kích thước modulus; ECDSA là `r||s`
  /// (bên gọi tự chuyển sang DER).
  static Future<ServiceResult<Uint8List>> internalAuthenticate({
    required String appletID,
    required String pin,
    required Uint8List dataToSign,
  }) async {
    try {
      final Map<String, dynamic> arguments = {
        'appletID': appletID,
        'pin': pin,
        'dataToSign': dataToSign,
      };

      final Uint8List? signature =
          await _channel.invokeMethod('internalAuthenticate', arguments);

      return ServiceResult.success(signature);

    } on PlatformException catch (e) {
      return ServiceResult.fromPlatformException(e);
    } on MissingPluginException {
      return ServiceResult.failure(
        status: CardStatus.operationNotSupported,
        message: 'Nền tảng này chưa hỗ trợ thao tác này',
      );
    } catch (e) {
      return ServiceResult.failure(
        status: CardStatus.unknownError,
        message: e.toString(),
      );
    }
  }

  /// Thực hiện chuỗi lệnh ký số XML hoàn chỉnh trên thẻ thông minh.
  ///
  /// Bao gồm các bước: Chọn Applet, Xác thực PIN, và Ký dữ liệu.
  /// Trả về một đối tượng [ServiceResult] chứa chữ ký hoặc thông tin lỗi chi tiết.
  ///
  static Future<ServiceResult<Map<String, Uint8List>>> generateXMLSignature({
    required String appletID,
    required String pin,
    required Uint8List dataToSign,
    int keyIndex = 0,
  }) async {
    try {
      if (kDebugMode) {
        print('🔍 [XML Single Session] Bắt đầu ký XML trong một session');
      }

      final Map<String, dynamic> arguments = {
        'appletID': appletID,
        'pin': pin,
        'dataToSign': dataToSign,
        'keyIndex': keyIndex,
      };

      final dynamic result = await _channel.invokeMethod('generateXMLSignature', arguments);

      if (kDebugMode) {
        print('🔍 [XML Single Session] Kiểu kết quả: ${result.runtimeType}');
      }

      Uint8List certificate;
      Uint8List signature;

      if (result is Uint8List) {
        if (kDebugMode) {
          print('🔍 [XML Single Session] Nhận Uint8List từ iOS');
        }
        // iOS trả về Uint8List chứa JSON
        final String jsonString = String.fromCharCodes(result);
        final Map<String, dynamic> resultMap = jsonDecode(jsonString);

        certificate = base64.decode(resultMap['certificate'] as String);
        signature = base64.decode(resultMap['signature'] as String);

      } else if (result is Map) {
        if (kDebugMode) {
          print('🔍 [XML Single Session] Nhận Map từ Android');
        }
        // Android trả về Map trực tiếp
        final Map<dynamic, dynamic> resultMap = result;

        // Xử lý cả hai trường hợp: String (base64) hoặc Uint8List
        if (resultMap['certificate'] is String) {
          certificate = base64.decode(resultMap['certificate'] as String);
        } else {
          throw Exception('Định dạng certificate không hợp lệ từ Android: ${resultMap['certificate']?.runtimeType}');
        }

        if (resultMap['signature'] is String) {
          signature = base64.decode(resultMap['signature'] as String);
        } else {
          throw Exception('Định dạng signature không hợp lệ từ Android: ${resultMap['signature']?.runtimeType}');
        }
      } else {
        throw Exception('Kiểu kết quả không được hỗ trợ: ${result.runtimeType}');
      }

      if (kDebugMode) {
        print('✅ [XML Single Session] Ký XML thành công');
        print(
            '✅ [XML Single Session] Certificate length: ${certificate.length}');
        print('✅ [XML Single Session] Signature length: ${signature.length}');
      }
      return ServiceResult.success({
        'certificate': certificate,
        'signature': signature,
      });

    } on PlatformException catch (e) {
      if (kDebugMode) {
        print('❌ [XML Single Session] PlatformException: ${e.message}');
      }
      return ServiceResult.fromPlatformException(e);
    } on MissingPluginException {
      return ServiceResult.failure(
        status: CardStatus.operationNotSupported,
        message: 'Nền tảng này chưa hỗ trợ thao tác này',
      );
    } catch (e, stackTrace) {
      if (kDebugMode) {
        print('❌ [XML Single Session] Lỗi không mong muốn: $e');
        print('❌ [XML Single Session] Stack trace: $stackTrace');
      }
      return ServiceResult.failure(
        status: CardStatus.unknownError,
        message: 'Lỗi ký XML: $e',
      );
    }
  }

  /// Lấy khóa công khai RSA từ thẻ dựa trên vai trò của khóa.

  static Future<ServiceResult<Uint8List>> getRsaPublicKey({
    required String appletID,
    required KeyRole keyRole,
  }) async {
    try {
      // Chuyển enum thành chuỗi mà lớp native mong đợi
      final String keyRoleString = keyRole.toString().split('.').last;

      final Map<String, dynamic> arguments = {
        'appletID': appletID,
        'keyRole': keyRoleString,
      };

      final Uint8List? publicKey = await _channel.invokeMethod('getRsaPublicKey', arguments);

      return ServiceResult.success(publicKey);

    } on PlatformException catch (e) {
      return ServiceResult.fromPlatformException(e);
    } on MissingPluginException {
      return ServiceResult.failure(
        status: CardStatus.operationNotSupported,
        message: 'Nền tảng này chưa hỗ trợ thao tác này',
      );
    } catch (e) {
      return ServiceResult.failure(
        status: CardStatus.unknownError,
        message: e.toString(),
      );
    }
  }
  /// Theo chuẩn BMC Card, đối tượng Certificate được lưu với tag `7F21`.
  static Future<ServiceResult<Uint8List>> getCertificate({
    required String appletID,
    required KeyRole keyRole,
  }) async {
    try {
      final String keyRoleString = keyRole.toString().split('.').last;

      final Map<String, dynamic> arguments = {
        'appletID': appletID,
        'keyRole': keyRoleString,
      };

      final Uint8List? certificate = await _channel.invokeMethod('getCertificate', arguments);

      return ServiceResult.success(certificate);

    } on PlatformException catch (e) {
      return ServiceResult.fromPlatformException(e);
    } on MissingPluginException {
      return ServiceResult.failure(
        status: CardStatus.operationNotSupported,
        message: 'Nền tảng này chưa hỗ trợ thao tác này',
      );
    } catch (e) {
      return ServiceResult.failure(
        status: CardStatus.unknownError,
        message: e.toString(),
      );
    }
  }

  /// Ký trực tiếp lên một file PDF bằng cách sử dụng logic native.
  ///
  /// [pdfBytes] là nội dung (dạng byte) của file PDF gốc.
  ///
  /// [pdfHashBytes] không còn được dùng: dữ liệu thẻ cần ký là hash của
  /// *signed attributes* trong CMS, chỉ tính được trong lúc dựng chữ ký, nên
  /// lớp native tự tính. Tham số được giữ lại để không phá vỡ mã cũ.
  ///
  /// Trả về một ServiceResult chứa nội dung (dạng byte) của file PDF đã được ký.
  /// Nền tảng không tạo được chữ ký PDF thật sẽ trả lỗi
  /// [CardStatus.operationNotSupported], không bao giờ trả lại PDF chưa ký.
  static Future<ServiceResult<Uint8List>> signPdf({
    required Uint8List pdfBytes,
    required String appletID,
    required String pin,
    int keyIndex = 0,
    String reason = "Ký duyệt!",
    String location = "Hanoi",
    PdfSignatureConfig? signatureConfig,
    @Deprecated('Không còn được dùng; lớp native tự tính dữ liệu cần ký')
    Uint8List? pdfHashBytes,
  }) async {
    if (debugUseDartPdfSigner ?? (!kIsWeb && (Platform.isIOS || Platform.isMacOS))) {
      return _signPdfInDart(
        pdfBytes: pdfBytes,
        appletID: appletID,
        pin: pin,
        keyIndex: keyIndex,
        reason: reason,
        location: location,
        config: signatureConfig ?? const PdfSignatureConfig(),
      );
    }
    try {
      final Map<String, dynamic> arguments = {
        'pdfBytes': pdfBytes,
        'appletID': appletID,
        'pin': pin,
        'keyIndex': keyIndex,
        'reason': reason,
        'location': location,
        'signatureConfig': signatureConfig?.toMap(),
        // Giữ khoá này cho lớp native cũ; lớp native mới bỏ qua nó.
        // ignore: deprecated_member_use_from_same_package
        'pdfHashBytes': pdfHashBytes ?? Uint8List(0),
      };

      final dynamic result = await _channel.invokeMethod('signPdf', arguments);

      if (result is Uint8List && result.isNotEmpty) {
        return ServiceResult.success(result);
      } else if (result is Map) {
        // Bản native build thiếu thư viện PDF (PoDoFo) chỉ trả dữ liệu thô.
        // Không được coi PDF gốc là "đã ký".
        return ServiceResult.failure(
          status: CardStatus.operationNotSupported,
          message: 'Nền tảng này được build không kèm thư viện ký PDF',
        );
      } else {
        return ServiceResult.failure(
          status: CardStatus.unknownError,
          message: 'Định dạng kết quả không hợp lệ từ nền tảng',
        );
      }

    } on PlatformException catch (e) {
      return ServiceResult.fromPlatformException(e);
    } on MissingPluginException {
      return ServiceResult.failure(
        status: CardStatus.operationNotSupported,
        message: 'Nền tảng này chưa hỗ trợ thao tác này',
      );
    } catch (e) {
      return ServiceResult.failure(
        status: CardStatus.unknownError,
        message: e.toString(),
      );
    }
  }
  /// Ký số một tài liệu XML theo chuẩn XML-DSig (hoàn toàn trên Dart)
  ///
  /// [xmlContent] là nội dung XML cần ký
  /// [appletID] là ID của applet trên thẻ
  /// [pin] là mã PIN để xác thực
  /// [keyIndex] là chỉ số của khóa ký (mặc định 0)
  /// [signatureConfig] là cấu hình cho chữ ký XML
  /// Trả về một ServiceResult chứa nội dung XML đã được ký
  static Future<ServiceResult<String>> signXml({
    required String xmlContent,
    required String appletID,
    required String pin,
    int keyIndex = 0,
    XmlSignatureConfig? signatureConfig,
  }) async {
    try {

      // Tạo DigestInfo cho XML
      final digestInfo = XmlSigner.createDigestInfoForXml(
        xmlContent: xmlContent,
        config: signatureConfig ?? const XmlSignatureConfig(),
      );
      // Platform-specific implementation
      ServiceResult<Map<String, Uint8List>> resultData;
      if (Platform.isIOS || Platform.isAndroid) {
        // Ký DigestInfo bằng thẻ
        resultData = await generateXMLSignature(
          appletID: appletID,
          pin: pin,
          dataToSign: digestInfo,
          keyIndex: keyIndex,
        );

        if (!resultData.isSuccess) {
          return ServiceResult.failure(
            status: resultData.status,
            message: 'Lỗi ký số: ${resultData.message}',
          );
        }
      }
      else {
        if (kDebugMode) {
          print('🔍 [XML Signing] Desktop: lấy certificate và ký trong hai giao dịch');
        }
        // Sử dụng multiple sessions approach cho Android
        final certificateResult = await getCertificate(
          appletID: appletID,
          keyRole: KeyRole.sig,
        );

        if (!certificateResult.isSuccess) {
          return ServiceResult.failure(
            status: certificateResult.status,
            message: 'Lỗi lấy certificate: ${certificateResult.message}',
          );
        }

        final signatureResult = await generateSignature(
          appletID: appletID,
          pin: pin,
          dataToSign: digestInfo,
          keyIndex: keyIndex,
        );

        if (!signatureResult.isSuccess) {
          return ServiceResult.failure(
            status: signatureResult.status,
            message: 'Lỗi ký số: ${signatureResult.message}',
          );
        }
        if (certificateResult.data == null || signatureResult.data == null) {
          return ServiceResult.failure(
            status: CardStatus.unknownError,
            message: 'Thẻ không trả về certificate hoặc chữ ký',
          );
        }
        resultData = ServiceResult.success({
          'certificate': certificateResult.data!,
          'signature': signatureResult.data!,
        });
      }
      // Tạo XML đã ký
      final signedXml = XmlSigner.signXml(
        xmlContent: xmlContent,
        signatureBytes: resultData.data!['signature']!,
        certificateBytes: resultData.data!['certificate']!,
        config: signatureConfig ?? const XmlSignatureConfig(),
      );

      return ServiceResult.success(signedXml);

    } on MissingPluginException {
      return ServiceResult.failure(
        status: CardStatus.operationNotSupported,
        message: 'Nền tảng này chưa hỗ trợ thao tác này',
      );
    } catch (e) {
      return ServiceResult.failure(
        status: CardStatus.unknownError,
        message: 'Lỗi ký XML: $e',
      );
    }
  }

  /// Ký PDF với phần xử lý PDF chạy trên Dart (cập nhật tăng dần + CMS), khoá
  /// nằm trên thẻ.
  ///
  /// Dùng trên iOS và macOS, nơi không có thư viện ký PDF native. Thẻ chỉ ký
  /// một DigestInfo. Trên iOS, chữ ký và certificate lấy trong cùng một lần
  /// chạm thẻ (lệnh native `generateXMLSignature`, vốn là "ký + đọc
  /// certificate"); macOS (đầu đọc cắm sẵn) dùng hai lệnh riêng.
  static Future<ServiceResult<Uint8List>> _signPdfInDart({
    required Uint8List pdfBytes,
    required String appletID,
    required String pin,
    required int keyIndex,
    required String reason,
    required String location,
    required PdfSignatureConfig config,
  }) {
    return _signPdfWith(
      pdfBytes: pdfBytes,
      reason: reason,
      location: location,
      config: config,
      sign: (digestInfo) async {
        if (!kIsWeb && Platform.isMacOS && debugUseDartPdfSigner == null) {
          final cert = await getCertificate(appletID: appletID, keyRole: KeyRole.sig);
          if (!cert.isSuccess || cert.data == null) return _failAs(cert);
          final sig = await generateSignature(
              appletID: appletID, pin: pin, dataToSign: digestInfo, keyIndex: keyIndex);
          if (!sig.isSuccess || sig.data == null) return _failAs(sig);
          return ServiceResult.success((signature: sig.data!, certificate: cert.data!));
        }
        final r = await generateXMLSignature(
          appletID: appletID,
          pin: pin,
          dataToSign: digestInfo,
          keyIndex: keyIndex,
        );
        if (!r.isSuccess || r.data == null) return _failAs(r);
        return ServiceResult.success(
            (signature: r.data!['signature']!, certificate: r.data!['certificate']!));
      },
    );
  }

  /// Ký PDF bằng SIM-PKI qua dịch vụ MSSP của Ban Cơ yếu Chính phủ.
  ///
  /// Luồng: lấy certificate theo [phone] → chuẩn bị PDF → gửi DigestInfo tới
  /// MSSP → người dùng xác nhận và **nhập PIN trên chính điện thoại có SIM**
  /// (app không bao giờ nhận PIN SIM) → nhận chữ ký → ghép vào PDF.
  ///
  /// [onVerificationCode] được gọi với mã giao dịch 6 số ngay trước khi gửi
  /// yêu cầu: hiển thị mã này để người dùng đối chiếu với mã hiện trên điện
  /// thoại (`%%VC%%` trong [displayMessage]) trước khi nhập PIN.
  ///
  /// Hàm chờ tối đa [MsspConfig.signTimeout] (mặc định 300 giây).
  static Future<ServiceResult<Uint8List>> signPdfWithSim({
    required Uint8List pdfBytes,
    required String phone,
    required MsspConfig mssp,
    String reason = 'Ký duyệt!',
    String location = '',
    PdfSignatureConfig? signatureConfig,
    String displayMessage = MsspClient.defaultDisplayMessage,
    void Function(String verificationCode)? onVerificationCode,
    @visibleForTesting MsspClient? client,
  }) async {
    final mssClient = client ?? MsspClient(mssp);
    final cert = await mssClient.getCertificate(phone);
    if (!cert.isSuccess || cert.data == null) return _failAs(cert);

    return _signPdfWith(
      pdfBytes: pdfBytes,
      reason: reason,
      location: location,
      config: signatureConfig ?? const PdfSignatureConfig(),
      sign: (digestInfo) async {
        onVerificationCode?.call(MsspClient.verificationCode(digestInfo));
        final sig = await mssClient.sign(
          phone: phone,
          dataToBeSigned: digestInfo,
          displayMessage: displayMessage,
        );
        if (!sig.isSuccess || sig.data == null) return _failAs(sig);
        return ServiceResult.success((signature: sig.data!, certificate: cert.data!));
      },
    );
  }

  static ServiceResult<T> _failAs<T>(ServiceResult<Object?> r) => ServiceResult.failure(
      status: r.status, message: r.message, sw1: r.sw1, sw2: r.sw2);

  static Future<ServiceResult<Uint8List>> _signPdfWith({
    required Uint8List pdfBytes,
    required String reason,
    required String location,
    required PdfSignatureConfig config,
    required Future<ServiceResult<({Uint8List signature, Uint8List certificate})>>
            Function(Uint8List digestInfo)
        sign,
  }) async {
    ServiceResult<Object?>? signFailure;
    try {
      final signDate = config.signDate ?? DateTime.now();
      String two(int v) => v.toString().padLeft(2, '0');
      final dateText = '${two(signDate.day)}/${two(signDate.month)}/${signDate.year} '
          '${two(signDate.hour)}:${two(signDate.minute)}:${two(signDate.second)}';

      final appearance = await SignatureAppearanceRenderer.render(
        width: config.width,
        height: config.height,
        signatureImage: config.signatureImage,
        imageWidth: config.signatureImageWidth,
        imageHeight: config.signatureImageHeight,
        lines: [
          if (config.signerName?.isNotEmpty == true) 'Ký bởi: ${config.signerName}',
          'Ngày ký: $dateText',
          if (reason.isNotEmpty) 'Lý do: $reason',
          if (location.isNotEmpty) 'Nơi ký: $location',
          if (config.contact?.isNotEmpty == true) 'Liên hệ: ${config.contact}',
        ],
      );

      final signed = await PdfIncrementalSigner.sign(
        pdf: pdfBytes,
        signingTime: signDate,
        field: PdfSignatureField(
          pageNumber: config.pageNumber,
          x: config.x,
          y: config.y,
          width: config.width,
          height: config.height,
          signerName: config.signerName,
          reason: reason,
          location: location,
          contactInfo: config.contact,
          appearance: appearance,
        ),
        signer: (digestInfo) async {
          final r = await sign(digestInfo);
          if (!r.isSuccess || r.data == null) {
            signFailure = r;
            throw const _CardSigningFailed();
          }
          return r.data!;
        },
      );
      return ServiceResult.success(signed);
    } on _CardSigningFailed {
      return _failAs(signFailure!);
    } on PdfSignatureMismatchException catch (e) {
      return ServiceResult.failure(status: CardStatus.unknownError, message: e.toString());
    } on PdfFormatException catch (e) {
      return ServiceResult.failure(
          status: CardStatus.invalidParameters, message: 'PDF không hợp lệ: ${e.message}');
    } on ArgumentError catch (e) {
      return ServiceResult.failure(
          status: CardStatus.invalidParameters, message: '${e.message}');
    } catch (e) {
      return ServiceResult.failure(
          status: CardStatus.unknownError, message: 'Lỗi ký PDF: $e');
    }
  }

  /// Giải mã dữ liệu bằng private key trên thẻ thông minh.
  ///
  /// Dùng PSO:DECIPHER (INS 0x2A, P1P2 8086) với command chaining cho
  /// RSA-2048/4096. Mỗi lệnh là một giao dịch thẻ đầy đủ
  /// (connect → SELECT → VERIFY PIN → thao tác → disconnect); để giải mã
  /// nhiều khối trong một lần chạm thẻ, dùng [CardSessionApi.open] thay vì
  /// gọi hàm này lặp lại.
  ///
  /// [appletID] là ID của applet trên thẻ
  /// [pin] là mã PIN để xác thực
  /// [encryptedData] là dữ liệu đã mã hoá cần giải mã
  /// [keyIndex] là chỉ số của khóa giải mã (mặc định 0)
  static Future<ServiceResult<Uint8List>> decryptData({
    required String appletID,
    required String pin,
    required Uint8List encryptedData,
    int keyIndex = 0,
  }) async {
    try {
      final Map<String, dynamic> arguments = {
        'appletID': appletID,
        'pin': pin,
        'encryptedData': encryptedData,
        'keyIndex': keyIndex,
      };

      final Uint8List? result =
          await _channel.invokeMethod('decryptData', arguments);

      // Truoc day tra ve success(null) khi lop native khong co du lieu, nen
      // loi im lang bi bao la thanh cong. Khong con nua.
      if (result == null || result.isEmpty) {
        return ServiceResult.failure(
          status: CardStatus.unknownError,
          message: 'Thẻ không trả về dữ liệu giải mã',
        );
      }
      return ServiceResult.success(result);
    } on PlatformException catch (e) {
      return ServiceResult.fromPlatformException(e);
    } on MissingPluginException {
      return ServiceResult.failure(
        status: CardStatus.operationNotSupported,
        message: 'Nền tảng này chưa hỗ trợ thao tác này',
      );
    } catch (e) {
      return ServiceResult.failure(
        status: CardStatus.unknownError,
        message: 'Lỗi giải mã: $e',
      );
    }
  }
}

class _CardSigningFailed implements Exception {
  const _CardSigningFailed();
}
