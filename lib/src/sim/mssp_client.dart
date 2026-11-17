import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:xml/xml.dart';

import '../../models/card_status.dart';
import '../../models/service_result.dart';
import 'bcy_ca.dart';

/// Cấu hình kết nối MSSP (dịch vụ ký số SIM-PKI của Ban Cơ yếu Chính phủ).
///
/// Theo tài liệu SDK-MobilePKI, kết nối dùng TLS 1.2 xác thực hai chiều:
/// cần chứng thư số AP (PKCS#12) do Cục CTSBMTT cấp, cùng APID/mật khẩu AP.
/// Ngoài ra MSSP chỉ nhận kết nối từ IP đã đăng ký cho APID.
///
/// Không bao giờ gắn cứng các giá trị này trong mã nguồn ứng dụng: nhận từ
/// người dùng và lưu trong Keychain / Android Keystore.
class MsspConfig {
  const MsspConfig({
    required this.apId,
    required this.apPassword,
    required this.clientCertificate,
    required this.clientCertificatePassword,
    this.baseUrl = 'https://mpki1.ca.gov.vn:18083/soap/services/',
    this.msspId = 'http://hmssp.mobile-id.vn',
    this.trustedCertificates,
    this.signTimeout = const Duration(seconds: 300),
  });

  /// APID do Cục CTSBMTT cấp (ví dụ `http://ap.mobile-id.vn/xxx`).
  final String apId;

  /// Mật khẩu AP (AP_PWD) — không phải PIN của SIM.
  final String apPassword;

  /// Chứng thư số AP dạng PKCS#12 (.p12 / .pfx).
  final Uint8List clientCertificate;
  final String clientCertificatePassword;

  /// Thư mục dịch vụ, kết thúc bằng `/`. Mặc định theo
  /// "Cap-nhat-link-webservice-mssp-moi-nhat.txt".
  final String baseUrl;

  final String msspId;

  /// Chứng chỉ CA tin cậy cho máy chủ MSSP (PEM hoặc DER). `null`: RootCA và
  /// SubCA của Ban Cơ yếu (kèm SDK) cộng kho CA của hệ điều hành.
  final List<Uint8List>? trustedCertificates;

  /// Thời gian chờ người dùng xác nhận trên điện thoại (TimeOut của MSSP).
  final Duration signTimeout;
}

/// Lỗi trả về từ MSSP (SOAP Fault hoặc Status khác thành công).
class MsspException implements Exception {
  MsspException(this.code, this.message);

  /// Mã lỗi MSSP (101…900), hoặc `null` nếu là lỗi kết nối.
  final int? code;
  final String message;

  @override
  String toString() => 'MsspException(${code ?? '-'}): $message';
}

/// Gửi một bản tin SOAP, trả về nội dung phản hồi (kể cả khi HTTP 500 —
/// SOAP Fault đi kèm mã 500).
typedef MsspTransport = Future<String> Function(Uri url, String soapXml, Duration timeout);

/// Client gọi trực tiếp MSSP Webservice (ETSI TS 102 204, SOAP 1.2 rpc/literal).
///
/// Định dạng bản tin được đối chiếu với stub Axis trong `laverca-mobileid_v2.jar`
/// và proxy `MSS_SignaturePort.cs` của SDK.
class MsspClient {
  MsspClient(this.config, {MsspTransport? transport})
      : _transport = transport ?? _HttpTransport(config).send;

  final MsspConfig config;
  final MsspTransport _transport;

  static const _soapNs = 'http://www.w3.org/2003/05/soap-envelope';
  static const _tnsNs = 'http://ae.mobile-id.vn/TS102204/etsi204';
  static const _mssNs = 'http://uri.etsi.org/TS102204/v1.1.2#';
  static const _signatureProfile = 'http://mobile-id.vn/digitalSignature';
  static const _formatPkcs1 = 'http://uri.etsi.org/TS102204/v1.1.2#PKCS1';
  static const _svcSigningCertificate =
      'http://mobile-id.vn/MSSP/v1.0.0#signingCertificate';
  static const _svcSignatureValidation =
      'http://mobile-id.vn/MSSP/v1.0.0#signatureValidation';

  /// Chuỗi hiển thị mặc định trên điện thoại. MSSP thay `%%VC%%` bằng mã xác
  /// thực giao dịch tính từ dữ liệu ký (xem [verificationCode]).
  static const defaultDisplayMessage =
      'Ma giao dich %%VC%%. Vui long xac nhan giao dich';

  // ---------------------------------------------------------------------------
  // Tiện ích
  // ---------------------------------------------------------------------------

  /// Mã xác thực giao dịch (6 chữ số) — cùng thuật toán với
  /// `VerificationCodeCalculator` trong SDK. Hiển thị trên app để người dùng
  /// đối chiếu với mã hiện trên điện thoại trước khi nhập PIN SIM.
  static String verificationCode(Uint8List dataToBeSigned) {
    final d = sha256.convert(dataToBeSigned).bytes;
    final right = (d[d.length - 2] << 8) | d[d.length - 1];
    final left = (d[0] << 8) | d[1];
    String last3(int v) {
      final s = '0000$v';
      return s.substring(s.length - 3);
    }

    return last3(right) + last3(left);
  }

  /// Chuẩn hoá số điện thoại về dạng MSISDN `84xxxxxxxxx`.
  static String normalizeMsisdn(String phone) {
    var p = phone.replaceAll(RegExp(r'[\s\-.()]'), '');
    if (p.startsWith('+')) p = p.substring(1);
    if (p.startsWith('0')) p = '84${p.substring(1)}';
    if (!RegExp(r'^84\d{9,10}$').hasMatch(p)) {
      throw ArgumentError('Số điện thoại không hợp lệ: $phone');
    }
    return p;
  }

  /// AP_TransID như mẫu C# của SDK: đổi mỗi 15 phút. Theo ghi chú trong mẫu
  /// Java, giữ nguyên trong 15 phút để SIM "cache PIN" khi ký liên tiếp.
  static String transactionId(DateTime now) {
    String two(int v) => v.toString().padLeft(2, '0');
    return 'A${two(now.year % 100)}${two(now.month)}${two(now.day)}'
        '${two(now.hour)}${now.minute ~/ 15}';
  }

  static String _instant(DateTime t) {
    String two(int v) => v.toString().padLeft(2, '0');
    final off = t.timeZoneOffset;
    final sign = off.isNegative ? '-' : '+';
    return '${t.year.toString().padLeft(4, '0')}-${two(t.month)}-${two(t.day)}'
        'T${two(t.hour)}:${two(t.minute)}:${two(t.second)}'
        '$sign${two(off.inHours.abs())}:${two(off.inMinutes.abs() % 60)}';
  }

  // ---------------------------------------------------------------------------
  // API
  // ---------------------------------------------------------------------------

  /// Lấy certificate ký số của thuê bao (MSS_Registration). Trả về DER.
  Future<ServiceResult<Uint8List>> getCertificate(String phone, {DateTime? now}) =>
      _guard(() async {
        final msisdn = normalizeMsisdn(phone);
        final xml = _envelope('MSS_Registration', 'MSS_RegistrationReq', (b) {
          _messageHeader(b, now ?? DateTime.now());
          b.element('MobileUser', namespace: _mssNs, nest: () {
            b.element('MSISDN', namespace: _mssNs, nest: msisdn);
          });
          b.element('CertificateResponse', namespace: _mssNs, nest: () {
            b.element('CertificateURI', namespace: _mssNs, nest: _signatureProfile);
          });
        });
        final resp = await _call('MSS_RegistrationPort', xml, const Duration(seconds: 60));
        final body = _responseBody(resp, 'MSS_RegistrationResp');
        _checkStatus(body);
        final certEl = body.descendantElements
            .where((e) => e.name.local == 'X509Certificate')
            .firstOrNull;
        if (certEl == null || certEl.innerText.trim().isEmpty) {
          throw MsspException(422, 'MSSP không trả về certificate (NO_CERT_FOUND)');
        }
        return _decodeCertificate(certEl.innerText);
      });

  /// Gửi [dataToBeSigned] (DigestInfo) để SIM của [phone] ký (MSS_Signature,
  /// chế độ đồng bộ). Người dùng xác nhận và nhập PIN trên điện thoại; hàm chờ
  /// tối đa [MsspConfig.signTimeout]. Trả về chữ ký RSA PKCS#1 v1.5.
  Future<ServiceResult<Uint8List>> sign({
    required String phone,
    required Uint8List dataToBeSigned,
    String displayMessage = defaultDisplayMessage,
    DateTime? now,
  }) =>
      _guard(() async {
        final msisdn = normalizeMsisdn(phone);
        final timeoutSec = config.signTimeout.inSeconds;
        final xml = _envelope('MSS_Signature', 'MSS_SignatureReq', (b) {
          _messageHeader(b, now ?? DateTime.now());
          b.element('MobileUser', namespace: _mssNs, nest: () {
            b.element('MSISDN', namespace: _mssNs, nest: msisdn);
          });
          b.element('DataToBeSigned', namespace: _mssNs, nest: () {
            b.attribute('MimeType', 'application/octet-stream');
            b.attribute('Encoding', 'base64');
            b.text(base64.encode(dataToBeSigned));
          });
          b.element('DataToBeDisplayed', namespace: _mssNs, nest: () {
            b.attribute('MimeType', 'text/plain');
            b.attribute('Encoding', 'UTF-8');
            b.text(displayMessage);
          });
          b.element('MSS_Format', namespace: _mssNs, nest: () {
            b.element('mssURI', namespace: _mssNs, nest: _formatPkcs1);
          });
          b.element('SignatureProfile', namespace: _mssNs, nest: () {
            b.element('mssURI', namespace: _mssNs, nest: _signatureProfile);
          });
          b.element('AdditionalServices', namespace: _mssNs, nest: () {
            for (final uri in [_svcSigningCertificate, _svcSignatureValidation]) {
              b.element('Service', namespace: _mssNs, nest: () {
                b.element('Description', namespace: _mssNs, nest: () {
                  b.element('mssURI', namespace: _mssNs, nest: uri);
                });
              });
            }
          });
        }, rootAttributes: {
          'TimeOut': '$timeoutSec',
          'MessagingMode': 'synch',
        });
        final resp = await _call('MSS_SignaturePort', xml,
            config.signTimeout + const Duration(seconds: 30));
        final body = _responseBody(resp, 'MSS_SignatureResp');
        _checkStatus(body);
        final sigEl = body.descendantElements
            .where((e) => e.name.local == 'Base64Signature')
            .firstOrNull;
        if (sigEl == null || sigEl.innerText.trim().isEmpty) {
          throw MsspException(406, 'MSSP không trả về chữ ký (PB_SIGNATURE_PROCESS)');
        }
        return Uint8List.fromList(base64.decode(_stripWs(sigEl.innerText)));
      });

  // ---------------------------------------------------------------------------
  // SOAP
  // ---------------------------------------------------------------------------

  String _envelope(
    String operation,
    String part,
    void Function(XmlBuilder b) content, {
    Map<String, String> rootAttributes = const {},
  }) {
    final b = XmlBuilder();
    b.declaration(encoding: 'UTF-8');
    b.element('Envelope', namespace: _soapNs, namespaces: {_soapNs: 'soap'}, nest: () {
      b.element('Body', namespace: _soapNs, nest: () {
        b.element(operation, namespace: _tnsNs, namespaces: {_tnsNs: 'tns'}, nest: () {
          // Phần tử tham số rpc/literal: không namespace.
          b.element(part, namespaces: {_mssNs: 'mss'}, nest: () {
            b.attribute('MajorVersion', '1');
            b.attribute('MinorVersion', '1');
            rootAttributes.forEach(b.attribute);
            content(b);
          });
        });
      });
    });
    return b.buildDocument().toXmlString();
  }

  void _messageHeader(XmlBuilder b, DateTime now) {
    b.element('AP_Info', namespace: _mssNs, nest: () {
      b.attribute('AP_ID', config.apId);
      b.attribute('AP_PWD', config.apPassword);
      b.attribute('AP_TransID', transactionId(now));
      b.attribute('Instant', _instant(now));
    });
    b.element('MSSP_Info', namespace: _mssNs, nest: () {
      b.element('MSSP_ID', namespace: _mssNs, nest: () {
        b.element('URI', namespace: _mssNs, nest: config.msspId);
      });
    });
  }

  Future<String> _call(String port, String xml, Duration timeout) async {
    final url = Uri.parse('${config.baseUrl}$port');
    try {
      return await _transport(url, xml, timeout);
    } on TimeoutException {
      throw MsspException(208, 'Hết thời gian chờ xác nhận trên điện thoại');
    } on HandshakeException catch (e) {
      throw MsspException(null,
          'Không bắt tay TLS được với MSSP (chứng thư số AP hoặc CA): ${e.message}');
    } on TlsException catch (e) {
      // Thường gặp nhất: sai mật khẩu hoặc file .p12 hỏng.
      throw MsspException(null,
          'Không đọc được chứng thư số AP (.p12) — kiểm tra file và mật khẩu: ${e.message}');
    } on SocketException catch (e) {
      throw MsspException(null, 'Không kết nối được MSSP: ${e.message}');
    }
  }

  /// Phần tử kết quả trong Body; ném [MsspException] nếu là SOAP Fault.
  static XmlElement _responseBody(String response, String resultName) {
    final XmlDocument doc;
    try {
      doc = XmlDocument.parse(response);
    } on XmlException {
      throw MsspException(null, 'Phản hồi MSSP không phải XML hợp lệ');
    }
    final fault = doc.descendantElements.where((e) => e.name.local == 'Fault').firstOrNull;
    if (fault != null) throw _parseFault(fault);
    final result =
        doc.descendantElements.where((e) => e.name.local == resultName).firstOrNull;
    if (result == null) {
      throw MsspException(null, 'Phản hồi MSSP thiếu $resultName');
    }
    return result;
  }

  static MsspException _parseFault(XmlElement fault) {
    // SOAP 1.2: Code/Value + Subcode/Value (vd. "mss:_401"); Reason/Text.
    // Chấp nhận cả SOAP 1.1 (faultcode, faultstring).
    final codes = fault.descendantElements
        .where((e) => e.name.local == 'Value' || e.name.local == 'faultcode')
        .map((e) => e.innerText)
        .join(' ');
    final m = RegExp(r'(?:^|[^\d])(\d{3})(?:$|[^\d])').allMatches(codes).lastOrNull;
    final code = m == null ? null : int.parse(m.group(1)!);
    final reason = fault.descendantElements
            .where((e) => e.name.local == 'Text' || e.name.local == 'faultstring')
            .firstOrNull
            ?.innerText
            .trim() ??
        '';
    return MsspException(code, reason.isNotEmpty ? reason : (msspCodeNames[code] ?? 'Lỗi MSSP'));
  }

  static void _checkStatus(XmlElement body) {
    final codeEl = body.descendantElements
        .where((e) => e.name.local == 'StatusCode' && e.getAttribute('Value') != null)
        .firstOrNull;
    if (codeEl == null) return;
    final code = int.tryParse(codeEl.getAttribute('Value')!);
    // ETSI TS 102 204: 100 REQUEST_OK, 500 SIGNATURE, 502 VALID_SIGNATURE…
    // Mã lỗi theo tài liệu là 101–209 và 401–900 (trừ 5xx thành công).
    if (code == null || code == 100 || (code >= 500 && code < 600)) return;
    final msg = body.descendantElements
        .where((e) => e.name.local == 'StatusMessage')
        .firstOrNull
        ?.innerText;
    throw MsspException(code, msg ?? msspCodeNames[code] ?? 'Lỗi MSSP');
  }

  static Uint8List _decodeCertificate(String text) {
    var bytes = Uint8List.fromList(base64.decode(_stripWs(text)));
    // Máy chủ có thể mã hoá base64 hai lần, hoặc trả PEM (mẫu Java giải mã
    // thêm một lần, mẫu C# đưa thẳng vào X509Certificate2 — chấp nhận cả hai).
    for (var i = 0; i < 2 && !(bytes.isNotEmpty && bytes[0] == 0x30); i++) {
      final s = latin1.decode(bytes, allowInvalid: true)
          .replaceAll(RegExp(r'-----[A-Z ]+-----'), '');
      bytes = Uint8List.fromList(base64.decode(_stripWs(s)));
    }
    if (bytes.isEmpty || bytes[0] != 0x30) {
      throw MsspException(425, 'Certificate từ MSSP không đọc được (ERROR_CERTIFICATE)');
    }
    return bytes;
  }

  static String _stripWs(String s) => s.replaceAll(RegExp(r'\s'), '');

  static Future<ServiceResult<T>> _guard<T>(Future<T> Function() body) async {
    try {
      return ServiceResult.success(await body());
    } on MsspException catch (e) {
      final name = e.code == null ? '' : ' ${msspCodeNames[e.code] ?? ''}';
      return ServiceResult.failure(
        status: statusForCode(e.code),
        message: e.code == null
            ? e.message
            : '[MSSP ${e.code}$name] ${msspCodeMessages[e.code] ?? e.message}',
      );
    } on ArgumentError catch (e) {
      return ServiceResult.failure(
          status: CardStatus.invalidParameters, message: '${e.message}');
    }
  }

  /// Ánh xạ mã lỗi MSSP sang [CardStatus].
  static CardStatus statusForCode(int? code) => switch (code) {
        null => CardStatus.communicationError,
        101 || 102 || 103 || 107 => CardStatus.invalidParameters,
        104 || 105 || 106 => CardStatus.authError,
        401 || 402 || 403 => CardStatus.authError,
        404 || 422 || 424 || 425 => CardStatus.unsupportedCard,
        108 || 109 => CardStatus.operationNotSupported,
        208 || 209 => CardStatus.communicationError,
        _ => CardStatus.unknownError,
      };

  /// Tên mã lỗi theo "MSSP – Tài liệu đặc tả tích hợp AE", mục 5.
  static const msspCodeNames = <int, String>{
    101: 'WRONG_PARAM', 102: 'MISSING_PARAM', 103: 'WRONG_DATA_LENGTH',
    104: 'UNAUTHORIZED_ACCESS', 105: 'UNKNOWN_CLIENT', 106: 'HANDSHAKE_REQUIRED',
    107: 'INAPPROPRIATE_DATA', 108: 'INCOMPATIBLE_INTERFACE', 109: 'UNSUPPORTED_PROFILE',
    208: 'EXPIRED_TRANSACTION', 209: 'OTA_ERROR', 401: 'USER_CANCEL',
    402: 'PIN_NR_BLOCKED', 403: 'CARD_BLOCKED', 404: 'NO_KEY_FOUND',
    405: 'NO_URL_FOUND', 406: 'PB_SIGNATURE_PROCESS', 407: 'REGISTRATION_NOK',
    422: 'NO_CERT_FOUND', 423: 'CRL_PB', 424: 'CRL_EXPIRED',
    425: 'ERROR_CERTIFICATE', 900: 'INTERNAL_ERROR',
  };

  /// Thông báo cho người dùng.
  static const msspCodeMessages = <int, String>{
    104: 'APID/mật khẩu AP không hợp lệ, hoặc IP của thiết bị chưa được đăng ký với MSSP',
    105: 'MSSP không nhận ra bên gọi (APID hoặc chứng thư số AP)',
    208: 'Hết thời gian chờ xác nhận trên điện thoại',
    209: 'Lỗi gửi tin nhắn tới SIM',
    401: 'Người dùng đã huỷ giao dịch trên điện thoại',
    402: 'PIN của SIM đã bị khoá',
    403: 'SIM ký số đã bị khoá',
    404: 'SIM không có khoá ký số',
    422: 'Số điện thoại chưa có chứng thư số SIM-PKI',
    900: 'Lỗi nội bộ của MSSP',
  };
}

class _HttpTransport {
  _HttpTransport(this.config);
  final MsspConfig config;

  SecurityContext _context() {
    final ctx = SecurityContext(withTrustedRoots: config.trustedCertificates == null);
    for (final ca in config.trustedCertificates ??
        [utf8.encode(bcyRootCaPem), utf8.encode(bcySubCaPem)]) {
      ctx.setTrustedCertificatesBytes(ca);
    }
    ctx.useCertificateChainBytes(config.clientCertificate,
        password: config.clientCertificatePassword);
    ctx.usePrivateKeyBytes(config.clientCertificate,
        password: config.clientCertificatePassword);
    return ctx;
  }

  Future<String> send(Uri url, String xml, Duration timeout) async {
    final client = HttpClient(context: _context())
      ..connectionTimeout = const Duration(seconds: 20);
    try {
      final req = await client.postUrl(url);
      req.headers.contentType =
          ContentType('application', 'soap+xml', charset: 'utf-8');
      req.add(utf8.encode(xml));
      final resp = await req.close().timeout(timeout);
      final body = await resp.transform(utf8.decoder).join().timeout(timeout);
      if (resp.statusCode != 200 && !body.contains('Fault')) {
        throw MsspException(null, 'MSSP trả HTTP ${resp.statusCode}');
      }
      return body;
    } finally {
      client.close(force: true);
    }
  }
}
