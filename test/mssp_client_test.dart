import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:nfcsigner/nfcsigner.dart';
import 'package:nfcsigner/src/pdf/cms.dart';
import 'package:nfcsigner/src/pdf/pdf_document.dart';
import 'package:xml/xml.dart';

import 'test_rsa.dart';

const _certB64 = 'MIIDEzCCAfugAwIBAgIUdrFL/PIK662nrBhxH16nD/cS7FkwDQYJKoZIhvcNAQELBQAwGTEXMBUGA1UEAwwObmZjc2lnbmVyIHRlc3QwHhcNMjYxMTE2MDkyMTU0WhcNMzYxMTEzMDkyMTU0WjAZMRcwFQYDVQQDDA5uZmNzaWduZXIgdGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANKsBoOVjTb8o38TS8NXN84eRowcGJfcNfdeEmLbBOXlz3pkF/5GFDlPEky5prTo8CEfyiPEYB/z4pAsIkKgZjq08bKwccEqG0WdT+ZTalZSu1/k3sbPTmj60Toj93H+pHwyFo/M54QK/jnU70nNvlv/KE1cIiHcXSCV0HUaPhcu0RgNLhgTNF13VuSYZmANAaVkJA635mAZBmSJOL4JiM/G63pobcbQyatbShUBULZm5y+2AVNtcJes0lgya9IMroP+h0fJ54Q55Pj2rpXWPq+1GWrY62FD4/N9RdXmi5S6X0ukGD/rpUH9y8B6ks5fZJHp2J4134uIMmz2Rq65y5ECAwEAAaNTMFEwHQYDVR0OBBYEFHSSZMhASlbsMbgEhSHgfXnEgE8XMB8GA1UdIwQYMBaAFHSSZMhASlbsMbgEhSHgfXnEgE8XMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBALY7TxRq78j1x877Y9MotkQU4EshNpnY07oTQHDYUxewuXO1GEuC9FpLOV8Oxj/SpaV38QAWRc0p/vhwczbH8FdU0kTNSUToM9DDrmgt7+wU7HvCDEYTxG2mWfjCWgt/HpYluEfwwPQQr815VKnT7LLRo855F94tNPhCfyiO+fep2ey1YgZYShdzyYnW/wPpPB9O+s5cfT3uSpVKfiwBiTbhQ2w/79L+9+zQRnjGIJgQu5a4H90S7Aj64kAXX0MnIScBosZ+zcFFgTvS2y1WShPAWVIGmwd2o+l6TyDB4+NrCuLij3syqFjrwnQiH2KaQyhIHsEvzyf9gpcEpdg0oHk=';
const _soap = 'http://www.w3.org/2003/05/soap-envelope';
const _tns = 'http://ae.mobile-id.vn/TS102204/etsi204';
const _mss = 'http://uri.etsi.org/TS102204/v1.1.2#';

final _config = MsspConfig(
  apId: 'http://ap.mobile-id.vn/test',
  apPassword: 'ap-secret',
  clientCertificate: Uint8List(0),
  clientCertificatePassword: '',
);

String _signatureResponse(Uint8List sig, {int status = 500}) => '''<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="$_soap"><soapenv:Body>
<ns1:MSS_SignatureResponse xmlns:ns1="$_tns">
<MSS_SignatureResp MajorVersion="1" MinorVersion="1" MSSP_TransID="M1798702590996149" xmlns:ns2="$_mss">
<ns2:AP_Info AP_ID="http://ap.mobile-id.vn/test" AP_PWD="" AP_TransID="A1" Instant="2026-01-01T00:00:00+07:00"/>
<ns2:MSSP_Info><ns2:MSSP_ID><ns2:URI>http://hmssp.mobile-id.vn</ns2:URI></ns2:MSSP_ID></ns2:MSSP_Info>
<ns2:MobileUser><ns2:MSISDN>84900000001</ns2:MSISDN></ns2:MobileUser>
<ns2:MSS_Signature><ns2:Base64Signature>${base64.encode(sig)}</ns2:Base64Signature></ns2:MSS_Signature>
<ns2:Status><ns2:StatusCode Value="$status"/><ns2:StatusMessage>SIGNATURE</ns2:StatusMessage></ns2:Status>
</MSS_SignatureResp></ns1:MSS_SignatureResponse></soapenv:Body></soapenv:Envelope>''';

String _registrationResponse(String x509Text) => '''<soapenv:Envelope xmlns:soapenv="$_soap"><soapenv:Body>
<ns1:MSS_RegistrationResponse xmlns:ns1="$_tns"><MSS_RegistrationResp MajorVersion="1" MinorVersion="1" xmlns:ns2="$_mss">
<ns2:AP_Info AP_ID="x" AP_PWD="" AP_TransID="A1" Instant="2026-01-01T00:00:00+07:00"/>
<ns2:MSSP_Info><ns2:MSSP_ID><ns2:URI>http://hmssp.mobile-id.vn</ns2:URI></ns2:MSSP_ID></ns2:MSSP_Info>
<ns2:Status><ns2:StatusCode Value="100"/></ns2:Status>
<ns2:CertificateResponse><ns2:CertificateURI>http://mobile-id.vn/digitalSignature</ns2:CertificateURI>
<ns2:X509Certificate>$x509Text</ns2:X509Certificate></ns2:CertificateResponse>
</MSS_RegistrationResp></ns1:MSS_RegistrationResponse></soapenv:Body></soapenv:Envelope>''';

String _fault(String subcode, String reason) => '''<soapenv:Envelope xmlns:soapenv="$_soap"><soapenv:Body><soapenv:Fault>
<soapenv:Code><soapenv:Value>soapenv:Receiver</soapenv:Value>
<soapenv:Subcode><soapenv:Value xmlns:mss="$_mss">$subcode</soapenv:Value></soapenv:Subcode></soapenv:Code>
<soapenv:Reason><soapenv:Text xml:lang="en">$reason</soapenv:Text></soapenv:Reason>
</soapenv:Fault></soapenv:Body></soapenv:Envelope>''';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('tiện ích', () {
    test('mã xác thực khớp VerificationCodeCalculator.java của SDK', () {
      Uint8List hex(String h) => Uint8List.fromList(
          [for (var i = 0; i < h.length; i += 2) int.parse(h.substring(i, i + 2), radix: 16)]);
      expect(MsspClient.verificationCode(hex('3021300906052B0E03021A0500041492902E74284AC4060C83C5EC6805C9C4BD89FA83')),
          '564999');
      expect(MsspClient.verificationCode(hex('3031300d060960864801650304020105000420${'11' * 32}')),
          '220334');
    });

    test('chuẩn hoá số điện thoại', () {
      expect(MsspClient.normalizeMsisdn('0912 345 678'), '84912345678');
      expect(MsspClient.normalizeMsisdn('+84912345678'), '84912345678');
      expect(() => MsspClient.normalizeMsisdn('123'), throwsArgumentError);
    });

    test('AP_TransID đổi mỗi 15 phút', () {
      expect(MsspClient.transactionId(DateTime(2026, 11, 16, 9, 14)), 'A261116090');
      expect(MsspClient.transactionId(DateTime(2026, 11, 16, 9, 45)), 'A261116093');
    });
  });

  group('MSS_Signature', () {
    test('bản tin đúng cấu trúc rpc/literal của WSDL', () async {
      late Uri url;
      late String sent;
      final client = MsspClient(_config, transport: (u, xml, t) async {
        url = u;
        sent = xml;
        return _signatureResponse(Uint8List.fromList([1, 2, 3]));
      });
      final di = Uint8List.fromList(List.generate(51, (i) => i));
      final r = await client.sign(phone: '0900000001', dataToBeSigned: di, now: DateTime(2026, 1, 2, 3, 4, 5));
      expect(r.isSuccess, isTrue, reason: r.message);
      expect(r.data, [1, 2, 3]);
      expect(url.toString(), 'https://mpki1.ca.gov.vn:18083/soap/services/MSS_SignaturePort');

      final doc = XmlDocument.parse(sent);
      final env = doc.rootElement;
      expect((env.name.local, env.namespaceUri), ('Envelope', _soap));
      final op = env.findElements('Body', namespace: _soap).single.childElements.single;
      expect((op.name.local, op.namespaceUri), ('MSS_Signature', _tns));
      final req = op.childElements.single;
      expect(req.name.local, 'MSS_SignatureReq');
      expect(req.namespaceUri, isNull, reason: 'phần tử tham số rpc/literal không có namespace');
      expect(req.getAttribute('MajorVersion'), '1');
      expect(req.getAttribute('MessagingMode'), 'synch');
      expect(req.getAttribute('TimeOut'), '300');
      expect(req.childElements.map((e) => e.name.local).toList(), [
        'AP_Info', 'MSSP_Info', 'MobileUser', 'DataToBeSigned', 'DataToBeDisplayed',
        'MSS_Format', 'SignatureProfile', 'AdditionalServices',
      ], reason: 'thứ tự theo xs:sequence');
      expect(req.childElements.every((e) => e.namespaceUri == _mss), isTrue);

      final ap = req.childElements.first;
      expect(ap.getAttribute('AP_ID'), 'http://ap.mobile-id.vn/test');
      expect(ap.getAttribute('AP_PWD'), 'ap-secret');
      expect(ap.getAttribute('AP_TransID'), 'A260102030');
      expect(req.findAllElements('MSISDN', namespace: _mss).single.innerText, '84900000001');
      final dtbs = req.findElements('DataToBeSigned', namespace: _mss).single;
      expect(dtbs.getAttribute('Encoding'), 'base64');
      expect(base64.decode(dtbs.innerText), di);
      expect(req.findElements('DataToBeDisplayed', namespace: _mss).single.innerText,
          contains('%%VC%%'));
      expect(req.findAllElements('mssURI', namespace: _mss).map((e) => e.innerText), containsAll([
        'http://uri.etsi.org/TS102204/v1.1.2#PKCS1',
        'http://mobile-id.vn/digitalSignature',
      ]));
      expect(sent, isNot(contains('PIN')), reason: 'PIN SIM không bao giờ đi qua API');
    });

    test('SOAP Fault 401 → người dùng huỷ', () async {
      final client = MsspClient(_config,
          transport: (u, x, t) async => _fault('mss:_401', 'USER_CANCEL'));
      final r = await client.sign(phone: '0900000001', dataToBeSigned: Uint8List(51));
      expect(r.status, CardStatus.authError);
      expect(r.message, contains('401'));
      expect(r.message, contains('huỷ'));
    });

    test('Status lỗi trong phản hồi → thất bại', () async {
      final client = MsspClient(_config,
          transport: (u, x, t) async => _signatureResponse(Uint8List(0), status: 402));
      final r = await client.sign(phone: '0900000001', dataToBeSigned: Uint8List(51));
      expect(r.isSuccess, isFalse);
      expect(r.message, contains('402'));
    });

    test('mất kết nối → communicationError', () async {
      final client = MsspClient(_config,
          transport: (u, x, t) => Future<String>.error(const SocketException('x')));
      final r = await client.sign(phone: '0900000001', dataToBeSigned: Uint8List(51));
      expect(r.status, CardStatus.communicationError);
    });

    test('hết thời gian chờ xác nhận → 208', () async {
      final client = MsspClient(_config,
          transport: (u, x, t) => Future<String>.error(TimeoutException('x')));
      final r = await client.sign(phone: '0900000001', dataToBeSigned: Uint8List(51));
      expect(r.status, CardStatus.communicationError);
      expect(r.message, contains('208'));
    });
  });

  group('MSS_Registration', () {
    final der = base64.decode(_certB64);
    for (final (name, text) in [
      ('DER base64', _certB64),
      ('base64 hai lần (như mẫu Java)', base64.encode(utf8.encode(_certB64))),
      ('PEM trong base64', base64.encode(utf8.encode('-----BEGIN CERTIFICATE-----\n$_certB64\n-----END CERTIFICATE-----\n'))),
    ]) {
      test('đọc certificate: $name', () async {
        late String sent;
        final client = MsspClient(_config, transport: (u, xml, t) async {
          sent = xml;
          expect(u.path, endsWith('/MSS_RegistrationPort'));
          return _registrationResponse(text);
        });
        final r = await client.getCertificate('0900000001');
        expect(r.isSuccess, isTrue, reason: r.message);
        expect(r.data, der);
        final req = XmlDocument.parse(sent).findAllElements('MSS_RegistrationReq').single;
        expect(req.namespaceUri, isNull);
        expect(req.parentElement!.name.local, 'MSS_Registration');
      });
    }
  });

  test('signPdfWithSim: một luồng đầy đủ, chữ ký hợp lệ, có mã giao dịch', () async {
    String? vc;
    Uint8List? dtbs;
    final client = MsspClient(_config, transport: (u, xml, t) async {
      if (u.path.endsWith('MSS_RegistrationPort')) return _registrationResponse(_certB64);
      final req = XmlDocument.parse(xml);
      dtbs = base64.decode(req.findAllElements('DataToBeSigned', namespace: _mss).single.innerText);
      return _signatureResponse(testRsaSign(dtbs!));
    });

    final pdf = File('test/fixtures/sample.pdf').existsSync()
        ? File('test/fixtures/sample.pdf').readAsBytesSync()
        : _onePagePdf();
    final r = await Nfcsigner.signPdfWithSim(
      pdfBytes: pdf,
      phone: '0900000001',
      mssp: _config,
      client: client,
      reason: 'Phê duyệt',
      signatureConfig: const PdfSignatureConfig(signerName: 'Nguyễn Văn A'),
      onVerificationCode: (code) => vc = code,
    );
    expect(r.isSuccess, isTrue, reason: r.message);
    expect(vc, MsspClient.verificationCode(dtbs!));
    expect(vc, matches(RegExp(r'^\d{6}$')));

    final doc = PdfDocument.parse(r.data!);
    expect(doc.pageRefs(), hasLength(1));
    expect(RsaVerifier.verify(
        certificate: base64.decode(_certB64), digestInfo: dtbs!, signature: testRsaSign(dtbs!)), isTrue);

    final out = Platform.environment['NFCSIGNER_SIM_PDF_OUT'];
    if (out != null) File(out).writeAsBytesSync(r.data!);
  });

  test('signPdfWithSim: số chưa có chứng thư → dừng trước khi gửi yêu cầu ký', () async {
    var signCalls = 0;
    final client = MsspClient(_config, transport: (u, xml, t) async {
      if (u.path.endsWith('MSS_SignaturePort')) signCalls++;
      return _fault('mss:_422', 'NO_CERT_FOUND');
    });
    final r = await Nfcsigner.signPdfWithSim(
        pdfBytes: _onePagePdf(), phone: '0900000001', mssp: _config, client: client);
    expect(r.isSuccess, isFalse);
    expect(r.message, contains('422'));
    expect(signCalls, 0);
  });
}

Uint8List _onePagePdf() {
  const objs = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>',
  ];
  final b = StringBuffer('%PDF-1.4\n');
  final offsets = <int>[];
  for (var i = 0; i < objs.length; i++) {
    offsets.add(b.length);
    b.write('${i + 1} 0 obj\n${objs[i]}\nendobj\n');
  }
  final xref = b.length;
  b.write('xref\n0 4\n0000000000 65535 f\r\n');
  for (final o in offsets) {
    b.write('${o.toString().padLeft(10, '0')} 00000 n\r\n');
  }
  b.write('trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n$xref\n%%EOF\n');
  return Uint8List.fromList(latin1.encode(b.toString()));
}
