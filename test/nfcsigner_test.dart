import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nfcsigner/nfcsigner.dart';
import 'package:xml/xml.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('nfcsigner');
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;

  void mock(Future<Object?>? Function(MethodCall call) handler) {
    messenger.setMockMethodCallHandler(channel, handler);
  }

  tearDown(() => messenger.setMockMethodCallHandler(channel, null));

  group('signPdf', () {
    test('trả PDF đã ký khi native trả bytes', () async {
      final signed = Uint8List.fromList([1, 2, 3]);
      mock((call) async => signed);
      final r = await Nfcsigner.signPdf(
          pdfBytes: Uint8List.fromList([9]), appletID: 'D276', pin: '1');
      expect(r.isSuccess, isTrue);
      expect(r.data, signed);
    });

    test('không bao giờ trả PDF gốc như thể đã ký khi native không ký được', () async {
      mock((call) async => {'raw': true});
      final r = await Nfcsigner.signPdf(
          pdfBytes: Uint8List.fromList([9]), appletID: 'D276', pin: '1');
      expect(r.isSuccess, isFalse);
      expect(r.status, CardStatus.operationNotSupported);
    });
  });

  test('nền tảng chưa triển khai → operationNotSupported', () async {
    mock((call) async => throw MissingPluginException());
    final r = await Nfcsigner.internalAuthenticate(
        appletID: 'D276', pin: '1', dataToSign: Uint8List(1));
    expect(r.status, CardStatus.operationNotSupported);
  });

  test('lỗi PIN mang theo SW', () async {
    mock((call) async => throw PlatformException(
        code: 'AUTH_ERROR', message: 'sai', details: {'sw1': 0x63, 'sw2': 0xC2}));
    final r = await Nfcsigner.generateSignature(
        appletID: 'D276', pin: '1', dataToSign: Uint8List(1));
    expect(r.status, CardStatus.authError);
    expect(r.sw1, 0x63);
    expect(r.sw2, 0xC2);
  });

  test('signXml đặt chữ ký và certificate đúng chỗ', () async {
    final sig = Uint8List.fromList([0xAA, 0xBB]);
    final cert = Uint8List.fromList([0x30, 0x01]);
    Uint8List? signedDigest;
    mock((call) async {
      switch (call.method) {
        case 'getCertificate':
          return cert;
        case 'generateSignature':
          signedDigest = (call.arguments as Map)['dataToSign'] as Uint8List;
          return sig;
        case 'generateXMLSignature':
          signedDigest = (call.arguments as Map)['dataToSign'] as Uint8List;
          return {'certificate': base64.encode(cert), 'signature': base64.encode(sig)};
      }
      return null;
    });

    const xml = '<a><b>x</b></a>';
    final r = await Nfcsigner.signXml(xmlContent: xml, appletID: 'D276', pin: '1');
    expect(r.isSuccess, isTrue, reason: r.message);

    final doc = XmlDocument.parse(r.data!);
    const ds = 'http://www.w3.org/2000/09/xmldsig#';
    expect(doc.findAllElements('SignatureValue', namespace: ds).single.innerText,
        base64.encode(sig));
    expect(doc.findAllElements('X509Certificate', namespace: ds).single.innerText,
        base64.encode(cert));
    // Thẻ phải ký đúng DigestInfo của SignedInfo.
    expect(signedDigest,
        XmlSigner.createDigestInfoForXml(xmlContent: xml, config: const XmlSignatureConfig()));
  });
}
