import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nfcsigner/nfcsigner.dart';
import 'package:nfcsigner/src/pdf/cms.dart';
import 'package:nfcsigner/src/pdf/pdf_document.dart';

import 'test_rsa.dart';

// Certificate tự ký chỉ dùng cho test.
const _certB64 = 'MIIDEzCCAfugAwIBAgIUdrFL/PIK662nrBhxH16nD/cS7FkwDQYJKoZIhvcNAQELBQAwGTEXMBUGA1UEAwwObmZjc2lnbmVyIHRlc3QwHhcNMjYxMTE2MDkyMTU0WhcNMzYxMTEzMDkyMTU0WjAZMRcwFQYDVQQDDA5uZmNzaWduZXIgdGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANKsBoOVjTb8o38TS8NXN84eRowcGJfcNfdeEmLbBOXlz3pkF/5GFDlPEky5prTo8CEfyiPEYB/z4pAsIkKgZjq08bKwccEqG0WdT+ZTalZSu1/k3sbPTmj60Toj93H+pHwyFo/M54QK/jnU70nNvlv/KE1cIiHcXSCV0HUaPhcu0RgNLhgTNF13VuSYZmANAaVkJA635mAZBmSJOL4JiM/G63pobcbQyatbShUBULZm5y+2AVNtcJes0lgya9IMroP+h0fJ54Q55Pj2rpXWPq+1GWrY62FD4/N9RdXmi5S6X0ukGD/rpUH9y8B6ks5fZJHp2J4134uIMmz2Rq65y5ECAwEAAaNTMFEwHQYDVR0OBBYEFHSSZMhASlbsMbgEhSHgfXnEgE8XMB8GA1UdIwQYMBaAFHSSZMhASlbsMbgEhSHgfXnEgE8XMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBALY7TxRq78j1x877Y9MotkQU4EshNpnY07oTQHDYUxewuXO1GEuC9FpLOV8Oxj/SpaV38QAWRc0p/vhwczbH8FdU0kTNSUToM9DDrmgt7+wU7HvCDEYTxG2mWfjCWgt/HpYluEfwwPQQr815VKnT7LLRo855F94tNPhCfyiO+fep2ey1YgZYShdzyYnW/wPpPB9O+s5cfT3uSpVKfiwBiTbhQ2w/79L+9+zQRnjGIJgQu5a4H90S7Aj64kAXX0MnIScBosZ+zcFFgTvS2y1WShPAWVIGmwd2o+l6TyDB4+NrCuLij3syqFjrwnQiH2KaQyhIHsEvzyf9gpcEpdg0oHk=';
const _pngB64 = 'iVBORw0KGgoAAAANSUhEUgAAAAgAAAAECAYAAACzzX7wAAAAEklEQVR4nGM4ISf3Hx9moL0CAI/kQGElaeV9AAAAAElFTkSuQmCC';

/// PDF tối thiểu (xref cổ điển) với [pages] trang.
Uint8List _minimalPdf(int pages) {
  final objs = <String>[];
  final kids = [for (var i = 0; i < pages; i++) '${3 + i * 2} 0 R'].join(' ');
  objs.add('<< /Type /Catalog /Pages 2 0 R >>');
  objs.add('<< /Type /Pages /Kids [$kids] /Count $pages >>');
  for (var i = 0; i < pages; i++) {
    objs.add('<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents ${4 + i * 2} 0 R >>');
    objs.add('<< /Length 0 >>\nstream\n\nendstream');
  }
  final b = StringBuffer('%PDF-1.4\n');
  final offsets = <int>[];
  for (var i = 0; i < objs.length; i++) {
    offsets.add(b.length);
    b.write('${i + 1} 0 obj\n${objs[i]}\nendobj\n');
  }
  final xref = b.length;
  b.write('xref\n0 ${objs.length + 1}\n0000000000 65535 f\r\n');
  for (final o in offsets) {
    b.write('${o.toString().padLeft(10, '0')} 00000 n\r\n');
  }
  b.write('trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n$xref\n%%EOF\n');
  return Uint8List.fromList(latin1.encode(b.toString()));
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('nfcsigner');
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;

  setUp(() => Nfcsigner.debugUseDartPdfSigner = true);
  tearDown(() {
    Nfcsigner.debugUseDartPdfSigner = null;
    messenger.setMockMethodCallHandler(channel, null);
  });

  test('ký PDF bằng Dart: ByteRange, messageDigest và DigestInfo gửi thẻ khớp nhau', () async {
    final cert = base64.decode(_certB64);
    Uint8List? sentToCard;
    var calls = 0;
    messenger.setMockMethodCallHandler(channel, (call) async {
      expect(call.method, 'generateXMLSignature');
      calls++;
      sentToCard = (call.arguments as Map)['dataToSign'] as Uint8List;
      return {
        'certificate': base64.encode(cert),
        'signature': base64.encode(testRsaSign(sentToCard!)),
      };
    });

    final pdf = _minimalPdf(2);
    final r = await Nfcsigner.signPdf(
      pdfBytes: pdf,
      appletID: 'D27600012401',
      pin: '123456',
      reason: 'Phê duyệt',
      location: 'Hà Nội',
      signatureConfig: PdfSignatureConfig(
        pageNumber: 2,
        signerName: 'Nguyễn Văn A',
        signatureImage: base64.decode(_pngB64),
        signDate: DateTime(2026, 1, 2, 3, 4, 5),
      ),
    );
    expect(r.isSuccess, isTrue, reason: r.message);
    expect(calls, 1, reason: 'chỉ một lần chạm thẻ');
    final out = r.data!;

    // File gốc được giữ nguyên byte (cập nhật tăng dần).
    expect(out.sublist(0, pdf.length), pdf);

    // Trường chữ ký nằm trên trang 2.
    final doc = PdfDocument.parse(out);
    final page2 = doc.resolve(doc.pageRefs()[1]) as PdfDict;
    final widget = doc.resolve((doc.resolve(page2['Annots']) as PdfArray).items.single) as PdfDict;
    final sig = doc.resolve(widget['V']) as PdfDict;
    expect((sig['SubFilter'] as PdfName).raw, 'adbe.pkcs7.detached');

    final br = (sig['ByteRange'] as PdfArray).items.map((e) => (e as PdfNumber).intValue).toList();
    expect(br[0], 0);
    expect(br[2] + br[3], out.length);
    final signedBytes = [...out.sublist(0, br[1]), ...out.sublist(br[2])];
    final contentDigest = sha256.convert(signedBytes).bytes;

    // Giải CMS: messageDigest phải bằng hash vùng được ký.
    final cms = (sig['Contents'] as PdfString).bytes;
    final contentInfo = DerElement.read(Uint8List.fromList(cms), 0);
    final signedData = contentInfo.children()[1].children().first;
    final signerInfo = signedData.children().last.children().first;
    final attrsEl = signerInfo.children()[3];
    expect(attrsEl.tag, 0xA0);
    final attrsAsSet = Uint8List.fromList(attrsEl.encoded)..[0] = 0x31;
    final md = attrsEl.children().firstWhere((a) =>
        a.children()[0].content.toString() ==
        Der.oid('1.2.840.113549.1.9.4').sublist(2).toString());
    expect(md.children()[1].children().first.content, contentDigest);

    // Thẻ phải được yêu cầu ký đúng DigestInfo(SHA-256(signedAttrs)).
    expect(sentToCard, CryptoUtils.createSha256DigestInfo(attrsAsSet));

    final outPath = Platform.environment['NFCSIGNER_PDF_OUT'];
    if (outPath != null) File(outPath).writeAsBytesSync(out);
  });

  test('chữ ký không khớp certificate bị chặn, không ghi PDF', () async {
    messenger.setMockMethodCallHandler(channel, (call) async {
      final di = (call.arguments as Map)['dataToSign'] as Uint8List;
      final wrong = Uint8List.fromList(di)..[di.length - 1] ^= 1;
      return {
        'certificate': _certB64,
        'signature': base64.encode(testRsaSign(wrong)),
      };
    });
    final r = await Nfcsigner.signPdf(
        pdfBytes: _minimalPdf(1), appletID: 'D276', pin: '0');
    expect(r.isSuccess, isFalse);
    expect(r.data, isNull);
    expect(r.message, contains('không hợp lệ'));
  });

  test('lỗi PIN từ thẻ được trả nguyên trạng, không có PDF', () async {
    messenger.setMockMethodCallHandler(channel, (call) async {
      throw PlatformException(code: 'AUTH_ERROR', message: 'Sai PIN', details: {'sw1': 0x63, 'sw2': 0xC1});
    });
    final r = await Nfcsigner.signPdf(
        pdfBytes: _minimalPdf(1), appletID: 'D276', pin: '0');
    expect(r.status, CardStatus.authError);
    expect(r.sw2, 0xC1);
    expect(r.data, isNull);
  });

  test('PDF hỏng → invalidParameters, không chạm thẻ', () async {
    var calls = 0;
    messenger.setMockMethodCallHandler(channel, (call) async {
      calls++;
      return null;
    });
    final r = await Nfcsigner.signPdf(
        pdfBytes: Uint8List.fromList(utf8.encode('không phải PDF')), appletID: 'D276', pin: '0');
    expect(r.status, CardStatus.invalidParameters);
    expect(calls, 0);
  });

  test('trang không tồn tại → invalidParameters', () async {
    final r = await Nfcsigner.signPdf(
        pdfBytes: _minimalPdf(1),
        appletID: 'D276',
        pin: '0',
        signatureConfig: const PdfSignatureConfig(pageNumber: 5));
    expect(r.status, CardStatus.invalidParameters);
  });

  group('ký bằng chữ ký từ dịch vụ ngoài (MSSP)', () {
    test('prepare → ký DigestInfo → complete, nhận base64 như MSSP trả về', () async {
      final pdf = _minimalPdf(1);
      final prep = await Nfcsigner.preparePdfSignature(
        pdfBytes: pdf,
        reason: 'Phê duyệt',
        signatureConfig: PdfSignatureConfig(signerName: 'Nguyễn Văn A'),
      );
      expect(prep.isSuccess, isTrue, reason: prep.message);
      final prepared = prep.data!;
      expect(prepared.dataToBeSigned.length, 51); // DigestInfo SHA-256
      expect(prepared.dataToBeSigned.sublist(19), prepared.hash);

      // Lưu / khôi phục giữa hai bước.
      final restored = PdfPreparedSignature.fromJson(
          jsonDecode(jsonEncode(prepared.toJson())) as Map<String, dynamic>);

      // MSSP: Base64Signature (base64) và certificate base64 hai lớp (vgca.mssp.jar).
      final sigB64 = utf8.encode(base64.encode(testRsaSign(restored.dataToBeSigned)));
      final certB64x2 = utf8.encode(base64.encode(utf8.encode(_certB64)));
      final r = Nfcsigner.completePdfSignature(
        prepared: restored,
        signature: Uint8List.fromList(sigB64),
        certificate: Uint8List.fromList(certB64x2),
      );
      expect(r.isSuccess, isTrue, reason: r.message);
      final out = r.data!;
      expect(out.sublist(0, pdf.length), pdf);
      expect(out.length, prepared.pdf.length);

      final doc = PdfDocument.parse(out);
      final page = doc.resolve(doc.pageRefs()[0]) as PdfDict;
      final widget = doc.resolve((doc.resolve(page['Annots']) as PdfArray).items.single) as PdfDict;
      final sig = doc.resolve(widget['V']) as PdfDict;
      final cms = (sig['Contents'] as PdfString).bytes;
      final signerInfo = DerElement.read(Uint8List.fromList(cms), 0)
          .children()[1].children().first.children().last.children().first;
      final attrs = Uint8List.fromList(signerInfo.children()[3].encoded)..[0] = 0x31;
      expect(attrs, prepared.signedAttributes);
      expect(signerInfo.children().last.content, testRsaSign(prepared.dataToBeSigned));
    });

    test('chữ ký không khớp → lỗi, không trả PDF', () async {
      final prepared = (await Nfcsigner.preparePdfSignature(pdfBytes: _minimalPdf(1))).data!;
      final wrong = Uint8List.fromList(prepared.dataToBeSigned)..[50] ^= 1;
      final r = Nfcsigner.completePdfSignature(
        prepared: prepared,
        signature: testRsaSign(wrong),
        certificate: base64.decode(_certB64),
      );
      expect(r.isSuccess, isFalse);
      expect(r.data, isNull);
    });

    test('PDF bị sửa sau bước chuẩn bị → invalidParameters', () async {
      final prepared = (await Nfcsigner.preparePdfSignature(pdfBytes: _minimalPdf(1))).data!;
      final json = prepared.toJson();
      final pdf = base64.decode(json['pdf'] as String)..[10] ^= 1;
      json['pdf'] = base64.encode(pdf);
      expect(() => PdfPreparedSignature.fromJson(json), throwsArgumentError);

      final tampered = PdfPreparedSignature(
        pdf: pdf,
        contentsOffset: prepared.contentsOffset,
        reservedBytes: prepared.reservedBytes,
        signedAttributes: prepared.signedAttributes,
      );
      final r = Nfcsigner.completePdfSignature(
        prepared: tampered,
        signature: testRsaSign(prepared.dataToBeSigned),
        certificate: base64.decode(_certB64),
      );
      expect(r.status, CardStatus.invalidParameters);
    });
  });
}
