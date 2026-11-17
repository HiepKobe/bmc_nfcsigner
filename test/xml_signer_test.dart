import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:nfcsigner/nfcsigner.dart';
import 'package:nfcsigner/src/c14n.dart';
import 'package:xml/xml.dart';

// Giá trị mong đợi của C14N được sinh bằng lxml (libxml2).
void main() {
  group('C14n', () {
  group('a.xml', () {
    const src = r'''<?xml version="1.0" encoding="UTF-8"?>
<!-- header comment -->
<HDon xmlns="urn:invoice" xmlns:x="urn:x" z="1" a="2">
  <DLHDon Id="data">
    <TTChung><PBan>2.0.0</PBan><THDon>Hóa đơn &amp; GTGT</THDon></TTChung>
    <x:Empty/>
    <Note attr="a&quot;b&#9;c">text &lt; 5 &gt; 3</Note>
    <!-- inner comment -->
  </DLHDon>
  <DSCKS><NBan/></DSCKS>
</HDon>
''';
    test('inclusive', () {
      expect(C14n.canonicalize(XmlDocument.parse(src), algorithm: C14n.inclusive),
          r'''<HDon xmlns="urn:invoice" xmlns:x="urn:x" a="2" z="1">
  <DLHDon Id="data">
    <TTChung><PBan>2.0.0</PBan><THDon>Hóa đơn &amp; GTGT</THDon></TTChung>
    <x:Empty></x:Empty>
    <Note attr="a&quot;b&#x9;c">text &lt; 5 &gt; 3</Note>
    
  </DLHDon>
  <DSCKS><NBan></NBan></DSCKS>
</HDon>''');
    });
    test('exclusive', () {
      expect(C14n.canonicalize(XmlDocument.parse(src), algorithm: C14n.exclusive),
          r'''<HDon xmlns="urn:invoice" a="2" z="1">
  <DLHDon Id="data">
    <TTChung><PBan>2.0.0</PBan><THDon>Hóa đơn &amp; GTGT</THDon></TTChung>
    <x:Empty xmlns:x="urn:x"></x:Empty>
    <Note attr="a&quot;b&#x9;c">text &lt; 5 &gt; 3</Note>
    
  </DLHDon>
  <DSCKS><NBan></NBan></DSCKS>
</HDon>''');
    });
  });
  group('c.xml', () {
    const src = r'''<p:Root xmlns:p="urn:p" xmlns:unused="urn:u"><p:Item p:k="v" b="x">  spaced  </p:Item><Plain xmlns="">x</Plain><W xmlns="urn:w"><E/></W></p:Root>
''';
    test('inclusive', () {
      expect(C14n.canonicalize(XmlDocument.parse(src), algorithm: C14n.inclusive),
          r'''<p:Root xmlns:p="urn:p" xmlns:unused="urn:u"><p:Item b="x" p:k="v">  spaced  </p:Item><Plain>x</Plain><W xmlns="urn:w"><E></E></W></p:Root>''');
    });
    test('exclusive', () {
      expect(C14n.canonicalize(XmlDocument.parse(src), algorithm: C14n.exclusive),
          r'''<p:Root xmlns:p="urn:p"><p:Item b="x" p:k="v">  spaced  </p:Item><Plain>x</Plain><W xmlns="urn:w"><E></E></W></p:Root>''');
    });
  });
  });

  group('XmlSigner', () {
    const xml = '<HDon><DLHDon Id="d">x</DLHDon><DSCKS><NBan/></DSCKS></HDon>';
    const config = XmlSignatureConfig(referenceUri: '#d', xpath: '/HDon/DSCKS/NBan');

    test('DigestInfo SHA-256 ổn định giữa các lần gọi', () {
      final a = XmlSigner.createDigestInfoForXml(xmlContent: xml, config: config);
      final b = XmlSigner.createDigestInfoForXml(xmlContent: xml, config: config);
      expect(a.length, 51);
      expect(a, b);
    });

    test('chữ ký và certificate được đặt đúng chỗ', () {
      final sig = Uint8List.fromList([1, 2, 3]);
      final cert = Uint8List.fromList([9, 8, 7, 6]);
      final out = XmlSigner.signXml(
          xmlContent: xml, signatureBytes: sig, certificateBytes: cert, config: config);
      final doc = XmlDocument.parse(out);
      const ds = 'http://www.w3.org/2000/09/xmldsig#';
      expect(doc.findAllElements('SignatureValue', namespace: ds).single.innerText,
          base64.encode(sig));
      expect(doc.findAllElements('X509Certificate', namespace: ds).single.innerText,
          base64.encode(cert));
      expect(doc.findAllElements('Signature', namespace: ds).single.parentElement!.name.local,
          'NBan');
    });

    test('DigestValue không phụ thuộc chữ ký đã chèn (enveloped)', () {
      final signed = XmlSigner.signXml(
          xmlContent: xml,
          signatureBytes: Uint8List.fromList([1]),
          certificateBytes: Uint8List.fromList([2]),
          config: config);
      // Ký lại tài liệu đã ký (bỏ chữ ký cũ) phải cho cùng SignedInfo.
      final doc = XmlDocument.parse(signed);
      doc.findAllElements('Signature', namespace: 'http://www.w3.org/2000/09/xmldsig#')
          .single
          .remove();
      expect(
          XmlSigner.createDigestInfoForXml(xmlContent: doc.toXmlString(), config: config),
          XmlSigner.createDigestInfoForXml(xmlContent: xml, config: config));
    });

    test('từ chối thuật toán không hỗ trợ', () {
      expect(
          () => XmlSigner.createDigestInfoForXml(
              xmlContent: xml,
              config: const XmlSignatureConfig(
                  signatureMethod: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1')),
          throwsArgumentError);
    });
  });
}
