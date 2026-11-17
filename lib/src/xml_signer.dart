import 'dart:convert';
import 'dart:typed_data';

import 'package:xml/xml.dart';

import '../models/xml_signature_config.dart';
import 'c14n.dart';
import 'crypto_utils.dart';

/// Ký XML theo chuẩn XML-DSig (enveloped), với khoá nằm trên thẻ.
///
/// Quy trình hai bước, vì phép ký RSA diễn ra trên thẻ:
/// 1. [createDigestInfoForXml] dựng `<Signature>` (chưa có SignatureValue),
///    chuẩn hoá `<SignedInfo>` và trả về `DigestInfo(SHA-256(SignedInfo))` để
///    gửi lên thẻ ký (PSO:CDS).
/// 2. [signXml] dựng lại đúng cấu trúc đó, điền chữ ký và certificate, rồi
///    trả về XML đã ký.
///
/// Hai bước cho ra cùng một `SignedInfo` miễn là cùng [xmlContent] và
/// [XmlSignatureConfig] — `SignedInfo` không chứa gì phụ thuộc thời gian.
class XmlSigner {
  const XmlSigner._();

  static const _dsNs = 'http://www.w3.org/2000/09/xmldsig#';
  static const _envelopedTransform =
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature';
  static const _rsaSha256 =
      'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
  static const _sha256 = 'http://www.w3.org/2001/04/xmlenc#sha256';

  /// Tạo DigestInfo (PKCS#1, SHA-256) của `<SignedInfo>` đã chuẩn hoá.
  ///
  /// Đây là dữ liệu cần gửi cho thẻ ký.
  static Uint8List createDigestInfoForXml({
    required String xmlContent,
    required XmlSignatureConfig config,
  }) {
    final plan = _prepare(xmlContent, config);
    // createSha256DigestInfo tự băm SHA-256 dữ liệu đầu vào.
    return CryptoUtils.createSha256DigestInfo(plan.signedInfoCanonical);
  }

  /// Ghép chữ ký (do thẻ tạo trên DigestInfo của [createDigestInfoForXml]) và
  /// certificate vào XML, trả về tài liệu đã ký.
  static String signXml({
    required String xmlContent,
    required Uint8List signatureBytes,
    required Uint8List certificateBytes,
    required XmlSignatureConfig config,
  }) {
    if (signatureBytes.isEmpty) {
      throw ArgumentError('Chữ ký rỗng');
    }
    final plan = _prepare(xmlContent, config);
    final sig = plan.signature;

    sig
        .findElements('SignatureValue', namespace: _dsNs)
        .single
        .children
        .add(XmlText(base64.encode(signatureBytes)));

    if (config.includeCertificate) {
      if (certificateBytes.isEmpty) {
        throw ArgumentError('Certificate rỗng nhưng includeCertificate = true');
      }
      sig
          .findAllElements('X509Certificate', namespace: _dsNs)
          .single
          .children
          .add(XmlText(base64.encode(certificateBytes)));
    }

    return plan.document.toXmlString();
  }

  static _Plan _prepare(String xmlContent, XmlSignatureConfig config) {
    if (config.signatureMethod != _rsaSha256) {
      throw ArgumentError(
          'Chỉ hỗ trợ SignatureMethod $_rsaSha256 (thẻ ký DigestInfo SHA-256)');
    }
    if (config.digestMethod != _sha256) {
      throw ArgumentError('Chỉ hỗ trợ DigestMethod $_sha256');
    }
    if (!C14n.isSupported(config.canonicalizationMethod)) {
      throw ArgumentError(
          'CanonicalizationMethod không được hỗ trợ: ${config.canonicalizationMethod}');
    }
    if (!config.enveloped) {
      throw ArgumentError('Chỉ hỗ trợ chữ ký dạng enveloped');
    }

    // Trình phân tích XML chuẩn hoá xuống dòng thành LF.
    final normalized =
        xmlContent.replaceAll('\r\n', '\n').replaceAll('\r', '\n');
    final document = XmlDocument.parse(normalized);

    // 1. Digest của dữ liệu được tham chiếu (trước khi chèn chữ ký — tương
    //    đương transform enveloped-signature).
    final referenceUri = config.referenceUri ?? '';
    final XmlNode referenced;
    if (referenceUri.isEmpty) {
      referenced = document;
    } else if (referenceUri.startsWith('#')) {
      referenced = _findById(document, referenceUri.substring(1));
    } else {
      throw ArgumentError(
          'Chỉ hỗ trợ tham chiếu trong cùng tài liệu ("" hoặc "#id"), nhận: $referenceUri');
    }
    // Tham chiếu cùng tài liệu luôn bỏ comment.
    final referenceCanonical = C14n.canonicalize(
      referenced,
      algorithm: config.canonicalizationMethod,
      withComments: false,
    );
    final digestValue =
        base64.encode(CryptoUtils.sha256Hash(utf8.encode(referenceCanonical)));

    // 2. Dựng <Signature> và chèn vào vị trí đích.
    final signature = _buildSignature(config, referenceUri, digestValue);
    final parent = _findParent(document, config.xpath);
    parent.children.add(signature);

    // 3. Chuẩn hoá SignedInfo trong ngữ cảnh namespace thực của nó.
    final signedInfo =
        signature.findElements('SignedInfo', namespace: _dsNs).single;
    final signedInfoCanonical = utf8.encode(C14n.canonicalize(
      signedInfo,
      algorithm: config.canonicalizationMethod,
    ));

    return _Plan(document, signature, Uint8List.fromList(signedInfoCanonical));
  }

  static XmlElement _buildSignature(
    XmlSignatureConfig config,
    String referenceUri,
    String digestValue,
  ) {
    final c14n = _attr(config.canonicalizationMethod);
    final b = StringBuffer()
      ..write('<ds:Signature xmlns:ds="$_dsNs"');
    if (config.signatureId != null && config.signatureId!.isNotEmpty) {
      b.write(' Id="${_attr(config.signatureId!)}"');
    }
    b
      ..write('>')
      ..write('<ds:SignedInfo>')
      ..write('<ds:CanonicalizationMethod Algorithm="$c14n"></ds:CanonicalizationMethod>')
      ..write('<ds:SignatureMethod Algorithm="$_rsaSha256"></ds:SignatureMethod>')
      ..write('<ds:Reference URI="${_attr(referenceUri)}">')
      ..write('<ds:Transforms>')
      ..write('<ds:Transform Algorithm="$_envelopedTransform"></ds:Transform>')
      ..write('<ds:Transform Algorithm="$c14n"></ds:Transform>')
      ..write('</ds:Transforms>')
      ..write('<ds:DigestMethod Algorithm="$_sha256"></ds:DigestMethod>')
      ..write('<ds:DigestValue>$digestValue</ds:DigestValue>')
      ..write('</ds:Reference>')
      ..write('</ds:SignedInfo>')
      ..write('<ds:SignatureValue></ds:SignatureValue>');
    if (config.includeCertificate) {
      b.write('<ds:KeyInfo><ds:X509Data><ds:X509Certificate>'
          '</ds:X509Certificate></ds:X509Data></ds:KeyInfo>');
    }
    b.write('</ds:Signature>');
    return XmlDocument.parse(b.toString()).rootElement.copy();
  }

  /// Tìm phần tử cha để đặt chữ ký.
  ///
  /// [path] là đường dẫn tuyệt đối đơn giản theo tên cục bộ, ví dụ
  /// `/HDon/DSCKS/NBan`. `null` hoặc rỗng: phần tử gốc.
  static XmlElement _findParent(XmlDocument doc, String? path) {
    final root = doc.rootElement;
    if (path == null || path.trim().isEmpty || path.trim() == '/') return root;
    final parts = path.split('/').where((p) => p.isNotEmpty).map((p) {
      final i = p.indexOf(':');
      return i >= 0 ? p.substring(i + 1) : p;
    }).toList();
    if (parts.first != root.name.local) {
      throw ArgumentError('xpath "$path" không khớp phần tử gốc <${root.name.local}>');
    }
    var current = root;
    for (final name in parts.skip(1)) {
      final next = current.childElements
          .where((e) => e.name.local == name)
          .firstOrNull;
      if (next == null) {
        throw ArgumentError('Không tìm thấy phần tử "$name" theo xpath "$path"');
      }
      current = next;
    }
    return current;
  }

  static XmlElement _findById(XmlDocument doc, String id) {
    for (final e in doc.descendantElements) {
      for (final a in e.attributes) {
        final local = a.name.local;
        if ((local == 'Id' || local == 'ID' || local == 'id') && a.value == id) {
          return e;
        }
      }
    }
    throw ArgumentError('Không tìm thấy phần tử có Id="$id"');
  }

  static String _attr(String s) => s
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('"', '&quot;');
}

class _Plan {
  _Plan(this.document, this.signature, this.signedInfoCanonical);
  final XmlDocument document;
  final XmlElement signature;
  final Uint8List signedInfoCanonical;
}
