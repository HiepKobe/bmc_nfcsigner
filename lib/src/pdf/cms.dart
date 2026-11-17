import 'dart:typed_data';

/// Mã hoá DER tối thiểu và dựng CMS SignedData (RFC 5652) dạng detached cho
/// chữ ký PDF (`adbe.pkcs7.detached` / `ETSI.CAdES.detached`).
class Der {
  const Der._();

  static Uint8List tlv(int tag, List<int> content) {
    final len = content.length;
    final b = BytesBuilder(copy: false)..addByte(tag);
    if (len < 0x80) {
      b.addByte(len);
    } else {
      final lenBytes = <int>[];
      var l = len;
      while (l > 0) {
        lenBytes.insert(0, l & 0xFF);
        l >>= 8;
      }
      b
        ..addByte(0x80 | lenBytes.length)
        ..add(lenBytes);
    }
    b.add(content);
    return b.toBytes();
  }

  static Uint8List seq(List<List<int>> items) => tlv(0x30, _cat(items));
  static Uint8List set(List<List<int>> items) => tlv(0x31, _cat(items));

  /// SET OF theo DER: các phần tử được sắp theo thứ tự byte của mã hoá.
  static Uint8List setOf(List<Uint8List> items) {
    final sorted = [...items]..sort(_compareBytes);
    return tlv(0x31, _cat(sorted));
  }

  static Uint8List integer(int v) {
    final bytes = <int>[];
    var x = v;
    do {
      bytes.insert(0, x & 0xFF);
      x >>= 8;
    } while (x > 0);
    if (bytes.first & 0x80 != 0) bytes.insert(0, 0);
    return tlv(0x02, bytes);
  }

  static Uint8List oid(String dotted) {
    final parts = dotted.split('.').map(int.parse).toList();
    final out = <int>[parts[0] * 40 + parts[1]];
    for (final p in parts.skip(2)) {
      final chunk = <int>[p & 0x7F];
      var x = p >> 7;
      while (x > 0) {
        chunk.insert(0, 0x80 | (x & 0x7F));
        x >>= 7;
      }
      out.addAll(chunk);
    }
    return tlv(0x06, out);
  }

  static Uint8List nullValue() => Uint8List.fromList([0x05, 0x00]);
  static Uint8List octets(List<int> v) => tlv(0x04, v);

  static Uint8List utcTime(DateTime t) {
    final u = t.toUtc();
    String two(int v) => v.toString().padLeft(2, '0');
    final s = '${two(u.year % 100)}${two(u.month)}${two(u.day)}'
        '${two(u.hour)}${two(u.minute)}${two(u.second)}Z';
    return tlv(0x17, s.codeUnits);
  }

  static Uint8List explicit(int n, List<int> content) => tlv(0xA0 | n, content);

  static Uint8List _cat(List<List<int>> items) {
    final b = BytesBuilder(copy: false);
    for (final i in items) {
      b.add(i);
    }
    return b.toBytes();
  }

  static int _compareBytes(Uint8List a, Uint8List b) {
    for (var i = 0; i < a.length && i < b.length; i++) {
      if (a[i] != b[i]) return a[i] - b[i];
    }
    return a.length - b.length;
  }
}

/// Phần tử DER đã đọc: tag, và vị trí nội dung trong bộ đệm gốc.
class DerElement {
  DerElement(this.buf, this.tag, this.start, this.headerLen, this.length);
  final Uint8List buf;
  final int tag;
  final int start;
  final int headerLen;
  final int length;

  int get end => start + headerLen + length;
  Uint8List get encoded => Uint8List.sublistView(buf, start, end);
  Uint8List get content => Uint8List.sublistView(buf, start + headerLen, end);

  static DerElement read(Uint8List buf, int pos) {
    if (pos + 2 > buf.length) throw const FormatException('DER bị cắt cụt');
    final tag = buf[pos];
    var len = buf[pos + 1];
    var header = 2;
    if (len & 0x80 != 0) {
      final n = len & 0x7F;
      if (n == 0 || n > 4) throw const FormatException('Độ dài DER không hỗ trợ');
      len = 0;
      for (var i = 0; i < n; i++) {
        len = (len << 8) | buf[pos + 2 + i];
      }
      header += n;
    }
    if (pos + header + len > buf.length) {
      throw const FormatException('DER bị cắt cụt');
    }
    return DerElement(buf, tag, pos, header, len);
  }

  List<DerElement> children() {
    final out = <DerElement>[];
    var p = start + headerLen;
    while (p < end) {
      final e = read(buf, p);
      out.add(e);
      p = e.end;
    }
    return out;
  }
}

class CmsSigner {
  const CmsSigner._();

  static const _oidData = '1.2.840.113549.1.7.1';
  static const _oidSignedData = '1.2.840.113549.1.7.2';
  static const _oidContentType = '1.2.840.113549.1.9.3';
  static const _oidMessageDigest = '1.2.840.113549.1.9.4';
  static const _oidSigningTime = '1.2.840.113549.1.9.5';
  static const _oidSha256 = '2.16.840.1.101.3.4.2.1';
  static const _oidRsaEncryption = '1.2.840.113549.1.1.1';

  /// Các signed attributes dưới dạng SET (tag 0x31) — chính là dữ liệu được
  /// băm và ký. Không phụ thuộc certificate, nên ký được trước khi biết cert
  /// (cho phép ký và đọc cert trong cùng một lần chạm thẻ).
  static Uint8List signedAttributes({
    required Uint8List contentDigest,
    required DateTime signingTime,
  }) {
    Uint8List attr(String oid, Uint8List value) =>
        Der.seq([Der.oid(oid), Der.set([value])]);
    return Der.setOf([
      attr(_oidContentType, Der.oid(_oidData)),
      attr(_oidSigningTime, Der.utcTime(signingTime)),
      attr(_oidMessageDigest, Der.octets(contentDigest)),
    ]);
  }

  /// Dựng ContentInfo(SignedData) hoàn chỉnh.
  ///
  /// [signedAttrs] là đầu ra của [signedAttributes]; [signature] là chữ ký
  /// RSA PKCS#1 v1.5 trên `DigestInfo(SHA-256(signedAttrs))`.
  static Uint8List build({
    required Uint8List signedAttrs,
    required Uint8List signature,
    required Uint8List certificate,
  }) {
    final cert = DerElement.read(certificate, 0);
    if (cert.tag != 0x30) throw const FormatException('Certificate không phải DER');
    final tbs = cert.children().first.children();
    // TBSCertificate: [0] version (tuỳ chọn), serialNumber, signature, issuer, ...
    var i = 0;
    if (tbs[0].tag == 0xA0) i = 1;
    final serial = tbs[i].encoded;
    final issuer = tbs[i + 2].encoded;

    final sha256Alg = Der.seq([Der.oid(_oidSha256), Der.nullValue()]);
    final rsaAlg = Der.seq([Der.oid(_oidRsaEncryption), Der.nullValue()]);

    // signedAttrs được mã hoá với tag [0] IMPLICIT thay cho SET.
    final attrsImplicit = Uint8List.fromList(signedAttrs)..[0] = 0xA0;

    final signerInfo = Der.seq([
      Der.integer(1),
      Der.seq([issuer, serial]),
      sha256Alg,
      attrsImplicit,
      rsaAlg,
      Der.octets(signature),
    ]);

    final signedData = Der.seq([
      Der.integer(1),
      Der.set([sha256Alg]),
      Der.seq([Der.oid(_oidData)]),
      Der.tlv(0xA0, cert.encoded),
      Der.set([signerInfo]),
    ]);

    return Der.seq([Der.oid(_oidSignedData), Der.explicit(0, signedData)]);
  }
}

/// Kiểm tra chữ ký RSA PKCS#1 v1.5 bằng khoá công khai trong certificate.
///
/// Dùng để chặn chữ ký sai (ký nhầm dữ liệu, ghép nhầm certificate) trước khi
/// ghi vào PDF — tốt hơn để người nhận phát hiện khi mở bằng Adobe.
class RsaVerifier {
  const RsaVerifier._();

  /// `true` nếu [signature] là chữ ký PKCS#1 v1.5 trên đúng [digestInfo] bằng
  /// khoá của [certificate]. Ném [FormatException] nếu certificate không phải
  /// khoá RSA.
  static bool verify({
    required Uint8List certificate,
    required Uint8List digestInfo,
    required Uint8List signature,
  }) {
    final (n, e) = rsaPublicKey(certificate);
    final k = (n.bitLength + 7) ~/ 8;
    if (signature.length != k) return false;
    final s = _toBigInt(signature);
    if (s >= n) return false;
    final m = s.modPow(e, n);
    final em = _toBytes(m, k);
    // EM = 00 01 FF..FF 00 || DigestInfo, tối thiểu 8 byte FF.
    final psLen = k - 3 - digestInfo.length;
    if (psLen < 8 || em[0] != 0x00 || em[1] != 0x01 || em[2 + psLen] != 0x00) {
      return false;
    }
    for (var i = 2; i < 2 + psLen; i++) {
      if (em[i] != 0xFF) return false;
    }
    for (var i = 0; i < digestInfo.length; i++) {
      if (em[3 + psLen + i] != digestInfo[i]) return false;
    }
    return true;
  }

  /// (modulus, exponent) của khoá RSA trong certificate X.509.
  static (BigInt, BigInt) rsaPublicKey(Uint8List certificate) {
    final tbs = DerElement.read(certificate, 0).children().first.children();
    final i = tbs[0].tag == 0xA0 ? 1 : 0;
    // serial, signature, issuer, validity, subject, subjectPublicKeyInfo
    final spki = tbs[i + 5].children();
    const rsaOid = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
    final algOid = spki[0].children()[0].content;
    if (algOid.length != rsaOid.length ||
        !List.generate(rsaOid.length, (j) => algOid[j] == rsaOid[j]).every((b) => b)) {
      throw const FormatException('Certificate không chứa khoá RSA');
    }
    final bitString = spki[1].content; // byte đầu: số bit thừa (0)
    final rsaKey = DerElement.read(Uint8List.sublistView(bitString, 1), 0).children();
    return (_toBigInt(rsaKey[0].content), _toBigInt(rsaKey[1].content));
  }

  static BigInt _toBigInt(List<int> bytes) {
    var r = BigInt.zero;
    for (final b in bytes) {
      r = (r << 8) | BigInt.from(b);
    }
    return r;
  }

  static Uint8List _toBytes(BigInt v, int len) {
    final out = Uint8List(len);
    var x = v;
    for (var i = len - 1; i >= 0; i--) {
      out[i] = (x & BigInt.from(0xFF)).toInt();
      x >>= 8;
    }
    return out;
  }
}
