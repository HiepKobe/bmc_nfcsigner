import 'dart:convert';
import 'dart:io' show ZLibCodec;
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import '../crypto_utils.dart';
import 'cms.dart';
import 'pdf_document.dart';

/// Hàm ký trên thẻ: nhận DigestInfo (SHA-256), trả chữ ký RSA và certificate
/// của khoá ký — trong cùng một giao dịch thẻ.
typedef PdfCardSigner = Future<({Uint8List signature, Uint8List certificate})>
    Function(Uint8List digestInfo);

/// Ảnh hiển thị của chữ ký (RGB + kênh alpha, 8 bit mỗi kênh).
class PdfAppearanceImage {
  PdfAppearanceImage({
    required this.width,
    required this.height,
    required this.rgb,
    required this.alpha,
  }) : assert(rgb.length == width * height * 3),
       assert(alpha.length == width * height);

  final int width;
  final int height;
  final Uint8List rgb;
  final Uint8List alpha;
}

/// Vị trí và nội dung của trường chữ ký.
class PdfSignatureField {
  const PdfSignatureField({
    required this.pageNumber,
    required this.x,
    required this.y,
    required this.width,
    required this.height,
    this.signerName,
    this.reason,
    this.location,
    this.contactInfo,
    this.appearance,
  });

  /// Trang (bắt đầu từ 1).
  final int pageNumber;
  final double x;
  final double y;
  final double width;
  final double height;
  final String? signerName;
  final String? reason;
  final String? location;
  final String? contactInfo;

  /// `null`: chữ ký không hiển thị (trường vẫn nằm trên trang, kích thước 0).
  final PdfAppearanceImage? appearance;
}

/// Ký PDF bằng cập nhật tăng dần (ISO 32000-1 §12.8), giữ nguyên toàn bộ byte
/// của file gốc — nên các chữ ký có sẵn trong file vẫn hợp lệ.
///
/// Chữ ký là CMS `adbe.pkcs7.detached`, SHA-256, RSA PKCS#1 v1.5.
class PdfIncrementalSigner {
  const PdfIncrementalSigner._();

  /// Số byte dành sẵn cho CMS (đủ cho RSA-4096 + chuỗi certificate dài).
  static const defaultReservedBytes = 8192;

  /// Ký trong một lần: [prepare] → [signer] → [complete].
  static Future<Uint8List> sign({
    required Uint8List pdf,
    required PdfSignatureField field,
    required PdfCardSigner signer,
    DateTime? signingTime,
    int reservedBytes = defaultReservedBytes,
  }) async {
    final prepared = prepare(
      pdf: pdf,
      field: field,
      signingTime: signingTime,
      reservedBytes: reservedBytes,
    );
    final result = await signer(prepared.dataToBeSigned);
    return complete(
      prepared: prepared,
      signature: result.signature,
      certificate: result.certificate,
    );
  }

  /// Bước 1: thêm trường chữ ký (vùng /Contents để trống) và tính dữ liệu cần
  /// ký. Gửi [PdfPreparedSignature.dataToBeSigned] (DigestInfo SHA-256) tới
  /// dịch vụ ký, rồi gọi [complete] với chữ ký nhận được.
  static PdfPreparedSignature prepare({
    required Uint8List pdf,
    required PdfSignatureField field,
    DateTime? signingTime,
    int reservedBytes = defaultReservedBytes,
  }) {
    final doc = PdfDocument.parse(pdf);
    final time = signingTime ?? DateTime.now();
    final pages = doc.pageRefs();
    if (field.pageNumber < 1 || field.pageNumber > pages.length) {
      throw ArgumentError(
          'Trang ${field.pageNumber} không tồn tại (PDF có ${pages.length} trang)');
    }
    final pageRef = pages[field.pageNumber - 1];

    var nextNum = doc.size;
    int alloc() => nextNum++;

    // Đối tượng mới / đối tượng ghi đè: số đối tượng -> (gen, nội dung).
    final objects = <int, (int, PdfObject)>{};

    final sigRef = PdfRef(alloc(), 0);
    final widgetRef = PdfRef(alloc(), 0);

    // --- Appearance ---------------------------------------------------------
    PdfRef? apRef;
    final w = field.appearance == null ? 0.0 : field.width;
    final h = field.appearance == null ? 0.0 : field.height;
    if (field.appearance != null) {
      final img = field.appearance!;
      final imgRef = PdfRef(alloc(), 0);
      final maskRef = PdfRef(alloc(), 0);
      apRef = PdfRef(alloc(), 0);
      final zlib = ZLibCodec(level: 9);
      objects[maskRef.num] = (
        0,
        PdfStream(
          PdfDict({
            'Type': const PdfName('XObject'),
            'Subtype': const PdfName('Image'),
            'Width': PdfNumber('${img.width}'),
            'Height': PdfNumber('${img.height}'),
            'ColorSpace': const PdfName('DeviceGray'),
            'BitsPerComponent': const PdfNumber('8'),
            'Filter': const PdfName('FlateDecode'),
          }),
          Uint8List.fromList(zlib.encode(img.alpha)),
        )
      );
      objects[imgRef.num] = (
        0,
        PdfStream(
          PdfDict({
            'Type': const PdfName('XObject'),
            'Subtype': const PdfName('Image'),
            'Width': PdfNumber('${img.width}'),
            'Height': PdfNumber('${img.height}'),
            'ColorSpace': const PdfName('DeviceRGB'),
            'BitsPerComponent': const PdfNumber('8'),
            'Filter': const PdfName('FlateDecode'),
            'SMask': maskRef,
          }),
          Uint8List.fromList(zlib.encode(img.rgb)),
        )
      );
      final content = 'q ${_n(w)} 0 0 ${_n(h)} 0 0 cm /Im1 Do Q';
      objects[apRef.num] = (
        0,
        PdfStream(
          PdfDict({
            'Type': const PdfName('XObject'),
            'Subtype': const PdfName('Form'),
            'BBox': PdfArray([
              const PdfNumber('0'),
              const PdfNumber('0'),
              PdfNumber(_n(w)),
              PdfNumber(_n(h)),
            ]),
            'Resources': PdfDict({
              'XObject': PdfDict({'Im1': imgRef}),
            }),
          }),
          Uint8List.fromList(latin1.encode(content)),
        )
      );
    }

    // --- Trường chữ ký (widget) ----------------------------------------------
    final catalog = (doc.resolve(doc.catalogRef) as PdfDict);
    final acroFormRaw = catalog['AcroForm'];
    final acroForm = PdfDict(Map.of((doc.resolve(acroFormRaw) as PdfDict?)?.entries ?? {}));
    final fields = <PdfObject>[
      ...((doc.resolve(acroForm['Fields']) as PdfArray?)?.items ?? const [])
    ];
    final fieldName = _uniqueFieldName(doc, fields);

    final widget = PdfDict({
      'Type': const PdfName('Annot'),
      'Subtype': const PdfName('Widget'),
      'FT': const PdfName('Sig'),
      'T': PdfWriter.ascii(fieldName),
      'V': sigRef,
      'F': const PdfNumber('132'), // Print | Locked
      'P': pageRef,
      'Rect': PdfArray([
        PdfNumber(_n(field.x)),
        PdfNumber(_n(field.y)),
        PdfNumber(_n(field.x + w)),
        PdfNumber(_n(field.y + h)),
      ]),
    });
    if (apRef != null) widget['AP'] = PdfDict({'N': apRef});
    objects[widgetRef.num] = (0, widget);

    // --- Trang: thêm widget vào /Annots ------------------------------------
    final page = PdfDict(Map.of((doc.resolve(pageRef) as PdfDict).entries));
    final annotsRaw = page['Annots'];
    final annots = <PdfObject>[
      ...((doc.resolve(annotsRaw) as PdfArray?)?.items ?? const []),
      widgetRef
    ];
    if (annotsRaw is PdfRef) {
      // Mảng /Annots là đối tượng riêng: ghi đè đối tượng đó.
      objects[annotsRaw.num] = (annotsRaw.gen, PdfArray(annots));
    } else {
      page['Annots'] = PdfArray(annots);
      objects[pageRef.num] = (pageRef.gen, page);
    }

    // --- AcroForm ----------------------------------------------------------
    fields.add(widgetRef);
    acroForm['Fields'] = PdfArray(fields);
    acroForm['SigFlags'] = const PdfNumber('3'); // SignaturesExist | AppendOnly
    if (acroFormRaw is PdfRef) {
      objects[acroFormRaw.num] = (acroFormRaw.gen, acroForm);
    } else {
      final newCatalog = PdfDict(Map.of(catalog.entries));
      newCatalog['AcroForm'] = acroForm;
      objects[doc.catalogRef.num] = (doc.catalogRef.gen, newCatalog);
    }

    // --- Từ điển chữ ký (placeholder) --------------------------------------
    const byteRangePlaceholder = '[0 0000000000 0000000000 0000000000]';
    final contentsHexLen = reservedBytes * 2;
    final sigDict = PdfDict({
      'Type': const PdfName('Sig'),
      'Filter': const PdfName('Adobe.PPKLite'),
      'SubFilter': const PdfName('adbe.pkcs7.detached'),
      'ByteRange': PdfRaw(byteRangePlaceholder),
      'Contents': PdfRaw('<${'0' * contentsHexLen}>'),
      'M': PdfWriter.ascii(_pdfDate(time)),
    });
    if (field.signerName?.isNotEmpty == true) sigDict['Name'] = PdfWriter.text(field.signerName!);
    if (field.reason?.isNotEmpty == true) sigDict['Reason'] = PdfWriter.text(field.reason!);
    if (field.location?.isNotEmpty == true) sigDict['Location'] = PdfWriter.text(field.location!);
    if (field.contactInfo?.isNotEmpty == true) {
      sigDict['ContactInfo'] = PdfWriter.text(field.contactInfo!);
    }
    objects[sigRef.num] = (0, sigDict);

    // --- Ghi bản cập nhật ----------------------------------------------------
    final out = BytesBuilder(copy: false)..add(pdf);
    if (pdf.isNotEmpty && pdf.last != 0x0A && pdf.last != 0x0D) out.addByte(0x0A);

    final offsets = <int, (int, int)>{}; // num -> (offset, gen)
    final nums = objects.keys.toList()..sort();
    for (final num in nums) {
      final (gen, obj) = objects[num]!;
      offsets[num] = (out.length, gen);
      out.add(latin1.encode('$num $gen obj\n'));
      PdfWriter.write(obj, out);
      out.add(latin1.encode('\nendobj\n'));
    }

    final newTrailer = PdfDict({
      'Root': doc.catalogRef,
      'Prev': PdfNumber('${doc.startXref}'),
    });
    if (doc.trailer['Info'] != null) newTrailer['Info'] = doc.trailer['Info']!;
    if (doc.trailer['ID'] != null) newTrailer['ID'] = doc.trailer['ID']!;

    final xrefOffset = out.length;
    if (doc.usesXrefStream) {
      final xrefNum = alloc();
      offsets[xrefNum] = (xrefOffset, 0);
      final entries = BytesBuilder(copy: false);
      final sortedNums = offsets.keys.toList()..sort();
      for (final n in sortedNums) {
        final (off, gen) = offsets[n]!;
        entries
          ..addByte(1)
          ..add([(off >> 24) & 0xFF, (off >> 16) & 0xFF, (off >> 8) & 0xFF, off & 0xFF])
          ..add([(gen >> 8) & 0xFF, gen & 0xFF]);
      }
      final dict = PdfDict({
        'Type': const PdfName('XRef'),
        'Size': PdfNumber('$nextNum'),
        'Index': PdfArray(_subsections(sortedNums)
            .expand((s) => [PdfNumber('${s.$1}'), PdfNumber('${s.$2}')])
            .toList()),
        'W': PdfArray(const [PdfNumber('1'), PdfNumber('4'), PdfNumber('2')]),
        ...newTrailer.entries,
      });
      out.add(latin1.encode('$xrefNum 0 obj\n'));
      PdfWriter.write(PdfStream(dict, entries.toBytes()), out);
      out.add(latin1.encode('\nendobj\n'));
    } else {
      out.add(latin1.encode('xref\n'));
      final sortedNums = offsets.keys.toList()..sort();
      for (final (start, count) in _subsections(sortedNums)) {
        out.add(latin1.encode('$start $count\n'));
        for (var n = start; n < start + count; n++) {
          final (off, gen) = offsets[n]!;
          out.add(latin1.encode(
              '${off.toString().padLeft(10, '0')} ${gen.toString().padLeft(5, '0')} n\r\n'));
        }
      }
      newTrailer['Size'] = PdfNumber('$nextNum');
      out.add(latin1.encode('trailer\n'));
      PdfWriter.write(newTrailer, out);
      out.add(latin1.encode('\n'));
    }
    out.add(latin1.encode('startxref\n$xrefOffset\n%%EOF\n'));

    final bytes = out.toBytes();

    // --- ByteRange & băm ----------------------------------------------------
    final sigStart = offsets[sigRef.num]!.$1;
    final contentsStart = _indexOf(bytes, latin1.encode('<${'0' * 16}'), sigStart);
    final contentsEnd = contentsStart + contentsHexLen + 2;
    final brStart = _indexOf(bytes, latin1.encode(byteRangePlaceholder), sigStart);
    if (contentsStart < 0 || brStart < 0) {
      throw StateError('Không định vị được vùng chữ ký');
    }
    final byteRange =
        '[0 $contentsStart $contentsEnd ${bytes.length - contentsEnd}]';
    if (byteRange.length > byteRangePlaceholder.length) {
      throw StateError('PDF quá lớn cho ByteRange');
    }
    bytes.setRange(brStart, brStart + byteRangePlaceholder.length,
        latin1.encode(byteRange.padRight(byteRangePlaceholder.length)));

    final digestSink = _DigestSink();
    sha256.startChunkedConversion(digestSink)
      ..add(Uint8List.sublistView(bytes, 0, contentsStart))
      ..add(Uint8List.sublistView(bytes, contentsEnd))
      ..close();
    final digest = digestSink.value.bytes;

    final signedAttrs = CmsSigner.signedAttributes(
      contentDigest: Uint8List.fromList(digest),
      signingTime: time,
    );
    return PdfPreparedSignature(
      pdf: bytes,
      contentsOffset: contentsStart,
      reservedBytes: reservedBytes,
      signedAttributes: signedAttrs,
    );
  }

  /// Bước 2: ghép chữ ký RSA PKCS#1 v1.5 ([signature], ký trên
  /// [PdfPreparedSignature.dataToBeSigned]) và [certificate] (DER) của người ký
  /// thành CMS, ghi vào PDF đã chuẩn bị. Trả về PDF đã ký.
  ///
  /// Ném [PdfSignatureMismatchException] nếu chữ ký không khớp dữ liệu hoặc
  /// certificate; [ArgumentError] nếu [prepared] không còn nguyên vẹn.
  static Uint8List complete({
    required PdfPreparedSignature prepared,
    required Uint8List signature,
    required Uint8List certificate,
  }) {
    prepared.checkIntegrity();
    // Chặn chữ ký sai trước khi ghi file: ký nhầm dữ liệu hoặc certificate
    // không thuộc khoá đã ký đều cho ra PDF không verify được.
    if (!RsaVerifier.verify(
      certificate: certificate,
      digestInfo: prepared.dataToBeSigned,
      signature: signature,
    )) {
      throw PdfSignatureMismatchException();
    }
    final cms = CmsSigner.build(
      signedAttrs: prepared.signedAttributes,
      signature: signature,
      certificate: certificate,
    );
    if (cms.length > prepared.reservedBytes) {
      throw StateError(
          'Chữ ký (${cms.length} byte) vượt vùng dành sẵn (${prepared.reservedBytes} byte)');
    }
    final bytes = Uint8List.fromList(prepared.pdf);
    final hex = cms.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    final start = prepared.contentsOffset + 1;
    bytes.setRange(start, start + hex.length, latin1.encode(hex));
    return bytes;
  }

  // ---------------------------------------------------------------------------

  static String _uniqueFieldName(PdfDocument doc, List<PdfObject> fields) {
    final names = <String>{};
    for (final f in fields) {
      final d = doc.resolve(f);
      if (d is PdfDict) {
        final t = doc.resolve(d['T']);
        if (t is PdfString) names.add(latin1.decode(t.bytes, allowInvalid: true));
      }
    }
    var i = 1;
    while (names.contains('Signature$i')) {
      i++;
    }
    return 'Signature$i';
  }

  static List<(int, int)> _subsections(List<int> sorted) {
    final out = <(int, int)>[];
    for (final n in sorted) {
      if (out.isNotEmpty && out.last.$1 + out.last.$2 == n) {
        out[out.length - 1] = (out.last.$1, out.last.$2 + 1);
      } else {
        out.add((n, 1));
      }
    }
    return out;
  }

  static int _indexOf(Uint8List hay, List<int> needle, int from) {
    outer:
    for (var i = from; i <= hay.length - needle.length; i++) {
      for (var j = 0; j < needle.length; j++) {
        if (hay[i + j] != needle[j]) continue outer;
      }
      return i;
    }
    return -1;
  }

  static String _n(double v) {
    if (v == v.roundToDouble()) return v.toInt().toString();
    return v.toStringAsFixed(3);
  }

  static String _pdfDate(DateTime t) {
    String two(int v) => v.toString().padLeft(2, '0');
    final off = t.timeZoneOffset;
    final sign = off.isNegative ? '-' : '+';
    final oh = two(off.inHours.abs());
    final om = two(off.inMinutes.abs() % 60);
    return 'D:${t.year}${two(t.month)}${two(t.day)}${two(t.hour)}${two(t.minute)}'
        "${two(t.second)}$sign$oh'$om'";
  }
}

class _DigestSink implements Sink<Digest> {
  late Digest value;
  @override
  void add(Digest data) => value = data;
  @override
  void close() {}
}

/// Chữ ký trả về không khớp với dữ liệu cần ký hoặc với certificate.
class PdfSignatureMismatchException implements Exception {
  @override
  String toString() =>
      'Chữ ký không hợp lệ với certificate (ký sai dữ liệu hoặc sai certificate)';
}

/// PDF đã chuẩn bị chờ chữ ký (kết quả của [PdfIncrementalSigner.prepare]).
///
/// Lưu được qua [toJson] / [fromJson] khi bước ký diễn ra ở nơi khác hoặc mất
/// nhiều thời gian (ví dụ chờ người dùng xác nhận ký trên SIM).
class PdfPreparedSignature {
  PdfPreparedSignature({
    required this.pdf,
    required this.contentsOffset,
    required this.reservedBytes,
    required this.signedAttributes,
  });

  /// PDF đã có trường chữ ký, /ByteRange đã điền, /Contents còn toàn số 0.
  final Uint8List pdf;

  /// Vị trí ký tự `<` mở đầu /Contents trong [pdf].
  final int contentsOffset;

  /// Số byte dành cho CMS trong /Contents.
  final int reservedBytes;

  /// Signed attributes của CMS (SET, DER) — dữ liệu thực sự được ký.
  final Uint8List signedAttributes;

  /// DigestInfo(SHA-256(signedAttributes)) — đưa vào `DataToBeSigned` khi gọi
  /// dịch vụ ký (MSSP `MSS_Signature`, MSS_Format PKCS1).
  Uint8List get dataToBeSigned => CryptoUtils.createSha256DigestInfo(signedAttributes);

  /// SHA-256(signedAttributes), 32 byte — cho dịch vụ ký nhận hash thô.
  Uint8List get hash => Uint8List.fromList(sha256.convert(signedAttributes).bytes);

  Map<String, dynamic> toJson() => {
        'pdf': base64.encode(pdf),
        'contentsOffset': contentsOffset,
        'reservedBytes': reservedBytes,
        'signedAttributes': base64.encode(signedAttributes),
      };

  factory PdfPreparedSignature.fromJson(Map<String, dynamic> json) {
    final p = PdfPreparedSignature(
      pdf: base64.decode(json['pdf'] as String),
      contentsOffset: json['contentsOffset'] as int,
      reservedBytes: json['reservedBytes'] as int,
      signedAttributes: base64.decode(json['signedAttributes'] as String),
    );
    p.checkIntegrity();
    return p;
  }

  /// Kiểm tra [pdf] vẫn là file đã chuẩn bị: vùng /Contents còn trống và hash
  /// các vùng /ByteRange khớp messageDigest trong [signedAttributes].
  void checkIntegrity() {
    final end = contentsOffset + reservedBytes * 2 + 1;
    if (contentsOffset < 0 || end >= pdf.length || pdf[contentsOffset] != 0x3C || pdf[end] != 0x3E) {
      throw ArgumentError('Dữ liệu chuẩn bị không hợp lệ: không thấy vùng /Contents');
    }
    for (var i = contentsOffset + 1; i < end; i++) {
      if (pdf[i] != 0x30) {
        throw ArgumentError('PDF đã được ghi chữ ký hoặc bị sửa sau bước chuẩn bị');
      }
    }
    final sink = _DigestSink();
    sha256.startChunkedConversion(sink)
      ..add(Uint8List.sublistView(pdf, 0, contentsOffset))
      ..add(Uint8List.sublistView(pdf, end + 1))
      ..close();
    if (!_contains(signedAttributes, sink.value.bytes)) {
      throw ArgumentError('PDF không khớp với dữ liệu đã ký (bị sửa sau bước chuẩn bị)');
    }
  }

  static bool _contains(List<int> hay, List<int> needle) {
    outer:
    for (var i = 0; i <= hay.length - needle.length; i++) {
      for (var j = 0; j < needle.length; j++) {
        if (hay[i + j] != needle[j]) continue outer;
      }
      return true;
    }
    return false;
  }
}
