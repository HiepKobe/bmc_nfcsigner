import 'dart:convert';
import 'dart:io' show ZLibCodec;
import 'dart:typed_data';

/// Bộ đọc PDF tối thiểu, đủ cho việc ký bằng cập nhật tăng dần (incremental
/// update): đọc bảng xref (dạng bảng cổ điển và dạng xref stream, kể cả file
/// lai), object stream, và cây trang.
///
/// Không giải mã nội dung trang, không hỗ trợ PDF mã hoá.

// ---------------------------------------------------------------------------
// Mô hình đối tượng
// ---------------------------------------------------------------------------

sealed class PdfObject {
  const PdfObject();
}

class PdfNull extends PdfObject {
  const PdfNull();
}

class PdfBool extends PdfObject {
  const PdfBool(this.value);
  final bool value;
}

class PdfNumber extends PdfObject {
  const PdfNumber(this.raw);
  final String raw;
  num get value => num.parse(raw);
  int get intValue => value.toInt();
}

class PdfName extends PdfObject {
  /// Tên ở dạng nguồn (đã bỏ dấu `/`, giữ nguyên chuỗi thoát `#xx`).
  const PdfName(this.raw);
  final String raw;
}

class PdfString extends PdfObject {
  /// [source] là token gốc, gồm cả dấu `( )` hoặc `< >`, để ghi lại y hệt.
  const PdfString(this.source, this.bytes);
  final Uint8List source;
  final Uint8List bytes;
}

class PdfArray extends PdfObject {
  PdfArray(this.items);
  final List<PdfObject> items;
}

class PdfDict extends PdfObject {
  PdfDict([Map<String, PdfObject>? entries]) : entries = entries ?? {};
  final Map<String, PdfObject> entries;

  PdfObject? operator [](String key) => entries[key];
  void operator []=(String key, PdfObject value) => entries[key] = value;
}

class PdfRef extends PdfObject {
  const PdfRef(this.num, this.gen);
  final int num;
  final int gen;

  @override
  bool operator ==(Object other) =>
      other is PdfRef && other.num == num && other.gen == gen;

  @override
  int get hashCode => Object.hash(num, gen);
}

class PdfStream extends PdfObject {
  PdfStream(this.dict, this.data);
  final PdfDict dict;

  /// Dữ liệu thô (chưa giải nén).
  final Uint8List data;
}

/// Văn bản ghi nguyên văn (placeholder cho ByteRange / Contents khi ký).
class PdfRaw extends PdfObject {
  const PdfRaw(this.text);
  final String text;
}

class PdfFormatException implements Exception {
  PdfFormatException(this.message);
  final String message;
  @override
  String toString() => 'PdfFormatException: $message';
}

// ---------------------------------------------------------------------------
// Ghi đối tượng
// ---------------------------------------------------------------------------

class PdfWriter {
  static void write(PdfObject o, BytesBuilder out) {
    switch (o) {
      case PdfNull():
        out.add(latin1.encode('null'));
      case PdfRaw(:final text):
        out.add(latin1.encode(text));
      case PdfBool(:final value):
        out.add(latin1.encode(value ? 'true' : 'false'));
      case PdfNumber(:final raw):
        out.add(latin1.encode(raw));
      case PdfName(:final raw):
        out.add(latin1.encode('/$raw'));
      case PdfString(:final source):
        out.add(source);
      case PdfRef(:final num, :final gen):
        out.add(latin1.encode('$num $gen R'));
      case PdfArray(:final items):
        out.addByte(0x5B);
        for (var i = 0; i < items.length; i++) {
          if (i > 0) out.addByte(0x20);
          write(items[i], out);
        }
        out.addByte(0x5D);
      case PdfDict(:final entries):
        out.add(latin1.encode('<<'));
        entries.forEach((k, v) {
          out.add(latin1.encode('/$k '));
          write(v, out);
          out.addByte(0x20);
        });
        out.add(latin1.encode('>>'));
      case PdfStream(:final dict, :final data):
        dict['Length'] = PdfNumber('${data.length}');
        write(dict, out);
        out.add(latin1.encode('\nstream\n'));
        out.add(data);
        out.add(latin1.encode('\nendstream'));
    }
  }

  static Uint8List toBytes(PdfObject o) {
    final b = BytesBuilder(copy: false);
    write(o, b);
    return b.toBytes();
  }

  /// Chuỗi văn bản PDF: UTF-16BE có BOM, dạng hex — an toàn cho mọi ký tự.
  static PdfString text(String s) {
    final units = <int>[0xFE, 0xFF];
    for (final cu in s.codeUnits) {
      units
        ..add(cu >> 8)
        ..add(cu & 0xFF);
    }
    final hex = units.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    return PdfString(
        Uint8List.fromList(latin1.encode('<$hex>')), Uint8List.fromList(units));
  }

  static PdfString ascii(String s) {
    final escaped = s
        .replaceAll(r'\', r'\\')
        .replaceAll('(', r'\(')
        .replaceAll(')', r'\)');
    return PdfString(Uint8List.fromList(latin1.encode('($escaped)')),
        Uint8List.fromList(latin1.encode(s)));
  }
}

// ---------------------------------------------------------------------------
// Phân tích cú pháp
// ---------------------------------------------------------------------------

class _Lexer {
  _Lexer(this.data, this.pos);
  final Uint8List data;
  int pos;

  static bool isWhite(int c) =>
      c == 0 || c == 9 || c == 10 || c == 12 || c == 13 || c == 32;
  static bool isDelim(int c) =>
      c == 0x28 || c == 0x29 || c == 0x3C || c == 0x3E || c == 0x5B ||
      c == 0x5D || c == 0x7B || c == 0x7D || c == 0x2F || c == 0x25;

  void skipWs() {
    while (pos < data.length) {
      final c = data[pos];
      if (isWhite(c)) {
        pos++;
      } else if (c == 0x25) {
        while (pos < data.length && data[pos] != 10 && data[pos] != 13) {
          pos++;
        }
      } else {
        break;
      }
    }
  }

  String? peekKeyword() {
    skipWs();
    final start = pos;
    var p = pos;
    while (p < data.length && !isWhite(data[p]) && !isDelim(data[p])) {
      p++;
    }
    if (p == start) return null;
    return latin1.decode(data.sublist(start, p));
  }

  String readKeyword() {
    final k = peekKeyword();
    if (k == null) throw PdfFormatException('Mong đợi từ khoá tại $pos');
    pos += k.length;
    return k;
  }

  bool _isNumberToken(String t) => RegExp(r'^[+-]?(\d+\.?\d*|\.\d+)$').hasMatch(t);

  PdfObject parse() {
    skipWs();
    if (pos >= data.length) throw PdfFormatException('Hết dữ liệu');
    final c = data[pos];
    if (c == 0x2F) {
      pos++;
      final start = pos;
      while (pos < data.length && !isWhite(data[pos]) && !isDelim(data[pos])) {
        pos++;
      }
      return PdfName(latin1.decode(data.sublist(start, pos)));
    }
    if (c == 0x3C && pos + 1 < data.length && data[pos + 1] == 0x3C) {
      pos += 2;
      final dict = PdfDict();
      while (true) {
        skipWs();
        if (data[pos] == 0x3E && data[pos + 1] == 0x3E) {
          pos += 2;
          return dict;
        }
        final key = parse();
        if (key is! PdfName) throw PdfFormatException('Khoá dict không phải tên tại $pos');
        dict[key.raw] = parse();
      }
    }
    if (c == 0x3C) {
      final start = pos;
      pos++;
      final hex = StringBuffer();
      while (data[pos] != 0x3E) {
        if (!isWhite(data[pos])) hex.writeCharCode(data[pos]);
        pos++;
      }
      pos++;
      var h = hex.toString();
      if (h.length.isOdd) h += '0';
      final bytes = Uint8List(h.length ~/ 2);
      for (var i = 0; i < bytes.length; i++) {
        bytes[i] = int.parse(h.substring(i * 2, i * 2 + 2), radix: 16);
      }
      return PdfString(data.sublist(start, pos), bytes);
    }
    if (c == 0x28) {
      final start = pos;
      pos++;
      var depth = 1;
      final out = <int>[];
      while (depth > 0) {
        final b = data[pos++];
        if (b == 0x5C) {
          final n = data[pos++];
          switch (n) {
            case 0x6E: out.add(10);
            case 0x72: out.add(13);
            case 0x74: out.add(9);
            case 0x62: out.add(8);
            case 0x66: out.add(12);
            case 0x0D:
              if (pos < data.length && data[pos] == 0x0A) pos++;
            case 0x0A:
              break;
            default:
              if (n >= 0x30 && n <= 0x37) {
                var v = n - 0x30;
                for (var k = 0; k < 2 && data[pos] >= 0x30 && data[pos] <= 0x37; k++) {
                  v = v * 8 + data[pos++] - 0x30;
                }
                out.add(v & 0xFF);
              } else {
                out.add(n);
              }
          }
        } else if (b == 0x28) {
          depth++;
          out.add(b);
        } else if (b == 0x29) {
          depth--;
          if (depth > 0) out.add(b);
        } else {
          out.add(b);
        }
      }
      return PdfString(data.sublist(start, pos), Uint8List.fromList(out));
    }
    if (c == 0x5B) {
      pos++;
      final items = <PdfObject>[];
      while (true) {
        skipWs();
        if (data[pos] == 0x5D) {
          pos++;
          return PdfArray(items);
        }
        items.add(parse());
      }
    }

    final token = readKeyword();
    if (token == 'true') return const PdfBool(true);
    if (token == 'false') return const PdfBool(false);
    if (token == 'null') return const PdfNull();
    if (_isNumberToken(token)) {
      // Có thể là tham chiếu "n g R".
      if (RegExp(r'^\d+$').hasMatch(token)) {
        final save = pos;
        final t2 = peekKeyword();
        if (t2 != null && RegExp(r'^\d+$').hasMatch(t2)) {
          pos += t2.length;
          final t3 = peekKeyword();
          if (t3 == 'R') {
            pos += 1;
            return PdfRef(int.parse(token), int.parse(t2));
          }
        }
        pos = save;
      }
      return PdfNumber(token);
    }
    throw PdfFormatException('Token không hợp lệ "$token" tại $pos');
  }
}

class _XrefEntry {
  _XrefEntry.offset(this.offset, this.gen) : stream = null, index = null;
  _XrefEntry.compressed(this.stream, this.index) : offset = null, gen = 0;
  final int? offset;
  final int gen;
  final int? stream;
  final int? index;
}

class PdfDocument {
  PdfDocument._(this.bytes);

  final Uint8List bytes;
  final Map<int, _XrefEntry> _xref = {};
  final Map<int, PdfObject> _cache = {};
  final Map<int, List<(int, int)>> _objStmIndex = {};

  /// Trailer của lần cập nhật mới nhất.
  late final PdfDict trailer;

  /// Vị trí bảng xref mới nhất (dùng cho /Prev).
  late final int startXref;

  /// Lần cập nhật mới nhất dùng xref stream (thay vì bảng cổ điển).
  late final bool usesXrefStream;

  /// Số đối tượng lớn nhất + 1.
  int get size => (trailer['Size'] as PdfNumber).intValue;

  static PdfDocument parse(Uint8List bytes) {
    final doc = PdfDocument._(bytes);
    doc._load();
    return doc;
  }

  void _load() {
    final tail = latin1.decode(
        bytes.sublist(bytes.length > 2048 ? bytes.length - 2048 : 0));
    final i = tail.lastIndexOf('startxref');
    if (i < 0) throw PdfFormatException('Không tìm thấy startxref');
    final m = RegExp(r'startxref\s+(\d+)').firstMatch(tail.substring(i));
    if (m == null) throw PdfFormatException('startxref không hợp lệ');
    startXref = int.parse(m.group(1)!);

    PdfDict? first;
    var offset = startXref;
    final seen = <int>{};
    var isFirst = true;
    while (seen.add(offset)) {
      final (dict, isStream) = _readXrefSection(offset);
      if (isFirst) {
        usesXrefStream = isStream;
        isFirst = false;
      }
      first ??= dict;
      final xrefStm = dict['XRefStm'];
      if (xrefStm is PdfNumber) _readXrefSection(xrefStm.intValue);
      final prev = dict['Prev'];
      if (prev is! PdfNumber) break;
      offset = prev.intValue;
    }
    trailer = first!;
    if (trailer['Encrypt'] != null) {
      throw PdfFormatException('PDF đã mã hoá — không hỗ trợ ký');
    }
  }

  (PdfDict, bool) _readXrefSection(int offset) {
    final lx = _Lexer(bytes, offset);
    if (lx.peekKeyword() == 'xref') {
      lx.readKeyword();
      while (true) {
        final k = lx.peekKeyword();
        if (k == 'trailer') {
          lx.readKeyword();
          return (lx.parse() as PdfDict, false);
        }
        final start = int.parse(lx.readKeyword());
        final count = int.parse(lx.readKeyword());
        for (var n = 0; n < count; n++) {
          final off = int.parse(lx.readKeyword());
          final gen = int.parse(lx.readKeyword());
          final type = lx.readKeyword();
          final num = start + n;
          if (type == 'n' && !_xref.containsKey(num)) {
            _xref[num] = _XrefEntry.offset(off, gen);
          } else if (type == 'f') {
            _xref.putIfAbsent(num, () => _XrefEntry.offset(null, gen));
          }
        }
      }
    }
    // Xref stream.
    final obj = _parseIndirectAt(offset);
    if (obj is! PdfStream) throw PdfFormatException('Xref tại $offset không hợp lệ');
    final d = obj.dict;
    final w = (d['W'] as PdfArray).items.map((e) => (e as PdfNumber).intValue).toList();
    final index = d['Index'] is PdfArray
        ? (d['Index'] as PdfArray).items.map((e) => (e as PdfNumber).intValue).toList()
        : [0, (d['Size'] as PdfNumber).intValue];
    final data = decodeStream(obj);
    final rowLen = w.reduce((a, b) => a + b);
    var p = 0;
    int field(int width, int def) {
      if (width == 0) return def;
      var v = 0;
      for (var k = 0; k < width; k++) {
        v = (v << 8) | data[p++];
      }
      return v;
    }

    for (var s = 0; s < index.length; s += 2) {
      for (var n = 0; n < index[s + 1]; n++) {
        if (p + rowLen > data.length) break;
        final type = field(w[0], 1);
        final f2 = field(w[1], 0);
        final f3 = field(w[2], 0);
        final num = index[s] + n;
        if (_xref.containsKey(num)) continue;
        if (type == 1) {
          _xref[num] = _XrefEntry.offset(f2, f3);
        } else if (type == 2) {
          _xref[num] = _XrefEntry.compressed(f2, f3);
        } else {
          _xref[num] = _XrefEntry.offset(null, f3);
        }
      }
    }
    return (d, true);
  }

  PdfObject _parseIndirectAt(int offset) {
    final lx = _Lexer(bytes, offset);
    lx.readKeyword(); // số đối tượng
    lx.readKeyword(); // thế hệ
    if (lx.readKeyword() != 'obj') {
      throw PdfFormatException('Thiếu "obj" tại $offset');
    }
    final o = lx.parse();
    if (o is PdfDict && lx.peekKeyword() == 'stream') {
      lx.readKeyword();
      if (bytes[lx.pos] == 13) lx.pos++;
      if (bytes[lx.pos] == 10) lx.pos++;
      final lenObj = resolve(o['Length']);
      var len = lenObj is PdfNumber ? lenObj.intValue : -1;
      if (len < 0 || lx.pos + len > bytes.length) {
        // Length hỏng: tìm endstream.
        final s = latin1.decode(bytes.sublist(lx.pos));
        len = s.indexOf('endstream');
        if (len < 0) throw PdfFormatException('Thiếu endstream');
      }
      return PdfStream(o, bytes.sublist(lx.pos, lx.pos + len));
    }
    return o;
  }

  /// Lấy đối tượng gián tiếp theo số.
  PdfObject getObject(int num) {
    final cached = _cache[num];
    if (cached != null) return cached;
    final e = _xref[num];
    PdfObject result;
    if (e == null || (e.offset == null && e.stream == null)) {
      result = const PdfNull();
    } else if (e.offset != null) {
      result = _parseIndirectAt(e.offset!);
    } else {
      result = _readFromObjectStream(e.stream!, e.index!);
    }
    _cache[num] = result;
    return result;
  }

  int generationOf(int num) => _xref[num]?.gen ?? 0;

  PdfObject _readFromObjectStream(int stmNum, int index) {
    final stm = getObject(stmNum);
    if (stm is! PdfStream) throw PdfFormatException('Object stream $stmNum hỏng');
    final data = decodeStream(stm);
    final pairs = _objStmIndex.putIfAbsent(stmNum, () {
      final n = (stm.dict['N'] as PdfNumber).intValue;
      final lx = _Lexer(data, 0);
      return [
        for (var i = 0; i < n; i++)
          (int.parse(lx.readKeyword()), int.parse(lx.readKeyword()))
      ];
    });
    final first = (stm.dict['First'] as PdfNumber).intValue;
    return _Lexer(data, first + pairs[index].$2).parse();
  }

  PdfObject? resolve(PdfObject? o) {
    var cur = o;
    for (var i = 0; i < 32 && cur is PdfRef; i++) {
      cur = getObject(cur.num);
    }
    return cur;
  }

  /// Giải nén dữ liệu stream (FlateDecode + predictor PNG).
  Uint8List decodeStream(PdfStream s) {
    final filter = resolve(s.dict['Filter']);
    final filters = filter == null
        ? <String>[]
        : filter is PdfName
            ? [filter.raw]
            : (filter as PdfArray).items.map((e) => (resolve(e) as PdfName).raw).toList();
    var data = s.data;
    for (final f in filters) {
      if (f != 'FlateDecode') {
        throw PdfFormatException('Bộ lọc stream không hỗ trợ: $f');
      }
      data = Uint8List.fromList(ZLibCodec().decode(data));
    }
    var parms = resolve(s.dict['DecodeParms']);
    if (parms is PdfArray) parms = parms.items.isEmpty ? null : resolve(parms.items.first);
    if (parms is PdfDict) {
      final predictor = (resolve(parms['Predictor']) as PdfNumber?)?.intValue ?? 1;
      if (predictor >= 10) {
        final columns = (resolve(parms['Columns']) as PdfNumber?)?.intValue ?? 1;
        final colors = (resolve(parms['Colors']) as PdfNumber?)?.intValue ?? 1;
        final bpc = (resolve(parms['BitsPerComponent']) as PdfNumber?)?.intValue ?? 8;
        data = _undoPng(data, columns, colors, bpc);
      } else if (predictor != 1) {
        throw PdfFormatException('Predictor không hỗ trợ: $predictor');
      }
    }
    return data;
  }

  static Uint8List _undoPng(Uint8List data, int columns, int colors, int bpc) {
    final bpp = ((colors * bpc) + 7) ~/ 8;
    final rowLen = (columns * colors * bpc + 7) ~/ 8;
    final rows = data.length ~/ (rowLen + 1);
    final out = Uint8List(rows * rowLen);
    var prev = Uint8List(rowLen);
    for (var r = 0; r < rows; r++) {
      final type = data[r * (rowLen + 1)];
      final row = Uint8List.sublistView(data, r * (rowLen + 1) + 1, (r + 1) * (rowLen + 1));
      final cur = Uint8List(rowLen);
      for (var i = 0; i < rowLen; i++) {
        final a = i >= bpp ? cur[i - bpp] : 0;
        final b = prev[i];
        final c = i >= bpp ? prev[i - bpp] : 0;
        int v;
        switch (type) {
          case 0: v = row[i];
          case 1: v = row[i] + a;
          case 2: v = row[i] + b;
          case 3: v = row[i] + ((a + b) >> 1);
          case 4:
            final p = a + b - c;
            final pa = (p - a).abs(), pb = (p - b).abs(), pc = (p - c).abs();
            v = row[i] + ((pa <= pb && pa <= pc) ? a : (pb <= pc ? b : c));
          default:
            throw PdfFormatException('Bộ lọc PNG không hợp lệ: $type');
        }
        cur[i] = v & 0xFF;
      }
      out.setRange(r * rowLen, (r + 1) * rowLen, cur);
      prev = cur;
    }
    return out;
  }

  PdfRef get catalogRef {
    final root = trailer['Root'];
    if (root is! PdfRef) throw PdfFormatException('Trailer thiếu /Root');
    return root;
  }

  /// Danh sách tham chiếu tới các trang, theo thứ tự.
  List<PdfRef> pageRefs() {
    final catalog = resolve(catalogRef) as PdfDict;
    final out = <PdfRef>[];
    final visited = <PdfRef>{};
    void walk(PdfRef ref) {
      if (!visited.add(ref)) return;
      final node = resolve(ref);
      if (node is! PdfDict) return;
      final type = resolve(node['Type']);
      final kids = resolve(node['Kids']);
      if ((type is PdfName && type.raw == 'Pages') || kids is PdfArray) {
        for (final k in (kids as PdfArray).items) {
          if (k is PdfRef) walk(k);
        }
      } else {
        out.add(ref);
      }
    }

    final pages = catalog['Pages'];
    if (pages is! PdfRef) throw PdfFormatException('Catalog thiếu /Pages');
    walk(pages);
    return out;
  }
}
