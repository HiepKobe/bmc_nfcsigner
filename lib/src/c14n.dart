import 'package:xml/xml.dart';

/// Canonical XML (C14N) cho XML-DSig, chạy trên cây của `package:xml`.
///
/// Hỗ trợ:
/// * Canonical XML 1.0 (inclusive), có / không có comment
///   (`http://www.w3.org/TR/2001/REC-xml-c14n-20010315[#WithComments]`).
/// * Exclusive XML Canonicalization 1.0, có / không có comment
///   (`http://www.w3.org/2001/10/xml-exc-c14n#[WithComments]`), không hỗ trợ
///   `InclusiveNamespaces PrefixList`.
///
/// Không hỗ trợ: DTD (giá trị mặc định của thuộc tính, entity tự định nghĩa),
/// và chuẩn hoá giá trị thuộc tính theo kiểu khai báo trong DTD.
class C14n {
  const C14n._();

  static const inclusive = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
  static const inclusiveWithComments =
      'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';
  static const exclusive = 'http://www.w3.org/2001/10/xml-exc-c14n#';
  static const exclusiveWithComments =
      'http://www.w3.org/2001/10/xml-exc-c14n#WithComments';

  static const _xmlNs = 'http://www.w3.org/XML/1998/namespace';

  static bool isSupported(String algorithm) =>
      algorithm == inclusive ||
      algorithm == inclusiveWithComments ||
      algorithm == exclusive ||
      algorithm == exclusiveWithComments;

  /// Chuẩn hoá [node] (một [XmlDocument] hoặc một [XmlElement] nằm trong cây)
  /// theo [algorithm].
  ///
  /// [withComments] ghi đè việc giữ comment — tham chiếu cùng tài liệu
  /// (`URI=""`, `URI="#id"`) luôn bỏ comment, bất kể thuật toán.
  ///
  /// [exclude] là phần tử bị loại khỏi tập nút (dùng cho transform
  /// enveloped-signature).
  static String canonicalize(
    XmlNode node, {
    required String algorithm,
    bool? withComments,
    XmlElement? exclude,
  }) {
    if (!isSupported(algorithm)) {
      throw ArgumentError('Thuật toán chuẩn hoá không được hỗ trợ: $algorithm');
    }
    final comments = withComments ?? algorithm.endsWith('#WithComments');
    final exc = algorithm.startsWith(exclusive);
    final w = _Writer(exclusive: exc, comments: comments, exclude: exclude);

    if (node is XmlDocument) {
      w.writeDocument(node);
    } else if (node is XmlElement) {
      w.writeApex(node);
    } else {
      throw ArgumentError('Chỉ chuẩn hoá được tài liệu hoặc phần tử');
    }
    return w.out.toString();
  }

  /// Khai báo namespace trong phạm vi của [element] (gồm cả kế thừa từ tổ
  /// tiên). Khoá là prefix (`''` cho namespace mặc định).
  static Map<String, String> inScopeNamespaces(XmlElement element) {
    final chain = <XmlElement>[];
    XmlNode? n = element;
    while (n is XmlElement) {
      chain.add(n);
      n = n.parent;
    }
    final ns = <String, String>{};
    for (final e in chain.reversed) {
      ns.addAll(_declarations(e));
    }
    return ns;
  }

  static Map<String, String> _declarations(XmlElement e) {
    final out = <String, String>{};
    for (final a in e.attributes) {
      if (a.name.prefix == null && a.name.local == 'xmlns') {
        out[''] = a.value;
      } else if (a.name.prefix == 'xmlns') {
        out[a.name.local] = a.value;
      }
    }
    return out;
  }

  static bool _isNsDecl(XmlAttribute a) =>
      (a.name.prefix == null && a.name.local == 'xmlns') ||
      a.name.prefix == 'xmlns';
}

class _Writer {
  _Writer({required this.exclusive, required this.comments, this.exclude});

  final bool exclusive;
  final bool comments;
  final XmlElement? exclude;
  final out = StringBuffer();

  void writeDocument(XmlDocument doc) {
    final root = doc.rootElement;
    var beforeRoot = true;
    for (final child in doc.children) {
      if (identical(child, root)) {
        _element(root, const {}, C14n.inScopeNamespaces(root), apex: true);
        beforeRoot = false;
      } else if (child is XmlProcessing || (child is XmlComment && comments)) {
        // Nút ngoài phần tử gốc: xuống dòng ngăn cách theo vị trí.
        if (!beforeRoot) out.write('\n');
        _leaf(child);
        if (beforeRoot) out.write('\n');
      }
      // XmlDeclaration, XmlDoctype, khoảng trắng ngoài gốc: bỏ.
    }
  }

  void writeApex(XmlElement e) {
    _element(e, const {}, C14n.inScopeNamespaces(e), apex: true);
  }

  void _leaf(XmlNode n) {
    if (n is XmlProcessing) {
      out.write('<?${n.target}');
      if (n.value.isNotEmpty) out.write(' ${n.value}');
      out.write('?>');
    } else if (n is XmlComment) {
      out.write('<!--${n.value}-->');
    }
  }

  /// [rendered]: namespace đã được xuất ở tổ tiên gần nhất trong đầu ra.
  /// [inScope]: namespace trong phạm vi của [e] trong tài liệu.
  void _element(
    XmlElement e,
    Map<String, String> rendered,
    Map<String, String> inScope, {
    bool apex = false,
  }) {
    if (exclude != null && identical(e, exclude)) return;

    final nsToRender = <String, String>{};
    if (exclusive) {
      final used = <String>{e.name.prefix ?? ''};
      for (final a in e.attributes) {
        if (C14n._isNsDecl(a)) continue;
        final p = a.name.prefix;
        if (p != null && p != 'xml') used.add(p);
      }
      for (final p in used) {
        final uri = inScope[p] ?? '';
        if (p.isEmpty && uri.isEmpty) {
          if ((rendered[''] ?? '').isNotEmpty) nsToRender[''] = '';
        } else if (rendered[p] != uri) {
          nsToRender[p] = uri;
        }
      }
    } else {
      inScope.forEach((p, uri) {
        if (p == 'xml') return;
        if (p.isEmpty && uri.isEmpty) {
          if ((rendered[''] ?? '').isNotEmpty) nsToRender[''] = '';
        } else if (rendered[p] != uri) {
          nsToRender[p] = uri;
        }
      });
    }

    // Thuộc tính thường (không phải khai báo namespace).
    final attrs = <_Attr>[];
    for (final a in e.attributes) {
      if (C14n._isNsDecl(a)) continue;
      final p = a.name.prefix;
      final uri = p == null
          ? ''
          : (p == 'xml' ? C14n._xmlNs : (inScope[p] ?? ''));
      attrs.add(_Attr(a.name.qualified, a.name.local, uri, a.value));
    }
    // Inclusive C14N trên tập con: phần tử đỉnh kế thừa xml:* của tổ tiên.
    if (apex && !exclusive) {
      final present = attrs
          .where((a) => a.uri == C14n._xmlNs)
          .map((a) => a.local)
          .toSet();
      XmlNode? p = e.parent;
      while (p is XmlElement) {
        for (final a in p.attributes) {
          if (a.name.prefix == 'xml' && present.add(a.name.local)) {
            attrs.add(_Attr(a.name.qualified, a.name.local, C14n._xmlNs, a.value));
          }
        }
        p = p.parent;
      }
    }
    attrs.sort((x, y) {
      final c = x.uri.compareTo(y.uri);
      return c != 0 ? c : x.local.compareTo(y.local);
    });

    final qname = e.name.qualified;
    out.write('<$qname');
    final prefixes = nsToRender.keys.toList()..sort();
    for (final p in prefixes) {
      out.write(p.isEmpty ? ' xmlns="' : ' xmlns:$p="');
      out.write(_escapeAttr(nsToRender[p]!));
      out.write('"');
    }
    for (final a in attrs) {
      out.write(' ${a.qname}="${_escapeAttr(a.value)}"');
    }
    out.write('>');

    final childRendered = nsToRender.isEmpty
        ? rendered
        : (Map<String, String>.of(rendered)..addAll(nsToRender));

    for (final child in e.children) {
      if (child is XmlElement) {
        final childScope = C14n._declarations(child);
        final scope = childScope.isEmpty
            ? inScope
            : (Map<String, String>.of(inScope)..addAll(childScope));
        _element(child, childRendered, scope);
      } else if (child is XmlCDATA) {
        out.write(_escapeText(child.value));
      } else if (child is XmlText) {
        out.write(_escapeText(child.value));
      } else if (child is XmlProcessing) {
        _leaf(child);
      } else if (child is XmlComment && comments) {
        _leaf(child);
      }
    }
    out.write('</$qname>');
  }

  static String _escapeText(String s) => s
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('\r', '&#xD;');

  static String _escapeAttr(String s) => s
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('"', '&quot;')
      .replaceAll('\t', '&#x9;')
      .replaceAll('\n', '&#xA;')
      .replaceAll('\r', '&#xD;');
}

class _Attr {
  _Attr(this.qname, this.local, this.uri, this.value);
  final String qname;
  final String local;
  final String uri;
  final String value;
}
