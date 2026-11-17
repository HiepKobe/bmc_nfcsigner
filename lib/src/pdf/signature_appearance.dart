import 'dart:typed_data';
import 'dart:ui' as ui;

import 'package:flutter/painting.dart';

import 'pdf_incremental_signer.dart';

/// Vẽ hình hiển thị của chữ ký (ảnh chữ ký bên trái, thông tin bên phải)
/// thành ảnh raster để nhúng vào PDF.
///
/// Vẽ bằng engine của Flutter nên dùng được font hệ thống — tiếng Việt có dấu
/// hiển thị đúng mà không phải nhúng font vào PDF.
class SignatureAppearanceRenderer {
  const SignatureAppearanceRenderer._();

  static Future<PdfAppearanceImage> render({
    required double width,
    required double height,
    required List<String> lines,
    Uint8List? signatureImage,
    double imageWidth = 50,
    double imageHeight = 50,
    double scale = 3,
  }) async {
    if (width <= 0 || height <= 0) {
      throw ArgumentError('Kích thước khung chữ ký phải dương');
    }
    final pw = (width * scale).round();
    final ph = (height * scale).round();

    final recorder = ui.PictureRecorder();
    final canvas = Canvas(recorder)..scale(scale);
    const color = Color(0xFF1A3D8F);

    canvas.drawRect(
      Rect.fromLTWH(0.5, 0.5, width - 1, height - 1),
      Paint()
        ..style = PaintingStyle.stroke
        ..strokeWidth = 0.8
        ..color = color,
    );

    var textLeft = 4.0;
    if (signatureImage != null && signatureImage.isNotEmpty) {
      final codec = await ui.instantiateImageCodec(signatureImage);
      final frame = await codec.getNextFrame();
      final img = frame.image;
      // Giữ tỉ lệ ảnh, vừa trong ô imageWidth x imageHeight và trong khung.
      final boxW = imageWidth.clamp(1.0, width / 2);
      final boxH = imageHeight.clamp(1.0, height - 4);
      final ratio = (boxW / img.width) < (boxH / img.height)
          ? boxW / img.width
          : boxH / img.height;
      final dw = img.width * ratio;
      final dh = img.height * ratio;
      canvas.drawImageRect(
        img,
        Rect.fromLTWH(0, 0, img.width.toDouble(), img.height.toDouble()),
        Rect.fromLTWH(3 + (boxW - dw) / 2, (height - dh) / 2, dw, dh),
        Paint()..filterQuality = FilterQuality.high,
      );
      img.dispose();
      textLeft = boxW + 8;
    }

    final textWidth = width - textLeft - 3;
    if (lines.isNotEmpty && textWidth > 10) {
      // Thu nhỏ chữ cho tới khi vừa khung.
      for (var fontSize = 9.0; fontSize >= 4; fontSize -= 0.5) {
        final painter = TextPainter(
          text: TextSpan(
            children: [
              for (var i = 0; i < lines.length; i++)
                TextSpan(
                  text: i == lines.length - 1 ? lines[i] : '${lines[i]}\n',
                  style: TextStyle(
                    fontSize: fontSize,
                    height: 1.25,
                    color: color,
                    fontWeight: i == 0 ? FontWeight.bold : FontWeight.normal,
                  ),
                ),
            ],
          ),
          textDirection: TextDirection.ltr,
        )..layout(maxWidth: textWidth);
        if (painter.height <= height - 4 || fontSize <= 4) {
          painter.paint(
              canvas, Offset(textLeft, (height - painter.height) / 2));
          painter.dispose();
          break;
        }
        painter.dispose();
      }
    }

    final picture = recorder.endRecording();
    final image = await picture.toImage(pw, ph);
    picture.dispose();
    final data = await image.toByteData(format: ui.ImageByteFormat.rawStraightRgba);
    image.dispose();
    if (data == null) throw StateError('Không vẽ được hình chữ ký');

    final rgba = data.buffer.asUint8List(data.offsetInBytes, data.lengthInBytes);
    final rgb = Uint8List(pw * ph * 3);
    final alpha = Uint8List(pw * ph);
    for (var i = 0, j = 0; i < pw * ph; i++, j += 4) {
      rgb[i * 3] = rgba[j];
      rgb[i * 3 + 1] = rgba[j + 1];
      rgb[i * 3 + 2] = rgba[j + 2];
      alpha[i] = rgba[j + 3];
    }
    return PdfAppearanceImage(width: pw, height: ph, rgb: rgb, alpha: alpha);
  }
}
