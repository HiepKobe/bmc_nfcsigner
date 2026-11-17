import 'dart:typed_data';

import 'package:nfcsigner/src/pdf/cms.dart';

/// Khoá RSA-2048 CHỈ DÙNG CHO TEST, cặp với certificate tự ký trong
/// pdf_signer_test.dart (CN=nfcsigner test). Không dùng cho mục đích khác.
final _n = BigInt.parse('D2AC0683958D36FCA37F134BC35737CE1E468C1C1897DC35F75E1262DB04E5E5CF7A6417FE4614394F124CB9A6B4E8F0211FCA23C4601FF3E2902C2242A0663AB4F1B2B071C12A1B459D4FE6536A5652BB5FE4DEC6CF4E68FAD13A23F771FEA47C32168FCCE7840AFE39D4EF49CDBE5BFF284D5C2221DC5D2095D0751A3E172ED1180D2E1813345D7756E49866600D01A564240EB7E6601906648938BE0988CFC6EB7A686DC6D0C9AB5B4A150150B666E72FB601536D7097ACD258326BD20CAE83FE8747C9E78439E4F8F6AE95D63EAFB5196AD8EB6143E3F37D45D5E68B94BA5F4BA4183FEBA541FDCBC07A92CE5F6491E9D89E35DF8B88326CF646AEB9CB91', radix: 16);
final _d = BigInt.parse('40cc1b86ce716c57c17bfcf5e123caecd16016892fc149c0a9909c2c1ebc7f6fb364ac33bb085801168284e9d74e2e956942cb5c3bf2eaf10b1f180c039d2d4462523309553bba154050b5fa1c6f0915123fd8f7f28361d5254c444b3ab92bbef0da411942c774d422c4abeb5bb27619fabdad29a8efec45129831d14adc8d295074dd299dfef2ca7f4d663070edf6ee6117fe829f9e5ccebd796308c598e9a403490115fa00b22a949fe9664d20bb09e199b9fc22ed9d3af3659a371050e4f83c9565e28d4464fe5b78d08696d322ee9b971a44206a5fc7e57a7b81516fd24da99a95c26ebc053e9d54680414f267740c2f19ca53edda166ef24af77a017a3f', radix: 16);

/// Ký PKCS#1 v1.5 trên [digestInfo] — mô phỏng PSO:CDS của thẻ / SIM-PKI.
Uint8List testRsaSign(Uint8List digestInfo) {
  final k = (_n.bitLength + 7) ~/ 8;
  final em = Uint8List(k)
    ..[0] = 0
    ..[1] = 1;
  final psEnd = k - digestInfo.length - 1;
  for (var i = 2; i < psEnd; i++) {
    em[i] = 0xFF;
  }
  em[psEnd] = 0;
  em.setRange(psEnd + 1, k, digestInfo);
  var m = BigInt.zero;
  for (final b in em) {
    m = (m << 8) | BigInt.from(b);
  }
  var s = m.modPow(_d, _n);
  final out = Uint8List(k);
  for (var i = k - 1; i >= 0; i--) {
    out[i] = (s & BigInt.from(0xFF)).toInt();
    s >>= 8;
  }
  return out;
}

// Giữ import cms.dart để test phát hiện nếu RsaVerifier đổi API.
const testRsaVerifier = RsaVerifier.verify;
