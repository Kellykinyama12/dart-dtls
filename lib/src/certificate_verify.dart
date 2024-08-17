import 'dart:typed_data';

import 'package:dtls2/src/algo_pair.dart';
import 'package:dtls2/src/utils.dart';

class CertificateVerify {
  AlgoPair algoPair = AlgoPair();
  Uint8List? Signature;
  dynamic Decode(Uint8List buf, int offset, int arrayLen)
  // (int, error)
  {
    algoPair = AlgoPair();
    var err;
    (offset, err) = algoPair.Decode(buf, offset, arrayLen);
    if (err != null) {
      return (offset, err);
    }
    int signatureLength = uint16(buf.sublist(offset, offset + 2));
    offset += 2;
    Signature = buf.sublist(offset, offset + signatureLength);
    offset += signatureLength;
    return (offset, null);
  }
}
