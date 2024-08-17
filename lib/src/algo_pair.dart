import 'dart:typed_data';

import 'package:dtls2/src/utils.dart';

class AlgoPair {
  HashAlgorithm? hashAlgorithm;
  SignatureAlgorithm? signatureAlgorithm;

  dynamic Decode(Uint8List buf, int offset, int arrayLen)
  // (int, error)
  {
    hashAlgorithm = buf[offset];
    offset += 1;
    signatureAlgorithm = buf[offset];
    offset += 1;
    return (offset, null);
  }
}
