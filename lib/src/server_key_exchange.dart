import 'dart:typed_data';

import 'package:dtls2/src/algo_pair.dart';
import 'package:dtls2/src/utils.dart';

class ServerKeyExchange {
  int? ellipticCurveType;
  int? namedCurve;
  Uint8List? publicKey;
  AlgoPair? algoPair;
  Uint8List? signature;

  dynamic Decode(Uint8List buf, int offset, int arrayLen)
  //(int, error)
  {
    ellipticCurveType = (buf[offset]) as CurveType;
    offset++;
    namedCurve = uint16(buf.sublist(offset, offset + 2));
    offset += 2;
    var publicKeyLength = buf[offset];
    offset++;
    //m.PublicKey = make([]byte, publicKeyLength)
    publicKey = buf.sublist(offset, offset + publicKeyLength);
    algoPair = AlgoPair();
    var err;
    (offset, err) = algoPair!.Decode(buf, offset, arrayLen);
    if (err != null) {
      return (offset, err);
    }
    var signatureLength = uint16(buf.sublist(offset, offset + 2));
    offset += 2;
    //m.ignature = make([]byte, signatureLength)
    signature = buf.sublist(offset, offset + signatureLength);
    offset += signatureLength;
    return (offset, null);
  }
}
