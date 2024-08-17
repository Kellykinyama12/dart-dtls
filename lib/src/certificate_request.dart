import 'dart:typed_data';

import 'package:dtls2/src/algo_pair.dart';
import 'package:dtls2/src/utils.dart';

class CertificateRequest {
  List<int> CertificateTypes = [];
  List<AlgoPair> algoPairs = [];

  dynamic Decode(Uint8List buf, int offset, int arrayLen)
  //(int, error)
  {
    var certificateTypeCount = buf[offset];
    offset++;
    //m.CertificateTypes = make([]CertificateType, int(certificateTypeCount))
    for (int i = 0; i < certificateTypeCount; i++) {
      CertificateTypes.add(buf[offset + i]);
    }
    offset += certificateTypeCount;
    var algoPairLength = uint16(buf.sublist(offset, offset + 2));
    offset += 2;
    var algoPairCount = algoPairLength / 2;
    //m.AlgoPairs = make([]AlgoPair, algoPairCount)
    for (int i = 0; i < algoPairCount; i++) {
      algoPairs.add(AlgoPair());
      var (lastOffset, err) = algoPairs[i].Decode(buf, offset, arrayLen);
      if (err != null) {
        return (offset, err);
      }
      offset = lastOffset;
    }
    offset += 2; // Distinguished Names Length

    return (offset, null);
  }
}
