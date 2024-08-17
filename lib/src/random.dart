import 'dart:typed_data';

import 'package:dtls2/src/utils.dart';

const RandomBytesLength = 28;

class DtlsRandom {
  int? GMTUnixTime;
  Uint8List? RandomBytes;
}

dynamic DecodeRandom(Uint8List buf, int offset, int arrayLen)
//(*Random, int, error)
{
  var result = DtlsRandom();
  result.GMTUnixTime = uint32(buf.sublist(offset, offset + 4));
  offset += 4;
  result.RandomBytes = buf.sublist(offset, offset + RandomBytesLength);
  offset += RandomBytesLength;

  return (result, offset, null);
}
