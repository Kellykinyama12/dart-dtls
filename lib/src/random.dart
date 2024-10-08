import 'dart:math';
import 'dart:typed_data';

import 'package:dtls2/src/utils.dart';

const RandomBytesLength = 28;

Uint8List generateRandomBytes(int length) {
  final random = Random.secure();
  final bytes = Uint8List(length);
  for (int i = 0; i < length; i++) {
    bytes[i] = random.nextInt(256);
  }
  return bytes;
}

class DtlsRandom {
  int? GMTUnixTime;
  Uint8List RandomBytes = generateRandomBytes(RandomBytesLength);

  Uint8List Encode()
  //[]byte
  {
    List<int> result = [];

    int time = DateTime.now().microsecondsSinceEpoch;

    //binary.BigEndian.PutUint32(result[0:4], uint32(r.GMTUnixTime.Unix()))
    result.addAll(uint32toUint8List(time));
    result.addAll(RandomBytes);
    return Uint8List.fromList(result);
  }
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
