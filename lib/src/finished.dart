import 'dart:typed_data';

class Finished {
  Uint8List? VerifyData;
  dynamic Decode(Uint8List buf, int offset, int arrayLen)
  //(int, error)
  {
//	m.VerifyData = make([]byte, arrayLen)
    VerifyData = buf.sublist(offset, offset + arrayLen);
    offset += VerifyData!.length;
    return (offset, null);
  }
}
