import 'dart:typed_data';

import 'package:dtls2/src/extensions.dart';
import 'package:dtls2/src/random.dart';
import 'package:dtls2/src/utils.dart';

class ServerHello {
  int? version;
  DtlsRandom? random;
  Uint8List? SessionID;
  int? cipherSuiteID;
  int? compressionMethodID;
  Map<ExtensionType, dynamic> extensions = {};

  dynamic decode(Uint8List buf, int offset, int arrayLen)
  //(int, error)
  {
    // https://github.com/pion/dtls/blob/680c851ed9efc926757f7df6858c82ac63f03a5d/pkg/protocol/handshake/message_client_hello.go#L66
    version = uint16(buf.sublist(offset, offset + 2));
    offset += 2;

    var decodedRandom;
    var err;
    (decodedRandom, offset, err) = DecodeRandom(buf, offset, arrayLen);
    if (err != null) {
      return (offset, err);
    }
    random = decodedRandom;

    var sessionIDLength = buf[offset];
    offset++;
    //m.SessionID = make([]byte, sessionIDLength)
    SessionID = buf.sublist(offset, offset + sessionIDLength);
    offset += sessionIDLength;

    cipherSuiteID = uint16(buf.sublist(offset, offset + 2));
    offset += 2;

    compressionMethodID = buf[offset];
    offset++;
    var extensionsMap;
    (extensionsMap, offset, err) = DecodeExtensionMap(buf, offset, arrayLen);
    if (err != null) {
      return (offset, err);
    }
    extensions = extensionsMap;
    return (offset, null);
  }
}
