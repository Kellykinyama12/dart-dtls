import 'dart:typed_data';

import 'package:dtls2/src/extensions.dart';
import 'package:dtls2/src/random.dart';
import 'package:dtls2/src/utils.dart';

class ClientHello {
  int? version;
  DtlsRandom? random;
  Uint8List? SessionID;
  Uint8List? Cookie;
  List<CipherSuiteID> cipherSuiteIDs = [];
  List<int> compressionMethodIDs = [];
  Map<ExtensionType, dynamic> extensions = {};

  dynamic Decode(Uint8List buf, int offset, int arrayLen)
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

    var cookieLength = buf[offset];
    offset++;
    //m.Cookie = make([]byte, cookieLength)
    Cookie = buf.sublist(offset, offset + cookieLength);
    offset += cookieLength;
    var localCipherSuiteIDs;
    (localCipherSuiteIDs, offset, err) =
        decodeCipherSuiteIDs(buf, offset, arrayLen);
    if (err != null) {
      return (offset, err);
    }
    cipherSuiteIDs = localCipherSuiteIDs;
    var localCompressionMethodIDs;
    (localCompressionMethodIDs, offset, err) =
        decodeCompressionMethodIDs(buf, offset, arrayLen);
    if (err != null) {
      return (offset, err);
    }
    compressionMethodIDs = localCompressionMethodIDs;

    var exts;
    (exts, offset, err) = DecodeExtensionMap(buf, offset, arrayLen);
    if (err != null) {
      return (offset, err);
    }
    extensions = exts;

    return (offset, null);
  }
}

dynamic decodeCipherSuiteIDs(Uint8List buf, int offset, int arrayLen)
//([]CipherSuiteID, int, error)
{
  var length = uint16(buf.sublist(offset, offset + 2));
  var count = length / 2;
  offset += 2;
  List<CipherSuiteID> result = [];
  for (int i = 0; i < count; i++) {
    result.add(uint16(buf.sublist(offset, offset + 2)));
    offset += 2;
  }
  return (result, offset, null);
}

dynamic decodeCompressionMethodIDs(Uint8List buf, int offset, int arrayLen)
//([]byte, int, error)
{
  var count = buf[offset];
  offset += 1;
  List<int> result = [];
  for (int i = 0; i < count; i++) {
    result.add(buf[offset]);
    offset += 1;
  }
  return (result, offset, null);
}
