import 'dart:typed_data';

import 'package:dtls2/src/utils.dart';

// enum HandshakeType {
//   hello_request(0),
//   client_hello(1),
//   server_hello(2),
//   certificate(11),
//   server_key_exchange(12),
//   certificate_request(13),
//   server_hello_done(14),
//   certificate_verify(15),
//   client_key_exchange(16),
//   finished(20),
//   unkown(255);

//   const HandshakeType(this.value);

//   final int value;

//   factory HandshakeType.fromInt(int key) {
//     return values.firstWhere((element) => element.value == key);
//   }
// }

enum HandshakeType {
  // https://github.com/eclipse/tinydtls/blob/706888256c3e03d9fcf1ec37bb1dd6499213be3c/dtls.h#L344
  HelloRequest(0),
  ClientHello(1),
  ServerHello(2),
  HelloVerifyRequest(3),
  Certificate(11),
  ServerKeyExchange(12),
  CertificateRequest(13),
  ServerHelloDone(14),
  CertificateVerify(15),
  ClientKeyExchange(16),
  Finished(20);

  const HandshakeType(this.value);

  final int value;

  factory HandshakeType.fromInt(int key) {
    return values.firstWhere((element) => element.value == key);
  }
}

class HandshakeHeader {
  HandshakeType? handshakeType;
  int? Length;
  int? MessageSequence;
  int? FragmentOffset;
  int? FragmentLength;
//   int DecodeHandshakeHeader(Uint8List buf, int offset, int arrayLen) {
//     var handshakeType = buf[offset];
//     //print("Handshake type: $HandshakeType");
//     offset++;

//     var length = buf.sublist(offset, offset + 3); //NewUint24FromBytes
//     //print("handshake Length: $length");
//     offset += 3;
//     var MessageSequence = buf.sublist(offset, offset + 2);
//     //print("Message sequence: $MessageSequence");
//     var buffer = MessageSequence.buffer;
//     var bytes = ByteData.view(buffer);
//     var intMessageSequence = bytes.getUint16(0);
//     //print("Message sequence: $intMessageSequence");
//     offset += 2;
// //  result.FragmentOffset = NewUint24FromBytes(buf[offset : offset+3])
// //  offset += 3

//     var FragmentOffset = buf.sublist(offset, offset + 2);
//     //print("Fragment offset: $FragmentOffset");
//     buffer = MessageSequence.buffer;
//     bytes = ByteData.view(buffer);
//     var intFragmentOffset = bytes.getUint16(0);
//     //print("Fragment offset: $intFragmentOffset");
//     offset += 3;
// // result.FragmentLength = NewUint24FromBytes(buf[offset : offset+3])
// // offset += 3
//     var FragmentLength = buf.sublist(offset, offset + 2);
//     //print("Fragment offset: $FragmentLength");
//     buffer = MessageSequence.buffer;
//     bytes = ByteData.view(buffer);
//     var intFragmentLength = bytes.getUint16(0);
//     //print("Fragment Length: $intFragmentLength");
//     offset += 3;

//     decodeHandshake(
//         HandshakeType.fromInt(handshakeType), buf, offset, arrayLen);

//     return offset;
//   }
}

dynamic DecodeHandshakeHeader(Uint8List buf, int offset, int arrayLen)
//(*HandshakeHeader, int, error)
{
  var result = HandshakeHeader();

  result.handshakeType = HandshakeType.fromInt(buf[offset]);
  offset++;
  result.Length = uint24FromBytes(buf.sublist(offset, offset + 3));
  offset += 3;
  result.MessageSequence = uint16(buf.sublist(offset, offset + 2));
  offset += 2;
  result.FragmentOffset = uint24FromBytes(buf.sublist(offset, offset + 3));
  offset += 3;
  result.FragmentLength = uint24FromBytes(buf.sublist(offset, offset + 3));
  offset += 3;
  return (result, offset, null);
}
