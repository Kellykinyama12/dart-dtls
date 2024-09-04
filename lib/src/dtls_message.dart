import 'dart:typed_data';

import 'package:dtls2/src/alert.dart';
import 'package:dtls2/src/certificate.dart';
import 'package:dtls2/src/certificate_request.dart';
import 'package:dtls2/src/certificate_verify.dart';
import 'package:dtls2/src/change_cipher_spec.dart';
import 'package:dtls2/src/client_hello.dart';
import 'package:dtls2/src/client_key_exchange.dart';
import 'package:dtls2/src/finished.dart';
import 'package:dtls2/src/handshake_context.dart';
import 'package:dtls2/src/handshake_header.dart';
import 'package:dtls2/src/record_header.dart';
import 'package:dtls2/src/server_hello.dart';
import 'package:dtls2/src/server_hello_done.dart';
import 'package:dtls2/src/server_key_exchange.dart';
import 'package:dtls2/src/utils.dart';

enum Errors {
  IncompleteDtlsMessage("data contains incomplete DTLS message"),
  UnknownDtlsContentType("data contains unkown DTLS content type"),
  UnknownDtlsHandshakeType("data contains unkown DTLS handshake type");

  const Errors(this.value);
  final String value;

  factory Errors.fromInt(String key) {
    return values.firstWhere((element) => element.value == key);
  }
}

class BaseDtlsMessage {
  // GetContentType() ContentType
  // Encode() []byte
  // Decode(buf []byte, offset int, arrayLen int) (int, error)
  // String() string

  RecordHeader recordHeader = RecordHeader();

  static dynamic DecodeDtlsMessage(
      HandshakeContext context, Uint8List buf, int offset, int arrayLen)
  //(*RecordHeader, *HandshakeHeader, BaseDtlsMessage, int, error)
  {
    if (arrayLen < 1) {
      // return nil, nil, nil, offset, errIncompleteDtlsMessage
      return (null, null, null, offset, Errors.IncompleteDtlsMessage);
    }
    RecordHeader header;
    var err;
    (header, offset, err) = DecodeRecordHeader(buf, offset, arrayLen);
    if (err != null) {
      return (null, null, null, offset, err);
    }

    print("Epoch: ${header.intEpoch}");
    print("Client Epoch: ${context.ClientEpoch}");
    if (header.intEpoch! < context.ClientEpoch) {
      // Ignore incoming message
      offset += header.intLength as int;
      return (null, null, null, offset, null);
    }

    context.ClientEpoch = header.intEpoch!;

    Uint8List? decryptedBytes; // []byte
    Uint8List? encryptedBytes; // []byte
    if (header.intEpoch! > 0) {
      // Data arrives encrypted, we should decrypt it before.
      if (context.IsCipherSuiteInitialized) {
        encryptedBytes = buf.sublist(offset, offset + header.intLength!);
        offset += header.intLength!;
        (decryptedBytes, err) = context.gcm.decrypt(header, encryptedBytes);
        if (err != null) {
          //return nil, nil, nil, offset, err
          return (null, null, null, offset, null);
        }
      }
    }
    var result;

    switch (header.enumContentType) {
      case ContentType.handshake:
        if (decryptedBytes == null) {
          var offsetBackup = offset;
          var handshakeHeader;
          var err;
          (handshakeHeader, offset, err) =
              DecodeHandshakeHeader(buf, offset, arrayLen);
          if (err != null) {
            return (null, null, null, offset, err);
          }
          if ((handshakeHeader.Length) != (handshakeHeader.FragmentLength)) {
            // Ignore fragmented packets
            print("Ignore fragmented packets: ${header.enumContentType}");
            return (
              null,
              null,
              null,
              offset + handshakeHeader.FragmentLength.ToUint32(),
              null
            );
          }

          (result, offset, err) =
              decodeHandshake(header, handshakeHeader, buf, offset, arrayLen);
          if (err != null) {
            return (null, null, null, offset, err);
          }
          //copyArray := make([]byte, offset-offsetBackup)
          var copyArray = buf.sublist(offsetBackup, offset);
          context.HandshakeMessagesReceived[handshakeHeader.handshakeType] =
              copyArray;

          return (header, handshakeHeader, result, offset, err);
        } else {
          var (handshakeHeader, decryptedOffset, err) =
              DecodeHandshakeHeader(decryptedBytes, 0, decryptedBytes.length);
          if (err != null) {
            return (null, null, null, offset, err);
          }

          (result, _, err) = decodeHandshake(
              header,
              handshakeHeader,
              decryptedBytes,
              decryptedOffset,
              decryptedBytes.length - decryptedOffset as int);

          context.HandshakeMessagesReceived[handshakeHeader.HandshakeType] =
              decryptedBytes.sublist(0);

          return (header, handshakeHeader, result, offset, err);
        }
      case ContentType.change_cipher_spec:
        var changeCipherSpec = ChangeCipherSpec();
        (offset, err) = changeCipherSpec.Decode(buf, offset, arrayLen);
        if (err != null) {
          return (null, null, null, offset, err);
        }
        return (header, null, changeCipherSpec, offset, null);
      case ContentType.alert:
        var alert = Alert();
        if (decryptedBytes == null) {
          (offset, err) = alert.Decode(buf, offset, arrayLen);
        } else {
          (_, err) = alert.Decode(decryptedBytes, 0, decryptedBytes.length);
        }
        if (err != null) {
          return (null, null, null, offset, err);
        }
        return (header, null, alert, offset, null);

      default:
        return (null, null, null, offset, Errors.UnknownDtlsContentType);
    }
  }

//   dynamic decodeHandshake(
//     HandshakeType handshakeType, Uint8List buf, int offset, int arrayLen) {
//   switch (handshakeType) {
//     case HandshakeType.client_hello:
//       //result = new(ClientHello)
//       //decodeClientHello(buf, offset, arrayLen);
//     case HandshakeType.server_hello:
//       //decodeServerHello(buf, offset, arrayLen);
//     case HandshakeType.certificate:
//       //decodeCertificate(buf, offset, arrayLen);
//     case HandshakeType.server_key_exchange:
//       //decodeServerKeyExchange(buf, offset, arrayLen);
//     case HandshakeType.certificate_request:
//       //decodeCertificateRequest(buf, offset, arrayLen);
//     case HandshakeType.server_hello_done:
//       //decodeServerHelloDone(buf, offset, arrayLen);
//     case HandshakeType.client_key_exchange:
//       //decodeClientKeyExchange(buf, offset, arrayLen);
//     case HandshakeType.certificate_verify:
//       //decodeCertificateVerify(buf, offset, arrayLen);
//     case HandshakeType.finished:
//       //decodeFinished(buf, offset, arrayLen);
//     default:
//     //return nil, offset, errUnknownDtlsHandshakeType
//   }
//   // offset, err := result.Decode(buf, offset, arrayLen)
//   // return result, offset, err

//   return offset;
// }
}

class BaseDtlsHandshakeMessage {
  // GetContentType() ContentType
  // GetHandshakeType() HandshakeType
  // Encode() []byte
  // Decode(buf []byte, offset int, arrayLen int) (int, error)
}

dynamic decodeHandshake(RecordHeader header, HandshakeHeader handshakeHeader,
    Uint8List buf, int offset, int arrayLen)
//(BaseDtlsMessage, int, error)
{
  var result; // = BaseDtlsMessage();
  switch (handshakeHeader.handshakeType) {
    case HandshakeType.ClientHello:
      {
        result = ClientHello();
      }
    case HandshakeType.ServerHello:
      {
        result = ServerHello();
      }
    case HandshakeType.Certificate:
      {
        result = Certificate();
      }
    case HandshakeType.ServerKeyExchange:
      {
        result = ServerKeyExchange();
      }
    case HandshakeType.CertificateRequest:
      {
        result = CertificateRequest();
      }
    case HandshakeType.ServerHelloDone:
      {
        result = ServerHelloDone();
      }
    case HandshakeType.ClientKeyExchange:
      {
        result = ClientKeyExchange();
      }
    case HandshakeType.CertificateVerify:
      {
        result = CertificateVerify();
      }
    case HandshakeType.Finished:
      {
        result = Finished();
      }
    default:
      return (null, offset, Errors.UnknownDtlsHandshakeType);
  }
  var err;
  (offset, err) = result.Decode(buf, offset, arrayLen);
  return (result, offset, err);
}
