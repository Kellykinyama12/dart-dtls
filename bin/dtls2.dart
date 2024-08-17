import 'dart:io';
import 'dart:typed_data';

import 'package:dtls2/src/dtls_message.dart';
import 'package:dtls2/src/handshake_context.dart';
import 'package:dtls2/src/handshake_manager.dart';
import 'package:dtls2/src/init.dart';

// typedef CurveType = int;
// typedef Curve = int;
// typedef HashAlgorithm = int;
// typedef SignatureAlgorithm = int;
// typedef CertificateType = int;
// typedef PointFormat = int;

// const SequenceNumberSize = 6;

// enum ExtensionType {
//   ServerName(0),
//   SupportedEllipticCurves(10),
//   SupportedPointFormats(11),
//   SupportedSignatureAlgorithms(13),
//   UseSRTP(14),
//   ALPN(16),
//   UseExtendedMasterSecret(23),
//   RenegotiationInfo(65281),

//   ExtensionTypeUnknown(65535); //Not a valid value

//   const ExtensionType(this.value);

//   final int value;

//   factory ExtensionType.fromInt(int key) {
//     return values.firstWhere((element) => element.value == key);
//   }
// }

// enum ContentType {
//   change_cipher_spec(20),
//   alert(21),
//   handshake(22),
//   application_data(23),
//   unknown(255);

//   const ContentType(this.value);

//   final int value;

//   factory ContentType.fromInt(int key) {
//     return values.firstWhere((element) => element.value == key);
//   }
// }

// int uint24ToUint32(Uint8List b) {
//   // https://stackoverflow.com/questions/45000982/convert-3-bytes-to-int-in-go
//   return (b[2]) | (b[1]) << 8 | (b[0]) << 16;
// }

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

// class DTLSPlaintext {
//   ContentType type;
//   Uint8List version;
//   int? epoch; // New field
//   Uint8List? sequence_number; // New field
//   int? length;
//   Uint8List? fragment; //[DTLSPlaintext.length];

//   DTLSPlaintext(this.type, this.version);

//   int decodeRecordHeader(
//       Client client, Uint8List buf, int offset, int arrayLen) {
//     var contentType = buf[offset];
//     print("Content type: $contentType");
//     offset++;

//     var version = buf.sublist(offset, offset + 2);
//     print("Version(Uint8List): $version");
//     var buffer = version.buffer;
//     var bytes = ByteData.view(buffer);
//     var intVersion = bytes.getUint16(0);
//     print("Version : $intVersion");
//     offset += 2;

//     var epoch = buf.sublist(offset, offset + 2);
//     print("Epoch : $epoch");
//     buffer = epoch.buffer;
//     bytes = ByteData.view(buffer);
//     var intEpoch = bytes.getUint16(0);
//     print("intEpoch : $intEpoch");
//     offset += 2;

//     var sequenceNumber = buf.sublist(offset, offset + SequenceNumberSize);
//     print("Sequence number: $sequenceNumber");
//     offset += SequenceNumberSize;

//     var length = buf.sublist(offset, offset + 2);
//     print("Length : $length");
//     buffer = length.buffer;
//     bytes = ByteData.view(buffer);
//     var intLength = bytes.getUint16(0);
//     print("intLength : $intLength");
//     offset += 2;

//     ContentType enumContentType = ContentType.fromInt(contentType);

//     switch (enumContentType) {
//       case ContentType.handshake:
//         {
//           int offsetBackup = offset;
//           offset = DecodeHandshakeHeader(buf, offset, arrayLen);
//            decodeHandshake(buf, offset, arrayLen);
//         }
//       default:
//         {
//           print("Unknown content type: $enumContentType");
//         }
//     }

//     return offset;
//   }
// }

// class RecordHeader {
//   //https://github.com/eclipse/tinydtls/blob/706888256c3e03d9fcf1ec37bb1dd6499213be3c/dtls.h#L320
//   int contentType;
//   Uint8List DtlsVersion = Uint8List(2);
//   int Epoch; //          uint16
//   Uint8List SequenceNumber =
//       Uint8List(SequenceNumberSize); // [SequenceNumberSize]byte
//   Uint8List Length = Uint8List(2); //         uint16
//   RecordHeader(this.contentType, this.DtlsVersion, this.Epoch,
//       this.SequenceNumber, this.Length);
// }

// class ClientHello {
//   Uint8List DtlsVersion = Uint8List(2);

//   Uint8List gmtUnixtime = Uint8List(4);
//   Uint8List random_bytes = Uint8List(28);
//   Uint8List? Cookie; //  =Uint8List(length);//             []byte
//   Uint8List? SessionID; //            []byte
//   Uint8List? CipherSuiteIDs; //       []CipherSuiteID
//   Uint8List? CompressionMethodIDs; // []byte
//   Uint8List? Extensions; //          map[ExtensionType]Extension
// }

// class HelloVerifyRequest {
//   Uint8List Version;
//   Uint8List Cookie; // []byte
//   HelloVerifyRequest(this.Version, this.Cookie);
// }

// var ProtocolVersion = Uint8List.fromList([0xFE, 0xFF]);
// var cookie = Uint8List.fromList([
//   0x25,
//   0xfb,
//   0xee,
//   0xb3,
//   0x7c,
//   0x95,
//   0xcf,
//   0x00,
//   0xeb,
//   0xad,
//   0xe2,
//   0xef,
//   0xc7,
//   0xfd,
//   0xbb,
//   0xed,
//   0xf7,
//   0x1f,
//   0x6c,
//   0xcd,
// ]);

// class Client {
//   HandshakeType state = HandshakeType.unkown;

//   ClientHello? clientHello;
// }

// Map<String, Client> clients = {};

// int decodeExtUseExtendedMasterSecret(
//     int extensionLength, Uint8List buf, int offset, int arrayLen) {
//   return offset;
// }

// decodeExtUseSRTP(int extensionLength, Uint8List buf, int offset, int arrayLen) {
//   // protectionProfilesLength := binary.BigEndian.Uint16(buf[offset : offset+2])
//   // offset += 2
//   // protectionProfilesCount := protectionProfilesLength / 2
//   // e.ProtectionProfiles = make([]SRTPProtectionProfile, protectionProfilesCount)
//   // for i := 0; i < int(protectionProfilesCount); i++ {
//   // 	e.ProtectionProfiles[i] = SRTPProtectionProfile(binary.BigEndian.Uint16(buf[offset : offset+2]))
//   // 	offset += 2
//   // }
//   // mkiLength := buf[offset]
//   // offset++

//   var protectionProfilesLength = buf.sublist(offset, offset + 2);
//   var buffer = protectionProfilesLength.buffer;
//   var bytes = ByteData.view(buffer);
//   var intProtectionProfilesLength = bytes.getUint16(0);
//   offset += 2;
//   var protectionProfilesCount = intProtectionProfilesLength / 2;

//   List<int> ProtectionProfiles = [];

//   for (int i = 0; i < protectionProfilesCount; i++) {
//     var SRTPProtectionProfile = buf.sublist(offset, offset + 2);
//     buffer = SRTPProtectionProfile.buffer;
//     bytes = ByteData.view(buffer);
//     var intSRTPProtectionProfile = bytes.getUint16(0);
//     ProtectionProfiles[i] = intSRTPProtectionProfile;
//     offset += 2;
//   }
//   var mkiLength = buf[offset];

//   var Mki = buf.sublist(offset, offset + mkiLength);
//   offset += mkiLength;

//   return offset;
// }

// decodeExtSupportedPointFormats(
//     int extensionLength, Uint8List buf, int offset, int arrayLen) {
//   var pointFormatsCount = buf[offset];
//   offset++;
//   List<int> PointFormats = []; // make([]PointFormat, pointFormatsCount)
//   for (int i = 0; i < pointFormatsCount; i++) {
//     PointFormats[i] = (buf[offset]) as PointFormat;
//     offset++;
//   }

//   return offset;
// }

// int decodeChangeCipherSpec(Uint8List buf, int offset, int arrayLen) {
//   if (arrayLen < 1 || buf[offset] != 1) {
//     offset++;
//     print("invalid cipher spec");
//     return offset; //, errors.New("invalid cipher spec")
//   }
//   offset++;
//   return offset; //, nil
// }

// int decodeFinished(Uint8List buf, int offset, int arrayLen) {
//   var verifyData = buf.sublist(offset, offset + arrayLen);
//   offset += verifyData.length;
//   return offset; //, nil
// }

// int decodeCertificateRequest(Uint8List buf, int offset, int arrayLen) {
//   var certificateTypeCount = buf[offset];
//   offset++;
//   List<dynamic> CertificateTypes =
//       []; // make([]CertificateType, int(certificateTypeCount))
//   for (int i = 0; i < certificateTypeCount; i++) {
//     CertificateTypes[i] = (buf[offset + i]) as CertificateType;
//   }
//   offset += certificateTypeCount;

//   var algoPairLength = buf.sublist(offset, offset + 2);
//   var buffer = algoPairLength.buffer;
//   var bytes = ByteData.view(buffer);
//   var intAlgoPairLength = bytes.getUint16(0);

//   var algoPairCount = intAlgoPairLength / 2;

//   //m.AlgoPairs = make([]AlgoPair, algoPairCount)
//   for (int i = 0; i < algoPairCount; i++) {
//     //m.AlgoPairs[i] = AlgoPair{}
//     var lastOffset = decodeAlgoPair(buf, offset, arrayLen);
//     // if err != nil {
//     // 	return offset, err
//     // }
//     offset = lastOffset;
//   }
//   offset += 2; // Distinguished Names Length

//   return offset; //, nil
// }

// int decodeCertificateVerify(Uint8List buf, int offset, int arrayLen) {
//   //m.AlgoPair = AlgoPair{}
//   offset = decodeAlgoPair(buf, offset, arrayLen);
//   // if err != nil {
//   // 	return offset, err
//   // }
//   // signatureLength := binary.BigEndian.Uint16(buf[offset : offset+2])
//   // offset += 2
//   // m.Signature = make([]byte, signatureLength)
//   // copy(m.Signature, buf[offset:offset+int(signatureLength)])
//   // offset += int(signatureLength)

//   var signatureLength = buf.sublist(offset, offset + 2);
//   var buffer = signatureLength.buffer;
//   var bytes = ByteData.view(buffer);
//   var intSignatureLength = bytes.getUint16(0);
//   offset += 2;

//   var signature = buf.sublist(offset, offset + intSignatureLength);
//   offset += intSignatureLength;
//   return offset; //, nil
// }

// int decodeClientKeyExchange(Uint8List buf, int offset, int arrayLen) {
//   var publicKeyLength = buf[offset];
//   offset++;
//   var publicKey = buf.sublist(offset, offset + publicKeyLength);
//   offset += publicKeyLength;
//   return offset; //, nil
// }

// int decodeServerHelloDone(Uint8List buf, int offset, int arrayLen) {
//   return offset; //, nil
// }

// int decodeAlgoPair(Uint8List buf, int offset, int arrayLen) {
//   var hashAlgorithm = (buf[offset]) as HashAlgorithm;
//   offset += 1;
//   var signatureAlgorithm = (buf[offset]) as SignatureAlgorithm;
//   offset += 1;
//   return offset; //, nil
// }

// int decodeServerKeyExchange(Uint8List buf, int offset, int arrayLen) {
//   var ellipticCurveType = (buf[offset]) as CurveType;
//   offset++;

//   var namedCurve = buf.sublist(offset, offset + 2);
//   var buffer = namedCurve.buffer;
//   var bytes = ByteData.view(buffer);
//   var intNamedCurve = bytes.getUint16(0);
//   offset += 2;

//   var publicKeyLength = buf[offset];
//   offset++;
//   var publicKey = buf.sublist(offset, offset + publicKeyLength);
//   //m.AlgoPair = AlgoPair{}
//   offset = decodeAlgoPair(buf, offset, arrayLen);
//   // if err != nil {
//   // 	return offset, err
//   // }

//   var signatureLength = buf.sublist(offset, offset + 2);
//   buffer = signatureLength.buffer;
//   bytes = ByteData.view(buffer);
//   var intSignatureLength = bytes.getUint16(0);
//   offset += 2;

//   var signature = buf.sublist(offset, offset + intSignatureLength);
//   offset += intSignatureLength;
//   return offset; //, nil
// }

// int decodeClientHello(Uint8List buf, int offset, int arrayLen) {
//   var version = buf.sublist(offset, offset + 2);
//   //print("Handshake Version(Uint8List) : $version");
//   var buffer = version.buffer;
//   var bytes = ByteData.view(buffer);
//   var intVersion = bytes.getUint16(0);
//   //print("Handshake Version int: $intVersion");
//   offset += 2;

//   var gmtUnixtime = buf.sublist(offset, offset + 4);
//   //print("GMT Unixtime(Uint8List) : $gmtUnixtime");
//   buffer = gmtUnixtime.buffer;
//   bytes = ByteData.view(buffer);
//   var intGmtUnixtime = bytes.getUint32(0);
//   //print("GMT Unixtime int: $intGmtUnixtime");
//   offset += 4;

//   var random_bytes = buf.sublist(offset, offset + 28);
//   //print("GMT Unixtime(Uint8List) : $random_bytes");
//   // buffer = random_bytes.buffer;
//   // bytes = ByteData.view(buffer);
//   // var intrandom_bytes = bytes.getUint32(0);
//   //print("Random bytes int: $random_bytes");
//   offset += 28;

//   var sessionIDLength = buf[offset];
//   //print("Session ID length : $sessionIDLength");
//   offset++;

//   var SessionID = buf.sublist(offset, offset + sessionIDLength);
//   //print("Session ID: $SessionID");
//   offset = offset + sessionIDLength;

//   var cookieLength = buf[offset];
//   print("Cookie length: $cookieLength");
//   offset++;

//   var cookie = buf.sublist(offset, offset + cookieLength);
//   print("Cookie: $cookie");
//   offset = offset + cookieLength;

//   offset = decodeCipherSuiteIDs(buf, offset, arrayLen);
//   offset = decodeCompressionMethodIDs(buf, offset, arrayLen);

//   try {
//     offset = DecodeExtensionMap(buf, offset, arrayLen);
//   } catch (exception) {
//     print(exception);
//   }
//   return offset;
// }

// Uint8List encodeServerHello() {
//   return serverHello;
// }

// int decodeCertificate(Uint8List buf, int offset, int arrayLen) {
//   var length = buf.sublist(offset, offset + 3);
//   //print("Cipher Suite ID length(Uint8List) : $length");
//   var buffer = length.buffer;
//   var bytes = ByteData.view(buffer);
//   var intLength = uint24ToUint32(length);
//   //print("Cipher Suite ID length int: $intLength");
//   offset += 3;
//   var offsetBackup = offset;

// //	m.Certificates = make([][]byte, 0)

//   while (offset < offsetBackup + intLength) {
//     var certificateLength = buf.sublist(offset, offset + 3);
//     //print("Cipher Suite ID length(Uint8List) : $length");
//     buffer = length.buffer;
//     bytes = ByteData.view(buffer);
//     var intCertificateLength = uint24ToUint32(length);
//     offset += 3;

//     var certificateBytes = buf.sublist(offset, offset + intCertificateLength);
//     offset += intCertificateLength;
//     //m.Certificates = append(m.Certificates, certificateBytes)
//   }
//   return offset;
// }

// int decodeServerHello(Uint8List buf, int offset, int arrayLen) {
//   // https://github.com/pion/dtls/blob/680c851ed9efc926757f7df6858c82ac63f03a5d/pkg/protocol/handshake/message_client_hello.go#L66
//   var version = buf.sublist(offset, offset + 2);
//   print("Handshake Version(Uint8List) : $version");
//   var buffer = version.buffer;
//   var bytes = ByteData.view(buffer);
//   var intVersion = bytes.getUint16(0);
//   print("Handshake Version int: $intVersion");
//   offset += 2;

//   var gmtUnixtime = buf.sublist(offset, offset + 4);
//   print("GMT Unixtime(Uint8List) : $gmtUnixtime");
//   buffer = gmtUnixtime.buffer;
//   bytes = ByteData.view(buffer);
//   var intGmtUnixtime = bytes.getUint32(0);
//   print("GMT Unixtime int: $intGmtUnixtime");
//   offset += 4;

//   var random_bytes = buf.sublist(offset, offset + 28);
//   print("GMT Unixtime(Uint8List) : $random_bytes");
//   // buffer = random_bytes.buffer;
//   // bytes = ByteData.view(buffer);
//   // var intrandom_bytes = bytes.getUint32(0);
//   //print("Random bytes int: $random_bytes");
//   offset += 28;

//   var sessionIDLength = buf[offset];
//   print("Session ID length : $sessionIDLength");
//   offset++;

//   var SessionID = buf.sublist(offset, offset + sessionIDLength);
//   print("Session ID: $SessionID");
//   offset = offset + sessionIDLength;

//   offset = decodeCipherSuiteIDs(buf, offset, arrayLen);
//   offset = decodeCompressionMethodIDs(buf, offset, arrayLen);

//   try {
//     offset = DecodeExtensionMap(buf, offset, arrayLen);
//   } catch (exception) {
//     print(exception);
//   }

//   return offset;
// }

// int decodeExtSupportedEllipticCurves(
//     int extensionLength, Uint8List buf, int offset, int arrayLen) {
//   var curvesLength = buf.sublist(offset, offset + 2);
//   //print("Curves length : $curvesLength");
//   var buffer = curvesLength.buffer;
//   var bytes = ByteData.view(buffer);
//   var intCurvesLength = bytes.getUint16(0);
//   //print("Cipher Suite ID length int: $intCurvesLength");
//   offset += 2;

//   // curvesLength := binary.BigEndian.Uint16(buf[offset:])
//   // offset += 2
//   var curvesCount = intCurvesLength / 2;
//   //e.Curves = make([]Curve, curvesCount)
//   for (int i = 0; i < curvesCount; i++) {
//     // e.Curves[i] = Curve(binary.BigEndian.Uint16(buf[offset:]))
//     // offset += 2

//     var curve = buf.sublist(offset, offset + 2);
//     //print("Curve Uint8List: $curve");
//     buffer = curve.buffer;
//     bytes = ByteData.view(buffer);
//     var intCurve = bytes.getUint16(0);
//     // print("Curve int: $intCurve");
//     offset += 2;
//   }

//   return offset;
// }

// int DecodeExtensionMap(Uint8List buf, int offset, int arrayLen) {
//   //result := map[ExtensionType]Extension{}
//   var length = buf.sublist(offset, offset + 2);
//   //print("Cipher Suite ID length(Uint8List) : $length");
//   var buffer = length.buffer;
//   var bytes = ByteData.view(buffer);
//   var intLength = bytes.getUint16(0);
//   //print("Cipher Suite ID length int: $intLength");
//   offset += 2;

//   var offsetBackup = offset;
//   while (offset < offsetBackup + intLength && offset < arrayLen - 2) {
//     //var extensionType := ExtensionType(binary.BigEndian.Uint16(buf[offset : offset+2]))
//     var extensionType = buf.sublist(offset, offset + 2);
//     buffer = extensionType.buffer;
//     bytes = ByteData.view(buffer);
//     var intExtensionType = bytes.getUint16(0);
//     //print("Extension type: $intExtensionType");
//     offset += 2;

//     var extensionLength = buf.sublist(offset, offset + 2);
//     buffer = extensionLength.buffer;
//     bytes = ByteData.view(buffer);
//     var intExtensionLength = bytes.getUint16(0);
//     //print("Extension length: $intExtensionLength");
//     offset += 2;
//     //offset += intExtensionLength;
//     // var extension Extension = nil

//     var enumExtensionType = ExtensionType.fromInt(intExtensionType);

//     switch (enumExtensionType) {
//       case ExtensionType
//             .UseExtendedMasterSecret: //ExtensionTypeUseExtendedMasterSecret:
//         decodeExtUseExtendedMasterSecret(
//             intExtensionLength, buf, offset, arrayLen);
//       case ExtensionType.UseSRTP: //ExtensionTypeUseSRTP:
//         decodeExtUseSRTP(intExtensionLength, buf, offset, arrayLen);
//       case ExtensionType
//             .SupportedPointFormats: //ExtensionTypeSupportedPointFormats:
//         decodeExtSupportedPointFormats(
//             intExtensionLength, buf, offset, arrayLen);
//       case ExtensionType
//             .SupportedEllipticCurves: //ExtensionTypeSupportedEllipticCurves:
//         {
//           decodeExtSupportedEllipticCurves(
//               intExtensionLength, buf, offset, arrayLen);
//         }
//       default:
//         {
//           print("Unknown extension type: $intExtensionType");
//         }
//       // 	extension = &ExtUnknown{
//       // 		Type:       extensionType,
//       // 		DataLength: extensionLength,
//       // 	}
//       // }
//       // if extension != nil {
//       // 	err := extension.Decode(int(extensionLength), buf, offset, arrayLen)

//       // 	if err != nil {
//       // 		return nil, offset, err
//       // 	}
//       // 	AddExtension(result, extension)
//     }
//     offset += intExtensionLength;
//   }
//   return offset; //, nil
// }

// int decodeCompressionMethodIDs(Uint8List buf, int offset, int arrayLen) {
// // var length = buf.sublist(offset, offset + 2);
// //   print("Cipher Suite ID length(Uint8List) : $length");
// //   var buffer = length.buffer;
// //   var bytes = ByteData.view(buffer);
// //   var intLength = bytes.getUint16(0);
// //   print("Cipher Suite ID length int: $intLength");
// //   offset += 1;

//   var count = buf[offset];
//   //print("Compression method count: $count");
//   offset += 1;
//   for (int i = 0; i < count; i++) {
//     var compressionMethodID = buf[offset];
//     //print("Compression method ID: $compressionMethodID");
//     // buffer = cipherSuiteID.buffer;
//     // bytes = ByteData.view(buffer);
//     // intLength = bytes.getUint16(0);
//     //print("Cipher Suite ID length int: $intLength");
//     offset++;
//   }

//   return offset;
// }

// int decodeCipherSuiteIDs(Uint8List buf, int offset, int arrayLen) {
//   var length = buf.sublist(offset, offset + 2);
//   //print("Cipher Suite ID length(Uint8List) : $length");
//   var buffer = length.buffer;
//   var bytes = ByteData.view(buffer);
//   var intLength = bytes.getUint16(0);
//   //print("Cipher Suite ID length int: $intLength");
//   offset += 2;

//   var count = intLength / 2;
//   for (int i = 0; i < count; i++) {
//     var cipherSuiteID = buf.sublist(offset, offset + 2);
//     //print("Cipher Suite ID length(Uint8List) : $cipherSuiteID");
//     // buffer = cipherSuiteID.buffer;
//     // bytes = ByteData.view(buffer);
//     // intLength = bytes.getUint16(0);
//     //print("Cipher Suite ID length int: $intLength");
//     offset += 2;
//   }

//   return offset;
// }

// int decodeHandshake(
//     HandshakeType handshakeType, Uint8List buf, int offset, int arrayLen) {
//   switch (handshakeType) {
//     case HandshakeType.client_hello:
//       //result = new(ClientHello)
//       decodeClientHello(buf, offset, arrayLen);
//     case HandshakeType.server_hello:
//       decodeServerHello(buf, offset, arrayLen);
//     case HandshakeType.certificate:
//       decodeCertificate(buf, offset, arrayLen);
//     case HandshakeType.server_key_exchange:
//       decodeServerKeyExchange(buf, offset, arrayLen);
//     case HandshakeType.certificate_request:
//       decodeCertificateRequest(buf, offset, arrayLen);
//     case HandshakeType.server_hello_done:
//       decodeServerHelloDone(buf, offset, arrayLen);
//     case HandshakeType.client_key_exchange:
//       decodeClientKeyExchange(buf, offset, arrayLen);
//     case HandshakeType.certificate_verify:
//       decodeCertificateVerify(buf, offset, arrayLen);
//     case HandshakeType.finished:
//       decodeFinished(buf, offset, arrayLen);
//     default:
//     //return nil, offset, errUnknownDtlsHandshakeType
//   }
//   // offset, err := result.Decode(buf, offset, arrayLen)
//   // return result, offset, err

//   return offset;
// }

// int DecodeHandshakeHeader(Uint8List buf, int offset, int arrayLen) {
//   var handshakeType = buf[offset];
//   //print("Handshake type: $HandshakeType");
//   offset++;

//   var length = buf.sublist(offset, offset + 3); //NewUint24FromBytes
//   //print("handshake Length: $length");
//   offset += 3;
//   var MessageSequence = buf.sublist(offset, offset + 2);
//   //print("Message sequence: $MessageSequence");
//   var buffer = MessageSequence.buffer;
//   var bytes = ByteData.view(buffer);
//   var intMessageSequence = bytes.getUint16(0);
//   //print("Message sequence: $intMessageSequence");
//   offset += 2;
// //  result.FragmentOffset = NewUint24FromBytes(buf[offset : offset+3])
// //  offset += 3

//   var FragmentOffset = buf.sublist(offset, offset + 2);
//   //print("Fragment offset: $FragmentOffset");
//   buffer = MessageSequence.buffer;
//   bytes = ByteData.view(buffer);
//   var intFragmentOffset = bytes.getUint16(0);
//   //print("Fragment offset: $intFragmentOffset");
//   offset += 3;
// // result.FragmentLength = NewUint24FromBytes(buf[offset : offset+3])
// // offset += 3
//   var FragmentLength = buf.sublist(offset, offset + 2);
//   //print("Fragment offset: $FragmentLength");
//   buffer = MessageSequence.buffer;
//   bytes = ByteData.view(buffer);
//   var intFragmentLength = bytes.getUint16(0);
//   //print("Fragment Length: $intFragmentLength");
//   offset += 3;

//   decodeHandshake(HandshakeType.fromInt(handshakeType), buf, offset, arrayLen);

//   return offset;
// }

// int decodeRecordHeader(Client client, Uint8List buf, int offset, int arrayLen) {
//   var contentType = buf[offset];
//   //print("Content type : $contentType");
//   offset++;

//   var version = buf.sublist(offset, offset + 2);
//   //print("Version(Uint8List) : $version");
//   var buffer = version.buffer;
//   var bytes = ByteData.view(buffer);
//   var intVersion = bytes.getUint16(0);
//   //print("Version : $intVersion");
//   offset += 2;

//   var epoch = buf.sublist(offset, offset + 2);
//   //print("Epoch : $epoch");
//   buffer = epoch.buffer;
//   bytes = ByteData.view(buffer);
//   var intEpoch = bytes.getUint16(0);
//   //print("intEpoch : $intEpoch");
//   offset += 2;

//   var sequenceNumber = buf.sublist(offset, offset + SequenceNumberSize);
//   //print("Sequence number: $sequenceNumber");
//   offset += SequenceNumberSize;

//   var length = buf.sublist(offset, offset + 2);
//   //print("Length : $length");
//   buffer = length.buffer;
//   bytes = ByteData.view(buffer);
//   var intLength = bytes.getUint16(0);
//   //print("intLength : $intLength");
//   offset += 2;

//   ContentType enumContentType = ContentType.fromInt(contentType);

//   switch (enumContentType) {
//     case ContentType.handshake:
//       {
//         int offsetBackup = offset;
//         offset = DecodeHandshakeHeader(buf, offset, arrayLen);
//         // decodeHandshake(buf, offset, arrayLen);
//       }
//     default:
//       {
//         print("Unknown content type: $enumContentType");
//       }
//   }

//   return offset;
// }

// void decode(Uint8List buf, int offset, int arrayLen) {
//   var version = buf.sublist(offset, offset + 2);
//   //print("Version(Uint8List) : $version");

//   var buffer = version.buffer;
//   var bytes = ByteData.view(buffer);
//   var intVersion = bytes.getUint16(0);
//   print("Version : $intVersion");

// // var epoch = buf.sublist(offset, offset + 2);
// // binary.BigEndian.Uint16(buf[offset : offset+2])
// // offset += 2
// }
HandshakeManager manager = HandshakeManager();

void main(List<String> args) {
  Init();
  RawDatagramSocket.bind(InternetAddress("127.0.0.1"), 4444)
      .then((RawDatagramSocket socket) {
    print('Datagram socket ready to receive');
    print('${socket.address.address}:${socket.port}');

    int ClientEpoch = 0;

    socket.listen((RawSocketEvent e) {
      Datagram? d = socket.receive();
      if (d == null) return;

      //String message = new String.fromCharCodes(d.data).trim();
      print('Datagram from ${d.address.address}:${d.port}');

      // if (clients["${d.address.address}${d.port.toString()}"] == null) {
      //   clients["${d.address.address}${d.port.toString()}"] = Client();
      // }

      if (manager.contexts["${d.address.address}${d.port.toString()}"] ==
          null) {
        manager.contexts["${d.address.address}${d.port.toString()}"] =
            HandshakeContext();
        // manager.contexts["${d.address.address}${d.port.toString()}"]!
        //     .processMessage(d.data);

        var (header, handshakeHeader, result, offset, err) =
            BaseDtlsMessage.DecodeDtlsMessage(
                manager.contexts["${d.address.address}${d.port.toString()}"]!,
                d.data,
                0,
                d.data.length);

        manager.contexts["${d.address.address}${d.port.toString()}"]!
            .processMessage(header, handshakeHeader, result, offset, err);
      } else {
        // manager.contexts["${d.address.address}${d.port.toString()}"]!
        //     .processMessage(d.data);
        var (header, handshakeHeader, result, offset, err) =
            BaseDtlsMessage.DecodeDtlsMessage(
                manager.contexts["${d.address.address}${d.port.toString()}"]!,
                d.data,
                0,
                d.data.length);
        manager.contexts["${d.address.address}${d.port.toString()}"]!
            .processMessage(header, handshakeHeader, result, offset, err);
      }

      // int offset = decodeRecordHeader(
      //     clients["${d.address.address}${d.port.toString()}"]!,
      //     d.data,
      //     0,
      //     d.data.length);
      //print("Record header: ${d.data.sublist(0, offset)}");

      //decodeRecordHeader(clients["${d.address.address}${d.port.toString()}"]!,
      //   serverHello, 0, d.data.length);
      //serverHello

      // if (clients["${d.address.address}${d.port.toString()}"] != null) {
      //   // print(
      //   //     "Client state: ${clients["${d.address.address}${d.port.toString()}"]!.state}");
      //   if (clients["${d.address.address}${d.port.toString()}"]!.state ==
      //       HandshakeType.hello_request) {
      //     var hvr = HelloVerifyRequest(ProtocolVersion, cookie);
      //     socket.send(serverHello, d.address, d.port);
      //     clients["${d.address.address}${d.port.toString()}"]!.state =
      //         HandshakeType.certificate;
      //   }
      //   if (clients["${d.address.address}${d.port.toString()}"]!.state ==
      //       HandshakeType.unkown) {
      //     var hvr = HelloVerifyRequest(ProtocolVersion, cookie);
      //     socket.send(serverHello, d.address, d.port);
      //     clients["${d.address.address}${d.port.toString()}"]!.state =
      //         HandshakeType.hello_request;
      //   }
      // }
      //socket.send(buffer, address, port);
    });
  });
}

Uint8List serverHello = Uint8List.fromList([
  0x16,
  0xfe,
  0xfd,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x62,
  0x02,
  0x00,
  0x00,
  0x56,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x56,
  0xfe,
  0xfd,
  0x70,
  0x71,
  0x72,
  0x73,
  0x74,
  0x75,
  0x76,
  0x77,
  0x78,
  0x79,
  0x7a,
  0x7b,
  0x7c,
  0x7d,
  0x7e,
  0x7f,
  0x80,
  0x81,
  0x82,
  0x83,
  0x84,
  0x85,
  0x86,
  0x87,
  0x88,
  0x89,
  0x8a,
  0x8b,
  0x8c,
  0x8d,
  0x8e,
  0x8f,
  0x00,
  192, //  0x13,//CipherSuite ID192, 43
  43, // 0x01,//
  0x00,
  0x00,
  0x2e,
  0x00,
  0x33,
  0x00,
  0x24,
  0x00,
  0x1d,
  0x00,
  0x20,
  0x9f,
  0xd7,
  0xad,
  0x6d,
  0xcf,
  0xf4,
  0x29,
  0x8d,
  0xd3,
  0xf9,
  0x6d,
  0x5b,
  0x1b,
  0x2a,
  0xf9,
  0x10,
  0xa0,
  0x53,
  0x5b,
  0x14,
  0x88,
  0xd7,
  0xf8,
  0xfa,
  0xbb,
  0x34,
  0x9a,
  0x98,
  0x28,
  0x80,
  0xb6,
  0x15,
  0x00,
  0x2b,
  0x00,
  0x02,
  0xfe,
  0xfc
]);
