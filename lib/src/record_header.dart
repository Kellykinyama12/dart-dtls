import 'dart:typed_data';

import 'package:dtls2/src/handshake_context.dart';
import 'package:dtls2/src/utils.dart';

const SequenceNumberSize = 6;

enum ContentType {
  change_cipher_spec(20),
  alert(21),
  handshake(22),
  application_data(23),
  unknown(255);

  const ContentType(this.value);

  final int value;

  factory ContentType.fromInt(int key) {
    return values.firstWhere((element) => element.value == key);
  }
}

class RecordHeader {
  //https://github.com/eclipse/tinydtls/blob/706888256c3e03d9fcf1ec37bb1dd6499213be3c/dtls.h#L320
  ContentType? enumContentType;
  int? intVersion;
  int? intEpoch;
  Uint8List? sequenceNumber;
  int? intLength;
  // Uint8List DtlsVersion = Uint8List(2);
  // int Epoch; //          uint16
  // Uint8List SequenceNumber =
  //     Uint8List(SequenceNumberSize); // [SequenceNumberSize]byte
  // Uint8List Length = Uint8List(2); //         uint16
  RecordHeader();

  Uint8List? data;

  // dynamic decodeRecordHeader(Uint8List buf, int offset, int arrayLen) {
  //   var contentType = buf[offset];
  //   print("Content type: $contentType");
  //   offset++;

  //   var version = buf.sublist(offset, offset + 2);
  //   print("Version(Uint8List): $version");
  //   var buffer = version.buffer;
  //   var bytes = ByteData.view(buffer);
  //   intVersion = bytes.getUint16(0);
  //   print("Version : $intVersion");
  //   offset += 2;

  //   var epoch = buf.sublist(offset, offset + 2);
  //   print("Epoch : $epoch");
  //   buffer = epoch.buffer;
  //   bytes = ByteData.view(buffer);
  //   intEpoch = bytes.getUint16(0);
  //   print("intEpoch : $intEpoch");
  //   offset += 2;

  //   sequenceNumber = buf.sublist(offset, offset + SequenceNumberSize);
  //   print("Sequence number: $sequenceNumber");
  //   offset += SequenceNumberSize;

  //   var length = buf.sublist(offset, offset + 2);
  //   print("Length : $length");
  //   buffer = length.buffer;
  //   bytes = ByteData.view(buffer);
  //   intLength = bytes.getUint16(0);
  //   print("intLength : $intLength");
  //   offset += 2;

  //   ContentType enumContentType = ContentType.fromInt(contentType);

  //   switch (enumContentType) {
  //     case ContentType.handshake:
  //       {
  //         int offsetBackup = offset;
  //         //offset = DecodeHandshakeHeader(buf, offset, arrayLen);
  //         // decodeHandshake(buf, offset, arrayLen);
  //       }
  //     default:
  //       {
  //         print("Unknown content type: $enumContentType");
  //       }
  //   }

  //   return offset;
  // }
}

dynamic DecodeRecordHeader(Uint8List buf, int offset, int arrayLen)
//(*RecordHeader, int, error)
{
  var result = RecordHeader();

  result.enumContentType = ContentType.fromInt(buf[offset]);
  offset++;
  result.intVersion = uint16(buf.sublist(offset, offset + 2));
  offset += 2;
  result.intEpoch = uint16(buf.sublist(offset, offset + 2));
  offset += 2;
  result.sequenceNumber = buf.sublist(offset, offset + SequenceNumberSize);
  offset += SequenceNumberSize;
  result.intLength = uint16(buf.sublist(offset, offset + 2));
  offset += 2;

  print("Record length: ${result.intLength}, array length: $arrayLen");

  result.data = buf.sublist(offset);
  return (result, offset, null);
}
