import 'dart:typed_data';

typedef HashAlgorithm = int;
typedef SignatureAlgorithm = int;
typedef SRTPProtectionProfile = int;
typedef PointFormat = int;
typedef Curve = int;
typedef CurveType = int;

typedef CipherSuiteID = int;

int uint24FromBytes(Uint8List b) {
  // https://stackoverflow.com/questions/45000982/convert-3-bytes-to-int-in-go
  if (b.length != 3) {
    throw ArgumentError("Incorrect length");
  }
  return (b[2]) | (b[1]) << 8 | (b[0]) << 16;
}

int uint16(Uint8List b) {
  // https://stackoverflow.com/questions/45000982/convert-3-bytes-to-int-in-go
  //return (b[2]) | (b[1]) << 8 | (b[0]) << 16;

  if (b.length != 2) {
    throw ArgumentError("Incorrect length");
  }
  var data = b.sublist(0);
  var buffer = data.buffer;
  var bytes = ByteData.view(buffer);
  return bytes.getUint16(0);
}

// int uint16toUint8List(int b) {
//   // https://stackoverflow.com/questions/45000982/convert-3-bytes-to-int-in-go
//   //return (b[2]) | (b[1]) << 8 | (b[0]) << 16;

//   // if (b.length != 2) {
//   //   throw ArgumentError("Incorrect length");
//   // }
//   var data = Uint8List(2);
//   var buffer = data.buffer;
//   var bytes = ByteData.view(buffer);

//   /
// }

int uint32(Uint8List b) {
  // https://stackoverflow.com/questions/45000982/convert-3-bytes-to-int-in-go
  //return (b[2]) | (b[1]) << 8 | (b[0]) << 16;

  if (b.length != 4) {
    throw ArgumentError("Incorrect length");
  }
  var data = b.sublist(0);
  var buffer = data.buffer;
  var bytes = ByteData.view(buffer);
  return bytes.getUint32(0);
}
