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

Uint8List uint16toUint8List(int b) {
  // Create a ByteData buffer with 2 bytes (16 bits)
  ByteData byteData = ByteData(2);

  // Set the uint16 value at offset 0
  byteData.setUint16(0, b, Endian.big);

  // Convert ByteData to Uint8List
  Uint8List uint8List = byteData.buffer.asUint8List();

  return uint8List; // Output: [52, 18]
}

Uint8List uint32toUint8List(int b) {
  // Create a ByteData buffer with 2 bytes (16 bits)
  ByteData byteData = ByteData(4);

  // Set the uint16 value at offset 0
  byteData.setUint32(0, b, Endian.big);

  // Convert ByteData to Uint8List
  Uint8List uint8List = byteData.buffer.asUint8List();

  return uint8List; // Output: [52, 18]
}
// Uint8List int16toUint8List(int b) {

//   // Create a ByteData buffer with 2 bytes (16 bits)
//   ByteData byteData = ByteData(2);

//   // Set the uint16 value at offset 0
//   byteData.setInt16(0, b, Endian.big);

//   // Convert ByteData to Uint8List
//   Uint8List uint8List = byteData.buffer.asUint8List();

//   return uint8List; // Output: [52, 18]
// }

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
