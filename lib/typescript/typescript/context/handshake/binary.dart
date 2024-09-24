import 'package:binary_data/binary_data.dart';

final uint16be = BinaryDataType.uint16be;
final uint24be = BinaryDataType.uint24be;
final buffer = BinaryDataType.buffer;
final array = BinaryDataType.array;
final uint8 = BinaryDataType.uint8;
final string = BinaryDataType.string;

// final Random = {
//   'gmt_unix_time': BinaryDataType.uint32be,
//   'random_bytes': buffer(28),
// };

final Extension = {
  'type': uint16be,
  'data': buffer(uint16be),
};

final ExtensionList = array(Extension, uint16be, 'bytes');

final ASN11Cert = buffer(uint24be);

final ClientCertificateType = uint8;
final DistinguishedName = string(uint16be);

final SignatureHashAlgorithm = {'hash': uint8, 'signature': uint8};

final ProtocolVersion = {'major': uint8, 'minor': uint8};