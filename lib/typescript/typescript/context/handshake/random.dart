import 'dart:typed_data';
import 'package:binary_data/binary_data.dart';
import 'dart:math';

class DtlsRandom {
  static final spec = {
    'gmt_unix_time': BinaryDataType.uint32be,
    'random_bytes': BinaryDataType.buffer(28),
  };

  int gmtUnixTime;
  Uint8List randomBytes;

  DtlsRandom([int? gmtUnixTime, Uint8List? randomBytes])
      : gmtUnixTime = gmtUnixTime ?? (DateTime.now().millisecondsSinceEpoch ~/ 1000),
        randomBytes = randomBytes ?? Uint8List.fromList(List.generate(28, (_) => Random().nextInt(256)));

  factory DtlsRandom.deSerialize(Uint8List buf) {
    final decoded = decode(buf, DtlsRandom.spec);
    return DtlsRandom(
      decoded['gmt_unix_time'],
      decoded['random_bytes'],
    );
  }

  factory DtlsRandom.from(Map<String, dynamic> spec) {
    return DtlsRandom(
      spec['gmt_unix_time'],
      spec['random_bytes'],
    );
  }

  Uint8List serialize() {
    final encoded = encode({
      'gmt_unix_time': gmtUnixTime,
      'random_bytes': randomBytes,
    }, DtlsRandom.spec);
    return Uint8List.fromList(encoded);
  }
}