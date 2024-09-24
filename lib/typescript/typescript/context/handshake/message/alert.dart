import 'dart:typed_data';
import 'package:binary_data/binary_data.dart';

class Alert {
  static final spec = {
    'level': BinaryDataType.uint8,
    'description': BinaryDataType.uint8,
  };

  int level;
  int description;

  Alert(this.level, this.description);

  factory Alert.deSerialize(Uint8List buf) {
    final decoded = decode(buf, Alert.spec);
    return Alert(
      decoded['level'],
      decoded['description'],
    );
  }

  Uint8List serialize() {
    final encoded = encode({
      'level': level,
      'description': description,
    }, Alert.spec);
    return Uint8List.fromList(encoded);
  }
}
