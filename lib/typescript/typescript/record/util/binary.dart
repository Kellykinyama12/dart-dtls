import 'dart:typed_data';
import 'package:binary_data/binary_data.dart';

Uint8List encodeBuffer(Map<String, dynamic> obj, Map<String, dynamic> spec) {
  final encoded = encode(obj, spec);
  return Uint8List.fromList(encoded);
}
