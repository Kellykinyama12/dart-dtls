import 'dart:typed_data';
import 'package:binary_data/binary_data.dart';
import 'fragment.dart';
import 'domain.dart';
import 'binary.dart';
import 'const.dart';

// 7.4.2.  Server Certificate
// 7.4.6.  Client Certificate

class Certificate implements Handshake {
  @override
  final int msgType = HandshakeType.certificate11.value;
  @override
  int? messageSeq;

  static final spec = {
    'certificateList': BinaryDataType.array(ASN11Cert, BinaryDataType.uint24be, 'bytes'),
  };

  List<Uint8List> certificateList;

  Certificate(this.certificateList);

  factory Certificate.createEmpty() {
    return Certificate([]);
  }

  factory Certificate.deSerialize(Uint8List buf) {
    final decoded = decode(buf, Certificate.spec);
    return Certificate(
      decoded['certificateList'],
    );
  }

  Uint8List serialize() {
    final encoded = encode({
      'certificateList': certificateList,
    }, Certificate.spec);
    return Uint8List.fromList(encoded);
  }

  FragmentedHandshake toFragment() {
    final body = serialize();
    return FragmentedHandshake(
      msgType,
      body.length,
      messageSeq!,
      0,
      body.length,
      body,
    );
  }
}