import 'dart:convert';
import 'dart:typed_data';
import 'package:pointycastle/export.dart' as pc;

/**
 * Calculates HMAC using provided hash.
 * @param {String} algorithm - Hash algorithm.
 * @param {Uint8List} secret - Hmac seed.
 * @param {Uint8List} data - Input data.
 * @returns {Uint8List}
 */
Uint8List hmac(String algorithm, Uint8List secret, Uint8List data) {
  final hmac = pc.HMac(pc.Digest(algorithm), 64)..init(pc.KeyParameter(secret));
  hmac.update(data, 0, data.length);
  final out = Uint8List(hmac.macSize);
  hmac.doFinal(out, 0);
  return out;
}

/**
 * A data expansion function for PRF.
 * @param {int} bytes - The number of bytes required by PRF.
 * @param {String} algorithm - Hmac hash algorithm.
 * @param {Uint8List} secret - Hmac secret.
 * @param {Uint8List} seed - Input data.
 * @returns {Uint8List}
 */
Uint8List pHash(int bytes, String algorithm, Uint8List secret, Uint8List seed) {
  final totalLength = bytes;
  final bufs = <Uint8List>[];
  var Ai = seed; // A0

  do {
    Ai = hmac(algorithm, secret, Ai); // A(i) = HMAC(secret, A(i-1))
    final output = hmac(algorithm, secret, Uint8List.fromList(Ai + seed));
    bufs.add(output);
    bytes -= output.length;
  } while (bytes > 0);

  return Uint8List.fromList(bufs.expand((x) => x).toList())
      .sublist(0, totalLength);
}

//export { hmac, pHash };