import 'dart:convert';
import 'dart:typed_data';
import 'package:pointycastle/export.dart' as pc;
import 'package:tweetnacl/tweetnacl.dart' as nacl;

class NamedCurveAlgorithm {
  static const int secp256r1_23 = 23;
  static const int x25519_29 = 29;
}

typedef NamedCurveAlgorithms = int;

Uint8List prfPreMasterSecret(
    Uint8List publicKey, Uint8List privateKey, NamedCurveAlgorithms curve) {
  switch (curve) {
    case NamedCurveAlgorithm.secp256r1_23:
      final elliptic = pc.ECDomainParameters('prime256v1');
      final pub = elliptic.curve.decodePoint(publicKey);
      final priv = pc.ECPrivateKey(
          BigInt.parse(hex.encode(privateKey), radix: 16), elliptic);
      final res = pub!.multiply(priv.d);
      final secret = Uint8List.fromList(res!.getEncoded(false).sublist(1, 33));
      return secret;
    case NamedCurveAlgorithm.x25519_29:
      return Uint8List.fromList(nacl.scalarMult(privateKey, publicKey));
    default:
      throw Exception('Unsupported curve algorithm');
  }
}

Uint8List hmac(String algorithm, Uint8List secret, Uint8List data) {
  final hmac = pc.HMac(pc.Digest(algorithm), 64)..init(pc.KeyParameter(secret));
  hmac.update(data, 0, data.length);
  final out = Uint8List(hmac.macSize);
  hmac.doFinal(out, 0);
  return out;
}

Uint8List prfPHash(Uint8List secret, Uint8List seed, int requestedLength,
    [String algorithm = 'SHA-256']) {
  final totalLength = requestedLength;
  final bufs = <Uint8List>[];
  var Ai = seed;

  do {
    Ai = hmac(algorithm, secret, Ai);
    final output = hmac(algorithm, secret, Uint8List.fromList(Ai + seed));
    bufs.add(output);
    requestedLength -= output.length;
  } while (requestedLength > 0);

  return Uint8List.fromList(bufs.expand((x) => x).toList())
      .sublist(0, totalLength);
}

Uint8List prfMasterSecret(
    Uint8List preMasterSecret, Uint8List clientRandom, Uint8List serverRandom) {
  final seed = Uint8List.fromList(
      utf8.encode('master secret') + clientRandom + serverRandom);
  return prfPHash(preMasterSecret, seed, 48);
}

Uint8List prfExtendedMasterSecret(
    Uint8List preMasterSecret, Uint8List handshakes) {
  final sessionHash = hash('SHA-256', handshakes);
  final label = 'extended master secret';
  return prfPHash(preMasterSecret,
      Uint8List.fromList(utf8.encode(label) + sessionHash), 48);
}

Uint8List exportKeyingMaterial(String label, int length, Uint8List masterSecret,
    Uint8List localRandom, Uint8List remoteRandom, bool isClient) {
  final clientRandom = isClient ? localRandom : remoteRandom;
  final serverRandom = isClient ? remoteRandom : localRandom;
  final seed =
      Uint8List.fromList(utf8.encode(label) + clientRandom + serverRandom);
  return prfPHash(masterSecret, seed, length);
}

Uint8List hash(String algorithm, Uint8List data) {
  final digest = pc.Digest(algorithm);
  digest.update(data, 0, data.length);
  final out = Uint8List(digest.digestSize);
  digest.doFinal(out, 0);
  return out;
}

Uint8List prfVerifyData(
    Uint8List masterSecret, Uint8List handshakes, String label,
    [int size = 12]) {
  final bytes = hash('SHA-256', handshakes);
  return prfPHash(
      masterSecret, Uint8List.fromList(utf8.encode(label) + bytes), size);
}

Uint8List prfVerifyDataClient(Uint8List masterSecret, Uint8List handshakes) {
  return prfVerifyData(masterSecret, handshakes, 'client finished');
}

Uint8List prfVerifyDataServer(Uint8List masterSecret, Uint8List handshakes) {
  return prfVerifyData(masterSecret, handshakes, 'server finished');
}

Map<String, Uint8List> prfEncryptionKeys(
    Uint8List masterSecret,
    Uint8List clientRandom,
    Uint8List serverRandom,
    int prfKeyLen,
    int prfIvLen,
    int prfNonceLen,
    [String algorithm = 'SHA-256']) {
  final size = prfKeyLen * 2 + prfIvLen * 2;
  final secret = masterSecret;
  final seed = Uint8List.fromList(serverRandom + clientRandom);
  final keyBlock = prfPHash(secret,
      Uint8List.fromList(utf8.encode('key expansion') + seed), size, algorithm);
  final stream = ByteData.sublistView(keyBlock);

  final clientWriteKey = stream.buffer.asUint8List(0, prfKeyLen);
  final serverWriteKey = stream.buffer.asUint8List(prfKeyLen, prfKeyLen);

  final clientNonceImplicit =
      stream.buffer.asUint8List(prfKeyLen * 2, prfIvLen);
  final serverNonceImplicit =
      stream.buffer.asUint8List(prfKeyLen * 2 + prfIvLen, prfIvLen);

  final clientNonce = Uint8List(prfNonceLen);
  final serverNonce = Uint8List(prfNonceLen);

  clientNonce.setRange(0, prfIvLen, clientNonceImplicit);
  serverNonce.setRange(0, prfIvLen, serverNonceImplicit);

  return {
    'clientWriteKey': clientWriteKey,
    'serverWriteKey': serverWriteKey,
    'clientNonce': clientNonce,
    'serverNonce': serverNonce,
  };
}
