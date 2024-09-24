import 'package:pointycastle/export.dart' as pc;
import 'package:tweetnacl/tweetnacl.dart' as nacl;

class NamedCurveAlgorithm {
  static const int secp256r1_23 = 23;
  static const int x25519_29 = 29;
}

typedef NamedCurveAlgorithms = int;

class NamedCurveKeyPair {
  final NamedCurveAlgorithms curve;
  final List<int> publicKey;
  final List<int> privateKey;

  NamedCurveKeyPair({
    required this.curve,
    required this.publicKey,
    required this.privateKey,
  });
}

NamedCurveKeyPair generateKeyPair(NamedCurveAlgorithms namedCurve) {
  switch (namedCurve) {
    case NamedCurveAlgorithm.secp256r1_23:
      final keyParams = pc.ECKeyGeneratorParameters(pc.ECCurve_secp256r1());
      final keyGenerator = pc.ECKeyGenerator();
      keyGenerator.init(pc.ParametersWithRandom(keyParams, pc.SecureRandom()));
      final keyPair = keyGenerator.generateKeyPair();
      final privateKey =
          (keyPair.privateKey as pc.ECPrivateKey).d!.toByteArray();
      final publicKey =
          (keyPair.publicKey as pc.ECPublicKey).Q!.getEncoded(false);
      return NamedCurveKeyPair(
        curve: namedCurve,
        privateKey: privateKey,
        publicKey: publicKey,
      );
    case NamedCurveAlgorithm.x25519_29:
      final keyPair = nacl.KeyPair();
      return NamedCurveKeyPair(
        curve: namedCurve,
        privateKey: keyPair.secretKey,
        publicKey: keyPair.publicKey,
      );
    default:
      throw Exception('Unsupported curve algorithm');
  }
}
