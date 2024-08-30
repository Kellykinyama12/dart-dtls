import 'package:dtls2/typescript/cipher/const.dart';
import 'package:basic_utils/basic_utils.dart';
// export interface NamedCurveKeyPair {
//   curve: NamedCurveAlgorithms;
//   publicKey: Buffer;
//   privateKey: Buffer;
// }

//({})

typedef NamedCurveKeyPair = (ECPrivateKey, ECPublicKey, NamedCurveAlgorithm);

NamedCurveKeyPair generateKeyPair(NamedCurveAlgorithm namedCurve) {
  switch (namedCurve) {
    case NamedCurveAlgorithm.secp256r1_23:
      {
        // const elliptic = new ec("p256");
        // const key = elliptic.genKeyPair();
        // const privateKey = key.getPrivate().toBuffer("be");
        // const publicKey = Buffer.from(key.getPublic().encode("array", false));

        AsymmetricKeyPair<PublicKey, PrivateKey> pair =
            CryptoUtils.generateEcKeyPair(curve: "secp256r1");
        var privKey = pair.privateKey as ECPrivateKey;
        var pubKey = pair.publicKey as ECPublicKey;

        return (privKey, pubKey, namedCurve);
      }
    // case NamedCurveAlgorithm.x25519_29:
    //   {
    //     const keys = nacl.box.keyPair();

    //     return {
    //       curve: namedCurve,
    //       privateKey: Buffer.from(keys.secretKey.buffer),
    //       publicKey: Buffer.from(keys.publicKey.buffer),
    //     };
    //   }
    default:
      throw "Unkown named curve";
  }
}
