import 'dart:typed_data';
import 'package:pointycastle/export.dart' as pc;
import 'package:basic_utils/basic_utils.dart';
import 'package:cryptography/cryptography.dart' as crypto;
import 'package:asn1lib/asn1lib.dart';
import 'package:date/date.dart';
import 'package:convert/convert.dart';

import 'const.dart';
import 'named_curve.dart';
import 'prf.dart';
import 'abstract.dart';
import 'aead.dart';
import 'binary.dart';
import 'random.dart';
import 'plaintext.dart';

class CipherContext {
  late DtlsRandom localRandom;
  late DtlsRandom remoteRandom;
  late CipherSuites cipherSuite;
  Uint8List? remoteCertificate;
  late NamedCurveKeyPair remoteKeyPair;
  late NamedCurveKeyPair localKeyPair;
  late Uint8List masterSecret;
  late AEADCipher cipher;
  late NamedCurveAlgorithms namedCurve;
  SignatureHash? signatureHashAlgorithm;
  late Uint8List localCert;
  late pc.PrivateKey localPrivateKey;

  CipherContext(
    this.sessionType, {
    String? certPem,
    String? keyPem,
    SignatureHash? signatureHashAlgorithm,
  }) {
    if (certPem != null && keyPem != null && signatureHashAlgorithm != null) {
      parseX509(certPem, keyPem, signatureHashAlgorithm);
    }
  }

  final SessionTypes sessionType;

  static Future<Map<String, dynamic>> createSelfSignedCertificateWithKey(
    SignatureHash signatureHash, {
    NamedCurveAlgorithms? namedCurveAlgorithm,
  }) async {
    final signatureAlgorithmName = () {
      switch (signatureHash.signature) {
        case SignatureAlgorithm.rsa_1:
          return 'RSASSA-PKCS1-v1_5';
        case SignatureAlgorithm.ecdsa_3:
          return 'ECDSA';
      }
    }();

    final hash = () {
      switch (signatureHash.hash) {
        case HashAlgorithm.sha256_4:
          return 'SHA-256';
      }
    }();

    final namedCurve = () {
      switch (namedCurveAlgorithm) {
        case NamedCurveAlgorithm.secp256r1_23:
          return 'P-256';
        case NamedCurveAlgorithm.x25519_29:
          if (signatureAlgorithmName == 'ECDSA') {
            return 'P-256';
          }
          return 'X25519';
        default:
          if (signatureAlgorithmName == 'ECDSA') return 'P-256';
          if (signatureAlgorithmName == 'RSASSA-PKCS1-v1_5') return 'X25519';
      }
    }();

    final alg = () {
      switch (signatureAlgorithmName) {
        case 'ECDSA':
          return {
            'name': signatureAlgorithmName,
            'hash': hash,
            'namedCurve': namedCurve,
          };
        case 'RSASSA-PKCS1-v1_5':
          return {
            'name': signatureAlgorithmName,
            'hash': hash,
            'publicExponent': Uint8List.fromList([1, 0, 1]),
            'modulusLength': 2048,
          };
      }
    }();

    final keys = await crypto.Crypto().generateKeyPair(alg);

    final cert = await crypto.X509CertificateGenerator.createSelfSigned(
      serialNumber: hex.encode(pc.SecureRandom().nextBytes(8)),
      name: 'C=AU, ST=Some-State, O=Internet Widgits Pty Ltd',
      notBefore: DateTime.now(),
      notAfter: DateTime.now().add(Duration(days: 365 * 10)),
      signingAlgorithm: alg,
      keys: keys,
    );

    final certPem = cert.toPem();
    final keyPem = crypto.PemConverter.encode(
      await crypto.Crypto().exportKey('pkcs8', keys.privateKey),
      'private key',
    );

    return {
      'certPem': certPem,
      'keyPem': keyPem,
      'signatureHash': signatureHash
    };
  }

  DtlsPlaintext encryptPacket(DtlsPlaintext pkt) {
    final header = pkt.recordLayerHeader;
    final enc = cipher.encrypt(
        sessionType,
        pkt.fragment,
        CipherHeader(
          type: header.contentType,
          version: decode(
            Uint8List.fromList(
                encode(header.protocolVersion, ProtocolVersion).toList()),
            {'version': pc.Uint16BE()},
          )['version'],
          epoch: header.epoch,
          sequenceNumber: header.sequenceNumber,
        ));
    pkt.fragment = enc;
    pkt.recordLayerHeader.contentLen = enc.length;
    return pkt;
  }

  Uint8List decryptPacket(DtlsPlaintext pkt) {
    final header = pkt.recordLayerHeader;
    final dec = cipher.decrypt(
        sessionType,
        pkt.fragment,
        CipherHeader(
          type: header.contentType,
          version: decode(
            Uint8List.fromList(
                encode(header.protocolVersion, ProtocolVersion).toList()),
            {'version': pc.Uint16BE()},
          )['version'],
          epoch: header.epoch,
          sequenceNumber: header.sequenceNumber,
        ));
    return dec;
  }

  Uint8List verifyData(Uint8List buf) {
    if (sessionType == SessionType.CLIENT) {
      return prfVerifyDataClient(masterSecret, buf);
    } else {
      return prfVerifyDataServer(masterSecret, buf);
    }
  }

  Uint8List signatureData(Uint8List data, String hash) {
    final signature = pc.Signer(hash).update(data);
    final key = localPrivateKey.toPem();
    final signed = signature.sign(key);
    return signed;
  }

  Uint8List generateKeySignature(String hashAlgorithm) {
    final clientRandom =
        sessionType == SessionType.CLIENT ? localRandom : remoteRandom;
    final serverRandom =
        sessionType == SessionType.SERVER ? localRandom : remoteRandom;

    final sig = valueKeySignature(
      clientRandom.serialize(),
      serverRandom.serialize(),
      localKeyPair.publicKey,
      namedCurve,
    );

    final enc = localPrivateKey.sign(sig, hashAlgorithm);
    return enc;
  }

  void parseX509(String certPem, String keyPem, SignatureHash signatureHash) {
    final cert = pc.Certificate.fromPem(certPem);
    final sec = pc.PrivateKey.fromPem(keyPem);
    localCert = cert.raw;
    localPrivateKey = sec;
    signatureHashAlgorithm = signatureHash;
  }

  Uint8List valueKeySignature(
    Uint8List clientRandom,
    Uint8List serverRandom,
    Uint8List publicKey,
    int namedCurve,
  ) {
    final serverParams = Uint8List.fromList(encode({
      'type': CurveType.named_curve_3,
      'curve': namedCurve,
      'len': publicKey.length,
    }, {
      'type': pc.Uint8(),
      'curve': pc.Uint16BE(),
      'len': pc.Uint8(),
    }).toList());
    return Uint8List.fromList(
        clientRandom + serverRandom + serverParams + publicKey);
  }
}
