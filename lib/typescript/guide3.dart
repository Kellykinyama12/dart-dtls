Convert the following to dart programming language: export const SignatureAlgorithm = {
  rsa_1: 1,
  ecdsa_3: 3,
} as const;
export type SignatureAlgorithms =
  typeof SignatureAlgorithm[keyof typeof SignatureAlgorithm];

export const HashAlgorithm = {
  sha256_4: 4,
} as const;
export type HashAlgorithms = typeof HashAlgorithm[keyof typeof HashAlgorithm];

export type SignatureHash = {
  hash: HashAlgorithms;
  signature: SignatureAlgorithms;
};

export const CipherSuite = {
  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_49195: 0xc02b, //49195,
  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256_49199: 0xc02f, //49199
} as const;
export type CipherSuites = typeof CipherSuite[keyof typeof CipherSuite];
export const CipherSuiteList: CipherSuites[] = Object.values(CipherSuite);

export const NamedCurveAlgorithm = {
  x25519_29: 29,
  secp256r1_23: 23,
} as const;
export type NamedCurveAlgorithms =
  typeof NamedCurveAlgorithm[keyof typeof NamedCurveAlgorithm];
export const NamedCurveAlgorithmList: NamedCurveAlgorithms[] =
  Object.values(NamedCurveAlgorithm);

export const CurveType = { named_curve_3: 3 } as const;
export type CurveTypes = typeof CurveType[keyof typeof CurveType];

export const SignatureScheme = {
  rsa_pkcs1_sha256: 0x0401,
  ecdsa_secp256r1_sha256: 0x0403,
} as const;
export type SignatureSchemes =
  typeof SignatureScheme[keyof typeof SignatureScheme];
Copilot
Sent by Copilot:
Here’s the Dart equivalent of your JavaScript code:

Dart

class SignatureAlgorithm {
  static const int rsa_1 = 1;
  static const int ecdsa_3 = 3;
}

typedef SignatureAlgorithms = int;

class HashAlgorithm {
  static const int sha256_4 = 4;
}

typedef HashAlgorithms = int;

class SignatureHash {
  final HashAlgorithms hash;
  final SignatureAlgorithms signature;

  SignatureHash({required this.hash, required this.signature});
}

class CipherSuite {
  static const int TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_49195 = 0xc02b;
  static const int TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256_49199 = 0xc02f;
}

typedef CipherSuites = int;
final List<CipherSuites> CipherSuiteList = [
  CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_49195,
  CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256_49199,
];

class NamedCurveAlgorithm {
  static const int x25519_29 = 29;
  static const int secp256r1_23 = 23;
}

typedef NamedCurveAlgorithms = int;
final List<NamedCurveAlgorithms> NamedCurveAlgorithmList = [
  NamedCurveAlgorithm.x25519_29,
  NamedCurveAlgorithm.secp256r1_23,
];

class CurveType {
  static const int named_curve_3 = 3;
}

typedef CurveTypes = int;

class SignatureScheme {
  static const int rsa_pkcs1_sha256 = 0x0401;
  static const int ecdsa_secp256r1_sha256 = 0x0403;
}

typedef SignatureSchemes = int;
AI-generated code. Review and use carefully. More info on FAQ.
This Dart code mirrors the structure and constants from your JavaScript code. If you have any questions or need further adjustments, feel free to ask!

Learn more

1
codeconvert.ai
2
codingfleet.com
3
quicktype.io
4
codedocumentation.app
You
Sent by you:
Convert the following code to dart as well: const signTypes = {
  NULL: 0,
  ECDHE: 1,
};

const keyTypes = {
  NULL: 0,
  RSA: 1,
  ECDSA: 2,
  PSK: 3,
};

const kxTypes = {
  NULL: 0,
  RSA: 1,
  ECDHE_RSA: 2,
  ECDHE_ECDSA: 3,
  PSK: 4,
  ECDHE_PSK: 5,
};

/**
 * This class represent type of key exchange mechanism.
 */
export class KeyExchange {
  id = 0;
  name?: string;
  signType?: number;
  keyType?: number;

  /**
   * @returns {string}
   */
  toString() {
    return this.name;
  }
}

/**
 * Creates `RSA` key exchange.
 * @returns {KeyExchange}
 */
export function createRSAKeyExchange() {
  const exchange = new KeyExchange();

  exchange.id = kxTypes.RSA;
  exchange.name = "RSA";

  exchange.keyType = keyTypes.RSA;

  return exchange;
}

/**
 * Creates `ECDHE_RSA` key exchange.
 * @returns {KeyExchange}
 */
export function createECDHERSAKeyExchange() {
  const exchange = new KeyExchange();

  exchange.id = kxTypes.ECDHE_RSA;
  exchange.name = "ECDHE_RSA";

  exchange.signType = signTypes.ECDHE;
  exchange.keyType = keyTypes.RSA;

  return exchange;
}

/**
 * Creates `ECDHE_ECDSA` key exchange.
 * @returns {KeyExchange}
 */
export function createECDHEECDSAKeyExchange() {
  const exchange = new KeyExchange();

  exchange.id = kxTypes.ECDHE_ECDSA;
  exchange.name = "ECDHE_ECDSA";

  exchange.signType = signTypes.ECDHE;
  exchange.keyType = keyTypes.ECDSA;

  return exchange;
}

/**
 * Creates `NULL` key exchange.
 * @returns {KeyExchange}
 */
export function createNULLKeyExchange() {
  const exchange = new KeyExchange();

  exchange.id = kxTypes.NULL;
  exchange.name = "NULL";

  exchange.signType = signTypes.NULL;
  exchange.keyType = keyTypes.NULL;

  return exchange;
}

/**
 * Creates `PSK` key exchange.
 * @returns {KeyExchange}
 */
export function createPSKKeyExchange() {
  const exchange = new KeyExchange();

  exchange.id = kxTypes.PSK;
  exchange.name = "PSK";

  exchange.signType = signTypes.NULL;
  exchange.keyType = keyTypes.PSK;

  return exchange;
}

/**
 * Creates `ECDHE_PSK` key exchange.
 * @returns {KeyExchange}
 */
export function createECDHEPSKKeyExchange() {
  const exchange = new KeyExchange();

  exchange.id = kxTypes.ECDHE_PSK;
  exchange.name = "ECDHE_PSK";

  exchange.signType = signTypes.ECDHE;
  exchange.keyType = keyTypes.PSK;

  return exchange;
}
Copilot
Sent by Copilot:
Here’s the Dart equivalent of your JavaScript code:

Dart

class SignTypes {
  static const int NULL = 0;
  static const int ECDHE = 1;
}

class KeyTypes {
  static const int NULL = 0;
  static const int RSA = 1;
  static const int ECDSA = 2;
  static const int PSK = 3;
}

class KxTypes {
  static const int NULL = 0;
  static const int RSA = 1;
  static const int ECDHE_RSA = 2;
  static const int ECDHE_ECDSA = 3;
  static const int PSK = 4;
  static const int ECDHE_PSK = 5;
}

class KeyExchange {
  int id = 0;
  String? name;
  int? signType;
  int? keyType;

  @override
  String toString() {
    return name ?? '';
  }
}

KeyExchange createRSAKeyExchange() {
  final exchange = KeyExchange()
    ..id = KxTypes.RSA
    ..name = 'RSA'
    ..keyType = KeyTypes.RSA;

  return exchange;
}

KeyExchange createECDHERSAKeyExchange() {
  final exchange = KeyExchange()
    ..id = KxTypes.ECDHE_RSA
    ..name = 'ECDHE_RSA'
    ..signType = SignTypes.ECDHE
    ..keyType = KeyTypes.RSA;

  return exchange;
}

KeyExchange createECDHEECDSAKeyExchange() {
  final exchange = KeyExchange()
    ..id = KxTypes.ECDHE_ECDSA
    ..name = 'ECDHE_ECDSA'
    ..signType = SignTypes.ECDHE
    ..keyType = KeyTypes.ECDSA;

  return exchange;
}

KeyExchange createNULLKeyExchange() {
  final exchange = KeyExchange()
    ..id = KxTypes.NULL
    ..name = 'NULL'
    ..signType = SignTypes.NULL
    ..keyType = KeyTypes.NULL;

  return exchange;
}

KeyExchange createPSKKeyExchange() {
  final exchange = KeyExchange()
    ..id = KxTypes.PSK
    ..name = 'PSK'
    ..signType = SignTypes.NULL
    ..keyType = KeyTypes.PSK;

  return exchange;
}

KeyExchange createECDHEPSKKeyExchange() {
  final exchange = KeyExchange()
    ..id = KxTypes.ECDHE_PSK
    ..name = 'ECDHE_PSK'
    ..signType = SignTypes.ECDHE
    ..keyType = KeyTypes.PSK;

  return exchange;
}
AI-generated code. Review and use carefully. More info on FAQ.
This Dart code mirrors the structure and functionality of your JavaScript code. If you need any further adjustments or have any questions, feel free to ask!

Learn more

1

codeconvert.ai
2

codingfleet.com
3

quicktype.io
4

codedocumentation.app
You
Sent by you:
convert the following code to dart as well: import { ec } from "elliptic";
import * as nacl from "tweetnacl";

import { NamedCurveAlgorithm, NamedCurveAlgorithms } from "./const";

export interface NamedCurveKeyPair {
  curve: NamedCurveAlgorithms;
  publicKey: Buffer;
  privateKey: Buffer;
}

export function generateKeyPair(
  namedCurve: NamedCurveAlgorithms
): NamedCurveKeyPair {
  switch (namedCurve) {
    case NamedCurveAlgorithm.secp256r1_23: {
      const elliptic = new ec("p256");
      const key = elliptic.genKeyPair();
      const privateKey = key.getPrivate().toBuffer("be");
      const publicKey = Buffer.from(key.getPublic().encode("array", false));

      return {
        curve: namedCurve,
        privateKey,
        publicKey,
      };
    }
    case NamedCurveAlgorithm.x25519_29: {
      const keys = nacl.box.keyPair();

      return {
        curve: namedCurve,
        privateKey: Buffer.from(keys.secretKey.buffer),
        publicKey: Buffer.from(keys.publicKey.buffer),
      };
    }
    default:
      throw new Error();
  }
}
Copilot
Sent by Copilot:
Here’s the Dart equivalent of your JavaScript code:

Dart

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
      final privateKey = (keyPair.privateKey as pc.ECPrivateKey).d!.toByteArray();
      final publicKey = (keyPair.publicKey as pc.ECPublicKey).Q!.getEncoded(false);
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
AI-generated code. Review and use carefully. More info on FAQ.
This Dart code uses the pointycastle package for elliptic curve operations and the tweetnacl package for X25519 key generation. If you have any questions or need further adjustments, feel free to ask!

Learn more

1

codeconvert.ai
2

codingfleet.com
3

quicktype.io
4

codedocumentation.app
You
Sent by you:
Convert to dart as well: import { createDecode } from "binary-data";
import { createHash, createHmac } from "crypto";
import { ec } from "elliptic";
import * as nacl from "tweetnacl";

import { NamedCurveAlgorithm, NamedCurveAlgorithms } from "./const";

export function prfPreMasterSecret(
  publicKey: Buffer,
  privateKey: Buffer,
  curve: NamedCurveAlgorithms
) {
  switch (curve) {
    case NamedCurveAlgorithm.secp256r1_23:
      const elliptic = new ec("p256"); // aka secp256r1
      const pub = elliptic.keyFromPublic(publicKey).getPublic();
      const priv = elliptic.keyFromPrivate(privateKey).getPrivate();
      const res = pub.mul(priv);
      const secret = Buffer.from(res.encode("array", false)).slice(1, 33);
      return secret;
    case NamedCurveAlgorithm.x25519_29:
      return Buffer.from(nacl.scalarMult(privateKey, publicKey));
    default:
      throw new Error();
  }
}

export function hmac(algorithm: string, secret: Buffer, data: Buffer) {
  const hash = createHmac(algorithm, secret);
  hash.update(data);
  return hash.digest();
}

export function prfPHash(
  secret: Buffer,
  seed: Buffer,
  requestedLegth: number,
  algorithm = "sha256"
) {
  const totalLength = requestedLegth;
  const bufs: Buffer[] = [];
  let Ai = seed; // A0

  do {
    Ai = hmac(algorithm, secret, Ai); // A(i) = HMAC(secret, A(i-1))
    const output = hmac(algorithm, secret, Buffer.concat([Ai, seed]));

    bufs.push(output);
    requestedLegth -= output.length; // eslint-disable-line no-param-reassign
  } while (requestedLegth > 0);

  return Buffer.concat(bufs, totalLength);
}

export function prfMasterSecret(
  preMasterSecret: Buffer,
  clientRandom: Buffer,
  serverRandom: Buffer
) {
  const seed = Buffer.concat([
    Buffer.from("master secret"),
    clientRandom,
    serverRandom,
  ]);
  return prfPHash(preMasterSecret, seed, 48);
}

export function prfExtendedMasterSecret(
  preMasterSecret: Buffer,
  handshakes: Buffer
) {
  const sessionHash = hash("sha256", handshakes);
  const label = "extended master secret";
  return prfPHash(
    preMasterSecret,
    Buffer.concat([Buffer.from(label), sessionHash]),
    48
  );
}

export function exportKeyingMaterial(
  label: string,
  length: number,
  masterSecret: Buffer,
  localRandom: Buffer,
  remoteRandom: Buffer,
  isClient: boolean
) {
  const clientRandom = isClient ? localRandom : remoteRandom;
  const serverRandom = isClient ? remoteRandom : localRandom;
  const seed = Buffer.concat([Buffer.from(label), clientRandom, serverRandom]);
  return prfPHash(masterSecret, seed, length);
}

export function hash(algorithm: string, data: Buffer) {
  return createHash(algorithm).update(data).digest();
}

export function prfVerifyData(
  masterSecret: Buffer,
  handshakes: Buffer,
  label: string,
  size = 12
) {
  const bytes = hash("sha256", handshakes);
  return prfPHash(
    masterSecret,
    Buffer.concat([Buffer.from(label), bytes]),
    size
  );
}

export function prfVerifyDataClient(masterSecret: Buffer, handshakes: Buffer) {
  return prfVerifyData(masterSecret, handshakes, "client finished");
}

export function prfVerifyDataServer(masterSecret: Buffer, handshakes: Buffer) {
  return prfVerifyData(masterSecret, handshakes, "server finished");
}

export function prfEncryptionKeys(
  masterSecret: Buffer,
  clientRandom: Buffer,
  serverRandom: Buffer,
  prfKeyLen: number,
  prfIvLen: number,
  prfNonceLen: number,
  algorithm = "sha256"
) {
  const size = prfKeyLen * 2 + prfIvLen * 2;
  const secret = masterSecret;
  const seed = Buffer.concat([serverRandom, clientRandom]);
  const keyBlock = prfPHash(
    secret,
    Buffer.concat([Buffer.from("key expansion"), seed]),
    size,
    algorithm
  );
  const stream = createDecode(keyBlock);

  const clientWriteKey = stream.readBuffer(prfKeyLen);
  const serverWriteKey = stream.readBuffer(prfKeyLen);

  const clientNonceImplicit = stream.readBuffer(prfIvLen);
  const serverNonceImplicit = stream.readBuffer(prfIvLen);

  const clientNonce = Buffer.alloc(prfNonceLen, 0);
  const serverNonce = Buffer.alloc(prfNonceLen, 0);

  clientNonceImplicit.copy(clientNonce, 0);
  serverNonceImplicit.copy(serverNonce, 0);

  return { clientWriteKey, serverWriteKey, clientNonce, serverNonce };
}
Copilot
Sent by Copilot:
Here’s the Dart equivalent of your JavaScript code:

Dart

import 'dart:convert';
import 'dart:typed_data';
import 'package:pointycastle/export.dart' as pc;
import 'package:tweetnacl/tweetnacl.dart' as nacl;

class NamedCurveAlgorithm {
  static const int secp256r1_23 = 23;
  static const int x25519_29 = 29;
}

typedef NamedCurveAlgorithms = int;

Uint8List prfPreMasterSecret(Uint8List publicKey, Uint8List privateKey, NamedCurveAlgorithms curve) {
  switch (curve) {
    case NamedCurveAlgorithm.secp256r1_23:
      final elliptic = pc.ECDomainParameters('prime256v1');
      final pub = elliptic.curve.decodePoint(publicKey);
      final priv = pc.ECPrivateKey(BigInt.parse(hex.encode(privateKey), radix: 16), elliptic);
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

Uint8List prfPHash(Uint8List secret, Uint8List seed, int requestedLength, [String algorithm = 'SHA-256']) {
  final totalLength = requestedLength;
  final bufs = <Uint8List>[];
  var Ai = seed;

  do {
    Ai = hmac(algorithm, secret, Ai);
    final output = hmac(algorithm, secret, Uint8List.fromList(Ai + seed));
    bufs.add(output);
    requestedLength -= output.length;
  } while (requestedLength > 0);

  return Uint8List.fromList(bufs.expand((x) => x).toList()).sublist(0, totalLength);
}

Uint8List prfMasterSecret(Uint8List preMasterSecret, Uint8List clientRandom, Uint8List serverRandom) {
  final seed = Uint8List.fromList(utf8.encode('master secret') + clientRandom + serverRandom);
  return prfPHash(preMasterSecret, seed, 48);
}

Uint8List prfExtendedMasterSecret(Uint8List preMasterSecret, Uint8List handshakes) {
  final sessionHash = hash('SHA-256', handshakes);
  final label = 'extended master secret';
  return prfPHash(preMasterSecret, Uint8List.fromList(utf8.encode(label) + sessionHash), 48);
}

Uint8List exportKeyingMaterial(String label, int length, Uint8List masterSecret, Uint8List localRandom, Uint8List remoteRandom, bool isClient) {
  final clientRandom = isClient ? localRandom : remoteRandom;
  final serverRandom = isClient ? remoteRandom : localRandom;
  final seed = Uint8List.fromList(utf8.encode(label) + clientRandom + serverRandom);
  return prfPHash(masterSecret, seed, length);
}

Uint8List hash(String algorithm, Uint8List data) {
  final digest = pc.Digest(algorithm);
  digest.update(data, 0, data.length);
  final out = Uint8List(digest.digestSize);
  digest.doFinal(out, 0);
  return out;
}

Uint8List prfVerifyData(Uint8List masterSecret, Uint8List handshakes, String label, [int size = 12]) {
  final bytes = hash('SHA-256', handshakes);
  return prfPHash(masterSecret, Uint8List.fromList(utf8.encode(label) + bytes), size);
}

Uint8List prfVerifyDataClient(Uint8List masterSecret, Uint8List handshakes) {
  return prfVerifyData(masterSecret, handshakes, 'client finished');
}

Uint8List prfVerifyDataServer(Uint8List masterSecret, Uint8List handshakes) {
  return prfVerifyData(masterSecret, handshakes, 'server finished');
}

Map<String, Uint8List> prfEncryptionKeys(Uint8List masterSecret, Uint8List clientRandom, Uint8List serverRandom, int prfKeyLen, int prfIvLen, int prfNonceLen, [String algorithm = 'SHA-256']) {
  final size = prfKeyLen * 2 + prfIvLen * 2;
  final secret = masterSecret;
  final seed = Uint8List.fromList(serverRandom + clientRandom);
  final keyBlock = prfPHash(secret, Uint8List.fromList(utf8.encode('key expansion') + seed), size, algorithm);
  final stream = ByteData.sublistView(keyBlock);

  final clientWriteKey = stream.buffer.asUint8List(0, prfKeyLen);
  final serverWriteKey = stream.buffer.asUint8List(prfKeyLen, prfKeyLen);

  final clientNonceImplicit = stream.buffer.asUint8List(prfKeyLen * 2, prfIvLen);
  final serverNonceImplicit = stream.buffer.asUint8List(prfKeyLen * 2 + prfIvLen, prfIvLen);

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
AI-generated code. Review and use carefully. More info on FAQ.
This Dart code mirrors the structure and functionality of your JavaScript code. If you have any questions or need further adjustments, feel free to ask!

Learn more

1

codeconvert.ai
2

codingfleet.com
3

quicktype.io
4

codedocumentation.app
You
Sent by you:
Convert to dart ase well: import * as crypto from "crypto";

/**
 * Culculates HMAC using provided hash.
 * @param {string} algorithm - Hash algorithm.
 * @param {Buffer} secret - Hmac seed.
 * @param {Buffer} data - Input data.
 * @returns {Buffer}
 */
function hmac(algorithm: string, secret: Buffer, data: Buffer) {
  const hash = crypto.createHmac(algorithm, secret);
  hash.update(data);
  return hash.digest();
}

/**
 * A data expansion function for PRF.
 * @param {number} bytes - The number of bytes required by PRF.
 * @param {string} algorithm - Hmac hash algorithm.
 * @param {Buffer} secret - Hmac secret.
 * @param {Buffer} seed - Input data.
 * @returns {Buffer}
 */
function pHash(bytes: number, algorithm: string, secret: Buffer, seed: Buffer) {
  const totalLength = bytes;
  const bufs: Buffer[] = [];
  let Ai = seed; // A0

  do {
    Ai = hmac(algorithm, secret, Ai); // A(i) = HMAC(secret, A(i-1))
    const output = hmac(algorithm, secret, Buffer.concat([Ai, seed]));

    bufs.push(output);
    bytes -= output.length; // eslint-disable-line no-param-reassign
  } while (bytes > 0);

  return Buffer.concat(bufs, totalLength);
}

export { hmac, pHash };
Copilot
Sent by Copilot:
Here’s the Dart equivalent of your JavaScript code:

Dart

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

  return Uint8List.fromList(bufs.expand((x) => x).toList()).sublist(0, totalLength);
}

export { hmac, pHash };
AI-generated code. Review and use carefully. More info on FAQ.
This Dart code mirrors the structure and functionality of your JavaScript code. If you have any questions or need further adjustments, feel free to ask!

Learn more

1

codeconvert.ai
2

codingfleet.com
3

quicktype.io
4

codedocumentation.app
You
Sent by you:
Convert to dart as well: import {
  createECDHEECDSAKeyExchange,
  createECDHEPSKKeyExchange,
  createECDHERSAKeyExchange,
  createPSKKeyExchange,
  createRSAKeyExchange,
  KeyExchange,
} from "./key-exchange";
import AEADCipher from "./suites/aead";

const cipherSuites = {
  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: 0xc02b,
  TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: 0xc02c,
  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: 0xc02f,
  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: 0xc030,
  TLS_RSA_WITH_AES_128_GCM_SHA256: 0x009c,
  TLS_RSA_WITH_AES_256_GCM_SHA384: 0x009d,
  TLS_PSK_WITH_AES_128_GCM_SHA256: 0x00a8,
  TLS_PSK_WITH_AES_256_GCM_SHA384: 0x00a9,
  TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256: 0xd001,
  TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384: 0xd002,
  TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256: 0xccac,
  TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: 0xcca9,
  TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: 0xcca8,
  TLS_PSK_WITH_CHACHA20_POLY1305_SHA256: 0xccab,
};

const AEAD_AES_128_GCM = {
  K_LEN: 16, // Length of a key.
  N_MIN: 12, // Min nonce length.
  N_MAX: 12, // Max nonce length.
  P_MAX: 2 ** 36 - 31, // Max length of a plaintext.

  // Max safe int in js is 2 ** 53. So, use this value
  // instead of 2 ** 61 as described in rfc5116.
  A_MAX: 2 ** 53 - 1, // Max length of an additional data.
  C_MAX: 2 ** 36 - 15, // Cipher text length.
};

const AEAD_AES_256_GCM = {
  K_LEN: 32, // Length of a key.
  N_MIN: 12, // Min nonce length.
  N_MAX: 12, // Max nonce length.
  P_MAX: 2 ** 36 - 31, // Max length of a plaintext.

  // Note: see above.
  A_MAX: 2 ** 53 - 1, // Max length of an additional data.
  C_MAX: 2 ** 36 - 15, // Cipher text length.
};

const RSA_KEY_EXCHANGE = createRSAKeyExchange();
const ECDHE_RSA_KEY_EXCHANGE = createECDHERSAKeyExchange();
const ECDHE_ECDSA_KEY_EXCHANGE = createECDHEECDSAKeyExchange();
const PSK_KEY_EXCHANGE = createPSKKeyExchange();
const ECDHE_PSK_KEY_EXCHANGE = createECDHEPSKKeyExchange();

/**
 * Convert cipher value to cipher instance.
 * @param {number} cipher
 */
export function createCipher(cipher: number) {
  switch (cipher) {
    case cipherSuites.TLS_RSA_WITH_AES_128_GCM_SHA256:
      return createAEADCipher(
        cipherSuites.TLS_RSA_WITH_AES_128_GCM_SHA256,
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "aes-128-gcm",
        RSA_KEY_EXCHANGE,
        AEAD_AES_128_GCM
      );
    case cipherSuites.TLS_RSA_WITH_AES_256_GCM_SHA384:
      return createAEADCipher(
        cipherSuites.TLS_RSA_WITH_AES_256_GCM_SHA384,
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "aes-256-gcm",
        RSA_KEY_EXCHANGE,
        AEAD_AES_256_GCM,
        "sha384"
      );
    case cipherSuites.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
      return createAEADCipher(
        cipherSuites.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "aes-128-gcm",
        ECDHE_RSA_KEY_EXCHANGE,
        AEAD_AES_128_GCM
      );
    case cipherSuites.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
      return createAEADCipher(
        cipherSuites.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "aes-256-gcm",
        ECDHE_RSA_KEY_EXCHANGE,
        AEAD_AES_256_GCM,
        "sha384"
      );
    case cipherSuites.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
      return createAEADCipher(
        cipherSuites.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "aes-128-gcm",
        ECDHE_ECDSA_KEY_EXCHANGE,
        AEAD_AES_128_GCM
      );
    case cipherSuites.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
      return createAEADCipher(
        cipherSuites.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "aes-256-gcm",
        ECDHE_ECDSA_KEY_EXCHANGE,
        AEAD_AES_256_GCM,
        "sha384"
      );
    case cipherSuites.TLS_PSK_WITH_AES_128_GCM_SHA256:
      return createAEADCipher(
        cipherSuites.TLS_PSK_WITH_AES_128_GCM_SHA256,
        "TLS_PSK_WITH_AES_128_GCM_SHA256",
        "aes-128-gcm",
        PSK_KEY_EXCHANGE,
        AEAD_AES_128_GCM,
        "sha256"
      );
    case cipherSuites.TLS_PSK_WITH_AES_256_GCM_SHA384:
      return createAEADCipher(
        cipherSuites.TLS_PSK_WITH_AES_256_GCM_SHA384,
        "TLS_PSK_WITH_AES_256_GCM_SHA384",
        "aes-256-gcm",
        PSK_KEY_EXCHANGE,
        AEAD_AES_256_GCM,
        "sha384"
      );
    case cipherSuites.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256:
      return createAEADCipher(
        cipherSuites.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256,
        "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256",
        "aes-128-gcm",
        ECDHE_PSK_KEY_EXCHANGE,
        AEAD_AES_128_GCM,
        "sha256"
      );
    case cipherSuites.TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384:
      return createAEADCipher(
        cipherSuites.TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384,
        "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384",
        "aes-256-gcm",
        ECDHE_PSK_KEY_EXCHANGE,
        AEAD_AES_256_GCM,
        "sha384"
      );
    default:
      break;
  }

  return null as any as AEADCipher;
}

/**
 * @param {number} id An internal id of cipher suite.
 * @param {string} name A valid cipher suite name.
 * @param {string} block A valid nodejs cipher name.
 * @param {KeyExchange} kx Key exchange type.
 * @param {Object} constants Cipher specific constants.
 * @param {string} hash
 * @returns {AEADCipher}
 */
export function createAEADCipher(
  id: number,
  name: string,
  block: string,
  kx: KeyExchange,
  constants: { K_LEN: number; N_MAX: number },
  hash = "sha256"
) {
  const cipher = new AEADCipher();

  cipher.id = id;
  cipher.name = name;
  cipher.blockAlgorithm = block;
  cipher.kx = kx;
  cipher.hashAlgorithm = hash;

  cipher.keyLength = constants.K_LEN;
  cipher.nonceLength = constants.N_MAX;

  // RFC5288, sec. 3
  cipher.nonceImplicitLength = 4;
  cipher.nonceExplicitLength = 8;

  cipher.ivLength = cipher.nonceImplicitLength;

  cipher.authTagLength = 16;

  return cipher;
}
Copilot
Sent by Copilot:
Here’s the Dart equivalent of your JavaScript code:

Dart

import 'package:pointycastle/export.dart' as pc;
import 'key_exchange.dart';
import 'aead_cipher.dart';

class CipherSuites {
  static const int TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02b;
  static const int TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xc02c;
  static const int TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xc02f;
  static const int TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xc030;
  static const int TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009c;
  static const int TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009d;
  static const int TLS_PSK_WITH_AES_128_GCM_SHA256 = 0x00a8;
  static const int TLS_PSK_WITH_AES_256_GCM_SHA384 = 0x00a9;
  static const int TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 = 0xd001;
  static const int TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 = 0xd002;
  static const int TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xccac;
  static const int TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca9;
  static const int TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca8;
  static const int TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xccab;
}

class AEAD_AES_128_GCM {
  static const int K_LEN = 16; // Length of a key.
  static const int N_MIN = 12; // Min nonce length.
  static const int N_MAX = 12; // Max nonce length.
  static const int P_MAX = (1 << 36) - 31; // Max length of a plaintext.
  static const int A_MAX = (1 << 53) - 1; // Max length of an additional data.
  static const int C_MAX = (1 << 36) - 15; // Cipher text length.
}

class AEAD_AES_256_GCM {
  static const int K_LEN = 32; // Length of a key.
  static const int N_MIN = 12; // Min nonce length.
  static const int N_MAX = 12; // Max nonce length.
  static const int P_MAX = (1 << 36) - 31; // Max length of a plaintext.
  static const int A_MAX = (1 << 53) - 1; // Max length of an additional data.
  static const int C_MAX = (1 << 36) - 15; // Cipher text length.
}

final rsaKeyExchange = createRSAKeyExchange();
final ecdheRsaKeyExchange = createECDHERSAKeyExchange();
final ecdheEcdsaKeyExchange = createECDHEECDSAKeyExchange();
final pskKeyExchange = createPSKKeyExchange();
final ecdhePskKeyExchange = createECDHEPSKKeyExchange();

AEADCipher createCipher(int cipher) {
  switch (cipher) {
    case CipherSuites.TLS_RSA_WITH_AES_128_GCM_SHA256:
      return createAEADCipher(
        CipherSuites.TLS_RSA_WITH_AES_128_GCM_SHA256,
        'TLS_RSA_WITH_AES_128_GCM_SHA256',
        'aes-128-gcm',
        rsaKeyExchange,
        AEAD_AES_128_GCM,
      );
    case CipherSuites.TLS_RSA_WITH_AES_256_GCM_SHA384:
      return createAEADCipher(
        CipherSuites.TLS_RSA_WITH_AES_256_GCM_SHA384,
        'TLS_RSA_WITH_AES_256_GCM_SHA384',
        'aes-256-gcm',
        rsaKeyExchange,
        AEAD_AES_256_GCM,
        'sha384',
      );
    case CipherSuites.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
      return createAEADCipher(
        CipherSuites.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
        'aes-128-gcm',
        ecdheRsaKeyExchange,
        AEAD_AES_128_GCM,
      );
    case CipherSuites.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
      return createAEADCipher(
        CipherSuites.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        'aes-256-gcm',
        ecdheRsaKeyExchange,
        AEAD_AES_256_GCM,
        'sha384',
      );
    case CipherSuites.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
      return createAEADCipher(
        CipherSuites.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
        'aes-128-gcm',
        ecdheEcdsaKeyExchange,
        AEAD_AES_128_GCM,
      );
    case CipherSuites.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
      return createAEADCipher(
        CipherSuites.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
        'aes-256-gcm',
        ecdheEcdsaKeyExchange,
        AEAD_AES_256_GCM,
        'sha384',
      );
    case CipherSuites.TLS_PSK_WITH_AES_128_GCM_SHA256:
      return createAEADCipher(
        CipherSuites.TLS_PSK_WITH_AES_128_GCM_SHA256,
        'TLS_PSK_WITH_AES_128_GCM_SHA256',
        'aes-128-gcm',
        pskKeyExchange,
        AEAD_AES_128_GCM,
        'sha256',
      );
    case CipherSuites.TLS_PSK_WITH_AES_256_GCM_SHA384:
      return createAEADCipher(
        CipherSuites.TLS_PSK_WITH_AES_256_GCM_SHA384,
        'TLS_PSK_WITH_AES_256_GCM_SHA384',
        'aes-256-gcm',
        pskKeyExchange,
        AEAD_AES_256_GCM,
        'sha384',
      );
    case CipherSuites.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256:
      return createAEADCipher(
        CipherSuites.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256,
        'TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256',
        'aes-128-gcm',
        ecdhePskKeyExchange,
        AEAD_AES_128_GCM,
        'sha256',
      );
    case CipherSuites.TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384:
      return createAEADCipher(
        CipherSuites.TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384,
        'TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384',
        'aes-256-gcm',
        ecdhePskKeyExchange,
        AEAD_AES_256_GCM,
        'sha384',
      );
    default:
      throw Exception('Unsupported cipher suite');
  }
}

AEADCipher createAEADCipher(
  int id,
  String name,
  String block,
  KeyExchange kx,
  dynamic constants, [
  String hash = 'sha256',
]) {
  final cipher = AEADCipher();

  cipher.id = id;
  cipher.name = name;
  cipher.blockAlgorithm = block;
  cipher.kx = kx;
  cipher.hashAlgorithm = hash;

  cipher.keyLength = constants.K_LEN;
  cipher.nonceLength = constants.N_MAX;

  // RFC5288, sec. 3
  cipher.nonceImplicitLength = 4;
  cipher.nonceExplicitLength = 8;

  cipher.ivLength = cipher.nonceImplicitLength;

  cipher.authTagLength = 16;

  return cipher;
}
AI-generated code. Review and use carefully. More info on FAQ.
This Dart code mirrors the structure and functionality of your JavaScript code. If you have any questions or need further adjustments, feel free to ask!

Learn more

1

codeconvert.ai
2

codingfleet.com
3

quicktype.io
4

codedocumentation.app
5
github.com
+3 more
You
Sent by you:
Convert to dart: import { KeyExchange } from "../key-exchange";

export type CipherHeader = {
  type: number;
  version: number;
  epoch: number;
  sequenceNumber: number;
};

export const SessionType = {
  CLIENT: 1,
  SERVER: 2,
} as const;
export type SessionTypes = typeof SessionType[keyof typeof SessionType];

export default abstract class AbstractCipher {
  id = 0;
  name?: string;
  hashAlgorithm?: string;
  verifyDataLength = 12;

  blockAlgorithm?: string;
  kx?: KeyExchange;

  /**
   * Init cipher.
   * @abstract
   */
  init(...args: any) {
    throw new Error("not implemented");
  }

  /**
   * Encrypts data.
   * @abstract
   */
  encrypt(...args: any): Buffer {
    throw new Error("not implemented");
  }

  /**
   * Decrypts data.
   * @abstract
   */
  decrypt(...args: any): Buffer {
    throw new Error("not implemented");
  }

  /**
   * @returns {string}
   */
  toString() {
    return this.name;
  }
}
Copilot
Sent by Copilot:
Here’s the Dart equivalent of your JavaScript code:

Dart

import 'key_exchange.dart';

class CipherHeader {
  final int type;
  final int version;
  final int epoch;
  final int sequenceNumber;

  CipherHeader({
    required this.type,
    required this.version,
    required this.epoch,
    required this.sequenceNumber,
  });
}

class SessionType {
  static const int CLIENT = 1;
  static const int SERVER = 2;
}

typedef SessionTypes = int;

abstract class AbstractCipher {
  int id = 0;
  String? name;
  String? hashAlgorithm;
  int verifyDataLength = 12;

  String? blockAlgorithm;
  KeyExchange? kx;

  /**
   * Init cipher.
   * @abstract
   */
  void init([dynamic args]) {
    throw UnimplementedError('not implemented');
  }

  /**
   * Encrypts data.
   * @abstract
   */
  Uint8List encrypt([dynamic args]) {
    throw UnimplementedError('not implemented');
  }

  /**
   * Decrypts data.
   * @abstract
   */
  Uint8List decrypt([dynamic args]) {
    throw UnimplementedError('not implemented');
  }

  @override
  String toString() {
    return name ?? '';
  }
}
AI-generated code. Review and use carefully. More info on FAQ.
This Dart code mirrors the structure and functionality of your JavaScript code. If you have any questions or need further adjustments, feel free to ask!

Learn more

1

codeconvert.ai
2

codingfleet.com
3

quicktype.io
4

codedocumentation.app
You
Sent by you:
Convert to dart as well: import * as crypto from "crypto";
import debug from "debug";

import { dumpBuffer, getObjectSummary } from "../../helper";
import { prfEncryptionKeys } from "../prf";
import Cipher, { CipherHeader, SessionType, SessionTypes } from "./abstract";
const {
  createDecode,
  encode,
  types: { uint8, uint16be, uint48be },
} = require("binary-data");

const ContentType = uint8;
const ProtocolVersion = uint16be;

const AEADAdditionalData = {
  epoch: uint16be,
  sequence: uint48be,
  type: ContentType,
  version: ProtocolVersion,
  length: uint16be,
};

const err = debug(
  "werift-dtls : packages/dtls/src/cipher/suites/aead.ts : err"
);

/**
 * This class implements AEAD cipher family.
 */
export default class AEADCipher extends Cipher {
  keyLength = 0;
  nonceLength = 0;
  ivLength = 0;
  authTagLength = 0;

  nonceImplicitLength = 0;
  nonceExplicitLength = 0;

  clientWriteKey?: Buffer;
  serverWriteKey?: Buffer;

  clientNonce?: Buffer;
  serverNonce?: Buffer;

  constructor() {
    super();
  }

  get summary() {
    return getObjectSummary(this);
  }

  init(masterSecret: Buffer, serverRandom: Buffer, clientRandom: Buffer) {
    const keys = prfEncryptionKeys(
      masterSecret,
      clientRandom,
      serverRandom,
      this.keyLength,
      this.ivLength,
      this.nonceLength,
      this.hashAlgorithm
    );

    this.clientWriteKey = keys.clientWriteKey;
    this.serverWriteKey = keys.serverWriteKey;
    this.clientNonce = keys.clientNonce;
    this.serverNonce = keys.serverNonce;
  }

  /**
   * Encrypt message.
   */
  encrypt(type: SessionTypes, data: Buffer, header: CipherHeader) {
    const isClient = type === SessionType.CLIENT;
    const iv = isClient ? this.clientNonce : this.serverNonce;
    const writeKey = isClient ? this.clientWriteKey : this.serverWriteKey;
    if (!iv || !writeKey) throw new Error();

    iv.writeUInt16BE(header.epoch, this.nonceImplicitLength);
    iv.writeUIntBE(header.sequenceNumber, this.nonceImplicitLength + 2, 6);

    const explicitNonce = iv.slice(this.nonceImplicitLength);

    const additionalData = {
      epoch: header.epoch,
      sequence: header.sequenceNumber,
      type: header.type,
      version: header.version,
      length: data.length,
    };

    const additionalBuffer = encode(additionalData, AEADAdditionalData).slice();

    const cipher = crypto.createCipheriv(
      this.blockAlgorithm as crypto.CipherCCMTypes,
      writeKey,
      iv,
      {
        authTagLength: this.authTagLength,
      }
    );

    cipher.setAAD(additionalBuffer, {
      plaintextLength: data.length,
    });

    const headPart = cipher.update(data);
    const finalPart = cipher.final();
    const authTag = cipher.getAuthTag();

    return Buffer.concat([explicitNonce, headPart, finalPart, authTag]);
  }

  /**
   * Decrypt message.
   */
  decrypt(type: SessionTypes, data: Buffer, header: CipherHeader) {
    const isClient = type === SessionType.CLIENT;
    const iv = isClient ? this.serverNonce : this.clientNonce;
    const writeKey = isClient ? this.serverWriteKey : this.clientWriteKey;
    if (!iv || !writeKey) throw new Error();

    const final = createDecode(data);

    const explicitNonce = final.readBuffer(this.nonceExplicitLength);
    explicitNonce.copy(iv, this.nonceImplicitLength);

    const encrypted = final.readBuffer(final.length - this.authTagLength);
    const authTag = final.readBuffer(this.authTagLength);

    const additionalData = {
      epoch: header.epoch,
      sequence: header.sequenceNumber,
      type: header.type,
      version: header.version,
      length: encrypted.length,
    };

    const additionalBuffer = encode(additionalData, AEADAdditionalData).slice();

    const decipher = crypto.createDecipheriv(
      this.blockAlgorithm as crypto.CipherCCMTypes,
      writeKey,
      iv,
      {
        authTagLength: this.authTagLength,
      }
    );

    decipher.setAuthTag(authTag);
    decipher.setAAD(additionalBuffer, {
      plaintextLength: encrypted.length,
    });

    const headPart = decipher.update(encrypted);
    try {
      const finalPart = decipher.final();
      return finalPart.length > 0
        ? Buffer.concat([headPart, finalPart])
        : headPart;
    } catch (error) {
      err(
        "decrypt failed",
        error,
        type,
        dumpBuffer(data),
        header,
        this.summary
      );
      throw error;
    }
  }
}
Copilot
Sent by Copilot:
Here’s the Dart equivalent of your JavaScript code:

Dart

import 'dart:typed_data';
import 'package:pointycastle/export.dart' as pc;
import 'package:logging/logging.dart';
import 'helper.dart';
import 'prf.dart';
import 'abstract.dart';

final log = Logger('AEADCipher');

class ContentType {
  static const int value = 8;
}

class ProtocolVersion {
  static const int value = 16;
}

class AEADAdditionalData {
  final int epoch;
  final int sequence;
  final int type;
  final int version;
  final int length;

  AEADAdditionalData({
    required this.epoch,
    required this.sequence,
    required this.type,
    required this.version,
    required this.length,
  });

  Uint8List encode() {
    final buffer = ByteData(13);
    buffer.setUint16(0, epoch);
    buffer.setUint48(2, sequence);
    buffer.setUint8(8, type);
    buffer.setUint16(9, version);
    buffer.setUint16(11, length);
    return buffer.buffer.asUint8List();
  }
}

class AEADCipher extends AbstractCipher {
  int keyLength = 0;
  int nonceLength = 0;
  int ivLength = 0;
  int authTagLength = 0;

  int nonceImplicitLength = 0;
  int nonceExplicitLength = 0;

  Uint8List? clientWriteKey;
  Uint8List? serverWriteKey;

  Uint8List? clientNonce;
  Uint8List? serverNonce;

  @override
  void init(Uint8List masterSecret, Uint8List serverRandom, Uint8List clientRandom) {
    final keys = prfEncryptionKeys(
      masterSecret,
      clientRandom,
      serverRandom,
      keyLength,
      ivLength,
      nonceLength,
      hashAlgorithm,
    );

    clientWriteKey = keys['clientWriteKey'];
    serverWriteKey = keys['serverWriteKey'];
    clientNonce = keys['clientNonce'];
    serverNonce = keys['serverNonce'];
  }

  @override
  Uint8List encrypt(SessionTypes type, Uint8List data, CipherHeader header) {
    final isClient = type == SessionType.CLIENT;
    final iv = isClient ? clientNonce : serverNonce;
    final writeKey = isClient ? clientWriteKey : serverWriteKey;
    if (iv == null || writeKey == null) throw Exception('IV or WriteKey is null');

    final buffer = ByteData.view(iv.buffer);
    buffer.setUint16(nonceImplicitLength, header.epoch);
    buffer.setUint48(nonceImplicitLength + 2, header.sequenceNumber);

    final explicitNonce = iv.sublist(nonceImplicitLength);

    final additionalData = AEADAdditionalData(
      epoch: header.epoch,
      sequence: header.sequenceNumber,
      type: header.type,
      version: header.version,
      length: data.length,
    );

    final additionalBuffer = additionalData.encode();

    final cipher = pc.GCMBlockCipher(pc.AESEngine())
      ..init(
        true,
        pc.AEADParameters(
          pc.KeyParameter(writeKey),
          authTagLength * 8,
          iv,
          additionalBuffer,
        ),
      );

    final output = Uint8List(cipher.getOutputSize(data.length));
    final len = cipher.processBytes(data, 0, data.length, output, 0);
    cipher.doFinal(output, len);

    return Uint8List.fromList(explicitNonce + output);
  }

  @override
  Uint8List decrypt(SessionTypes type, Uint8List data, CipherHeader header) {
    final isClient = type == SessionType.CLIENT;
    final iv = isClient ? serverNonce : clientNonce;
    final writeKey = isClient ? serverWriteKey : clientWriteKey;
    if (iv == null || writeKey == null) throw Exception('IV or WriteKey is null');

    final explicitNonce = data.sublist(0, nonceExplicitLength);
    iv.setRange(nonceImplicitLength, iv.length, explicitNonce);

    final encrypted = data.sublist(nonceExplicitLength, data.length - authTagLength);
    final authTag = data.sublist(data.length - authTagLength);

    final additionalData = AEADAdditionalData(
      epoch: header.epoch,
      sequence: header.sequenceNumber,
      type: header.type,
      version: header.version,
      length: encrypted.length,
    );

    final additionalBuffer = additionalData.encode();

    final cipher = pc.GCMBlockCipher(pc.AESEngine())
      ..init(
        false,
        pc.AEADParameters(
          pc.KeyParameter(writeKey),
          authTagLength * 8,
          iv,
          additionalBuffer,
        ),
      );

    final output = Uint8List(cipher.getOutputSize(encrypted.length));
    final len = cipher.processBytes(encrypted, 0, encrypted.length, output, 0);
    try {
      cipher.doFinal(output, len);
      return output;
    } catch (e) {
      log.severe('decrypt failed', e, type, dumpBuffer(data), header, summary);
      rethrow;
    }
  }

  @override
  String toString() {
    return name ?? '';
  }
}
AI-generated code. Review and use carefully. More info on FAQ.
This Dart code mirrors the structure and functionality of your JavaScript code. If you have any questions or need further adjustments, feel free to ask!

Learn more

1

codeconvert.ai
2

codingfleet.com
3

quicktype.io
4

codedocumentation.app
You
Sent by you:
Convert to dart as well: import { createNULLKeyExchange } from "../key-exchange";
import Cipher from "./abstract";

/**
 * Default passthrough cipher.
 */
export default class NullCipher extends Cipher {
  /**
   * @class NullCipher
   */
  constructor() {
    super();

    this.name = "NULL_NULL_NULL"; // key, mac, hash
    this.blockAlgorithm = "NULL";
    this.kx = createNULLKeyExchange();
    this.hashAlgorithm = "NULL";
  }

  /**
   * Encrypts data.
   * @param {AbstractSession} session
   * @param {Buffer} data Content to encryption.
   * @returns {Buffer}
   */
  encrypt(session: any, data: Buffer) {
    return data;
  }

  /**
   * Decrypts data.
   * @param {AbstractSession} session
   * @param {Buffer} data Content to encryption.
   * @returns {Buffer}
   */
  decrypt(session: any, data: Buffer) {
    return data;
  }
}
Copilot
Sent by Copilot:
Here’s the Dart equivalent of your JavaScript code:

Dart

import 'key_exchange.dart';
import 'abstract.dart';

/**
 * Default passthrough cipher.
 */
class NullCipher extends AbstractCipher {
  /**
   * @class NullCipher
   */
  NullCipher() {
    name = "NULL_NULL_NULL"; // key, mac, hash
    blockAlgorithm = "NULL";
    kx = createNULLKeyExchange();
    hashAlgorithm = "NULL";
  }

  /**
   * Encrypts data.
   * @param {AbstractSession} session
   * @param {Uint8List} data Content to encryption.
   * @returns {Uint8List}
   */
  @override
  Uint8List encrypt(dynamic session, Uint8List data) {
    return data;
  }

  /**
   * Decrypts data.
   * @param {AbstractSession} session
   * @param {Uint8List} data Content to encryption.
   * @returns {Uint8List}
   */
  @override
  Uint8List decrypt(dynamic session, Uint8List data) {
    return data;
  }
}
AI-generated code. Review and use carefully. More info on FAQ.
This Dart code mirrors the structure and functionality of your JavaScript code. If you have any questions or need further adjustments, feel free to ask!

Learn more

1

codeconvert.ai
2

codingfleet.com
3

quicktype.io
4

codedocumentation.app
You
Sent by you:
Convert to dart as well: import { Certificate, PrivateKey } from "@fidm/x509";
import { Crypto } from "@peculiar/webcrypto";
import * as x509 from "@peculiar/x509";
import { decode, encode, types } from "binary-data";
import nodeCrypto, { createSign } from "crypto";
import addYears from "date-fns/addYears";

import {
  CipherSuites,
  CurveType,
  HashAlgorithm,
  NamedCurveAlgorithm,
  NamedCurveAlgorithms,
  SignatureAlgorithm,
  SignatureHash,
} from "../cipher/const";
import { NamedCurveKeyPair } from "../cipher/namedCurve";
import { prfVerifyDataClient, prfVerifyDataServer } from "../cipher/prf";
import { SessionType, SessionTypes } from "../cipher/suites/abstract";
import AEADCipher from "../cipher/suites/aead";
import { ProtocolVersion } from "../handshake/binary";
import { DtlsRandom } from "../handshake/random";
import { DtlsPlaintext } from "../record/message/plaintext";

const crypto = new Crypto();
x509.cryptoProvider.set(crypto as any);

export class CipherContext {
  localRandom!: DtlsRandom;
  remoteRandom!: DtlsRandom;
  cipherSuite!: CipherSuites;
  remoteCertificate?: Buffer;
  remoteKeyPair!: Partial<NamedCurveKeyPair>;
  localKeyPair!: NamedCurveKeyPair;
  masterSecret!: Buffer;
  cipher!: AEADCipher;
  namedCurve!: NamedCurveAlgorithms;
  signatureHashAlgorithm?: SignatureHash;
  localCert!: Buffer;
  localPrivateKey!: PrivateKey;

  constructor(
    public sessionType: SessionTypes,
    public certPem?: string,
    public keyPem?: string,
    signatureHashAlgorithm?: SignatureHash
  ) {
    if (certPem && keyPem && signatureHashAlgorithm) {
      this.parseX509(certPem, keyPem, signatureHashAlgorithm);
    }
  }

  /**
   *
   * @param signatureHash
   * @param namedCurveAlgorithm necessary when use ecdsa
   */
  static createSelfSignedCertificateWithKey = async (
    signatureHash: SignatureHash,
    namedCurveAlgorithm?: NamedCurveAlgorithms
  ) => {
    const signatureAlgorithmName = (() => {
      switch (signatureHash.signature) {
        case SignatureAlgorithm.rsa_1:
          return "RSASSA-PKCS1-v1_5";
        case SignatureAlgorithm.ecdsa_3:
          return "ECDSA";
      }
    })();
    const hash = (() => {
      switch (signatureHash.hash) {
        case HashAlgorithm.sha256_4:
          return "SHA-256";
      }
    })();
    const namedCurve = (() => {
      switch (namedCurveAlgorithm) {
        case NamedCurveAlgorithm.secp256r1_23:
          return "P-256";
        case NamedCurveAlgorithm.x25519_29:
          // todo fix (X25519 not supported with ECDSA)
          if (signatureAlgorithmName === "ECDSA") {
            return "P-256";
          }
          return "X25519";
        default: {
          if (signatureAlgorithmName === "ECDSA") return "P-256";
          if (signatureAlgorithmName === "RSASSA-PKCS1-v1_5") return "X25519";
        }
      }
    })();
    const alg = (() => {
      switch (signatureAlgorithmName) {
        case "ECDSA":
          return { name: signatureAlgorithmName, hash, namedCurve };
        case "RSASSA-PKCS1-v1_5":
          return {
            name: signatureAlgorithmName,
            hash,
            publicExponent: new Uint8Array([1, 0, 1]),
            modulusLength: 2048,
          };
      }
    })();

    const keys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);

    const cert = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: nodeCrypto.randomBytes(8).toString("hex"),
      name: "C=AU, ST=Some-State, O=Internet Widgits Pty Ltd",
      notBefore: new Date(),
      notAfter: addYears(Date.now(), 10),
      signingAlgorithm: alg,
      keys,
    });

    const certPem = cert.toString("pem");
    const keyPem = x509.PemConverter.encode(
      await crypto.subtle.exportKey("pkcs8", keys.privateKey as any),
      "private key"
    );

    return { certPem, keyPem, signatureHash };
  };

  encryptPacket(pkt: DtlsPlaintext) {
    const header = pkt.recordLayerHeader;
    const enc = this.cipher.encrypt(this.sessionType, pkt.fragment, {
      type: header.contentType,
      version: decode(
        Buffer.from(encode(header.protocolVersion, ProtocolVersion).slice()),
        { version: types.uint16be }
      ).version,
      epoch: header.epoch,
      sequenceNumber: header.sequenceNumber,
    });
    pkt.fragment = enc;
    pkt.recordLayerHeader.contentLen = enc.length;
    return pkt;
  }

  decryptPacket(pkt: DtlsPlaintext) {
    const header = pkt.recordLayerHeader;
    const dec = this.cipher.decrypt(this.sessionType, pkt.fragment, {
      type: header.contentType,
      version: decode(
        Buffer.from(encode(header.protocolVersion, ProtocolVersion).slice()),
        { version: types.uint16be }
      ).version,
      epoch: header.epoch,
      sequenceNumber: header.sequenceNumber,
    });
    return dec;
  }

  verifyData(buf: Buffer) {
    if (this.sessionType === SessionType.CLIENT)
      return prfVerifyDataClient(this.masterSecret, buf);
    else return prfVerifyDataServer(this.masterSecret, buf);
  }

  signatureData(data: Buffer, hash: string) {
    const signature = createSign(hash).update(data);
    const key = this.localPrivateKey.toPEM().toString();
    const signed = signature.sign(key);
    return signed;
  }

  generateKeySignature(hashAlgorithm: string) {
    const clientRandom =
      this.sessionType === SessionType.CLIENT
        ? this.localRandom
        : this.remoteRandom;
    const serverRandom =
      this.sessionType === SessionType.SERVER
        ? this.localRandom
        : this.remoteRandom;

    const sig = this.valueKeySignature(
      clientRandom.serialize(),
      serverRandom.serialize(),
      this.localKeyPair.publicKey,
      this.namedCurve
    );

    const enc = this.localPrivateKey.sign(sig, hashAlgorithm);
    return enc;
  }

  parseX509(certPem: string, keyPem: string, signatureHash: SignatureHash) {
    const cert = Certificate.fromPEM(Buffer.from(certPem));
    const sec = PrivateKey.fromPEM(Buffer.from(keyPem));
    this.localCert = cert.raw;
    this.localPrivateKey = sec;
    this.signatureHashAlgorithm = signatureHash;
  }

  private valueKeySignature(
    clientRandom: Buffer,
    serverRandom: Buffer,
    publicKey: Buffer,
    namedCurve: number
  ) {
    const serverParams = Buffer.from(
      encode(
        {
          type: CurveType.named_curve_3,
          curve: namedCurve,
          len: publicKey.length,
        },
        { type: types.uint8, curve: types.uint16be, len: types.uint8 }
      ).slice()
    );
    return Buffer.concat([clientRandom, serverRandom, serverParams, publicKey]);
  }
}
Copilot
Sent by Copilot:
Here’s the Dart equivalent of your JavaScript code:

Dart

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

    return {'certPem': certPem, 'keyPem': keyPem, 'signatureHash': signatureHash};
  }

  DtlsPlaintext encryptPacket(DtlsPlaintext pkt) {
    final header = pkt.recordLayerHeader;
    final enc = cipher.encrypt(sessionType, pkt.fragment, CipherHeader(
      type: header.contentType,
      version: decode(
        Uint8List.fromList(encode(header.protocolVersion, ProtocolVersion).toList()),
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
    final dec = cipher.decrypt(sessionType, pkt.fragment, CipherHeader(
      type: header.contentType,
      version: decode(
        Uint8List.fromList(encode(header.protocolVersion, ProtocolVersion).toList()),
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
    final clientRandom = sessionType == SessionType.CLIENT ? localRandom : remoteRandom;
    final serverRandom = sessionType == SessionType.SERVER ? localRandom : remoteRandom;

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
    return Uint8List.fromList(clientRandom + serverRandom + serverParams + publicKey);
  }
}
AI-generated code. Review and use carefully. More info on FAQ.
This Dart code mirrors the structure and functionality of your JavaScript code. If you have any questions or need further adjustments, feel free to ask!

Learn more

1

codeconvert.ai
2

codingfleet.com
3

quicktype.io
4

codedocumentation.app
You
Sent by you:
Convert to dart: import { debug } from "debug";

import { HashAlgorithms, SignatureAlgorithms } from "../cipher/const";
import { SessionTypes } from "../cipher/suites/abstract";
import { FragmentedHandshake } from "../record/message/fragment";
import { Options } from "../socket";
import { Handshake } from "../typings/domain";

const log = debug("werift-dtls : packages/dtls/src/context/dtls.ts : log");

export class DtlsContext {
  version = { major: 255 - 1, minor: 255 - 2 };

  lastFlight: Handshake[] = [];
  lastMessage: Buffer[] = [];
  recordSequenceNumber = 0;
  sequenceNumber = 0;
  epoch = 0;
  flight = 0;
  handshakeCache: {
    [flight: number]: {
      isLocal: boolean;
      data: FragmentedHandshake[];
      flight: number;
    };
  } = {};
  cookie?: Buffer;
  requestedCertificateTypes: number[] = [];
  requestedSignatureAlgorithms: {
    hash: HashAlgorithms;
    signature: SignatureAlgorithms;
  }[] = [];
  remoteExtendedMasterSecret = false;

  constructor(public options: Options, public sessionType: SessionTypes) {}

  get sessionId() {
    return this.cookie ? this.cookie.toString("hex").slice(0, 10) : "";
  }

  get sortedHandshakeCache() {
    return Object.entries(this.handshakeCache)
      .sort(([a], [b]) => Number(a) - Number(b))
      .map(([, { data }]) => data.sort((a, b) => a.message_seq - b.message_seq))
      .flatMap((v) => v);
  }

  checkHandshakesExist = (handshakes: number[]) =>
    !handshakes.find(
      (type) =>
        this.sortedHandshakeCache.find((h) => h.msg_type === type) == undefined
    );

  bufferHandshakeCache(
    handshakes: FragmentedHandshake[],
    isLocal: boolean,
    flight: number
  ) {
    if (!this.handshakeCache[flight]) {
      this.handshakeCache[flight] = { data: [], isLocal, flight };
    }

    const filtered = handshakes.filter((h) => {
      const exist = this.handshakeCache[flight].data.find(
        (t) => t.msg_type === h.msg_type
      );
      if (exist) {
        log(this.sessionId, "exist", exist.summary, isLocal, flight);
        return false;
      }
      return true;
    });

    this.handshakeCache[flight].data = [
      ...this.handshakeCache[flight].data,
      ...filtered,
    ];
  }
}
Copilot
Sent by Copilot:
Here’s the Dart equivalent of your JavaScript code:

Dart

import 'package:logging/logging.dart';
import 'const.dart';
import 'abstract.dart';
import 'fragment.dart';
import 'socket.dart';
import 'domain.dart';

final log = Logger('werift-dtls : packages/dtls/src/context/dtls.dart : log');

class DtlsContext {
  final version = {'major': 255 - 1, 'minor': 255 - 2};

  List<Handshake> lastFlight = [];
  List<Uint8List> lastMessage = [];
  int recordSequenceNumber = 0;
  int sequenceNumber = 0;
  int epoch = 0;
  int flight = 0;
  Map<int, HandshakeCache> handshakeCache = {};
  Uint8List? cookie;
  List<int> requestedCertificateTypes = [];
  List<SignatureHashAlgorithm> requestedSignatureAlgorithms = [];
  bool remoteExtendedMasterSecret = false;

  final Options options;
  final SessionTypes sessionType;

  DtlsContext(this.options, this.sessionType);

  String get sessionId => cookie != null ? hex.encode(cookie!).substring(0, 10) : '';

  List<FragmentedHandshake> get sortedHandshakeCache {
    return handshakeCache.entries
        .toList()
        .sort((a, b) => a.key.compareTo(b.key))
        .expand((entry) => entry.value.data..sort((a, b) => a.messageSeq.compareTo(b.messageSeq)))
        .toList();
  }

  bool checkHandshakesExist(List<int> handshakes) {
    return !handshakes.any((type) => sortedHandshakeCache.any((h) => h.msgType == type) == false);
  }

  void bufferHandshakeCache(List<FragmentedHandshake> handshakes, bool isLocal, int flight) {
    handshakeCache.putIfAbsent(flight, () => HandshakeCache(isLocal: isLocal, data: [], flight: flight));

    final filtered = handshakes.where((h) {
      final exist = handshakeCache[flight]!.data.any((t) => t.msgType == h.msgType);
      if (exist) {
        log.info('$sessionId exist ${h.summary} $isLocal $flight');
        return false;
      }
      return true;
    }).toList();

    handshakeCache[flight]!.data.addAll(filtered);
  }
}

class HandshakeCache {
  final bool isLocal;
  final List<FragmentedHandshake> data;
  final int flight;

  HandshakeCache({required this.isLocal, required this.data, required this.flight});
}

class SignatureHashAlgorithm {
  final HashAlgorithms hash;
  final SignatureAlgorithms signature;

  SignatureHashAlgorithm({required this.hash, required this.signature});
}
AI-generated code. Review and use carefully. More info on FAQ.
This Dart code mirrors the structure and functionality of your JavaScript code. If you have any questions or need further adjustments, feel free to ask!

Learn more

1

codeconvert.ai
2

codingfleet.com
3

quicktype.io
4

codedocumentation.app
You
Sent by you:
Convert to dart: export class SrtpContext {
  srtpProfile?: Profile;

  static findMatchingSRTPProfile(remote: Profile[], local: Profile[]) {
    for (const v of local) {
      if (remote.includes(v)) return v;
    }
  }
}

export const ProtectionProfileAes128CmHmacSha1_80 = 0x0001 as const;
export const ProtectionProfileAeadAes128Gcm = 0x0007 as const;

export const Profiles = [
  ProtectionProfileAes128CmHmacSha1_80,
  ProtectionProfileAeadAes128Gcm,
] as const;

export type Profile = typeof Profiles[number];
Copilot
Sent by Copilot:
Here’s the Dart equivalent of your JavaScript code:

Dart

class SrtpContext {
  Profile? srtpProfile;

  static Profile? findMatchingSRTPProfile(List<Profile> remote, List<Profile> local) {
    for (final v in local) {
      if (remote.contains(v)) return v;
    }
    return null;
  }
}

const int ProtectionProfileAes128CmHmacSha1_80 = 0x0001;
const int ProtectionProfileAeadAes128Gcm = 0x0007;

const List<int> Profiles = [
  ProtectionProfileAes128CmHmacSha1_80,
  ProtectionProfileAeadAes128Gcm,
];

typedef Profile = int;
AI-generated code. Review and use carefully. More info on FAQ.
This Dart code mirrors the structure and functionality of your JavaScript code. If you have any questions or need further adjustments, feel free to ask!

Learn more

1

codeconvert.ai
2

codingfleet.com
3

quicktype.io
4

codedocumentation.app
You
Sent by you:
Convert to dart: const width = 64; // bits / entries, must be multiple of INT_SIZE
const INT_SIZE = 32; // in JS, bitwise operators use 32bit ints

/**
 * Provides protection against replay attacks by remembering received packets in a sliding window
 */
export class AntiReplayWindow {
  // window bitmap looks as follows:
  //  v- upper end                    lower end --v
  // [111011 ... window_n]...[11111101 ... window_0]
  private window: number[] = [];
  private ceiling: number = 0; // upper end of the window bitmap / highest received seq_num

  constructor() {
    this.reset();
  }
  /**
   * Initializes the anti replay window to its default state
   */
  public reset(): void {
    this.window = [];
    for (let i = 0; i < width / INT_SIZE; i++) {
      this.window[i] = 0;
    }
    this.ceiling = width - 1;
  }

  /**
   * Checks if the packet with the given sequence number may be received or has to be discarded
   * @param seq_num - The sequence number of the packet to be checked
   */
  public mayReceive(seq_num: number): boolean {
    if (seq_num > this.ceiling + width) {
      // we skipped a lot of packets... I don't think we should accept
      return false;
    } else if (seq_num > this.ceiling) {
      // always accept new packets
      return true;
    } else if (seq_num >= this.ceiling - width + 1 && seq_num <= this.ceiling) {
      // packet falls within the window, check if it was received already.
      // if so, don't accept
      return !this.hasReceived(seq_num);
    } /* seq_num <= this.ceiling - width */ else {
      // too old, don't accept
      return false;
    }
  }

  /**
   * Checks if the packet with the given sequence number is marked as received
   * @param seq_num - The sequence number of the packet to be checked
   */
  public hasReceived(seq_num: number): boolean {
    // check if the packet was received already
    const lowerBound = this.ceiling - width + 1;
    // find out where the bit is located
    const bitIndex = seq_num - lowerBound;
    const windowIndex = Math.floor(bitIndex / INT_SIZE);
    const windowBit = bitIndex % INT_SIZE;
    const flag = 1 << windowBit;
    // check if it is set;
    return (this.window[windowIndex] & flag) === flag;
  }

  /**
   * Marks the packet with the given sequence number as received
   * @param seq_num - The sequence number of the packet
   */
  public markAsReceived(seq_num: number): void {
    if (seq_num > this.ceiling) {
      // shift the window
      let amount = seq_num - this.ceiling;
      // first shift whole blocks
      while (amount > INT_SIZE) {
        for (let i = 1; i < this.window.length; i++) {
          this.window[i - 1] = this.window[i];
        }
        this.window[this.window.length - 1] = 0;
        amount -= INT_SIZE;
      }
      // now shift bitwise (to the right)
      let overflow = 0;
      for (let i = 0; i < this.window.length; i++) {
        overflow = this.window[i] << (INT_SIZE - amount); // BBBBBBAA => AA000000
        this.window[i] = this.window[i] >>> amount; // BBBBBBAA ==> 00BBBBBB
        if (i > 0) this.window[i - 1] |= overflow;
      }
      // and remember the new ceiling
      this.ceiling = seq_num;
    }
    const lowerBound = this.ceiling - width + 1;

    // find out where the bit is located
    const bitIndex = seq_num - lowerBound;
    const windowIndex = Math.floor(bitIndex / INT_SIZE);
    const windowBit = bitIndex % INT_SIZE;
    const flag = 1 << windowBit;
    // and set it
    this.window[windowIndex] |= flag;
  }
}
Copilot
Sent by Copilot:
Here’s the Dart equivalent of your JavaScript code:

Dart

const int width = 64; // bits / entries, must be multiple of INT_SIZE
const int INT_SIZE = 32; // in Dart, bitwise operators use 32bit ints

/**
 * Provides protection against replay attacks by remembering received packets in a sliding window
 */
class AntiReplayWindow {
  // window bitmap looks as follows:
  //  v- upper end                    lower end --v
  // [111011 ... window_n]...[11111101 ... window_0]
  List<int> window = [];
  int ceiling = 0; // upper end of the window bitmap / highest received seq_num

  AntiReplayWindow() {
    reset();
  }

  /**
   * Initializes the anti replay window to its default state
   */
  void reset() {
    window = List.filled(width ~/ INT_SIZE, 0);
    ceiling = width - 1;
  }

  /**
   * Checks if the packet with the given sequence number may be received or has to be discarded
   * @param seq_num - The sequence number of the packet to be checked
   */
  bool mayReceive(int seqNum) {
    if (seqNum > ceiling + width) {
      // we skipped a lot of packets... I don't think we should accept
      return false;
    } else if (seqNum > ceiling) {
      // always accept new packets
      return true;
    } else if (seqNum >= ceiling - width + 1 && seqNum <= ceiling) {
      // packet falls within the window, check if it was received already.
      // if so, don't accept
      return !hasReceived(seqNum);
    } else {
      // too old, don't accept
      return false;
    }
  }

  /**
   * Checks if the packet with the given sequence number is marked as received
   * @param seq_num - The sequence number of the packet to be checked
   */
  bool hasReceived(int seqNum) {
    // check if the packet was received already
    final lowerBound = ceiling - width + 1;
    // find out where the bit is located
    final bitIndex = seqNum - lowerBound;
    final windowIndex = bitIndex ~/ INT_SIZE;
    final windowBit = bitIndex % INT_SIZE;
    final flag = 1 << windowBit;
    // check if it is set;
    return (window[windowIndex] & flag) == flag;
  }

  /**
   * Marks the packet with the given sequence number as received
   * @param seq_num - The sequence number of the packet
   */
  void markAsReceived(int seqNum) {
    if (seqNum > ceiling) {
      // shift the window
      var amount = seqNum - ceiling;
      // first shift whole blocks
      while (amount > INT_SIZE) {
        for (var i = 1; i < window.length; i++) {
          window[i - 1] = window[i];
        }
        window[window.length - 1] = 0;
        amount -= INT_SIZE;
      }
      // now shift bitwise (to the right)
      var overflow = 0;
      for (var i = 0; i < window.length; i++) {
        overflow = window[i] << (INT_SIZE - amount); // BBBBBBAA => AA000000
        window[i] = window[i] >>> amount; // BBBBBBAA ==> 00BBBBBB
        if (i > 0) window[i - 1] |= overflow;
      }
      // and remember the new ceiling
      ceiling = seqNum;
    }
    final lowerBound = ceiling - width + 1;

    // find out where the bit is located
    final bitIndex = seqNum - lowerBound;
    final windowIndex = bitIndex ~/ INT_SIZE;
    final windowBit = bitIndex % INT_SIZE;
    final flag = 1 << windowBit;
    // and set it
    window[windowIndex] |= flag;
  }
}
AI-generated code. Review and use carefully. More info on FAQ.
This Dart code mirrors the structure and functionality of your JavaScript code. If you have any questions or need further adjustments, feel free to ask!

Learn more

1

codeconvert.ai
2

codingfleet.com
3

quicktype.io
4

codedocumentation.app
You
Sent by you:
Convert to dart: import { DtlsContext } from "../context/dtls";
import { Handshake } from "../typings/domain";
import { DtlsPlaintext } from "./message/plaintext";

export type Message = { type: number; fragment: Buffer };

export const createFragments =
  (dtls: DtlsContext) => (handshakes: Handshake[]) => {
    dtls.lastFlight = handshakes;

    return handshakes
      .map((handshake) => {
        handshake.messageSeq = dtls.sequenceNumber++;
        const fragment = handshake.toFragment();
        const fragments = fragment.chunk();
        return fragments;
      })
      .flatMap((v) => v);
  };

export const createPlaintext =
  (dtls: DtlsContext) =>
  (fragments: Message[], recordSequenceNumber: number) => {
    return fragments.map((msg) => {
      const plaintext = new DtlsPlaintext(
        {
          contentType: msg.type,
          protocolVersion: dtls.version,
          epoch: dtls.epoch,
          sequenceNumber: recordSequenceNumber,
          contentLen: msg.fragment.length,
        },
        msg.fragment
      );
      return plaintext;
    });
  };
Copilot
Sent by Copilot:
Here’s the Dart equivalent of your JavaScript code:

Dart

import 'dtls_context.dart';
import 'domain.dart';
import 'plaintext.dart';

class Message {
  final int type;
  final Uint8List fragment;

  Message({required this.type, required this.fragment});
}

List<FragmentedHandshake> Function(List<Handshake>) createFragments(DtlsContext dtls) {
  return (List<Handshake> handshakes) {
    dtls.lastFlight = handshakes;

    return handshakes
        .map((handshake) {
          handshake.messageSeq = dtls.sequenceNumber++;
          final fragment = handshake.toFragment();
          final fragments = fragment.chunk();
          return fragments;
        })
        .expand((v) => v)
        .toList();
  };
}

List<DtlsPlaintext> Function(List<Message>, int) createPlaintext(DtlsContext dtls) {
  return (List<Message> fragments, int recordSequenceNumber) {
    return fragments.map((msg) {
      final plaintext = DtlsPlaintext(
        contentType: msg.type,
        protocolVersion: dtls.version,
        epoch: dtls.epoch,
        sequenceNumber: recordSequenceNumber,
        contentLen: msg.fragment.length,
        fragment: msg.fragment,
      );
      return plaintext;
    }).toList();
  };
}
AI-generated code. Review and use carefully. More info on FAQ.
This Dart code mirrors the structure and functionality of your JavaScript code. If you have any questions or need further adjustments, feel free to ask!

Learn more

1

codeconvert.ai
2

codingfleet.com
3

quicktype.io
4

codedocumentation.app
You
Sent by you:
Convert to dart: export enum ContentType {
  changeCipherSpec = 20,
  alert = 21,
  handshake = 22,
  applicationData = 23,
}

export enum AlertDesc {
  CloseNotify = 0,
  UnexpectedMessage = 10,
  BadRecordMac = 20,
  DecryptionFailed = 21,
  RecordOverflow = 22,
  DecompressionFailure = 30,
  HandshakeFailure = 40,
  NoCertificate = 41,
  BadCertificate = 42,
  UnsupportedCertificate = 43,
  CertificateRevoked = 44,
  CertificateExpired = 45,
  CertificateUnknown = 46,
  IllegalParameter = 47,
  UnknownCa = 48,
  AccessDenied = 49,
  DecodeError = 50,
  DecryptError = 51,
  ExportRestriction = 60,
  ProtocolVersion = 70,
  InsufficientSecurity = 71,
  InternalError = 80,
  UserCanceled = 90,
  NoRenegotiation = 100,
  UnsupportedExtension = 110,
}
Copilot
Sent by Copilot:
Here’s the Dart equivalent of your TypeScript enums:

Dart

enum ContentType {
  changeCipherSpec(20),
  alert(21),
  handshake(22),
  applicationData(23);

  final int value;
  const ContentType(this.value);
}

enum AlertDesc {
  CloseNotify(0),
  UnexpectedMessage(10),
  BadRecordMac(20),
  DecryptionFailed(21),
  RecordOverflow(22),
  DecompressionFailure(30),
  HandshakeFailure(40),
  NoCertificate(41),
  BadCertificate(42),
  UnsupportedCertificate(43),
  CertificateRevoked(44),
  CertificateExpired(45),
  CertificateUnknown(46),
  IllegalParameter(47),
  UnknownCa(48),
  AccessDenied(49),
  DecodeError(50),
  DecryptError(51),
  ExportRestriction(60),
  ProtocolVersion(70),
  InsufficientSecurity(71),
  InternalError(80),
  UserCanceled(90),
  NoRenegotiation(100),
  UnsupportedExtension(110);

  final int value;
  const AlertDesc(this.value);
}
AI-generated code. Review and use carefully. More info on FAQ.
This Dart code mirrors the structure and functionality of your TypeScript enums. If you have any questions or need further adjustments, feel free to ask!

You
Sent by you:
Convert to dart: import debug from "debug";

import { CipherContext } from "../context/cipher";
import { DtlsContext } from "../context/dtls";
import { Alert } from "../handshake/message/alert";
import { AlertDesc, ContentType } from "./const";
import { FragmentedHandshake } from "./message/fragment";
import { DtlsPlaintext } from "./message/plaintext";

const log = debug("werift-dtls : packages/dtls/record/receive.ts : log");
const err = debug("werift-dtls : packages/dtls/record/receive.ts : err");

export const parsePacket = (data: Buffer) => {
  let start = 0;
  const packets: DtlsPlaintext[] = [];
  while (data.length > start) {
    const fragmentLength = data.readUInt16BE(start + 11);
    if (data.length < start + (12 + fragmentLength)) break;
    const packet = DtlsPlaintext.deSerialize(data.slice(start));
    packets.push(packet);

    start += 13 + fragmentLength;
  }

  return packets;
};

export const parsePlainText =
  (dtls: DtlsContext, cipher: CipherContext) => (plain: DtlsPlaintext) => {
    const contentType = plain.recordLayerHeader.contentType;

    switch (contentType) {
      case ContentType.changeCipherSpec: {
        log(dtls.sessionId, "change cipher spec");
        return {
          type: ContentType.changeCipherSpec,
          data: undefined,
        };
      }
      case ContentType.handshake: {
        let raw = plain.fragment;
        try {
          if (plain.recordLayerHeader.epoch > 0) {
            log(dtls.sessionId, "decrypt handshake");
            raw = cipher.decryptPacket(plain);
          }
        } catch (error) {
          err(dtls.sessionId, "decrypt failed", error);
          throw error;
        }
        try {
          return {
            type: ContentType.handshake,
            data: FragmentedHandshake.deSerialize(raw),
          };
        } catch (error) {
          err(dtls.sessionId, "decSerialize failed", error, raw);
          throw error;
        }
      }
      case ContentType.applicationData: {
        return {
          type: ContentType.applicationData,
          data: cipher.decryptPacket(plain),
        };
      }
      case ContentType.alert: {
        let alert = Alert.deSerialize(plain.fragment);

        // TODO impl more better about handle encrypted alert
        if (AlertDesc[alert.description] == undefined) {
          const dec = cipher.decryptPacket(plain);
          alert = Alert.deSerialize(dec);
        }
        err(
          dtls.sessionId,
          "ContentType.alert",
          alert,
          AlertDesc[alert.description],
          "flight",
          dtls.flight,
          "lastFlight",
          dtls.lastFlight
        );
        if (alert.level > 1) {
          throw new Error("alert fatal error");
        }
      }
      // eslint-disable-next-line no-fallthrough
      default: {
        return { type: ContentType.alert, data: undefined };
      }
    }
  };
Copilot
Sent by Copilot:
Here’s the Dart equivalent of your JavaScript code:

Dart

import 'package:logging/logging.dart';
import 'cipher_context.dart';
import 'dtls_context.dart';
import 'alert.dart';
import 'const.dart';
import 'fragment.dart';
import 'plaintext.dart';

final log = Logger('werift-dtls : packages/dtls/record/receive.ts : log');
final err = Logger('werift-dtls : packages/dtls/record/receive.ts : err');

List<DtlsPlaintext> parsePacket(Uint8List data) {
  int start = 0;
  final packets = <DtlsPlaintext>[];
  while (data.length > start) {
    final fragmentLength = data.buffer.asByteData().getUint16(start + 11);
    if (data.length < start + (12 + fragmentLength)) break;
    final packet = DtlsPlaintext.deSerialize(data.sublist(start));
    packets.add(packet);

    start += 13 + fragmentLength;
  }

  return packets;
}

Function parsePlainText(DtlsContext dtls, CipherContext cipher) {
  return (DtlsPlaintext plain) {
    final contentType = plain.recordLayerHeader.contentType;

    switch (contentType) {
      case ContentType.changeCipherSpec:
        log.info('${dtls.sessionId} change cipher spec');
        return {
          'type': ContentType.changeCipherSpec,
          'data': null,
        };
      case ContentType.handshake:
        var raw = plain.fragment;
        try {
          if (plain.recordLayerHeader.epoch > 0) {
            log.info('${dtls.sessionId} decrypt handshake');
            raw = cipher.decryptPacket(plain);
          }
        } catch (error) {
          err.severe('${dtls.sessionId} decrypt failed', error);
          throw error;
        }
        try {
          return {
            'type': ContentType.handshake,
            'data': FragmentedHandshake.deSerialize(raw),
          };
        } catch (error) {
          err.severe('${dtls.sessionId} deSerialize failed', error, raw);
          throw error;
        }
      case ContentType.applicationData:
        return {
          'type': ContentType.applicationData,
          'data': cipher.decryptPacket(plain),
        };
      case ContentType.alert:
        var alert = Alert.deSerialize(plain.fragment);

        // TODO: Implement better handling for encrypted alerts
        if (AlertDesc.values[alert.description] == null) {
          final dec = cipher.decryptPacket(plain);
          alert = Alert.deSerialize(dec);
        }
        err.severe(
          '${dtls.sessionId} ContentType.alert $alert ${AlertDesc.values[alert.description]} flight ${dtls.flight} lastFlight ${dtls.lastFlight}',
        );
        if (alert.level > 1) {
          throw Exception('alert fatal error');
        }
        break;
      default:
        return {'type': ContentType.alert, 'data': null};
    }
  };
}
AI-generated code. Review and use carefully. More info on FAQ.
This Dart code mirrors the structure and functionality of your JavaScript code. If you have any questions or need further adjustments, feel free to ask!

You
Sent by you:
Convert to dart: import { encode } from "binary-data";

export function encodeBuffer(obj: object, spec: object) {
  return Buffer.from(encode(obj, spec).slice());
}
Copilot
Sent by Copilot:
Here’s the Dart equivalent of your JavaScript code:

Dart

import 'dart:typed_data';
import 'package:binary_data/binary_data.dart';

Uint8List encodeBuffer(Map<String, dynamic> obj, Map<String, dynamic> spec) {
  final encoded = encode(obj, spec);
  return Uint8List.fromList(encoded);
}
AI-generated code. Review and use carefully. More info on FAQ.
This Dart code mirrors the structure and functionality of your JavaScript code. If you have any questions or need further adjustments, feel free to ask!

You
Sent by you:
Convert to dart: import { CipherSuiteList } from "../../cipher/const";
import { CipherContext } from "../../context/cipher";
import { DtlsContext } from "../../context/dtls";
import { TransportContext } from "../../context/transport";
import { ClientHello } from "../../handshake/message/client/hello";
import { DtlsRandom } from "../../handshake/random";
import { Extension } from "../../typings/domain";
import { Flight } from "../flight";

export class Flight1 extends Flight {
  constructor(
    udp: TransportContext,
    dtls: DtlsContext,
    private cipher: CipherContext
  ) {
    super(udp, dtls, 1, 3);
  }

  async exec(extensions: Extension[]) {
    if (this.dtls.flight === 1) throw new Error();
    this.dtls.flight = 1;

    const hello = new ClientHello(
      { major: 255 - 1, minor: 255 - 2 },
      new DtlsRandom(),
      Buffer.from([]),
      Buffer.from([]),
      CipherSuiteList,
      [0], // don't compress
      extensions
    );
    this.dtls.version = hello.clientVersion;
    this.cipher.localRandom = DtlsRandom.from(hello.random);

    const packets = this.createPacket([hello]);
    const buf = Buffer.concat(packets.map((v) => v.serialize()));
    await this.transmit([buf]);
  }
}
Copilot
Sent by Copilot:
Here’s the Dart equivalent of your JavaScript code:

Dart

import 'cipher_const.dart';
import 'cipher_context.dart';
import 'dtls_context.dart';
import 'transport_context.dart';
import 'client_hello.dart';
import 'dtls_random.dart';
import 'domain.dart';
import 'flight.dart';

class Flight1 extends Flight {
  final CipherContext cipher;

  Flight1(
    TransportContext udp,
    DtlsContext dtls,
    this.cipher,
  ) : super(udp, dtls, 1, 3);

  Future<void> exec(List<Extension> extensions) async {
    if (dtls.flight == 1) throw Exception('Flight already in progress');
    dtls.flight = 1;

    final hello = ClientHello(
      {'major': 255 - 1, 'minor': 255 - 2},
      DtlsRandom(),
      Uint8List(0),
      Uint8List(0),
      CipherSuiteList,
      [0], // don't compress
      extensions,
    );
    dtls.version = hello.clientVersion;
    cipher.localRandom = DtlsRandom.from(hello.random);

    final packets = createPacket([hello]);
    final buf = Uint8List.fromList(packets.expand((v) => v.serialize()).toList());
    await transmit([buf]);
  }
}
AI-generated code. Review and use carefully. More info on FAQ.
This Dart code mirrors the structure and functionality of your JavaScript code. If you have any questions or need further adjustments, feel free to ask!

Learn more

1

codeconvert.ai
2

codingfleet.com
3

quicktype.io
4

codedocumentation.app
You
Sent by you:
Convert to dart: import { DtlsContext } from "../../context/dtls";
import { TransportContext } from "../../context/transport";
import { ClientHello } from "../../handshake/message/client/hello";
import { ServerHelloVerifyRequest } from "../../handshake/message/server/helloVerifyRequest";
import { Flight } from "../flight";

export class Flight3 extends Flight {
  constructor(udp: TransportContext, dtls: DtlsContext) {
    super(udp, dtls, 3, 5);
  }

  async exec(verifyReq: ServerHelloVerifyRequest) {
    if (this.dtls.flight === 3) throw new Error();
    this.dtls.flight = 3;

    this.dtls.handshakeCache = [];

    const [clientHello] = this.dtls.lastFlight as [ClientHello];
    clientHello.cookie = verifyReq.cookie;
    this.dtls.cookie = verifyReq.cookie;

    const packets = this.createPacket([clientHello]);

    const buf = Buffer.concat(packets.map((v) => v.serialize()));
    await this.transmit([buf]);
  }
}
Copilot
Sent by Copilot:
Here’s the Dart equivalent of your JavaScript code:

Dart

import 'dtls_context.dart';
import 'transport_context.dart';
import 'client_hello.dart';
import 'server_hello_verify_request.dart';
import 'flight.dart';

class Flight3 extends Flight {
  Flight3(TransportContext udp, DtlsContext dtls) : super(udp, dtls, 3, 5);

  Future<void> exec(ServerHelloVerifyRequest verifyReq) async {
    if (dtls.flight == 3) throw Exception('Flight already in progress');
    dtls.flight = 3;

    dtls.handshakeCache.clear();

    final clientHello = dtls.lastFlight.first as ClientHello;
    clientHello.cookie = verifyReq.cookie;
    dtls.cookie = verifyReq.cookie;

    final packets = createPacket([clientHello]);

    final buf = Uint8List.fromList(packets.expand((v) => v.serialize()).toList());
    await transmit([buf]);
  }
}
AI-generated code. Review and use carefully. More info on FAQ.
This Dart code mirrors the structure and functionality of your JavaScript code. If you have any questions or need further adjustments, feel free to ask!

You
Sent by you:
Convert to dart: import debug from "debug";

import { SignatureAlgorithm, SignatureScheme } from "../../cipher/const";
import { createCipher } from "../../cipher/create";
import { generateKeyPair } from "../../cipher/namedCurve";
import {
  prfExtendedMasterSecret,
  prfMasterSecret,
  prfPreMasterSecret,
} from "../../cipher/prf";
import { CipherContext } from "../../context/cipher";
import { DtlsContext } from "../../context/dtls";
import { Profile, SrtpContext } from "../../context/srtp";
import { TransportContext } from "../../context/transport";
import { HandshakeType } from "../../handshake/const";
import { ExtendedMasterSecret } from "../../handshake/extensions/extendedMasterSecret";
import { RenegotiationIndication } from "../../handshake/extensions/renegotiationIndication";
import { UseSRTP } from "../../handshake/extensions/useSrtp";
import { Certificate } from "../../handshake/message/certificate";
import { ChangeCipherSpec } from "../../handshake/message/changeCipherSpec";
import { CertificateVerify } from "../../handshake/message/client/certificateVerify";
import { ClientKeyExchange } from "../../handshake/message/client/keyExchange";
import { Finished } from "../../handshake/message/finished";
import { ServerCertificateRequest } from "../../handshake/message/server/certificateRequest";
import { ServerHello } from "../../handshake/message/server/hello";
import { ServerHelloDone } from "../../handshake/message/server/helloDone";
import { ServerKeyExchange } from "../../handshake/message/server/keyExchange";
import { DtlsRandom } from "../../handshake/random";
import { dumpBuffer } from "../../helper";
import { createPlaintext } from "../../record/builder";
import { ContentType } from "../../record/const";
import { FragmentedHandshake } from "../../record/message/fragment";
import { Flight } from "../flight";

const log = debug(
  "werift-dtls : packages/dtls/src/flight/client/flight5.ts : log"
);

export class Flight5 extends Flight {
  constructor(
    udp: TransportContext,
    dtls: DtlsContext,
    private cipher: CipherContext,
    private srtp: SrtpContext
  ) {
    super(udp, dtls, 5, 7);
  }

  handleHandshake(handshake: FragmentedHandshake) {
    this.dtls.bufferHandshakeCache([handshake], false, 4);
    const message = (() => {
      switch (handshake.msg_type) {
        case HandshakeType.server_hello_2:
          return ServerHello.deSerialize(handshake.fragment);
        case HandshakeType.certificate_11:
          return Certificate.deSerialize(handshake.fragment);
        case HandshakeType.server_key_exchange_12:
          return ServerKeyExchange.deSerialize(handshake.fragment);
        case HandshakeType.certificate_request_13:
          return ServerCertificateRequest.deSerialize(handshake.fragment);
        case HandshakeType.server_hello_done_14:
          return ServerHelloDone.deSerialize(handshake.fragment);
      }
    })();

    if (message) {
      handlers[message.msgType]({
        dtls: this.dtls,
        cipher: this.cipher,
        srtp: this.srtp,
      })(message);
    }
  }

  async exec() {
    if (this.dtls.flight === 5) {
      log(this.dtls.sessionId, "flight5 twice");
      this.send(this.dtls.lastMessage);
      return;
    }
    this.dtls.flight = 5;

    const needCertificate = this.dtls.requestedCertificateTypes.length > 0;
    log(this.dtls.sessionId, "send flight5", needCertificate);

    const messages = [
      needCertificate && this.sendCertificate(),
      this.sendClientKeyExchange(),
      needCertificate && this.sendCertificateVerify(),
      this.sendChangeCipherSpec(),
      this.sendFinished(),
    ].filter((v) => v) as Buffer[];

    this.dtls.lastMessage = messages;
    await this.transmit(messages);
  }

  private sendCertificate() {
    const certificate = new Certificate([Buffer.from(this.cipher.localCert)]);

    const packets = this.createPacket([certificate]);

    const buf = Buffer.concat(packets.map((v) => v.serialize()));
    return buf;
  }

  private sendClientKeyExchange() {
    if (!this.cipher.localKeyPair) throw new Error();

    const clientKeyExchange = new ClientKeyExchange(
      this.cipher.localKeyPair.publicKey
    );
    const packets = this.createPacket([clientKeyExchange]);
    const buf = Buffer.concat(packets.map((v) => v.serialize()));

    const localKeyPair = this.cipher.localKeyPair;
    const remoteKeyPair = this.cipher.remoteKeyPair;

    if (!remoteKeyPair.publicKey) throw new Error("not exist");

    const preMasterSecret = prfPreMasterSecret(
      remoteKeyPair.publicKey,
      localKeyPair.privateKey,
      localKeyPair.curve
    );

    log(
      this.dtls.sessionId,
      "extendedMasterSecret",
      this.dtls.options.extendedMasterSecret,
      this.dtls.remoteExtendedMasterSecret
    );

    const handshakes = Buffer.concat(
      this.dtls.sortedHandshakeCache.map((v) => v.serialize())
    );
    this.cipher.masterSecret =
      this.dtls.options.extendedMasterSecret &&
      this.dtls.remoteExtendedMasterSecret
        ? prfExtendedMasterSecret(preMasterSecret, handshakes)
        : prfMasterSecret(
            preMasterSecret,
            this.cipher.localRandom.serialize(),
            this.cipher.remoteRandom.serialize()
          );

    this.cipher.cipher = createCipher(this.cipher.cipherSuite);
    this.cipher.cipher.init(
      this.cipher.masterSecret,
      this.cipher.remoteRandom.serialize(),
      this.cipher.localRandom.serialize()
    );
    log(this.dtls.sessionId, "cipher", this.cipher.cipher.summary);

    return buf;
  }

  private sendCertificateVerify() {
    const cache = Buffer.concat(
      this.dtls.sortedHandshakeCache.map((v) => v.serialize())
    );
    const signed = this.cipher.signatureData(cache, "sha256");
    const signatureScheme = (() => {
      switch (this.cipher.signatureHashAlgorithm?.signature) {
        case SignatureAlgorithm.ecdsa_3:
          return SignatureScheme.ecdsa_secp256r1_sha256;
        case SignatureAlgorithm.rsa_1:
          return SignatureScheme.rsa_pkcs1_sha256;
      }
    })();
    if (!signatureScheme) throw new Error();
    log(
      this.dtls.sessionId,
      "signatureScheme",
      this.cipher.signatureHashAlgorithm?.signature,
      signatureScheme
    );

    const certificateVerify = new CertificateVerify(signatureScheme, signed);
    const packets = this.createPacket([certificateVerify]);
    const buf = Buffer.concat(packets.map((v) => v.serialize()));
    return buf;
  }

  private sendChangeCipherSpec() {
    const changeCipherSpec = ChangeCipherSpec.createEmpty().serialize();
    const packets = createPlaintext(this.dtls)(
      [{ type: ContentType.changeCipherSpec, fragment: changeCipherSpec }],
      ++this.dtls.recordSequenceNumber
    );
    const buf = Buffer.concat(packets.map((v) => v.serialize()));
    return buf;
  }

  private sendFinished() {
    const cache = Buffer.concat(
      this.dtls.sortedHandshakeCache.map((v) => v.serialize())
    );
    const localVerifyData = this.cipher.verifyData(cache);

    const finish = new Finished(localVerifyData);
    this.dtls.epoch = 1;
    const [packet] = this.createPacket([finish]);
    log(
      this.dtls.sessionId,
      "raw finish packet",
      packet.summary,
      this.dtls.sortedHandshakeCache.map((h) => h.summary)
    );

    this.dtls.recordSequenceNumber = 0;

    const buf = this.cipher.encryptPacket(packet).serialize();
    log(this.dtls.sessionId, "finished", this.cipher.cipher.summary);
    return buf;
  }
}

const handlers: {
  [key: number]: (contexts: {
    dtls: DtlsContext;
    cipher: CipherContext;
    srtp: SrtpContext;
  }) => (message: any) => void;
} = {};

handlers[HandshakeType.server_hello_2] =
  ({ cipher, srtp, dtls }) =>
  (message: ServerHello) => {
    log(dtls.sessionId, "serverHello", message.cipherSuite);
    cipher.remoteRandom = DtlsRandom.from(message.random);
    cipher.cipherSuite = message.cipherSuite;
    log(dtls.sessionId, "selected cipherSuite", cipher.ciphe
Copilot
Sent by Copilot:
Here’s the Dart equivalent of your JavaScript code:

Dart

import 'package:logging/logging.dart';
import 'cipher_const.dart';
import 'cipher_create.dart';
import 'named_curve.dart';
import 'prf.dart';
import 'cipher_context.dart';
import 'dtls_context.dart';
import 'srtp_context.dart';
import 'transport_context.dart';
import 'handshake_const.dart';
import 'extended_master_secret.dart';
import 'renegotiation_indication.dart';
import 'use_srtp.dart';
import 'certificate.dart';
import 'change_cipher_spec.dart';
import 'certificate_verify.dart';
import 'client_key_exchange.dart';
import 'finished.dart';
import 'server_certificate_request.dart';
import 'server_hello.dart';
import 'server_hello_done.dart';
import 'server_key_exchange.dart';
import 'dtls_random.dart';
import 'helper.dart';
import 'builder.dart';
import 'record_const.dart';
import 'fragment.dart';
import 'flight.dart';

final log = Logger('werift-dtls : packages/dtls/src/flight/client/flight5.ts : log');

class Flight5 extends Flight {
  final CipherContext cipher;
  final SrtpContext srtp;

  Flight5(
    TransportContext udp,
    DtlsContext dtls,
    this.cipher,
    this.srtp,
  ) : super(udp, dtls, 5, 7);

  void handleHandshake(FragmentedHandshake handshake) {
    dtls.bufferHandshakeCache([handshake], false, 4);
    final message = () {
      switch (handshake.msgType) {
        case HandshakeType.server_hello_2:
          return ServerHello.deSerialize(handshake.fragment);
        case HandshakeType.certificate_11:
          return Certificate.deSerialize(handshake.fragment);
        case HandshakeType.server_key_exchange_12:
          return ServerKeyExchange.deSerialize(handshake.fragment);
        case HandshakeType.certificate_request_13:
          return ServerCertificateRequest.deSerialize(handshake.fragment);
        case HandshakeType.server_hello_done_14:
          return ServerHelloDone.deSerialize(handshake.fragment);
      }
    }();

    if (message != null) {
      handlers[message.msgType]!({
        'dtls': dtls,
        'cipher': cipher,
        'srtp': srtp,
      })(message);
    }
  }

  Future<void> exec() async {
    if (dtls.flight == 5) {
      log.info('${dtls.sessionId} flight5 twice');
      send(dtls.lastMessage);
      return;
    }
    dtls.flight = 5;

    final needCertificate = dtls.requestedCertificateTypes.isNotEmpty;
    log.info('${dtls.sessionId} send flight5 $needCertificate');

    final messages = [
      if (needCertificate) sendCertificate(),
      sendClientKeyExchange(),
      if (needCertificate) sendCertificateVerify(),
      sendChangeCipherSpec(),
      sendFinished(),
    ].whereType<Uint8List>().toList();

    dtls.lastMessage = messages;
    await transmit(messages);
  }

  Uint8List sendCertificate() {
    final certificate = Certificate([Uint8List.fromList(cipher.localCert)]);

    final packets = createPacket([certificate]);

    final buf = Uint8List.fromList(packets.expand((v) => v.serialize()).toList());
    return buf;
  }

  Uint8List sendClientKeyExchange() {
    if (cipher.localKeyPair == null) throw Exception('Local key pair is null');

    final clientKeyExchange = ClientKeyExchange(cipher.localKeyPair!.publicKey);
    final packets = createPacket([clientKeyExchange]);
    final buf = Uint8List.fromList(packets.expand((v) => v.serialize()).toList());

    final localKeyPair = cipher.localKeyPair!;
    final remoteKeyPair = cipher.remoteKeyPair;

    if (remoteKeyPair.publicKey == null) throw Exception('Remote public key does not exist');

    final preMasterSecret = prfPreMasterSecret(
      remoteKeyPair.publicKey!,
      localKeyPair.privateKey,
      localKeyPair.curve,
    );

    log.info('${dtls.sessionId} extendedMasterSecret ${dtls.options.extendedMasterSecret} ${dtls.remoteExtendedMasterSecret}');

    final handshakes = Uint8List.fromList(dtls.sortedHandshakeCache.expand((v) => v.serialize()).toList());
    cipher.masterSecret = dtls.options.extendedMasterSecret && dtls.remoteExtendedMasterSecret
        ? prfExtendedMasterSecret(preMasterSecret, handshakes)
        : prfMasterSecret(
            preMasterSecret,
            cipher.localRandom.serialize(),
            cipher.remoteRandom.serialize(),
          );

    cipher.cipher = createCipher(cipher.cipherSuite);
    cipher.cipher.init(
      cipher.masterSecret,
      cipher.remoteRandom.serialize(),
      cipher.localRandom.serialize(),
    );
    log.info('${dtls.sessionId} cipher ${cipher.cipher.summary}');

    return buf;
  }

  Uint8List sendCertificateVerify() {
    final cache = Uint8List.fromList(dtls.sortedHandshakeCache.expand((v) => v.serialize()).toList());
    final signed = cipher.signatureData(cache, 'sha256');
    final signatureScheme = () {
      switch (cipher.signatureHashAlgorithm?.signature) {
        case SignatureAlgorithm.ecdsa_3:
          return SignatureScheme.ecdsa_secp256r1_sha256;
        case SignatureAlgorithm.rsa_1:
          return SignatureScheme.rsa_pkcs1_sha256;
      }
    }();
    if (signatureScheme == null) throw Exception('Signature scheme is null');
    log.info('${dtls.sessionId} signatureScheme ${cipher.signatureHashAlgorithm?.signature} $signatureScheme');

    final certificateVerify = CertificateVerify(signatureScheme, signed);
    final packets = createPacket([certificateVerify]);
    final buf = Uint8List.fromList(packets.expand((v) => v.serialize()).toList());
    return buf;
  }

  Uint8List sendChangeCipherSpec() {
    final changeCipherSpec = ChangeCipherSpec.createEmpty().serialize();
    final packets = createPlaintext(dtls)(
      [{'type': ContentType.changeCipherSpec, 'fragment': changeCipherSpec}],
      ++dtls.recordSequenceNumber,
    );
    final buf = Uint8List.fromList(packets.expand((v) => v.serialize()).toList());
    return buf;
  }

  Uint8List sendFinished() {
    final cache = Uint8List.fromList(dtls.sortedHandshakeCache.expand((v) => v.serialize()).toList());
    final localVerifyData = cipher.verifyData(cache);

    final finish = Finished(localVerifyData);
    dtls.epoch = 1;
    final packet = createPacket([finish]).first;
    log.info('${dtls.sessionId} raw finish packet ${packet.summary} ${dtls.sortedHandshakeCache.map((h) => h.summary)}');

    dtls.recordSequenceNumber = 0;

    final buf = cipher.encryptPacket(packet).serialize();
    log.info('${dtls.sessionId} finished ${cipher.cipher.summary}');
    return buf;
  }
}

final handlers = <int, Function(Map<String, dynamic>) Function(dynamic)>{
  HandshakeType.server_hello_2: ({required dtls, required cipher, required srtp}) => (ServerHello message) {
    log.info('${dtls.sessionId} serverHello ${message.cipherSuite}');
    cipher.remoteRandom = DtlsRandom.from(message.random);
    cipher.cipherSuite = message.cipherSuite;
    log.info('${dtls.sessionId} selected cipherSuite ${cipher.cipherSuite}');
  },
};
AI-generated code. Review and use carefully. More info on FAQ.
This Dart code mirrors the structure and functionality of your JavaScript code. If you have any questions or need further adjustments, feel free to ask!

Learn more

1

github.com
You
Sent by you:
Continue converting: handlers[HandshakeType.certificate_11] =
  ({ cipher, dtls }) =>
  (message: Certificate) => {
    log(dtls.sessionId, "handshake certificate", message);
    cipher.remoteCertificate = message.certificateList[0];
  };

handlers[HandshakeType.server_key_exchange_12] =
  ({ cipher, dtls }) =>
  (message: ServerKeyExchange) => {
    if (!cipher.localRandom || !cipher.remoteRandom) throw new Error();
    log(dtls.sessionId, "ServerKeyExchange", message);

    log(dtls.sessionId, "selected curve", message.namedCurve);
    cipher.remoteKeyPair = {
      curve: message.namedCurve,
      publicKey: message.publicKey,
    };
    cipher.localKeyPair = generateKeyPair(message.namedCurve);
  };

handlers[HandshakeType.certificate_request_13] =
  ({ dtls }) =>
  (message: ServerCertificateRequest) => {
    log(dtls.sessionId, "certificate_request", message);
    dtls.requestedCertificateTypes = message.certificateTypes;
    dtls.requestedSignatureAlgorithms = message.signatures;
  };

handlers[HandshakeType.server_hello_done_14] =
  ({ dtls }) =>
  (msg) => {
    log(dtls.sessionId, "server_hello_done", msg);
  };
Copilot
Sent by Copilot:
Continuing with the conversion to Dart:

Dart

handlers[HandshakeType.certificate_11] = ({required cipher, required dtls}) => (Certificate message) {
  log.info('${dtls.sessionId} handshake certificate $message');
  cipher.remoteCertificate = message.certificateList[0];
};

handlers[HandshakeType.server_key_exchange_12] = ({required cipher, required dtls}) => (ServerKeyExchange message) {
  if (cipher.localRandom == null || cipher.remoteRandom == null) throw Exception('Local or remote random is null');
  log.info('${dtls.sessionId} ServerKeyExchange $message');

  log.info('${dtls.sessionId} selected curve ${message.namedCurve}');
  cipher.remoteKeyPair = NamedCurveKeyPair(
    curve: message.namedCurve,
    publicKey: message.publicKey,
  );
  cipher.localKeyPair = generateKeyPair(message.namedCurve);
};

handlers[HandshakeType.certificate_request_13] = ({required dtls}) => (ServerCertificateRequest message) {
  log.info('${dtls.sessionId} certificate_request $message');
  dtls.requestedCertificateTypes = message.certificateTypes;
  dtls.requestedSignatureAlgorithms = message.signatures;
};

handlers[HandshakeType.server_hello_done_14] = ({required dtls}) => (msg) {
  log.info('${dtls.sessionId} server_hello_done $msg');
};
AI-generated code. Review and use carefully. More info on FAQ.
This Dart code mirrors the structure and functionality of your JavaScript code. If you have any questions or need further adjustments, feel free to ask!

You
Sent by you:
Convert to dart: import debug from "debug";
import { setTimeout } from "timers/promises";

import { DtlsContext } from "../context/dtls";
import { TransportContext } from "../context/transport";
import { createFragments, createPlaintext } from "../record/builder";
import { ContentType } from "../record/const";
import { Handshake } from "../typings/domain";

const warn = debug("werift-dtls : packages/dtls/src/flight/flight.ts : warn");
const err = debug("werift-dtls : packages/dtls/src/flight/flight.ts : err");

const flightTypes = ["PREPARING", "SENDING", "WAITING", "FINISHED"] as const;

type FlightType = typeof flightTypes[number];

export abstract class Flight {
  state: FlightType = "PREPARING";
  static RetransmitCount = 10;

  constructor(
    private transport: TransportContext,
    public dtls: DtlsContext,
    private flight: number,
    private nextFlight?: number
  ) {}

  protected createPacket(handshakes: Handshake[]) {
    const fragments = createFragments(this.dtls)(handshakes);
    this.dtls.bufferHandshakeCache(fragments, true, this.flight);
    const packets = createPlaintext(this.dtls)(
      fragments.map((fragment) => ({
        type: ContentType.handshake,
        fragment: fragment.serialize(),
      })),
      ++this.dtls.recordSequenceNumber
    );
    return packets;
  }

  protected async transmit(buffers: Buffer[]) {
    let retransmitCount = 0;
    for (; retransmitCount <= Flight.RetransmitCount; retransmitCount++) {
      this.setState("SENDING");
      this.send(buffers).catch((e) => {
        err("fail to send", err);
      });
      this.setState("WAITING");

      if (this.nextFlight === undefined) {
        this.setState("FINISHED");
        break;
      }

      await setTimeout(1000 * ((retransmitCount + 1) / 2));

      if (this.dtls.flight >= this.nextFlight) {
        this.setState("FINISHED");
        break;
      } else {
        warn(
          this.dtls.sessionId,
          "retransmit",
          retransmitCount,
          this.dtls.flight
        );
      }
    }

    if (retransmitCount > Flight.RetransmitCount) {
      err(this.dtls.sessionId, "retransmit failed", retransmitCount);
      throw new Error(
        `over retransmitCount : ${this.flight} ${this.nextFlight}`
      );
    }
  }

  protected send = (buf: Buffer[]) =>
    Promise.all(buf.map((v) => this.transport.send(v)));

  private setState(state: FlightType) {
    this.state = state;
  }
}
Copilot
Sent by Copilot:
Here’s the Dart equivalent of your JavaScript code:

Dart

import 'dart:async';
import 'package:logging/logging.dart';
import 'dtls_context.dart';
import 'transport_context.dart';
import 'builder.dart';
import 'record_const.dart';
import 'domain.dart';

final warn = Logger('werift-dtls : packages/dtls/src/flight/flight.ts : warn');
final err = Logger('werift-dtls : packages/dtls/src/flight/flight.ts : err');

const flightTypes = ['PREPARING', 'SENDING', 'WAITING', 'FINISHED'];

typedef FlightType = String;

abstract class Flight {
  FlightType state = 'PREPARING';
  static const int RetransmitCount = 10;

  final TransportContext transport;
  final DtlsContext dtls;
  final int flight;
  final int? nextFlight;

  Flight(this.transport, this.dtls, this.flight, [this.nextFlight]);

  List<DtlsPlaintext> createPacket(List<Handshake> handshakes) {
    final fragments = createFragments(dtls)(handshakes);
    dtls.bufferHandshakeCache(fragments, true, flight);
    final packets = createPlaintext(dtls)(
      fragments.map((fragment) => {
        return {
          'type': ContentType.handshake,
          'fragment': fragment.serialize(),
        };
      }).toList(),
      ++dtls.recordSequenceNumber,
    );
    return packets;
  }

  Future<void> transmit(List<Uint8List> buffers) async {
    int retransmitCount = 0;
    for (; retransmitCount <= Flight.RetransmitCount; retransmitCount++) {
      setState('SENDING');
      try {
        await send(buffers);
      } catch (e) {
        err.severe('fail to send', e);
      }
      setState('WAITING');

      if (nextFlight == null) {
        setState('FINISHED');
        break;
      }

      await Future.delayed(Duration(seconds: (retransmitCount + 1) ~/ 2));

      if (dtls.flight >= nextFlight!) {
        setState('FINISHED');
        break;
      } else {
        warn.warning('${dtls.sessionId} retransmit $retransmitCount ${dtls.flight}');
      }
    }

    if (retransmitCount > Flight.RetransmitCount) {
      err.severe('${dtls.sessionId} retransmit failed $retransmitCount');
      throw Exception('over retransmitCount : $flight $nextFlight');
    }
  }

  Future<void> send(List<Uint8List> buf) {
    return Future.wait(buf.map((v) => transport.send(v)));
  }

  void setState(FlightType state) {
    this.state = state;
  }
}
AI-generated code. Review and use carefully. More info on FAQ.
This Dart code mirrors the structure and functionality of your JavaScript code. If you have any questions or need further adjustments, feel free to ask!

You
Sent by you:
Convert to dart: import { randomBytes } from "crypto";
import debug from "debug";

import {
  CipherSuite,
  NamedCurveAlgorithmList,
  NamedCurveAlgorithms,
  SignatureAlgorithm,
} from "../../cipher/const";
import { generateKeyPair } from "../../cipher/namedCurve";
import { CipherContext } from "../../context/cipher";
import { DtlsContext } from "../../context/dtls";
import { Profile, SrtpContext } from "../../context/srtp";
import { TransportContext } from "../../context/transport";
import { EllipticCurves } from "../../handshake/extensions/ellipticCurves";
import { ExtendedMasterSecret } from "../../handshake/extensions/extendedMasterSecret";
import { RenegotiationIndication } from "../../handshake/extensions/renegotiationIndication";
import { Signature } from "../../handshake/extensions/signature";
import { UseSRTP } from "../../handshake/extensions/useSrtp";
import { ClientHello } from "../../handshake/message/client/hello";
import { ServerHelloVerifyRequest } from "../../handshake/message/server/helloVerifyRequest";
import { DtlsRandom } from "../../handshake/random";
import { createFragments, createPlaintext } from "../../record/builder";
import { ContentType } from "../../record/const";

const log = debug("werift-dtls : packages/dtls/flight/server/flight2.ts : log");

// HelloVerifyRequest do not retransmit

export const flight2 =
  (
    udp: TransportContext,
    dtls: DtlsContext,
    cipher: CipherContext,
    srtp: SrtpContext
  ) =>
  (clientHello: ClientHello) => {
    dtls.flight = 2;

    // if flight 2 restarts due to packet loss, sequence numbers are reused from the top:
    // https://datatracker.ietf.org/doc/html/rfc6347#section-4.2.2
    // The first message each side transmits in each handshake always has
    // message_seq = 0.  Whenever each new message is generated, the
    // message_seq value is incremented by one.  Note that in the case of a
    // rehandshake, this implies that the HelloRequest will have message_seq = 0
    // and the ServerHello will have message_seq = 1.  When a message is
    // retransmitted, the same message_seq value is used.
    dtls.recordSequenceNumber = 0;
    dtls.sequenceNumber = 0;

    clientHello.extensions.forEach((extension) => {
      switch (extension.type) {
        case EllipticCurves.type:
          {
            const curves = EllipticCurves.fromData(extension.data).data;
            log(dtls.sessionId, "curves", curves);
            const curve = curves.find((curve) =>
              NamedCurveAlgorithmList.includes(curve as any)
            ) as NamedCurveAlgorithms;
            cipher.namedCurve = curve;
            log(dtls.sessionId, "curve selected", cipher.namedCurve);
          }
          break;
        case Signature.type:
          {
            if (!cipher.signatureHashAlgorithm)
              throw new Error("need to set certificate");

            const signatureHash = Signature.fromData(extension.data).data;
            log(dtls.sessionId, "hash,signature", signatureHash);
            const signature = signatureHash.find(
              (v) => v.signature === cipher.signatureHashAlgorithm?.signature
            )?.signature;
            const hash = signatureHash.find(
              (v) => v.hash === cipher.signatureHashAlgorithm?.hash
            )?.hash;
            if (signature == undefined || hash == undefined) {
              throw new Error("invalid signatureHash");
            }
          }
          break;
        case UseSRTP.type:
          {
            if (!dtls.options?.srtpProfiles) return;
            if (dtls.options.srtpProfiles.length === 0) return;

            const useSrtp = UseSRTP.fromData(extension.data);
            log(dtls.sessionId, "srtp profiles", useSrtp.profiles);
            const profile = SrtpContext.findMatchingSRTPProfile(
              useSrtp.profiles as Profile[],
              dtls.options?.srtpProfiles
            );
            if (!profile) {
              throw new Error();
            }
            srtp.srtpProfile = profile;
            log(dtls.sessionId, "srtp profile selected", srtp.srtpProfile);
          }
          break;
        case ExtendedMasterSecret.type:
          {
            dtls.remoteExtendedMasterSecret = true;
          }
          break;
        case RenegotiationIndication.type:
          {
            log(dtls.sessionId, "RenegotiationIndication", extension.data);
          }
          break;
      }
    });

    cipher.localRandom = new DtlsRandom();
    cipher.remoteRandom = DtlsRandom.from(clientHello.random);

    const suites = clientHello.cipherSuites;
    log(dtls.sessionId, "cipher suites", suites);
    const suite = (() => {
      switch (cipher.signatureHashAlgorithm?.signature) {
        case SignatureAlgorithm.ecdsa_3:
          return CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_49195;
        case SignatureAlgorithm.rsa_1:
          return CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256_49199;
      }
    })();
    if (suite === undefined || !suites.includes(suite)) {
      throw new Error("dtls cipher suite negotiation failed");
    }
    cipher.cipherSuite = suite;
    log(dtls.sessionId, "selected cipherSuite", cipher.cipherSuite);

    cipher.localKeyPair = generateKeyPair(cipher.namedCurve);

    dtls.cookie ||= randomBytes(20);
    const helloVerifyReq = new ServerHelloVerifyRequest(
      {
        major: 255 - 1,
        minor: 255 - 2,
      },
      dtls.cookie
    );
    const fragments = createFragments(dtls)([helloVerifyReq]);
    const packets = createPlaintext(dtls)(
      fragments.map((fragment) => ({
        type: ContentType.handshake,
        fragment: fragment.serialize(),
      })),
      ++dtls.recordSequenceNumber
    );

    const chunk = packets.map((v) => v.serialize());
    for (const buf of chunk) {
      udp.send(buf);
    }
  };
Copilot
Sent by Copilot:
Here’s the Dart equivalent of your JavaScript code:

Dart

import 'dart:typed_data';
import 'dart:math';
import 'package:logging/logging.dart';
import 'cipher_const.dart';
import 'named_curve.dart';
import 'cipher_context.dart';
import 'dtls_context.dart';
import 'srtp_context.dart';
import 'transport_context.dart';
import 'elliptic_curves.dart';
import 'extended_master_secret.dart';
import 'renegotiation_indication.dart';
import 'signature.dart';
import 'use_srtp.dart';
import 'client_hello.dart';
import 'server_hello_verify_request.dart';
import 'dtls_random.dart';
import 'builder.dart';
import 'record_const.dart';

final log = Logger('werift-dtls : packages/dtls/flight/server/flight2.ts : log');

// HelloVerifyRequest do not retransmit

void Function(ClientHello) flight2(
  TransportContext udp,
  DtlsContext dtls,
  CipherContext cipher,
  SrtpContext srtp,
) {
  return (ClientHello clientHello) {
    dtls.flight = 2;

    // if flight 2 restarts due to packet loss, sequence numbers are reused from the top:
    // https://datatracker.ietf.org/doc/html/rfc6347#section-4.2.2
    // The first message each side transmits in each handshake always has
    // message_seq = 0.  Whenever each new message is generated, the
    // message_seq value is incremented by one.  Note that in the case of a
    // rehandshake, this implies that the HelloRequest will have message_seq = 0
    // and the ServerHello will have message_seq = 1.  When a message is
    // retransmitted, the same message_seq value is used.
    dtls.recordSequenceNumber = 0;
    dtls.sequenceNumber = 0;

    for (final extension in clientHello.extensions) {
      switch (extension.type) {
        case EllipticCurves.type:
          final curves = EllipticCurves.fromData(extension.data).data;
          log.info('${dtls.sessionId} curves $curves');
          final curve = curves.firstWhere(
            (curve) => NamedCurveAlgorithmList.contains(curve),
            orElse: () => throw Exception('No matching curve found'),
          ) as NamedCurveAlgorithms;
          cipher.namedCurve = curve;
          log.info('${dtls.sessionId} curve selected ${cipher.namedCurve}');
          break;
        case Signature.type:
          if (cipher.signatureHashAlgorithm == null) {
            throw Exception('Need to set certificate');
          }

          final signatureHash = Signature.fromData(extension.data).data;
          log.info('${dtls.sessionId} hash,signature $signatureHash');
          final signature = signatureHash.firstWhere(
            (v) => v.signature == cipher.signatureHashAlgorithm?.signature,
            orElse: () => throw Exception('Invalid signatureHash'),
          ).signature;
          final hash = signatureHash.firstWhere(
            (v) => v.hash == cipher.signatureHashAlgorithm?.hash,
            orElse: () => throw Exception('Invalid signatureHash'),
          ).hash;
          break;
        case UseSRTP.type:
          if (dtls.options?.srtpProfiles == null || dtls.options.srtpProfiles.isEmpty) {
            return;
          }

          final useSrtp = UseSRTP.fromData(extension.data);
          log.info('${dtls.sessionId} srtp profiles ${useSrtp.profiles}');
          final profile = SrtpContext.findMatchingSRTPProfile(
            useSrtp.profiles.cast<Profile>(),
            dtls.options.srtpProfiles,
          );
          if (profile == null) {
            throw Exception('No matching SRTP profile found');
          }
          srtp.srtpProfile = profile;
          log.info('${dtls.sessionId} srtp profile selected ${srtp.srtpProfile}');
          break;
        case ExtendedMasterSecret.type:
          dtls.remoteExtendedMasterSecret = true;
          break;
        case RenegotiationIndication.type:
          log.info('${dtls.sessionId} RenegotiationIndication ${extension.data}');
          break;
      }
    }

    cipher.localRandom = DtlsRandom();
    cipher.remoteRandom = DtlsRandom.from(clientHello.random);

    final suites = clientHello.cipherSuites;
    log.info('${dtls.sessionId} cipher suites $suites');
    final suite = () {
      switch (cipher.signatureHashAlgorithm?.signature) {
        case SignatureAlgorithm.ecdsa_3:
          return CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_49195;
        case SignatureAlgorithm.rsa_1:
          return CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256_49199;
      }
    }();
    if (suite == null || !suites.contains(suite)) {
      throw Exception('DTLS cipher suite negotiation failed');
    }
    cipher.cipherSuite = suite;
    log.info('${dtls.sessionId} selected cipherSuite ${cipher.cipherSuite}');

    cipher.localKeyPair = generateKeyPair(cipher.namedCurve);

    dtls.cookie ??= Uint8List.fromList(List.generate(20, (_) => Random().nextInt(256)));
    final helloVerifyReq = ServerHelloVerifyRequest(
      {'major': 255 - 1, 'minor': 255 - 2},
      dtls.cookie!,
    );
    final fragments = createFragments(dtls)([helloVerifyReq]);
    final packets = createPlaintext(dtls)(
      fragments.map((fragment) => {
        return {
          'type': ContentType.handshake,
          'fragment': fragment.serialize(),
        };
      }).toList(),
      ++dtls.recordSequenceNumber,
    );

    final chunk = packets.map((v) => v.serialize()).toList();
    for (final buf in chunk) {
      udp.send(buf);
    }
  };
}
AI-generated code. Review and use carefully. More info on FAQ.
This Dart code mirrors the structure and functionality of your JavaScript code. If you have any questions or need further adjustments, feel free to ask!

You
Sent by you:
Convert to dart: import debug from "debug";

import {
  CurveType,
  HashAlgorithm,
  SignatureAlgorithm,
} from "../../cipher/const";
import { CipherContext } from "../../context/cipher";
import { DtlsContext } from "../../context/dtls";
import { SrtpContext } from "../../context/srtp";
import { TransportContext } from "../../context/transport";
import { ExtendedMasterSecret } from "../../handshake/extensions/extendedMasterSecret";
import { RenegotiationIndication } from "../../handshake/extensions/renegotiationIndication";
import { UseSRTP } from "../../handshake/extensions/useSrtp";
import { Certificate } from "../../handshake/message/certificate";
import { ServerCertificateRequest } from "../../handshake/message/server/certificateRequest";
import { ServerHello } from "../../handshake/message/server/hello";
import { ServerHelloDone } from "../../handshake/message/server/helloDone";
import { ServerKeyExchange } from "../../handshake/message/server/keyExchange";
import { FragmentedHandshake } from "../../record/message/fragment";
import { Extension } from "../../typings/domain";
import { Flight } from "../flight";

const log = debug("werift-dtls : packages/dtls/flight/server/flight4.ts : log");

export class Flight4 extends Flight {
  constructor(
    udp: TransportContext,
    dtls: DtlsContext,
    private cipher: CipherContext,
    private srtp: SrtpContext
  ) {
    super(udp, dtls, 4, 6);
  }

  async exec(
    clientHello: FragmentedHandshake,
    certificateRequest: boolean = false
  ) {
    if (this.dtls.flight === 4) {
      log(this.dtls.sessionId, "flight4 twice");
      this.send(this.dtls.lastMessage);
      return;
    }
    this.dtls.flight = 4;
    this.dtls.sequenceNumber = 1;
    this.dtls.bufferHandshakeCache([clientHello], false, 4);

    const messages = [
      this.sendServerHello(),
      this.sendCertificate(),
      this.sendServerKeyExchange(),
      certificateRequest && this.sendCertificateRequest(),
      this.sendServerHelloDone(),
    ].filter((v) => v) as Buffer[];

    this.dtls.lastMessage = messages;
    await this.transmit(messages);
  }

  private sendServerHello() {
    // todo fix; should use socket.extensions
    const extensions: Extension[] = [];
    if (this.srtp.srtpProfile) {
      extensions.push(
        UseSRTP.create([this.srtp.srtpProfile], Buffer.from([0x00])).extension
      );
    }
    if (this.dtls.options.extendedMasterSecret) {
      extensions.push({
        type: ExtendedMasterSecret.type,
        data: Buffer.alloc(0),
      });
    }
    const renegotiationIndication = RenegotiationIndication.createEmpty();
    extensions.push(renegotiationIndication.extension);

    const serverHello = new ServerHello(
      this.dtls.version,
      this.cipher.localRandom,
      Buffer.from([0x00]),
      this.cipher.cipherSuite,
      0, // do not compression
      extensions
    );
    const packets = this.createPacket([serverHello]);
    return Buffer.concat(packets.map((v) => v.serialize()));
  }

  // 7.4.2 Server Certificate
  private sendCertificate() {
    const certificate = new Certificate([Buffer.from(this.cipher.localCert)]);

    const packets = this.createPacket([certificate]);
    return Buffer.concat(packets.map((v) => v.serialize()));
  }

  private sendServerKeyExchange() {
    const signature = this.cipher.generateKeySignature("sha256");
    if (!this.cipher.signatureHashAlgorithm) throw new Error("not exist");

    const keyExchange = new ServerKeyExchange(
      CurveType.named_curve_3,
      this.cipher.namedCurve,
      this.cipher.localKeyPair.publicKey.length,
      this.cipher.localKeyPair.publicKey,
      this.cipher.signatureHashAlgorithm.hash,
      this.cipher.signatureHashAlgorithm.signature,
      signature.length,
      signature
    );

    const packets = this.createPacket([keyExchange]);
    return Buffer.concat(packets.map((v) => v.serialize()));
  }

  // 7.4.4.  Certificate Request
  private sendCertificateRequest() {
    const handshake = new ServerCertificateRequest(
      [
        1, // clientCertificateTypeRSASign
        64, // clientCertificateTypeECDSASign
      ],
      [
        { hash: HashAlgorithm.sha256_4, signature: SignatureAlgorithm.rsa_1 },
        { hash: HashAlgorithm.sha256_4, signature: SignatureAlgorithm.ecdsa_3 },
      ],
      []
    );
    log(this.dtls.sessionId, "sendCertificateRequest", handshake);
    const packets = this.createPacket([handshake]);
    return Buffer.concat(packets.map((v) => v.serialize()));
  }

  private sendServerHelloDone() {
    const handshake = new ServerHelloDone();

    const packets = this.createPacket([handshake]);
    return Buffer.concat(packets.map((v) => v.serialize()));
  }
}
Copilot
Sent by Copilot:
Here’s the Dart equivalent of your JavaScript code:

Dart

import 'dart:typed_data';
import 'package:logging/logging.dart';
import 'cipher_const.dart';
import 'cipher_context.dart';
import 'dtls_context.dart';
import 'srtp_context.dart';
import 'transport_context.dart';
import 'extended_master_secret.dart';
import 'renegotiation_indication.dart';
import 'use_srtp.dart';
import 'certificate.dart';
import 'server_certificate_request.dart';
import 'server_hello.dart';
import 'server_hello_done.dart';
import 'server_key_exchange.dart';
import 'fragment.dart';
import 'domain.dart';
import 'flight.dart';

final log = Logger('werift-dtls : packages/dtls/flight/server/flight4.ts : log');

class Flight4 extends Flight {
  final CipherContext cipher;
  final SrtpContext srtp;

  Flight4(
    TransportContext udp,
    DtlsContext dtls,
    this.cipher,
    this.srtp,
  ) : super(udp, dtls, 4, 6);

  Future<void> exec(FragmentedHandshake clientHello, {bool certificateRequest = false}) async {
    if (dtls.flight == 4) {
      log.info('${dtls.sessionId} flight4 twice');
      send(dtls.lastMessage);
      return;
    }
    dtls.flight = 4;
    dtls.sequenceNumber = 1;
    dtls.bufferHandshakeCache([clientHello], false, 4);

    final messages = [
      sendServerHello(),
      sendCertificate(),
      sendServerKeyExchange(),
      if (certificateRequest) sendCertificateRequest(),
      sendServerHelloDone(),
    ].whereType<Uint8List>().toList();

    dtls.lastMessage = messages;
    await transmit(messages);
  }

  Uint8List sendServerHello() {
    // todo fix; should use socket.extensions
    final extensions = <Extension>[];
    if (srtp.srtpProfile != null) {
      extensions.add(
        UseSRTP.create([srtp.srtpProfile!], Uint8List.fromList([0x00])).extension,
      );
    }
    if (dtls.options.extendedMasterSecret) {
      extensions.add(
        Extension(
          type: ExtendedMasterSecret.type,
          data: Uint8List(0),
        ),
      );
    }
    final renegotiationIndication = RenegotiationIndication.createEmpty();
    extensions.add(renegotiationIndication.extension);

    final serverHello = ServerHello(
      dtls.version,
      cipher.localRandom,
      Uint8List.fromList([0x00]),
      cipher.cipherSuite,
      0, // do not compress
      extensions,
    );
    final packets = createPacket([serverHello]);
    return Uint8List.fromList(packets.expand((v) => v.serialize()).toList());
  }

  // 7.4.2 Server Certificate
  Uint8List sendCertificate() {
    final certificate = Certificate([Uint8List.fromList(cipher.localCert)]);

    final packets = createPacket([certificate]);
    return Uint8List.fromList(packets.expand((v) => v.serialize()).toList());
  }

  Uint8List sendServerKeyExchange() {
    final signature = cipher.generateKeySignature('sha256');
    if (cipher.signatureHashAlgorithm == null) throw Exception('Signature hash algorithm does not exist');

    final keyExchange = ServerKeyExchange(
      CurveType.named_curve_3,
      cipher.namedCurve,
      cipher.localKeyPair.publicKey.length,
      cipher.localKeyPair.publicKey,
      cipher.signatureHashAlgorithm!.hash,
      cipher.signatureHashAlgorithm!.signature,
      signature.length,
      signature,
    );

    final packets = createPacket([keyExchange]);
    return Uint8List.fromList(packets.expand((v) => v.serialize()).toList());
  }

  // 7.4.4.  Certificate Request
  Uint8List sendCertificateRequest() {
    final handshake = ServerCertificateRequest(
      [
        1, // clientCertificateTypeRSASign
        64, // clientCertificateTypeECDSASign
      ],
      [
        SignatureHashAlgorithm(hash: HashAlgorithm.sha256_4, signature: SignatureAlgorithm.rsa_1),
        SignatureHashAlgorithm(hash: HashAlgorithm.sha256_4, signature: SignatureAlgorithm.ecdsa_3),
      ],
      [],
    );
    log.info('${dtls.sessionId} sendCertificateRequest $handshake');
    final packets = createPacket([handshake]);
    return Uint8List.fromList(packets.expand((v) => v.serialize()).toList());
  }

  Uint8List sendServerHelloDone() {
    final handshake = ServerHelloDone();

    final packets = createPacket([handshake]);
    return Uint8List.fromList(packets.expand((v) => v.serialize()).toList());
  }
}
AI-generated code. Review and use carefully. More info on FAQ.
This Dart code mirrors the structure and functionality of your JavaScript code. If you have any questions or need further adjustments, feel free to ask!

You
Sent by you:
Convert to dart: import debug from "debug";

import { createCipher } from "../../cipher/create";
import {
  prfExtendedMasterSecret,
  prfMasterSecret,
  prfPreMasterSecret,
} from "../../cipher/prf";
import { CipherContext } from "../../context/cipher";
import { DtlsContext } from "../../context/dtls";
import { TransportContext } from "../../context/transport";
import { HandshakeType } from "../../handshake/const";
import { Certificate } from "../../handshake/message/certificate";
import { ChangeCipherSpec } from "../../handshake/message/changeCipherSpec";
import { CertificateVerify } from "../../handshake/message/client/certificateVerify";
import { ClientKeyExchange } from "../../handshake/message/client/keyExchange";
import { Finished } from "../../handshake/message/finished";
import { createPlaintext } from "../../record/builder";
import { ContentType } from "../../record/const";
import { FragmentedHandshake } from "../../record/message/fragment";
import { Flight } from "../flight";

const log = debug("werift-dtls : packages/dtls/flight/server/flight6.ts");

export class Flight6 extends Flight {
  constructor(
    udp: TransportContext,
    dtls: DtlsContext,
    private cipher: CipherContext
  ) {
    super(udp, dtls, 6);
  }

  handleHandshake(handshake: FragmentedHandshake) {
    this.dtls.bufferHandshakeCache([handshake], false, 5);

    const message = (() => {
      switch (handshake.msg_type) {
        case HandshakeType.certificate_11:
          return Certificate.deSerialize(handshake.fragment);
        case HandshakeType.certificate_verify_15:
          return CertificateVerify.deSerialize(handshake.fragment);
        case HandshakeType.client_key_exchange_16:
          return ClientKeyExchange.deSerialize(handshake.fragment);
        case HandshakeType.finished_20:
          return Finished.deSerialize(handshake.fragment);
      }
    })();

    if (message) {
      const handler = handlers[message.msgType];
      if (!handler) {
        // todo handle certificate_11
        // todo handle certificate_verify_15
        return;
      }
      handler({ dtls: this.dtls, cipher: this.cipher })(message);
    }
  }

  async exec() {
    if (this.dtls.flight === 6) {
      log(this.dtls.sessionId, "flight6 twice");
      this.send(this.dtls.lastMessage);
      return;
    }
    this.dtls.flight = 6;

    const messages = [this.sendChangeCipherSpec(), this.sendFinished()];
    this.dtls.lastMessage = messages;
    await this.transmit(messages);
  }

  private sendChangeCipherSpec() {
    const changeCipherSpec = ChangeCipherSpec.createEmpty().serialize();
    const packets = createPlaintext(this.dtls)(
      [{ type: ContentType.changeCipherSpec, fragment: changeCipherSpec }],
      ++this.dtls.recordSequenceNumber
    );
    const buf = Buffer.concat(packets.map((v) => v.serialize()));
    return buf;
  }

  private sendFinished() {
    const cache = Buffer.concat(
      this.dtls.sortedHandshakeCache.map((v) => v.serialize())
    );

    const localVerifyData = this.cipher.verifyData(cache);
    const finish = new Finished(localVerifyData);

    this.dtls.epoch = 1;
    const [packet] = this.createPacket([finish]);
    this.dtls.recordSequenceNumber = 0;

    const buf = this.cipher.encryptPacket(packet).serialize();
    return buf;
  }
}

const handlers: {
  [key: number]: (contexts: {
    dtls: DtlsContext;
    cipher: CipherContext;
  }) => (message: any) => void;
} = {};

handlers[HandshakeType.client_key_exchange_16] =
  ({ cipher, dtls }) =>
  (message: ClientKeyExchange) => {
    cipher.remoteKeyPair = {
      curve: cipher.namedCurve,
      publicKey: message.publicKey,
    };
    if (
      !cipher.remoteKeyPair.publicKey ||
      !cipher.localKeyPair ||
      !cipher.remoteRandom ||
      !cipher.localRandom
    )
      throw new Error("not exist");

    const preMasterSecret = prfPreMasterSecret(
      cipher.remoteKeyPair.publicKey,
      cipher.localKeyPair.privateKey,
      cipher.localKeyPair.curve
    );

    log(
      dtls.sessionId,
      "extendedMasterSecret",
      dtls.options.extendedMasterSecret,
      dtls.remoteExtendedMasterSecret
    );

    const handshakes = Buffer.concat(
      dtls.sortedHandshakeCache.map((v) => v.serialize())
    );
    cipher.masterSecret =
      dtls.options.extendedMasterSecret && dtls.remoteExtendedMasterSecret
        ? prfExtendedMasterSecret(preMasterSecret, handshakes)
        : prfMasterSecret(
            preMasterSecret,
            cipher.remoteRandom.serialize(),
            cipher.localRandom.serialize()
          );

    cipher.cipher = createCipher(cipher.cipherSuite!);
    cipher.cipher.init(
      cipher.masterSecret,
      cipher.localRandom.serialize(),
      cipher.remoteRandom.serialize()
    );
    log(dtls.sessionId, "setup cipher", cipher.cipher.summary);
  };

handlers[HandshakeType.finished_20] =
  ({ dtls }) =>
  (message: Finished) => {
    log(dtls.sessionId, "finished", message);
  };
Copilot
Sent by Copilot:
Here’s the Dart equivalent of your JavaScript code:

Dart

import 'dart:typed_data';
import 'package:logging/logging.dart';
import 'cipher_create.dart';
import 'prf.dart';
import 'cipher_context.dart';
import 'dtls_context.dart';
import 'transport_context.dart';
import 'handshake_const.dart';
import 'certificate.dart';
import 'change_cipher_spec.dart';
import 'certificate_verify.dart';
import 'client_key_exchange.dart';
import 'finished.dart';
import 'builder.dart';
import 'record_const.dart';
import 'fragment.dart';
import 'flight.dart';

final log = Logger('werift-dtls : packages/dtls/flight/server/flight6.ts');

class Flight6 extends Flight {
  final CipherContext cipher;

  Flight6(
    TransportContext udp,
    DtlsContext dtls,
    this.cipher,
  ) : super(udp, dtls, 6);

  void handleHandshake(FragmentedHandshake handshake) {
    dtls.bufferHandshakeCache([handshake], false, 5);

    final message = () {
      switch (handshake.msgType) {
        case HandshakeType.certificate_11:
          return Certificate.deSerialize(handshake.fragment);
        case HandshakeType.certificate_verify_15:
          return CertificateVerify.deSerialize(handshake.fragment);
        case HandshakeType.client_key_exchange_16:
          return ClientKeyExchange.deSerialize(handshake.fragment);
        case HandshakeType.finished_20:
          return Finished.deSerialize(handshake.fragment);
      }
    }();

    if (message != null) {
      final handler = handlers[message.msgType];
      if (handler == null) {
        // todo handle certificate_11
        // todo handle certificate_verify_15
        return;
      }
      handler({'dtls': dtls, 'cipher': cipher})(message);
    }
  }

  Future<void> exec() async {
    if (dtls.flight == 6) {
      log.info('${dtls.sessionId} flight6 twice');
      send(dtls.lastMessage);
      return;
    }
    dtls.flight = 6;

    final messages = [sendChangeCipherSpec(), sendFinished()];
    dtls.lastMessage = messages;
    await transmit(messages);
  }

  Uint8List sendChangeCipherSpec() {
    final changeCipherSpec = ChangeCipherSpec.createEmpty().serialize();
    final packets = createPlaintext(dtls)(
      [{'type': ContentType.changeCipherSpec, 'fragment': changeCipherSpec}],
      ++dtls.recordSequenceNumber,
    );
    return Uint8List.fromList(packets.expand((v) => v.serialize()).toList());
  }

  Uint8List sendFinished() {
    final cache = Uint8List.fromList(dtls.sortedHandshakeCache.expand((v) => v.serialize()).toList());

    final localVerifyData = cipher.verifyData(cache);
    final finish = Finished(localVerifyData);

    dtls.epoch = 1;
    final packet = createPacket([finish]).first;
    dtls.recordSequenceNumber = 0;

    return cipher.encryptPacket(packet).serialize();
  }
}

final handlers = <int, Function(Map<String, dynamic>) Function(dynamic)>{
  HandshakeType.client_key_exchange_16: ({required cipher, required dtls}) => (ClientKeyExchange message) {
    cipher.remoteKeyPair = NamedCurveKeyPair(
      curve: cipher.namedCurve,
      publicKey: message.publicKey,
    );
    if (cipher.remoteKeyPair.publicKey == null ||
        cipher.localKeyPair == null ||
        cipher.remoteRandom == null ||
        cipher.localRandom == null) {
      throw Exception('Key pair or random values do not exist');
    }

    final preMasterSecret = prfPreMasterSecret(
      cipher.remoteKeyPair.publicKey!,
      cipher.localKeyPair!.privateKey,
      cipher.localKeyPair!.curve,
    );

    log.info('${dtls.sessionId} extendedMasterSecret ${dtls.options.extendedMasterSecret} ${dtls.remoteExtendedMasterSecret}');

    final handshakes = Uint8List.fromList(dtls.sortedHandshakeCache.expand((v) => v.serialize()).toList());
    cipher.masterSecret = dtls.options.extendedMasterSecret && dtls.remoteExtendedMasterSecret
        ? prfExtendedMasterSecret(preMasterSecret, handshakes)
        : prfMasterSecret(
            preMasterSecret,
            cipher.remoteRandom!.serialize(),
            cipher.localRandom!.serialize(),
          );

    cipher.cipher = createCipher(cipher.cipherSuite!);
    cipher.cipher.init(
      cipher.masterSecret,
      cipher.localRandom!.serialize(),
      cipher.remoteRandom!.serialize(),
    );
    log.info('${dtls.sessionId} setup cipher ${cipher.cipher.summary}');
  },
  HandshakeType.finished_20: ({required dtls}) => (Finished message) {
    log.info('${dtls.sessionId} finished $message');
  },
};
AI-generated code. Review and use carefully. More info on FAQ.
This Dart code mirrors the structure and functionality of your JavaScript code. If you have any questions or need further adjustments, feel free to ask!

Learn more

1

github.com


AI-generated content may be incorrect
What is the purpose of this class?
How can I use it in my Dart application?
Thank you! This is helpful.

Response stopped

New topic
Ask me anything...
