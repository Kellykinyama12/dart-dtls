// import { createDecode } from "binary-data";
// import { createHash, createHmac } from "crypto";
// import { ec } from "elliptic";
// import * as nacl from "tweetnacl";

// import { NamedCurveAlgorithm, NamedCurveAlgorithms } from "./const";

import 'dart:convert';

import 'package:dtls2/typescript/cipher/const.dart';
//import 'package:basic_utils/basic_utils.dart';
// import 'package:pinenacl/public.dart' show SealedBox, PrivateKey;
// import 'package:pinenacl/api.dart';
// import 'package:pinenacl/api/api.dart';
 import 'package:pinenacl/api/authenticated_encryption.dart';
import 'package:pinenacl/x25519.dart';
// import 'package:pinenacl/api/encoding.dart';
// import 'package:pinenacl/api/signatures.dart';
// import 'package:pinenacl/digests.dart';
// import 'package:pinenacl/ed25519.dart';
// import 'package:pinenacl/encoding.dart';
// import 'package:pinenacl/key_derivation.dart';
// import 'package:pinenacl/message_authentication.dart';
// import 'package:pinenacl/tweetnacl.dart';
// import 'package:pinenacl/x25519.dart';

import 'package:cryptography/cryptography.dart';

import 'package:crypto/crypto.dart' as crypto;

export function prfPreMasterSecret(
  publicKey: Buffer,
  privateKey: Buffer,
  curve: NamedCurveAlgorithms
)async {
  switch (curve) {
    case NamedCurveAlgorithm.secp256r1_23:
      // const elliptic = new ec("p256"); // aka secp256r1
      // const pub = elliptic.keyFromPublic(publicKey).getPublic();
      // const priv = elliptic.keyFromPrivate(privateKey).getPrivate();
      // const res = pub.mul(priv);
      // const secret = Buffer.from(res.encode("array", false)).slice(1, 33);

      // Generate Bob's private key, which must be kept secret
  final skbob = PrivateKey.generate();
  final pkbob = skbob.publicKey;

  // Alice wishes to send a encrypted message to Bob,
  // but prefers the message to be untraceable
  // she puts it into a secretbox and seals it.
  final sealedBox = SealedBox(pkbob);

  final message = 'The world is changing around us and we can either get '
      'with the change or we can try to resist it';

  final encrypted = sealedBox.encrypt(Uint8List.fromList(message.codeUnits));

  // Bob unseals the box with his privatekey, and decrypts it.
  final unsealedBox = SealedBox(skbob);

  final plainText = unsealedBox.decrypt(encrypted);
  print(String.fromCharCodes(plainText));
  assert(message == String.fromCharCodes(plainText));



      //  AsymmetricKeyPair<PublicKey, PrivateKey> pair =
      //       CryptoUtils.generateEcKeyPair(curve: "secp256r1");
      //   var privKey = pair.privateKey as ECPrivateKey;
      //   var pubKey = pair.publicKey as ECPublicKey;
      return sealedBox;
    case NamedCurveAlgorithm.x25519_29:
      {
        // return Buffer.from(nacl.scalarMult(privateKey, publicKey));

 // Generate a key pair for Alice
  final algorithm = X25519();
  final aliceKeyPair = await algorithm.newKeyPair();
  final alicePublicKey = await aliceKeyPair.extractPublicKey();

  // Generate a key pair for Bob
  final bobKeyPair = await algorithm.newKeyPair();
  final bobPublicKey = await bobKeyPair.extractPublicKey();

  // Alice calculates the shared secret using Bob's public key
  final aliceSharedSecret = await algorithm.sharedSecretKey(
    keyPair: aliceKeyPair,
    remotePublicKey: bobPublicKey,
  );

  // Bob calculates the shared secret using Alice's public key
  final bobSharedSecret = await algorithm.sharedSecretKey(
    keyPair: bobKeyPair,
    remotePublicKey: alicePublicKey,
  );

  // The shared secrets should be the same
  print('Alice\'s shared secret: ${aliceSharedSecret.bytes}');
  print('Bob\'s shared secret: ${bobSharedSecret.bytes}');
      }
    default:
      throw new Error();
  }
}

dynamic hmac(algorithm: string, secret: Buffer, data: Buffer) async{
  // const hash = createHmac(algorithm, secret);
  // hash.update(data);
  // return hash.digest();

  final sink = Sha256().newHashSink();

  // Add all parts of the authenticated message
  sink.add([1, 2, 3]);
  sink.add([4, 5]);
  sink.add([6]);

  // Calculate hash
  sink.close();
  final hash = await sink.hash();

  print('SHA-512 hash: ${hash.bytes}');
}

dynamic prfPHash(
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

// export function exportKeyingMaterial(
//   label: string,
//   length: number,
//   masterSecret: Buffer,
//   localRandom: Buffer,
//   remoteRandom: Buffer,
//   isClient: boolean
// ) {
//   const clientRandom = isClient ? localRandom : remoteRandom;
//   const serverRandom = isClient ? remoteRandom : localRandom;
//   const seed = Buffer.concat([Buffer.from(label), clientRandom, serverRandom]);
//   return prfPHash(masterSecret, seed, length);
// }

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

Future<void> extendedMasterSecret() async {
  // Define the pre-master secret, client random, and server random
  final preMasterSecret = utf8.encode('pre-master-secret');
  final clientRandom = utf8.encode('client-random');
  final serverRandom = utf8.encode('server-random');

  // Concatenate client random and server random
  final seed = Uint8List.fromList(clientRandom + serverRandom);

  // Generate the master secret using HMAC with SHA-256
  final hmac = Hmac(sha256);
  final masterSecret = await hmac.calculateMac(
    Uint8List.fromList(preMasterSecret),
    secretKey: SecretKey(seed),
  );

  // Print the master secret in hexadecimal format
  print('Master Secret: ${masterSecret.bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join()}');
}


Future<void> preMasterSecret() async {
  // Define the elliptic curve algorithm
  final algorithm = X25519();

  // Generate a key pair for Alice
  final aliceKeyPair = await algorithm.newKeyPair();
  final alicePublicKey = await aliceKeyPair.extractPublicKey();

  // Generate a key pair for Bob
  final bobKeyPair = await algorithm.newKeyPair();
  final bobPublicKey = await bobKeyPair.extractPublicKey();

  // Alice calculates the shared secret using Bob's public key
  final aliceSharedSecret = await algorithm.sharedSecretKey(
    keyPair: aliceKeyPair,
    remotePublicKey: bobPublicKey,
  );

  // Bob calculates the shared secret using Alice's public key
  final bobSharedSecret = await algorithm.sharedSecretKey(
    keyPair: bobKeyPair,
    remotePublicKey: alicePublicKey,
  );

  // The shared secrets should be the same
  print('Alice\'s shared secret: ${aliceSharedSecret.bytes}');
  print('Bob\'s shared secret: ${bobSharedSecret.bytes}');
}


Future<void> finalKeyUsingSharedSecret() async {
  // Define the elliptic curve algorithm
  final algorithm = X25519();

  // Generate a key pair for the client
  final clientKeyPair = await algorithm.newKeyPair();
  final clientPublicKey = await clientKeyPair.extractPublicKey();

  // Generate a key pair for the server
  final serverKeyPair = await algorithm.newKeyPair();
  final serverPublicKey = await serverKeyPair.extractPublicKey();

  // Define client and server write keys (for demonstration purposes, using the public keys)
  final clientWriteKey = clientPublicKey.bytes;
  final serverWriteKey = serverPublicKey.bytes;

  // Define client and server nonces
  final clientNonce = utf8.encode('client-nonce');
  final serverNonce = utf8.encode('server-nonce');

  // Client calculates the shared secret using the server's public key
  final clientSharedSecret = await algorithm.sharedSecretKey(
    keyPair: clientKeyPair,
    remotePublicKey: serverPublicKey,
  );

  // Server calculates the shared secret using the client's public key
  final serverSharedSecret = await algorithm.sharedSecretKey(
    keyPair: serverKeyPair,
    remotePublicKey: clientPublicKey,
  );

  // The shared secrets should be the same
  print('Client\'s shared secret: ${clientSharedSecret.bytes}');
  print('Server\'s shared secret: ${serverSharedSecret.bytes}');

  // Derive a final key using the shared secret, client write key, server write key, client nonce, and server nonce
  final finalKey = Hmac(sha256).calculateMac(
    Uint8List.fromList(clientSharedSecret.bytes + clientWriteKey + serverWriteKey + clientNonce + serverNonce),
    secretKey: SecretKey(clientSharedSecret.bytes),
  );

  print('Final derived key: ${finalKey.bytes}');
}
// AI-generated code. Review and use carefully. More info on FAQ.
// Explanation
// Algorithm Definition: Define the elliptic curve algorithm (X25519 in this case).
// Key Pair Generation: Generate key pairs for both the client and the server.
// Public Key Extraction: Extract the public keys from the generated key pairs.
// Parameter Definition: Define the client write key, server write key, client nonce, and server nonce.
// Shared Secret Calculation: Both the client and the server calculate the shared secret using their private key and the other party’s public key.
// Final Key Derivation: Use HMAC with SHA-256 to derive a final key from the shared secret, client write key, server write key, client nonce, and server nonce.
// Output: Print the shared secrets and the final derived key.
// This example demonstrates how to use the specified parameters to derive a shared secret and a final key using elliptic curve cryptography in Dart. If you have any specific requirements or further questions, feel free to ask!

Future<void> exportKeyingMaterial() async {
  // Define the elliptic curve algorithm
  final algorithm = X25519();

  // Generate a key pair for the client
  final clientKeyPair = await algorithm.newKeyPair();
  final clientPublicKey = await clientKeyPair.extractPublicKey();

  // Generate a key pair for the server
  final serverKeyPair = await algorithm.newKeyPair();
  final serverPublicKey = await serverKeyPair.extractPublicKey();

  // Client calculates the shared secret using the server's public key
  final clientSharedSecret = await algorithm.sharedSecretKey(
    keyPair: clientKeyPair,
    remotePublicKey: serverPublicKey,
  );

  // Server calculates the shared secret using the client's public key
  final serverSharedSecret = await algorithm.sharedSecretKey(
    keyPair: serverKeyPair,
    remotePublicKey: clientPublicKey,
  );

  // The shared secrets should be the same
  assert(clientSharedSecret.bytes == serverSharedSecret.bytes);

  // Define client write key, server write key, client nonce, and server nonce
  final clientWriteKey = utf8.encode('client-write-key');
  final serverWriteKey = utf8.encode('server-write-key');
  final clientNonce = utf8.encode('client-nonce');
  final serverNonce = utf8.encode('server-nonce');

  // Derive keying material using HMAC with SHA-256
  final hmac = Hmac(sha256);
  final keyingMaterial = await hmac.calculateMac(
    Uint8List.fromList(clientSharedSecret.bytes + clientWriteKey + serverWriteKey + clientNonce + serverNonce),
    secretKey: SecretKey(clientSharedSecret.bytes),
  );

  // Print the derived keying material in hexadecimal format
  print('Derived Keying Material: ${keyingMaterial.bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join()}');
}
// AI-generated code. Review and use carefully. More info on FAQ.
// Explanation
// Algorithm Definition: Define the elliptic curve algorithm (X25519 in this case).
// Key Pair Generation: Generate key pairs for both the client and the server.
// Shared Secret Calculation: Both the client and the server calculate the shared secret using their private key and the other party’s public key.
// Parameter Definition: Define the client write key, server write key, client nonce, and server nonce.
// Keying Material Derivation: Use HMAC with SHA-256 to derive keying material from the shared secret and the specified parameters.
// Output: Print the derived keying material in hexadecimal format.
// This example demonstrates how to derive and export keying material using elliptic curve cryptography and HMAC in Dart. If you have any specific requirements or further questions, feel free to ask!

Future<void> exportKeyingMaterial2() async {
  // Define the elliptic curve algorithm
  final algorithm = X25519();

  // Generate a key pair for the client
  final clientKeyPair = await algorithm.newKeyPair();
  final clientPublicKey = await clientKeyPair.extractPublicKey();

  // Generate a key pair for the server
  final serverKeyPair = await algorithm.newKeyPair();
  final serverPublicKey = await serverKeyPair.extractPublicKey();

  // Client calculates the shared secret using the server's public key
  final clientSharedSecret = await algorithm.sharedSecretKey(
    keyPair: clientKeyPair,
    remotePublicKey: serverPublicKey,
  );

  // Server calculates the shared secret using the client's public key
  final serverSharedSecret = await algorithm.sharedSecretKey(
    keyPair: serverKeyPair,
    remotePublicKey: clientPublicKey,
  );

  // The shared secrets should be the same
  assert((await clientSharedSecret.extractBytes()) == (await serverSharedSecret.extractBytes()));

  // Define client write key, server write key, client nonce, and server nonce
  final clientWriteKey = utf8.encode('client-write-key');
  final serverWriteKey = utf8.encode('server-write-key');
  final clientNonce = utf8.encode('client-nonce');
  final serverNonce = utf8.encode('server-nonce');

  // Extract bytes from the shared secret
  final sharedSecretBytes = await clientSharedSecret.extractBytes();

  // Derive keying material using HMAC with SHA-256
  final hmac = Hmac(sha256);
  final keyingMaterial = await hmac.calculateMac(
    Uint8List.fromList(sharedSecretBytes + clientWriteKey + serverWriteKey + clientNonce + serverNonce),
    secretKey: SecretKey(sharedSecretBytes),
  );

  // Print the derived keying material in hexadecimal format
  print('Derived Keying Material: ${keyingMaterial.bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join()}');
}