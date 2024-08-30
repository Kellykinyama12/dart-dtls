// Here’s the updated example to derive session keys from the master secret, ensuring the crypto package is correctly imported and used:

// Dart

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
//import 'package:crypto/crypto.dart' as Crpto;
import 'package:cryptography/cryptography.dart';

const CurveX25519 = 0x001d;


Uint8List generateRandomBytes(int length) {
  final random = Random.secure();
  final bytes = Uint8List(length);
  for (int i = 0; i < length; i++) {
    bytes[i] = random.nextInt(256);
  }
  return bytes;
}

void clientHello() {
  final clientRandom = generateRandomBytes(32);
  final supportedCipherSuites = [0x1301, 0x1302, 0x1303]; // Example cipher suites
  final clientHelloMessage = {
    'version': 'TLS 1.3',
    'random': clientRandom,
    'cipher_suites': supportedCipherSuites,
  };
  print('ClientHello: ${jsonEncode(clientHelloMessage)}');
}

void serverHello() {
  final serverRandom = generateRandomBytes(32);
  final chosenCipherSuite = 0x1301; // Example chosen cipher suite
  final serverHelloMessage = {
    'version': 'TLS 1.3',
    'random': serverRandom,
    'cipher_suite': chosenCipherSuite,
  };
  print('ServerHello: ${jsonEncode(serverHelloMessage)}');
}
Future<void> main() async {
  // Example master secret and random values
  final masterSecret = SecretKey(utf8.encode('master-secret'));

  
  final clientRandom = utf8.encode('client-random');
  final serverRandom = utf8.encode('server-random');

  // Derive session keys
  final sessionKeys =
      await deriveSessionKeys(masterSecret, clientRandom, serverRandom);

  // Print the derived session keys
  print('Client Write Key: ${sessionKeys['clientWriteKey']}');
  print('Server Write Key: ${sessionKeys['serverWriteKey']}');
  print('Client IV: ${sessionKeys['clientIV']}');
  print('Server IV: ${sessionKeys['serverIV']}');
}

Future<void> keyExchange() async {
  final algorithm = X25519();

  // Client generates key pair
  final clientKeyPair = await algorithm.newKeyPair();
  final clientPublicKey = await clientKeyPair.extractPublicKey();

  // Server generates key pair
  final serverKeyPair = await algorithm.newKeyPair();
  final serverPublicKey = await serverKeyPair.extractPublicKey();

  // Client calculates shared secret
  final clientSharedSecret = await algorithm.sharedSecretKey(
    keyPair: clientKeyPair,
    remotePublicKey: serverPublicKey,
  );

  // Server calculates shared secret
  final serverSharedSecret = await algorithm.sharedSecretKey(
    keyPair: serverKeyPair,
    remotePublicKey: clientPublicKey,
  );

  // The shared secrets should be the same
  assert((await clientSharedSecret.extractBytes()) ==
      (await serverSharedSecret.extractBytes()));

  print('Shared Secret: ${await clientSharedSecret.extractBytes()}');
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
  print('Alice\'s shared secret: ${aliceSharedSecret..extractBytes()}');
  print('Bob\'s shared secret: ${bobSharedSecret..extractBytes()}');
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
  assert((await clientSharedSecret.extractBytes()) ==
      (await serverSharedSecret.extractBytes()));

  // Define client write key, server write key, client nonce, and server nonce
  final clientWriteKey = utf8.encode('client-write-key');
  final serverWriteKey = utf8.encode('server-write-key');
  final clientNonce = utf8.encode('client-nonce');
  final serverNonce = utf8.encode('server-nonce');

  // Extract bytes from the shared secret
  final sharedSecretBytes = await clientSharedSecret.extractBytes();

  // Derive keying material using HMAC with SHA-256
  final hmac = Hmac.sha256();
  final keyingMaterial = await hmac.calculateMac(
    Uint8List.fromList(sharedSecretBytes +
        clientWriteKey +
        serverWriteKey +
        clientNonce +
        serverNonce),
    secretKey: SecretKey(sharedSecretBytes),
  );

  // Print the derived keying material in hexadecimal format
  print(
      'Derived Keying Material: ${keyingMaterial.bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join()}');
}

Future<SecretKey> deriveMasterSecret(SecretKey preMasterSecret,
    Uint8List clientRandom, Uint8List serverRandom) async {
  final hmac = Hmac.sha256();
  final seed = Uint8List.fromList(clientRandom + serverRandom);
  final masterSecret = await hmac.calculateMac(
    seed,
    secretKey: preMasterSecret,
  );
  return SecretKey(masterSecret.bytes);
}

Future<void> extendedMasterSecret() async {
  // Define the pre-master secret, client random, and server random
  final preMasterSecret = utf8.encode('pre-master-secret');
  final clientRandom = utf8.encode('client-random');
  final serverRandom = utf8.encode('server-random');

  // Concatenate client random and server random
  final seed = Uint8List.fromList(clientRandom + serverRandom);

  // Generate the master secret using HMAC with SHA-256
  final hmac = Hmac.sha256();
  final masterSecret = await hmac.calculateMac(
    Uint8List.fromList(preMasterSecret),
    secretKey: SecretKey(seed),
  );

  // Print the master secret in hexadecimal format
  print(
      'Master Secret: ${masterSecret.bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join()}');
}

Future<Map<String, Uint8List>> deriveSessionKeys(SecretKey masterSecret,
    Uint8List clientRandom, Uint8List serverRandom) async {
  final hmac = Hmac.sha256();
  final seed = Uint8List.fromList(clientRandom + serverRandom);

  // Derive key material
  final keyMaterial = await hmac.calculateMac(
    seed,
    secretKey: masterSecret,
  );

  // Split the key material into session keys and IVs
  final keyMaterialBytes = keyMaterial.bytes;
  final clientWriteKey = keyMaterialBytes.sublist(0, 16);
  final serverWriteKey = keyMaterialBytes.sublist(16, 32);
  final clientIV = keyMaterialBytes.sublist(32, 48);
  final serverIV = keyMaterialBytes.sublist(48, 64);

  return {
    'clientWriteKey': Uint8List.fromList(clientWriteKey),
    'serverWriteKey': Uint8List.fromList(serverWriteKey),
    'clientIV': Uint8List.fromList(clientIV),
    'serverIV': Uint8List.fromList(serverIV),
  };
}
// AI-generated code. Review and use carefully. More info on FAQ.
// Explanation
// Import the Package: Ensure the crypto package is imported correctly.
// Master Secret and Random Values: Define the master secret and the client/server random values.
// Key Derivation Function (KDF): Use HMAC with SHA-256 to derive key material from the master secret and the concatenated client and server random values.
// Split Key Material: Split the derived key material into session keys and IVs. In this example, we assume 16 bytes for each key and IV.
// Output: Print the derived session keys and IVs.
// This should resolve the issue with the sha256 constant not being recognized. If you have any further questions or need additional assistance, feel free to ask!
Future<void> PreMasterSecretFromPrivPub() async {
  // Define the elliptic curve algorithm
  final algorithm = X25519();

  // Example private key bytes (32 bytes)
  final privateKeyBytes = Uint8List.fromList([
    0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
    0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
    0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
    0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
  ]);

  // Example public key bytes (32 bytes)
  final publicKeyBytes = Uint8List.fromList([
    0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
    0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
    0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
    0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
  ]);

  // Create the private key object
  final privateKey = SimpleKeyPairData(
    privateKeyBytes,
    publicKey: SimplePublicKey(publicKeyBytes, type: KeyPairType.x25519),
    type: KeyPairType.x25519,
  );

  // Create the public key object
  final publicKey = SimplePublicKey(publicKeyBytes, type: KeyPairType.x25519);

  // Calculate the shared secret (pre-master secret)
  final sharedSecret = await algorithm.sharedSecretKey(
    keyPair: privateKey,
    remotePublicKey: publicKey,
  );

  // Extract the shared secret bytes
  final sharedSecretBytes = await sharedSecret.extractBytes();

  print('Pre-Master Secret: ${sharedSecretBytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join()}');
}

dynamic GenerateCurveKeypair(curve) async
//([]byte, []byte, error)
{
  switch (curve) {
    case CurveX25519:
      final algorithm = X25519();
      // TODO: For now, it generates only using X25519
      // https://github.com/pion/dtls/blob/bee42643f57a7f9c85ee3aa6a45a4fa9811ed122/pkg/crypto/elliptic/elliptic.go#L70
      // Client generates key pair
      final clientKeyPair = await algorithm.newKeyPair();
      final clientPublicKey = await clientKeyPair.extractPublicKey();

      final clientPrivateKey = await clientKeyPair.extractPrivateKeyBytes();
      return (clientPublicKey.bytes, clientPrivateKey, null);
  }
  return (null, null, ("not supported curve"));
}

Future<void> AES_GCM() async {
  // Define the AES-GCM algorithm
  final algorithm = AesGcm.with256bits();

  // Define the keys and IVs
  final localKey = SecretKey(Uint8List.fromList(List.generate(32, (i) => i))); // Example 256-bit key
  final localWriteIV = Uint8List.fromList(List.generate(12, (i) => i)); // Example 96-bit IV
  final remoteKey = SecretKey(Uint8List.fromList(List.generate(32, (i) => 32 + i))); // Example 256-bit key
  final remoteWriteIV = Uint8List.fromList(List.generate(12, (i) => 12 + i)); // Example 96-bit IV

  // Define the message to be encrypted
  final message = utf8.encode('Hello, AES-GCM with specific keys and IVs!');

  // Encrypt the message using localKey and localWriteIV
  final secretBox = await algorithm.encrypt(
    message,
    secretKey: localKey,
    nonce: localWriteIV,
  );

  // Print the encrypted data
  print('Encrypted: ${base64Encode(secretBox.cipherText)}');
  print('Nonce: ${base64Encode(secretBox.nonce)}');
  print('MAC: ${base64Encode(secretBox.mac.bytes)}');

  // Decrypt the message using remoteKey and remoteWriteIV
  final decryptedMessage = await algorithm.decrypt(
    SecretBox(
      secretBox.cipherText,
      nonce: remoteWriteIV,
      mac: secretBox.mac,
    ),
    secretKey: remoteKey,
  );

  // Print the decrypted message
  print('Decrypted: ${utf8.decode(decryptedMessage)}');
}