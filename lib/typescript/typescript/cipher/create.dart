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
