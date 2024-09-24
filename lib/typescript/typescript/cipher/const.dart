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