enum SignatureAlgorithm {
  rsa_1(1),
  ecdsa_3(3);

  const SignatureAlgorithm(this.value);
  final int value;

  
  factory SignatureAlgorithm.fromInt(int key) {
    return values.firstWhere((element) => element.value == key);
  }
}

//const ({int rsa_1, int ecdsa_3}) SignatureAlgorithm = (rsa_1: 1, ecdsa_3: 3);
// export type SignatureAlgorithms =
//   typeof SignatureAlgorithm[keyof typeof SignatureAlgorithm];

const Map<int, SignatureAlgorithm> SignatureAlgorithms = {
  1: SignatureAlgorithm.rsa_1,
  3: SignatureAlgorithm.ecdsa_3
};

enum HashAlgorithm {
   sha256_4(4);

   const HashAlgorithm(this.value);
   final int value;
 }
const Map<int,HashAlgorithm>HashAlgorithms = {};

const SignatureHash = (hash:HashAlgorithms,signature:SignatureAlgorithms);
// export type SignatureHash = {
//   hash: HashAlgorithms;
//   signature: SignatureAlgorithms;
// };

enum CipherSuite{
  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_49195(0xc02b), //49195,
  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256_49199(0xc02f); //49199

  const CipherSuite(this.value);
  final int value;

    factory CipherSuite.fromInt(int key) {
    return values.firstWhere((element) => element.value == key);
  }
} 
// export type CipherSuites = typeof CipherSuite[keyof typeof CipherSuite];
// export const CipherSuiteList: CipherSuites[] = Object.values(CipherSuite);

enum NamedCurveAlgorithm {
  x25519_29(29),
  secp256r1_23(23);

  const NamedCurveAlgorithm(this.value);
  final int value;

    factory NamedCurveAlgorithm.fromInt(int key) {
    return values.firstWhere((element) => element.value == key);
  }
} 
// export type NamedCurveAlgorithms =
//   typeof NamedCurveAlgorithm[keyof typeof NamedCurveAlgorithm];
// export const NamedCurveAlgorithmList: NamedCurveAlgorithms[] =
//   Object.values(NamedCurveAlgorithm);

enum CurveType { named_curve_3(3);
const CurveType(this.value);
  final int value;

    factory CurveType.fromInt(int key) {
    return values.firstWhere((element) => element.value == key);
  }
 } 
// export type CurveTypes = typeof CurveType[keyof typeof CurveType];

enum SignatureScheme {
  rsa_pkcs1_sha256(0x0401),
  ecdsa_secp256r1_sha256(0x0403);

  const SignatureScheme(this.value);
  final int value;

    factory SignatureScheme.fromInt(int key) {
    return values.firstWhere((element) => element.value == key);
  }
} 
// export type SignatureSchemes =
//   typeof SignatureScheme[keyof typeof SignatureScheme];
