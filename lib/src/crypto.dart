//import 'dart:io';
//import 'dart:typed_data';
//import 'package:asn1lib/asn1lib.dart';
import 'package:basic_utils/basic_utils.dart';
//import 'package:cryptography/cryptography.dart';

String generateSelfSignedCertificate() {
  var pair = CryptoUtils.generateEcKeyPair();
  var privKey = pair.privateKey as ECPrivateKey;
  var pubKey = pair.publicKey as ECPublicKey;
  var dn = {
    'CN': 'Self-Signed',
  };
  var csr = X509Utils.generateEccCsrPem(dn, privKey, pubKey);

  var x509PEM = X509Utils.generateSelfSignedCertificate(
    privKey,
    csr,
    365,
  );
  return x509PEM;
}
