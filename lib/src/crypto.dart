//import 'dart:io';
//import 'dart:typed_data';
//import 'package:asn1lib/asn1lib.dart';
import 'dart:async';
import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart' as cryptoUtils;
import 'package:cryptography/cryptography.dart';
import 'package:dtls2/src/record_header.dart';
import 'package:dtls2/src/utils.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:dtls2/typescript/cipher/const.dart';
//import 'package:cryptography/cryptography.dart';

typedef HashAlgorithm = int;
const CurveX25519 = 0x001d;

String generateSelfSignedCertificate() {
  cryptoUtils.AsymmetricKeyPair<cryptoUtils.PublicKey, cryptoUtils.PrivateKey>
      pair = cryptoUtils.CryptoUtils.generateEcKeyPair();
  var privKey = pair.privateKey as cryptoUtils.ECPrivateKey;
  var pubKey = pair.publicKey as cryptoUtils.ECPublicKey;
  var dn = {
    'CN': 'Self-Signed',
  };
  var csr = cryptoUtils.X509Utils.generateEccCsrPem(dn, privKey, pubKey);

  var x509PEM = cryptoUtils.X509Utils.generateSelfSignedCertificate(
    privKey,
    csr,
    365,
  );
  return x509PEM;
}

Uint8List generateAEADAdditionalData(RecordHeader h, int payloadLen) //[]byte
{
  //https://github.com/pion/dtls/blob/b3e235f54b60ccc31aa10193807b5e8e394f17ff/pkg/crypto/ciphersuite/ciphersuite.go#L18
  /*
		var additionalData [13]byte
		binary.BigEndian.PutUint16(additionalData[0:], h.Epoch)
		copy(additionalData[2:], h.SequenceNumber[:])
		additionalData[8] = byte(h.ContentType)
		binary.BigEndian.PutUint16(additionalData[9:], uint16(h.Version))
		binary.BigEndian.PutUint16(additionalData[len(additionalData)-2:], uint16(payloadLen))

		return additionalData[:]
	*/

  /*
		var additionalData [13]byte
		binary.BigEndian.PutUint16(additionalData[0:], h.Epoch)
		copy(additionalData[2:], h.SequenceNumber[:])
		additionalData[8] = byte(h.ContentType)
		binary.BigEndian.PutUint16(additionalData[9:], uint16(h.Version))

		binary.BigEndian.PutUint16(additionalData[len(additionalData)-2:], uint16(payloadLen))

	*/

  List<int> additionalData = [];
  // SequenceNumber MUST be set first
  // we only want uint48, clobbering an extra 2 (using uint64, Golang doesn't have uint48)
  //binary.BigEndian.PutUint16(additionalData[:], h.Epoch)
  additionalData.addAll(h.epoch);
  //copy(additionalData[2:], h.SequenceNumber[:])

  additionalData.addAll(h.sequenceNumber!);
  additionalData.add(h.enumContentType!.value);
  //binary.BigEndian.PutUint16(additionalData[9:], uint16(h.Version))
  additionalData.addAll(h.version);
  //binary.BigEndian.PutUint16(additionalData[len(additionalData)-2:], uint16(payloadLen))
  additionalData.addAll(uint16toUint8List(payloadLen));
  return Uint8List.fromList(additionalData);
}

Future<(Uint8List, bool?)> GenerateKeyingMaterial(
    Uint8List masterSecret,
    Uint8List clientRandom,
    Uint8List serverRandom,
    HashAlgorithm hashAlgorithm,
    int length)
//([]byte, error)
async {
  List<int> seed =
      []; // := append(append([]byte("EXTRACTOR-dtls_srtp"), clientRandom...), serverRandom...)
  seed.addAll("EXTRACTOR-dtls_srtp".codeUnits);
  seed.addAll(clientRandom);
  seed.addAll(serverRandom);
  final result = await PHash(
      masterSecret, Uint8List.fromList(seed), length, hashAlgorithm);
  // if err != nil {
  // 	return nil, err
  // }
  //logging.Descf(logging.ProtoCRYPTO, "Generated Keying Material using Master Secret, Client Random and Server Random via <u>%s</u>: <u>0x%x</u> (<u>%d bytes</u>)", hashAlgorithm, result, len(result))
  return (result, null);
}

// PHash is PRF is the SHA-256 hash function is used for all cipher suites
// defined in this TLS 1.2 document and in TLS documents published prior to this
// document when TLS 1.2 is negotiated.  New cipher suites MUST explicitly
// specify a PRF and, in general, SHOULD use the TLS PRF with SHA-256 or a
// stronger standard hash function.
//
//    P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
//                           HMAC_hash(secret, A(2) + seed) +
//                           HMAC_hash(secret, A(3) + seed) + ...
//
// A() is defined as:
//
//    A(0) = seed
//    A(i) = HMAC_hash(secret, A(i-1))
//
// P_hash can be iterated as many times as necessary to produce the
// required quantity of data.  For example, if P_SHA256 is being used to
// create 80 bytes of data, it will have to be iterated three times
// (through A(3)), creating 96 bytes of output data; the last 16 bytes
// of the final iteration will then be discarded, leaving 80 bytes of
// output data.
//
// https://tools.ietf.org/html/rfc4346w

// See for further: https://github.com/pion/dtls/blob/a6397ff7282bc56dc37a68ea9211702edb4de1de/pkg/crypto/prf/prf.go#L155
Future<Uint8List> PHash(Uint8List secret, Uint8List seed, int requestedLength,
    HashAlgorithm hashAlgorithm) async
//([]byte, error)
{
  // hashFunc := hashAlgorithm.GetFunction()

  final hashFunc = Hmac.sha256();

  // hmacSHA256 := func(key, data []byte) ([]byte, error) {
  // 	mac := hmac.New(hashFunc, key)
  // 	if _, err := mac.Write(data); err != nil {
  // 		return nil, err
  // 	}
  // 	return mac.Sum(nil), nil
  // }

  // Create a SecretKey from the Uint8List
  // final key = Key(uint8List);

  final secretKey = SecretKey(secret);

  var masterSecret = await hashFunc.calculateMac(
    seed,
    secretKey: secretKey,
  );

  masterSecret = await hashFunc.calculateMac(
    seed,
    secretKey: secretKey,
  );
  return Uint8List.fromList(masterSecret.bytes);

  // var err error
  // lastRound := seed
  // out := []byte{}

  // iterations := int(math.Ceil(float64(requestedLength) / float64(hashFunc().Size())))
  // for i := 0; i < iterations; i++ {
  // 	lastRound, err = hmacSHA256(secret, lastRound)
  // 	if err != nil {
  // 		return nil, err
  // 	}
  // 	withSecret, err := hmacSHA256(secret, append(lastRound, seed...))
  // 	if err != nil {
  // 		return nil, err
  // 	}
  // 	out = append(out, withSecret...)
  // }

  // return out[:requestedLength], nil
}

// func GetCertificateFingerprintFromBytes( Uint8List certificate )  {
// 	fingerprint := sha256.Sum256(certificate)

// 	var buf bytes.Buffer
// 	for i, f := range fingerprint {
// 		if i > 0 {
// 			fmt.Fprintf(&buf, ":")
// 		}
// 		fmt.Fprintf(&buf, "%02X", f)
// 	}
// 	return buf.String()
// }

String GetCertificateFingerprint(List<Uint8List> certificate) {
  return GetCertificateFingerprintFromBytes(certificate.Certificate[0]);
}

String GetCertificateFingerprintFromBytes(Uint8List certificateBytes) {
  // Compute the SHA-256 hash of the certificate bytes
  var digest = crypto.sha256.convert(certificateBytes);

  // Convert the hash to a hexadecimal string
  return digest.bytes
      .map((byte) => byte.toRadixString(16).padLeft(2, '0'))
      .join(':');
}

Future<(Uint8List?, String?)> GeneratePreMasterSecret(
    Uint8List publicKeyBytes, Uint8List privateKeyBytes, Curve curve) async
//([]byte, error)
{
  // TODO: For now, it generates only using X25519
  // https://github.com/pion/dtls/blob/bee42643f57a7f9c85ee3aa6a45a4fa9811ed122/pkg/crypto/prf/prf.go#L106
  switch (curve) {
    case CurveX25519:
      // result, err := curve25519.X25519(privateKey, publicKey)
      // if err != nil {
      // 	return nil, err
      // }
      // logging.Descf(logging.ProtoCRYPTO, "Generated Pre-Master Secret using ClientKeyExchangePublic key and ServerPrivateKey via <u>%s</u>", curve)
      // return result, nil

      // Define the elliptic curve algorithm
      final algorithm = X25519();

      // Example private key bytes (32 bytes)

      // Example public key bytes (32 bytes)

      // Create the private key object
      final privateKey = SimpleKeyPairData(
        privateKeyBytes,
        publicKey: SimplePublicKey(publicKeyBytes, type: KeyPairType.x25519),
        type: KeyPairType.x25519,
      );

      // Create the public key object
      final publicKey =
          SimplePublicKey(publicKeyBytes, type: KeyPairType.x25519);

      // Calculate the shared secret (pre-master secret)
      final sharedSecret = await algorithm.sharedSecretKey(
        keyPair: privateKey,
        remotePublicKey: publicKey,
      );

      // Extract the shared secret bytes
      final sharedSecretBytes = await sharedSecret.extractBytes();
      return (Uint8List.fromList(sharedSecretBytes), null);
  }
  return (null, "not supported curve type");
}

Future<Uint8List> GenerateMasterSecret(
    Uint8List preMasterSecret,
    Uint8List clientRandom,
    Uint8List serverRandom,
    HashAlgorithm hashAlgorithm) async
//([]byte, error)
{
  List<int> seed = [];
  seed.addAll("master secret".codeUnits);
  seed.addAll(clientRandom);
  seed.addAll(serverRandom);
  //seed := append(append([]byte("master secret"), clientRandom...), serverRandom...)
  final result =
      await PHash(preMasterSecret, Uint8List.fromList(seed), 48, hashAlgorithm);
  // if err != nil {
  // 	return nil, err
  // }
  // logging.Descf(logging.ProtoCRYPTO, "Generated MasterSecret (not Extended) using Pre-Master Secret, Client Random and Server Random via <u>%s</u>: <u>0x%x</u> (<u>%d bytes</u>)", hashAlgorithm, result, len(result))
  // return result, nil
  return result;
}

Future<Uint8List> GenerateExtendedMasterSecret(Uint8List preMasterSecret,
    Uint8List handshakeHash, HashAlgorithm hashAlgorithm) async
//([]byte, error)
{
  List<int> seed = [];
  seed.addAll("extended master secret".codeUnits);
  seed.addAll(handshakeHash);

  final result =
      await PHash(preMasterSecret, Uint8List.fromList(seed), 48, hashAlgorithm);

  // if err != nil {
  // 	return nil, err
  // }
  // logging.Descf(logging.ProtoCRYPTO, "Generated Extended MasterSecret using Pre-Master Secret, Handshake Hash via <u>%s</u>: <u>0x%x</u> (<u>%d bytes</u>)", hashAlgorithm, result, len(result))
  // return result, nil
  return result;
}

dynamic GenerateEncryptionKeys(
    Uint8List masterSecret,
    Uint8List clientRandom,
    Uint8List serverRandom,
    int keyLen,
    int ivLen,
    HashAlgorithm hashAlgorithm) async
//(*EncryptionKeys, error)
{
  //https://github.com/pion/dtls/blob/bee42643f57a7f9c85ee3aa6a45a4fa9811ed122/pkg/crypto/prf/prf.go#L199
  // logging.Descf(logging.ProtoCRYPTO, "Generating encryption keys with Key Length: <u>%d</u>, IV Length: <u>%d</u> via <u>%s</u>, using Master Secret, Server Random, Client Random...", keyLen, ivLen, hashAlgorithm)
  // seed := append(append([]byte("key expansion"), serverRandom...), clientRandom...)
  // keyMaterial, err := PHash(masterSecret, seed, (2*keyLen)+(2*ivLen), hashAlgorithm)
  // if err != nil {
  // 	return nil, err
  // }

  List<int> seed = [];
  seed.addAll("key expansion".codeUnits);
  seed.addAll(serverRandom);
  seed.addAll(clientRandom);

  final keyMaterial = await PHash(masterSecret, Uint8List.fromList(seed),
      (2 * keyLen) + (2 * ivLen), hashAlgorithm);

  final clientWriteKey = keyMaterial.sublist(0, keyLen); //[:keyLen]
  final keyMaterial2 = keyMaterial.sublist(keyLen);

  final serverWriteKey = keyMaterial2.sublist(0, keyLen);
  final keyMaterial3 = keyMaterial2.sublist(keyLen);

  final clientWriteIV = keyMaterial3.sublist(
    0,
    ivLen,
  );
  final keyMaterial4 = keyMaterial3.sublist(ivLen);

  final serverWriteIV = keyMaterial4.sublist(0, ivLen);

  return (
    MasterSecret: masterSecret,
    ClientWriteKey: clientWriteKey,
    ServerWriteKey: serverWriteKey,
    ClientWriteIV: clientWriteIV,
    ServerWriteIV: serverWriteIV,
  );
}

dynamic InitGCM(Uint8List masterSecret, Uint8List clientRandom, Uint8List serverRandom, CipherSuite cipherSuite )
//  (*GCM, error)
  {
	//https://github.com/pion/dtls/blob/bee42643f57a7f9c85ee3aa6a45a4fa9811ed122/internal/ciphersuite/tls_ecdhe_ecdsa_with_aes_128_gcm_sha256.go#L60
	//const (
	const	prfKeyLen = 16;
	const	prfIvLen  = 4;
	//)
	// logging.Descf(logging.ProtoCRYPTO, "Initializing GCM with Key Length: <u>%d</u>, IV Length: <u>%d</u>, these values are constants of <u>%s</u> cipher suite.",
	// 	prfKeyLen, prfIvLen, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256")

	final keys = GenerateEncryptionKeys(masterSecret, clientRandom, serverRandom, prfKeyLen, prfIvLen, cipherSuite.HashAlgorithm)
	// if err != nil {
	// 	return nil, err
	// }

	// logging.Descf(logging.ProtoCRYPTO, "Generated encryption keys from keying material (Key Length: <u>%d</u>, IV Length: <u>%d</u>) (<u>%d bytes</u>)\n\tMasterSecret: <u>0x%x</u> (<u>%d bytes</u>)\n\tClientWriteKey: <u>0x%x</u> (<u>%d bytes</u>)\n\tServerWriteKey: <u>0x%x</u> (<u>%d bytes</u>)\n\tClientWriteIV: <u>0x%x</u> (<u>%d bytes</u>)\n\tServerWriteIV: <u>0x%x</u> (<u>%d bytes</u>)",
	// 	prfKeyLen, prfIvLen, prfKeyLen*2+prfIvLen*2,
	// 	keys.MasterSecret, len(keys.MasterSecret),
	// 	keys.ClientWriteKey, len(keys.ClientWriteKey),
	// 	keys.ServerWriteKey, len(keys.ServerWriteKey),
	// 	keys.ClientWriteIV, len(keys.ClientWriteIV),
	// 	keys.ServerWriteIV, len(keys.ServerWriteIV))

	final gcm = NewGCM(keys.ServerWriteKey, keys.ServerWriteIV, keys.ClientWriteKey, keys.ClientWriteIV);
	// if err != nil {
	// 	return nil, err
	// }
	return gcm;//, nil
}

dynamic VerifyCertificate( Uint8List handshakeMessages, HashAlgorithm hashAlgorithm , Uint8List clientSignature, List<Uint8List> clientCertificates) 
//error
 {
	//https://github.com/pion/dtls/blob/b3e235f54b60ccc31aa10193807b5e8e394f17ff/crypto.go#L130
	if( clientCertificates.length == 0) {
		return "client has not sent any certificate";
	}
	// clientCertificate, err := x509.ParseCertificate(clientCertificates[0])
	// if err != nil {
	// 	return err
	// }
	// switch clientCertificatePublicKey := clientCertificate.PublicKey.(type) {
	// case *ecdsa.PublicKey:
	// 	var ecdsaSign ecdsaSignature
	// 	_, err := asn1.Unmarshal(clientSignature, &ecdsaSign)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	if ecdsaSign.R.Sign() <= 0 || ecdsaSign.S.Sign() <= 0 {
	// 		return errors.New("invalid ECDSA signature")
	// 	}
	// 	hash := hashAlgorithm.Execute(handshakeMessages)
	// 	if !ecdsa.Verify(clientCertificatePublicKey, hash, ecdsaSign.R, ecdsaSign.S) {
	// 		return errors.New("key-signature mismatch")
	// 	}
	// 	return nil
	// default:
	// 	return errors.New("unsupported certificate type")
	// }
}

dynamic VerifyFinishedData( Uint8List handshakeMessages, Uint8List serverMasterSecret, HashAlgorithm hashAlgorithm )
 //([]byte, error)
  {
	// hashFunc := hashAlgorithm.GetFunction()()
	// _, err := hashFunc.Write(handshakeMessages)
	// if err != nil {
	// 	return nil, err
	// }
	// seed := append([]byte("server finished"), hashFunc.Sum(nil)...)
	// return PHash(serverMasterSecret, seed, 12, hashAlgorithm)
}
