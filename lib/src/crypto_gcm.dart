// import "package:cryptography/src/cryptography/cryptography.dart";
import "dart:typed_data";

import "package:cryptography/cryptography.dart";
import "package:cryptography/src/cryptography/algorithms.dart";
import "package:dtls2/src/crypto.dart";
import "package:dtls2/src/record_header.dart";

//const (
const gcmTagLength = 16;
const gcmNonceLength = 12;
const headerSize = 13;
//)

class GCM {
  final localGCM = AesGcm.with256bits(nonceLength: gcmNonceLength);
  final remoteGCM =
      AesGcm.with256bits(nonceLength: gcmNonceLength); //         cipher.AEAD
// Uint8List	localWriteIV,
//  Uint8List remoteWriteIV;

  final localKey;// = SecretKey(
     // Uint8List.fromList(List.generate(32, (i) => i))); // Example 256-bit key
  final localWriteIV;// =
      //Uint8List.fromList(List.generate(12, (i) => i)); // Example 96-bit IV
  final remoteKey;// = SecretKey(Uint8List.fromList(
      //List.generate(32, (i) => 32 + i))); // Example 256-bit key
  final remoteWriteIV;// =
     // Uint8List.fromList(List.generate(12, (i) => 12 + i)); // Example 96-bit IV


GCM(this.localKey, this.localWriteIV,this. remoteKey, this.remoteWriteIV);
// Encrypts a DTLS RecordLayer message
  Future<Uint8List> encrypt(RecordHeader header, Uint8List raw) async
//([]byte, error)
  {
    // nonce := make([]byte, gcmNonceLength)
    // copy(nonce, g.localWriteIV[:4])
    // if _, err := rand.Read(nonce[4:]); err != nil {
    // 	return nil, err
    // }

    Uint8List additionalData = generateAEADAdditionalData(header, raw.length);
    // Encrypt the message using localKey and localWriteIV
    final secretBox = await localGCM.encrypt(raw,
        secretKey: localKey, nonce: localWriteIV, aad: additionalData);

    return secretBox.concatenation();
    // encryptedPayload := g.localGCM.Seal(nil, nonce, raw, additionalData)
    // r := make([]byte, len(nonce[4:])+len(encryptedPayload))
    // copy(r, nonce[4:])
    // copy(r[len(nonce[4:]):], encryptedPayload)
    // return r, nil
  }

// Decrypts a DTLS RecordLayer message
  dynamic decrypt(RecordHeader h, Uint8List encryptedBytes) async
// ([]byte, error)

  {
    if (h.enumContentType == ContentType.change_cipher_spec) {
      //case ContentType.change_cipher_spec:
      // Nothing to encrypt with ChangeCipherSpec
      return (encryptedBytes, null);
    }

    SecretBox secretBox = SecretBox.fromConcatenation(encryptedBytes,
        nonceLength: gcmNonceLength, macLength: gcmTagLength);

    // nonce := make([]byte, 0, gcmNonceLength)
    // nonce = append(append(nonce, g.remoteWriteIV[:4]...), in[0:8]...)
    // out := in[8:]

    // additionalData := generateAEADAdditionalData(h, len(out)-gcmTagLength)
    // var err error
    // out, err = g.remoteGCM.Open(out[:0], nonce, out, additionalData)
    // if err != nil {
    // 	return nil, fmt.Errorf("error on decrypting packet: %v", err)
    // }
    // return out, nil

    Uint8List additionalData =
        generateAEADAdditionalData(h, secretBox.cipherText.sublist(8).length);
// Decrypt the message using remoteKey and remoteWriteIV
    final decryptedMessage = await remoteGCM.decrypt(
        SecretBox(
          secretBox.cipherText,
          nonce: remoteWriteIV,
          mac: secretBox.mac,
        ),
        secretKey: remoteKey,
        aad: additionalData);

    return (decryptedMessage, null);
  }
  // localKey, localWriteIV, remoteKey, remoteWriteIV []byte
}

// NewGCM creates a DTLS GCM Cipher
// func NewGCM(localKey, localWriteIV, remoteKey, remoteWriteIV) (*GCM, error) {
// 	localBlock, err := aes.NewCipher(localKey)
// 	if err != nil {
// 		return nil, err
// 	}
// 	localGCM, err := cipher.NewGCM(localBlock)
// 	if err != nil {
// 		return nil, err
// 	}

// 	remoteBlock, err := aes.NewCipher(remoteKey)
// 	if err != nil {
// 		return nil, err
// 	}
// 	remoteGCM, err := cipher.NewGCM(remoteBlock)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return &GCM{
// 		localGCM:      localGCM,
// 		localWriteIV:  localWriteIV,
// 		remoteGCM:     remoteGCM,
// 		remoteWriteIV: remoteWriteIV,
// 	}, nil
// }
