import 'dart:typed_data';

import 'package:dtls2/typescript/typescript/cipher/key_exchange.dart';

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