import 'dart:typed_data';

import '../key_exchange.dart';

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