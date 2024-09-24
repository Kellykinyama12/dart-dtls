class SignTypes {
  static const int NULL = 0;
  static const int ECDHE = 1;
}

class KeyTypes {
  static const int NULL = 0;
  static const int RSA = 1;
  static const int ECDSA = 2;
  static const int PSK = 3;
}

class KxTypes {
  static const int NULL = 0;
  static const int RSA = 1;
  static const int ECDHE_RSA = 2;
  static const int ECDHE_ECDSA = 3;
  static const int PSK = 4;
  static const int ECDHE_PSK = 5;
}

class KeyExchange {
  int id = 0;
  String? name;
  int? signType;
  int? keyType;

  @override
  String toString() {
    return name ?? '';
  }
}

KeyExchange createRSAKeyExchange() {
  final exchange = KeyExchange()
    ..id = KxTypes.RSA
    ..name = 'RSA'
    ..keyType = KeyTypes.RSA;

  return exchange;
}

KeyExchange createECDHERSAKeyExchange() {
  final exchange = KeyExchange()
    ..id = KxTypes.ECDHE_RSA
    ..name = 'ECDHE_RSA'
    ..signType = SignTypes.ECDHE
    ..keyType = KeyTypes.RSA;

  return exchange;
}

KeyExchange createECDHEECDSAKeyExchange() {
  final exchange = KeyExchange()
    ..id = KxTypes.ECDHE_ECDSA
    ..name = 'ECDHE_ECDSA'
    ..signType = SignTypes.ECDHE
    ..keyType = KeyTypes.ECDSA;

  return exchange;
}

KeyExchange createNULLKeyExchange() {
  final exchange = KeyExchange()
    ..id = KxTypes.NULL
    ..name = 'NULL'
    ..signType = SignTypes.NULL
    ..keyType = KeyTypes.NULL;

  return exchange;
}

KeyExchange createPSKKeyExchange() {
  final exchange = KeyExchange()
    ..id = KxTypes.PSK
    ..name = 'PSK'
    ..signType = SignTypes.NULL
    ..keyType = KeyTypes.PSK;

  return exchange;
}

KeyExchange createECDHEPSKKeyExchange() {
  final exchange = KeyExchange()
    ..id = KxTypes.ECDHE_PSK
    ..name = 'ECDHE_PSK'
    ..signType = SignTypes.ECDHE
    ..keyType = KeyTypes.PSK;

  return exchange;
}