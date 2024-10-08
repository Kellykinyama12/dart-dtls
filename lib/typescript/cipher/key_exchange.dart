const signTypes = (
  NULL: 0,
  ECDHE: 1,
);

const keyTypes = (
  NULL: 0,
  RSA: 1,
  ECDSA: 2,
  PSK: 3,
);

const kxTypes = (
  NULL: 0,
  RSA: 1,
  ECDHE_RSA: 2,
  ECDHE_ECDSA: 3,
  PSK: 4,
  ECDHE_PSK: 5,
);

/**
 * This class represent type of key exchange mechanism.
 */
class KeyExchange {
  num id = 0;
  String? name;//?: string;
  int? signType;//?: number;
  int? keyType;//?: number;

  KeyExchange();

  /**
   * @returns {string}
   */
  @override
  toString() {
    return "$name";
  }
}

/**
 * Creates `RSA` key exchange.
 * @returns {KeyExchange}
 */
KeyExchange createRSAKeyExchange() {
  final exchange = KeyExchange();

  exchange.id = kxTypes.RSA;
  exchange.name = "RSA";

  exchange.keyType = keyTypes.RSA;

  return exchange;
}

/**
 * Creates `ECDHE_RSA` key exchange.
 * @returns {KeyExchange}
 */
KeyExchange createECDHERSAKeyExchange() {
  final exchange = KeyExchange();

  exchange.id = kxTypes.ECDHE_RSA;
  exchange.name = "ECDHE_RSA";

  exchange.signType = signTypes.ECDHE;
  exchange.keyType = keyTypes.RSA;

  return exchange;
}

/**
 * Creates `ECDHE_ECDSA` key exchange.
 * @returns {KeyExchange}
 */
KeyExchange createECDHEECDSAKeyExchange() {
  final exchange = new KeyExchange();

  exchange.id = kxTypes.ECDHE_ECDSA;
  exchange.name = "ECDHE_ECDSA";

  exchange.signType = signTypes.ECDHE;
  exchange.keyType = keyTypes.ECDSA;

  return exchange;
}

/**
 * Creates `NULL` key exchange.
 * @returns {KeyExchange}
 */
KeyExchangecreateNULLKeyExchange() {
  final exchange = new KeyExchange();

  exchange.id = kxTypes.NULL;
  exchange.name = "NULL";

  exchange.signType = signTypes.NULL;
  exchange.keyType = keyTypes.NULL;

  return exchange;
}

/**
 * Creates `PSK` key exchange.
 * @returns {KeyExchange}
 */
KeyExchange createPSKKeyExchange() {
  final exchange = new KeyExchange();

  exchange.id = kxTypes.PSK;
  exchange.name = "PSK";

  exchange.signType = signTypes.NULL;
  exchange.keyType = keyTypes.PSK;

  return exchange;
}

/**
 * Creates `ECDHE_PSK` key exchange.
 * @returns {KeyExchange}
 */
KeyExchange createECDHEPSKKeyExchange() {
  final exchange = new KeyExchange();

  exchange.id = kxTypes.ECDHE_PSK;
  exchange.name = "ECDHE_PSK";

  exchange.signType = signTypes.ECDHE;
  exchange.keyType = keyTypes.PSK;

  return exchange;
}
