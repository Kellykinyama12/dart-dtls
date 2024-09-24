import 'package:logging/logging.dart';
import 'cipher_const.dart';
import 'cipher_create.dart';
import 'named_curve.dart';
import 'prf.dart';
import 'cipher_context.dart';
import 'dtls_context.dart';
import 'srtp_context.dart';
import 'transport_context.dart';
import 'handshake_const.dart';
import 'extended_master_secret.dart';
import 'renegotiation_indication.dart';
import 'use_srtp.dart';
import 'certificate.dart';
import 'change_cipher_spec.dart';
import 'certificate_verify.dart';
import 'client_key_exchange.dart';
import 'finished.dart';
import 'server_certificate_request.dart';
import 'server_hello.dart';
import 'server_hello_done.dart';
import 'server_key_exchange.dart';
import 'dtls_random.dart';
import 'helper.dart';
import 'builder.dart';
import 'record_const.dart';
import 'fragment.dart';
import 'flight.dart';

final log = Logger('werift-dtls : packages/dtls/src/flight/client/flight5.ts : log');

class Flight5 extends Flight {
  final CipherContext cipher;
  final SrtpContext srtp;

  Flight5(
    TransportContext udp,
    DtlsContext dtls,
    this.cipher,
    this.srtp,
  ) : super(udp, dtls, 5, 7);

  void handleHandshake(FragmentedHandshake handshake) {
    dtls.bufferHandshakeCache([handshake], false, 4);
    final message = () {
      switch (handshake.msgType) {
        case HandshakeType.server_hello_2:
          return ServerHello.deSerialize(handshake.fragment);
        case HandshakeType.certificate_11:
          return Certificate.deSerialize(handshake.fragment);
        case HandshakeType.server_key_exchange_12:
          return ServerKeyExchange.deSerialize(handshake.fragment);
        case HandshakeType.certificate_request_13:
          return ServerCertificateRequest.deSerialize(handshake.fragment);
        case HandshakeType.server_hello_done_14:
          return ServerHelloDone.deSerialize(handshake.fragment);
      }
    }();

    if (message != null) {
      handlers[message.msgType]!({
        'dtls': dtls,
        'cipher': cipher,
        'srtp': srtp,
      })(message);
    }
  }

  Future<void> exec() async {
    if (dtls.flight == 5) {
      log.info('${dtls.sessionId} flight5 twice');
      send(dtls.lastMessage);
      return;
    }
    dtls.flight = 5;

    final needCertificate = dtls.requestedCertificateTypes.isNotEmpty;
    log.info('${dtls.sessionId} send flight5 $needCertificate');

    final messages = [
      if (needCertificate) sendCertificate(),
      sendClientKeyExchange(),
      if (needCertificate) sendCertificateVerify(),
      sendChangeCipherSpec(),
      sendFinished(),
    ].whereType<Uint8List>().toList();

    dtls.lastMessage = messages;
    await transmit(messages);
  }

  Uint8List sendCertificate() {
    final certificate = Certificate([Uint8List.fromList(cipher.localCert)]);

    final packets = createPacket([certificate]);

    final buf = Uint8List.fromList(packets.expand((v) => v.serialize()).toList());
    return buf;
  }

  Uint8List sendClientKeyExchange() {
    if (cipher.localKeyPair == null) throw Exception('Local key pair is null');

    final clientKeyExchange = ClientKeyExchange(cipher.localKeyPair!.publicKey);
    final packets = createPacket([clientKeyExchange]);
    final buf = Uint8List.fromList(packets.expand((v) => v.serialize()).toList());

    final localKeyPair = cipher.localKeyPair!;
    final remoteKeyPair = cipher.remoteKeyPair;

    if (remoteKeyPair.publicKey == null) throw Exception('Remote public key does not exist');

    final preMasterSecret = prfPreMasterSecret(
      remoteKeyPair.publicKey!,
      localKeyPair.privateKey,
      localKeyPair.curve,
    );

    log.info('${dtls.sessionId} extendedMasterSecret ${dtls.options.extendedMasterSecret} ${dtls.remoteExtendedMasterSecret}');

    final handshakes = Uint8List.fromList(dtls.sortedHandshakeCache.expand((v) => v.serialize()).toList());
    cipher.masterSecret = dtls.options.extendedMasterSecret && dtls.remoteExtendedMasterSecret
        ? prfExtendedMasterSecret(preMasterSecret, handshakes)
        : prfMasterSecret(
            preMasterSecret,
            cipher.localRandom.serialize(),
            cipher.remoteRandom.serialize(),
          );

    cipher.cipher = createCipher(cipher.cipherSuite);
    cipher.cipher.init(
      cipher.masterSecret,
      cipher.remoteRandom.serialize(),
      cipher.localRandom.serialize(),
    );
    log.info('${dtls.sessionId} cipher ${cipher.cipher.summary}');

    return buf;
  }

  Uint8List sendCertificateVerify() {
    final cache = Uint8List.fromList(dtls.sortedHandshakeCache.expand((v) => v.serialize()).toList());
    final signed = cipher.signatureData(cache, 'sha256');
    final signatureScheme = () {
      switch (cipher.signatureHashAlgorithm?.signature) {
        case SignatureAlgorithm.ecdsa_3:
          return SignatureScheme.ecdsa_secp256r1_sha256;
        case SignatureAlgorithm.rsa_1:
          return SignatureScheme.rsa_pkcs1_sha256;
      }
    }();
    if (signatureScheme == null) throw Exception('Signature scheme is null');
    log.info('${dtls.sessionId} signatureScheme ${cipher.signatureHashAlgorithm?.signature} $signatureScheme');

    final certificateVerify = CertificateVerify(signatureScheme, signed);
    final packets = createPacket([certificateVerify]);
    final buf = Uint8List.fromList(packets.expand((v) => v.serialize()).toList());
    return buf;
  }

  Uint8List sendChangeCipherSpec() {
    final changeCipherSpec = ChangeCipherSpec.createEmpty().serialize();
    final packets = createPlaintext(dtls)(
      [{'type': ContentType.changeCipherSpec, 'fragment': changeCipherSpec}],
      ++dtls.recordSequenceNumber,
    );
    final buf = Uint8List.fromList(packets.expand((v) => v.serialize()).toList());
    return buf;
  }

  Uint8List sendFinished() {
    final cache = Uint8List.fromList(dtls.sortedHandshakeCache.expand((v) => v.serialize()).toList());
    final localVerifyData = cipher.verifyData(cache);

    final finish = Finished(localVerifyData);
    dtls.epoch = 1;
    final packet = createPacket([finish]).first;
    log.info('${dtls.sessionId} raw finish packet ${packet.summary} ${dtls.sortedHandshakeCache.map((h) => h.summary)}');

    dtls.recordSequenceNumber = 0;

    final buf = cipher.encryptPacket(packet).serialize();
    log.info('${dtls.sessionId} finished ${cipher.cipher.summary}');
    return buf;
  }
}

final handlers = <int, Function(Map<String, dynamic>) Function(dynamic)>{
  HandshakeType.server_hello_2: ({required dtls, required cipher, required srtp}) => (ServerHello message) {
    log.info('${dtls.sessionId} serverHello ${message.cipherSuite}');
    cipher.remoteRandom = DtlsRandom.from(message.random);
    cipher.cipherSuite = message.cipherSuite;
    log.info('${dtls.sessionId} selected cipherSuite ${cipher.cipherSuite}');
  },

  handlers[HandshakeType.certificate_11] = ({required cipher, required dtls}) => (Certificate message) {
  log.info('${dtls.sessionId} handshake certificate $message');
  cipher.remoteCertificate = message.certificateList[0];
};

handlers[HandshakeType.server_key_exchange_12] = ({required cipher, required dtls}) => (ServerKeyExchange message) {
  if (cipher.localRandom == null || cipher.remoteRandom == null) throw Exception('Local or remote random is null');
  log.info('${dtls.sessionId} ServerKeyExchange $message');

  log.info('${dtls.sessionId} selected curve ${message.namedCurve}');
  cipher.remoteKeyPair = NamedCurveKeyPair(
    curve: message.namedCurve,
    publicKey: message.publicKey,
  );
  cipher.localKeyPair = generateKeyPair(message.namedCurve);
};

handlers[HandshakeType.certificate_request_13] = ({required dtls}) => (ServerCertificateRequest message) {
  log.info('${dtls.sessionId} certificate_request $message');
  dtls.requestedCertificateTypes = message.certificateTypes;
  dtls.requestedSignatureAlgorithms = message.signatures;
};

handlers[HandshakeType.server_hello_done_14] = ({required dtls}) => (msg) {
  log.info('${dtls.sessionId} server_hello_done $msg');
};
};