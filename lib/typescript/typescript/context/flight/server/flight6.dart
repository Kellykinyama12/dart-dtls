import 'dart:typed_data';
import 'package:logging/logging.dart';
import 'cipher_create.dart';
import 'prf.dart';
import 'cipher_context.dart';
import 'dtls_context.dart';
import 'transport_context.dart';
import 'handshake_const.dart';
import 'certificate.dart';
import 'change_cipher_spec.dart';
import 'certificate_verify.dart';
import 'client_key_exchange.dart';
import 'finished.dart';
import 'builder.dart';
import 'record_const.dart';
import 'fragment.dart';
import 'flight.dart';

final log = Logger('werift-dtls : packages/dtls/flight/server/flight6.ts');

class Flight6 extends Flight {
  final CipherContext cipher;

  Flight6(
    TransportContext udp,
    DtlsContext dtls,
    this.cipher,
  ) : super(udp, dtls, 6);

  void handleHandshake(FragmentedHandshake handshake) {
    dtls.bufferHandshakeCache([handshake], false, 5);

    final message = () {
      switch (handshake.msgType) {
        case HandshakeType.certificate_11:
          return Certificate.deSerialize(handshake.fragment);
        case HandshakeType.certificate_verify_15:
          return CertificateVerify.deSerialize(handshake.fragment);
        case HandshakeType.client_key_exchange_16:
          return ClientKeyExchange.deSerialize(handshake.fragment);
        case HandshakeType.finished_20:
          return Finished.deSerialize(handshake.fragment);
      }
    }();

    if (message != null) {
      final handler = handlers[message.msgType];
      if (handler == null) {
        // todo handle certificate_11
        // todo handle certificate_verify_15
        return;
      }
      handler({'dtls': dtls, 'cipher': cipher})(message);
    }
  }

  Future<void> exec() async {
    if (dtls.flight == 6) {
      log.info('${dtls.sessionId} flight6 twice');
      send(dtls.lastMessage);
      return;
    }
    dtls.flight = 6;

    final messages = [sendChangeCipherSpec(), sendFinished()];
    dtls.lastMessage = messages;
    await transmit(messages);
  }

  Uint8List sendChangeCipherSpec() {
    final changeCipherSpec = ChangeCipherSpec.createEmpty().serialize();
    final packets = createPlaintext(dtls)(
      [{'type': ContentType.changeCipherSpec, 'fragment': changeCipherSpec}],
      ++dtls.recordSequenceNumber,
    );
    return Uint8List.fromList(packets.expand((v) => v.serialize()).toList());
  }

  Uint8List sendFinished() {
    final cache = Uint8List.fromList(dtls.sortedHandshakeCache.expand((v) => v.serialize()).toList());

    final localVerifyData = cipher.verifyData(cache);
    final finish = Finished(localVerifyData);

    dtls.epoch = 1;
    final packet = createPacket([finish]).first;
    dtls.recordSequenceNumber = 0;

    return cipher.encryptPacket(packet).serialize();
  }
}

final handlers = <int, Function(Map<String, dynamic>) Function(dynamic)>{
  HandshakeType.client_key_exchange_16: ({required cipher, required dtls}) => (ClientKeyExchange message) {
    cipher.remoteKeyPair = NamedCurveKeyPair(
      curve: cipher.namedCurve,
      publicKey: message.publicKey,
    );
    if (cipher.remoteKeyPair.publicKey == null ||
        cipher.localKeyPair == null ||
        cipher.remoteRandom == null ||
        cipher.localRandom == null) {
      throw Exception('Key pair or random values do not exist');
    }

    final preMasterSecret = prfPreMasterSecret(
      cipher.remoteKeyPair.publicKey!,
      cipher.localKeyPair!.privateKey,
      cipher.localKeyPair!.curve,
    );

    log.info('${dtls.sessionId} extendedMasterSecret ${dtls.options.extendedMasterSecret} ${dtls.remoteExtendedMasterSecret}');

    final handshakes = Uint8List.fromList(dtls.sortedHandshakeCache.expand((v) => v.serialize()).toList());
    cipher.masterSecret = dtls.options.extendedMasterSecret && dtls.remoteExtendedMasterSecret
        ? prfExtendedMasterSecret(preMasterSecret, handshakes)
        : prfMasterSecret(
            preMasterSecret,
            cipher.remoteRandom!.serialize(),
            cipher.localRandom!.serialize(),
          );

    cipher.cipher = createCipher(cipher.cipherSuite!);
    cipher.cipher.init(
      cipher.masterSecret,
      cipher.localRandom!.serialize(),
      cipher.remoteRandom!.serialize(),
    );
    log.info('${dtls.sessionId} setup cipher ${cipher.cipher.summary}');
  },
  HandshakeType.finished_20: ({required dtls}) => (Finished message) {
    log.info('${dtls.sessionId} finished $message');
  },
};