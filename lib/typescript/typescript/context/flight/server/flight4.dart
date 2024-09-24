import 'dart:typed_data';
import 'package:logging/logging.dart';
import 'cipher_const.dart';
import 'cipher_context.dart';
import 'dtls_context.dart';
import 'srtp_context.dart';
import 'transport_context.dart';
import 'extended_master_secret.dart';
import 'renegotiation_indication.dart';
import 'use_srtp.dart';
import 'certificate.dart';
import 'server_certificate_request.dart';
import 'server_hello.dart';
import 'server_hello_done.dart';
import 'server_key_exchange.dart';
import 'fragment.dart';
import 'domain.dart';
import 'flight.dart';

final log =
    Logger('werift-dtls : packages/dtls/flight/server/flight4.ts : log');

class Flight4 extends Flight {
  final CipherContext cipher;
  final SrtpContext srtp;

  Flight4(
    TransportContext udp,
    DtlsContext dtls,
    this.cipher,
    this.srtp,
  ) : super(udp, dtls, 4, 6);

  Future<void> exec(FragmentedHandshake clientHello,
      {bool certificateRequest = false}) async {
    if (dtls.flight == 4) {
      log.info('${dtls.sessionId} flight4 twice');
      send(dtls.lastMessage);
      return;
    }
    dtls.flight = 4;
    dtls.sequenceNumber = 1;
    dtls.bufferHandshakeCache([clientHello], false, 4);

    final messages = [
      sendServerHello(),
      sendCertificate(),
      sendServerKeyExchange(),
      if (certificateRequest) sendCertificateRequest(),
      sendServerHelloDone(),
    ].whereType<Uint8List>().toList();

    dtls.lastMessage = messages;
    await transmit(messages);
  }

  Uint8List sendServerHello() {
    // todo fix; should use socket.extensions
    final extensions = <Extension>[];
    if (srtp.srtpProfile != null) {
      extensions.add(
        UseSRTP.create([srtp.srtpProfile!], Uint8List.fromList([0x00]))
            .extension,
      );
    }
    if (dtls.options.extendedMasterSecret) {
      extensions.add(
        Extension(
          type: ExtendedMasterSecret.type,
          data: Uint8List(0),
        ),
      );
    }
    final renegotiationIndication = RenegotiationIndication.createEmpty();
    extensions.add(renegotiationIndication.extension);

    final serverHello = ServerHello(
      dtls.version,
      cipher.localRandom,
      Uint8List.fromList([0x00]),
      cipher.cipherSuite,
      0, // do not compress
      extensions,
    );
    final packets = createPacket([serverHello]);
    return Uint8List.fromList(packets.expand((v) => v.serialize()).toList());
  }

  // 7.4.2 Server Certificate
  Uint8List sendCertificate() {
    final certificate = Certificate([Uint8List.fromList(cipher.localCert)]);

    final packets = createPacket([certificate]);
    return Uint8List.fromList(packets.expand((v) => v.serialize()).toList());
  }

  Uint8List sendServerKeyExchange() {
    final signature = cipher.generateKeySignature('sha256');
    if (cipher.signatureHashAlgorithm == null)
      throw Exception('Signature hash algorithm does not exist');

    final keyExchange = ServerKeyExchange(
      CurveType.named_curve_3,
      cipher.namedCurve,
      cipher.localKeyPair.publicKey.length,
      cipher.localKeyPair.publicKey,
      cipher.signatureHashAlgorithm!.hash,
      cipher.signatureHashAlgorithm!.signature,
      signature.length,
      signature,
    );

    final packets = createPacket([keyExchange]);
    return Uint8List.fromList(packets.expand((v) => v.serialize()).toList());
  }

  // 7.4.4.  Certificate Request
  Uint8List sendCertificateRequest() {
    final handshake = ServerCertificateRequest(
      [
        1, // clientCertificateTypeRSASign
        64, // clientCertificateTypeECDSASign
      ],
      [
        SignatureHashAlgorithm(
            hash: HashAlgorithm.sha256_4, signature: SignatureAlgorithm.rsa_1),
        SignatureHashAlgorithm(
            hash: HashAlgorithm.sha256_4,
            signature: SignatureAlgorithm.ecdsa_3),
      ],
      [],
    );
    log.info('${dtls.sessionId} sendCertificateRequest $handshake');
    final packets = createPacket([handshake]);
    return Uint8List.fromList(packets.expand((v) => v.serialize()).toList());
  }

  Uint8List sendServerHelloDone() {
    final handshake = ServerHelloDone();

    final packets = createPacket([handshake]);
    return Uint8List.fromList(packets.expand((v) => v.serialize()).toList());
  }
}
