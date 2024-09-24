import 'dart:typed_data';
import 'dart:math';
import 'package:logging/logging.dart';
import 'cipher_const.dart';
import 'named_curve.dart';
import 'cipher_context.dart';
import 'dtls_context.dart';
import 'srtp_context.dart';
import 'transport_context.dart';
import 'elliptic_curves.dart';
import 'extended_master_secret.dart';
import 'renegotiation_indication.dart';
import 'signature.dart';
import 'use_srtp.dart';
import 'client_hello.dart';
import 'server_hello_verify_request.dart';
import 'dtls_random.dart';
import 'builder.dart';
import 'record_const.dart';

final log = Logger('werift-dtls : packages/dtls/flight/server/flight2.ts : log');

// HelloVerifyRequest do not retransmit

void Function(ClientHello) flight2(
  TransportContext udp,
  DtlsContext dtls,
  CipherContext cipher,
  SrtpContext srtp,
) {
  return (ClientHello clientHello) {
    dtls.flight = 2;

    // if flight 2 restarts due to packet loss, sequence numbers are reused from the top:
    // https://datatracker.ietf.org/doc/html/rfc6347#section-4.2.2
    // The first message each side transmits in each handshake always has
    // message_seq = 0.  Whenever each new message is generated, the
    // message_seq value is incremented by one.  Note that in the case of a
    // rehandshake, this implies that the HelloRequest will have message_seq = 0
    // and the ServerHello will have message_seq = 1.  When a message is
    // retransmitted, the same message_seq value is used.
    dtls.recordSequenceNumber = 0;
    dtls.sequenceNumber = 0;

    for (final extension in clientHello.extensions) {
      switch (extension.type) {
        case EllipticCurves.type:
          final curves = EllipticCurves.fromData(extension.data).data;
          log.info('${dtls.sessionId} curves $curves');
          final curve = curves.firstWhere(
            (curve) => NamedCurveAlgorithmList.contains(curve),
            orElse: () => throw Exception('No matching curve found'),
          ) as NamedCurveAlgorithms;
          cipher.namedCurve = curve;
          log.info('${dtls.sessionId} curve selected ${cipher.namedCurve}');
          break;
        case Signature.type:
          if (cipher.signatureHashAlgorithm == null) {
            throw Exception('Need to set certificate');
          }

          final signatureHash = Signature.fromData(extension.data).data;
          log.info('${dtls.sessionId} hash,signature $signatureHash');
          final signature = signatureHash.firstWhere(
            (v) => v.signature == cipher.signatureHashAlgorithm?.signature,
            orElse: () => throw Exception('Invalid signatureHash'),
          ).signature;
          final hash = signatureHash.firstWhere(
            (v) => v.hash == cipher.signatureHashAlgorithm?.hash,
            orElse: () => throw Exception('Invalid signatureHash'),
          ).hash;
          break;
        case UseSRTP.type:
          if (dtls.options?.srtpProfiles == null || dtls.options.srtpProfiles.isEmpty) {
            return;
          }

          final useSrtp = UseSRTP.fromData(extension.data);
          log.info('${dtls.sessionId} srtp profiles ${useSrtp.profiles}');
          final profile = SrtpContext.findMatchingSRTPProfile(
            useSrtp.profiles.cast<Profile>(),
            dtls.options.srtpProfiles,
          );
          if (profile == null) {
            throw Exception('No matching SRTP profile found');
          }
          srtp.srtpProfile = profile;
          log.info('${dtls.sessionId} srtp profile selected ${srtp.srtpProfile}');
          break;
        case ExtendedMasterSecret.type:
          dtls.remoteExtendedMasterSecret = true;
          break;
        case RenegotiationIndication.type:
          log.info('${dtls.sessionId} RenegotiationIndication ${extension.data}');
          break;
      }
    }

    cipher.localRandom = DtlsRandom();
    cipher.remoteRandom = DtlsRandom.from(clientHello.random);

    final suites = clientHello.cipherSuites;
    log.info('${dtls.sessionId} cipher suites $suites');
    final suite = () {
      switch (cipher.signatureHashAlgorithm?.signature) {
        case SignatureAlgorithm.ecdsa_3:
          return CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_49195;
        case SignatureAlgorithm.rsa_1:
          return CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256_49199;
      }
    }();
    if (suite == null || !suites.contains(suite)) {
      throw Exception('DTLS cipher suite negotiation failed');
    }
    cipher.cipherSuite = suite;
    log.info('${dtls.sessionId} selected cipherSuite ${cipher.cipherSuite}');

    cipher.localKeyPair = generateKeyPair(cipher.namedCurve);

    dtls.cookie ??= Uint8List.fromList(List.generate(20, (_) => Random().nextInt(256)));
    final helloVerifyReq = ServerHelloVerifyRequest(
      {'major': 255 - 1, 'minor': 255 - 2},
      dtls.cookie!,
    );
    final fragments = createFragments(dtls)([helloVerifyReq]);
    final packets = createPlaintext(dtls)(
      fragments.map((fragment) => {
        return {
          'type': ContentType.handshake,
          'fragment': fragment.serialize(),
        };
      }).toList(),
      ++dtls.recordSequenceNumber,
    );

    final chunk = packets.map((v) => v.serialize()).toList();
    for (final buf in chunk) {
      udp.send(buf);
    }
  };
}