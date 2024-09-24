import 'package:logging/logging.dart';
import 'cipher_context.dart';
import 'dtls_context.dart';
import 'alert.dart';
import 'const.dart';
import 'fragment.dart';
import 'plaintext.dart';

final log = Logger('werift-dtls : packages/dtls/record/receive.ts : log');
final err = Logger('werift-dtls : packages/dtls/record/receive.ts : err');

List<DtlsPlaintext> parsePacket(Uint8List data) {
  int start = 0;
  final packets = <DtlsPlaintext>[];
  while (data.length > start) {
    final fragmentLength = data.buffer.asByteData().getUint16(start + 11);
    if (data.length < start + (12 + fragmentLength)) break;
    final packet = DtlsPlaintext.deSerialize(data.sublist(start));
    packets.add(packet);

    start += 13 + fragmentLength;
  }

  return packets;
}

Function parsePlainText(DtlsContext dtls, CipherContext cipher) {
  return (DtlsPlaintext plain) {
    final contentType = plain.recordLayerHeader.contentType;

    switch (contentType) {
      case ContentType.changeCipherSpec:
        log.info('${dtls.sessionId} change cipher spec');
        return {
          'type': ContentType.changeCipherSpec,
          'data': null,
        };
      case ContentType.handshake:
        var raw = plain.fragment;
        try {
          if (plain.recordLayerHeader.epoch > 0) {
            log.info('${dtls.sessionId} decrypt handshake');
            raw = cipher.decryptPacket(plain);
          }
        } catch (error) {
          err.severe('${dtls.sessionId} decrypt failed', error);
          throw error;
        }
        try {
          return {
            'type': ContentType.handshake,
            'data': FragmentedHandshake.deSerialize(raw),
          };
        } catch (error) {
          err.severe('${dtls.sessionId} deSerialize failed', error, raw);
          throw error;
        }
      case ContentType.applicationData:
        return {
          'type': ContentType.applicationData,
          'data': cipher.decryptPacket(plain),
        };
      case ContentType.alert:
        var alert = Alert.deSerialize(plain.fragment);

        // TODO: Implement better handling for encrypted alerts
        if (AlertDesc.values[alert.description] == null) {
          final dec = cipher.decryptPacket(plain);
          alert = Alert.deSerialize(dec);
        }
        err.severe(
          '${dtls.sessionId} ContentType.alert $alert ${AlertDesc.values[alert.description]} flight ${dtls.flight} lastFlight ${dtls.lastFlight}',
        );
        if (alert.level > 1) {
          throw Exception('alert fatal error');
        }
        break;
      default:
        return {'type': ContentType.alert, 'data': null};
    }
  };
}
