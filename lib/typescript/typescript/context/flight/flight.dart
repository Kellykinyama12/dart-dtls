import 'dart:async';
import 'dart:typed_data';
import 'package:logging/logging.dart';
import 'dtls_context.dart';
import 'transport_context.dart';
import 'builder.dart';
import 'record_const.dart';
import 'domain.dart';

final warn = Logger('werift-dtls : packages/dtls/src/flight/flight.ts : warn');
final err = Logger('werift-dtls : packages/dtls/src/flight/flight.ts : err');

const flightTypes = ['PREPARING', 'SENDING', 'WAITING', 'FINISHED'];

typedef FlightType = String;

abstract class Flight {
  FlightType state = 'PREPARING';
  static const int RetransmitCount = 10;

  final TransportContext transport;
  final DtlsContext dtls;
  final int flight;
  final int? nextFlight;

  Flight(this.transport, this.dtls, this.flight, [this.nextFlight]);

  List<DtlsPlaintext> createPacket(List<Handshake> handshakes) {
    final fragments = createFragments(dtls)(handshakes);
    dtls.bufferHandshakeCache(fragments, true, flight);
    final packets = createPlaintext(dtls)(
      fragments.map((fragment) => {
        return {
          'type': ContentType.handshake,
          'fragment': fragment.serialize(),
        };
      }).toList(),
      ++dtls.recordSequenceNumber,
    );
    return packets;
  }

  Future<void> transmit(List<Uint8List> buffers) async {
    int retransmitCount = 0;
    for (; retransmitCount <= Flight.RetransmitCount; retransmitCount++) {
      setState('SENDING');
      try {
        await send(buffers);
      } catch (e) {
        err.severe('fail to send', e);
      }
      setState('WAITING');

      if (nextFlight == null) {
        setState('FINISHED');
        break;
      }

      await Future.delayed(Duration(seconds: (retransmitCount + 1) ~/ 2));

      if (dtls.flight >= nextFlight!) {
        setState('FINISHED');
        break;
      } else {
        warn.warning('${dtls.sessionId} retransmit $retransmitCount ${dtls.flight}');
      }
    }

    if (retransmitCount > Flight.RetransmitCount) {
      err.severe('${dtls.sessionId} retransmit failed $retransmitCount');
      throw Exception('over retransmitCount : $flight $nextFlight');
    }
  }

  Future<void> send(List<Uint8List> buf) {
    return Future.wait(buf.map((v) => transport.send(v)));
  }

  void setState(FlightType state) {
    this.state = state;
  }
}