import 'dtls_context.dart';
import 'transport_context.dart';
import 'client_hello.dart';
import 'server_hello_verify_request.dart';
import 'flight.dart';

class Flight3 extends Flight {
  Flight3(TransportContext udp, DtlsContext dtls) : super(udp, dtls, 3, 5);

  Future<void> exec(ServerHelloVerifyRequest verifyReq) async {
    if (dtls.flight == 3) throw Exception('Flight already in progress');
    dtls.flight = 3;

    dtls.handshakeCache.clear();

    final clientHello = dtls.lastFlight.first as ClientHello;
    clientHello.cookie = verifyReq.cookie;
    dtls.cookie = verifyReq.cookie;

    final packets = createPacket([clientHello]);

    final buf = Uint8List.fromList(packets.expand((v) => v.serialize()).toList());
    await transmit([buf]);
  }
}