import 'cipher_const.dart';
import 'cipher_context.dart';
import 'dtls_context.dart';
import 'transport_context.dart';
import 'client_hello.dart';
import 'dtls_random.dart';
import 'domain.dart';
import 'flight.dart';

class Flight1 extends Flight {
  final CipherContext cipher;

  Flight1(
    TransportContext udp,
    DtlsContext dtls,
    this.cipher,
  ) : super(udp, dtls, 1, 3);

  Future<void> exec(List<Extension> extensions) async {
    if (dtls.flight == 1) throw Exception('Flight already in progress');
    dtls.flight = 1;

    final hello = ClientHello(
      {'major': 255 - 1, 'minor': 255 - 2},
      DtlsRandom(),
      Uint8List(0),
      Uint8List(0),
      CipherSuiteList,
      [0], // don't compress
      extensions,
    );
    dtls.version = hello.clientVersion;
    cipher.localRandom = DtlsRandom.from(hello.random);

    final packets = createPacket([hello]);
    final buf =
        Uint8List.fromList(packets.expand((v) => v.serialize()).toList());
    await transmit([buf]);
  }
}
