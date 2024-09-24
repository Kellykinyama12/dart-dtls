import 'package:logging/logging.dart';
import 'const.dart';
import 'abstract.dart';
import 'fragment.dart';
import 'socket.dart';
import 'domain.dart';

final log = Logger('werift-dtls : packages/dtls/src/context/dtls.dart : log');

class DtlsContext {
  final version = {'major': 255 - 1, 'minor': 255 - 2};

  List<Handshake> lastFlight = [];
  List<Uint8List> lastMessage = [];
  int recordSequenceNumber = 0;
  int sequenceNumber = 0;
  int epoch = 0;
  int flight = 0;
  Map<int, HandshakeCache> handshakeCache = {};
  Uint8List? cookie;
  List<int> requestedCertificateTypes = [];
  List<SignatureHashAlgorithm> requestedSignatureAlgorithms = [];
  bool remoteExtendedMasterSecret = false;

  final Options options;
  final SessionTypes sessionType;

  DtlsContext(this.options, this.sessionType);

  String get sessionId =>
      cookie != null ? hex.encode(cookie!).substring(0, 10) : '';

  List<FragmentedHandshake> get sortedHandshakeCache {
    return handshakeCache.entries
        .toList()
        .sort((a, b) => a.key.compareTo(b.key))
        .expand((entry) => entry.value.data
          ..sort((a, b) => a.messageSeq.compareTo(b.messageSeq)))
        .toList();
  }

  bool checkHandshakesExist(List<int> handshakes) {
    return !handshakes.any(
        (type) => sortedHandshakeCache.any((h) => h.msgType == type) == false);
  }

  void bufferHandshakeCache(
      List<FragmentedHandshake> handshakes, bool isLocal, int flight) {
    handshakeCache.putIfAbsent(flight,
        () => HandshakeCache(isLocal: isLocal, data: [], flight: flight));

    final filtered = handshakes.where((h) {
      final exist =
          handshakeCache[flight]!.data.any((t) => t.msgType == h.msgType);
      if (exist) {
        log.info('$sessionId exist ${h.summary} $isLocal $flight');
        return false;
      }
      return true;
    }).toList();

    handshakeCache[flight]!.data.addAll(filtered);
  }
}

class HandshakeCache {
  final bool isLocal;
  final List<FragmentedHandshake> data;
  final int flight;

  HandshakeCache(
      {required this.isLocal, required this.data, required this.flight});
}

class SignatureHashAlgorithm {
  final HashAlgorithms hash;
  final SignatureAlgorithms signature;

  SignatureHashAlgorithm({required this.hash, required this.signature});
}
