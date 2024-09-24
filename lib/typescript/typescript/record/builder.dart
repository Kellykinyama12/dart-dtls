import 'dtls_context.dart';
import 'domain.dart';
import 'plaintext.dart';

class Message {
  final int type;
  final Uint8List fragment;

  Message({required this.type, required this.fragment});
}

List<FragmentedHandshake> Function(List<Handshake>) createFragments(DtlsContext dtls) {
  return (List<Handshake> handshakes) {
    dtls.lastFlight = handshakes;

    return handshakes
        .map((handshake) {
          handshake.messageSeq = dtls.sequenceNumber++;
          final fragment = handshake.toFragment();
          final fragments = fragment.chunk();
          return fragments;
        })
        .expand((v) => v)
        .toList();
  };
}

List<DtlsPlaintext> Function(List<Message>, int) createPlaintext(DtlsContext dtls) {
  return (List<Message> fragments, int recordSequenceNumber) {
    return fragments.map((msg) {
      final plaintext = DtlsPlaintext(
        contentType: msg.type,
        protocolVersion: dtls.version,
        epoch: dtls.epoch,
        sequenceNumber: recordSequenceNumber,
        contentLen: msg.fragment.length,
        fragment: msg.fragment,
      );
      return plaintext;
    }).toList();
  };
}