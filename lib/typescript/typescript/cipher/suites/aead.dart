import 'dart:typed_data';
import 'package:pointycastle/export.dart' as pc;
import 'package:logging/logging.dart';
import 'helper.dart';
import 'prf.dart';
import 'abstract.dart';

final log = Logger('AEADCipher');

class ContentType {
  static const int value = 8;
}

class ProtocolVersion {
  static const int value = 16;
}

class AEADAdditionalData {
  final int epoch;
  final int sequence;
  final int type;
  final int version;
  final int length;

  AEADAdditionalData({
    required this.epoch,
    required this.sequence,
    required this.type,
    required this.version,
    required this.length,
  });

  Uint8List encode() {
    final buffer = ByteData(13);
    buffer.setUint16(0, epoch);
    buffer.setUint48(2, sequence);
    buffer.setUint8(8, type);
    buffer.setUint16(9, version);
    buffer.setUint16(11, length);
    return buffer.buffer.asUint8List();
  }
}

class AEADCipher extends AbstractCipher {
  int keyLength = 0;
  int nonceLength = 0;
  int ivLength = 0;
  int authTagLength = 0;

  int nonceImplicitLength = 0;
  int nonceExplicitLength = 0;

  Uint8List? clientWriteKey;
  Uint8List? serverWriteKey;

  Uint8List? clientNonce;
  Uint8List? serverNonce;

  @override
  void init(Uint8List masterSecret, Uint8List serverRandom, Uint8List clientRandom) {
    final keys = prfEncryptionKeys(
      masterSecret,
      clientRandom,
      serverRandom,
      keyLength,
      ivLength,
      nonceLength,
      hashAlgorithm,
    );

    clientWriteKey = keys['clientWriteKey'];
    serverWriteKey = keys['serverWriteKey'];
    clientNonce = keys['clientNonce'];
    serverNonce = keys['serverNonce'];
  }

  @override
  Uint8List encrypt(SessionTypes type, Uint8List data, CipherHeader header) {
    final isClient = type == SessionType.CLIENT;
    final iv = isClient ? clientNonce : serverNonce;
    final writeKey = isClient ? clientWriteKey : serverWriteKey;
    if (iv == null || writeKey == null) throw Exception('IV or WriteKey is null');

    final buffer = ByteData.view(iv.buffer);
    buffer.setUint16(nonceImplicitLength, header.epoch);
    buffer.setUint48(nonceImplicitLength + 2, header.sequenceNumber);

    final explicitNonce = iv.sublist(nonceImplicitLength);

    final additionalData = AEADAdditionalData(
      epoch: header.epoch,
      sequence: header.sequenceNumber,
      type: header.type,
      version: header.version,
      length: data.length,
    );

    final additionalBuffer = additionalData.encode();

    final cipher = pc.GCMBlockCipher(pc.AESEngine())
      ..init(
        true,
        pc.AEADParameters(
          pc.KeyParameter(writeKey),
          authTagLength * 8,
          iv,
          additionalBuffer,
        ),
      );

    final output = Uint8List(cipher.getOutputSize(data.length));
    final len = cipher.processBytes(data, 0, data.length, output, 0);
    cipher.doFinal(output, len);

    return Uint8List.fromList(explicitNonce + output);
  }

  @override
  Uint8List decrypt(SessionTypes type, Uint8List data, CipherHeader header) {
    final isClient = type == SessionType.CLIENT;
    final iv = isClient ? serverNonce : clientNonce;
    final writeKey = isClient ? serverWriteKey : clientWriteKey;
    if (iv == null || writeKey == null) throw Exception('IV or WriteKey is null');

    final explicitNonce = data.sublist(0, nonceExplicitLength);
    iv.setRange(nonceImplicitLength, iv.length, explicitNonce);

    final encrypted = data.sublist(nonceExplicitLength, data.length - authTagLength);
    final authTag = data.sublist(data.length - authTagLength);

    final additionalData = AEADAdditionalData(
      epoch: header.epoch,
      sequence: header.sequenceNumber,
      type: header.type,
      version: header.version,
      length: encrypted.length,
    );

    final additionalBuffer = additionalData.encode();

    final cipher = pc.GCMBlockCipher(pc.AESEngine())
      ..init(
        false,
        pc.AEADParameters(
          pc.KeyParameter(writeKey),
          authTagLength * 8,
          iv,
          additionalBuffer,
        ),
      );

    final output = Uint8List(cipher.getOutputSize(encrypted.length));
    final len = cipher.processBytes(encrypted, 0, encrypted.length, output, 0);
    try {
      cipher.doFinal(output, len);
      return output;
    } catch (e) {
      log.severe('decrypt failed', e, type, dumpBuffer(data), header, summary);
      rethrow;
    }
  }

  @override
  String toString() {
    return name ?? '';
  }
}