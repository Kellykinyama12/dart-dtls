import 'dart:typed_data';

enum AlertLevel {
  AlertLevelWarning(1),
  AlertLevelFatal(2);

  const AlertLevel(this.value);

  final int value;

  factory AlertLevel.fromInt(int key) {
    return values.firstWhere((element) => element.value == key);
  }
}

enum AlertDescription {
  AlertDescriptionCloseNotify(0),
  AlertDescriptionUnexpectedMessage(10),
  AlertDescriptionBadRecordMac(20),
  AlertDescriptionDecryptionFailed(21),
  AlertDescriptionRecordOverflow(22),
  AlertDescriptionDecompressionFailure(30),
  AlertDescriptionHandshakeFailure(40),
  AlertDescriptionNoCertificate(41),
  AlertDescriptionBadCertificate(42),
  AlertDescriptionUnsupportedCertificate(43),
  AlertDescriptionCertificateRevoked(44),
  AlertDescriptionCertificateExpired(45),
  AlertDescriptionCertificateUnknown(46),
  AlertDescriptionIllegalParameter(47),
  AlertDescriptionUnknownCA(48),
  AlertDescriptionAccessDenied(49),
  AlertDescriptionDecodeError(50),
  AlertDescriptionDecryptError(51),
  AlertDescriptionExportRestriction(60),
  AlertDescriptionProtocolVersion(70),
  AlertDescriptionInsufficientSecurity(71),
  AlertDescriptionInternalError(80),
  AlertDescriptionUserCanceled(90),
  AlertDescriptionNoRenegotiation(100),
  AlertDescriptionUnsupportedExtension(110);

  const AlertDescription(this.value);

  final int value;

  factory AlertDescription.fromInt(int key) {
    return values.firstWhere((element) => element.value == key);
  }
}

class Alert {
  AlertLevel? Level;
  AlertDescription? Description;

  dynamic Decode(Uint8List buf, int offset, int arrayLen)
  //(int, error)
  {
    Level = AlertLevel.fromInt(buf[offset]);
    offset++;
    Description = AlertDescription.fromInt(buf[offset]);
    offset++;
    return (offset, null);
  }
}
