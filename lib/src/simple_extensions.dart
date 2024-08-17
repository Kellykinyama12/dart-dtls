import 'dart:typed_data';

import 'package:dtls2/src/extensions.dart';
import 'package:dtls2/src/utils.dart';

class ExtUseExtendedMasterSecret {
  dynamic Decode(int extensionLength, Uint8List buf, int offset, int arrayLen)
  //error
  {
    return null;
  }
}

class ExtRenegotiationInfo {}

class ExtUseSRTP {
  List<SRTPProtectionProfile> ProtectionProfiles = [];
  Uint8List? Mki; //                []byte
}

// Only Uncompressed was implemented.
// See for further Elliptic Curve Point Format classs: https://www.rfc-editor.org/rfc/rfc8422.html#section-5.1.2
class ExtSupportedPointFormats {
  List<PointFormat> pointFormats = [];

  dynamic Decode(int extensionLength, Uint8List buf, int offset, int arrayLen) {
    var pointFormatsCount = buf[offset];
    offset++;
    //e.PointFormats = make([]PointFormat, pointFormatsCount)
    for (int i = 0; i < pointFormatsCount; i++) {
      pointFormats.add((buf[offset]));
      offset++;
    }

    return null;
  }
}

// Only X25519 was implemented.
// See for further NamedCurve classs: https://www.rfc-editor.org/rfc/rfc8422.html#section-5.1.1
class ExtSupportedEllipticCurves {
  List<Curve> Curves = [];
  dynamic Decode(int extensionLength, Uint8List buf, int offset, int arrayLen)
  //error
  {
    var curvesLength = uint16(buf.sublist(offset, offset + 2));
    offset += 2;
    var curvesCount = curvesLength / 2;
    // e.Curves = make([]Curve, curvesCount)
    for (int i = 0; i < curvesCount; i++) {
      Curves.add(uint16(buf.sublist(offset, offset + 2)));
      offset += 2;
    }

    return null;
  }
}

// ExtUnknown is not for processing. It is only for debugging purposes.
class ExtUnknown {
  ExtensionType? Type;
  int? DataLength;

  ExtUnknown(this.Type, this.DataLength);
  dynamic Decode(int extensionLength, Uint8List buf, int offset, int arrayLen)
  //error
  {
    print("Unknown extension: $Type cannot be decoded");
    return null;
  }
}
