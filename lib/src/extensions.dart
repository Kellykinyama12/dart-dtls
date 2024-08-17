import 'dart:typed_data';

import 'package:dtls2/src/simple_extensions.dart';
import 'package:dtls2/src/utils.dart';

enum ExtensionType{
	ServerName                   (0),
	SupportedEllipticCurves      (10),
	SupportedPointFormats        (11),
	SupportedSignatureAlgorithms (13),
	UseSRTP                      (14),
	ALPN                         (16),
	UseExtendedMasterSecret      (23),
	RenegotiationInfo            (65281),

	Unknown (65535); //Not a valid value
  const ExtensionType(this.value);

  final int value;

  factory ExtensionType.fromInt(int key) {
    return values.firstWhere((element) => element.value == key);
  }
}

class DtlsExtension  {
	// ExtensionType() ExtensionType
	// Encode() []byte
	// Decode(extensionLength int, buf []byte, offset int, arrayLen int) error
	// String() string
}

dynamic DecodeExtensionMap(Uint8List buf, int offset, int arrayLen)
 //(map[ExtensionType]Extension, int, error)
  {
	Map<ExtensionType,dynamic> result = {};
	var length = uint16(buf.sublist(offset , offset+2));
	offset += 2;
	var offsetBackup = offset;
	while (offset < offsetBackup+length) {
		var extensionType = ExtensionType.fromInt(uint16(buf.sublist(offset , offset+2)));
		offset += 2;
		var extensionLength = uint16(buf.sublist(offset , offset+2));
		offset += 2;
		var extension;
		switch (extensionType) {
		case ExtensionType.UseExtendedMasterSecret:
			extension = ExtUseExtendedMasterSecret();
		case ExtensionType.UseSRTP:
			extension = ExtUseSRTP();
		case ExtensionType.SupportedPointFormats:
			extension = ExtSupportedPointFormats();
		case ExtensionType.SupportedEllipticCurves:
			extension = ExtSupportedEllipticCurves();
		default:
			extension = ExtUnknown(extensionType,extensionLength);
			
		}
		if (extension != null) {
			var err = extension.Decode(extensionLength, buf, offset, arrayLen);

			if (err != null) {
				return (null, offset, err);
			}
			result[extensionType]= extension;
		}
		offset += extensionLength;
	}
	return (result, offset, null);
}
