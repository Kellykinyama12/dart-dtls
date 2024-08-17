import 'dart:typed_data';

import 'package:dtls2/src/utils.dart';

class Certificate {
List<Uint8List> Certificates=[];
  dynamic Decode(Uint8List buf, int offset, int arrayLen)
  // (int, error)
    {
	//Certificates = make([][]byte, 0)
	//length = uint24FromBytes(buf[offset : offset+3])
	var lengthInt = uint24FromBytes(buf.sublist(offset,offset+3));
	offset += 3;
	var offsetBackup = offset;
	while (offset < offsetBackup+lengthInt) {
		//certificateLength := NewUint24FromBytes(buf[offset : offset+3])
		var certificateLengthInt = uint24FromBytes(buf.sublist(offset,offset+3));
		offset += 3;

		var certificateBytes = buf.sublist(offset,offset+certificateLengthInt);
		//copy(certificateBytes, buf[offset:offset+certificateLengthInt])
		offset += certificateLengthInt;
		Certificates.add( certificateBytes);
	}
	return (offset, null);
}

}
