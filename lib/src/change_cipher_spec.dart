import 'dart:typed_data';

import 'package:dtls2/src/dtls_message.dart';

class ChangeCipherSpec {

 dynamic Decode(Uint8List buf, int offset, int arrayLen) 
 //(int, error)
  {
	if (arrayLen < 1 || buf[offset] != 1) {
		offset++;
		return (offset, Errors.fromInt("invalid cipher spec"));
	}
	offset++;
	return (offset, null);
}
}
