import 'dart:typed_data';

class ClientKeyExchange {

  Uint8List? PublicKey;

  dynamic Decode(Uint8List buf, int offset, int arrayLen) 
  //(int, error) 
  {
	var publicKeyLength = buf[offset];
	offset++;
	PublicKey = buf.sublist(offset,offset+publicKeyLength);
	offset += publicKeyLength;
	return (offset, null);
}
}
