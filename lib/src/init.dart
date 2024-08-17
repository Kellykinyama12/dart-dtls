import 'package:dtls2/src/crypto.dart';

String? serverCertificate; //            *tls.Certificate
//String	ServerCertificateFingerprint;// string

void Init() {
  print("Initializing self signed certificate for server...");
  serverCertificate = generateSelfSignedCertificate();
  // if (err != null) {
  // 	throw(err);
  // }
  // ServerCertificate = serverCertificate;
  // ServerCertificateFingerprint = GetCertificateFingerprint(serverCertificate);
  print("Self signed certificate created: $serverCertificate>");
  // print( "This certificate is stored in dtls.ServerCertificate variable globally, it will be used while DTLS handshake, sending SDP, SRTP, SRTCP packets, etc...");
}
