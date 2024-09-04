import 'dart:js_interop';
import 'dart:typed_data';

import 'package:dtls2/src/crypto.dart';
import 'package:dtls2/src/crypto_gcm.dart';
import 'package:dtls2/src/dtls_message.dart';
import 'package:dtls2/src/extensions.dart';
import 'package:dtls2/src/handshake_header.dart';
import 'package:dtls2/src/random.dart';
import 'package:dtls2/src/record_header.dart';
import 'package:dtls2/src/server_hello.dart';
import 'package:dtls2/src/utils.dart';
import 'package:pinenacl/api.dart';
import 'package:pinenacl/x25519.dart';

enum Flight {
  Flight0(0),
  Flight2(2),
  Flight4(4),
  Flight6(6);

  const Flight(this.value);
  final int value;
}

class HandshakeContext  {
	//Client IP and Port
	// Addr *net.UDPAddr
	// //Server UDP listener connection
	// Conn                    *net.UDPConn
	// ClientUfrag             string
	// ExpectedFingerprintHash string

	// DTLSState                DTLSState
	// OnDTLSStateChangeHandler func(DTLSState)

	// ProtocolVersion         DtlsVersion
	 CipherSuite             cipherSuite=CipherSuiteID();
	// CurveType               CurveType
	// Curve                   Curve
	// SRTPProtectionProfile   SRTPProtectionProfile
	late DtlsRandom clientRandom=DtlsRandom();  //          *Random
	// ClientKeyExchangePublic []byte

	DtlsRandom serverRandom =DtlsRandom();//       *Random
	late Uint8List serverMasterSecret;// []byte
	// ServerPublicKey    []byte
	// ServerPrivateKey   []byte
	// ServerKeySignature []byte
	// ClientCertificates [][]byte

	// IsCipherSuiteInitialized bool
	// GCM                      *GCM

	// UseExtendedMasterSecret bool

	// HandshakeMessagesReceived map[HandshakeType][]byte
	// HandshakeMessagesSent     map[HandshakeType][]byte

	// ClientEpoch                   uint16
	// ClientSequenceNumber          uint16
	late int serverEpoch;//                   uint16
	late int serverSequenceNumber;//          uint16
	late int serverHandshakeSequenceNumber;// uint16

	// Cookie []byte
	// Flight Flight

	late Uint8List keyingMaterialCache;// []byte

 void IncreaseServerEpoch() {
	serverEpoch++;
	serverSequenceNumber = 0;
}

void IncreaseServerSequence() {
	serverSequenceNumber++;
}

void IncreaseServerHandshakeSequence() {
	serverHandshakeSequenceNumber++;
}


//https://github.com/pion/dtls/blob/bee42643f57a7f9c85ee3aa6a45a4fa9811ed122/state.go#L182
Future<(Uint8List,bool?)> ExportKeyingMaterial(int length )async
 //([]byte, error) 
 {
	if (keyingMaterialCache != null) {
		return (keyingMaterialCache, null);
	}
	Uint8List encodedClientRandom = clientRandom.Encode();
	Uint8List encodedServerRandom = serverRandom.Encode();
	//var err error
	//logging.Descf(logging.ProtoDTLS, "Exporting keying material from DTLS context (<u>expected length: %d</u>)...", length)
	var (localKeyingMaterialCache, err) =await GenerateKeyingMaterial(serverMasterSecret, encodedClientRandom, encodedServerRandom, cipherSuite.HashAlgorithm, length);
	// if err != nil {
	// 	return nil, err
	// }
	return (localKeyingMaterialCache, null);
}

void SetDTLSState(DTLSState dtlsStateParam) {
	if (dtlsState == dtlsStateParam) {
		return;
	}
// dtlsState =
// 	if c.OnDTLSStateChangeHandler != nil {
// 		c.OnDTLSStateChangeHandler(dtlsState)
// 	}
}
}


