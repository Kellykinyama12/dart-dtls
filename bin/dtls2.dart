import 'dart:io';
import 'dart:typed_data';

import 'package:dtls2/src/crypto_gcm.dart';
import 'package:dtls2/src/handshake_header.dart';
import 'package:dtls2/src/random.dart';
import 'package:dtls2/src/utils.dart';
import 'package:dtls2/typescript/cipher/const.dart';
import 'package:pinenacl/x25519.dart';


// type Flight byte

enum Flight{
	Flight0 (0),
	Flight2 (2),
	Flight4 (4),
	Flight6 (6);

  const Flight(this.value);
  final int value;
}

class HandshakeContext {
	//Client IP and Port
	InternetAddress addr;// *net.UDPAddr
	//Server UDP listener connection
	RawDatagramSocket conn;//                    *net.UDPConn
	String clientUfrag;//             string
	String expectedFingerprintHash;// string

	DTLSState                dtlsState;
	Function onDTLSStateChangeHandler;// func(DTLSState)

	Uint8List protocolVersion;//         DtlsVersion;
	CipherSuite             cipherSuite;
	CurveType               curveType;
	Curve                   curve;
	SRTPProtectionProfile   srtpProtectionProfile;
	DtlsRandom clientRandom=DtlsRandom();//            *Random
	Uint8List clientKeyExchangePublic;// []byte

	DtlsRandom serverRandom;//       *Random
	Uint8List serverMasterSecret;// []byte
	Uint8List serverPublicKey;//    []byte
	Uint8List serverPrivateKey;//   []byte
	Uint8List serverKeySignature;// []byte
	List<Uint8List> ClientCertificates=[];// [][]byte

	bool isCipherSuiteInitialized;// bool
	GCM                      gcm=GCM();

	bool useExtendedMasterSecret;// bool

	Map<HandshakeType,Uint8List> HandshakeMessagesReceived={};// map[HandshakeType][]byte
	Map<HandshakeType,Uint8List> HandshakeMessagesSent ={};//    map[HandshakeType][]byte

	int clientEpoch;//                   uint16
	int clientSequenceNumber;//          uint16
	int serverEpoch;//                   uint16
	int serverSequenceNumber;//          uint16
	int serverHandshakeSequenceNumber;// uint16

	Uint8List cookie;// []byte
	Flight flight;

	Uint8List keyingMaterialCache;// []byte

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
(Uint8List,bool?) ExportKeyingMaterial(int length)
 //([]byte, error)
  {
	if (keyingMaterialCache != null) {
		return (keyingMaterialCache, null);
	}
	var encodedClientRandom = clientRandom.encode();
	encodedServerRandom := c.ServerRandom.Encode()
	var err error
	logging.Descf(logging.ProtoDTLS, "Exporting keying material from DTLS context (<u>expected length: %d</u>)...", length)
	c.KeyingMaterialCache, err = GenerateKeyingMaterial(c.ServerMasterSecret, encodedClientRandom, encodedServerRandom, c.CipherSuite.HashAlgorithm, length)
	if err != nil {
		return nil, err
	}
	return c.KeyingMaterialCache, nil
}


}










// func (c *HandshakeContext) SetDTLSState(dtlsState DTLSState) {
// 	if c.DTLSState == dtlsState {
// 		return
// 	}
// 	c.DTLSState = dtlsState
// 	if c.OnDTLSStateChangeHandler != nil {
// 		c.OnDTLSStateChangeHandler(dtlsState)
// 	}
// }
