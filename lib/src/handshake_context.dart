import 'dart:js_interop';
import 'dart:typed_data';

import 'package:dtls2/src/dtls_message.dart';
import 'package:dtls2/src/handshake_header.dart';
import 'package:dtls2/src/record_header.dart';
import 'package:dtls2/src/server_hello.dart';

enum Flight {
  Flight0(0),
  Flight2(2),
  Flight4(4),
  Flight6(6);

  const Flight(this.value);
  final int value;
}

class HandshakeContext {
  //Client IP and Port
//InternetAddress	Addr;// *net.UDPAddr
  //Server UDP listener connection
  // RawDatagramSocket Conn;//                    *net.UDPConn
  // String ClientUfrag;             string
  // ExpectedFingerprintHash string

  // DTLSState                DTLSState
  // OnDTLSStateChangeHandler func(DTLSState)

  // ProtocolVersion         DtlsVersion
  // CipherSuite             *CipherSuite
  // CurveType               CurveType
  // Curve                   Curve
  // SRTPProtectionProfile   SRTPProtectionProfile
  // ClientRandom            *Random
  // ClientKeyExchangePublic []byte

  // ServerRandom       *Random
  // ServerMasterSecret []byte
  // ServerPublicKey    []byte
  // ServerPrivateKey   []byte
  // ServerKeySignature []byte
  // ClientCertificates [][]byte

  bool IsCipherSuiteInitialized = false;
  // GCM                      *GCM

  // UseExtendedMasterSecret bool

  Map<HandshakeType, Uint8List> HandshakeMessagesReceived =
      {}; //map[HandshakeType][]byte
  // HandshakeMessagesSent     map[HandshakeType][]byte

  int ClientEpoch = 0; //                   uint16
  // ClientSequenceNumber          uint16
  // ServerEpoch                   uint16
  // ServerSequenceNumber          uint16
  // ServerHandshakeSequenceNumber uint16

  // Cookie []byte
  Flight? flight;

  // void processMessage(Uint8List dtlsMessage){
  //  BaseDtlsMessage.DecodeDtlsMessage()
  // }

  // KeyingMaterialCache []byte
  void processMessage(header, handshakeHeader, result, offset, err) {
    print("Content type: ${header.enumContentType}");

    switch (header.enumContentType) {
      case ContentType.handshake:
        {
          print("Handshake type: ${handshakeHeader.handshakeType}");
          switch (handshakeHeader.handshakeType) {
            case HandshakeType.ClientHello:
              {
                List<int> serverHello=[];
                serverHello.add(ContentType.handshake.value);
              }
          }
        }
    }
  }
}

// ServerHello createDtlsServerHello(HandshakeContext context)
//  //ServerHello
//   {
// 	ServerHello result = ServerHello();
// 		// TODO: Before sending a ServerHello, we should negotiate on same protocol version which client supported and server supported protocol versions.
// 		// But for now, we accept the version directly came from client.
// 		result.Version:       context.ProtocolVersion,
// 		Random:        context.ServerRandom,
// 		CipherSuiteID: context.CipherSuite.ID, //CipherSuiteID_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 0xc02b
// 		Extensions:    map[ExtensionType]Extension{},
// 	}
// 	if context.UseExtendedMasterSecret {
// 		AddExtension(result.Extensions, new(ExtUseExtendedMasterSecret))
// 	}
// 	AddExtension(result.Extensions, new(ExtRenegotiationInfo))

// 	if context.SRTPProtectionProfile != 0 {
// 		useSRTP := new(ExtUseSRTP)
// 		useSRTP.ProtectionProfiles = []SRTPProtectionProfile{context.SRTPProtectionProfile} // SRTPProtectionProfile_AEAD_AES_128_GCM 0x0007
// 		AddExtension(result.Extensions, useSRTP)
// 	}
// 	supportedPointFormats := new(ExtSupportedPointFormats)
// 	// TODO: For now, we choose one point format hardcoded. It should be choosen by a negotiation process.
// 	supportedPointFormats.PointFormats = []PointFormat{PointFormatUncompressed} // 0x00
// 	AddExtension(result.Extensions, supportedPointFormats)

// 	return result
// }