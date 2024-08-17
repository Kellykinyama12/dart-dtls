import 'dart:io';

import 'package:dtls2/src/dtls_message.dart';
import 'package:dtls2/src/handshake_context.dart';

class HandshakeManager {
  HandshakeManager();
  Map<String, HandshakeContext> contexts = {};

  HandshakeContext NewContext(InternetAddress addr, RawDatagramSocket conn,
      String clientUfrag, String expectedFingerprintHash)
  //*HandshakeContext
  {
    return HandshakeContext();
    // Addr:                    addr,
    // Conn:                    conn,
    // ClientUfrag:             clientUfrag,
    // ExpectedFingerprintHash: expectedFingerprintHash,
    // DTLSState:               DTLSStateNew,
    // // TODO: For now, we choose one curve type hardcoded. It should be choosen by a negotiation process.
    // CurveType:                 CurveTypeNamedCurve,
    // HandshakeMessagesReceived: map[HandshakeType][]byte{},
    // HandshakeMessagesSent:     map[HandshakeType][]byte{},
  }

//   dynamic ProcessIncomingMessage(HandshakeContext context, BaseDtlsHandshakeMessage incomingMessage )
//    //error
//    {
// 	switch message := incomingMessage.(type) {
// 	case *ClientHello:
// 		switch context.Flight {
// 		case Flight0:
// 			context.SetDTLSState(DTLSStateConnecting)
// 			context.ProtocolVersion = message.Version
// 			context.Cookie = generateDtlsCookie()
// 			logging.Descf(logging.ProtoDTLS, "DTLS Cookie was generated and set to <u>0x%x</u> in handshake context (<u>%d bytes</u>).", context.Cookie, len(context.Cookie))

// 			context.Flight = Flight2
// 			logging.Descf(logging.ProtoDTLS, "Running into <u>Flight %d</u>.", context.Flight)
// 			logging.LineSpacer(2)
// 			helloVerifyRequestResponse := createDtlsHelloVerifyRequest(context)
// 			m.SendMessage(context, &helloVerifyRequestResponse)
// 			return nil
// 		case Flight2:
// 			if len(message.Cookie) == 0 {
// 				context.Flight = Flight0
// 				logging.Errorf(logging.ProtoDTLS, "Expected not empty Client Hello Cookie but <nil> found!")
// 				logging.Descf(logging.ProtoDTLS, "Running into <u>Flight %d</u>.", context.Flight)
// 				logging.LineSpacer(2)
// 				return nil
// 			}
// 			if !bytes.Equal(context.Cookie, message.Cookie) {
// 				return m.setStateFailed(context, errors.New("client hello cookie is invalid"))
// 			}
// 			negotiatedCipherSuite, err := m.negotiateOnCipherSuiteIDs(message.CipherSuiteIDs)
// 			if err != nil {
// 				return m.setStateFailed(context, err)
// 			}
// 			context.CipherSuite = negotiatedCipherSuite
// 			logging.Descf(logging.ProtoDTLS, "Negotiation on cipher suites: Client sent a list of cipher suites, server selected one of them (mutually supported), and assigned in handshake context: %s", negotiatedCipherSuite)
// 			for _, extensionItem := range message.Extensions {
// 				switch msgExtension := extensionItem.(type) {
// 				case *ExtSupportedEllipticCurves:
// 					negotiatedCurve, err := m.negotiateOnCurves(msgExtension.Curves)
// 					if err != nil {
// 						return m.setStateFailed(context, err)
// 					}
// 					context.Curve = negotiatedCurve
// 					logging.Descf(logging.ProtoDTLS, "Negotiation on curves: Client sent a list of curves, server selected one of them (mutually supported), and assigned in handshake context: <u>%s</u>", negotiatedCurve)
// 				case *ExtUseSRTP:
// 					negotiatedProtectionProfile, err := m.negotiateOnSRTPProtectionProfiles(msgExtension.ProtectionProfiles)
// 					if err != nil {
// 						return m.setStateFailed(context, err)
// 					}
// 					context.SRTPProtectionProfile = negotiatedProtectionProfile
// 					logging.Descf(logging.ProtoDTLS, "Negotiation on SRTP protection profiles: Client sent a list of SRTP protection profiles, server selected one of them (mutually supported), and assigned in handshake context: <u>%s</u>", negotiatedProtectionProfile)
// 				case *ExtUseExtendedMasterSecret:
// 					context.UseExtendedMasterSecret = true
// 					logging.Descf(logging.ProtoDTLS, "Client sent UseExtendedMasterSecret extension, client wants to use ExtendedMasterSecret. We will generate the master secret via extended way further.")
// 				}
// 			}

// 			context.ClientRandom = &message.Random
// 			logging.Descf(logging.ProtoDTLS, "Client sent Client Random, it set to <u>0x%x</u> in handshake context.", message.Random.Encode())
// 			context.ServerRandom = new(Random)
// 			context.ServerRandom.Generate()
// 			logging.Descf(logging.ProtoDTLS, "We generated Server Random, set to <u>0x%x</u> in handshake context.", context.ServerRandom.Encode())

// 			serverPublicKey, serverPrivateKey, err := GenerateCurveKeypair(context.Curve)
// 			if err != nil {
// 				return m.setStateFailed(context, err)
// 			}

// 			context.ServerPublicKey = serverPublicKey
// 			context.ServerPrivateKey = serverPrivateKey
// 			logging.Descf(logging.ProtoDTLS, "We generated Server Public and Private Key pair via <u>%s</u>, set in handshake context. Public Key: <u>0x%x</u>", context.Curve, context.ServerPublicKey)

// 			clientRandomBytes := context.ClientRandom.Encode()[:]
// 			serverRandomBytes := context.ServerRandom.Encode()[:]

// 			logging.Descf(logging.ProtoDTLS, "Generating ServerKeySignature. It will be sent to client via ServerKeyExchange DTLS message further.")
// 			context.ServerKeySignature, err = GenerateKeySignature(
// 				clientRandomBytes,
// 				serverRandomBytes,
// 				context.ServerPublicKey,
// 				context.Curve, //x25519
// 				ServerCertificate.PrivateKey,
// 				context.CipherSuite.HashAlgorithm)
// 			if err != nil {
// 				return m.setStateFailed(context, err)
// 			}
// 			logging.Descf(logging.ProtoDTLS, "ServerKeySignature was generated and set in handshake context (<u>%d bytes</u>).", len(context.ServerKeySignature))

// 			context.Flight = Flight4
// 			logging.Descf(logging.ProtoDTLS, "Running into <u>Flight %d</u>.", context.Flight)
// 			logging.LineSpacer(2)
// 			serverHelloResponse := createDtlsServerHello(context)
// 			m.SendMessage(context, &serverHelloResponse)
// 			certificateResponse := createDtlsCertificate()
// 			m.SendMessage(context, &certificateResponse)
// 			serverKeyExchangeResponse := createDtlsServerKeyExchange(context)
// 			m.SendMessage(context, &serverKeyExchangeResponse)
// 			certificateRequestResponse := createDtlsCertificateRequest(context)
// 			m.SendMessage(context, &certificateRequestResponse)
// 			serverHelloDoneResponse := createDtlsServerHelloDone(context)
// 			m.SendMessage(context, &serverHelloDoneResponse)
// 		}
// 	case *Certificate:
// 		context.ClientCertificates = message.Certificates
// 		logging.Descf(logging.ProtoDTLS, "Generating certificate fingerprint hash from incoming Client Certificate...")
// 		certificateFingerprintHash := GetCertificateFingerprintFromBytes(context.ClientCertificates[0])
// 		logging.Descf(logging.ProtoDTLS, "Checking fingerprint hash of client certificate incoming by this packet <u>%s</u> equals to expected fingerprint hash <u>%s</u> came from Signaling SDP", certificateFingerprintHash, context.ExpectedFingerprintHash)
// 		if context.ExpectedFingerprintHash != certificateFingerprintHash {
// 			return m.setStateFailed(context, errors.New("incompatible fingerprint hashes from SDP and DTLS data"))
// 		}
// 	case *CertificateVerify:
// 		logging.Descf(logging.ProtoDTLS, "Checking incoming HashAlgorithm <u>%s</u> equals to negotiated before via hello messages <u>%s</u>", message.AlgoPair.HashAlgorithm, context.CipherSuite.HashAlgorithm)
// 		logging.Descf(logging.ProtoDTLS, "Checking incoming SignatureAlgorithm <u>%s</u> equals to negotiated before via hello messages <u>%s</u>", message.AlgoPair.SignatureAlgorithm, context.CipherSuite.SignatureAlgorithm)
// 		logging.LineSpacer(2)
// 		if !(context.CipherSuite.HashAlgorithm == message.AlgoPair.HashAlgorithm &&
// 			HashAlgorithm(context.CipherSuite.SignatureAlgorithm) == HashAlgorithm(message.AlgoPair.SignatureAlgorithm)) {
// 			return m.setStateFailed(context, errors.New("incompatible signature scheme"))
// 		}
// 		handshakeMessages, handshakeMessageTypes, ok := m.concatHandshakeMessages(context, false, false)
// 		if !ok {
// 			return m.setStateFailed(context, errors.New("error while concatenating handshake messages"))
// 		}
// 		logging.Descf(logging.ProtoDTLS,
// 			common.JoinSlice("\n", false,
// 				common.ProcessIndent("Verifying client certificate...", "+", []string{
// 					fmt.Sprintf("Concatenating messages in single byte array: \n<u>%s</u>", common.JoinSlice("\n", true, handshakeMessageTypes...)),
// 					fmt.Sprintf("Generating hash from the byte array (<u>%d bytes</u>) via <u>%s</u>.", len(handshakeMessages), context.CipherSuite.HashAlgorithm),
// 					"Verifying the calculated hash, the incoming signature by CertificateVerify message and client certificate public key.",
// 				})))
// 		err := VerifyCertificate(handshakeMessages, context.CipherSuite.HashAlgorithm, message.Signature, context.ClientCertificates)
// 		if err != nil {
// 			return m.setStateFailed(context, err)
// 		}
// 	case *ClientKeyExchange:
// 		context.ClientKeyExchangePublic = message.PublicKey
// 		if !context.IsCipherSuiteInitialized {
// 			err := m.initCipherSuite(context)
// 			if err != nil {
// 				return m.setStateFailed(context, err)
// 			}
// 		}
// 	case *Finished:
// 		logging.Descf(logging.ProtoDTLS, "Received first encrypted message and decrypted successfully: Finished (epoch was increased to <u>%d</u>)", context.ClientEpoch)
// 		logging.LineSpacer(2)

// 		handshakeMessages, handshakeMessageTypes, ok := m.concatHandshakeMessages(context, true, true)
// 		if !ok {
// 			return m.setStateFailed(context, errors.New("error while concatenating handshake messages"))
// 		}
// 		logging.Descf(logging.ProtoDTLS,
// 			common.JoinSlice("\n", false,
// 				common.ProcessIndent("Verifying Finished message...", "+", []string{
// 					fmt.Sprintf("Concatenating messages in single byte array: \n<u>%s</u>", common.JoinSlice("\n", true, handshakeMessageTypes...)),
// 					fmt.Sprintf("Generating hash from the byte array (<u>%d bytes</u>) via <u>%s</u>, using server master secret.", len(handshakeMessages), context.CipherSuite.HashAlgorithm),
// 				})))
// 		calculatedVerifyData, err := VerifyFinishedData(handshakeMessages, context.ServerMasterSecret, context.CipherSuite.HashAlgorithm)
// 		if err != nil {
// 			return m.setStateFailed(context, err)
// 		}
// 		logging.Descf(logging.ProtoDTLS, "Calculated Finish Verify Data: <u>0x%x</u> (<u>%d bytes</u>). This data will be sent via Finished message further.", calculatedVerifyData, len(calculatedVerifyData))
// 		context.Flight = Flight6
// 		logging.Descf(logging.ProtoDTLS, "Running into <u>Flight %d</u>.", context.Flight)
// 		logging.LineSpacer(2)
// 		changeCipherSpecResponse := createDtlsChangeCipherSpec(context)
// 		m.SendMessage(context, &changeCipherSpecResponse)
// 		context.IncreaseServerEpoch()

// 		finishedResponse := createDtlsFinished(context, calculatedVerifyData)
// 		m.SendMessage(context, &finishedResponse)
// 		logging.Descf(logging.ProtoDTLS, "Sent first encrypted message successfully: Finished (epoch was increased to <u>%d</u>)", context.ServerEpoch)
// 		logging.LineSpacer(2)

// 		logging.Infof(logging.ProtoDTLS, "Handshake Succeeded with <u>%v:%v</u>.\n", context.Addr.IP, context.Addr.Port)
// 		context.SetDTLSState(DTLSStateConnected)
// 	default:
// 	}
// 	return nil
// }
}
