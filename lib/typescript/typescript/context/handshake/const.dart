enum HandshakeType {
  helloRequest0(0),
  clientHello1(1),
  serverHello2(2),
  helloVerifyRequest3(3),
  certificate11(11),
  serverKeyExchange12(12),
  certificateRequest13(13),
  serverHelloDone14(14),
  certificateVerify15(15),
  clientKeyExchange16(16),
  finished20(20);

  final int value;
  const HandshakeType(this.value);
}