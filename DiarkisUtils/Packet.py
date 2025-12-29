import msgpack

from .Encryption import Encryption


class Packet:
    # Diarkis UDP Constant

    UDP_PROTO = 0x1
    RUDP_PROTO_SYN = 0x2
    RUDP_PROTO_DAT = 0x3
    RUDP_PROTO_ACK = 0x4
    RUDP_PROTO_RST = 0x5
    RUDP_PROTO_EACK = 0x6
    RUDP_PROTO_FIN = 0x7
    PUSH_STATUS = 0xFF

    REQ_HEADER_SIZE = 10
    RES_HEADER_SIZE = 11

    HEADER_SYMBOL = bytes([0xFE, 0xBE, 0xDE, 0xEF])

    # struct

    class PacketHeader:
        Ver: int
        Cmd: int
        Status: int = 1  # -1 时数据包无效
        PayloadSize: int

    class Error:
        message: str
        code: int

    class UDPPacket:
        Invalid: bool
        Flag: int
        Seq: int
        Packet: bytes
        IsRUDP: bool

    class Parsed:
        Invalid: bool
        Header: any
        Payload: bytes
        ConsumedSize: int  # Header 长度 + Payload 长度

    class Addr:
        Address: str
        Port: int

    class P2PClientAddr:
        UserID: str
        PublicAddr: str
        LocalAddrs: list

    class Payload:
        # 客户端
        Sid: bytes
        Signature: bytes
        ActualPayloadSize: int  # 去除sid长度、hmac长度的包长
        ActualPayload: bytes  # 去除了头16位sid及32位hmac

    class BroadcastPayload:
        # 解析客户端的广播包
        isRUDP: bool
        RoomID: str
        ActualPayload: bytes  # 有效payload（非反序列化）

    class ServerPayload:
        ActualPayloadSize: int
        Signature: bytes
        ActualPayload: bytes

    class Secret:
        Key: bytes
        Iv: bytes
        MacKey: bytes

    @staticmethod
    def IsHeaderSymbol(packet: bytes) -> bool:
        return packet == Packet.HEADER_SYMBOL

    @staticmethod
    def ParseUDPPacket(packet: bytes, size: int = 0) -> UDPPacket:
        udpPacket = Packet.UDPPacket()
        if len(packet) < 4:
            udpPacket.Invalid = True
            return udpPacket
        udpPacket.Invalid = False
        fourBytes: bytearray = bytearray(packet[:4])
        # 获取flag
        udpPacket.Flag = int(fourBytes[3])
        # 获取seq
        fourBytes[3] = 0x00
        udpPacket.Seq = int.from_bytes(fourBytes, byteorder="little", signed=False)
        # 获取packet
        if size == 0:
            size = len(packet)
        udpPacket.Packet = packet[4:size]
        udpPacket.IsRUDP = udpPacket.Flag != Packet.UDP_PROTO
        return udpPacket

    @staticmethod
    def DetectCombinedPacket(packet: bytes) -> list:
        split: list = []
        udpPacket = Packet.UDPPacket()
        udpPacket.Flag = int(packet[3])
        if udpPacket.Flag != Packet.RUDP_PROTO_ACK and udpPacket.Flag != Packet.RUDP_PROTO_EACK:
            return split
        num = int(len(packet) / 20)
        for i in range(num):
            start_index = i * 20
            end_index = start_index + 20
            newPacket = Packet.ParseUDPPacket(packet=packet[start_index:end_index], size=20)
            split.append(newPacket)

        return split[1:]

    @staticmethod
    def CreateUDPPacket(flag: int, seq: int, payload: bytes) -> bytes:
        fourBytes: bytearray = bytearray(int.to_bytes(flag, byteorder="big", signed=False, length=4))
        fourBytes[0] = seq
        return bytes(fourBytes + bytearray(payload))

    @staticmethod
    def ParseHeader(packet: bytes) -> PacketHeader:
        fourBytes: bytearray = bytearray(packet[:4])
        if not Packet.IsHeaderSymbol(bytes(fourBytes)):
            invalidHeader = Packet.PacketHeader()
            invalidHeader.Status = -1
            return invalidHeader
        startOffset = 4
        fourBytes = bytearray(packet[startOffset: startOffset + 4])
        # 获取payloadsize
        # fourBytes.reverse()
        fourBytes[0] = 0x00
        payloadSize = int.from_bytes(fourBytes, byteorder="big", signed=False)
        header = Packet.PacketHeader()
        header.PayloadSize = payloadSize  # 此payloadSize包含hmac的长度
        # 获取ver，ver 1字节
        fourBytes = bytearray(packet[startOffset: startOffset + 1 + 3])  # 后面3字节为填充字节，下面同理
        fourBytes[1] = 0x00
        fourBytes[2] = 0x00
        fourBytes[3] = 0x00
        header.Ver = int.from_bytes(fourBytes, byteorder="little", signed=False)
        # 获取Cmd（cs代码的cmd为short），Cmd 2字节
        startOffset = 8
        fourBytes = bytearray(packet[startOffset: startOffset + 2 + 2])
        fourBytes[2] = fourBytes[0]
        fourBytes[3] = fourBytes[1]
        fourBytes.reverse()
        header.Cmd = int.from_bytes(fourBytes[:2], byteorder="little", signed=False)
        # 来自客户端的Packet不包含Status
        # 获取Status，Status 1字节
        startOffset = 10
        fourBytes = bytearray(packet[startOffset: startOffset + 1])
        fourBytes.extend([0x00, 0x00, 0x00])
        header.Status = int.from_bytes(fourBytes, byteorder="little", signed=False)

        return header

    @staticmethod
    def ParseProtocolPacket(packet: bytes) -> Parsed:
        """
        Protocol Packet：Packet起始4字节为0xfe、0xbe、0xde、0xef
        :param packet:
        :return:
        """
        parsed = Packet.Parsed()
        parsed.Invalid = True
        if len(packet) < Packet.REQ_HEADER_SIZE:
            return parsed
        parsed.Header = Packet.ParseHeader(packet)
        if parsed.Header.Status == -1:
            print("无效的协议Header。")
            return parsed
        if parsed.Header.PayloadSize > len(packet) - Packet.REQ_HEADER_SIZE:
            print("payload 长度无效。")
            return parsed
        parsed.Invalid = False
        startOffset = Packet.REQ_HEADER_SIZE
        payload: bytes = packet[startOffset: startOffset + parsed.Header.PayloadSize]
        parsed.Payload = payload
        parsed.ConsumedSize = Packet.REQ_HEADER_SIZE + parsed.Header.PayloadSize
        return parsed

    @staticmethod
    def ParseNonProtocolPacket(packet: bytes) -> bytes:
        """
        NonProtocol整个payload均为有效信息
        :param packet:
        :return:
        """
        return packet

    @staticmethod
    def CreateProtocolPayload(payload: ServerPayload, ver: int, cmd: int, status: int) -> bytes:
        """
        生成发送给客户端的协议包。
        头：标志Protocol的Header + Header
        0-4：HeaderSymbol
        4-11：从低到高：payloadSize（4）、ver（1）、cmd（2）、packet（status）
        此处的
        :param status:
        :param ver:
        :param cmd:
        :param payload:
        :return:
        """
        cmd = int.to_bytes(cmd, length=2, byteorder="big", signed=False)
        Status = int.to_bytes(status, length=1, byteorder="big", signed=False)
        actualPayloadSize = int.to_bytes(payload.ActualPayloadSize, length=4, byteorder="big", signed=False)
        ver = int.to_bytes(ver, length=1, byteorder="big", signed=False)
        payloadSize = len(payload.Signature) + len(payload.ActualPayload)
        payloadSize = int.to_bytes(payloadSize, length=3, byteorder="big", signed=False)
        # 开始按协议顺序拼接
        protocolPayload = bytearray()
        protocolPayload.extend(bytearray(Packet.HEADER_SYMBOL))
        protocolPayload.extend(ver)
        protocolPayload.extend(payloadSize)
        protocolPayload.extend(cmd)
        protocolPayload.extend(Status)
        protocolPayload.extend(payload.Signature)
        protocolPayload.extend(payload.ActualPayload)
        return bytes(protocolPayload)

    @staticmethod
    def CreateServerPayload(key: bytes, iv: bytes, macKey: bytes, payload: bytes, push: bool = False) -> ServerPayload:
        """
        生成*ServerPayload*
        :param push:是否为push_status包。push_status包头4字节包含信息长度
        :param key:
        :param iv:
        :param macKey:
        :param payload:
        :return:
        """
        serverPayload = Packet.ServerPayload()
        serverPayload.ActualPayloadSize = len(payload)
        payloadSizeBuff = int.to_bytes(len(payload), length=4, byteorder="big", signed=False)
        if push:
            payload = bytes(bytearray(payloadSizeBuff) + bytearray(payload))
        securePayload = Packet.CreateServerSecurePayload(key, iv, macKey, payload)
        serverPayload.Signature = securePayload[:32]
        serverPayload.ActualPayload = securePayload[32:]

        return serverPayload

    @staticmethod
    def GetSIDFromParsedPacket(ParsedPacket: Parsed) -> str:
        """
        获取DAT/RST包的SID
        """
        return ParsedPacket.Payload[:16].hex()

    @staticmethod
    def ParseProtocolPayload(ParsedPacket: Parsed, secret: Secret) -> Payload:
        """
        解析客户端的SecurePayload
        :param secret:
        :param ParsedPacket:
        :return: Payload
        *Payload* 包含
        Sid: bytes （16位）
        Signature: bytes （32位）
        ActualPayloadSize: int  # 去除sid长度、hmac长度的包长
        ActualPayload: bytes （不定）
        """
        payload = Packet.Payload()
        packet = ParsedPacket.Payload
        payload.Sid = packet[:16]
        payload.Signature = packet[16: 16 + 32]
        decodeSecurePayload = Packet.DecodeClientSecurePayload(secret.Key, secret.Iv, secret.MacKey, packet)
        packet = decodeSecurePayload[16:]
        # Header的PayloadSize是加密处理之前的payload
        payload.ActualPayloadSize = ParsedPacket.Header.PayloadSize
        payload.ActualPayload = packet

        return payload

    @staticmethod
    def ParseBroadcastPayload(payload: bytes) -> BroadcastPayload:
        """
        解析客户端的Broadcast Payload
        :param payload:
        :return:
        客户端的Broadcast Payload由
        RUDP flag： 1 byte
        RoomID： 52 bytes
        实际Payload：the rest of size.
        组成。
        """
        isRUDP = bool(payload[0])
        RoomID = payload[1:53].decode()
        bpayload: Packet.BroadcastPayload = Packet.BroadcastPayload()
        bpayload.isRUDP = isRUDP
        bpayload.RoomID = RoomID
        bpayload.ActualPayload = payload[53:]
        return bpayload

    @staticmethod
    def CreateServerSecurePayload(key: bytes, iv: bytes, macKey: bytes, payload: bytes) -> bytes:
        """
        生成头部不带有sid的payload（服务端的包）
        :param key:
        :param iv:
        :param macKey:
        :param payload:
        :return:
        """
        securePayload = payload
        if Packet.IsSecureEnabled(key, iv, macKey):
            securePayload = Encryption.EncryptAndSign(key, iv, macKey, securePayload)
        return securePayload

    @staticmethod
    def CreateClientSecurePayload(sid: bytes, key: bytes, iv: bytes, macKey: bytes, payload: bytes) -> bytes:
        """
        生成带有头部含有sid信息的payload（客户端的包），可以以不加密的方式生成。
        不加密时key、iv、macKey传入长度为0的bytes
        :param sid:
        :param key:
        :param iv:
        :param macKey:
        :param payload:
        :return: sid（一般为16字节） + payload
        """
        securePayload: bytearray = bytearray(sid)
        if Packet.IsSecureEnabled(key, iv, macKey):
            encrypted = Encryption.EncryptAndSign(key, iv, macKey, payload)
            securePayload.extend(encrypted)
        else:
            securePayload.extend(payload)
        return bytes(securePayload)

    @staticmethod
    def DecodeClientSecurePayload(key: bytes, iv: bytes, macKey: bytes, payload: bytes) -> bytes:
        """
        解密指定的SecurePayload（头部带sid）
        :param key:
        :param iv:
        :param macKey:
        :param payload:
        :return: sid + decrypted
        """
        sid = payload[:16]
        encrypted = payload[16:]
        if Packet.IsSecureEnabled(key, iv, macKey):
            encrypted = Encryption.AuthAndDecrypt(key, iv, macKey, encrypted)
            decode = encrypted[0]
            payloadLen = encrypted[1]
            encrypted = decode[:payloadLen]
        decodePayload = bytearray(sid)
        decodePayload.extend(encrypted)
        return decodePayload

    @staticmethod
    def IsSecureEnabled(key: bytes, iv: bytes, macKey: bytes) -> bool:
        if len(key) > 0 and len(iv) > 0 and len(macKey) > 0:
            return True
        return False

    @staticmethod
    def PackMsgpack(payload: any) -> bytes:
        packed = msgpack.packb(payload, use_single_float=True)
        return packed

    @staticmethod
    def UnpackMsgPack(payload: bytes) -> dict:
        unpack = msgpack.unpackb(payload, strict_map_key=False)
        return unpack


def run_test():
    packet: bytes = bytes.fromhex("00000004475ac4d8a58f2907b8e32617d6d992f801000004475ac4d8a58f2907b8e32617d6d992f802000004475ac4d8a58f2907b8e32617d6d992f8")
    split = Packet.DetectCombinedPacket(packet)
    split_packet = split[0]
    print(split)


if __name__ == '__main__':
    run_test()
