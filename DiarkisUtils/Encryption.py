import hmac
import base64
import msgpack
from hashlib import sha256
from typing import Tuple

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

import server_config


class Encryption:
    # mac校验key长度

    ENCRYPTION_MAC_LEN = 32
    ENCRYPTION_AES_BLOCKSIZE = AES.block_size

    @staticmethod
    def EncryptAndSign(key: bytes, iv: bytes, macKey: bytes, payload: bytes) -> bytes:
        # 需要对序列进行Padding处理，ZeroPadding，PayloadSize不算填充数
        payloadSize = len(payload)
        encrypted = Encryption.EncryptWith(key, iv, payload)
        sizeBytes: bytes = int.to_bytes(payloadSize, length=4, byteorder="big", signed=False)  # 转成网络字节序
        """
        加密后的payload长度：encrypted + mackey 长度 + 4
        首4字节为加密前payload的长度
        """
        res: bytearray = bytearray(sizeBytes)
        hmacBytes = hmac.new(key=macKey, msg=encrypted, digestmod="sha256").digest()
        res.extend(hmacBytes)
        res.extend(encrypted)
        """
        加密payload组成：原始payload长度（4字节）+ hmac签名（32字节）+ 加密后payload
        """
        return res

    @staticmethod
    def EncryptWith(key: bytes, iv: bytes, payload: bytes) -> bytes:
        Aes = AES.new(key, AES.MODE_CBC, iv)
        payload = Encryption.PaddingDataWithZero(payload)
        encrypted = Aes.encrypt(payload)
        return encrypted

    @staticmethod
    def AuthAndDecrypt(key: bytes, iv: bytes, macKey: bytes, payload: bytes) -> Tuple[bytes, int]:
        # TODO： 根据PayloadSize找出Unpad后的数据
        sizeBytes: bytes = payload[:4]
        decryptedSize = int.from_bytes(sizeBytes, byteorder="big", signed=False)
        encrypted: bytes = payload[4:len(payload)]
        remoteHmac: bytes = encrypted[:Encryption.ENCRYPTION_MAC_LEN]
        payloadToAuth = encrypted[Encryption.ENCRYPTION_MAC_LEN:]
        thisHmac = hmac.new(key=macKey, msg=payloadToAuth, digestmod="sha256").digest()
        if thisHmac != remoteHmac:
            raise Exception("HMAC校验失败")
        return (Encryption.DecryptWith(key, iv, payloadToAuth), decryptedSize)

    @staticmethod
    def DecryptWith(key: bytes, iv: bytes, payload: bytes) -> bytes:
        Aes = AES.new(key, AES.MODE_CBC, iv)
        decrypted = Aes.decrypt(payload)
        return decrypted

    @staticmethod
    def PaddingDataWithZero(packet: bytes) -> bytes:
        """
        diarkis的udp packet使用类似pkcs7方式，不过是用0x00填充数据
        :param packet:
        :return:
        """
        packet: bytearray = bytearray(packet)
        paddingZero = 0
        dataLen = len(packet)
        if dataLen < Encryption.ENCRYPTION_AES_BLOCKSIZE:
            paddingZero = Encryption.ENCRYPTION_AES_BLOCKSIZE - dataLen
        elif dataLen % Encryption.ENCRYPTION_AES_BLOCKSIZE != 0:
            paddingZero = Encryption.ENCRYPTION_AES_BLOCKSIZE - (dataLen % Encryption.ENCRYPTION_AES_BLOCKSIZE)
        else:
            paddingZero = 0
        PaddingBytes = [0x00] * (paddingZero + 16)
        packet.extend(bytearray(PaddingBytes))
        return bytes(packet)
    
    def DecryptApiResponse(encrypted_data):
        AES_handler = AES.new(server_config.key, AES.MODE_CBC, server_config.iv)
        decrypted = unpad(AES_handler.decrypt(encrypted_data), AES.block_size)
        json_data = msgpack.unpackb(decrypted)
        return json_data
