"""
Diarkis中物体属性信息
"""
from typing import Any, Final
from . import Packet


class SyncProperty:
    """Diarkis同步属性的序列化和反序列化工具类"""

    __slots__ = ()

    # 类型常量
    TYPE_INVALID: Final[int] = 0
    TYPE_BYTE: Final[int] = 1
    TYPE_INT32: Final[int] = 2
    TYPE_INT64: Final[int] = 3
    TYPE_STRING: Final[int] = 4
    TYPE_FLOAT: Final[int] = 5
    TYPE_BOOL: Final[int] = 6
    TYPE_OBJECT: Final[int] = 7

    TYPE_MAPPING = {
        TYPE_INVALID: "Invalid",
        TYPE_BYTE: "Byte",
        TYPE_INT32: "Int32",
        TYPE_INT64: "Int64",
        TYPE_STRING: "String",
        TYPE_FLOAT: "Float",
        TYPE_BOOL: "Bool",
        TYPE_OBJECT: "Object",
    }

    @staticmethod
    def ParseBytes(buff: bytes) -> tuple[bool, bytes | int]:
        if buff[0] != SyncProperty.TYPE_BYTE:
            return False, 0
        if len(buff) < 5:
            return False, 0
        data_size = int.from_bytes(buff[1:5], byteorder="big", signed=False)
        data_bytes = buff[5:5 + data_size]
        return True, data_bytes

    @staticmethod
    def ParseInt32(buff: bytes) -> tuple[bool, int]:
        if buff[0] != SyncProperty.TYPE_INT32:
            return False, 0xff
        if len(buff) < 5:
            return False, 0xff
        data_size = int.from_bytes(buff[1:5], byteorder="big", signed=False)
        data_bytes = buff[5:5 + data_size]
        data_int = int.from_bytes(data_bytes, byteorder="big")
        return True, data_int

    @staticmethod
    def ParseString(buff: bytes) -> tuple[bool, str]:
        if buff[0] != SyncProperty.TYPE_STRING:
            return False, ""
        if len(buff) < 5:
            return False, ""
        data_size = int.from_bytes(buff[1:5], byteorder="big", signed=False)
        data_bytes = buff[5:5 + data_size]
        return True, data_bytes.decode("utf-8")

    @staticmethod
    def PackBytes(buff: bytes) -> bytes:
        pack_buff = bytearray()
        pack_buff.append(SyncProperty.TYPE_BYTE)
        buff_size_bytes = len(buff).to_bytes(length=4, byteorder="big", signed=False)
        pack_buff.extend(buff_size_bytes)
        pack_buff.extend(buff)
        return bytes(pack_buff)

    @staticmethod
    def PackInt32(value: int) -> bytes:
        pack_buff = bytearray()
        pack_buff.append(SyncProperty.TYPE_INT32)
        buff_size_bytes = (4).to_bytes(length=4, byteorder="big", signed=False)
        pack_buff.extend(buff_size_bytes)
        value_bytes = value.to_bytes(length=4, byteorder="big")
        pack_buff.extend(value_bytes)
        return bytes(pack_buff)

    @staticmethod
    def PackString(value: str) -> bytes:
        pack_buff = bytearray()
        pack_buff.append(SyncProperty.TYPE_STRING)
        value_bytes = value.encode("utf-8")
        buff_size_bytes = len(value_bytes).to_bytes(length=4, byteorder="big", signed=False)
        pack_buff.extend(buff_size_bytes)
        pack_buff.extend(value_bytes)
        return bytes(pack_buff)

    @staticmethod
    def PackObject(buff: Any) -> bytes:
        # 目前先不解析SyncObject
        return buff

    @staticmethod
    def ParseObject(buff: Any) -> tuple[bool, dict]:
        if buff[0] != SyncProperty.TYPE_OBJECT:
            return False, 0
        if len(buff) < 5:
            return False, 0
        data_size = int.from_bytes(buff[1:5], byteorder="big", signed=False)
        data_bytes = buff[5:5 + data_size]
        return True, Packet.UnpackMsgPack(data_bytes)
    
    @staticmethod
    def ParseSyncPropertyData(buff: bytes) -> tuple[bool, str, Any]:
        if buff[0] == SyncProperty.TYPE_OBJECT:
            success, data = SyncProperty.ParseObject(buff)
            if success:
                return True, "Object", data
        elif buff[0] == SyncProperty.TYPE_STRING:
            success, data = SyncProperty.ParseString(buff)
            if success:
                return True, "String", data
        elif buff[0] == SyncProperty.TYPE_INT32:
            success, data = SyncProperty.ParseInt32(buff)
            if success:
                return True, "Int32", data
        elif buff[0] == SyncProperty.TYPE_BYTE:
            success, data = SyncProperty.ParseBytes(buff)
            if success:
                return True, "Byte", data
        elif buff[0] == SyncProperty.TYPE_INT64:
            success, data = SyncProperty.ParseInt32(buff)
            if success:
                return True, "Int64", data
        elif buff[0] == SyncProperty.TYPE_FLOAT:
            # 尚未实现
            pass
        elif buff[0] == SyncProperty.TYPE_BOOL:
            # 尚未实现
            pass
        else:
            pass
        return False, "Invalid", {}
