from abc import abstractmethod, ABC
from typing import Tuple, Type, List, Any, TypeVar


class HasSerializedSize(ABC):
    """
    A base serialization mixin, denoting a type with a constant-size serialized representation.
    """

    @classmethod
    @abstractmethod
    def serialized_size(cls) -> int:
        """
        Returns the size in bytes of the serialized representation of this object
        (obtained with ``bytes()`` or ``to_secret_bytes()``).
        """
        raise NotImplementedError


class Deserializable(HasSerializedSize):
    """
    A mixin for composable deserialization.
    """

    Self = TypeVar('Self', bound='Deserializable')

    @classmethod
    def from_bytes(cls: Type[Self], data: bytes) -> Self:
        """
        Restores the object from serialized bytes.
        """
        expected_size = cls.serialized_size()
        if len(data) != expected_size:
            raise ValueError(f"Expected {expected_size} bytes, got {len(data)}")
        return cls._from_exact_bytes(data)

    @staticmethod
    def _split(data: bytes, *types: Type) -> List[Any]:
        """
        Given a list of ``Deserializable`` types, attempts to deserialize them from the bytestring
        one by one and returns the list of the resulting objects and the remaining bytestring.
        """
        objs = []
        pos = 0

        for tp in types:

            if issubclass(tp, bool):
                size = bool_serialized_size()
            else:
                size = tp.serialized_size()

            chunk = data[pos:pos+size]

            if issubclass(tp, bool):
                obj = bool_from_exact_bytes(chunk)
            else:
                obj = tp._from_exact_bytes(chunk)

            objs.append(obj)
            pos += size

        return objs

    @classmethod
    @abstractmethod
    def _from_exact_bytes(cls: Type[Self], data: bytes) -> Self:
        """
        Deserializes the object from a bytestring of exactly the expected length
        (defined by ``serialized_size()``).
        """
        raise NotImplementedError


class Serializable(HasSerializedSize):
    """
    A mixin for composable serialization.
    """

    @abstractmethod
    def __bytes__(self):
        """
        Serializes the object into bytes.
        """
        raise NotImplementedError


class SerializableSecret(HasSerializedSize):
    """
    A mixin for composable serialization of objects containing secret data.
    """

    @abstractmethod
    def to_secret_bytes(self):
        """
        Serializes the object into bytes.
        This bytestring is secret, handle with care!
        """
        raise NotImplementedError


def bool_serialized_size() -> int:
    return 1


def bool_bytes(b: bool) -> bytes:
    return b'\x01' if b else b'\x00'


def bool_from_exact_bytes(data: bytes) -> bool:
    if data == b'\x01':
        b = True
    elif data == b'\x00':
        b = False
    else:
        raise ValueError("Incorrectly serialized boolean; "
                         f"expected b'\\x00' or b'\\x01', got {repr(data)}")
    return b
