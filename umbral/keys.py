import os
from typing import Tuple

from .curve_scalar import CurveScalar
from .curve_point import CurvePoint
from .dem import kdf
from .hashing import Hash
from .serializable import Serializable, SerializableSecret, Deserializable


class SecretKey(SerializableSecret, Deserializable):
    """
    Umbral secret (private) key.
    """

    def __init__(self, scalar_key: CurveScalar):
        self._scalar_key = scalar_key
        # Precached public key.
        # We are assuming here that there will be on average more
        # derivations of a public key from a secret key than secret key instantiations.
        self._public_key = PublicKey(CurvePoint.generator() * self._scalar_key)

    @classmethod
    def random(cls) -> 'SecretKey':
        """
        Generates a random secret key and returns it.
        """
        return cls(CurveScalar.random_nonzero())

    def public_key(self) -> 'PublicKey':
        """
        Returns the associated public key.
        """
        return self._public_key

    def __str__(self):
        return f"{self.__class__.__name__}:..."

    def __hash__(self):
        raise RuntimeError("Hashing secret objects is not secure")

    def secret_scalar(self) -> CurveScalar:
        return self._scalar_key

    @classmethod
    def serialized_size(cls):
        return CurveScalar.serialized_size()

    @classmethod
    def _from_exact_bytes(cls, data: bytes):
        return cls(CurveScalar._from_exact_bytes(data))

    def to_secret_bytes(self) -> bytes:
        return bytes(self._scalar_key)


class PublicKey(Serializable, Deserializable):
    """
    Umbral public key.

    Created using :py:meth:`SecretKey.public_key`.
    """

    def __init__(self, point_key: CurvePoint):
        self._point_key = point_key

    def point(self) -> CurvePoint:
        return self._point_key

    @classmethod
    def serialized_size(cls):
        return CurvePoint.serialized_size()

    @classmethod
    def _from_exact_bytes(cls, data: bytes):
        return cls(CurvePoint._from_exact_bytes(data))

    def __bytes__(self) -> bytes:
        return bytes(self._point_key)

    def __str__(self):
        return f"{self.__class__.__name__}:{bytes(self).hex()[:16]}"

    def __eq__(self, other):
        return self._point_key == other._point_key

    def __hash__(self) -> int:
        return hash((self.__class__, bytes(self)))


class SecretKeyFactory(SerializableSecret, Deserializable):
    """
    This class handles keyring material for Umbral, by allowing deterministic
    derivation of :py:class:`SecretKey` objects based on labels.

    Don't use this key material directly as a key.
    """

    _KEY_SEED_SIZE = 32
    _DERIVED_KEY_SIZE = 64

    def __init__(self, key_seed: bytes):
        self.__key_seed = key_seed

    @classmethod
    def random(cls) -> 'SecretKeyFactory':
        """
        Creates a random factory.
        """
        return cls(os.urandom(cls._KEY_SEED_SIZE))

    @classmethod
    def seed_size(cls):
        """
        Returns the seed size required by
        :py:meth:`~SecretKeyFactory.from_secure_randomness`.
        """
        return cls._KEY_SEED_SIZE

    @classmethod
    def from_secure_randomness(cls, seed: bytes) -> 'SecretKeyFactory':
        """
        Creates a secret key factory using the given random bytes
        (of size :py:meth:`~SecretKeyFactory.seed_size`).

        .. warning::

            Make sure the given seed has been obtained
            from a cryptographically secure source of randomness!
        """
        if len(seed) != cls.seed_size():
            raise ValueError(f"Expected {cls.seed_size()} bytes, got {len(seed)}")
        return cls(seed)

    def secret_key_by_label(self, label: bytes) -> SecretKey:
        """
        Creates a :py:class:`SecretKey` deterministically from the given label.
        """
        tag = b"KEY_DERIVATION/" + label
        key = kdf(self.__key_seed, self._DERIVED_KEY_SIZE, info=tag)

        digest = Hash(tag)
        digest.update(key)
        scalar_key = CurveScalar.from_digest(digest)

        return SecretKey(scalar_key)

    def secret_key_factory_by_label(self, label: bytes) -> 'SecretKeyFactory':
        """
        Creates a :py:class:`SecretKeyFactory` deterministically from the given label.
        """
        tag = b"FACTORY_DERIVATION/" + label
        key_seed = kdf(self.__key_seed, self._KEY_SEED_SIZE, info=tag)
        return SecretKeyFactory(key_seed)

    @classmethod
    def serialized_size(cls):
        return cls._KEY_SEED_SIZE

    @classmethod
    def _from_exact_bytes(cls, data: bytes):
        return cls(data)

    def to_secret_bytes(self) -> bytes:
        return bytes(self.__key_seed)

    def __str__(self):
        return f"{self.__class__.__name__}:..."

    def __hash__(self):
        raise RuntimeError("Hashing secret objects is not secure")
