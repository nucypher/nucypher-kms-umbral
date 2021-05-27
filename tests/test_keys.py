import os
import string

import pytest

from umbral.keys import PublicKey, SecretKey, SecretKeyFactory, Signature
from umbral.hashing import Hash


def test_gen_key():
    sk = SecretKey.random()
    assert type(sk) == SecretKey

    pk = PublicKey.from_secret_key(sk)
    assert type(pk) == PublicKey

    pk2 = PublicKey.from_secret_key(sk)
    assert pk == pk2


def test_derive_key_from_label():
    factory = SecretKeyFactory.random()

    label = b"my_healthcare_information"

    sk1 = factory.secret_key_by_label(label)
    assert type(sk1) == SecretKey

    pk1 = PublicKey.from_secret_key(sk1)
    assert type(pk1) == PublicKey

    # Check that key derivation is reproducible
    sk2 = factory.secret_key_by_label(label)
    pk2 = PublicKey.from_secret_key(sk2)
    assert sk1 == sk2
    assert pk1 == pk2

    # Different labels on the same master secret create different keys
    label = b"my_tax_information"
    sk3 = factory.secret_key_by_label(label)
    pk3 = PublicKey.from_secret_key(sk3)
    assert sk1 != sk3


def test_secret_key_serialization():
    sk = SecretKey.random()
    encoded_key = bytes(sk)
    decoded_key = SecretKey.from_bytes(encoded_key)
    assert sk == decoded_key


def test_secret_key_str():
    sk = SecretKey.random()
    s = str(sk)
    assert s == "SecretKey:..."


def test_secret_key_hash():
    sk = SecretKey.random()
    # Insecure Python hash, shouldn't be available.
    with pytest.raises(NotImplementedError):
        hash(sk)


def test_secret_key_factory_str():
    skf = SecretKeyFactory.random()
    s = str(skf)
    assert s == "SecretKeyFactory:..."


def test_secret_key_factory_hash():
    skf = SecretKeyFactory.random()
    # Insecure Python hash, shouldn't be available.
    with pytest.raises(NotImplementedError):
        hash(skf)


def test_public_key_serialization():
    sk = SecretKey.random()
    pk = PublicKey.from_secret_key(sk)

    encoded_key = bytes(pk)
    decoded_key = PublicKey.from_bytes(encoded_key)
    assert pk == decoded_key


def test_public_key_point():
    pk = PublicKey.from_secret_key(SecretKey.random())
    assert bytes(pk) == bytes(pk.point())


def test_public_key_str():
    pk = PublicKey.from_secret_key(SecretKey.random())
    s = str(pk)
    assert 'PublicKey' in s


def test_keying_material_serialization():
    factory = SecretKeyFactory.random()

    encoded_factory = bytes(factory)
    decoded_factory = SecretKeyFactory.from_bytes(encoded_factory)

    label = os.urandom(32)
    sk1 = factory.secret_key_by_label(label)
    sk2 = decoded_factory.secret_key_by_label(label)
    assert sk1 == sk2


def test_public_key_is_hashable():
    sk = SecretKey.random()
    pk = PublicKey.from_secret_key(sk)

    sk2 = SecretKey.random()
    pk2 = PublicKey.from_secret_key(sk2)
    assert hash(pk) != hash(pk2)

    pk3 = PublicKey.from_bytes(bytes(pk))
    assert hash(pk) == hash(pk3)


@pytest.mark.parametrize('execution_number', range(20))  # Run this test 20 times.
def test_sign_and_verify(execution_number):
    sk = SecretKey.random()
    pk = PublicKey.from_secret_key(sk)

    message = b"peace at dawn"
    dst = b"dst"

    digest = Hash(dst)
    digest.update(message)
    signature = sk.sign_digest(digest)

    digest = Hash(dst)
    digest.update(message)
    assert signature.verify_digest(pk, digest)


@pytest.mark.parametrize('execution_number', range(20))  # Run this test 20 times.
def test_sign_serialize_and_verify(execution_number):
    sk = SecretKey.random()
    pk = PublicKey.from_secret_key(sk)

    message = b"peace at dawn"
    dst = b"dst"

    digest = Hash(dst)
    digest.update(message)
    signature = sk.sign_digest(digest)

    signature_bytes = bytes(signature)
    signature_restored = Signature.from_bytes(signature_bytes)

    digest = Hash(dst)
    digest.update(message)
    assert signature_restored.verify_digest(pk, digest)


def test_verification_fail():
    sk = SecretKey.random()
    pk = PublicKey.from_secret_key(sk)

    message = b"peace at dawn"
    dst = b"dst"

    digest = Hash(dst)
    digest.update(message)
    signature = sk.sign_digest(digest)

    # wrong DST
    digest = Hash(b"other dst")
    digest.update(message)
    assert not signature.verify_digest(pk, digest)

    # wrong message
    digest = Hash(dst)
    digest.update(b"no peace at dawn")
    assert not signature.verify_digest(pk, digest)

    # bad signature
    signature_bytes = bytes(signature)
    signature_bytes = b'\x00' + signature_bytes[1:]
    signature_restored = Signature.from_bytes(signature_bytes)

    digest = Hash(dst)
    digest.update(message)
    assert not signature_restored.verify_digest(pk, digest)


def test_signature_repr():

    sk = SecretKey.random()
    pk = PublicKey.from_secret_key(sk)

    message = b"peace at dawn"
    dst = b"dst"

    digest = Hash(dst)
    digest.update(message)
    signature = sk.sign_digest(digest)

    s = repr(signature)
    assert 'Signature' in s
