import pytest

from umbral import encrypt, reencrypt, CapsuleFrag, VerifiedCapsuleFrag, Capsule, VerificationError
from umbral.curve_point import CurvePoint


def test_cfrag_serialization(verification_keys, capsule, kfrags):

    verifying_pk, delegating_pk, receiving_pk = verification_keys

    for kfrag in kfrags:
        cfrag = reencrypt(capsule, kfrag)
        cfrag_bytes = bytes(cfrag)

        new_cfrag = CapsuleFrag.from_bytes(cfrag_bytes)

        verified_cfrag = new_cfrag.verify(capsule,
                                          verifying_pk=verifying_pk,
                                          delegating_pk=delegating_pk,
                                          receiving_pk=receiving_pk,
                                          )
        assert verified_cfrag == cfrag

        # Wrong delegating key
        with pytest.raises(VerificationError):
            new_cfrag.verify(capsule,
                             verifying_pk=verifying_pk,
                             delegating_pk=receiving_pk,
                             receiving_pk=receiving_pk,
                             )

        # Wrong receiving key
        with pytest.raises(VerificationError):
            new_cfrag.verify(capsule,
                             verifying_pk=verifying_pk,
                             delegating_pk=delegating_pk,
                             receiving_pk=delegating_pk,
                             )

        # Wrong signing key
        with pytest.raises(VerificationError):
            new_cfrag.verify(capsule,
                             verifying_pk=receiving_pk,
                             delegating_pk=delegating_pk,
                             receiving_pk=receiving_pk,
                             )


def test_cfrag_with_wrong_capsule(verification_keys, kfrags, capsule_and_ciphertext, message):

    capsule, ciphertext = capsule_and_ciphertext
    verifying_pk, delegating_pk, receiving_pk = verification_keys

    capsule_alice1 = capsule
    capsule_alice2, _unused_key2 = Capsule.from_public_key(delegating_pk)

    cfrag = reencrypt(capsule_alice2, kfrags[0])
    cfrag = CapsuleFrag.from_bytes(bytes(cfrag)) # de-verify

    with pytest.raises(VerificationError):
        cfrag.verify(capsule_alice1,
                     verifying_pk=verifying_pk,
                     delegating_pk=delegating_pk,
                     receiving_pk=receiving_pk,
                     )


def test_cfrag_with_wrong_data(verification_keys, kfrags, capsule_and_ciphertext, message):

    capsule, ciphertext = capsule_and_ciphertext
    verifying_pk, delegating_pk, receiving_pk = verification_keys

    cfrag = reencrypt(capsule, kfrags[0])

    # Let's put random garbage in one of the cfrags
    cfrag = CapsuleFrag.from_bytes(bytes(cfrag)) # de-verify
    cfrag.point_e1 = CurvePoint.random()
    cfrag.point_v1 = CurvePoint.random()

    with pytest.raises(VerificationError):
        cfrag.verify(capsule,
                     verifying_pk=verifying_pk,
                     delegating_pk=delegating_pk,
                     receiving_pk=receiving_pk,
                     )


def test_cfrag_is_hashable(verification_keys, capsule, kfrags):

    verifying_pk, delegating_pk, receiving_pk = verification_keys

    cfrag0 = reencrypt(capsule, kfrags[0])
    cfrag1 = reencrypt(capsule, kfrags[1])

    assert hash(cfrag0) != hash(cfrag1)

    new_cfrag = CapsuleFrag.from_bytes(bytes(cfrag0))
    assert hash(new_cfrag) != hash(cfrag0)

    verified_cfrag = new_cfrag.verify(capsule,
                                      verifying_pk=verifying_pk,
                                      delegating_pk=delegating_pk,
                                      receiving_pk=receiving_pk,
                                      )

    assert hash(verified_cfrag) == hash(cfrag0)


def test_cfrag_str(capsule, kfrags):
    cfrag0 = reencrypt(capsule, kfrags[0])
    s = str(cfrag0)
    assert 'VerifiedCapsuleFrag' in s

    s = str(CapsuleFrag.from_bytes(bytes(cfrag0)))
    assert "VerifiedCapsuleFrag" not in s
    assert "CapsuleFrag" in s


def test_from_verified_bytes(capsule, kfrags):
    verified_cfrag = reencrypt(capsule, kfrags[0])
    cfrag_bytes = bytes(verified_cfrag)
    verified_cfrag_back = VerifiedCapsuleFrag.from_verified_bytes(cfrag_bytes)
    assert verified_cfrag == verified_cfrag_back


def test_serialized_size(capsule, kfrags):
    verified_cfrag = reencrypt(capsule, kfrags[0])
    cfrag = CapsuleFrag.from_bytes(bytes(verified_cfrag))
    assert verified_cfrag.serialized_size() == cfrag.serialized_size()
