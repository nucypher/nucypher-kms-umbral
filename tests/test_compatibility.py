import pytest

try:
    import umbral_pre as umbral_rs
except ImportError:
    umbral_rs = None

import umbral as umbral_py


def pytest_generate_tests(metafunc):
    if 'implementations' in metafunc.fixturenames:
        implementations = [(umbral_py, umbral_py)]
        ids = ['python -> python']
        if umbral_rs is not None:
            implementations.extend([(umbral_py, umbral_rs), (umbral_rs, umbral_py)])
            ids.extend(['python -> rust', 'rust -> python'])

        metafunc.parametrize('implementations', implementations, ids=ids)


def _create_keypair(umbral):
    sk = umbral.SecretKey.random()
    pk = sk.public_key()
    return sk.to_secret_bytes(), bytes(pk)


def _restore_keys(umbral, sk_bytes, pk_bytes):
    sk = umbral.SecretKey.from_bytes(sk_bytes)
    pk_from_sk = sk.public_key()
    pk_from_bytes = umbral.PublicKey.from_bytes(pk_bytes)
    assert pk_from_sk == pk_from_bytes


def test_keys(implementations):
    umbral1, umbral2 = implementations

    # On client 1
    sk_bytes, pk_bytes = _create_keypair(umbral1)

    # On client 2
    _restore_keys(umbral2, sk_bytes, pk_bytes)


def _create_sk_factory_and_sk(umbral, skf_label, key_label):
    skf = umbral.SecretKeyFactory.random()
    derived_skf = skf.secret_key_factory_by_label(skf_label)
    sk = derived_skf.secret_key_by_label(key_label)
    return skf.to_secret_bytes(), derived_skf.to_secret_bytes(), sk.to_secret_bytes()


def _check_sk_is_same(umbral, skf_label, key_label, skf_bytes, derived_skf_bytes, sk_bytes):
    skf = umbral.SecretKeyFactory.from_bytes(skf_bytes)

    derived_skf_restored = umbral.SecretKeyFactory.from_bytes(derived_skf_bytes)
    derived_skf_generated = skf.secret_key_factory_by_label(skf_label)
    assert derived_skf_generated.to_secret_bytes() == derived_skf_restored.to_secret_bytes()

    sk_restored = umbral.SecretKey.from_bytes(sk_bytes)
    sk_generated = derived_skf_generated.secret_key_by_label(key_label)
    assert sk_restored.to_secret_bytes() == sk_generated.to_secret_bytes()


def test_secret_key_factory(implementations):
    umbral1, umbral2 = implementations
    skf_label = b'skf label'
    key_label = b'key label'

    skf_bytes, derived_skf_bytes, sk_bytes = _create_sk_factory_and_sk(umbral1, skf_label, key_label)
    _check_sk_is_same(umbral2, skf_label, key_label, skf_bytes, derived_skf_bytes, sk_bytes)


def _encrypt(umbral, plaintext, pk_bytes):
    pk = umbral.PublicKey.from_bytes(pk_bytes)
    capsule, ciphertext = umbral.encrypt(pk, plaintext)
    return bytes(capsule), ciphertext


def _decrypt_original(umbral, sk_bytes, capsule_bytes, ciphertext):
    capsule = umbral.Capsule.from_bytes(bytes(capsule_bytes))
    sk = umbral.SecretKey.from_bytes(sk_bytes)
    return umbral.decrypt_original(sk, capsule, ciphertext)


def test_encrypt_decrypt(implementations):

    umbral1, umbral2 = implementations
    plaintext = b'peace at dawn'

    # On client 1
    sk_bytes, pk_bytes = _create_keypair(umbral1)

    # On client 2
    capsule_bytes, ciphertext = _encrypt(umbral2, plaintext, pk_bytes)

    # On client 1
    plaintext_decrypted = _decrypt_original(umbral1, sk_bytes, capsule_bytes, ciphertext)

    assert plaintext_decrypted == plaintext


def _generate_kfrags(umbral, delegating_sk_bytes, receiving_pk_bytes,
                     signing_sk_bytes, threshold, num_kfrags):

    delegating_sk = umbral.SecretKey.from_bytes(delegating_sk_bytes)
    receiving_pk = umbral.PublicKey.from_bytes(receiving_pk_bytes)
    signing_sk = umbral.SecretKey.from_bytes(signing_sk_bytes)

    kfrags = umbral.generate_kfrags(delegating_sk=delegating_sk,
                                    receiving_pk=receiving_pk,
                                    signer=umbral.Signer(signing_sk),
                                    threshold=threshold,
                                    num_kfrags=num_kfrags,
                                    sign_delegating_key=True,
                                    sign_receiving_key=True,
                                    )

    return [bytes(kfrag) for kfrag in kfrags]


def _verify_kfrags(umbral, kfrags_bytes, verifying_pk_bytes, delegating_pk_bytes, receiving_pk_bytes):
    kfrags = [umbral.KeyFrag.from_bytes(kfrag_bytes) for kfrag_bytes in kfrags_bytes]
    verifying_pk = umbral.PublicKey.from_bytes(verifying_pk_bytes)
    delegating_pk = umbral.PublicKey.from_bytes(delegating_pk_bytes)
    receiving_pk = umbral.PublicKey.from_bytes(receiving_pk_bytes)
    return [kfrag.verify(verifying_pk=verifying_pk,
                         delegating_pk=delegating_pk,
                         receiving_pk=receiving_pk) for kfrag in kfrags]


def test_kfrags(implementations):

    umbral1, umbral2 = implementations

    threshold = 2
    num_kfrags = 3
    plaintext = b'peace at dawn'

    # On client 1

    receiving_sk_bytes, receiving_pk_bytes = _create_keypair(umbral1)
    delegating_sk_bytes, delegating_pk_bytes = _create_keypair(umbral1)
    signing_sk_bytes, verifying_pk_bytes = _create_keypair(umbral1)
    kfrags_bytes = _generate_kfrags(umbral1, delegating_sk_bytes, receiving_pk_bytes,
                                    signing_sk_bytes, threshold, num_kfrags)

    # On client 2

    _verify_kfrags(umbral2, kfrags_bytes, verifying_pk_bytes, delegating_pk_bytes, receiving_pk_bytes)


def _reencrypt(umbral, verifying_pk_bytes, delegating_pk_bytes, receiving_pk_bytes,
               capsule_bytes, kfrags_bytes, threshold):
    capsule = umbral.Capsule.from_bytes(bytes(capsule_bytes))
    verified_kfrags = _verify_kfrags(umbral, kfrags_bytes,
                                     verifying_pk_bytes, delegating_pk_bytes, receiving_pk_bytes)
    cfrags = [umbral.reencrypt(capsule, kfrag) for kfrag in verified_kfrags[:threshold]]
    return [bytes(cfrag) for cfrag in cfrags]


def _decrypt_reencrypted(umbral, receiving_sk_bytes, delegating_pk_bytes, verifying_pk_bytes,
                         capsule_bytes, cfrags_bytes, ciphertext):

    receiving_sk = umbral.SecretKey.from_bytes(receiving_sk_bytes)
    receiving_pk = receiving_sk.public_key()
    delegating_pk = umbral.PublicKey.from_bytes(delegating_pk_bytes)
    verifying_pk = umbral.PublicKey.from_bytes(verifying_pk_bytes)

    capsule = umbral.Capsule.from_bytes(bytes(capsule_bytes))
    cfrags = [umbral.CapsuleFrag.from_bytes(cfrag_bytes) for cfrag_bytes in cfrags_bytes]

    verified_cfrags = [cfrag.verify(capsule,
                                    verifying_pk=verifying_pk,
                                    delegating_pk=delegating_pk,
                                    receiving_pk=receiving_pk,
                                    )
                       for cfrag in cfrags]

    # Decryption by Bob
    plaintext = umbral.decrypt_reencrypted(receiving_sk=receiving_sk,
                                           delegating_pk=delegating_pk,
                                           capsule=capsule,
                                           verified_cfrags=verified_cfrags,
                                           ciphertext=ciphertext,
                                           )

    return plaintext


def test_reencrypt(implementations):

    umbral1, umbral2 = implementations

    threshold = 2
    num_kfrags = 3
    plaintext = b'peace at dawn'

    # On client 1

    receiving_sk_bytes, receiving_pk_bytes = _create_keypair(umbral1)
    delegating_sk_bytes, delegating_pk_bytes = _create_keypair(umbral1)
    signing_sk_bytes, verifying_pk_bytes = _create_keypair(umbral1)

    capsule_bytes, ciphertext = _encrypt(umbral1, plaintext, delegating_pk_bytes)

    kfrags_bytes = _generate_kfrags(umbral1, delegating_sk_bytes, receiving_pk_bytes,
                                    signing_sk_bytes, threshold, num_kfrags)

    # On client 2

    cfrags_bytes = _reencrypt(umbral2, verifying_pk_bytes, delegating_pk_bytes, receiving_pk_bytes,
                              capsule_bytes, kfrags_bytes, threshold)

    # On client 1

    plaintext_reencrypted = _decrypt_reencrypted(umbral1,
                                                 receiving_sk_bytes, delegating_pk_bytes, verifying_pk_bytes,
                                                 capsule_bytes, cfrags_bytes, ciphertext)

    assert plaintext_reencrypted == plaintext


def _sign_message(umbral, sk_bytes, message):
    sk = umbral.SecretKey.from_bytes(sk_bytes)
    signer = umbral.Signer(sk)
    assert signer.verifying_key() == sk.public_key()
    return bytes(signer.sign(message))


def _verify_message(umbral, pk_bytes, signature_bytes, message):
    pk = umbral.PublicKey.from_bytes(pk_bytes)
    signature = umbral.Signature.from_bytes(signature_bytes)
    return signature.verify(pk, message)


def test_signer(implementations):

    umbral1, umbral2 = implementations

    message = b'peace at dawn'

    sk_bytes, pk_bytes = _create_keypair(umbral1)

    signature1_bytes = _sign_message(umbral1, sk_bytes, message)
    signature2_bytes = _sign_message(umbral2, sk_bytes, message)

    # Signatures are random, so we can't compare them.
    # Cross-verify instead

    assert _verify_message(umbral1, pk_bytes, signature2_bytes, message)
    assert _verify_message(umbral2, pk_bytes, signature1_bytes, message)


def _measure_sizes(umbral):

    sized_types = [
        umbral.SecretKey,
        umbral.SecretKeyFactory,
        umbral.PublicKey,
        umbral.Signature,
        umbral.Capsule,
        umbral.KeyFrag,
        umbral.VerifiedKeyFrag,
        umbral.CapsuleFrag,
        umbral.VerifiedCapsuleFrag,
        ]

    return {tp.__name__: tp.serialized_size() for tp in sized_types}


def test_serialization_size(implementations):

    umbral1, umbral2 = implementations

    sizes1 = _measure_sizes(umbral1)
    sizes2 = _measure_sizes(umbral1)

    assert sizes1 == sizes2
