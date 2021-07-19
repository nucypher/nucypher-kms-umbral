Public API
==========

.. automodule:: umbral

Keys
----

.. autoclass:: SecretKey()
    :members:
    :show-inheritance:

.. autoclass:: PublicKey()
    :members:
    :special-members: __eq__, __hash__
    :show-inheritance:

.. autoclass:: SecretKeyFactory()
    :members:
    :show-inheritance:

.. autoclass:: Signer
    :members:

.. autoclass:: Signature()
    :members:
    :special-members: __eq__, __hash__
    :show-inheritance:

Intermediate objects
--------------------

.. autoclass:: Capsule()
    :special-members: __eq__, __hash__
    :show-inheritance:

.. autoclass:: KeyFrag()
    :members: verify
    :special-members: __eq__, __hash__
    :show-inheritance:

.. autoclass:: VerifiedKeyFrag()
    :members:
    :special-members: __eq__, __hash__
    :show-inheritance:

.. autoclass:: CapsuleFrag()
    :members:
    :special-members: __eq__, __hash__
    :show-inheritance:

.. autoclass:: VerifiedCapsuleFrag()
    :members:
    :special-members: __eq__, __hash__
    :show-inheritance:

Encryption, re-encryption and decryption
----------------------------------------

.. autofunction:: encrypt

.. autofunction:: decrypt_original

.. autofunction:: generate_kfrags

.. autofunction:: reencrypt

.. autofunction:: decrypt_reencrypted

Utilities
---------

.. autoclass:: umbral.VerificationError
    :show-inheritance:

.. autoclass:: umbral.serializable.HasSerializedSize
    :members:

.. autoclass:: umbral.serializable.Serializable
    :special-members: __bytes__
    :show-inheritance:

.. autoclass:: umbral.serializable.SerializableSecret
    :members:
    :show-inheritance:

.. autoclass:: umbral.serializable.Deserializable
    :members:
    :show-inheritance:
