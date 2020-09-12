"""
This file is part of pyUmbral.

pyUmbral is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

pyUmbral is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with pyUmbral. If not, see <https://www.gnu.org/licenses/>.
"""

import pytest

from umbral import pre
from umbral.curvebn import CurveBN
from umbral.point import Point
from umbral.pre import Capsule
from umbral.signing import Signer
from umbral.keys import UmbralPrivateKey
from umbral.config import default_params


def test_capsule_creation(alices_keys):

    params = default_params()

    with pytest.raises(TypeError):
        rare_capsule = Capsule(params)  # Alice cannot make a capsule this way.

    # Typical Alice, constructing a typical capsule
    delegating_privkey, _signing_key = alices_keys
    plaintext = b'peace at dawn'
    ciphertext, typical_capsule = pre.encrypt(delegating_privkey.get_pubkey(), plaintext)

    assert isinstance(typical_capsule, Capsule)

    # Some users may create capsules their own way.
    # Using the data from the previously created capsule to make sure it will pass verification.
    custom_capsule = Capsule(params,
                             point_e=typical_capsule.point_e,
                             point_v=typical_capsule.point_v,
                             bn_sig=typical_capsule.bn_sig)

    assert isinstance(custom_capsule, Capsule)


def test_capsule_equality(alices_keys):
    params = default_params()
    delegating_privkey, _signing_key = alices_keys
    plaintext = b'peace at dawn'
    _ciphertext, typical_capsule = pre.encrypt(delegating_privkey.get_pubkey(), plaintext)

    one_capsule = Capsule(params,
                          point_e=typical_capsule.point_e,
                          point_v=typical_capsule.point_v,
                          bn_sig=typical_capsule.bn_sig)

    same_capsule = Capsule(params,
                          point_e=typical_capsule.point_e,
                          point_v=typical_capsule.point_v,
                          bn_sig=typical_capsule.bn_sig)

    assert one_capsule == same_capsule

    # Capsule creation involves RNG, so it will have different components
    _ciphertext, another_typical_capsule = pre.encrypt(delegating_privkey.get_pubkey(), plaintext)

    another_capsule = Capsule(params,
                              point_e=another_typical_capsule.point_e,
                              point_v=another_typical_capsule.point_v,
                              bn_sig=another_typical_capsule.bn_sig)

    assert one_capsule != another_capsule


def test_decapsulation_by_alice(alices_keys):
    params = default_params()

    delegating_privkey, _signing_privkey = alices_keys

    sym_key, capsule = pre._encapsulate(delegating_privkey.get_pubkey())
    assert len(sym_key) == 32

    # The symmetric key sym_key is perhaps used for block cipher here in a real-world scenario.
    sym_key_2 = pre._decapsulate_original(delegating_privkey, capsule)
    assert sym_key_2 == sym_key


def test_bad_capsule_cannot_be_created():
    params = default_params()

    with pytest.raises(Capsule.NotValid, match="Capsule verification failed."):
        bollocks_capsule = Capsule(params,
                                   point_e=Point.gen_rand(),
                                   point_v=Point.gen_rand(),
                                   bn_sig=CurveBN.gen_rand())


def test_capsule_as_dict_key(alices_keys, bobs_keys):
    delegating_privkey, signing_privkey = alices_keys
    signer_alice = Signer(signing_privkey)
    delegating_pubkey = delegating_privkey.get_pubkey()
    signing_pubkey = signing_privkey.get_pubkey()

    receiving_privkey, receiving_pubkey = bobs_keys

    plain_data = b'peace at dawn'
    ciphertext, capsule = pre.encrypt(delegating_pubkey, plain_data)

    # We can use the capsule as a key, and successfully lookup using it.
    some_dict = {capsule: "Thing that Bob wants to try per-Capsule"}
    assert some_dict[capsule] == "Thing that Bob wants to try per-Capsule"

    # And if we change the value for this key, all is still well.
    some_dict[capsule] = "Bob has changed his mind."
    assert some_dict[capsule] == "Bob has changed his mind."
    assert len(some_dict.keys()) == 1
