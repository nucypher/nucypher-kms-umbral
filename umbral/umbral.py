from cryptography.hazmat.primitives.asymmetric import ec

from umbral.bignum import BigNum
from umbral.point import Point
from umbral.utils import poly_eval, lambda_coeff, hash_to_bn, kdf


class UmbralParameters(object):
    def __init__(self):
        self.curve = ec.SECP256K1()
        self.g = Point.get_generator_from_curve(self.curve)
        self.order = Point.get_order_from_curve(self.curve)
        self.h = Point.gen_rand(self.curve)
        self.u = Point.gen_rand(self.curve)


class KFrag(object):
    def __init__(self, id_, key, x, u1, z1, z2):
        self.bn_id = id_
        self.bn_key = key
        self.point_eph_ni = x
        self.point_commitment = u1
        self.bn_sig1 = z1
        self.bn_sig2 = z2

    @staticmethod
    def from_bytes(data: bytes, curve: ec.EllipticCurve):
        """
        Instantiate a KFrag object from the serialized data.
        """
        id = BigNum.from_bytes(data[0:32], curve)
        key = BigNum.from_bytes(data[32:64], curve)
        eph_ni = Point.from_bytes(data[64:97], curve)
        commitment = Point.from_bytes(data[97:130], curve)
        sig1 = BigNum.from_bytes(data[130:162], curve)
        sig2 = BigNum.from_bytes(data[162:194], curve)

        return KFrag(id, key, eph_ni, commitment, sig1, sig2)

    def to_bytes(self):
        """
        Serialize the KFrag into a bytestring.
        """
        id = self.bn_id.to_bytes()
        key = self.bn_key.to_bytes()
        eph_ni = self.point_eph_ni.to_bytes()
        commitment = self.point_commitment.to_bytes()
        sig1 = self.bn_sig1.to_bytes()
        sig2 = self.bn_sig2.to_bytes()

        return id + key + eph_ni + commitment + sig1 + sig2

    def verify(self, pub_a, pub_b, params: UmbralParameters):

        u1 = self.point_commitment
        z1 = self.bn_sig1
        z2 = self.bn_sig2
        x = self.point_eph_ni

        g_y = (params.g * z2) + (pub_a * z1)

        return z1 == hash_to_bn([g_y, self.bn_id, pub_a, pub_b, u1, x], params)

    def is_consistent(self, vKeys, params: UmbralParameters):
        if vKeys is None or len(vKeys) == 0:
            raise ValueError('vKeys must not be empty')

        # TODO: change this!
        h = params.h
        lh_exp = h * self.bn_key

        rh_exp = vKeys[0]
        i_j = self.bn_id
        for vKey in vKeys[1:]:
            rh_exp = rh_exp + (vKey * i_j)
            i_j = i_j * self.bn_id

        return lh_exp == rh_exp

    def __bytes__(self):
        return self.to_bytes()


class CapsuleFrag(object):
    def __init__(self, e1, v1, id_, x):
        self.point_eph_e1 = e1
        self.point_eph_v1 = v1
        self.bn_kfrag_id = id_
        self.point_eph_ni = x

    @staticmethod
    def from_bytes(data: bytes, curve: ec.EllipticCurve):
        """
        Instantiates a CapsuleFrag object from the serialized data.
        """
        e1 = Point.from_bytes(data[0:33], curve)
        v1 = Point.from_bytes(data[33:66], curve)
        kfrag_id = BigNum.from_bytes(data[66:98], curve)
        eph_ni = Point.from_bytes(data[98:131], curve)

        return CapsuleFrag(e1, v1, kfrag_id, eph_ni)

    def to_bytes(self):
        """
        Serialize the CapsuleFrag into a bytestring.
        """
        e1 = self.point_eph_e1.to_bytes()
        v1 = self.point_eph_v1.to_bytes()
        kfrag_id = self.bn_kfrag_id.to_bytes()
        eph_ni = self.point_eph_ni.to_bytes()

        return e1 + v1 + kfrag_id + eph_ni

    def __bytes__(self):
        return self.to_bytes()


class Capsule(object):
    def __init__(self,
                 point_eph_e=None,
                 point_eph_v=None,
                 bn_sig=None,
                 e_prime=None,
                 v_prime=None,
                 noninteractive_point=None):

        if not point_eph_e and not e_prime:
            raise ValueError(
                "Can't make a Capsule from nothing.  Pass either Alice's data (ie, point_eph_e) or Bob's (e_prime). \
                Passing both is also fine.")

        self._point_eph_e = point_eph_e
        self._point_eph_v = point_eph_v
        self._bn_sig = bn_sig

        self._point_eph_e_prime = e_prime
        self._point_eph_v_prime = v_prime
        self._point_noninteractive = noninteractive_point

        self.cfrags = {}
        self._contents = None

    @classmethod
    def from_original_bytes(cls, data: bytes, curve: ec.EllipticCurve):
        """
        Instantiates a Capsule object from the serialized data.
        """
        eph_e = Point.from_bytes(data[0:33], curve)
        eph_v = Point.from_bytes(data[33:66], curve)
        sig = BigNum.from_bytes(data[66:98], curve)

        return cls(eph_e, eph_v, sig)

    @classmethod
    def from_reconstructed_bytes(cls, data: bytes, curve: ec.EllipticCurve):
        """
        Instantiate a Capsule from serialized data after reconstruction has occurred.

        The most obvious use case is Bob affixing at least m cFrags and then serializing the Capsule.
        """
        # TODO: Seems like a job for BytestringSplitter ?
        e_prime = Point.from_bytes(data[0:33], curve)
        v_prime = Point.from_bytes(data[33:66], curve)
        eph_ni = Point.from_bytes(data[66:99], curve)

        return cls(e_prime=e_prime, v_prime=v_prime, noninteractive_point=eph_ni)

    @property
    def contents(self):
        return self._contents

    def to_bytes(self):
        """
        Serialize the Capsule into a bytestring.
        """
        eph_e = self._point_eph_e.to_bytes()
        eph_v = self._point_eph_v.to_bytes()
        sig = self._bn_sig.to_bytes()

        return eph_e + eph_v + sig

    def verify(self, params: UmbralParameters):

        e = self._point_eph_e
        v = self._point_eph_v
        s = self._bn_sig
        h = hash_to_bn([e, v], params)

        return params.g * s == v + (e * h)

    def attach_cfrag(self, cfrag: CapsuleFrag):
        self.cfrags[cfrag.bn_kfrag_id] = cfrag

    def original_ephemeral_points(self):
        return self._point_eph_e + self._point_eph_v

    def reconstructed_ephemeral_points(self):
        return self._point_eph_e_prime + self._point_eph_v_prime

    def open(self, pub_bob, priv_bob, pub_alice, force_reopen=False, pre=None):
        # TODO: Raise an error here if Bob has gathered enough cFrags.
        if self.contents and not force_reopen:
            newly_opened = True
        else:
            self._reconstruct(pre=pre)
            if not pre:
                pre = PRE(UmbralParameters())
            self._contents = pre._decapsulate_reencrypted(pub_bob, priv_bob, pub_alice, self)
            newly_opened = False
        return self.contents, newly_opened

    def original_components(self):
        return self._point_eph_e, self._point_eph_v, self._bn_sig

    def _reconstruct(self, pre):
        id_cfrag_pairs = list(self.cfrags.items())
        id_0, cfrag_0 = id_cfrag_pairs[0]
        if len(id_cfrag_pairs) > 1:
            ids = self.cfrags.keys()
            lambda_0 = lambda_coeff(id_0, ids)
            e = cfrag_0.point_eph_e1 * lambda_0
            v = cfrag_0.point_eph_v1 * lambda_0

            for id_i, cfrag in id_cfrag_pairs[1:]:
                lambda_i = lambda_coeff(id_i, ids)
                e = e + (cfrag.point_eph_e1 * lambda_i)
                v = v + (cfrag.point_eph_v1 * lambda_i)
        else:
            e = cfrag_0.point_eph_e1
            v = cfrag_0.point_eph_v1

        self._point_eph_e_prime = e
        self._point_eph_v_prime = v
        self._point_noninteractive = cfrag_0.point_eph_ni

    def _reconstructed_bytes(self):
        """
        Serialize the reconstruction components into a bytestring.
        """
        eph_e = self._point_eph_e_prime
        eph_v = self._point_eph_v_prime
        point_noninter = self._point_noninteractive

        return eph_e.to_bytes() + eph_v.to_bytes() + point_noninter.to_bytes()

    def __bytes__(self):
        self.to_bytes()


class ChallengeResponse(object):
    def __init__(self, e2, v2, u1, u2, z1, z2, z3):
        self.point_eph_e2 = e2
        self.point_eph_v2 = v2
        self.point_kfrag_commitment = u1
        self.point_kfrag_pok = u2
        self.bn_kfrag_sig1 = z1
        self.bn_kfrag_sig2 = z2
        self.bn_sig = z3

    @staticmethod
    def from_bytes(data: bytes, curve: ec.EllipticCurve):
        """
        Instantiate ChallengeResponse from serialized data.
        """
        e2 = Point.from_bytes(data[0:33], curve)
        v2 = Point.from_bytes(data[33:66], curve)
        kfrag_commitment = Point.from_bytes(data[66:99], curve)
        kfrag_pok = Point.from_bytes(data[99:132], curve)
        kfrag_sig1 = BigNum.from_bytes(data[132:164], curve)
        kfrag_sig2 = BigNum.from_bytes(data[164:196], curve)
        sig = BigNum.from_bytes(data[196:228], curve)

        return ChallengeResponse(e2, v2, kfrag_commitment, kfrag_pok,
                                 kfrag_sig1, kfrag_sig2, sig)

    def to_bytes(self):
        """
        Serialize the ChallengeResponse to a bytestring.
        """
        e2 = self.point_eph_e2.to_bytes()
        v2 = self.point_eph_v2.to_bytes()
        kfrag_commitment = self.point_kfrag_commitment.to_bytes()
        kfrag_pok = self.point_kfrag_pok.to_bytes()
        kfrag_sig1 = self.bn_kfrag_sig1.to_bytes()
        kfrag_sig2 = self.bn_kfrag_sig2.to_bytes()
        sig = self.bn_sig.to_bytes()

        return (e2 + v2 + kfrag_commitment + kfrag_pok + kfrag_sig1
                + kfrag_sig2 + sig)

    def __bytes__(self):
        return self.to_bytes()


class PRE(object):
    def __init__(self, params: UmbralParameters):
        self.params = params

    def gen_priv(self):
        return BigNum.gen_rand(self.params.curve)

    def priv2pub(self, priv):
        g = self.params.g
        return g * priv

    def split_rekey(self, priv_a, pub_b, threshold, N):
        g = self.params.g

        pub_a = g * priv_a

        x = BigNum.gen_rand(self.params.curve)
        xcomp = g * x
        d = hash_to_bn([xcomp, pub_b, pub_b * x], self.params)

        coeffs = [priv_a * (~d)]
        coeffs += [BigNum.gen_rand(self.params.curve) for _ in range(threshold - 1)]

        h = self.params.h
        u = self.params.u

        vKeys = [h * coeff for coeff in coeffs]

        rk_shares = []
        for _ in range(N):
            id_kfrag = BigNum.gen_rand(self.params.curve)
            rk = poly_eval(coeffs, id_kfrag)

            u1 = u * rk
            y = BigNum.gen_rand(self.params.curve)

            z1 = hash_to_bn([g * y, id_kfrag, pub_a, pub_b, u1, xcomp], self.params)
            z2 = y - priv_a * z1

            kFrag = KFrag(id_=id_kfrag, key=rk, x=xcomp, u1=u1, z1=z1, z2=z2)
            rk_shares.append(kFrag)

        return rk_shares, vKeys

    def reencrypt(self, kFrag, capsule):
        # TODO: Put the assert at the end, but exponentiate by a randon number when false?
        assert capsule.verify(self.params), "Generic Umbral Error"

        e1 = capsule._point_eph_e * kFrag.bn_key
        v1 = capsule._point_eph_v * kFrag.bn_key

        cFrag = CapsuleFrag(e1=e1, v1=v1, id_=kFrag.bn_id, x=kFrag.point_eph_ni)
        return cFrag

    def challenge(self, rk, capsule, cFrag):
        e1 = cFrag.point_eph_e1
        v1 = cFrag.point_eph_v1

        e = capsule._point_eph_e
        v = capsule._point_eph_v

        u = self.params.u
        u1 = rk.point_commitment

        t = BigNum.gen_rand(self.params.curve)
        e2 = e * t
        v2 = v * t
        u2 = u * t

        h = hash_to_bn([e, e1, e2, v, v1, v2, u, u1, u2], self.params)

        z3 = t + h * rk.bn_key

        ch_resp = ChallengeResponse(e2=e2, v2=v2, u1=u1, u2=u2, z1=rk.bn_sig1, z2=rk.bn_sig2, z3=z3)

        # Check correctness of original ciphertext (check nº 2) at the end 
        # to avoid timing oracles
        assert capsule.verify(self.params), "Generic Umbral Error"
        return ch_resp

    def check_challenge(self, capsule, cFrag, challenge_resp, pub_a, pub_b):
        e = capsule._point_eph_e
        v = capsule._point_eph_v

        e1 = cFrag.point_eph_e1
        v1 = cFrag.point_eph_v1
        xcomp = cFrag.point_eph_ni
        kfrag_id = cFrag.bn_kfrag_id

        e2 = challenge_resp.point_eph_e2
        v2 = challenge_resp.point_eph_v2

        g = self.params.g

        u = self.params.u
        u1 = challenge_resp.point_kfrag_commitment
        u2 = challenge_resp.point_kfrag_pok

        z1 = challenge_resp.bn_kfrag_sig1
        z2 = challenge_resp.bn_kfrag_sig2
        z3 = challenge_resp.bn_sig

        g_y = (g * z2) + (pub_a * z1)

        h = hash_to_bn([e, e1, e2, v, v1, v2, u, u1, u2], self.params)

        check31 = z1 == hash_to_bn([g_y, kfrag_id, pub_a, pub_b, u1, xcomp], self.params)
        check32 = e * z3 == e2 + (e1 * h)
        check33 = u * z3 == u2 + (u1 * h)

        return check31 & check32 & check33

    def encapsulate(self, pub_key, key_length=32):
        """Generates a symmetric key and its associated KEM ciphertext"""
        g = self.params.g

        priv_r = BigNum.gen_rand(self.params.curve)
        pub_r = g * priv_r

        priv_u = BigNum.gen_rand(self.params.curve)
        pub_u = g * priv_u

        h = hash_to_bn([pub_r, pub_u], self.params)
        s = priv_u + (priv_r * h)

        shared_key = pub_key * (priv_r + priv_u)

        # Key to be used for symmetric encryption
        key = kdf(shared_key, key_length)

        return key, Capsule(point_eph_e=pub_r, point_eph_v=pub_u, bn_sig=s)

    def decapsulate_original(self, priv_key, capsule, key_length=32):
        """Derive the same symmetric key"""

        shared_key = capsule.original_ephemeral_points() * priv_key
        key = kdf(shared_key, key_length)

        # Check correctness of original ciphertext (check nº 2) at the end 
        # to avoid timing oracles
        assert capsule.verify(self.params), "Generic Umbral Error"
        return key

    def _decapsulate_reencrypted(self, pub_key: Point, priv_key: BigNum, orig_pub_key: Point,
                                 capsule: Capsule, key_length=32):
        """Derive the same symmetric key"""

        xcomp = capsule._point_noninteractive

        d = hash_to_bn([xcomp, pub_key, xcomp * priv_key], self.params)
        shared_key = capsule.reconstructed_ephemeral_points() * d
        key_bytes = kdf(shared_key, key_length)

        if capsule._point_eph_e:
            # TODO: So, here, we have Alice's data too.  What's actually going on here?
            e = capsule._point_eph_e
            v = capsule._point_eph_v
            s = capsule._bn_sig
            h = hash_to_bn([e, v], self.params)
            inv_d = ~d
            assert orig_pub_key * (s * inv_d) == capsule._point_eph_v_prime + (
                capsule._point_eph_e_prime * h), "Generic Umbral Error"

        return key_bytes
