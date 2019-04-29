#!/usr/bin/env python3

"""
gnuk-extractor: Extract PGP secret keys from Gnuk / Nitrokey Start firmwares
Copyright (C) 2019 rot42

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License version 3
as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import logging

from enum import Enum, IntEnum, auto
from binascii import hexlify, unhexlify
from struct import pack, unpack
from hashlib import sha256
from itertools import islice, cycle, permutations

from pgpy import PGPKey
from pgpy.packet import PrivKeyV4, PrivSubKeyV4
from pgpy.constants import PubKeyAlgorithm, EllipticCurveOID, SymmetricKeyAlgorithm, HashAlgorithm
from pgpy.packet.fields import RSAPriv, MPI, MPIs, ECDHPub, ECDHPriv, ECDSAPub, ECDSAPriv, OpaquePrivKey

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

__all__ = ['Firmware']

PAGE_SIZE    = 1024
AES_SIZE     = 16          # block size and key length (only AES-128 used)
CODE_SIZE    = 0x00019000  # approximate code size at the start of the firmware
BASE_ADDR    = 0x08000000  # address at which the flash program is mapped
DEFAULT_PW   = b'123456'

class DataObject(IntEnum):
    FP_SIG         = 0x01
    FP_DEC         = 0x02
    FP_AUT         = 0x03
    PRVKEY_SIG     = 0x0e
    PRVKEY_DEC     = 0x0f
    PRVKEY_AUT     = 0x10
    KEYSTRING_PW1  = 0x11
    ATTR_SIG       = 0xf1
    ATTR_DEC       = 0xf2
    ATTR_AUT       = 0xf3

class KeyAlgo(IntEnum):
    RSA4096    = 0
    NISTP256R1 = 1
    SECP256K1  = 2
    ED25519    = 3
    CURVE25519 = 4
    RSA2048    = 255

class KeyType(Enum):
    SIGN    = auto()
    ENCRYPT = auto()
    AUTH    = auto()


class PrivKey:
    """ Container for the different information of one subkey stored in firmware """

    # (private, public) key length in firmware for each supported algo
    _algo_len = {
        KeyAlgo.RSA2048    : (256, 256),
        KeyAlgo.RSA4096    : (512, 512),
        KeyAlgo.NISTP256R1 : (32, 64),
        KeyAlgo.SECP256K1  : (32, 64),
        KeyAlgo.ED25519    : (64, 32),
        KeyAlgo.CURVE25519 : (32, 32),
    }

    def __init__(self, typ, algo, data, dek, iv, cks):
        self.typ  = typ                       # KeyType
        self.algo = algo                      # KeyAlgo
        slen, plen = PrivKey._algo_len[algo]
        self.priv = data[:slen]               # encrypted private key part(s)
        self.pub  = data[slen:slen+plen]      # public key part(s)
        self.dek  = dek  # encrypted data encryption key encrypting self.priv
        self.iv   = iv   # IV used with above symmetric key
        self.cks  = cks  # encrypted checksum
        self.locked = True

    def _checksum(data):
        """ Compute key data checksum: openpgp-do.c compute_key_data_checksum """
        assert len(data) % 4 == 0
        cks = [0, 0, 0, 0]
        for i in range(len(data) // 4):
            cks[i&3] ^= unpack('<I', data[i*4:i*4+4])[0]
        return pack('<IIII', *cks)

    def _key_derive(uniqueid, password, salt):
        """ Derive key from password: openpgp.c s2k """
        return sha256(uniqueid + bytes(islice(cycle(salt + password), 192))).digest()

    def _decrypt_dek(self, key):
        """ Decrypt AES data encryption key with AES key encryption key: openpgp-do.c decrypt_dek """
        assert len(key) == AES_SIZE
        dec = Cipher(algorithms.AES(key), modes.ECB(), default_backend()).decryptor()
        return dec.update(self.dek) + dec.finalize()

    def _priv_decrypt(self, dek):
        """ Decrypt RSA private key and checksum with AES data encryption key: openpgp-do.c decrypt """
        assert len(dek) == AES_SIZE
        dec = Cipher(algorithms.AES(dek), modes.CFB(self.iv), default_backend()).decryptor()
        pt = dec.update(self.priv + self.cks) + dec.finalize()
        return pt[:len(self.priv)], pt[len(self.priv):]

    def decrypt(self, udid, password, salt=b''):
        """ Decrypt data encryption key, private key and checksum only if password is valid """
        assert self.locked
        kek = PrivKey._key_derive(udid, password, salt)[:AES_SIZE] # key encryption key
        dek = self._decrypt_dek(kek)                              # decrypt data encryption key
        privkey, cks = self._priv_decrypt(dek)                    # decrypt private key and checksum
        if PrivKey._checksum(privkey) == cks:
            self.priv = privkey
            self.dek  = dek
            self.cks  = cks
            self.locked = False
            return True
        return False


class Firmware:
    """ Container for the different keys and values extracted from a GNUK firmware """
    def __init__(self, filepath, udid):
        self._udid  = udid
        # read firmware content
        with open(filepath, 'rb') as f:
            self.data = f.read()

        # find key material and data objects addresses in code
        self._find_addresses()
        # extract raw key material and data objects
        rawkeys = self._extract_raw_keys()
        self._extract_do_table()
        if not self._do_table or not any(len(k) > 0 for k in rawkeys):
            raise Exception("No key in firmware image")
        self._build_keys(rawkeys)

        # extract password related fields
        self.locked = True
        if DataObject.KEYSTRING_PW1 in self._do_table:
            # password will need to be provided to the unlock method
            self._pwlen = self._do_table[DataObject.KEYSTRING_PW1][0]
            self._salt  = self._do_table[DataObject.KEYSTRING_PW1][1:]
        else:
            # firmware is using the default password, we can already unlock it
            self._salt  = b''
            self._pwlen = len(DEFAULT_PW)
            if not self.unlock(DEFAULT_PW):
                raise Exception("Firmware was compiled with a different default password")
            logging.info("Firmware unlocked with default password: {}".format(DEFAULT_PW))
            self.locked = False

    def _find_addresses(self):
        """ Find the addresses of the key material and data objects in the code """
        assert len(self.data) > CODE_SIZE
        start = BASE_ADDR + CODE_SIZE
        end   = BASE_ADDR + len(self.data)

        # find all possible candidate addresses
        addresses = set()
        for i in range(0, CODE_SIZE - 3):
            addr = unpack('<I', self.data[i:i+4])[0]
            if start <= addr < end and addr % PAGE_SIZE == 0:
                addresses.add(addr - BASE_ADDR)

        # find a pair of addresses separated by 3 pages:
        # - start of key material
        # - start of data objects
        for a1, a2 in permutations(addresses, 2):
            if a2 - a1 == 3 * PAGE_SIZE:
                self._km_addr = a1
                self._do_addr = a2
                return

        raise Exception("No valid addresses found in firmware")

    def _extract_raw_keys(self):
        """ Extract private keys' bytes from firmware: will be decoded later """
        CHUNK_SIZE = 64 # g.c.d. of key storage sizes: openpgp-do.c gpg_get_algo_attr_key_size

        keys = [b'', b'', b'']
        i = self._km_addr
        for k in range(len(keys)):
            page_end = i + PAGE_SIZE - i % PAGE_SIZE
            # skip possible padding at start of block
            while i < page_end and (all(self.data[j] == 0xff for j in range(i, i+CHUNK_SIZE)) or
                    all(self.data[j] == 0x00 for j in range(i, i+CHUNK_SIZE))):
                i += CHUNK_SIZE
            # extract key material, if any
            while i < page_end and not (all(self.data[j] == 0xff for j in range(i, i+CHUNK_SIZE)) or
                    all(self.data[j] == 0x00 for j in range(i, i+CHUNK_SIZE))):
                keys[k] += self.data[i:i+CHUNK_SIZE]
                i += CHUNK_SIZE
            i = page_end
        return keys

    def _extract_do_table(self):
        """ Extract the data object table from the firmware: openpgp-do.c gpg_data_scan """
        i = self._do_addr
        self._do_table = {}
        while i < len(self.data) and self.data[i] == 0xff:
            i += 1
        while i < len(self.data) and self.data[i] != 0xff:
            nr, l = self.data[i:i+2]
            i += 2
            try:
                nr = DataObject(nr)
                self._do_table[nr] = self.data[i:i+l]
            except:
                # do not extract this data object
                pass
            if nr < 0x80:
                i += l + 1 if l & 1 else l

    def _build_keys(self, rawkeys):
        # extract useful information from data objects
        self._keys = {}
        for kt, km, fp, attr, prvk in zip(KeyType, rawkeys,
                (DataObject.FP_SIG, DataObject.FP_DEC, DataObject.FP_AUT),
                (DataObject.ATTR_SIG, DataObject.ATTR_DEC, DataObject.ATTR_AUT),
                (DataObject.PRVKEY_SIG, DataObject.PRVKEY_DEC, DataObject.PRVKEY_AUT)):
            # extract fingerprint
            try:
                fp = self._do_table[fp]
            except KeyError:
                continue # key not present in firmware
            # extract key algo
            try:
                algo = KeyAlgo(len(self._do_table[attr]))
            except KeyError:
                algo = KeyAlgo.RSA2048
            # extract data encryption key related values
            iv  = self._do_table[prvk][:AES_SIZE]
            cks = self._do_table[prvk][AES_SIZE:2*AES_SIZE]
            dek = self._do_table[prvk][2*AES_SIZE:3*AES_SIZE]
            self._keys[fp] = PrivKey(kt, algo, km, dek, iv, cks)

    def _nosecrete_private_key(pubkey):
        """ Create the parent certify key without the private parts """
        km = OpaquePrivKey()
        km.parse(pubkey.keymaterial.__bytearray__())
        # S2K GNU extension: private key without secrete parts
        km.s2k.parse(bytearray(b'\xff\x00\x65\x00GNU\x01'))
        # wrap key material in PrivKeyV4 containing info about algo, creation timestamp, ...
        privkey = PrivKeyV4()
        privkey.pkalg = pubkey.pkalg
        privkey.keymaterial = km
        privkey.created = pubkey.created
        privkey.update_hlen()
        # wrap private key in a PGPKey object
        key = PGPKey()
        key._key = privkey
        return key

    def _create_private_key(self, pubkey, subkey=True):
        """ Create a private (sub)key from public key and firmware key material """
        fp = bytes(pubkey.fingerprint)
        if fp not in self._keys:
            return None
        key = self._keys[fp]
        pubkm = pubkey._key.keymaterial

        if key.algo == KeyAlgo.RSA2048 or key.algo == KeyAlgo.RSA4096:
            assert pubkey._key.pkalg in [PubKeyAlgorithm.RSAEncryptOrSign,
                    PubKeyAlgorithm.RSAEncrypt, PubKeyAlgorithm.RSASign]
            plen = len(key.priv) // 2
            km = RSAPriv()
            km.n = pubkm.n
            km.e = pubkm.e
            km.p = MPI(MPIs.bytes_to_int(key.priv[:plen]))
            km.q = MPI(MPIs.bytes_to_int(key.priv[plen:]))
            km.d = MPI(rsa.rsa_crt_iqmp((km.p-1) * (km.q-1), km.e))
            km.u = MPI(rsa.rsa_crt_iqmp(km.q, km.p))
        elif key.algo == KeyAlgo.CURVE25519:
            km = ECDHPriv()
            km.oid = EllipticCurveOID.Curve25519
            km.p = pubkm.p
            km.kdf = pubkm.kdf
            # GnuPG stores the secret value in the wrong order
            # https://lists.gnupg.org/pipermail/gnupg-devel/2018-February/033437.html
            km.s = MPI(MPIs.bytes_to_int(key.priv, 'little'))
        elif key.algo == KeyAlgo.ED25519:
            # GNUK stores "SHA-512(secret)"
            # PGP private key stores "secret"
            logging.warning("Cannot extract Ed25519 key: GNUK format incompatible with PGP format\n"
                            "          sha512(secret) = {}".format(hexlify(key.priv).decode('utf-8')))
            return None
        elif key.algo in [KeyAlgo.SECP256K1, KeyAlgo.NISTP256R1]:
            # Secp256k1 can be used with both ECDH and ECDSA
            if isinstance(pubkm, ECDSAPub):
                km = ECDSAPriv()
            elif isinstance(pubkm, ECDHPub):
                km = ECDHPriv()
                km.kdf = pubkm.kdf
            else:
                raise Exception("Curve {} cannot be used with algorithm {}".format(
                    str(key.algo), pubkm.__class__.__name__))
            if key.algo == KeyAlgo.SECP256K1:
                km.oid = EllipticCurveOID.SECP256K1
            elif key.algo == KeyAlgo.NISTP256R1:
                km.oid = EllipticCurveOID.NIST_P256
            else:
                raise Exception("Should not happen")
            km.p = pubkm.p
            km.s = MPI(MPIs.bytes_to_int(key.priv))
        else:
            # https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-06
            raise Exception("Key algo {} not implemented yet".format(str(key.algo)))

        km._compute_chksum()
        privkey = PrivSubKeyV4() if subkey else PrivKeyV4()
        privkey.pkalg = pubkey._key.pkalg
        privkey.keymaterial = km
        privkey.created = pubkey._key.created
        privkey.update_hlen()
        key = PGPKey()
        key._key = privkey
        key._signatures = pubkey._signatures
        return key

    def unlock(self, password):
        """ Decrypts private keys and returns True if password is valid """
        assert self.locked
        if len(password) != self._pwlen:
            return False
        for k in self._keys.values():
            if not k.decrypt(self._udid, password, self._salt):
                return False
        self.locked = False
        return True

    def extract_key(self, pubkey):
        """ Build the PGP private key from the corresponding public key and this firmware key material """
        assert not self.locked
        assert pubkey.is_public

        # create parent key
        privkey = self._create_private_key(pubkey, False)
        if not privkey:
            privkey = Firmware._nosecrete_private_key(pubkey._key)

        # take user IDs with their signatures from the public key
        for uid in pubkey.userids:
            privkey._uids.append(uid)

        # extract all sub keys
        for sk in pubkey.subkeys.values():
            key = self._create_private_key(sk)
            if not key:
                logging.warning("Subkey not present in firmware: {}".format(sk.fingerprint))
                continue
            privkey._children[key.fingerprint.keyid] = key
            key._parent = privkey

        # reload key so every field is correctly computed
        return PGPKey.from_blob(bytes(privkey))[0]
