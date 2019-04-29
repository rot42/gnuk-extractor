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

import pytest

from binascii import unhexlify
from gnukextract import Firmware
from pgpy import PGPKey, PGPMessage
from pgpy.constants import CompressionAlgorithm, KeyFlags


UDID    = unhexlify('34ff6c064e55373226332443')
GOODPW  = b'bignukey'
WRONGPW = b'123456'
MESSAGE = b'This is an encrypted test message\n'

# Firmwares to test
nopass_algos = ['curve25519', 'nistp256', 'rsa2048', 'rsa4096', 'secp256k1']
pass_algos   = ['rsa2048']


# helper functions
def get_key_with_flag(key, flag):
    """ Returns the (sub)key with flag set """
    #print("DEBUG:", key._get_key_flags())
    if flag in key._get_key_flags():
        return key
    for sk in key.subkeys.values():
        if flag in sk._get_key_flags():
            return sk

@pytest.mark.parametrize("algo", nopass_algos)
def test_firmware_nopass(algo):
    # extract private key from firmware
    firmware = Firmware("firmwares/{}.firmware.bin".format(algo), UDID)
    assert not firmware.locked
    pubkey, _ = PGPKey.from_file("pubkeys/{}.pub.key.asc".format(algo))
    privkey = firmware.extract_key(pubkey)
    assert privkey is not None

    # test message decryption
    subk = get_key_with_flag(privkey, KeyFlags.EncryptCommunications)
    assert subk is not None
    enc = PGPMessage.from_file("messages/{}.enc.msg.gpg".format(algo))
    dec = subk.decrypt(enc)
    assert bytes(dec.message) == MESSAGE

    # test signature: except Ed25519 which cannot be extracted
    subk = get_key_with_flag(privkey, KeyFlags.Sign)
    if algo != 'curve25519':
        assert subk is not None
        msg = PGPMessage.new(MESSAGE, compression=CompressionAlgorithm.Uncompressed)
        sig = subk.sign(msg)
        subk = get_key_with_flag(pubkey, KeyFlags.Sign)
        assert subk is not None
        assert subk.verify(MESSAGE, sig)
    else:
        assert subk is None


@pytest.mark.parametrize("algo", pass_algos)
def test_firmware_pass(algo):
    # test firmware decryption with wrong and correct password
    firmware = Firmware("firmwares/{}.pass.firmware.bin".format(algo), UDID)
    assert firmware.locked
    assert not firmware.unlock(WRONGPW)
    assert firmware.unlock(GOODPW)
    assert not firmware.locked

    # extract private key from firmware
    pubkey, _ = PGPKey.from_file("pubkeys/{}.pub.key.asc".format(algo))
    privkey = firmware.extract_key(pubkey)
    assert privkey is not None

    # test message decryption
    subk = get_key_with_flag(privkey, KeyFlags.EncryptCommunications)
    assert subk is not None
    enc = PGPMessage.from_file("messages/{}.enc.msg.gpg".format(algo))
    dec = subk.decrypt(enc)
    assert bytes(dec.message) == MESSAGE

    # test signature
    subk = get_key_with_flag(privkey, KeyFlags.Sign)
    assert subk is not None
    msg = PGPMessage.new(MESSAGE, compression=CompressionAlgorithm.Uncompressed)
    sig = subk.sign(msg)
    subk = get_key_with_flag(pubkey, KeyFlags.Sign)
    assert subk is not None
    assert subk.verify(MESSAGE, sig)
