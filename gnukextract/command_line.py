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

import argparse
import logging
import sys

from binascii import unhexlify
from gnukextract import Firmware
from pgpy import PGPKey


def bruteforce(wordlist, firmware):
    with open(wordlist, 'rb') as f:
        for password in f:
            password = password.strip()
            if not password or len(password) != firmware._pwlen:
                continue
            if firmware.unlock(password):
                return password
    return None


def parseargs():
    parser = argparse.ArgumentParser(
            description='Extract PGP private key from GNUK / Nitrokey Start firmware.',)
    parser.add_argument('-o', '--out', metavar='FILE', default="-",
            help='export private key to FILE [default: stdout]')
    parser.add_argument('-d', '--dict', metavar='DICT', help='password dictionary')
    required = parser.add_argument_group('required arguments')
    required.add_argument('-f', '--fw', metavar='FW', required=True,
            help='GNUK / Nitrokey Start firmware')
    required.add_argument('-k', '--key', metavar='PUB', required=True,
            help='corresponding GPG public key')
    required.add_argument('-u', '--udid', help='STM32 unique device ID', required=True)

    args = parser.parse_args()
    # check UDID format
    args.udid = unhexlify(args.udid)
    assert len(args.udid) == 12

    return args


def main():
    args = parseargs()
    # also print info messages
    logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

    # extract key material from firmware
    firmware = Firmware(args.fw, args.udid)

    # bruteforce firmware password if necessary
    if firmware.locked:
        if not args.dict:
            logging.critical("Firmware is password protected: please provide a dictionary with -d option")
            sys.exit(1)
        password = bruteforce(args.dict, firmware)
        if password is None:
            logging.critical("No valid password found in provided dictionary")
            sys.exit(1)
        logging.info("Firmware unlocked with password: {}".format(password))

    pubkey, _ = PGPKey.from_file(args.key)
    privkey = firmware.extract_key(pubkey)

    if args.out == '-':
        # export ASCII armored version if writing to stdout
        sys.stdout.write(str(privkey))
    else:
        with open(args.out, 'wb') as f:
            # export binary version when writing to file
            f.write(bytes(privkey))
