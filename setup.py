#!/usr/bin/env python3

from setuptools import setup

from setuptools.command.install import install
from pip._internal import main as pip

setup(
    name='gnukextract',
    version='1.0.0',
    description='Extract PGP private key from Gnuk / Nitrokey Start firmware',
    packages=['gnukextract'],
    scripts=['gnuk-extractor'],
    install_requires=['PGPy == 0.5.2'],
)
