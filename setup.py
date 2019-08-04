#!/usr/bin/env python3

from setuptools import setup

from setuptools.command.install import install
from pip._internal import main as pip

setup(
    name='gnuk-extractor',
    version='1.0.1',
    description='Extract PGP private key from Gnuk / Nitrokey Start firmware',
    url='https://github.com/rot42/gnuk-extractor',
    author='rot42',
    license='AGPLv3',
    packages=['gnukextract'],
    install_requires=['PGPy == 0.5.2'],
    extras_require={
        'test': ['pytest'],
    },
    entry_points={
        'console_scripts': [
            'gnuk-extractor = gnukextract.command_line:main',
        ],
    }
)
