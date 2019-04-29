#!/usr/bin/env python3

from setuptools import setup

from setuptools.command.install import install
from pip._internal import main as pip

# Ugly hack to install local version of PGPy instead of PyPI version
# Could not find a clean way to do it with setuptools
class InstallPGPy(install):
    def run(self):
        install.run(self)
        pip(['install', './PGPy'])

setup(
    name='gnukextract',
    version='1.0.0',
    description='Extract PGP private key from Gnuk / Nitrokey Start firmware',
    packages=['gnukextract'],
    scripts=['gnuk-extractor'],
    # TODO: replace once PGPy pull requests are merged and new version is published on PyPI
    #install_requires=['PGPy == 0.4.?'],
    cmdclass={'install': InstallPGPy}
)
