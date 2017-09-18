#!/usr/bin/env python

from distutils.core import setup

import dovecotauth


setup(
    name='dovecotauth',
    version=dovecotauth.__version__,
    author='Keith Gaughan',
    author_email='k@stereochro.me',
    url='https://github.com/kgaughan/dovecotauth/',
    description='A client for the Dovecot Authentication Protocol v1.1',
    long_description=open('README').read(),
    license='MIT',
    classifiers=[
        'Programming Language :: Python',
    ],
    py_modules=[
        'dovecotauth'
    ],
)
