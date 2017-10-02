#!/usr/bin/env python

from setuptools import setup

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
        'Development Status :: 4 - Beta',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Topic :: Communications :: Email :: Mail Transport Agents',
        'Topic :: Security',
        'Topic :: Utilities',
    ],
    py_modules=[
        'dovecotauth'
    ],
)
