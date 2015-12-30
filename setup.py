#!/usr/bin/env python3
import codecs
from setuptools import setup


with codecs.open('README.origin.rst', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='miserable',
    version='1.0',
    license='http://www.apache.org/licenses/LICENSE-2.0',
    description="A fast tunnel proxy that help you get through firewalls",
    author='Wiky',
    author_email='wiiiky@outlook.com',
    url='https://github.com/wiiiky/miserable',
    packages=['miserable', 'miserable.crypto',
              'miserable.dns', 'miserable.tcp'],
    package_data={
        'miserable': ['README.rst', 'LICENSE']
    },
    install_requires=[],
    entry_points="""
    [console_scripts]
    mislocal = miserable.local:main
    """,
    classifiers=[
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Internet :: Proxy Servers',
    ],
    long_description=long_description,
    test_suite='tests',
)
