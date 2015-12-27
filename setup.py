#!/usr/bin/env python3
import codecs
from setuptools import setup


with codecs.open('README.origin.rst', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='shadowsocks',
    version='2.8.2',
    license='http://www.apache.org/licenses/LICENSE-2.0',
    description="A fast tunnel proxy that help you get through firewalls",
    author='Wiky',
    author_email='wiiiky@outlook.com',
    url='https://github.com/wiiiky/miserable',
    packages=['shadowsocks', 'shadowsocks.crypto', 'shadowsocks.dns', 'shadowsocks.tcp'],
    package_data={
        'shadowsocks': ['README.rst', 'LICENSE']
    },
    install_requires=[],
    entry_points="""
    [console_scripts]
    sslocal = shadowsocks.local:main
    ssserver = shadowsocks.server:main
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
