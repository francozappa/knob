#!/usr/bin/python2
# -*- coding: utf-8 -*-

"""
constants.py

"""

from binascii import unhexlify, hexlify
from BitVector import *

import logging
log = logging.getLogger()
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(name)-4s %(levelname)-4s %(message)s')
handler.setFormatter(formatter)
log.addHandler(handler)
# log.setLevel(logging.DEBUG)

Ar_ROUNDS = 8
Ar_KEY_LEN = 16  # Bytes, 128 biis
EN_RAND_LEN = 16  # Bytes, 96 bits
KEYS_LEN = 16  # Bytes, Kl, Kc, Kc_prime

COF_LEN = 12  # Bytes, 96 bits
ACO_LEN = 12  # Bytes, 96 bits

BTADD_LEN = 6  # Bytes, 48 bits

CRC_LEN = 2  # Bytes, pag 1598
MIC_LEN = 4  # Bytes, pag 1704

# NOTE: NEX is the master
NEX_BTADD  = 'ccfa0070dcb6'
MOTO_BTADD = '829f669bda24'

SRES_LEN = 4  # Bytes, 32 bits
CLK26_1_LEN = 4  # Bytes, 32 bits

# NOTE: path to the E0 binary
E0_IMPL_PATH = "/home/mel/knob/e0/e0"

PATTERNS = {
    'L2CAP1'              : '\x08\x00\x01\x00',
    'L2CAP1_R'            : '\x00\x01\x00\x08',
    'L2CAP2'              : '\x0c\x00\x01\x00',
    'L2CAP2_R'            : '\x00\x01\x00\x0c',
    'L2CAP3'              : '\x0a\x00\x01\x00',
    'L2CAP3_R'            : '\x00\x01\x00\x0a',
    'L2CAP1_T'            : '\x03\x00\x49\x00',
    'L2CAP1_TR'           : '\x00\x49\x00\x03',
    'aaaa'                : '\x61\x61\x61\x61',
    'bbbb'                : '\x62\x62\x62\x62',
    'cccc'                : '\x63\x63\x63\x63',
    'dddd'                : '\x64\x64\x64\x64',
    'image'               : '\x69\x6d\x61\x67\x65',
    'jpeg'                : '\x6a\x70\x65\x67',
    'f_i_l_e'             : '\x66\x00\x69\x00\x6c\x00\x65',
    'j_p_e_g'             : '\6a\x00\x70\x00\x65\x00\x67',
    # NOTE: compute and add CRCs
}


G1 = [
    0x00,                                       # not used
    0x0000011d,                                 # L=1
    0x0001003f,                                 # L=2
    0x010000db,
    0x01000000af,
    0x010000000039,
    0x01000000000291,
    0x0100000000000095,
    0x01000000000000001b,
    0x01000000000000000609,
    0x0100000000000000000215,
    0x01000000000000000000013b,
    0x010000000000000000000000dd,
    0x010000000000000000000000049d,
    0x01000000000000000000000000014f,
    0x010000000000000000000000000000e7,
    0x0000000100000000000000000000000000000000, # L = 16
]

G2 = [
    0x00,                                       # not used
    0xe275a0abd218d4cf928b9bbf6cb08f,           # L=1
    0x01e3f63d7659b37f18c258cff6efef,           # L=2
    0x000001bef66c6c3ab1030a5a1919808b,
    0x016ab89969de17467fd3736ad9,
    0x0163063291da50ec55715247,
    0x2c9352aa6cc054468311,
    0xb3f7fffce279f3a073,
    0xa1ab815bc7ec8025,
    0x02c98011d8b04d,
    0x058e24f9a4bb,
    0x0ca76024d7,
    0x1c9c26b9,
    0x26d9e3,
    0x4377,
    0x89,
    0x01,                                       # L = 16
]


# NOTE: used for nonlin_subs
EXP_45 = []
for i in range(0, 256):
    EXP_45.append(int( ((45**i) % 257 ) % 256))

