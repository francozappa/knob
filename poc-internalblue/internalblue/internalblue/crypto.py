#!/usr/bin/python3

"""
Bluetooth BR/EDR crypto

128 bits - 16 B:
    LINK_KEY
    EN_RAND
    EK_TEMP

96 bits - 12 B:
    COF

https://www.doc.ic.ac.uk/~mrh/330tutor/ch04s02.html

    Galois field is a finite field of order n = p^m, GF(n) = GF(p^m)
    addition and multiplication modulo a prime number p form finite fields of
        order n = p^1
    One way to construct a finite field with m > 1 is using the polynomial basis
    poly : a_n x^n + ... + a_1, where n is the degree of a poly
    If a polynomial is divisible only by itself and constants, then we call
        this polynomial an irreducible polynomial.
    We will see later that
        irreducible polynomials have properties similar to prime numbers.
    If the coefficients are taken from a field F, then we say it is a
        polynomial over F
    Similar to integers, you can do modular arithmetic with polynomials over a field


"""

# NOTE: not implemented
def lmp_aes(link_key):
    """
    Use AES-CCM [Vol 2] Part H, Section 7.7.6)

    EN_RAND is NOT used

    9.4 ENCRYPTION KEY SIZE REDUCTION (pag 1706)
    When the devices have negotiated a key size shorter than the maximum
    length, the key will be shortened by replacing LSOs of the key with 0x00.
    """
    raise NotImplemented


def lmp_Kc(link_key):
    """
    Derive Kc from link key
    """
    Kc = b''


    return Kc


def lmp_e0(Kc, clock, BD_ADDR, EN_RAND):
    """
    EO stream cipher (no SECURE_CONNECTIONS), pag 1662
    """

    # FIXME: still don't know where EN_RAND is used
    L = 1
    Kc_prime = lmp_Kc_prime(Kc, L)


def lmp_Kc_prime(Kc, L):
    # poly
    g1 = [
        1: 0x01,
        2: 0x02,
        3: 0x03,
    ]
    g2 = [
        1: 0x01,
        2: 0x02,
        3: 0x03,
    ]

    Kc_prime = b''
    Kc_prime = g2[L] * (Kc % g1[L])
    return Kc_prime


def lmp_e3(link_key, EN_RAND, cof):
    """
    Use E3 algo [Vol 2] Part H, Section 6.4
    """
    pass


def lmp_hash(link_key, EN_RAND, COF, L=12):
    """
    (EQ 13) pag 1675
    """
    pass


def lmp_shorten_ek(Kc, g1, g2):
    """

    The key length may be reduced by a modulo operation between K C and a
    polynomial of desired degree. After reduction, the result is encoded with
    a block code in order to distribute the starting states more uniformly.
    The operation shall be as defined in (EQ 10, pag 1668).

    g1(x) is a poly of degree 8L
    g2(x) is a poly of degree \le 128 - 8L

    """
    Kc_prime = b''

    # TODO

    return Kc_prime


def lmp_cof(is_master_key, master_btaddr=b''):
    """
    (EQ 3) pag 1675

    if master key is used
        returns master_btaddr | master_btaddr
    else
        returns Authenticated Ciphering Offset (ACO)
    """
    cof = b''
    if is_master_key:
        cof = master_btaddr + master_btaddr
    else:
        cof = aco

    return cof


if __name__ == "__main__":


    LINK_KEY = b''
    assert len(LINK_KEY) == 16, "len(LINK_KEY) is {}, it should be 16 B".format(len(LINK_KEY))
    EN_RAND = b''
    assert len(EN_RAND) == 16, "len(EN_RAND) is {}, it should be 16 B".format(len(EN_RAND))
    COF = b''
    assert len(COF) == 12, "len(COF) is {}, it should be 12 B".format(len(COF))

    EK_LEN = 1  # Bytes

    SECURE_CONNECTIONS = False
    if SECURE_CONNECTIONS:
        ALGO = ek_aes
    else:
        ALGO = ek_e0

