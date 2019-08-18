"""
bf_tests.py

"""

from bf import *


def test_xor_bytes_till_shorter():

    ct       = bytearray.fromhex('cad9a65b9fca1c1da2320fcf7c4ae48e')
    Kstream  = bytearray.fromhex('0000000000000000000000000000')
    out      = bytearray.fromhex('cad9a65b9fca1c1da2320fcf7c4a')
    assert xor_bytes_till_shorter(ct, Kstream) == out
    assert xor_bytes_till_shorter(Kstream, ct) == out

    ct       = bytearray.fromhex('cad9a65b9fca1c1da2320fcf7c4ae48e')
    Kstream  = bytearray.fromhex('FFFFFFFFFFFFFFFFFFFFFFFFFFFF')
    out      = bytearray('5&Y\xa4`5\xe3\xe2]\xcd\xf00\x83\xb5')
    assert xor_bytes_till_shorter(ct, Kstream) == out
    assert xor_bytes_till_shorter(Kstream, ct) == out


def test_clk_gen(BEGIN, END):

    for i in count(BEGIN):  # BEGIN..END
        if i % 50000 == 0:
            log.info('attack_tests i: {:10}, BEGIN: {}, END: {}'.format(i, BEGIN, END))
        CLK_HEX = hex(i)[2:]
        if len(CLK_HEX) % 2 == 1:
            CLK_HEX = '0' + CLK_HEX
        # log.info('attack_tests {:10} CLK_HEX: {}'.format(i, CLK_HEX))
        CLK = bytearray.fromhex(CLK_HEX)
        while len(CLK) < 4:
            CLK = '\x00' + CLK
        assert(len(CLK) == 4)
        log.info('attack_tests {:10} CLK_HEX: {}, CLK: {}'.format(i, CLK_HEX, repr(CLK)))

        if i == END:
            break


def test_clk_targets(clk_uint):
    clk_26_1 = clk_targets(clk_uint)
    log.info('test_clk_targets bin: {}, {} bits'.format(clk_26_1.bin, clk_26_1.len))
    log.info('test_clk_targets be : {}'.format(clk_26_1.uintbe))
    log.info('test_clk_targets le : {}'.format(clk_26_1.uintle))


def test_pattern_match():
    out = bytearray.fromhex('08000100')
    log.info('test_pattern_match: {}'.format(repr(pattern_match(PATTERNS, out))))
    out = bytearray.fromhex('00010008')
    log.info('test_pattern_match: {}'.format(repr(pattern_match(PATTERNS, out))))
    out = bytearray.fromhex('00010008')
    log.info('test_pattern_match: {}'.format(repr(pattern_match(PATTERNS, out))))
    out = bytearray.fromhex('00490003')
    log.info('test_pattern_match: {}'.format(repr(pattern_match(PATTERNS, out))))
    out = bytearray.fromhex('61616161')
    log.info('test_pattern_match: {}'.format(repr(pattern_match(PATTERNS, out))))
    out = bytearray.fromhex('62626262')
    log.info('test_pattern_match: {}'.format(repr(pattern_match(PATTERNS, out))))
    out = bytearray.fromhex('6363636364646464')
    log.info('test_pattern_match: {}'.format(repr(pattern_match(PATTERNS, out))))


def test_Kc_prime_count(L):
    """L are the Kc_prime bytes."""

    BEGIN = 255
    END   = BEGIN + 30

    with open("bf3/L{}-{}-{}.txt".format(L, BEGIN, END), mode="w") as fp:

        for i in count(BEGIN):
            Kc_HEX = hex(i)[2:]
            if len(Kc_HEX) % 2 == 1:
                Kc_HEX = '0' + Kc_HEX
            Kc = bytearray.fromhex(Kc_HEX)
            # NOTE: bytearray grows from right to left
            while len(Kc) < KEYS_LEN:
                Kc = '\x00' + Kc
            assert(len(Kc) == KEYS_LEN)
            Kc_prime, red = Kc_to_Kc_prime(Kc, L, red=True)

            fp.write('i  : {}\n'.format(i))
            fp.write('Kc : {}\n'.format(bytearray_to_hexstring(Kc)))
            fp.write("red: {}\n".format(bytearray_to_hexstring(red)))
            fp.write("Kc': {}\n".format(bytearray_to_hexstring(Kc_prime)))
            fp.write('\n')

            log.info('i  : {}'.format(i))
            log.info('Kc : {}'.format(bytearray_to_hexstring(Kc)))
            log.info("red: {}".format(bytearray_to_hexstring(red)))
            log.info("Kc': {}".format(bytearray_to_hexstring(Kc_prime)))
            log.info('')

            if i >= END:
                break


def L1_Kc_primes_aes():
    """Generate a list with all 256 AES-CCM keys (L=1)

    16-L least significant bytes are zeroed.

    MSB is key[0].
    """

    KC_PRIMES = []

    for i in range(256):
        key = bytearray(16)
        key[0] = i
        # log.info('L1_Kc_primes_aes {} key: {}'.format(i, repr(key)))
        KC_PRIMES.append(key)

    assert len(KC_PRIMES) == 256
    return KC_PRIMES


def L1_Kc_primes_e0():
    """Generate a list with all 256 E0 keys (L=1)

    """

    g1 = BitVector(intVal=G1[1], size=128)
    g2 = BitVector(intVal=G2[1], size=128)
    one = BitVector(intVal=0x01, size=128)

    KC_PRIMES = []

    for i in range(256):
        red = BitVector(intVal=i, size=128)
        key_bv = g2.gf_multiply(red)[128:]
        key = BitVector_to_bytearray(key_bv)
        assert len(key) == Ar_KEY_LEN and type(key) == bytearray
        # log.info('L1_Kc_primes_e0 {} key: {}'.format(i, repr(key)))
        KC_PRIMES.append(key)

    assert len(KC_PRIMES) == 256
    return KC_PRIMES


def L1_table():
    # row = '{} & \texttt\{{}\}  & \texttt\{{}\} \\'.format(1, 2, 3)
    e0s = L1_Kc_primes_e0()
    aess = L1_Kc_primes_aes()
    with open("table.txt", mode="w") as fp:
        # for i in range(256):
        for i in range(80):
            # NOTE use {{ or }} to escape curly braces in a format string
            row = ''
            # row  = '{:3} & '.format(i)
            row += '\\texttt{{{}}} & '.format(bytearray_to_hexstring(e0s[i]))
            row += '\\texttt{{{}}} '.format(bytearray_to_hexstring(aess[i]))
            row += '\\\\'
            row += '\n'
            fp.write(row)



if __name__ == '__main__':

    # test_xor_bytes_till_shorter()
    # test_clk_gen(0, 0x010000)
    # test_clk_targets(314606)
    # test_pattern_match()
    # test_clk_targets(3146060000)

    # NOTE: alternative impl of clk_target
    # foo = 3146060000 >> 1
    # foo = foo & 0x3ffffff
    # print(foo)

    # test_Kc_prime_count(1)

    # L1_Kc_primes_e0()
    # L1_Kc_primes_aes()
    L1_table()

