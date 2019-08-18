# Brute force and validate low entropy E0 keys

This folder contains the code that we developed to brute force, and validate
encryption keys generated using the E0 stream cipher. E0 uses custom security
functions, including the H hash function, and the Es entropy reduction
function. Refer to Figure 6 of our
[paper](https://www.usenix.org/conference/usenixsecurity19/presentation/antonioli) 
for an high level description of those functions.

* `h.py` contains an implementation of a custom hash function used by Bluetooth,
and indicated in the standard as H.

* `e1.py` uses H to compute SRES and ACO, ACO is used as COF.

* `e3.py` uses H to compute Kc that is an encryption key with 16 bytes of
    entropy.

* `es.py` reduces the entropy of Kc according to the negotiated entropy N

* `constants.py` contains the constants
    * change `E0_IMPL_PATH = "/home/mel/knob/e0/e0"` to your full path

* [`BitVector.py`](https://engineering.purdue.edu/kak/dist/BitVector-3.4.8.html) is used to perform computation in 
  Galois field and bit manipulations.

* `e0` binary compiled using [this](https://github.com/adelmas/e0) open source C implementation of E0

* `Makefile` contains several targets such as
    * `make tests` to check that all the modules are working correctly
    * `make bf` to launch our brute force script against the ciphertext in `cts.py`
