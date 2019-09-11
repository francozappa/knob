# README

This folder is a Mirror of https://github.com/demantz/lmp_wireshark_dissector.git

* [2019-09-11] I've tested the plugin using `wireshark`v2.6.6 using Arch Linux.

# BTBB Wireshark plugin from the Ubertooth libbtbb project

This is the Bluetooth baseband plugin for Wireshark, it also includes an LMP
level dissector.


# About this repository

This repository contains only the Wireshark dissector without the rest of
the libbtbb library. The dissector was updated to be compatible with
Wireshark 2.6. All credit goes to the original authors of libbtbb. For
additional information see the original repository:

https://github.com/greatscottgadgets/libbtbb


# Build and Install

If you are running Debian/Ubuntu/BackTrack install:

    sudo apt-get install wireshark-dev wireshark

Then run

    mkdir build
    cd build
    cmake ..
    make
    make install

This will install to the `~/.local/lib/wireshark/plugins/2.6/epan/` in your home
directory. To override this set the DESTDIR environment variable when running
cmake.

