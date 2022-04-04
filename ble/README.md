# KNOB Attack on BLE

## Custom Linux Kernel

Those are the steps to patch a Linux kernel in order to always propose 7 bytes
of entropy during BLE pairing. This setup can be used to test if a remote
victim is vulnerable to the KNOB attack on BLE
* Download and unzip the kernel source code
* Open `net/bluetooth/smp.c`
* Set `SMP_DEV(hdev)->max_key_size = 7` (or any other value that you want to test)
* Re-compile and install the kernel
* Try to pair over BLE
* Check in Wireshark that the SMP Pairing Request/Response from the patched
    device has `KeySize` equal to `7`

So far I've not been able to find a BLE device accepting less than 7 bytes of
entropy, Please ping @francozappa if you find one :)
