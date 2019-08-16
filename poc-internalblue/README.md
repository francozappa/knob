# README

## Requirements

* Rooted Nexus 5 running the `internalblue/android_bluetooth_stack/nexus5_android6_0_1/bluetooth.default.so` Android Bluetooth stack

* Laptop running a Linux based OS 

* Wireshark
    * Optionally install the [LMP dissection plugin](https://github.com/greatscottgadgets/libbtbb) 
        to easily follow the packet capture. I was able to install using Wireshark v2.6.10
 
## Perform the KNOB attack

1. Connect the Nexus 5 to your laptop via USB

2. Install our modified internalblue v0.1 by opening a terminal and cd'ing into
    `internalblue` and running `sudo python2 setup.py install`

3. Open a terminal and run `internalblue`

4. From the internalblue prompt start LMP monitoring with `monitor lmp start`
    * A Wireshark window should pop up
    * If from the terminal you get a bunch of error messages including `Error: unrecognized option -mthumb` 
      you should close the Wireshark window and `internalblue`, 
      uncomment line `116` in `internalblue/internalblue/core.py` to trigger a
      custom exception,  and restart from step 2 (installation).

4. Pair a target Bluetooth device with the Nexus 5

5. Start a connection **from the Nexus 5 to the target device**. In other words the Nexus 5 has to be
   the master and should send the first `LMP_encryption_key_size_req` packet. We have other internalblue
   patches to perform the same attack when the Nexus 5 is the slave, it is
   just a matter of sending the correct LMP packet format.

6. On Wireshark you should see that the Nexus (Bluetooth master) negotiating encryption keys with 1 byte
    of entropy (like what happens from packet 121 to packet 127 in
    [our sample pcap file](https://github.com/francozappa/knob/blob/master/poc-internalblue/sample-nexmaster-galaxys9slave.pcapng). Note that our sample pcap was captured before the release of any KNOB attack patch.

7. Check if the target device is vulnerable
    * Android (tested only on a Pixel 2): If the target device sends first an `LMP_accept` (in response to an `LMP_start_encryption_req`) and then an `LMP_detach` message due to security reasons then the target device is patched against the KNOB attack.

8. Close Wireshark and internalblue

## FAQ

### What should I do if I find a new vulnerable device

Please let us know, such as we can update our evaluation results.

### Wait, this is not an attack over the air

We implemented the KNOB attack by simulating a remote attacker
using InternalBlue. Alternatively, we could have conducted
the attacks over the air using signal manipulation and
(reactive) jamming. However, the InternalBlue setup is
simpler, more reliable, cheaper, and easier to reproduce than
the over-the-air setup, while affecting the victims in the same
way as a remote over the air attack.

