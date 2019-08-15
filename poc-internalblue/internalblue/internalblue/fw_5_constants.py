# Device Infos
DEVICE_NAME = 0x2178B4  # [type: 1byte] [len: 1byte] [name: len byte]
BD_ADDR = 0x210C2C


# Memory Sections
class MemorySection:
    def __init__(self, start_addr, end_addr, is_rom, is_ram):
        self.start_addr = start_addr
        self.end_addr = end_addr
        self.is_rom = is_rom
        self.is_ram = is_ram

    def size(self):
        return self.end_addr - self.start_addr

#                          start,    end,      is_rom? is_ram?
SECTIONS = [ MemorySection(0x0,      0x90000,  True , False),
             MemorySection(0xd0000,  0xd8000,  False, True ),
            #MemorySection(0xe0000,  0x1f0000, True , False),
             MemorySection(0x200000, 0x228000, False, True ),
             MemorySection(0x260000, 0x268000, True , False),
            #MemorySection(0x280000, 0x2a0000, True , False),
             MemorySection(0x318000, 0x320000, False, False),
             MemorySection(0x324000, 0x360000, False, False),
             MemorySection(0x362000, 0x362100, False, False),
             MemorySection(0x363000, 0x363100, False, False),
             MemorySection(0x600000, 0x600800, False, False),
             MemorySection(0x640000, 0x640800, False, False),
             MemorySection(0x650000, 0x650800, False, False),
            #MemorySection(0x680000, 0x800000, False, False)
            ]


# Connection Structure and Table
CONNECTION_ARRAY_ADDRESS = 0x002038E8
CONNECTION_ARRAY_SIZE    = 11
CONNECTION_STRUCT_LENGTH = 0x14C


# Address of the enable table
PATCHRAM_ENABLED_BITMAP_ADDRESS = 0x310204
# Address of the target table
PATCHRAM_TARGET_TABLE_ADDRESS   = 0x310000
# Address of the new values table
PATCHRAM_VALUE_TABLE_ADDRESS    = 0xd0000
PATCHRAM_NUMBER_OF_SLOTS        = 128


# LMP

# These arrays contain the sizes for LMP packets (including the opcode) depending
# on the LMP opcode or escaped LMP opcode. The values can be obtained from the BT
# specification or from the LMP handler table in the firmware.
LMP_LENGTHS = [
     0,  2, 17,  2,  3,  1,  3,  2, 17, 17,  #  0..9
    17, 17,  5, 17, 17,  2,  2, 17,  1,  5,  #  10..19
     7,  7,  0, 10,  1, 17,  0,  6, 13,  9,  #  20..29
    15,  2,  2,  1,  1,  1,  2,  6,  6,  9,  #  30..39
     9,  4,  4,  7,  3,  2,  2,  1,  3,  1,  #  40..49
     1,  1,  9,  3,  3,  3,  1, 10,  1,  3,  #  50..59
    16, 4, 17, 17, 17, 17, 17, 0]

# LMP_ESC_LENGTHS = [0, 4, 5, 12, 12, 12, 8, 3, 0, 0, 0, 3, 16, 4, 0, 0, 7, 12, 0, 0, 0, 9, 9, 2, 2, 5, 5, 2, 2, 2, 3, 3, 3]
# NOTE: starts from 0
LMP_ESC_LENGTHS = [
    0, 4, 5, 12, 12, 12, 8, 3, 0, 0,   #  0..9
    0, 3, 16, 4, 0, 0, 7, 12, 0, 0,    # 10..19
    0, 9, 9, 2, 2, 5, 5, 2, 2, 2,      # 20..29
    3, 3, 3, 2, 2
]

# Snippet for sendLmpPacket()
# NOTE: called by sendlmp command, no need to add extra code
# NOTE: NOT called by monitor lmp start
SENDLMP_CODE_BASE_ADDRESS = 0xd7500
SENDLMP_ASM_CODE = """
        push {r4,lr}

        // malloc buffer for LMP packet
        bl 0x3F17E      // malloc_0x20_bloc_buffer_memzero
        mov r4, r0      // store buffer for LMP packet inside r4

        // fill buffer
        add r0, 0xC         // The actual LMP packet must start at offset 0xC in the buffer.
                            // The first 12 bytes are (supposely?) unused and remain zero.
        ldr r1, =payload    // LMP packet is stored at the end of the snippet
        mov r2, 20          // Max. size of an LMP packet is 19 (I guess). The send_LMP_packet
                            // function will use the LMP opcode to lookup the actual size and
                            // use it for actually transmitting the correct number of bytes.
        bl  0x2e03c         // memcpy(dest=r0, source=r1, size=20)

        // load conn struct pointer (needed for determine if we are master or slave)
        mov r0, %d      // connection number is injected by sendLmpPacket()
        bl 0x42c04      // find connection struct from conn nr (r0 will hold pointer to conn struct)

        // set tid bit if we are the slave
        ldr r1, [r0, 0x1c]  // Load a bitmap from the connection struct into r1.
        lsr r1, 15          // The 'we are master'-bit is at position 15 of this bitmap
        and r1, 0x1         // isolate the bit to get the correct value for the TID bit
        ldr r2, [r4, 0xC]   // Load the LMP opcode into r2. Note: The opcode was already shifted
                            // left by 1 bit (done by sendLmpPacket()). The TID bit goes into
                            // the LSB (least significant bit) of this shifted opcode byte.
        orr r2, r1          // insert the TID bit into the byte
        str r2, [r4, 0xC]   // Store the byte back into the LMP packet buffer

        // send LMP packet
        mov r1, r4      // load the address of the LMP packet buffer into r1.
                        // r0 still contains the connection number.
        pop {r4,lr}     // restore r4 and the lr
        b 0xf81a        // branch to send_LMP_packet. send_LMP_packet will do the return for us.

        .align          // The payload (LMP packet) must be 4-byte aligend (memcpy needs aligned addresses)
        payload:        // Note: the payload will be appended here by the sendLmpPacket() function
        """

# Assembler snippet for the readMemAligned() function
READ_MEM_ALIGNED_ASM_LOCATION = 0xd7900
READ_MEM_ALIGNED_ASM_SNIPPET = """
        push {r4, lr}

        // malloc HCI event buffer
        mov  r0, 0xff    // event code is 0xff (vendor specific HCI Event)
        mov  r1, %d      // readMemAligned() injects the number of bytes it wants to read here
        add  r1, 6       // + type and length + 'READ'
        bl   0x7AFC      // malloc_hci_event_buffer (will automatically copy event code and length into the buffer)
        mov  r4, r0      // save pointer to the buffer in r4

        // append our custom header (the word 'READ') after the event code and event length field
        add  r0, 2            // write after the length field
        ldr  r1, =0x44414552  // 'READ'
        str  r1, [r0]
        add  r0, 4            // advance the pointer. r0 now points to the beginning of our read data

        // copy data to buffer
        ldr  r1, =0x%x  // readMemAligned() injects the read_address here. r1 will be used as src pointer in the loop
        mov  r2, %d     // readMemAligned() injects the number of dwords to read here. r2 will be the loop counter
    loop:
        ldr  r3, [r1]   // read 4 bytes from the read_address
        str  r3, [r0]   // store them inside the HCI buffer
        add  r0, 4      // advance the buffer pointer
        add  r1, 4      // advance the read_address
        subs r2, 1      // decrement the loop variable
        bne  loop       // branch if r2 is not zero yet

        // send HCI buffer to the host
        mov r0, r4      // r4 still points to the beginning of the HCI buffer
        bl  0x398c1     // send_hci_event_without_free()

        // free HCI buffer
        mov r0, r4
        bl  0x3FA36     // free_bloc_buffer_aligned

        pop {r4, pc}    // return
    """

