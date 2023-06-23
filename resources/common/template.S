# This assembly file includes the raw binaries for interpreter and jit, the data and shadow stack space

.global main
.global gigue_jit_start
.global gigue_int_start
.global ss_start
.global ss_end


# Note: The 0 bits correspond to the MPP field, responsible 
# of the mode selection (0b00 for U, 0b01 for S and 0b11 for M)
.equiv MASK_MPP_USER_MODE, 0xFFFFE7FF

# PMP address registers contains:
#  63   54 53              0
# |   0   |    addr[55:2]   |

.equiv PMP_ADDR0, gigue_jit_start

.equiv PMP_ADDR1, tab

.equiv PMP_ADDR2, ss_start

.equiv PMP_ADDR3, ss_end

.equiv PMP_ADDR4, 0x80020000

# PMP config registers contains 8 (4 in rv32) 8-bit configs that consist of:
#   7  6  5 4   3  2   1   0
# | L | 00 |  A  | X | W | R
# with: 
# L (lock), X (execute), W (write), R (read) 
# A matching mode (0b00-OFF, 0b01-TOR, 0b10-NA4, 0b11-NAPOT)

# Config for this test:
# region0: locked TOR all rights   -> 0b10001111/0x8F  interpreter
# region1: locked TOR all rights   -> 0b10011111/0x8F  jit code
# region2: locked TOR RW           -> 0b10011011/0x8B  jit data 
# region3: locked TOR RW           -> 0b10001011/0x8B  shadow stack
# region4: locked TOR RW           -> 0b10001011/0x8B  main stack

.equiv PMP_CONFIG, 0x0000008B8B8B8F8F

.section .text

pmp_setup:
    # Read the mode
    csrr t0, mstatus

    # Setup user mode
    li t1, MASK_MPP_USER_MODE
    and t0, t0, t1             # Set MPP to user mode
    or t0, t0, 8               # Set MIE
    csrw mstatus, t0           # Write the value back to the CSR

    # Setup user mode entry address
    la t0, gigue_int_start
    csrw mepc, t0

    # Setup first PMP region: Base interpreter
    la t0, PMP_ADDR0   # End of interpreter code!
    srli t0, t0, 2     # Note: addr should be shifted by 2
    csrw pmpaddr0, t0

    # Setup second PMP region: JIT code
    la t0, PMP_ADDR1   # End of jit code!
    srli t0, t0, 2     # Note: addr should be shifted by 2
    csrw pmpaddr1, t0

    # Setup third PMP region: JIT data
    la t0, PMP_ADDR2   # End of data!
    srli t0, t0, 2     # Note: addr should be shifted by 2
    csrw pmpaddr2, t0

    # Setup fourth PMP region: Shadow Stack
    la t0, PMP_ADDR3         # End of shadow stack!
    srli t0, t0, 2           # Note: addr should be shifted by 2
    csrw pmpaddr3, t0

    # Setup fifth PMP region: Main Stack
    li t0, 0x80800000        # End of shadow stack!
    srli t0, t0, 2           # Note: addr should be shifted by 2
    csrw pmpaddr4, t0

    # Setup PMP config 
    li t0, PMP_CONFIG
    csrw pmpcfg0, t0

    # Jump to the mepc address (test_start)
    mret

main:
    la t6, tab             # Load the data address in t6
    la t3, ss_end          # Load the shadow stack address in t3 (grows downwards)
    call pmp_setup         # Call the generated binary
    li a0, 0               # Pass 0 to the exit function
    call exit              # 
    
    # addi    a7, x0, 93     # Set ecall to exit (93) function
    # ecall                  # Call linux to terminate the program

gigue_int_start:
    .incbin "bin/int.bin"

gigue_jit_start:
    .incbin "bin/jit.bin"

.section .data
tab: 
    .incbin "bin/data.bin"

ss_start:
    .incbin "bin/ss.bin"

ss_end: