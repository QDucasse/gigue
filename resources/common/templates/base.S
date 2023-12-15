# This assembly file includes the raw binaries for interpreter and jit, the data and shadow stack space

.section .text

.global main

#define PMP_ADDR0 0x100000000000
#define PMP_CONFIG 0x000000000000000f

main:
    la t6, gigue_jit_data  # Load the data address in t6
    la t3, gigue_ss_end    # Load the shadow stack address in t3 (grows downwards)
    call umode_setup       # Pass in user mode
    li a0, 0               # Pass 0 to the exit function
    call exit              # 
    
    # addi    a7, x0, 93     # Set ecall to exit (93) function
    # ecall                  # Call linux to terminate the program

umode_setup:
    /* Machine mode setup
    _____________________ */

    # Read the mode
    # csrr t0, mstatus

    # Setup user mode
    # li t1, MASK_MPP_USER_MODE
    # and t0, t0, t1             # Set MPP to user mode
    # or t0, t0, 8               # Set MIE
    # csrw mstatus, t0           # Write the value back to the CSR

    # Equivalent? As MPP and MIE will be set to user mode
    csrwi mstatus, 0 

    # Setup user mode entry address
    la t0, gigue_int_start
    csrw mepc, t0

    /* PMP CSR setup
    _____________________ */

    # Setup PMP Region 0 TOR all rights
    li t0, PMP_ADDR0
    srli t0, t0, 2     # Note: addr should be shifted by 2
    csrw pmpaddr0, t0

    # Setup PMP config 
    li t0, PMP_CONFIG
    csrw pmpcfg0, t0

    mret

gigue_int_start:
    .incbin "bin/int.bin"

gigue_jit_start:
    .incbin "bin/jit.bin"

.section .data
gigue_jit_data: 
    .incbin "bin/data.bin"

gigue_ss_start:
    .incbin "bin/ss.bin"

gigue_ss_end: