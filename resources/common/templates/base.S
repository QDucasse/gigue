# This assembly file includes the raw binaries for interpreter and jit, the data and shadow stack space

.global main
.global umode_setup
.global gigue_jit_start
.global gigue_int_start
.global ss_start
.global ss_end

#define PMP_ADDR0 0xc0000000
#define PMP_CONFIG 0x000000000000000f
#define MASK_MPP_USER_MODE 0xffffe7ff

.section .text


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

    # Setup PMP Region 0: Domain 0 Code pt1 (TOR)
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

main:
    la t6, tab             # Load the data address in t6
    la t3, ss_end          # Load the shadow stack address in t3 (grows downwards)
    call umode_setup       # Pass in user mode
    li a0, 0               # Pass 0 to the exit function
    call exit              # 
    
    # addi    a7, x0, 93     # Set ecall to exit (93) function
    # ecall                  # Call linux to terminate the program

.section .data
tab: 
    .incbin "bin/data.bin"

ss_start:
    .incbin "bin/ss.bin"

ss_end: