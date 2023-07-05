# This assembly file includes the raw binaries for interpreter and jit, the data and shadow stack space

.global main
.global gigue_jit_start
.global gigue_int_start
.global ss_start
.global ss_end


# Note: The 0 bits correspond to the MPP field, responsible 
# of the mode selection (0b00 for U, 0b01 for S and 0b11 for M)
.equiv MASK_MPP_USER_MODE, 0xFFFFE7FF

# DMP Config for this setup
# region0: domain 0  -> 0b00  - interpreter
# region1: domain 1  -> 0b01  - jit code      
# region2: domain 1  -> 0b01  - jit data      
# region3: domain 2  -> 0b10  - shadow stack 
# region4: inclusive -> 0b11  - main stack
# Or when concatenated: 0b(00)11_1001_0100 > 0x394

.equiv DMP_CONFIG, 0x0000000000000394

.equiv DMP_CODE, 0x3f0

.equiv CURDOM_CODE, 0x3f1

.section .text

dmp_setup:
    # Setup DMP 
    # \__________
    li t0, DMP_CONFIG
    csrrw x0, DMP_CODE, t0
    # Note: equivalent of csrw dmpcfg, t0

    # Setup current domain
    # \_____________________
    csrrw x0, CURDOM_CODE, x0
    # Note: equivalent of csrw dmpcfg, t0
    
    ret

main:
    la t6, tab             # Load the data address in t6
    la t3, ss_end          # Load the shadow stack address in t3 (grows downwards)
    call dmp_setup         # call simple dmp
    .incbin "bin/unit.bin" # Include the bytes for the unit test
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