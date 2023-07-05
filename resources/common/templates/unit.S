# This assembly file includes the raw binaries for interpreter and jit, the data and shadow stack space

.global main
.global ss_start
.global ss_end

main:
    la t6, tab             # Load the data address in t6
    la t3, ss_end          # Load the shadow stack address in t3 (grows downwards)
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