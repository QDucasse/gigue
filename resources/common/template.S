# This assembly file includes the raw binary

    .global gigue_start
gigue_start:
    .incbin "bin/out.bin"

    .global gigue_end
gigue_end:

    .global gigue_size
gigue_size:
    .int gigue_end - gigue_start

    .global main
main:
    la t6, tab             # Load the data address in t6
    call gigue_start       # Call the generated binary
    j exit
    
    # addi    a7, x0, 93     # Set ecall to exit (93) function
    # ecall                  # Call linux to terminate the program

.section .data
tab: 
    .incbin "bin/data.bin"