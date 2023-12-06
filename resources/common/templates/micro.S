# This assembly file includes the raw binaries for interpreter and jit, the data and shadow stack space

.global main

.section .text

main:
    .incbin "bin/unit.bin" # Include the bytes for the unit test
    li a0, 0               # Pass 0 to the exit function
    call exit              # 