# This assembly file includes the raw binary

    .global gigue_start
gigue_start:
    .incbin "bin/out.bin"

    .global gigue_end
gigue_end:

    .global gigue_size
gigue_size:
    .int gigue_end - gigue_start


; .text.startup:
    .global main
main:
    call gigue_start
    j exit