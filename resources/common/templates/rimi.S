# This assembly file includes the raw binaries for interpreter and jit, the data and shadow stack space
#
# PMP config registers contains 4 8-bit configs that consist of:
#   7  6  5 4   3  2   1   0
# | L | 00 |  A  | X | W | R
# with: 
# L (lock), X (execute), W (write), R (read) 
# A matching mode (0-OFF, 1-TOR, 2-NA4, 3-NAPOT)

# Note:
# - TOR means Top-of-range, will match an address A between 
#   pmpaddr(i-1) <= A < pmpaddr(i) 
# - NAPOT means Naturally aligned power-of-two, will match an address A  
#   using a base address and a size embedded in the address
#
# The memory layout of all tests is the following:
# 
# ╔══════════════════╦═══════════════════╗  low address          ╔══════════════╗
# ║ //////////////// ║                   ║                       ║ Interpreter  ║
# ║ // DOM 0 CODE // ║ PMP0 - RX - TOR   ║═══╗                   ║    Domain    ║
# ║ //////////////// ║                   ║   ║ TOR points here   ║              ║
# ╠═ -------------- ═╬═ --------------- ═╣   ║                   ╠══════════════╣
# ║    DOM 0 TRAMP   ║ PMP0 - RX -  TOR  ║   ║                   ║  Call Tramp  ║
# ╠══════════════════╬═══════════════════╣<══╝                   ╠══════════════╣
# ║    DOM 1 CODE    ║ PMP1 - RX -  TOR  ║═══╗                   ║  JIT Code    ║
# ╠══════════════════╬═══════════════════╣<══╝ TOR points here   ╠══════════════╣
# ║    DOM 1 DATA    ║ PMP2 - RW -  TOR  ║                       ║  JIT Data    ║
# ╠══════════════════╬═══════════════════╣                       ╠══════════════╣
# ║    DOM 2 DATA    ║ PMP3 - RW -  TOR  ║═══╗                   ║ Shadow Stack ║
# ╠══════════════════╬═══════════════════╣<══╝ TOR points here   ╠══════════════╣
# ║ //////////////// ║                   ║                       ║              ║
# ║ // DOM 0 DATA // ║ PMP4 - RW - TOR   ║═══╗                   ║  Main Stack  ║
# ║ //////////////// ║                   ║   ║ TOR points here   ║              ║
# ╠══════════════════╬═══════════════════╣<══╝                   ╠══════════════╣
# ╚══════════════════╩═══════════════════╝  high address         ╚══════════════╝
# 
# From linker script:
# _dom0_code_start = 0x80000000;
# _dom1_code_start = 0x80004000;
# _dom1_data_start = 0x80005000;
# _dom0_data_start = 0x80006000;
# _dom2_data_start = 0x80007000;

.global main
# .global umode_setup
# .global gigue_jit_start
# .global gigue_int_start
# .global gigue_jit_data
# .global gigue_ss_start
# .global gigue_ss_end

# PMP Region 0: Interpreter code + call trampoline (domain 0)
#define PMP_ADDR0 gigue_jit_start
# > PMPCFG0: 0x0f or 0b0_00_01_1_1_1
# Unlocked TOR RWX - | L 00 A  X W R |
# > DMPCFG0: 0x8 or 0b1_0_00
#   Locked Domain0 -| L 0 DOM | 
# Note: needs RWX because tohost is at address 080001000
# Note2: not properly working when moving it into data0

# PMP Region 1: JIT code (domain 1)
#define PMP_ADDR1 gigue_jit_data
# > PMPCFG1:  0x8d or 0b1_00_01_1_0_1 
#   Locked TOR RX  -  | L 00 A  X W R |
# > DMPCFG1: 0x9 or 0b1_0_01
#   Locked Domain1 -| L 0 DOM | 

# PMP Region 2: JIT data (domain 1)
#define PMP_ADDR2 gigue_ss_start
# > PMPCFG2: 0x8b or 0b1_00_01_0_1_1
#   Locked TOR RW  - | L 00 A  X W R |
# > DMPCFG2: 0x9 or 0b1_0_01
#   Locked Domain1 -| L 0 DOM | 

# PMP Region 3: Shadow Stack (domain 2)
#define PMP_ADDR3 gigue_ss_end
# > PMPCFG5:  0x8b or 0b0_00_11_0_1_1
#   Locked TOR RW   - | L 00 A  X W R |
# > DMPCFG5: 0xa or 0b1_0_10
#   Locked Domain2 -| L 0 DOM | 

# PMP Region 4: Domain 0 Data pt2 (TOR)
#define PMP_ADDR4 0x800000000000
# > PMPCFG6: 0x0b or 0b0_00_01_0_1_1
#  Unocked TOR RW  - | L 00 A  X W R |
# > DMPCFG6: 0x8 or 0b1_0_00
#   Locked Domain0 -| L 0 DOM | 

# Concatenation of the pmpcfg/dmpcfg:
# Locking only dom1/dom2, fully locking domains
#define PMP_CONFIG 0x0000000b8b8b8d0f
#define DMP_CONFIG 0x000000000008a998
# Fully locked version
# #define PMP_CONFIG 0x008b9b8b8d9b9d8f
# #define DMP_CONFIG 0x0000000008a88998
# Unlocked version
# #define PMP_CONFIG 0x000b1b0b0d1b1d0f
# #define DMP_CONFIG 0x0000000000200110

# All inclusive, no locks
# | L 00 A  X W R | PMPCFG
# | 0 00 01 1 1 1 | 0x0f  <- TOR all inclusive
# | 0 00 11 1 1 1 | 0x1f  <- NAPOT all inclusive
# | L 0 DOM |       DMPCFG
# | 0 0  11 |       0x3
# #define PMP_CONFIG 0x000f1f0f0f1f1f0f
# #define DMP_CONFIG 0x0000000003333333

# Small test
# #define PMP_CONFIG 0x000000000000000f
# #define DMP_CONFIG 0x0000000000000000

.section .text

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

    # Setup PMP Region 0: Interpreter Code + call trampoline (TOR)
    la t0, PMP_ADDR0
    srli t0, t0, 2     # Note: addr should be shifted by 2
    csrw pmpaddr0, t0

    # Setup PMP Region 1: JIT Code (TOR)
    la t0, PMP_ADDR1
    srli t0, t0, 2     # Note: addr should be shifted by 2
    csrw pmpaddr1, t0

    # Setup PMP Region 2: JIT Data (TOR)
    la t0, PMP_ADDR2
    srli t0, t0, 2     # Note: addr should be shifted by 2
    csrw pmpaddr2, t0

    # Setup PMP Region 3: Shadow Stack (TOR)
    la t0, PMP_ADDR3
    srli t0, t0, 2     # Note: addr should be shifted by 2
    csrw pmpaddr3, t0

    # Setup PMP Region 4: Base data (TOR)
    li t0, PMP_ADDR4
    srli t0, t0, 2     # Note: addr should be shifted by 2
    csrw pmpaddr4, t0

    # Setup PMP config 
    li t0, PMP_CONFIG
    csrw pmpcfg0, t0

    /* DMP CSR setup
    _____________________ */

    # Setup DMP config 
    li t0, DMP_CONFIG
    csrw dmpcfg0, t0

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