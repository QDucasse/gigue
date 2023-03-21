from gigue.constants import OP7_OP3_MASK, InstructionInfo

RIMI_SHADOW_STACK_REG = 28  # t3
RIMI_DATA_REG_D1 = 29  # t4

RIMI_INSTRUCTIONS_INFO = {
    # Rules to choose opcodes:
    # - loads:       All op7 are changed from 0b0000011 > 0b0011111 | mask 0b0011100
    # - stores:      All op7 are changed from 0b0100011 > 0b0111111 | mask 0b0011100
    # - dom changes:          chdom           0b1100111 > 0b1110111 | mask 0b0010000
    #                         retdom          0b1100111 > 0b1111111 | mask 0b0011000
    # ______________________________________________________________________________
    # Duplicated loads
    "lb1": InstructionInfo("lb1", 0b0011111, 0b000, "I", cmp_mask=OP7_OP3_MASK),
    "lbu1": InstructionInfo("lbu1", 0b0011111, 0b100, "I", cmp_mask=OP7_OP3_MASK),
    "lh1": InstructionInfo("lh1", 0b0011111, 0b001, "I", cmp_mask=OP7_OP3_MASK),
    "lhu1": InstructionInfo("lhu1", 0b0011111, 0b101, "I", cmp_mask=OP7_OP3_MASK),
    "lw1": InstructionInfo("lw1", 0b0011111, 0b010, "I", cmp_mask=OP7_OP3_MASK),
    "lwu1": InstructionInfo("lwu1", 0b0011111, 0b110, "I", cmp_mask=OP7_OP3_MASK),
    "ld1": InstructionInfo("ld1", 0b0011111, 0b011, "I", cmp_mask=OP7_OP3_MASK),
    # Duplicated stores
    "sb1": InstructionInfo("sb1", 0b0111111, 0b000, "S", cmp_mask=OP7_OP3_MASK),
    "sh1": InstructionInfo("sh1", 0b0111111, 0b001, "S", cmp_mask=OP7_OP3_MASK),
    "sw1": InstructionInfo("sw1", 0b0111111, 0b010, "S", cmp_mask=OP7_OP3_MASK),
    "sd1": InstructionInfo("sd1", 0b0111111, 0b011, "S", cmp_mask=OP7_OP3_MASK),
    # Domain switching routines
    "chdom": InstructionInfo("chdom", 0b1110111, 0b000, "I", cmp_mask=OP7_OP3_MASK),
    "retdom": InstructionInfo("retdom", 0b1111111, 0b000, "I", cmp_mask=OP7_OP3_MASK),
    # Shadow stack instructions
    "ss": InstructionInfo("ss", 0b0111111, 0b111, "S", cmp_mask=OP7_OP3_MASK),
    "ls": InstructionInfo("ls", 0b0011111, 0b111, "I", cmp_mask=OP7_OP3_MASK),
}
