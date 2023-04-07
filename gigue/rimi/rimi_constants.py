from typing import Dict

from gigue.constants import OPCODE_FUNC3_MASK, InstructionInfo

RIMI_SHADOW_STACK_REG: int = 28  # t3
RIMI_DATA_REG_D1: int = 29  # t4

RIMI_INSTRUCTIONS_INFO: Dict[str, InstructionInfo] = {
    # Rules to choose opcodes:
    # - loads:       All op7 are changed from 0b0000011 > 0b0011111 | mask 0b0011100
    # - stores:      All op7 are changed from 0b0100011 > 0b0111111 | mask 0b0011100
    # - dom changes:          chdom           0b1100111 > 0b1110111 | mask 0b0010000
    #                         retdom          0b1100111 > 0b1111111 | mask 0b0011000
    # ______________________________________________________________________________
    # Duplicated loads
    "lb1": InstructionInfo(
        name="lb1",
        opcode=0b0011111,
        funct3=0b000,
        instr_type="I",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "lbu1": InstructionInfo(
        name="lbu1",
        opcode=0b0011111,
        funct3=0b100,
        instr_type="I",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "lh1": InstructionInfo(
        name="lh1",
        opcode=0b0011111,
        funct3=0b001,
        instr_type="I",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "lhu1": InstructionInfo(
        name="lhu1",
        opcode=0b0011111,
        funct3=0b101,
        instr_type="I",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "lw1": InstructionInfo(
        name="lw1",
        opcode=0b0011111,
        funct3=0b010,
        instr_type="I",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "lwu1": InstructionInfo(
        name="lwu1",
        opcode=0b0011111,
        funct3=0b110,
        instr_type="I",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "ld1": InstructionInfo(
        name="ld1",
        opcode=0b0011111,
        funct3=0b011,
        instr_type="I",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    # Duplicated stores
    "sb1": InstructionInfo(
        name="sb1",
        opcode=0b0111111,
        funct3=0b000,
        instr_type="S",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "sh1": InstructionInfo(
        name="sh1",
        opcode=0b0111111,
        funct3=0b001,
        instr_type="S",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "sw1": InstructionInfo(
        name="sw1",
        opcode=0b0111111,
        funct3=0b010,
        instr_type="S",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "sd1": InstructionInfo(
        name="sd1",
        opcode=0b0111111,
        funct3=0b011,
        instr_type="S",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    # Domain switching routines
    "chdom": InstructionInfo(
        name="chdom",
        opcode=0b1110111,
        funct3=0b000,
        instr_type="I",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "retdom": InstructionInfo(
        name="retdom",
        opcode=0b1111111,
        funct3=0b000,
        instr_type="I",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    # Shadow stack instructions
    "ss": InstructionInfo(
        name="ss",
        opcode=0b0111111,
        funct3=0b111,
        instr_type="S",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "ls": InstructionInfo(
        name="ls",
        opcode=0b0011111,
        funct3=0b111,
        instr_type="I",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
}
