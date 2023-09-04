from typing import Dict

from gigue.constants import OPCODE_FUNC3_MASK, InstructionInfo

RIMI_SSP_REG: int = 28  # t3
SHADOW_STACK_SIZE: int = 100 * 8


OPCODES_RIMI: Dict[str, int] = {
    "OP_LOAD1": 0b0011111,
    "OP_LOADSS": 0b0001111,
    "OP_STORE1": 0b0111111,
    "OP_STORESS": 0b0111011,
    "OP_CHDOM": 0b1110111,
    "OP_RETDOM": 0b1111111,
}

OPCODES_NAMES_RIMI: Dict[int, str] = dict(
    (value, key) for (key, value) in OPCODES_RIMI.items()
)

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
        opcode=OPCODES_RIMI["OP_LOAD1"],
        funct3=0b000,
        instr_type="I",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "lbu1": InstructionInfo(
        name="lbu1",
        opcode=OPCODES_RIMI["OP_LOAD1"],
        funct3=0b100,
        instr_type="I",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "lh1": InstructionInfo(
        name="lh1",
        opcode=OPCODES_RIMI["OP_LOAD1"],
        funct3=0b001,
        instr_type="I",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "lhu1": InstructionInfo(
        name="lhu1",
        opcode=OPCODES_RIMI["OP_LOAD1"],
        funct3=0b101,
        instr_type="I",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "lw1": InstructionInfo(
        name="lw1",
        opcode=OPCODES_RIMI["OP_LOAD1"],
        funct3=0b010,
        instr_type="I",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "lwu1": InstructionInfo(
        name="lwu1",
        opcode=OPCODES_RIMI["OP_LOAD1"],
        funct3=0b110,
        instr_type="I",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "ld1": InstructionInfo(
        name="ld1",
        opcode=OPCODES_RIMI["OP_LOAD1"],
        funct3=0b011,
        instr_type="I",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    # Duplicated stores
    "sb1": InstructionInfo(
        name="sb1",
        opcode=OPCODES_RIMI["OP_STORE1"],
        funct3=0b000,
        instr_type="S",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "sh1": InstructionInfo(
        name="sh1",
        opcode=OPCODES_RIMI["OP_STORE1"],
        funct3=0b001,
        instr_type="S",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "sw1": InstructionInfo(
        name="sw1",
        opcode=OPCODES_RIMI["OP_STORE1"],
        funct3=0b010,
        instr_type="S",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "sd1": InstructionInfo(
        name="sd1",
        opcode=OPCODES_RIMI["OP_STORE1"],
        funct3=0b011,
        instr_type="S",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    # Domain switching routines
    "chdom": InstructionInfo(
        name="chdom",
        opcode=OPCODES_RIMI["OP_CHDOM"],
        funct3=0b000,
        instr_type="I",
        instr_class="branching",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "retdom": InstructionInfo(
        name="retdom",
        opcode=OPCODES_RIMI["OP_RETDOM"],
        funct3=0b000,
        instr_type="I",
        instr_class="branching",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    # Shadow stack instructions
    "ss": InstructionInfo(
        name="ss",
        opcode=OPCODES_RIMI["OP_STORESS"],
        funct3=0b011,
        instr_type="S",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "ls": InstructionInfo(
        name="ls",
        opcode=OPCODES_RIMI["OP_LOADSS"],
        funct3=0b011,
        instr_type="I",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
}
