from typing import Dict

from gigue.constants import OPCODE_FUNC3_MASK, OPCODES, InstructionInfo

RIMI_SSP_REG: int = 28  # t3
SHADOW_STACK_SIZE: int = 100 * 8


OP_LOAD1 = OPCODES["OP_CUSTOM0"]
OP_STORE1 = OPCODES["OP_CUSTOM1"]
OP_DOMCHG = OPCODES["OP_CUSTOM2"]


RIMI_INSTRUCTIONS_INFO: Dict[str, InstructionInfo] = {
    # Duplicated loads
    "lb1": InstructionInfo(
        name="lb1",
        opcode=OP_LOAD1,
        funct3=0b000,
        instr_type="I",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "lbu1": InstructionInfo(
        name="lbu1",
        opcode=OP_LOAD1,
        funct3=0b100,
        instr_type="I",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "lh1": InstructionInfo(
        name="lh1",
        opcode=OP_LOAD1,
        funct3=0b001,
        instr_type="I",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "lhu1": InstructionInfo(
        name="lhu1",
        opcode=OP_LOAD1,
        funct3=0b101,
        instr_type="I",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "lw1": InstructionInfo(
        name="lw1",
        opcode=OP_LOAD1,
        funct3=0b010,
        instr_type="I",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "lwu1": InstructionInfo(
        name="lwu1",
        opcode=OP_LOAD1,
        funct3=0b110,
        instr_type="I",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "ld1": InstructionInfo(
        name="ld1",
        opcode=OP_LOAD1,
        funct3=0b011,
        instr_type="I",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    # Duplicated stores
    "sb1": InstructionInfo(
        name="sb1",
        opcode=OP_STORE1,
        funct3=0b000,
        instr_type="S",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "sh1": InstructionInfo(
        name="sh1",
        opcode=OP_STORE1,
        funct3=0b001,
        instr_type="S",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "sw1": InstructionInfo(
        name="sw1",
        opcode=OP_STORE1,
        funct3=0b010,
        instr_type="S",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "sd1": InstructionInfo(
        name="sd1",
        opcode=OP_STORE1,
        funct3=0b011,
        instr_type="S",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    # Domain switching routines
    "chdom": InstructionInfo(
        name="chdom",
        opcode=OP_DOMCHG,
        funct3=0b001,
        instr_type="I",
        instr_class="branching",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "retdom": InstructionInfo(
        name="retdom",
        opcode=OP_DOMCHG,
        funct3=0b000,
        instr_type="I",
        instr_class="branching",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    # Shadow stack instructions
    "ss": InstructionInfo(
        name="ss",
        opcode=OP_STORE1,
        funct3=0b111,
        instr_type="S",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "ls": InstructionInfo(
        name="ls",
        opcode=OP_LOAD1,
        funct3=0b111,
        instr_type="I",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
}
