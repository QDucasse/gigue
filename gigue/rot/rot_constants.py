from __future__ import annotations

from typing import Dict

from gigue.constants import OPCODE_FUNC3_FUNC6_MASK, OPCODES, InstructionInfo

ROT_INSTRUCTIONS_INFO: Dict[str, InstructionInfo] = {
    # Register rotations
    "rol": InstructionInfo(
        name="rol",
        opcode=OPCODES["OP_OP"],
        funct3=0b001,
        funct7=0b0110000,
        instr_type="R",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_FUNC6_MASK,
    ),
    "ror": InstructionInfo(
        name="ror",
        opcode=OPCODES["OP_OP"],
        funct3=0b101,
        funct7=0b0110000,
        instr_type="R",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_FUNC6_MASK,
    ),
    # Immediate rotations
    "rori": InstructionInfo(
        name="rori",
        opcode=OPCODES["OP_OP_IMM"],
        funct3=0b101,
        funct7=0b011000,
        instr_type="I",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_FUNC6_MASK,
    ),
    # Note: no roli as it can be encoded with a negative immediate
}
