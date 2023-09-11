from __future__ import annotations

from typing import Dict

from gigue.constants import OPCODES, RoCCCustomInstructionInfo

FIXER_CMP_REG: int = 28  # t3

FIXER_INSTRUCTIONS_INFO: Dict[str, RoCCCustomInstructionInfo] = {
    # CFI tags
    "cficall": RoCCCustomInstructionInfo(
        name="cficall",
        opcode=OPCODES["OP_CUSTOM0"],
        xd=0,
        xs1=1,
        xs2=0,
        funct7=0b0000000,
        instr_type="R",
        instr_class="fixer",
    ),
    "cfiret": RoCCCustomInstructionInfo(
        name="cfiret",
        opcode=OPCODES["OP_CUSTOM0"],
        xd=1,
        xs1=0,
        xs2=0,
        funct7=0b0000001,
        instr_type="R",
        instr_class="fixer",
    ),
}
