from __future__ import annotations

from typing import Dict

from gigue.constants import RoCCCustomInstructionInfo

FIXER_CMP_REG: int = 28  # t3

FIXER_INSTRUCTIONS_INFO: Dict[str, RoCCCustomInstructionInfo] = {
    # CFI tags
    "cficall": RoCCCustomInstructionInfo(
        name="cficall", custom_nb=0, xd=0, xs1=1, xs2=0, funct7=0b0000000
    ),
    "cfiret": RoCCCustomInstructionInfo(
        name="cfiret", custom_nb=0, xd=1, xs1=0, xs2=0, funct7=0b0000001
    ),
}
