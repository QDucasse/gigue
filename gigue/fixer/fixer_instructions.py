from __future__ import annotations

from typing import TYPE_CHECKING, Dict

from gigue.fixer.fixer_constants import FIXER_INSTRUCTIONS_INFO
from gigue.instructions import CustomInstruction

if TYPE_CHECKING:
    from gigue.constants import CustomInstructionInfo


class FIXERCustomInstruction(CustomInstruction):
    CUSTOM_INSTRUCTIONS_INFO: Dict[str, CustomInstructionInfo] = FIXER_INSTRUCTIONS_INFO

    @classmethod
    def cficall(cls, rd: int, rs1: int, rs2: int) -> CustomInstruction:
        return cls.custom_instr("cficall", rd, rs1, rs2)

    @classmethod
    def cfiret(cls, rd: int, rs1: int, rs2: int) -> CustomInstruction:
        return cls.custom_instr("cfiret", rd, rs1, rs2)
