from gigue.fixer.constants import FIXER_INSTRUCTIONS_INFO
from gigue.instructions import CustomInstruction


class FIXERCustomInstruction(CustomInstruction):
    CUSTOM_INSTRUCTIONS_INFO = FIXER_INSTRUCTIONS_INFO

    @classmethod
    def cficall(cls, rd, rs1, rs2):
        return cls.custom_instr("cficall", rd, rs1, rs2)

    @classmethod
    def cfiret(cls, rd, rs1, rs2):
        return cls.custom_instr("cfiret", rd, rs1, rs2)
