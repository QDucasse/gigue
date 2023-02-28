from gigue.instructions import IInstruction
from gigue.instructions import SInstruction
from gigue.rimi.constants import RIMI_INSTRUCTIONS_INFO


class RIMIIInstruction(IInstruction):

    @classmethod
    def i_instr(cls, name, rd, rs1, imm):
        return cls(
            name,
            RIMI_INSTRUCTIONS_INFO[name].opcode7,
            RIMI_INSTRUCTIONS_INFO[name].opcode3,
            rd,
            rs1,
            imm,
            RIMI_INSTRUCTIONS_INFO[name].top7,
        )

    @classmethod
    def lw1(cls, rd, rs1, imm):
        return cls.i_instr("lw1", rd, rs1, imm)


class RIMISInstruction(SInstruction):

    @classmethod
    def s_instr(cls, name, rs1, rs2, imm):
        return cls(
            name,
            RIMI_INSTRUCTIONS_INFO[name].opcode7,
            RIMI_INSTRUCTIONS_INFO[name].opcode3,
            rs1,
            rs2,
            imm,
        )

    @classmethod
    def sw1(cls, rs1, rs2, imm):
        return cls.s_instr("sw1", rs1, rs2, imm)
