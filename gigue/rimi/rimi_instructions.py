from gigue.instructions import IInstruction, SInstruction
from gigue.rimi.rimi_constants import RIMI_INSTRUCTIONS_INFO


class RIMIIInstruction(IInstruction):
    @classmethod
    def i_instr(cls, name, rd, rs1, imm):
        return cls(
            name,
            RIMI_INSTRUCTIONS_INFO[name].opcode,
            RIMI_INSTRUCTIONS_INFO[name].funct3,
            rd,
            rs1,
            imm,
            RIMI_INSTRUCTIONS_INFO[name].funct7,
        )

    @classmethod
    def lb1(cls, rd, rs1, imm):
        return cls.i_instr("lb1", rd, rs1, imm)

    @classmethod
    def lbu1(cls, rd, rs1, imm):
        return cls.i_instr("lbu1", rd, rs1, imm)

    @classmethod
    def lh1(cls, rd, rs1, imm):
        return cls.i_instr("lh1", rd, rs1, imm)

    @classmethod
    def lhu1(cls, rd, rs1, imm):
        return cls.i_instr("lhu1", rd, rs1, imm)

    @classmethod
    def lw1(cls, rd, rs1, imm):
        return cls.i_instr("lw1", rd, rs1, imm)

    @classmethod
    def lwu1(cls, rd, rs1, imm):
        return cls.i_instr("lwu1", rd, rs1, imm)

    @classmethod
    def ld1(cls, rd, rs1, imm):
        return cls.i_instr("ld1", rd, rs1, imm)

    @classmethod
    def lst(cls, rd, rs1, imm):
        return cls.i_instr("lst", rd, rs1, imm)

    @classmethod
    def chdom(cls, rd, rs1, imm):
        return cls.i_instr("chdom", rd, rs1, imm)

    @classmethod
    def retdom(cls):
        return cls.i_instr("retdom", 0, 1, 0)


class RIMISInstruction(SInstruction):
    @classmethod
    def s_instr(cls, name, rs1, rs2, imm):
        return cls(
            name,
            RIMI_INSTRUCTIONS_INFO[name].opcode,
            RIMI_INSTRUCTIONS_INFO[name].funct3,
            rs1,
            rs2,
            imm,
        )

    @classmethod
    def sb1(cls, rs1, rs2, imm):
        return cls.s_instr("sb1", rs1, rs2, imm)

    @classmethod
    def sh1(cls, rs1, rs2, imm):
        return cls.s_instr("sh1", rs1, rs2, imm)

    @classmethod
    def sw1(cls, rs1, rs2, imm):
        return cls.s_instr("sw1", rs1, rs2, imm)

    @classmethod
    def sd1(cls, rs1, rs2, imm):
        return cls.s_instr("sd1", rs1, rs2, imm)

    @classmethod
    def sst(cls, rs1, rs2, imm):
        return cls.s_instr("sst", rs1, rs2, imm)
