from gigue.instructions import IInstruction, RInstruction
from gigue.rot.rot_constants import ROT_INSTRUCTIONS_INFO


class RotIInstruction(IInstruction):
    @classmethod
    def i_instr(cls, name, rd, rs1, imm):
        return cls(
            name,
            ROT_INSTRUCTIONS_INFO[name].opcode,
            ROT_INSTRUCTIONS_INFO[name].funct3,
            rd,
            rs1,
            imm,
            ROT_INSTRUCTIONS_INFO[name].funct7,
        )

    @classmethod
    def rori(cls, rd, rs1, imm):
        return cls.i_instr("rori", rd, rs1, imm)


class RotRInstruction(RInstruction):
    @classmethod
    def i_instr(cls, name, rd, rs1, rs2):
        return cls(
            name,
            ROT_INSTRUCTIONS_INFO[name].opcode,
            ROT_INSTRUCTIONS_INFO[name].funct3,
            rd,
            rs1,
            rs2,
            ROT_INSTRUCTIONS_INFO[name].funct7,
        )

    @classmethod
    def rol(cls, rd, rs1, rs2):
        return cls.r_instr("rori", rd, rs1, rs2)

    @classmethod
    def ror(cls, rd, rs1, rs2):
        return cls.r_instr("rori", rd, rs1, rs2)
