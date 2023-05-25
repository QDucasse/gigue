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
    def ls(cls, rd, rs1, imm):
        return cls.i_instr("ls", rd, rs1, imm)

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
    def ss(cls, rs1, rs2, imm):
        return cls.s_instr("ss", rs1, rs2, imm)


if __name__ == "__main__":
    # instructions = [
    #     # Base loads/stores in a correct domain
    #     IInstruction.lw(rd=30, rs1=5, imm=0),
    #     SInstruction.sw(rs1=5, rs2=30, imm=0),
    #     # Duplicated load/store in a correct domain
    #     RIMIIInstruction.lw1(rd=31, rs1=6, imm=0),
    #     RIMISInstruction.sw1(rs1=6, rs2=30, imm=0),
    #     # Base load/store in an incorrect domain
    #     IInstruction.lw(rd=30, rs1=6, imm=0),
    #     SInstruction.sw(rs1=6, rs2=30, imm=0),
    #     # Duplicated load/store in an incorrect domain
    #     RIMIIInstruction.lw1(rd=31, rs1=5, imm=0),
    #     RIMISInstruction.sw1(rs1=5, rs2=30, imm=0),
    # ]

    # bytes = b"".join([instr.generate_bytes() for instr in instructions])

    # with open("bin/rimi.bin", "bw") as file:
    #   file.write(bytes)

    instrs = [
        RIMIIInstruction.lb1(0, 0, 0),
        RIMIIInstruction.lbu1(0, 0, 0),
        RIMIIInstruction.lh1(0, 0, 0),
        RIMIIInstruction.lhu1(0, 0, 0),
        RIMIIInstruction.lw1(0, 0, 0),
        RIMIIInstruction.lwu1(0, 0, 0),
        RIMIIInstruction.ld1(0, 0, 0),

        RIMISInstruction.sb1(0, 0, 0),
        RIMISInstruction.sh1(0, 0, 0),
        RIMISInstruction.sw1(0, 0, 0),
        RIMISInstruction.sd1(0, 0, 0),

        RIMIIInstruction.ls(0, 0, 0),
        RIMISInstruction.ss(0, 0, 0),

        RIMIIInstruction.chdom(0, 0, 0),
        RIMIIInstruction.retdom(),
    ]

    for instr in instrs:
        print(f"def {instr.name.upper(): <19} = BitPat(\"{instr.rocket_display(RIMI_INSTRUCTIONS_INFO)}\")")
