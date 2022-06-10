from gigue.constants import instructions_info


# TODO: Doc
class Instruction:
    def __init__(self, name, opcode7, top7=0):
        self.name = name
        self.opcode7 = opcode7
        self.top7 = top7
        self.machine_instruction = 0

    def generate(self):
        raise NotImplementedError("Please Implement this method")


# TODO: Doc
class RInstruction(Instruction):
    def __init__(self, name, opcode7, opcode3, rd, rs1, rs2, top7=0):
        super().__init__(name, opcode7, top7)
        self.opcode3 = opcode3
        self.rd = rd
        self.rs1 = rs1
        self.rs2 = rs2

    def generate(self):
        self.machine_instruction = self.opcode7
        self.machine_instruction |= self.rd << 7
        self.machine_instruction |= self.opcode3 << 12
        self.machine_instruction |= self.rs1 << 15
        self.machine_instruction |= self.rs2 << 20
        self.machine_instruction |= self.top7 << 25
        return self.machine_instruction

    @classmethod
    def r_instr(cls, name, rd, rs1, rs2):
        return cls(name, instructions_info[name].opcode7,
                   instructions_info[name].opcode3, rd, rs1, rs2)

    # TODO: Autogenerate?
    @classmethod
    def add(cls, rd, rs1, rs2):
        return cls.r_instr("add", rd, rs1, rs2)

    @classmethod
    def addw(cls, rd, rs1, rs2):
        return cls.r_instr("addw", rd, rs1, rs2)

    @classmethod
    def andr(cls, rd, rs1, rs2):
        return cls.r_instr("andr", rd, rs1, rs2)

    @classmethod
    def mul(cls, rd, rs1, rs2):
        return cls.r_instr("mul", rd, rs1, rs2)

    @classmethod
    def mulh(cls, rd, rs1, rs2):
        return cls.r_instr("mulh", rd, rs1, rs2)

    @classmethod
    def mulhsu(cls, rd, rs1, rs2):
        return cls.r_instr("mulhsu", rd, rs1, rs2)

    @classmethod
    def mulhu(cls, rd, rs1, rs2):
        return cls.r_instr("mulhu", rd, rs1, rs2)

    @classmethod
    def mulw(cls, rd, rs1, rs2):
        return cls.r_instr("mulw", rd, rs1, rs2)

    @classmethod
    def orr(cls, rd, rs1, rs2):
        return cls.r_instr("orr", rd, rs1, rs2)

    @classmethod
    def sll(cls, rd, rs1, rs2):
        return cls.r_instr("sll", rd, rs1, rs2)

    @classmethod
    def sllw(cls, rd, rs1, rs2):
        return cls.r_instr("sllw", rd, rs1, rs2)

    @classmethod
    def slt(cls, rd, rs1, rs2):
        return cls.r_instr("slt", rd, rs1, rs2)

    @classmethod
    def sltu(cls, rd, rs1, rs2):
        return cls.r_instr("sltu", rd, rs1, rs2)

    @classmethod
    def sra(cls, rd, rs1, rs2):
        return cls.r_instr("sra", rd, rs1, rs2)

    @classmethod
    def sraw(cls, rd, rs1, rs2):
        return cls.r_instr("sraw", rd, rs1, rs2)

    @classmethod
    def srl(cls, rd, rs1, rs2):
        return cls.r_instr("srl", rd, rs1, rs2)

    @classmethod
    def srlw(cls, rd, rs1, rs2):
        return cls.r_instr("srlw", rd, rs1, rs2)

    @classmethod
    def sub(cls, rd, rs1, rs2):
        return cls.r_instr("sub", rd, rs1, rs2)

    @classmethod
    def subw(cls, rd, rs1, rs2):
        return cls.r_instr("subw", rd, rs1, rs2)

    @classmethod
    def xor(cls, rd, rs1, rs2):
        return cls.r_instr("xor", rd, rs1, rs2)


# TODO: Doc
class IInstruction(Instruction):
    def __init__(self, name, opcode7, opcode3, rd, rs1, imm):
        super().__init__(name, opcode7)
        self.opcode3 = opcode3
        self.rd = rd
        self.rs1 = rs1
        self.imm = imm

    def generate(self):
        self.machine_instruction = self.opcode7
        self.machine_instruction |= self.rd << 7
        self.machine_instruction |= self.opcode3 << 12
        self.machine_instruction |= self.rs1 << 15
        self.machine_instruction |= self.imm << 20
        return self.machine_instruction

    @classmethod
    def i_instr(cls, name, rd, rs1, imm):
        return cls(name, instructions_info[name].opcode7,
                   instructions_info[name].opcode3, rd, rs1, imm)

    # TODO: Autogenerate
    @classmethod
    def addi(cls, rd, rs1, imm):
        return cls.i_instr("addi", rd, rs1, imm)

    @classmethod
    def addiw(cls, rd, rs1, imm):
        return cls.i_instr("addiw", rd, rs1, imm)

    @classmethod
    def andi(cls, rd, rs1, imm):
        return cls.i_instr("andi", rd, rs1, imm)

    @classmethod
    def jalr(cls, rd, rs1, imm):
        return cls.i_instr("jalr", rd, rs1, imm)

    @classmethod
    def lb(cls, rd, rs1, imm):
        return cls.i_instr("lb", rd, rs1, imm)

    @classmethod
    def lbu(cls, rd, rs1, imm):
        return cls.i_instr("lbu", rd, rs1, imm)

    @classmethod
    def ld(cls, rd, rs1, imm):
        return cls.i_instr("ld", rd, rs1, imm)

    @classmethod
    def lh(cls, rd, rs1, imm):
        return cls.i_instr("lh", rd, rs1, imm)

    @classmethod
    def lhu(cls, rd, rs1, imm):
        return cls.i_instr("lhu", rd, rs1, imm)

    @classmethod
    def ori(cls, rd, rs1, imm):
        return cls.i_instr("ori", rd, rs1, imm)

    @classmethod
    def slli(cls, rd, rs1, imm):
        return cls.i_instr("slli", rd, rs1, imm)

    @classmethod
    def slliw(cls, rd, rs1, imm):
        return cls.i_instr("slliw", rd, rs1, imm)

    @classmethod
    def slti(cls, rd, rs1, imm):
        return cls.i_instr("slti", rd, rs1, imm)

    @classmethod
    def sltiu(cls, rd, rs1, imm):
        return cls.i_instr("sltiu", rd, rs1, imm)

    @classmethod
    def srai(cls, rd, rs1, imm):
        return cls.i_instr("srai", rd, rs1, imm)

    @classmethod
    def sraiw(cls, rd, rs1, imm):
        return cls.i_instr("sraiw", rd, rs1, imm)

    @classmethod
    def srli(cls, rd, rs1, imm):
        return cls.i_instr("srli", rd, rs1, imm)

    @classmethod
    def srliw(cls, rd, rs1, imm):
        return cls.i_instr("srliw", rd, rs1, imm)

    @classmethod
    def xori(cls, rd, rs1, imm):
        return cls.i_instr("xori", rd, rs1, imm)


# TODO: Doc
class UInstruction(Instruction):
    def __init__(self, name, opcode7, rd, imm):
        super().__init__(name, opcode7)
        self.rd = rd
        self.imm = imm

    def generate(self):
        self.machine_instruction = self.opcode7
        self.machine_instruction |= self.rd << 7
        self.machine_instruction |= self.imm & 0xFFFFF000
        return self.machine_instruction

    @classmethod
    def u_instr(cls, name, rd, imm):
        return cls(name, instructions_info[name].opcode7, rd, imm)

    # TODO: Autogenerate
    @classmethod
    def auipc(cls, rd, imm):
        return cls.u_instr("auipc", rd, imm)

    @classmethod
    def lui(cls, rd, imm):
        return cls.u_instr("lui", rd, imm)


# TODO: Doc
class JInstruction(Instruction):
    def __init__(self, name, opcode7, rd, imm):
        super().__init__(name, opcode7)
        self.rd = rd
        self.imm = imm

    def shuffle_imm(self):
        # imm[20 | 10:1 | 11 | 19:12]
        shuffle = ((self.imm >> 20) & 0x1) << 19   # 20th bit
        shuffle |= ((self.imm >> 1) & 0x3FF) << 9  # 10th to 1st
        shuffle |= ((self.imm >> 11) & 0x1) << 8    # 11th bit
        shuffle |= ((self.imm >> 12) & 0xFF)        # 12th to 19th
        return shuffle

    def generate(self):
        self.machine_instruction = self.opcode7
        self.machine_instruction |= self.rd << 7
        self.machine_instruction |= self.shuffle_imm() << 12
        return self.machine_instruction

    @classmethod
    def j_instr(cls, name, rd, imm):
        return cls(name, instructions_info[name].opcode7, rd, imm)

    # TODO: Autogenerate
    @classmethod
    def jal(cls, rd, imm):
        return cls.j_instr("jal", rd, imm)


# TODO: Doc
class SInstruction(Instruction):
    def __init__(self, name, opcode7, opcode3, rs1, rs2, imm):
        super().__init__(name, opcode7)
        self.opcode3 = opcode3
        self.rs1 = rs1
        self.rs2 = rs2
        self.imm = imm

    def generate(self):
        self.machine_instruction = self.opcode7
        self.machine_instruction |= (self.imm & 0x1F) << 7
        self.machine_instruction |= self.opcode3 << 12
        self.machine_instruction |= self.rs1 << 15
        self.machine_instruction |= self.rs2 << 20
        self.machine_instruction |= ((self.imm & 0xFE0) >> 5) << 25
        return self.machine_instruction

    @classmethod
    def s_instr(cls, name, rs1, rs2, imm):
        return cls(name, instructions_info[name].opcode7,
                   instructions_info[name].opcode3, rs1, rs2, imm)

    # TODO: Autogenerate
    @classmethod
    def sb(cls, rs1, rs2, imm):
        return cls.s_instr("sb", rs1, rs2, imm)

    @classmethod
    def sh(cls, rs1, rs2, imm):
        return cls.s_instr("sh", rs1, rs2, imm)

    @classmethod
    def sw(cls, rs1, rs2, imm):
        return cls.s_instr("sw", rs1, rs2, imm)

    @classmethod
    def sd(cls, rs1, rs2, imm):
        return cls.s_instr("sd", rs1, rs2, imm)


# TODO: Doc
class BInstruction(Instruction):
    def __init__(self, name, opcode7, opcode3, rs1, rs2, imm):
        super().__init__(name, opcode7)
        self.opcode3 = opcode3
        self.rs1 = rs1
        self.rs2 = rs2
        self.imm = imm

    def shuffle_imm(self):
        # imm1: imm[12|10:5]
        shuffle1 = ((self.imm >> 12) & 0x1) << 6   # 12th bit
        shuffle1 |= ((self.imm >> 5) & 0x3F)       # 10th to 5th
        # imm2: imm[4:1|11]
        shuffle2 = ((self.imm >> 1) & 0xF) << 1   # 4th to 1st
        shuffle2 |= ((self.imm >> 11) & 0x1)       # 11th
        return shuffle1, shuffle2

    def generate(self):
        shuffle1, shuffle2 = self.shuffle_imm()
        self.machine_instruction = self.opcode7
        self.machine_instruction |= shuffle2 << 7
        self.machine_instruction |= self.opcode3 << 12
        self.machine_instruction |= self.rs1 << 15
        self.machine_instruction |= self.rs2 << 20
        self.machine_instruction |= shuffle1 << 25
        return self.machine_instruction

    @classmethod
    def b_instr(cls, name, rs1, rs2, imm):
        return cls(name, instructions_info[name].opcode7,
                   instructions_info[name].opcode3, rs1, rs2, imm)

    @classmethod
    def beq(cls, rs1, rs2, imm):
        return cls.b_instr("beq", rs1, rs2, imm)

    @classmethod
    def bge(cls, rs1, rs2, imm):
        return cls.b_instr("bge", rs1, rs2, imm)

    @classmethod
    def bgeu(cls, rs1, rs2, imm):
        return cls.b_instr("bgeu", rs1, rs2, imm)

    @classmethod
    def blt(cls, rs1, rs2, imm):
        return cls.b_instr("blt", rs1, rs2, imm)

    @classmethod
    def bltu(cls, rs1, rs2, imm):
        return cls.b_instr("bltu", rs1, rs2, imm)

    @classmethod
    def bne(cls, rs1, rs2, imm):
        return cls.b_instr("bne", rs1, rs2, imm)


if __name__ == "__main__":
    add = RInstruction.add(rd=5, rs1=6, rs2=7)
    add.generate()
    print(add)
    print(add.__dict__)

    addi = IInstruction.addi(rd=5, rs1=6, imm=1234)
    addi.generate()
    print(addi)
    print(addi.__dict__)
    # print(hex(instr.machine_instruction))
