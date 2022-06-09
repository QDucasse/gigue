from gigue.constants import instructions_info


class Instruction:
    def __init__(self, name, opcode7):
        self.name = name
        self.opcode7 = opcode7
        self.machine_instruction = 0

    def generate(self):
        raise NotImplementedError("Please Implement this method")


class R_Instruction(Instruction):
    def __init__(self, name, opcode7, opcode3, rd, rs1, rs2):
        super().__init__(name, opcode7)
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

    @classmethod
    def r_instr(cls, name, rd, rs1, rs2):
        return cls(name, instructions_info[name].opcode7, instructions_info[name].opcode3, rd, rs1, rs2)

    @classmethod
    def add(cls, rd, rs1, rs2):
        return cls.r_instr("add", rd, rs1, rs2)


class I_Instruction(Instruction):
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

    @classmethod
    def i_instr(cls, name, rd, rs1, imm):
        return cls(name, instructions_info[name].opcode7, instructions_info[name].opcode3, rd, rs1, imm)

    @classmethod
    def addi(cls, rd, rs1, imm):
        return cls.i_instr("addi", rd, rs1, imm)


if __name__ == "__main__":
    add = R_Instruction.add(rd=5, rs1=6, rs2=7)
    add.generate()
    print(add)
    print(add.__dict__)

    addi = I_Instruction.addi(rd=5, rs1=6, imm=255)
    addi.generate()
    print(addi)
    print(addi.__dict__)
    # print(hex(instr.machine_instruction))
