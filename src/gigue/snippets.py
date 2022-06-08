import abc


class Instruction(abc.ABC):
    def __init__(self, opcode7):
        self.opcode7 = opcode7
        self.machine_instruction = 0

    def extract_info(self, size, shift):
        mask = (1 << size) - 1
        return (self.machine_instruction & (mask << shift)) >> shift

    def disassemble(self):
        disa_instr = "Disassembled Instruction:\n"
        disa_instr += "opcode: {}\n".format(str(bin(self.extract_info(7, 0))))
        return disa_instr

    @abc.abstractmethod
    def generate(self):
        raise NotImplementedError("Please Implement this method")


class R_Instruction(Instruction):
    def __init__(self, opcode7, opcode3, rd, rs1, rs2):
        super().__init__(opcode7)
        self.rd = rd
        self.rs1 = rs1
        self.rs2 = rs2
        self.opcode3 = opcode3

    def generate(self):
        self.machine_instruction = self.opcode7
        self.machine_instruction |= self.rd << 7
        self.machine_instruction |= self.opcode3 << 12
        self.machine_instruction |= self.rs1 << 15
        self.machine_instruction |= self.rs2 << 20

    def disassemble(self):
        disa_instr = super().disassemble()
        disa_instr += "opcode3: {}\n".format(str(bin(self.extract_info(3, 12))))
        disa_instr += "rd: {}\n".format(str(self.extract_info(5, 7)))
        disa_instr += "rs1: {}\n".format(str(self.extract_info(5, 15)))
        disa_instr += "rs2: {}".format(str(self.extract_info(5, 20)))
        return disa_instr


class Add(R_Instruction):

    OPCODE7_ADD = 0b0110011
    OPCODE3_ADD = 0b000

    def __init__(self, rd, rs1, rs2):
        super().__init__(opcode7=Add.OPCODE7_ADD, opcode3=Add.OPCODE3_ADD, rd=rd, rs1=rs1, rs2=rs2)


if __name__ == "__main__":
    instr = Add(rd=5, rs1=6, rs2=7)
    instr.generate()
    print(hex(instr.machine_instruction))
    print(instr.disassemble())
