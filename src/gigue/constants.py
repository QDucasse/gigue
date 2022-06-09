
class InstructionInfo:

    def __init__(self, name, opcode7, opcode3, instr_type):
        self.name = name
        self.opcode7 = opcode7
        self.opcode3 = opcode3
        self.instr_type = instr_type


def find_instr_for_opcode(opcode):
    for info in instructions_info.values():
        if info.opcode7 == opcode:
            return info.instr_type


instructions_info = {
    "add": InstructionInfo("add", 0b0110011, 0b000, "R"),
    "addi": InstructionInfo("addi", 0b0010011, 0b000, "I"),
    "addiw": InstructionInfo("addiw", 0b0011011, 0b000, "I"),
    "addw": InstructionInfo("addw", 0b0111011, 0b000, "R"),
}


if __name__ == "__main__":
    print(instructions_info["addi"].opcode3)
