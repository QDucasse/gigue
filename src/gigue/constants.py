# [R, I, U, J, B]
INSTRUCTION_WEIGHTS = [35, 40, 10, 5, 10]
CALLER_SAVED_REG = [5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17, 28, 29, 30, 31]
CALLEE_SAVED_REG = [8, 9, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27]
RA = 1
SP = 2
BIN_DIR = "bin/"


class InstructionInfo:
    def __init__(self, name, opcode7, opcode3, instr_type, top7=0):
        self.name = name
        self.opcode7 = opcode7
        self.opcode3 = opcode3
        self.top7 = top7
        self.instr_type = instr_type


def find_instr_for_opcode(opcode):
    for info in INSTRUCTIONS_INFO.values():
        if info.opcode7 == opcode:
            return info


INSTRUCTIONS_INFO = {
    # Adds
    "add": InstructionInfo("add", 0b0110011, 0b000, "R"),
    "addi": InstructionInfo("addi", 0b0010011, 0b000, "I"),
    "addiw": InstructionInfo("addiw", 0b0011011, 0b000, "I"),
    "addw": InstructionInfo("addw", 0b0111011, 0b000, "R"),
    # Ands
    "andr": InstructionInfo("andr", 0b0110011, 0b111, "R"),
    "andi": InstructionInfo("andi", 0b0010011, 0b111, "I"),
    # Add upp imm to PC
    "auipc": InstructionInfo("auipc", 0b0010111, 0b000, "U"),
    # Branches
    "beq": InstructionInfo("beq", 0b1100011, 0b000, "B"),
    "bge": InstructionInfo("bge", 0b1100011, 0b101, "B"),
    "bgeu": InstructionInfo("bgeu", 0b1100011, 0b111, "B"),
    "blt": InstructionInfo("blt", 0b1100011, 0b100, "B"),
    "bltu": InstructionInfo("bltu", 0b1100011, 0b110, "B"),
    "bne": InstructionInfo("bne", 0b1100011, 0b001, "B"),
    # Jumps
    "jal": InstructionInfo("jal", 0b1101111, 0b000, "J"),
    "jalr": InstructionInfo("jalr", 0b1100111, 0b000, "I"),
    # Loads
    "lb": InstructionInfo("lb", 0b0000011, 0b000, "I"),
    "lbu": InstructionInfo("lbu", 0b0000011, 0b100, "I"),
    "ld": InstructionInfo("ld", 0b0000011, 0b011, "I"),
    "lh": InstructionInfo("lh", 0b0000011, 0b001, "I"),
    "lhu": InstructionInfo("lhu", 0b0000011, 0b101, "I"),
    "lw": InstructionInfo("lw", 0b0000011, 0b010, "I"),
    # Load upper immediate
    "lui": InstructionInfo("lui", 0b0110111, 0b000, "U"),
    # Muls
    "mul": InstructionInfo("mul", 0b0110011, 0b000, "R", 0b0000001),
    "mulh": InstructionInfo("mulh", 0b0110011, 0b001, "R", 0b0000001),
    "mulhsu": InstructionInfo("mulhsu", 0b0110011, 0b010, "R", 0b0000001),
    "mulhu": InstructionInfo("mulhu", 0b0110011, 0b011, "R", 0b0000001),
    "mulw": InstructionInfo("mulw", 0b0111011, 0b000, "R", 0b0000001),
    # Ors
    "orr": InstructionInfo("orr", 0b0110011, 0b110, "R"),
    "ori": InstructionInfo("ori", 0b0010011, 0b110, "I"),
    # Stores
    "sb": InstructionInfo("sb", 0b0100011, 0b000, "S"),
    "sd": InstructionInfo("sd", 0b0100011, 0b011, "S"),
    "sh": InstructionInfo("sb", 0b0100011, 0b001, "S"),
    "sw": InstructionInfo("sb", 0b0100011, 0b010, "S"),
    # Logical shift left
    "sll": InstructionInfo("sll", 0b0110011, 0b001, "R"),
    "slli": InstructionInfo("slli", 0b0010011, 0b001, "I"),
    "slliw": InstructionInfo("slliw", 0b0011011, 0b001, "I"),
    "sllw": InstructionInfo("sllw", 0b0111011, 0b001, "R"),
    # Set if
    "slt": InstructionInfo("slt", 0b0110011, 0b010, "R"),
    "slti": InstructionInfo("slti", 0b0010011, 0b010, "I"),
    "sltiu": InstructionInfo("sltiu", 0b0010011, 0b011, "I"),
    "sltu": InstructionInfo("sltu", 0b0110011, 0b011, "R"),
    # Arithmetic shift right
    # Note (srai, sraiw) the top7 here is used on top of the shift immediate
    "sra": InstructionInfo("sra", 0b0110011, 0b101, "R", 0b0100000),
    "srai": InstructionInfo("srai", 0b0010011, 0b101, "I", 0b0100000),
    "sraiw": InstructionInfo("sraiw", 0b0011011, 0b101, "I", 0b0100000),
    "sraw": InstructionInfo("sraw", 0b0111011, 0b101, "R", 0b0100000),
    # Logical shift right
    "srl": InstructionInfo("srl", 0b0110011, 0b101, "R"),
    "srli": InstructionInfo("srli", 0b0010011, 0b101, "I"),
    "srliw": InstructionInfo("srliw", 0b0011011, 0b101, "I"),
    "srlw": InstructionInfo("srlw", 0b0111011, 0b101, "R"),
    # Subs
    "sub": InstructionInfo("sub", 0b0110011, 0b000, "R", 0b0100000),
    "subw": InstructionInfo("subw", 0b0111011, 0b000, "R", 0b0100000),
    # Note: subi is performed with addi!
    # Xors
    "xor": InstructionInfo("xor", 0b0110011, 0b100, "R"),
    "xori": InstructionInfo("xori", 0b0010011, 0b100, "I"),
}


if __name__ == "__main__":
    print(INSTRUCTIONS_INFO["addi"].opcode3)
