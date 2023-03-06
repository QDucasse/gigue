from typing import Dict
from typing import Optional

# [R, I, U, J, B, stores, loads]
INSTRUCTION_WEIGHTS = [25, 30, 10, 5, 10, 10, 10]

# Register info
CALLER_SAVED_REG = [5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17, 28, 29, 30, 31]
CALLEE_SAVED_REG = [8, 9, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27]

# RISCV shortcuts
RA = 1
SP = 2

# Paths
BIN_DIR = "bin/"

# PICs info
HIT_CASE_REG = 5
CMP_REG = 6

# Data info
DATA_REG = 31
DATA_SIZE = 0x100


class InstructionInfo:
    def __init__(
        self,
        name: str,
        opcode7: int,
        opcode3: Optional[int],
        instr_type: str,
        top7: Optional[int] = 0,
    ):
        self.name: str = name
        self.opcode7: int = opcode7
        self.opcode3: Optional[int] = opcode3
        self.top7: Optional[int] = top7
        self.instr_type: str = instr_type


class CustomInstructionInfo(InstructionInfo):
    def __init__(
        self,
        name: str,
        custom_nb: int,
        xd: int = 0,
        xs1: int = 0,
        xs2: int = 0,
        top7: int = 0,
    ):
        custom_instr_info = INSTRUCTIONS_INFO["custom-" + str(custom_nb)]
        opcode7 = custom_instr_info.opcode7
        opcode3 = (xd << 2) + (xs1 << 1) + xs2
        self.xd = xd
        self.xs1 = xs1
        self.xs2 = xs2
        instr_type = custom_instr_info.instr_type
        super().__init__(
            name=name,
            opcode7=opcode7,
            opcode3=opcode3,
            instr_type=instr_type,
            top7=top7,
        )


def find_instr_for_opcode(opcode):
    for info in INSTRUCTIONS_INFO.values():
        if info.opcode7 == opcode:
            return info


INSTRUCTIONS_INFO: Dict[str, InstructionInfo] = {
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
    "lwu": InstructionInfo("lwu", 0b0000011, 0b110, "I"),
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
    "sh": InstructionInfo("sh", 0b0100011, 0b001, "S"),
    "sw": InstructionInfo("sw", 0b0100011, 0b010, "S"),
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
    # Breakpoint
    "ebreak": InstructionInfo("ebreak", 0b1110011, 0b000, "I"),
    # Custom
    "custom-0": InstructionInfo("custom-0", 0b0001011, None, "R"),
    "custom-1": InstructionInfo("custom-1", 0b0101011, None, "R"),
    "custom-2": InstructionInfo("custom-2", 0b1011011, None, "R"),
    "custom-3": InstructionInfo("custom-3", 0b1111011, None, "R"),
}


if __name__ == "__main__":
    print(INSTRUCTIONS_INFO["addi"].opcode3)
