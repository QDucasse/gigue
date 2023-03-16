from typing import Dict

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


# Instruction masks
OP7_MASK = 0x0000007F
OP7_OP3_MASK = 0x0000707F
OP7_OP3_TOP7_MASK = 0xFE000707F
OP7_OP3_TOP6_MASK = 0xFC000707F
FULL_MASK = 0xFFFFFFFF


class InstructionInfo:
    def __init__(
        self,
        name: str,
        opcode7: int,
        opcode3: int,
        instr_type: str,
        top7: int = 0,
        cmp_mask: int = OP7_OP3_TOP7_MASK,
    ):
        self.name: str = name
        self.opcode7: int = opcode7
        self.opcode3: int = opcode3
        self.top7: int = top7
        self.instr_type: str = instr_type
        self.cmp_mask = cmp_mask
        self.cmp_val = (
            self.opcode7 + (self.opcode3 << 12) + (self.top7 << 25)
        ) & self.cmp_mask


class ExceptionInstructionInfo(InstructionInfo):
    def __init__(self, imm, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.imm = imm
        self.cmp_val = (
            self.opcode7 + (self.opcode3 << 12) + (self.imm << 20)
        ) & self.cmp_mask


class CustomInstructionInfo(InstructionInfo):
    def __init__(
        self,
        name: str,
        custom_nb: int,
        xd: int = 0,
        xs1: int = 0,
        xs2: int = 0,
        top7: int = 0,
        cmp_mask: int = OP7_OP3_TOP7_MASK,
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
            cmp_mask=cmp_mask,
        )


INSTRUCTIONS_INFO: Dict[str, InstructionInfo] = {
    # Adds
    "add": InstructionInfo("add", 0b0110011, 0b000, "R", cmp_mask=OP7_OP3_TOP7_MASK),
    "addi": InstructionInfo("addi", 0b0010011, 0b000, "I", cmp_mask=OP7_OP3_MASK),
    "addiw": InstructionInfo("addiw", 0b0011011, 0b000, "I", cmp_mask=OP7_OP3_MASK),
    "addw": InstructionInfo("addw", 0b0111011, 0b000, "R", cmp_mask=OP7_OP3_TOP7_MASK),
    # Ands
    "andr": InstructionInfo("andr", 0b0110011, 0b111, "R", cmp_mask=OP7_OP3_TOP7_MASK),
    "andi": InstructionInfo("andi", 0b0010011, 0b111, "I", cmp_mask=OP7_OP3_MASK),
    # Add upp imm to PC
    "auipc": InstructionInfo("auipc", 0b0010111, 0b000, "U", cmp_mask=OP7_MASK),
    # Branches
    "beq": InstructionInfo("beq", 0b1100011, 0b000, "B", cmp_mask=OP7_OP3_MASK),
    "bge": InstructionInfo("bge", 0b1100011, 0b101, "B", cmp_mask=OP7_OP3_MASK),
    "bgeu": InstructionInfo("bgeu", 0b1100011, 0b111, "B", cmp_mask=OP7_OP3_MASK),
    "blt": InstructionInfo("blt", 0b1100011, 0b100, "B", cmp_mask=OP7_OP3_MASK),
    "bltu": InstructionInfo("bltu", 0b1100011, 0b110, "B", cmp_mask=OP7_OP3_MASK),
    "bne": InstructionInfo("bne", 0b1100011, 0b001, "B", cmp_mask=OP7_OP3_MASK),
    # Jumps
    "jal": InstructionInfo("jal", 0b1101111, 0b000, "J", cmp_mask=OP7_MASK),
    "jalr": InstructionInfo("jalr", 0b1100111, 0b000, "I", cmp_mask=OP7_OP3_MASK),
    # Loads
    "lb": InstructionInfo("lb", 0b0000011, 0b000, "I", cmp_mask=OP7_OP3_MASK),
    "lbu": InstructionInfo("lbu", 0b0000011, 0b100, "I", cmp_mask=OP7_OP3_MASK),
    "ld": InstructionInfo("ld", 0b0000011, 0b011, "I", cmp_mask=OP7_OP3_MASK),
    "lh": InstructionInfo("lh", 0b0000011, 0b001, "I", cmp_mask=OP7_OP3_MASK),
    "lhu": InstructionInfo("lhu", 0b0000011, 0b101, "I", cmp_mask=OP7_OP3_MASK),
    "lw": InstructionInfo("lw", 0b0000011, 0b010, "I", cmp_mask=OP7_OP3_MASK),
    "lwu": InstructionInfo("lwu", 0b0000011, 0b110, "I", cmp_mask=OP7_OP3_MASK),
    # Load upper immediate
    "lui": InstructionInfo("lui", 0b0110111, 0b000, "U", cmp_mask=OP7_MASK),
    # Muls
    "mul": InstructionInfo(
        "mul", 0b0110011, 0b000, "R", 0b0000001, cmp_mask=OP7_OP3_TOP7_MASK
    ),
    "mulh": InstructionInfo(
        "mulh", 0b0110011, 0b001, "R", 0b0000001, cmp_mask=OP7_OP3_TOP7_MASK
    ),
    "mulhsu": InstructionInfo(
        "mulhsu", 0b0110011, 0b010, "R", 0b0000001, cmp_mask=OP7_OP3_TOP7_MASK
    ),
    "mulhu": InstructionInfo(
        "mulhu", 0b0110011, 0b011, "R", 0b0000001, cmp_mask=OP7_OP3_TOP7_MASK
    ),
    "mulw": InstructionInfo(
        "mulw", 0b0111011, 0b000, "R", 0b0000001, cmp_mask=OP7_OP3_TOP7_MASK
    ),
    # Ors
    "orr": InstructionInfo("orr", 0b0110011, 0b110, "R", cmp_mask=OP7_OP3_TOP7_MASK),
    "ori": InstructionInfo("ori", 0b0010011, 0b110, "I", cmp_mask=OP7_OP3_MASK),
    # Stores
    "sb": InstructionInfo("sb", 0b0100011, 0b000, "S", cmp_mask=OP7_OP3_MASK),
    "sd": InstructionInfo("sd", 0b0100011, 0b011, "S", cmp_mask=OP7_OP3_MASK),
    "sh": InstructionInfo("sh", 0b0100011, 0b001, "S", cmp_mask=OP7_OP3_MASK),
    "sw": InstructionInfo("sw", 0b0100011, 0b010, "S", cmp_mask=OP7_OP3_MASK),
    # Logical shift left
    "sll": InstructionInfo("sll", 0b0110011, 0b001, "R", cmp_mask=OP7_OP3_TOP6_MASK),
    "slli": InstructionInfo("slli", 0b0010011, 0b001, "I", cmp_mask=OP7_OP3_TOP6_MASK),
    "slliw": InstructionInfo(
        "slliw", 0b0011011, 0b001, "I", cmp_mask=OP7_OP3_TOP6_MASK
    ),
    "sllw": InstructionInfo("sllw", 0b0111011, 0b001, "R", cmp_mask=OP7_OP3_TOP6_MASK),
    # Set if
    "slt": InstructionInfo("slt", 0b0110011, 0b010, "R", cmp_mask=OP7_OP3_TOP7_MASK),
    "slti": InstructionInfo("slti", 0b0010011, 0b010, "I", cmp_mask=OP7_OP3_MASK),
    "sltiu": InstructionInfo("sltiu", 0b0010011, 0b011, "I", cmp_mask=OP7_OP3_MASK),
    "sltu": InstructionInfo("sltu", 0b0110011, 0b011, "R", cmp_mask=OP7_OP3_TOP7_MASK),
    # Arithmetic shift right
    # Note (srai, sraiw) the top7 here is used on top of the shift immediate
    "sra": InstructionInfo(
        "sra", 0b0110011, 0b101, "R", 0b0100000, cmp_mask=OP7_OP3_TOP6_MASK
    ),
    "srai": InstructionInfo(
        "srai", 0b0010011, 0b101, "I", 0b0100000, cmp_mask=OP7_OP3_TOP6_MASK
    ),
    "sraiw": InstructionInfo(
        "sraiw", 0b0011011, 0b101, "I", 0b0100000, cmp_mask=OP7_OP3_TOP6_MASK
    ),
    "sraw": InstructionInfo(
        "sraw", 0b0111011, 0b101, "R", 0b0100000, cmp_mask=OP7_OP3_TOP6_MASK
    ),
    # Logical shift right
    "srl": InstructionInfo("srl", 0b0110011, 0b101, "R", cmp_mask=OP7_OP3_TOP6_MASK),
    "srli": InstructionInfo("srli", 0b0010011, 0b101, "I", cmp_mask=OP7_OP3_TOP6_MASK),
    "srliw": InstructionInfo(
        "srliw", 0b0011011, 0b101, "I", cmp_mask=OP7_OP3_TOP6_MASK
    ),
    "srlw": InstructionInfo("srlw", 0b0111011, 0b101, "R", cmp_mask=OP7_OP3_TOP6_MASK),
    # Subs
    "sub": InstructionInfo(
        "sub", 0b0110011, 0b000, "R", 0b0100000, cmp_mask=OP7_OP3_TOP7_MASK
    ),
    "subw": InstructionInfo(
        "subw", 0b0111011, 0b000, "R", 0b0100000, cmp_mask=OP7_OP3_TOP7_MASK
    ),
    # Note: subi is performed with addi!
    # Xors
    "xor": InstructionInfo("xor", 0b0110011, 0b100, "R", cmp_mask=OP7_OP3_TOP7_MASK),
    "xori": InstructionInfo("xori", 0b0010011, 0b100, "I", cmp_mask=OP7_OP3_MASK),
    # Exceptions
    "ebreak": ExceptionInstructionInfo(
        1, "ebreak", 0b1110011, 0b000, "I", cmp_mask=FULL_MASK
    ),
    "ecall": ExceptionInstructionInfo(
        0, "ecall", 0b1110011, 0b000, "I", cmp_mask=FULL_MASK
    ),
    # Custom
    "custom-0": InstructionInfo(
        "custom-0", 0b0001011, 0b000, "R", cmp_mask=OP7_OP3_TOP7_MASK
    ),
    "custom-1": InstructionInfo(
        "custom-1", 0b0101011, 0b000, "R", cmp_mask=OP7_OP3_TOP7_MASK
    ),
    "custom-2": InstructionInfo(
        "custom-2", 0b1011011, 0b000, "R", cmp_mask=OP7_OP3_TOP7_MASK
    ),
    "custom-3": InstructionInfo(
        "custom-3", 0b1111011, 0b000, "R", cmp_mask=OP7_OP3_TOP7_MASK
    ),
    # Note: opcode3 is set at 0 by default but should be redefined by the subclasses!
}


if __name__ == "__main__":
    print(INSTRUCTIONS_INFO["addi"].opcode3)
