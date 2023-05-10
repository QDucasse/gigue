from typing import Dict, List

# Instruction Weights
# \___________________

# [R, I, U, J, B, stores, loads]
INSTRUCTION_WEIGHTS: List[int] = [25, 30, 10, 5, 10, 10, 10]

# Registers and aliases
# \_____________________

# Register lists
# https://en.wikichip.org/wiki/risc-v/registers
CALLER_SAVED_REG: List[int] = [5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17, 28, 29, 30, 31]
CALLEE_SAVED_REG: List[int] = [8, 9, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27]

# RISCV aliases
X0: int = 0
RA: int = 1
SP: int = 2
T0: int = 5
T1: int = 6
T2: int = 7

# PICs info
HIT_CASE_REG: int = T0
CMP_REG: int = T1

# Binary path
# \____________

BIN_DIR: str = "bin/"

# Data generation
# \_______________

DATA_REG: int = 31
DATA_SIZE: int = 0x100


# Comparison masks
# \________________

# Instruction masks
OPCODE_MASK: int = 0x0000007F
OPCODE_FUNC3_MASK: int = 0x0000707F
OPCODE_FUNC3_FUNC7_MASK: int = 0xFE000707F
OPCODE_FUNC3_FUNC6_MASK: int = 0xFC000707F
FENCE_MASK: int = 0xF00FFFFF
FULL_MASK: int = 0xFFFFFFFF

# Trampoline Generation
# \________________

# This one is only used as the cmp reg when calling a pic so should be ok!!
CALL_TMP_REG: int = 6

DEFAULT_TRAMPOLINES: List[str] = [
    "call_jit_elt",
    "ret_from_jit_elt",
]


class InstructionInfo:
    def __init__(
        self,
        name: str,
        opcode: int,
        funct3: int,
        instr_type: str,
        instr_class: str,
        funct7: int = 0,
        cmp_mask: int = OPCODE_FUNC3_FUNC7_MASK,
    ):
        self.name: str = name
        self.opcode: int = opcode
        self.funct3: int = funct3
        self.funct7: int = funct7
        self.instr_type: str = instr_type
        self.instr_class: str = instr_class
        self.cmp_mask: int = cmp_mask
        self.cmp_val: int = (
            self.opcode + (self.funct3 << 12) + (self.funct7 << 25)
        ) & self.cmp_mask


class ExceptionInstructionInfo(InstructionInfo):
    def __init__(self, imm: int, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.imm: int = imm
        self.cmp_val: int = (
            self.opcode + (self.funct3 << 12) + (self.imm << 20)
        ) & self.cmp_mask


class CustomInstructionInfo(InstructionInfo):
    def __init__(
        self,
        name: str,
        custom_nb: int,
        xd: int = 0,
        xs1: int = 0,
        xs2: int = 0,
        funct7: int = 0,
        cmp_mask: int = OPCODE_FUNC3_FUNC7_MASK,
    ):
        custom_instr_info: InstructionInfo = INSTRUCTIONS_INFO[
            "custom-" + str(custom_nb)
        ]
        opcode: int = custom_instr_info.opcode
        funct3: int = (xd << 2) + (xs1 << 1) + xs2
        self.xd: int = xd
        self.xs1: int = xs1
        self.xs2: int = xs2
        instr_type: str = custom_instr_info.instr_type
        instr_class: str = custom_instr_info.instr_class
        super().__init__(
            name=name,
            opcode=opcode,
            funct3=funct3,
            instr_type=instr_type,
            instr_class=instr_class,
            funct7=funct7,
            cmp_mask=cmp_mask,
        )


INSTRUCTIONS_INFO: Dict[str, InstructionInfo] = {
    # Adds
    "add": InstructionInfo(
        name="add",
        opcode=0b0110011,
        funct3=0b000,
        instr_type="R",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_FUNC7_MASK,
    ),
    "addi": InstructionInfo(
        name="addi",
        opcode=0b0010011,
        funct3=0b000,
        instr_type="I",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "addiw": InstructionInfo(
        name="addiw",
        opcode=0b0011011,
        funct3=0b000,
        instr_type="I",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "addw": InstructionInfo(
        name="addw",
        opcode=0b0111011,
        funct3=0b000,
        instr_type="R",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_FUNC7_MASK,
    ),
    # Ands
    "andr": InstructionInfo(
        name="andr",
        opcode=0b0110011,
        funct3=0b111,
        instr_type="R",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_FUNC7_MASK,
    ),
    "andi": InstructionInfo(
        name="andi",
        opcode=0b0010011,
        funct3=0b111,
        instr_type="I",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    # Add upp imm to PC
    "auipc": InstructionInfo(
        name="auipc",
        opcode=0b0010111,
        funct3=0b000,
        instr_type="U",
        instr_class="arithmetic",
        cmp_mask=OPCODE_MASK,
    ),
    # Branches
    "beq": InstructionInfo(
        name="beq",
        opcode=0b1100011,
        funct3=0b000,
        instr_type="B",
        instr_class="branching",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "bge": InstructionInfo(
        name="bge",
        opcode=0b1100011,
        funct3=0b101,
        instr_type="B",
        instr_class="branching",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "bgeu": InstructionInfo(
        name="bgeu",
        opcode=0b1100011,
        funct3=0b111,
        instr_type="B",
        instr_class="branching",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "blt": InstructionInfo(
        name="blt",
        opcode=0b1100011,
        funct3=0b100,
        instr_type="B",
        instr_class="branching",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "bltu": InstructionInfo(
        name="bltu",
        opcode=0b1100011,
        funct3=0b110,
        instr_type="B",
        instr_class="branching",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "bne": InstructionInfo(
        name="bne",
        opcode=0b1100011,
        funct3=0b001,
        instr_type="B",
        instr_class="branching",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    # Jumps
    "jal": InstructionInfo(
        name="jal",
        opcode=0b1101111,
        funct3=0b000,
        instr_type="J",
        instr_class="branching",
        cmp_mask=OPCODE_MASK,
    ),
    "jalr": InstructionInfo(
        name="jalr",
        opcode=0b1100111,
        funct3=0b000,
        instr_type="I",
        instr_class="branching",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    # Loads
    "lb": InstructionInfo(
        name="lb",
        opcode=0b0000011,
        funct3=0b000,
        instr_type="I",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "lbu": InstructionInfo(
        name="lbu",
        opcode=0b0000011,
        funct3=0b100,
        instr_type="I",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "ld": InstructionInfo(
        name="ld",
        opcode=0b0000011,
        funct3=0b011,
        instr_type="I",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "lh": InstructionInfo(
        name="lh",
        opcode=0b0000011,
        funct3=0b001,
        instr_type="I",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "lhu": InstructionInfo(
        name="lhu",
        opcode=0b0000011,
        funct3=0b101,
        instr_type="I",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "lw": InstructionInfo(
        name="lw",
        opcode=0b0000011,
        funct3=0b010,
        instr_type="I",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "lwu": InstructionInfo(
        name="lwu",
        opcode=0b0000011,
        funct3=0b110,
        instr_type="I",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    # Load upper immediate
    "lui": InstructionInfo(
        name="lui",
        opcode=0b0110111,
        funct3=0b000,
        instr_type="U",
        instr_class="arithmetic",
        cmp_mask=OPCODE_MASK,
    ),
    # Muls
    "mul": InstructionInfo(
        name="mul",
        opcode=0b0110011,
        funct3=0b000,
        instr_type="R",
        funct7=0b0000001,
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_FUNC7_MASK,
    ),
    "mulh": InstructionInfo(
        name="mulh",
        opcode=0b0110011,
        funct3=0b001,
        instr_type="R",
        instr_class="arithmetic",
        funct7=0b0000001,
        cmp_mask=OPCODE_FUNC3_FUNC7_MASK,
    ),
    "mulhsu": InstructionInfo(
        name="mulhsu",
        opcode=0b0110011,
        funct3=0b010,
        instr_type="R",
        instr_class="arithmetic",
        funct7=0b0000001,
        cmp_mask=OPCODE_FUNC3_FUNC7_MASK,
    ),
    "mulhu": InstructionInfo(
        name="mulhu",
        opcode=0b0110011,
        funct3=0b011,
        instr_type="R",
        instr_class="arithmetic",
        funct7=0b0000001,
        cmp_mask=OPCODE_FUNC3_FUNC7_MASK,
    ),
    "mulw": InstructionInfo(
        name="mulw",
        opcode=0b0111011,
        funct3=0b000,
        instr_type="R",
        instr_class="arithmetic",
        funct7=0b0000001,
        cmp_mask=OPCODE_FUNC3_FUNC7_MASK,
    ),
    # Ors
    "orr": InstructionInfo(
        name="orr",
        opcode=0b0110011,
        funct3=0b110,
        instr_type="R",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_FUNC7_MASK,
    ),
    "ori": InstructionInfo(
        name="ori",
        opcode=0b0010011,
        funct3=0b110,
        instr_type="I",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    # Stores
    "sb": InstructionInfo(
        name="sb",
        opcode=0b0100011,
        funct3=0b000,
        instr_type="S",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "sd": InstructionInfo(
        name="sd",
        opcode=0b0100011,
        funct3=0b011,
        instr_type="S",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "sh": InstructionInfo(
        name="sh",
        opcode=0b0100011,
        funct3=0b001,
        instr_type="S",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "sw": InstructionInfo(
        name="sw",
        opcode=0b0100011,
        funct3=0b010,
        instr_type="S",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    # Logical shift left
    "sll": InstructionInfo(
        name="sll",
        opcode=0b0110011,
        funct3=0b001,
        instr_type="R",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_FUNC6_MASK,
    ),
    "slli": InstructionInfo(
        name="slli",
        opcode=0b0010011,
        funct3=0b001,
        instr_type="I",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_FUNC6_MASK,
    ),
    "slliw": InstructionInfo(
        name="slliw",
        opcode=0b0011011,
        funct3=0b001,
        instr_type="I",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_FUNC6_MASK,
    ),
    "sllw": InstructionInfo(
        name="sllw",
        opcode=0b0111011,
        funct3=0b001,
        instr_type="R",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_FUNC6_MASK,
    ),
    # Set if
    "slt": InstructionInfo(
        name="slt",
        opcode=0b0110011,
        funct3=0b010,
        instr_type="R",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_FUNC7_MASK,
    ),
    "slti": InstructionInfo(
        name="slti",
        opcode=0b0010011,
        funct3=0b010,
        instr_type="I",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "sltiu": InstructionInfo(
        name="sltiu",
        opcode=0b0010011,
        funct3=0b011,
        instr_type="I",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "sltu": InstructionInfo(
        name="sltu",
        opcode=0b0110011,
        funct3=0b011,
        instr_type="R",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_FUNC7_MASK,
    ),
    # Arithmetic shift right
    # Note (srai, sraiw) the funct7 here is used on top of the shift immediate
    "sra": InstructionInfo(
        name="sra",
        opcode=0b0110011,
        funct3=0b101,
        instr_type="R",
        instr_class="arithmetic",
        funct7=0b0100000,
        cmp_mask=OPCODE_FUNC3_FUNC6_MASK,
    ),
    "srai": InstructionInfo(
        name="srai",
        opcode=0b0010011,
        funct3=0b101,
        instr_type="I",
        instr_class="arithmetic",
        funct7=0b0100000,
        cmp_mask=OPCODE_FUNC3_FUNC6_MASK,
    ),
    "sraiw": InstructionInfo(
        name="sraiw",
        opcode=0b0011011,
        funct3=0b101,
        instr_type="I",
        instr_class="arithmetic",
        funct7=0b0100000,
        cmp_mask=OPCODE_FUNC3_FUNC6_MASK,
    ),
    "sraw": InstructionInfo(
        name="sraw",
        opcode=0b0111011,
        funct3=0b101,
        instr_type="R",
        instr_class="arithmetic",
        funct7=0b0100000,
        cmp_mask=OPCODE_FUNC3_FUNC6_MASK,
    ),
    # Logical shift right
    "srl": InstructionInfo(
        name="srl",
        opcode=0b0110011,
        funct3=0b101,
        instr_type="R",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_FUNC6_MASK,
    ),
    "srli": InstructionInfo(
        name="srli",
        opcode=0b0010011,
        funct3=0b101,
        instr_type="I",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_FUNC6_MASK,
    ),
    "srliw": InstructionInfo(
        name="srliw",
        opcode=0b0011011,
        funct3=0b101,
        instr_type="I",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_FUNC6_MASK,
    ),
    "srlw": InstructionInfo(
        name="srlw",
        opcode=0b0111011,
        funct3=0b101,
        instr_type="R",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_FUNC6_MASK,
    ),
    # Subs
    "sub": InstructionInfo(
        name="sub",
        opcode=0b0110011,
        funct3=0b000,
        instr_type="R",
        instr_class="arithmetic",
        funct7=0b0100000,
        cmp_mask=OPCODE_FUNC3_FUNC7_MASK,
    ),
    "subw": InstructionInfo(
        name="subw",
        opcode=0b0111011,
        funct3=0b000,
        instr_type="R",
        instr_class="arithmetic",
        funct7=0b0100000,
        cmp_mask=OPCODE_FUNC3_FUNC7_MASK,
    ),
    # Note: subi is performed with addi!
    # Xors
    "xor": InstructionInfo(
        name="xor",
        opcode=0b0110011,
        funct3=0b100,
        instr_type="R",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_FUNC7_MASK,
    ),
    "xori": InstructionInfo(
        name="xori",
        opcode=0b0010011,
        funct3=0b100,
        instr_type="I",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    # Exceptions
    "ebreak": ExceptionInstructionInfo(
        imm=1,
        name="ebreak",
        opcode=0b1110011,
        funct3=0b000,
        instr_type="I",
        instr_class="internal",
        cmp_mask=FULL_MASK,
    ),
    "ecall": ExceptionInstructionInfo(
        imm=0,
        name="ecall",
        opcode=0b1110011,
        funct3=0b000,
        instr_type="I",
        instr_class="internal",
        cmp_mask=FULL_MASK,
    ),
    # Custom
    "custom-0": InstructionInfo(
        name="custom-0",
        opcode=0b0001011,
        funct3=0b000,
        instr_type="R",
        instr_class="custom",
        cmp_mask=OPCODE_FUNC3_FUNC7_MASK,
    ),
    "custom-1": InstructionInfo(
        name="custom-1",
        opcode=0b0101011,
        funct3=0b000,
        instr_type="R",
        instr_class="custom",
        cmp_mask=OPCODE_FUNC3_FUNC7_MASK,
    ),
    "custom-2": InstructionInfo(
        name="custom-2",
        opcode=0b1011011,
        funct3=0b000,
        instr_type="R",
        instr_class="custom",
        cmp_mask=OPCODE_FUNC3_FUNC7_MASK,
    ),
    "custom-3": InstructionInfo(
        name="custom-3",
        opcode=0b1111011,
        funct3=0b000,
        instr_type="R",
        instr_class="custom",
        cmp_mask=OPCODE_FUNC3_FUNC7_MASK,
    ),
    # Note: funct3 is set at 0 by default but should be redefined by the subclasses!
    # Internals
    # Note: Those instructions are not generated by Gigue but can be found in the
    #       Rocket log as they are used by the core helpers.
    "fence": InstructionInfo(
        name="fence",
        opcode=0b0001111,
        funct3=0b000,
        instr_type="I",
        instr_class="internal",
        cmp_mask=FENCE_MASK,
    ),
    "fence.i": InstructionInfo(
        name="fence.i",
        opcode=0b0001111,
        funct3=0b001,
        instr_type="I",
        instr_class="internal",
        cmp_mask=FULL_MASK,
    ),
    "csrrw": InstructionInfo(
        name="csrrw",
        opcode=0b1110011,
        funct3=0b001,
        instr_type="I",
        instr_class="internal",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "csrrs": InstructionInfo(
        name="csrrs",
        opcode=0b1110011,
        funct3=0b010,
        instr_type="I",
        instr_class="internal",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "csrrc": InstructionInfo(
        name="csrrc",
        opcode=0b1110011,
        funct3=0b011,
        instr_type="I",
        instr_class="internal",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "csrrwi": InstructionInfo(
        name="csrrwi",
        opcode=0b1110011,
        funct3=0b101,
        instr_type="I",
        instr_class="internal",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "csrrsi": InstructionInfo(
        name="csrrsi",
        opcode=0b1110011,
        funct3=0b110,
        instr_type="I",
        instr_class="internal",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "csrrci": InstructionInfo(
        name="csrrci",
        opcode=0b1110011,
        funct3=0b111,
        instr_type="I",
        instr_class="internal",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    # Debug
    "dret": InstructionInfo(
        name="dret",
        opcode=0b1110011,
        funct3=0b000,
        instr_type="I",
        instr_class="internal",
        cmp_mask=FULL_MASK,
    ),
}

# Aliases
INSTRUCTIONS_INFO_ALIASES = {
    # Reserved keyword
    "and": "andr",
    "or": "orr",
    # Jumps
    "ret": "jalr",
    "j": "jal",
    "jr": "jalr",
    # Load immediate (can extend to more!)
    "li": "addi",
    # Arithmetic
    "mv": "addi",
    "not": "xori",
    "nop": "addi",
    "seqz": "sltiu",
    "snez": "sltu",
    "sltz": "slt",
    "sgtz": "slt",
    # Branches
    "bgt": "blt",
    "ble": "bge",
    "bgtu": "bltu",
    "bleu": "bgeu",
    # Branches compare to 0
    "beqz": "beq",
    "bnez": "bne",
    "blez": "bge",
    "bgez": "bge",
    "bltz": "blt",
    "bgtz": "blt",
    # Internals
    "rdinstret": "csrrs",
    "rdcycle": "csrrs",
    "rdtime": "csrrs",
    "csrr": "csrrs",
    "csrw": "csrrw",
    "csrs": "csrrs",
    "csrc": "csrrc",
    "csrwi": "csrrwi",
    "csrsi": "csrrsi",
    "csrci": "csrrci",
}

for key, value in INSTRUCTIONS_INFO_ALIASES.items():
    INSTRUCTIONS_INFO[key] = INSTRUCTIONS_INFO[value]

if __name__ == "__main__":
    print(INSTRUCTIONS_INFO["addi"].funct3)
