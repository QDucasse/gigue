from typing import Dict, List, Optional

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


# Following the separation/naming defined in the CVA6 core:
# https://github.com/QDucasse/cva6/blob/master/core/include/riscv_pkg.sv#L222-L291

# Names -> Values
OPCODES: Dict[str, int] = {
    # Quadrant 0
    "OP_LOAD": 0b0000011,
    "OP_LOAD_FP": 0b0000111,  # Unused
    "OP_CUSTOM0": 0b0001011,
    "OP_MISC_MEM": 0b0001111,
    "OP_OP_IMM": 0b0010011,
    "OP_AUIPC": 0b0010111,
    "OP_OP_IMM_32": 0b0011011,
    # Quadrant 1
    "OP_STORE": 0b0100011,
    "OP_STORE_FP": 0b0100111,  # Unused
    "OP_CUSTOM1": 0b0101011,
    "OP_AMO": 0b0101111,  # Unused
    "OP_OP": 0b0110011,
    "OP_LUI": 0b0110111,
    "OP_OP_32": 0b0111011,
    # Quadrant 2
    "OP_MADD": 0b1000011,  # Unused
    "OP_MSUB": 0b1000111,  # Unused
    "OP_NMSUB": 0b1001011,  # Unused
    "OP_NMADD": 0b1001111,  # Unused
    "OP_OP_FP": 0b1010011,  # Unused
    "OP_VEC": 0b1010111,  # Unused
    "OP_CUSTOM2": 0b1011011,
    # Quadrant 3
    "OP_BRANCH": 0b1100011,
    "OP_JALR": 0b1100111,
    "OP_RSRVD2": 0b1101011,  # Unused
    "OP_JAL": 0b1101111,
    "OP_SYSTEM": 0b1110011,
    "OP_RSRVD3": 0b1110111,  # Unused
    "OP_CUSTOM3": 0b1111011,
}

# Values -> Names
OPCODES_NAMES: Dict[int, str] = dict((value, key) for (key, value) in OPCODES.items())


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


class RoCCCustomInstructionInfo(InstructionInfo):
    def __init__(
        self,
        name: str,
        opcode: int,
        instr_type: Optional[str] = None,
        instr_class: Optional[str] = None,
        xd: int = 0,
        xs1: int = 0,
        xs2: int = 0,
        funct7: int = 0,
        cmp_mask: int = OPCODE_FUNC3_FUNC7_MASK,
    ):
        if instr_type is None:
            instr_type = "R"
        if instr_class is None:
            instr_class = "custom"
        funct3: int = (xd << 2) + (xs1 << 1) + xs2
        self.xd: int = xd
        self.xs1: int = xs1
        self.xs2: int = xs2
        super().__init__(
            name=name,
            opcode=opcode,
            instr_type=instr_type,
            instr_class=instr_class,
            funct3=funct3,
            funct7=funct7,
            cmp_mask=cmp_mask,
        )


INSTRUCTIONS_INFO: Dict[str, InstructionInfo] = {
    # Adds
    "add": InstructionInfo(
        name="add",
        opcode=OPCODES["OP_OP"],
        funct3=0b000,
        instr_type="R",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_FUNC7_MASK,
    ),
    "addi": InstructionInfo(
        name="addi",
        opcode=OPCODES["OP_OP_IMM"],
        funct3=0b000,
        instr_type="I",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "addiw": InstructionInfo(
        name="addiw",
        opcode=OPCODES["OP_OP_IMM_32"],
        funct3=0b000,
        instr_type="I",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "addw": InstructionInfo(
        name="addw",
        opcode=OPCODES["OP_OP_32"],
        funct3=0b000,
        instr_type="R",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_FUNC7_MASK,
    ),
    # Ands
    "andr": InstructionInfo(
        name="andr",
        opcode=OPCODES["OP_OP"],
        funct3=0b111,
        instr_type="R",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_FUNC7_MASK,
    ),
    "andi": InstructionInfo(
        name="andi",
        opcode=OPCODES["OP_OP_IMM"],
        funct3=0b111,
        instr_type="I",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    # Add upp imm to PC
    "auipc": InstructionInfo(
        name="auipc",
        opcode=OPCODES["OP_AUIPC"],
        funct3=0b000,
        instr_type="U",
        instr_class="arithmetic",
        cmp_mask=OPCODE_MASK,
    ),
    # Branches
    "beq": InstructionInfo(
        name="beq",
        opcode=OPCODES["OP_BRANCH"],
        funct3=0b000,
        instr_type="B",
        instr_class="branching",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "bge": InstructionInfo(
        name="bge",
        opcode=OPCODES["OP_BRANCH"],
        funct3=0b101,
        instr_type="B",
        instr_class="branching",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "bgeu": InstructionInfo(
        name="bgeu",
        opcode=OPCODES["OP_BRANCH"],
        funct3=0b111,
        instr_type="B",
        instr_class="branching",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "blt": InstructionInfo(
        name="blt",
        opcode=OPCODES["OP_BRANCH"],
        funct3=0b100,
        instr_type="B",
        instr_class="branching",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "bltu": InstructionInfo(
        name="bltu",
        opcode=OPCODES["OP_BRANCH"],
        funct3=0b110,
        instr_type="B",
        instr_class="branching",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "bne": InstructionInfo(
        name="bne",
        opcode=OPCODES["OP_BRANCH"],
        funct3=0b001,
        instr_type="B",
        instr_class="branching",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    # Jumps
    "jal": InstructionInfo(
        name="jal",
        opcode=OPCODES["OP_JAL"],
        funct3=0b000,
        instr_type="J",
        instr_class="branching",
        cmp_mask=OPCODE_MASK,
    ),
    "jalr": InstructionInfo(
        name="jalr",
        opcode=OPCODES["OP_JALR"],
        funct3=0b000,
        instr_type="I",
        instr_class="branching",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    # Loads
    "lb": InstructionInfo(
        name="lb",
        opcode=OPCODES["OP_LOAD"],
        funct3=0b000,
        instr_type="I",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "lbu": InstructionInfo(
        name="lbu",
        opcode=OPCODES["OP_LOAD"],
        funct3=0b100,
        instr_type="I",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "ld": InstructionInfo(
        name="ld",
        opcode=OPCODES["OP_LOAD"],
        funct3=0b011,
        instr_type="I",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "lh": InstructionInfo(
        name="lh",
        opcode=OPCODES["OP_LOAD"],
        funct3=0b001,
        instr_type="I",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "lhu": InstructionInfo(
        name="lhu",
        opcode=OPCODES["OP_LOAD"],
        funct3=0b101,
        instr_type="I",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "lw": InstructionInfo(
        name="lw",
        opcode=OPCODES["OP_LOAD"],
        funct3=0b010,
        instr_type="I",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "lwu": InstructionInfo(
        name="lwu",
        opcode=OPCODES["OP_LOAD"],
        funct3=0b110,
        instr_type="I",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    # Load upper immediate
    "lui": InstructionInfo(
        name="lui",
        opcode=OPCODES["OP_LUI"],
        funct3=0b000,
        instr_type="U",
        instr_class="arithmetic",
        cmp_mask=OPCODE_MASK,
    ),
    # Muls
    "mul": InstructionInfo(
        name="mul",
        opcode=OPCODES["OP_OP"],
        funct3=0b000,
        instr_type="R",
        funct7=0b0000001,
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_FUNC7_MASK,
    ),
    "mulh": InstructionInfo(
        name="mulh",
        opcode=OPCODES["OP_OP"],
        funct3=0b001,
        instr_type="R",
        instr_class="arithmetic",
        funct7=0b0000001,
        cmp_mask=OPCODE_FUNC3_FUNC7_MASK,
    ),
    "mulhsu": InstructionInfo(
        name="mulhsu",
        opcode=OPCODES["OP_OP"],
        funct3=0b010,
        instr_type="R",
        instr_class="arithmetic",
        funct7=0b0000001,
        cmp_mask=OPCODE_FUNC3_FUNC7_MASK,
    ),
    "mulhu": InstructionInfo(
        name="mulhu",
        opcode=OPCODES["OP_OP"],
        funct3=0b011,
        instr_type="R",
        instr_class="arithmetic",
        funct7=0b0000001,
        cmp_mask=OPCODE_FUNC3_FUNC7_MASK,
    ),
    "mulw": InstructionInfo(
        name="mulw",
        opcode=OPCODES["OP_OP_32"],
        funct3=0b000,
        instr_type="R",
        instr_class="arithmetic",
        funct7=0b0000001,
        cmp_mask=OPCODE_FUNC3_FUNC7_MASK,
    ),
    # Ors
    "orr": InstructionInfo(
        name="orr",
        opcode=OPCODES["OP_OP"],
        funct3=0b110,
        instr_type="R",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_FUNC7_MASK,
    ),
    "ori": InstructionInfo(
        name="ori",
        opcode=OPCODES["OP_OP_IMM"],
        funct3=0b110,
        instr_type="I",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    # Stores
    "sb": InstructionInfo(
        name="sb",
        opcode=OPCODES["OP_STORE"],
        funct3=0b000,
        instr_type="S",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "sd": InstructionInfo(
        name="sd",
        opcode=OPCODES["OP_STORE"],
        funct3=0b011,
        instr_type="S",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "sh": InstructionInfo(
        name="sh",
        opcode=OPCODES["OP_STORE"],
        funct3=0b001,
        instr_type="S",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "sw": InstructionInfo(
        name="sw",
        opcode=OPCODES["OP_STORE"],
        funct3=0b010,
        instr_type="S",
        instr_class="memory",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    # Logical shift left
    "sll": InstructionInfo(
        name="sll",
        opcode=OPCODES["OP_OP"],
        funct3=0b001,
        instr_type="R",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_FUNC6_MASK,
    ),
    "slli": InstructionInfo(
        name="slli",
        opcode=OPCODES["OP_OP_IMM"],
        funct3=0b001,
        instr_type="I",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_FUNC6_MASK,
    ),
    "slliw": InstructionInfo(
        name="slliw",
        opcode=OPCODES["OP_OP_IMM_32"],
        funct3=0b001,
        instr_type="I",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_FUNC6_MASK,
    ),
    "sllw": InstructionInfo(
        name="sllw",
        opcode=OPCODES["OP_OP_32"],
        funct3=0b001,
        instr_type="R",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_FUNC6_MASK,
    ),
    # Set if
    "slt": InstructionInfo(
        name="slt",
        opcode=OPCODES["OP_OP"],
        funct3=0b010,
        instr_type="R",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_FUNC7_MASK,
    ),
    "slti": InstructionInfo(
        name="slti",
        opcode=OPCODES["OP_OP_IMM"],
        funct3=0b010,
        instr_type="I",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "sltiu": InstructionInfo(
        name="sltiu",
        opcode=OPCODES["OP_OP_IMM"],
        funct3=0b011,
        instr_type="I",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "sltu": InstructionInfo(
        name="sltu",
        opcode=OPCODES["OP_OP"],
        funct3=0b011,
        instr_type="R",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_FUNC7_MASK,
    ),
    # Arithmetic shift right
    # Note (srai, sraiw) the funct7 here is used on top of the shift immediate
    "sra": InstructionInfo(
        name="sra",
        opcode=OPCODES["OP_OP"],
        funct3=0b101,
        instr_type="R",
        instr_class="arithmetic",
        funct7=0b0100000,
        cmp_mask=OPCODE_FUNC3_FUNC6_MASK,
    ),
    "srai": InstructionInfo(
        name="srai",
        opcode=OPCODES["OP_OP_IMM"],
        funct3=0b101,
        instr_type="I",
        instr_class="arithmetic",
        funct7=0b0100000,
        cmp_mask=OPCODE_FUNC3_FUNC6_MASK,
    ),
    "sraiw": InstructionInfo(
        name="sraiw",
        opcode=OPCODES["OP_OP_IMM_32"],
        funct3=0b101,
        instr_type="I",
        instr_class="arithmetic",
        funct7=0b0100000,
        cmp_mask=OPCODE_FUNC3_FUNC6_MASK,
    ),
    "sraw": InstructionInfo(
        name="sraw",
        opcode=OPCODES["OP_OP_32"],
        funct3=0b101,
        instr_type="R",
        instr_class="arithmetic",
        funct7=0b0100000,
        cmp_mask=OPCODE_FUNC3_FUNC6_MASK,
    ),
    # Logical shift right
    "srl": InstructionInfo(
        name="srl",
        opcode=OPCODES["OP_OP"],
        funct3=0b101,
        instr_type="R",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_FUNC6_MASK,
    ),
    "srli": InstructionInfo(
        name="srli",
        opcode=OPCODES["OP_OP_IMM"],
        funct3=0b101,
        instr_type="I",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_FUNC6_MASK,
    ),
    "srliw": InstructionInfo(
        name="srliw",
        opcode=OPCODES["OP_OP_IMM_32"],
        funct3=0b101,
        instr_type="I",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_FUNC6_MASK,
    ),
    "srlw": InstructionInfo(
        name="srlw",
        opcode=OPCODES["OP_OP_32"],
        funct3=0b101,
        instr_type="R",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_FUNC6_MASK,
    ),
    # Subs
    "sub": InstructionInfo(
        name="sub",
        opcode=OPCODES["OP_OP"],
        funct3=0b000,
        instr_type="R",
        instr_class="arithmetic",
        funct7=0b0100000,
        cmp_mask=OPCODE_FUNC3_FUNC7_MASK,
    ),
    "subw": InstructionInfo(
        name="subw",
        opcode=OPCODES["OP_OP_32"],
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
        opcode=OPCODES["OP_OP"],
        funct3=0b100,
        instr_type="R",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_FUNC7_MASK,
    ),
    "xori": InstructionInfo(
        name="xori",
        opcode=OPCODES["OP_OP_IMM"],
        funct3=0b100,
        instr_type="I",
        instr_class="arithmetic",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    # Exceptions
    "ebreak": ExceptionInstructionInfo(
        imm=1,
        name="ebreak",
        opcode=OPCODES["OP_SYSTEM"],
        funct3=0b000,
        instr_type="I",
        instr_class="internal",
        cmp_mask=FULL_MASK,
    ),
    "ecall": ExceptionInstructionInfo(
        imm=0,
        name="ecall",
        opcode=OPCODES["OP_SYSTEM"],
        funct3=0b000,
        instr_type="I",
        instr_class="internal",
        cmp_mask=FULL_MASK,
    ),
    # Custom
    "custom0": InstructionInfo(
        name="custom0",
        opcode=OPCODES["OP_CUSTOM0"],
        funct3=0b000,
        instr_type="R",
        instr_class="custom",
        cmp_mask=OPCODE_FUNC3_FUNC7_MASK,
    ),
    "custom1": InstructionInfo(
        name="custom1",
        opcode=OPCODES["OP_CUSTOM1"],
        funct3=0b000,
        instr_type="R",
        instr_class="custom",
        cmp_mask=OPCODE_FUNC3_FUNC7_MASK,
    ),
    "custom2": InstructionInfo(
        name="custom2",
        opcode=OPCODES["OP_CUSTOM2"],
        funct3=0b000,
        instr_type="R",
        instr_class="custom",
        cmp_mask=OPCODE_FUNC3_FUNC7_MASK,
    ),
    "custom3": InstructionInfo(
        name="custom3",
        opcode=OPCODES["OP_CUSTOM3"],
        funct3=0b000,
        instr_type="R",
        instr_class="custom",
        cmp_mask=OPCODE_FUNC3_FUNC7_MASK,
    ),
    # Note: funct3 is set at 0 by default but should be redefined by the subclasses!
    # Internals
    # Note: Those instructions are not generated by Gigue but can be found in the
    #       core execution log as they are used by the core helpers.
    "fence": InstructionInfo(
        name="fence",
        opcode=OPCODES["OP_MISC_MEM"],
        funct3=0b000,
        instr_type="I",
        instr_class="internal",
        cmp_mask=FENCE_MASK,
    ),
    "fence.i": InstructionInfo(
        name="fence.i",
        opcode=OPCODES["OP_MISC_MEM"],
        funct3=0b001,
        instr_type="I",
        instr_class="internal",
        cmp_mask=FULL_MASK,
    ),
    "csrrw": InstructionInfo(
        name="csrrw",
        opcode=OPCODES["OP_SYSTEM"],
        funct3=0b001,
        instr_type="I",
        instr_class="internal",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "csrrs": InstructionInfo(
        name="csrrs",
        opcode=OPCODES["OP_SYSTEM"],
        funct3=0b010,
        instr_type="I",
        instr_class="internal",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "csrrc": InstructionInfo(
        name="csrrc",
        opcode=OPCODES["OP_SYSTEM"],
        funct3=0b011,
        instr_type="I",
        instr_class="internal",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "csrrwi": InstructionInfo(
        name="csrrwi",
        opcode=OPCODES["OP_SYSTEM"],
        funct3=0b101,
        instr_type="I",
        instr_class="internal",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "csrrsi": InstructionInfo(
        name="csrrsi",
        opcode=OPCODES["OP_SYSTEM"],
        funct3=0b110,
        instr_type="I",
        instr_class="internal",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    "csrrci": InstructionInfo(
        name="csrrci",
        opcode=OPCODES["OP_SYSTEM"],
        funct3=0b111,
        instr_type="I",
        instr_class="internal",
        cmp_mask=OPCODE_FUNC3_MASK,
    ),
    # Debug
    "dret": InstructionInfo(
        name="dret",
        opcode=OPCODES["OP_SYSTEM"],
        funct3=0b000,
        instr_type="I",
        instr_class="internal",
        cmp_mask=FULL_MASK,
    ),
    # Debug
    "unknown": InstructionInfo(
        name="unknown",
        opcode=0,
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
    "sext": "addiw",
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
