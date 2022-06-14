import random

from gigue.instructions import BInstruction
from gigue.instructions import IInstruction
from gigue.instructions import JInstruction
from gigue.instructions import RInstruction
from gigue.instructions import UInstruction

MAX_METHOD_SIZE = 30
MAX_CALL_NUMBER = 5
MAX_CASE_NUMBER = 5


class InstructionBuilder:
    R_INSTRUCTIONS = [
        "add", "addw", "andr", "mul", "mulh", "mulhsu", "mulhu", "mulw",
        "orr", "sll", "sllw", "slt", "sltu", "sra", "sraw", "srl", "srlw",
        "sub", "subw", "xor"
    ]
    I_INSTRUCTIONS = ["addi", "addiw", "andi", "ori", "slti", "sltiu", "xori"]
    I_INSTRUCTIONS_LOAD = ["lb", "lbu", "ld", "lh", "lhu"]
    U_INSTRUCTIONS = ["auipc", "lui"]
    S_INSTRUCTIONS = ["sb", "sd", "sh", "sw"]
    B_INSTRUCTIONS = ["beq", "bge", "bgeu", "blt", "bltu", "bne"]

    def build_random_r_instruction(self, registers):
        name = random.choice(InstructionBuilder.R_INSTRUCTIONS)
        constr = getattr(RInstruction, name)
        rd, rs1, rs2 = tuple(random.choices(registers, k=3))
        return constr(rd=rd, rs1=rs1, rs2=rs2)

    def build_random_i_instruction(self, registers):
        name = random.choice(InstructionBuilder.I_INSTRUCTIONS)
        constr = getattr(IInstruction, name)
        rd, rs1 = tuple(random.choices(registers, k=2))
        imm = random.randint(0, 0xFFF)
        return constr(rd=rd, rs1=rs1, imm=imm)

    # TODO: loads

    def build_random_u_instruction(self, registers):
        name = random.choice(InstructionBuilder.U_INSTRUCTIONS)
        constr = getattr(UInstruction, name)
        rd = random.choice(registers)
        imm = random.randint(0, 0xFFFFFFFF)
        return constr(rd=rd, imm=imm)

    def build_random_j_instruction(self, max_address):
        # Jump to stay in the method and keep aligment
        offset = random.randrange(0, min(max_address, 0x7FFFFFFF), 2)
        return JInstruction.jal(0, offset)

    # TODO: stores

    def build_random_b_instruction(self, registers, max_address):
        name = random.choice(InstructionBuilder.B_INSTRUCTIONS)
        constr = getattr(BInstruction, name)
        rs1, rs2 = random.choices(registers, k=2)
        offset = random.randrange(0, min(max_address, 0x7FF), 2)
        return constr(rs1=rs1, rs2=rs2, imm=offset)

    def build_random(self):
        pass


class Method:
    def __init__(self, size, call_number, address, registers: list):
        self.address = address
        self.size = min(size, MAX_METHOD_SIZE)
        self.call_number = min(call_number, MAX_CALL_NUMBER)

        self.registers = registers

        self.machine_code = []
        self.instructions = []
        self.callees = []

    def add_instructions(self):
        current_size = 0
        while current_size < self.size:
            # Add random instructions
            self.instructions.append()

    def generate(self):
        self.machine_code = [instruction.generate() for instruction in self.instructions]
        return self.machine_code

    def patch_calls(self, callees):
        # Replace calls with
        self.callees = callees


class PIC:
    def __init__(self, case_number, method_size, address):
        self.case_number = case_number
        self.address = address

    def generate(self):
        pass


if __name__ == "__main__":
    ib = InstructionBuilder()
    ib.build_random_r_instruction([5, 6, 7])
