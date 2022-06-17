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

    def build_random_j_instruction(self, registers, max_address):
        # Jump to stay in the method and keep aligment
        rd = random.choice(registers)
        offset = random.randrange(4, max(8, max_address), 2)
        return JInstruction.jal(rd, offset)

    # TODO: stores

    def build_random_b_instruction(self, registers, max_address):
        name = random.choice(InstructionBuilder.B_INSTRUCTIONS)
        constr = getattr(BInstruction, name)
        rs1, rs2 = random.choices(registers, k=2)
        offset = random.randrange(4, max(8, max_address), 2)
        return constr(rs1=rs1, rs2=rs2, imm=offset)

    def build_random_instruction(self, registers, max_address,
                                 weights=[35, 40, 10, 5, 10]):
        method_name, needs_max_addr = random.choices([
            ("build_random_r_instruction", False),
            ("build_random_i_instruction", False),
            ("build_random_u_instruction", False),
            ("build_random_j_instruction", True),
            ("build_random_b_instruction", True)
        ], weights)[0]
        method = getattr(InstructionBuilder, method_name)
        instruction = method(self, registers, max_address) if needs_max_addr else method(self, registers)
        return instruction


class Method:
    def __init__(self, size, call_number, address, registers: list):
        self.address = address
        self.size = min(size, MAX_METHOD_SIZE)
        self.call_number = min(call_number, MAX_CALL_NUMBER)

        self.registers = registers

        self.instruction_builder = InstructionBuilder()
        self.machine_code = []
        self.bytes = b''
        self.instructions = []
        self.callees = []

    def add_instructions(self, weights=[35, 40, 10, 5, 10]):
        for current_address in range(self.address, self.address + self.size * 4, 4):
            # Add random instructions
            max_offset = self.address + self.size * 4 - current_address
            instruction = self.instruction_builder.build_random_instruction(
                self.registers, max_offset, weights
            )
            self.instructions.append(instruction)

    def generate(self):
        self.machine_code = [instruction.generate() for instruction in self.instructions]
        return self.machine_code

    def generate_bytes(self):
        for instruction in self.instructions:
            self.bytes += instruction.generate_bytes()
        return self.bytes

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
