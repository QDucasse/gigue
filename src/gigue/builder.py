import random

from gigue.constants import INSTRUCTION_WEIGHTS
from gigue.instructions import BInstruction
from gigue.instructions import IInstruction
from gigue.instructions import JInstruction
from gigue.instructions import RInstruction
from gigue.instructions import UInstruction


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

    @staticmethod
    def build_random_r_instruction(registers):
        name = random.choice(InstructionBuilder.R_INSTRUCTIONS)
        constr = getattr(RInstruction, name)
        rd, rs1, rs2 = tuple(random.choices(registers, k=3))
        return constr(rd=rd, rs1=rs1, rs2=rs2)

    @staticmethod
    def build_random_i_instruction(registers):
        name = random.choice(InstructionBuilder.I_INSTRUCTIONS)
        constr = getattr(IInstruction, name)
        rd, rs1 = tuple(random.choices(registers, k=2))
        imm = random.randint(0, 0xFFF)
        return constr(rd=rd, rs1=rs1, imm=imm)

    @staticmethod
    def build_random_u_instruction(registers):
        name = random.choice(InstructionBuilder.U_INSTRUCTIONS)
        constr = getattr(UInstruction, name)
        rd = random.choice(registers)
        imm = random.randint(0, 0xFFFFFFFF)
        return constr(rd=rd, imm=imm)

    @staticmethod
    def build_random_j_instruction(registers, max_offset):
        # Jump to stay in the method and keep aligment
        rd = random.choice(registers)
        offset = random.randrange(4, max(4, max_offset), 4)
        return JInstruction.jal(rd, offset)

    # TODO: stores
    # TODO: loads

    @staticmethod
    def build_random_b_instruction(registers, max_offset):
        name = random.choice(InstructionBuilder.B_INSTRUCTIONS)
        constr = getattr(BInstruction, name)
        rs1, rs2 = random.choices(registers, k=2)
        offset = random.randrange(4, max(4, max_offset), 4)
        return constr(rs1=rs1, rs2=rs2, imm=offset)

    def build_random_instruction(self, registers, max_offset, weights=None):
        if weights is None:
            weights = INSTRUCTION_WEIGHTS
        method_name, needs_max_offset = random.choices([
            ("build_random_r_instruction", False),
            ("build_random_i_instruction", False),
            ("build_random_u_instruction", False),
            ("build_random_j_instruction", True),
            ("build_random_b_instruction", True)
        ], weights)[0]
        method = getattr(InstructionBuilder, method_name)
        instruction = method(registers, max_offset) if needs_max_offset else method(registers)
        return instruction

    @staticmethod
    def build_nop():
        return IInstruction.nop()

    @staticmethod
    def build_ret():
        return IInstruction.ret()

    @staticmethod
    def build_call(offset):
        offset_low = offset & 0xFFF
        # The right part handles the low offset sign extension (that should be mitigated)
        offset_high = (offset & 0xFFFFF000) + ((offset & 0x800) << 1)
        # print("offset: {}/{} -> olow: {} + ohigh: {}".format(
        #     hex(offset),
        #     hex(offset & 0xFFFFFFFF),
        #     hex(offset_low),
        #     hex(offset_high)
        # ))
        return [UInstruction.auipc(1, offset_high), IInstruction.jalr(1, 1, offset_low)]
