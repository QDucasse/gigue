import random

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

    def build_random_u_instruction(self, registers):
        name = random.choice(InstructionBuilder.U_INSTRUCTIONS)
        constr = getattr(UInstruction, name)
        rd = random.choice(registers)
        imm = random.randint(0, 0xFFFFFFFF)
        return constr(rd=rd, imm=imm)

    def build_random_j_instruction(self, registers, max_offset):
        # Jump to stay in the method and keep aligment
        rd = random.choice(registers)
        offset = random.randrange(4, max(4, max_offset), 4)
        return JInstruction.jal(rd, offset)

    # TODO: stores
    # TODO: loads

    def build_random_b_instruction(self, registers, max_offset):
        name = random.choice(InstructionBuilder.B_INSTRUCTIONS)
        constr = getattr(BInstruction, name)
        rs1, rs2 = random.choices(registers, k=2)
        offset = random.randrange(4, max(4, max_offset), 4)
        return constr(rs1=rs1, rs2=rs2, imm=offset)

    def build_random_instruction(self, registers, max_offset,
                                 weights=[35, 40, 10, 5, 10]):
        method_name, needs_max_offset = random.choices([
            ("build_random_r_instruction", False),
            ("build_random_i_instruction", False),
            ("build_random_u_instruction", False),
            ("build_random_j_instruction", True),
            ("build_random_b_instruction", True)
        ], weights)[0]
        method = getattr(InstructionBuilder, method_name)
        instruction = method(self, registers, max_offset) if needs_max_offset else method(self, registers)
        return instruction

    def build_nop(self):
        return IInstruction.nop()

    def build_ret(self):
        return IInstruction.ret()

    def build_call(self, offset):
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
