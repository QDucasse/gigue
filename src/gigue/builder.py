import random

from gigue.constants import CALLEE_SAVED_REG
from gigue.constants import INSTRUCTION_WEIGHTS
from gigue.constants import RA
from gigue.constants import SP
from gigue.instructions import BInstruction
from gigue.instructions import IInstruction
from gigue.instructions import JInstruction
from gigue.instructions import RInstruction
from gigue.instructions import SInstruction
from gigue.instructions import UInstruction


class InstructionBuilder:
    R_INSTRUCTIONS = [
        "add",
        "addw",
        "andr",
        "mul",
        "mulh",
        "mulhsu",
        "mulhu",
        "mulw",
        "orr",
        "sll",
        "sllw",
        "slt",
        "sltu",
        "sra",
        "sraw",
        "srl",
        "srlw",
        "sub",
        "subw",
        "xor",
    ]
    I_INSTRUCTIONS = ["addi", "addiw", "andi", "ori", "slti", "sltiu", "xori"]
    I_INSTRUCTIONS_LOAD = ["lb", "lbu", "ld", "lh", "lhu"]
    U_INSTRUCTIONS = ["auipc", "lui"]
    S_INSTRUCTIONS = ["sb", "sd", "sh", "sw"]
    B_INSTRUCTIONS = ["beq", "bge", "bgeu", "blt", "bltu", "bne"]

    @staticmethod
    def build_nop():
        return IInstruction.nop()

    @staticmethod
    def build_ret():
        return IInstruction.ret()

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
        method_name, needs_max_offset = random.choices(
            [
                ("build_random_r_instruction", False),
                ("build_random_i_instruction", False),
                ("build_random_u_instruction", False),
                ("build_random_j_instruction", True),
                ("build_random_b_instruction", True),
            ],
            weights,
        )[0]
        method = getattr(InstructionBuilder, method_name)
        instruction = (
            method(registers, max_offset) if needs_max_offset else method(registers)
        )
        return instruction

    @staticmethod
    def build_method_call(offset):
        if offset < 0x8:
            raise Exception
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

    @staticmethod
    def build_pic_call(offset, hit_case, hit_case_reg):
        if offset < 0x8:
            raise Exception
        offset_low = offset & 0xFFF
        # The right part handles the low offset sign extension (that should be mitigated)
        offset_high = (offset & 0xFFFFF000) + ((offset & 0x800) << 1)
        # print("offset: {}/{} -> olow: {} + ohigh: {}".format(
        #     hex(offset),
        #     hex(offset & 0xFFFFFFFF),
        #     hex(offset_low),
        #     hex(offset_high)
        # ))
        # 1. Needed case hit
        # 2/3. Jump to the PC-related PIC location
        return [
            IInstruction.addi(rd=hit_case_reg, rs1=0, imm=hit_case),
            UInstruction.auipc(rd=1, imm=offset_high),
            IInstruction.jalr(rd=1, rs1=1, imm=offset_low),
        ]

    @staticmethod
    def build_switch_case(case_number, method_offset, hit_case_reg, cmp_reg):
        # Switch for one case:
        #   1 - Loading the value to compare in x6
        #   2 - Compare to the current case (should be in x5)
        #   3 - Jump to the corresponding method if equal
        #   4 - Go to the next case if not
        # Note: beq is not used to cover a wider range (2Mb rather than 8kb)
        return [
            IInstruction.addi(rd=hit_case_reg, rs1=0, imm=case_number),
            BInstruction.bne(rs1=cmp_reg, rs2=hit_case_reg, imm=8),
            JInstruction.jal(rd=0, imm=method_offset),
        ]

    @staticmethod
    def build_prologue(used_s_regs, local_var_nb, contains_call):
        # An example prologue would be:
        # addi sp sp -16
        # sw s0 0(sp)
        # sw s1 4(sp)
        # sw s2 8(sp)
        # sw ra 12(sp)
        instructions = []
        stack_space = (used_s_regs + local_var_nb + (1 if contains_call else 0)) * 4
        # Decrement sp by number of s registers + local variable space
        instructions.append(IInstruction.addi(rd=SP, rs1=SP, imm=-stack_space))
        # Store any saved registers used
        for i in range(used_s_regs):
            instructions.append(
                SInstruction.sw(rs1=SP, rs2=CALLEE_SAVED_REG[i], imm=i * 4)
            )
        # Store ra is a function call is made
        if contains_call:
            instructions.append(SInstruction.sw(rs1=SP, rs2=RA, imm=used_s_regs * 4))
        return instructions

    @staticmethod
    def build_epilogue(used_s_regs, local_var_nb, contains_call):
        # An example epilogue would be:
        # lw s0 0(sp)
        # lw s1 4(sp
        # lw s2 8(sp
        # lw ra 12(sp)
        # addi sp sp 16
        # jr ra
        instructions = []
        stack_space = (used_s_regs + local_var_nb + (1 if contains_call else 0)) * 4
        # Reload saved registers used
        for i in range(used_s_regs):
            instructions.append(
                IInstruction.lw(rd=CALLEE_SAVED_REG[i], rs1=SP, imm=i * 4)
            )
        # Reload ra (if necessary)
        if contains_call:
            instructions.append(IInstruction.lw(rd=RA, rs1=SP, imm=used_s_regs * 4))
        # Increment sp to previous value
        instructions.append(IInstruction.addi(rd=SP, rs1=SP, imm=stack_space))
        # Jump back to return address
        instructions.append(IInstruction.ret())
        return instructions

    @staticmethod
    def consolidate_bytes(instructions):
        return b"".join([instr.generate_bytes() for instr in instructions])
