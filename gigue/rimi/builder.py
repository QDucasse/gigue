# from gigue.constants import CMP_REG
# from gigue.constants import INSTRUCTION_WEIGHTS

# from gigue.helpers import align

import random

from gigue.builder import InstructionBuilder
from gigue.constants import CALLEE_SAVED_REG
from gigue.constants import HIT_CASE_REG
from gigue.constants import RA
from gigue.constants import SP
from gigue.helpers import align
from gigue.instructions import IInstruction
from gigue.instructions import UInstruction
from gigue.rimi.constants import RIMI_SHADOW_STACK_REG
from gigue.rimi.instructions import RIMIIInstruction
from gigue.rimi.instructions import RIMIJInstruction
from gigue.rimi.instructions import RIMISInstruction


class RIMIInstructionBuilder(InstructionBuilder):
    RIMI_S_INSTRUCTIONS = ["sb1", "sh1", "sw1", "sd1"]
    RIMI_I_INSTRUCTIONS_LOAD = ["lb1", "lbu1", "lh1", "lhu1", "lw1", "lwu1", "ld1"]

    # JIT Code modifications
    # 1. New instructions for stores/loads
    # 2. Domain change routines in calls/returns
    # 3. Shadow stack instructions
    # \______________________________________________

    # 1. Duplicated instructions
    # \_________________________

    @staticmethod
    def build_random_s_instruction(registers, data_reg, data_size, *args, **kwargs):
        name = random.choice(InstructionBuilder.S_INSTRUCTIONS)
        constr = getattr(RIMISInstruction, name)
        # Note: sd, rs2, off(rs1) stores the contents of rs2
        # at the address in rs1 + offset
        rs1 = data_reg
        rs2 = random.choice(registers)
        alignment = InstructionBuilder.define_memory_access_alignment(name)
        imm = align(random.randint(0, min(data_size, 0x7FF)), alignment)
        return constr(rs1=rs1, rs2=rs2, imm=imm)

    @staticmethod
    def build_random_l_instruction(registers, data_reg, data_size, *args, **kwargs):
        name = random.choice(InstructionBuilder.RIMI_I_INSTRUCTIONS_LOAD)
        constr = getattr(RIMIIInstruction, name)
        # Note: ld, rd, off(rs1) loads the value at the address
        # stored in rs1 + off in rd
        rd = random.choice(registers)
        rs1 = data_reg
        alignment = InstructionBuilder.define_memory_access_alignment(name)
        imm = align(random.randint(0, min(data_size, 0x7FF)), alignment)
        return constr(rd=rd, rs1=rs1, imm=imm)

    # 2. Domain change routines in calls
    # \_________________________________

    @staticmethod
    def build_method_call(offset):
        # if offset < 0x8:
        #     raise Exception
        offset_low = offset & 0xFFF
        # The right part handles the low offset sign extension (that should be mitigated)
        offset_high = (offset & 0xFFFFF000) + ((offset & 0x800) << 1)
        # print("offset: {}/{} -> olow: {} + ohigh: {}".format(
        #     hex(offset),
        #     hex(offset & 0xFFFFFFFF),
        #     hex(offset_low),
        #     hex(offset_high)
        # ))
        return [
            UInstruction.auipc(1, offset_high),
            RIMIJInstruction.jalx(1, 1, offset_low),
        ]

    @staticmethod
    def build_pic_call(offset, hit_case, hit_case_reg=HIT_CASE_REG):
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
            RIMIJInstruction.jalx(rd=1, rs1=1, imm=offset_low),
        ]

    # 3. Shadow stack instructions
    # \___________________________

    # TODO: Choose shadow stack implementation:
    # 1. unique call stack, the shadow stack itself
    # 2. duplicated call stack, needs a check

    @staticmethod
    def build_prologue(*args, **kwargs):
        # An example prologue would be:
        # Regular call stack!
        # addi sp sp -16 (+local vars)
        # sd s0 0(sp) ...
        # sd s1 4(sp) ...
        # sd s2 8(sp) ...
        # sd ra 12(sp)
        # Shadow stack! > load both and compare?
        # addi ssreg ssreg -4
        # sws  ra, 0(ssreg)
        instructions = InstructionBuilder.build_prologue(*args, **kwargs)
        # Shadow stack
        instructions.append(
            IInstruction.addi(
                rd=RIMI_SHADOW_STACK_REG, rs1=RIMI_SHADOW_STACK_REG, imm=-4
            )
        )
        instructions.append(
            RIMISInstruction.sws(rs1=RIMI_SHADOW_STACK_REG, rs2=RA, imm=0)
        )
        return instructions

    @staticmethod
    def build_epilogue(used_s_regs, local_var_nb, contains_call):
        # An example epilogue would be:
        # Regular call stack!
        # ld s0 0(sp)
        # ld s1 4(sp
        # ld s2 8(sp
        # ld ra 12(sp)  > load both and compare?
        # addi sp sp 16 (+local vars)
        # lws ra 12(sp)
        # jalrx
        instructions = []
        stack_space = (used_s_regs + local_var_nb + (1 if contains_call else 0)) * 8
        # Reload saved registers used
        for i in range(used_s_regs):
            instructions.append(
                IInstruction.ld(rd=CALLEE_SAVED_REG[i], rs1=SP, imm=i * 8)
            )
        # Reload ra (if necessary)
        if contains_call:
            instructions.append(IInstruction.ld(rd=RA, rs1=SP, imm=used_s_regs * 8))
        # Increment sp to previous value
        instructions.append(IInstruction.addi(rd=SP, rs1=SP, imm=stack_space))
        # Shadow stack load
        instructions.append(
            RIMIIInstruction.lws(rd=RA, rs1=RIMI_SHADOW_STACK_REG, imm=0)
        )
        instructions.append(
            IInstruction.addi(
                rd=RIMI_SHADOW_STACK_REG, rs1=RIMI_SHADOW_STACK_REG, imm=4
            )
        )
        # Jump back to return address
        instructions.append(RIMIIInstruction.jalrx())
        instructions.append(IInstruction.ret())
        return instructions
