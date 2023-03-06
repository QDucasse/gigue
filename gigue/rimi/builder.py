# from gigue.constants import CMP_REG
# from gigue.constants import INSTRUCTION_WEIGHTS

# from gigue.helpers import align

import random

from gigue.builder import InstructionBuilder
from gigue.constants import HIT_CASE_REG, RA
from gigue.helpers import align
from gigue.instructions import IInstruction, UInstruction
from gigue.rimi.constants import RIMI_SHADOW_STACK_REG
from gigue.rimi.instructions import RIMIIInstruction, RIMIJInstruction, RIMISInstruction


class RIMIShadowStackInstructionBuilder(InstructionBuilder):
    @staticmethod
    def build_prologue(contains_call, *args, **kwargs):
        # An example prologue would be:
        # Regular call stack!
        # addi sp sp -12 (+local vars)
        # sd s0 0(sp) ...
        # sd s1 4(sp) ...
        # sd s2 8(sp) ...
        # REMOVED -- sd ra 12(sp) --
        # Shadow stack!
        # addi ssreg ssreg -4
        # sws  ra, 0(ssreg)
        instructions = InstructionBuilder.build_prologue(contains_call, *args, **kwargs)
        # Shadow stack
        instructions.append(
            IInstruction.addi(
                rd=RIMI_SHADOW_STACK_REG, rs1=RIMI_SHADOW_STACK_REG, imm=-4
            )
        )
        sws_instr = RIMISInstruction.sws(rs1=RIMI_SHADOW_STACK_REG, rs2=RA, imm=0)
        if contains_call:
            # Overwrite the ra store
            instructions[-1] = sws_instr
        else:
            # Otherwise simply add it!
            instructions.append(sws_instr)
        return instructions

    @staticmethod
    def build_epilogue(contains_call, *args, **kwargs):
        # An example epilogue would be:
        # Regular call stack!
        # ld s0 0(sp)
        # ld s1 4(sp
        # ld s2 8(sp
        # REMOVED -- ld ra 12(sp) --
        # lws ra 0(sp)
        # addi ssreg ssreg 4
        # addi sp sp 12 (+local vars)
        # ret
        instructions = InstructionBuilder.build_epilogue(contains_call, *args, **kwargs)
        # Shadow stack load ()
        lws_instr = RIMIIInstruction.lws(rd=RA, rs1=RIMI_SHADOW_STACK_REG, imm=0)
        if contains_call:
            # Overwrite the ra load
            instructions[-2] = lws_instr
        else:
            # Otherwise insert it
            instructions[-2:-2] = lws_instr

        instructions[-2:-2] = IInstruction.addi(
            rd=RIMI_SHADOW_STACK_REG, rs1=RIMI_SHADOW_STACK_REG, imm=4
        )
        return instructions


class RIMIFullInstructionBuilder(RIMIShadowStackInstructionBuilder):
    RIMI_S_INSTRUCTIONS = ["sb1", "sh1", "sw1", "sd1"]
    RIMI_I_INSTRUCTIONS_LOAD = ["lb1", "lbu1", "lh1", "lhu1", "lw1", "lwu1", "ld1"]

    # JIT Code modifications
    # 1. New instructions for stores/loads
    # 2. Domain change routines in calls/returns
    # 3. Shadow stack instructions - derived from the superclass
    # \_________________________________________________________

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
        # The right part handles the low offset sign
        # extension (that should be mitigated)
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
        # The right part handles the low offset sign
        # extension (that should be mitigated)
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
    # 1. unique call stack, the shadow stack itself <--
    # 2. duplicated call stack, needs a check
