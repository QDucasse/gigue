from __future__ import annotations

import logging
import random
from typing import TYPE_CHECKING, Callable, List

if TYPE_CHECKING:
    from gigue.instructions import Instruction

from gigue.builder import InstructionBuilder
from gigue.constants import CALL_TMP_REG, HIT_CASE_REG, INSTRUCTION_WEIGHTS, RA, X0
from gigue.exceptions import WrongOffsetException
from gigue.helpers import align
from gigue.instructions import IInstruction, UInstruction
from gigue.rimi.rimi_constants import RIMI_SSP_REG
from gigue.rimi.rimi_instructions import RIMIIInstruction, RIMISInstruction

logger = logging.getLogger("gigue.rimi")


class RIMIShadowStackInstructionBuilder(InstructionBuilder):
    # /!\ NOTE:
    # This version of the shadow stack DOES NOT use the traditional
    # data stack at all to store the return address. All stores/loads
    # of the RA to the data stack are replaced with the custom instruction
    @staticmethod
    def build_prologue(
        used_s_regs: int, local_var_nb: int, contains_call: bool
    ) -> List[Instruction]:
        # An example prologue would be:
        # Regular call stack!
        # addi sp sp -20 (+local vars)
        # sd s0 0(sp) ...
        # sd s1 8(sp) ...
        # sd s2 16(sp) ...
        # REMOVED -- sd ra 20(sp) --
        # Shadow stack!
        # addi ssreg ssreg -8
        # ss  ra, 0(ssreg)
        instructions: List[Instruction] = InstructionBuilder.build_prologue(
            used_s_regs=used_s_regs,
            local_var_nb=local_var_nb,
            contains_call=False,
        )
        # Note: We pass false to contains call to size the stack space without the
        # need for RA!
        # Shadow stack
        if contains_call:
            # Overwrite the RA store with stack pointer modif
            instructions.append(
                IInstruction.addi(rd=RIMI_SSP_REG, rs1=RIMI_SSP_REG, imm=-8)
            )
            # Add store to shadow stack memory
            instructions.append(RIMISInstruction.sst(rs1=RIMI_SSP_REG, rs2=RA, imm=0))
        return instructions

    @staticmethod
    def build_epilogue(
        used_s_regs: int, local_var_nb: int, contains_call: bool
    ) -> List[Instruction]:
        # An example epilogue would be:
        # Regular call stack!
        # ld s0 0(sp)
        # ld s1 8(sp
        # ld s2 16(sp
        # REMOVED -- ld ra 20(sp) --
        # addi sp sp 20 (+local vars)
        # ls ra 0(sp)
        # addi ssreg ssreg 8
        # ret
        instructions: List[Instruction] = InstructionBuilder.build_epilogue(
            used_s_regs=used_s_regs,
            local_var_nb=local_var_nb,
            contains_call=False,
        )
        # Note: We pass false to contains call to size the stack space without the
        # need for RA!
        if contains_call:
            # Overwrite the RA load with a load from the shadow stack
            instructions.insert(
                -1, RIMIIInstruction.lst(rd=RA, rs1=RIMI_SSP_REG, imm=0)
            )
            # Insert the addi
            instructions.insert(
                -1, IInstruction.addi(rd=RIMI_SSP_REG, rs1=RIMI_SSP_REG, imm=8)
            )
        return instructions


class RIMIFullInstructionBuilder(RIMIShadowStackInstructionBuilder):
    RIMI_S_INSTRUCTIONS: List[str] = ["sb1", "sh1", "sw1", "sd1"]
    RIMI_I_INSTRUCTIONS_LOAD: List[str] = [
        "lb1",
        "lbu1",
        "lh1",
        "lhu1",
        "lw1",
        "lwu1",
        "ld1",
    ]

    # JIT Code modifications
    # 1. New instructions for stores/loads
    # 2. Domain change routines in calls/returns
    # 3. Shadow stack instructions - derived from the superclass
    # \_________________________________________________________

    # 1. Duplicated instructions
    # \_________________________

    @staticmethod
    def build_random_s_instruction(
        registers: List[int], data_reg: int, data_size: int, *args, **kwargs
    ) -> RIMISInstruction:
        name: str = random.choice(RIMIFullInstructionBuilder.RIMI_S_INSTRUCTIONS)
        constr: Callable = getattr(RIMISInstruction, name)
        # Note: sd, rs2, off(rs1) stores the contents of rs2
        # at the address in rs1 + offset
        rs1: int = data_reg
        rs2: int = random.choice(registers)
        alignment: int = InstructionBuilder.define_memory_access_alignment(name[:-1])
        # Note: remove suffix 1 to determine alignment
        imm: int = align(random.randint(0, min(data_size - 8, 0x7FF)), alignment)
        return constr(rs1=rs1, rs2=rs2, imm=imm)

    @staticmethod
    def build_random_l_instruction(
        registers: List[int], data_reg: int, data_size: int, *args, **kwargs
    ) -> RIMIIInstruction:
        name: str = random.choice(RIMIFullInstructionBuilder.RIMI_I_INSTRUCTIONS_LOAD)
        constr: Callable = getattr(RIMIIInstruction, name)
        # Note: ld, rd, off(rs1) loads the value at the address
        # stored in rs1 + off in rd
        rd: int = random.choice(registers)
        rs1: int = data_reg
        alignment: int = InstructionBuilder.define_memory_access_alignment(name[:-1])
        # Note: remove suffix 1 to determine alignment
        imm: int = align(random.randint(0, min(data_size - 8, 0x7FF)), alignment)
        return constr(rd=rd, rs1=rs1, imm=imm)

    # TODO: Should be better than copy pasted with a changed class but eh
    @staticmethod
    def build_random_instruction(
        registers: List[int],
        max_offset: int,
        data_reg: int,
        data_size: int,
        call_size: int = 3,
        weights: List[int] = INSTRUCTION_WEIGHTS,
    ) -> Instruction:
        method_name: str = random.choices(
            [
                "build_random_r_instruction",
                "build_random_i_instruction",
                "build_random_u_instruction",
                "build_random_j_instruction",
                "build_random_b_instruction",
                "build_random_s_instruction",
                "build_random_l_instruction",
            ],
            weights,
        )[0]
        method: Callable = getattr(RIMIFullInstructionBuilder, method_name)
        instruction: Instruction = method(
            registers=registers,
            max_offset=max_offset,
            data_reg=data_reg,
            data_size=data_size,
            call_size=call_size,
        )
        return instruction

    # TODO: Goodbye
    # # 2. Domain change routines in calls
    # # \_________________________________

    # @staticmethod
    # def build_method_base_call(offset: int) -> List[Instruction]:
    #     # Base method call, no trampolines
    #     try:
    #         # Split offset
    #         offset_low: int
    #         offset_high: int
    #         offset_low, offset_high = InstructionBuilder.split_offset(offset)
    #     except WrongOffsetException as err:
    #         logger.error(err)
    #         raise
    #     return [
    #         UInstruction.auipc(rd=1, imm=offset_high),
    #         RIMIIInstruction.chdom(rd=1, rs1=1, imm=offset_low),
    #     ]

    # @staticmethod
    # def build_pic_base_call(
    #     offset: int, hit_case: int, hit_case_reg: int = HIT_CASE_REG
    # ) -> List[Instruction]:
    #     # Base PIC call, no trampolines
    #     try:
    #         # Split offset
    #         offset_low: int
    #         offset_high: int
    #         offset_low, offset_high = InstructionBuilder.split_offset(offset)
    #     except WrongOffsetException as err:
    #         logger.error(err)
    #         raise
    #     return [
    #         IInstruction.addi(rd=hit_case_reg, rs1=0, imm=hit_case),
    #         UInstruction.auipc(rd=1, imm=offset_high),
    #         RIMIIInstruction.chdom(rd=1, rs1=1, imm=offset_low),
    #     ]

    # 3. Trampolines
    # \______________

    # @staticmethod
    # def build_call_jit_elt_trampoline() -> List[Instruction]:
    #     # The call JIT trampoline is used to call a JIT method/PIC (wow).
    #     # RIMI checks (masks) the destination address to check if it needs
    #     # to change domains.
    #     # Note that:
    #     #  - The callee address is set in a dedicated register.
    #     return [
    #         # Load the PC
    #         UInstruction.auipc(rd=T2, imm=0),
    #         # Compare the PC to the RA, if RA < PC need to change domain
    #         BInstruction.blt(rs1=RA, rs2=T2, imm=8),
    #         # Calling without switching domain
    #         IInstruction.jr(rs1=CALL_TMP_REG),
    #         # Calling and switching domain
    #         RIMIIInstruction.chdom(rd=0, rs1=CALL_TMP_REG, imm=0),
    #     ]

    # @staticmethod
    # def build_ret_from_jit_elt_trampoline() -> List[Instruction]:
    #     # The ret JIT trampoline is used to return from a JIT method/PIC (wow).
    #     # FIXER loads the return address it previously loaded in memory
    #     # Note that:
    #     #  - The RA should be set by the caller (in RA).
    #     #  - For now the branch jumps over an ecall instruction if correct
    #     #    but it should jump to a dedicated exception trap
    #     return [
    #         # Load the PC
    #         UInstruction.auipc(rd=T2, imm=0),
    #         # Compare the PC to the RA, if RA < PC need to change domain
    #         BInstruction.blt(rs1=RA, rs2=T2, imm=8),
    #         # Returning without switching domain
    #         IInstruction.ret(),
    #         # Returning and switching domain
    #         RIMIIInstruction.retdom(),
    #     ]

    # Interpreter calls
    # \___________________

    @staticmethod
    def build_interpreter_trampoline_method_call(
        offset: int, call_trampoline_offset: int
    ) -> List[Instruction]:
        # This method uses the trampoline to call a JIT element
        # It is composed as follows:
        # 1. Setup the calling address in a temporary register
        # 2. Call the "call jit elt" trampoline
        # /!\ The trampoline offset is computed starting from the base address

        # 0x00 auipc temp_call_reg, off_high               (JIT elt addr)
        # 0x04 addi  temp_call_reg, temp_call_reg, off_low (JIT elt addr)
        # 0x08 auipc ra, offset_high (trampoline)
        # 0x0c jalr  offset_low(ra)  (trampoline)

        try:
            # Split offset
            offset_low_target: int
            offset_high_target: int
            offset_low_target, offset_high_target = InstructionBuilder.split_offset(
                offset=offset, min_offset=0xC
            )
            # Split offset trampoline
            offset_low_tramp: int
            offset_high_tramp: int
            offset_low_tramp, offset_high_tramp = InstructionBuilder.split_offset(
                call_trampoline_offset - 0x8, min_offset=0xC
            )
        except WrongOffsetException as err:
            logger.error(err)
            raise
        # Note: minimum offset size of call, mitigation two instructions before call
        return [
            # 1. Setup the calling address in a temporary register
            UInstruction.auipc(CALL_TMP_REG, offset_high_target),
            IInstruction.addi(CALL_TMP_REG, CALL_TMP_REG, offset_low_target),
            UInstruction.auipc(RA, offset_high_tramp),
            RIMIIInstruction.chdom(RA, RA, offset_low_tramp),
        ]

    @staticmethod
    def build_interpreter_trampoline_pic_call(
        offset: int,
        call_trampoline_offset: int,
        hit_case: int,
        hit_case_reg: int = HIT_CASE_REG,
    ) -> List[Instruction]:
        # This method uses the trampoline to call a JIT element
        # It is composed as follows:
        # 1. Setup the calling address in a temporary register
        # 2. Setup the pic case
        # 2. Call the "call jit elt" trampoline
        # /!\ The trampoline offset is computed starting from the base address

        # 0x00 auipc temp_call_reg, off_high               (JIT elt addr)
        # 0x04 addi  temp_call_reg, temp_call_reg, off_low (JIT elt addr)
        # 0x08 addi  hitcase_reg, x0, hit case   (load hit case to check)
        # 0x0c auipc ra, offset_high (trampoline)
        # 0x10 jalr  offset_low(ra)  (trampoline)

        try:
            # Split offset
            offset_low_target: int
            offset_high_target: int
            offset_low_target, offset_high_target = InstructionBuilder.split_offset(
                offset=offset, min_offset=0x14
            )
            # Split offset trampoline
            offset_low_tramp: int
            offset_high_tramp: int
            offset_low_tramp, offset_high_tramp = InstructionBuilder.split_offset(
                call_trampoline_offset - 0xC, min_offset=0x14
            )
        except WrongOffsetException as err:
            logger.error(err)
            raise
        # Note: minimum offset size of call, mitigation two instructions before call
        return [
            # 1. Setup the calling address in a temporary register
            UInstruction.auipc(CALL_TMP_REG, offset_high_target),
            IInstruction.addi(CALL_TMP_REG, CALL_TMP_REG, offset_low_target),
            IInstruction.addi(rd=hit_case_reg, rs1=X0, imm=hit_case),
            UInstruction.auipc(RA, offset_high_tramp),
            RIMIIInstruction.chdom(RA, RA, offset_low_tramp),
        ]

    # Trampolines
    # \_____________

    @staticmethod
    def build_call_jit_elt_trampoline() -> List[Instruction]:
        # The call JIT trampoline is used to call a JIT method/PIC (wow) from the
        # interpreter. It does not do much without isolation solution set up
        # (see RIMI builder!).
        # 1. It stores the return address of the interpreter in the call stack
        # 2. It sets the RA register to the  "return" trampoline
        # 3. It transfers control-flow to the CALL_TMP_REG
        return [
            # 1. Store the return address on the control stack
            IInstruction.addi(rd=RIMI_SSP_REG, rs1=RIMI_SSP_REG, imm=-8),
            RIMISInstruction.sst(rs1=RIMI_SSP_REG, rs2=RA, imm=0),
            # 2. Set RA to the return trampoline (note: should be right after)
            UInstruction.auipc(rd=RA, imm=0),
            IInstruction.addi(rd=RA, rs1=RA, imm=0xC),
            # 3. CF transfer
            IInstruction.jr(rs1=CALL_TMP_REG),
        ]

    @staticmethod
    def build_ret_from_jit_elt_trampoline() -> List[Instruction]:
        # The ret JIT trampoline is used to return from a JIT method/PIC (wow).
        # It does not do much without isolation solution set up (see RIMI builder!).
        # 1. It pops the return address from the call stack
        # 2. Comparison if the return address is JIT/interpreter
        # 3. Transfer control-flow (with ret or variant)
        return [
            # 1. Store the return address on the control stack
            RIMIIInstruction.lst(rd=RA, rs1=RIMI_SSP_REG, imm=0),
            IInstruction.addi(rd=RIMI_SSP_REG, rs1=RIMI_SSP_REG, imm=8),
            # 2. Compare to PC
            # UInstruction.auipc(rd=CALL_TMP_REG, imm=0),
            # BInstruction.blt(rs1=RA, rs2=CALL_TMP_REG, imm=8),
            # # 3. CF transfer (identical in this case)
            # IInstruction.ret(),
            RIMIIInstruction.retdom(),
        ]
