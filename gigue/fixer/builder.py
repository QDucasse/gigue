from typing import List

from gigue.builder import InstructionBuilder
from gigue.constants import CALL_TMP_REG, RA
from gigue.exceptions import WrongOffsetException
from gigue.fixer.constants import FIXER_CMP_REG
from gigue.fixer.instructions import FIXERCustomInstruction
from gigue.instructions import BInstruction, IInstruction, Instruction, UInstruction


class FIXERInstructionBuilder(InstructionBuilder):
    # NO TRAMPOLINE
    # \__________________________________________________________________________________

    # Tags around calls
    # \_________________

    # Note: These method should come in through the generator
    # and expand around the existing callsite.
    # Note 2: This means the element addresses should be patched
    # as well!
    @staticmethod
    def build_method_base_call(offset: int) -> List[Instruction]:
        # The instrumented call looks like the following:
        # 0x00 auipc fix, 0         |  \
        # 0x04 addi  fix, fix, 0x14 | - > Generate the return address
        # 0x08 cficall              | - > Store the ra in fix in memory
        # 0x0c auipc ra, ra, off    |  \
        # 0x10 jalr  ra, off        | - > Generic call with corrected offset
        # 0x14 < ra should point here!
        if abs(offset) < 20:
            raise WrongOffsetException(
                f"Call offset should be greater than 20 (currently {offset})."
            )
        instructions: List[Instruction] = [
            # Storing ra in FIXER_CMP_REG, has to take in account
            UInstruction.auipc(rd=FIXER_CMP_REG, imm=0),
            IInstruction.addi(rd=FIXER_CMP_REG, rs1=FIXER_CMP_REG, imm=0x14),
            # Custom instruction to store the saved ra in memory
            FIXERCustomInstruction.cficall(rd=0, rs1=FIXER_CMP_REG, rs2=0),
        ]
        instructions += InstructionBuilder.build_method_base_call(offset - 12)
        # Note: -12 to mitigate the three additional instructions
        return instructions

    @staticmethod
    def build_pic_base_call(offset: int, *args, **kwargs) -> List[Instruction]:
        # The instrumented call looks like the following:
        # 0x00 auipc fix, 0         |  \
        # 0x04 addi  fix, fix, 0x18 | - > Generate the return address
        # 0x08 cficall              | - > Store the ra in fix in memory
        # 0x0c li cmp, hitcase      |
        # 0x10 auipc ra, ra, off    |  \
        # 0x14 jalr  ra, off        | - > Generic call with corrected offset
        # 0x18 < ra should point here!
        if abs(offset) < 24:
            raise WrongOffsetException(
                f"Call offset should be greater than 20 (currently {offset})."
            )
        instructions: List[Instruction] = [
            # Storing ra in FIXER_CMP_REG, has to take in account
            UInstruction.auipc(rd=FIXER_CMP_REG, imm=0),
            IInstruction.addi(rd=FIXER_CMP_REG, rs1=FIXER_CMP_REG, imm=0x18),
            # Custom instruction to store the saved ra in memory
            FIXERCustomInstruction.cficall(rd=0, rs1=FIXER_CMP_REG, rs2=0),
        ]
        instructions += InstructionBuilder.build_pic_base_call(
            offset=offset - 12, *args, **kwargs  # type: ignore
        )
        # Note:  type ignore due to star args
        # Note: -12 to mitigate the three additional instructions
        return instructions

    # Tags around rets
    # \________________

    # If the check does not pass, it goes to ebreak, otherwise jumps over
    @staticmethod
    def build_epilogue(*args, **kwargs) -> List[Instruction]:
        instructions: List[Instruction] = InstructionBuilder.build_epilogue(
            *args, **kwargs
        )
        instructions.insert(
            -1, FIXERCustomInstruction.cfiret(rd=FIXER_CMP_REG, rs1=0, rs2=0)
        )

        instructions.insert(-1, BInstruction.beq(rs1=RA, rs2=FIXER_CMP_REG, imm=8))
        instructions.insert(-1, IInstruction.ecall())
        return instructions

    # WITH TRAMPOLINES
    # \__________________________________________________________________________________

    # Tags around calls
    # \_________________

    @staticmethod
    def build_call_jit_elt_trampoline() -> List[Instruction]:
        # The call JIT trampoline is used to call a JIT method/PIC (wow).
        # FIXER saves the RA in coprocessor memory
        # Note that:
        #  - The RA should be set by the caller.
        #  - The callee address is set in a dedicated register.
        return [
            FIXERCustomInstruction.cficall(rd=0, rs1=RA, rs2=0),
            IInstruction.jr(rs1=CALL_TMP_REG),
        ]

    @staticmethod
    def build_ret_from_jit_elt_trampoline() -> List[Instruction]:
        # The ret JIT trampoline is used to return from a JIT method/PIC (wow).
        # FIXER loads the return address it previously loaded in memory
        # Note that:
        #  - The RA should be set by the caller (in RA).
        #  - For now the branch jumps over an ecall instruction if correct
        #    but it should jump to a dedicated exception trap
        return [
            FIXERCustomInstruction.cfiret(rd=FIXER_CMP_REG, rs1=0, rs2=0),
            BInstruction.beq(rs1=RA, rs2=FIXER_CMP_REG, imm=8),
            IInstruction.ecall(),
            IInstruction.ret(),
        ]
