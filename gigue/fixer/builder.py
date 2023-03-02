from gigue.builder import InstructionBuilder
from gigue.constants import RA
from gigue.fixer.constants import FIXER_CMP_REG
from gigue.fixer.instructions import FIXERCustomInstruction
from gigue.instructions import BInstruction


class FIXERInstructionBuilder(InstructionBuilder):
    # Tags around calls
    # \________________

    @staticmethod
    def build_method_call(*args, **kwargs):
        instructions = [FIXERCustomInstruction.cficall(rd=0, rs1=FIXER_CMP_REG, rs2=0)]
        instructions += InstructionBuilder.build_method_call(*args, **kwargs)

    @staticmethod
    def build_pic_call(*args, **kwargs):
        instructions = [FIXERCustomInstruction.cficall(rd=0, rs1=FIXER_CMP_REG)]
        instructions += InstructionBuilder.build_method_call(*args, **kwargs)

    # Tags around rets
    # \_______________

    # TODO: Branch to fail!!!
    @staticmethod
    def build_epilogue(offset_cfi_fail, *args, **kwargs):
        instructions = InstructionBuilder.build_epilogue(*args, **kwargs)
        instructions.insert(
            -1, FIXERCustomInstruction.cfiret(rd=FIXER_CMP_REG, rs1=0, rs2=0)
        )
        instructions.insert(
            -1, BInstruction.bne(rs1=RA, rs2=FIXER_CMP_REG, imm=offset_cfi_fail)
        )
        return instructions
