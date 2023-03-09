from gigue.builder import InstructionBuilder
from gigue.constants import RA
from gigue.fixer.constants import FIXER_CMP_REG
from gigue.fixer.instructions import FIXERCustomInstruction
from gigue.instructions import BInstruction, IInstruction


class FIXERInstructionBuilder(InstructionBuilder):
    # Tags around calls
    # \________________

    @staticmethod
    def build_method_call(*args, **kwargs):
        instructions = [FIXERCustomInstruction.cficall(rd=0, rs1=FIXER_CMP_REG, rs2=0)]
        instructions += InstructionBuilder.build_method_call(*args, **kwargs)
        return instructions

    @staticmethod
    def build_pic_call(*args, **kwargs):
        instructions = [FIXERCustomInstruction.cficall(rd=0, rs1=FIXER_CMP_REG, rs2=0)]
        instructions += InstructionBuilder.build_pic_call(*args, **kwargs)
        return instructions

    # Tags around rets
    # \_______________

    # If the check does not pass, it goes to ebreak, otherwise jumps over
    @staticmethod
    def build_epilogue(*args, **kwargs):
        instructions = InstructionBuilder.build_epilogue(*args, **kwargs)
        instructions.insert(
            -1, FIXERCustomInstruction.cfiret(rd=FIXER_CMP_REG, rs1=0, rs2=0)
        )

        instructions.insert(-1, BInstruction.beq(rs1=RA, rs2=FIXER_CMP_REG, imm=8))
        instructions.insert(-1, IInstruction.ebreak())
        return instructions
