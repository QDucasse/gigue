import random
from typing import Callable, List

from gigue.builder import InstructionBuilder
from gigue.rot.rot_instructions import RotIInstruction, RotRInstruction


class RotInstructionBuilder(InstructionBuilder):
    ROT_I_INSTRUCTIONS = ["rori"]
    ROT_R_INSTRUCTIONS = ["rol", "ror"]

    @staticmethod
    def build_random_i_instruction(
        registers: List[int], *args, **kwargs
    ) -> RotIInstruction:
        name: str = random.choice(
            InstructionBuilder.I_INSTRUCTIONS + RotInstructionBuilder.ROT_I_INSTRUCTIONS
        )
        constr: Callable = getattr(RotIInstruction, name)
        # Choose registers
        rd: int
        rs1: int
        [rd, rs1] = tuple(random.choices(registers, k=2))
        # Choose immediate (note: max 6 bits for rotations)
        imm = random.randint(0, 0x1F)
        return constr(rd=rd, rs1=rs1, imm=imm)

    @staticmethod
    def build_random_r_instruction(
        registers: List[int], *args, **kwargs
    ) -> RotRInstruction:
        # Get instruction constructor
        name: str = random.choice(
            InstructionBuilder.R_INSTRUCTIONS + RotInstructionBuilder.ROT_R_INSTRUCTIONS
        )
        constr: Callable = getattr(RotRInstruction, name)
        # Choose registers
        rs1: int
        rs2: int
        rd: int
        [rs1, rs2, rd] = tuple(random.choices(registers, k=3))
        return constr(rd=rd, rs1=rs1, rs2=rs2)
