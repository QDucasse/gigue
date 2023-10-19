import logging
from dataclasses import dataclass
from typing import List

from gigue.instructions import IInstruction, Instruction, UInstruction
from gigue.rimi.rimi_instructions import RIMIIInstruction, RIMISInstruction
from prelude.exceptions import MissingExampleException

logger = logging.getLogger("prelude")


@dataclass
class InstructionExample:
    keys: List[str]
    instructions: List[Instruction]


class Tutorial:
    def __init__(self, examples: List[InstructionExample]):
        self.examples: List[InstructionExample] = examples

    def example_for(self, instr_name: str) -> List[Instruction]:
        for example in self.examples:
            if instr_name in example.keys:
                return example.instructions
        print(self.examples)
        msg = f"No example were found for key {instr_name}."
        logger.error(msg)
        raise MissingExampleException(msg)

    def example_binary_for(self, instr_name: str) -> bytes:
        list_instr = [instr.generate_bytes() for instr in self.example_for(instr_name)]
        bytes_instr = b"".join(list_instr)
        return bytes_instr


# Base instructions tutorial
# TODO!


# FIXER instructions tutorial
# TODO!


# RIMI instructions tutorial
RIMI_TUTORIAL: Tutorial = Tutorial(
    examples=[
        # ==========================
        # load/stores:
        #    add value to check
        #    store value
        #    load value back
        # ==========================
        InstructionExample(
            ["lb1", "sb1"],
            [
                IInstruction.addi(rd=10, rs1=0, imm=0x12),
                RIMISInstruction.sb1(rs1=31, rs2=10, imm=0),
                RIMIIInstruction.lb1(rd=10, rs1=31, imm=0),
            ],
        ),
        InstructionExample(
            ["lh1", "sh1"],
            [
                IInstruction.addi(rd=10, rs1=0, imm=0x1234),
                RIMISInstruction.sh1(rs1=31, rs2=10, imm=0),
                RIMIIInstruction.lh1(rd=10, rs1=31, imm=0),
            ],
        ),
        InstructionExample(
            ["lw1", "sw1"],
            [
                IInstruction.addi(rd=10, rs1=0, imm=0xFF),
                RIMISInstruction.sw1(rs1=31, rs2=10, imm=0),
                RIMIIInstruction.lw1(rd=10, rs1=31, imm=0),
            ],
        ),
        InstructionExample(
            ["ld1", "sd1"],
            [
                IInstruction.addi(rd=10, rs1=0, imm=0xFF),
                RIMISInstruction.sd1(rs1=31, rs2=10, imm=0),
                RIMIIInstruction.ld1(rd=10, rs1=31, imm=0),
            ],
        ),
        InstructionExample(
            ["lst", "sst"],
            [
                IInstruction.addi(rd=10, rs1=0, imm=0x12345678),
                RIMISInstruction.sst(rs1=28, rs2=1, imm=0),
                RIMIIInstruction.lst(rd=1, rs1=28, imm=0),
            ],
        ),
        # ==========================
        # change domain:
        #    add pc + 6
        #    jump to this value
        #    return from domain
        # ==========================
        InstructionExample(
            ["chdom", "retdom"],
            [
                UInstruction.auipc(6, 0),
                IInstruction.addi(6, 6, 12),
                RIMIIInstruction.chdom(0, 6, 0),
                RIMIIInstruction.retdom(),
            ],
        ),
    ]
)
