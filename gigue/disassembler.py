from __future__ import annotations

from typing import TYPE_CHECKING, Dict, List

from gigue.constants import INSTRUCTIONS_INFO
from gigue.exceptions import UnknownInstructionException
from gigue.helpers import to_signed

if TYPE_CHECKING:
    from gigue.constants import InstructionInfo


class Disassembler:
    DEFAULT_SIGN_EXTENSION: bool = False

    def __init__(
        self, instructions_info: Dict[str, InstructionInfo] = INSTRUCTIONS_INFO
    ):
        self.instructions_info: Dict[str, InstructionInfo] = instructions_info

    # ===================================
    #              Helpers
    # ===================================

    @staticmethod
    def sign_extend(value: int, bits: int) -> int:
        sign_bit: int = 1 << (bits - 1)
        return (value & (sign_bit - 1)) - (value & sign_bit)

    @staticmethod
    def extract_info(instruction: int, size: int, shift: int) -> int:
        mask: int = (1 << size) - 1
        return (instruction & (mask << shift)) >> shift

    # ===================================
    #     Instruction info extractors
    # ===================================

    def get_instruction_type(self, instruction: int) -> str:
        return self.get_instruction_info(instruction).instr_type

    def get_instruction_name(self, instruction: int) -> str:
        return self.get_instruction_info(instruction).name

    def get_instruction_info(self, instruction: int) -> InstructionInfo:
        for info in self.instructions_info.values():
            if (info.cmp_mask & instruction) == info.cmp_val:
                return info
        raise UnknownInstructionException(
            f"No match for instruction {hex(instruction)}. Extracted opcode"
            f" ({hex(self.extract_opcode(instruction))}), funct3"
            f" ({self.extract_funct3(instruction)}) and funct7"
            f" ({self.extract_funct7(instruction)})."
        )

    # ===================================
    #         Field extraction
    # ===================================

    def extract_opcode(self, instruction: int) -> int:
        return self.extract_info(instruction, 7, 0)

    def extract_funct3(self, instruction: int) -> int:
        return self.extract_info(instruction, 3, 12)

    def extract_xd(self, instruction: int) -> int:
        return self.extract_info(instruction, 1, 14)

    def extract_xs1(self, instruction: int) -> int:
        return self.extract_info(instruction, 1, 13)

    def extract_xs2(self, instruction: int) -> int:
        return self.extract_info(instruction, 1, 12)

    def extract_rd(self, instruction: int) -> int:
        return self.extract_info(instruction, 5, 7)

    def extract_rs1(self, instruction: int) -> int:
        return self.extract_info(instruction, 5, 15)

    def extract_rs2(self, instruction: int) -> int:
        return self.extract_info(instruction, 5, 20)

    def extract_funct7(self, instruction: int) -> int:
        return self.extract_info(instruction, 7, 25)

    # ===================================
    #     Immediate value extraction
    # ===================================

    def extract_imm_b(
        self, instruction: int, sign_extend: bool = DEFAULT_SIGN_EXTENSION
    ) -> int:
        # imm[12|10:5] << 25
        # imm[4:1|11]  << 7
        immediate: int = self.extract_info(instruction, 4, 8) << 1
        immediate |= self.extract_info(instruction, 6, 25) << 5
        immediate |= self.extract_info(instruction, 1, 7) << 11
        immediate |= self.extract_info(instruction, 1, 31) << 12
        if sign_extend:
            return to_signed(immediate, 13)
        return immediate

    def extract_imm_i(
        self, instruction: int, sign_extend: bool = DEFAULT_SIGN_EXTENSION
    ) -> int:
        immediate: int = self.extract_info(instruction, 12, 20)
        if sign_extend:
            return to_signed(immediate, 12)
        return immediate

    def extract_imm_j(
        self, instruction: int, sign_extend: bool = DEFAULT_SIGN_EXTENSION
    ) -> int:
        # imm[20 | 10:1 | 11 | 19:12]
        immediate: int = self.extract_info(instruction, 10, 21) << 1
        immediate |= self.extract_info(instruction, 1, 20) << 11
        immediate |= self.extract_info(instruction, 8, 12) << 12
        immediate |= self.extract_info(instruction, 1, 31) << 20
        if sign_extend:
            return to_signed(immediate, 21)
        return immediate

    def extract_imm_s(
        self, instruction: int, sign_extend: bool = DEFAULT_SIGN_EXTENSION
    ):
        immediate: int = self.extract_info(instruction, 5, 7)
        immediate |= self.extract_info(instruction, 7, 25) << 5
        if sign_extend:
            return to_signed(immediate, 12)
        return immediate

    def extract_imm_u(
        self, instruction: int, sign_extend: bool = DEFAULT_SIGN_EXTENSION
    ):
        immediate: int = self.extract_info(instruction, 20, 12) << 12
        if sign_extend:
            return to_signed(immediate, 32)
        return immediate

    def extract_pc_relative_offset(self, instructions: List[int]) -> int:
        # instructions correspond to [auipc(offset high), jalr(offset low)]
        offset_low: int = self.extract_imm_i(instructions[1])
        offset_high: int = self.extract_imm_u(instructions[0])
        signed_offset_low: int = self.sign_extend(offset_low, 12)
        signed_offset_high: int = self.sign_extend(offset_high, 32)
        # print(
        #     "Disassembler:\nlowo {}\nhigho {}\nsignlowo {}\nsignhigho {}\nsum"
        #     " {}\n__________".format(
        #         hex(offset_low),
        #         hex(offset_high),
        #         hex(signed_offset_low),
        #         hex(signed_offset_high),
        #         hex(signed_offset_low + signed_offset_high),
        #     )
        # )
        return signed_offset_low + signed_offset_high

    # ===================================
    #            Disassembly
    # ===================================

    def disassemble(self, instruction: int) -> str:
        instr_type: str = self.get_instruction_type(instruction)
        if instr_type == "R":
            return self.disassemble_r_instruction(instruction)
        elif instr_type == "I":
            return self.disassemble_i_instruction(instruction)
        elif instr_type == "J":
            return self.disassemble_r_instruction(instruction)
        elif instr_type == "U":
            return self.disassemble_u_instruction(instruction)
        elif instr_type == "S":
            return self.disassemble_s_instruction(instruction)
        else:
            raise NotImplementedError("Instruction type not recognized.")

    def disassemble_r_instruction(self, instruction: int) -> str:
        disa_instr: str = "Disassembled R instruction:\n"
        disa_instr += "opcode: {}\n".format(str(bin(self.extract_opcode(instruction))))
        disa_instr += "funct3: {}\n".format(str(bin(self.extract_funct3(instruction))))
        disa_instr += "rd: {}\n".format(str(self.extract_rd(instruction)))
        disa_instr += "rs1: {}\n".format(str(self.extract_rs1(instruction)))
        disa_instr += "rs2: {}".format(str(self.extract_rs2(instruction)))
        return disa_instr

    def disassemble_i_instruction(self, instruction: int) -> str:
        disa_instr: str = "Disassembled I instruction:\n"
        disa_instr += "opcode: {}\n".format(str(bin(self.extract_opcode(instruction))))
        disa_instr += "funct3: {}\n".format(str(bin(self.extract_funct3(instruction))))
        disa_instr += "rd: {}\n".format(str(self.extract_rd(instruction)))
        disa_instr += "rs1: {}\n".format(str(self.extract_rs1(instruction)))
        disa_instr += "imm: {}".format(str(self.extract_imm_i(instruction)))
        return disa_instr

    def disassemble_u_instruction(self, instruction: int) -> str:
        disa_instr: str = "Disassembled U instruction:\n"
        disa_instr += "opcode: {}\n".format(str(bin(self.extract_opcode(instruction))))
        disa_instr += "rd: {}\n".format(str(self.extract_rd(instruction)))
        disa_instr += "imm: {}".format(str(self.extract_imm_u(instruction)))
        return disa_instr

    def disassemble_j_instruction(self, instruction: int) -> str:
        disa_instr: str = "Disassembled  instruction:\n"
        disa_instr += "opcode: {}\n".format(str(bin(self.extract_opcode(instruction))))
        disa_instr += "rd: {}\n".format(str(self.extract_rd(instruction)))
        disa_instr += "imm: {}".format(str(self.extract_imm_j(instruction)))
        return disa_instr

    def disassemble_s_instruction(self, instruction: int) -> str:
        disa_instr: str = "Disassembled S instruction:\n"
        disa_instr += "opcode: {}\n".format(str(bin(self.extract_opcode(instruction))))
        disa_instr += "funct3: {}\n".format(str(bin(self.extract_funct3(instruction))))
        disa_instr += "rs1: {}\n".format(str(self.extract_rs1(instruction)))
        disa_instr += "rs2: {}\n".format(str(self.extract_rs2(instruction)))
        disa_instr += "imm: {}".format(str(self.extract_imm_s(instruction)))
        return disa_instr

    def disassemble_b_instruction(self, instruction: int) -> str:
        disa_instr: str = "Disassembled B instruction:\n"
        disa_instr += "opcode: {}\n".format(str(bin(self.extract_opcode(instruction))))
        disa_instr += "funct3: {}\n".format(str(bin(self.extract_funct3(instruction))))
        disa_instr += "rs1: {}\n".format(str(self.extract_rs1(instruction)))
        disa_instr += "rs2: {}\n".format(str(self.extract_rs2(instruction)))
        disa_instr += "imm: {}".format(str(self.extract_imm_b(instruction)))
        return disa_instr


if __name__ == "__main__":
    # addi 5, 6, 255
    instr = 0xFF30293
    disa = Disassembler()
    print(disa.get_instruction_type(instr))
    print(disa.disassemble(instr))
