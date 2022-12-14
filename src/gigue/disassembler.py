from gigue.constants import find_instr_for_opcode


# TODO: Doc
class Disassembler:
    @staticmethod
    def sign_extend(value, bits):
        sign_bit = 1 << (bits - 1)
        return (value & (sign_bit - 1)) - (value & sign_bit)

    @staticmethod
    def extract_info(instruction, size, shift):
        mask = (1 << size) - 1
        return (instruction & (mask << shift)) >> shift

    @staticmethod
    def get_instruction_type(instruction):
        return find_instr_for_opcode(instruction & 0x3F).type

    def extract_opcode7(self, instruction):
        return self.extract_info(instruction, 7, 0)

    def extract_opcode3(self, instruction):
        return self.extract_info(instruction, 3, 12)

    def extract_imm_b(self, instruction):
        # imm[12|10:5] << 25
        # imm[4:1|11]  << 7
        immediate = self.extract_info(instruction, 4, 8) << 1
        immediate |= self.extract_info(instruction, 6, 25) << 5
        immediate |= self.extract_info(instruction, 1, 7) << 11
        immediate |= self.extract_info(instruction, 1, 31) << 12
        return self.sign_extend(immediate, 13)

    def extract_imm_i(self, instruction):
        immediate = self.extract_info(instruction, 12, 20)
        return self.sign_extend(immediate, 12)

    def extract_imm_j(self, instruction):
        # imm[20 | 10:1 | 11 | 19:12]
        immediate = self.extract_info(instruction, 10, 21) << 1
        immediate |= self.extract_info(instruction, 1, 20) << 11
        immediate |= self.extract_info(instruction, 8, 12) << 12
        immediate |= self.extract_info(instruction, 1, 31) << 20
        return self.sign_extend(immediate, 21)

    def extract_imm_s(self, instruction):
        immediate = self.extract_info(instruction, 5, 7)
        immediate |= self.extract_info(instruction, 7, 25) << 5
        return self.sign_extend(immediate, 12)

    def extract_imm_u(self, instruction):
        immediate = self.extract_info(instruction, 20, 12) << 12
        return self.sign_extend(immediate, 32)

    def extract_rd(self, instruction):
        return self.extract_info(instruction, 5, 7)

    def extract_rs1(self, instruction):
        return self.extract_info(instruction, 5, 15)

    def extract_rs2(self, instruction):
        return self.extract_info(instruction, 5, 20)

    def extract_top7(self, instruction):
        return self.extract_info(instruction, 7, 25)

    def extract_call_offset(self, instructions):
        # instructions correspond to [auipc(offset high), jalr(offset low)]
        offset_low = self.extract_imm_i(instructions[1])
        offset_high = self.extract_imm_u(instructions[0])
        signed_offset_low = self.sign_extend(offset_low, 12)
        signed_offset_high = self.sign_extend(offset_high, 32)
        print(
            "Disassembler:\nlowo {}\nhigho {}\nsignlowo {}\nsignhigho {}\nsum {}\n__________".format(
                hex(offset_low),
                hex(offset_high),
                hex(signed_offset_low),
                hex(signed_offset_high),
                hex(signed_offset_low + signed_offset_high),
            )
        )
        return signed_offset_low + signed_offset_high

    def disassemble(self, instruction):
        instr_type = self.get_instruction_type(instruction)
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

    def disassemble_r_instruction(self, instruction):
        disa_instr = "Disassembled R instruction:\n"
        disa_instr += "opcode7: {}\n".format(
            str(bin(self.extract_opcode7(instruction)))
        )
        disa_instr += "opcode3: {}\n".format(
            str(bin(self.extract_opcode3(instruction)))
        )
        disa_instr += "rd: {}\n".format(str(self.extract_rd(instruction)))
        disa_instr += "rs1: {}\n".format(str(self.extract_rs1(instruction)))
        disa_instr += "rs2: {}".format(str(self.extract_rs2(instruction)))
        return disa_instr

    def disassemble_i_instruction(self, instruction):
        disa_instr = "Disassembled I instruction:\n"
        disa_instr += "opcode7: {}\n".format(
            str(bin(self.extract_opcode7(instruction)))
        )
        disa_instr += "opcode3: {}\n".format(
            str(bin(self.extract_opcode3(instruction)))
        )
        disa_instr += "rd: {}\n".format(str(self.extract_rd(instruction)))
        disa_instr += "rs1: {}\n".format(str(self.extract_rs1(instruction)))
        disa_instr += "imm: {}".format(str(self.extract_imm_i(instruction)))
        return disa_instr

    def disassemble_u_instruction(self, instruction):
        disa_instr = "Disassembled U instruction:\n"
        disa_instr += "opcode7: {}\n".format(
            str(bin(self.extract_opcode7(instruction)))
        )
        disa_instr += "rd: {}\n".format(str(self.extract_rd(instruction)))
        disa_instr += "imm: {}".format(str(self.extract_imm_u(instruction)))
        return disa_instr

    def disassemble_j_instruction(self, instruction):
        disa_instr = "Disassembled  instruction:\n"
        disa_instr += "opcode7: {}\n".format(
            str(bin(self.extract_opcode7(instruction)))
        )
        disa_instr += "rd: {}\n".format(str(self.extract_rd(instruction)))
        disa_instr += "imm: {}".format(str(self.extract_imm_j(instruction)))
        return disa_instr

    def disassemble_s_instruction(self, instruction):
        disa_instr = "Disassembled S instruction:\n"
        disa_instr += "opcode7: {}\n".format(
            str(bin(self.extract_opcode7(instruction)))
        )
        disa_instr += "opcode3: {}\n".format(
            str(bin(self.extract_opcode3(instruction)))
        )
        disa_instr += "rs1: {}\n".format(str(self.extract_rs1(instruction)))
        disa_instr += "rs2: {}\n".format(str(self.extract_rs2(instruction)))
        disa_instr += "imm: {}".format(str(self.extract_imm_s(instruction)))
        return disa_instr

    def disassemble_b_instruction(self, instruction):
        disa_instr = "Disassembled B instruction:\n"
        disa_instr += "opcode7: {}\n".format(
            str(bin(self.extract_opcode7(instruction)))
        )
        disa_instr += "opcode3: {}\n".format(
            str(bin(self.extract_opcode3(instruction)))
        )
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
