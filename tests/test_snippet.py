import unittest

from gigue.constants import instructions_info
from gigue.snippets import I_Instruction
from gigue.snippets import R_Instruction


class SnippetTest(unittest.TestCase):

    def test_add(self):
        instr = R_Instruction.add(rd=5, rs1=6, rs2=7)
        print(instr.opcode3)
        self.assertEqual(instr.opcode7, instructions_info["add"].opcode7)
        self.assertEqual(instr.opcode3, instructions_info["add"].opcode3)

    def test_addi(self):
        instr = I_Instruction.addi(rd=5, rs1=6, imm=255)
        self.assertEqual(instr.opcode7, instructions_info["addi"].opcode7)
        self.assertEqual(instr.opcode3, instructions_info["addi"].opcode3)


if __name__ == "__main__":
    unittest.main()
