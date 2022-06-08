import unittest

from gigue.snippets import Add


class SnippetTest(unittest.TestCase):

    def test_add(self):
        instr = Add(rd=5, rs1=6, rs2=7)
        instr.generate()
        self.assertEqual(instr.opcode7, Add.OPCODE7_ADD)
        self.assertEqual(instr.opcode3, Add.OPCODE3_ADD)
