import pytest

from gigue.constants import instructions_info
from gigue.instructions import IInstruction
from gigue.instructions import RInstruction
from gigue.disassembler import Disassembler


disassembler = Disassembler()


@pytest.mark.parametrize("name", ["add", "addw"])
def test_correct_encoding_rinstr(name):
    constr = getattr(RInstruction, name)
    instr = constr(rd=5, rs1=6, rs2=7)
    mc_instr = instr.generate()
    assert instr.opcode7 == instructions_info[name].opcode7
    assert instr.opcode3 == instructions_info[name].opcode3
    assert instr.rd == disassembler.extract_rd(mc_instr)
    assert instr.rs1 == disassembler.extract_rs1(mc_instr)
    assert instr.rs2 == disassembler.extract_rs2(mc_instr)


@pytest.mark.parametrize("name", ["addi", "addiw"])
def test_correct_encoding_iinstr(name):
    constr = getattr(IInstruction, name)
    instr = constr(rd=5, rs1=6, imm=255)
    mc_instr = instr.generate()
    assert instr.opcode7 == instructions_info[name].opcode7
    assert instr.opcode3 == instructions_info[name].opcode3
    assert instr.rd == disassembler.extract_rd(mc_instr)
    assert instr.rs1 == disassembler.extract_rs1(mc_instr)
    assert instr.imm == disassembler.extract_imm_i(mc_instr)
