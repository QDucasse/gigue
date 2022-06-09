import pytest

from gigue.constants import instructions_info
from gigue.disassembler import Disassembler
from gigue.instructions import IInstruction
from gigue.instructions import RInstruction
from gigue.instructions import UInstruction

disassembler = Disassembler()


# TODO: Check
@pytest.mark.parametrize("name", [
    "add", "addw", "andr", "mul", "mulh", "mulhsu", "mulhu", "mulw", "orr", "sll",
    "sllw", "slt", "sltu", "sra", "sraw", "srl", "srlw", "sub", "subw", "xor"
])
def test_correct_encoding_rinstr(name):
    constr = getattr(RInstruction, name)
    instr = constr(rd=5, rs1=6, rs2=7)
    mc_instr = instr.generate()
    assert instr.opcode7 == instructions_info[name].opcode7
    assert instr.opcode3 == instructions_info[name].opcode3
    assert instr.rd == disassembler.extract_rd(mc_instr)
    assert instr.rs1 == disassembler.extract_rs1(mc_instr)
    assert instr.rs2 == disassembler.extract_rs2(mc_instr)
    assert instr.top7 == disassembler.extract_top7(mc_instr)


# TODO: Check
@pytest.mark.parametrize("name", [
    "addi", "addiw", "andi", "jalr", "lb", "lbu", "ld", "lh", "lhu", "ori",
    "slli", "slliw", "slti", "sltiu", "srai", "sraiw", "srli", "srliw", "xori"
])
def test_correct_encoding_iinstr(name):
    constr = getattr(IInstruction, name)
    instr = constr(rd=5, rs1=6, imm=255)
    mc_instr = instr.generate()
    assert instr.opcode7 == instructions_info[name].opcode7
    assert instr.opcode3 == instructions_info[name].opcode3
    assert instr.rd == disassembler.extract_rd(mc_instr)
    assert instr.rs1 == disassembler.extract_rs1(mc_instr)
    assert instr.imm == disassembler.extract_imm_i(mc_instr)


# TODO: Check
@pytest.mark.parametrize("name", ["auipc", "lui"])
def test_correct_encoding_uinstr(name):
    constr = getattr(UInstruction, name)
    instr = constr(rd=5, imm=0x7FFFFFFF)
    mc_instr = instr.generate()
    assert instr.opcode7 == instructions_info[name].opcode7
    assert instr.rd == disassembler.extract_rd(mc_instr)
    assert instr.imm & 0xFFFFF000 == disassembler.extract_imm_u(mc_instr)
