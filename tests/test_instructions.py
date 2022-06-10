import pytest

from gigue.constants import instructions_info
from gigue.disassembler import Disassembler
from gigue.instructions import BInstruction
from gigue.instructions import IInstruction
from gigue.instructions import JInstruction
from gigue.instructions import RInstruction
from gigue.instructions import SInstruction
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
@pytest.mark.parametrize("imm", [0x7FFFFFFF, 0x7FFFF000, 0x00001FFF])
def test_correct_encoding_uinstr(name, imm):
    constr = getattr(UInstruction, name)
    instr = constr(rd=5, imm=imm)
    mc_instr = instr.generate()
    assert instr.opcode7 == instructions_info[name].opcode7
    assert instr.rd == disassembler.extract_rd(mc_instr)
    assert instr.imm & 0xFFFFF000 == disassembler.extract_imm_u(mc_instr)


@pytest.mark.parametrize("imm,res", [
    (0x7FFFFFFF, 0xFFFFF),
    (0x7FFFF000, 0x800FF),
    (0x00001FFF, 0x7FF01),
    (0x000001FF, 0x1FE00),
    (0x001FFFFE, 0xFFFFF)
])
def test_immediate_shuffle(imm, res):
    instr = JInstruction("rand", 0b1111111, 6, imm)
    shuffle = instr.shuffle_imm()
    assert shuffle == res


# TODO: Check
@pytest.mark.parametrize("name", ["jal"])
@pytest.mark.parametrize("imm", [
    0x7FFFFFFF, 0x7FFFF000, 0x00001FFF, 0x001FFFFE, 0x000001FF
])
def test_correct_encoding_jinstr(name, imm):
    constr = getattr(JInstruction, name)
    instr = constr(rd=5, imm=imm)
    mc_instr = instr.generate()
    assert instr.opcode7 == instructions_info[name].opcode7
    assert instr.rd == disassembler.extract_rd(mc_instr)
    print(hex(instr.imm & 0x1FFFFE))
    assert instr.imm & 0x1FFFFE == disassembler.extract_imm_j(mc_instr)


# TODO: Check
@pytest.mark.parametrize("name", ["sb", "sd", "sh", "sw"])
@pytest.mark.parametrize("imm", [0xFFF, 0x1F, 0xFC0])
def test_correct_encoding_sinstr(name, imm):
    constr = getattr(SInstruction, name)
    instr = constr(rs1=5, rs2=6, imm=imm)
    mc_instr = instr.generate()
    assert instr.opcode7 == instructions_info[name].opcode7
    assert instr.opcode3 == instructions_info[name].opcode3
    assert instr.rs1 == disassembler.extract_rs1(mc_instr)
    assert instr.rs2 == disassembler.extract_rs2(mc_instr)
    assert instr.imm & 0xFFF == disassembler.extract_imm_s(mc_instr)


# TODO: Check
@pytest.mark.parametrize("name", ["beq", "bge", "bgeu", "blt", "bltu", "bne"])
@pytest.mark.parametrize("imm", [0xFFF, 0x1F, 0xFC0])
def test_correct_encoding_binstr(name, imm):
    constr = getattr(BInstruction, name)
    instr = constr(rs1=5, rs2=6, imm=imm)
    mc_instr = instr.generate()
    assert instr.opcode7 == instructions_info[name].opcode7
    assert instr.opcode3 == instructions_info[name].opcode3
    assert instr.rs1 == disassembler.extract_rs1(mc_instr)
    assert instr.rs2 == disassembler.extract_rs2(mc_instr)
    assert instr.imm & 0x1FFE == disassembler.extract_imm_b(mc_instr)
