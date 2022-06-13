import pytest
from capstone import CS_ARCH_RISCV
from capstone import CS_MODE_RISCV64
from capstone import Cs

from gigue.constants import instructions_info
from gigue.disassembler import Disassembler
from gigue.instructions import BInstruction
from gigue.instructions import IInstruction
from gigue.instructions import JInstruction
from gigue.instructions import RInstruction
from gigue.instructions import SInstruction
from gigue.instructions import UInstruction


# =================================
#         Disassemblers
# =================================


disassembler = Disassembler()
cap_disasm = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)


def imm_str(immediate):
    if immediate < 0xA:
        return str(immediate)
    else:
        return hex(immediate)


# =================================
#         R Instructions
# =================================


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


@pytest.mark.parametrize("name", [
    "add", "addw", "mul", "mulh", "mulhsu", "mulhu", "mulw", "sll", "sllw",
    "slt", "sltu", "sra", "sraw", "srl", "srlw", "sub", "subw", "xor"
])
def test_capstone_rinstr(name):
    constr = getattr(RInstruction, name)
    instr = constr(rd=5, rs1=6, rs2=7)
    bytes = instr.generate_bytes()
    instr_disasm = next(cap_disasm.disasm(bytes, 0x1000))
    assert instr_disasm.mnemonic == name
    assert instr_disasm.op_str == "t0, t1, t2"


@pytest.mark.parametrize("name", ["andr", "orr"])
def test_capstone_rinstr_special_cases(name):
    constr = getattr(RInstruction, name)
    instr = constr(rd=5, rs1=6, rs2=7)
    bytes = instr.generate_bytes()
    instr_disasm = next(cap_disasm.disasm(bytes, 0x1000))
    assert instr_disasm.mnemonic + "r" == name
    assert instr_disasm.op_str == "t0, t1, t2"


# =================================
#         I Instructions
# =================================


# TODO: Check
@pytest.mark.parametrize("name", [
    "addi", "addiw", "andi", "jalr", "lb", "lbu", "ld", "lh", "lhu", "ori",
    "slti", "sltiu", "xori"
])
@pytest.mark.parametrize("imm", [0x00, 0x01, 0x1C, 0xFF, 0xFFF])
def test_correct_encoding_iinstr(name, imm):
    constr = getattr(IInstruction, name)
    instr = constr(rd=5, rs1=6, imm=imm)
    mc_instr = instr.generate()
    assert instr.opcode7 == instructions_info[name].opcode7
    assert instr.opcode3 == instructions_info[name].opcode3
    assert instr.rd == disassembler.extract_rd(mc_instr)
    assert instr.rs1 == disassembler.extract_rs1(mc_instr)
    assert instr.imm == disassembler.extract_imm_i(mc_instr)


# TODO: Check
@pytest.mark.parametrize("name", [
    "slli", "slliw", "srai", "sraiw", "srli", "srliw"
])
@pytest.mark.parametrize("imm", [0x00, 0x01, 0x1C, 0xFF, 0xFFF])
def test_correct_encoding_iinstr_shifts(name, imm):
    constr = getattr(IInstruction, name)
    instr = constr(rd=5, rs1=6, imm=imm)
    mc_instr = instr.generate()
    assert instr.opcode7 == instructions_info[name].opcode7
    assert instr.opcode3 == instructions_info[name].opcode3
    assert instr.rd == disassembler.extract_rd(mc_instr)
    assert instr.rs1 == disassembler.extract_rs1(mc_instr)
    imm_disasm = disassembler.extract_imm_i(mc_instr)
    if name.endswith("w"):
        masked_imm = imm_disasm & 0x1F
    else:
        masked_imm = imm_disasm & 0x2F
    assert instr.imm == masked_imm


@pytest.mark.parametrize("name", [
    "addi", "addiw", "andi", "jalr", "ori", "slti", "sltiu", "xori"
])
@pytest.mark.parametrize("imm", [0x1C, 0xFF, 0x7FF])
def test_capstone_iinstr(name, imm):
    constr = getattr(IInstruction, name)
    instr = constr(rd=5, rs1=6, imm=imm)
    bytes = instr.generate_bytes()
    instr_disasm = next(cap_disasm.disasm(bytes, 0x1000))
    assert instr_disasm.mnemonic == name
    assert instr_disasm.op_str == "t0, t1, " + imm_str(imm)


@pytest.mark.parametrize("name", [
    "slli", "slliw", "srai", "sraiw", "srli", "srliw"
])
def test_capstone_iinstr_shifts(name):
    constr = getattr(IInstruction, name)
    instr = constr(rd=5, rs1=6, imm=0x3F)
    bytes = instr.generate_bytes()
    instr_disasm = next(cap_disasm.disasm(bytes, 0x1000))
    assert instr_disasm.mnemonic == name
    if name.endswith("w"):
        res = "t0, t1, 0x1f"
    else:
        res = "t0, t1, 0x2f"
    assert instr_disasm.op_str == res


@pytest.mark.parametrize("name", ["lb", "lbu", "ld", "lh", "lhu"])
def test_capstone_iinstr_loads(name):
    constr = getattr(IInstruction, name)
    instr = constr(rd=5, rs1=6, imm=0xFF)
    bytes = instr.generate_bytes()
    instr_disasm = next(cap_disasm.disasm(bytes, 0x1000))
    assert instr_disasm.mnemonic == name
    assert instr_disasm.op_str == "t0, 0xff(t1)"


# =================================
#         U Instructions
# =================================


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


@pytest.mark.parametrize("name", ["auipc", "lui"])
@pytest.mark.parametrize("imm", [0x7FFFFFFF, 0x7FFFF000, 0x00001FFF])
def test_capstone_uinstr(name, imm):
    constr = getattr(UInstruction, name)
    instr = constr(rd=5, imm=imm)
    bytes = instr.generate_bytes()
    instr_disasm = next(cap_disasm.disasm(bytes, 0x1000))
    assert instr_disasm.mnemonic == name
    assert instr_disasm.op_str == "t0, " + imm_str((imm & 0xFFFFF000) >> 12)


# =================================
#         J Instructions
# =================================


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


@pytest.mark.parametrize("name", ["jal"])
@pytest.mark.parametrize("imm", [
    0x1FE, 0x1FFE, 0x01FFFE, 0xFFFFE
])
def test_capstone_jinstr(name, imm):
    constr = getattr(JInstruction, name)
    instr = constr(rd=5, imm=imm)
    bytes = instr.generate_bytes()
    instr_disasm = next(cap_disasm.disasm(bytes, 0x1000))
    assert instr_disasm.mnemonic == name
    assert instr_disasm.op_str == "t0, " + imm_str(imm)


# =================================
#         S Instructions
# =================================


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
