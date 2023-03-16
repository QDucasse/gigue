import pytest

# from gigue.rimi.constants import RIMI_SHADOW_STACK_REG
from gigue.rimi.instructions import RIMIIInstruction, RIMIJInstruction, RIMISInstruction
from tests.conftest import ADDRESS

# from tests.rimi.conftest import UC_RIMI_SHADOW_STACK_REG


@pytest.mark.parametrize(
    "name", ["lws", "lb1", "lbu1", "lh1", "lhu1", "lw1", "lwu1", "ld1"]
)
def test_capstone_rimi_loads(name, cap_disasm_custom_setup, rimi_disasm_setup):
    constr = getattr(RIMIIInstruction, name)
    instr = constr(rd=5, rs1=6, imm=0)
    bytes = instr.generate_bytes()
    mc = instr.generate()
    # Disassembly
    cap_disasm = cap_disasm_custom_setup
    instr_disasm = next(cap_disasm.disasm(bytes, ADDRESS))
    assert instr_disasm.mnemonic == "custom"
    # RIMI
    rimi_disasm = rimi_disasm_setup
    instr_info = rimi_disasm.get_instruction_info(mc)
    assert instr_info.name == name
    assert instr_info.opcode7 == rimi_disasm.extract_opcode7(mc)
    assert instr_info.opcode3 == rimi_disasm.extract_opcode3(mc)
    assert instr_info.top7 == rimi_disasm.extract_top7(mc)


@pytest.mark.parametrize("name", ["sws", "sb1", "sh1", "sw1", "sd1"])
def test_capstone_rimi_stores(name, cap_disasm_custom_setup, rimi_disasm_setup):
    constr = getattr(RIMISInstruction, name)
    instr = constr(rs1=5, rs2=6, imm=0)
    bytes = instr.generate_bytes()
    mc = instr.generate()
    # Disassembly
    cap_disasm = cap_disasm_custom_setup
    instr_disasm = next(cap_disasm.disasm(bytes, ADDRESS))
    assert instr_disasm.mnemonic == "custom"
    # RIMI
    rimi_disasm = rimi_disasm_setup
    instr_info = rimi_disasm.get_instruction_info(mc)
    assert instr_info.name == name
    assert instr_info.opcode7 == rimi_disasm.extract_opcode7(mc)
    assert instr_info.opcode3 == rimi_disasm.extract_opcode3(mc)


def test_capstone_rimi_change_domain_fw(cap_disasm_custom_setup, rimi_disasm_setup):
    constr = getattr(RIMIJInstruction, "jalx")
    instr = constr(rd=1, imm=0)
    bytes = instr.generate_bytes()
    mc = instr.generate()
    # Disassembly
    cap_disasm = cap_disasm_custom_setup
    instr_disasm = next(cap_disasm.disasm(bytes, ADDRESS))
    assert instr_disasm.mnemonic == "custom"
    # RIMI
    rimi_disasm = rimi_disasm_setup
    instr_info = rimi_disasm.get_instruction_info(mc)
    assert instr_info.name == "jalx"
    assert instr_info.opcode7 == rimi_disasm.extract_opcode7(mc)
    assert instr_info.opcode3 == rimi_disasm.extract_opcode3(mc)


def test_capstone_rimi_change_domain_bw(cap_disasm_custom_setup, rimi_disasm_setup):
    constr = getattr(RIMIIInstruction, "jalrx")
    instr = constr()
    bytes = instr.generate_bytes()
    mc = instr.generate()
    # Disassembly
    cap_disasm = cap_disasm_custom_setup
    instr_disasm = next(cap_disasm.disasm(bytes, ADDRESS))
    assert instr_disasm.mnemonic == "custom"
    # RIMI
    rimi_disasm = rimi_disasm_setup
    instr_info = rimi_disasm.get_instruction_info(mc)
    assert instr_info.name == "jalrx"
    assert instr_info.opcode7 == rimi_disasm.extract_opcode7(mc)
    assert instr_info.opcode3 == rimi_disasm.extract_opcode3(mc)
