import pytest
from unicorn import UcError

from gigue.fixer.instructions import FIXERCustomInstruction
from tests.conftest import ADDRESS


@pytest.mark.parametrize("name", ["cficall", "cfiret"])
def test_capstone_fixer(name, cap_disasm_custom_setup, fixer_disasm_setup):
    constr = getattr(FIXERCustomInstruction, name)
    instr = constr(rd=0, rs1=5, rs2=0)
    bytes = instr.generate_bytes()
    mc = instr.generate()
    # Disassembly
    cap_disasm = cap_disasm_custom_setup
    instr_disasm = next(cap_disasm.disasm(bytes, ADDRESS))
    assert instr_disasm.mnemonic == "custom"
    # FIXER
    fix_disasm = fixer_disasm_setup
    instr_info = fix_disasm.get_instruction_info(mc)
    assert instr_info.name == name
    assert instr_info.opcode7 == fix_disasm.extract_opcode7(mc)
    assert instr_info.opcode3 == fix_disasm.extract_opcode3(mc)
    assert instr_info.top7 == fix_disasm.extract_top7(mc)
    assert instr_info.xd == fix_disasm.extract_xd(mc)
    assert instr_info.xs1 == fix_disasm.extract_xs1(mc)
    assert instr_info.xs2 == fix_disasm.extract_xs2(mc)


@pytest.mark.parametrize("name", ["cficall", "cfiret"])
def test_unicorn_fixer(
    name,
    cap_disasm_custom_setup,
    uc_emul_setup,
    fixer_handler_setup,
):
    constr = getattr(FIXERCustomInstruction, name)
    instr = constr(rd=0, rs1=5, rs2=0)
    bytes = instr.generate_bytes()
    # Disassembly
    cap_disasm = cap_disasm_custom_setup
    next(cap_disasm.disasm(bytes, ADDRESS))
    # Emulation
    uc_emul = uc_emul_setup
    uc_emul.mem_write(ADDRESS, bytes)
    try:
        uc_emul.emu_start(ADDRESS, ADDRESS + 4)
    except UcError:
        fixer_handler = fixer_handler_setup
        fixer_handler.handle_custom_instruction(uc_emul, name)
    uc_emul.emu_stop()
