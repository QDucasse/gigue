import pytest

from gigue.fixer.fixer_constants import FIXER_CMP_REG
from gigue.fixer.fixer_instructions import FIXERCustomInstruction
from tests.conftest import ADDRESS, RET_ADDRESS
from tests.fixer.conftest import UC_FIXER_CMP_REG


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
    assert instr_info.opcode == fix_disasm.extract_opcode(mc)
    assert instr_info.funct3 == fix_disasm.extract_funct3(mc)
    assert instr_info.funct7 == fix_disasm.extract_funct7(mc)
    assert instr_info.xd == fix_disasm.extract_xd(mc)
    assert instr_info.xs1 == fix_disasm.extract_xs1(mc)
    assert instr_info.xs2 == fix_disasm.extract_xs2(mc)


def test_unicorn_fixer_cficall(
    cap_disasm_custom_setup,
    uc_emul_full_setup,
    fixer_handler_setup,
):
    instr = FIXERCustomInstruction.cficall(rd=0, rs1=FIXER_CMP_REG, rs2=0)
    bytes = instr.generate_bytes()
    # Disassembly
    cap_disasm = cap_disasm_custom_setup
    next(cap_disasm.disasm(bytes, ADDRESS))
    # Handler
    fixer_handler = fixer_handler_setup
    assert not fixer_handler.shadow_stack
    # Emulation
    uc_emul = uc_emul_full_setup
    fixer_handler.hook_handler_expected(uc_emul, "cficall")
    uc_emul.reg_write(UC_FIXER_CMP_REG, RET_ADDRESS)
    uc_emul.mem_write(ADDRESS, bytes)
    uc_emul.emu_start(ADDRESS, ADDRESS + 4)
    uc_emul.emu_stop()
    assert fixer_handler.shadow_stack[0] == RET_ADDRESS


def test_unicorn_fixer_cfiret(
    cap_disasm_custom_setup,
    uc_emul_full_setup,
    fixer_handler_setup,
):
    instr = FIXERCustomInstruction.cfiret(rd=FIXER_CMP_REG, rs1=0, rs2=0)
    bytes = instr.generate_bytes()
    # Disassembly
    cap_disasm = cap_disasm_custom_setup
    next(cap_disasm.disasm(bytes, ADDRESS))
    # Handler
    fixer_handler = fixer_handler_setup
    assert not fixer_handler.shadow_stack
    fixer_handler.shadow_stack.append(RET_ADDRESS)
    # Emulation
    uc_emul = uc_emul_full_setup
    fixer_handler.hook_handler_expected(uc_emul, "cfiret")
    uc_emul.mem_write(ADDRESS, bytes)
    uc_emul.emu_start(ADDRESS, ADDRESS + 4)
    uc_emul.emu_stop()
    assert not fixer_handler.shadow_stack
    # Compensate for unicorn reg shift
    assert uc_emul.reg_read(UC_FIXER_CMP_REG) == RET_ADDRESS
