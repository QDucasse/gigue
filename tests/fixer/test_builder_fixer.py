import pytest
from unicorn.riscv_const import UC_RISCV_REG_PC, UC_RISCV_REG_RA

from gigue.constants import HIT_CASE_REG, RA
from gigue.fixer.builder import FIXERInstructionBuilder
from gigue.fixer.constants import FIXER_CMP_REG
from tests.conftest import ADDRESS

# =================================
#       Disassembly calls
# =================================


@pytest.mark.parametrize("offset", [0x800, 0xFFF, 0x80000, 0x1FFFE])
def test_build_method_call(offset, fixer_disasm_setup, cap_disasm_custom_setup):
    instr_builder = FIXERInstructionBuilder()
    instrs = instr_builder.build_method_call(offset)
    gen_instrs = [instr.generate() for instr in instrs]
    # Name check
    assert instrs[0].name == "auipc"
    assert instrs[1].name == "addi"
    assert instrs[2].name == "cficall"
    assert instrs[3].name == "auipc"
    assert instrs[4].name == "jalr"
    # Smoke capstone disassembly
    cap_disasm = cap_disasm_custom_setup
    bytes = b"".join([instr.generate_bytes() for instr in instrs])
    for i in cap_disasm.disasm(bytes, 0x1000):
        # print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
        pass
    # Disassembly
    fixer_disasm = fixer_disasm_setup
    assert fixer_disasm.get_instruction_info(gen_instrs[0]).name == "auipc"
    assert fixer_disasm.get_instruction_info(gen_instrs[1]).name == "addi"
    assert fixer_disasm.get_instruction_info(gen_instrs[2]).name == "cficall"
    assert fixer_disasm.get_instruction_info(gen_instrs[3]).name == "auipc"
    assert fixer_disasm.get_instruction_info(gen_instrs[4]).name == "jalr"
    # Info on first auipc
    assert fixer_disasm.extract_rd(gen_instrs[0]) == FIXER_CMP_REG
    assert fixer_disasm.extract_imm_u(gen_instrs[0]) == 0
    # Info on addi
    assert fixer_disasm.extract_rd(gen_instrs[1]) == FIXER_CMP_REG
    assert fixer_disasm.extract_rs1(gen_instrs[1]) == FIXER_CMP_REG
    assert fixer_disasm.extract_imm_i(gen_instrs[1]) == 0x14
    # Check cficall
    assert fixer_disasm.extract_rs1(gen_instrs[2]) == FIXER_CMP_REG
    # Check call offset
    assert fixer_disasm.extract_call_offset(gen_instrs[3:]) == offset - 12


@pytest.mark.parametrize("offset", [0x800, 0xFFF, 0x80000, 0x1FFFE])
@pytest.mark.parametrize("hit_case", range(1, 5))
def test_build_pic_call(offset, hit_case, fixer_disasm_setup, cap_disasm_custom_setup):
    instr_builder = FIXERInstructionBuilder()
    instrs = instr_builder.build_pic_call(offset=offset, hit_case=hit_case)
    gen_instrs = [instr.generate() for instr in instrs]
    # Name check
    assert instrs[0].name == "auipc"
    assert instrs[1].name == "addi"
    assert instrs[2].name == "cficall"
    assert instrs[3].name == "addi"
    assert instrs[4].name == "auipc"
    assert instrs[5].name == "jalr"
    # Smoke capstone disassembly
    cap_disasm = cap_disasm_custom_setup
    bytes = b"".join([instr.generate_bytes() for instr in instrs])
    for i in cap_disasm.disasm(bytes, 0x1000):
        # print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
        pass
    # Disassembly
    fixer_disasm = fixer_disasm_setup
    assert fixer_disasm.get_instruction_info(gen_instrs[0]).name == "auipc"
    assert fixer_disasm.get_instruction_info(gen_instrs[1]).name == "addi"
    assert fixer_disasm.get_instruction_info(gen_instrs[2]).name == "cficall"
    assert fixer_disasm.get_instruction_info(gen_instrs[3]).name == "addi"
    assert fixer_disasm.get_instruction_info(gen_instrs[4]).name == "auipc"
    assert fixer_disasm.get_instruction_info(gen_instrs[5]).name == "jalr"
    # Info on first auipc
    assert fixer_disasm.extract_rd(gen_instrs[0]) == FIXER_CMP_REG
    assert fixer_disasm.extract_imm_u(gen_instrs[0]) == 0
    # Info on addi
    assert fixer_disasm.extract_rd(gen_instrs[1]) == FIXER_CMP_REG
    assert fixer_disasm.extract_rs1(gen_instrs[1]) == FIXER_CMP_REG
    assert fixer_disasm.extract_imm_i(gen_instrs[1]) == 0x18
    # Check cficall
    assert fixer_disasm.extract_rs1(gen_instrs[2]) == FIXER_CMP_REG
    # Verify hit case
    assert fixer_disasm.extract_rd(gen_instrs[3]) == HIT_CASE_REG
    assert fixer_disasm.extract_imm_i(gen_instrs[3]) == hit_case
    # Check call offset
    assert fixer_disasm.extract_call_offset(gen_instrs[4:]) == offset - 16


@pytest.mark.parametrize("used_s_regs", [0, 5, 10])
@pytest.mark.parametrize("local_var_nb", [0, 5, 10])
@pytest.mark.parametrize("contains_call", [True, False])
def test_build_epilogue(
    used_s_regs,
    local_var_nb,
    contains_call,
    fixer_disasm_setup,
    cap_disasm_custom_setup,
):
    instr_builder = FIXERInstructionBuilder()
    instrs = instr_builder.build_epilogue(
        used_s_regs=used_s_regs, local_var_nb=local_var_nb, contains_call=contains_call
    )
    gen_instrs = [instr.generate() for instr in instrs]
    # Name check
    assert instrs[-4].name == "cfiret"
    assert instrs[-3].name == "beq"
    assert instrs[-2].name == "ebreak"
    # Smoke capstone disassembly
    cap_disasm = cap_disasm_custom_setup
    bytes = b"".join([instr.generate_bytes() for instr in instrs])
    for i in cap_disasm.disasm(bytes, 0x1000):
        # print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
        pass
    # Disassembly
    fixer_disasm = fixer_disasm_setup
    assert fixer_disasm.get_instruction_info(gen_instrs[-4]).name == "cfiret"
    assert fixer_disasm.get_instruction_info(gen_instrs[-3]).name == "beq"
    assert fixer_disasm.get_instruction_info(gen_instrs[-2]).name == "ebreak"
    assert fixer_disasm.extract_rd(gen_instrs[-4]) == FIXER_CMP_REG
    assert fixer_disasm.extract_rs1(gen_instrs[-3]) == RA
    assert fixer_disasm.extract_rs2(gen_instrs[-3]) == FIXER_CMP_REG
    assert fixer_disasm.extract_imm_b(gen_instrs[-3]) == 8


# =================================
#            Execution
# =================================


@pytest.mark.parametrize("offset", [0x800, 0xFFE, 0x80000, 0x1FFFE, 0xFFFFE])
def test_build_method_call_execution(
    offset, cap_disasm_custom_setup, uc_emul_full_setup, fixer_handler_setup
):
    instr_builder = FIXERInstructionBuilder()
    instrs = instr_builder.build_method_call(offset)
    bytes = instr_builder.consolidate_bytes(instrs)
    # Disassembly
    cap_disasm = cap_disasm_custom_setup
    for i in cap_disasm.disasm(bytes, ADDRESS):
        # print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
        pass
    # Handler
    fixer_handler = fixer_handler_setup
    # Emulation
    uc_emul = uc_emul_full_setup
    uc_emul.mem_write(ADDRESS, bytes)
    fixer_handler.handle_execution(uc_emul, ADDRESS, ADDRESS + offset)
    current_ra = uc_emul.reg_read(UC_RISCV_REG_RA)
    current_pc = uc_emul.reg_read(UC_RISCV_REG_PC)
    expected_ra = ADDRESS + len(instrs) * 4  # right after the call!
    assert current_ra == expected_ra
    assert current_pc == ADDRESS + offset
    assert fixer_handler.shadow_stack[0] == expected_ra


@pytest.mark.parametrize("offset", [0x800, 0xFFE, 0x80000, 0x1FFFE, 0xFFFFE])
def test_build_pic_call_execution(
    offset, cap_disasm_custom_setup, uc_emul_full_setup, fixer_handler_setup
):
    instr_builder = FIXERInstructionBuilder()
    instrs = instr_builder.build_pic_call(offset=offset, hit_case=5, hit_case_reg=5)
    bytes = instr_builder.consolidate_bytes(instrs)
    # Disassembly
    cap_disasm = cap_disasm_custom_setup
    for i in cap_disasm.disasm(bytes, ADDRESS):
        # print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
        pass
    # Handler
    fixer_handler = fixer_handler_setup
    # Emulation
    uc_emul = uc_emul_full_setup
    uc_emul.mem_write(ADDRESS, bytes)
    fixer_handler.handle_execution(uc_emul, ADDRESS, ADDRESS + offset)
    current_ra = uc_emul.reg_read(UC_RISCV_REG_RA)
    current_pc = uc_emul.reg_read(UC_RISCV_REG_PC)
    expected_ra = ADDRESS + len(instrs) * 4  # right after the call!
    assert current_ra == expected_ra
    assert current_pc == ADDRESS + offset
    assert fixer_handler.shadow_stack[0] == expected_ra
