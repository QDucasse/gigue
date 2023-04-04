import pytest
from unicorn.riscv_const import UC_RISCV_REG_PC, UC_RISCV_REG_RA

from gigue.constants import CALL_TMP_REG, HIT_CASE_REG, RA
from gigue.fixer.builder import FIXERInstructionBuilder
from gigue.fixer.constants import FIXER_CMP_REG
from gigue.helpers import int_to_bytes64
from tests.conftest import ADDRESS, RET_ADDRESS, STACK_ADDRESS, UC_CALL_TMP_REG, RET_ADDRESS
from tests.fixer.conftest import UC_FIXER_CMP_REG

# =================================
#       Disassembly calls
# =================================


@pytest.mark.parametrize("offset", [0x800, 0xFFF, 0x80000, 0x1FFFE])
def test_build_method_call(offset, fixer_disasm_setup, cap_disasm_custom_setup):
    instr_builder = FIXERInstructionBuilder()
    instrs = instr_builder.build_method_base_call(offset)
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
    assert fixer_disasm.extract_pc_relative_offset(gen_instrs[3:]) == offset - 0xC
    # Note: 0xc to mitigate the three previous instructions


@pytest.mark.parametrize("offset", [0x800, 0xFFF, 0x80000, 0x1FFFE])
@pytest.mark.parametrize("hit_case", range(1, 5))
def test_build_pic_base_call(
    offset, hit_case, fixer_disasm_setup, cap_disasm_custom_setup
):
    instr_builder = FIXERInstructionBuilder()
    instrs = instr_builder.build_pic_base_call(offset=offset, hit_case=hit_case)
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
    assert fixer_disasm.extract_pc_relative_offset(gen_instrs[4:]) == offset - 16


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
    assert instrs[-2].name == "ecall"
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
    assert fixer_disasm.get_instruction_info(gen_instrs[-2]).name == "ecall"
    assert fixer_disasm.extract_rd(gen_instrs[-4]) == FIXER_CMP_REG
    assert fixer_disasm.extract_rs1(gen_instrs[-3]) == RA
    assert fixer_disasm.extract_rs2(gen_instrs[-3]) == FIXER_CMP_REG
    assert fixer_disasm.extract_imm_b(gen_instrs[-3]) == 8


# Trampolines
# \___________

def test_build_call_jit_elt_trampoline(
    fixer_disasm_setup,
    cap_disasm_custom_setup,
):
    instr_builder = FIXERInstructionBuilder()
    instrs = instr_builder.build_call_jit_elt_trampoline()
    gen_instrs = [instr.generate() for instr in instrs]
    # Name check
    assert instrs[0].name == "cficall"
    assert instrs[1].name == "jalr"
    # Smoke capstone disassembly
    cap_disasm = cap_disasm_custom_setup
    bytes = b"".join([instr.generate_bytes() for instr in instrs])
    for i in cap_disasm.disasm(bytes, 0x1000):
        # print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
        pass
    # Disassembly
    fixer_disasm = fixer_disasm_setup
    assert fixer_disasm.get_instruction_info(gen_instrs[0]).name == "cficall"
    assert fixer_disasm.extract_rs1(gen_instrs[0]) == RA
    assert fixer_disasm.get_instruction_info(gen_instrs[1]).name == "jalr"
    assert fixer_disasm.extract_rs1(gen_instrs[1]) == CALL_TMP_REG


def test_build_ret_from_jit_elt_trampoline(
    fixer_disasm_setup,
    cap_disasm_custom_setup,
):
    instr_builder = FIXERInstructionBuilder()
    instrs = instr_builder.build_ret_from_jit_elt_trampoline()
    gen_instrs = [instr.generate() for instr in instrs]
    # Name check
    assert instrs[0].name == "cfiret"
    assert instrs[1].name == "beq"
    assert instrs[2].name == "ecall"
    assert instrs[3].name == "jalr"
    # Smoke capstone disassembly
    cap_disasm = cap_disasm_custom_setup
    bytes = b"".join([instr.generate_bytes() for instr in instrs])
    for i in cap_disasm.disasm(bytes, 0x1000):
        # print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
        pass
    # Disassembly
    fixer_disasm = fixer_disasm_setup
    assert fixer_disasm.get_instruction_info(gen_instrs[0]).name == "cfiret"
    assert fixer_disasm.extract_rd(gen_instrs[0]) == FIXER_CMP_REG
    assert fixer_disasm.get_instruction_info(gen_instrs[1]).name == "beq"
    assert fixer_disasm.extract_rs1(gen_instrs[1]) == RA
    assert fixer_disasm.extract_rs2(gen_instrs[1]) == FIXER_CMP_REG
    assert fixer_disasm.extract_imm_b(gen_instrs[1]) == 8
    assert fixer_disasm.get_instruction_info(gen_instrs[2]).name == "ecall"
    assert fixer_disasm.get_instruction_info(gen_instrs[3]).name == "jalr"


# =================================
#            Execution
# =================================


@pytest.mark.parametrize("offset", [0x800, 0xFFE, 0x80000, 0x1FFFE, 0xFFFFE])
def test_build_method_base_call_execution(
    offset, cap_disasm_custom_setup, uc_emul_full_setup, fixer_handler_setup
):
    instr_builder = FIXERInstructionBuilder()
    instrs = instr_builder.build_method_base_call(offset)
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
    fixer_handler.hook_handler(uc_emul)
    uc_emul.emu_start(ADDRESS, ADDRESS + offset)
    current_ra = uc_emul.reg_read(UC_RISCV_REG_RA)
    current_pc = uc_emul.reg_read(UC_RISCV_REG_PC)
    expected_ra = ADDRESS + len(instrs) * 4  # right after the call!
    assert current_ra == expected_ra
    assert current_pc == ADDRESS + offset
    assert fixer_handler.shadow_stack[0] == expected_ra
    uc_emul.emu_stop()


@pytest.mark.parametrize("offset", [0x800, 0xFFE, 0x80000, 0x1FFFE, 0xFFFFE])
def test_build_pic_base_call_execution(
    offset, cap_disasm_custom_setup, uc_emul_full_setup, fixer_handler_setup
):
    instr_builder = FIXERInstructionBuilder()
    instrs = instr_builder.build_pic_base_call(
        offset=offset, hit_case=5, hit_case_reg=5
    )
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
    fixer_handler.hook_handler(uc_emul)
    uc_emul.emu_start(ADDRESS, ADDRESS + offset)
    current_ra = uc_emul.reg_read(UC_RISCV_REG_RA)
    current_pc = uc_emul.reg_read(UC_RISCV_REG_PC)
    expected_ra = ADDRESS + len(instrs) * 4  # right after the call!
    assert current_ra == expected_ra
    assert current_pc == ADDRESS + offset
    assert fixer_handler.shadow_stack[0] == expected_ra
    uc_emul.emu_stop()


@pytest.mark.parametrize("used_s_regs", [0, 5, 10])
@pytest.mark.parametrize("local_var_nb", [0, 5, 10])
def test_build_epilogue_correct_execution(
    used_s_regs,
    local_var_nb,
    cap_disasm_custom_setup,
    uc_emul_full_setup,
    fixer_handler_setup,
):
    instr_builder = FIXERInstructionBuilder()
    instrs = instr_builder.build_epilogue(
        used_s_regs=used_s_regs, local_var_nb=local_var_nb, contains_call=True
    )
    bytes = instr_builder.consolidate_bytes(instrs)
    # Disassembly
    cap_disasm = cap_disasm_custom_setup
    for i in cap_disasm.disasm(bytes, ADDRESS):
        # print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
        pass
    # Handler
    fixer_handler = fixer_handler_setup
    # Add the called address to the shadow stack
    called_address = RET_ADDRESS - 24
    fixer_handler.shadow_stack.append(called_address)
    # Emulation
    uc_emul = uc_emul_full_setup
    uc_emul.mem_write(ADDRESS, bytes)
    # Write saved values and the return address in the stack
    for i in range(used_s_regs):
        uc_emul.mem_write(STACK_ADDRESS + i * 8, int_to_bytes64(i + 1))
    uc_emul.mem_write(STACK_ADDRESS + used_s_regs * 8, int_to_bytes64(called_address))
    fixer_handler.hook_handler(uc_emul)
    uc_emul.emu_start(ADDRESS, called_address)
    current_pc = uc_emul.reg_read(UC_RISCV_REG_PC)
    assert current_pc == called_address
    assert len(fixer_handler.shadow_stack) == 0
    assert fixer_handler.cfi_exception == 0
    uc_emul.emu_stop()


@pytest.mark.parametrize("used_s_regs", [0, 5, 10])
@pytest.mark.parametrize("local_var_nb", [0, 5, 10])
def test_build_epilogue_failing_execution(
    used_s_regs,
    local_var_nb,
    cap_disasm_custom_setup,
    uc_emul_full_setup,
    fixer_handler_setup,
):
    instr_builder = FIXERInstructionBuilder()
    instrs = instr_builder.build_epilogue(
        used_s_regs=used_s_regs, local_var_nb=local_var_nb, contains_call=True
    )
    bytes = instr_builder.consolidate_bytes(instrs)
    # Disassembly
    cap_disasm = cap_disasm_custom_setup
    for i in cap_disasm.disasm(bytes, ADDRESS):
        # print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
        pass
    # Handler
    fixer_handler = fixer_handler_setup
    # Add the called address to the shadow stack
    called_address = RET_ADDRESS - 24
    fixer_handler.shadow_stack.append(called_address - 8)  # Different address!!
    # Emulation
    uc_emul = uc_emul_full_setup
    uc_emul.mem_write(ADDRESS, bytes)
    # Write saved values and the return address in the stack
    for i in range(used_s_regs):
        uc_emul.mem_write(STACK_ADDRESS + i * 8, int_to_bytes64(i + 1))
    uc_emul.mem_write(STACK_ADDRESS + used_s_regs * 8, int_to_bytes64(called_address))
    fixer_handler.hook_handler(uc_emul)
    uc_emul.emu_start(ADDRESS, ADDRESS + len(bytes) - 4)
    current_pc = uc_emul.reg_read(UC_RISCV_REG_PC)
    assert current_pc == ADDRESS + len(bytes) - 4
    assert len(fixer_handler.shadow_stack) == 0
    assert fixer_handler.cfi_exception == 1
    # Should be done in handler but by precaution
    uc_emul.emu_stop()


# Trampolines
# \___________

def test_build_trampoline_call_jit_elt_execution(
    cap_disasm_custom_setup,
    uc_emul_full_setup,
    fixer_handler_setup,
):
    instr_builder = FIXERInstructionBuilder()
    instrs = instr_builder.build_call_jit_elt_trampoline()
    bytes = instr_builder.consolidate_bytes(instrs)
    # Disassembly
    cap_disasm = cap_disasm_custom_setup
    for i in cap_disasm.disasm(bytes, ADDRESS):
        # print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
        pass
    # Handler
    fixer_handler = fixer_handler_setup
    # Emulation
    called_address = RET_ADDRESS - 24
    uc_emul = uc_emul_full_setup
    uc_emul.mem_write(ADDRESS, bytes)
    # Write saved values and the return address in the stack
    fixer_handler.hook_handler(uc_emul)
    uc_emul.reg_write(UC_CALL_TMP_REG, called_address)
    uc_emul.emu_start(ADDRESS, called_address)
    current_pc = uc_emul.reg_read(UC_RISCV_REG_PC)
    assert current_pc == called_address
    assert fixer_handler.shadow_stack[0] == RET_ADDRESS
    uc_emul.emu_stop()


def test_build_trampoline_ret_from_jit_elt_correct_execution(
    cap_disasm_custom_setup,
    uc_emul_full_setup,
    fixer_handler_setup,
):
    instr_builder = FIXERInstructionBuilder()
    instrs = instr_builder.build_ret_from_jit_elt_trampoline()
    bytes = instr_builder.consolidate_bytes(instrs)
    # Disassembly
    cap_disasm = cap_disasm_custom_setup
    for i in cap_disasm.disasm(bytes, ADDRESS):
        # print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
        pass
    # Handler
    fixer_handler = fixer_handler_setup
    fixer_handler.shadow_stack.append(RET_ADDRESS)
    # Emulation
    uc_emul = uc_emul_full_setup
    uc_emul.mem_write(ADDRESS, bytes)
    # Write saved values and the return address in the stack
    fixer_handler.hook_handler(uc_emul)
    uc_emul.emu_start(ADDRESS, RET_ADDRESS)
    fixer_cmp_reg = uc_emul.reg_read(UC_FIXER_CMP_REG)
    assert len(fixer_handler.shadow_stack) == 0
    assert fixer_handler.cfi_exception == 0
    assert fixer_cmp_reg == RET_ADDRESS
    uc_emul.emu_stop()


def test_build_trampoline_ret_from_jit_elt_incorrect_execution(
    cap_disasm_custom_setup,
    uc_emul_full_setup,
    fixer_handler_setup,
):
    instr_builder = FIXERInstructionBuilder()
    instrs = instr_builder.build_ret_from_jit_elt_trampoline()
    bytes = instr_builder.consolidate_bytes(instrs)
    # Disassembly
    cap_disasm = cap_disasm_custom_setup
    for i in cap_disasm.disasm(bytes, ADDRESS):
        # print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
        pass
    # Handler
    fixer_handler = fixer_handler_setup
    fixer_handler.shadow_stack.append(RET_ADDRESS - 8)  # Differrent value!!
    # Emulation
    uc_emul = uc_emul_full_setup
    uc_emul.mem_write(ADDRESS, bytes)
    # Write saved values and the return address in the stack
    fixer_handler.hook_handler(uc_emul)
    uc_emul.emu_start(ADDRESS, RET_ADDRESS)
    fixer_cmp_reg = uc_emul.reg_read(UC_FIXER_CMP_REG)
    assert len(fixer_handler.shadow_stack) == 0
    assert fixer_handler.cfi_exception == 1
    assert fixer_cmp_reg == RET_ADDRESS - 8
    # Should be done in handler but by precaution
    uc_emul.emu_stop()
