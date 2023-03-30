import pytest
from unicorn.riscv_const import (
    UC_RISCV_REG_PC,
    UC_RISCV_REG_RA,
    UC_RISCV_REG_S0,
    UC_RISCV_REG_S1,
    UC_RISCV_REG_S2,
    UC_RISCV_REG_S3,
    UC_RISCV_REG_S4,
    UC_RISCV_REG_S5,
    UC_RISCV_REG_S6,
    UC_RISCV_REG_S7,
    UC_RISCV_REG_S8,
    UC_RISCV_REG_S9,
    UC_RISCV_REG_SP,
    UC_RISCV_REG_T0,
    UC_RISCV_REG_T1,
)

from gigue.builder import InstructionBuilder
from gigue.constants import CALL_TMP_REG, CMP_REG, HIT_CASE_REG, RA, SP
from gigue.helpers import bytes_to_int, int_to_bytes64
from tests.conftest import (
    ADDRESS,
    RET_ADDRESS,
    STACK_ADDRESS,
    TEST_CALLER_SAVED_REG,
    TEST_DATA_REG,
    TEST_DATA_SIZE,
    cap_disasm_bytes,
)

# =================================
#        Random instructions
# =================================


@pytest.mark.parametrize("execution_number", range(30))
def test_build_random_r_instruction(execution_number):
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_random_r_instruction(TEST_CALLER_SAVED_REG)
    assert instr.rd in TEST_CALLER_SAVED_REG
    assert instr.rs1 in TEST_CALLER_SAVED_REG
    assert instr.rs2 in TEST_CALLER_SAVED_REG


@pytest.mark.parametrize("execution_number", range(30))
def test_build_random_i_instruction(execution_number):
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_random_i_instruction(TEST_CALLER_SAVED_REG)
    assert instr.rd in TEST_CALLER_SAVED_REG
    assert instr.rs1 in TEST_CALLER_SAVED_REG
    assert 0 <= instr.imm <= 0xFFF


@pytest.mark.parametrize("execution_number", range(10))
def test_build_random_u_instruction(execution_number):
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_random_u_instruction(TEST_CALLER_SAVED_REG)
    assert instr.rd in TEST_CALLER_SAVED_REG
    assert 0 <= instr.imm <= 0xFFFFFFFF


@pytest.mark.parametrize("execution_number", range(5))
def test_build_random_j_instruction(execution_number):
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_random_j_instruction(TEST_CALLER_SAVED_REG, 0x7FF)
    assert instr.rd in TEST_CALLER_SAVED_REG
    assert 0 <= instr.imm <= 0xFFF
    assert instr.imm % 2 == 0


@pytest.mark.parametrize("execution_number", range(10))
def test_build_random_b_instruction(execution_number):
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_random_b_instruction(TEST_CALLER_SAVED_REG, 0x7FF)
    assert instr.rs1 in TEST_CALLER_SAVED_REG
    assert instr.rs2 in TEST_CALLER_SAVED_REG
    assert 0 <= instr.imm <= 0xFFF
    assert instr.imm % 2 == 0


@pytest.mark.parametrize(
    "max_offset,expected_offsets",
    [
        (8, [4, 8]),
        (12, [4, 12]),
        (24, [4, 12, 24]),
        (36, [4, 12, 24, 36]),
        (16, [4, 16]),
        (20, [4, 8, 20]),
    ],
)
def test_size_offset(max_offset, expected_offsets):
    assert sorted(InstructionBuilder.size_offset(max_offset)) == expected_offsets


@pytest.mark.parametrize(
    "max_offset,expected_offset",
    [
        (8, [4, 8]),
        (12, [4, 12]),
        (24, [4, 12, 24]),
        (36, [4, 12, 24, 36]),
        (16, [4, 16]),
        (20, [4, 8, 20]),
    ],
)
def test_check_random_b_instruction_offset(max_offset, expected_offset, disasm_setup):
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_random_b_instruction(TEST_CALLER_SAVED_REG, max_offset)
    disasm = disasm_setup
    assert disasm.extract_imm_b(instr.generate()) in expected_offset


# =================================
#        Specific structures
# =================================


@pytest.mark.parametrize("offset", [0x8, 0x800, 0xFFF, 0x80000, 0x1FFFE])
def test_build_method_base_call(offset, disasm_setup):
    instr_builder = InstructionBuilder()
    instrs = instr_builder.build_method_base_call(offset)
    gen_instrs = [instr.generate() for instr in instrs]
    assert instrs[0].name == "auipc"
    assert instrs[1].name == "jalr"
    # Disassembly
    disasm = disasm_setup
    assert disasm.get_instruction_info(gen_instrs[0]).name == "auipc"
    assert disasm.get_instruction_info(gen_instrs[1]).name == "jalr"
    assert offset == disasm.extract_pc_relative_offset(
        [instr.generate() for instr in instrs]
    )


@pytest.mark.parametrize("offset", [0x800, 0xFFF, 0x80000, 0x1FFFE])
@pytest.mark.parametrize("hit_case", range(1, 5))
def test_build_pic_base_call(offset, hit_case, disasm_setup):
    instr_builder = InstructionBuilder()
    instrs = instr_builder.build_pic_base_call(offset=offset, hit_case=hit_case)
    gen_instrs = [instr.generate() for instr in instrs]
    assert instrs[0].name == "addi"
    assert instrs[1].name == "auipc"
    assert instrs[2].name == "jalr"
    # Disassembly
    disasm = disasm_setup
    assert disasm.get_instruction_info(gen_instrs[0]).name == "addi"
    assert disasm.get_instruction_info(gen_instrs[1]).name == "auipc"
    assert disasm.get_instruction_info(gen_instrs[2]).name == "jalr"
    assert disasm.extract_rd(gen_instrs[0]) == HIT_CASE_REG
    assert disasm.extract_imm_i(gen_instrs[0]) == hit_case
    assert offset == disasm.extract_pc_relative_offset(gen_instrs[1:])


@pytest.mark.parametrize("offset", [0x800, 0xFFE, 0x80000, 0x1FFFE])
@pytest.mark.parametrize("case_number", range(1, 5))
def test_build_switch_pic(offset, disasm_setup, case_number):
    instr_builder = InstructionBuilder()
    instrs = instr_builder.build_switch_case(
        case_number=case_number, method_offset=offset
    )
    gen_instrs = [instr.generate() for instr in instrs]
    # Disassembly
    disasm = disasm_setup
    # Load the value in x6
    assert instrs[0].name == "addi"
    assert disasm.extract_rd(gen_instrs[0]) == CMP_REG
    assert disasm.extract_imm_i(gen_instrs[0]) == case_number
    # Compare and branch i
    assert instrs[1].name == "bne"
    assert disasm.extract_imm_b(gen_instrs[1]) == 8
    assert disasm.extract_rs1(gen_instrs[1]) == CMP_REG
    assert disasm.extract_rs2(gen_instrs[1]) == HIT_CASE_REG
    # Compare and branch i
    assert instrs[2].name == "jal"
    assert offset == disasm.extract_imm_j(gen_instrs[2])


@pytest.mark.parametrize("used_s_regs", [0, 5, 10])
@pytest.mark.parametrize("local_var_nb", [0, 5, 10])
@pytest.mark.parametrize("contains_call", [True, False])
def test_build_prologue(used_s_regs, local_var_nb, contains_call, disasm_setup):
    instr_builder = InstructionBuilder()
    instrs = instr_builder.build_prologue(
        used_s_regs=used_s_regs, local_var_nb=local_var_nb, contains_call=contains_call
    )
    gen_instrs = [instr.generate() for instr in instrs]
    # Disassembly
    disasm = disasm_setup
    # Space on top of the stack
    assert instrs[0].name == "addi"
    assert (
        disasm.extract_imm_i(gen_instrs[0], sign_extend=True)
        == -(used_s_regs + local_var_nb + (1 if contains_call else 0)) * 8
    )
    # Filling of the stack
    for i, (instr, generated) in enumerate(zip(instrs[1:-1], gen_instrs[1:-1])):
        assert instr.name == "sd"
        assert disasm.extract_imm_s(generated) == i * 8
    # RA check
    if contains_call:
        assert instrs[-1].name == "sd"
        assert disasm.extract_imm_s(gen_instrs[-1]) == used_s_regs * 8
        assert disasm.extract_rs2(instrs[-1].generate()) == RA


@pytest.mark.parametrize("used_s_regs", [0, 5, 10])
@pytest.mark.parametrize("local_var_nb", [0, 5, 10])
@pytest.mark.parametrize("contains_call", [True, False])
def test_build_epilogue(used_s_regs, local_var_nb, contains_call, disasm_setup):
    instr_builder = InstructionBuilder()
    instrs = instr_builder.build_epilogue(
        used_s_regs=used_s_regs, local_var_nb=local_var_nb, contains_call=contains_call
    )
    gen_instrs = [instr.generate() for instr in instrs]
    # Disassembly
    disasm = disasm_setup
    # Restore saved regs
    for i, (instr, generated) in enumerate(zip(instrs[:-2], gen_instrs[:-2])):
        assert instr.name == "ld"
        assert disasm.extract_imm_i(generated) == i * 8
    # RA check and restore
    if contains_call:
        assert instrs[used_s_regs].name == "ld"
        assert disasm.extract_imm_i(gen_instrs[used_s_regs]) == used_s_regs * 8
        assert disasm.extract_rd(gen_instrs[used_s_regs]) == RA
        assert disasm.extract_rs1(gen_instrs[used_s_regs]) == SP
    # Restore SP
    assert instrs[-2].name == "addi"
    assert (
        disasm.extract_imm_i(gen_instrs[-2])
        == (used_s_regs + local_var_nb + (1 if contains_call else 0)) * 8
    )
    # Jump check
    assert instrs[-1].name == "jalr"
    assert instrs[-1].rd == 0
    assert instrs[-1].rs1 == RA


# Trampolines
# \__________


@pytest.mark.parametrize(
    "offset",
    [0x8, 0x800, 0xFFF, 0x80000, 0x1FFFE, -0x8, -0x800, -0xFFF, -0x80000, -0x1FFFE],
)
@pytest.mark.parametrize("register", TEST_CALLER_SAVED_REG)
def test_build_pc_relative_reg_save(offset, register, disasm_setup):
    instr_builder = InstructionBuilder()
    instrs = instr_builder.build_pc_relative_reg_save(offset=offset, register=register)
    gen_instrs = [instr.generate() for instr in instrs]
    assert instrs[0].name == "auipc"
    assert instrs[1].name == "addi"
    # Disassembly
    disasm = disasm_setup
    assert disasm.get_instruction_info(gen_instrs[0]).name == "auipc"
    assert disasm.get_instruction_info(gen_instrs[1]).name == "addi"
    assert offset == disasm.extract_pc_relative_offset(gen_instrs)


def test_build_call_jit_elt_trampoline(disasm_setup):
    instr_builder = InstructionBuilder()
    instrs = instr_builder.build_call_jit_elt_trampoline()
    gen_instrs = [instr.generate() for instr in instrs]
    assert instrs[0].name == "jalr"
    # Disassembly
    disasm = disasm_setup
    assert disasm.get_instruction_info(gen_instrs[0]).name == "jalr"
    assert disasm.extract_imm_i(gen_instrs[0]) == 0
    assert disasm.extract_rd(gen_instrs[0]) == 0
    assert disasm.extract_rs1(gen_instrs[0]) == CALL_TMP_REG


def test_build_ret_from_jit_elt_trampoline(disasm_setup):
    instr_builder = InstructionBuilder()
    instrs = instr_builder.build_ret_from_jit_elt_trampoline()
    gen_instrs = [instr.generate() for instr in instrs]
    assert instrs[0].name == "jalr"
    # Disassembly
    disasm = disasm_setup
    assert disasm.extract_imm_i(gen_instrs[0]) == 0
    assert disasm.extract_rd(gen_instrs[0]) == 0
    assert disasm.extract_rs1(gen_instrs[0]) == RA
    assert disasm.get_instruction_info(gen_instrs[0]).name == "jalr"


@pytest.mark.parametrize("offset", [0x800, 0xFFF, 0x80000, 0x1FFFE])
@pytest.mark.parametrize(
    "call_trampoline_offset", [-4, -8, -0x800, -0xFFF, -0x80000, -0x1FFFE]
)
def test_build_method_trampoline_call(offset, call_trampoline_offset, disasm_setup):
    instr_builder = InstructionBuilder()
    instrs = instr_builder.build_method_trampoline_call(
        offset=offset, call_trampoline_offset=call_trampoline_offset  # right before!
    )
    gen_instrs = [instr.generate() for instr in instrs]
    # Test code
    assert instrs[0].name == "auipc"
    assert instrs[1].name == "addi"
    assert instrs[2].name == "auipc"
    assert instrs[3].name == "addi"
    assert instrs[4].name == "jal"
    # Disassembly
    disasm = disasm_setup
    assert disasm.get_instruction_info(gen_instrs[0]).name == "auipc"
    assert disasm.get_instruction_info(gen_instrs[1]).name == "addi"
    assert disasm.get_instruction_info(gen_instrs[2]).name == "auipc"
    assert disasm.get_instruction_info(gen_instrs[3]).name == "addi"
    assert disasm.get_instruction_info(gen_instrs[4]).name == "jal"
    # Check RA
    assert disasm.extract_pc_relative_offset(gen_instrs[0:2]) == len(instrs) * 4
    # Check call target
    assert disasm.extract_pc_relative_offset(gen_instrs[2:4]) == offset - 8
    # Check trampoline jump
    aligned_trampoline_offset = (call_trampoline_offset >> 1) << 1
    assert (
        disasm.extract_imm_j(gen_instrs[-1], sign_extend=True)
        == aligned_trampoline_offset - (len(instrs) - 1) * 4
        # Note: The offset is corrected with the length of the other instructions
    )


@pytest.mark.parametrize("offset", [0x800, 0xFFF, 0x80000, 0x1FFFE])
@pytest.mark.parametrize("hit_case", range(1, 5))
@pytest.mark.parametrize(
    "call_trampoline_offset", [-4, -8, -0x800, -0xFFF, -0x80000, -0x1FFFE]
)
def test_build_pic_trampoline_call(
    offset, call_trampoline_offset, hit_case, disasm_setup
):
    instr_builder = InstructionBuilder()
    instrs = instr_builder.build_pic_trampoline_call(
        offset=offset, call_trampoline_offset=call_trampoline_offset, hit_case=hit_case
    )
    gen_instrs = [instr.generate() for instr in instrs]
    assert instrs[0].name == "addi"
    assert instrs[1].name == "auipc"
    assert instrs[2].name == "addi"
    assert instrs[3].name == "auipc"
    assert instrs[4].name == "addi"
    assert instrs[5].name == "jal"
    # Disassembly
    disasm = disasm_setup
    assert disasm.get_instruction_info(gen_instrs[0]).name == "addi"
    assert disasm.get_instruction_info(gen_instrs[1]).name == "auipc"
    assert disasm.get_instruction_info(gen_instrs[2]).name == "addi"
    assert disasm.get_instruction_info(gen_instrs[3]).name == "auipc"
    assert disasm.get_instruction_info(gen_instrs[4]).name == "addi"
    assert disasm.get_instruction_info(gen_instrs[5]).name == "jal"
    assert disasm.extract_rd(gen_instrs[0]) == HIT_CASE_REG
    assert disasm.extract_imm_i(gen_instrs[0]) == hit_case
    # Check RA
    assert disasm.extract_pc_relative_offset(gen_instrs[1:3]) == (len(instrs) - 1) * 4
    # Note: The RA should point at the end of the block and it does not take
    # in account the first instruction
    # Check call target
    assert disasm.extract_pc_relative_offset(gen_instrs[3:5]) == offset - 0xC
    # Note: The offset is used once the hitcase is loaded (1 instr) and
    # RA is computed (2 instrs) so 3 instructions should be removed from it
    # Check trampoline jump
    aligned_trampoline_offset = (call_trampoline_offset >> 1) << 1
    assert (
        disasm.extract_imm_j(gen_instrs[-1], sign_extend=True)
        == aligned_trampoline_offset - (len(instrs) - 1) * 4
        # Note: The offset is corrected with the length of the other instructions
    )


# =================================
#      Disassembly/Execution
# =================================

# Specific instructions
# \____________________


def test_build_nop(cap_disasm_setup):
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_nop()
    bytes = instr.generate_bytes()
    # Disassembly
    cap_disasm = cap_disasm_setup
    instr_disasm = next(cap_disasm.disasm(bytes, ADDRESS))
    assert instr_disasm.mnemonic == "nop"


def test_build_ret(cap_disasm_setup):
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_ret()
    bytes = instr.generate_bytes()
    # Disassembly
    cap_disasm = cap_disasm_setup
    instr_disasm = next(cap_disasm.disasm(bytes, ADDRESS))
    assert instr_disasm.mnemonic == "ret"


# Random instructions
# \__________________


@pytest.mark.parametrize("execution_number", range(30))
def test_build_random_instruction_disassembly_smoke(execution_number, cap_disasm_setup):
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_random_instruction(
        registers=TEST_CALLER_SAVED_REG,
        max_offset=0x7FF,
        data_reg=TEST_DATA_REG,
        data_size=TEST_DATA_SIZE,
    )
    bytes = instr.generate_bytes()
    # Disassembly
    cap_disasm = cap_disasm_setup
    next(cap_disasm.disasm(bytes, ADDRESS))


@pytest.mark.parametrize("execution_number", range(30))
@pytest.mark.parametrize(
    "build_method",
    [
        getattr(InstructionBuilder, "build_random_r_instruction"),
        getattr(InstructionBuilder, "build_random_i_instruction"),
        getattr(InstructionBuilder, "build_random_u_instruction"),
    ],
)
def test_build_random_riu_disassembly_execution_smoke(
    execution_number, build_method, uc_emul_setup, cap_disasm_setup
):
    instr = build_method(TEST_CALLER_SAVED_REG)
    bytes = instr.generate_bytes()
    # Disassembly
    cap_disasm = cap_disasm_setup
    next(cap_disasm.disasm(bytes, ADDRESS))
    # Emulation
    uc_emul = uc_emul_setup
    uc_emul.mem_write(ADDRESS, bytes)
    uc_emul.emu_start(ADDRESS, ADDRESS + len(bytes))
    uc_emul.emu_stop()


@pytest.mark.parametrize("execution_number", range(5))
def test_random_j_disassembly_execution_smoke(
    execution_number, cap_disasm_setup, uc_emul_full_setup
):
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_random_j_instruction(
        TEST_CALLER_SAVED_REG, (RET_ADDRESS - ADDRESS) & 0xFFFFF
    )
    bytes = instr.generate_bytes()
    # Disassembly
    cap_disasm = cap_disasm_setup
    next(cap_disasm.disasm(bytes, ADDRESS))
    # Emulation
    uc_emul = uc_emul_full_setup
    uc_emul.mem_write(ADDRESS, bytes)
    uc_emul.emu_start(ADDRESS, 0, count=1)
    uc_emul.emu_stop()


@pytest.mark.parametrize("execution_number", range(10))
def test_random_b_disassembly_execution_smoke(
    execution_number, cap_disasm_setup, uc_emul_full_setup
):
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_random_b_instruction(
        TEST_CALLER_SAVED_REG, (RET_ADDRESS - ADDRESS) & 0x7FF
    )
    bytes = instr.generate_bytes()
    # Disassembly
    cap_disasm = cap_disasm_setup
    next(cap_disasm.disasm(bytes, ADDRESS))
    # Emulation
    uc_emul = uc_emul_full_setup
    uc_emul.mem_write(ADDRESS, bytes)
    uc_emul.emu_start(ADDRESS, 0, count=1)
    uc_emul.emu_stop()


@pytest.mark.parametrize("execution_number", range(5))
def test_random_s_disassembly_execution_smoke(
    execution_number, uc_emul_full_setup, cap_disasm_setup
):
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_random_s_instruction(
        registers=TEST_CALLER_SAVED_REG,
        data_reg=TEST_DATA_REG,
        data_size=TEST_DATA_SIZE,
    )
    bytes = instr.generate_bytes()
    # Disassembly
    cap_disasm = cap_disasm_setup
    next(cap_disasm.disasm(bytes, ADDRESS))
    # Emulation
    uc_emul = uc_emul_full_setup
    bytes = instr.generate_bytes()
    uc_emul.mem_write(ADDRESS, bytes)
    uc_emul.emu_start(ADDRESS, 0, count=1)
    uc_emul.emu_stop()


@pytest.mark.parametrize("execution_number", range(5))
def test_random_l_disassembly_execution_smoke(
    execution_number, uc_emul_full_setup, cap_disasm_setup
):
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_random_l_instruction(
        registers=TEST_CALLER_SAVED_REG,
        data_reg=TEST_DATA_REG,
        data_size=TEST_DATA_SIZE,
    )
    bytes = instr.generate_bytes()
    # Disassembly
    cap_disasm = cap_disasm_setup
    next(cap_disasm.disasm(bytes, ADDRESS))
    # Emulation
    uc_emul = uc_emul_full_setup
    bytes = instr.generate_bytes()
    uc_emul.mem_write(ADDRESS, bytes)
    uc_emul.emu_start(ADDRESS, 0, count=1)
    uc_emul.emu_stop()


# Base Calls
# \__________


@pytest.mark.parametrize("offset", [0x8, 0x800, 0xFFE, 0x80000, 0x1FFFE, 0xFFFFE])
def test_build_method_call_execution(offset, uc_emul_full_setup, cap_disasm_setup):
    instr_builder = InstructionBuilder()
    instrs = instr_builder.build_method_base_call(offset)
    bytes = instr_builder.consolidate_bytes(instrs)
    # Disassembly
    cap_disasm = cap_disasm_setup
    for _ in cap_disasm.disasm(bytes, ADDRESS):
        pass
    # Emulation
    uc_emul = uc_emul_full_setup
    uc_emul.mem_write(ADDRESS, bytes)
    uc_emul.emu_start(begin=ADDRESS, until=ADDRESS + offset)
    current_ra = uc_emul.reg_read(UC_RISCV_REG_RA)
    current_pc = uc_emul.reg_read(UC_RISCV_REG_PC)
    assert current_ra == ADDRESS + 8  # size of the
    assert current_pc == ADDRESS + offset
    uc_emul.emu_stop()


@pytest.mark.parametrize("offset", [0x800, 0xFFE, 0x80000, 0x1FFFE, 0xFFFFE])
@pytest.mark.parametrize("hit_case", range(1, 5))
def test_build_pic_call_execution(
    offset, hit_case, uc_emul_full_setup, cap_disasm_setup
):
    instr_builder = InstructionBuilder()
    instrs = instr_builder.build_pic_base_call(offset, hit_case, 5)
    bytes = instr_builder.consolidate_bytes(instrs)
    # Disassembly
    cap_disasm = cap_disasm_setup
    for _ in cap_disasm.disasm(bytes, ADDRESS):
        pass
    # Emulation
    uc_emul = uc_emul_full_setup
    uc_emul.mem_write(ADDRESS, bytes)
    uc_emul.emu_start(begin=ADDRESS, until=ADDRESS + offset + 4)
    current_t0 = uc_emul.reg_read(UC_RISCV_REG_T0)
    assert current_t0 == hit_case
    uc_emul.emu_stop()


# PIC Switch
# \__________


@pytest.mark.parametrize("offset", [0x8, 0x800, 0xFFE, 0x80000, 0x1FFFE, 0xFFFFE])
@pytest.mark.parametrize("case_number", range(5))
def test_build_switch_pic_execution(
    offset, case_number, uc_emul_full_setup, cap_disasm_setup
):
    instr_builder = InstructionBuilder()
    instrs = instr_builder.build_switch_case(
        case_number=case_number, method_offset=offset
    )
    bytes = instr_builder.consolidate_bytes(instrs)
    # Disassembly
    cap_disasm = cap_disasm_setup
    for _ in cap_disasm.disasm(bytes, ADDRESS):
        pass
    # Emulation
    uc_emul = uc_emul_full_setup
    uc_emul.mem_write(ADDRESS, bytes)
    # Force the hit on the given case
    uc_emul.reg_write(UC_RISCV_REG_T0, case_number)
    uc_emul.emu_start(begin=ADDRESS, until=ADDRESS + 8 + offset)
    current_t1 = uc_emul.reg_read(UC_RISCV_REG_T1)
    assert current_t1 == case_number
    uc_emul.emu_stop()


# Prologue/Epilogue
# \_________________


@pytest.mark.parametrize("used_s_regs", [0, 5, 10])
@pytest.mark.parametrize("local_var_nb", [0, 5, 10])
@pytest.mark.parametrize("contains_call", [True, False])
def test_build_prologue_execution(
    used_s_regs, local_var_nb, contains_call, uc_emul_full_setup, cap_disasm_setup
):
    instr_builder = InstructionBuilder()
    instrs = instr_builder.build_prologue(
        used_s_regs=used_s_regs, local_var_nb=local_var_nb, contains_call=contains_call
    )
    bytes = instr_builder.consolidate_bytes(instrs)
    # Disassembly
    cap_disasm = cap_disasm_setup
    for _ in cap_disasm.disasm(bytes, ADDRESS):
        pass
    # Emulation
    uc_emul = uc_emul_full_setup
    uc_emul.mem_write(ADDRESS, bytes)
    # Write in callee-saved regs
    uc_emul.reg_write(UC_RISCV_REG_S0, 0x1)
    uc_emul.reg_write(UC_RISCV_REG_S1, 0x2)
    uc_emul.reg_write(UC_RISCV_REG_S2, 0x3)
    uc_emul.reg_write(UC_RISCV_REG_S3, 0x4)
    uc_emul.reg_write(UC_RISCV_REG_S4, 0x5)
    uc_emul.reg_write(UC_RISCV_REG_S5, 0x6)
    uc_emul.reg_write(UC_RISCV_REG_S6, 0x7)
    uc_emul.reg_write(UC_RISCV_REG_S7, 0x8)
    uc_emul.reg_write(UC_RISCV_REG_S8, 0x9)
    uc_emul.reg_write(UC_RISCV_REG_S9, 0xA)
    uc_emul.emu_start(begin=ADDRESS, until=ADDRESS + len(bytes))
    current_sp = uc_emul.reg_read(UC_RISCV_REG_SP)
    for i in range(used_s_regs):
        tmp = uc_emul.mem_read(current_sp + i * 8, 8)
        assert bytes_to_int(tmp) == i + 1
    if contains_call:
        tmp = uc_emul.mem_read(current_sp + used_s_regs * 8, 8)
        assert bytes_to_int(tmp) == RET_ADDRESS
    uc_emul.emu_stop()


@pytest.mark.parametrize("used_s_regs", [0, 5, 10])
@pytest.mark.parametrize("local_var_nb", [0, 5, 10])
@pytest.mark.parametrize("contains_call", [True, False])
def test_build_epilogue_execution(
    used_s_regs, local_var_nb, contains_call, uc_emul_full_setup, cap_disasm_setup
):
    instr_builder = InstructionBuilder()
    instrs = instr_builder.build_epilogue(
        used_s_regs=used_s_regs, local_var_nb=local_var_nb, contains_call=contains_call
    )
    bytes = instr_builder.consolidate_bytes(instrs)
    # Disassembly
    cap_disasm = cap_disasm_setup
    for _ in cap_disasm.disasm(bytes, ADDRESS):
        pass
    # Emulation
    uc_emul = uc_emul_full_setup
    uc_emul.mem_write(ADDRESS, bytes)
    # Zero out callee saved regs
    callee_saved_regs = [
        UC_RISCV_REG_S0,
        UC_RISCV_REG_S1,
        UC_RISCV_REG_S2,
        UC_RISCV_REG_S3,
        UC_RISCV_REG_S4,
        UC_RISCV_REG_S5,
        UC_RISCV_REG_S6,
        UC_RISCV_REG_S7,
        UC_RISCV_REG_S8,
        UC_RISCV_REG_S9,
    ]
    for reg in callee_saved_regs:
        uc_emul.reg_write(reg, 0x0)
    # Write values at addresses
    for i in range(used_s_regs):
        uc_emul.mem_write(STACK_ADDRESS + i * 8, int_to_bytes64(i + 1))
    # Previously saved RA
    called_address = RET_ADDRESS - 24
    if contains_call:
        uc_emul.mem_write(
            STACK_ADDRESS + used_s_regs * 8, int_to_bytes64(called_address)
        )
    # Setup capstone
    cap_disasm = cap_disasm_setup
    for _ in cap_disasm.disasm(bytes, ADDRESS):
        pass
    # Launch emulation
    uc_emul.emu_start(
        begin=ADDRESS, until=(called_address if contains_call else RET_ADDRESS)
    )
    # Check registers
    for i, reg in enumerate(callee_saved_regs[:used_s_regs]):
        tmp = uc_emul.reg_read(reg)
        assert tmp == i + 1
    current_sp = uc_emul.reg_read(UC_RISCV_REG_SP)
    current_pc = uc_emul.reg_read(UC_RISCV_REG_PC)
    assert (
        current_sp
        == STACK_ADDRESS
        + (used_s_regs + local_var_nb + (1 if contains_call else 0)) * 8
    )
    assert current_pc == called_address if contains_call else RET_ADDRESS
    uc_emul.emu_stop()


# Trampolines
# \___________


def test_pc_relative_reg_save_execution():
    pass


@pytest.mark.parametrize("offset", [0x800, 0xFFE, 0x80000, 0x1FFFE, 0xFFFFE])
def test_build_method_call_trampoline_execution(
    offset, uc_emul_full_setup, cap_disasm_setup, handler_setup
):
    instr_builder = InstructionBuilder()
    tramp_instrs = instr_builder.build_call_jit_elt_trampoline()
    tramp_bytes = instr_builder.consolidate_bytes(tramp_instrs)
    instrs = instr_builder.build_method_trampoline_call(
        offset=offset,
        call_trampoline_offset=-4,  # The trampoline is right before!
    )
    bytes = instr_builder.consolidate_bytes(instrs)
    CODE_ADDRESS = ADDRESS + len(tramp_bytes)
    # Disassembly
    cap_disasm = cap_disasm_setup
    cap_disasm_bytes(cap_disasm, tramp_bytes, ADDRESS)
    cap_disasm_bytes(cap_disasm, bytes, CODE_ADDRESS)
    # Handler
    handler = handler_setup
    # Emulation
    uc_emul = uc_emul_full_setup
    handler.hook_instr_tracer(uc_emul)
    uc_emul.mem_write(ADDRESS, tramp_bytes)
    uc_emul.mem_write(CODE_ADDRESS, bytes)
    uc_emul.emu_start(begin=CODE_ADDRESS, until=CODE_ADDRESS + offset)
    current_ra = uc_emul.reg_read(UC_RISCV_REG_RA)
    current_pc = uc_emul.reg_read(UC_RISCV_REG_PC)
    assert current_ra == CODE_ADDRESS + 0x14  # size of the call mitigated!
    assert current_pc == CODE_ADDRESS + offset
    uc_emul.emu_stop()


@pytest.mark.parametrize("offset", [0x800, 0xFFE, 0x80000, 0x1FFFE, 0xFFFFE])
@pytest.mark.parametrize("hit_case", range(1, 5))
def test_build_pic_call_trampoline_execution(
    offset, hit_case, uc_emul_full_setup, cap_disasm_setup, handler_setup
):
    instr_builder = InstructionBuilder()
    tramp_instrs = instr_builder.build_call_jit_elt_trampoline()
    tramp_bytes = instr_builder.consolidate_bytes(tramp_instrs)
    instrs = instr_builder.build_pic_trampoline_call(
        offset=offset,
        call_trampoline_offset=-4,  # The trampoline is right before!
        hit_case=hit_case,
        hit_case_reg=5,
    )
    bytes = instr_builder.consolidate_bytes(instrs)
    CODE_ADDRESS = ADDRESS + len(tramp_bytes)
    # Disassembly
    cap_disasm = cap_disasm_setup
    cap_disasm_bytes(cap_disasm, tramp_bytes, ADDRESS)
    cap_disasm_bytes(cap_disasm, bytes, CODE_ADDRESS)
    # Handler
    handler = handler_setup
    # Emulation
    uc_emul = uc_emul_full_setup
    handler.hook_instr_tracer(uc_emul)
    uc_emul.mem_write(ADDRESS, tramp_bytes)
    uc_emul.mem_write(CODE_ADDRESS, bytes)
    uc_emul.emu_start(begin=CODE_ADDRESS, until=CODE_ADDRESS + offset)
    current_t0 = uc_emul.reg_read(UC_RISCV_REG_T0)
    current_ra = uc_emul.reg_read(UC_RISCV_REG_RA)
    current_pc = uc_emul.reg_read(UC_RISCV_REG_PC)
    assert current_ra == CODE_ADDRESS + 0x18  # size of the call mitigated!
    assert current_pc == CODE_ADDRESS + offset
    assert current_t0 == hit_case
    uc_emul.emu_stop()
