import pytest
from unicorn.riscv_const import UC_RISCV_REG_RA

from gigue.constants import RA
from gigue.rimi.rimi_builder import (
    RIMIFullInstructionBuilder,
    RIMIShadowStackInstructionBuilder,
)
from gigue.rimi.rimi_constants import RIMI_SSP_REG
from tests.conftest import (
    ADDRESS,
    JIT_START_ADDRESS,
    RET_ADDRESS,
    TEST_CALLER_SAVED_REG,
    TEST_DATA_REG,
    TEST_DATA_SIZE,
    UC_CALL_TMP_REG,
    cap_disasm_bytes,
)
from tests.rimi.conftest import (
    DomainAccessException,
    WrongDomainException,
    start_resumable_emulation,
)

# from tests.conftest import ADDRESS, RET_ADDRESS, STACK_ADDRESS, UC_CALL_TMP_REG

# ===================================
#         RIMI Shadow Stack
# ===================================

# Base version
# \____________


@pytest.mark.parametrize("used_s_regs", [0, 5, 10])
@pytest.mark.parametrize("local_var_nb", [0, 5, 10])
@pytest.mark.parametrize("contains_call", [True, False])
def test_build_ss_prologue(
    used_s_regs, local_var_nb, contains_call, rimi_disasm_setup, cap_disasm_custom_setup
):
    instr_builder = RIMIShadowStackInstructionBuilder()
    instrs = instr_builder.build_prologue(
        used_s_regs=used_s_regs, local_var_nb=local_var_nb, contains_call=contains_call
    )
    gen_instrs = [instr.generate() for instr in instrs]
    # RIMI disassembler
    rimi_disasm = rimi_disasm_setup
    # Space on top of the stack
    assert instrs[0].name == "addi"
    assert (
        rimi_disasm.extract_imm_i(gen_instrs[0], sign_extend=True)
        == -(used_s_regs + local_var_nb) * 8
    )
    # Filling of the stack
    for i, (instr, generated) in enumerate(zip(instrs[1:-2], gen_instrs[1:-2])):
        assert instr.name == "sd"
        assert rimi_disasm.extract_imm_s(generated) == i * 8
    # Shadow stack pointer decrease and store (push)
    if contains_call:
        assert instrs[-2].name == "addi"
        assert rimi_disasm.extract_imm_i(gen_instrs[-2], sign_extend=True) == -8
        assert rimi_disasm.extract_rs1(instrs[-2].generate()) == RIMI_SSP_REG
        assert rimi_disasm.extract_rd(instrs[-2].generate()) == RIMI_SSP_REG
        assert instrs[-1].name == "ss"
        assert rimi_disasm.extract_imm_s(gen_instrs[-1]) == 0
        assert rimi_disasm.extract_rs2(instrs[-1].generate()) == RA
        assert rimi_disasm.extract_rs1(instrs[-1].generate()) == RIMI_SSP_REG


@pytest.mark.parametrize("used_s_regs", [0, 5, 10])
@pytest.mark.parametrize("local_var_nb", [0, 5, 10])
@pytest.mark.parametrize("contains_call", [True, False])
def test_build_ss_epilogue(used_s_regs, local_var_nb, contains_call, rimi_disasm_setup):
    instr_builder = RIMIShadowStackInstructionBuilder()
    instrs = instr_builder.build_epilogue(
        used_s_regs=used_s_regs, local_var_nb=local_var_nb, contains_call=contains_call
    )
    gen_instrs = [instr.generate() for instr in instrs]
    # Disassembly
    rimi_disasm = rimi_disasm_setup
    # Restore saved regs
    for i, (instr, generated) in enumerate(zip(instrs[:-4], gen_instrs[:-4])):
        assert instr.name == "ld"
        assert rimi_disasm.extract_imm_i(generated) == i * 8
    # Restore SP
    assert instrs[used_s_regs].name == "addi"
    assert (
        rimi_disasm.extract_imm_i(gen_instrs[used_s_regs])
        == (used_s_regs + local_var_nb) * 8
    )
    # Shadow stack pointer increase and store (pop)
    if contains_call:
        assert instrs[-3].name == "ls"
        assert rimi_disasm.extract_imm_i(gen_instrs[-3]) == 0
        assert rimi_disasm.extract_rd(instrs[-3].generate()) == RA
        assert rimi_disasm.extract_rs1(instrs[-3].generate()) == RIMI_SSP_REG
        assert instrs[-2].name == "addi"
        assert rimi_disasm.extract_imm_i(gen_instrs[-2], sign_extend=True) == +8
        assert rimi_disasm.extract_rs1(instrs[-2].generate()) == RIMI_SSP_REG
        assert rimi_disasm.extract_rd(instrs[-2].generate()) == RIMI_SSP_REG
    # Ret check
    assert instrs[-1].name == "jalr"
    assert rimi_disasm.extract_rd(instrs[-1].generate()) == 0
    assert rimi_disasm.extract_rs1(instrs[-1].generate()) == RA


# Trampoline version
# \__________________


@pytest.mark.parametrize("used_s_regs", [0, 5, 10])
@pytest.mark.parametrize("local_var_nb", [0, 5, 10])
@pytest.mark.parametrize("contains_call", [True, False])
@pytest.mark.parametrize(
    "ret_trampoline_offset", [-4, -8, -0x800, -0xFFF, -0x80000, -0x1FFFE]
)
def test_build_ss_trampoline_epilogue(
    used_s_regs, local_var_nb, contains_call, ret_trampoline_offset, rimi_disasm_setup
):
    instr_builder = RIMIShadowStackInstructionBuilder()
    instrs = instr_builder.build_trampoline_epilogue(
        used_s_regs=used_s_regs,
        local_var_nb=local_var_nb,
        contains_call=contains_call,
        ret_trampoline_offset=ret_trampoline_offset,
    )
    gen_instrs = [instr.generate() for instr in instrs]
    # Disassembly
    rimi_disasm = rimi_disasm_setup
    # Restore saved regs
    for i, (instr, generated) in enumerate(zip(instrs[:-4], gen_instrs[:-4])):
        assert instr.name == "ld"
        assert rimi_disasm.extract_imm_i(generated) == i * 8
    # Restore SP
    assert instrs[used_s_regs].name == "addi"
    assert (
        rimi_disasm.extract_imm_i(gen_instrs[used_s_regs])
        == (used_s_regs + local_var_nb) * 8
    )
    # Shadow stack pointer increase and store (pop)
    if contains_call:
        assert instrs[-3].name == "ls"
        assert rimi_disasm.extract_imm_i(gen_instrs[-3]) == 0
        assert rimi_disasm.extract_rd(instrs[-3].generate()) == RA
        assert rimi_disasm.extract_rs1(instrs[-3].generate()) == RIMI_SSP_REG
        assert instrs[-2].name == "addi"
        assert rimi_disasm.extract_imm_i(gen_instrs[-2], sign_extend=True) == +8
        assert rimi_disasm.extract_rs1(instrs[-2].generate()) == RIMI_SSP_REG
        assert rimi_disasm.extract_rd(instrs[-2].generate()) == RIMI_SSP_REG
    # Ret check
    # Jump check
    assert instrs[-1].name == "jal"
    aligned_trampoline_offset = (ret_trampoline_offset >> 1) << 1
    assert (
        rimi_disasm.extract_imm_j(gen_instrs[-1], sign_extend=True)
        == aligned_trampoline_offset - (len(instrs) - 1) * 4
        # Note: The offset is corrected with the length of the other instructions
    )


# ===================================
#             Execution
# ===================================

# Prologue/Epilogue
# \_________________

# Duplicated accesses
# \___________________


@pytest.mark.parametrize("execution_number", range(10))
def test_build_random_s_instruction_correct(
    execution_number,
    rimi_handler_setup,
    cap_disasm_custom_setup,
    rimi_uc_emul_full_setup,
):
    instr_builder = RIMIFullInstructionBuilder()
    instr = instr_builder.build_random_s_instruction(
        registers=TEST_CALLER_SAVED_REG,
        data_reg=TEST_DATA_REG,
        data_size=TEST_DATA_SIZE,
    )
    bytes = instr.generate_bytes()
    # Disassembly
    cap_disasm = cap_disasm_custom_setup
    next(cap_disasm.disasm(bytes, ADDRESS))
    # Handler
    rimi_handler = rimi_handler_setup
    rimi_handler.current_domain = 1
    # Emulation
    uc_emul = rimi_uc_emul_full_setup
    rimi_handler.hook_handler(uc_emul)
    uc_emul.mem_write(ADDRESS, bytes)
    uc_emul.emu_start(ADDRESS, 0, count=1)
    uc_emul.emu_stop()


@pytest.mark.parametrize("execution_number", range(10))
def test_build_random_s_instruction_wrong_domain(
    execution_number,
    rimi_handler_setup,
    cap_disasm_custom_setup,
    rimi_uc_emul_full_setup,
):
    instr_builder = RIMIFullInstructionBuilder()
    instr = instr_builder.build_random_s_instruction(
        registers=TEST_CALLER_SAVED_REG,
        data_reg=TEST_DATA_REG,
        data_size=TEST_DATA_SIZE,
    )
    bytes = instr.generate_bytes()
    # Disassembly
    cap_disasm = cap_disasm_custom_setup
    next(cap_disasm.disasm(bytes, ADDRESS))
    # Handler
    rimi_handler = rimi_handler_setup
    rimi_handler.current_domain = 0  # Wrong domain!!!
    # Emulation
    uc_emul = rimi_uc_emul_full_setup
    rimi_handler.hook_handler(uc_emul)
    uc_emul.mem_write(ADDRESS, bytes)
    with pytest.raises(WrongDomainException):
        uc_emul.emu_start(ADDRESS, 0, count=1)
        uc_emul.emu_stop()


@pytest.mark.parametrize("execution_number", range(10))
def test_build_random_s_instruction_access_fault(
    execution_number,
    rimi_handler_setup,
    cap_disasm_custom_setup,
    rimi_uc_emul_full_setup,
):
    instr_builder = RIMIFullInstructionBuilder()
    instr = instr_builder.build_random_s_instruction(
        registers=TEST_CALLER_SAVED_REG,
        data_reg=RIMI_SSP_REG,  # Wrong address for access!!!
        data_size=TEST_DATA_SIZE,
    )
    bytes = instr.generate_bytes()
    # Disassembly
    cap_disasm = cap_disasm_custom_setup
    next(cap_disasm.disasm(bytes, ADDRESS))
    # Handler
    rimi_handler = rimi_handler_setup
    rimi_handler.current_domain = 1
    # Emulation
    uc_emul = rimi_uc_emul_full_setup
    rimi_handler.hook_handler(uc_emul)
    uc_emul.mem_write(ADDRESS, bytes)
    with pytest.raises(DomainAccessException):
        uc_emul.emu_start(ADDRESS, 0, count=1)
        uc_emul.emu_stop()


@pytest.mark.parametrize("execution_number", range(10))
def test_build_random_l_instruction_correct(
    execution_number,
    rimi_handler_setup,
    cap_disasm_custom_setup,
    rimi_uc_emul_full_setup,
):
    instr_builder = RIMIFullInstructionBuilder()
    instr = instr_builder.build_random_l_instruction(
        registers=TEST_CALLER_SAVED_REG,
        data_reg=TEST_DATA_REG,
        data_size=TEST_DATA_SIZE,
    )
    bytes = instr.generate_bytes()
    # Disassembly
    cap_disasm = cap_disasm_custom_setup
    next(cap_disasm.disasm(bytes, ADDRESS))
    # Handler
    rimi_handler = rimi_handler_setup
    rimi_handler.current_domain = 1
    # Emulation
    uc_emul = rimi_uc_emul_full_setup
    rimi_handler.hook_handler(uc_emul)
    uc_emul.mem_write(ADDRESS, bytes)
    uc_emul.emu_start(ADDRESS, 0, count=1)
    uc_emul.emu_stop()


@pytest.mark.parametrize("execution_number", range(10))
def test_build_random_l_instruction_wrong_domain(
    execution_number,
    rimi_handler_setup,
    cap_disasm_custom_setup,
    rimi_uc_emul_full_setup,
):
    instr_builder = RIMIFullInstructionBuilder()
    instr = instr_builder.build_random_l_instruction(
        registers=TEST_CALLER_SAVED_REG,
        data_reg=TEST_DATA_REG,
        data_size=TEST_DATA_SIZE,
    )
    bytes = instr.generate_bytes()
    # Disassembly
    cap_disasm = cap_disasm_custom_setup
    next(cap_disasm.disasm(bytes, ADDRESS))
    # Handler
    rimi_handler = rimi_handler_setup
    rimi_handler.current_domain = 0  # Wrong domain!!!
    # Emulation
    uc_emul = rimi_uc_emul_full_setup
    rimi_handler.hook_handler(uc_emul)
    uc_emul.mem_write(ADDRESS, bytes)
    with pytest.raises(WrongDomainException):
        uc_emul.emu_start(ADDRESS, 0, count=1)
        uc_emul.emu_stop()


@pytest.mark.parametrize("execution_number", range(10))
def test_build_random_l_instruction_access_fault(
    execution_number,
    rimi_handler_setup,
    cap_disasm_custom_setup,
    rimi_uc_emul_full_setup,
):
    instr_builder = RIMIFullInstructionBuilder()
    instr = instr_builder.build_random_l_instruction(
        registers=TEST_CALLER_SAVED_REG,
        data_reg=RIMI_SSP_REG,  # Wrong address for access!!!
        data_size=TEST_DATA_SIZE,
    )
    bytes = instr.generate_bytes()
    # Disassembly
    cap_disasm = cap_disasm_custom_setup
    next(cap_disasm.disasm(bytes, ADDRESS))
    # Handler
    rimi_handler = rimi_handler_setup
    rimi_handler.current_domain = 1
    # Emulation
    uc_emul = rimi_uc_emul_full_setup
    rimi_handler.hook_handler(uc_emul)
    uc_emul.mem_write(ADDRESS, bytes)
    with pytest.raises(DomainAccessException):
        uc_emul.emu_start(ADDRESS, 0, count=1)
        uc_emul.emu_stop()


# Trampolines
# \___________


def test_build_call_jit_elt_from_jit_trampoline(
    rimi_handler_setup,
    cap_disasm_custom_setup,
    rimi_uc_emul_full_setup,
):
    instr_builder = RIMIFullInstructionBuilder()
    instr = instr_builder.build_call_jit_elt_trampoline()
    bytes = instr_builder.consolidate_bytes(instr)
    # Disassembly
    cap_disasm = cap_disasm_custom_setup
    cap_disasm_bytes(cap_disasm, bytes, JIT_START_ADDRESS)
    # Handler
    rimi_handler = rimi_handler_setup
    rimi_handler.current_domain = 1
    # Emulation
    uc_emul = rimi_uc_emul_full_setup
    rimi_handler.hook_handler(uc_emul)
    rimi_handler.hook_instr_tracer(uc_emul)

    # To simulate a JIT -> JIT call, we have to fill the called address and RA
    start_address = JIT_START_ADDRESS  # \
    end_address = JIT_START_ADDRESS + 24  # -> Calling a JIT method
    ret_address = JIT_START_ADDRESS + 56  # -> from another JIT method

    uc_emul.mem_write(start_address, bytes)
    uc_emul.reg_write(UC_CALL_TMP_REG, end_address)
    uc_emul.reg_write(UC_RISCV_REG_RA, ret_address)

    start_resumable_emulation(uc_emul, start_address, end_address)
    assert rimi_handler.current_domain == 1


def test_build_call_jit_elt_from_int_trampoline(
    rimi_handler_setup,
    cap_disasm_custom_setup,
    rimi_uc_emul_full_setup,
):
    instr_builder = RIMIFullInstructionBuilder()
    instr = instr_builder.build_call_jit_elt_trampoline()
    bytes = instr_builder.consolidate_bytes(instr)
    # Disassembly
    cap_disasm = cap_disasm_custom_setup
    cap_disasm_bytes(cap_disasm, bytes, JIT_START_ADDRESS)
    # Handler
    rimi_handler = rimi_handler_setup
    rimi_handler.current_domain = 0  # Calling from domain 0
    # Emulation
    uc_emul = rimi_uc_emul_full_setup
    rimi_handler.hook_handler(uc_emul)
    rimi_handler.hook_instr_tracer(uc_emul)
    rimi_handler.hook_reg_tracer(uc_emul)

    # To simulate a INT -> JIT call, we have to fill the called address and RA
    start_address = JIT_START_ADDRESS  # \
    end_address = JIT_START_ADDRESS + 24  # -> Calling a JIT method
    ret_address = RET_ADDRESS  # -> from the interpreter

    uc_emul.mem_write(start_address, bytes)
    uc_emul.reg_write(UC_CALL_TMP_REG, end_address)
    uc_emul.reg_write(UC_RISCV_REG_RA, ret_address)

    start_resumable_emulation(uc_emul, start_address, end_address)
    assert rimi_handler.current_domain == 1


def test_build_ret_from_jit_to_jit_trampoline(
    rimi_handler_setup,
    cap_disasm_custom_setup,
    rimi_uc_emul_full_setup,
):
    instr_builder = RIMIFullInstructionBuilder()
    instr = instr_builder.build_ret_from_jit_elt_trampoline()
    bytes = instr_builder.consolidate_bytes(instr)
    # Disassembly
    cap_disasm = cap_disasm_custom_setup
    cap_disasm_bytes(cap_disasm, bytes, JIT_START_ADDRESS)
    # Handler
    rimi_handler = rimi_handler_setup
    rimi_handler.current_domain = 1  # Returning from domain 1 (JIT)
    # Emulation
    uc_emul = rimi_uc_emul_full_setup
    rimi_handler.hook_handler(uc_emul)
    rimi_handler.hook_instr_tracer(uc_emul)

    # To simulate a JIT -> JIT return, we have to fill the RA
    start_address = JIT_START_ADDRESS  # \
    end_address = JIT_START_ADDRESS + 24
    ret_address = JIT_START_ADDRESS + 56  # -> from another JIT method

    uc_emul.mem_write(start_address, bytes)
    uc_emul.reg_write(UC_CALL_TMP_REG, end_address)  # Unused
    uc_emul.reg_write(UC_RISCV_REG_RA, ret_address)

    start_resumable_emulation(uc_emul, start_address, ret_address)
    assert rimi_handler.current_domain == 1


def test_build_ret_from_jit_to_int_trampoline(
    rimi_handler_setup,
    cap_disasm_custom_setup,
    rimi_uc_emul_full_setup,
):
    instr_builder = RIMIFullInstructionBuilder()
    instr = instr_builder.build_ret_from_jit_elt_trampoline()
    bytes = instr_builder.consolidate_bytes(instr)
    # Disassembly
    cap_disasm = cap_disasm_custom_setup
    cap_disasm_bytes(cap_disasm, bytes, JIT_START_ADDRESS)
    # Handler
    rimi_handler = rimi_handler_setup
    rimi_handler.current_domain = 1  # Returning from domain 1 (JIT)
    # Emulation
    uc_emul = rimi_uc_emul_full_setup
    rimi_handler.hook_handler(uc_emul)
    rimi_handler.hook_instr_tracer(uc_emul)
    rimi_handler.hook_reg_tracer(uc_emul)

    # To simulate a JIT -> INT return, we have to fill the called address and RA
    start_address = JIT_START_ADDRESS  # \
    end_address = JIT_START_ADDRESS + 24  # -> Calling a JIT method
    ret_address = RET_ADDRESS  # -> from the interpreter

    uc_emul.mem_write(start_address, bytes)
    uc_emul.reg_write(UC_CALL_TMP_REG, end_address)  # Unused
    uc_emul.reg_write(UC_RISCV_REG_RA, ret_address)

    start_resumable_emulation(uc_emul, start_address, ret_address)
    assert rimi_handler.current_domain == 0
