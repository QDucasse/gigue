import pytest

from gigue.constants import RA
from gigue.rimi.rimi_builder import RIMIShadowStackInstructionBuilder
from gigue.rimi.rimi_constants import RIMI_SSP_REG

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
        assert rimi_disasm.extract_imm_i(gen_instrs[-2], sign_extend=True) == -4
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
        assert rimi_disasm.extract_imm_i(gen_instrs[-2], sign_extend=True) == +4
        assert rimi_disasm.extract_rs1(instrs[-2].generate()) == RIMI_SSP_REG
        assert rimi_disasm.extract_rd(instrs[-2].generate()) == RIMI_SSP_REG
    # Ret check
    assert instrs[-1].name == "jalr"
    assert instrs[-1].rd == 0
    assert instrs[-1].rs1 == RA


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
        assert rimi_disasm.extract_imm_i(gen_instrs[-2], sign_extend=True) == +4
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
#           RIMI Domains
# ===================================

# Duplicated accesses
# \___________________


def test_build_random_s_instruction():
    pass


def test_build_random_l_instruction():
    pass


# Trampolines
# \___________


def test_build_call_jit_elt_from_jit_trampoline():
    pass


def test_build_call_jit_elt_from_int_trampoline():
    pass


def test_build_ret_from_jit_to_jit_trampoline():
    pass


def test_build_ret_from_jit_to_int_trampoline():
    pass
