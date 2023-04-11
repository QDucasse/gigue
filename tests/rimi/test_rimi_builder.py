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
        == -(used_s_regs + local_var_nb + (1 if contains_call else 0)) * 8
    )
    # Filling of the stack
    for i, (instr, generated) in enumerate(zip(instrs[1:-2], gen_instrs[1:-2])):
        assert instr.name == "sd"
        assert rimi_disasm.extract_imm_s(generated) == i * 8
    # RA check
    if contains_call:
        assert instrs[-2].name == "addi"
        assert rimi_disasm.extract_imm_i(gen_instrs[-2], sign_extend=True) == -4
        assert rimi_disasm.extract_rs1(instrs[-2].generate()) == RIMI_SSP_REG
        assert rimi_disasm.extract_rd(instrs[-2].generate()) == RIMI_SSP_REG
        assert instrs[-1].name == "ss"
        assert rimi_disasm.extract_imm_s(gen_instrs[-1]) == 0
        assert rimi_disasm.extract_rs2(instrs[-1].generate()) == RA
        assert rimi_disasm.extract_rs1(instrs[-1].generate()) == RIMI_SSP_REG


def test_build_ss_epilogue():
    pass


# Trampoline version
# \__________________

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
