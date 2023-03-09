import pytest

from gigue.constants import HIT_CASE_REG
from gigue.fixer.builder import FIXERInstructionBuilder
from gigue.fixer.constants import FIXER_CMP_REG

# =================================
#       Disassembly calls
# =================================


@pytest.mark.parametrize("offset", [0x8, 0x800, 0xFFF, 0x80000, 0x1FFFE])
def test_build_method_call(offset, disasm_setup):
    instr_builder = FIXERInstructionBuilder()
    instrs = instr_builder.build_method_call(offset)
    gen_instrs = [instr.generate() for instr in instrs]
    # Name check
    assert instrs[0].name == "cficall"
    assert instrs[1].name == "auipc"
    assert instrs[2].name == "jalr"
    # Disassembly
    disasm = disasm_setup
    assert disasm.extract_rs1(gen_instrs[0]) == FIXER_CMP_REG
    assert offset == disasm.extract_call_offset(
        [instr.generate() for instr in instrs[1:]]
    )


@pytest.mark.parametrize("offset", [0x8, 0x800, 0xFFF, 0x80000, 0x1FFFE])
@pytest.mark.parametrize("hit_case", range(1, 5))
def test_build_pic_call(offset, hit_case, disasm_setup):
    instr_builder = FIXERInstructionBuilder()
    instrs = instr_builder.build_pic_call(offset=offset, hit_case=hit_case)
    gen_instrs = [instr.generate() for instr in instrs]
    # Name check
    assert instrs[0].name == "cficall"
    assert instrs[1].name == "addi"
    assert instrs[2].name == "auipc"
    assert instrs[3].name == "jalr"
    # Disassembly
    disasm = disasm_setup
    assert disasm.extract_rs1(gen_instrs[0]) == FIXER_CMP_REG
    assert disasm.extract_rd(gen_instrs[1]) == HIT_CASE_REG
    assert disasm.extract_imm_i(gen_instrs[1]) == hit_case
    assert offset == disasm.extract_call_offset(gen_instrs[2:])
