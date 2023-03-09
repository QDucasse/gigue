import pytest

from gigue.constants import HIT_CASE_REG, RA
from gigue.fixer.builder import FIXERInstructionBuilder
from gigue.fixer.constants import FIXER_CMP_REG

# =================================
#       Disassembly calls
# =================================


@pytest.mark.parametrize("offset", [0x8, 0x800, 0xFFF, 0x80000, 0x1FFFE])
def test_build_method_call(offset, fixer_disasm_setup, cap_disasm_custom_setup):
    instr_builder = FIXERInstructionBuilder()
    instrs = instr_builder.build_method_call(offset)
    gen_instrs = [instr.generate() for instr in instrs]
    # Name check
    assert instrs[0].name == "cficall"
    assert instrs[1].name == "auipc"
    assert instrs[2].name == "jalr"
    # Smoke capstone disassembly
    cap_disasm = cap_disasm_custom_setup
    bytes = b"".join([instr.generate_bytes() for instr in instrs])
    for i in cap_disasm.disasm(bytes, 0x1000):
        # print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
        pass
    # Disassembly
    fixer_disasm = fixer_disasm_setup
    assert fixer_disasm.get_instruction_info(gen_instrs[0]).name == "cficall"
    assert fixer_disasm.get_instruction_info(gen_instrs[1]).name == "auipc"
    assert fixer_disasm.get_instruction_info(gen_instrs[2]).name == "jalr"
    assert fixer_disasm.extract_rs1(gen_instrs[0]) == FIXER_CMP_REG
    assert fixer_disasm.extract_call_offset(gen_instrs[1:]) == offset


@pytest.mark.parametrize("offset", [0x8, 0x800, 0xFFF, 0x80000, 0x1FFFE])
@pytest.mark.parametrize("hit_case", range(1, 5))
def test_build_pic_call(offset, hit_case, fixer_disasm_setup, cap_disasm_custom_setup):
    instr_builder = FIXERInstructionBuilder()
    instrs = instr_builder.build_pic_call(offset=offset, hit_case=hit_case)
    gen_instrs = [instr.generate() for instr in instrs]
    # Name check
    assert instrs[0].name == "cficall"
    assert instrs[1].name == "addi"
    assert instrs[2].name == "auipc"
    assert instrs[3].name == "jalr"
    # Smoke capstone disassembly
    cap_disasm = cap_disasm_custom_setup
    bytes = b"".join([instr.generate_bytes() for instr in instrs])
    for i in cap_disasm.disasm(bytes, 0x1000):
        # print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
        pass
    # Disassembly
    fixer_disasm = fixer_disasm_setup
    assert fixer_disasm.get_instruction_info(gen_instrs[0]).name == "cficall"
    assert fixer_disasm.get_instruction_info(gen_instrs[1]).name == "addi"
    assert fixer_disasm.get_instruction_info(gen_instrs[2]).name == "auipc"
    assert fixer_disasm.get_instruction_info(gen_instrs[3]).name == "jalr"
    assert fixer_disasm.extract_rs1(gen_instrs[0]) == FIXER_CMP_REG
    assert fixer_disasm.extract_rd(gen_instrs[1]) == HIT_CASE_REG
    assert fixer_disasm.extract_imm_i(gen_instrs[1]) == hit_case
    assert fixer_disasm.extract_call_offset(gen_instrs[2:]) == offset


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
