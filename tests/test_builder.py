import pytest
from capstone import CS_ARCH_RISCV
from capstone import CS_MODE_RISCV64
from capstone import Cs
from unicorn import Uc
from unicorn.riscv_const import UC_RISCV_REG_PC
from unicorn.riscv_const import UC_RISCV_REG_RA
from unicorn.riscv_const import UC_RISCV_REG_T0
from unicorn.unicorn_const import UC_ARCH_RISCV
from unicorn.unicorn_const import UC_MODE_RISCV64

from gigue.builder import InstructionBuilder
from gigue.constants import CALLER_SAVED_REG
from gigue.constants import RA
from gigue.constants import SP
from gigue.disassembler import Disassembler
from gigue.instructions import IInstruction

# =================================
#            Constants
# =================================

ADDRESS = 0x1000
RET_ADDRESS = 0xBEEF


@pytest.fixture
def disasm_wrap():
    disassembler = Disassembler()
    return disassembler


@pytest.fixture
def capstone_wrap():
    cap_disasm = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)
    return cap_disasm


@pytest.fixture
def unicorn_wrap():
    uc_emul = Uc(UC_ARCH_RISCV, UC_MODE_RISCV64)
    uc_emul.mem_map(ADDRESS, 2 * 1024 * 1024)
    # Fill memory with nops up to RET_ADDRESS by default
    for addr in range(ADDRESS, RET_ADDRESS, 4):
        uc_emul.mem_write(addr, IInstruction.nop().generate_bytes())
    uc_emul.reg_write(UC_RISCV_REG_RA, RET_ADDRESS)
    return uc_emul


# =================================
#        Specific structures
# =================================


@pytest.mark.parametrize("offset", [0x8, 0x800, 0xFFF, 0x80000, 0xFFFFFF])
def test_build_method_call(offset, disasm_wrap):
    instr_builder = InstructionBuilder()
    instrs = instr_builder.build_method_call(offset)
    assert instrs[0].name == "auipc"
    assert instrs[1].name == "jalr"
    assert offset == disasm_wrap.extract_call_offset(
        [instr.generate() for instr in instrs]
    )


@pytest.mark.parametrize("offset", [0x8, 0x800, 0xFFF, 0x80000, 0xFFFFFF])
def test_build_pic_call(offset, disasm_wrap):
    instr_builder = InstructionBuilder()
    instrs = instr_builder.build_pic_call(offset, 5, 5)
    assert instrs[0].name == "addi"
    assert instrs[1].name == "auipc"
    assert instrs[2].name == "jalr"
    assert offset == disasm_wrap.extract_call_offset(
        [instr.generate() for instr in instrs[1:]]
    )


@pytest.mark.parametrize("offset", [0x4, 0x800, 0xFFE, 0x80000, 0x1FFFE])
def test_build_switch_pic(offset, disasm_wrap):
    instr_builder = InstructionBuilder()
    instrs = instr_builder.build_switch_case(
        case_number=3, method_offset=offset, hit_case_reg=6, cmp_reg=5
    )
    gen_instrs = [instr.generate() for instr in instrs]
    # Load the value in x6
    assert instrs[0].name == "addi"
    assert disasm_wrap.extract_rd(gen_instrs[0]) == 6
    assert disasm_wrap.extract_imm_i(gen_instrs[0]) == 3
    # Compare and branch i
    assert instrs[1].name == "bne"
    assert disasm_wrap.extract_imm_b(gen_instrs[1]) == 8
    assert disasm_wrap.extract_rs1(gen_instrs[1]) == 5
    assert disasm_wrap.extract_rs2(gen_instrs[1]) == 6
    # Compare and branch i
    assert instrs[2].name == "jal"
    assert offset == disasm_wrap.extract_imm_j(gen_instrs[2])


@pytest.mark.parametrize("used_s_regs", [0, 5, 10])
@pytest.mark.parametrize("local_var_nb", [0, 5, 10])
@pytest.mark.parametrize("contains_call", [True, False])
def test_build_prologue(used_s_regs, local_var_nb, contains_call, disasm_wrap):
    instr_builder = InstructionBuilder()
    instrs = instr_builder.build_prologue(
        used_s_regs=used_s_regs, local_var_nb=local_var_nb, contains_call=contains_call
    )
    gen_instrs = [instr.generate() for instr in instrs]
    # Space on top of the stack
    assert instrs[0].name == "addi"
    assert (
        disasm_wrap.extract_imm_i(gen_instrs[0], sign_extend=True)
        == -(used_s_regs + local_var_nb + (1 if contains_call else 0)) * 4
    )
    # Filling of the stack
    for i, (instr, generated) in enumerate(zip(instrs[1:-1], gen_instrs[1:-1])):
        assert instr.name == "sw"
        assert disasm_wrap.extract_imm_s(generated) == i * 4
    # RA check
    if contains_call:
        assert instrs[-1].name == "sw"
        assert disasm_wrap.extract_imm_s(gen_instrs[-1]) == used_s_regs * 4
        assert disasm_wrap.extract_rs1(instrs[-1].generate()) == 1


@pytest.mark.parametrize("used_s_regs", [0, 5, 10])
@pytest.mark.parametrize("local_var_nb", [0, 5, 10])
@pytest.mark.parametrize("contains_call", [True, False])
def test_build_epilogue(used_s_regs, local_var_nb, contains_call, disasm_wrap):
    instr_builder = InstructionBuilder()
    instrs = instr_builder.build_epilogue(
        used_s_regs=used_s_regs, local_var_nb=local_var_nb, contains_call=contains_call
    )
    gen_instrs = [instr.generate() for instr in instrs]
    # Restore saved regs
    for i, (instr, generated) in enumerate(zip(instrs[:-2], gen_instrs[:-2])):
        assert instr.name == "lw"
        assert disasm_wrap.extract_imm_i(generated) == i * 4
    # RA check and restore
    if contains_call:
        assert instrs[used_s_regs].name == "lw"
        assert disasm_wrap.extract_imm_i(gen_instrs[used_s_regs]) == used_s_regs * 4
        assert disasm_wrap.extract_rd(gen_instrs[used_s_regs]) == RA
        assert disasm_wrap.extract_rs1(gen_instrs[used_s_regs]) == SP
    # Restore SP
    assert instrs[-2].name == "addi"
    assert (
        disasm_wrap.extract_imm_i(gen_instrs[-2])
        == (used_s_regs + local_var_nb + (1 if contains_call else 0)) * 4
    )
    # Jump check
    assert instrs[-1].name == "jalr"
    assert instrs[-1].rd == 0
    assert instrs[-1].rs1 == 1


# =================================
#        Random instructions
# =================================


@pytest.mark.parametrize("execution_number", range(30))
def test_build_random_r_instruction(execution_number):
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_random_r_instruction(CALLER_SAVED_REG)
    assert instr.rd in CALLER_SAVED_REG
    assert instr.rs1 in CALLER_SAVED_REG
    assert instr.rs2 in CALLER_SAVED_REG


@pytest.mark.parametrize("execution_number", range(30))
def test_build_random_i_instruction(execution_number):
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_random_i_instruction(CALLER_SAVED_REG)
    assert instr.rd in CALLER_SAVED_REG
    assert instr.rs1 in CALLER_SAVED_REG
    assert 0 <= instr.imm <= 0xFFF


@pytest.mark.parametrize("execution_number", range(10))
def test_build_random_u_instruction(execution_number):
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_random_u_instruction(CALLER_SAVED_REG)
    assert instr.rd in CALLER_SAVED_REG
    assert 0 <= instr.imm <= 0xFFFFFFFF


@pytest.mark.parametrize("execution_number", range(5))
def test_build_random_j_instruction(execution_number):
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_random_j_instruction(CALLER_SAVED_REG, 0x7FF)
    assert instr.rd in CALLER_SAVED_REG
    assert 0 <= instr.imm <= 0xFFF
    assert instr.imm % 2 == 0


@pytest.mark.parametrize("execution_number", range(10))
def test_build_random_b_instruction(execution_number):
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_random_b_instruction(CALLER_SAVED_REG, 0x7FF)
    assert instr.rs1 in CALLER_SAVED_REG
    assert instr.rs2 in CALLER_SAVED_REG
    assert 0 <= instr.imm <= 0xFFF
    assert instr.imm % 2 == 0


# =================================
#        Capstone/Unicorn
# =================================

# Disassembly / Smoke exec
# ========================


def test_build_nop(capstone_wrap):
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_nop()
    bytes = instr.generate_bytes()
    instr_disasm = next(capstone_wrap.disasm(bytes, ADDRESS))
    assert instr_disasm.mnemonic == "nop"


def test_build_ret(capstone_wrap):
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_ret()
    bytes = instr.generate_bytes()
    instr_disasm = next(capstone_wrap.disasm(bytes, ADDRESS))
    assert instr_disasm.mnemonic == "ret"


@pytest.mark.parametrize("execution_number", range(30))
def test_build_random_instruction_disassembly_smoke(execution_number, capstone_wrap):
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_random_instruction(CALLER_SAVED_REG, 0x7FF)
    bytes = instr.generate_bytes()
    next(capstone_wrap.disasm(bytes, ADDRESS))


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
    execution_number, build_method, unicorn_wrap, capstone_wrap
):
    instr = build_method(CALLER_SAVED_REG)
    bytes = instr.generate_bytes()
    next(capstone_wrap.disasm(bytes, ADDRESS))
    unicorn_wrap.mem_write(ADDRESS, bytes)
    unicorn_wrap.emu_start(ADDRESS, ADDRESS + len(bytes))
    unicorn_wrap.emu_stop()


@pytest.mark.parametrize("execution_number", range(5))
def test_random_j_disassembly_execution_smoke(execution_number, unicorn_wrap):
    # Fill memory with nops up to 0xBEEF by default
    for addr in range(ADDRESS, RET_ADDRESS, 4):
        unicorn_wrap.mem_write(addr, IInstruction.nop().generate_bytes())
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_random_j_instruction(
        CALLER_SAVED_REG, (RET_ADDRESS - ADDRESS) & 0xFFFFF
    )
    bytes = instr.generate_bytes()
    unicorn_wrap.mem_write(ADDRESS, bytes)
    unicorn_wrap.emu_start(ADDRESS, 0, count=1)
    unicorn_wrap.emu_stop()


@pytest.mark.parametrize("execution_number", range(10))
def test_random_b_disassembly_execution_smoke(execution_number, unicorn_wrap):
    # Fill memory with nops up to 0xBEEF by default
    for addr in range(ADDRESS, RET_ADDRESS, 4):
        unicorn_wrap.mem_write(addr, IInstruction.nop().generate_bytes())
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_random_b_instruction(
        CALLER_SAVED_REG, (RET_ADDRESS - ADDRESS) & 0x7FF
    )
    bytes = instr.generate_bytes()
    unicorn_wrap.mem_write(ADDRESS, bytes)
    unicorn_wrap.emu_start(ADDRESS, 0, count=1)
    unicorn_wrap.emu_stop()


# Disassembly / Exec
# ========================


@pytest.mark.parametrize("offset", [0x8, 0x800, 0xFF0, 0x80000])
def test_build_method_call_execution(offset, unicorn_wrap, capstone_wrap):
    instr_builder = InstructionBuilder()
    instrs = instr_builder.build_method_call(offset)
    bytes = instr_builder.consolidate_bytes(instrs)
    print(bytes)
    for i in capstone_wrap.disasm(bytes, ADDRESS):
        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
    unicorn_wrap.mem_write(ADDRESS, bytes)
    unicorn_wrap.emu_start(begin=ADDRESS, until=ADDRESS + offset)
    # TODO: Registers not updating?
    # current_ra = uc_emul.reg_read(UC_RISCV_REG_RA)
    current_pc = unicorn_wrap.reg_read(UC_RISCV_REG_PC)
    # print(current_pc)
    # print(current_ra)
    assert current_pc == ADDRESS + offset
    unicorn_wrap.emu_stop()


@pytest.mark.parametrize("offset", [0x8, 0x800, 0xFF0, 0x80000])
def test_build_pic_call_execution(offset, unicorn_wrap, capstone_wrap):
    instr_builder = InstructionBuilder()
    instrs = instr_builder.build_pic_call(offset, 5, 5)
    bytes = instr_builder.consolidate_bytes(instrs)
    for i in capstone_wrap.disasm(bytes, ADDRESS):
        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
    unicorn_wrap.mem_write(ADDRESS, bytes)
    unicorn_wrap.emu_start(begin=ADDRESS, until=ADDRESS + offset + 4)
    current_t0 = unicorn_wrap.reg_read(UC_RISCV_REG_T0)
    current_pc = unicorn_wrap.reg_read(UC_RISCV_REG_PC)
    assert current_t0 == 5
    assert current_pc == ADDRESS + offset + 4
    unicorn_wrap.emu_stop()


# @pytest.mark.parametrize("offset", [0x4, 0x800, 0xFFE, 0x80000, 0x1FFFE])
# def test_build_switch_pic(offset):
#     instr_builder = InstructionBuilder()
#     instrs = instr_builder.build_switch_case(
#         case_number=3, method_offset=offset, hit_case_reg=6, cmp_reg=5
#     )
#     gen_instrs = [instr.generate() for instr in instrs]
#     # Load the value in x6
#     assert instrs[0].name == "addi"
#     assert disassembler.extract_rd(gen_instrs[0]) == 6
#     assert disassembler.extract_imm_i(gen_instrs[0]) == 3
#     # Compare and branch i
#     assert instrs[1].name == "bne"
#     assert disassembler.extract_imm_b(gen_instrs[1]) == 8
#     assert disassembler.extract_rs1(gen_instrs[1]) == 5
#     assert disassembler.extract_rs2(gen_instrs[1]) == 6
#     # Compare and branch i
#     assert instrs[2].name == "jal"
#     assert offset == disassembler.extract_imm_j(gen_instrs[2])


# @pytest.mark.parametrize("used_s_regs", [0, 5, 10])
# @pytest.mark.parametrize("local_var_nb", [0, 5, 10])
# @pytest.mark.parametrize("contains_call", [True, False])
# def test_build_prologue(used_s_regs, local_var_nb, contains_call):
#     instr_builder = InstructionBuilder()
#     instrs = instr_builder.build_prologue(
#         used_s_regs=used_s_regs, local_var_nb=local_var_nb, contains_call=contains_call
#     )
#     gen_instrs = [instr.generate() for instr in instrs]
#     # Space on top of the stack
#     assert instrs[0].name == "addi"
#     assert (
#         disassembler.extract_imm_i(gen_instrs[0], sign_extend=True)
#         == -(used_s_regs + local_var_nb + (1 if contains_call else 0)) * 4
#     )
#     # Filling of the stack
#     for i, (instr, generated) in enumerate(zip(instrs[1:-1], gen_instrs[1:-1])):
#         assert instr.name == "sw"
#         assert disassembler.extract_imm_s(generated) == i * 4
#     # RA check
#     if contains_call:
#         assert instrs[-1].name == "sw"
#         assert disassembler.extract_imm_s(gen_instrs[-1]) == used_s_regs * 4
#         assert disassembler.extract_rs1(instrs[-1].generate()) == 1


# @pytest.mark.parametrize("used_s_regs", [0, 5, 10])
# @pytest.mark.parametrize("local_var_nb", [0, 5, 10])
# @pytest.mark.parametrize("contains_call", [True, False])
# def test_build_epilogue(used_s_regs, local_var_nb, contains_call):
#     instr_builder = InstructionBuilder()
#     instrs = instr_builder.build_epilogue(
#         used_s_regs=used_s_regs, local_var_nb=local_var_nb, contains_call=contains_call
#     )
#     gen_instrs = [instr.generate() for instr in instrs]
#     # Restore saved regs
#     for i, (instr, generated) in enumerate(zip(instrs[:-2], gen_instrs[:-2])):
#         assert instr.name == "lw"
#         assert disassembler.extract_imm_i(generated) == i * 4
#     # RA check and restore
#     if contains_call:
#         assert instrs[used_s_regs].name == "lw"
#         assert disassembler.extract_imm_i(gen_instrs[used_s_regs]) == used_s_regs * 4
#         assert disassembler.extract_rd(gen_instrs[used_s_regs]) == RA
#         assert disassembler.extract_rs1(gen_instrs[used_s_regs]) == SP
#     # Restore SP
#     assert instrs[-2].name == "addi"
#     assert (
#         disassembler.extract_imm_i(gen_instrs[-2])
#         == (used_s_regs + local_var_nb + (1 if contains_call else 0)) * 4
#     )
#     # Jump check
#     assert instrs[-1].name == "jalr"
#     assert instrs[-1].rd == 0
#     assert instrs[-1].rs1 == 1
