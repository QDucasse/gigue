import pytest
from capstone import CS_ARCH_RISCV
from capstone import CS_MODE_RISCV64
from capstone import Cs
from unicorn import Uc
from unicorn.riscv_const import UC_RISCV_REG_RA
from unicorn.unicorn_const import UC_ARCH_RISCV
from unicorn.unicorn_const import UC_MODE_RISCV64

from gigue.builder import InstructionBuilder
from gigue.instructions import IInstruction

# =================================
#            Constants
# =================================


CALLER_SAVED_REG = [5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17, 28, 29, 30, 31]

ADDRESS = 0x1000
RET_ADDRESS = 0xBEEF

cap_disasm = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)
uc_emul = Uc(UC_ARCH_RISCV, UC_MODE_RISCV64)
uc_emul.mem_map(ADDRESS, 2 * 1024 * 1024)
# Fill memory with nops up to F00D by default
for addr in range(ADDRESS, RET_ADDRESS, 4):
    uc_emul.mem_write(addr, IInstruction.nop().generate_bytes())
uc_emul.reg_write(UC_RISCV_REG_RA, RET_ADDRESS)


def setup_function():
    # Zero out registers
    for reg in CALLER_SAVED_REG:
        uc_emul.reg_write(reg, 0)
    uc_emul.reg_write(UC_RISCV_REG_RA, RET_ADDRESS)


# =================================
#       Instruction Builder
# =================================


@pytest.mark.parametrize("execution_number", range(30))
def test_builder_random_r_instruction(execution_number):
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_random_r_instruction(CALLER_SAVED_REG)
    assert instr.rd in CALLER_SAVED_REG
    assert instr.rs1 in CALLER_SAVED_REG
    assert instr.rs2 in CALLER_SAVED_REG


@pytest.mark.parametrize("execution_number", range(30))
def test_builder_random_i_instruction(execution_number):
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_random_i_instruction(CALLER_SAVED_REG)
    assert instr.rd in CALLER_SAVED_REG
    assert instr.rs1 in CALLER_SAVED_REG
    assert 0 <= instr.imm <= 0xFFF


@pytest.mark.parametrize("execution_number", range(10))
def test_builder_random_u_instruction(execution_number):
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_random_u_instruction(CALLER_SAVED_REG)
    assert instr.rd in CALLER_SAVED_REG
    assert 0 <= instr.imm <= 0xFFFFFFFF


@pytest.mark.parametrize("execution_number", range(5))
def test_builder_random_j_instruction(execution_number):
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_random_j_instruction(CALLER_SAVED_REG, 0x7FF)
    assert instr.rd in CALLER_SAVED_REG
    assert 0 <= instr.imm <= 0xFFF
    assert instr.imm % 2 == 0


@pytest.mark.parametrize("execution_number", range(10))
def test_builder_random_b_instruction(execution_number):
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_random_b_instruction(CALLER_SAVED_REG, 0x7FF)
    assert instr.rs1 in CALLER_SAVED_REG
    assert instr.rs2 in CALLER_SAVED_REG
    assert 0 <= instr.imm <= 0xFFF
    assert instr.imm % 2 == 0


@pytest.mark.parametrize("execution_number", range(30))
def test_builder_random_instruction_disassembly_smoke(execution_number):
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_random_instruction(CALLER_SAVED_REG, 0x7FF)
    bytes = instr.generate_bytes()
    next(cap_disasm.disasm(bytes, ADDRESS))


@pytest.mark.parametrize("execution_number", range(30))
@pytest.mark.parametrize("build_method", [
    getattr(InstructionBuilder, "build_random_r_instruction"),
    getattr(InstructionBuilder, "build_random_i_instruction"),
    getattr(InstructionBuilder, "build_random_u_instruction"),
])
def test_random_riu_disassembly_execution_smoke(execution_number, build_method):
    instr_builder = InstructionBuilder()
    instr = build_method(instr_builder, CALLER_SAVED_REG)
    bytes = instr.generate_bytes()
    next(cap_disasm.disasm(bytes, ADDRESS))
    uc_emul.mem_write(ADDRESS, bytes)
    uc_emul.emu_start(ADDRESS, ADDRESS + len(bytes))
    uc_emul.emu_stop()


@pytest.mark.parametrize("execution_number", range(5))
def test_random_j_disassembly_execution_smoke(execution_number):
    # Fill memory with nops up to 0xBEEF by default
    for addr in range(ADDRESS, RET_ADDRESS, 4):
        uc_emul.mem_write(addr, IInstruction.nop().generate_bytes())
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_random_j_instruction(CALLER_SAVED_REG, (RET_ADDRESS - ADDRESS) & 0xFFFFF)
    bytes = instr.generate_bytes()
    uc_emul.mem_write(ADDRESS, bytes)
    uc_emul.emu_start(ADDRESS, 0, count=1)
    uc_emul.emu_stop()


@pytest.mark.parametrize("execution_number", range(10))
def test_random_b_disassembly_execution_smoke(execution_number):
    # Fill memory with nops up to 0xBEEF by default
    for addr in range(ADDRESS, RET_ADDRESS, 4):
        uc_emul.mem_write(addr, IInstruction.nop().generate_bytes())
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_random_b_instruction(CALLER_SAVED_REG, (RET_ADDRESS - ADDRESS) & 0x7FF)
    bytes = instr.generate_bytes()
    uc_emul.mem_write(ADDRESS, bytes)
    uc_emul.emu_start(ADDRESS, 0, count=1)
    uc_emul.emu_stop()
