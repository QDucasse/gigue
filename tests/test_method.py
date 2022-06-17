import pytest
from capstone import CS_ARCH_RISCV
from capstone import CS_MODE_RISCV64
from capstone import Cs
from unicorn import Uc
from unicorn.unicorn_const import UC_ARCH_RISCV
from unicorn.unicorn_const import UC_MODE_RISCV64

from gigue.method import InstructionBuilder
from gigue.method import Method

# =================================
#            Constants
# =================================


CALLER_SAVED_REG = [5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17, 28, 29, 30, 31]

ADDRESS = 0x1000
cap_disasm = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)
uc_emul = Uc(UC_ARCH_RISCV, UC_MODE_RISCV64)
uc_emul.mem_map(ADDRESS, 2 * 1024 * 1024)


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
    instr = instr_builder.build_random_j_instruction(CALLER_SAVED_REG, 0xFFF)
    assert instr.rd in CALLER_SAVED_REG
    assert 0 <= instr.imm <= 0xFFF
    assert instr.imm % 2 == 0


@pytest.mark.parametrize("execution_number", range(10))
def test_builder_random_b_instruction(execution_number):
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_random_b_instruction(CALLER_SAVED_REG, 0xFFF)
    assert instr.rs1 in CALLER_SAVED_REG
    assert instr.rs2 in CALLER_SAVED_REG
    assert 0 <= instr.imm <= 0xFFF
    assert instr.imm % 2 == 0


@pytest.mark.parametrize("execution_number", range(30))
def test_builder_random_instruction_disassembly_smoke(execution_number):
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_random_instruction(CALLER_SAVED_REG, 0xFFF)
    bytes = instr.generate_bytes()
    next(cap_disasm.disasm(bytes, ADDRESS))


@pytest.mark.parametrize("execution_number", range(30))
@pytest.mark.parametrize("build_method", [
    getattr(InstructionBuilder, "build_random_r_instruction"),
    getattr(InstructionBuilder, "build_random_i_instruction"),
    getattr(InstructionBuilder, "build_random_u_instruction")
])
def test_random_riu_disassembly_execution_smoke(execution_number, build_method):
    instr_builder = InstructionBuilder()
    instr = build_method(instr_builder, CALLER_SAVED_REG)
    bytes = instr.generate_bytes()
    next(cap_disasm.disasm(bytes, ADDRESS))
    uc_emul.mem_write(ADDRESS, bytes)
    uc_emul.emu_start(ADDRESS, ADDRESS + len(bytes))
    uc_emul.emu_stop()


# TODO: Smoke execution tests for J/B

@pytest.mark.parametrize("execution_number", range(5))
def test_random_j_disassembly_smoke(execution_number):
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_random_j_instruction(CALLER_SAVED_REG, 2 * 1024 * 1024)
    bytes = instr.generate_bytes()
    next(cap_disasm.disasm(bytes, ADDRESS))


@pytest.mark.parametrize("execution_number", range(10))
def test_random_b_disassembly_smoke(execution_number):
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_random_b_instruction(CALLER_SAVED_REG, 2 * 1024 * 1024)
    bytes = instr.generate_bytes()
    next(cap_disasm.disasm(bytes, ADDRESS))


# =================================
#             Method
# =================================


def test_initialization():
    method = Method(size=32, address=0x7FFFFF, call_number=15, registers=[])
    assert method.size == 30
    assert method.address == 0x7FFFFF
    assert method.call_number == 5


@pytest.mark.parametrize("execution_number", range(5))
def test_instructions_adding(execution_number):
    method = Method(size=32, address=0x1000, call_number=15, registers=CALLER_SAVED_REG)
    method.add_instructions()
    assert len(method.instructions) == method.size


@pytest.mark.parametrize("execution_number", range(30))
@pytest.mark.parametrize("weights", [
    [100, 0, 0, 0, 0],
    [0, 100, 0, 0, 0],
    [0, 0, 100, 0, 0],
    # [0, 0, 0, 100, 0],
    # [0, 0, 0, 0, 100],
    # [35, 40, 10, 5, 10],
])
def test_instructions_disassembly_execution_smoke(execution_number, weights):
    method = Method(size=10, address=0x1000, call_number=15, registers=CALLER_SAVED_REG)
    method.add_instructions(weights)
    bytes = method.generate_bytes()
    for i in cap_disasm.disasm(bytes, ADDRESS):
        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
    uc_emul.mem_write(ADDRESS, bytes)
    uc_emul.emu_start(ADDRESS, ADDRESS + len(bytes))
    uc_emul.emu_stop()


if __name__ == "__main__":
    method = Method(size=32, address=0x1000, call_number=15, registers=CALLER_SAVED_REG)
    method.add_instructions(weights=[0, 0, 0, 100, 0])
    # jal_instr = JInstruction.jal(0, )
    bytes = method.generate_bytes()
    for i in cap_disasm.disasm(bytes, ADDRESS):
        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
    uc_emul.mem_write(ADDRESS, bytes)
    uc_emul.emu_start(ADDRESS, ADDRESS + len(bytes))
    uc_emul.emu_stop()
