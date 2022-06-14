import pytest

from gigue.method import InstructionBuilder
from gigue.method import Method

# =================================
#       Instruction Builder
# =================================

CALLER_SAVED_REG = [5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17, 28, 29, 30, 31]


@pytest.mark.parametrize("execution_number", range(20))
def test_builder_random_r_instruction(execution_number):
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_random_r_instruction(CALLER_SAVED_REG)
    assert instr.rd in CALLER_SAVED_REG
    assert instr.rs1 in CALLER_SAVED_REG
    assert instr.rs2 in CALLER_SAVED_REG


@pytest.mark.parametrize("execution_number", range(20))
def test_builder_random_i_instruction(execution_number):
    instr_builder = InstructionBuilder()
    instr = instr_builder.build_random_i_instruction(CALLER_SAVED_REG)
    assert instr.rd in CALLER_SAVED_REG
    assert instr.rs1 in CALLER_SAVED_REG
    assert 0 <= instr.imm <= 0xFFF


# =================================
#             Method
# =================================


def test_initialization():
    method = Method(size=32, address=0x7FFFFF, call_number=15, registers=[])
    assert method.size == 30
    assert method.address == 0x7FFFFF
    assert method.call_number == 5
